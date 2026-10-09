use std::sync::Arc;

use crate::core::metrics::ClientMetrics;
use crate::core::otel::OtelTelemetry;
use crate::core::proxy::ProxyConfig;
use crate::core::request_builder::RequestExecutionOptions;
use crate::rate_limit::RateLimiter;
use crate::resilience::{CircuitBreaker, RetryBudget};

use super::transport::{TransportAgents, make_agent_configs};
use super::{AdaptiveConcurrencyController, Client, ClientInner, RequestLimiters};

/// Settings specific to the synchronous HTTP transport.
pub struct BlockingTransportOptions {
    pub(crate) pool_max_idle_connections: usize,
}

impl Default for BlockingTransportOptions {
    fn default() -> Self {
        Self {
            pool_max_idle_connections: 16,
        }
    }
}

/// Builds a blocking [`Client`] with transport, timeout, retry, TLS, and
/// observability settings.
///
/// Shared settings are documented on [`crate::ClientBuilder`]. HTTP/2 forcing,
/// proxy authorization headers, TLS version bounds, and PKCS#12 identities
/// are specific to the async transport. Blocking proxy authentication uses
/// credentials in the proxy URI; blocking client identities use PEM.
///
/// ```compile_fail
/// reqx::blocking::Client::builder("https://example.com")
///     .try_proxy_authorization("Basic dXNlcjpwYXNz");
/// ```
///
/// ```compile_fail
/// reqx::blocking::Client::builder("https://example.com")
///     .tls_client_identity_pkcs12(vec![1, 2, 3], "password");
/// ```
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "blocking-tls-rustls-ring",
        feature = "blocking-tls-rustls-aws-lc-rs",
        feature = "blocking-tls-rustls-graviola",
        feature = "blocking-tls-rustls-no-provider",
        feature = "blocking-tls-native"
    )))
)]
pub type ClientBuilder = crate::core::client_builder::ClientBuilder<BlockingTransportOptions>;

impl ClientBuilder {
    /// Sets the maximum number of idle pooled connections kept in total.
    ///
    /// Zero disables global idle connection retention.
    pub fn pool_max_idle_connections(mut self, pool_max_idle_connections: usize) -> Self {
        self.transport_options.pool_max_idle_connections = pool_max_idle_connections;
        self
    }

    /// Validates the builder and constructs the client.
    ///
    /// Unsupported backend-specific combinations return [`crate::Error::TlsConfig`].
    pub fn build(mut self) -> crate::Result<Client> {
        let dns_overrides = self.validate()?;

        let otel = if self.otel_enabled {
            OtelTelemetry::try_enabled_with_path_normalizer(
                self.client_name.clone(),
                self.otel_path_normalizer,
            )?
        } else {
            OtelTelemetry::disabled()
        };

        let proxy_config = self.http_proxy.map(|uri| ProxyConfig {
            uri,
            authorization: None,
            no_proxy_rules: self.no_proxy_rules,
        });

        let (direct_config, proxy_config_for_agent) = make_agent_configs(
            self.tls_backend,
            &self.tls_options,
            &self.client_name,
            self.pool_idle_timeout,
            self.pool_max_idle_per_host,
            self.transport_options.pool_max_idle_connections,
            proxy_config.as_ref().map(|config| &config.uri),
        )?;

        let direct = super::dns::build_agent(direct_config, dns_overrides);
        let proxied = proxy_config_for_agent.map(|config| config.new_agent());
        let clock = self.clock;

        Ok(Client {
            inner: Arc::new(ClientInner {
                base_url: self.base_url,
                default_headers: self.default_headers,
                request_defaults: RequestExecutionOptions {
                    request_timeout: self.request_timeout,
                    total_timeout: self.total_timeout,
                    max_response_body_bytes: self.max_response_body_bytes,
                    retry_policy: Arc::new(self.retry_policy),
                    redirect_policy: self.redirect_policy,
                    status_policy: self.default_status_policy,
                },
                buffered_auto_accept_encoding: self.buffered_auto_accept_encoding,
                stream_auto_accept_encoding: self.stream_auto_accept_encoding,
                stream_deadline_slack: self.stream_deadline_slack,
                retry_eligibility: self.retry_eligibility,
                retry_budget: self
                    .retry_budget_policy
                    .map(|policy| Arc::new(RetryBudget::new(policy, Arc::clone(&clock)))),
                circuit_breaker: self
                    .circuit_breaker_policy
                    .map(|policy| Arc::new(CircuitBreaker::new(policy, Arc::clone(&clock)))),
                adaptive_concurrency: self.adaptive_concurrency_policy.map(|policy| {
                    Arc::new(AdaptiveConcurrencyController::new(
                        policy,
                        Arc::clone(&clock),
                    ))
                }),
                rate_limiter: RateLimiter::new(
                    self.global_rate_limit_policy,
                    self.per_host_rate_limit_policy,
                    Arc::clone(&clock),
                )
                .map(Arc::new),
                server_throttle_scope: self.server_throttle_scope,
                tls_backend: self.tls_backend,
                transport: TransportAgents {
                    direct,
                    proxy: proxied,
                },
                proxy_config,
                endpoint_selector: self.endpoint_selector,
                clock: Arc::clone(&clock),
                backoff_source: self.backoff_source,
                connect_timeout: self.connect_timeout,
                request_limiters: RequestLimiters::new(
                    self.max_in_flight,
                    self.max_in_flight_per_host,
                    Arc::clone(&clock),
                ),
                metrics: ClientMetrics::with_options(self.metrics_enabled, otel),
                interceptors: self.interceptors,
                observers: self.observers,
            }),
        })
    }
}

#[cfg(test)]
mod contract_tests;
