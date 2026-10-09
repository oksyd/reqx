use std::sync::Arc;

use http::HeaderValue;

use crate::async_client::limiters::RequestLimiters;
use crate::core::error::Error;
use crate::core::metrics::ClientMetrics;
use crate::core::otel::OtelTelemetry;
use crate::core::proxy::ProxyConfig;
use crate::core::request_builder::RequestExecutionOptions;
use crate::core::util::{parse_header_value, redact_uri_for_logs};
use crate::rate_limit::RateLimiter;
use crate::resilience::{CircuitBreaker, RetryBudget};
use crate::tls::TlsVersion;

use super::adaptive::AdaptiveConcurrencyController;
use super::transport::build_transport_client;
use super::{Client, ClientInner};

/// Settings specific to the asynchronous HTTP transport.
#[derive(Default)]
pub struct AsyncTransportOptions {
    pub(crate) http2_only: bool,
    pub(crate) proxy_authorization: Option<HeaderValue>,
}

#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-rustls-graviola",
        feature = "async-tls-rustls-no-provider",
        feature = "async-tls-native"
    )))
)]
/// Builds an async [`Client`] with transport, timeout, retry, TLS, and
/// observability settings.
///
/// Start from [`Client::builder`] and override only the controls your SDK
/// actually needs.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "_async")]
/// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// use std::time::Duration;
///
/// use reqx::advanced::RateLimitPolicy;
/// use reqx::prelude::{Client, RetryPolicy};
/// use reqx::TlsVersion;
///
/// let client = Client::builder("https://api.example.com")
///     .request_timeout(Duration::from_secs(3))
///     .total_timeout(Some(Duration::from_secs(10)))
///     .retry_policy(RetryPolicy::standard())
///     .http_proxy("http://proxy.internal:8080".parse()?)
///     .tls_max_version(TlsVersion::V1_2)
///     .global_rate_limit_policy(Some(RateLimitPolicy::standard()))
///     .build()?;
///
/// let _ = client;
/// # Ok(())
/// # }
/// ```
pub type ClientBuilder = crate::core::client_builder::ClientBuilder<AsyncTransportOptions>;

impl ClientBuilder {
    /// Forces HTTP/2 for all requests.
    pub fn http2_only(mut self, http2_only: bool) -> Self {
        self.transport_options.http2_only = http2_only;
        self
    }

    /// Sets the `Proxy-Authorization` header sent to the configured HTTP proxy.
    pub fn proxy_authorization(mut self, mut proxy_authorization: HeaderValue) -> Self {
        proxy_authorization.set_sensitive(true);
        self.transport_options.proxy_authorization = Some(proxy_authorization);
        self
    }

    /// Parses and sets the `Proxy-Authorization` header.
    pub fn try_proxy_authorization(self, proxy_authorization: &str) -> crate::Result<Self> {
        let proxy_authorization = parse_header_value("proxy-authorization", proxy_authorization)?;
        Ok(self.proxy_authorization(proxy_authorization))
    }

    /// Pins both the minimum and maximum TLS version to `version`.
    ///
    /// Async `rustls` backends accept both [`TlsVersion::V1_2`] and
    /// [`TlsVersion::V1_3`]. Async `native-tls` forwards the configured range
    /// to the underlying platform TLS implementation.
    pub fn tls_version(mut self, version: TlsVersion) -> Self {
        self.tls_options.min_protocol_version = Some(version);
        self.tls_options.max_protocol_version = Some(version);
        self
    }

    /// Sets the minimum TLS version accepted for outbound connections.
    ///
    /// Async `native-tls` forwards the configured range to the underlying
    /// platform TLS implementation.
    pub fn tls_min_version(mut self, version: TlsVersion) -> Self {
        self.tls_options.min_protocol_version = Some(version);
        self
    }

    /// Sets the maximum TLS version accepted for outbound connections.
    ///
    /// Async `native-tls` forwards the configured range to the underlying
    /// platform TLS implementation.
    pub fn tls_max_version(mut self, version: TlsVersion) -> Self {
        self.tls_options.max_protocol_version = Some(version);
        self
    }

    /// Clears any configured TLS version bounds.
    pub fn clear_tls_version_bounds(mut self) -> Self {
        self.tls_options.min_protocol_version = None;
        self.tls_options.max_protocol_version = None;
        self
    }

    /// Sets a PKCS#12 client identity for mTLS.
    pub fn tls_client_identity_pkcs12(
        mut self,
        identity_der: impl Into<Vec<u8>>,
        password: impl Into<String>,
    ) -> Self {
        self.tls_options.client_identity = Some(crate::tls::TlsClientIdentity::Pkcs12 {
            identity_der: identity_der.into(),
            password: password.into(),
        });
        self
    }

    /// Validates the builder and constructs the client.
    ///
    /// Unsupported backend-specific TLS combinations return
    /// [`crate::Error::TlsConfig`].
    pub fn build(mut self) -> crate::Result<Client> {
        let dns_overrides = self.validate()?;
        if let Some(proxy_uri) = self.http_proxy.as_ref() {
            let proxy_uri_has_credentials = proxy_uri
                .authority()
                .is_some_and(|authority| authority.as_str().contains('@'));
            if proxy_uri_has_credentials {
                return Err(Error::InvalidProxyConfig {
                    proxy_uri: redact_uri_for_logs(&proxy_uri.to_string()),
                    message: "async http_proxy URI must not include credentials; use proxy_authorization(...) for HTTP proxy authentication".to_owned(),
                });
            }
        }
        if self.transport_options.proxy_authorization.is_some() && self.http_proxy.is_none() {
            return Err(Error::ProxyAuthorizationRequiresHttpProxy);
        }

        if self
            .max_in_flight
            .is_some_and(|limit| limit > tokio::sync::Semaphore::MAX_PERMITS)
            || self
                .max_in_flight_per_host
                .is_some_and(|limit| limit > tokio::sync::Semaphore::MAX_PERMITS)
        {
            return Err(Error::InvalidConcurrencyLimitConfig {
                max_in_flight: self.max_in_flight,
                max_in_flight_per_host: self.max_in_flight_per_host,
                message: "concurrency limits must not exceed tokio::sync::Semaphore::MAX_PERMITS",
            });
        }

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
            authorization: self.transport_options.proxy_authorization,
            no_proxy_rules: self.no_proxy_rules,
        });
        let transport = build_transport_client(
            self.tls_backend,
            super::proxy::ProxyConnector::new(
                proxy_config.clone(),
                self.connect_timeout,
                dns_overrides,
            ),
            &self.tls_options,
            self.pool_idle_timeout,
            self.pool_max_idle_per_host,
            self.transport_options.http2_only,
        )?;
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
                client_name: self.client_name,
                tls_backend: self.tls_backend,
                proxy_config,
                transport,
                endpoint_selector: self.endpoint_selector,
                clock: Arc::clone(&clock),
                backoff_source: self.backoff_source,
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
mod tests {
    use http::HeaderValue;
    use http::header::{AUTHORIZATION, COOKIE};

    use super::Client;

    #[test]
    fn default_header_marks_sensitive_values_for_debug() {
        crate::test_support::install_crypto_provider();
        let builder = Client::builder("https://api.example.com")
            .default_header(
                AUTHORIZATION,
                HeaderValue::from_static("Bearer secret-token"),
            )
            .default_header(COOKIE, HeaderValue::from_static("session=secret-cookie"));

        let debug = format!("{:?}", builder.default_headers);
        assert!(debug.contains("Sensitive"));
        assert!(!debug.contains("secret-token"));
        assert!(!debug.contains("secret-cookie"));
    }

    #[test]
    fn concurrency_limits_reject_values_above_semaphore_capacity() {
        crate::test_support::install_crypto_provider();
        let max = tokio::sync::Semaphore::MAX_PERMITS;
        for limit in [max + 1, usize::MAX] {
            for per_host in [false, true] {
                let builder = super::Client::builder("http://localhost");
                let builder = if per_host {
                    builder.max_in_flight_per_host(Some(limit))
                } else {
                    builder.max_in_flight(Some(limit))
                };
                assert!(matches!(
                    builder.build(),
                    Err(crate::Error::InvalidConcurrencyLimitConfig { .. })
                ));
            }
        }
        assert!(
            super::Client::builder("http://localhost")
                .max_in_flight(Some(max))
                .max_in_flight_per_host(Some(max))
                .build()
                .is_ok()
        );
    }
}

#[cfg(test)]
mod contract_tests;
