use std::sync::Arc;
use std::time::Duration;

use http::HeaderMap;

use crate::core::extensions::{BackoffSource, Clock, EndpointSelector};
use crate::core::metrics::ClientMetrics;
use crate::core::observe::Observer;
use crate::core::policy::Interceptor;
use crate::core::proxy::ProxyConfig;
use crate::core::request_builder::RequestExecutionOptions;
use crate::core::retry::RetryEligibility;
use crate::rate_limit::{RateLimiter, ServerThrottleScope};
use crate::resilience::{CircuitBreaker, RetryBudget};
use crate::tls::TlsBackend;

mod adaptive;
mod body;
pub(crate) mod builder;
mod client;
mod dns;
pub(crate) mod limiters;
mod proxy;
mod request;
mod transport;
mod transport_error;

use adaptive::AdaptiveConcurrencyController;
pub use builder::ClientBuilder;
use limiters::RequestLimiters;
pub use request::RequestBuilder;
use transport::TransportClient;

#[derive(Clone)]
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
/// Reusable async HTTP client for SDK transports.
///
/// Cloning a client is cheap and shares its connection pool, configuration,
/// metrics and concurrency/resilience controls. Reuse a client across requests.
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    base_url: String,
    default_headers: HeaderMap,
    request_defaults: RequestExecutionOptions,
    buffered_auto_accept_encoding: bool,
    stream_auto_accept_encoding: bool,
    stream_deadline_slack: Duration,
    retry_eligibility: Arc<dyn RetryEligibility>,
    retry_budget: Option<Arc<RetryBudget>>,
    circuit_breaker: Option<Arc<CircuitBreaker>>,
    adaptive_concurrency: Option<Arc<AdaptiveConcurrencyController>>,
    rate_limiter: Option<Arc<RateLimiter>>,
    server_throttle_scope: ServerThrottleScope,
    client_name: String,
    tls_backend: TlsBackend,
    proxy_config: Option<ProxyConfig>,
    transport: TransportClient,
    endpoint_selector: Option<Arc<dyn EndpointSelector>>,
    clock: Arc<dyn Clock>,
    backoff_source: Option<Arc<dyn BackoffSource>>,
    request_limiters: Option<RequestLimiters>,
    metrics: ClientMetrics,
    interceptors: Vec<Arc<dyn Interceptor>>,
    observers: Vec<Arc<dyn Observer>>,
}
