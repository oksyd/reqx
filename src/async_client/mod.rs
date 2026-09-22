use std::sync::Arc;
use std::time::Duration;

use http::HeaderMap;

use crate::extensions::{BackoffSource, BodyCodec, Clock, EndpointSelector};
use crate::metrics::ClientMetrics;
use crate::observe::Observer;
use crate::policy::{Interceptor, RedirectPolicy, StatusPolicy};
use crate::proxy::ProxyConfig;
use crate::rate_limit::{RateLimiter, ServerThrottleScope};
use crate::resilience::{CircuitBreaker, RetryBudget};
use crate::retry::{RetryEligibility, RetryPolicy};
use crate::tls::TlsBackend;

mod adaptive;
pub(crate) mod body;
mod builder;
pub(crate) mod client;
pub(crate) mod limiters;
pub(crate) mod request;
mod transport;

use adaptive::AdaptiveConcurrencyController;
pub use builder::ClientBuilder;
use limiters::RequestLimiters;
use transport::TransportClient;

#[derive(Clone)]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-rustls-no-provider",
        feature = "async-tls-native"
    )))
)]
/// Reusable async HTTP client for SDK transports.
pub struct Client {
    base_url: String,
    default_headers: HeaderMap,
    buffered_auto_accept_encoding: bool,
    stream_auto_accept_encoding: bool,
    request_timeout: Duration,
    total_timeout: Option<Duration>,
    stream_deadline_slack: Duration,
    max_response_body_bytes: usize,
    retry_policy: RetryPolicy,
    retry_eligibility: Arc<dyn RetryEligibility>,
    retry_budget: Option<Arc<RetryBudget>>,
    circuit_breaker: Option<Arc<CircuitBreaker>>,
    adaptive_concurrency: Option<Arc<AdaptiveConcurrencyController>>,
    rate_limiter: Option<Arc<RateLimiter>>,
    server_throttle_scope: ServerThrottleScope,
    redirect_policy: RedirectPolicy,
    default_status_policy: StatusPolicy,
    client_name: String,
    tls_backend: TlsBackend,
    proxy_config: Option<ProxyConfig>,
    transport: TransportClient,
    endpoint_selector: Arc<dyn EndpointSelector>,
    body_codec: Arc<dyn BodyCodec>,
    clock: Arc<dyn Clock>,
    backoff_source: Arc<dyn BackoffSource>,
    request_limiters: Option<RequestLimiters>,
    metrics: ClientMetrics,
    interceptors: Vec<Arc<dyn Interceptor>>,
    observers: Vec<Arc<dyn Observer>>,
}
