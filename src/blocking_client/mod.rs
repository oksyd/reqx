use std::io::Read;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use http::HeaderMap;

use crate::core::extensions::{BackoffSource, Clock, EndpointSelector};
use crate::core::metrics::ClientMetrics;
use crate::core::observe::Observer;
use crate::core::policy::Interceptor;
use crate::core::proxy::ProxyConfig;
use crate::core::request_builder::RequestExecutionOptions;
use crate::core::retry::RetryEligibility;
use crate::core::util::lock_unpoisoned;
use crate::rate_limit::{RateLimiter, ServerThrottleScope};
use crate::resilience::{
    AdaptiveConcurrencyOutcome, AdaptiveConcurrencyPolicy, AdaptiveConcurrencyState,
    CircuitBreaker, RetryBudget,
};
use crate::tls::TlsBackend;

pub(crate) mod builder;
mod dns;
mod execute;
pub(crate) mod limiters;
mod request;
pub(crate) mod transport;
use crate::blocking_client::limiters::RequestLimiters;
pub use builder::ClientBuilder;
pub use request::RequestBuilder;

struct AdaptiveConcurrencyController {
    policy: AdaptiveConcurrencyPolicy,
    state: Mutex<AdaptiveConcurrencyState>,
    clock: Arc<dyn Clock>,
    condvar: Condvar,
}

impl AdaptiveConcurrencyController {
    fn new(policy: AdaptiveConcurrencyPolicy, clock: Arc<dyn Clock>) -> Self {
        Self {
            policy,
            state: Mutex::new(AdaptiveConcurrencyState::new(policy)),
            clock,
            condvar: Condvar::new(),
        }
    }

    fn acquire(
        self: &Arc<Self>,
        deadline_at: Option<Instant>,
    ) -> Option<AdaptiveConcurrencyPermit> {
        let mut state = lock_unpoisoned(&self.state);
        while !state.try_acquire() {
            state = match deadline_at {
                Some(deadline_at) => {
                    let now = Instant::now();
                    if now >= deadline_at {
                        return None;
                    }
                    let wait_for = deadline_at.duration_since(now);
                    let (next_state, wait_result) = match self.condvar.wait_timeout(state, wait_for)
                    {
                        Ok(result) => result,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    if wait_result.timed_out() && Instant::now() >= deadline_at {
                        return None;
                    }
                    next_state
                }
                None => match self.condvar.wait(state) {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                },
            };
        }
        drop(state);
        Some(AdaptiveConcurrencyPermit {
            controller: Arc::clone(self),
            started_at: self.clock.now_monotonic(),
            completed: false,
        })
    }

    fn release_and_record(&self, outcome: AdaptiveConcurrencyOutcome, latency: Duration) {
        let mut state = lock_unpoisoned(&self.state);
        state.release_and_record(self.policy, outcome, latency);
        self.condvar.notify_all();
    }

    fn release_without_record(&self) {
        let mut state = lock_unpoisoned(&self.state);
        state.release_without_record();
        self.condvar.notify_all();
    }
}

struct AdaptiveConcurrencyPermit {
    controller: Arc<AdaptiveConcurrencyController>,
    started_at: Instant,
    completed: bool,
}

impl AdaptiveConcurrencyPermit {
    fn latency(&self) -> Duration {
        self.controller
            .clock
            .now_monotonic()
            .saturating_duration_since(self.started_at)
    }
}

impl crate::core::execution::AttemptOutcome for AdaptiveConcurrencyPermit {
    fn mark_success(mut self) {
        self.controller
            .release_and_record(AdaptiveConcurrencyOutcome::Success, self.latency());
        self.completed = true;
    }

    fn mark_failure(mut self) {
        self.controller
            .release_and_record(AdaptiveConcurrencyOutcome::Failure, self.latency());
        self.completed = true;
    }

    fn cancel(mut self) {
        self.controller.release_without_record();
        self.completed = true;
    }
}

impl Drop for AdaptiveConcurrencyPermit {
    fn drop(&mut self) {
        if !self.completed {
            self.controller.release_without_record();
        }
    }
}

type RequestBody = crate::core::request_body::RequestBody<Box<dyn Read + Send>>;

#[derive(Clone)]
/// Reusable blocking HTTP client for SDK transports.
///
/// Cloning a client is cheap and shares its connection pool, configuration,
/// metrics and concurrency/resilience controls. Reuse a client across threads.
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
    tls_backend: TlsBackend,
    transport: transport::TransportAgents,
    proxy_config: Option<ProxyConfig>,
    endpoint_selector: Option<Arc<dyn EndpointSelector>>,
    clock: Arc<dyn Clock>,
    backoff_source: Option<Arc<dyn BackoffSource>>,
    connect_timeout: Duration,
    request_limiters: Option<RequestLimiters>,
    metrics: ClientMetrics,
    interceptors: Vec<Arc<dyn Interceptor>>,
    observers: Vec<Arc<dyn Observer>>,
}
