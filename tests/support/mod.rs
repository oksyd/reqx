// Shared setup for tests that require a working default client.
// Missing-provider behavior is tested in a separate integration test process.
#[cfg(any(feature = "_async", feature = "_blocking"))]
#[allow(dead_code)]
pub fn configure_then_disable_controls<T>(
    builder: reqx::ClientBuilder<T>,
) -> reqx::ClientBuilder<T> {
    use reqx::advanced::{
        AdaptiveConcurrencyPolicy, BackoffSource, CircuitBreakerPolicy, RateLimitPolicy,
        RetryBudgetPolicy, RoundRobinEndpointSelector,
    };

    struct LongBackoff;
    impl BackoffSource for LongBackoff {
        fn backoff_for_retry(
            &self,
            _policy: &reqx::prelude::RetryPolicy,
            _attempt: usize,
        ) -> std::time::Duration {
            std::time::Duration::from_secs(60)
        }
    }

    builder
        .endpoint_selector(Some(std::sync::Arc::new(
            RoundRobinEndpointSelector::new(["http://192.0.2.1"]).expect("valid unused endpoint"),
        )))
        .endpoint_selector(None)
        .backoff_source(Some(std::sync::Arc::new(LongBackoff)))
        .backoff_source(None)
        .max_in_flight(Some(0))
        .max_in_flight(None)
        .max_in_flight_per_host(Some(0))
        .max_in_flight_per_host(None)
        .retry_budget_policy(Some(
            RetryBudgetPolicy::standard()
                .retry_ratio(0.0)
                .min_retries_per_window(0),
        ))
        .retry_budget_policy(None)
        .circuit_breaker_policy(Some(CircuitBreakerPolicy::standard().failure_threshold(1)))
        .circuit_breaker_policy(None)
        .adaptive_concurrency_policy(Some(
            AdaptiveConcurrencyPolicy::standard()
                .initial_limit(1)
                .max_limit(1),
        ))
        .adaptive_concurrency_policy(None)
        .global_rate_limit_policy(Some(
            RateLimitPolicy::standard()
                .requests_per_second(0.001)
                .burst(1),
        ))
        .global_rate_limit_policy(None)
        .per_host_rate_limit_policy(Some(
            RateLimitPolicy::standard()
                .requests_per_second(0.001)
                .burst(1),
        ))
        .per_host_rate_limit_policy(None)
}

#[allow(dead_code)]
pub fn install_crypto_provider() {
    #[cfg(any(
        feature = "async-tls-rustls-no-provider",
        feature = "blocking-tls-rustls-no-provider"
    ))]
    {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            rustls_graviola::default_provider()
                .install_default()
                .expect("install test crypto provider before building clients");
        });
    }
}
