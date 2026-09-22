use std::time::Duration;

use crate::async_client::Client;
use crate::core::config::ClientProfile;
use crate::core::error::{Error, ErrorCode};
use crate::core::policy::StatusPolicy;
use crate::rate_limit::RateLimitPolicy;
use crate::resilience::{AdaptiveConcurrencyPolicy, CircuitBreakerPolicy, RetryBudgetPolicy};
use crate::tls::{TlsBackend, TlsRootStore, TlsVersion};

#[cfg(feature = "async-tls-rustls-ring")]
#[test]
fn selecting_tls_version_for_rustls_ring_builds() {
    let client = Client::builder("https://example.com")
        .tls_backend(TlsBackend::RustlsRing)
        .tls_version(TlsVersion::V1_2)
        .build()
        .expect("rustls ring client should build with explicit tls version");

    assert_eq!(client.tls_backend(), TlsBackend::RustlsRing);
}

#[cfg(feature = "async-tls-rustls-aws-lc-rs")]
#[test]
fn selecting_tls_version_for_rustls_aws_lc_builds() {
    let client = Client::builder("https://example.com")
        .tls_backend(TlsBackend::RustlsAwsLcRs)
        .tls_max_version(TlsVersion::V1_2)
        .build()
        .expect("rustls aws-lc client should build with max tls version");

    assert_eq!(client.tls_backend(), TlsBackend::RustlsAwsLcRs);
}

#[cfg(feature = "async-tls-native")]
#[test]
fn selecting_tls_version_for_native_tls12_builds() {
    let client = Client::builder("https://example.com")
        .tls_backend(TlsBackend::NativeTls)
        .tls_version(TlsVersion::V1_2)
        .build()
        .expect("native tls client should build with explicit tls 1.2");

    assert_eq!(client.tls_backend(), TlsBackend::NativeTls);
}

#[cfg(feature = "async-tls-native")]
#[test]
fn selecting_tls13_bounds_for_native_tls_builds() {
    let client = Client::builder("https://example.com")
        .tls_backend(TlsBackend::NativeTls)
        .tls_min_version(TlsVersion::V1_2)
        .tls_max_version(TlsVersion::V1_3)
        .build()
        .expect("native tls client should build with tls 1.2..=1.3 bounds");

    assert_eq!(client.tls_backend(), TlsBackend::NativeTls);
}

#[test]
fn invalid_tls_root_ca_pem_returns_tls_config_error() {
    let result = Client::builder("https://api.example.com")
        .tls_root_ca_pem("not-a-pem-certificate")
        .build();
    let error = match result {
        Ok(_) => panic!("invalid root ca pem should fail"),
        Err(error) => error,
    };
    match error {
        Error::TlsConfig { .. } => {}
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_invalid_base_url_early() {
    let result = Client::builder("not-a-valid-base-url").build();
    let error = match result {
        Ok(_) => panic!("invalid base url should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "not-a-valid-base-url");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_base_url_with_empty_port_authority() {
    let result = Client::builder("https://api.example.com:/v1").build();
    let error = match result {
        Ok(_) => panic!("base url with empty authority port should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://api.example.com:/v1");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_non_http_base_url_scheme() {
    let result = Client::builder("ftp://api.example.com").build();
    let error = match result {
        Ok(_) => panic!("non-http base url should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "ftp://api.example.com/");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_non_http_proxy_scheme() {
    let proxy_uri: http::Uri = "https://proxy.example.com:8443"
        .parse()
        .expect("proxy uri should parse");
    let result = Client::builder("https://api.example.com")
        .http_proxy(proxy_uri)
        .build();
    let error = match result {
        Ok(_) => panic!("non-http proxy scheme should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidProxyConfig { proxy_uri, message } => {
            assert_eq!(proxy_uri, "https://proxy.example.com:8443/");
            assert!(message.contains("http scheme"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_http_proxy_uri_with_invalid_authority() {
    let proxy_uri: http::Uri = "http://proxy.example.com:invalid"
        .parse()
        .expect("proxy uri should parse");
    let result = Client::builder("https://api.example.com")
        .http_proxy(proxy_uri)
        .build();
    let error = match result {
        Ok(_) => panic!("http_proxy URI with invalid authority should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidProxyConfig { proxy_uri, message } => {
            assert_eq!(proxy_uri, "http://proxy.example.com:invalid/");
            assert!(message.contains("valid authority"));
            assert!(message.contains("numeric port"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_http_proxy_uri_with_empty_port() {
    let proxy_uri: http::Uri = "http://proxy.example.com:/"
        .parse()
        .expect("proxy uri should parse");
    let result = Client::builder("https://api.example.com")
        .http_proxy(proxy_uri)
        .build();
    let error = match result {
        Ok(_) => panic!("http_proxy URI with empty port should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidProxyConfig { proxy_uri, message } => {
            assert_eq!(proxy_uri, "http://proxy.example.com:/");
            assert!(message.contains("valid authority"));
            assert!(message.contains("numeric port"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_http_proxy_uri_with_credentials() {
    let proxy_uri: http::Uri = "http://user:pass@proxy.example.com:8080"
        .parse()
        .expect("proxy uri should parse");
    let result = Client::builder("https://api.example.com")
        .http_proxy(proxy_uri)
        .build();
    let error = match result {
        Ok(_) => panic!("async http_proxy URI with credentials should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidProxyConfig { proxy_uri, message } => {
            assert_eq!(proxy_uri, "http://proxy.example.com:8080/");
            assert!(message.contains("must not include credentials"));
            assert!(message.contains("proxy_authorization"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_proxy_authorization_without_http_proxy() {
    let result = Client::builder("https://api.example.com")
        .try_proxy_authorization("Basic dXNlcjpwYXNz")
        .expect("proxy authorization header should parse")
        .build();
    let error = match result {
        Ok(_) => panic!("proxy authorization without http_proxy should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::ProxyAuthorizationRequiresHttpProxy => {}
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_base_url_with_query() {
    let result = Client::builder("https://api.example.com/v1?token=abc").build();
    let error = match result {
        Ok(_) => panic!("base url with query should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://api.example.com/v1");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_base_url_with_fragment() {
    let result = Client::builder("https://api.example.com/v1#anchor").build();
    let error = match result {
        Ok(_) => panic!("base url with fragment should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://api.example.com/v1");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_base_url_with_userinfo() {
    let result = Client::builder("https://user:pass@api.example.com/v1").build();
    let error = match result {
        Ok(_) => panic!("base url with userinfo should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://api.example.com/v1");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_base_url_with_surrounding_whitespace() {
    let result = Client::builder(" https://api.example.com/v1 ").build();
    let error = match result {
        Ok(_) => panic!("base url with surrounding whitespace should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://api.example.com/v1");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn client_profile_and_direct_builder_overrides_compose() {
    let client = Client::builder("https://api.example.com")
        .profile(ClientProfile::LowLatency)
        .request_timeout(Duration::from_secs(4))
        .total_timeout(Duration::from_secs(9))
        .max_response_body_bytes(16 * 1024)
        .default_status_policy(StatusPolicy::Response)
        .build()
        .expect("client should build with profile and direct overrides");
    assert_eq!(client.default_status_policy(), StatusPolicy::Response);
}

#[test]
fn build_rejects_invalid_adaptive_concurrency_policy() {
    let policy = AdaptiveConcurrencyPolicy::standard()
        .min_limit(10)
        .initial_limit(8)
        .max_limit(5);
    let result = Client::builder("https://api.example.com")
        .adaptive_concurrency_policy(policy)
        .build();
    let error = match result {
        Ok(_) => panic!("invalid adaptive concurrency policy should fail"),
        Err(error) => error,
    };
    match error {
        Error::InvalidAdaptiveConcurrencyPolicy {
            min_limit,
            initial_limit,
            max_limit,
            ..
        } => {
            assert_eq!(min_limit, 10);
            assert_eq!(initial_limit, 8);
            assert_eq!(max_limit, 5);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_invalid_retry_budget_policy() {
    let policy = RetryBudgetPolicy::standard().window(Duration::ZERO);
    let result = Client::builder("https://api.example.com")
        .retry_budget_policy(policy)
        .build();
    let error = match result {
        Ok(_) => panic!("invalid retry budget policy should fail"),
        Err(error) => error,
    };
    match error {
        Error::InvalidRetryBudgetPolicy {
            window_ms,
            retry_ratio,
            min_retries_per_window,
            message,
        } => {
            assert_eq!(window_ms, 0);
            assert_eq!(retry_ratio, 0.2);
            assert_eq!(min_retries_per_window, 3);
            assert_eq!(message, "window must be greater than zero");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_invalid_concurrency_limit_config() {
    let result = Client::builder("https://api.example.com")
        .max_in_flight(0)
        .build();
    let error = match result {
        Ok(_) => panic!("invalid concurrency limit should fail"),
        Err(error) => error,
    };
    match error {
        Error::InvalidConcurrencyLimitConfig {
            max_in_flight,
            max_in_flight_per_host,
            message,
        } => {
            assert_eq!(max_in_flight, Some(0));
            assert_eq!(max_in_flight_per_host, None);
            assert_eq!(message, "max_in_flight must be greater than zero");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_empty_client_name() {
    let result = Client::builder("https://api.example.com")
        .client_name("   ")
        .build();
    let error = match result {
        Ok(_) => panic!("empty client name should fail"),
        Err(error) => error,
    };
    match error {
        Error::InvalidClientNameConfig {
            client_name_len,
            message,
        } => {
            assert_eq!(client_name_len, 3);
            assert_eq!(message, "client_name must not be empty");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_client_name_that_is_not_a_header_value() {
    let result = Client::builder("https://api.example.com")
        .client_name("bad\r\nuser-agent")
        .build();
    let error = match result {
        Ok(_) => panic!("invalid client name should fail"),
        Err(error) => error,
    };
    match error {
        Error::InvalidClientNameConfig {
            client_name_len,
            message,
        } => {
            assert_eq!(client_name_len, "bad\r\nuser-agent".len());
            assert_eq!(message, "client_name must be a valid HTTP header value");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_invalid_circuit_breaker_policy() {
    let policy = CircuitBreakerPolicy::standard().open_timeout(Duration::ZERO);
    let result = Client::builder("https://api.example.com")
        .circuit_breaker_policy(policy)
        .build();
    let error = match result {
        Ok(_) => panic!("invalid circuit breaker policy should fail"),
        Err(error) => error,
    };
    match error {
        Error::InvalidCircuitBreakerPolicy {
            failure_threshold,
            open_timeout_ms,
            half_open_max_requests,
            half_open_success_threshold,
            ..
        } => {
            assert_eq!(failure_threshold, 5);
            assert_eq!(open_timeout_ms, 0);
            assert_eq!(half_open_max_requests, 2);
            assert_eq!(half_open_success_threshold, 2);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_invalid_global_rate_limit_policy() {
    let policy = RateLimitPolicy::standard().requests_per_second(0.0);
    let result = Client::builder("https://api.example.com")
        .global_rate_limit_policy(policy)
        .build();
    let error = match result {
        Ok(_) => panic!("invalid global rate limit policy should fail"),
        Err(error) => error,
    };
    match error {
        Error::InvalidRateLimitPolicy {
            requests_per_second,
            burst,
            ..
        } => {
            assert_eq!(requests_per_second, 0.0);
            assert_eq!(burst, 50);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_invalid_per_host_rate_limit_policy() {
    let policy = RateLimitPolicy::standard().burst(0);
    let result = Client::builder("https://api.example.com")
        .per_host_rate_limit_policy(policy)
        .build();
    let error = match result {
        Ok(_) => panic!("invalid per-host rate limit policy should fail"),
        Err(error) => error,
    };
    match error {
        Error::InvalidRateLimitPolicy {
            requests_per_second,
            burst,
            ..
        } => {
            assert_eq!(requests_per_second, 50.0);
            assert_eq!(burst, 0);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn tls_root_store_specific_without_roots_returns_tls_config_error() {
    let result = Client::builder("https://api.example.com")
        .tls_root_store(TlsRootStore::Specific)
        .build();
    let error = match result {
        Ok(_) => panic!("specific root store without roots should fail"),
        Err(error) => error,
    };
    match error {
        Error::TlsConfig { message, .. } => {
            assert!(message.contains("TlsRootStore::Specific"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn custom_root_ca_requires_explicit_root_store() {
    let result = Client::builder("https://api.example.com")
        .tls_root_ca_der([1_u8, 2, 3, 4])
        .build();
    let error = match result {
        Ok(_) => panic!("custom root ca should require an explicit root store"),
        Err(error) => error,
    };
    match error {
        Error::TlsConfig { message, .. } => {
            assert!(message.contains("TlsRootStore::WebPki"));
            assert!(message.contains("TlsRootStore::System"));
            assert!(message.contains("TlsRootStore::Specific"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
#[test]
fn async_rustls_root_ca_pem_rejects_non_certificate_blocks() {
    #[cfg(feature = "async-tls-rustls-ring")]
    let backend = TlsBackend::RustlsRing;
    #[cfg(all(
        not(feature = "async-tls-rustls-ring"),
        feature = "async-tls-rustls-aws-lc-rs"
    ))]
    let backend = TlsBackend::RustlsAwsLcRs;

    let result = Client::builder("https://api.example.com")
        .tls_backend(backend)
        .tls_root_store(TlsRootStore::WebPki)
        .tls_root_ca_pem(
            b"-----BEGIN PRIVATE KEY-----\nAQIDBA==\n-----END PRIVATE KEY-----\n".to_vec(),
        )
        .build();

    let error = match result {
        Ok(_) => panic!("root CA PEM should reject non-certificate PEM blocks"),
        Err(error) => error,
    };
    match error {
        Error::TlsConfig { message, .. } => {
            assert!(message.contains("non-certificate block"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn rustls_backend_rejects_pkcs12_identity_configuration() {
    #[cfg(feature = "async-tls-rustls-ring")]
    let backend = Some(TlsBackend::RustlsRing);
    #[cfg(all(
        not(feature = "async-tls-rustls-ring"),
        feature = "async-tls-rustls-aws-lc-rs"
    ))]
    let backend = Some(TlsBackend::RustlsAwsLcRs);
    #[cfg(all(
        not(feature = "async-tls-rustls-ring"),
        not(feature = "async-tls-rustls-aws-lc-rs")
    ))]
    let backend: Option<TlsBackend> = None;

    let Some(backend) = backend else {
        return;
    };

    let result = Client::builder("https://api.example.com")
        .tls_backend(backend)
        .tls_client_identity_pkcs12(vec![0x30, 0x82], "secret")
        .build();
    let error = match result {
        Ok(_) => panic!("rustls should reject pkcs12 identity"),
        Err(error) => error,
    };

    match error {
        Error::TlsConfig { message, .. } => {
            assert!(message.contains("PKCS#12 identity"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "async-tls-native")]
#[test]
fn native_tls_invalid_pkcs12_identity_returns_tls_config_error() {
    let result = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .tls_client_identity_pkcs12(vec![1, 2, 3, 4], "secret")
        .build();
    let error = match result {
        Ok(_) => panic!("invalid native tls identity should fail"),
        Err(error) => error,
    };
    match error {
        Error::TlsConfig { .. } => {}
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "async-tls-native")]
#[test]
fn native_tls_webpki_root_store_is_rejected() {
    let result = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .tls_root_store(TlsRootStore::WebPki)
        .build();
    let error = match result {
        Ok(_) => panic!("native tls should reject webpki root store"),
        Err(error) => error,
    };
    match error {
        Error::TlsConfig { message, .. } => {
            assert!(message.contains("TlsRootStore::WebPki"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn try_add_no_proxy_rejects_invalid_rule() {
    let result = Client::builder("https://api.example.com").try_add_no_proxy("[::1]not-a-port");
    let error = match result {
        Ok(_) => panic!("invalid no_proxy rule should fail"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
    match error {
        Error::InvalidNoProxyRule { rule } => assert_eq!(rule, "[::1]not-a-port"),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn try_no_proxy_rejects_url_rule_with_path() {
    let result =
        Client::builder("https://api.example.com").try_no_proxy(["https://api.example.com/v1"]);
    let error = match result {
        Ok(_) => panic!("url-shaped no_proxy rule with path should fail"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
    match error {
        Error::InvalidNoProxyRule { rule } => assert_eq!(rule, "https://api.example.com/v1"),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn try_no_proxy_redacts_sensitive_url_shaped_rule() {
    let result = Client::builder("https://api.example.com")
        .try_no_proxy(["https://user:pass@api.example.com/v1?token=secret"]);
    let error = match result {
        Ok(_) => panic!("sensitive invalid no_proxy rule should fail"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
    match error {
        Error::InvalidNoProxyRule { rule } => assert_eq!(rule, "https://api.example.com/v1"),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn try_no_proxy_rejects_url_rule_with_non_http_scheme() {
    let result = Client::builder("https://api.example.com").try_no_proxy(["ftp://api.example.com"]);
    let error = match result {
        Ok(_) => panic!("url-shaped no_proxy rule with non-http scheme should fail"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
    match error {
        Error::InvalidNoProxyRule { rule } => assert_eq!(rule, "ftp://api.example.com"),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn try_no_proxy_rejects_malformed_http_url_shape() {
    let result = Client::builder("https://api.example.com").try_no_proxy(["http:/api.example.com"]);
    let error = match result {
        Ok(_) => panic!("malformed http no_proxy rule should fail"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
    match error {
        Error::InvalidNoProxyRule { rule } => assert_eq!(rule, "http:/api.example.com"),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn try_no_proxy_rejects_url_rule_with_invalid_authority() {
    let result = Client::builder("https://api.example.com")
        .try_no_proxy(["https://api.example.com:invalid"]);
    let error = match result {
        Ok(_) => panic!("url-shaped no_proxy rule with invalid authority should fail"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
    match error {
        Error::InvalidNoProxyRule { rule } => assert_eq!(rule, "https://api.example.com:invalid"),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn try_no_proxy_rejects_url_rule_with_empty_port() {
    let result =
        Client::builder("https://api.example.com").try_no_proxy(["https://api.example.com:/"]);
    let error = match result {
        Ok(_) => panic!("url-shaped no_proxy rule with empty port should fail"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
    match error {
        Error::InvalidNoProxyRule { rule } => assert_eq!(rule, "https://api.example.com:/"),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn try_no_proxy_rejects_invalid_rule() {
    let result =
        Client::builder("https://api.example.com").try_no_proxy(["example.com", "[::1]not-a-port"]);
    let error = match result {
        Ok(_) => panic!("invalid no_proxy rule should fail"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
}

#[test]
fn try_no_proxy_rejects_non_numeric_port_suffix() {
    let result = Client::builder("https://api.example.com").try_no_proxy(["example.com:abc"]);
    let error = match result {
        Ok(_) => panic!("invalid no_proxy rule should fail"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
}

#[test]
fn no_proxy_records_invalid_rule_and_build_fails() {
    let result = Client::builder("https://api.example.com")
        .no_proxy(["example.com", "[::1]not-a-port"])
        .build();
    let error = match result {
        Ok(_) => panic!("invalid no_proxy rule should fail at build time"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
}

#[test]
fn no_proxy_build_error_redacts_sensitive_url_shaped_rule() {
    let result = Client::builder("https://api.example.com")
        .no_proxy(["https://user:pass@api.example.com/v1?token=secret"])
        .build();
    let error = match result {
        Ok(_) => panic!("sensitive invalid no_proxy rule should fail at build time"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
    match error {
        Error::InvalidNoProxyRule { rule } => assert_eq!(rule, "https://api.example.com/v1"),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[cfg(not(feature = "otel"))]
#[test]
fn async_builder_rejects_otel_when_feature_is_unavailable() {
    let result = Client::builder("https://api.example.com")
        .otel_enabled(true)
        .build();
    let error = match result {
        Ok(_) => panic!("OpenTelemetry should require the otel feature"),
        Err(error) => error,
    };

    match error {
        Error::FeatureUnavailable {
            feature,
            capability,
        } => {
            assert_eq!(feature, "otel");
            assert_eq!(capability, "OpenTelemetry observer emission");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "otel")]
#[test]
fn async_builder_accepts_otel_when_feature_is_available() {
    Client::builder("https://api.example.com")
        .otel_enabled(true)
        .build()
        .expect("OpenTelemetry should be available with the otel feature");
}

#[cfg(feature = "async-tls-rustls-ring")]
#[test]
fn selecting_rustls_ring_backend_builds_when_feature_enabled() {
    let client = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsRing)
        .build()
        .expect("rustls ring backend should build when feature is enabled");
    assert_eq!(client.tls_backend(), TlsBackend::RustlsRing);
}

#[cfg(not(feature = "async-tls-rustls-ring"))]
#[test]
fn selecting_rustls_ring_backend_returns_unavailable_when_feature_disabled() {
    let result = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsRing)
        .build();
    let error = match result {
        Ok(_) => panic!("rustls ring backend should be unavailable when feature is disabled"),
        Err(error) => error,
    };
    match error {
        Error::TlsBackendUnavailable { backend } => {
            assert_eq!(backend, TlsBackend::RustlsRing.as_str());
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "async-tls-rustls-aws-lc-rs")]
#[test]
fn selecting_rustls_aws_lc_backend_builds_when_feature_enabled() {
    let client = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsAwsLcRs)
        .build()
        .expect("rustls aws-lc-rs backend should build when feature is enabled");
    assert_eq!(client.tls_backend(), TlsBackend::RustlsAwsLcRs);
}

#[cfg(not(feature = "async-tls-rustls-aws-lc-rs"))]
#[test]
fn selecting_rustls_aws_lc_backend_returns_unavailable_when_feature_disabled() {
    let result = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsAwsLcRs)
        .build();
    let error = match result {
        Ok(_) => panic!("rustls aws-lc-rs backend should be unavailable when feature is disabled"),
        Err(error) => error,
    };
    match error {
        Error::TlsBackendUnavailable { backend } => {
            assert_eq!(backend, TlsBackend::RustlsAwsLcRs.as_str());
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "async-tls-native")]
#[test]
fn selecting_native_tls_backend_builds_when_feature_enabled() {
    let client = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .build()
        .expect("native tls backend should build when feature is enabled");
    assert_eq!(client.tls_backend(), TlsBackend::NativeTls);
}

#[cfg(not(feature = "async-tls-native"))]
#[test]
fn selecting_native_tls_backend_returns_unavailable_when_feature_disabled() {
    let result = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .build();
    let error = match result {
        Ok(_) => panic!("native tls backend should be unavailable when feature is disabled"),
        Err(error) => error,
    };
    match error {
        Error::TlsBackendUnavailable { backend } => {
            assert_eq!(backend, TlsBackend::NativeTls.as_str());
        }
        other => panic!("unexpected error: {other}"),
    }
}
