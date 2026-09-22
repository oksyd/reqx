use std::collections::BTreeSet;
use std::fmt;

use crate::core::error::{Error, ErrorCode, TransportErrorKind, transport_error};

#[test]
fn error_code_maps_expected_variant() {
    let error = Error::InvalidUri {
        uri: "bad://uri".to_owned(),
    };
    assert_eq!(error.code(), ErrorCode::InvalidUri);
    assert_eq!(error.code().as_str(), "invalid_uri");
}

#[test]
fn error_display_redacts_query_from_request_uri() {
    let error = transport_error(
        TransportErrorKind::Connect,
        http::Method::GET,
        crate::core::util::redact_uri_for_logs("https://api.example.com/v1/items?token=secret"),
        std::io::Error::other("connect failed"),
    );

    let display = error.to_string();
    let debug = format!("{error:?}");
    assert!(!display.contains("token=secret"));
    assert!(!debug.contains("token=secret"));
    assert!(display.contains("/v1/items"));
}

#[test]
fn transport_error_display_redacts_uri_like_source_messages() {
    let source = TestNestedError::with_source(
        "connect failed for https://user:pass@api.example.com/v1/items?token=secret#frag",
        TestNestedError::new(
            "proxy handshake failed via http://proxy-user:proxy-pass@proxy.example.com:badport/tunnel?secret=1",
        ),
    );
    let error = transport_error(
        TransportErrorKind::Connect,
        http::Method::GET,
        "https://api.example.com/v1/items".to_owned(),
        source,
    );

    let display = error.to_string();
    let debug = format!("{error:?}");
    for rendered in [display, debug] {
        assert!(!rendered.contains("user:pass"));
        assert!(!rendered.contains("proxy-user:proxy-pass"));
        assert!(!rendered.contains("token=secret"));
        assert!(!rendered.contains("secret=1"));
        assert!(rendered.contains("https://api.example.com/v1/items"));
        assert!(rendered.contains("http://proxy.example.com:badport/tunnel"));
    }
}

#[derive(Debug)]
struct TestNestedError {
    message: &'static str,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl TestNestedError {
    fn new(message: &'static str) -> Self {
        Self {
            message,
            source: None,
        }
    }

    fn with_source(
        message: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message,
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for TestNestedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for TestNestedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

#[test]
fn transport_error_display_includes_nested_source_chain() {
    let source = TestNestedError::with_source(
        "client error (Connect)",
        TestNestedError::new("received fatal alert: ProtocolVersion"),
    );
    let error = transport_error(
        TransportErrorKind::Other,
        http::Method::POST,
        "https://example.com/v1/login".to_owned(),
        source,
    );

    let display = error.to_string();
    assert!(display.contains("client error (Connect)"));
    assert!(display.contains("received fatal alert: ProtocolVersion"));
}

#[test]
fn error_safe_request_accessors_return_method_uri_and_path() {
    let error = Error::HttpStatus {
        status: 404,
        method: http::Method::POST,
        uri: "https://api.example.com/v1/items".to_owned(),
        headers: Box::new(http::HeaderMap::new()),
        body: String::new(),
    };

    assert_eq!(
        error.request_method().map(http::Method::as_str),
        Some("POST")
    );
    assert_eq!(
        error.request_uri_redacted(),
        Some("https://api.example.com/v1/items")
    );
    assert_eq!(
        error.request_uri_redacted_owned().as_deref(),
        Some("https://api.example.com/v1/items")
    );
    assert_eq!(error.request_path().as_deref(), Some("/v1/items"));
}

#[test]
fn error_code_contract_table_is_stable() {
    let codes = ErrorCode::all();
    assert_eq!(codes.len(), 39);

    let names: Vec<&str> = codes.iter().map(|code| code.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "invalid_uri",
            "invalid_no_proxy_rule",
            "invalid_dns_override_config",
            "invalid_proxy_config",
            "invalid_timeout_config",
            "invalid_client_name_config",
            "invalid_concurrency_limit_config",
            "invalid_retry_policy",
            "invalid_retry_budget_policy",
            "invalid_adaptive_concurrency_policy",
            "invalid_circuit_breaker_policy",
            "invalid_rate_limit_policy",
            "serialize_json",
            "serialize_query",
            "serialize_form",
            "request_build",
            "transport",
            "timeout",
            "deadline_exceeded",
            "read_body",
            "write_body",
            "response_body_too_large",
            "http_status",
            "deserialize_json",
            "decode_text",
            "invalid_header_name",
            "invalid_header_value",
            "decode_content_encoding",
            "concurrency_limit_closed",
            "tls_backend_unavailable",
            "tls_backend_init",
            "tls_config",
            "retry_budget_exhausted",
            "circuit_open",
            "missing_redirect_location",
            "invalid_redirect_location",
            "redirect_limit_exceeded",
            "redirect_body_not_replayable",
            "feature_unavailable",
        ]
    );

    let unique: BTreeSet<&str> = names.iter().copied().collect();
    assert_eq!(unique.len(), names.len());
}

#[test]
fn error_code_maps_feature_unavailable_variant() {
    let error = Error::FeatureUnavailable {
        feature: "otel",
        capability: "OpenTelemetry observer emission",
    };
    assert_eq!(error.code(), ErrorCode::FeatureUnavailable);
    assert_eq!(error.code().as_str(), "feature_unavailable");
}

#[test]
fn error_code_maps_tls_config_variant() {
    let error = Error::TlsConfig {
        backend: "native-tls",
        message: "bad cert".to_owned(),
    };
    assert_eq!(error.code(), ErrorCode::TlsConfig);
    assert_eq!(error.code().as_str(), "tls_config");
}

#[test]
fn error_code_maps_invalid_proxy_config_variant() {
    let error = Error::InvalidProxyConfig {
        proxy_uri: "http://proxy.example.com:8080".to_owned(),
        message: "bad proxy configuration".to_owned(),
    };
    assert_eq!(error.code(), ErrorCode::InvalidProxyConfig);
    assert_eq!(error.code().as_str(), "invalid_proxy_config");
}

#[test]
fn error_code_maps_proxy_authorization_requires_http_proxy_variant() {
    let error = Error::ProxyAuthorizationRequiresHttpProxy;
    assert_eq!(error.code(), ErrorCode::InvalidProxyConfig);
    assert_eq!(error.code().as_str(), "invalid_proxy_config");
}

#[test]
fn error_code_maps_invalid_timeout_config_variant() {
    let error = Error::InvalidTimeoutConfig {
        request_timeout_ms: 0,
        total_timeout_ms: Some(10),
        connect_timeout_ms: Some(5),
        message: "request_timeout must be greater than zero",
    };
    assert_eq!(error.code(), ErrorCode::InvalidTimeoutConfig);
    assert_eq!(error.code().as_str(), "invalid_timeout_config");
}

#[test]
fn error_code_maps_invalid_client_name_config_variant() {
    let error = Error::InvalidClientNameConfig {
        client_name_len: 4,
        message: "client_name must be a valid HTTP header value",
    };
    assert_eq!(error.code(), ErrorCode::InvalidClientNameConfig);
    assert_eq!(error.code().as_str(), "invalid_client_name_config");
}

#[test]
fn error_code_maps_invalid_concurrency_limit_config_variant() {
    let error = Error::InvalidConcurrencyLimitConfig {
        max_in_flight: Some(0),
        max_in_flight_per_host: Some(8),
        message: "max_in_flight must be greater than zero",
    };
    assert_eq!(error.code(), ErrorCode::InvalidConcurrencyLimitConfig);
    assert_eq!(error.code().as_str(), "invalid_concurrency_limit_config");
}

#[test]
fn error_code_maps_invalid_retry_policy_variant() {
    let error = Error::InvalidRetryPolicy {
        max_attempts: 0,
        base_backoff_ms: 1,
        max_backoff_ms: 100,
        jitter_ratio: 0.0,
        message: "max_attempts must be greater than zero",
    };
    assert_eq!(error.code(), ErrorCode::InvalidRetryPolicy);
    assert_eq!(error.code().as_str(), "invalid_retry_policy");
}

#[test]
fn error_code_maps_invalid_retry_budget_policy_variant() {
    let error = Error::InvalidRetryBudgetPolicy {
        window_ms: 0,
        retry_ratio: f64::NAN,
        min_retries_per_window: 3,
        message: "retry_ratio must be finite and between 0.0 and 1.0",
    };
    assert_eq!(error.code(), ErrorCode::InvalidRetryBudgetPolicy);
    assert_eq!(error.code().as_str(), "invalid_retry_budget_policy");
}

#[test]
fn error_code_maps_invalid_adaptive_concurrency_policy_variant() {
    let error = Error::InvalidAdaptiveConcurrencyPolicy {
        min_limit: 10,
        initial_limit: 8,
        max_limit: 5,
        message: "min_limit must be <= max_limit",
    };
    assert_eq!(error.code(), ErrorCode::InvalidAdaptiveConcurrencyPolicy);
    assert_eq!(error.code().as_str(), "invalid_adaptive_concurrency_policy");
}

#[test]
fn error_code_maps_invalid_circuit_breaker_policy_variant() {
    let error = Error::InvalidCircuitBreakerPolicy {
        failure_threshold: 0,
        open_timeout_ms: 0,
        half_open_max_requests: 1,
        half_open_success_threshold: 1,
        message: "failure_threshold must be >= 1",
    };
    assert_eq!(error.code(), ErrorCode::InvalidCircuitBreakerPolicy);
    assert_eq!(error.code().as_str(), "invalid_circuit_breaker_policy");
}

#[test]
fn error_code_maps_invalid_rate_limit_policy_variant() {
    let error = Error::InvalidRateLimitPolicy {
        requests_per_second: 0.0,
        burst: 1,
        message: "requests_per_second must be finite and > 0",
    };
    assert_eq!(error.code(), ErrorCode::InvalidRateLimitPolicy);
    assert_eq!(error.code().as_str(), "invalid_rate_limit_policy");
}

#[test]
fn error_code_maps_redirect_limit_exceeded_variant() {
    let error = Error::RedirectLimitExceeded {
        max_redirects: 3,
        method: http::Method::GET,
        uri: "https://example.com/a".to_owned(),
    };
    assert_eq!(error.code(), ErrorCode::RedirectLimitExceeded);
    assert_eq!(error.code().as_str(), "redirect_limit_exceeded");
}

#[test]
fn error_code_maps_retry_budget_exhausted_variant() {
    let error = Error::RetryBudgetExhausted {
        method: http::Method::GET,
        uri: "https://example.com/retry-budget".to_owned(),
    };
    assert_eq!(error.code(), ErrorCode::RetryBudgetExhausted);
    assert_eq!(error.code().as_str(), "retry_budget_exhausted");
}

#[test]
fn error_code_maps_circuit_open_variant() {
    let error = Error::CircuitOpen {
        method: http::Method::GET,
        uri: "https://example.com/circuit".to_owned(),
        retry_after_ms: 1000,
    };
    assert_eq!(error.code(), ErrorCode::CircuitOpen);
    assert_eq!(error.code().as_str(), "circuit_open");
}

#[test]
fn write_body_error_accessors_expose_request_context() {
    let error = Error::WriteBody {
        method: http::Method::GET,
        uri: "https://api.example.com/v1/download".to_owned(),
        source: Box::new(std::io::Error::other("writer failed")),
    };

    assert_eq!(error.code(), ErrorCode::WriteBody);
    assert_eq!(
        error.request_method().map(http::Method::as_str),
        Some("GET")
    );
    assert_eq!(
        error.request_uri_redacted(),
        Some("https://api.example.com/v1/download")
    );
    assert_eq!(error.request_path().as_deref(), Some("/v1/download"));
}

#[test]
fn read_and_write_body_error_display_omit_source_messages() {
    let read_error = Error::ReadBody {
        source: Box::new(std::io::Error::other(
            "upstream leaked https://api.example.com/v1?token=secret",
        )),
    };
    let write_error = Error::WriteBody {
        method: http::Method::GET,
        uri: "https://api.example.com/v1/download".to_owned(),
        source: Box::new(std::io::Error::other(
            "sink leaked https://api.example.com/v1?token=secret",
        )),
    };

    let read_display = read_error.to_string();
    let read_debug = format!("{read_error:?}");
    let write_display = write_error.to_string();
    let write_debug = format!("{write_error:?}");

    assert!(!read_display.contains("token=secret"));
    assert!(!read_debug.contains("token=secret"));
    assert!(!write_display.contains("token=secret"));
    assert!(!write_debug.contains("token=secret"));
    assert!(!read_display.contains("upstream leaked"));
    assert!(!write_display.contains("sink leaked"));
}
