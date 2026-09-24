use std::time::Duration;

use super::request_supports_retry;

use crate::core::error::{TimeoutPhase, TransportErrorKind};
use crate::core::retry::{RetryDecision, RetryPolicy, RetryReason};

#[test]
fn retry_policy_backoff_is_capped() {
    let retry_policy = RetryPolicy::standard()
        .base_backoff(Duration::from_millis(100))
        .max_backoff(Duration::from_millis(250))
        .jitter_ratio(0.0);
    assert_eq!(
        retry_policy.backoff_for_retry(1),
        Duration::from_millis(100)
    );
    assert_eq!(
        retry_policy.backoff_for_retry(2),
        Duration::from_millis(200)
    );
    assert_eq!(
        retry_policy.backoff_for_retry(3),
        Duration::from_millis(250)
    );
}

#[test]
fn retry_policy_backoff_preserves_sub_millisecond_durations() {
    let retry_policy = RetryPolicy::standard()
        .base_backoff(Duration::from_micros(500))
        .max_backoff(Duration::from_micros(900))
        .jitter_ratio(0.0);

    assert_eq!(
        retry_policy.backoff_for_retry(1),
        Duration::from_micros(500)
    );
    assert_eq!(
        retry_policy.backoff_for_retry(2),
        Duration::from_micros(900)
    );
}

#[test]
fn retry_policy_can_filter_transport_error_kinds() {
    let retry_policy =
        RetryPolicy::standard().retryable_transport_error_kinds([TransportErrorKind::Connect]);
    let connect_decision = RetryDecision::new(
        1,
        3,
        http::Method::GET,
        "https://example.com".to_owned(),
        RetryReason::Transport(TransportErrorKind::Connect),
    );
    let dns_decision = RetryDecision::new(
        1,
        3,
        http::Method::GET,
        "https://example.com".to_owned(),
        RetryReason::Transport(TransportErrorKind::Dns),
    );

    assert!(retry_policy.should_retry_decision(&connect_decision));
    assert!(!retry_policy.should_retry_decision(&dns_decision));
}

#[test]
fn retry_policy_standard_skips_tls_and_other_transport_errors() {
    let retry_policy = RetryPolicy::standard();
    let tls_decision = RetryDecision::new(
        1,
        3,
        http::Method::GET,
        "https://example.com/tls".to_owned(),
        RetryReason::Transport(TransportErrorKind::Tls),
    );
    let other_decision = RetryDecision::new(
        1,
        3,
        http::Method::GET,
        "https://example.com/tls".to_owned(),
        RetryReason::Transport(TransportErrorKind::Other),
    );

    assert!(!retry_policy.should_retry_decision(&tls_decision));
    assert!(!retry_policy.should_retry_decision(&other_decision));
}

#[test]
fn retry_policy_status_retry_window_caps_followup_attempts() {
    let retry_policy = RetryPolicy::standard()
        .retryable_status_codes([429_u16, 503_u16])
        .status_retry_window(429, 2);
    let first_429 = RetryDecision::new(
        1,
        5,
        http::Method::GET,
        "https://example.com/rate".to_owned(),
        RetryReason::Status(http::StatusCode::TOO_MANY_REQUESTS),
    );
    let second_429 = RetryDecision::new(
        2,
        5,
        http::Method::GET,
        "https://example.com/rate".to_owned(),
        RetryReason::Status(http::StatusCode::TOO_MANY_REQUESTS),
    );
    let third_503 = RetryDecision::new(
        3,
        5,
        http::Method::GET,
        "https://example.com/rate".to_owned(),
        RetryReason::Status(http::StatusCode::SERVICE_UNAVAILABLE),
    );

    assert!(retry_policy.should_retry_decision(&first_429));
    assert!(!retry_policy.should_retry_decision(&second_429));
    assert!(retry_policy.should_retry_decision(&third_503));
}

#[test]
fn retry_policy_timeout_and_read_body_windows_are_configurable() {
    let retry_policy = RetryPolicy::standard()
        .retryable_timeout_phases([TimeoutPhase::Transport])
        .timeout_retry_window(TimeoutPhase::Transport, 2)
        .response_body_read_retry_window(2);
    let transport_timeout_first = RetryDecision::new(
        1,
        5,
        http::Method::GET,
        "https://example.com/timeout".to_owned(),
        RetryReason::Timeout(TimeoutPhase::Transport),
    );
    let transport_timeout_second = RetryDecision::new(
        2,
        5,
        http::Method::GET,
        "https://example.com/timeout".to_owned(),
        RetryReason::Timeout(TimeoutPhase::Transport),
    );
    let response_timeout = RetryDecision::new(
        1,
        5,
        http::Method::GET,
        "https://example.com/timeout".to_owned(),
        RetryReason::Timeout(TimeoutPhase::ResponseBody),
    );
    let read_body_first = RetryDecision::new(
        1,
        5,
        http::Method::GET,
        "https://example.com/timeout".to_owned(),
        RetryReason::ResponseBodyRead,
    );
    let read_body_second = RetryDecision::new(
        2,
        5,
        http::Method::GET,
        "https://example.com/timeout".to_owned(),
        RetryReason::ResponseBodyRead,
    );

    assert!(retry_policy.should_retry_decision(&transport_timeout_first));
    assert!(!retry_policy.should_retry_decision(&transport_timeout_second));
    assert!(!retry_policy.should_retry_decision(&response_timeout));
    assert!(retry_policy.should_retry_decision(&read_body_first));
    assert!(!retry_policy.should_retry_decision(&read_body_second));
}

#[test]
fn post_without_idempotency_key_is_not_retryable() {
    let headers = http::HeaderMap::new();
    assert!(!request_supports_retry(&http::Method::POST, &headers));
}

#[test]
fn post_with_idempotency_key_is_retryable() {
    let mut headers = http::HeaderMap::new();
    headers.insert("idempotency-key", http::HeaderValue::from_static("abc"));
    assert!(request_supports_retry(&http::Method::POST, &headers));
}
