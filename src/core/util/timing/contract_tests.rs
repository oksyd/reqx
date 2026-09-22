use std::time::{Duration, SystemTime};

use super::{
    bounded_retry_delay, duration_from_millis_saturating, duration_millis_ceil, parse_retry_after,
};

#[test]
fn diagnostic_milliseconds_preserve_nonzero_sub_millisecond_durations() {
    assert_eq!(duration_millis_ceil(Duration::ZERO), 0);
    assert_eq!(duration_millis_ceil(Duration::from_nanos(1)), 1);
    assert_eq!(duration_millis_ceil(Duration::from_micros(999)), 1);
    assert_eq!(duration_millis_ceil(Duration::from_micros(1_500)), 2);
    assert_eq!(duration_millis_ceil(Duration::from_millis(2)), 2);
}

#[test]
fn millisecond_conversion_uses_full_duration_range() {
    let max_seconds_ms = u128::from(u64::MAX) * 1_000;
    assert_eq!(
        duration_from_millis_saturating(max_seconds_ms + 999),
        Duration::new(u64::MAX, 999_000_000)
    );
    assert_eq!(
        duration_from_millis_saturating(max_seconds_ms + 1_000),
        Duration::MAX
    );
}

#[test]
fn parse_retry_after_header_seconds() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::RETRY_AFTER,
        http::HeaderValue::from_static("5"),
    );
    assert_eq!(
        parse_retry_after(&headers, SystemTime::UNIX_EPOCH),
        Some(Duration::from_secs(5))
    );
}

#[test]
fn parse_retry_after_header_http_date() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let retry_at = now + Duration::from_secs(30);
    let mut headers = http::HeaderMap::new();
    let retry_at_text = httpdate::fmt_http_date(retry_at);
    headers.insert(
        http::header::RETRY_AFTER,
        http::HeaderValue::from_str(&retry_at_text).expect("valid retry-after date"),
    );
    assert_eq!(
        parse_retry_after(&headers, now),
        Some(Duration::from_secs(30))
    );
}

#[test]
fn bounded_retry_delay_respects_total_timeout() {
    let start = std::time::Instant::now();
    let retry_delay = Duration::from_millis(100);
    let total_timeout = Some(Duration::from_millis(100));
    assert_eq!(bounded_retry_delay(retry_delay, total_timeout, start), None);
}
