use std::time::Duration;

use super::{select_base_url, status_retry_delay};

use crate::core::error::Error;
use crate::core::extensions::{EndpointSelector, SystemClock};

#[derive(Debug)]
struct StaticEndpointSelector(&'static str);

impl EndpointSelector for StaticEndpointSelector {
    fn select_base_url(
        &self,
        _method: &http::Method,
        _path: &str,
        _configured_base_url: &str,
    ) -> crate::Result<String> {
        Ok(self.0.to_owned())
    }
}

#[test]
fn select_base_url_rejects_invalid_endpoint_selector_value() {
    let selector = StaticEndpointSelector("https://api.example.com:/v1");
    let error = select_base_url(
        &selector,
        &http::Method::GET,
        "/users",
        "https://fallback.example.com/v1",
    )
    .expect_err("invalid endpoint selector base url should be rejected");
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://api.example.com:/v1");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn status_retry_delay_caps_retry_after_to_max_delay() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::RETRY_AFTER,
        http::HeaderValue::from_static("120"),
    );

    let clock = SystemClock;
    let delay = status_retry_delay(
        &clock,
        &headers,
        Duration::from_millis(200),
        Duration::from_secs(45),
    );
    assert_eq!(delay, Duration::from_secs(45));
}

#[test]
fn status_retry_delay_uses_configured_cap_when_small() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::RETRY_AFTER,
        http::HeaderValue::from_static("120"),
    );

    let clock = SystemClock;
    let delay = status_retry_delay(
        &clock,
        &headers,
        Duration::from_millis(200),
        Duration::from_secs(2),
    );
    assert_eq!(delay, Duration::from_secs(2));
}
