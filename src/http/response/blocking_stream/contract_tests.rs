use std::time::Duration;

use super::BlockingResponseStreamContext;

#[cfg(feature = "_blocking")]
#[test]
fn blocking_response_stream_debug_omits_raw_uri_query() {
    let stream = crate::http::response::BlockingResponseStream::new(
        http::StatusCode::OK,
        http::HeaderMap::new(),
        ureq::Body::builder().data("body"),
        BlockingResponseStreamContext {
            method: http::Method::GET,
            uri_raw: "https://api.example.com/v1/items?token=secret-token".to_owned(),
            uri_redacted: "https://api.example.com/v1/items".to_owned(),
            timeout_ms: 1000,
            total_timeout_ms: None,
            deadline_at: None,
            deadline_slack: Duration::from_millis(10),
            lifecycle: None,
            global_permit: None,
            host_permit: None,
        },
    );

    let debug = format!("{stream:?}");

    assert!(debug.contains("uri_redacted"));
    assert!(debug.contains("https://api.example.com/v1/items"));
    assert!(!debug.contains("uri_raw"));
    assert!(!debug.contains("secret-token"));
}
