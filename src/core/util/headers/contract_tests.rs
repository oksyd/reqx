use http::header::{AUTHORIZATION, COOKIE, TRANSFER_ENCODING};
use http::{HeaderMap, HeaderValue};

use super::{mark_sensitive_headers, parse_header_value, validate_request_framing_headers};

use crate::core::error::Error;

#[test]
fn parse_header_value_marks_standard_sensitive_headers_for_debug() {
    for (name, value, secret) in [
        ("authorization", "Bearer secret-token", "secret-token"),
        ("Cookie", "session=secret-cookie", "secret-cookie"),
        (
            "proxy-authorization",
            "Basic secret-proxy-token",
            "secret-proxy-token",
        ),
    ] {
        let value = parse_header_value(name, value).expect("sensitive header value should parse");
        let debug = format!("{value:?}");

        assert!(debug.contains("Sensitive"));
        assert!(!debug.contains(secret));
    }
}

#[test]
fn mark_sensitive_headers_marks_interceptor_inserted_values_for_debug() {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        "Bearer interceptor-token"
            .parse()
            .expect("authorization should parse"),
    );
    headers.insert(
        COOKIE,
        "session=interceptor-cookie"
            .parse()
            .expect("cookie should parse"),
    );

    mark_sensitive_headers(&mut headers);

    let debug = format!("{headers:?}");
    assert!(debug.contains("Sensitive"));
    assert!(!debug.contains("interceptor-token"));
    assert!(!debug.contains("interceptor-cookie"));
}

#[test]
fn request_framing_rejects_transport_managed_transfer_encoding() {
    let mut headers = HeaderMap::new();
    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("Chunked"));

    let error = validate_request_framing_headers(
        &headers,
        None,
        &http::Method::POST,
        "https://api.example.com/upload",
    )
    .expect_err("transport-managed framing should not be caller-controlled");

    match error {
        Error::InvalidRequestFraming { message, .. } => {
            assert_eq!(message, "transfer-encoding is managed by the transport");
        }
        other => panic!("unexpected error: {other}"),
    }
}
