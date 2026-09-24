use bytes::Bytes;
use http::{HeaderMap, StatusCode};

use super::Response;

use crate::core::error::Error;

#[test]
fn response_json_decode_error_contains_body() {
    let response = Response::new(
        http::StatusCode::OK,
        http::HeaderMap::new(),
        bytes::Bytes::from_static(b"not-json"),
    );
    let error = response
        .json::<serde_json::Value>()
        .expect_err("invalid json should return error");
    match error {
        Error::DeserializeJson { body, .. } => assert_eq!(body, "not-json"),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn response_debug_omits_body_contents() {
    let response = Response::new(
        http::StatusCode::OK,
        http::HeaderMap::new(),
        bytes::Bytes::from_static(b"secret-response-body"),
    );

    let debug = format!("{response:?}");

    assert!(debug.contains("body_len"));
    assert!(!debug.contains("secret-response-body"));
}

#[test]
fn response_text_accepts_valid_utf8() {
    let response = Response::new(
        StatusCode::OK,
        HeaderMap::new(),
        Bytes::from_static(b"hello"),
    );
    assert_eq!(response.text().expect("text should decode"), "hello");
}

#[test]
fn response_text_rejects_invalid_utf8() {
    let response = Response::new(
        StatusCode::OK,
        HeaderMap::new(),
        Bytes::from_static(b"hello\xff"),
    );
    let error = response.text().expect_err("invalid utf-8 should fail");
    match error {
        Error::DecodeText { body, .. } => assert_eq!(body, "hello\u{fffd}"),
        other => panic!("unexpected error variant: {other}"),
    }
}
