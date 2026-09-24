#[cfg(feature = "compression-gzip")]
use std::io::Write;

use bytes::Bytes;
#[cfg(feature = "compression-gzip")]
use flate2::Compression;
#[cfg(feature = "compression-gzip")]
use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};

use super::{
    DecodeContentEncodingError, decode_content_encoded_body_limited,
    should_decode_content_encoded_body,
};

#[test]
fn should_decode_content_encoded_body_only_when_body_semantics_allow() {
    assert!(!should_decode_content_encoded_body(
        &http::Method::HEAD,
        http::StatusCode::OK,
        32
    ));
    assert!(!should_decode_content_encoded_body(
        &http::Method::GET,
        http::StatusCode::NO_CONTENT,
        32
    ));
    assert!(!should_decode_content_encoded_body(
        &http::Method::GET,
        http::StatusCode::NOT_MODIFIED,
        32
    ));
    assert!(!should_decode_content_encoded_body(
        &http::Method::GET,
        http::StatusCode::OK,
        0
    ));
    assert!(should_decode_content_encoded_body(
        &http::Method::GET,
        http::StatusCode::OK,
        32
    ));
}

#[cfg(feature = "compression-gzip")]
#[test]
fn decode_content_encoded_body_decodes_gzip_payload() {
    let source = br#"{"ok":true}"#;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(source)
        .expect("write gzip source bytes should succeed");
    let compressed = encoder.finish().expect("finish gzip stream should succeed");

    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_ENCODING,
        http::HeaderValue::from_static("gzip"),
    );
    let decoded =
        decode_content_encoded_body_limited(bytes::Bytes::from(compressed), &headers, 1024)
            .expect("gzip payload should decode");
    assert_eq!(decoded.as_ref(), source);
}

#[cfg(feature = "compression-gzip")]
#[test]
fn decode_content_encoded_body_accepts_zlib_and_raw_deflate_payloads() {
    let source = br#"{"ok":true}"#;
    let mut zlib_encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    zlib_encoder
        .write_all(source)
        .expect("write zlib deflate source bytes should succeed");
    let zlib_compressed = zlib_encoder
        .finish()
        .expect("finish zlib deflate stream should succeed");

    let mut raw_encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    raw_encoder
        .write_all(source)
        .expect("write raw deflate source bytes should succeed");
    let raw_compressed = raw_encoder
        .finish()
        .expect("finish raw deflate stream should succeed");

    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_ENCODING,
        http::HeaderValue::from_static("deflate"),
    );

    let zlib_decoded =
        decode_content_encoded_body_limited(bytes::Bytes::from(zlib_compressed), &headers, 1024)
            .expect("zlib-wrapped deflate payload should decode");
    assert_eq!(zlib_decoded.as_ref(), source);

    let raw_decoded =
        decode_content_encoded_body_limited(bytes::Bytes::from(raw_compressed), &headers, 1024)
            .expect("raw deflate payload should decode");
    assert_eq!(raw_decoded.as_ref(), source);
}

#[cfg(feature = "compression-gzip")]
#[test]
fn decode_content_encoded_body_combines_multiple_content_encoding_headers() {
    let source = br#"{"ok":true}"#;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(source)
        .expect("write gzip source bytes should succeed");
    let compressed = encoder.finish().expect("finish gzip stream should succeed");

    let mut headers = http::HeaderMap::new();
    headers.append(
        http::header::CONTENT_ENCODING,
        http::HeaderValue::from_static("identity"),
    );
    headers.append(
        http::header::CONTENT_ENCODING,
        http::HeaderValue::from_static("gzip"),
    );

    let decoded =
        decode_content_encoded_body_limited(bytes::Bytes::from(compressed), &headers, 1024)
            .expect("split content-encoding headers should decode in wire order");
    assert_eq!(decoded.as_ref(), source);
}

#[test]
fn decode_content_encoded_body_rejects_unknown_encoding() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_ENCODING,
        http::HeaderValue::from_static("x-custom"),
    );
    let error =
        decode_content_encoded_body_limited(bytes::Bytes::from_static(b"abc"), &headers, 64)
            .expect_err("unknown content-encoding should fail");
    match error {
        DecodeContentEncodingError::Decode { encoding, .. } => assert_eq!(encoding, "x-custom"),
        other => panic!("unexpected decode error: {other:?}"),
    }
}

#[test]
fn decode_content_encoded_body_limited_rejects_unencoded_payload() {
    let headers = http::HeaderMap::new();
    let error =
        decode_content_encoded_body_limited(bytes::Bytes::from_static(b"abcdef"), &headers, 4)
            .expect_err("unencoded payload should still honor the decode limit");

    match error {
        DecodeContentEncodingError::TooLarge { actual_bytes } => {
            assert_eq!(actual_bytes, 6);
        }
        other => panic!("unexpected decode error: {other:?}"),
    }
}

#[cfg(feature = "compression-gzip")]
#[test]
fn decode_content_encoded_body_limited_rejects_expanded_payload() {
    let source = vec![b'a'; 16 * 1024];
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&source)
        .expect("write gzip source bytes should succeed");
    let compressed = encoder.finish().expect("finish gzip stream should succeed");

    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_ENCODING,
        http::HeaderValue::from_static("gzip"),
    );
    let error = decode_content_encoded_body_limited(bytes::Bytes::from(compressed), &headers, 512)
        .expect_err("expanded payload should exceed decode limit");
    match error {
        DecodeContentEncodingError::TooLarge { actual_bytes } => {
            assert!(actual_bytes > 512);
        }
        other => panic!("unexpected decode error: {other:?}"),
    }
}

#[test]
fn decode_content_encoded_body_limited_honors_zero_limit() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_ENCODING,
        http::HeaderValue::from_static("identity"),
    );

    let empty = decode_content_encoded_body_limited(Bytes::new(), &headers, 0)
        .expect("empty body should fit zero byte limit");
    assert!(empty.is_empty());

    let error = decode_content_encoded_body_limited(Bytes::from_static(b"x"), &headers, 0)
        .expect_err("non-empty body should exceed zero byte limit");
    match error {
        DecodeContentEncodingError::TooLarge { actual_bytes } => {
            assert_eq!(actual_bytes, 1);
        }
        other => panic!("unexpected decode error: {other:?}"),
    }
}
