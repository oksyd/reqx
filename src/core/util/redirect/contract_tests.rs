use http::header::{
    AUTHORIZATION, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, EXPECT,
    HOST, HeaderName, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderValue};

use super::{
    default_port, rate_limit_bucket_key, resolve_redirect_uri, same_origin,
    sanitize_headers_for_redirect,
};

#[test]
fn default_port_handles_uppercase_scheme() {
    let https: http::Uri = "HTTPS://api.example.com/path"
        .parse()
        .expect("uri should parse");
    let http: http::Uri = "HTTP://api.example.com/path"
        .parse()
        .expect("uri should parse");
    assert_eq!(default_port(&https), Some(443));
    assert_eq!(default_port(&http), Some(80));
}

#[test]
fn rate_limit_bucket_key_uses_default_port_for_uppercase_scheme() {
    let uri: http::Uri = "HTTPS://api.example.com/path"
        .parse()
        .expect("uri should parse");
    assert_eq!(
        rate_limit_bucket_key(&uri).as_deref(),
        Some("api.example.com:443")
    );
}

#[test]
fn rate_limit_bucket_key_normalizes_trailing_dot_hosts() {
    let uri: http::Uri = "https://api.example.com./path"
        .parse()
        .expect("uri should parse");
    assert_eq!(
        rate_limit_bucket_key(&uri).as_deref(),
        Some("api.example.com:443")
    );
}

#[test]
fn rate_limit_bucket_key_brackets_ipv6_hosts() {
    let uri: http::Uri = "https://[2001:db8::1]/path"
        .parse()
        .expect("uri should parse");
    assert_eq!(
        rate_limit_bucket_key(&uri).as_deref(),
        Some("[2001:db8::1]:443")
    );
}

#[test]
fn same_origin_handles_uppercase_scheme() {
    let left: http::Uri = "HTTPS://api.example.com/path"
        .parse()
        .expect("left uri should parse");
    let right: http::Uri = "https://api.example.com:443/other"
        .parse()
        .expect("right uri should parse");
    assert!(same_origin(&left, &right));
}

#[test]
fn same_origin_normalizes_trailing_dot_hosts() {
    let left: http::Uri = "https://api.example.com./path"
        .parse()
        .expect("left uri should parse");
    let right: http::Uri = "https://api.example.com:443/other"
        .parse()
        .expect("right uri should parse");
    assert!(same_origin(&left, &right));
}

#[test]
fn resolve_redirect_uri_rejects_non_http_scheme() {
    let current: http::Uri = "https://api.example.com/v1/old"
        .parse()
        .expect("current uri should parse");
    assert!(resolve_redirect_uri(&current, "mailto:user:pass@example.com").is_none());
    assert!(resolve_redirect_uri(&current, "javascript:alert(1)").is_none());
}

#[test]
fn resolve_redirect_uri_rejects_userinfo_location() {
    let current: http::Uri = "https://api.example.com/v1/old"
        .parse()
        .expect("current uri should parse");
    assert!(resolve_redirect_uri(&current, "https://user:pass@example.com/v1/new").is_none());
}

#[test]
fn resolve_redirect_uri_accepts_network_path_reference() {
    let current: http::Uri = "https://api.example.com/v1/old"
        .parse()
        .expect("current uri should parse");
    let redirected =
        resolve_redirect_uri(&current, "//cdn.example.com/v1/new?token=public#section")
            .expect("network-path redirect location should resolve");

    assert_eq!(
        redirected.to_string(),
        "https://cdn.example.com/v1/new?token=public"
    );
}

#[test]
fn resolve_redirect_uri_rejects_malformed_http_absolute_location() {
    let current: http::Uri = "https://api.example.com/v1/old"
        .parse()
        .expect("current uri should parse");
    assert!(resolve_redirect_uri(&current, "http:/x").is_none());
    assert!(resolve_redirect_uri(&current, "https:/x").is_none());
    assert!(resolve_redirect_uri(&current, "https:///x").is_none());
    assert!(resolve_redirect_uri(&current, "http:foo").is_none());
    assert!(resolve_redirect_uri(&current, "https://example.com:invalid/v1/new").is_none());
}

#[test]
fn resolve_redirect_uri_rejects_network_path_location_with_empty_port() {
    let current: http::Uri = "https://api.example.com/v1/old"
        .parse()
        .expect("current uri should parse");
    assert!(resolve_redirect_uri(&current, "//example.com:/v1/new").is_none());
}

#[test]
fn sanitize_headers_for_redirect_removes_proxy_authorization() {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_ENCODING,
        "gzip".parse().expect("content-encoding should parse"),
    );
    headers.insert(
        CONTENT_LENGTH,
        "3".parse().expect("content-length should parse"),
    );
    headers.insert(
        CONTENT_TYPE,
        "application/json"
            .parse()
            .expect("content-type should parse"),
    );
    headers.insert(EXPECT, "100-continue".parse().expect("expect should parse"));
    headers.insert(
        "content-digest",
        "sha-256=:abc=:"
            .parse()
            .expect("content-digest should parse"),
    );
    headers.insert(
        "content-md5",
        "Q2hlY2sgSW50ZWdyaXR5IQ=="
            .parse()
            .expect("content-md5 should parse"),
    );
    headers.insert(
        "digest",
        "SHA-256=xyz".parse().expect("digest should parse"),
    );
    headers.insert(
        TRAILER,
        "x-checksum".parse().expect("trailer header should parse"),
    );
    headers.insert(
        TRANSFER_ENCODING,
        "chunked".parse().expect("transfer-encoding should parse"),
    );
    headers.insert(HOST, "api.example.com".parse().expect("host should parse"));
    headers.insert(
        AUTHORIZATION,
        "Bearer token".parse().expect("authorization should parse"),
    );
    headers.insert(COOKIE, "session=abc".parse().expect("cookie should parse"));
    headers.insert(
        PROXY_AUTHORIZATION,
        "Basic dXNlcjpwYXNz"
            .parse()
            .expect("proxy-authorization should parse"),
    );

    sanitize_headers_for_redirect(&mut headers, true, true);

    assert!(!headers.contains_key(CONTENT_ENCODING));
    assert!(!headers.contains_key(CONTENT_LENGTH));
    assert!(!headers.contains_key(CONTENT_TYPE));
    assert!(!headers.contains_key("content-digest"));
    assert!(!headers.contains_key("content-md5"));
    assert!(!headers.contains_key("digest"));
    assert!(!headers.contains_key(EXPECT));
    assert!(!headers.contains_key(TRAILER));
    assert!(!headers.contains_key(TRANSFER_ENCODING));
    assert!(!headers.contains_key(HOST));
    assert!(headers.contains_key(AUTHORIZATION));
    assert!(headers.contains_key(COOKIE));
    assert!(!headers.contains_key(PROXY_AUTHORIZATION));
}

#[test]
fn sanitize_headers_for_cross_origin_redirect_removes_credentials() {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        "Bearer token".parse().expect("authorization should parse"),
    );
    headers.insert(COOKIE, "session=abc".parse().expect("cookie should parse"));
    headers.insert(
        PROXY_AUTHORIZATION,
        "Basic dXNlcjpwYXNz"
            .parse()
            .expect("proxy-authorization should parse"),
    );
    let mut api_key = HeaderValue::from_static("secret-api-key");
    api_key.set_sensitive(true);
    headers.insert("x-api-key", api_key);
    headers.insert(
        "x-request-label",
        HeaderValue::from_static("safe-to-forward"),
    );

    sanitize_headers_for_redirect(&mut headers, false, false);

    assert!(!headers.contains_key(AUTHORIZATION));
    assert!(!headers.contains_key(COOKIE));
    assert!(!headers.contains_key(PROXY_AUTHORIZATION));
    assert!(!headers.contains_key("x-api-key"));
    assert!(headers.contains_key("x-request-label"));
}

#[test]
fn sanitize_headers_for_redirect_removes_hop_by_hop_headers() {
    let mut headers = HeaderMap::new();
    let connection_option = HeaderName::from_static("x-connection-option");
    headers.insert(
        CONNECTION,
        "keep-alive, x-connection-option"
            .parse()
            .expect("connection header should parse"),
    );
    headers.insert(
        "keep-alive",
        "timeout=5".parse().expect("keep-alive should parse"),
    );
    headers.insert(
        "proxy-connection",
        "keep-alive".parse().expect("proxy-connection should parse"),
    );
    headers.insert(TE, "trailers".parse().expect("te should parse"));
    headers.insert(TRAILER, "x-checksum".parse().expect("trailer should parse"));
    headers.insert(
        TRANSFER_ENCODING,
        "chunked".parse().expect("transfer-encoding should parse"),
    );
    headers.insert(UPGRADE, "websocket".parse().expect("upgrade should parse"));
    headers.insert(
        connection_option,
        "present"
            .parse()
            .expect("connection-scoped header should parse"),
    );
    headers.insert(
        AUTHORIZATION,
        "Bearer token".parse().expect("authorization should parse"),
    );

    sanitize_headers_for_redirect(&mut headers, false, true);

    assert!(!headers.contains_key(CONNECTION));
    assert!(!headers.contains_key("keep-alive"));
    assert!(!headers.contains_key("proxy-connection"));
    assert!(!headers.contains_key(TE));
    assert!(!headers.contains_key(TRAILER));
    assert!(!headers.contains_key(TRANSFER_ENCODING));
    assert!(!headers.contains_key(UPGRADE));
    assert!(!headers.contains_key("x-connection-option"));
    assert!(headers.contains_key(AUTHORIZATION));
}
