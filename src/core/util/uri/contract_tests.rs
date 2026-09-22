use std::collections::BTreeMap;

use super::{append_query_pairs, join_base_path, resolve_uri};

use crate::core::error::Error;

#[test]
fn join_base_path_handles_slashes() {
    assert_eq!(
        join_base_path("https://api.example.com/v1/", "/users"),
        "https://api.example.com/v1/users"
    );
}

#[test]
fn join_base_path_preserves_extra_leading_slashes() {
    assert_eq!(
        join_base_path("https://api.example.com/v1/", "//users"),
        "https://api.example.com/v1//users"
    );
    assert_eq!(
        join_base_path("https://api.example.com/v1/", "///users"),
        "https://api.example.com/v1///users"
    );
}

#[test]
fn join_base_path_keeps_query_and_fragment_on_base_resource() {
    assert_eq!(
        join_base_path("https://api.example.com/v1/", "?page=1"),
        "https://api.example.com/v1?page=1"
    );
    assert_eq!(
        join_base_path("https://api.example.com/v1/", "#section"),
        "https://api.example.com/v1#section"
    );
    assert_eq!(
        join_base_path("https://api.example.com/v1/", "?page=1#section"),
        "https://api.example.com/v1?page=1#section"
    );
}

#[test]
fn resolve_uri_keeps_absolute_uri() {
    let (uri_text, uri) = resolve_uri("https://api.example.com/v1", "https://x.test/a")
        .expect("absolute uri should parse");
    assert_eq!(uri_text, "https://x.test/a");
    assert_eq!(uri.to_string(), "https://x.test/a");
}

#[test]
fn resolve_uri_keeps_absolute_uri_with_uppercase_scheme() {
    let (uri_text, uri) = resolve_uri("https://api.example.com/v1", "HTTPS://x.test/a")
        .expect("absolute uri with uppercase scheme should parse");
    assert_eq!(uri_text, "HTTPS://x.test/a");
    assert_eq!(uri.host().expect("host should be present"), "x.test",);
}

#[test]
fn resolve_uri_rejects_non_http_absolute_uri() {
    let error = resolve_uri("https://api.example.com/v1", "ftp://x.test/a")
        .expect_err("non-http absolute uri should be rejected");
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "ftp://x.test/a");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn resolve_uri_rejects_absolute_uri_with_userinfo() {
    let error = resolve_uri("https://api.example.com/v1", "https://user:pass@x.test/a")
        .expect_err("absolute uri with userinfo should be rejected");
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://x.test/a");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn resolve_uri_rejects_malformed_http_absolute_uri() {
    let error = resolve_uri("https://api.example.com/v1", "HTTPS:/x")
        .expect_err("malformed absolute http URI should be rejected");
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "HTTPS:/x");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn resolve_uri_rejects_absolute_uri_with_invalid_authority() {
    let error = resolve_uri(
        "https://api.example.com/v1",
        "https://example.com:invalid/v1/new?token=secret#frag",
    )
    .expect_err("absolute uri with invalid authority should be rejected");
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://example.com:invalid/v1/new");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn resolve_uri_rejects_absolute_uri_with_empty_port() {
    let error = resolve_uri(
        "https://api.example.com/v1",
        "https://example.com:/v1/new?token=secret",
    )
    .expect_err("absolute uri with empty authority port should be rejected");
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://example.com:/v1/new");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn resolve_uri_keeps_query_only_relative_on_base_resource() {
    let (uri_text, uri) = resolve_uri("https://api.example.com/v1", "?page=1")
        .expect("query-only relative URI should resolve against the base resource");
    assert_eq!(uri_text, "https://api.example.com/v1?page=1");
    assert_eq!(uri.to_string(), "https://api.example.com/v1?page=1");
}

#[test]
fn resolve_uri_preserves_extra_leading_slashes_in_relative_path() {
    let (uri_text, uri) = resolve_uri("https://api.example.com/v1", "//users")
        .expect("double-slash relative path should resolve against the base resource");
    assert_eq!(uri_text, "https://api.example.com/v1//users");
    assert_eq!(uri.to_string(), "https://api.example.com/v1//users");
}

#[test]
fn resolve_uri_rejects_malformed_http_absolute_uri_after_query_append() {
    let query_pairs = vec![("page".to_owned(), "1".to_owned())];
    let path = append_query_pairs("HTTPS:/x", &query_pairs);
    let error = resolve_uri("https://api.example.com/v1", &path)
        .expect_err("malformed absolute http URI should stay rejected after query append");
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "HTTPS:/x");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn append_query_pairs_merges_existing_query_and_fragment() {
    let query_pairs = vec![
        ("name".to_owned(), "alice bob".to_owned()),
        ("page".to_owned(), "2".to_owned()),
    ];
    let merged = append_query_pairs("/v1/users?active=true#section", &query_pairs);
    assert!(merged.starts_with("/v1/users?"));
    assert!(merged.ends_with("#section"));

    let query_text = merged
        .split_once('?')
        .and_then(|(_, right)| right.split_once('#').map(|(query, _)| query))
        .unwrap_or_default();
    let parsed: BTreeMap<String, String> = url::form_urlencoded::parse(query_text.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    assert_eq!(parsed.get("active"), Some(&"true".to_owned()));
    assert_eq!(parsed.get("name"), Some(&"alice bob".to_owned()));
    assert_eq!(parsed.get("page"), Some(&"2".to_owned()));
}

#[test]
fn query_append_preserves_existing_uri_bytes() {
    let pairs = vec![("next".to_owned(), "a b+c".to_owned())];
    for input in [
        "/v1/a/../b?token=%2f%2F&space=%20&flag&raw=%FF&&",
        "https://EXAMPLE.com:443/v1/a/../b?token=%2f%2F&space=%20&flag&raw=%FF&&",
    ] {
        assert_eq!(
            append_query_pairs(input, &pairs),
            format!("{input}next=a+b%2Bc")
        );
    }
    assert_eq!(
        append_query_pairs("/v1?q=?#fragment?", &pairs),
        "/v1?q=?&next=a+b%2Bc#fragment?"
    );
    for input in ["/v1?", "https://example.com/v1?"] {
        assert_eq!(
            append_query_pairs(input, &pairs),
            format!("{input}next=a+b%2Bc")
        );
    }
}

#[test]
fn append_query_pairs_handles_absolute_url() {
    let query_pairs = vec![
        ("topic".to_owned(), "rust sdk".to_owned()),
        ("lang".to_owned(), "zh".to_owned()),
    ];
    let merged = append_query_pairs("https://api.example.com/search?q=hello", &query_pairs);
    let parsed = url::Url::parse(&merged).expect("merged url should parse");
    let parsed_query: BTreeMap<String, String> = parsed
        .query_pairs()
        .map(|pair| (pair.0.into_owned(), pair.1.into_owned()))
        .collect();
    assert_eq!(parsed_query.get("q"), Some(&"hello".to_owned()));
    assert_eq!(parsed_query.get("topic"), Some(&"rust sdk".to_owned()));
    assert_eq!(parsed_query.get("lang"), Some(&"zh".to_owned()));
}

#[test]
fn append_query_pairs_preserves_malformed_http_absolute_shape() {
    let query_pairs = vec![("page".to_owned(), "1".to_owned())];
    let merged = append_query_pairs("HTTPS:/x", &query_pairs);
    assert_eq!(merged, "HTTPS:/x?page=1");
}
