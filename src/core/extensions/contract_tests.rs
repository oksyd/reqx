use crate::core::extensions::{
    EndpointSelector, OtelPathNormalizer, RoundRobinEndpointSelector, StandardOtelPathNormalizer,
};

#[test]
fn round_robin_rejects_empty_and_invalid_endpoints_at_construction() {
    let error = RoundRobinEndpointSelector::new(Vec::<String>::new())
        .expect_err("empty endpoint list must fail");
    assert_eq!(error.code(), crate::ErrorCode::InvalidEndpointConfig);
    assert!(matches!(
        RoundRobinEndpointSelector::new(["https://example.com", "file:///tmp/data"]),
        Err(crate::Error::InvalidUri { .. })
    ));
}

#[test]
fn round_robin_rotates_through_validated_endpoints() {
    let selector = RoundRobinEndpointSelector::new([
        "https://primary.example.com/api",
        "https://backup.example.com/api",
    ])
    .expect("valid endpoints");
    for expected in [
        "https://primary.example.com/api",
        "https://backup.example.com/api",
        "https://primary.example.com/api",
    ] {
        assert_eq!(
            selector
                .select_base_url(&http::Method::GET, "/items", "https://unused.example.com")
                .expect("selected endpoint"),
            expected
        );
    }
}

#[test]
fn standard_otel_path_normalizer_truncates_on_segment_boundary() {
    let input = format!(
        "/{}",
        std::iter::repeat_n("segment", 30)
            .collect::<Vec<_>>()
            .join("/")
    );
    let normalizer = StandardOtelPathNormalizer;
    let normalized = normalizer.normalize_path(&input);
    assert!(normalized.len() <= 128);
    assert!(
        normalized
            .split('/')
            .skip(1)
            .all(|segment| segment == "segment"),
        "truncated path should not keep partial segments: {normalized}"
    );
}

#[test]
fn standard_otel_path_normalizer_reduces_short_numeric_segments() {
    let normalizer = StandardOtelPathNormalizer;
    let normalized = normalizer.normalize_path("/v1/users/42/orders/12345");

    assert_eq!(normalized, "/v1/users/:int/orders/:int");
}

#[test]
fn standard_otel_path_normalizer_drops_partial_first_segment() {
    let input = format!("/{}", "secret%2Ftoken".repeat(20));
    let normalizer = StandardOtelPathNormalizer;
    let normalized = normalizer.normalize_path(&input);

    assert_eq!(normalized, "/");
    assert!(!normalized.contains("secret"));
}
