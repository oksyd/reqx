use http::header::{AUTHORIZATION, CONTENT_LENGTH, COOKIE};
use http::{HeaderMap, HeaderValue, Method, Uri};

use super::{
    redact_uri_for_logs, redact_uri_like_text_for_logs, same_origin, sanitize_headers_for_redirect,
    validate_request_framing_headers,
};

struct DeterministicInput(u64);

impl DeterministicInput {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn token(&mut self, len: usize) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|_| ALPHABET[(self.next() as usize) % ALPHABET.len()] as char)
            .collect()
    }
}

#[test]
fn generated_uri_credentials_are_always_redacted_idempotently() {
    let mut input = DeterministicInput::new(0x5eed_cafe_f00d_beef);

    for _ in 0..2_000 {
        let username = input.token(8);
        let password = input.token(24);
        let query_secret = input.token(32);
        let path = input.token(12);
        let raw = format!(
            "https://{username}:{password}@api.example.com/{path}?token={query_secret}#fragment"
        );

        let redacted = redact_uri_for_logs(&raw);
        assert!(!redacted.contains(&username));
        assert!(!redacted.contains(&password));
        assert!(!redacted.contains(&query_secret));
        assert_eq!(redact_uri_for_logs(&redacted), redacted);

        let embedded = format!("request failed for ({raw}); retrying");
        let embedded_redacted = redact_uri_like_text_for_logs(&embedded);
        assert!(!embedded_redacted.contains(&password));
        assert!(!embedded_redacted.contains(&query_secret));
    }
}

#[test]
fn generated_content_lengths_match_exactly_or_fail() {
    for actual in 0..=512_usize {
        for declared in [
            0,
            actual.saturating_sub(1),
            actual,
            actual.saturating_add(1),
            512,
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                CONTENT_LENGTH,
                HeaderValue::from_str(&declared.to_string()).expect("generated length is valid"),
            );
            let result = validate_request_framing_headers(
                &headers,
                Some(actual),
                &Method::POST,
                "https://api.example.com/upload",
            );
            assert_eq!(result.is_ok(), declared == actual);
        }
    }
}

#[test]
fn cross_origin_redirects_remove_every_sensitive_value() {
    let mut input = DeterministicInput::new(0xdec0_de01_1234_5678);

    for _ in 0..1_000 {
        let source_host = format!("{}.example.com", input.token(10));
        let target_host = format!("{}.example.net", input.token(10));
        let source: Uri = format!("https://{source_host}/start")
            .parse()
            .expect("generated source URI is valid");
        let target: Uri = format!("https://{target_host}/next")
            .parse()
            .expect("generated target URI is valid");
        assert!(!same_origin(&source, &target));

        let mut custom_secret =
            HeaderValue::from_str(&input.token(24)).expect("generated secret header is valid");
        custom_secret.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
        headers.insert(COOKIE, HeaderValue::from_static("session=secret"));
        headers.insert("x-sdk-secret", custom_secret);
        headers.insert("x-request-id", HeaderValue::from_static("request-1"));

        sanitize_headers_for_redirect(&mut headers, false, false);
        assert!(!headers.contains_key(AUTHORIZATION));
        assert!(!headers.contains_key(COOKIE));
        assert!(!headers.contains_key("x-sdk-secret"));
        assert_eq!(
            headers.get("x-request-id"),
            Some(&HeaderValue::from_static("request-1"))
        );
    }
}
