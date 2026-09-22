use super::{
    redact_uri_for_logs, redact_uri_like_text_for_logs, redact_uri_without_url_normalization,
};

#[test]
fn redact_uri_for_logs_masks_credential_like_path_segments_and_removes_query() {
    let redacted = redact_uri_for_logs(
        "https://api.telegram.org/bot123456:AAABBBCCCDDDEE/getUpdates?offset=10",
    );
    assert_eq!(
        redacted,
        "https://api.telegram.org/bot123456:redacted/getUpdates"
    );
}

#[test]
fn redact_uri_for_logs_masks_percent_encoded_credential_path_separator() {
    let redacted = redact_uri_for_logs(
        "https://api.telegram.org/bot123456%3AAAABBBCCCDDDEE/getUpdates?offset=10",
    );
    assert_eq!(
        redacted,
        "https://api.telegram.org/bot123456:redacted/getUpdates"
    );
    assert!(!redacted.contains("AAABBBCCCDDDEE"));
}

#[test]
fn redact_uri_for_logs_masks_userinfo() {
    let redacted = redact_uri_for_logs("http://user:pass@proxy.example.com:7890/path");
    assert_eq!(redacted, "http://proxy.example.com:7890/path");
}

#[test]
fn redact_uri_for_logs_fallback_masks_userinfo_query_and_fragment() {
    let redacted =
        redact_uri_for_logs("https://user:pass@proxy.example.com:badport/path?token=secret#frag");
    assert_eq!(redacted, "https://proxy.example.com:badport/path");
}

#[test]
fn redact_uri_for_logs_fallback_masks_userinfo_without_host() {
    let redacted = redact_uri_for_logs("https://user:pass@?token=secret#frag");
    assert_eq!(redacted, "https://<redacted>@");
}

#[test]
fn redact_uri_for_logs_fallback_masks_network_path_userinfo_without_host() {
    let redacted = redact_uri_without_url_normalization("//user:pass@/path?token=secret#frag");
    assert_eq!(redacted, "//<redacted>@/path");
}

#[test]
fn redact_uri_for_logs_masks_non_authority_credentials() {
    let redacted = redact_uri_for_logs("mailto:user:pass@example.com?subject=secret");
    assert_eq!(redacted, "mailto:<redacted>@example.com");
}

#[test]
fn redact_uri_for_logs_keeps_unknown_non_authority_uri_shape() {
    let redacted = redact_uri_for_logs("urn:example:foo@bar?token=secret");
    assert_eq!(redacted, "urn:example:foo@bar");
}

#[test]
fn redact_uri_like_text_for_logs_redacts_embedded_uri_tokens() {
    let redacted = redact_uri_like_text_for_logs(
        "connect failed: url=https://user:pass@api.example.com/v1?token=secret#frag, proxy=http://proxy-user:proxy-pass@proxy.example.com:badport/tunnel?secret=1",
    );

    assert!(!redacted.contains("user:pass"));
    assert!(!redacted.contains("proxy-user:proxy-pass"));
    assert!(!redacted.contains("token=secret"));
    assert!(!redacted.contains("secret=1"));
    assert!(redacted.contains("url=https://api.example.com/v1,"));
    assert!(redacted.contains("proxy=http://proxy.example.com:badport/tunnel"));
}

#[test]
fn redact_uri_like_text_for_logs_redacts_adjacent_uri_tokens_without_whitespace() {
    let redacted = redact_uri_like_text_for_logs(
        "connect failed:url=https://api.example.com/v1,proxy=http://proxy-user:proxy-pass@proxy.example.com/tunnel",
    );

    assert!(!redacted.contains("proxy-user:proxy-pass"));
    assert!(
        redacted.contains("url=https://api.example.com/v1,proxy=http://proxy.example.com/tunnel")
    );
}
