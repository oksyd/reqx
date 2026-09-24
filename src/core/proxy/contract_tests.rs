use super::{NoProxyRule, should_bypass_proxy_uri};

#[test]
fn no_proxy_rule_matches_domain_and_subdomain() {
    let rule = NoProxyRule::parse(".example.com").expect("valid rule");
    assert!(rule.matches("example.com", None));
    assert!(rule.matches("api.example.com", None));
    assert!(!rule.matches("another.com", None));
}

#[test]
fn no_proxy_rule_treats_leading_wildcard_as_domain_suffix() {
    let rule = NoProxyRule::parse("*.example.com").expect("valid wildcard suffix rule");
    assert!(rule.matches("example.com", None));
    assert!(rule.matches("api.example.com", None));
    assert!(!rule.matches("another.com", None));
}

#[test]
fn no_proxy_rule_matches_trailing_dot_fqdn_hosts() {
    let rule = NoProxyRule::parse(".example.com.").expect("valid rule");
    assert!(rule.matches("example.com.", None));
    assert!(rule.matches("api.example.com.", None));
    assert!(!rule.matches("another.com.", None));
}

#[test]
fn no_proxy_rule_parses_bracketed_ipv6_with_port() {
    let rule = NoProxyRule::parse("[::1]:8080").expect("valid ipv6 rule");
    assert!(rule.matches("::1", Some(8080)));
    assert!(!rule.matches("::1", Some(8081)));
    assert!(!rule.matches("::2", Some(8080)));
}

#[test]
fn no_proxy_rule_rejects_bracketed_non_ip_host() {
    assert!(NoProxyRule::parse("[example.com]").is_none());
}

#[test]
fn no_proxy_rule_keeps_plain_ipv6_without_port() {
    let rule = NoProxyRule::parse("2001:db8::1").expect("valid ipv6 rule");
    assert!(rule.matches("2001:db8::1", None));
    assert!(!rule.matches("2001:db8::2", None));
}

#[test]
fn no_proxy_rule_ip_literals_do_not_match_suffixes() {
    let ipv4_rule = NoProxyRule::parse("127.0.0.1").expect("valid ipv4 rule");
    assert!(ipv4_rule.matches("127.0.0.1", None));
    assert!(!ipv4_rule.matches("api.127.0.0.1", None));

    let suffix_like_rule = NoProxyRule::parse("0.0.1").expect("valid numeric domain rule");
    assert!(!suffix_like_rule.matches("127.0.0.1", None));
}

#[test]
fn no_proxy_rule_ipv6_matches_canonical_equivalents_only() {
    let rule = NoProxyRule::parse("::1").expect("valid ipv6 rule");
    assert!(rule.matches("0:0:0:0:0:0:0:1", None));
    assert!(!rule.matches("2001:db8::1", None));
}

#[test]
fn no_proxy_rule_with_port_requires_matching_port() {
    let rule = NoProxyRule::parse("api.example.com:8443").expect("valid host:port rule");
    assert!(rule.matches("api.example.com", Some(8443)));
    assert!(!rule.matches("api.example.com", Some(443)));
    assert!(!rule.matches("api.example.com", None));
}

#[test]
fn no_proxy_rule_accepts_url_authority_without_path() {
    let rule = NoProxyRule::parse("https://api.example.com:8443").expect("valid url-shaped rule");
    assert!(rule.matches("api.example.com", Some(8443)));
    assert!(!rule.matches("api.example.com", Some(443)));
}

#[test]
fn no_proxy_url_rule_without_explicit_port_uses_scheme_default_port() {
    let rules = vec![NoProxyRule::parse("https://api.example.com").expect("valid url-shaped rule")];
    let https_default_uri: http::Uri = "https://api.example.com/v1"
        .parse()
        .expect("uri should parse");
    let https_explicit_default_uri: http::Uri = "https://api.example.com:443/v1"
        .parse()
        .expect("uri should parse");
    let https_non_default_uri: http::Uri = "https://api.example.com:8443/v1"
        .parse()
        .expect("uri should parse");
    let http_uri: http::Uri = "http://api.example.com/v1"
        .parse()
        .expect("uri should parse");

    assert!(should_bypass_proxy_uri(&rules, &https_default_uri));
    assert!(should_bypass_proxy_uri(&rules, &https_explicit_default_uri));
    assert!(!should_bypass_proxy_uri(&rules, &https_non_default_uri));
    assert!(!should_bypass_proxy_uri(&rules, &http_uri));
}

#[test]
fn no_proxy_bypass_uses_default_uri_port_when_missing() {
    let rules = vec![NoProxyRule::parse("api.example.com:443").expect("valid host:port rule")];
    let https_uri: http::Uri = "https://api.example.com/v1"
        .parse()
        .expect("uri should parse");
    let http_uri: http::Uri = "http://api.example.com/v1"
        .parse()
        .expect("uri should parse");
    assert!(should_bypass_proxy_uri(&rules, &https_uri));
    assert!(!should_bypass_proxy_uri(&rules, &http_uri));
}

#[test]
fn no_proxy_bypass_matches_trailing_dot_uri_host() {
    let rules = vec![NoProxyRule::parse("api.example.com").expect("valid host rule")];
    let uri: http::Uri = "https://api.example.com./v1"
        .parse()
        .expect("uri should parse");
    assert!(should_bypass_proxy_uri(&rules, &uri));
}

#[test]
fn no_proxy_bypass_does_not_treat_ipv4_suffix_as_match() {
    let rules = vec![NoProxyRule::parse("0.0.1").expect("valid numeric domain rule")];
    let uri: http::Uri = "http://127.0.0.1/v1".parse().expect("uri should parse");
    assert!(!should_bypass_proxy_uri(&rules, &uri));
}

#[test]
fn no_proxy_rule_rejects_non_numeric_port_suffix() {
    assert!(
        NoProxyRule::parse("example.com:abc").is_none(),
        "non-numeric no_proxy port suffix must be rejected"
    );
}

#[test]
fn no_proxy_rule_rejects_url_with_path_query_or_userinfo() {
    assert!(NoProxyRule::parse("https://api.example.com/v1").is_none());
    assert!(NoProxyRule::parse("https://api.example.com?scope=one").is_none());
    assert!(NoProxyRule::parse("https://user:pass@api.example.com").is_none());
}

#[test]
fn no_proxy_rule_rejects_plain_rule_with_path_query_fragment_or_userinfo() {
    assert!(NoProxyRule::parse("api.example.com/v1").is_none());
    assert!(NoProxyRule::parse("api.example.com?scope=one").is_none());
    assert!(NoProxyRule::parse("api.example.com#fragment").is_none());
    assert!(NoProxyRule::parse("user@api.example.com").is_none());
    assert!(NoProxyRule::parse("api example.com").is_none());
    assert!(NoProxyRule::parse(r"api.example.com\v1").is_none());
}

#[test]
fn no_proxy_rule_rejects_unsupported_wildcard_globs() {
    assert!(NoProxyRule::parse("*example.com").is_none());
    assert!(NoProxyRule::parse("api.*.example.com").is_none());
    assert!(NoProxyRule::parse("example.*").is_none());
}

#[test]
fn no_proxy_rule_rejects_url_with_non_http_scheme() {
    assert!(NoProxyRule::parse("ftp://api.example.com").is_none());
    assert!(NoProxyRule::parse("socks5://api.example.com:1080").is_none());
}

#[test]
fn no_proxy_rule_rejects_malformed_http_url_shapes() {
    assert!(NoProxyRule::parse("http:/api.example.com").is_none());
    assert!(NoProxyRule::parse("https:api.example.com").is_none());
}

#[test]
fn no_proxy_rule_rejects_url_with_invalid_authority() {
    assert!(NoProxyRule::parse("https://api.example.com:invalid").is_none());
}

#[test]
fn no_proxy_rule_rejects_url_with_empty_port() {
    assert!(NoProxyRule::parse("https://api.example.com:/").is_none());
    assert!(NoProxyRule::parse("https:///api.example.com").is_none());
}
