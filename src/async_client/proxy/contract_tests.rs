use super::normalize_tunnel_target_uri;

#[test]
fn normalize_tunnel_target_uri_sets_https_default_port() {
    let uri: http::Uri = "https://api.example.com/v1/users"
        .parse()
        .expect("uri should parse");
    let normalized = normalize_tunnel_target_uri(uri);
    assert_eq!(
        normalized.to_string(),
        "https://api.example.com:443/v1/users"
    );
}

#[test]
fn normalize_tunnel_target_uri_sets_http_default_port() {
    let uri: http::Uri = "http://api.example.com/v1/users"
        .parse()
        .expect("uri should parse");
    let normalized = normalize_tunnel_target_uri(uri);
    assert_eq!(normalized.to_string(), "http://api.example.com:80/v1/users");
}

#[test]
fn normalize_tunnel_target_uri_keeps_explicit_port() {
    let uri: http::Uri = "https://api.example.com:9443/v1/users"
        .parse()
        .expect("uri should parse");
    let normalized = normalize_tunnel_target_uri(uri);
    assert_eq!(
        normalized.to_string(),
        "https://api.example.com:9443/v1/users"
    );
}

#[test]
fn normalize_tunnel_target_uri_handles_uppercase_scheme() {
    let uri: http::Uri = "HTTPS://api.example.com/v1/users"
        .parse()
        .expect("uri should parse");
    let normalized = normalize_tunnel_target_uri(uri);
    assert_eq!(normalized.host(), Some("api.example.com"));
    assert_eq!(normalized.port_u16(), Some(443));
    assert!(
        normalized
            .scheme_str()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
    );
}
