use http::header::{
    AUTHORIZATION, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, EXPECT,
    HOST, HeaderName, LOCATION, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, Method, StatusCode, Uri};

use super::uri::{
    is_valid_absolute_http_uri_text, is_valid_http_network_path_reference,
    looks_like_malformed_http_absolute_uri, normalized_uri_host, uri_has_userinfo,
};

pub(crate) fn is_redirect_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

pub(crate) fn redirect_method(method: &Method, status: StatusCode) -> Method {
    match status {
        StatusCode::SEE_OTHER if *method != Method::HEAD => Method::GET,
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND if *method == Method::POST => Method::GET,
        _ => method.clone(),
    }
}

pub(crate) fn redirect_location(headers: &HeaderMap) -> Option<String> {
    headers
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

pub(crate) fn default_port(uri: &Uri) -> Option<u16> {
    uri.port_u16().or_else(|| {
        let scheme = uri.scheme_str()?;
        if scheme.eq_ignore_ascii_case("https") {
            return Some(443);
        }
        if scheme.eq_ignore_ascii_case("http") {
            return Some(80);
        }
        None
    })
}

pub(crate) fn rate_limit_bucket_key(uri: &Uri) -> Option<String> {
    let host = normalized_uri_host(uri)?;
    let Some(port) = default_port(uri) else {
        return Some(host);
    };
    if host.contains(':') && !host.starts_with('[') {
        return Some(format!("[{host}]:{port}"));
    }
    Some(format!("{host}:{port}"))
}

pub(crate) fn same_origin(left: &Uri, right: &Uri) -> bool {
    let left_scheme = left.scheme_str().unwrap_or_default();
    let right_scheme = right.scheme_str().unwrap_or_default();
    if !left_scheme.eq_ignore_ascii_case(right_scheme) {
        return false;
    }

    let Some(left_host) = normalized_uri_host(left) else {
        return false;
    };
    let Some(right_host) = normalized_uri_host(right) else {
        return false;
    };
    if left_host != right_host {
        return false;
    }

    default_port(left) == default_port(right)
}

fn remove_hop_by_hop_redirect_headers(headers: &mut HeaderMap) {
    let connection_scoped_headers: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| {
            let token = token.trim();
            if token.is_empty() {
                return None;
            }
            HeaderName::from_bytes(token.as_bytes()).ok()
        })
        .collect();
    for header_name in connection_scoped_headers {
        headers.remove(header_name);
    }

    headers.remove(CONNECTION);
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
    headers.remove(TE);
    headers.remove(TRAILER);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(UPGRADE);
}

pub(crate) fn resolve_redirect_uri(current_uri: &Uri, location: &str) -> Option<Uri> {
    match location.parse::<Uri>() {
        Ok(uri) if uri.host().is_some() => {
            if let Some(scheme) = uri.scheme_str() {
                if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
                    return None;
                }
                if uri_has_userinfo(&uri) || !is_valid_absolute_http_uri_text(location) {
                    return None;
                }
                return Some(uri);
            }
            if !location.starts_with("//") {
                return None;
            }
        }
        Ok(uri) if uri.scheme_str().is_some() => return None,
        Err(_) if looks_like_malformed_http_absolute_uri(location) => return None,
        _ => {}
    }
    if location.starts_with("//") && !is_valid_http_network_path_reference(location) {
        return None;
    }

    let base = url::Url::parse(&current_uri.to_string()).ok()?;
    let joined = base.join(location).ok()?;
    if !matches!(joined.scheme(), "http" | "https") {
        return None;
    }
    if !joined.username().is_empty() || joined.password().is_some() {
        return None;
    }
    let resolved: Uri = joined.as_str().parse().ok()?;
    if uri_has_userinfo(&resolved) {
        return None;
    }
    Some(resolved)
}

pub(crate) fn sanitize_headers_for_redirect(
    headers: &mut HeaderMap,
    drops_body: bool,
    same_origin_redirect: bool,
) {
    remove_hop_by_hop_redirect_headers(headers);
    headers.remove(HOST);
    if drops_body {
        headers.remove(CONTENT_ENCODING);
        headers.remove(CONTENT_LENGTH);
        headers.remove(CONTENT_TYPE);
        headers.remove("content-digest");
        headers.remove("content-md5");
        headers.remove("digest");
        headers.remove(EXPECT);
    }
    if !same_origin_redirect {
        headers.remove(AUTHORIZATION);
        headers.remove(COOKIE);
        let sensitive_headers = headers
            .iter()
            .filter(|(_, value)| value.is_sensitive())
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        for name in sensitive_headers {
            headers.remove(name);
        }
    }
    headers.remove(PROXY_AUTHORIZATION);
}

#[cfg(test)]
mod contract_tests;
