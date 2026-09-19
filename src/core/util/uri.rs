use http::Uri;

use crate::error::Error;

use super::redaction::{redact_uri_for_logs, redact_uri_without_url_normalization};

fn invalid_base_url_error(base_url: &str) -> Error {
    Error::InvalidUri {
        uri: redact_uri_for_logs(base_url),
    }
}

fn invalid_proxy_uri_error(proxy_uri: &Uri, message: impl Into<String>) -> Error {
    Error::InvalidProxyConfig {
        proxy_uri: redact_uri_for_logs(&proxy_uri.to_string()),
        message: message.into(),
    }
}

pub(super) fn uri_has_userinfo(uri: &Uri) -> bool {
    uri.authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
}

pub(crate) fn normalize_host_key(host: &str) -> Option<String> {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    Some(normalized)
}

pub(super) fn normalized_uri_host(uri: &Uri) -> Option<String> {
    normalize_host_key(uri.host()?)
}

pub(super) fn looks_like_malformed_http_absolute_uri(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http:"))
        || bytes
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https:"))
}

fn has_valid_raw_http_authority_syntax(uri_text: &str, allow_network_path_reference: bool) -> bool {
    let bytes = uri_text.as_bytes();
    let prefix_len = if bytes
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http://"))
    {
        7
    } else if bytes
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https://"))
    {
        8
    } else if allow_network_path_reference && uri_text.starts_with("//") {
        2
    } else {
        return false;
    };

    let remainder = &uri_text[prefix_len..];
    if remainder.is_empty() || remainder.starts_with('/') {
        return false;
    }

    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() {
        return false;
    }

    let host_port = authority
        .rsplit_once('@')
        .map(|(_, host_port)| host_port)
        .unwrap_or(authority);
    if host_port.is_empty() {
        return false;
    }

    if let Some(stripped) = host_port.strip_prefix('[') {
        let Some(end) = stripped.find(']') else {
            return false;
        };
        if end == 0 {
            return false;
        }
        let suffix = &stripped[end + 1..];
        return suffix.is_empty()
            || suffix.strip_prefix(':').is_some_and(|port| {
                !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit())
            });
    }

    if host_port.starts_with('.') {
        return false;
    }
    if host_port.matches(':').count() > 1 {
        return false;
    }
    if let Some((host, port)) = host_port.rsplit_once(':') {
        return !host.is_empty() && !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit());
    }
    true
}

pub(super) fn is_valid_http_network_path_reference(uri_text: &str) -> bool {
    has_valid_raw_http_authority_syntax(uri_text, true)
}

pub(crate) fn is_valid_absolute_http_uri_text(uri_text: &str) -> bool {
    if !has_valid_raw_http_authority_syntax(uri_text, false) {
        return false;
    }

    let Ok(parsed) = url::Url::parse(uri_text) else {
        return false;
    };
    matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some()
}

pub(crate) fn resolve_uri(base_url: &str, path: &str) -> Result<(String, Uri), Error> {
    let uri_text = match path.parse::<Uri>() {
        Ok(uri) if uri.host().is_some() => {
            let Some(scheme) = uri.scheme_str() else {
                return Err(Error::InvalidUri {
                    uri: redact_uri_without_url_normalization(path),
                });
            };
            if uri_has_userinfo(&uri) {
                return Err(Error::InvalidUri {
                    uri: redact_uri_for_logs(path),
                });
            }
            if (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
                && is_valid_absolute_http_uri_text(path)
            {
                path.to_owned()
            } else {
                return Err(Error::InvalidUri {
                    uri: redact_uri_for_logs(path),
                });
            }
        }
        Ok(uri) if uri.scheme_str().is_some() => {
            return Err(Error::InvalidUri {
                uri: redact_uri_for_logs(path),
            });
        }
        Err(_) if looks_like_malformed_http_absolute_uri(path) => {
            return Err(Error::InvalidUri {
                uri: redact_uri_without_url_normalization(path),
            });
        }
        _ => join_base_path(base_url, path),
    };
    let uri = uri_text.parse().map_err(|_| Error::InvalidUri {
        uri: redact_uri_for_logs(&uri_text),
    })?;
    if uri_has_userinfo(&uri) {
        return Err(Error::InvalidUri {
            uri: redact_uri_for_logs(&uri_text),
        });
    }
    Ok((uri_text, uri))
}

pub(crate) fn validate_base_url(base_url: &str) -> Result<(), Error> {
    let normalized = base_url.trim();
    if normalized.len() != base_url.len() {
        return Err(invalid_base_url_error(base_url));
    }
    if normalized.is_empty() {
        return Err(invalid_base_url_error(base_url));
    }

    let parsed = url::Url::parse(normalized).map_err(|_| invalid_base_url_error(base_url))?;
    let scheme = parsed.scheme();
    if !matches!(scheme, "http" | "https") {
        return Err(invalid_base_url_error(base_url));
    }
    if parsed.host_str().is_none() {
        return Err(invalid_base_url_error(base_url));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid_base_url_error(base_url));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid_base_url_error(base_url));
    }
    if !is_valid_absolute_http_uri_text(normalized) {
        return Err(invalid_base_url_error(base_url));
    }

    let uri = normalized
        .parse::<Uri>()
        .map_err(|_| invalid_base_url_error(base_url))?;
    if uri.scheme_str().is_none() || uri.host().is_none() {
        return Err(invalid_base_url_error(base_url));
    };

    Ok(())
}

pub(crate) fn validate_http_proxy_uri(proxy_uri: &Uri) -> Result<(), Error> {
    let Some(scheme) = proxy_uri.scheme_str() else {
        return Err(invalid_proxy_uri_error(
            proxy_uri,
            "http_proxy URI must include an explicit scheme",
        ));
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(invalid_proxy_uri_error(
            proxy_uri,
            "http_proxy URI must use http scheme",
        ));
    }
    if proxy_uri.host().is_none() {
        return Err(invalid_proxy_uri_error(
            proxy_uri,
            "http_proxy URI must include host",
        ));
    }
    if let Some(path_and_query) = proxy_uri.path_and_query() {
        let path = path_and_query.path();
        if !path.is_empty() && path != "/" {
            return Err(invalid_proxy_uri_error(
                proxy_uri,
                "http_proxy URI must not include path segments",
            ));
        }
        if path_and_query.query().is_some() {
            return Err(invalid_proxy_uri_error(
                proxy_uri,
                "http_proxy URI must not include query parameters",
            ));
        }
    }
    if !is_valid_absolute_http_uri_text(&proxy_uri.to_string()) {
        return Err(invalid_proxy_uri_error(
            proxy_uri,
            "http_proxy URI must include a valid authority and numeric port",
        ));
    }
    Ok(())
}

pub(crate) fn append_query_pairs(path: &str, query_pairs: &[(String, String)]) -> String {
    if query_pairs.is_empty() {
        return path.to_owned();
    }

    // Only encode new pairs. Re-parsing the existing query would change escapes,
    // bare keys and non-UTF-8 bytes, and URL parsing would also normalize the path.
    let (prefix, fragment) = path
        .split_once('#')
        .map_or((path, None), |(prefix, fragment)| (prefix, Some(fragment)));
    let mut merged = prefix.to_owned();
    match prefix.split_once('?') {
        None => merged.push('?'),
        Some((_, query)) if !query.is_empty() && !query.ends_with('&') => merged.push('&'),
        _ => {}
    }
    let appended = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(query_pairs.iter().map(|(name, value)| (name, value)))
        .finish();
    merged.push_str(&appended);
    if let Some(fragment) = fragment {
        merged.push('#');
        merged.push_str(fragment);
    }
    merged
}

pub(crate) fn join_base_path(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if let Some(suffix) = path.strip_prefix('?') {
        return if base.is_empty() {
            format!("?{suffix}")
        } else {
            format!("{base}?{suffix}")
        };
    }
    if let Some(suffix) = path.strip_prefix('#') {
        return if base.is_empty() {
            format!("#{suffix}")
        } else {
            format!("{base}#{suffix}")
        };
    }
    let relative = path.strip_prefix('/').unwrap_or(path);
    match (base.is_empty(), relative.is_empty()) {
        (true, true) => String::new(),
        (true, false) => relative.to_owned(),
        (false, true) => base.to_owned(),
        (false, false) => format!("{base}/{relative}"),
    }
}
