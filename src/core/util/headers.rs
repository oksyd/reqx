use http::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, COOKIE, HeaderName, HeaderValue,
    PROXY_AUTHORIZATION, SET_COOKIE, TRANSFER_ENCODING,
};
use http::{HeaderMap, Method};

use crate::error::Error;

const MAX_ERROR_BODY_LEN: usize = 2048;

pub(crate) fn merge_headers(default_headers: &HeaderMap, request_headers: &HeaderMap) -> HeaderMap {
    let mut merged = default_headers.clone();
    for (name, value) in request_headers {
        merged.insert(name.clone(), value.clone());
    }
    merged
}

fn enabled_accept_encoding() -> Option<&'static str> {
    match (
        cfg!(feature = "compression-gzip"),
        cfg!(feature = "compression-brotli"),
        cfg!(feature = "compression-zstd"),
    ) {
        (true, true, true) => Some("gzip, br, deflate, zstd"),
        (true, true, false) => Some("gzip, br, deflate"),
        (true, false, true) => Some("gzip, deflate, zstd"),
        (true, false, false) => Some("gzip, deflate"),
        (false, true, true) => Some("br, zstd"),
        (false, true, false) => Some("br"),
        (false, false, true) => Some("zstd"),
        (false, false, false) => None,
    }
}

fn ensure_accept_encoding(method: &Method, headers: &mut HeaderMap) {
    // Byte ranges refer to the encoded representation. Automatically negotiating
    // compression can turn an ordinary range into a fragment we cannot decode.
    if *method == Method::HEAD
        || headers.contains_key(ACCEPT_ENCODING)
        || headers.contains_key(http::header::RANGE)
    {
        return;
    }
    if let Some(value) = enabled_accept_encoding() {
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(value));
    }
}

#[cfg(feature = "_async")]
pub(crate) fn ensure_accept_encoding_async(method: &Method, headers: &mut HeaderMap) {
    ensure_accept_encoding(method, headers);
}

#[cfg(feature = "_blocking")]
pub(crate) fn ensure_accept_encoding_blocking(method: &Method, headers: &mut HeaderMap) {
    ensure_accept_encoding(method, headers);
}

pub(crate) fn parse_header_name(name: &str) -> Result<HeaderName, Error> {
    name.parse().map_err(|source| Error::InvalidHeaderName {
        name: name.to_owned(),
        source,
    })
}

fn is_sensitive_header_name(name: &HeaderName) -> bool {
    *name == AUTHORIZATION || *name == COOKIE || *name == PROXY_AUTHORIZATION || *name == SET_COOKIE
}

fn is_sensitive_header_name_text(name: &str) -> bool {
    let Ok(name) = name.parse::<HeaderName>() else {
        return false;
    };
    is_sensitive_header_name(&name)
}

pub(crate) fn mark_sensitive_header_value(name: &HeaderName, value: &mut HeaderValue) {
    if is_sensitive_header_name(name) {
        value.set_sensitive(true);
    }
}

pub(crate) fn mark_sensitive_headers(headers: &mut HeaderMap) {
    for (name, value) in headers.iter_mut() {
        mark_sensitive_header_value(name, value);
    }
}

pub(crate) fn parse_header_value(name: &str, value: &str) -> Result<HeaderValue, Error> {
    let mut value: HeaderValue = value.parse().map_err(|source| Error::InvalidHeaderValue {
        name: name.to_owned(),
        source,
    })?;
    if is_sensitive_header_name_text(name) {
        value.set_sensitive(true);
    }
    Ok(value)
}

pub(crate) fn validate_request_framing_headers(
    headers: &HeaderMap,
    expected_body_len: Option<usize>,
    method: &Method,
    redacted_uri: &str,
) -> Result<(), Error> {
    if headers.contains_key(CONTENT_LENGTH) && headers.contains_key(TRANSFER_ENCODING) {
        return Err(Error::InvalidRequestFraming {
            method: method.clone(),
            uri: redacted_uri.to_owned(),
            message: "content-length and transfer-encoding cannot be combined",
        });
    }
    if headers.contains_key(TRANSFER_ENCODING) {
        return Err(Error::InvalidRequestFraming {
            method: method.clone(),
            uri: redacted_uri.to_owned(),
            message: "transfer-encoding is managed by the transport",
        });
    }

    let mut content_lengths = headers.get_all(CONTENT_LENGTH).iter();
    let Some(content_length) = content_lengths.next() else {
        return Ok(());
    };
    if content_lengths.next().is_some() {
        return Err(Error::InvalidRequestFraming {
            method: method.clone(),
            uri: redacted_uri.to_owned(),
            message: "content-length must contain exactly one value",
        });
    }

    let content_length = content_length
        .to_str()
        .ok()
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()));
    let Some(content_length) = content_length.and_then(|value| value.parse::<u64>().ok()) else {
        return Err(Error::InvalidRequestFraming {
            method: method.clone(),
            uri: redacted_uri.to_owned(),
            message: "content-length must be an unsigned decimal integer within the u64 range",
        });
    };
    if expected_body_len.is_some_and(|expected| u128::from(content_length) != expected as u128) {
        return Err(Error::InvalidRequestFraming {
            method: method.clone(),
            uri: redacted_uri.to_owned(),
            message: "content-length does not match the buffered request body",
        });
    }

    Ok(())
}

pub(crate) fn truncate_body(body: &[u8]) -> String {
    // One Unicode scalar consumes at most four input bytes. Include one extra
    // scalar to detect truncation without decoding or copying an entire body.
    let prefix = &body[..body.len().min((MAX_ERROR_BODY_LEN + 1) * 4)];
    let text = String::from_utf8_lossy(prefix);
    match text.char_indices().nth(MAX_ERROR_BODY_LEN) {
        Some((end, _)) => format!("{}...(truncated)", &text[..end]),
        None => text.into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use http::header::ACCEPT_ENCODING;
    use http::{HeaderMap, HeaderValue, Method};

    use super::ensure_accept_encoding;

    #[test]
    fn error_body_excerpt_handles_unicode_and_invalid_utf8_at_the_limit() {
        use super::{MAX_ERROR_BODY_LEN, truncate_body};
        for character in ["a", "é", "界", "🦀"] {
            let exact = character.repeat(MAX_ERROR_BODY_LEN);
            assert_eq!(truncate_body(exact.as_bytes()), exact);
            let mut longer = exact.clone();
            longer.push_str(character);
            assert_eq!(
                truncate_body(longer.as_bytes()),
                format!("{exact}...(truncated)")
            );
        }
        let invalid = vec![0xff; 64 * 1024];
        assert_eq!(
            truncate_body(&invalid),
            format!("{}...(truncated)", "�".repeat(MAX_ERROR_BODY_LEN))
        );
        assert_eq!(truncate_body(b""), "");
        assert_eq!(truncate_body(&[0xf0, 0x9f]), "�");
    }

    #[cfg(feature = "compression-gzip")]
    #[test]
    fn range_requests_do_not_implicitly_negotiate_compression() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::RANGE, HeaderValue::from_static("bytes=10-20"));
        ensure_accept_encoding(&Method::GET, &mut headers);
        assert!(!headers.contains_key(ACCEPT_ENCODING));
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        ensure_accept_encoding(&Method::GET, &mut headers);
        assert_eq!(headers[ACCEPT_ENCODING], "gzip");
    }

    #[test]
    fn advertised_encodings_match_enabled_codec_features() {
        let mut expected = Vec::new();
        if cfg!(feature = "compression-gzip") {
            expected.push("gzip");
        }
        if cfg!(feature = "compression-brotli") {
            expected.push("br");
        }
        if cfg!(feature = "compression-gzip") {
            expected.push("deflate");
        }
        if cfg!(feature = "compression-zstd") {
            expected.push("zstd");
        }

        let mut headers = HeaderMap::new();
        ensure_accept_encoding(&Method::GET, &mut headers);
        let actual = headers
            .get(ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok());
        let expected = (!expected.is_empty()).then(|| expected.join(", "));
        assert_eq!(actual, expected.as_deref());
    }

    #[test]
    fn automatic_encoding_never_overrides_explicit_or_head_requests() {
        let mut explicit = HeaderMap::new();
        explicit.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        ensure_accept_encoding(&Method::GET, &mut explicit);
        assert_eq!(
            explicit.get(ACCEPT_ENCODING),
            Some(&HeaderValue::from_static("identity"))
        );

        let mut head = HeaderMap::new();
        ensure_accept_encoding(&Method::HEAD, &mut head);
        assert!(!head.contains_key(ACCEPT_ENCODING));
    }
}
