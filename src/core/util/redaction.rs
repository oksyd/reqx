use super::uri::is_valid_absolute_http_uri_text;

fn strip_query_and_fragment(uri_text: &str) -> &str {
    let query_index = uri_text.find('?');
    let fragment_index = uri_text.find('#');
    let cutoff = match (query_index, fragment_index) {
        (Some(query), Some(fragment)) => query.min(fragment),
        (Some(query), None) => query,
        (None, Some(fragment)) => fragment,
        (None, None) => uri_text.len(),
    };
    &uri_text[..cutoff]
}

pub(crate) fn redact_uri_without_url_normalization(uri_text: &str) -> String {
    let stripped = strip_query_and_fragment(uri_text);
    let authority_redacted = redact_userinfo_in_authority(stripped);
    redact_non_authority_credentials(&authority_redacted)
}

fn redact_userinfo_in_authority(uri_text: &str) -> String {
    fn redact_with_prefix(prefix: &str, rest: &str) -> Option<String> {
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let (authority, suffix) = rest.split_at(authority_end);
        let at_index = authority.rfind('@')?;
        let host_port = &authority[at_index + 1..];
        if host_port.is_empty() {
            return Some(format!("{prefix}<redacted>@{suffix}"));
        }
        Some(format!("{prefix}{host_port}{suffix}"))
    }

    if let Some(scheme_separator) = uri_text.find("://") {
        let prefix_end = scheme_separator + 3;
        let (prefix, rest) = uri_text.split_at(prefix_end);
        if let Some(redacted) = redact_with_prefix(prefix, rest) {
            return redacted;
        }
        return uri_text.to_owned();
    }

    if let Some(rest) = uri_text.strip_prefix("//")
        && let Some(redacted) = redact_with_prefix("//", rest)
    {
        return redacted;
    }

    uri_text.to_owned()
}

fn redact_non_authority_credentials(uri_text: &str) -> String {
    let Some((scheme, remainder)) = uri_text.split_once(':') else {
        return uri_text.to_owned();
    };
    let redactable_scheme = matches!(
        scheme.to_ascii_lowercase().as_str(),
        "mailto" | "sip" | "sips"
    );
    if !redactable_scheme {
        return uri_text.to_owned();
    }
    if remainder.starts_with("//") {
        return uri_text.to_owned();
    }

    let Some(at_index) = remainder.rfind('@') else {
        return uri_text.to_owned();
    };
    let credential_like_prefix = &remainder[..at_index];
    if credential_like_prefix.is_empty() {
        return uri_text.to_owned();
    }
    if !credential_like_prefix.contains(':')
        && !credential_like_prefix.to_ascii_lowercase().contains("%3a")
    {
        return uri_text.to_owned();
    }

    let suffix = &remainder[at_index + 1..];
    format!("{scheme}:<redacted>@{suffix}")
}

fn is_token_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '~' | '+' | '=')
}

fn is_token_like(segment: &str) -> bool {
    !segment.is_empty() && segment.chars().all(is_token_char)
}

fn credential_separator(segment: &str) -> Option<(usize, usize)> {
    let plain = segment.find(':').map(|index| (index, 1));
    let lower = segment.to_ascii_lowercase();
    let encoded = lower.find("%3a").map(|index| (index, 3));

    match (plain, encoded) {
        (Some(plain), Some(encoded)) => Some(if plain.0 <= encoded.0 { plain } else { encoded }),
        (Some(separator), None) | (None, Some(separator)) => Some(separator),
        (None, None) => None,
    }
}

fn split_credential_like_segment(segment: &str) -> Option<(&str, &str)> {
    let (separator_index, separator_len) = credential_separator(segment)?;
    let left = &segment[..separator_index];
    let right = &segment[separator_index + separator_len..];
    if left.is_empty() || right.is_empty() {
        return None;
    }
    if left.len() < 3 || right.len() < 6 {
        return None;
    }
    if !is_token_like(left) || !is_token_like(right) {
        return None;
    }
    Some((left, right))
}

fn redact_sensitive_path_segments(parsed: &mut url::Url) {
    let Some(mut path_segments) = parsed
        .path_segments()
        .map(|segments| segments.map(ToOwned::to_owned).collect::<Vec<_>>())
    else {
        return;
    };
    if path_segments.is_empty() {
        return;
    }

    let mut redacted = false;
    for segment in &mut path_segments {
        if let Some((left, _)) = split_credential_like_segment(segment) {
            *segment = format!("{left}:redacted");
            redacted = true;
        }
    }
    if !redacted {
        return;
    }

    let has_trailing_slash = parsed.path().ends_with('/');
    let mut rebuilt_path = String::new();
    for segment in &path_segments {
        rebuilt_path.push('/');
        rebuilt_path.push_str(segment);
    }
    if rebuilt_path.is_empty() || (has_trailing_slash && !rebuilt_path.ends_with('/')) {
        rebuilt_path.push('/');
    }
    parsed.set_path(&rebuilt_path);
}

pub(crate) fn redact_uri_for_logs(uri_text: &str) -> String {
    let bytes = uri_text.as_bytes();
    let looks_like_http_absolute = bytes
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http://"))
        || bytes
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https://"));
    if looks_like_http_absolute && !is_valid_absolute_http_uri_text(uri_text) {
        return redact_uri_without_url_normalization(uri_text);
    }

    let Ok(mut parsed) = url::Url::parse(uri_text) else {
        return redact_uri_without_url_normalization(uri_text);
    };

    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    redact_sensitive_path_segments(&mut parsed);

    let serialized = parsed.to_string();
    let authority_redacted = redact_userinfo_in_authority(&serialized);
    redact_non_authority_credentials(&authority_redacted)
}

fn find_uri_like_start(lower: &str, offset: usize) -> Option<(usize, usize)> {
    ["https://", "http://", "mailto:", "sips:", "sip:"]
        .into_iter()
        .filter_map(|pattern| {
            lower
                .get(offset..)?
                .find(pattern)
                .map(|index| (offset + index, pattern.len()))
        })
        .min_by_key(|(index, _)| *index)
}

fn uri_like_span_end(core: &str, lower: &str, uri_start: usize, pattern_len: usize) -> usize {
    let Some((next_uri_start, _)) = find_uri_like_start(lower, uri_start + pattern_len) else {
        return core.len();
    };

    core[uri_start..next_uri_start]
        .char_indices()
        .rev()
        .find_map(|(index, character)| {
            matches!(character, ',' | ';' | '|').then_some(uri_start + index)
        })
        .unwrap_or(next_uri_start)
}

fn redact_uri_like_core_for_logs(core: &str) -> String {
    let lower = core.to_ascii_lowercase();
    let mut redacted = String::with_capacity(core.len());
    let mut copied_until = 0;
    let mut search_from = 0;

    while let Some((uri_start, pattern_len)) = find_uri_like_start(&lower, search_from) {
        redacted.push_str(&core[copied_until..uri_start]);
        let uri_end = uri_like_span_end(core, &lower, uri_start, pattern_len);
        redacted.push_str(&redact_uri_for_logs(&core[uri_start..uri_end]));
        copied_until = uri_end;
        search_from = uri_end;
    }

    redacted.push_str(&core[copied_until..]);
    redacted
}

fn redact_uri_like_token_for_logs(token: &str) -> String {
    const LEADING_PUNCTUATION: &[char] = &['(', '[', '{', '<', '"', '\''];
    const TRAILING_PUNCTUATION: &[char] = &[')', ']', '}', '>', '"', '\'', ',', ';'];

    let leading_len = token
        .char_indices()
        .find_map(|(index, character)| (!LEADING_PUNCTUATION.contains(&character)).then_some(index))
        .unwrap_or(token.len());
    let (leading, without_leading) = token.split_at(leading_len);

    let trailing_start = without_leading
        .char_indices()
        .rev()
        .find_map(|(index, character)| {
            (!TRAILING_PUNCTUATION.contains(&character)).then_some(index + character.len_utf8())
        })
        .unwrap_or(0);
    let (core, trailing) = without_leading.split_at(trailing_start);

    if find_uri_like_start(&core.to_ascii_lowercase(), 0).is_none() {
        return token.to_owned();
    }

    format!("{leading}{}{trailing}", redact_uri_like_core_for_logs(core))
}

pub(crate) fn redact_uri_like_text_for_logs(text: &str) -> String {
    let mut redacted = String::with_capacity(text.len());
    for token in text.split_inclusive(char::is_whitespace) {
        let trim_len = token.trim_end_matches(char::is_whitespace).len();
        let (body, whitespace) = token.split_at(trim_len);
        redacted.push_str(&redact_uri_like_token_for_logs(body));
        redacted.push_str(whitespace);
    }
    redacted
}
