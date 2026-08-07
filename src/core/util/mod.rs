mod backoff;
mod headers;
mod io;
mod redaction;
mod redirect;
mod timing;
mod transport_error;
mod uri;

pub(crate) use backoff::{clamp_f64_or_fallback, exponential_backoff_with_jitter};
#[cfg(feature = "_async")]
pub(crate) use headers::ensure_accept_encoding_async;
#[cfg(feature = "_blocking")]
pub(crate) use headers::ensure_accept_encoding_blocking;
#[cfg(any(test, feature = "_async", feature = "_blocking"))]
pub(crate) use headers::validate_request_framing_headers;
#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) use headers::{
    mark_sensitive_header_value, mark_sensitive_headers, parse_header_name, parse_header_value,
};
pub(crate) use headers::{merge_headers, truncate_body};
#[cfg(all(feature = "_async", feature = "resumable-upload"))]
pub(crate) use io::read_async_retry_interrupted;
#[cfg(any(
    test,
    feature = "_blocking",
    feature = "compression-gzip",
    feature = "compression-brotli",
    feature = "compression-zstd",
    feature = "resumable-upload"
))]
pub(crate) use io::read_retry_interrupted;
pub(crate) use io::{lock_unpoisoned, normalize_usize_at_least_one};
pub(crate) use redaction::{
    redact_uri_for_logs, redact_uri_like_text_for_logs, redact_uri_without_url_normalization,
};
pub(crate) use redirect::{
    default_port, is_redirect_status, rate_limit_bucket_key, redirect_location, redirect_method,
    resolve_redirect_uri, same_origin, sanitize_headers_for_redirect,
};
#[cfg(feature = "_async")]
pub(crate) use timing::duration_millis_u64_saturating;
pub(crate) use timing::{
    bounded_retry_delay, deadline_exceeded_error, duration_from_secs_f64_saturating,
    duration_millis_ceil, parse_retry_after, parse_retry_after_capped, phase_timeout,
    total_timeout_deadline, total_timeout_expired,
};
#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) use timing::{duration_from_millis_saturating, saturating_u64_to_usize};
#[cfg(any(
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
pub(crate) use transport_error::classify_transport_error;
#[cfg(feature = "_blocking")]
pub(crate) use transport_error::is_timeout_io_error;
#[cfg(all(test, feature = "_async"))]
pub(crate) use transport_error::{
    classify_transport_error_source_for_test, classify_transport_error_text_for_test,
};
#[cfg(all(test, feature = "_async"))]
pub(crate) use uri::join_base_path;
#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) use uri::validate_http_proxy_uri;
pub(crate) use uri::{
    append_query_pairs, is_valid_absolute_http_uri_text, normalize_host_key, resolve_uri,
    validate_base_url,
};

#[cfg(test)]
mod property_tests;
