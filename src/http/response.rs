use bytes::Bytes;
#[cfg(any(feature = "_async", feature = "_blocking"))]
use http::Method;
#[cfg(any(feature = "_async", feature = "_blocking"))]
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH};
use http::{HeaderMap, StatusCode};
use serde::de::DeserializeOwned;
#[cfg(any(feature = "_async", feature = "_blocking"))]
use std::io;
#[cfg(any(feature = "_async", feature = "_blocking"))]
use std::time::{Duration, Instant};

use crate::core::error::Error;
use crate::core::util::truncate_body;

#[derive(Clone)]
/// Fully buffered HTTP response body and metadata.
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Response")
            .field("status", &self.status)
            .field("headers_len", &self.headers.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl Response {
    pub(crate) fn new(status: StatusCode, headers: HeaderMap, body: Bytes) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    /// Returns the HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the raw response body bytes.
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Interprets the buffered body as UTF-8 text.
    pub fn text(&self) -> crate::Result<&str> {
        std::str::from_utf8(&self.body).map_err(|source| Error::DecodeText {
            source,
            body: truncate_body(&self.body),
        })
    }

    /// Decodes the buffered body as lossy UTF-8 text.
    pub fn text_lossy(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Consumes the response and decodes its body as UTF-8 text.
    ///
    /// Reuses the body allocation when it is uniquely owned and reusable.
    pub fn into_text(self) -> crate::Result<String> {
        String::from_utf8(self.body.into()).map_err(|source| Error::DecodeText {
            source: source.utf8_error(),
            body: truncate_body(source.as_bytes()),
        })
    }

    /// Consumes the response and decodes its body as lossy UTF-8 text.
    pub fn into_text_lossy(self) -> String {
        String::from_utf8_lossy_owned(self.body.into())
    }

    /// Deserializes the buffered body from JSON.
    pub fn json<T>(&self) -> crate::Result<T>
    where
        T: DeserializeOwned,
    {
        serde_json::from_slice(&self.body).map_err(|source| Error::DeserializeJson {
            source,
            body: truncate_body(&self.body),
        })
    }
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) fn deadline_elapsed(deadline_at: Instant, now: Instant) -> bool {
    now >= deadline_at
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) fn deadline_limits_wait(
    phase_timeout: Duration,
    deadline_at: Instant,
    now: Instant,
) -> bool {
    deadline_at.saturating_duration_since(now) <= phase_timeout
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) fn deadline_within_slack(
    deadline_at: Instant,
    now: Instant,
    deadline_slack: Duration,
) -> bool {
    deadline_at.saturating_duration_since(now) <= deadline_slack
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
fn stream_read_io_error_kind(error: &Error) -> io::ErrorKind {
    #[cfg(any(feature = "_async", feature = "_blocking"))]
    fn io_error_kind_in_chain(error: &(dyn std::error::Error + 'static)) -> Option<io::ErrorKind> {
        let mut current = Some(error);
        while let Some(source) = current {
            if let Some(io_error) = source.downcast_ref::<io::Error>() {
                return Some(io_error.kind());
            }
            current = source.source();
        }
        None
    }

    #[cfg(feature = "_async")]
    fn async_stream_error_kind(error: &(dyn std::error::Error + 'static)) -> Option<io::ErrorKind> {
        if let Some(kind) = io_error_kind_in_chain(error) {
            return Some(kind);
        }

        let hyper_error = error.downcast_ref::<hyper::Error>()?;
        if hyper_error.is_timeout() {
            return Some(io::ErrorKind::TimedOut);
        }
        if hyper_error.is_incomplete_message()
            || hyper_error.is_closed()
            || hyper_error.is_shutdown()
        {
            return Some(io::ErrorKind::UnexpectedEof);
        }
        if hyper_error.is_body_write_aborted() {
            return Some(io::ErrorKind::BrokenPipe);
        }

        None
    }

    match error {
        Error::Timeout { .. } | Error::DeadlineExceeded { .. } => io::ErrorKind::TimedOut,
        Error::ReadBody { source } => {
            #[cfg(feature = "_async")]
            if let Some(kind) = async_stream_error_kind(source.as_ref()) {
                return kind;
            }

            io_error_kind_in_chain(source.as_ref()).unwrap_or(io::ErrorKind::Other)
        }
        Error::WriteBody { source, .. } => {
            io_error_kind_in_chain(source.as_ref()).unwrap_or(io::ErrorKind::Other)
        }
        _ => io::ErrorKind::Other,
    }
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(super) fn into_stream_read_io_error(error: Error) -> io::Error {
    let kind = stream_read_io_error_kind(&error);
    io::Error::new(kind, error)
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(super) fn write_body_error<E>(method: &Method, uri: &str, source: E) -> Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    Error::WriteBody {
        method: method.clone(),
        uri: uri.to_owned(),
        source: Box::new(source),
    }
}

#[cfg(feature = "_async")]
mod async_stream;
#[cfg(feature = "_blocking")]
mod blocking_stream;

#[cfg(feature = "_async")]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-rustls-graviola",
        feature = "async-tls-rustls-no-provider",
        feature = "async-tls-native"
    )))
)]
pub use async_stream::ResponseStream;
#[cfg(feature = "_async")]
pub(crate) use async_stream::ResponseStreamContext;
#[cfg(feature = "_blocking")]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "blocking-tls-rustls-ring",
        feature = "blocking-tls-rustls-aws-lc-rs",
        feature = "blocking-tls-rustls-graviola",
        feature = "blocking-tls-rustls-no-provider",
        feature = "blocking-tls-native"
    )))
)]
pub use blocking_stream::BlockingResponseStream;
#[cfg(feature = "_blocking")]
pub(crate) use blocking_stream::BlockingResponseStreamContext;

#[cfg(test)]
mod contract_tests;
