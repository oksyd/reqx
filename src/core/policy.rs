use http::{HeaderMap, Method, StatusCode};

use crate::core::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Redirect handling policy with a logical-request hop limit.
///
/// Disabled by default. Follows 301, 302, 303, 307, and 308 up to the configured
/// hop limit. POST changes to GET for 301/302; 303 changes non-HEAD methods to GET.
/// These rewrites drop the body. Other cases preserve method/body and require a
/// replayable body; a consumed reader/stream returns `Error::RedirectBodyNotReplayable`.
///
/// Sensitive/hop-scoped credentials are removed when crossing origins. Custom
/// sensitive header values must be marked sensitive. The policy does not restrict
/// redirects to a caller allowlist; disable following and validate destinations
/// yourself when that is required. Retry attempts and redirect hops have separate
/// counters; the original total deadline covers both.
pub struct RedirectPolicy {
    max_redirects: usize,
}

impl RedirectPolicy {
    /// Disables automatic redirect following.
    pub const fn none() -> Self {
        Self { max_redirects: 0 }
    }

    /// Follows redirects up to `max_redirects`.
    pub const fn limited(max_redirects: usize) -> Self {
        Self { max_redirects }
    }

    /// Follows redirects with the default limit of 10 hops.
    pub const fn follow() -> Self {
        Self::limited(10)
    }

    /// Returns whether redirect following is enabled.
    pub const fn enabled(self) -> bool {
        self.max_redirects > 0
    }

    /// Returns the configured redirect limit.
    pub const fn max_redirects(self) -> usize {
        self.max_redirects
    }
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self::none()
    }
}

#[cfg(test)]
mod tests {
    use super::RedirectPolicy;

    #[test]
    fn redirect_policy_limited_zero_is_equivalent_to_none() {
        let policy = RedirectPolicy::limited(0);
        assert!(!policy.enabled());
        assert_eq!(policy.max_redirects(), 0);
        assert_eq!(policy, RedirectPolicy::none());
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
/// How final HTTP statuses should be surfaced to the caller.
///
/// Retryable statuses are handled first, regardless of this policy. `Error`
/// accepts only 2xx; `Response` also returns final non-2xx statuses as `Ok`.
/// Neither changes body decoding, size bounds, transport errors, or deadlines.
/// A retryable non-2xx response still counts as a resilience failure when returned
/// under `Response`. With redirects disabled, 3xx responses follow this policy.
pub enum StatusPolicy {
    #[default]
    /// Treat non-success statuses as [`Error::HttpStatus`](crate::Error::HttpStatus).
    Error,
    /// Return HTTP status responses without converting them into errors.
    Response,
}

impl StatusPolicy {
    /// Returns `true` when non-success statuses are converted into errors.
    pub const fn is_error(self) -> bool {
        matches!(self, Self::Error)
    }
}

#[derive(Clone, Debug)]
/// Immutable request metadata passed to interceptors and observers.
pub struct RequestContext {
    method: Method,
    uri: String,
    attempt: usize,
    max_attempts: usize,
    redirect_count: usize,
}

impl RequestContext {
    pub(crate) fn new(
        method: Method,
        uri: String,
        attempt: usize,
        max_attempts: usize,
        redirect_count: usize,
    ) -> Self {
        Self {
            method,
            uri,
            attempt,
            max_attempts,
            redirect_count,
        }
    }

    /// Returns the request method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the request URI with the crate's redaction rules applied.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Returns the retry attempt number, starting at `1`.
    ///
    /// Followed redirects keep this number and increment [`Self::redirect_count`].
    /// A scheduled retry increments this number; it is not a count of every hop.
    pub fn attempt(&self) -> usize {
        self.attempt
    }

    /// Returns the maximum number of attempts allowed for this request.
    pub fn max_attempts(&self) -> usize {
        self.max_attempts
    }

    /// Returns how many redirects have already been followed.
    pub fn redirect_count(&self) -> usize {
        self.redirect_count
    }
}

/// Active hook for mutating or observing request attempts.
///
/// Registered hooks run synchronously, in registration order, for each transport
/// attempt (including retries and followed redirects). They can be called
/// concurrently by client clones and should not block an async executor.
/// Request hooks mutate headers; response hooks observe status/headers before
/// buffering or decoding, including responses that will be retried or redirected.
///
/// Error hooks cover terminal errors emitted by the attempt driver. Preparation
/// errors, global queue errors before attempts, returned stream I/O, and later
/// JSON/text conversions are handled through their returned results instead.
/// Callbacks do not replace transport error handling. Panics are not caught.
///
/// The header example requires `http` as an application dependency.
///
/// ```
/// # #[cfg(feature = "_async")]
/// # fn example() -> reqx::Result<()> {
/// use std::sync::Arc;
/// use reqx::advanced::{Interceptor, RequestContext};
/// struct AcceptJson;
/// impl Interceptor for AcceptJson {
///     fn on_request(&self, _: &RequestContext, headers: &mut http::HeaderMap) {
///         headers.insert(http::header::ACCEPT, http::HeaderValue::from_static("application/json"));
///     }
/// }
/// let client = reqx::Client::builder("https://example.com")
///     .interceptor(Arc::new(AcceptJson))
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub trait Interceptor: Send + Sync {
    /// Called before a request is sent. Interceptors may mutate headers.
    ///
    /// Removing headers required by the active retry eligibility policy disables
    /// subsequent retries. Adding headers does not expand the eligibility decided
    /// during request preparation.
    fn on_request(&self, _context: &RequestContext, _headers: &mut HeaderMap) {}

    /// Called after a response status and headers are received.
    fn on_response(&self, _context: &RequestContext, _status: StatusCode, _headers: &HeaderMap) {}

    /// Called when request execution ends in an error.
    fn on_error(&self, _context: &RequestContext, _error: &Error) {}
}
