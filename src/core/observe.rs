use std::time::Duration;

use crate::core::policy::RequestContext;
use crate::core::retry::RetryDecision;
use crate::rate_limit::ServerThrottleScope;

/// Passive observer for request attempt, retry, and throttling events.
///
/// Callbacks run synchronously in registration order, possibly concurrently
/// across client clones. `on_request_start` is per attempt, not once per logical
/// request. Response-stream completion is tracked in metrics, not a completion
/// callback on this trait. Keep callbacks short and handle returned request/stream
/// errors separately. Panics are not caught.
///
/// ```
/// # #[cfg(feature = "_async")]
/// # fn example() -> reqx::Result<()> {
/// use std::sync::Arc;
/// use reqx::advanced::{Observer, RequestContext};
/// struct TraceAttempts;
/// impl Observer for TraceAttempts {
///     fn on_request_start(&self, context: &RequestContext) {
///         eprintln!("attempt={} uri={}", context.attempt(), context.uri());
///     }
/// }
/// let client = reqx::Client::builder("https://example.com")
///     .observer(Arc::new(TraceAttempts))
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub trait Observer: Send + Sync {
    /// Called when a request attempt starts.
    fn on_request_start(&self, _context: &RequestContext) {}

    /// Called when a retry has been scheduled.
    fn on_retry_scheduled(
        &self,
        _context: &RequestContext,
        _decision: &RetryDecision,
        _delay: Duration,
    ) {
    }

    /// Called when the client honors a server throttling hint.
    fn on_server_throttle(
        &self,
        _context: &RequestContext,
        _scope: ServerThrottleScope,
        _delay: Duration,
    ) {
    }
}
