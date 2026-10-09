use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use http::Method;

use crate::core::retry::RetryPolicy;
use crate::core::util::validate_base_url;

/// Chooses the base URL for a logical request's relative path.
///
/// Called once during preparation, before queueing and attempts. Retries reuse
/// that selection; redirects use their target URI. Absolute HTTP(S) request URLs
/// replace the base URL after this callback. The returned base must be valid
/// HTTP(S) and is validated before network I/O.
///
/// Return `Cow::Borrowed` for a configured or internally stored URL, and
/// `Cow::Owned` for a newly constructed one. The lifetime permits borrowing from
/// either `self` or `configured_base_url`. Implementations are shared via `Arc`,
/// can receive concurrent calls, and run synchronously; selection is not automatic
/// per-attempt failover. `path` is the caller's request path and can contain query
/// data, whereas observer request contexts carry redacted URIs.
pub trait EndpointSelector: Send + Sync {
    /// Returns the base URL that should be used for this request.
    fn select_base_url<'a>(
        &'a self,
        method: &Method,
        path: &str,
        configured_base_url: &'a str,
    ) -> crate::Result<Cow<'a, str>>;
}

#[derive(Debug)]
/// Endpoint selector that cycles through a fixed list of base URLs.
///
/// Rotation is per logical request and shared across all clients using the same
/// `Arc`. Concurrent call order is not guaranteed. Endpoints are validated during
/// construction; the list is immutable afterwards.
///
/// ```
/// # #[cfg(feature = "_async")]
/// # fn example() -> reqx::Result<()> {
/// use std::sync::Arc;
/// use reqx::advanced::RoundRobinEndpointSelector;
/// let selector = RoundRobinEndpointSelector::new([
///     "https://api-a.example.com/v1",
///     "https://api-b.example.com/v1",
/// ])?;
/// let client = reqx::Client::builder("https://api.example.com/v1")
///     .endpoint_selector(Some(Arc::new(selector)))
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct RoundRobinEndpointSelector {
    endpoints: Vec<String>,
    next: AtomicUsize,
}

impl RoundRobinEndpointSelector {
    /// Creates a selector that rotates through nonempty, valid HTTP(S) base URLs.
    ///
    /// Empty lists and invalid URLs are rejected immediately.
    pub fn new<I, S>(endpoints: I) -> crate::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let endpoints: Vec<String> = endpoints.into_iter().map(Into::into).collect();
        if endpoints.is_empty() {
            return Err(crate::Error::InvalidEndpointConfig {
                message: "at least one endpoint is required",
            });
        }
        for endpoint in &endpoints {
            validate_base_url(endpoint)?;
        }
        Ok(Self {
            endpoints,
            next: AtomicUsize::new(0),
        })
    }
}

impl EndpointSelector for RoundRobinEndpointSelector {
    fn select_base_url<'a>(
        &'a self,
        _method: &Method,
        _path: &str,
        _configured_base_url: &'a str,
    ) -> crate::Result<Cow<'a, str>> {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        Ok(Cow::Borrowed(&self.endpoints[index % self.endpoints.len()]))
    }
}

/// Provides the fallback delay used before retrying a failed request.
///
/// `attempt` is one-based: `1` computes the wait before the second attempt.
/// The policy is the effective request policy, including an explicit override.
/// Server `Retry-After` hints can replace the fallback and the overall deadline
/// bounds waits. This hook changes delays, not retry eligibility or attempt caps.
/// It runs synchronously and should return promptly; actual sleeps are performed
/// by the client runtime. `None` in the builder uses `RetryPolicy::backoff_for_retry`.
pub trait BackoffSource: Send + Sync {
    /// Returns the retry backoff for `attempt`.
    fn backoff_for_retry(&self, retry_policy: &RetryPolicy, attempt: usize) -> Duration;
}

/// Time source used by retry/resilience bookkeeping and other internal control loops.
///
/// Real transport sleeps and socket deadlines still use the runtime or OS timers.
/// Custom clocks should therefore track wall time monotonically rather than simulating
/// arbitrary jumps unless they are only used in tests for pure control-flow components.
pub trait Clock: Send + Sync {
    /// Returns the current wall-clock time.
    fn now_system(&self) -> SystemTime;

    /// Returns a monotonic instant for elapsed-time calculations.
    fn now_monotonic(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Debug, Default)]
/// Clock implementation backed by the system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_system(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Normalizes request paths before they are attached to OpenTelemetry spans.
pub trait OtelPathNormalizer: Send + Sync {
    /// Returns a normalized path suitable for low-cardinality telemetry.
    fn normalize_path(&self, path: &str) -> String;
}

#[derive(Debug, Default)]
/// Default path normalizer used by `reqx` OpenTelemetry spans.
pub struct StandardOtelPathNormalizer;

impl OtelPathNormalizer for StandardOtelPathNormalizer {
    fn normalize_path(&self, path: &str) -> String {
        let normalized = if path.is_empty() { "/" } else { path };
        let mut collapsed = String::with_capacity(normalized.len().min(128));
        let mut first = true;
        for segment in normalized.split('/') {
            if first {
                first = false;
                if normalized.starts_with('/') {
                    collapsed.push('/');
                }
                if segment.is_empty() {
                    continue;
                }
            } else if !collapsed.ends_with('/') {
                collapsed.push('/');
            }
            if segment.is_empty() {
                continue;
            }
            collapsed.push_str(normalize_path_segment(segment));
        }
        if collapsed.is_empty() {
            collapsed.push('/');
        }
        if collapsed.len() > 128 {
            collapsed = truncate_path_at_segment_boundary(&collapsed, 128);
        }
        collapsed
    }
}

fn truncate_path_at_segment_boundary(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        return path.to_owned();
    }

    let mut cutoff = max_len.min(path.len());
    while cutoff > 0 && !path.is_char_boundary(cutoff) {
        cutoff = cutoff.saturating_sub(1);
    }
    if cutoff == 0 {
        return "/".to_owned();
    }

    let cut_in_middle_of_segment = cutoff < path.len() && !path[cutoff..].starts_with('/');
    if !cut_in_middle_of_segment {
        let kept = path[..cutoff].trim_end_matches('/');
        return if kept.is_empty() {
            "/".to_owned()
        } else {
            kept.to_owned()
        };
    }

    let prefix = path[..cutoff].trim_end_matches('/');
    if prefix.is_empty() {
        return "/".to_owned();
    }
    if let Some(last_separator) = prefix.rfind('/') {
        if last_separator == 0 {
            "/".to_owned()
        } else {
            prefix[..last_separator].to_owned()
        }
    } else {
        "/".to_owned()
    }
}

fn normalize_path_segment(segment: &str) -> &str {
    if is_uuid_like(segment) {
        return ":uuid";
    }
    if !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()) {
        return ":int";
    }
    if segment.len() >= 16 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
        return ":hex";
    }
    if segment.len() >= 24 && looks_like_token(segment) {
        return ":token";
    }
    segment
}

fn is_uuid_like(segment: &str) -> bool {
    if segment.len() != 36 {
        return false;
    }
    for (index, character) in segment.chars().enumerate() {
        let is_hyphen_position = matches!(index, 8 | 13 | 18 | 23);
        if is_hyphen_position {
            if character != '-' {
                return false;
            }
        } else if !character.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn looks_like_token(segment: &str) -> bool {
    segment.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '~' | '.' | '=' | '+')
    })
}

#[cfg(test)]
mod contract_tests;
