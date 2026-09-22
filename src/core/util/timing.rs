use std::time::{Duration, Instant, SystemTime};

use http::header::RETRY_AFTER;
use http::{HeaderMap, Method};

use crate::core::error::Error;

pub(crate) fn phase_timeout(
    per_attempt_timeout: Duration,
    total_timeout: Option<Duration>,
    request_started_at: Instant,
) -> Option<Duration> {
    let Some(total_timeout) = total_timeout else {
        return Some(per_attempt_timeout);
    };

    let elapsed = request_started_at.elapsed();
    if elapsed >= total_timeout {
        return None;
    }

    let remaining = total_timeout - elapsed;
    Some(per_attempt_timeout.min(remaining))
}

#[cfg(feature = "_async")]
pub(crate) fn duration_millis_u64_saturating(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

pub(crate) fn duration_millis_ceil(duration: Duration) -> u128 {
    duration.as_nanos().div_ceil(1_000_000)
}

pub(crate) fn duration_from_millis_saturating(milliseconds: u128) -> Duration {
    const MILLIS_PER_SECOND: u128 = 1_000;
    const NANOS_PER_MILLI: u128 = 1_000_000;

    let seconds = milliseconds / MILLIS_PER_SECOND;
    if seconds > u128::from(u64::MAX) {
        return Duration::MAX;
    }

    Duration::new(
        seconds as u64,
        ((milliseconds % MILLIS_PER_SECOND) * NANOS_PER_MILLI) as u32,
    )
}

pub(crate) fn duration_from_nanos_saturating(nanoseconds: u128) -> Duration {
    const NANOS_PER_SECOND: u128 = 1_000_000_000;

    let seconds = nanoseconds / NANOS_PER_SECOND;
    if seconds > u128::from(u64::MAX) {
        return Duration::MAX;
    }

    Duration::new(seconds as u64, (nanoseconds % NANOS_PER_SECOND) as u32)
}

pub(crate) const fn saturating_u64_to_usize(value: u64) -> usize {
    if value > usize::MAX as u64 {
        usize::MAX
    } else {
        value as usize
    }
}

pub(crate) fn duration_from_secs_f64_saturating(seconds: f64) -> Duration {
    if seconds <= 0.0 {
        return Duration::ZERO;
    }
    if !seconds.is_finite() || seconds >= Duration::MAX.as_secs_f64() {
        return Duration::MAX;
    }
    Duration::from_secs_f64(seconds)
}

pub(crate) fn total_timeout_expired(
    total_timeout: Option<Duration>,
    request_started_at: Instant,
) -> bool {
    total_timeout.is_some_and(|timeout| request_started_at.elapsed() >= timeout)
}

pub(crate) fn total_timeout_deadline(
    total_timeout: Option<Duration>,
    request_started_at: Instant,
) -> Option<Instant> {
    total_timeout.and_then(|timeout| request_started_at.checked_add(timeout))
}

pub(crate) fn bounded_retry_delay(
    retry_delay: Duration,
    total_timeout: Option<Duration>,
    request_started_at: Instant,
) -> Option<Duration> {
    let Some(total_timeout) = total_timeout else {
        return Some(retry_delay);
    };

    let elapsed = request_started_at.elapsed();
    if elapsed >= total_timeout {
        return None;
    }

    let remaining = total_timeout - elapsed;
    if retry_delay >= remaining {
        return None;
    }
    Some(retry_delay)
}

pub(crate) fn deadline_exceeded_error(
    total_timeout: Option<Duration>,
    method: &Method,
    uri: &str,
) -> Error {
    let timeout_ms = total_timeout.map(duration_millis_ceil).unwrap_or(0);
    Error::DeadlineExceeded {
        timeout_ms,
        method: method.clone(),
        uri: uri.to_owned(),
    }
}

pub(crate) fn parse_retry_after(headers: &HeaderMap, now: SystemTime) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?;
    let raw_value = value.to_str().ok()?.trim();
    if let Ok(seconds) = raw_value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let date = httpdate::parse_http_date(raw_value).ok()?;
    match date.duration_since(now) {
        Ok(duration) => Some(duration),
        Err(_) => Some(Duration::ZERO),
    }
}

pub(crate) fn parse_retry_after_capped(
    headers: &HeaderMap,
    now: SystemTime,
    max_delay: Duration,
) -> Option<Duration> {
    parse_retry_after(headers, now).map(|delay| delay.min(max_delay))
}

#[cfg(test)]
mod contract_tests;
