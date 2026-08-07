use std::time::Duration;

use rand::RngExt;

use super::timing::duration_from_nanos_saturating;

pub(crate) fn clamp_f64_or_fallback(value: f64, min: f64, max: f64, nan_fallback: f64) -> f64 {
    debug_assert!(min.is_finite());
    debug_assert!(max.is_finite());
    debug_assert!(nan_fallback.is_finite());
    debug_assert!(min <= max);

    if value.is_nan() {
        nan_fallback.clamp(min, max)
    } else {
        value.clamp(min, max)
    }
}

pub(crate) fn exponential_backoff_with_jitter(
    retry_index: usize,
    base_backoff: Duration,
    max_backoff: Duration,
    jitter_ratio: f64,
) -> Duration {
    let capped_exponent = retry_index.saturating_sub(1).min(31) as u32;
    let multiplier = 1_u128 << capped_exponent;
    let base_nanos = base_backoff.as_nanos().max(1);
    let max_nanos = max_backoff.as_nanos().max(base_nanos);
    let delay_nanos = base_nanos.saturating_mul(multiplier).min(max_nanos);
    apply_backoff_jitter(
        duration_from_nanos_saturating(delay_nanos),
        duration_from_nanos_saturating(max_nanos),
        jitter_ratio,
    )
}

fn apply_backoff_jitter(backoff: Duration, max_backoff: Duration, jitter_ratio: f64) -> Duration {
    let jitter_ratio = clamp_f64_or_fallback(jitter_ratio, 0.0, 1.0, 0.0);
    if jitter_ratio <= f64::EPSILON {
        return backoff;
    }

    let backoff_nanos = backoff.as_nanos();
    if backoff_nanos <= 1 {
        return backoff;
    }

    let max_backoff_nanos = max_backoff.as_nanos().max(1);
    let jitter_span = ((backoff_nanos as f64) * jitter_ratio).round().max(1.0) as u128;
    let low = backoff_nanos.saturating_sub(jitter_span);
    let high = backoff_nanos.saturating_add(jitter_span).max(low);
    let mut rng = rand::rng();
    let sampled_nanos = rng.random_range(low..=high).min(max_backoff_nanos);
    duration_from_nanos_saturating(sampled_nanos)
}
