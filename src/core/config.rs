use std::time::Duration;

use http::header::USER_AGENT;
use http::{HeaderMap, HeaderValue};

use crate::core::error::Error;
use crate::core::policy::{RedirectPolicy, StatusPolicy};
use crate::core::retry::RetryPolicy;
use crate::core::util::duration_millis_ceil;

pub(crate) const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
pub(crate) const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 8;
pub(crate) const DEFAULT_STREAM_DEADLINE_SLACK: Duration = Duration::from_millis(10);
pub(crate) const DEFAULT_CLIENT_NAME: &str = "reqx";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
/// Preset transport defaults tuned for common SDK traffic patterns.
///
/// | Profile | Request timeout | Total deadline | Attempts | Buffered limit |
/// | --- | --- | --- | --- | --- |
/// | `StandardSdk` (default) | 10 s | None | 3 | 8 MiB |
/// | `LowLatency` | 2 s | 5 s | 2 | 2 MiB |
/// | `HighThroughput` | 20 s | 60 s | 4 | 32 MiB |
///
/// All profiles disable redirects and use the error status policy. Retry counts
/// include the first attempt and remain subject to request eligibility. Profiles
/// do not enable concurrency, rate limits, metrics, or OpenTelemetry. Applying
/// a profile replaces request/total timeouts, attempts/backoff policy, body limit,
/// redirect policy, and status policy; apply custom overrides afterwards.
pub enum ClientProfile {
    #[default]
    /// Balanced defaults for general SDK API traffic.
    StandardSdk,
    /// Lower timeouts and lighter retries for latency-sensitive calls.
    LowLatency,
    /// Larger buffers and wider budgets for bulk throughput.
    HighThroughput,
}

#[derive(Clone, Debug)]
pub(crate) struct ProfileDefaults {
    pub request_timeout: Duration,
    pub total_timeout: Option<Duration>,
    pub retry_policy: RetryPolicy,
    pub max_response_body_bytes: usize,
    pub redirect_policy: RedirectPolicy,
    pub status_policy: StatusPolicy,
}

pub(crate) fn validate_timeout_config(
    request_timeout: Duration,
    total_timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
) -> crate::Result<()> {
    if request_timeout.is_zero() {
        return Err(invalid_timeout_config(
            request_timeout,
            total_timeout,
            connect_timeout,
            "request_timeout must be greater than zero",
        ));
    }
    if total_timeout.is_some_and(|timeout| timeout.is_zero()) {
        return Err(invalid_timeout_config(
            request_timeout,
            total_timeout,
            connect_timeout,
            "total_timeout must be greater than zero",
        ));
    }
    if connect_timeout.is_some_and(|timeout| timeout.is_zero()) {
        return Err(invalid_timeout_config(
            request_timeout,
            total_timeout,
            connect_timeout,
            "connect_timeout must be greater than zero",
        ));
    }
    Ok(())
}

fn invalid_timeout_config(
    request_timeout: Duration,
    total_timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    message: &'static str,
) -> Error {
    Error::InvalidTimeoutConfig {
        request_timeout_ms: duration_millis_ceil(request_timeout),
        total_timeout_ms: total_timeout.map(duration_millis_ceil),
        connect_timeout_ms: connect_timeout.map(duration_millis_ceil),
        message,
    }
}

pub(crate) fn default_headers_with_user_agent(
    client_name: &str,
    mut default_headers: HeaderMap,
) -> crate::Result<HeaderMap> {
    let invalid_config = |message| Error::InvalidClientNameConfig {
        client_name_len: client_name.len(),
        message,
    };
    if client_name.trim().is_empty() {
        return Err(invalid_config("client_name must not be empty"));
    }
    let user_agent = HeaderValue::from_str(client_name)
        .map_err(|_| invalid_config("client_name must be a valid HTTP header value"))?;
    if !default_headers.contains_key(USER_AGENT) {
        default_headers.insert(USER_AGENT, user_agent);
    }
    Ok(default_headers)
}

impl ClientProfile {
    pub(crate) fn defaults(self) -> ProfileDefaults {
        match self {
            Self::StandardSdk => ProfileDefaults {
                request_timeout: Duration::from_secs(10),
                total_timeout: None,
                retry_policy: RetryPolicy::standard(),
                max_response_body_bytes: 8 * 1024 * 1024,
                redirect_policy: RedirectPolicy::none(),
                status_policy: StatusPolicy::Error,
            },
            Self::LowLatency => ProfileDefaults {
                request_timeout: Duration::from_secs(2),
                total_timeout: Some(Duration::from_secs(5)),
                retry_policy: RetryPolicy::standard()
                    .max_attempts(2)
                    .base_backoff(Duration::from_millis(50))
                    .max_backoff(Duration::from_millis(300)),
                max_response_body_bytes: 2 * 1024 * 1024,
                redirect_policy: RedirectPolicy::none(),
                status_policy: StatusPolicy::Error,
            },
            Self::HighThroughput => ProfileDefaults {
                request_timeout: Duration::from_secs(20),
                total_timeout: Some(Duration::from_secs(60)),
                retry_policy: RetryPolicy::standard()
                    .max_attempts(4)
                    .base_backoff(Duration::from_millis(150))
                    .max_backoff(Duration::from_secs(3)),
                max_response_body_bytes: 32 * 1024 * 1024,
                redirect_policy: RedirectPolicy::none(),
                status_policy: StatusPolicy::Error,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http::header::USER_AGENT;
    use http::{HeaderMap, HeaderValue};

    use super::{ClientProfile, default_headers_with_user_agent, validate_timeout_config};
    use crate::core::error::Error;
    use crate::core::policy::RedirectPolicy;

    #[test]
    fn common_build_config_injects_user_agent_when_absent() {
        let headers = default_headers_with_user_agent("reqx-test", HeaderMap::new())
            .expect("common config should validate");

        assert_eq!(
            headers.get(USER_AGENT),
            Some(&HeaderValue::from_static("reqx-test"))
        );
    }

    #[test]
    fn common_build_config_preserves_explicit_user_agent() {
        let mut default_headers = HeaderMap::new();
        default_headers.insert(USER_AGENT, HeaderValue::from_static("custom-sdk"));

        let headers = default_headers_with_user_agent("reqx-test", default_headers)
            .expect("common config should validate");

        assert_eq!(
            headers.get(USER_AGENT),
            Some(&HeaderValue::from_static("custom-sdk"))
        );
    }

    #[test]
    fn timeout_validation_reports_sub_millisecond_values_without_zeroing_them() {
        let error = validate_timeout_config(
            Duration::from_micros(1_500),
            Some(Duration::ZERO),
            Some(Duration::from_micros(500)),
        )
        .expect_err("zero total timeout should be rejected");

        match error {
            Error::InvalidTimeoutConfig {
                request_timeout_ms,
                total_timeout_ms,
                connect_timeout_ms,
                ..
            } => {
                assert_eq!(request_timeout_ms, 2);
                assert_eq!(total_timeout_ms, Some(0));
                assert_eq!(connect_timeout_ms, Some(1));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn client_profiles_keep_redirects_opt_in() {
        for profile in [
            ClientProfile::StandardSdk,
            ClientProfile::LowLatency,
            ClientProfile::HighThroughput,
        ] {
            assert_eq!(profile.defaults().redirect_policy, RedirectPolicy::none());
        }
    }
}
