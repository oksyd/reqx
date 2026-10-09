use std::sync::Arc;
use std::time::Duration;

use crate::core::config::validate_timeout_config;
use crate::core::policy::{RedirectPolicy, StatusPolicy};
use crate::core::retry::RetryPolicy;

#[derive(Default)]
pub(crate) struct RequestExecutionOverrides {
    pub(crate) request_timeout: Option<Duration>,
    // None inherits the client setting; Some(None) explicitly disables it.
    pub(crate) total_timeout: Option<Option<Duration>>,
    pub(crate) retry_policy: Option<RetryPolicy>,
    pub(crate) max_response_body_bytes: Option<usize>,
    pub(crate) redirect_policy: Option<RedirectPolicy>,
    pub(crate) status_policy: Option<StatusPolicy>,
    pub(crate) auto_accept_encoding: Option<bool>,
}

pub(crate) struct RequestExecutionOptions {
    pub(crate) request_timeout: Duration,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) retry_policy: Arc<RetryPolicy>,
    pub(crate) max_response_body_bytes: usize,
    pub(crate) redirect_policy: RedirectPolicy,
    pub(crate) status_policy: StatusPolicy,
}

impl RequestExecutionOverrides {
    pub(crate) fn resolve(
        self,
        defaults: &RequestExecutionOptions,
    ) -> crate::Result<RequestExecutionOptions> {
        let request_timeout = self.request_timeout.unwrap_or(defaults.request_timeout);
        let total_timeout = self.total_timeout.unwrap_or(defaults.total_timeout);
        if self.request_timeout.is_some() || self.total_timeout.is_some() {
            validate_timeout_config(request_timeout, total_timeout, None)?;
        }

        let retry_policy = match self.retry_policy {
            Some(policy) => {
                policy.validate()?;
                Arc::new(policy)
            }
            None => Arc::clone(&defaults.retry_policy),
        };

        Ok(RequestExecutionOptions {
            request_timeout,
            total_timeout,
            retry_policy,
            max_response_body_bytes: self
                .max_response_body_bytes
                .unwrap_or(defaults.max_response_body_bytes),
            redirect_policy: self.redirect_policy.unwrap_or(defaults.redirect_policy),
            status_policy: self.status_policy.unwrap_or(defaults.status_policy),
        })
    }
}
