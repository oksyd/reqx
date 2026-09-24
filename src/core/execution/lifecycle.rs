//! Completion state shared by both streaming transports.
//!
//! A stream records exactly one terminal outcome. Dropping an unfinished stream
//! records cancellation; transport-specific stream bodies retain ownership of
//! their I/O resources and concurrency permits.

use crate::core::error::Error;
use crate::core::metrics::StreamCompletion;

pub(crate) trait StreamOutcomeHooks {
    fn complete_success(&mut self);

    fn complete_error(&mut self, error: &Error);

    fn complete_canceled(&mut self);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamLifecycleState {
    Pending,
    Success,
    Error,
    Canceled,
}

pub(crate) struct StreamLifecycle {
    completion: Option<StreamCompletion>,
    hooks: Option<Box<dyn StreamOutcomeHooks + Send>>,
    state: StreamLifecycleState,
}

impl StreamLifecycle {
    pub(crate) fn new(hooks: Option<Box<dyn StreamOutcomeHooks + Send>>) -> Self {
        Self {
            completion: None,
            hooks,
            state: StreamLifecycleState::Pending,
        }
    }

    pub(crate) fn attach_completion(&mut self, completion: StreamCompletion) {
        self.completion = Some(completion);
    }

    pub(crate) fn complete_success(&mut self) {
        if self.state != StreamLifecycleState::Pending {
            return;
        }
        self.state = StreamLifecycleState::Success;
        if let Some(hooks) = &mut self.hooks {
            hooks.complete_success();
        }
        if let Some(completion) = &mut self.completion {
            completion.complete_success();
        }
    }

    pub(crate) fn complete_error(&mut self, error: &Error) {
        if self.state != StreamLifecycleState::Pending {
            return;
        }
        self.state = StreamLifecycleState::Error;
        if let Some(hooks) = &mut self.hooks {
            hooks.complete_error(error);
        }
        if let Some(completion) = &mut self.completion {
            completion.complete_error(error);
        }
    }

    pub(crate) fn complete_canceled(&mut self) {
        if self.state != StreamLifecycleState::Pending {
            return;
        }
        self.state = StreamLifecycleState::Canceled;
        if let Some(hooks) = &mut self.hooks {
            hooks.complete_canceled();
        }
        if let Some(completion) = &mut self.completion {
            completion.complete_canceled();
        }
    }
}

impl std::fmt::Debug for StreamLifecycle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamLifecycle")
            .field("has_completion", &self.completion.is_some())
            .field("has_hooks", &self.hooks.is_some())
            .field("state", &self.state)
            .finish()
    }
}

impl Drop for StreamLifecycle {
    fn drop(&mut self) {
        self.complete_canceled();
    }
}

pub(crate) fn attach_completion(
    lifecycle: &mut Option<StreamLifecycle>,
    completion: StreamCompletion,
) {
    if let Some(lifecycle) = lifecycle {
        lifecycle.attach_completion(completion);
    } else {
        let mut new_lifecycle = StreamLifecycle::new(None);
        new_lifecycle.attach_completion(completion);
        *lifecycle = Some(new_lifecycle);
    }
}

pub(crate) fn complete_success(lifecycle: &mut Option<StreamLifecycle>) {
    if let Some(lifecycle) = lifecycle {
        lifecycle.complete_success();
    }
}

pub(crate) fn complete_error(lifecycle: &mut Option<StreamLifecycle>, error: &Error) {
    if let Some(lifecycle) = lifecycle {
        lifecycle.complete_error(error);
    }
}
