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

#[derive(Default)]
pub(crate) struct StreamLifecycle {
    completion: Option<StreamCompletion>,
    hooks: Option<Box<dyn StreamOutcomeHooks + Send>>,
    completed: bool,
}

impl StreamLifecycle {
    pub(crate) fn new(hooks: Box<dyn StreamOutcomeHooks + Send>) -> Self {
        Self {
            completion: None,
            hooks: Some(hooks),
            completed: false,
        }
    }

    pub(crate) fn attach_completion(&mut self, completion: StreamCompletion) {
        self.completion = Some(completion);
    }

    pub(crate) fn complete_success(&mut self) {
        if self.completed {
            return;
        }
        self.completed = true;
        if let Some(mut hooks) = self.hooks.take() {
            hooks.complete_success();
        }
        if let Some(mut completion) = self.completion.take() {
            completion.complete_success();
        }
    }

    pub(crate) fn complete_error(&mut self, error: &Error) {
        if self.completed {
            return;
        }
        self.completed = true;
        if let Some(mut hooks) = self.hooks.take() {
            hooks.complete_error(error);
        }
        if let Some(mut completion) = self.completion.take() {
            completion.complete_error(error);
        }
    }

    pub(crate) fn complete_canceled(&mut self) {
        if self.completed {
            return;
        }
        self.completed = true;
        if let Some(mut hooks) = self.hooks.take() {
            hooks.complete_canceled();
        }
        if let Some(mut completion) = self.completion.take() {
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
            .field("completed", &self.completed)
            .finish()
    }
}

impl Drop for StreamLifecycle {
    fn drop(&mut self) {
        self.complete_canceled();
    }
}
