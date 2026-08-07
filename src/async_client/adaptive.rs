use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use crate::extensions::Clock;
use crate::resilience::{
    AdaptiveConcurrencyOutcome, AdaptiveConcurrencyPolicy, AdaptiveConcurrencyState,
};
use crate::util::lock_unpoisoned;

pub(super) struct AdaptiveConcurrencyController {
    policy: AdaptiveConcurrencyPolicy,
    state: Mutex<AdaptiveConcurrencyState>,
    clock: Arc<dyn Clock>,
    notify: Notify,
}

impl AdaptiveConcurrencyController {
    pub(super) fn new(policy: AdaptiveConcurrencyPolicy, clock: Arc<dyn Clock>) -> Self {
        let policy = policy.normalize_for_runtime();
        Self {
            policy,
            state: Mutex::new(AdaptiveConcurrencyState::new(policy)),
            clock,
            notify: Notify::new(),
        }
    }

    pub(super) async fn acquire(self: &Arc<Self>) -> AdaptiveConcurrencyPermit {
        loop {
            let mut notified = std::pin::pin!(self.notify.notified());
            // `notify_waiters` does not store a permit for futures that have not
            // been registered yet. Enable before checking capacity so a release
            // racing with this check cannot be lost.
            notified.as_mut().enable();
            {
                let mut state = lock_unpoisoned(&self.state);
                if state.try_acquire() {
                    return AdaptiveConcurrencyPermit {
                        controller: Arc::clone(self),
                        started_at: self.clock.now_monotonic(),
                        completed: false,
                    };
                }
            }
            notified.await;
        }
    }

    fn release_and_record(&self, outcome: AdaptiveConcurrencyOutcome, latency: Duration) {
        let mut state = lock_unpoisoned(&self.state);
        state.release_and_record(self.policy, outcome, latency);
        self.notify.notify_waiters();
    }

    fn release_without_record(&self) {
        let mut state = lock_unpoisoned(&self.state);
        state.release_without_record();
        self.notify.notify_waiters();
    }
}

pub(super) struct AdaptiveConcurrencyPermit {
    controller: Arc<AdaptiveConcurrencyController>,
    started_at: Instant,
    completed: bool,
}

impl AdaptiveConcurrencyPermit {
    fn latency(&self) -> Duration {
        self.controller
            .clock
            .now_monotonic()
            .saturating_duration_since(self.started_at)
    }

    fn mark_success(mut self) {
        self.controller
            .release_and_record(AdaptiveConcurrencyOutcome::Success, self.latency());
        self.completed = true;
    }

    fn mark_failure(mut self) {
        self.controller
            .release_and_record(AdaptiveConcurrencyOutcome::Failure, self.latency());
        self.completed = true;
    }

    fn cancel(mut self) {
        self.controller.release_without_record();
        self.completed = true;
    }
}

impl crate::execution::AttemptOutcome for AdaptiveConcurrencyPermit {
    fn mark_success(self) {
        Self::mark_success(self);
    }

    fn mark_failure(self) {
        Self::mark_failure(self);
    }

    fn cancel(self) {
        Self::cancel(self);
    }
}

impl Drop for AdaptiveConcurrencyPermit {
    fn drop(&mut self) {
        if !self.completed {
            self.controller.release_without_record();
            self.completed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use crate::extensions::SystemClock;
    use crate::resilience::AdaptiveConcurrencyPolicy;

    use super::AdaptiveConcurrencyController;

    #[tokio::test]
    async fn adaptive_controller_unblocks_waiter_after_release() {
        let policy = AdaptiveConcurrencyPolicy::standard()
            .min_limit(1)
            .initial_limit(1)
            .max_limit(1);
        let controller = Arc::new(AdaptiveConcurrencyController::new(
            policy,
            Arc::new(SystemClock),
        ));

        let first_permit = controller.acquire().await;
        let waiter = {
            let controller = Arc::clone(&controller);
            tokio::spawn(async move {
                tokio::time::timeout(Duration::from_millis(300), controller.acquire())
                    .await
                    .is_ok()
            })
        };

        tokio::task::yield_now().await;
        drop(first_permit);

        let completed = waiter.await.expect("waiter task should join");
        assert!(completed, "waiter should acquire after permit release");
    }

    #[tokio::test]
    async fn dropping_adaptive_permit_releases_without_reducing_limit() {
        let policy = AdaptiveConcurrencyPolicy::standard()
            .min_limit(1)
            .initial_limit(2)
            .max_limit(2)
            .decrease_ratio(0.5);
        let controller = Arc::new(AdaptiveConcurrencyController::new(
            policy,
            Arc::new(SystemClock),
        ));

        let canceled = controller.acquire().await;
        let _active = controller.acquire().await;
        drop(canceled);

        let replacement =
            tokio::time::timeout(Duration::from_millis(50), controller.acquire()).await;
        assert!(
            replacement.is_ok(),
            "cancellation should release capacity without decreasing the limit"
        );
    }
}
