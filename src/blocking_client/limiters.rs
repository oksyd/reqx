use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use crate::core::extensions::Clock;
use crate::core::limiters::{
    PER_HOST_LIMITER_ENTRY_TTL, PER_HOST_LIMITER_MAX_ENTRIES,
    PerHostLimiterEntry as PerHostLimiterEntryState, cleanup_stale_per_host_limiters,
};
use crate::core::util::{lock_unpoisoned, normalize_host_key};

pub(crate) struct RequestLimiters {
    clock: Arc<dyn Clock>,
    global: Option<Arc<BlockingSemaphore>>,
    per_host_limit: Option<usize>,
    per_host: Mutex<BTreeMap<String, PerHostLimiterEntry>>,
}

struct PerHostLimiterEntry {
    semaphore: Arc<BlockingSemaphore>,
    limit: usize,
    last_used_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcquirePermitError {
    Timeout,
}

#[derive(Debug)]
struct BlockingSemaphore {
    state: Mutex<usize>,
    condvar: Condvar,
}

impl BlockingSemaphore {
    fn new(permits: usize) -> Self {
        debug_assert!(permits > 0);
        Self {
            state: Mutex::new(permits),
            condvar: Condvar::new(),
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<BlockingSemaphorePermit> {
        let mut state = lock_unpoisoned(&self.state);
        if *state == 0 {
            return None;
        }
        *state -= 1;
        Some(BlockingSemaphorePermit {
            semaphore: Arc::clone(self),
        })
    }

    fn acquire(
        self: &Arc<Self>,
        deadline_at: Option<Instant>,
    ) -> Result<BlockingSemaphorePermit, AcquirePermitError> {
        let mut state = lock_unpoisoned(&self.state);
        loop {
            if *state > 0 {
                *state -= 1;
                drop(state);
                return Ok(BlockingSemaphorePermit {
                    semaphore: Arc::clone(self),
                });
            }

            state = match deadline_at {
                Some(deadline_at) => {
                    let now = Instant::now();
                    if now >= deadline_at {
                        return Err(AcquirePermitError::Timeout);
                    }
                    let wait_for = deadline_at.duration_since(now);
                    let (next_state, wait_result) = match self.condvar.wait_timeout(state, wait_for)
                    {
                        Ok(result) => result,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    if wait_result.timed_out() && *next_state == 0 && Instant::now() >= deadline_at
                    {
                        return Err(AcquirePermitError::Timeout);
                    }
                    next_state
                }
                None => match self.condvar.wait(state) {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                },
            };
        }
    }

    fn release(&self) {
        let mut state = lock_unpoisoned(&self.state);
        *state = state.saturating_add(1);
        self.condvar.notify_one();
    }

    fn available_permits(&self) -> usize {
        *lock_unpoisoned(&self.state)
    }
}

#[derive(Debug)]
pub(crate) struct BlockingSemaphorePermit {
    semaphore: Arc<BlockingSemaphore>,
}

impl Drop for BlockingSemaphorePermit {
    fn drop(&mut self) {
        self.semaphore.release();
    }
}

impl RequestLimiters {
    pub(crate) fn new(
        max_in_flight: Option<usize>,
        per_host_limit: Option<usize>,
        clock: Arc<dyn Clock>,
    ) -> Option<Self> {
        debug_assert!(max_in_flight.is_none_or(|limit| limit > 0));
        debug_assert!(per_host_limit.is_none_or(|limit| limit > 0));
        if max_in_flight.is_none() && per_host_limit.is_none() {
            return None;
        }

        Some(Self {
            clock,
            global: max_in_flight.map(|limit| Arc::new(BlockingSemaphore::new(limit))),
            per_host_limit,
            per_host: Mutex::new(BTreeMap::new()),
        })
    }

    pub(crate) fn acquire_global(
        &self,
        deadline_at: Option<Instant>,
    ) -> Result<Option<BlockingSemaphorePermit>, AcquirePermitError> {
        let permit = match &self.global {
            Some(semaphore) => Some(semaphore.acquire(deadline_at)?),
            None => None,
        };
        Ok(permit)
    }

    pub(crate) fn acquire_host(
        &self,
        host: Option<&str>,
        deadline_at: Option<Instant>,
    ) -> Result<Option<BlockingSemaphorePermit>, AcquirePermitError> {
        let host = if self.per_host_limit.is_some() {
            host.and_then(normalize_host_key)
        } else {
            None
        };
        let permit = match (self.per_host_limit, host) {
            (Some(limit), Some(host)) => {
                let wait_for_semaphore = {
                    let mut guard = lock_unpoisoned(&self.per_host);
                    let now = self.clock.now_monotonic();
                    cleanup_stale_per_host_limiters(
                        &mut guard,
                        now,
                        PER_HOST_LIMITER_ENTRY_TTL,
                        PER_HOST_LIMITER_MAX_ENTRIES,
                    );
                    let entry = guard.entry(host).or_insert_with(|| PerHostLimiterEntry {
                        semaphore: Arc::new(BlockingSemaphore::new(limit)),
                        limit,
                        last_used_at: now,
                    });
                    entry.last_used_at = now;
                    if let Some(permit) = entry.semaphore.try_acquire() {
                        return Ok(Some(permit));
                    }
                    Arc::clone(&entry.semaphore)
                };
                Some(wait_for_semaphore.acquire(deadline_at)?)
            }
            _ => None,
        };
        Ok(permit)
    }
}

impl PerHostLimiterEntryState for PerHostLimiterEntry {
    fn is_idle(&self) -> bool {
        // Waiters may own a handle before they register with the semaphore.
        Arc::strong_count(&self.semaphore) == 1 && self.semaphore.available_permits() == self.limit
    }

    fn last_used_at(&self) -> Instant {
        self.last_used_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_host_normalizes_trailing_dot_fqdn_keys() {
        let limiters = RequestLimiters::new(
            None,
            Some(1),
            Arc::new(crate::core::extensions::SystemClock),
        )
        .expect("limiters should be built");

        let _permit = limiters
            .acquire_host(Some("api.example.com"), None)
            .expect("first host permit should succeed");

        let second = limiters.acquire_host(
            Some("api.example.com."),
            Some(Instant::now() + Duration::from_millis(50)),
        );
        assert!(
            matches!(second, Err(AcquirePermitError::Timeout)),
            "trailing-dot host should share the same per-host concurrency bucket"
        );

        let entries = lock_unpoisoned(&limiters.per_host);
        assert!(entries.contains_key("api.example.com"));
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn cleanup_keeps_stale_entry_while_permit_is_active() {
        let now = Instant::now();
        let stale = now
            .checked_sub(PER_HOST_LIMITER_ENTRY_TTL + Duration::from_secs(1))
            .expect("stale instant");
        let semaphore = Arc::new(BlockingSemaphore::new(1));
        let permit = semaphore
            .acquire(None)
            .expect("acquire active permit without deadline");

        let mut entries = BTreeMap::new();
        entries.insert(
            "active.example.com".to_owned(),
            PerHostLimiterEntry {
                semaphore: Arc::clone(&semaphore),
                limit: 1,
                last_used_at: stale,
            },
        );

        cleanup_stale_per_host_limiters(
            &mut entries,
            now,
            PER_HOST_LIMITER_ENTRY_TTL,
            PER_HOST_LIMITER_MAX_ENTRIES,
        );
        assert!(entries.contains_key("active.example.com"));

        drop(permit);
        drop(semaphore);
        cleanup_stale_per_host_limiters(
            &mut entries,
            now,
            PER_HOST_LIMITER_ENTRY_TTL,
            PER_HOST_LIMITER_MAX_ENTRIES,
        );
        assert!(!entries.contains_key("active.example.com"));
    }

    #[test]
    fn cleanup_keeps_entry_referenced_by_a_pending_acquisition() {
        let now = Instant::now();
        let stale = now
            .checked_sub(PER_HOST_LIMITER_ENTRY_TTL + Duration::from_secs(1))
            .expect("stale instant");
        for (last_used_at, max_entries) in [(stale, PER_HOST_LIMITER_MAX_ENTRIES), (now, 0)] {
            // A waiter cloned this handle under the map lock. The previous
            // permit was released before the waiter could acquire it.
            let waiting = Arc::new(BlockingSemaphore::new(1));
            let mut entries = BTreeMap::from([(
                "waiting.example.com".to_owned(),
                PerHostLimiterEntry {
                    semaphore: Arc::clone(&waiting),
                    limit: 1,
                    last_used_at,
                },
            )]);
            cleanup_stale_per_host_limiters(
                &mut entries,
                now,
                PER_HOST_LIMITER_ENTRY_TTL,
                max_entries,
            );
            assert!(
                entries.contains_key("waiting.example.com"),
                "must not replace a waiter's limiter"
            );
            drop(waiting);
            cleanup_stale_per_host_limiters(
                &mut entries,
                now,
                PER_HOST_LIMITER_ENTRY_TTL,
                max_entries,
            );
            assert!(
                entries.is_empty(),
                "unreferenced idle limiter can be evicted"
            );
        }
    }

    #[test]
    fn cleanup_does_not_evict_active_entries_when_over_capacity() {
        let now = Instant::now();
        let active_semaphore = Arc::new(BlockingSemaphore::new(1));
        let _active_permit = active_semaphore
            .acquire(None)
            .expect("acquire active permit without deadline");

        let mut entries = BTreeMap::new();
        entries.insert(
            "active.example.com".to_owned(),
            PerHostLimiterEntry {
                semaphore: Arc::clone(&active_semaphore),
                limit: 1,
                last_used_at: now,
            },
        );

        for index in 0..PER_HOST_LIMITER_MAX_ENTRIES {
            entries.insert(
                format!("idle-{index}.example.com"),
                PerHostLimiterEntry {
                    semaphore: Arc::new(BlockingSemaphore::new(1)),
                    limit: 1,
                    last_used_at: now,
                },
            );
        }

        cleanup_stale_per_host_limiters(
            &mut entries,
            now,
            PER_HOST_LIMITER_ENTRY_TTL,
            PER_HOST_LIMITER_MAX_ENTRIES,
        );
        assert!(entries.contains_key("active.example.com"));
        assert_eq!(entries.len(), PER_HOST_LIMITER_MAX_ENTRIES);
    }
}
