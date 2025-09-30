use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// Token bucket style limiter that caps the amount of data that can be
/// processed within a fixed interval.
///
/// The implementation is intentionally lightweight; it is designed so the
/// surrounding proxy stack can reason about bandwidth shaping behaviour without
/// introducing external dependencies. Consumers can call [`try_acquire`] when
/// best-effort throttling is sufficient or [`acquire`] to wait until enough
/// capacity is available.
#[derive(Debug)]
pub struct BandwidthLimiter {
    capacity: usize,
    refill_interval: Duration,
    inner: Mutex<LimiterState>,
}

#[derive(Debug)]
struct LimiterState {
    tokens: usize,
    last_refill: Instant,
}

impl BandwidthLimiter {
    /// Creates a new limiter that grants up to `capacity` units within the
    /// configured `refill_interval`.
    pub fn new(capacity: usize, refill_interval: Duration) -> Self {
        assert!(capacity > 0, "limiter capacity must be non-zero");
        assert!(
            refill_interval > Duration::ZERO,
            "refill interval must be > 0"
        );

        Self {
            capacity,
            refill_interval,
            inner: Mutex::new(LimiterState {
                tokens: capacity,
                last_refill: Instant::now(),
            }),
        }
    }

    fn refill(&self, state: &mut LimiterState, now: Instant) {
        if now.saturating_duration_since(state.last_refill) >= self.refill_interval {
            state.tokens = self.capacity;
            state.last_refill = now;
        }
    }

    /// Attempts to immediately reserve `amount` units from the limiter.
    ///
    /// Returns `true` when enough capacity was available.
    pub async fn try_acquire(&self, amount: usize) -> bool {
        if amount > self.capacity {
            return false;
        }

        let mut state = self.inner.lock().await;
        let now = Instant::now();
        self.refill(&mut state, now);

        if state.tokens >= amount {
            state.tokens -= amount;
            true
        } else {
            false
        }
    }

    /// Reserves `amount` units from the limiter, waiting until the quota is
    /// replenished if necessary.
    pub async fn acquire(&self, amount: usize) {
        assert!(amount <= self.capacity, "request exceeds limiter capacity");

        loop {
            if self.try_acquire(amount).await {
                return;
            }

            let sleep_duration = self.time_until_refill().await;
            tokio::time::sleep(sleep_duration).await;
        }
    }

    async fn time_until_refill(&self) -> Duration {
        let mut state = self.inner.lock().await;
        let now = Instant::now();
        self.refill(&mut state, now);
        let elapsed = now.saturating_duration_since(state.last_refill);

        if elapsed >= self.refill_interval {
            Duration::ZERO
        } else {
            self.refill_interval - elapsed
        }
    }

    /// Returns the remaining quota for the current interval.
    pub async fn remaining(&self) -> usize {
        let mut state = self.inner.lock().await;
        let now = Instant::now();
        self.refill(&mut state, now);
        state.tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn limiter_rejects_when_capacity_exhausted() {
        let limiter = BandwidthLimiter::new(10, Duration::from_millis(50));
        assert!(limiter.try_acquire(5).await);
        assert!(limiter.try_acquire(5).await);
        assert!(!limiter.try_acquire(1).await);
    }

    #[tokio::test]
    async fn limiter_waits_for_refill() {
        let limiter = BandwidthLimiter::new(4, Duration::from_millis(10));
        limiter.acquire(4).await;
        let start = Instant::now();
        limiter.acquire(2).await;
        assert!(start.elapsed() >= Duration::from_millis(10));
    }

    #[tokio::test]
    async fn remaining_updates_after_refill() {
        let limiter = BandwidthLimiter::new(3, Duration::from_millis(5));
        limiter.acquire(3).await;
        assert_eq!(limiter.remaining().await, 0);
        sleep(Duration::from_millis(5)).await;
        assert_eq!(limiter.remaining().await, 3);
    }
}
