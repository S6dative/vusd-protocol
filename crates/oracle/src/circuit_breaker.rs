// crates/oracle/src/circuit_breaker.rs
//
// Per-feed circuit breaker with exponential backoff.
//
// State machine:
//   Closed  → normal operation, requests pass through
//   Open    → feed is failing, requests blocked until cool-down expires
//   HalfOpen → cool-down expired, next request is a probe:
//              if it succeeds → Closed; if it fails → Open (with longer backoff)
//
// Backoff schedule (seconds between retries):
//   failure 1: 5s
//   failure 2: 10s
//   failure 3: 20s
//   failure 4: 40s
//   failure 5+: 300s (5 minutes, max)
//
// Usage: wrap each PriceFeed in a CircuitBreaker before adding to the oracle node.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use crate::{OracleError, PriceFeed};
use tracing::{debug, warn};

const MIN_BACKOFF_SECS: u64 = 5;
const MAX_BACKOFF_SECS: u64 = 300;
const FAILURE_THRESHOLD: u32 = 3; // open circuit after this many consecutive failures

#[derive(Debug, Clone, PartialEq)]
enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
struct BreakerInner {
    state:             BreakerState,
    consecutive_fails: u32,
    last_failure:      Option<Instant>,
    backoff_secs:      u64,
    total_calls:       u64,
    total_failures:    u64,
}

impl BreakerInner {
    fn new() -> Self {
        BreakerInner {
            state:             BreakerState::Closed,
            consecutive_fails: 0,
            last_failure:      None,
            backoff_secs:      MIN_BACKOFF_SECS,
            total_calls:       0,
            total_failures:    0,
        }
    }

    fn record_success(&mut self) {
        self.consecutive_fails = 0;
        self.backoff_secs      = MIN_BACKOFF_SECS;
        self.state             = BreakerState::Closed;
        self.total_calls      += 1;
    }

    fn record_failure(&mut self) {
        self.consecutive_fails += 1;
        self.total_failures    += 1;
        self.total_calls       += 1;
        self.last_failure       = Some(Instant::now());

        // Exponential backoff: 5, 10, 20, 40, ... capped at 300
        self.backoff_secs = std::cmp::min(
            MIN_BACKOFF_SECS * (1 << (self.consecutive_fails.saturating_sub(1))),
            MAX_BACKOFF_SECS,
        );

        if self.consecutive_fails >= FAILURE_THRESHOLD {
            self.state = BreakerState::Open;
        }
    }

    fn is_ready(&mut self) -> bool {
        match self.state {
            BreakerState::Closed   => true,
            BreakerState::HalfOpen => true, // allow probe
            BreakerState::Open     => {
                // Check if cool-down has expired
                let elapsed = self.last_failure
                    .map(|t| t.elapsed())
                    .unwrap_or(Duration::ZERO);
                if elapsed >= Duration::from_secs(self.backoff_secs) {
                    self.state = BreakerState::HalfOpen;
                    true
                } else {
                    false
                }
            }
        }
    }
}

/// A PriceFeed wrapper that implements circuit-breaker + exponential backoff.
pub struct CircuitBreaker {
    inner: Arc<RwLock<BreakerInner>>,
    feed:  Box<dyn PriceFeed>,
}

impl CircuitBreaker {
    pub fn new(feed: Box<dyn PriceFeed>) -> Self {
        CircuitBreaker {
            inner: Arc::new(RwLock::new(BreakerInner::new())),
            feed,
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        let inner = self.inner.read().unwrap();
        (inner.total_calls, inner.total_failures)
    }

    pub fn is_open(&self) -> bool {
        self.inner.read().unwrap().state == BreakerState::Open
    }
}

impl PriceFeed for CircuitBreaker {
    fn name(&self) -> &str { self.feed.name() }

    fn fetch_price(&self) -> Result<u64, OracleError> {
        let ready = self.inner.write().unwrap().is_ready();
        if !ready {
            let backoff = self.inner.read().unwrap().backoff_secs;
            debug!(
                feed = self.feed.name(),
                backoff_secs = backoff,
                "Circuit breaker OPEN — skipping feed"
            );
            return Err(OracleError::FeedError(format!(
                "{}: circuit breaker open (backoff {}s)", self.feed.name(), backoff
            )));
        }

        match self.feed.fetch_price() {
            Ok(price) => {
                self.inner.write().unwrap().record_success();
                Ok(price)
            }
            Err(e) => {
                let mut inner = self.inner.write().unwrap();
                inner.record_failure();
                warn!(
                    feed       = self.feed.name(),
                    fails      = inner.consecutive_fails,
                    backoff_s  = inner.backoff_secs,
                    state      = ?inner.state,
                    "Price feed failure: {}", e
                );
                Err(e)
            }
        }
    }
}

/// Wrap every feed in a circuit breaker.
pub fn with_circuit_breakers(feeds: Vec<Box<dyn PriceFeed>>) -> Vec<Box<dyn PriceFeed>> {
    feeds.into_iter()
        .map(|f| -> Box<dyn PriceFeed> { Box::new(CircuitBreaker::new(f)) })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockPriceFeed;
    use std::sync::Arc;

    fn make_breaker(price: u64) -> (CircuitBreaker, Arc<MockPriceFeed>) {
        let mock = Arc::new(MockPriceFeed::new("test_feed", price));
        let feed: Box<dyn PriceFeed> = Box::new(MockPriceFeed {
            name:    mock.name.clone(),
            price:   mock.price.clone(),
            offline: mock.offline.clone(),
        });
        (CircuitBreaker::new(feed), mock)
    }

    #[test]
    fn test_closed_allows_requests() {
        let (breaker, _) = make_breaker(100_000);
        assert!(!breaker.is_open());
        assert_eq!(breaker.fetch_price().unwrap(), 100_000);
    }

    #[test]
    fn test_opens_after_threshold_failures() {
        let (breaker, mock) = make_breaker(100_000);
        mock.set_offline(true);

        // 3 failures should open the circuit
        for _ in 0..FAILURE_THRESHOLD {
            assert!(breaker.fetch_price().is_err());
        }
        assert!(breaker.is_open());
    }

    #[test]
    fn test_open_circuit_blocks_immediately() {
        let (breaker, mock) = make_breaker(100_000);
        mock.set_offline(true);
        for _ in 0..FAILURE_THRESHOLD { let _ = breaker.fetch_price(); }
        assert!(breaker.is_open());

        // Even with feed back online, circuit is open
        mock.set_offline(false);
        let result = breaker.fetch_price();
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("circuit breaker open"), "expected circuit breaker message, got: {}", msg);
    }

    #[test]
    fn test_backoff_increases_with_failures() {
        let (breaker, mock) = make_breaker(100_000);
        mock.set_offline(true);

        for i in 1..=5u32 {
            let _ = breaker.fetch_price();
            let backoff = breaker.inner.read().unwrap().backoff_secs;
            let expected = std::cmp::min(MIN_BACKOFF_SECS * (1 << i.saturating_sub(1)), MAX_BACKOFF_SECS);
            assert_eq!(backoff, expected, "failure {}: expected backoff {}s, got {}s", i, expected, backoff);
        }
    }

    #[test]
    fn test_success_resets_state() {
        let (breaker, mock) = make_breaker(100_000);
        mock.set_offline(true);
        // Force it past threshold and back into a Closed-like state by manually resetting:
        for _ in 0..2 { let _ = breaker.fetch_price(); }
        mock.set_offline(false);
        // While still in < THRESHOLD failures, it should be Closed
        assert!(!breaker.is_open());
        let _ = breaker.fetch_price(); // success
        let inner = breaker.inner.read().unwrap();
        assert_eq!(inner.consecutive_fails, 0);
        assert_eq!(inner.backoff_secs, MIN_BACKOFF_SECS);
    }

    #[test]
    fn test_with_circuit_breakers_wraps_all() {
        let feeds: Vec<Box<dyn PriceFeed>> = vec![
            Box::new(MockPriceFeed::new("f1", 1)),
            Box::new(MockPriceFeed::new("f2", 2)),
        ];
        let wrapped = with_circuit_breakers(feeds);
        assert_eq!(wrapped.len(), 2);
        assert_eq!(wrapped[0].name(), "f1");
        assert_eq!(wrapped[1].name(), "f2");
    }
}
