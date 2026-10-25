use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher, RandomState};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pingora_limits::rate::Rate;

use crate::config::RateLimitConfig;

/// Upper bound on keys held in mitigation per rule. Bounds memory when an
/// attacker controls a key characteristic (path, user agent, IPv6 source).
pub const MAX_MITIGATED_KEYS: usize = 100_000;

/// A rate limiter instance for a single rule.
pub struct RuleLimiter {
    rate: Arc<Rate>,
    requests_per_period: u64,
    mitigation_timeout: Duration,
    /// When each key entered mitigation, by keyed hash of the key.
    mitigated: Mutex<HashMap<u64, Instant>>,
    /// Per-process random hash key, so key collisions cannot be precomputed.
    hasher: RandomState,
    max_mitigated: usize,
}

impl RuleLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        Self::with_capacity(config, MAX_MITIGATED_KEYS)
    }

    pub fn with_capacity(config: &RateLimitConfig, max_mitigated: usize) -> Self {
        let period = Duration::from_secs(config.period.max(1));
        Self {
            rate: Arc::new(Rate::new(period)),
            requests_per_period: config.requests_per_period,
            mitigation_timeout: Duration::from_secs(config.mitigation_timeout),
            mitigated: Mutex::new(HashMap::new()),
            hasher: RandomState::new(),
            max_mitigated,
        }
    }

    /// Observe a request and return true if it should be blocked.
    pub fn check_and_incr(&self, key: &RateLimitKey) -> bool {
        let mitigating = !self.mitigation_timeout.is_zero();
        let key_hash = self.hasher.hash_one(key);

        if mitigating {
            let mut mitigated = self.mitigated.lock().unwrap();
            if let Some(since) = mitigated.get(&key_hash) {
                if since.elapsed() < self.mitigation_timeout {
                    // Still in mitigation: count the request but stay blocked.
                    drop(mitigated);
                    self.rate.observe(key, 1);
                    return true;
                }
                mitigated.remove(&key_hash);
            }
        }

        let count = self.rate.observe(key, 1);
        let exceeded = count as u64 > self.requests_per_period;

        if exceeded && mitigating {
            let mut mitigated = self.mitigated.lock().unwrap();
            if mitigated.len() >= self.max_mitigated {
                let timeout = self.mitigation_timeout;
                mitigated.retain(|_, since| since.elapsed() < timeout);
            }
            // Still full: the request is blocked by the rate itself, but the
            // key is not remembered beyond the counting period.
            if mitigated.len() < self.max_mitigated {
                mitigated.entry(key_hash).or_insert_with(Instant::now);
            }
        }

        exceeded
    }

    /// Keys currently held in mitigation (including expired ones not yet
    /// swept).
    pub fn mitigated_len(&self) -> usize {
        self.mitigated.lock().unwrap().len()
    }
}

/// Composite key for rate limiting, built from characteristics.
#[derive(Clone, Debug)]
pub struct RateLimitKey {
    parts: Vec<String>,
}

impl Default for RateLimitKey {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitKey {
    pub fn new() -> Self {
        Self { parts: Vec::new() }
    }

    pub fn push(&mut self, value: String) {
        self.parts.push(value);
    }
}

impl std::fmt::Display for RateLimitKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.parts.join(":"))
    }
}

impl Hash for RateLimitKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for part in &self.parts {
            part.hash(state);
        }
    }
}

/// Manages rate limiters for all rules that have ratelimit config.
pub struct RateLimitManager {
    limiters: HashMap<String, RuleLimiter>,
}

impl Default for RateLimitManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitManager {
    pub fn new() -> Self {
        Self {
            limiters: HashMap::new(),
        }
    }

    pub fn add_rule(&mut self, rule_id: &str, config: &RateLimitConfig) {
        // Only create new limiter if rule doesn't already exist (preserves
        // state across reloads)
        if !self.limiters.contains_key(rule_id) {
            self.limiters
                .insert(rule_id.to_string(), RuleLimiter::new(config));
        }
    }

    /// Check if the rate limit for a rule is exceeded. Returns true if
    /// exceeded.
    pub fn check(&self, rule_id: &str, key: &RateLimitKey) -> bool {
        self.limiters
            .get(rule_id)
            .map(|limiter| limiter.check_and_incr(key))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(rpp: u64, timeout: u64) -> RateLimitConfig {
        RateLimitConfig {
            characteristics: vec![],
            period: 60,
            requests_per_period: rpp,
            mitigation_timeout: timeout,
        }
    }

    fn key(parts: &[&str]) -> RateLimitKey {
        let mut k = RateLimitKey::new();
        for p in parts {
            k.push(p.to_string());
        }
        k
    }

    #[test]
    fn mitigation_table_is_bounded() {
        // Regression: every exceeding key used to be kept until it returned.
        let limiter = RuleLimiter::with_capacity(&config(0, 3600), 1000);
        for i in 0..5000 {
            assert!(limiter.check_and_incr(&key(&[&format!("k{i}")])));
        }
        assert!(limiter.mitigated_len() <= 1000, "{}", limiter.mitigated_len());
    }

    #[test]
    fn mitigated_key_stays_blocked() {
        let limiter = RuleLimiter::new(&config(1, 3600));
        let k = key(&["1.2.3.4"]);
        assert!(!limiter.check_and_incr(&k));
        assert!(limiter.check_and_incr(&k));
        assert_eq!(limiter.mitigated_len(), 1);
        assert!(limiter.check_and_incr(&k));
    }

    #[test]
    fn keys_with_separator_do_not_collide() {
        // "a:b"+"c" and "a"+"b:c" used to share the string key "a:b:c".
        let limiter = RuleLimiter::new(&config(1, 3600));
        let a = key(&["a:b", "c"]);
        let b = key(&["a", "b:c"]);
        assert!(!limiter.check_and_incr(&a));
        assert!(limiter.check_and_incr(&a));
        assert!(!limiter.check_and_incr(&b), "distinct key was mitigated");
    }
}
