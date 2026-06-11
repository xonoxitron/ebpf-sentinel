use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use crate::config::{RateLimitConfig, SuppressionConfig};

#[derive(Debug, Clone)]
struct RateLimit {
    max_alerts: u32,
    window_ns: u64,
}

impl From<&RateLimitConfig> for RateLimit {
    fn from(cfg: &RateLimitConfig) -> Self {
        Self {
            max_alerts: cfg.max_alerts,
            window_ns: cfg.window_secs.saturating_mul(1_000_000_000),
        }
    }
}

pub struct AlertSuppressor {
    default: RateLimit,
    per_rule: HashMap<String, RateLimit>,
    buckets: Mutex<HashMap<(String, u32), VecDeque<u64>>>,
    suppressed: Mutex<u64>,
}

impl AlertSuppressor {
    pub fn new(config: &SuppressionConfig) -> Self {
        let per_rule = config
            .rules
            .iter()
            .map(|(id, cfg)| (id.clone(), RateLimit::from(cfg)))
            .collect();
        Self {
            default: RateLimit::from(&config.default),
            per_rule,
            buckets: Mutex::new(HashMap::new()),
            suppressed: Mutex::new(0),
        }
    }

    pub fn allow(&self, rule_id: &str, pid: u32, timestamp_ns: u64) -> bool {
        let limit = self
            .per_rule
            .get(rule_id)
            .cloned()
            .unwrap_or_else(|| self.default.clone());

        if limit.max_alerts == 0 {
            return false;
        }

        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets
            .entry((rule_id.to_string(), pid))
            .or_insert_with(VecDeque::new);

        let cutoff = timestamp_ns.saturating_sub(limit.window_ns);
        while bucket.front().is_some_and(|&ts| ts < cutoff) {
            bucket.pop_front();
        }

        if bucket.len() >= limit.max_alerts as usize {
            *self.suppressed.lock().unwrap() += 1;
            return false;
        }

        bucket.push_back(timestamp_ns);
        true
    }

    pub fn suppressed_total(&self) -> u64 {
        *self.suppressed.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SuppressionConfig;

    fn test_suppressor(max: u32, window_secs: u64) -> AlertSuppressor {
        AlertSuppressor::new(&SuppressionConfig {
            default: RateLimitConfig {
                max_alerts: max,
                window_secs,
            },
            rules: HashMap::new(),
        })
    }

    #[test]
    fn allows_up_to_max_within_window() {
        let s = test_suppressor(2, 60);
        assert!(s.allow("R1", 1, 1_000_000_000));
        assert!(s.allow("R1", 1, 2_000_000_000));
        assert!(!s.allow("R1", 1, 3_000_000_000));
        assert_eq!(s.suppressed_total(), 1);
    }

    #[test]
    fn separate_keys_independent() {
        let s = test_suppressor(1, 60);
        assert!(s.allow("R1", 1, 1));
        assert!(s.allow("R1", 2, 2));
        assert!(!s.allow("R1", 1, 3));
    }

    #[test]
    fn window_expires_old_entries() {
        let s = test_suppressor(1, 1);
        assert!(s.allow("R1", 1, 0));
        assert!(!s.allow("R1", 1, 500_000_000));
        assert!(s.allow("R1", 1, 2_000_000_001));
    }
}
