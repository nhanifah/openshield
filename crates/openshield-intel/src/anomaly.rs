//! Layer 2: behavioral anomaly detection over the event stream.
//!
//! Deterministic and explainable. Every signal has a threshold from the
//! config and a reason string. Per-client state lives in tumbling windows of
//! `window_s` seconds; the number of tracked clients is bounded.
//!
//! Signals per client and window:
//! - `rate_spike`: more than `rate_threshold` requests;
//! - `scanning`: at least `scan_404_threshold` distinct paths answered 404;
//! - `attack_burst`: at least `block_burst_threshold` rule blocks;
//! - `error_burst`: a 4xx/5xx share above `error_ratio_threshold`.
//!
//! Global: `traffic_spike` when the last full second exceeds the mean of
//! the previous 10 minutes by `traffic_spike_z` standard deviations.
//!
//! Scores combine as a noisy-OR of the signal weights, so one strong signal
//! gives about 0.5 and several push toward 1.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{BuildHasher, RandomState};

use serde::Serialize;

use crate::config::AnomalyConfig;
use crate::event::{Anomaly, AnomalyReason, SecurityEvent};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AlertDraft {
    pub kind: String,
    pub subject: String,
    pub severity: String,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AutoBlock {
    pub ip: String,
    pub ttl_s: u64,
    pub reason: String,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Observation {
    pub anomaly: Anomaly,
    pub alerts: Vec<AlertDraft>,
    pub auto_block: Option<AutoBlock>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientInfo {
    pub ip: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub requests: u64,
    pub blocked: u64,
    pub anomaly_score: f64,
}

struct ClientState {
    first_seen: i64,
    last_seen: i64,
    window_start: i64,
    count: u32,
    blocked: u32,
    errors: u32,
    not_found: HashSet<u64>,
    /// Signals already alerted in this window.
    alerted: u8,
    total: u64,
    total_blocked: u64,
    last_score: f64,
}

const SIG_RATE: u8 = 1;
const SIG_SCAN: u8 = 2;
const SIG_BURST: u8 = 4;
const SIG_ERROR: u8 = 8;
const SIG_AUTOBLOCK: u8 = 16;
const MAX_404_TRACKED: usize = 512;
const GLOBAL_HISTORY_S: usize = 600;

pub struct Detector {
    cfg: AnomalyConfig,
    clients: HashMap<String, ClientState>,
    hasher: RandomState,
    /// Requests per completed second, most recent last.
    history: VecDeque<u32>,
    current_sec: i64,
    current_count: u32,
    last_spike_alert: i64,
}

impl Detector {
    pub fn new(cfg: AnomalyConfig) -> Self {
        Self {
            cfg,
            clients: HashMap::new(),
            hasher: RandomState::new(),
            history: VecDeque::with_capacity(GLOBAL_HISTORY_S),
            current_sec: 0,
            current_count: 0,
            last_spike_alert: 0,
        }
    }

    pub fn tracked_clients(&self) -> usize {
        self.clients.len()
    }

    pub fn client(&self, ip: &str) -> Option<ClientInfo> {
        self.clients.get(ip).map(|c| ClientInfo {
            ip: ip.to_string(),
            first_seen: c.first_seen,
            last_seen: c.last_seen,
            requests: c.total,
            blocked: c.total_blocked,
            anomaly_score: c.last_score,
        })
    }

    /// Score one event and update state. `now_ms` is the event time.
    pub fn observe(&mut self, ev: &SecurityEvent, now_ms: i64) -> Observation {
        let mut obs = Observation::default();
        if !self.cfg.enabled {
            return obs;
        }
        self.observe_global(now_ms, &mut obs);

        if self.clients.len() >= self.cfg.max_clients && !self.clients.contains_key(&ev.client_ip) {
            self.evict();
        }
        let window_ms = (self.cfg.window_s.max(1) * 1000) as i64;
        let c = self.clients.entry(ev.client_ip.clone()).or_insert_with(|| ClientState {
            first_seen: now_ms,
            last_seen: now_ms,
            window_start: now_ms,
            count: 0,
            blocked: 0,
            errors: 0,
            not_found: HashSet::new(),
            alerted: 0,
            total: 0,
            total_blocked: 0,
            last_score: 0.0,
        });
        if now_ms - c.window_start >= window_ms {
            c.window_start = now_ms;
            c.count = 0;
            c.blocked = 0;
            c.errors = 0;
            c.not_found.clear();
            c.alerted = 0;
        }
        c.last_seen = now_ms;
        c.count += 1;
        c.total += 1;
        if ev.is_blocked() {
            c.blocked += 1;
            c.total_blocked += 1;
        }
        if ev.status >= 400 {
            c.errors += 1;
        }
        if ev.status == 404 && c.not_found.len() < MAX_404_TRACKED {
            c.not_found.insert(self.hasher.hash_one(&ev.path));
        }

        let cfg = &self.cfg;
        let mut reasons = Vec::new();
        let mut fired = 0u8;
        if c.count > cfg.rate_threshold {
            let over = (c.count as f64 / cfg.rate_threshold.max(1) as f64 - 1.0).min(1.0);
            reasons.push(AnomalyReason {
                kind: "rate_spike".into(),
                detail: format!("{} requests in {}s (threshold {})", c.count, cfg.window_s, cfg.rate_threshold),
                weight: 0.4 + 0.3 * over,
            });
            fired |= SIG_RATE;
        }
        if c.not_found.len() as u32 >= cfg.scan_404_threshold {
            reasons.push(AnomalyReason {
                kind: "scanning".into(),
                detail: format!("{} distinct paths answered 404 in {}s", c.not_found.len(), cfg.window_s),
                weight: 0.5,
            });
            fired |= SIG_SCAN;
        }
        if c.blocked >= cfg.block_burst_threshold {
            reasons.push(AnomalyReason {
                kind: "attack_burst".into(),
                detail: format!("{} requests blocked by rules in {}s", c.blocked, cfg.window_s),
                weight: 0.6,
            });
            fired |= SIG_BURST;
        }
        let min_for_ratio = (cfg.rate_threshold / 2).max(5);
        if c.count >= min_for_ratio && c.errors as f64 / c.count as f64 >= cfg.error_ratio_threshold {
            reasons.push(AnomalyReason {
                kind: "error_burst".into(),
                detail: format!("{} of {} responses were errors in {}s", c.errors, c.count, cfg.window_s),
                weight: 0.3,
            });
            fired |= SIG_ERROR;
        }

        let score = 1.0 - reasons.iter().fold(1.0, |acc, r| acc * (1.0 - r.weight));
        c.last_score = score;

        let new = fired & !c.alerted;
        for (bit, kind, severity) in [
            (SIG_RATE, "rate_spike", "medium"),
            (SIG_SCAN, "scanning", "medium"),
            (SIG_BURST, "attack_burst", "high"),
            (SIG_ERROR, "error_burst", "low"),
        ] {
            if new & bit != 0 {
                obs.alerts.push(AlertDraft {
                    kind: kind.into(),
                    subject: ev.client_ip.clone(),
                    severity: severity.into(),
                    detail: serde_json::json!({
                        "window_s": cfg.window_s,
                        "requests": c.count,
                        "blocked": c.blocked,
                        "not_found_paths": c.not_found.len(),
                        "errors": c.errors,
                        "reason": reasons.iter().find(|r| r.kind == kind).map(|r| r.detail.clone()),
                    }),
                });
            }
        }
        c.alerted |= fired;

        let ab = &cfg.auto_block;
        if ab.enabled && c.alerted & SIG_AUTOBLOCK == 0 {
            let by_count = ab.blocks_in_window > 0 && c.blocked >= ab.blocks_in_window;
            // The epsilon keeps a single 0.6 signal at a 0.6 threshold.
            let by_score = ab.min_score > 0.0 && score + 1e-9 >= ab.min_score;
            let reason = if by_count {
                Some(format!(
                    "auto-block: {} rule blocks in {}s (threshold {})",
                    c.blocked, cfg.window_s, ab.blocks_in_window
                ))
            } else if by_score {
                let kinds: Vec<&str> = reasons.iter().map(|r| r.kind.as_str()).collect();
                Some(format!(
                    "auto-block: anomaly score {:.2} ({}) in {}s (threshold {})",
                    score,
                    kinds.join(", "),
                    cfg.window_s,
                    ab.min_score
                ))
            } else {
                None
            };
            if let Some(reason) = reason {
                c.alerted |= SIG_AUTOBLOCK;
                obs.auto_block = Some(AutoBlock {
                    ip: ev.client_ip.clone(),
                    ttl_s: ab.ttl_s,
                    reason,
                });
            }
        }

        obs.anomaly = Anomaly { score, reasons };
        obs
    }

    fn observe_global(&mut self, now_ms: i64, obs: &mut Observation) {
        let sec = now_ms / 1000;
        if self.current_sec == 0 {
            self.current_sec = sec;
        }
        if sec > self.current_sec {
            let finished = self.current_count;
            // Seconds without traffic count as zero.
            let gap = ((sec - self.current_sec - 1) as usize).min(GLOBAL_HISTORY_S);
            self.check_spike(finished, sec, obs);
            self.push_history(finished);
            for _ in 0..gap {
                self.push_history(0);
            }
            self.current_sec = sec;
            self.current_count = 0;
        }
        self.current_count += 1;
    }

    fn push_history(&mut self, v: u32) {
        if self.history.len() >= GLOBAL_HISTORY_S {
            self.history.pop_front();
        }
        self.history.push_back(v);
    }

    fn check_spike(&mut self, value: u32, sec: i64, obs: &mut Observation) {
        if self.history.len() < 60 || sec - self.last_spike_alert < 60 {
            return;
        }
        let n = self.history.len() as f64;
        let mean = self.history.iter().map(|&v| v as f64).sum::<f64>() / n;
        let var = self.history.iter().map(|&v| (v as f64 - mean).powi(2)).sum::<f64>() / n;
        let std = var.sqrt().max(1.0);
        let z = (value as f64 - mean) / std;
        if z >= self.cfg.traffic_spike_z && value >= 20 {
            self.last_spike_alert = sec;
            obs.alerts.push(AlertDraft {
                kind: "traffic_spike".into(),
                subject: "global".into(),
                severity: if z >= self.cfg.traffic_spike_z * 2.0 { "high" } else { "medium" }.into(),
                detail: serde_json::json!({"rps": value, "mean_rps": (mean * 10.0).round() / 10.0,
                                           "std": (std * 10.0).round() / 10.0, "z": (z * 10.0).round() / 10.0}),
            });
        }
    }

    /// Drop the least recently seen tenth of the clients.
    fn evict(&mut self) {
        let mut seen: Vec<i64> = self.clients.values().map(|c| c.last_seen).collect();
        let k = (seen.len() / 10).max(1);
        let (_, cut, _) = seen.select_nth_unstable(k - 1);
        let cut = *cut;
        self.clients.retain(|_, c| c.last_seen > cut);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AutoBlockConfig;
    use crate::event::tests_support::sample_event;

    fn cfg() -> AnomalyConfig {
        AnomalyConfig {
            rate_threshold: 10,
            scan_404_threshold: 5,
            block_burst_threshold: 3,
            max_clients: 100,
            ..Default::default()
        }
    }

    fn ev(ip: &str, path: &str, status: u16, action: &str) -> SecurityEvent {
        let mut e = sample_event();
        e.client_ip = ip.into();
        e.path = path.into();
        e.status = status;
        e.action = action.into();
        e
    }

    #[test]
    fn normal_traffic_scores_zero() {
        let mut d = Detector::new(cfg());
        for i in 0..10 {
            let o = d.observe(&ev("1.1.1.1", "/", 200, "pass"), 1_000 + i * 100);
            assert_eq!(o.anomaly.score, 0.0);
            assert!(o.alerts.is_empty());
        }
    }

    #[test]
    fn rate_spike_alerts_once_per_window() {
        let mut d = Detector::new(cfg());
        let mut alerts = 0;
        let mut last = Observation::default();
        for i in 0..30 {
            last = d.observe(&ev("1.1.1.1", "/", 200, "pass"), 1_000 + i);
            alerts += last.alerts.iter().filter(|a| a.kind == "rate_spike").count();
        }
        assert_eq!(alerts, 1);
        assert!(last.anomaly.score >= 0.4);
        // A new window resets the counters.
        let o = d.observe(&ev("1.1.1.1", "/", 200, "pass"), 1_000 + 11_000);
        assert_eq!(o.anomaly.score, 0.0);
    }

    #[test]
    fn scanning_is_distinct_404_paths() {
        let mut d = Detector::new(cfg());
        for i in 0..4 {
            d.observe(&ev("2.2.2.2", "/same", 404, "pass"), 1_000 + i);
        }
        // Repeated 404s on one path are not scanning (they may be an
        // error burst, which is a separate signal).
        let o = d.observe(&ev("2.2.2.2", "/same", 404, "pass"), 1_010);
        assert!(!o.anomaly.reasons.iter().any(|r| r.kind == "scanning"), "{o:?}");
        let mut o = Observation::default();
        for i in 0..5 {
            o = d.observe(&ev("2.2.2.2", &format!("/p{i}"), 404, "pass"), 1_020 + i);
        }
        assert!(o.anomaly.reasons.iter().any(|r| r.kind == "scanning"), "{o:?}");
    }

    #[test]
    fn attack_burst_and_auto_block_use_rule_blocks_only() {
        let mut c = cfg();
        c.auto_block = AutoBlockConfig {
            enabled: true,
            blocks_in_window: 4,
            ttl_s: 60,
            ..Default::default()
        };
        let mut d = Detector::new(c);
        let mut blocks = Vec::new();
        for i in 0..6 {
            let o = d.observe(&ev("3.3.3.3", "/x", 403, "block"), 1_000 + i);
            if let Some(b) = o.auto_block {
                blocks.push(b);
            }
        }
        assert_eq!(blocks.len(), 1, "one auto-block per window");
        assert_eq!(blocks[0].ip, "3.3.3.3");
        // Errors without rule blocks never auto-block.
        let mut d = Detector::new(cfg());
        for i in 0..20 {
            assert!(d.observe(&ev("4.4.4.4", "/x", 403, "pass"), 1_000 + i).auto_block.is_none());
        }
    }

    fn score_block_cfg(blocks_in_window: u32) -> AnomalyConfig {
        let mut c = cfg();
        c.auto_block = AutoBlockConfig {
            enabled: true,
            blocks_in_window,
            min_score: 0.6,
            ttl_s: 3600,
        };
        c
    }

    #[test]
    fn auto_block_by_anomaly_score() {
        // Scanning (0.5) plus error burst (0.3) scores 0.65: blocked once.
        let mut d = Detector::new(score_block_cfg(0));
        let mut blocks = Vec::new();
        for i in 0..8 {
            if let Some(b) = d.observe(&ev("5.5.5.5", &format!("/p{i}"), 404, "pass"), 1_000 + i).auto_block {
                blocks.push(b);
            }
        }
        assert_eq!(blocks.len(), 1, "{blocks:?}");
        assert_eq!(blocks[0].ttl_s, 3600);
        assert!(blocks[0].reason.contains("anomaly score 0.65"), "{}", blocks[0].reason);
        assert!(blocks[0].reason.contains("scanning"), "{}", blocks[0].reason);

        // Attack burst alone scores exactly 0.6, which meets the threshold.
        let mut d = Detector::new(score_block_cfg(0));
        let mut hit = None;
        for i in 0..3 {
            hit = hit.or(d.observe(&ev("6.6.6.6", "/x", 403, "block"), 1_000 + i).auto_block);
        }
        assert!(hit.is_some_and(|b| b.reason.contains("anomaly score 0.60")));

        // Scanning alone (0.5, with enough 200s to stay out of an error
        // burst) stays under it.
        let mut d = Detector::new(score_block_cfg(0));
        let mut last = Observation::default();
        for i in 0..2 {
            d.observe(&ev("7.7.7.7", "/", 200, "pass"), 1_000 + i);
        }
        for i in 0..5 {
            last = d.observe(&ev("7.7.7.7", &format!("/p{i}"), 404, "pass"), 1_010 + i);
            assert!(last.auto_block.is_none(), "{last:?}");
        }
        assert!(last.anomaly.reasons.iter().any(|r| r.kind == "scanning"), "{last:?}");
        assert!((last.anomaly.score - 0.5).abs() < 1e-9, "{last:?}");
    }

    #[test]
    fn auto_block_count_and_score_are_separate_triggers() {
        // Count trigger with the score trigger off.
        let mut c = score_block_cfg(2);
        c.auto_block.min_score = 0.0;
        let mut d = Detector::new(c);
        d.observe(&ev("8.8.8.8", "/x", 403, "block"), 1_000);
        let b = d.observe(&ev("8.8.8.8", "/x", 403, "block"), 1_001).auto_block.expect("count trigger");
        assert!(b.reason.contains("2 rule blocks"), "{}", b.reason);
        // Both on: the count reason wins when both hold, still one block.
        let mut d = Detector::new(score_block_cfg(3));
        let n = (0..5)
            .filter_map(|i| d.observe(&ev("9.9.9.9", "/x", 403, "block"), 1_000 + i).auto_block)
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn auto_block_is_off_by_default() {
        let mut d = Detector::new(cfg());
        for i in 0..100 {
            assert!(d.observe(&ev("3.3.3.3", "/x", 403, "block"), 1_000 + i).auto_block.is_none());
        }
    }

    #[test]
    fn client_table_is_bounded() {
        let mut d = Detector::new(cfg());
        for i in 0..1000 {
            d.observe(&ev(&format!("10.0.{}.{}", i / 256, i % 256), "/", 200, "pass"), 1_000 + i);
        }
        assert!(d.tracked_clients() <= 100, "{}", d.tracked_clients());
    }

    #[test]
    fn global_traffic_spike() {
        let mut d = Detector::new(cfg());
        let mut t = 1_000_000i64;
        // 120 s of ~5 rps from many clients
        for s in 0..120 {
            for k in 0..5 {
                d.observe(&ev(&format!("9.9.{s}.{k}"), "/", 200, "pass"), t + s * 1000 + k * 10);
            }
        }
        t += 120_000;
        // then one second of 200 requests
        for k in 0..200 {
            d.observe(&ev(&format!("8.8.{}.{}", k / 200, k % 200), "/", 200, "pass"), t + k);
        }
        let o = d.observe(&ev("7.7.7.7", "/", 200, "pass"), t + 1_000);
        assert!(o.alerts.iter().any(|a| a.kind == "traffic_spike"), "{:?}", o.alerts);
    }
}
