//! In-memory traffic statistics for the dashboard.
//!
//! Three tiers, all fixed-size rings:
//! - 1-second counters for the last hour (live chart, 5m/15m ranges);
//! - 1-minute counters for the last 7 days (longer ranges);
//! - 10-minute blocks with breakdowns (top IPs, paths, rules, status
//!   classes, methods, countries) for the last 24 hours. Top tables are
//!   capped per block; keys first seen after a block is full are not
//!   counted in that block's table (totals stay exact).

use std::collections::HashMap;

use serde::Serialize;

use crate::event::SecurityEvent;

const SEC_SLOTS: usize = 3600;
const MIN_SLOTS: usize = 7 * 24 * 60;
const BLOCK_MS: i64 = 10 * 60 * 1000;
const BLOCK_SLOTS: usize = 24 * 6;
const TOP_CAP: usize = 500;
const SMALL_CAP: usize = 64;

/// Latency histogram: bucket i holds durations below `BOUNDS[i]` ms.
const BOUNDS: [f64; 28] = [
    0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0, 7.5, 10.0, 15.0, 20.0, 30.0, 50.0, 75.0, 100.0,
    150.0, 250.0, 500.0, 1000.0, 2000.0, 5000.0, 10000.0, 30000.0, f64::INFINITY,
];

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq)]
pub struct Counts {
    /// All requests. Serialized as `requests` (the API contract's name).
    #[serde(rename = "requests")]
    pub total: u64,
    pub pass: u64,
    pub allow: u64,
    pub block: u64,
    pub challenge: u64,
    pub suspicious: u64,
    pub status_5xx: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl Counts {
    fn add(&mut self, o: &Counts) {
        self.total += o.total;
        self.pass += o.pass;
        self.allow += o.allow;
        self.block += o.block;
        self.challenge += o.challenge;
        self.suspicious += o.suspicious;
        self.status_5xx += o.status_5xx;
        self.bytes_in += o.bytes_in;
        self.bytes_out += o.bytes_out;
    }
}

#[derive(Clone, Default)]
struct Slot {
    start: i64,
    counts: Counts,
    hist: [u32; 28],
}

impl Slot {
    fn reset(&mut self, start: i64) {
        *self = Slot {
            start,
            ..Default::default()
        };
    }
}

#[derive(Clone, Default)]
struct IpAgg {
    count: u64,
    blocked: u64,
    country: Option<String>,
    anomaly: f64,
}

#[derive(Clone, Default)]
struct Block {
    start: i64,
    ips: HashMap<String, IpAgg>,
    paths: HashMap<String, (u64, u64)>,
    rules: HashMap<String, u64>,
    status: [u64; 6],
    methods: HashMap<String, u64>,
    countries: HashMap<String, u64>,
}

pub struct Stats {
    secs: Vec<Slot>,
    mins: Vec<Slot>,
    blocks: Vec<Block>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SeriesPoint {
    pub t: i64,
    pub total: u64,
    pub pass: u64,
    pub allow: u64,
    pub block: u64,
    pub challenge: u64,
    pub suspicious: u64,
    pub p95_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopIp {
    pub ip: String,
    pub count: u64,
    pub blocked: u64,
    pub country: Option<String>,
    pub anomaly_score: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopPath {
    pub path: String,
    pub count: u64,
    pub blocked: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopRule {
    pub id: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Latency {
    pub p50: Option<f64>,
    pub p95: Option<f64>,
    pub p99: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub range_ms: i64,
    pub bucket_ms: i64,
    pub now: i64,
    pub totals: Counts,
    pub rps_current: f64,
    pub latency_ms: Latency,
    pub series: Vec<SeriesPoint>,
    pub top_ips: Vec<TopIp>,
    pub top_paths: Vec<TopPath>,
    pub top_rules: Vec<TopRule>,
    pub status_codes: HashMap<String, u64>,
    pub methods: HashMap<String, u64>,
    pub countries: HashMap<String, u64>,
}

/// Is this event "suspicious" for the counters: anomalous, or an AI verdict
/// of suspicious or malicious.
pub fn is_suspicious(ev: &SecurityEvent) -> bool {
    ev.anomaly.score >= 0.5
        || ev
            .ai
            .as_ref()
            .is_some_and(|v| matches!(v.category.as_str(), "suspicious" | "malicious"))
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    pub fn new() -> Self {
        Self {
            secs: vec![Slot::default(); SEC_SLOTS],
            mins: vec![Slot::default(); MIN_SLOTS],
            blocks: vec![Block::default(); BLOCK_SLOTS],
        }
    }

    pub fn record(&mut self, ev: &SecurityEvent) {
        let c = Counts {
            total: 1,
            pass: (ev.action == "pass") as u64,
            allow: (ev.action == "allow") as u64,
            block: (ev.action == "block") as u64,
            challenge: (ev.action == "challenge") as u64,
            suspicious: is_suspicious(ev) as u64,
            status_5xx: (ev.status >= 500) as u64,
            bytes_in: ev.bytes_in,
            bytes_out: ev.bytes_out,
        };
        let bucket = BOUNDS.iter().position(|b| ev.duration_ms < *b).unwrap_or(BOUNDS.len() - 1);
        for (slots, width) in [(&mut self.secs, 1000i64), (&mut self.mins, 60_000)] {
            let start = ev.ts - ev.ts.rem_euclid(width);
            let i = ((start / width) as usize) % slots.len();
            if slots[i].start != start {
                slots[i].reset(start);
            }
            slots[i].counts.add(&c);
            slots[i].hist[bucket] += 1;
        }

        let start = ev.ts - ev.ts.rem_euclid(BLOCK_MS);
        let i = ((start / BLOCK_MS) as usize) % BLOCK_SLOTS;
        let b = &mut self.blocks[i];
        if b.start != start {
            *b = Block {
                start,
                ..Default::default()
            };
        }
        let blocked = ev.is_blocked() as u64;
        if let Some(a) = capped(&mut b.ips, &ev.client_ip, TOP_CAP) {
            a.count += 1;
            a.blocked += blocked;
            if a.country.is_none() {
                a.country = ev.country.clone();
            }
            a.anomaly = a.anomaly.max(ev.anomaly.score);
        }
        if let Some(p) = capped(&mut b.paths, &ev.path, TOP_CAP) {
            p.0 += 1;
            p.1 += blocked;
        }
        for r in &ev.matched_rules {
            if let Some(n) = capped(&mut b.rules, &r.id, TOP_CAP) {
                *n += 1;
            }
        }
        b.status[((ev.status / 100) as usize).min(5)] += 1;
        if let Some(n) = capped(&mut b.methods, &ev.method, SMALL_CAP) {
            *n += 1;
        }
        if let Some(country) = &ev.country
            && let Some(n) = capped(&mut b.countries, country, 300)
        {
            *n += 1;
        }
    }

    /// Counts of the last full second (for the `stats` stream tick).
    pub fn second(&self, sec_start: i64) -> (Counts, Option<f64>) {
        let i = ((sec_start / 1000) as usize) % SEC_SLOTS;
        let s = &self.secs[i];
        if s.start == sec_start {
            (s.counts, percentile(&s.hist, 0.95))
        } else {
            (Counts::default(), None)
        }
    }

    pub fn overview(&self, now: i64, range_ms: i64) -> Overview {
        let (slots, width) = if range_ms <= 15 * 60_000 {
            (&self.secs, 1000i64)
        } else {
            (&self.mins, 60_000)
        };
        let range_ms = range_ms.min(width * slots.len() as i64);
        let n = (range_ms / width).max(1);
        // Group slots into at most ~120 chart points.
        let per_point = ((n + 119) / 120).max(1);
        let bucket_ms = width * per_point;
        let end = now - now.rem_euclid(width);
        let first = end - (n - 1) * width;

        let mut totals = Counts::default();
        let mut hist = [0u32; 28];
        let mut series = Vec::new();
        let mut point = Counts::default();
        let mut point_hist = [0u32; 28];
        let mut point_start = first;
        for k in 0..n {
            let start = first + k * width;
            let s = &slots[((start / width) as usize) % slots.len()];
            if s.start == start {
                point.add(&s.counts);
                totals.add(&s.counts);
                for (a, b) in point_hist.iter_mut().zip(s.hist.iter()) {
                    *a += b;
                }
                for (a, b) in hist.iter_mut().zip(s.hist.iter()) {
                    *a += b;
                }
            }
            if (k + 1) % per_point == 0 || k == n - 1 {
                series.push(SeriesPoint {
                    t: point_start,
                    total: point.total,
                    pass: point.pass,
                    allow: point.allow,
                    block: point.block,
                    challenge: point.challenge,
                    suspicious: point.suspicious,
                    p95_ms: percentile(&point_hist, 0.95),
                });
                point = Counts::default();
                point_hist = [0; 28];
                point_start = start + width;
            }
        }

        // Current rate: the last 5 complete seconds.
        let sec_now = now - now.rem_euclid(1000);
        let recent: u64 = (1..=5)
            .map(|k| {
                let st = sec_now - k * 1000;
                let s = &self.secs[((st / 1000) as usize) % SEC_SLOTS];
                if s.start == st { s.counts.total } else { 0 }
            })
            .sum();

        // Breakdowns from the 10-minute blocks overlapping the range (24 h max).
        let mut ips: HashMap<&str, IpAgg> = HashMap::new();
        let mut paths: HashMap<&str, (u64, u64)> = HashMap::new();
        let mut rules: HashMap<&str, u64> = HashMap::new();
        let mut status = [0u64; 6];
        let mut methods: HashMap<String, u64> = HashMap::new();
        let mut countries: HashMap<String, u64> = HashMap::new();
        let since = now - range_ms.min(BLOCK_MS * BLOCK_SLOTS as i64);
        for b in &self.blocks {
            if b.start + BLOCK_MS <= since || b.start > now || b.start == 0 {
                continue;
            }
            for (k, v) in &b.ips {
                let e = ips.entry(k).or_default();
                e.count += v.count;
                e.blocked += v.blocked;
                e.anomaly = e.anomaly.max(v.anomaly);
                if e.country.is_none() {
                    e.country = v.country.clone();
                }
            }
            for (k, v) in &b.paths {
                let e = paths.entry(k).or_default();
                e.0 += v.0;
                e.1 += v.1;
            }
            for (k, v) in &b.rules {
                *rules.entry(k).or_default() += v;
            }
            for (a, v) in status.iter_mut().zip(b.status.iter()) {
                *a += v;
            }
            for (k, v) in &b.methods {
                *methods.entry(k.clone()).or_default() += v;
            }
            for (k, v) in &b.countries {
                *countries.entry(k.clone()).or_default() += v;
            }
        }
        let mut top_ips: Vec<TopIp> = ips
            .into_iter()
            .map(|(ip, a)| TopIp {
                ip: ip.to_string(),
                count: a.count,
                blocked: a.blocked,
                country: a.country,
                anomaly_score: a.anomaly,
            })
            .collect();
        top_ips.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ip.cmp(&b.ip)));
        top_ips.truncate(20);
        let mut top_paths: Vec<TopPath> = paths
            .into_iter()
            .map(|(p, (c, b))| TopPath {
                path: p.to_string(),
                count: c,
                blocked: b,
            })
            .collect();
        top_paths.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.path.cmp(&b.path)));
        top_paths.truncate(20);
        let mut top_rules: Vec<TopRule> = rules
            .into_iter()
            .map(|(id, c)| TopRule {
                id: id.to_string(),
                count: c,
            })
            .collect();
        top_rules.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.id.cmp(&b.id)));
        top_rules.truncate(20);
        let status_codes = ["1xx", "2xx", "3xx", "4xx", "5xx"]
            .iter()
            .enumerate()
            .map(|(i, k)| (k.to_string(), status[i + 1]))
            .filter(|(_, v)| *v > 0)
            .collect();

        Overview {
            range_ms,
            bucket_ms,
            now,
            totals,
            rps_current: recent as f64 / 5.0,
            latency_ms: Latency {
                p50: percentile(&hist, 0.5),
                p95: percentile(&hist, 0.95),
                p99: percentile(&hist, 0.99),
            },
            series,
            top_ips,
            top_paths,
            top_rules,
            status_codes,
            methods,
            countries,
        }
    }

    /// Hits per rule over the last hour.
    pub fn rule_hits(&self, now: i64) -> HashMap<String, u64> {
        let mut out = HashMap::new();
        for b in &self.blocks {
            if b.start != 0 && b.start + BLOCK_MS > now - 3_600_000 && b.start <= now {
                for (k, v) in &b.rules {
                    *out.entry(k.clone()).or_default() += v;
                }
            }
        }
        out
    }
}

fn capped<'a, V: Default>(map: &'a mut HashMap<String, V>, key: &str, cap: usize) -> Option<&'a mut V> {
    if !map.contains_key(key) {
        if map.len() >= cap {
            return None;
        }
        map.insert(key.to_string(), V::default());
    }
    map.get_mut(key)
}

/// Approximate percentile from the histogram: the upper bound of the
/// bucket holding the requested rank, interpolated inside the bucket.
fn percentile(hist: &[u32; 28], p: f64) -> Option<f64> {
    let total: u64 = hist.iter().map(|&v| v as u64).sum();
    if total == 0 {
        return None;
    }
    let rank = (p * total as f64).ceil().max(1.0) as u64;
    let mut seen = 0u64;
    for (i, &n) in hist.iter().enumerate() {
        if seen + n as u64 >= rank {
            let lo = if i == 0 { 0.0 } else { BOUNDS[i - 1] };
            let hi = if BOUNDS[i].is_finite() { BOUNDS[i] } else { lo * 2.0 };
            let frac = (rank - seen) as f64 / n.max(1) as f64;
            return Some(((lo + (hi - lo) * frac) * 1000.0).round() / 1000.0);
        }
        seen += n as u64;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::MatchedRule;
    use crate::event::tests_support::sample_event;

    fn ev(ts: i64, action: &str, ip: &str, dur: f64) -> SecurityEvent {
        let mut e = sample_event();
        e.ts = ts;
        e.action = action.into();
        e.client_ip = ip.into();
        e.duration_ms = dur;
        if action == "block" {
            e.matched_rules.push(MatchedRule {
                id: "r1".into(),
                action: "block".into(),
            });
            e.status = 403;
        }
        e
    }

    #[test]
    fn totals_series_and_tops() {
        let mut s = Stats::new();
        let now = 1_761_400_000_000i64;
        for i in 0..90 {
            s.record(&ev(now - 30_000 + i * 100, "pass", "1.1.1.1", 1.0));
        }
        for i in 0..10 {
            s.record(&ev(now - 20_000 + i * 100, "block", "6.6.6.6", 0.2));
        }
        let o = s.overview(now, 5 * 60_000);
        assert_eq!(o.totals.total, 100);
        assert_eq!(o.totals.block, 10);
        assert_eq!(o.series.iter().map(|p| p.total).sum::<u64>(), 100);
        assert!(o.series.len() <= 120);
        assert_eq!(o.top_ips[0].ip, "1.1.1.1");
        assert_eq!(o.top_ips[1].blocked, 10);
        assert_eq!(o.top_rules[0].id, "r1");
        assert_eq!(o.status_codes["4xx"], 10);
        let p50 = o.latency_ms.p50.unwrap();
        // 1.0 ms falls in the [1.0, 1.5) bucket.
        assert!((1.0..=1.5).contains(&p50), "{p50}");
        assert_eq!(s.rule_hits(now)["r1"], 10);
    }

    #[test]
    fn old_slots_do_not_leak_into_new_ranges() {
        let mut s = Stats::new();
        let now = 1_761_400_000_000i64;
        s.record(&ev(now - 2 * 3_600_000, "pass", "1.1.1.1", 1.0));
        assert_eq!(s.overview(now, 15 * 60_000).totals.total, 0);
        assert_eq!(s.overview(now, 3 * 3_600_000).totals.total, 1);
    }

    #[test]
    fn top_tables_are_capped() {
        let mut s = Stats::new();
        let now = 1_761_400_000_000i64;
        for i in 0..2000 {
            s.record(&ev(now - 1000, "pass", &format!("10.0.{}.{}", i / 256, i % 256), 1.0));
        }
        let o = s.overview(now, 60_000);
        assert_eq!(o.totals.total, 2000, "totals stay exact");
        let b = &s.blocks[(((now - 1000) - (now - 1000).rem_euclid(BLOCK_MS)) / BLOCK_MS) as usize % BLOCK_SLOTS];
        assert!(b.ips.len() <= TOP_CAP);
    }

    #[test]
    fn percentile_of_empty_is_none() {
        assert_eq!(percentile(&[0; 28], 0.5), None);
    }
}
