//! Asynchronous AI supervision.
//!
//! The request path never waits for a model. Eligible events are offered to
//! a bounded queue (`try_send`: full means dropped and counted). A worker
//! batches them, answers from the cache when it can, and otherwise calls the
//! provider under a concurrency limit, a per-minute rate, a daily call
//! budget and a circuit breaker. Validated verdicts go to the event hub.
//!
//! Failure policy: AI analysis fails open. When the provider is slow, down,
//! rate-limited or over budget, events are simply left without a verdict;
//! deterministic rules, rate limits and dynamic blocks are unaffected
//! because they never depend on this module.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::{Semaphore, mpsc};

use super::gemini::{Completion, GeminiClient, ProviderError};
use super::prompt::{self, Validated, VerdictMeta};
use super::types::{AiInput, AiVerdict};
use crate::config::AiConfig;

enum Reserve {
    Granted,
    Wait(Duration),
    Denied(String),
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A model backend.
pub trait Provider: Send + Sync {
    fn name(&self) -> &str;
    fn model(&self) -> &str;
    fn classify<'a>(&'a self, inputs: &'a [AiInput]) -> BoxFuture<'a, Result<Completion, ProviderError>>;
    fn complete<'a>(
        &'a self,
        system: &'a str,
        user: &'a str,
        max_tokens: u64,
    ) -> BoxFuture<'a, Result<Completion, ProviderError>>;
}

impl Provider for GeminiClient {
    fn name(&self) -> &str {
        "gemini"
    }
    fn model(&self) -> &str {
        GeminiClient::model(self)
    }
    fn classify<'a>(&'a self, inputs: &'a [AiInput]) -> BoxFuture<'a, Result<Completion, ProviderError>> {
        Box::pin(GeminiClient::classify(self, inputs))
    }
    fn complete<'a>(
        &'a self,
        system: &'a str,
        user: &'a str,
        max_tokens: u64,
    ) -> BoxFuture<'a, Result<Completion, ProviderError>> {
        Box::pin(GeminiClient::complete(self, system, user, max_tokens))
    }
}

/// One event waiting for analysis.
#[derive(Debug, Clone)]
pub struct Job {
    pub event_id: String,
    pub fingerprint: String,
    pub input: AiInput,
}

/// What the supervisor reports for an event.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub event_id: String,
    pub fingerprint: String,
    pub result: Result<AiVerdict, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

struct Breaker {
    failures: u32,
    open_until: Option<Instant>,
    threshold: u32,
    cooldown: Duration,
}

impl Breaker {
    fn state(&self) -> BreakerState {
        match self.open_until {
            None => BreakerState::Closed,
            Some(t) if Instant::now() < t => BreakerState::Open,
            Some(_) => BreakerState::HalfOpen,
        }
    }
    fn allow(&self) -> bool {
        self.state() != BreakerState::Open
    }
    fn success(&mut self) {
        self.failures = 0;
        self.open_until = None;
    }
    fn failure(&mut self) {
        self.failures += 1;
        if self.failures >= self.threshold || self.state() == BreakerState::HalfOpen {
            self.open_until = Some(Instant::now() + self.cooldown);
        }
    }
}

/// Fixed-window limiter: at most `per_minute` calls per minute.
struct MinuteWindow {
    per_minute: u32,
    window_start: Instant,
    used: u32,
}

impl MinuteWindow {
    fn try_take(&mut self) -> Result<(), Duration> {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(60) {
            self.window_start = now;
            self.used = 0;
        }
        if self.used < self.per_minute {
            self.used += 1;
            Ok(())
        } else {
            Err(Duration::from_secs(60).saturating_sub(now.duration_since(self.window_start)))
        }
    }
}

#[derive(Default)]
pub struct Counters {
    pub queued: AtomicU64,
    pub analyzed: AtomicU64,
    pub failures: AtomicU64,
    pub invalid_outputs: AtomicU64,
    pub cache_hits: AtomicU64,
    pub dropped: AtomicU64,
    pub skipped_breaker: AtomicU64,
    pub skipped_budget: AtomicU64,
    pub calls: AtomicU64,
    pub tokens_in: AtomicU64,
    pub tokens_out: AtomicU64,
    /// Cost in millionths of a USD.
    pub cost_micro_usd: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub enabled: bool,
    pub provider: String,
    pub model: String,
    pub state: String,
    pub breaker: BreakerState,
    pub queue: u64,
    pub queue_capacity: usize,
    pub analyzed: u64,
    pub failures: u64,
    pub invalid_outputs: u64,
    pub cache_hits: u64,
    pub dropped: u64,
    pub skipped_breaker: u64,
    pub skipped_budget: u64,
    pub calls: u64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_usd: f64,
    pub budget: Budget,
    pub latency_ms: Latency,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Budget {
    pub calls_today: u32,
    pub max_calls_per_day: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Latency {
    pub p50: Option<u64>,
    pub p95: Option<u64>,
}

struct Inner {
    breaker: Breaker,
    window: MinuteWindow,
    day: i64,
    calls_today: u32,
    cache: HashMap<String, (AiVerdict, Instant)>,
    latencies: Vec<u64>,
    last_error: Option<String>,
}

pub struct Supervisor {
    cfg: AiConfig,
    provider: Arc<dyn Provider>,
    tx: mpsc::Sender<Job>,
    pub counters: Counters,
    inner: Mutex<Inner>,
    sem: Arc<Semaphore>,
}

const CACHE_MAX: usize = 10_000;
const LATENCY_SAMPLES: usize = 512;

impl Supervisor {
    /// Build the supervisor and spawn its worker on the current Tokio
    /// runtime. Outcomes are sent to `out`.
    pub fn start(cfg: AiConfig, provider: Arc<dyn Provider>, out: mpsc::UnboundedSender<Outcome>) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(cfg.queue_capacity.max(1));
        let sup = Arc::new(Self {
            sem: Arc::new(Semaphore::new(cfg.max_concurrency.max(1))),
            inner: Mutex::new(Inner {
                breaker: Breaker {
                    failures: 0,
                    open_until: None,
                    threshold: cfg.breaker_failures.max(1),
                    cooldown: Duration::from_secs(cfg.breaker_cooldown_s.max(1)),
                },
                window: MinuteWindow {
                    per_minute: cfg.requests_per_minute.max(1),
                    window_start: Instant::now(),
                    used: 0,
                },
                day: today(),
                calls_today: 0,
                cache: HashMap::new(),
                latencies: Vec::new(),
                last_error: None,
            }),
            cfg,
            provider,
            tx,
            counters: Counters::default(),
        });
        tokio::spawn(Arc::clone(&sup).run(rx, out));
        sup
    }

    /// Offer a job without waiting. Returns false when the queue is full.
    pub fn offer(&self, job: Job) -> bool {
        match self.tx.try_send(job) {
            Ok(()) => {
                self.counters.queued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => {
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn status(&self) -> Status {
        let c = &self.counters;
        let inner = self.inner.lock();
        let breaker = inner.breaker.state();
        let mut lat = inner.latencies.clone();
        lat.sort_unstable();
        let pct = |p: f64| (!lat.is_empty()).then(|| lat[((lat.len() - 1) as f64 * p) as usize]);
        let queue = (self.cfg.queue_capacity - self.tx.capacity()) as u64;
        let state = match breaker {
            BreakerState::Open => "open",
            BreakerState::HalfOpen => "degraded",
            BreakerState::Closed if inner.breaker.failures > 0 => "degraded",
            BreakerState::Closed => "ok",
        };
        Status {
            enabled: true,
            provider: self.provider.name().into(),
            model: self.provider.model().into(),
            state: state.into(),
            breaker,
            queue,
            queue_capacity: self.cfg.queue_capacity,
            analyzed: c.analyzed.load(Ordering::Relaxed),
            failures: c.failures.load(Ordering::Relaxed),
            invalid_outputs: c.invalid_outputs.load(Ordering::Relaxed),
            cache_hits: c.cache_hits.load(Ordering::Relaxed),
            dropped: c.dropped.load(Ordering::Relaxed),
            skipped_breaker: c.skipped_breaker.load(Ordering::Relaxed),
            skipped_budget: c.skipped_budget.load(Ordering::Relaxed),
            calls: c.calls.load(Ordering::Relaxed),
            tokens_in: c.tokens_in.load(Ordering::Relaxed),
            tokens_out: c.tokens_out.load(Ordering::Relaxed),
            cost_usd: c.cost_micro_usd.load(Ordering::Relaxed) as f64 / 1e6,
            budget: Budget {
                calls_today: inner.calls_today,
                max_calls_per_day: self.cfg.max_calls_per_day,
            },
            latency_ms: Latency {
                p50: pct(0.5),
                p95: pct(0.95),
            },
            last_error: inner.last_error.clone(),
        }
    }

    /// Reserve one provider call, waiting for the per-minute window if
    /// needed. On `Err` (breaker open, budget spent) no call may be made.
    async fn reserve_call(&self) -> Result<(), String> {
        loop {
            match self.try_reserve() {
                Reserve::Granted => return Ok(()),
                Reserve::Denied(r) => return Err(r),
                Reserve::Wait(d) => tokio::time::sleep(d.max(Duration::from_millis(50))).await,
            }
        }
    }

    fn try_reserve(&self) -> Reserve {
        match self.check_limits() {
            Ok(()) => Reserve::Granted,
            Err(Ok(wait)) => Reserve::Wait(wait),
            Err(Err(reason)) => Reserve::Denied(reason),
        }
    }

    /// Breaker, daily budget, then the minute window.
    fn check_limits(&self) -> Result<(), Result<Duration, String>> {
        let mut inner = self.inner.lock();
        if !inner.breaker.allow() {
            self.counters.skipped_breaker.fetch_add(1, Ordering::Relaxed);
            return Err(Err("circuit breaker open".into()));
        }
        let d = today();
        if inner.day != d {
            inner.day = d;
            inner.calls_today = 0;
        }
        if inner.calls_today >= self.cfg.max_calls_per_day {
            self.counters.skipped_budget.fetch_add(1, Ordering::Relaxed);
            return Err(Err("daily call budget exhausted".into()));
        }
        inner.window.try_take().map_err(Ok)?;
        inner.calls_today += 1;
        Ok(())
    }

    fn record_call(&self, res: &Result<Completion, ProviderError>) {
        self.counters.calls.fetch_add(1, Ordering::Relaxed);
        let mut inner = self.inner.lock();
        match res {
            Ok(c) => {
                inner.breaker.success();
                if inner.latencies.len() >= LATENCY_SAMPLES {
                    inner.latencies.remove(0);
                }
                inner.latencies.push(c.latency_ms);
                self.counters.tokens_in.fetch_add(c.tokens_in, Ordering::Relaxed);
                self.counters.tokens_out.fetch_add(c.tokens_out, Ordering::Relaxed);
                let cost = c.tokens_in as f64 * self.cfg.price_per_mtok_in + c.tokens_out as f64 * self.cfg.price_per_mtok_out;
                self.counters.cost_micro_usd.fetch_add(cost.round() as u64, Ordering::Relaxed);
            }
            Err(e) => {
                if e.is_transient() {
                    inner.breaker.failure();
                }
                inner.last_error = Some(e.to_string());
            }
        }
    }

    fn cache_get(&self, fp: &str) -> Option<AiVerdict> {
        let mut inner = self.inner.lock();
        match inner.cache.get(fp) {
            Some((v, exp)) if Instant::now() < *exp => Some(v.clone()),
            Some(_) => {
                inner.cache.remove(fp);
                None
            }
            None => None,
        }
    }

    fn cache_put(&self, fp: &str, v: &AiVerdict) {
        if self.cfg.cache_ttl_s == 0 {
            return;
        }
        let mut inner = self.inner.lock();
        if inner.cache.len() >= CACHE_MAX {
            let now = Instant::now();
            inner.cache.retain(|_, (_, exp)| now < *exp);
            if inner.cache.len() >= CACHE_MAX {
                inner.cache.clear();
            }
        }
        inner
            .cache
            .insert(fp.to_string(), (v.clone(), Instant::now() + Duration::from_secs(self.cfg.cache_ttl_s)));
    }

    async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<Job>, out: mpsc::UnboundedSender<Outcome>) {
        let max_batch = self.cfg.max_batch.max(1);
        while let Some(first) = rx.recv().await {
            let mut batch = vec![first];
            // Gather a batch for up to 200 ms.
            let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
            while batch.len() < max_batch {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some(j)) => batch.push(j),
                    _ => break,
                }
            }
            // Answer duplicates and cached shapes without a call.
            let mut pending: Vec<Job> = Vec::new();
            let mut seen: HashMap<String, usize> = HashMap::new();
            let mut followers: Vec<(Job, usize)> = Vec::new();
            for job in batch {
                if let Some(mut v) = self.cache_get(&job.fingerprint) {
                    v.cached = true;
                    self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
                    self.counters.analyzed.fetch_add(1, Ordering::Relaxed);
                    let _ = out.send(Outcome {
                        event_id: job.event_id,
                        fingerprint: job.fingerprint,
                        result: Ok(v),
                    });
                    continue;
                }
                if let Some(&leader) = seen.get(&job.fingerprint) {
                    followers.push((job, leader));
                } else {
                    seen.insert(job.fingerprint.clone(), pending.len());
                    pending.push(job);
                }
            }
            if pending.is_empty() {
                continue;
            }
            if let Err(reason) = self.reserve_call().await {
                for job in pending.into_iter().chain(followers.into_iter().map(|(j, _)| j)) {
                    let _ = out.send(Outcome {
                        event_id: job.event_id,
                        fingerprint: job.fingerprint,
                        result: Err(format!("not analyzed: {reason}")),
                    });
                }
                continue;
            }
            let permit = Arc::clone(&self.sem).acquire_owned().await.expect("semaphore open");
            let sup = Arc::clone(&self);
            let out = out.clone();
            tokio::spawn(async move {
                let _permit = permit;
                sup.analyze_batch(pending, followers, &out).await;
            });
        }
    }

    async fn analyze_batch(&self, jobs: Vec<Job>, followers: Vec<(Job, usize)>, out: &mpsc::UnboundedSender<Outcome>) {
        let inputs: Vec<AiInput> = jobs.iter().map(|j| j.input.clone()).collect();
        let res = self.provider.classify(&inputs).await;
        self.record_call(&res);
        let results: Vec<Result<AiVerdict, String>> = match res {
            Err(e) => {
                self.counters.failures.fetch_add(jobs.len() as u64, Ordering::Relaxed);
                jobs.iter().map(|_| Err(format!("provider error: {e}"))).collect()
            }
            Ok(c) => {
                let meta = VerdictMeta {
                    provider: self.provider.name().into(),
                    model: self.provider.model().into(),
                    model_version: c.model_version.clone(),
                    ts: chrono::Utc::now().timestamp_millis(),
                    latency_ms: c.latency_ms,
                };
                match prompt::validate(&c.text, &inputs, &meta) {
                    Err(e) => {
                        self.counters.invalid_outputs.fetch_add(jobs.len() as u64, Ordering::Relaxed);
                        self.inner.lock().last_error = Some(format!("invalid output: {e}"));
                        jobs.iter().map(|_| Err(format!("invalid model output: {e}"))).collect()
                    }
                    Ok(mut map) => jobs
                        .iter()
                        .map(|j| match map.remove(&j.input.ref_id) {
                            Some(Validated::Verdict(v)) => {
                                self.cache_put(&j.fingerprint, &v);
                                self.counters.analyzed.fetch_add(1, Ordering::Relaxed);
                                Ok(*v)
                            }
                            Some(Validated::Invalid(e)) => {
                                self.counters.invalid_outputs.fetch_add(1, Ordering::Relaxed);
                                Err(format!("invalid model output: {e}"))
                            }
                            None => Err("no result".into()),
                        })
                        .collect(),
                }
            }
        };
        for (job, result) in jobs.iter().zip(results.iter()) {
            let _ = out.send(Outcome {
                event_id: job.event_id.clone(),
                fingerprint: job.fingerprint.clone(),
                result: result.clone(),
            });
        }
        for (job, leader) in followers {
            let mut r = results[leader].clone();
            if let Ok(v) = &mut r {
                v.cached = true;
                self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
                self.counters.analyzed.fetch_add(1, Ordering::Relaxed);
            }
            let _ = out.send(Outcome {
                event_id: job.event_id,
                fingerprint: job.fingerprint,
                result: r,
            });
        }
    }

    /// One free-text completion under the same breaker and budget.
    pub async fn summarize(&self, system: &str, user: &str) -> Result<String, String> {
        self.reserve_call().await?;
        let res = self.provider.complete(system, user, 400).await;
        self.record_call(&res);
        res.map(|c| super::sanitize::truncate(c.text.trim(), 2000)).map_err(|e| e.to_string())
    }
}

fn today() -> i64 {
    chrono::Utc::now().timestamp() / 86_400
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// A scripted provider for resilience tests.
    pub struct Fake {
        pub calls: AtomicUsize,
        pub mode: Mutex<&'static str>,
    }

    impl Provider for Fake {
        fn name(&self) -> &str {
            "fake"
        }
        fn model(&self) -> &str {
            "fake-1"
        }
        fn classify<'a>(&'a self, inputs: &'a [AiInput]) -> BoxFuture<'a, Result<Completion, ProviderError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let mode = *self.mode.lock();
                match mode {
                    "down" => Err(ProviderError::Server(503)),
                    "slow" => {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        Err(ProviderError::Timeout)
                    }
                    "garbage" => Ok(Completion {
                        text: "not json".into(),
                        ..Default::default()
                    }),
                    _ => {
                        let results: Vec<_> = inputs
                            .iter()
                            .map(|i| serde_json::json!({"ref_id": i.ref_id, "category": "malicious", "risk": 0.9,
                                "confidence": 0.9, "explanation": "x", "evidence": [], "recommended_action": "monitor"}))
                            .collect();
                        Ok(Completion {
                            text: serde_json::json!({"results": results}).to_string(),
                            tokens_in: 100,
                            tokens_out: 20,
                            latency_ms: 3,
                            model_version: "fake-1.0".into(),
                        })
                    }
                }
            })
        }
        fn complete<'a>(&'a self, _: &'a str, _: &'a str, _: u64) -> BoxFuture<'a, Result<Completion, ProviderError>> {
            Box::pin(async {
                Ok(Completion {
                    text: "summary".into(),
                    ..Default::default()
                })
            })
        }
    }

    fn job(id: &str, fp: &str) -> Job {
        Job {
            event_id: id.into(),
            fingerprint: fp.into(),
            input: AiInput {
                ref_id: id.into(),
                method: "GET".into(),
                path: "/".into(),
                path_template: "/".into(),
                query: vec![],
                headers: vec![],
                body_excerpt: None,
                status: 403,
                firewall_action: "block".into(),
                rules_matched: vec![],
                scores: vec![],
                anomaly_score: 0.0,
                anomaly_reasons: vec![],
                client: "c".into(),
                country: None,
                asn: None,
                prompt_injection_markers: vec![],
            },
        }
    }

    fn cfg() -> AiConfig {
        AiConfig {
            enabled: true,
            model: "fake-1".into(),
            breaker_failures: 2,
            breaker_cooldown_s: 60,
            price_per_mtok_in: 1.0,
            price_per_mtok_out: 2.0,
            ..Default::default()
        }
    }

    async fn collect(rx: &mut mpsc::UnboundedReceiver<Outcome>, n: usize) -> Vec<Outcome> {
        let mut v = Vec::new();
        while v.len() < n {
            match tokio::time::timeout(Duration::from_secs(3), rx.recv()).await {
                Ok(Some(o)) => v.push(o),
                _ => break,
            }
        }
        v
    }

    fn fake(mode: &'static str) -> Arc<Fake> {
        Arc::new(Fake {
            calls: AtomicUsize::new(0),
            mode: Mutex::new(mode),
        })
    }

    #[tokio::test]
    async fn batches_dedups_and_caches() {
        let p = fake("ok");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sup = Supervisor::start(cfg(), p.clone(), tx);
        sup.offer(job("a", "fp1"));
        sup.offer(job("b", "fp1"));
        sup.offer(job("c", "fp2"));
        let out = collect(&mut rx, 3).await;
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|o| o.result.is_ok()));
        assert_eq!(p.calls.load(Ordering::SeqCst), 1, "one batched call");
        // Same shape again: served from cache.
        sup.offer(job("d", "fp1"));
        let out = collect(&mut rx, 1).await;
        assert!(out[0].result.as_ref().unwrap().cached);
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
        let st = sup.status();
        assert_eq!(st.cache_hits, 2);
        assert_eq!(st.tokens_in, 100);
        // 100 * 1.0 + 20 * 2.0 micro-dollars
        assert!((st.cost_usd - 140e-6).abs() < 1e-9);
    }

    #[tokio::test]
    async fn breaker_opens_after_failures_and_skips_calls() {
        let p = fake("down");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sup = Supervisor::start(cfg(), p.clone(), tx);
        for i in 0..2 {
            sup.offer(job(&format!("e{i}"), &format!("f{i}")));
            collect(&mut rx, 1).await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert_eq!(sup.status().breaker, BreakerState::Open);
        sup.offer(job("x", "fx"));
        let out = collect(&mut rx, 1).await;
        assert!(out[0].result.as_ref().unwrap_err().contains("circuit breaker"));
        assert_eq!(p.calls.load(Ordering::SeqCst), 2, "no call while open");
    }

    #[tokio::test]
    async fn invalid_output_is_rejected_and_counted() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sup = Supervisor::start(cfg(), fake("garbage"), tx);
        sup.offer(job("a", "f"));
        let out = collect(&mut rx, 1).await;
        assert!(out[0].result.is_err());
        assert_eq!(sup.status().invalid_outputs, 1);
    }

    #[tokio::test]
    async fn daily_budget_is_enforced() {
        let mut c = cfg();
        c.max_calls_per_day = 1;
        let p = fake("ok");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sup = Supervisor::start(c, p.clone(), tx);
        sup.offer(job("a", "f1"));
        collect(&mut rx, 1).await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        sup.offer(job("b", "f2"));
        let out = collect(&mut rx, 1).await;
        assert!(out[0].result.as_ref().unwrap_err().contains("budget"));
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn per_minute_limit_waits_instead_of_dropping() {
        let mut c = cfg();
        c.requests_per_minute = 1;
        let sup_cfg = c.clone();
        let (tx, _rx) = mpsc::unbounded_channel();
        let sup = Supervisor::start(sup_cfg, fake("ok"), tx);
        assert!(matches!(sup.try_reserve(), Reserve::Granted));
        assert!(matches!(sup.try_reserve(), Reserve::Wait(_)));
    }

    #[tokio::test]
    async fn full_queue_drops_without_blocking() {
        let mut c = cfg();
        c.queue_capacity = 2;
        let (tx, _rx) = mpsc::unbounded_channel();
        let sup = Supervisor::start(c, fake("slow"), tx);
        let start = Instant::now();
        let accepted = (0..100).filter(|i| sup.offer(job(&format!("{i}"), &format!("{i}")))).count();
        assert!(start.elapsed() < Duration::from_millis(50), "offer must not block");
        assert!(accepted < 100);
        assert!(sup.status().dropped > 0);
    }
}
