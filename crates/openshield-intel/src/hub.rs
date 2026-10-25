//! The event hub: receives finished requests from the proxy and drives the
//! intelligence pipeline off the request path.
//!
//! Proxy worker → [`EventHub::submit`] (`try_send`, never waits)
//!   → ingest task: redact, anomaly score, statistics, recent ring,
//!     simulation snapshots, AI eligibility, live stream
//!   → writer thread: batched SQLite inserts
//! AI outcomes come back through a channel and are attached to the event,
//! stored, streamed, and turned into candidate labels for review.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use openshield_core::Waf;
use openshield_core::logging::{AccessLogEntry, AuditLogEntry};
use openshield_core::waf::data::RequestData;
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use tokio::sync::{broadcast, mpsc};

use crate::ai::sanitize::Sanitizer;
use crate::ai::supervisor::{Job, Outcome, Supervisor};
use crate::ai::types::{AiVerdict, Category, VerdictStatus};
use crate::anomaly::{AlertDraft, Detector};
use crate::config::{AiTrigger, IntelConfig};
use crate::controls::{Controls, parse_target};
use crate::event::{MatchedRule, SecurityEvent};
use crate::policy::Snapshot;
use crate::stats::Stats;
use crate::store::{Control, Store, now_ms};

/// What the proxy hands over for each finished request. Raw: redaction
/// happens in the ingest task, not on the proxy worker.
pub struct RawEvent {
    pub waf: Arc<Waf>,
    pub request: Option<RequestData>,
    pub access: AccessLogEntry,
    pub audit: Option<AuditLogEntry>,
    pub action: String,
    pub body: Vec<u8>,
}

#[derive(Clone)]
pub struct StreamMsg {
    pub kind: &'static str,
    pub data: Arc<String>,
}

#[derive(Default)]
pub struct HubCounters {
    pub submitted: AtomicU64,
    pub dropped: AtomicU64,
    pub stored: AtomicU64,
    pub store_dropped: AtomicU64,
    /// Notable events not stored because their client used up its budget.
    pub store_sampled_out: AtomicU64,
    pub store_errors: AtomicU64,
    pub alerts: AtomicU64,
    pub auto_blocks: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HubStatus {
    pub submitted: u64,
    pub dropped: u64,
    pub stored: u64,
    pub store_dropped: u64,
    pub store_sampled_out: u64,
    pub store_errors: u64,
    pub alerts: u64,
    pub auto_blocks: u64,
    pub queue: usize,
    pub queue_capacity: usize,
    pub tracked_clients: usize,
}

enum DbMsg {
    Events(Vec<Arc<SecurityEvent>>),
    Verdict(String, Box<AiVerdict>),
    Candidate { event_id: String, label: String, model: String },
}

pub struct EventHub {
    cfg: IntelConfig,
    tx: mpsc::Sender<RawEvent>,
    pub store: Arc<Store>,
    pub controls: Arc<Controls>,
    pub stats: Arc<Mutex<Stats>>,
    detector: Arc<Mutex<Detector>>,
    /// Shared, not copied: the ring, the write batch and the stream all
    /// hold the same event.
    recent: Arc<RwLock<VecDeque<Arc<SecurityEvent>>>>,
    snapshots: Arc<Mutex<VecDeque<Snapshot>>>,
    pub stream: broadcast::Sender<StreamMsg>,
    /// Replaced when AI settings change; `None` while AI is off.
    ai: arc_swap::ArcSwapOption<Supervisor>,
    ai_tx: mpsc::UnboundedSender<Outcome>,
    /// Why AI is off, for the status page.
    ai_off_reason: Mutex<String>,
    pub settings: Arc<crate::settings::Settings>,
    pub sanitizer: Arc<Sanitizer>,
    pub counters: Arc<HubCounters>,
    db_tx: std::sync::mpsc::SyncSender<DbMsg>,
}

impl EventHub {
    /// Start the hub. Must be called inside a Tokio runtime.
    pub fn start(
        cfg: IntelConfig,
        store: Arc<Store>,
        controls: Arc<Controls>,
        settings: Arc<crate::settings::Settings>,
        sanitizer: Arc<Sanitizer>,
    ) -> Arc<Self> {
        let (ai_tx, ai_outcomes) = mpsc::unbounded_channel();
        let (tx, rx) = mpsc::channel(cfg.events.queue_capacity);
        let (stream, _) = broadcast::channel(4096);
        // At most 16 pending batches (16,000 events) wait for the writer;
        // beyond that batches are dropped and counted, so memory stays bounded
        // when storage cannot keep up.
        let (db_tx, db_rx) = std::sync::mpsc::sync_channel::<DbMsg>(16);
        let counters = Arc::new(HubCounters::default());
        let hub = Arc::new(Self {
            detector: Arc::new(Mutex::new(Detector::new(cfg.anomaly.clone()))),
            recent: Arc::new(RwLock::new(VecDeque::with_capacity(cfg.events.recent_capacity))),
            snapshots: Arc::new(Mutex::new(VecDeque::with_capacity(cfg.events.snapshot_capacity))),
            stats: Arc::new(Mutex::new(Stats::new())),
            cfg,
            tx,
            store: Arc::clone(&store),
            controls,
            stream,
            ai: arc_swap::ArcSwapOption::empty(),
            ai_tx,
            ai_off_reason: Mutex::new("disabled".into()),
            settings,
            sanitizer,
            counters: Arc::clone(&counters),
            db_tx,
        });

        // Writer thread: the only place events are inserted.
        {
            let store = Arc::clone(&store);
            let counters = Arc::clone(&counters);
            std::thread::Builder::new()
                .name("openshield-intel-db".into())
                .spawn(move || db_writer(store, db_rx, counters))
                .expect("spawn db writer");
        }
        tokio::spawn(Arc::clone(&hub).ingest(rx));
        tokio::spawn(Arc::clone(&hub).ai_results(ai_outcomes));
        tokio::spawn(Arc::clone(&hub).ticker());
        tokio::spawn(Arc::clone(&hub).maintenance());
        hub
    }

    /// Hand over a finished request. Never blocks; when the queue is full
    /// the event is dropped and counted.
    pub fn submit(&self, ev: RawEvent) {
        self.counters.submitted.fetch_add(1, Ordering::Relaxed);
        if self.tx.try_send(ev).is_err() {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn status(&self) -> HubStatus {
        let c = &self.counters;
        HubStatus {
            submitted: c.submitted.load(Ordering::Relaxed),
            dropped: c.dropped.load(Ordering::Relaxed),
            stored: c.stored.load(Ordering::Relaxed),
            store_dropped: c.store_dropped.load(Ordering::Relaxed),
            store_sampled_out: c.store_sampled_out.load(Ordering::Relaxed),
            store_errors: c.store_errors.load(Ordering::Relaxed),
            alerts: c.alerts.load(Ordering::Relaxed),
            auto_blocks: c.auto_blocks.load(Ordering::Relaxed),
            queue: self.cfg.events.queue_capacity - self.tx.capacity(),
            queue_capacity: self.cfg.events.queue_capacity,
            tracked_clients: self.detector.lock().tracked_clients(),
        }
    }

    pub fn recent_event(&self, id: &str) -> Option<SecurityEvent> {
        self.recent.read().iter().rev().find(|e| e.id == id).map(|e| (**e).clone())
    }

    /// An event from memory (freshest) or the store.
    pub fn event(&self, id: &str) -> Result<Option<SecurityEvent>, String> {
        if let Some(e) = self.recent_event(id) {
            return Ok(Some(e));
        }
        self.store.get_event(id)
    }

    pub fn snapshots(&self) -> Vec<Snapshot> {
        self.snapshots.lock().iter().cloned().collect()
    }

    pub fn client_info(&self, ip: &str) -> Option<crate::anomaly::ClientInfo> {
        self.detector.lock().client(ip)
    }

    /// The current AI supervisor, if AI is on.
    pub fn ai(&self) -> Option<Arc<Supervisor>> {
        self.ai.load_full()
    }

    pub fn ai_off_reason(&self) -> String {
        self.ai_off_reason.lock().clone()
    }

    /// Build (or stop) the AI supervisor from the current settings. Call
    /// inside the intel runtime. The previous supervisor finishes the calls
    /// it has in flight and then stops.
    pub fn reconfigure_ai(&self) -> Result<(), String> {
        let cfg = (*self.settings.ai.load_full()).clone();
        self.sanitizer.set_send_body(cfg.send_body);
        if !cfg.enabled {
            self.ai.store(None);
            *self.ai_off_reason.lock() = "disabled in settings".into();
            return Ok(());
        }
        let Some((key, source)) = self.settings.ai_key() else {
            self.ai.store(None);
            *self.ai_off_reason.lock() = "enabled, but no API key is set".into();
            return Err("AI is enabled but no API key is set".into());
        };
        let client = crate::ai::gemini::GeminiClient::new(
            &cfg.base_url,
            &cfg.model,
            key,
            Duration::from_millis(cfg.timeout_ms),
        )?;
        let provider: Arc<dyn crate::ai::supervisor::Provider> = Arc::new(client);
        log::info!("AI supervision: model {} at {} (key from {source})", cfg.model, cfg.base_url);
        self.ai.store(Some(Supervisor::start(cfg, provider, self.ai_tx.clone())));
        Ok(())
    }

    /// Queue one event for AI analysis now (operator request).
    pub fn analyze(&self, ev: &SecurityEvent) -> Result<(), String> {
        let ai = self.ai().ok_or("AI analysis is off")?;
        let job = Job {
            event_id: ev.id.clone(),
            fingerprint: format!("manual-{}", ev.id),
            input: self.sanitizer.input(&ev.id, ev),
        };
        if ai.offer(job) {
            Ok(())
        } else {
            Err("AI queue is full".into())
        }
    }

    fn publish<T: Serialize>(&self, kind: &'static str, v: &T) {
        if self.stream.receiver_count() == 0 {
            return;
        }
        if let Ok(s) = serde_json::to_string(v) {
            let _ = self.stream.send(StreamMsg {
                kind,
                data: Arc::new(s),
            });
        }
    }

    pub fn raise_alert(&self, a: &AlertDraft) {
        match self.store.raise_alert(&a.kind, &a.subject, &a.severity, &a.detail) {
            Ok((alert, new)) => {
                if new {
                    self.counters.alerts.fetch_add(1, Ordering::Relaxed);
                    log::warn!("Alert: {} {} ({})", alert.kind, alert.subject, alert.severity);
                }
                self.publish("alert", &alert);
            }
            Err(e) => log::error!("failed to store alert: {e}"),
        }
    }

    async fn ingest(self: Arc<Self>, mut rx: mpsc::Receiver<RawEvent>) {
        let mut batch: Vec<Arc<SecurityEvent>> = Vec::with_capacity(1024);
        let mut budget = ClientBudget::default();
        let mut flush = tokio::time::interval(Duration::from_millis(250));
        flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut streamed_sec = 0i64;
        let mut streamed = 0u32;
        loop {
            tokio::select! {
                raw = rx.recv() => {
                    let Some(raw) = raw else { break };
                    let ev = self.process(raw);
                    let sec = ev.ts / 1000;
                    if sec != streamed_sec {
                        streamed_sec = sec;
                        streamed = 0;
                    }
                    if streamed < self.max_stream_per_sec() {
                        streamed += 1;
                        self.publish("event", &ev.summary());
                    }
                    if self.should_store(&ev) {
                        if budget.take(&ev.client_ip, ev.ts / 1000, self.settings.storage.load().per_client_per_sec) {
                            batch.push(ev);
                        } else {
                            self.counters.store_sampled_out.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    if batch.len() >= 1000 {
                        self.flush(&mut batch);
                    }
                }
                _ = flush.tick() => self.flush(&mut batch),
            }
        }
    }

    fn max_stream_per_sec(&self) -> u32 {
        STREAM_MAX.load(Ordering::Relaxed) as u32
    }

    /// Every notable event is stored; ordinary traffic only at
    /// `benign_sample_rate` unless `store_all_events` is set. Statistics
    /// count every request either way.
    fn should_store(&self, ev: &SecurityEvent) -> bool {
        let st = self.settings.storage.load();
        st.store_all_events || ev.is_notable() || (st.benign_sample_rate > 0.0 && sample(&ev.id) < st.benign_sample_rate)
    }

    fn flush(&self, batch: &mut Vec<Arc<SecurityEvent>>) {
        if batch.is_empty() {
            return;
        }
        let events = std::mem::take(batch);
        let n = events.len() as u64;
        if self.db_tx.try_send(DbMsg::Events(events)).is_err() {
            self.counters.store_dropped.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Build the event, score it, and update in-memory state.
    fn process(&self, raw: RawEvent) -> Arc<SecurityEvent> {
        let mut ev = build_event(&raw, self.settings.storage.load().body_excerpt_bytes);
        let now = ev.ts;

        let obs = self.detector.lock().observe(&ev, now);
        ev.anomaly = obs.anomaly;
        for a in &obs.alerts {
            self.raise_alert(a);
        }
        if let Some(b) = obs.auto_block {
            self.auto_block(&b.ip, b.ttl_s, &b.reason);
        }
        self.stats.lock().record(&ev);

        // Snapshots for policy simulation. Kept unredacted: they never leave
        // this process except as the redacted method and path of a
        // simulation diff, and rules must see the real values to replay
        // faithfully. Moving the request in costs no copy.
        let snapshot = self.cfg.events.snapshot_capacity > 0
            && (ev.is_notable() || sample(&ev.id) < self.cfg.events.snapshot_benign_sample);
        if let Some(req) = raw.request
            && snapshot
        {
            let mut snaps = self.snapshots.lock();
            if snaps.len() >= self.cfg.events.snapshot_capacity {
                snaps.pop_front();
            }
            let mut body = raw.body;
            body.truncate(16 * 1024);
            snaps.push_back(Snapshot {
                event_id: ev.id.clone(),
                request: req,
                body,
            });
        }

        if let Some(ai) = self.ai()
            && self.eligible(&ev)
        {
            ai.offer(Job {
                event_id: ev.id.clone(),
                fingerprint: ev.fingerprint(),
                input: self.sanitizer.input(&ev.id, &ev),
            });
        }

        let ev = Arc::new(ev);
        {
            let mut recent = self.recent.write();
            if recent.len() >= self.cfg.events.recent_capacity {
                recent.pop_front();
            }
            recent.push_back(Arc::clone(&ev));
        }
        ev
    }

    fn eligible(&self, ev: &SecurityEvent) -> bool {
        let ai = self.settings.ai.load();
        let triggered = ai.triggers.iter().any(|t| match t {
            AiTrigger::Block => ev.action == "block",
            AiTrigger::Challenge => ev.action == "challenge",
            AiTrigger::RuleMatch => !ev.matched_rules.is_empty() && ev.action != "block",
            AiTrigger::Anomaly => ev.anomaly.score >= ai.min_anomaly,
        });
        if triggered {
            return true;
        }
        ai.sample_rate_benign > 0.0 && sample(&ev.id) < ai.sample_rate_benign
    }

    pub fn auto_block(&self, ip: &str, ttl_s: u64, reason: &str) {
        let Ok(net) = parse_target(ip) else { return };
        if self.controls.is_allowed(net.network_address(), now_ms()) {
            return;
        }
        let expires = now_ms() + (ttl_s as i64) * 1000;
        self.controls.block(net, Some(expires));
        let _ = self.store.put_control(&Control {
            kind: "ip_block".into(),
            value: ip.into(),
            expires_at: Some(expires),
            reason: reason.into(),
            actor: "system:auto-block".into(),
            created_at: now_ms(),
        });
        let _ = self.store.audit(
            "system:auto-block",
            "system",
            "ip_block",
            ip,
            &serde_json::json!({"ttl_s": ttl_s, "reason": reason}),
            "applied",
            "-",
        );
        self.counters.auto_blocks.fetch_add(1, Ordering::Relaxed);
        log::warn!("Auto-block {ip} for {ttl_s}s: {reason}");
    }

    async fn ai_results(self: Arc<Self>, mut rx: mpsc::UnboundedReceiver<Outcome>) {
        while let Some(o) = rx.recv().await {
            let Ok(v) = o.result else {
                continue;
            };
            let mut event_for_alert = None;
            {
                let mut recent = self.recent.write();
                if let Some(e) = recent.iter_mut().rev().find(|e| e.id == o.event_id) {
                    let mut updated = (**e).clone();
                    updated.ai = Some(v.clone());
                    event_for_alert = Some(updated.clone());
                    *e = Arc::new(updated);
                }
            }
            let ev = match event_for_alert {
                Some(e) => Some(e),
                None => self.store.get_event(&o.event_id).ok().flatten(),
            };
            let _ = self.db_tx.try_send(DbMsg::Verdict(o.event_id.clone(), Box::new(v.clone())));
            self.publish("ai", &serde_json::json!({"event_id": o.event_id, "ai": {
                "category": v.category.as_str(), "risk": v.risk, "confidence": v.confidence,
                "recommended_action": v.recommended_action.as_str(), "status": v.status}}));
            let Some(ev) = ev else { continue };
            if let Some(label) = candidate_label(&ev, &v) {
                let _ = self.db_tx.try_send(DbMsg::Candidate {
                    event_id: ev.id.clone(),
                    label: label.into(),
                    model: format!("{}:{}", v.model, v.model_version),
                });
            }
            if v.category == Category::Malicious && v.risk >= 0.8 && !ev.is_blocked() {
                self.raise_alert(&AlertDraft {
                    kind: "ai_malicious".into(),
                    subject: ev.client_ip.clone(),
                    severity: "high".into(),
                    detail: serde_json::json!({"event_id": ev.id, "path": ev.path, "risk": v.risk,
                        "confidence": v.confidence, "explanation": v.explanation,
                        "note": "advisory: the request was not blocked by rules"}),
                });
            }
        }
    }

    async fn ticker(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut last_ai_state = String::from("ok");
        loop {
            tick.tick().await;
            let now = now_ms();
            let sec = now - now.rem_euclid(1000) - 1000;
            let (c, p95) = self.stats.lock().second(sec);
            self.publish(
                "stats",
                &serde_json::json!({"t": sec, "total": c.total, "pass": c.pass, "allow": c.allow,
                    "block": c.block, "challenge": c.challenge, "suspicious": c.suspicious, "p95_ms": p95}),
            );
            if let Some(ai) = self.ai() {
                let st = ai.status();
                if st.state == "open" && last_ai_state != "open" {
                    self.raise_alert(&AlertDraft {
                        kind: "ai_degraded".into(),
                        subject: "ai".into(),
                        severity: "medium".into(),
                        detail: serde_json::json!({"state": st.state, "last_error": st.last_error,
                            "note": "AI analysis paused; deterministic rules unaffected"}),
                    });
                }
                last_ai_state = st.state;
            }
        }
    }

    async fn maintenance(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        let mut n = 0u64;
        loop {
            tick.tick().await;
            let now = now_ms();
            self.controls.sweep(now);
            let _ = self.store.purge_expired_controls(now);
            if n % 10 == 0 {
                let st = self.settings.storage.load();
                let cutoff = now - st.retention_days as i64 * 86_400_000;
                let store = Arc::clone(&self.store);
                let max = st.max_events;
                let _ = tokio::task::spawn_blocking(move || match store.retain(cutoff, max) {
                    Ok(d) if d > 0 => log::info!("Retention: deleted {d} events"),
                    Err(e) => log::error!("Retention failed: {e}"),
                    _ => {}
                })
                .await;
            }
            n += 1;
        }
    }
}

/// Events stored per client per second. A flood from one client (an attack
/// or a load test) would otherwise put every one of its requests in the
/// store: thousands of near-identical rows a second that saturate the
/// writer and help no one. Statistics and alerts still count them all.
#[derive(Default)]
struct ClientBudget {
    used: HashMap<String, (i64, u32)>,
}

impl ClientBudget {
    fn take(&mut self, client: &str, sec: i64, per_sec: u32) -> bool {
        if per_sec == 0 {
            return true; // 0 means no limit
        }
        if self.used.len() > 50_000 {
            self.used.retain(|_, (s, _)| *s >= sec);
        }
        let e = self.used.entry(client.to_string()).or_insert((sec, 0));
        if e.0 != sec {
            *e = (sec, 0);
        }
        if e.1 < per_sec {
            e.1 += 1;
            true
        } else {
            false
        }
    }
}

/// Upper bound for `event` stream messages per second (set from admin config).
pub static STREAM_MAX: AtomicU64 = AtomicU64::new(200);

fn db_writer(store: Arc<Store>, rx: std::sync::mpsc::Receiver<DbMsg>, counters: Arc<HubCounters>) {
    while let Ok(msg) = rx.recv() {
        match msg {
            DbMsg::Events(evs) => {
                let n = evs.len() as u64;
                match store.insert_events(&evs) {
                    Ok(()) => {
                        counters.stored.fetch_add(n, Ordering::Relaxed);
                    }
                    Err(e) => {
                        counters.store_errors.fetch_add(1, Ordering::Relaxed);
                        log::error!("event insert failed: {e}");
                    }
                }
            }
            DbMsg::Verdict(id, v) => {
                if let Err(e) = store.add_verdict(&id, &v) {
                    log::error!("verdict insert failed: {e}");
                }
            }
            DbMsg::Candidate { event_id, label, model } => {
                let _ = store.add_label(&event_id, &label, "ai_candidate", "candidate", "", &format!("ai:{model}"), None, Some(&model));
            }
        }
    }
}

/// The candidate label an AI verdict suggests, for the review queue. Only
/// verdicts that add information get one: disagreements with the rules,
/// and anything not plainly legitimate.
pub fn candidate_label(ev: &SecurityEvent, v: &AiVerdict) -> Option<&'static str> {
    let blocked = ev.is_blocked();
    match v.category {
        Category::Legitimate if blocked => Some("FALSE_POSITIVE"),
        Category::Malicious if !blocked => Some("FALSE_NEGATIVE"),
        Category::Legitimate if v.status == VerdictStatus::NeedsReview => Some("NEEDS_REVIEW"),
        Category::Legitimate => None,
        // Agreement with a rule block adds nothing for a reviewer; only flag
        // it when the verdict itself needs review.
        Category::Malicious if v.status == VerdictStatus::NeedsReview => Some("NEEDS_REVIEW"),
        Category::Malicious => None,
        Category::Suspicious => Some("SUSPICIOUS"),
        Category::PolicyViolation => Some("POLICY_VIOLATION"),
        Category::Unknown => Some("NEEDS_REVIEW"),
    }
}

/// Deterministic sampling in [0, 1) from the event id. Request ids are
/// random UUIDs, so their first 32 bits are already uniform; other ids are
/// hashed.
fn sample(id: &str) -> f64 {
    if let Some(head) = id.get(..8)
        && let Ok(v) = u32::from_str_radix(head, 16)
    {
        return v as f64 / (u32::MAX as f64 + 1.0);
    }
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(id.as_bytes());
    u64::from_be_bytes(h[..8].try_into().unwrap()) as f64 / u64::MAX as f64
}

/// Headers kept on every event (redacted). Events with a rule match keep
/// all headers.
const SUMMARY_HEADERS: &[&str] = &["user-agent", "content-type", "accept", "referer", "origin", "host"];

pub fn build_event(raw: &RawEvent, body_excerpt_bytes: usize) -> SecurityEvent {
    let redactor = raw.waf.redactor();
    let a = &raw.access;
    let req = raw.request.as_ref();
    let header = |name: &str| -> String {
        req.and_then(|r| r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)))
            .map(|(k, v)| redactor.header(k, v).into_owned())
            .unwrap_or_default()
    };
    let matched_rules: Vec<MatchedRule> = raw
        .audit
        .as_ref()
        .map(|au| {
            au.waf_matched_rules
                .iter()
                .map(|m| MatchedRule {
                    id: m.id.clone(),
                    action: m.action.clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    let scores: BTreeMap<String, i64> = raw
        .audit
        .as_ref()
        .map(|au| au.waf_scores.iter().map(|(k, v)| (k.clone(), *v)).collect())
        .unwrap_or_default();
    let matched = !matched_rules.is_empty();
    let headers: BTreeMap<String, String> = match (&raw.audit, req) {
        // Audit headers are already redacted.
        (Some(au), _) => au.request.headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        (None, Some(r)) => r
            .headers
            .iter()
            .filter(|(k, _)| SUMMARY_HEADERS.iter().any(|h| k.eq_ignore_ascii_case(h)))
            .map(|(k, v)| (k.to_ascii_lowercase(), redactor.header(k, v).into_owned()))
            .collect(),
        _ => BTreeMap::new(),
    };
    let content_type = header("content-type");
    let body_excerpt = if matched && body_excerpt_bytes > 0 && !raw.body.is_empty() {
        let cut = &raw.body[..raw.body.len().min(body_excerpt_bytes)];
        let text = String::from_utf8_lossy(cut);
        Some(redactor.body(Some(&content_type), &text).into_owned())
    } else {
        None
    };
    let action = raw
        .audit
        .as_ref()
        .map(|au| au.waf_action.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| raw.action.clone());
    let action = if action.is_empty() { "pass".to_string() } else { action };
    let detection_only = raw.waf.settings().detection_only;
    let enforced = !(detection_only && matches!(action.as_str(), "block" | "challenge") && !matched_rules.iter().any(|m| m.id.starts_with("dynamic:")));
    let geo = req.and_then(|r| r.geo.as_ref());
    SecurityEvent {
        id: a.request_id.clone(),
        ts: chrono::DateTime::parse_from_rfc3339(&a.timestamp)
            .map(|t| t.timestamp_millis())
            .unwrap_or_else(|_| now_ms()),
        client_ip: a.client_ip.clone(),
        country: geo.and_then(|g| g.country.clone()),
        asn: geo.and_then(|g| g.asn),
        method: a.method.clone(),
        protocol: a.protocol.clone(),
        host: redactor.text(&a.host).into_owned(),
        path: redactor.text(&a.path).into_owned(),
        query: a.query.clone(),
        status: a.status,
        duration_ms: a.duration_ms,
        bytes_in: a.bytes_received as u64,
        bytes_out: a.bytes_sent as u64,
        action,
        enforced,
        matched_rules,
        scores,
        user_agent: header("user-agent"),
        content_type,
        headers,
        body_excerpt,
        error: a.error.clone(),
        anomaly: Default::default(),
        ai: None,
        label: None,
    }
}

/// Stats of the hub used by readiness checks.
pub fn component_states(hub: &EventHub) -> HashMap<&'static str, String> {
    let mut m = HashMap::new();
    m.insert("store", if hub.store.ping() { "ok" } else { "error" }.to_string());
    m.insert(
        "ai",
        hub.ai().map(|a| a.status().state).unwrap_or_else(|| "disabled".into()),
    );
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests_support::sample_event;

    fn verdict(cat: Category, status: VerdictStatus) -> AiVerdict {
        AiVerdict {
            category: cat,
            risk: 0.5,
            confidence: 0.9,
            explanation: String::new(),
            evidence: vec![],
            recommended_action: crate::ai::types::RecommendedAction::None,
            status,
            review_reasons: vec![],
            provider: "p".into(),
            model: "m".into(),
            model_version: "1".into(),
            prompt_version: "v".into(),
            ts: 0,
            latency_ms: 0,
            cached: false,
        }
    }

    #[test]
    fn candidate_labels_capture_disagreements() {
        let mut blocked = sample_event();
        blocked.action = "block".into();
        let passed = sample_event();
        assert_eq!(candidate_label(&blocked, &verdict(Category::Legitimate, VerdictStatus::Ok)), Some("FALSE_POSITIVE"));
        assert_eq!(candidate_label(&passed, &verdict(Category::Malicious, VerdictStatus::Ok)), Some("FALSE_NEGATIVE"));
        assert_eq!(candidate_label(&passed, &verdict(Category::Legitimate, VerdictStatus::Ok)), None);
        // Agreement with a block is not queued for review.
        assert_eq!(candidate_label(&blocked, &verdict(Category::Malicious, VerdictStatus::Ok)), None);
        assert_eq!(candidate_label(&blocked, &verdict(Category::Malicious, VerdictStatus::NeedsReview)), Some("NEEDS_REVIEW"));
    }

    #[test]
    fn client_budget_limits_each_client_per_second() {
        let mut b = ClientBudget::default();
        let taken = (0..100).filter(|_| b.take("1.1.1.1", 10, 50)).count();
        assert_eq!(taken, 50);
        assert!(b.take("2.2.2.2", 10, 50), "other clients have their own budget");
        assert!(b.take("1.1.1.1", 11, 50), "budget resets each second");
        assert!((0..1000).all(|_| b.take("3.3.3.3", 10, 0)), "0 disables the limit");
    }

    #[test]
    fn sampling_is_deterministic_and_uniformish() {
        let n = 10_000;
        let hits = (0..n).filter(|i| sample(&format!("id-{i}")) < 0.1).count();
        let uuids = (0..n).filter(|_| sample(&uuid::Uuid::new_v4().to_string()) < 0.1).count();
        assert!((800..1200).contains(&uuids), "{uuids}");
        assert!((800..1200).contains(&hits), "{hits}");
        assert_eq!(sample("x"), sample("x"));
    }
}
