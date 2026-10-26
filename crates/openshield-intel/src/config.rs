//! Configuration for the intelligence layer and the admin server.
//!
//! Lives under two top-level keys of the proxy config: `intel` and `admin`.
//! Every section has safe defaults; AI analysis is off unless enabled.

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntelConfig {
    /// Record security events, compute statistics and run anomaly detection.
    pub enabled: bool,
    pub store: StoreConfig,
    pub events: EventsConfig,
    pub anomaly: AnomalyConfig,
    pub ai: AiConfig,
    pub geo: GeoConfig,
}

/// Where the IP location (City/Country) and ASN databases live. Both are
/// MaxMind DB files: DB-IP Lite (downloadable from the dashboard, CC BY 4.0)
/// or MaxMind GeoLite2 (kept current with `geoipupdate`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeoConfig {
    /// Defaults to `geo/dbip-city-lite.mmdb` next to the database.
    pub city_mmdb: Option<PathBuf>,
    /// Defaults to `geo/dbip-asn-lite.mmdb` next to the database.
    pub asn_mmdb: Option<PathBuf>,
    /// Download a fresh DB-IP Lite edition when the files are over a month
    /// old. Off by default: it makes outbound requests to download.db-ip.com.
    pub auto_update: bool,
}

impl Default for IntelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            store: StoreConfig::default(),
            events: EventsConfig::default(),
            anomaly: AnomalyConfig::default(),
            ai: AiConfig::default(),
            geo: GeoConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StoreConfig {
    /// SQLite database file. Created if missing.
    pub path: PathBuf,
    /// Delete events older than this many days.
    pub retention_days: u32,
    /// Keep at most this many events; the oldest are deleted first.
    pub max_events: u64,
    /// Store every request. When false (default), events with a rule
    /// match, an anomaly, a 5xx status or an error are always stored, plus
    /// `benign_sample_rate` of the rest. Statistics count every request
    /// either way. Storing everything costs a lot of write throughput.
    pub store_all_events: bool,
    /// Share (0 to 1) of ordinary requests stored when `store_all_events`
    /// is off, so the event list still shows normal traffic.
    pub benign_sample_rate: f64,
    /// Stored events per client per second (0: no limit). Applies to all
    /// stored events, so a flood keeps examples without filling the store.
    pub per_client_per_sec: u32,
    /// Bytes of (redacted) request body kept for events with a rule match.
    /// 0 keeps none.
    pub body_excerpt_bytes: usize,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("openshield-intel.db"),
            retention_days: 14,
            max_events: 2_000_000,
            store_all_events: false,
            benign_sample_rate: 0.01,
            per_client_per_sec: 50,
            body_excerpt_bytes: 2048,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EventsConfig {
    /// Events waiting for the pipeline. When full, new events are dropped
    /// and counted; the request path never waits.
    pub queue_capacity: usize,
    /// Recent events kept in memory for the live views.
    pub recent_capacity: usize,
    /// Recent requests kept in memory (redacted) for policy simulation.
    pub snapshot_capacity: usize,
    /// Share (0 to 1) of ordinary requests kept as snapshots; notable ones
    /// are always kept. Below 1, a simulation may miss rare paths.
    pub snapshot_benign_sample: f64,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 8_192,
            recent_capacity: 5_000,
            snapshot_capacity: 2_000,
            snapshot_benign_sample: 1.0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnomalyConfig {
    pub enabled: bool,
    /// Sliding window for per-client counters, in seconds.
    pub window_s: u64,
    /// Requests per window from one client before `rate_spike`.
    pub rate_threshold: u32,
    /// Distinct 404 paths per window from one client before `scanning`.
    pub scan_404_threshold: u32,
    /// Blocked requests per window from one client before `attack_burst`.
    pub block_burst_threshold: u32,
    /// 4xx/5xx share (with at least `rate_threshold / 2` requests) before
    /// `error_burst`.
    pub error_ratio_threshold: f64,
    /// Standard deviations above the 10-minute mean of requests per second
    /// before a global `traffic_spike`.
    pub traffic_spike_z: f64,
    /// Clients tracked at once (least recently seen are evicted).
    pub max_clients: usize,
    pub auto_block: AutoBlockConfig,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_s: 10,
            rate_threshold: 100,
            scan_404_threshold: 20,
            block_burst_threshold: 10,
            error_ratio_threshold: 0.8,
            traffic_spike_z: 4.0,
            max_clients: 100_000,
            auto_block: AutoBlockConfig::default(),
        }
    }
}

/// Automatic temporary blocks from deterministic evidence only (rule
/// blocks), never from AI output. Off by default: it is a high-impact
/// action.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AutoBlockConfig {
    pub enabled: bool,
    /// Rule blocks within one anomaly window that trigger a temporary block.
    pub blocks_in_window: u32,
    pub ttl_s: u64,
}

impl Default for AutoBlockConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            blocks_in_window: 50,
            ttl_s: 600,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiProviderKind {
    Gemini,
}

/// Which events are eligible for AI analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiTrigger {
    /// A rule blocked the request.
    Block,
    /// A rule challenged the request.
    Challenge,
    /// A score or log rule matched without a terminal action.
    RuleMatch,
    /// Anomaly score at or above `min_anomaly`.
    Anomaly,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AiConfig {
    pub enabled: bool,
    pub provider: AiProviderKind,
    /// Model id, for example `gemini-2.5-flash`. Required when enabled.
    pub model: String,
    /// Environment variable holding the API key. The key is never read
    /// from the config file and never logged.
    pub api_key_env: String,
    /// API base URL. Change only for a proxy or a test double.
    pub base_url: String,
    pub timeout_ms: u64,
    /// Events per model call.
    pub max_batch: usize,
    pub max_concurrency: usize,
    pub requests_per_minute: u32,
    pub max_calls_per_day: u32,
    /// Share of events without any trigger that is still analyzed, as a
    /// baseline of normal traffic (0 to 1).
    pub sample_rate_benign: f64,
    pub triggers: Vec<AiTrigger>,
    pub min_anomaly: f64,
    /// Seconds a verdict is reused for events with the same fingerprint.
    pub cache_ttl_s: u64,
    pub queue_capacity: usize,
    /// Include the redacted body excerpt in what is sent. Off by default.
    pub send_body: bool,
    /// Send a keyed hash of the client IP instead of the IP.
    pub pseudonymize_ip: bool,
    /// Consecutive failures that open the circuit breaker.
    pub breaker_failures: u32,
    /// Seconds the breaker stays open before a trial call.
    pub breaker_cooldown_s: u64,
    /// USD per million input tokens, for cost tracking. 0 disables it.
    pub price_per_mtok_in: f64,
    pub price_per_mtok_out: f64,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: AiProviderKind::Gemini,
            model: String::new(),
            api_key_env: "GEMINI_API_KEY".into(),
            base_url: "https://generativelanguage.googleapis.com".into(),
            timeout_ms: 8000,
            max_batch: 8,
            max_concurrency: 2,
            requests_per_minute: 30,
            max_calls_per_day: 2000,
            sample_rate_benign: 0.0,
            triggers: vec![AiTrigger::Block, AiTrigger::Challenge, AiTrigger::Anomaly],
            min_anomaly: 0.5,
            cache_ttl_s: 3600,
            queue_capacity: 10_000,
            send_body: false,
            pseudonymize_ip: true,
            breaker_failures: 5,
            breaker_cooldown_s: 30,
            price_per_mtok_in: 0.0,
            price_per_mtok_out: 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Analyst,
    Operator,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Analyst => "analyst",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminUser {
    pub name: String,
    pub role: Role,
    /// SHA-256 of the token, hex.
    #[serde(default)]
    pub token_sha256: Option<String>,
    /// Environment variable holding the token.
    #[serde(default)]
    pub token_env: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    pub enabled: bool,
    pub listen: String,
    pub users: Vec<AdminUser>,
    /// Policy changes and long IP blocks need a second admin.
    pub require_second_approver: bool,
    /// IP blocks longer than this (seconds) count as high impact.
    pub approval_threshold_s: u64,
    /// Upper bound of `event` messages per second on the live stream.
    pub stream_max_per_sec: u32,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:9091".into(),
            users: Vec::new(),
            require_second_approver: false,
            approval_threshold_s: 86_400,
            stream_max_per_sec: 200,
        }
    }
}

impl IntelConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.ai.enabled {
            if !self.enabled {
                return Err("intel.ai.enabled requires intel.enabled".into());
            }
            if self.ai.model.trim().is_empty() {
                return Err("intel.ai.model is required when AI is enabled".into());
            }
            if !(0.0..=1.0).contains(&self.ai.sample_rate_benign) {
                return Err("intel.ai.sample_rate_benign must be between 0 and 1".into());
            }
            if self.ai.max_batch == 0 || self.ai.max_batch > 50 {
                return Err("intel.ai.max_batch must be between 1 and 50".into());
            }
            if self.ai.max_concurrency == 0 {
                return Err("intel.ai.max_concurrency must be at least 1".into());
            }
            if !self.ai.base_url.starts_with("https://")
                && !self.ai.base_url.starts_with("http://127.0.0.1")
                && !self.ai.base_url.starts_with("http://localhost")
            {
                return Err("intel.ai.base_url must use https (plain http only for localhost)".into());
            }
        }
        for (name, v) in [
            ("intel.store.benign_sample_rate", self.store.benign_sample_rate),
            ("intel.events.snapshot_benign_sample", self.events.snapshot_benign_sample),
        ] {
            if !(0.0..=1.0).contains(&v) {
                return Err(format!("{name} must be between 0 and 1"));
            }
        }
        if self.events.queue_capacity == 0 || self.events.recent_capacity == 0 {
            return Err("intel.events capacities must be positive".into());
        }
        Ok(())
    }
}

impl AdminConfig {
    pub fn validate(&self, intel: &IntelConfig) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if !intel.enabled {
            return Err("admin.enabled requires intel.enabled".into());
        }
        let mut names = std::collections::HashSet::new();
        for u in &self.users {
            if !names.insert(&u.name) {
                return Err(format!("duplicate admin user {:?}", u.name));
            }
            match (&u.token_sha256, &u.token_env) {
                (Some(h), None) => {
                    if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Err(format!(
                            "admin user {:?}: token_sha256 must be 64 hex characters",
                            u.name
                        ));
                    }
                }
                (None, Some(_)) => {}
                _ => {
                    return Err(format!(
                        "admin user {:?}: set exactly one of token_sha256 or token_env",
                        u.name
                    ));
                }
            }
        }
        Ok(())
    }
}
