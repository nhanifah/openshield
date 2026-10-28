//! Settings managed from the dashboard.
//!
//! Like WordPress options: the config file gives the starting values, and a
//! section saved from the dashboard replaces the file's values for that
//! section until it is reset. Saved sections apply at once, without a
//! restart. Secret values (the AI API key) are encrypted at rest by the
//! store's vault and never sent back to clients.

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::{AiConfig, AiTrigger, AutoBlockConfig, IntelConfig, StoreConfig};
use crate::store::Store;

pub const AI_KEY: &str = "ai";
pub const AI_API_KEY: &str = "ai.api_key";
pub const STORAGE_KEY: &str = "storage";
pub const AUTO_BLOCK_KEY: &str = "auto_block";

/// The AI settings editable from the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AiSettings {
    pub enabled: bool,
    pub model: String,
    pub base_url: String,
    pub timeout_ms: u64,
    pub requests_per_minute: u32,
    pub max_calls_per_day: u32,
    pub triggers: Vec<AiTrigger>,
    pub send_body: bool,
    pub price_per_mtok_in: f64,
    pub price_per_mtok_out: f64,
}

impl AiSettings {
    pub fn from_config(c: &AiConfig) -> Self {
        Self {
            enabled: c.enabled,
            model: c.model.clone(),
            base_url: c.base_url.clone(),
            timeout_ms: c.timeout_ms,
            requests_per_minute: c.requests_per_minute,
            max_calls_per_day: c.max_calls_per_day,
            triggers: c.triggers.clone(),
            send_body: c.send_body,
            price_per_mtok_in: c.price_per_mtok_in,
            price_per_mtok_out: c.price_per_mtok_out,
        }
    }

    pub fn apply(&self, c: &mut AiConfig) {
        c.enabled = self.enabled;
        c.model = self.model.clone();
        c.base_url = self.base_url.clone();
        c.timeout_ms = self.timeout_ms;
        c.requests_per_minute = self.requests_per_minute;
        c.max_calls_per_day = self.max_calls_per_day;
        c.triggers = self.triggers.clone();
        c.send_body = self.send_body;
        c.price_per_mtok_in = self.price_per_mtok_in;
        c.price_per_mtok_out = self.price_per_mtok_out;
    }

    pub fn validate(&self) -> Result<(), String> {
        let model_ok = !self.model.trim().is_empty()
            && self.model.len() <= 100
            && self.model.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
        if self.enabled && !model_ok {
            return Err("model is required: letters, digits, '-', '_' or '.' only".into());
        }
        if !self.model.is_empty() && !model_ok {
            return Err("model may contain only letters, digits, '-', '_' or '.'".into());
        }
        let local = self.base_url.starts_with("http://127.0.0.1") || self.base_url.starts_with("http://localhost");
        if !self.base_url.starts_with("https://") && !local {
            return Err("base URL must use https (plain http only for localhost)".into());
        }
        if !(500..=60_000).contains(&self.timeout_ms) {
            return Err("timeout must be between 500 and 60000 ms".into());
        }
        if self.requests_per_minute == 0 || self.requests_per_minute > 10_000 {
            return Err("requests per minute must be between 1 and 10000".into());
        }
        if self.max_calls_per_day > 10_000_000 {
            return Err("calls per day is too large".into());
        }
        for p in [self.price_per_mtok_in, self.price_per_mtok_out] {
            if !p.is_finite() || !(0.0..=1000.0).contains(&p) {
                return Err("prices must be between 0 and 1000 USD per million tokens".into());
            }
        }
        Ok(())
    }
}

/// Event storage settings editable from the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StorageSettings {
    pub store_all_events: bool,
    pub benign_sample_rate: f64,
    pub per_client_per_sec: u32,
    pub retention_days: u32,
    pub max_events: u64,
    pub body_excerpt_bytes: usize,
}

impl StorageSettings {
    pub fn from_config(c: &StoreConfig) -> Self {
        Self {
            store_all_events: c.store_all_events,
            benign_sample_rate: c.benign_sample_rate,
            per_client_per_sec: c.per_client_per_sec,
            retention_days: c.retention_days,
            max_events: c.max_events,
            body_excerpt_bytes: c.body_excerpt_bytes,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.benign_sample_rate) || !self.benign_sample_rate.is_finite() {
            return Err("sample rate must be between 0 and 1".into());
        }
        if !(1..=3650).contains(&self.retention_days) {
            return Err("retention must be between 1 and 3650 days".into());
        }
        if !(1_000..=1_000_000_000).contains(&self.max_events) {
            return Err("max events must be between 1,000 and 1,000,000,000".into());
        }
        if self.body_excerpt_bytes > 65_536 {
            return Err("body excerpt must be at most 65536 bytes".into());
        }
        Ok(())
    }
}

/// Where a section's values come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    ConfigFile,
    Dashboard,
}

pub struct Settings {
    store: Arc<Store>,
    base: IntelConfig,
    pub ai: ArcSwap<AiConfig>,
    pub storage: ArcSwap<StorageSettings>,
    pub auto_block: ArcSwap<AutoBlockConfig>,
}

impl Settings {
    /// Load the file's values, then apply sections saved from the dashboard.
    pub fn load(store: Arc<Store>, base: IntelConfig) -> Result<Self, String> {
        let s = Self {
            ai: ArcSwap::from_pointee(base.ai.clone()),
            storage: ArcSwap::from_pointee(StorageSettings::from_config(&base.store)),
            auto_block: ArcSwap::from_pointee(base.anomaly.auto_block.clone()),
            store,
            base,
        };
        if let Some((json, _)) = s.store.setting(AI_KEY)? {
            match serde_json::from_str::<AiSettings>(&json) {
                Ok(a) => {
                    let mut c = s.base.ai.clone();
                    a.apply(&mut c);
                    s.ai.store(Arc::new(c));
                }
                Err(e) => log::error!("ignoring stored AI settings: {e}"),
            }
        }
        if let Some((json, _)) = s.store.setting(STORAGE_KEY)? {
            match serde_json::from_str::<StorageSettings>(&json) {
                Ok(st) => s.storage.store(Arc::new(st)),
                Err(e) => log::error!("ignoring stored storage settings: {e}"),
            }
        }
        if let Some((json, _)) = s.store.setting(AUTO_BLOCK_KEY)? {
            match serde_json::from_str::<AutoBlockConfig>(&json).map_err(|e| e.to_string()).and_then(|a| a.validate().map(|_| a)) {
                Ok(a) => s.auto_block.store(Arc::new(a)),
                Err(e) => log::error!("ignoring stored auto-block settings: {e}"),
            }
        }
        Ok(s)
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    fn source(&self, key: &str) -> Source {
        match self.store.setting(key) {
            Ok(Some(_)) => Source::Dashboard,
            _ => Source::ConfigFile,
        }
    }

    // ---- AI ---------------------------------------------------------------

    /// The API key to use and where it comes from: one saved in the
    /// dashboard wins over the environment variable named in the config.
    pub fn ai_key(&self) -> Option<(String, String)> {
        if let Ok(Some((k, _))) = self.store.setting(AI_API_KEY)
            && !k.is_empty()
        {
            return Some((k, "dashboard (encrypted)".into()));
        }
        let var = &self.base.ai.api_key_env;
        std::env::var(var)
            .ok()
            .filter(|k| !k.trim().is_empty())
            .map(|k| (k, format!("environment variable {var}")))
    }

    pub fn save_ai(&self, a: &AiSettings, by: &str) -> Result<(), String> {
        a.validate()?;
        self.store.put_setting(AI_KEY, &serde_json::to_string(a).map_err(|e| e.to_string())?, false, by)?;
        let mut c = self.base.ai.clone();
        a.apply(&mut c);
        self.ai.store(Arc::new(c));
        Ok(())
    }

    pub fn reset_ai(&self) -> Result<(), String> {
        self.store.delete_setting(AI_KEY)?;
        self.ai.store(Arc::new(self.base.ai.clone()));
        Ok(())
    }

    /// Save (`Some(non-empty)`) or remove (`Some("")`) the API key.
    pub fn set_ai_key(&self, key: &str, by: &str) -> Result<(), String> {
        if key.is_empty() {
            self.store.delete_setting(AI_API_KEY)?;
            return Ok(());
        }
        if key.len() > 512 || key.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("the API key must be a single line without spaces".into());
        }
        self.store.put_setting(AI_API_KEY, key, true, by)
    }

    // ---- storage --------------------------------------------------------------

    pub fn save_storage(&self, st: &StorageSettings, by: &str) -> Result<(), String> {
        st.validate()?;
        self.store
            .put_setting(STORAGE_KEY, &serde_json::to_string(st).map_err(|e| e.to_string())?, false, by)?;
        self.storage.store(Arc::new(st.clone()));
        Ok(())
    }

    pub fn reset_storage(&self) -> Result<(), String> {
        self.store.delete_setting(STORAGE_KEY)?;
        self.storage.store(Arc::new(StorageSettings::from_config(&self.base.store)));
        Ok(())
    }

    // ---- auto-block -------------------------------------------------------------

    pub fn save_auto_block(&self, a: &AutoBlockConfig, by: &str) -> Result<(), String> {
        a.validate()?;
        self.store
            .put_setting(AUTO_BLOCK_KEY, &serde_json::to_string(a).map_err(|e| e.to_string())?, false, by)?;
        self.auto_block.store(Arc::new(a.clone()));
        Ok(())
    }

    pub fn reset_auto_block(&self) -> Result<(), String> {
        self.store.delete_setting(AUTO_BLOCK_KEY)?;
        self.auto_block.store(Arc::new(self.base.anomaly.auto_block.clone()));
        Ok(())
    }

    /// Everything the settings page shows. Secrets appear only as
    /// "set / not set" with who changed them and when.
    pub fn describe(&self) -> Value {
        let ai = AiSettings::from_config(&self.ai.load());
        let key_meta = self.store.setting(AI_API_KEY).ok().flatten().map(|(_, m)| m);
        let key = self.ai_key();
        let ai_meta = self.store.setting(AI_KEY).ok().flatten().map(|(_, m)| m);
        let st_meta = self.store.setting(STORAGE_KEY).ok().flatten().map(|(_, m)| m);
        let ab_meta = self.store.setting(AUTO_BLOCK_KEY).ok().flatten().map(|(_, m)| m);
        json!({
            "ai": {
                "values": ai,
                "source": self.source(AI_KEY),
                "updated": ai_meta,
                "api_key": {
                    "set": key.is_some(),
                    "source": key.as_ref().map(|(_, s)| s.clone()),
                    "updated": key_meta,
                    "env_var": self.base.ai.api_key_env,
                },
                "triggers_available": ["block", "challenge", "rule_match", "anomaly"],
            },
            "storage": {
                "values": *self.storage.load_full(),
                "source": self.source(STORAGE_KEY),
                "updated": st_meta,
            },
            "auto_block": {
                "values": *self.auto_block.load_full(),
                "source": self.source(AUTO_BLOCK_KEY),
                "updated": ab_meta,
                "window_s": self.base.anomaly.window_s,
                "anomaly_enabled": self.base.anomaly.enabled,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        let store = Arc::new(Store::memory());
        store
            .set_vault(Arc::new(crate::vault::Vault::from_bytes(&[3u8; 32], "t").unwrap()))
            .unwrap();
        Settings::load(store, IntelConfig::default()).unwrap()
    }

    fn ai() -> AiSettings {
        AiSettings {
            enabled: true,
            model: "gemini-test-1".into(),
            base_url: "https://generativelanguage.googleapis.com".into(),
            timeout_ms: 8000,
            requests_per_minute: 30,
            max_calls_per_day: 2000,
            triggers: vec![AiTrigger::Block],
            send_body: false,
            price_per_mtok_in: 0.3,
            price_per_mtok_out: 2.5,
        }
    }

    #[test]
    fn dashboard_values_override_and_survive_reload() {
        let s = settings();
        assert!(!s.ai.load().enabled);
        s.save_ai(&ai(), "alice").unwrap();
        assert!(s.ai.load().enabled);
        assert_eq!(s.ai.load().model, "gemini-test-1");
        let reloaded = Settings::load(Arc::clone(&s.store), IntelConfig::default()).unwrap();
        assert_eq!(reloaded.ai.load().model, "gemini-test-1");
        reloaded.reset_ai().unwrap();
        assert!(!reloaded.ai.load().enabled, "reset returns to the config file");
    }

    #[test]
    fn api_key_is_never_described_and_dashboard_key_wins() {
        let s = settings();
        s.set_ai_key("AIzaSUPERSECRET", "alice").unwrap();
        let (k, src) = s.ai_key().unwrap();
        assert_eq!(k, "AIzaSUPERSECRET");
        assert!(src.contains("dashboard"));
        let d = s.describe().to_string();
        assert!(!d.contains("SUPERSECRET"), "{d}");
        assert!(d.contains("\"set\":true"));
        s.set_ai_key("", "alice").unwrap();
        assert!(s.store.setting(AI_API_KEY).unwrap().is_none());
        assert!(s.set_ai_key("two words", "alice").is_err());
    }

    #[test]
    fn invalid_values_are_rejected() {
        let s = settings();
        let mut a = ai();
        a.base_url = "http://evil.example".into();
        assert!(s.save_ai(&a, "x").is_err());
        let mut a = ai();
        a.model = "x;rm".into();
        assert!(s.save_ai(&a, "x").is_err());
        let mut st = StorageSettings::from_config(&StoreConfig::default());
        st.benign_sample_rate = 2.0;
        assert!(s.save_storage(&st, "x").is_err());
    }

    #[test]
    fn auto_block_settings_apply_at_once_and_reset() {
        let s = settings();
        assert!(!s.auto_block.load().enabled);
        let a = AutoBlockConfig { enabled: true, blocks_in_window: 10, min_score: 0.6, ttl_s: 3600 };
        s.save_auto_block(&a, "alice").unwrap();
        assert_eq!(**s.auto_block.load(), a);
        assert_eq!(s.describe()["auto_block"]["source"], "dashboard");
        let reloaded = Settings::load(Arc::clone(&s.store), IntelConfig::default()).unwrap();
        assert_eq!(**reloaded.auto_block.load(), a, "survives a restart");
        reloaded.reset_auto_block().unwrap();
        assert!(!reloaded.auto_block.load().enabled, "reset returns to the config file");
        for bad in [
            AutoBlockConfig { min_score: 1.5, ..a.clone() },
            AutoBlockConfig { min_score: f64::NAN, ..a.clone() },
            AutoBlockConfig { ttl_s: 0, ..a.clone() },
            AutoBlockConfig { blocks_in_window: 0, min_score: 0.0, ..a.clone() },
        ] {
            assert!(s.save_auto_block(&bad, "x").is_err(), "{bad:?}");
        }
        assert_eq!(**s.auto_block.load(), a, "a rejected save changes nothing");
    }

    #[test]
    fn storage_settings_apply_at_once() {
        let s = settings();
        let mut st = StorageSettings::from_config(&StoreConfig::default());
        st.store_all_events = true;
        st.per_client_per_sec = 0;
        s.save_storage(&st, "alice").unwrap();
        assert!(s.storage.load().store_all_events);
        assert_eq!(s.describe()["storage"]["source"], "dashboard");
    }
}
