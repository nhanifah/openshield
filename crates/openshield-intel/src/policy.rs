//! Runtime policy management: the active firewall can be replaced without
//! a restart, every version is stored, and a candidate can be dry-run
//! against recent traffic first.
//!
//! The policy is the WAF part of the config file (`rulesets`, `lists`,
//! `scores`, `detection_only`, …). Server keys are not part of it.
//!
//! Startup: if the newest stored version was derived from the same config
//! file content (same hash), it is reused, so API changes survive restarts.
//! If the file changed, the file wins and becomes a new version.

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use openshield_core::config::WafConfig;
use openshield_core::waf::data::RequestData;
use openshield_core::{BodyVerdict, Verdict, Waf};
use parking_lot::Mutex;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::store::Store;

/// Top-level keys a policy may contain.
pub const WAF_KEYS: &[&str] = &[
    "detection_only",
    "max_request_body_buffer",
    "request_body_limit_action",
    "inspect_response_body",
    "max_response_body_buffer",
    "response_body_limit_action",
    "log_payloads",
    "redaction",
    "geoip",
    "scores",
    "lists",
    "challenge",
    "token_configurations",
    "schemas",
    "rulesets",
];

/// A recent request kept (redacted) for simulations.
#[derive(Clone)]
pub struct Snapshot {
    pub event_id: String,
    pub request: RequestData,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub id: String,
    pub ruleset: String,
    pub phase: String,
    pub action: String,
    pub enabled: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimDiff {
    pub event_id: String,
    pub method: String,
    pub path: String,
    pub current: String,
    pub candidate: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Simulation {
    pub replayed: usize,
    pub changed: usize,
    pub current: BTreeMap<String, usize>,
    pub candidate: BTreeMap<String, usize>,
    pub diffs: Vec<SimDiff>,
}

struct Active {
    version: i64,
    yaml: String,
    config: WafConfig,
    applied_at: i64,
    actor: String,
    source: String,
}

pub struct PolicyManager {
    waf: ArcSwap<Waf>,
    active: Mutex<Active>,
}

pub fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// Placeholder sent instead of a secret value. Sending it back means "keep
/// the current value".
pub const SECRET_PLACEHOLDER: &str = "__secret_unchanged__";

/// Keys whose values are secrets: the Turnstile secret, the challenge
/// cookie key, and the private and symmetric members of JWKs.
const SECRET_KEYS: &[&str] = &["turnstile_secret_key", "cookie_secret", "k", "d", "p", "q", "dp", "dq", "qi"];

fn walk_secrets(v: &mut serde_yaml::Value, path: &mut Vec<String>, f: &mut dyn FnMut(&[String], &mut serde_yaml::Value)) {
    match v {
        serde_yaml::Value::Mapping(m) => {
            for (k, val) in m.iter_mut() {
                let key = k.as_str().unwrap_or("").to_string();
                path.push(key.clone());
                if SECRET_KEYS.contains(&key.as_str()) && val.is_string() {
                    f(path, val);
                } else {
                    walk_secrets(val, path, f);
                }
                path.pop();
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                path.push(format!("[{i}]"));
                walk_secrets(item, path, f);
                path.pop();
            }
        }
        _ => {}
    }
}

fn lookup<'a>(v: &'a serde_yaml::Value, path: &[String]) -> Option<&'a serde_yaml::Value> {
    let mut cur = v;
    for p in path {
        cur = if let Some(i) = p.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            cur.as_sequence()?.get(i.parse::<usize>().ok()?)?
        } else {
            cur.as_mapping()?.get(serde_yaml::Value::String(p.clone()))?
        };
    }
    Some(cur)
}

/// The policy with secret values replaced by [`SECRET_PLACEHOLDER`], for
/// anything shown to people. Policies without secrets come back unchanged.
pub fn mask_secrets(yaml: &str) -> String {
    let Ok(mut v) = serde_yaml::from_str::<serde_yaml::Value>(yaml) else {
        return yaml.to_string();
    };
    let mut changed = false;
    walk_secrets(&mut v, &mut Vec::new(), &mut |_, val| {
        *val = serde_yaml::Value::String(SECRET_PLACEHOLDER.into());
        changed = true;
    });
    if changed {
        serde_yaml::to_string(&v).unwrap_or_else(|_| yaml.to_string())
    } else {
        yaml.to_string()
    }
}

/// Put the current secret values back where a candidate still holds the
/// placeholder. A placeholder with no current value at that place is an
/// error: the editor moved or added a secret without giving its value.
pub fn restore_secrets(candidate: &str, current: &str) -> Result<String, String> {
    if !candidate.contains(SECRET_PLACEHOLDER) {
        return Ok(candidate.to_string());
    }
    let mut v: serde_yaml::Value = serde_yaml::from_str(candidate).map_err(|e| format!("invalid YAML: {e}"))?;
    let cur: serde_yaml::Value = serde_yaml::from_str(current).unwrap_or(serde_yaml::Value::Null);
    let mut missing = Vec::new();
    walk_secrets(&mut v, &mut Vec::new(), &mut |path, val| {
        if val.as_str() == Some(SECRET_PLACEHOLDER) {
            match lookup(&cur, path).filter(|x| x.as_str() != Some(SECRET_PLACEHOLDER)) {
                Some(orig) => *val = orig.clone(),
                None => missing.push(path.join(".")),
            }
        }
    });
    if !missing.is_empty() {
        return Err(format!(
            "no current value for masked secret(s) {}; enter the value instead of {SECRET_PLACEHOLDER}",
            missing.join(", ")
        ));
    }
    serde_yaml::to_string(&v).map_err(|e| e.to_string())
}

/// Extract the WAF keys of a full proxy config as a YAML document.
pub fn waf_yaml_from_config_file(full_yaml: &str) -> Result<String, String> {
    let v: serde_yaml::Value = serde_yaml::from_str(full_yaml).map_err(|e| e.to_string())?;
    let mut out = serde_yaml::Mapping::new();
    if let serde_yaml::Value::Mapping(m) = v {
        for (k, val) in m {
            if let Some(key) = k.as_str()
                && WAF_KEYS.contains(&key)
            {
                out.insert(k, val);
            }
        }
    }
    if out.is_empty() {
        return Ok("{}\n".into());
    }
    serde_yaml::to_string(&serde_yaml::Value::Mapping(out)).map_err(|e| e.to_string())
}

/// Parse and compile a policy. Unknown and server keys are rejected.
pub fn compile(yaml: &str) -> Result<(WafConfig, Waf), String> {
    let v: serde_yaml::Value = serde_yaml::from_str(yaml).map_err(|e| format!("invalid YAML: {e}"))?;
    match &v {
        serde_yaml::Value::Mapping(m) => {
            for k in m.keys() {
                let key = k.as_str().ok_or("policy keys must be strings")?;
                if !WAF_KEYS.contains(&key) {
                    return Err(format!(
                        "key {key:?} is not allowed in a policy (allowed: {})",
                        WAF_KEYS.join(", ")
                    ));
                }
            }
        }
        serde_yaml::Value::Null => {}
        _ => return Err("policy must be a YAML mapping".into()),
    }
    let config = WafConfig::from_yaml(yaml).map_err(|e| e.to_string())?;
    let waf = Waf::from_config(&config).map_err(|e| e.to_string())?;
    Ok((config, waf))
}

impl PolicyManager {
    /// Load the startup policy (see module docs) and record it.
    pub fn init(file_yaml: &str, store: Option<&Store>) -> Result<Self, String> {
        let file_hash = sha256_hex(file_yaml);
        let stored = match store {
            Some(s) => s.active_policy()?,
            None => None,
        };
        let (version, yaml, actor, source, applied_at) = match stored {
            Some(v) if v.file_hash == file_hash => {
                let y = v.yaml.clone().unwrap_or_default();
                log::info!("Policy: using stored version {} ({} by {})", v.version, v.source, v.actor);
                (v.version, y, v.actor, v.source, v.ts)
            }
            _ => {
                let (_, waf) = compile(file_yaml)?;
                let version = match store {
                    Some(s) => s.add_policy_version("config-file", "loaded from config file", "file", file_yaml, &file_hash, waf.rule_count())?,
                    None => 0,
                };
                (version, file_yaml.to_string(), "config-file".into(), "file".into(), crate::store::now_ms())
            }
        };
        let (config, waf) = compile(&yaml)?;
        Ok(Self {
            waf: ArcSwap::from_pointee(waf),
            active: Mutex::new(Active {
                version,
                yaml,
                config,
                applied_at,
                actor,
                source,
            }),
        })
    }

    /// The firewall for a new request.
    pub fn current(&self) -> Arc<Waf> {
        self.waf.load_full()
    }

    pub fn version(&self) -> i64 {
        self.active.lock().version
    }

    /// The active policy as stored, secrets included. Never send to clients.
    pub fn current_yaml(&self) -> String {
        self.active.lock().yaml.clone()
    }

    /// The active policy for display: secrets masked.
    pub fn info(&self) -> serde_json::Value {
        let a = self.active.lock();
        serde_json::json!({
            "version": a.version,
            "yaml": mask_secrets(&a.yaml),
            "applied_at": a.applied_at,
            "actor": a.actor,
            "source": a.source,
            "detection_only": a.config.detection_only,
        })
    }

    pub fn rules(&self) -> Vec<RuleInfo> {
        let a = self.active.lock();
        let mut out = Vec::new();
        for rs in &a.config.rulesets {
            for r in &rs.rules {
                out.push(RuleInfo {
                    id: r.id.clone(),
                    ruleset: rs.name.clone(),
                    phase: enum_name(&r.phase),
                    action: enum_name(&r.action),
                    enabled: r.enabled,
                    description: r.description.clone(),
                });
            }
        }
        out
    }

    pub fn detection_only(&self) -> bool {
        self.active.lock().config.detection_only
    }

    /// Compile and swap in a new policy, recording it as a version.
    pub fn apply(&self, yaml: &str, actor: &str, comment: &str, store: Option<&Store>) -> Result<i64, String> {
        let (config, waf) = compile(yaml)?;
        let rule_count = waf.rule_count();
        let file_hash = {
            // Keep the file hash of the base so restarts reuse this version
            // while the config file is unchanged.
            match store.and_then(|s| s.active_policy().ok().flatten()) {
                Some(v) => v.file_hash,
                None => String::new(),
            }
        };
        let version = match store {
            Some(s) => s.add_policy_version(actor, comment, "api", yaml, &file_hash, rule_count)?,
            None => self.version() + 1,
        };
        self.waf.store(Arc::new(waf));
        *self.active.lock() = Active {
            version,
            yaml: yaml.to_string(),
            config,
            applied_at: crate::store::now_ms(),
            actor: actor.to_string(),
            source: "api".into(),
        };
        log::warn!("Policy version {version} applied by {actor} ({rule_count} rules)");
        Ok(version)
    }

    /// Dry run: evaluate the request phases of recent requests with fresh
    /// instances of the current and the candidate policy, and compare the
    /// decisions. Fresh instances start with empty rate-limit counters on
    /// both sides, and leave live counters untouched.
    pub fn simulate(&self, candidate_yaml: &str, snapshots: &[Snapshot]) -> Result<Simulation, String> {
        let (_, cand) = compile(candidate_yaml)?;
        let current_yaml = self.active.lock().yaml.clone();
        let (_, cur) = compile(&current_yaml)?;
        let cur = Arc::new(cur);
        let cand = Arc::new(cand);
        let mut sim = Simulation {
            replayed: 0,
            changed: 0,
            current: BTreeMap::new(),
            candidate: BTreeMap::new(),
            diffs: Vec::new(),
        };
        for s in snapshots {
            let a = decide(&cur, s);
            let b = decide(&cand, s);
            *sim.current.entry(a.clone()).or_default() += 1;
            *sim.candidate.entry(b.clone()).or_default() += 1;
            sim.replayed += 1;
            if a != b {
                sim.changed += 1;
                if sim.diffs.len() < 200 {
                    sim.diffs.push(SimDiff {
                        event_id: s.event_id.clone(),
                        method: s.request.method.clone(),
                        path: s.request.path.clone(),
                        current: a,
                        candidate: b,
                    });
                }
            }
        }
        Ok(sim)
    }
}

fn enum_name<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The request-side decision of `waf` for a snapshot, as the action name
/// (the transaction's recorded action, so detection-only mode shows what
/// would have happened).
pub fn decide(waf: &Arc<Waf>, s: &Snapshot) -> String {
    let mut tx = waf.transaction();
    let v = tx.request_headers(s.request.clone());
    if matches!(v, Verdict::Block(_) | Verdict::Challenge) {
        return tx.action().to_string();
    }
    if let BodyVerdict::Block(_) = tx.request_body_chunk(&s.body, true) {
        return "block".into();
    }
    tx.action().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "rulesets:\n  - name: main\n    kind: root\n    rules:\n      - id: admin\n        action: block\n        expression: 'http.request.uri.path == \"/admin\"'\n";
    const STRICT: &str = "rulesets:\n  - name: main\n    kind: root\n    rules:\n      - id: admin\n        action: block\n        expression: 'starts_with(http.request.uri.path, \"/a\")'\n";

    fn snap(path: &str) -> Snapshot {
        Snapshot {
            event_id: path.into(),
            request: RequestData {
                client_ip: Some("10.0.0.1".parse().unwrap()),
                is_tls: false,
                method: "GET".into(),
                version: "HTTP/1.1".into(),
                host: "h".into(),
                full_uri: format!("http://h{path}"),
                uri: path.into(),
                path: path.into(),
                query: String::new(),
                extension: String::new(),
                headers: vec![],
                geo: None,
            },
            body: vec![],
        }
    }

    #[test]
    fn extracts_only_waf_keys_from_a_config_file() {
        let full = format!("listen: x\nupstream: y\nadmin: {{enabled: false}}\n{BASE}");
        let y = waf_yaml_from_config_file(&full).unwrap();
        assert!(!y.contains("listen"));
        assert!(y.contains("rulesets"));
        assert!(compile(&y).is_ok());
    }

    #[test]
    fn server_and_unknown_keys_are_rejected() {
        assert!(compile("listen: 0.0.0.0:80\n").err().unwrap().contains("not allowed"));
        assert!(compile("rulez: []\n").is_err());
        assert!(compile("- a\n").is_err());
        assert!(compile("rulesets:\n  - name: m\n    kind: root\n    rules:\n      - id: x\n        action: block\n        expression: 'nonsense =='\n").is_err());
    }

    #[test]
    fn apply_swaps_the_firewall_and_records_versions() {
        let store = Store::memory();
        let pm = PolicyManager::init(BASE, Some(&store)).unwrap();
        let v1 = pm.version();
        let before = pm.current();
        assert_eq!(decide(&before, &snap("/abc")), "pass");
        let v2 = pm.apply(STRICT, "alice", "tighten", Some(&store)).unwrap();
        assert!(v2 > v1);
        assert_eq!(decide(&pm.current(), &snap("/abc")), "block");
        // A request that started before the swap keeps its firewall.
        assert_eq!(decide(&before, &snap("/abc")), "pass");
        // A restart with the same file reuses the API version.
        let pm2 = PolicyManager::init(BASE, Some(&store)).unwrap();
        assert_eq!(pm2.version(), v2);
        // A changed file wins.
        let pm3 = PolicyManager::init(&format!("{BASE}detection_only: true\n"), Some(&store)).unwrap();
        assert!(pm3.version() > v2);
        assert!(pm3.detection_only());
    }

    #[test]
    fn invalid_policy_is_not_applied() {
        let pm = PolicyManager::init(BASE, None).unwrap();
        let v = pm.version();
        assert!(pm.apply("listen: x\n", "a", "", None).is_err());
        assert_eq!(pm.version(), v);
    }

    #[test]
    fn simulation_reports_changed_decisions() {
        let pm = PolicyManager::init(BASE, None).unwrap();
        let snaps = vec![snap("/admin"), snap("/abc"), snap("/home")];
        let sim = pm.simulate(STRICT, &snaps).unwrap();
        assert_eq!(sim.replayed, 3);
        assert_eq!(sim.changed, 1);
        assert_eq!(sim.diffs[0].path, "/abc");
        assert_eq!(sim.current["block"], 1);
        assert_eq!(sim.candidate["block"], 2);
    }

    #[test]
    fn secrets_are_masked_and_restored() {
        let full = "challenge:\n  turnstile_site_key: site\n  turnstile_secret_key: TOPSECRET\n  cookie_secret: COOKIEKEY\nrulesets: []\n";
        let masked = mask_secrets(full);
        assert!(!masked.contains("TOPSECRET") && !masked.contains("COOKIEKEY"), "{masked}");
        assert!(masked.contains("site"), "non-secret values stay");
        let edited = masked.replace("site\n", "site2\n");
        let restored = restore_secrets(&edited, full).unwrap();
        assert!(restored.contains("TOPSECRET") && restored.contains("COOKIEKEY") && restored.contains("site2"));
        // A placeholder where the current policy has no secret is refused.
        let moved = "challenge:\n  turnstile_site_key: s\n  turnstile_secret_key: __secret_unchanged__\n  cookie_secret: x\n";
        assert!(restore_secrets(moved, "rulesets: []\n").is_err());
        // Policies without secrets keep their formatting.
        assert_eq!(mask_secrets(BASE), BASE);
    }

    #[test]
    fn info_never_contains_secrets() {
        let yaml = format!("{BASE}challenge:\n  turnstile_site_key: s\n  turnstile_secret_key: TOPSECRET\n  cookie_secret: COOKIEKEY\n");
        let pm = PolicyManager::init(&yaml, None).unwrap();
        let info = pm.info().to_string();
        assert!(!info.contains("TOPSECRET") && !info.contains("COOKIEKEY"));
        assert!(pm.current_yaml().contains("TOPSECRET"));
    }

    #[test]
    fn rules_are_listed() {
        let pm = PolicyManager::init(BASE, None).unwrap();
        let r = pm.rules();
        assert_eq!(r[0].id, "admin");
        assert_eq!(r[0].action, "block");
    }
}
