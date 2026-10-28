//! Layer 4: reviewed datasets from labeled security events.
//!
//! Ground truth is the current label a person set on each event (status
//! `confirmed`). AI suggestions stay `suggested` until a person accepts,
//! overrides or dismisses them; an export can include pending suggestions
//! only in a separate `candidates.jsonl`, never in the splits.
//!
//! Export pipeline: current labels → join events → drop conflicting
//! fingerprints → deduplicate by (fingerprint, label) → cap any single
//! client's share (poisoning resistance) → split (temporal or by client) →
//! check that no fingerprint crosses splits → write JSONL plus a manifest
//! with SHA-256 checksums.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::ai::sanitize::Sanitizer;
use crate::event::SecurityEvent;
use crate::store::{Label, Store};

pub const LABELS: &[&str] = &[
    "ALLOWED_NORMAL",
    "ALLOWED_UNUSUAL",
    "SUSPICIOUS",
    "MALICIOUS_CONFIRMED",
    "POLICY_VIOLATION",
    "FALSE_POSITIVE",
    "FALSE_NEGATIVE",
    "UNKNOWN",
    "NEEDS_REVIEW",
];

/// Labels that are not usable as training targets.
const NON_TARGET: &[&str] = &["UNKNOWN", "NEEDS_REVIEW"];

pub const SCHEMA_VERSION: &str = "openshield-dataset-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Split {
    Temporal,
    Entity,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportParams {
    pub split: Split,
    pub include_candidates: bool,
    /// Largest share of records from one client, applied when there are at
    /// least 100 records.
    pub max_client_share: f64,
}

impl Default for ExportParams {
    fn default() -> Self {
        Self {
            split: Split::Temporal,
            include_candidates: false,
            max_client_share: 0.05,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct Record {
    event_id: String,
    features: Value,
    label: String,
    label_source: String,
    label_id: i64,
    labeled_by: String,
    reviewer: Option<String>,
    review_status: String,
    label_note: String,
    ai_candidate: Option<Value>,
    policy_version: Option<i64>,
    model_version: Option<String>,
    collected_ts: i64,
    labeled_ts: i64,
    dataset_version: String,
    fingerprint: String,
    client: String,
    split: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ExportStats {
    pub approved_labels: usize,
    pub missing_events: usize,
    pub non_target_labels: usize,
    pub conflicting_fingerprints: usize,
    pub duplicates_removed: usize,
    pub client_cap_removed: usize,
    pub contamination_removed: usize,
    pub records: BTreeMap<String, usize>,
    pub per_label: BTreeMap<String, BTreeMap<String, usize>>,
    /// Largest class count divided by smallest (over labels present).
    pub imbalance_ratio: Option<f64>,
    pub candidates: usize,
    /// Exported records whose triggering value may be masked.
    pub evidence_redacted: usize,
    pub files: BTreeMap<String, String>,
}

/// Feature vector for one event: sanitized, no raw IP.
pub fn features(ev: &SecurityEvent, sanitizer: &Sanitizer) -> Value {
    let input = sanitizer.input(&ev.id, ev);
    json!({
        "method": input.method,
        "path": input.path,
        "path_template": input.path_template,
        "query": input.query,
        "query_keys": input.query.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        "headers": input.headers,
        "status": input.status,
        "firewall_action": input.firewall_action,
        "rules_matched": input.rules_matched,
        "scores": input.scores,
        "anomaly_score": input.anomaly_score,
        "anomaly_reasons": input.anomaly_reasons,
        "country": input.country,
        "asn": input.asn,
        "duration_ms": ev.duration_ms,
        "bytes_in": ev.bytes_in,
        "bytes_out": ev.bytes_out,
        "prompt_injection_markers": input.prompt_injection_markers,
        "evidence_redacted": ev.evidence_redacted(),
    })
}

fn bucket(s: &str) -> u64 {
    let h = Sha256::digest(s.as_bytes());
    u64::from_be_bytes(h[..8].try_into().unwrap()) % 100
}

pub fn export(
    store: &Store,
    dir: &Path,
    actor: &str,
    params: &ExportParams,
    sanitizer: &Sanitizer,
) -> Result<(String, ExportStats), String> {
    let version = format!(
        "ds-{}-{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        &uuid::Uuid::new_v4().simple().to_string()[..6]
    );
    let mut stats = ExportStats::default();

    // 1. the current label of each event (set by a person)
    let labels = store.confirmed_labels()?;
    stats.approved_labels = labels.len();
    let mut per_event: HashMap<String, Label> = HashMap::new();
    for l in labels {
        match per_event.get(&l.event_id) {
            Some(prev) if prev.decided_ts.unwrap_or(prev.ts) >= l.decided_ts.unwrap_or(l.ts) => {}
            _ => {
                per_event.insert(l.event_id.clone(), l);
            }
        }
    }

    // 2. join events
    let mut rows: Vec<(SecurityEvent, Label)> = Vec::new();
    for (id, l) in per_event {
        if NON_TARGET.contains(&l.label.as_str()) {
            stats.non_target_labels += 1;
            continue;
        }
        match store.get_event(&id)? {
            Some(ev) => rows.push((ev, l)),
            None => stats.missing_events += 1,
        }
    }
    rows.sort_by(|a, b| a.0.ts.cmp(&b.0.ts).then_with(|| a.0.id.cmp(&b.0.id)));

    // 3. fingerprints labeled two different ways are ambiguous: drop them
    let mut fp_labels: HashMap<String, HashSet<String>> = HashMap::new();
    for (ev, l) in &rows {
        fp_labels.entry(ev.fingerprint()).or_default().insert(l.label.clone());
    }
    let conflicted: HashSet<String> = fp_labels
        .into_iter()
        .filter(|(_, ls)| ls.len() > 1)
        .map(|(fp, _)| fp)
        .collect();
    stats.conflicting_fingerprints = conflicted.len();
    rows.retain(|(ev, _)| !conflicted.contains(&ev.fingerprint()));

    // 4. deduplicate
    let mut seen = HashSet::new();
    let before = rows.len();
    rows.retain(|(ev, l)| seen.insert((ev.fingerprint(), l.label.clone())));
    stats.duplicates_removed = before - rows.len();

    // 5. per-client cap
    if rows.len() >= 100 {
        let cap = ((rows.len() as f64) * params.max_client_share).ceil() as usize;
        let mut per_client: HashMap<String, usize> = HashMap::new();
        let before = rows.len();
        rows.retain(|(ev, _)| {
            let n = per_client.entry(ev.client_ip.clone()).or_default();
            *n += 1;
            *n <= cap
        });
        stats.client_cap_removed = before - rows.len();
    }

    // 6. split
    let n = rows.len();
    let mut records: Vec<Record> = Vec::with_capacity(n);
    for (i, (ev, l)) in rows.into_iter().enumerate() {
        let client = sanitizer.client_id(&ev.client_ip);
        let split = match params.split {
            Split::Temporal => {
                let q = if n == 0 { 0.0 } else { i as f64 / n as f64 };
                if q < 0.70 {
                    "train"
                } else if q < 0.85 {
                    "validation"
                } else {
                    "test"
                }
            }
            Split::Entity => match bucket(&client) {
                0..70 => "train",
                70..85 => "validation",
                _ => "test",
            },
        };
        records.push(Record {
            event_id: ev.id.clone(),
            features: features(&ev, sanitizer),
            label: l.label.clone(),
            label_source: l.source.clone(),
            label_id: l.id,
            labeled_by: l.created_by.clone(),
            reviewer: l.reviewer.clone(),
            review_status: l.status.clone(),
            label_note: crate::ai::sanitize::truncate(&l.note, 500),
            ai_candidate: ev.ai.as_ref().map(|v| {
                json!({"category": v.category.as_str(), "risk": v.risk, "confidence": v.confidence,
                       "model": v.model, "model_version": v.model_version, "prompt_version": v.prompt_version})
            }),
            policy_version: l.policy_version,
            model_version: l.model_version.clone(),
            collected_ts: ev.ts,
            labeled_ts: l.decided_ts.unwrap_or(l.ts),
            dataset_version: version.clone(),
            fingerprint: ev.fingerprint(),
            client,
            split: split.into(),
        });
    }

    // 7. contamination: a fingerprint in train must not appear elsewhere
    let train_fps: HashSet<String> = records
        .iter()
        .filter(|r| r.split == "train")
        .map(|r| r.fingerprint.clone())
        .collect();
    let before = records.len();
    records.retain(|r| r.split == "train" || !train_fps.contains(&r.fingerprint));
    stats.contamination_removed = before - records.len();

    // 8. write
    let out_dir = dir.join(&version);
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    for split in ["train", "validation", "test"] {
        let rs: Vec<&Record> = records.iter().filter(|r| r.split == split).collect();
        stats.records.insert(split.into(), rs.len());
        let per = stats.per_label.entry(split.into()).or_default();
        for r in &rs {
            *per.entry(r.label.clone()).or_default() += 1;
        }
        let path = out_dir.join(format!("{split}.jsonl"));
        let sum = write_jsonl(&path, rs.iter().map(|r| serde_json::to_value(r).unwrap()))?;
        stats.files.insert(format!("{split}.jsonl"), sum);
    }
    stats.evidence_redacted = records
        .iter()
        .filter(|r| r.features["evidence_redacted"] == Value::Bool(true))
        .count();
    let mut totals: BTreeMap<&str, usize> = BTreeMap::new();
    for r in &records {
        *totals.entry(r.label.as_str()).or_default() += 1;
    }
    if let (Some(max), Some(min)) = (totals.values().max(), totals.values().min())
        && *min > 0
    {
        stats.imbalance_ratio = Some((*max as f64 / *min as f64 * 100.0).round() / 100.0);
    }

    if params.include_candidates {
        let cands: Vec<Value> = store
            .labels(Some("suggested"), None, 1_000_000)?
            .into_iter()
            .filter_map(|l| {
                let ev = store.get_event(&l.event_id).ok().flatten()?;
                Some(json!({
                    "event_id": ev.id, "features": features(&ev, sanitizer),
                    "candidate_label": l.label, "label_source": l.source, "status": "suggested",
                    "model_version": l.model_version, "collected_ts": ev.ts,
                    "dataset_version": version, "not_ground_truth": true,
                }))
            })
            .collect();
        stats.candidates = cands.len();
        let sum = write_jsonl(&out_dir.join("candidates.jsonl"), cands.into_iter())?;
        stats.files.insert("candidates.jsonl".into(), sum);
    }

    let manifest = json!({
        "schema": SCHEMA_VERSION,
        "version": version,
        "created_ts": crate::store::now_ms(),
        "created_by": actor,
        "params": params,
        "labels": LABELS,
        "stats": stats,
        "notes": [
            "Splits contain only labels set by a person.",
            "candidates.jsonl (if present) holds unreviewed suggestions and is not ground truth.",
            "Client identifiers are keyed hashes; raw IPs are not exported.",
            "Values were redacted at capture time and again at export.",
            "On requests that matched a rule, masked values keep their shape: letters become a, digits 9, attack keywords and punctuation stay.",
            "features.evidence_redacted marks records where a rule matched and part of the query or body was masked; the triggering value may be hidden, so consider excluding them from training."
        ],
    });
    let mpath = out_dir.join("manifest.json");
    std::fs::write(&mpath, serde_json::to_vec_pretty(&manifest).unwrap()).map_err(|e| e.to_string())?;
    store.add_dataset(
        &version,
        actor,
        &serde_json::to_value(params).unwrap(),
        &serde_json::to_value(&stats).unwrap(),
        &out_dir.to_string_lossy(),
    )?;
    Ok((version, stats))
}

fn write_jsonl(path: &PathBuf, rows: impl Iterator<Item = Value>) -> Result<String, String> {
    let mut f = std::fs::File::create(path).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    for r in rows {
        let mut line = serde_json::to_vec(&r).map_err(|e| e.to_string())?;
        line.push(b'\n');
        h.update(&line);
        f.write_all(&line).map_err(|e| e.to_string())?;
    }
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests_support::sample_event;

    fn ev(id: &str, ts: i64, ip: &str, path: &str, query: &str) -> SecurityEvent {
        let mut e = sample_event();
        e.id = id.into();
        e.ts = ts;
        e.client_ip = ip.into();
        e.path = path.into();
        e.query = query.into();
        e
    }

    fn approve(store: &Store, event: &str, label: &str) {
        store.set_label(event, Some(label), "", "alice", None).unwrap();
    }

    fn read(dir: &Path, version: &str, split: &str) -> Vec<Value> {
        std::fs::read_to_string(dir.join(version).join(format!("{split}.jsonl")))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn export_uses_only_approved_labels_and_dedups() {
        let store = Store::memory();
        let tmp = tempfile::tempdir().unwrap();
        let mut events = Vec::new();
        for i in 0..20 {
            events.push(ev(&format!("e{i}"), i, &format!("10.0.0.{i}"), &format!("/p{i}"), "a=1"));
        }
        // duplicate shape of e0 with the same label
        events.push(ev("dup", 100, "10.0.0.99", "/p0", "a=2"));
        // unreviewed AI candidate
        events.push(ev("cand", 101, "10.0.0.98", "/c", ""));
        store.insert_events(&events).unwrap();
        for i in 0..20 {
            approve(&store, &format!("e{i}"), if i % 2 == 0 { "ALLOWED_NORMAL" } else { "MALICIOUS_CONFIRMED" });
        }
        approve(&store, "dup", "ALLOWED_NORMAL");
        store.add_suggestion("cand", "MALICIOUS_CONFIRMED", "m").unwrap();
        let s = Sanitizer::new(Some(b"k".to_vec()), false);
        let (v, stats) = export(&store, tmp.path(), "admin", &ExportParams { include_candidates: true, ..Default::default() }, &s).unwrap();
        assert_eq!(stats.duplicates_removed, 1);
        let total: usize = stats.records.values().sum();
        assert_eq!(total, 20);
        let train = read(tmp.path(), &v, "train");
        assert_eq!(train.len(), 14);
        assert!(train.iter().all(|r| r["review_status"] == "confirmed"));
        let all: Vec<Value> = ["train", "validation", "test"].iter().flat_map(|s| read(tmp.path(), &v, s)).collect();
        assert!(all.iter().all(|r| r["event_id"] != "cand"), "candidate leaked into splits");
        assert!(all.iter().all(|r| !r.to_string().contains("10.0.0.")), "raw IP exported");
        assert_eq!(stats.candidates, 1);
        let manifest: Value = serde_json::from_str(&std::fs::read_to_string(tmp.path().join(&v).join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["schema"], SCHEMA_VERSION);
        assert_eq!(manifest["stats"]["files"]["train.jsonl"].as_str().unwrap().len(), 64);
        assert_eq!(store.datasets().unwrap().len(), 1);
    }

    #[test]
    fn temporal_split_keeps_test_after_train() {
        let store = Store::memory();
        let tmp = tempfile::tempdir().unwrap();
        let events: Vec<_> = (0..40).map(|i| ev(&format!("e{i}"), 1000 + i, &format!("10.1.0.{i}"), &format!("/t{i}"), "")).collect();
        store.insert_events(&events).unwrap();
        for i in 0..40 {
            approve(&store, &format!("e{i}"), "ALLOWED_NORMAL");
        }
        let s = Sanitizer::new(Some(b"k".to_vec()), false);
        let (v, _) = export(&store, tmp.path(), "a", &ExportParams::default(), &s).unwrap();
        let max_train = read(tmp.path(), &v, "train").iter().map(|r| r["collected_ts"].as_i64().unwrap()).max().unwrap();
        let min_test = read(tmp.path(), &v, "test").iter().map(|r| r["collected_ts"].as_i64().unwrap()).min().unwrap();
        assert!(max_train < min_test);
    }

    #[test]
    fn conflicting_labels_and_dominant_clients_are_removed() {
        let store = Store::memory();
        let tmp = tempfile::tempdir().unwrap();
        let mut events = vec![ev("x1", 1, "1.1.1.1", "/same", ""), ev("x2", 2, "2.2.2.2", "/same", "")];
        // 150 events from one client and 50 from others
        for i in 0..150 {
            events.push(ev(&format!("p{i}"), 10 + i, "6.6.6.6", &format!("/q{i}"), ""));
        }
        for i in 0..50 {
            events.push(ev(&format!("o{i}"), 500 + i, &format!("10.2.0.{i}"), &format!("/r{i}"), ""));
        }
        store.insert_events(&events).unwrap();
        approve(&store, "x1", "ALLOWED_NORMAL");
        approve(&store, "x2", "MALICIOUS_CONFIRMED");
        for i in 0..150 {
            approve(&store, &format!("p{i}"), "FALSE_POSITIVE");
        }
        for i in 0..50 {
            approve(&store, &format!("o{i}"), "ALLOWED_NORMAL");
        }
        let s = Sanitizer::new(Some(b"k".to_vec()), false);
        let (_, stats) = export(&store, tmp.path(), "a", &ExportParams { split: Split::Entity, ..Default::default() }, &s).unwrap();
        assert_eq!(stats.conflicting_fingerprints, 1);
        // cap = ceil(200 * 0.05) = 10 from 6.6.6.6
        assert_eq!(stats.client_cap_removed, 140);
        assert_eq!(stats.records.values().sum::<usize>(), 60);
    }

    #[test]
    fn evidence_redacted_marks_masked_values_on_matched_requests() {
        let s = Sanitizer::new(Some(b"k".to_vec()), false);
        let redactor = openshield_core::redact::Redactor::new(&Default::default());
        let mut matched = ev("m", 1, "10.0.0.1", "/p", &redactor.query_shaped("session_id=x'+or+1=1&q=a"));
        matched.matched_rules = vec![crate::event::MatchedRule { id: "sqli-args".into(), action: "block".into() }];
        let f = features(&matched, &s);
        assert_eq!(f["evidence_redacted"], true);
        // The shape survives the export's second redaction pass.
        // (query values stay URL-encoded in the export)
        assert_eq!(f["query"][0][1], "%5BREDACTED%5D+len%3D9+shape%3Da%27+OR+9%3D9");

        // Masked but no rule matched, or a rule matched with nothing masked.
        let mut plain = ev("p", 2, "10.0.0.2", "/p", &redactor.query("session_id=abc"));
        assert_eq!(features(&plain, &s)["evidence_redacted"], false);
        plain.query = "q=1".into();
        plain.matched_rules = matched.matched_rules.clone();
        assert_eq!(features(&plain, &s)["evidence_redacted"], false);
    }
}
