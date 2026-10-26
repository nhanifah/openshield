//! Geo data status and settings, and country/region/ASN rules.
//!
//! Rules live in the WAF policy (`geo_access`), so every change is a policy
//! version: audited, reversible with a rollback, and subject to second-admin
//! approval when that is on. They compile to request-headers rules
//! (`geo:<id>`) that run before every ruleset.

use std::collections::HashSet;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use openshield_core::config::{GeoAccessConfig, GeoRule};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ApiError, ApiResult, App, Caller, audit, ok};
use crate::config::Role;
use crate::geo::GeoSettings;
use crate::store::now_ms;

type S = State<Arc<App>>;

const MAX_RULES: usize = 50;
const IMPACT_WINDOW_MS: i64 = 24 * 3_600_000;

/// The geo rules in the active policy.
pub fn current_rules(app: &App) -> Vec<GeoRule> {
    let doc: Value = serde_yaml::from_str(&app.policy.current_yaml()).unwrap_or(Value::Null);
    doc.get("geo_access")
        .and_then(|g| serde_json::from_value::<GeoAccessConfig>(g.clone()).ok())
        .map(|g| g.rules)
        .unwrap_or_default()
}

/// Upper-case and de-duplicate codes, so the stored policy is canonical.
fn normalize(mut r: GeoRule) -> Result<GeoRule, ApiError> {
    let clean = |v: Vec<String>| {
        let mut seen = HashSet::new();
        v.into_iter()
            .map(|s| s.trim().to_ascii_uppercase())
            .filter(|s| !s.is_empty() && seen.insert(s.clone()))
            .collect::<Vec<_>>()
    };
    r.id = r.id.trim().to_ascii_lowercase();
    r.countries = clean(r.countries);
    // Region names keep their case: `id:Jakarta` becomes `ID:Jakarta`.
    let mut seen = HashSet::new();
    r.regions = r
        .regions
        .into_iter()
        .map(|x| {
            let x = x.trim().to_string();
            match x.split_once(':') {
                Some((cc, name)) => format!("{}:{}", cc.trim().to_ascii_uppercase(), name.trim()),
                None => x.to_ascii_uppercase(),
            }
        })
        .filter(|x| !x.is_empty() && seen.insert(x.clone()))
        .collect();
    let mut seen = HashSet::new();
    r.asns.retain(|a| seen.insert(*a));
    r.description = r
        .description
        .map(|d| d.trim().chars().filter(|c| !c.is_control()).take(200).collect::<String>())
        .filter(|d| !d.is_empty());
    r.validate().map_err(ApiError::bad)?;
    Ok(r)
}

pub async fn get_geo(State(app): S, c: Caller) -> ApiResult {
    let mut status = app.geo.status();
    if !c.user.can(Role::Admin) {
        // File locations are for admins.
        status["settings"] = Value::Null;
        status["files"] = Value::Null;
    }
    ok(json!({
        "status": status,
        "rules": current_rules(&app),
        "policy_version": app.policy.version(),
        "can_edit": c.user.can(Role::Admin),
    }))
}

pub async fn impact(State(app): S, _c: Caller, Json(rule): Json<GeoRule>) -> ApiResult {
    let rule = normalize(rule)?;
    let imp = app.hub.stats.lock().geo_impact(now_ms(), IMPACT_WINDOW_MS, &rule);
    ok(json!({"impact": imp, "geo_loaded": app.geo.loaded()}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesBody {
    rules: Vec<GeoRule>,
}

pub async fn put_rules(State(app): S, c: Caller, Json(b): Json<RulesBody>) -> ApiResult {
    c.require(Role::Admin)?;
    if b.rules.len() > MAX_RULES {
        return Err(ApiError::bad(format!("at most {MAX_RULES} geo rules")));
    }
    let mut ids = HashSet::new();
    let mut rules = Vec::with_capacity(b.rules.len());
    for r in b.rules {
        let r = normalize(r)?;
        if !ids.insert(r.id.clone()) {
            return Err(ApiError::bad(format!("two rules are named {:?}", r.id)));
        }
        rules.push(r);
    }
    if rules == current_rules(&app) {
        return ok(json!({"status": "unchanged", "version": app.policy.version()}));
    }

    let mut doc: serde_yaml::Value = serde_yaml::from_str(&app.policy.current_yaml()).map_err(ApiError::internal)?;
    if !doc.is_mapping() {
        doc = serde_yaml::Value::Mapping(Default::default());
    }
    let map = doc.as_mapping_mut().expect("mapping");
    let key = serde_yaml::Value::String("geo_access".into());
    if rules.is_empty() {
        map.remove(&key);
    } else {
        let v = serde_yaml::to_value(GeoAccessConfig { rules: rules.clone() }).map_err(ApiError::internal)?;
        map.insert(key, v);
    }
    let yaml = serde_yaml::to_string(&doc).map_err(ApiError::internal)?;
    let check = yaml.clone();
    tokio::task::spawn_blocking(move || crate::policy::compile(&check).map(|_| ()))
        .await
        .map_err(ApiError::internal)?
        .map_err(|e| ApiError::bad(format!("the policy would not compile: {e}")))?;

    let summary: Vec<Value> = rules
        .iter()
        .map(|r| json!({"id": r.id, "enabled": r.enabled, "mode": r.mode, "action": r.action,
                        "countries": r.countries, "regions": r.regions, "asns": r.asns}))
        .collect();
    let comment = format!(
        "Geo rules: {}",
        if rules.is_empty() { "all removed".to_string() } else { rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>().join(", ") }
    );
    if app.cfg.require_second_approver {
        let id = app
            .hub
            .store
            .add_change("policy_apply", &comment, &json!({"yaml": yaml, "comment": comment}), &c.user.name)
            .map_err(ApiError::internal)?;
        audit(&app, &c, "geo_rules", "geo_access", json!({"rules": summary}), "pending approval");
        return ok(json!({"status": "pending", "change_id": id}));
    }
    let v = app.policy.apply(&yaml, &c.user.name, &comment, Some(&app.hub.store)).map_err(ApiError::bad)?;
    audit(&app, &c, "geo_rules", "geo_access", json!({"rules": summary}), "applied");
    ok(json!({"status": "applied", "version": v}))
}

// ---- data files (admin) ---------------------------------------------------------

pub async fn put_settings(State(app): S, c: Caller, Json(b): Json<GeoSettings>) -> ApiResult {
    c.require(Role::Admin)?;
    let geo = Arc::clone(&app.geo);
    let by = c.user.name.clone();
    let b2 = b.clone();
    tokio::task::spawn_blocking(move || geo.save_settings(&b2, &by))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::bad)?;
    audit(&app, &c, "settings_geo", "geo", json!({"city_mmdb": b.city_mmdb, "asn_mmdb": b.asn_mmdb, "auto_update": b.auto_update}), "ok");
    ok(json!({"status": "saved", "geo": app.geo.status()}))
}

pub async fn reset_settings(State(app): S, c: Caller) -> ApiResult {
    c.require(Role::Admin)?;
    let geo = Arc::clone(&app.geo);
    tokio::task::spawn_blocking(move || geo.reset_settings())
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
    audit(&app, &c, "settings_geo", "geo", json!({"reset": true}), "ok");
    ok(json!({"status": "reset", "geo": app.geo.status()}))
}

/// Start downloading DB-IP Lite; the status shows progress and the result.
pub async fn update_now(State(app): S, c: Caller) -> ApiResult {
    c.require(Role::Admin)?;
    if app.geo.status()["updating"] == json!(true) {
        return Err(ApiError(StatusCode::CONFLICT, "a download is already running".into()));
    }
    let geo = Arc::clone(&app.geo);
    let app2 = Arc::clone(&app);
    let who = c.user.name.clone();
    let role = c.user.role.as_str();
    let ip = c.ip.to_string();
    tokio::spawn(async move {
        let client = reqwest::Client::builder().user_agent("openshield-geo-update").build();
        let result = match client {
            Ok(cl) => geo.download_dbip(&cl).await,
            Err(e) => Err(e.to_string()),
        };
        let (detail, outcome) = match &result {
            Ok(m) => (json!({"result": m}), "ok"),
            Err(e) => (json!({"error": e}), "failed"),
        };
        if let Err(e) = app2.hub.store.audit(&who, role, "geo_update", "dbip-lite", &detail, outcome, &ip) {
            log::error!("admin audit write failed: {e}");
        }
    });
    Ok((StatusCode::ACCEPTED, Json(json!({"status": "started"}))).into_response())
}
