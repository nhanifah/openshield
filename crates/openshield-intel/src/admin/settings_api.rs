//! Settings and user management endpoints (admin only).
//!
//! Secrets are write-only: requests may set or clear them, responses only
//! say whether one is set, by whom and when. Every change is audited.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

use super::auth::{SETUP_USER, UserSource, new_token, parse_role, token_digest_hex};
use super::{ApiError, ApiResult, App, Caller, audit, ok};
use crate::ai::gemini::GeminiClient;
use crate::config::{AutoBlockConfig, Role};
use crate::settings::{AiSettings, StorageSettings};

type S = State<Arc<App>>;

fn admin(c: &Caller) -> Result<(), ApiError> {
    if c.user.can(Role::Admin) {
        Ok(())
    } else {
        Err(ApiError::forbidden("requires role admin"))
    }
}

// ---- overview -----------------------------------------------------------------

pub async fn get_settings(State(app): S, c: Caller) -> ApiResult {
    admin(&c)?;
    let mut v = app.hub.settings.describe();
    v["ai"]["running"] = json!(app.hub.ai().is_some());
    v["ai"]["off_reason"] = json!(if app.hub.ai().is_some() { None } else { Some(app.hub.ai_off_reason()) });
    v["challenge"] = challenge_view(&app);
    v["security"] = json!({
        "secret_key_source": app.vault_source,
        "encryption": "AES-256-GCM",
        "setup_mode": app.auth.in_setup(),
    });
    ok(v)
}

// ---- AI -----------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiBody {
    #[serde(flatten)]
    settings: AiSettings,
    /// Absent: keep the stored key. Empty string: remove it.
    #[serde(default)]
    api_key: Option<String>,
}

pub async fn put_ai(State(app): S, c: Caller, Json(b): Json<AiBody>) -> ApiResult {
    admin(&c)?;
    let s = &app.hub.settings;
    let key_change = b.api_key.as_deref().map(str::trim).map(str::to_string);
    if let Some(k) = &key_change {
        s.set_ai_key(k, &c.user.name).map_err(ApiError::bad)?;
    }
    s.save_ai(&b.settings, &c.user.name).map_err(ApiError::bad)?;
    let applied = app.hub.reconfigure_ai();
    let key_note = match key_change.as_deref() {
        None => "unchanged",
        Some("") => "removed",
        Some(_) => "replaced",
    };
    audit(
        &app,
        &c,
        "settings_ai",
        "ai",
        json!({"enabled": b.settings.enabled, "model": b.settings.model, "base_url": b.settings.base_url,
               "requests_per_minute": b.settings.requests_per_minute, "max_calls_per_day": b.settings.max_calls_per_day,
               "send_body": b.settings.send_body, "api_key": key_note}),
        if applied.is_ok() { "applied" } else { "saved, AI off" },
    );
    ok(json!({"status": "saved", "running": app.hub.ai().is_some(), "warning": applied.err()}))
}

pub async fn reset_ai(State(app): S, c: Caller) -> ApiResult {
    admin(&c)?;
    app.hub.settings.reset_ai().map_err(ApiError::internal)?;
    let applied = app.hub.reconfigure_ai();
    audit(&app, &c, "settings_ai_reset", "ai", json!({}), "reset to config file");
    ok(json!({"status": "reset", "running": app.hub.ai().is_some(), "warning": applied.err()}))
}

/// One tiny call with the saved settings and key, to check the key, model
/// and network path. Costs a few tokens.
pub async fn test_ai(State(app): S, c: Caller) -> ApiResult {
    admin(&c)?;
    let cfg = app.hub.settings.ai.load_full();
    if cfg.model.trim().is_empty() {
        return Err(ApiError::bad("set a model first"));
    }
    let Some((key, _)) = app.hub.settings.ai_key() else {
        return Err(ApiError::bad("no API key is set"));
    };
    let client = GeminiClient::new(&cfg.base_url, &cfg.model, key, Duration::from_millis(cfg.timeout_ms.min(15_000)))
        .map_err(ApiError::bad)?;
    let start = Instant::now();
    let res = client
        .complete("Reply with the single word OK.", "Connection test from the OpenShield dashboard.", 8)
        .await;
    let ms = start.elapsed().as_millis() as u64;
    match res {
        Ok(comp) => {
            audit(&app, &c, "settings_ai_test", "ai", json!({"model": cfg.model}), "ok");
            ok(json!({"ok": true, "latency_ms": ms, "model_version": comp.model_version,
                      "reply": crate::ai::sanitize::truncate(comp.text.trim(), 40)}))
        }
        Err(e) => {
            audit(&app, &c, "settings_ai_test", "ai", json!({"model": cfg.model, "error": e.to_string()}), "failed");
            ok(json!({"ok": false, "latency_ms": ms, "error": e.to_string()}))
        }
    }
}

// ---- storage ------------------------------------------------------------------

pub async fn put_storage(State(app): S, c: Caller, Json(b): Json<StorageSettings>) -> ApiResult {
    admin(&c)?;
    app.hub.settings.save_storage(&b, &c.user.name).map_err(ApiError::bad)?;
    audit(&app, &c, "settings_storage", "storage", serde_json::to_value(&b).unwrap_or(Value::Null), "applied");
    ok(json!({"status": "saved"}))
}

pub async fn reset_storage(State(app): S, c: Caller) -> ApiResult {
    admin(&c)?;
    app.hub.settings.reset_storage().map_err(ApiError::internal)?;
    audit(&app, &c, "settings_storage_reset", "storage", json!({}), "reset to config file");
    ok(json!({"status": "reset"}))
}

// ---- auto-block -----------------------------------------------------------------

pub async fn put_auto_block(State(app): S, c: Caller, Json(b): Json<AutoBlockConfig>) -> ApiResult {
    admin(&c)?;
    app.hub.settings.save_auto_block(&b, &c.user.name).map_err(ApiError::bad)?;
    audit(&app, &c, "settings_auto_block", "auto_block", serde_json::to_value(&b).unwrap_or(Value::Null), "applied");
    ok(json!({"status": "saved"}))
}

pub async fn reset_auto_block(State(app): S, c: Caller) -> ApiResult {
    admin(&c)?;
    app.hub.settings.reset_auto_block().map_err(ApiError::internal)?;
    audit(&app, &c, "settings_auto_block_reset", "auto_block", json!({}), "reset to config file");
    ok(json!({"status": "reset"}))
}

// ---- challenge (Turnstile) -----------------------------------------------------

fn challenge_view(app: &App) -> Value {
    let yaml = app.policy.current_yaml();
    let v: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap_or(serde_yaml::Value::Null);
    let ch = v.get("challenge");
    let s = |k: &str| ch.and_then(|c| c.get(k)).and_then(|x| x.as_str()).map(str::to_string);
    let n = |k: &str| ch.and_then(|c| c.get(k)).and_then(|x| x.as_u64());
    json!({
        "enabled": ch.is_some(),
        "site_key": s("turnstile_site_key"),
        "secret_key_set": s("turnstile_secret_key").is_some_and(|x| !x.is_empty()),
        "cookie_secret_set": s("cookie_secret").is_some_and(|x| !x.is_empty()),
        "challenge_path": s("challenge_path").unwrap_or_else(|| "/__openshield/challenge".into()),
        "cookie_ttl": n("cookie_ttl").unwrap_or(3600),
        "policy_version": app.policy.version(),
        "note": "Saved as a new policy version; secrets are stored encrypted.",
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeBody {
    enabled: bool,
    #[serde(default)]
    site_key: String,
    /// Absent or empty: keep the current secret.
    #[serde(default)]
    secret_key: Option<String>,
    #[serde(default)]
    challenge_path: Option<String>,
    #[serde(default)]
    cookie_ttl: Option<u64>,
    /// Issue a new cookie signing key (signs out every verified visitor).
    #[serde(default)]
    rotate_cookie_secret: bool,
}

pub async fn put_challenge(State(app): S, c: Caller, Json(b): Json<ChallengeBody>) -> ApiResult {
    admin(&c)?;
    let current = app.policy.current_yaml();
    let mut doc: serde_yaml::Value = serde_yaml::from_str(&current).map_err(ApiError::internal)?;
    if doc.is_null() {
        doc = serde_yaml::Value::Mapping(Default::default());
    }
    let map = doc.as_mapping_mut().ok_or_else(|| ApiError::internal("policy is not a mapping"))?;
    let key = serde_yaml::Value::String("challenge".into());
    if b.enabled {
        let site = b.site_key.trim();
        if site.is_empty() || site.len() > 200 || site.chars().any(|ch| ch.is_whitespace()) {
            return Err(ApiError::bad("a site key without spaces is required"));
        }
        let old = map.get(&key).cloned().unwrap_or(serde_yaml::Value::Mapping(Default::default()));
        let old_s = |k: &str| old.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let secret = match b.secret_key.as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => {
                if s.len() > 200 || s.chars().any(|ch| ch.is_whitespace()) {
                    return Err(ApiError::bad("the secret key must not contain spaces"));
                }
                s.to_string()
            }
            _ => old_s("turnstile_secret_key").filter(|x| !x.is_empty()).ok_or_else(|| ApiError::bad("the secret key is required"))?,
        };
        let cookie_secret = match old_s("cookie_secret").filter(|x| !x.is_empty()) {
            Some(cs) if !b.rotate_cookie_secret => cs,
            _ => new_token(),
        };
        let path = b.challenge_path.clone().or_else(|| old_s("challenge_path")).unwrap_or_else(|| "/__openshield/challenge".into());
        if !path.starts_with('/') || path.len() > 200 || path.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
            return Err(ApiError::bad("challenge path must start with / and contain no spaces"));
        }
        let ttl = b.cookie_ttl.or_else(|| old.get("cookie_ttl").and_then(|x| x.as_u64())).unwrap_or(3600);
        if !(60..=30 * 86_400).contains(&ttl) {
            return Err(ApiError::bad("cookie lifetime must be between 60 seconds and 30 days"));
        }
        let mut m = old.as_mapping().cloned().unwrap_or_default();
        let set = |m: &mut serde_yaml::Mapping, k: &str, v: serde_yaml::Value| {
            m.insert(serde_yaml::Value::String(k.into()), v);
        };
        set(&mut m, "turnstile_site_key", site.into());
        set(&mut m, "turnstile_secret_key", secret.into());
        set(&mut m, "cookie_secret", cookie_secret.into());
        set(&mut m, "challenge_path", path.into());
        set(&mut m, "cookie_ttl", ttl.into());
        map.insert(key, serde_yaml::Value::Mapping(m));
    } else {
        map.remove(&key);
    }
    let yaml = serde_yaml::to_string(&doc).map_err(ApiError::internal)?;
    let check = yaml.clone();
    tokio::task::spawn_blocking(move || crate::policy::compile(&check).map(|_| ()))
        .await
        .map_err(ApiError::internal)?
        .map_err(|e| ApiError::bad(format!("the policy would not compile: {e}")))?;
    let comment = if b.enabled { "Settings: Turnstile challenge updated" } else { "Settings: Turnstile challenge removed" };
    let detail = json!({"enabled": b.enabled, "site_key": b.site_key.trim(),
                        "secret_key": if b.secret_key.as_deref().is_some_and(|s| !s.trim().is_empty()) { "replaced" } else { "unchanged" },
                        "cookie_secret_rotated": b.rotate_cookie_secret});
    if app.cfg.require_second_approver {
        let id = app
            .hub
            .store
            .add_change("policy_apply", comment, &json!({"yaml": yaml, "comment": comment}), &c.user.name)
            .map_err(ApiError::internal)?;
        audit(&app, &c, "settings_challenge", "challenge", detail, "pending approval");
        return ok(json!({"status": "pending", "change_id": id}));
    }
    let v = app.policy.apply(&yaml, &c.user.name, comment, Some(&app.hub.store)).map_err(ApiError::bad)?;
    audit(&app, &c, "settings_challenge", "challenge", detail, "applied");
    ok(json!({"status": "applied", "version": v}))
}

// ---- users -----------------------------------------------------------------

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) && n != SETUP_USER
}

pub async fn list_users(State(app): S, c: Caller) -> ApiResult {
    admin(&c)?;
    let mut out = Vec::new();
    for (name, role) in app.auth.config_users() {
        out.push(json!({"name": name, "role": role, "source": UserSource::ConfigFile, "editable": false}));
    }
    for u in app.hub.store.users().map_err(ApiError::internal)? {
        out.push(json!({"name": u.name, "role": u.role, "source": UserSource::Dashboard, "editable": true,
                        "created_ts": u.created_ts, "created_by": u.created_by, "rotated_ts": u.rotated_ts}));
    }
    ok(json!({"users": out, "setup_mode": app.auth.in_setup(), "me": c.user.name}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUser {
    name: String,
    role: String,
}

pub async fn create_user(State(app): S, c: Caller, Json(b): Json<NewUser>) -> ApiResult {
    admin(&c)?;
    let name = b.name.trim();
    if !valid_name(name) {
        return Err(ApiError::bad("name: 1-64 letters, digits, '.', '_' or '-'"));
    }
    let role = parse_role(&b.role).ok_or_else(|| ApiError::bad("role must be viewer, analyst, operator or admin"))?;
    if app.auth.is_config_user(name) {
        return Err(ApiError::bad("a user with this name is defined in the config file"));
    }
    let token = new_token();
    if !app.hub.store.add_user(name, role.as_str(), &token_digest_hex(&token), &c.user.name).map_err(ApiError::internal)? {
        return Err(ApiError(StatusCode::CONFLICT, "a user with this name already exists".into()));
    }
    app.auth.reload().map_err(ApiError::internal)?;
    audit(&app, &c, "user_create", name, json!({"role": role}), "ok");
    ok(json!({"name": name, "role": role, "token": token,
              "note": "Copy this token now. It is not stored and cannot be shown again."}))
}

pub async fn rotate_user(State(app): S, c: Caller, Path(name): Path<String>) -> ApiResult {
    admin(&c)?;
    let token = new_token();
    if !app.hub.store.set_user_token(&name, &token_digest_hex(&token)).map_err(ApiError::internal)? {
        return Err(ApiError::not_found());
    }
    app.auth.reload().map_err(ApiError::internal)?;
    audit(&app, &c, "user_rotate_token", &name, json!({}), "ok");
    ok(json!({"name": name, "token": token, "note": "The old token stopped working. Copy the new one now."}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleBody {
    role: String,
}

fn would_remove_last_admin(app: &App, name: &str) -> Result<bool, ApiError> {
    let users = app.hub.store.users().map_err(ApiError::internal)?;
    let target_is_admin = users.iter().any(|u| u.name == name && u.role == "admin");
    Ok(target_is_admin && app.auth.admin_count() <= 1)
}

pub async fn set_role(State(app): S, c: Caller, Path(name): Path<String>, Json(b): Json<RoleBody>) -> ApiResult {
    admin(&c)?;
    let role = parse_role(&b.role).ok_or_else(|| ApiError::bad("role must be viewer, analyst, operator or admin"))?;
    if name == c.user.name {
        return Err(ApiError::bad("you cannot change your own role"));
    }
    if role != Role::Admin && would_remove_last_admin(&app, &name)? {
        return Err(ApiError::bad("this is the last admin; create another admin first"));
    }
    if !app.hub.store.set_user_role(&name, role.as_str()).map_err(ApiError::internal)? {
        return Err(ApiError::not_found());
    }
    app.auth.reload().map_err(ApiError::internal)?;
    audit(&app, &c, "user_role", &name, json!({"role": role}), "ok");
    ok(json!({"name": name, "role": role}))
}

pub async fn delete_user(State(app): S, c: Caller, Path(name): Path<String>) -> ApiResult {
    admin(&c)?;
    if name == c.user.name {
        return Err(ApiError::bad("you cannot revoke your own access"));
    }
    if would_remove_last_admin(&app, &name)? {
        return Err(ApiError::bad("this is the last admin; create another admin first"));
    }
    if !app.hub.store.delete_user(&name).map_err(ApiError::internal)? {
        return Err(ApiError::not_found());
    }
    app.auth.reload().map_err(ApiError::internal)?;
    let keys = app.hub.store.delete_user_passkeys(&name).map_err(ApiError::internal)?;
    let sessions = app.auth.revoke_user_sessions(&name);
    audit(&app, &c, "user_revoke", &name, json!({"passkeys_removed": keys, "sessions_ended": sessions}), "ok");
    ok(json!({"status": "revoked"}))
}
