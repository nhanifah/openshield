//! Passkey endpoints: register and remove passkeys (signed in), sign in
//! with one (not signed in), and set the domain passkeys are bound to.
//!
//! Each ceremony uses a one-time challenge held in memory for five minutes.
//! A sign-in issues a session token (see `auth::Authenticator`); failed
//! attempts count toward the same per-address lockout as bad tokens.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::auth::{SESSION_TTL, SETUP_USER, UserSource};
use super::{ApiError, ApiResult, App, Caller, audit, ok};
use crate::config::Role;
use crate::store::{Passkey, now_ms};
use crate::webauthn::{self, RelyingParty, b64url, from_b64url};

type S = State<Arc<App>>;

const CHALLENGE_TTL: Duration = Duration::from_secs(300);
const MAX_PENDING: usize = 10_000;
const MAX_PASSKEYS_PER_USER: usize = 20;
const SETTING_KEY: &str = "passkeys";

#[derive(Default)]
pub struct PasskeyState {
    pending: Mutex<HashMap<String, Pending>>,
}

struct Pending {
    /// `Some(user)` for registration, `None` for sign-in.
    user: Option<String>,
    expires: Instant,
}

impl PasskeyState {
    fn start(&self, user: Option<String>) -> Result<String, ApiError> {
        let mut p = self.pending.lock();
        p.retain(|_, v| v.expires > Instant::now());
        if p.len() >= MAX_PENDING {
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "too many passkey requests in progress; try again shortly".into()));
        }
        let ch = webauthn::new_challenge();
        p.insert(
            ch.clone(),
            Pending {
                user,
                expires: Instant::now() + CHALLENGE_TTL,
            },
        );
        Ok(ch)
    }

    /// Take (and so use up) the challenge in `client_data`, if it belongs to
    /// the expected ceremony.
    fn take(&self, client_data: &[u8], user: Option<&str>) -> Result<String, String> {
        let ch = webauthn::client_data_challenge(client_data)?;
        let p = self.pending.lock().remove(&ch).ok_or("unknown or already used challenge; start again")?;
        if p.expires <= Instant::now() {
            return Err("the request took too long; start again".into());
        }
        if p.user.as_deref() != user {
            return Err("challenge belongs to another request".into());
        }
        Ok(ch)
    }
}

/// The caller's address without requiring a token.
pub struct ClientIp(IpAddr);

impl FromRequestParts<Arc<App>> for ClientIp {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, _: &Arc<App>) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0.ip())
                .unwrap_or(IpAddr::from([0, 0, 0, 0])),
        ))
    }
}

// ---- relying party (where passkeys work) ------------------------------------

#[derive(Serialize, Deserialize)]
pub struct RpSetting {
    pub rp_id: String,
    pub origins: Vec<String>,
}

/// The configured relying party, or the default: `localhost` with the
/// dashboard's port. Passkeys cannot be bound to an IP address, so a
/// dashboard opened at 127.0.0.1 must be opened at localhost instead.
fn relying_party(app: &App) -> Result<(RelyingParty, bool), ApiError> {
    if let Some((v, _)) = app.hub.store.setting(SETTING_KEY).map_err(ApiError::internal)?
        && let Ok(s) = serde_json::from_str::<RpSetting>(&v)
    {
        return Ok((RelyingParty { id: s.rp_id, origins: s.origins }, true));
    }
    let port = app.cfg.listen.rsplit_once(':').map(|(_, p)| p).unwrap_or("9091");
    Ok((
        RelyingParty {
            id: "localhost".into(),
            origins: vec![format!("http://localhost:{port}")],
        },
        false,
    ))
}

fn user_handle(name: &str) -> String {
    b64url(&Sha256::digest(format!("openshield-user:{name}").as_bytes())[..16])
}

fn decode(field: &str, v: &str) -> Result<Vec<u8>, ApiError> {
    if v.len() > 64 * 1024 {
        return Err(ApiError::bad(format!("{field} is too large")));
    }
    from_b64url(v).map_err(|e| ApiError::bad(format!("{field}: {e}")))
}

// ---- signed in: list, register, remove ----------------------------------------

#[derive(Deserialize)]
pub struct ListQ {
    all: Option<bool>,
}

pub async fn list(State(app): S, c: Caller, Query(q): Query<ListQ>) -> ApiResult {
    let all = q.all.unwrap_or(false);
    if all {
        c.require(Role::Admin)?;
    }
    let (rp, custom) = relying_party(&app)?;
    let keys = app
        .hub
        .store
        .passkeys(if all { None } else { Some(&c.user.name) })
        .map_err(ApiError::internal)?;
    ok(json!({
        "passkeys": keys,
        "rp_id": rp.id,
        "origins": rp.origins,
        "custom": custom,
        "can_register": c.user.source != UserSource::Setup,
    }))
}

pub async fn register_options(State(app): S, c: Caller) -> ApiResult {
    if c.user.source == UserSource::Setup || c.user.name == SETUP_USER {
        return Err(ApiError::bad(
            "the setup account is temporary; create your own user, sign in with it, then add a passkey",
        ));
    }
    let (rp, _) = relying_party(&app)?;
    let existing = app.hub.store.passkeys(Some(&c.user.name)).map_err(ApiError::internal)?;
    if existing.len() >= MAX_PASSKEYS_PER_USER {
        return Err(ApiError::bad(format!("at most {MAX_PASSKEYS_PER_USER} passkeys per user")));
    }
    let challenge = app.passkeys.start(Some(c.user.name.clone()))?;
    let exclude: Vec<Value> = existing
        .iter()
        .filter(|p| p.rp_id == rp.id)
        .map(|p| {
            json!({"type": "public-key", "id": p.id,
                   "transports": p.transports.split(',').filter(|t| !t.is_empty()).collect::<Vec<_>>()})
        })
        .collect();
    ok(json!({
        "challenge": challenge,
        "rp": {"id": rp.id, "name": "OpenShield"},
        "user": {"id": user_handle(&c.user.name), "name": c.user.name, "displayName": c.user.name},
        "pubKeyCredParams": webauthn::ALGORITHMS.iter().map(|a| json!({"type": "public-key", "alg": a})).collect::<Vec<_>>(),
        "excludeCredentials": exclude,
        "authenticatorSelection": {"residentKey": "required", "requireResidentKey": true, "userVerification": "required"},
        "attestation": "none",
        "timeout": 120_000,
    }))
}

#[derive(Deserialize)]
pub struct RegisterBody {
    client_data_json: String,
    attestation_object: String,
    #[serde(default)]
    transports: Vec<String>,
    #[serde(default)]
    label: String,
}

pub async fn register(State(app): S, c: Caller, Json(b): Json<RegisterBody>) -> ApiResult {
    let cd = decode("client_data_json", &b.client_data_json)?;
    let att = decode("attestation_object", &b.attestation_object)?;
    let (rp, _) = relying_party(&app)?;
    let fail = |msg: String| {
        audit(&app, &c, "passkey_add", &c.user.name, json!({"error": msg}), "rejected");
        ApiError::bad(msg)
    };
    let challenge = app.passkeys.take(&cd, Some(&c.user.name)).map_err(fail)?;
    let cred = webauthn::verify_registration(&rp, &challenge, &cd, &att).map_err(fail)?;
    let label: String = b.label.trim().chars().filter(|c| !c.is_control()).take(60).collect();
    let transports: Vec<&str> = b
        .transports
        .iter()
        .map(String::as_str)
        .filter(|t| matches!(*t, "usb" | "nfc" | "ble" | "internal" | "hybrid" | "smart-card"))
        .collect();
    let p = Passkey {
        id: b64url(&cred.id),
        user: c.user.name.clone(),
        label: if label.is_empty() { "Passkey".into() } else { label },
        rp_id: rp.id.clone(),
        alg: cred.alg,
        public_key: cred.public_key,
        sign_count: cred.sign_count,
        transports: transports.join(","),
        created_ts: now_ms(),
        last_used_ts: None,
    };
    if !app.hub.store.add_passkey(&p).map_err(ApiError::internal)? {
        return Err(ApiError(StatusCode::CONFLICT, "this passkey is already registered".into()));
    }
    audit(&app, &c, "passkey_add", &c.user.name, json!({"passkey": p.id, "label": p.label, "alg": p.alg}), "ok");
    ok(json!({"status": "added", "passkey": p}))
}

pub async fn remove(State(app): S, c: Caller, Path(id): Path<String>) -> ApiResult {
    let p = app.hub.store.passkey(&id).map_err(ApiError::internal)?.ok_or_else(ApiError::not_found)?;
    if p.user != c.user.name {
        c.require(Role::Admin)?;
    }
    app.hub.store.delete_passkey(&id).map_err(ApiError::internal)?;
    audit(&app, &c, "passkey_remove", &p.user, json!({"passkey": p.id, "label": p.label}), "ok");
    ok(json!({"status": "removed"}))
}

// ---- domain settings (admin) ------------------------------------------------------

pub async fn put_settings(State(app): S, c: Caller, Json(b): Json<RpSetting>) -> ApiResult {
    c.require(Role::Admin)?;
    let rp = RelyingParty {
        id: b.rp_id.trim().to_ascii_lowercase(),
        origins: b.origins.iter().map(|o| o.trim().trim_end_matches('/').to_ascii_lowercase()).filter(|o| !o.is_empty()).collect(),
    };
    webauthn::validate_rp(&rp).map_err(ApiError::bad)?;
    let v = serde_json::to_string(&RpSetting { rp_id: rp.id.clone(), origins: rp.origins.clone() }).map_err(ApiError::internal)?;
    app.hub.store.put_setting(SETTING_KEY, &v, false, &c.user.name).map_err(ApiError::internal)?;
    audit(&app, &c, "settings_passkeys", &rp.id, json!({"origins": rp.origins}), "ok");
    ok(json!({"status": "saved", "rp_id": rp.id, "origins": rp.origins}))
}

pub async fn reset_settings(State(app): S, c: Caller) -> ApiResult {
    c.require(Role::Admin)?;
    app.hub.store.delete_setting(SETTING_KEY).map_err(ApiError::internal)?;
    audit(&app, &c, "settings_passkeys", "default", json!({}), "ok");
    let (rp, _) = relying_party(&app)?;
    ok(json!({"status": "reset", "rp_id": rp.id, "origins": rp.origins}))
}

// ---- signed out: sign in ----------------------------------------------------------

pub async fn signin_options(State(app): S, ClientIp(ip): ClientIp) -> ApiResult {
    if app.auth.locked_out(ip) {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "too many failed attempts".into()));
    }
    let (rp, _) = relying_party(&app)?;
    let challenge = app.passkeys.start(None)?;
    ok(json!({
        "challenge": challenge,
        "rpId": rp.id,
        "origins": rp.origins,
        "userVerification": "required",
        "timeout": 120_000,
    }))
}

#[derive(Deserialize)]
pub struct SignInBody {
    id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
}

pub async fn signin(State(app): S, ClientIp(ip): ClientIp, Json(b): Json<SignInBody>) -> ApiResult {
    if app.auth.locked_out(ip) {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "too many failed attempts".into()));
    }
    let cd = decode("client_data_json", &b.client_data_json)?;
    let ad = decode("authenticator_data", &b.authenticator_data)?;
    let sig = decode("signature", &b.signature)?;
    let (rp, _) = relying_party(&app)?;
    let stored = if b.id.len() <= 2048 { app.hub.store.passkey(&b.id).map_err(ApiError::internal)? } else { None };
    let who = stored.as_ref().map(|p| p.user.clone()).unwrap_or_else(|| "-".into());

    let result = (|| -> Result<(Passkey, Role, u32), String> {
        let challenge = app.passkeys.take(&cd, None)?;
        let p = stored.ok_or("this passkey is not registered here (it may have been removed)")?;
        if p.rp_id != rp.id {
            return Err(format!("this passkey was made for {}, but passkeys now use {}", p.rp_id, rp.id));
        }
        let (role, _) = app.auth.role_of(&p.user).ok_or("the user of this passkey no longer exists")?;
        let count = webauthn::verify_assertion(&rp, &challenge, p.alg, &p.public_key, p.sign_count, &cd, &ad, &sig)?;
        Ok((p, role, count))
    })();

    match result {
        Ok((p, role, count)) => {
            app.hub.store.touch_passkey(&p.id, count).map_err(ApiError::internal)?;
            let token = app.auth.issue_session(&p.user);
            if let Err(e) = app.hub.store.audit(&p.user, role.as_str(), "passkey_signin", &p.user,
                &json!({"passkey": p.id, "label": p.label}), "ok", &ip.to_string()) {
                log::error!("admin audit write failed: {e}");
            }
            log::info!("admin: {} signed in with passkey {}", p.user, p.label);
            ok(json!({"token": token, "expires_in_s": SESSION_TTL.as_secs(), "user": p.user, "role": role}))
        }
        Err(msg) => {
            app.auth.record_failure(ip);
            if let Err(e) = app.hub.store.audit(&who, "-", "passkey_signin", &who, &json!({"error": msg}), "rejected", &ip.to_string()) {
                log::error!("admin audit write failed: {e}");
            }
            log::warn!("admin: passkey sign-in from {ip} rejected: {msg}");
            Err(ApiError(StatusCode::UNAUTHORIZED, msg))
        }
    }
}

/// End a passkey session. Token sign-ins have nothing to end server-side.
pub async fn logout(State(app): S, c: Caller, headers: HeaderMap) -> ApiResult {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");
    let ended = app.auth.revoke_session(token);
    if ended {
        audit(&app, &c, "signout", &c.user.name, json!({}), "ok");
    }
    ok(json!({"status": if ended { "session ended" } else { "nothing to end" }}))
}
