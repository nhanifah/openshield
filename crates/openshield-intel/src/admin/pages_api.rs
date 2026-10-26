//! Error pages: what visitors see when a request is blocked, rate limited,
//! too large, or the site behind the proxy is down.
//!
//! The settings live in the WAF policy (`error_pages`), so a change is a
//! policy version: audited, reversible, approved by a second admin when that
//! is on. Previews are rendered on the server and shown through a one-time
//! URL, because the dashboard's own CSP would strip a page's inline styles.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use openshield_core::error_page::{ErrorPagesConfig, PLACEHOLDERS, PageContext, PageKind};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ApiError, ApiResult, App, Caller, audit, ok};
use crate::config::Role;

type S = State<Arc<App>>;

/// Header a handler sets to keep its own CSP (removed before sending).
pub const PREVIEW_MARKER: &str = "x-openshield-preview";
const PREVIEW_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; \
                           base-uri 'none'; form-action 'none'; frame-ancestors 'self'";
const PREVIEW_TTL: Duration = Duration::from_secs(120);

#[derive(Default)]
pub struct Previews(Mutex<HashMap<String, (String, Instant)>>);

pub fn current(app: &App) -> ErrorPagesConfig {
    app.policy.current().error_pages().clone()
}

pub async fn get_pages(State(app): S, c: Caller) -> ApiResult {
    // Default texts in each language, so the form can show them as hints.
    let defaults: Value = ["en", "id"]
        .iter()
        .map(|lang| {
            let cfg: ErrorPagesConfig = serde_json::from_value(json!({"language": lang})).unwrap_or_default();
            let kinds: serde_json::Map<String, Value> = PageKind::ALL
                .iter()
                .map(|k| {
                    let r = cfg.render(
                        &PageContext { status: 403, kind: *k, request_id: "", client_ip: None, now: 0 },
                        Some("application/json"),
                    );
                    let v: Value = serde_json::from_str(&r.body).unwrap_or(Value::Null);
                    (k.as_str().to_string(), json!({"title": v["error"], "message": v["message"]}))
                })
                .collect();
            (lang.to_string(), Value::Object(kinds))
        })
        .collect::<serde_json::Map<_, _>>()
        .into();
    ok(json!({
        "config": current(&app),
        "defaults": defaults,
        "kinds": PageKind::ALL.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
        "placeholders": PLACEHOLDERS,
        "policy_version": app.policy.version(),
        "can_edit": c.user.can(Role::Admin),
    }))
}

fn clean(mut cfg: ErrorPagesConfig) -> Result<ErrorPagesConfig, ApiError> {
    let trim = |o: &mut Option<String>| {
        if let Some(s) = o {
            *s = s.trim().to_string();
        }
        if o.as_deref().is_some_and(str::is_empty) {
            *o = None;
        }
    };
    trim(&mut cfg.site_name);
    trim(&mut cfg.support_email);
    trim(&mut cfg.support_url);
    trim(&mut cfg.accent_color);
    if let Some(c) = &mut cfg.accent_color {
        *c = c.to_ascii_lowercase();
    }
    for p in cfg.pages.values_mut() {
        trim(&mut p.title);
        trim(&mut p.message);
        if p.html.as_deref().is_some_and(|h| h.trim().is_empty()) {
            p.html = None;
        }
    }
    cfg.pages.retain(|_, p| p.title.is_some() || p.message.is_some() || p.html.is_some());
    cfg.validate().map_err(ApiError::bad)?;
    Ok(cfg)
}

pub async fn put_pages(State(app): S, c: Caller, Json(cfg): Json<ErrorPagesConfig>) -> ApiResult {
    c.require(Role::Admin)?;
    let cfg = clean(cfg)?;
    if cfg == current(&app) {
        return ok(json!({"status": "unchanged", "version": app.policy.version()}));
    }
    let mut doc: serde_yaml::Value = serde_yaml::from_str(&app.policy.current_yaml()).map_err(ApiError::internal)?;
    if !doc.is_mapping() {
        doc = serde_yaml::Value::Mapping(Default::default());
    }
    let map = doc.as_mapping_mut().expect("mapping");
    let key = serde_yaml::Value::String("error_pages".into());
    if cfg == ErrorPagesConfig::default() {
        map.remove(&key);
    } else {
        map.insert(key, serde_yaml::to_value(&cfg).map_err(ApiError::internal)?);
    }
    let yaml = serde_yaml::to_string(&doc).map_err(ApiError::internal)?;
    let check = yaml.clone();
    tokio::task::spawn_blocking(move || crate::policy::compile(&check).map(|_| ()))
        .await
        .map_err(ApiError::internal)?
        .map_err(|e| ApiError::bad(format!("the policy would not compile: {e}")))?;
    let detail = json!({"language": cfg.language, "site_name": cfg.site_name, "custom": cfg.pages.keys().map(|k| k.as_str()).collect::<Vec<_>>()});
    let comment = "Error pages updated";
    if app.cfg.require_second_approver {
        let id = app
            .hub
            .store
            .add_change("policy_apply", comment, &json!({"yaml": yaml, "comment": comment}), &c.user.name)
            .map_err(ApiError::internal)?;
        audit(&app, &c, "error_pages", "error_pages", detail, "pending approval");
        return ok(json!({"status": "pending", "change_id": id}));
    }
    let v = app.policy.apply(&yaml, &c.user.name, comment, Some(&app.hub.store)).map_err(ApiError::bad)?;
    audit(&app, &c, "error_pages", "error_pages", detail, "applied");
    ok(json!({"status": "applied", "version": v}))
}

#[derive(Deserialize)]
pub struct PreviewBody {
    config: ErrorPagesConfig,
    kind: PageKind,
}

/// Render a draft and return a one-time URL for an iframe.
pub async fn preview(State(app): S, c: Caller, Json(b): Json<PreviewBody>) -> ApiResult {
    c.require(Role::Admin)?;
    let cfg = clean(b.config)?;
    let status = match b.kind {
        PageKind::Blocked | PageKind::Geo | PageKind::Challenge => 403,
        PageKind::RateLimited => 429,
        PageKind::TooLarge => 413,
        PageKind::BadRequest => 400,
        PageKind::Unavailable => 502,
        PageKind::Error => 500,
    };
    let html = if b.kind == PageKind::Challenge {
        // The widget needs Turnstile's script, which the preview does not
        // load: show a placeholder box where it goes.
        cfg.challenge_html("preview", "/__openshield/challenge")
            .replace(
                r#"<div class="cf-turnstile" data-sitekey="preview" data-callback="onSuccess"></div>"#,
                r#"<div style="width:300px;max-width:100%;height:65px;border:1px dashed #9ca3af;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:13px;color:#6b7280">Turnstile check</div>"#,
            )
    } else {
        cfg.render(
            &PageContext {
                status,
                kind: b.kind,
                request_id: "7f3c1a9e-2b4d-4e8f-9a61-0c5d3e2f1b7a",
                client_ip: Some("203.0.113.42"),
                now: crate::store::now_ms() / 1000,
            },
            Some("text/html"),
        )
        .body
    };
    let mut id_bytes = [0u8; 16];
    aws_lc_rs::rand::fill(&mut id_bytes).expect("system random generator");
    let id = hex::encode(id_bytes);
    let mut p = app.previews.0.lock();
    p.retain(|_, (_, t)| t.elapsed() < PREVIEW_TTL);
    if p.len() >= 200 {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "too many previews; wait a moment".into()));
    }
    p.insert(id.clone(), (html, Instant::now()));
    ok(json!({"url": format!("/preview/{id}")}))
}

/// The rendered draft; no session needed (the id is random and short-lived).
pub async fn show_preview(State(app): S, Path(id): Path<String>) -> Response {
    let html = app
        .previews
        .0
        .lock()
        .get(&id)
        .filter(|(_, t)| t.elapsed() < PREVIEW_TTL)
        .map(|(h, _)| h.clone());
    match html {
        Some(h) => {
            let mut r = (StatusCode::OK, h).into_response();
            let hd = r.headers_mut();
            hd.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
            hd.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(PREVIEW_CSP));
            hd.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("SAMEORIGIN"));
            hd.insert(PREVIEW_MARKER, HeaderValue::from_static("1"));
            r
        }
        None => (StatusCode::NOT_FOUND, "preview expired").into_response(),
    }
}
