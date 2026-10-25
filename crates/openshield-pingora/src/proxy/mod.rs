pub mod context;
pub mod headers;
pub mod metrics;
pub mod trusted;

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use context::RequestCtx;
use metrics::{
    ACTIVE_CONNECTIONS, BYTES_RECEIVED, BYTES_SENT, DECISIONS, REQUEST_DURATION, RULE_MATCHES,
    TOTAL_REQUESTS,
};
use openshield_core::challenge::{ChallengeManager, VerificationForm};
use openshield_core::logging::Logger;
use openshield_core::waf::data::{RequestData, ResponseData};
use openshield_core::{BodyVerdict, Intervention, ResponseOutcome, Verdict, Waf};
use openshield_intel::controls::Controls;
use openshield_intel::hub::{EventHub, RawEvent};
use openshield_intel::policy::PolicyManager;
use pingora::prelude::*;
use openshield_intel::store::now_ms;
use pingora::proxy::{ProxyHttp, Session};
pub use trusted::TrustedProxies;

/// Where each request gets its firewall from.
pub enum WafSource {
    /// Built once at startup.
    Static(Arc<Waf>),
    /// Managed at runtime (policy API, versions, rollback).
    Managed(Arc<PolicyManager>),
}

impl WafSource {
    pub fn current(&self) -> Arc<Waf> {
        match self {
            WafSource::Static(w) => Arc::clone(w),
            WafSource::Managed(p) => p.current(),
        }
    }
}

/// Rule id recorded for requests stopped by a dynamic IP block.
pub const DYNAMIC_BLOCK_RULE: &str = "dynamic:ip_block";

pub struct ReverseProxyHandler {
    pub waf: WafSource,
    /// Security event pipeline, when `intel.enabled`.
    pub intel: Option<Arc<EventHub>>,
    pub controls: Option<Arc<Controls>>,
    pub logger: Arc<Logger>,
    pub upstream_tls: bool,
    pub upstream_host: String,
    pub upstream_port: u16,
    /// Reject requests whose header block is larger than this (431).
    pub max_request_header_bytes: usize,
    pub trusted_proxies: TrustedProxies,
}

/// Header name/value pairs for the WAF.
///
/// Values are decoded lossily rather than with `to_str`: a value holding a
/// byte outside visible ASCII used to become `""` for the rules while the
/// upstream still received the original bytes, which hid any payload after
/// that byte from header rules.
pub(crate) fn header_pairs(headers: &http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Total size of a header block: names, values, and `": "` plus CRLF per line.
pub(crate) fn header_block_size(headers: &http::HeaderMap) -> usize {
    headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len() + 4)
        .sum()
}

fn extract_request_data(session: &Session, trusted: &TrustedProxies) -> RequestData {
    let req = session.req_header();
    let headers = header_pairs(&req.headers);

    let is_tls = session.digest().is_some_and(|d| d.ssl_digest.is_some());
    let host = req
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri.host())
        .unwrap_or("")
        .to_string();
    let path = req.uri.path().to_string();
    let query = req.uri.query().unwrap_or("").to_string();
    let scheme_str = req
        .uri
        .scheme_str()
        .unwrap_or(if is_tls { "https" } else { "http" });
    let full_uri = if query.is_empty() {
        format!("{scheme_str}://{host}{path}")
    } else {
        format!("{scheme_str}://{host}{path}?{query}")
    };
    let uri = if query.is_empty() {
        path.clone()
    } else {
        format!("{path}?{query}")
    };
    let after_slash = path.rsplit_once('/').map(|(_, f)| f).unwrap_or(&path);
    let extension = after_slash
        .rsplit_once('.')
        .map(|(_, ext)| ext)
        .unwrap_or("")
        .to_string();

    RequestData {
        client_ip: trusted.client_ip(client_ip(session), &req.headers),
        is_tls,
        method: req.method.as_str().to_string(),
        version: format!("{:?}", req.version),
        host,
        full_uri,
        uri,
        path,
        query,
        extension,
        headers,
        geo: None,
    }
}

fn extract_response_data(resp: &pingora::http::ResponseHeader) -> ResponseData {
    ResponseData {
        status: resp.status.as_u16(),
        headers: header_pairs(&resp.headers),
    }
}

async fn send_block_response(session: &mut Session, intervention: &Intervention, request_id: &str) {
    let code =
        http::StatusCode::from_u16(intervention.status_code).unwrap_or(http::StatusCode::FORBIDDEN);
    let body = intervention.content.as_deref().unwrap_or("").as_bytes();
    let ct = intervention.content_type.as_deref().unwrap_or("text/plain");

    let mut resp_header = pingora::http::ResponseHeader::build(code, Some(3)).unwrap();
    let _ = resp_header.insert_header("Content-Type", ct);
    let _ = resp_header.insert_header("Content-Length", body.len().to_string());
    let _ = resp_header.insert_header("X-Request-ID", request_id);
    let _ = session
        .write_response_header(Box::new(resp_header), false)
        .await;
    let _ = session
        .write_response_body(Some(bytes::Bytes::copy_from_slice(body)), true)
        .await;
}

async fn send_challenge_page(session: &mut Session, cm: &ChallengeManager, request_id: &str) {
    let body = cm.challenge_page().as_bytes();
    let mut resp =
        pingora::http::ResponseHeader::build(http::StatusCode::FORBIDDEN, Some(3)).unwrap();
    let _ = resp.insert_header("Content-Type", "text/html; charset=utf-8");
    let _ = resp.insert_header("Content-Length", body.len().to_string());
    let _ = resp.insert_header("Cache-Control", "no-store");
    let _ = resp.insert_header("X-Request-ID", request_id);
    let _ = session.write_response_header(Box::new(resp), false).await;
    let _ = session
        .write_response_body(Some(bytes::Bytes::copy_from_slice(body)), true)
        .await;
}

fn client_ip(session: &Session) -> Option<IpAddr> {
    session
        .client_addr()
        .and_then(|a| a.as_inet().map(|s| s.ip()))
}

impl ReverseProxyHandler {
    async fn handle_challenge_verify(
        &self,
        session: &mut Session,
        cm: &ChallengeManager,
        request_id: &str,
    ) -> Result<bool> {
        // Read the POST body to get the Turnstile token
        let mut body_buf = Vec::new();
        loop {
            let body = session.read_request_body().await?;
            match body {
                Some(data) => {
                    body_buf.extend_from_slice(&data);
                    if body_buf.len() > 8192 {
                        break;
                    }
                }
                None => break,
            }
        }

        let form = VerificationForm::parse(&body_buf);
        let client_ip_str = self
            .trusted_proxies
            .client_ip(client_ip(session), &session.req_header().headers)
            .map(|ip| ip.to_string())
            .unwrap_or_default();

        if let Some(token) = form.token.as_deref()
            && cm.verify_turnstile(token, &client_ip_str).await
        {
            // Verification passed: set cookie and redirect
            let cookie = cm.create_cookie(&client_ip_str);
            let host = session
                .req_header()
                .headers
                .get("host")
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                .unwrap_or_default();
            let location = openshield_core::challenge::safe_redirect(form.redirect.as_deref(), &host);
            let mut resp =
                pingora::http::ResponseHeader::build(http::StatusCode::FOUND, Some(3)).unwrap();
            let _ = resp.insert_header("Location", &location);
            let _ = resp.insert_header("Set-Cookie", &cookie);
            let _ = resp.insert_header("Cache-Control", "no-store");
            let _ = session.write_response_header(Box::new(resp), true).await;
            return Ok(true);
        }

        // Verification failed: show the challenge again
        send_challenge_page(session, cm, request_id).await;
        Ok(true)
    }
}

#[async_trait]
impl ProxyHttp for ReverseProxyHandler {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        TOTAL_REQUESTS.inc();
        ACTIVE_CONNECTIONS.inc();
        RequestCtx {
            tx: self.waf.current().transaction(),
            pending_block: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        if header_block_size(&session.req_header().headers) > self.max_request_header_bytes {
            ctx.tx
                .set_request(extract_request_data(session, &self.trusted_proxies));
            let _ = session.respond_error(431).await;
            return Ok(true);
        }
        let req_data = extract_request_data(session, &self.trusted_proxies);
        let request_id = ctx.tx.id().to_string();

        // Dynamic IP blocks (dashboard, auto-block) apply before any rule.
        if let (Some(controls), Some(ip)) = (&self.controls, req_data.client_ip)
            && controls.is_blocked(ip, now_ms())
        {
            ctx.tx.set_request(req_data);
            ctx.tx.record_external(DYNAMIC_BLOCK_RULE, "block");
            let intervention = Intervention {
                status_code: 403,
                content_type: Some("text/plain".into()),
                content: Some("blocked".into()),
            };
            send_block_response(session, &intervention, &request_id).await;
            return Ok(true);
        }

        let waf = ctx.tx.waf_arc();
        // The challenge page posting back for verification.
        if let Some(cm) = waf.challenge()
            && cm.is_verification_request(&req_data.method, &req_data.path)
        {
            ctx.tx.set_request(req_data);
            return self.handle_challenge_verify(session, cm, &request_id).await;
        }

        match ctx.tx.request_headers(req_data) {
            Verdict::Pass | Verdict::Allow => Ok(false),
            Verdict::Block(intervention) => {
                send_block_response(session, &intervention, &request_id).await;
                Ok(true)
            }
            Verdict::Challenge => match waf.challenge() {
                Some(cm) => {
                    send_challenge_page(session, cm, &request_id).await;
                    Ok(true)
                }
                None => Ok(false),
            },
        }
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let data = body.as_deref().unwrap_or(&[]);
        BYTES_RECEIVED.inc_by(data.len() as u64);

        match ctx.tx.request_body_chunk(data, end_of_stream) {
            BodyVerdict::Passthrough => {}
            // An empty chunk (not None) avoids signalling end-of-body to the
            // upstream (`upstream_end_of_body = end || data.is_none()`).
            BodyVerdict::Hold => *body = Some(bytes::Bytes::new()),
            // An empty release with no chunk from pingora (a bodyless request
            // at end of stream) must stay `None`: an empty chunk after the
            // upstream body finished makes pingora warn on every request.
            BodyVerdict::Forward(released) if released.is_empty() && body.is_none() => {}
            BodyVerdict::Forward(released) => *body = Some(bytes::Bytes::from(released)),
            BodyVerdict::Block(intervention) => {
                // Status and content are rendered from pending_block in
                // fail_to_proxy; the error only aborts proxying.
                let code = intervention.status_code;
                ctx.pending_block = Some(intervention);
                return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(code)));
            }
        }
        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> pingora::proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        // A body-phase rule asked to block: render the configured block
        // response.
        if let Some(intervention) = ctx.pending_block.take() {
            let request_id = ctx.tx.id().to_string();
            send_block_response(session, &intervention, &request_id).await;
            return pingora::proxy::FailToProxy {
                error_code: intervention.status_code,
                can_reuse_downstream: false,
            };
        }

        // Otherwise mirror pingora's default error handling.
        let code = match e.etype() {
            pingora::ErrorType::HTTPStatus(code) => *code,
            _ => match e.esource() {
                pingora::ErrorSource::Upstream => 502,
                pingora::ErrorSource::Downstream => match e.etype() {
                    pingora::ErrorType::WriteError
                    | pingora::ErrorType::ReadError
                    | pingora::ErrorType::ConnectionClosed => 0,
                    _ => 400,
                },
                pingora::ErrorSource::Internal | pingora::ErrorSource::Unset => 500,
            },
        };
        if code > 0 {
            let _ = session.respond_error(code).await;
        }
        pingora::proxy::FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = Box::new(HttpPeer::new(
            (&*self.upstream_host, self.upstream_port),
            self.upstream_tls,
            self.upstream_host.clone(),
        ));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        headers::set_upstream_headers(
            session,
            upstream_request,
            &self.upstream_host,
            self.upstream_port,
        );
        // Correlates upstream logs with OpenShield events and audit entries.
        let _ = upstream_request.insert_header("X-Request-ID", ctx.tx.id());
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let _ = upstream_response.insert_header("X-Request-ID", ctx.tx.id());
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Evaluated for its side effects only: by this point the response is
        // being proxied, so a block verdict here is not acted on.
        let _ = ctx
            .tx
            .response_headers(extract_response_data(upstream_response));
        // If a ResponseBody rule might rewrite/suppress the body, drop
        // Content-Length so the (possibly altered) body can be re-framed as
        // chunked.
        if ctx.tx.waf().rewrites_response_body() {
            upstream_response.remove_header(http::header::CONTENT_LENGTH.as_str());
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>> {
        let data = body.as_deref().unwrap_or(&[]);
        match ctx.tx.response_body_chunk(data, end_of_stream) {
            BodyVerdict::Passthrough => BYTES_SENT.inc_by(data.len() as u64),
            BodyVerdict::Hold => *body = Some(bytes::Bytes::new()),
            BodyVerdict::Forward(released) => {
                BYTES_SENT.inc_by(released.len() as u64);
                *body = Some(bytes::Bytes::from(released));
            }
            BodyVerdict::Block(intervention) => {
                // Status and headers were already sent downstream; only the
                // body can change here.
                let content = intervention.content.unwrap_or_default().into_bytes();
                BYTES_SENT.inc_by(content.len() as u64);
                *body = Some(bytes::Bytes::from(content));
            }
        }
        Ok(None)
    }

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let written = session.response_written();
        let status = written.map(|r| r.status.as_u16()).unwrap_or(0);
        let headers = written.map(|r| header_pairs(&r.headers));

        // Read before `finish`, which moves these into the audit entry.
        let action = ctx.tx.action().to_string();
        let keep_body = !ctx.tx.matched_rules().is_empty();
        let detection_only = ctx.tx.waf().settings().detection_only;

        let record = ctx.tx.finish(ResponseOutcome {
            status,
            headers: headers.as_deref(),
            error: error.map(|e| e.to_string()),
        });
        self.logger.access(&record.access);
        if let Some(audit) = &record.audit {
            self.logger.audit(audit);
        }

        let final_action = record
            .audit
            .as_ref()
            .map(|a| a.waf_action.as_str())
            .unwrap_or(action.as_str());
        let final_action = if final_action.is_empty() { "pass" } else { final_action };
        let dynamic = record
            .audit
            .as_ref()
            .is_some_and(|a| a.waf_matched_rules.iter().any(|r| r.id == DYNAMIC_BLOCK_RULE));
        let enforced = !detection_only || dynamic || !matches!(final_action, "block" | "challenge");
        DECISIONS
            .with_label_values(&[final_action, if enforced { "true" } else { "false" }])
            .inc();
        if let Some(audit) = &record.audit {
            for r in &audit.waf_matched_rules {
                RULE_MATCHES.with_label_values(&[&r.id, &r.action]).inc();
            }
        }
        REQUEST_DURATION.observe(record.access.duration_ms / 1000.0);

        if let Some(hub) = &self.intel {
            // Moved out of the finished transaction, not copied.
            let body = if keep_body { ctx.tx.take_request_body() } else { Vec::new() };
            hub.submit(RawEvent {
                waf: ctx.tx.waf_arc(),
                request: ctx.tx.take_request(),
                access: record.access,
                audit: record.audit,
                action,
                body,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_ascii_header_values_reach_the_rules() {
        // Regression: `to_str` failed on obs-text and the value became "".
        let mut h = http::HeaderMap::new();
        h.insert(
            "x-search",
            http::HeaderValue::from_bytes(b"\xe9 1' OR '1'='1").unwrap(),
        );
        let pairs = header_pairs(&h);
        assert_eq!(pairs[0].0, "x-search");
        assert!(pairs[0].1.ends_with("1' OR '1'='1"), "{:?}", pairs[0].1);
    }

    #[test]
    fn header_block_size_counts_names_values_and_separators() {
        let mut h = http::HeaderMap::new();
        h.insert("ab", http::HeaderValue::from_static("cde"));
        assert_eq!(header_block_size(&h), 2 + 3 + 4);
    }
}
