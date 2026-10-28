//! Per-request processing, driven phase by phase by the host server.
//!
//! The host extracts request and response data, calls the matching phase
//! method, and acts on the returned verdict. All WAF state for the request
//! (field values, scores, matched rules, buffered bodies) lives here.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use wirefilter_engine::ExecutionContext;

use crate::config::BodyLimitAction;
use crate::firewall::Waf;
use crate::logging::{AccessLogEntry, AuditLogEntry, AuditRequest, AuditResponse, MatchedRule};
use crate::waf::data::{GeoData, MultipartPartData, RequestData, ResponseData};
use crate::waf::engine::{self, Phase, RuleAction};
use crate::waf::schema::SchemaRequest;
use crate::waf::{lists, populate, scheme};

/// The response a rule asked the host to send in place of the proxied one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intervention {
    pub status_code: u16,
    pub content_type: Option<String>,
    pub content: Option<String>,
}

/// Outcome of a header phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No terminal rule matched. Continue.
    Pass,
    /// An allow rule matched. Continue; later phases still run.
    Allow,
    /// Stop and send this response to the client.
    Block(Intervention),
    /// Serve the challenge page (403, `text/html`, `Cache-Control: no-store`).
    /// Only returned when a challenge is configured and the client has no
    /// valid challenge cookie.
    Challenge,
}

/// What the host should do with a body chunk it just handed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyVerdict {
    /// Forward the chunk as received.
    Passthrough,
    /// Withhold the chunk. Send an empty, non-final chunk so the stream stays
    /// open, and keep feeding data.
    Hold,
    /// Forward these bytes in place of the chunk: held data released after a
    /// verdict.
    Forward(Vec<u8>),
    /// Stop the transfer. For a request, send this response instead of
    /// proxying. For a response, the status and headers are already on the
    /// wire, so only `content` applies: send it as the rest of the body and
    /// discard what the upstream still sends.
    Block(Intervention),
}

/// What was finally sent to the client, for the access and audit logs.
pub struct ResponseOutcome<'a> {
    /// Status sent to the client, or 0 if none was.
    pub status: u16,
    /// Headers of the response sent to the client, if one was.
    pub headers: Option<&'a [(String, String)]>,
    pub error: Option<String>,
}

/// Log entries produced when a transaction finishes.
pub struct LogRecord {
    pub access: AccessLogEntry,
    /// Present only when at least one rule matched with logging enabled.
    pub audit: Option<AuditLogEntry>,
}

/// Buffered body with size tracking and truncation at a limit.
pub struct BodyBuffer {
    pub buf: Vec<u8>,
    pub total_size: usize,
    pub truncated: bool,
    max_size: usize,
}

impl BodyBuffer {
    pub fn new(max_size: usize) -> Self {
        Self {
            buf: Vec::new(),
            total_size: 0,
            truncated: false,
            max_size,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.total_size += data.len();
        if !self.truncated {
            let remaining = self.max_size.saturating_sub(self.buf.len());
            if data.len() <= remaining {
                self.buf.extend_from_slice(data);
            } else {
                self.buf.extend_from_slice(&data[..remaining]);
                self.truncated = true;
            }
        }
    }
}

/// Streaming state for one direction of body inspection.
struct BodyStream {
    buffer: BodyBuffer,
    /// Bytes withheld from the other side pending a verdict.
    pending: Vec<u8>,
    /// The buffer was released and the remainder streams uninspected.
    passthrough: bool,
    /// A block verdict was reached; the remainder is discarded.
    blocked: bool,
}

impl BodyStream {
    fn new(max_size: usize) -> Self {
        Self {
            buffer: BodyBuffer::new(max_size),
            pending: Vec::new(),
            passthrough: false,
            blocked: false,
        }
    }

    fn release(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }
}

pub struct Transaction {
    waf: Arc<Waf>,
    id: String,
    start: Instant,
    ctx: ExecutionContext<'static>,
    request: Option<RequestData>,
    schema_request: Option<SchemaRequest>,
    req: BodyStream,
    res: BodyStream,
    scores: HashMap<String, i64>,
    matched_rules: Vec<(String, String)>, // (rule_id, action)
    payloads: serde_json::Map<String, serde_json::Value>,
    action: String,
}

impl Transaction {
    pub(crate) fn new(waf: Arc<Waf>) -> Self {
        let mut ctx = scheme::new_context(&waf.scheme);
        lists::install(&mut ctx, &waf.scheme, &waf.ip_lists, &waf.bytes_lists);
        let settings = &waf.settings;
        let req = BodyStream::new(settings.max_request_body_buffer);
        let res = BodyStream::new(settings.max_response_body_buffer);
        Self {
            waf,
            id: uuid::Uuid::new_v4().to_string(),
            start: Instant::now(),
            ctx,
            request: None,
            schema_request: None,
            req,
            res,
            scores: HashMap::new(),
            matched_rules: Vec::new(),
            payloads: serde_json::Map::new(),
            action: "pass".into(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn waf(&self) -> &Waf {
        &self.waf
    }

    /// The firewall this transaction runs on (it keeps it alive even if a
    /// new policy is swapped in mid-request).
    pub fn waf_arc(&self) -> Arc<Waf> {
        Arc::clone(&self.waf)
    }

    /// The terminal action taken so far: `pass`, `allow`, `block` or
    /// `challenge`.
    pub fn action(&self) -> &str {
        &self.action
    }

    /// The request as recorded by [`request_headers`] or [`set_request`].
    ///
    /// [`request_headers`]: Transaction::request_headers
    /// [`set_request`]: Transaction::set_request
    pub fn request(&self) -> Option<&RequestData> {
        self.request.as_ref()
    }

    /// Move the recorded request out (after [`finish`]), to hand it on
    /// without a copy.
    ///
    /// [`finish`]: Transaction::finish
    pub fn take_request(&mut self) -> Option<RequestData> {
        self.request.take()
    }

    /// Move the buffered request body out (after [`finish`]).
    ///
    /// [`finish`]: Transaction::finish
    pub fn take_request_body(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.req.buffer.buf)
    }

    /// The buffered (possibly truncated) request body.
    pub fn request_body(&self) -> &[u8] {
        &self.req.buffer.buf
    }

    /// Scores accumulated so far.
    pub fn scores(&self) -> &HashMap<String, i64> {
        &self.scores
    }

    /// Rules recorded so far as `(rule_id, action)`.
    pub fn matched_rules(&self) -> &[(String, String)] {
        &self.matched_rules
    }

    /// Time since the transaction started.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }

    /// Record a terminal decision made by the host outside the rule engine
    /// (for example a dynamic IP block), so it shows in the action and in
    /// the audit log like a rule match. Ignores `detection_only`: the host
    /// decides whether to enforce.
    pub fn record_external(&mut self, rule_id: &str, action: &str) {
        self.matched_rules.push((rule_id.to_string(), action.to_string()));
        self.action = action.to_string();
    }

    /// Record the request without evaluating any rules, so that [`finish`]
    /// can still log it. For requests the host answers itself.
    ///
    /// [`finish`]: Transaction::finish
    pub fn set_request(&mut self, request: RequestData) {
        self.request = Some(request);
    }

    /// Request-headers phase. Resolves GeoIP when the host did not, populates
    /// the request fields, runs JWT and schema validation, then evaluates the
    /// phase's rules.
    pub fn request_headers(&mut self, mut request: RequestData) -> Verdict {
        if request.geo.is_none()
            && let (Some(ip), Some(geoip)) = (request.client_ip, self.waf.geoip.as_ref())
        {
            request.geo = Some(GeoData::from(&geoip.lookup(ip)));
        }

        let waf = Arc::clone(&self.waf);
        populate::request_fields(&mut self.ctx, &waf.scheme, &request);
        if !waf.jwt.is_empty() {
            let outcomes = waf.jwt.evaluate(&self.ctx);
            populate::jwt_fields(&mut self.ctx, &waf.scheme, &outcomes);
        }
        if let Some((schema_request, outcome)) = waf.schemas.check_request(&request) {
            populate::schema_fields(&mut self.ctx, &waf.scheme, &outcome);
            self.schema_request = schema_request;
        }
        self.request = Some(request);

        match self.evaluate(&Phase::RequestHeaders) {
            RuleAction::Block {
                status_code,
                content_type,
                content,
                ..
            } => Verdict::Block(Intervention {
                status_code,
                content_type,
                content,
            }),
            RuleAction::Allow { .. } => Verdict::Allow,
            RuleAction::Challenge { .. } => {
                let Some(cm) = waf.challenge.as_ref() else {
                    return Verdict::Pass;
                };
                let request = self.request.as_ref().expect("request was just set");
                let client_ip = request
                    .client_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_default();
                let cookie = populate::get_header(&request.headers, "cookie");
                if cm.is_verified(cookie, &client_ip) {
                    Verdict::Pass
                } else {
                    Verdict::Challenge
                }
            }
            RuleAction::NoMatch => Verdict::Pass,
        }
    }

    /// Feed a request body chunk. Call with `end_of_stream` on the last chunk
    /// (which may be empty).
    pub fn request_body_chunk(&mut self, data: &[u8], end_of_stream: bool) -> BodyVerdict {
        let waf = Arc::clone(&self.waf);

        // No RequestBody rules: stream through, keeping a capped copy for
        // field population and the audit log.
        if !waf.has_request_body_rules {
            self.req.buffer.feed(data);
            if end_of_stream {
                self.finalize_request_body();
            }
            return BodyVerdict::Passthrough;
        }

        if self.req.passthrough {
            return BodyVerdict::Passthrough;
        }

        self.req.buffer.feed(data);
        self.req.pending.extend_from_slice(data);

        // Checked before end-of-stream handling: the bytes that cross the
        // limit may arrive in the final chunk, and those must not be
        // forwarded uninspected when the limit action is `reject`.
        if self.req.buffer.truncated {
            match waf.settings.request_body_limit_action {
                BodyLimitAction::Reject => {
                    self.action = "block".into();
                    return BodyVerdict::Block(Intervention {
                        status_code: 413,
                        content_type: None,
                        content: Some("request body too large".into()),
                    });
                }
                BodyLimitAction::ProcessPartial => {
                    self.finalize_request_body();
                    if let Some(intervention) = self.evaluate_body_phase(&Phase::RequestBody) {
                        return BodyVerdict::Block(intervention);
                    }
                    self.req.passthrough = true;
                    return BodyVerdict::Forward(self.req.release());
                }
            }
        }

        if end_of_stream {
            self.finalize_request_body();
            if let Some(intervention) = self.evaluate_body_phase(&Phase::RequestBody) {
                return BodyVerdict::Block(intervention);
            }
            return BodyVerdict::Forward(self.req.release());
        }

        BodyVerdict::Hold
    }

    /// Response-headers phase.
    pub fn response_headers(&mut self, response: ResponseData) -> Verdict {
        let waf = Arc::clone(&self.waf);
        populate::response_fields(&mut self.ctx, &waf.scheme, &response);
        match self.evaluate(&Phase::ResponseHeaders) {
            RuleAction::Block {
                status_code,
                content_type,
                content,
                ..
            } => Verdict::Block(Intervention {
                status_code,
                content_type,
                content,
            }),
            RuleAction::Allow { .. } => Verdict::Allow,
            RuleAction::Challenge { .. } | RuleAction::NoMatch => Verdict::Pass,
        }
    }

    /// Feed a response body chunk. Call with `end_of_stream` on the last
    /// chunk (which may be empty).
    pub fn response_body_chunk(&mut self, data: &[u8], end_of_stream: bool) -> BodyVerdict {
        let waf = Arc::clone(&self.waf);
        let settings = &waf.settings;

        // Not inspecting, or nothing to act on: stream through, evaluating
        // only for side effects (scores, logging, payload capture).
        if !settings.inspect_response_body || !waf.has_response_body_rules {
            if settings.inspect_response_body {
                self.res.buffer.feed(data);
                if end_of_stream {
                    self.finalize_response_body();
                    self.evaluate(&Phase::ResponseBody);
                }
            } else {
                // Not inspected, but still counted for the access log.
                self.res.buffer.total_size += data.len();
            }
            return BodyVerdict::Passthrough;
        }

        if self.res.blocked {
            return BodyVerdict::Hold;
        }
        if self.res.passthrough {
            return BodyVerdict::Passthrough;
        }

        self.res.buffer.feed(data);
        self.res.pending.extend_from_slice(data);

        if self.res.buffer.truncated {
            match settings.response_body_limit_action {
                BodyLimitAction::Reject => {
                    return self.suppress_response(Intervention {
                        status_code: 0,
                        content_type: None,
                        content: Some("response blocked".into()),
                    });
                }
                BodyLimitAction::ProcessPartial => {
                    self.finalize_response_body();
                    if let Some(intervention) = self.evaluate_body_phase(&Phase::ResponseBody) {
                        return self.suppress_response(intervention);
                    }
                    self.res.passthrough = true;
                    return BodyVerdict::Forward(self.res.release());
                }
            }
        }

        if end_of_stream {
            self.finalize_response_body();
            if let Some(intervention) = self.evaluate_body_phase(&Phase::ResponseBody) {
                return self.suppress_response(intervention);
            }
            return BodyVerdict::Forward(self.res.release());
        }

        BodyVerdict::Hold
    }

    /// Logging phase. Runs the `logging` rules and builds the log entries.
    pub fn finish(&mut self, outcome: ResponseOutcome<'_>) -> LogRecord {
        self.evaluate(&Phase::Logging);

        let elapsed = self.start.elapsed();
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let (client_ip, method, protocol, host, path, query) = match &self.request {
            Some(req) => (
                req.client_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "-".into()),
                req.method.clone(),
                req.version.clone(),
                if req.host.is_empty() {
                    "-".to_string()
                } else {
                    req.host.clone()
                },
                req.path.clone(),
                req.query.clone(),
            ),
            None => (
                "-".into(),
                String::new(),
                String::new(),
                "-".into(),
                String::new(),
                String::new(),
            ),
        };

        let access = AccessLogEntry {
            request_id: self.id.clone(),
            timestamp: timestamp.clone(),
            client_ip: client_ip.clone(),
            method: method.clone(),
            protocol: protocol.clone(),
            host: host.clone(),
            path: path.clone(),
            // A request that matched a rule keeps the shape of masked values,
            // so the evidence for the match stays readable.
            query: if self.matched_rules.is_empty() {
                self.waf.redactor().query(&query).into_owned()
            } else {
                self.waf.redactor().query_shaped(&query).into_owned()
            },
            status: outcome.status,
            duration_ms: elapsed.as_secs_f64() * 1000.0,
            bytes_received: self.req.buffer.total_size,
            bytes_sent: self.res.buffer.total_size,
            error: outcome.error,
        };

        if self.matched_rules.is_empty() {
            return LogRecord {
                access,
                audit: None,
            };
        }

        let redactor = self.waf.redactor();
        let headers = self
            .request
            .as_ref()
            .map(|r| audit_headers(redactor, &r.headers, true))
            .unwrap_or_default();
        let req_ct = self
            .request
            .as_ref()
            .and_then(|r| populate::get_header(&r.headers, "content-type"));
        let body = lossy_body(&self.req.buffer.buf).map(|b| redactor.body_shaped(req_ct, &b).into_owned());

        let response = outcome.headers.map(|headers| {
            let res_ct = populate::get_header(headers, "content-type");
            AuditResponse {
                status: outcome.status,
                headers: audit_headers(redactor, headers, false),
                body: lossy_body(&self.res.buffer.buf)
                    .map(|b| redactor.body(res_ct, &b).into_owned()),
                body_size: self.res.buffer.total_size,
            }
        });

        let audit = AuditLogEntry {
            request_id: self.id.clone(),
            timestamp,
            waf_action: std::mem::take(&mut self.action),
            waf_matched_rules: std::mem::take(&mut self.matched_rules)
                .into_iter()
                .map(|(id, action)| MatchedRule { id, action })
                .collect(),
            waf_scores: std::mem::take(&mut self.scores),
            waf_payloads: std::mem::take(&mut self.payloads),
            request: AuditRequest {
                client_ip,
                method,
                protocol,
                host,
                path,
                query: redactor.query_shaped(&query).into_owned(),
                headers,
                body,
                body_size: self.req.buffer.total_size,
            },
            response,
        };

        LogRecord {
            access,
            audit: Some(audit),
        }
    }

    /// Run one phase's rules, recording the outcome. In detection-only mode
    /// the outcome is recorded but reported as no match.
    fn evaluate(&mut self, phase: &Phase) -> RuleAction {
        let waf = Arc::clone(&self.waf);
        engine::sync_scores(&mut self.ctx, &waf.scheme, &self.scores);
        let action = waf.engine.evaluate(
            phase,
            &self.ctx,
            &mut self.scores,
            &mut self.matched_rules,
            &mut self.payloads,
        );

        let taken = match &action {
            RuleAction::Block { rule_id, log, .. } => Some((rule_id, *log, "block")),
            RuleAction::Allow { rule_id, log } => Some((rule_id, *log, "allow")),
            RuleAction::Challenge { rule_id, log } => Some((rule_id, *log, "challenge")),
            RuleAction::NoMatch => None,
        };
        if let Some((rule_id, log, name)) = taken {
            if log {
                self.matched_rules.push((rule_id.clone(), name.into()));
            }
            self.action = name.into();
        }

        if waf.settings.detection_only {
            RuleAction::NoMatch
        } else {
            action
        }
    }

    fn evaluate_body_phase(&mut self, phase: &Phase) -> Option<Intervention> {
        match self.evaluate(phase) {
            RuleAction::Block {
                status_code,
                content_type,
                content,
                ..
            } => Some(Intervention {
                status_code,
                content_type,
                content,
            }),
            _ => None,
        }
    }

    fn suppress_response(&mut self, intervention: Intervention) -> BodyVerdict {
        self.res.blocked = true;
        self.res.pending.clear();
        BodyVerdict::Block(intervention)
    }

    /// Populate the request-body fields (raw, form, multipart, schema
    /// violations) from the buffer.
    fn finalize_request_body(&mut self) {
        let waf = Arc::clone(&self.waf);
        let content_type = self
            .request
            .as_ref()
            .and_then(|r| populate::get_header(&r.headers, "content-type"))
            .map(str::to_string);
        let body = &self.req.buffer;
        populate::body_fields(
            &mut self.ctx,
            &waf.scheme,
            &body.buf,
            body.total_size,
            body.truncated,
            content_type.as_deref(),
        );
        if let Some(request) = &self.schema_request {
            let violations =
                waf.schemas
                    .check_body(request, content_type.as_deref(), &body.buf, body.truncated);
            populate::schema_body_fields(&mut self.ctx, &waf.scheme, &violations);
        }
        if let Some(boundary) = content_type
            .as_deref()
            .and_then(|ct| multer::parse_boundary(ct).ok())
        {
            let parts = parse_multipart(&body.buf, boundary);
            populate::multipart_fields(&mut self.ctx, &waf.scheme, &parts);
        }
    }

    fn finalize_response_body(&mut self) {
        let waf = Arc::clone(&self.waf);
        let body = &self.res.buffer;
        populate::response_body_fields(
            &mut self.ctx,
            &waf.scheme,
            &body.buf,
            body.total_size,
            body.truncated,
        );
    }
}

/// Headers for the audit log: values redacted, repeated headers joined with
/// `, ` so none are lost.
fn audit_headers(
    redactor: &crate::redact::Redactor,
    headers: &[(String, String)],
    shaped: bool,
) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::with_capacity(headers.len());
    for (k, v) in headers {
        let v = if shaped { redactor.header_shaped(k, v) } else { redactor.header(k, v) };
        out.entry(k.to_ascii_lowercase())
            .and_modify(|e| {
                e.push_str(", ");
                e.push_str(&v);
            })
            .or_insert_with(|| v.into_owned());
    }
    out
}

fn lossy_body(buf: &[u8]) -> Option<String> {
    if buf.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(buf).into_owned())
    }
}

/// Parse a complete (possibly truncated) multipart body into its parts.
fn parse_multipart(body: &[u8], boundary: String) -> Vec<MultipartPartData> {
    let data = bytes::Bytes::copy_from_slice(body);
    let stream = futures::stream::once(async move { Ok::<_, std::convert::Infallible>(data) });
    futures::executor::block_on(async move {
        let mut multipart = multer::Multipart::new(stream, boundary);
        let mut parts = Vec::new();
        while let Ok(Some(field)) = multipart.next_field().await {
            let name = field.name().map(String::from);
            let filename = field.file_name().map(String::from);
            let content_type = field.content_type().map(|m| m.to_string());
            let header = |name: &str| {
                field
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(String::from)
            };
            let content_disposition = header("content-disposition");
            let content_transfer_encoding = header("content-transfer-encoding");
            let value = field.text().await.unwrap_or_default();
            parts.push(MultipartPartData {
                name,
                filename,
                content_type,
                content_disposition,
                content_transfer_encoding,
                value,
            });
        }
        parts
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::config::WafConfig;

    /// A firewall from top-level `settings` YAML plus root-ruleset `rules`
    /// (a YAML list, unindented).
    fn waf(settings: &str, rules: &str) -> Arc<Waf> {
        let rules: String = rules
            .trim_matches('\n')
            .lines()
            .map(|l| format!("      {l}\n"))
            .collect();
        let yaml =
            format!("{settings}\nrulesets:\n  - name: main\n    kind: root\n    rules:\n{rules}");
        let config = WafConfig::from_yaml(&yaml).expect("config should parse");
        Arc::new(Waf::from_config(&config).expect("waf should build"))
    }

    fn request(path: &str, headers: &[(&str, &str)]) -> RequestData {
        RequestData {
            client_ip: Some("10.0.0.1".parse().unwrap()),
            is_tls: false,
            method: "POST".into(),
            version: "HTTP/1.1".into(),
            host: "example.com".into(),
            full_uri: format!("http://example.com{path}"),
            uri: path.into(),
            path: path.into(),
            query: String::new(),
            extension: String::new(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            geo: None,
            allowlisted: false,
        }
    }

    fn block(status: u16, content: Option<&str>) -> Intervention {
        Intervention {
            status_code: status,
            content_type: None,
            content: content.map(String::from),
        }
    }

    const BLOCK_ADMIN: &str = r#"
- id: admin
  action: block
  expression: 'http.request.uri.path == "/admin"'
  action_parameters:
    response:
      status_code: 418
      content: nope
"#;

    const BLOCK_EVIL_BODY: &str = r#"
- id: evil
  phase: request_body
  action: block
  expression: 'http.request.body.raw contains "evil"'
"#;

    const BLOCK_SECRET_RESPONSE: &str = r#"
- id: secret
  phase: response_body
  action: block
  expression: 'http.response.body.raw contains "secret"'
  action_parameters:
    response:
      content: redacted
"#;

    #[test]
    fn request_headers_block_returns_the_rule_response() {
        let mut tx = waf("", BLOCK_ADMIN).transaction();
        assert_eq!(
            tx.request_headers(request("/admin", &[])),
            Verdict::Block(block(418, Some("nope")))
        );
        assert_eq!(tx.action(), "block");
    }

    #[test]
    fn request_headers_pass_when_nothing_matches() {
        let mut tx = waf("", BLOCK_ADMIN).transaction();
        assert_eq!(tx.request_headers(request("/", &[])), Verdict::Pass);
        assert_eq!(tx.action(), "pass");
        let record = tx.finish(ResponseOutcome {
            status: 200,
            headers: Some(&[]),
            error: None,
        });
        assert!(record.audit.is_none());
        assert_eq!(record.access.method, "POST");
        assert_eq!(record.access.host, "example.com");
        assert_eq!(record.access.client_ip, "10.0.0.1");
        assert_eq!(record.access.status, 200);
    }

    #[test]
    fn detection_only_passes_but_records_the_block() {
        let mut tx = waf("detection_only: true", BLOCK_ADMIN).transaction();
        assert_eq!(tx.request_headers(request("/admin", &[])), Verdict::Pass);
        assert_eq!(tx.action(), "block");
        let audit = tx
            .finish(ResponseOutcome {
                status: 200,
                headers: None,
                error: None,
            })
            .audit
            .expect("matched rule should produce an audit entry");
        assert_eq!(audit.waf_action, "block");
        assert_eq!(audit.waf_matched_rules[0].id, "admin");
    }

    #[test]
    fn challenge_rule_without_cookie_serves_the_page() {
        let settings = r#"
challenge:
  turnstile_site_key: site
  turnstile_secret_key: secret
  cookie_secret: cookie
"#;
        let rules = r#"
- id: ch
  action: challenge
  expression: 'true'
"#;
        let waf = waf(settings, rules);
        let mut tx = waf.transaction();
        assert_eq!(tx.request_headers(request("/", &[])), Verdict::Challenge);

        // A cookie minted for the same client passes.
        let cookie = waf.challenge().unwrap().create_cookie("10.0.0.1");
        let cookie = cookie.split(';').next().unwrap();
        let mut tx = waf.transaction();
        assert_eq!(
            tx.request_headers(request("/", &[("cookie", cookie)])),
            Verdict::Pass
        );
    }

    #[test]
    fn request_body_streams_through_without_body_rules() {
        let mut tx = waf("", BLOCK_ADMIN).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(
            tx.request_body_chunk(b"abc", false),
            BodyVerdict::Passthrough
        );
        assert_eq!(
            tx.request_body_chunk(b"def", true),
            BodyVerdict::Passthrough
        );
        let record = tx.finish(ResponseOutcome {
            status: 200,
            headers: None,
            error: None,
        });
        assert_eq!(record.access.bytes_received, 6);
    }

    #[test]
    fn request_body_is_held_then_released() {
        let mut tx = waf("", BLOCK_EVIL_BODY).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(tx.request_body_chunk(b"hel", false), BodyVerdict::Hold);
        assert_eq!(
            tx.request_body_chunk(b"lo", true),
            BodyVerdict::Forward(b"hello".to_vec())
        );
    }

    #[test]
    fn request_body_block_at_end_of_stream() {
        let mut tx = waf("", BLOCK_EVIL_BODY).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(tx.request_body_chunk(b"so ", false), BodyVerdict::Hold);
        assert_eq!(
            tx.request_body_chunk(b"evil", true),
            BodyVerdict::Block(block(403, None))
        );
        assert_eq!(tx.action(), "block");
    }

    #[test]
    fn request_body_over_limit_is_rejected() {
        let settings = "max_request_body_buffer: 4\nrequest_body_limit_action: reject";
        let mut tx = waf(settings, BLOCK_EVIL_BODY).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(
            tx.request_body_chunk(b"abcdef", false),
            BodyVerdict::Block(block(413, Some("request body too large")))
        );
        assert_eq!(tx.action(), "block");
    }

    #[test]
    fn request_body_over_limit_in_final_chunk_is_rejected() {
        // Regression: the limit used to be checked only on non-final chunks.
        let settings = "max_request_body_buffer: 4\nrequest_body_limit_action: reject";
        let mut tx = waf(settings, BLOCK_EVIL_BODY).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(tx.request_body_chunk(b"abc", false), BodyVerdict::Hold);
        assert_eq!(
            tx.request_body_chunk(b"defevil", true),
            BodyVerdict::Block(block(413, Some("request body too large")))
        );
    }

    #[test]
    fn request_body_over_limit_in_single_final_chunk_is_rejected() {
        let settings = "max_request_body_buffer: 4\nrequest_body_limit_action: reject";
        let mut tx = waf(settings, BLOCK_EVIL_BODY).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(
            tx.request_body_chunk(b"abcdefgh", true),
            BodyVerdict::Block(block(413, Some("request body too large")))
        );
    }

    #[test]
    fn request_body_over_limit_in_final_chunk_process_partial_inspects_prefix() {
        let settings = "max_request_body_buffer: 4\nrequest_body_limit_action: process_partial";
        let mut tx = waf(settings, BLOCK_EVIL_BODY).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(
            tx.request_body_chunk(b"evilxx", true),
            BodyVerdict::Block(block(403, None))
        );
        let mut tx = waf(settings, BLOCK_EVIL_BODY).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(
            tx.request_body_chunk(b"abcdef", true),
            BodyVerdict::Forward(b"abcdef".to_vec())
        );
    }

    #[test]
    fn response_body_over_limit_in_final_chunk_is_suppressed_on_reject() {
        let settings = "inspect_response_body: true\nmax_response_body_buffer: 4\n\
                        response_body_limit_action: reject";
        let mut tx = waf(settings, BLOCK_SECRET_RESPONSE).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(
            tx.response_body_chunk(b"abcdef", true),
            BodyVerdict::Block(block(0, Some("response blocked")))
        );
    }

    #[test]
    fn request_body_over_limit_process_partial_releases_then_streams() {
        let settings = "max_request_body_buffer: 4\nrequest_body_limit_action: process_partial";
        let mut tx = waf(settings, BLOCK_EVIL_BODY).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(
            tx.request_body_chunk(b"abcdef", false),
            BodyVerdict::Forward(b"abcdef".to_vec())
        );
        assert_eq!(
            tx.request_body_chunk(b"evil", false),
            BodyVerdict::Passthrough
        );
        assert_eq!(tx.request_body_chunk(b"", true), BodyVerdict::Passthrough);
        assert_eq!(tx.action(), "pass");
    }

    #[test]
    fn request_body_over_limit_process_partial_blocks_on_inspected_prefix() {
        let settings = "max_request_body_buffer: 4\nrequest_body_limit_action: process_partial";
        let mut tx = waf(settings, BLOCK_EVIL_BODY).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(
            tx.request_body_chunk(b"evilxx", false),
            BodyVerdict::Block(block(403, None))
        );
    }

    #[test]
    fn multipart_parts_are_available_to_body_rules() {
        let rules = r#"
- id: part
  phase: request_body
  action: block
  expression: 'any(http.request.body.multipart.values[*] == "bad")'
"#;
        let mut tx = waf("", rules).transaction();
        tx.request_headers(request(
            "/",
            &[("content-type", "multipart/form-data; boundary=XX")],
        ));
        let body = b"--XX\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nbad\r\n--XX--\r\n";
        assert_eq!(
            tx.request_body_chunk(body, true),
            BodyVerdict::Block(block(403, None))
        );
    }

    #[test]
    fn response_body_passes_through_when_not_inspected() {
        let mut tx = waf("", BLOCK_SECRET_RESPONSE).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(
            tx.response_headers(ResponseData {
                status: 200,
                headers: vec![]
            }),
            Verdict::Pass
        );
        assert_eq!(
            tx.response_body_chunk(b"secret", true),
            BodyVerdict::Passthrough
        );
        assert_eq!(tx.action(), "pass");
    }

    #[test]
    fn bytes_sent_are_counted_without_response_inspection() {
        // Regression: bytes_sent was always 0 unless inspect_response_body.
        let mut tx = waf("", BLOCK_ADMIN).transaction();
        tx.request_headers(request("/", &[]));
        tx.response_body_chunk(b"hello", false);
        tx.response_body_chunk(b"!", true);
        let record = tx.finish(ResponseOutcome {
            status: 200,
            headers: None,
            error: None,
        });
        assert_eq!(record.access.bytes_sent, 6);
    }

    #[test]
    fn response_body_is_held_then_released() {
        let mut tx = waf("inspect_response_body: true", BLOCK_SECRET_RESPONSE).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(tx.response_body_chunk(b"hel", false), BodyVerdict::Hold);
        assert_eq!(
            tx.response_body_chunk(b"lo", true),
            BodyVerdict::Forward(b"hello".to_vec())
        );
    }

    #[test]
    fn response_body_block_replaces_the_rest_of_the_body() {
        let mut tx = waf("inspect_response_body: true", BLOCK_SECRET_RESPONSE).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(tx.response_body_chunk(b"sec", false), BodyVerdict::Hold);
        assert_eq!(
            tx.response_body_chunk(b"ret", true),
            BodyVerdict::Block(block(403, Some("redacted")))
        );
        // Anything the upstream still sends is discarded.
        assert_eq!(tx.response_body_chunk(b"more", true), BodyVerdict::Hold);
        assert_eq!(tx.action(), "block");
    }

    #[test]
    fn response_body_over_limit_is_suppressed_on_reject() {
        let settings = "inspect_response_body: true\nmax_response_body_buffer: 4\n\
                        response_body_limit_action: reject";
        let mut tx = waf(settings, BLOCK_SECRET_RESPONSE).transaction();
        tx.request_headers(request("/", &[]));
        assert_eq!(
            tx.response_body_chunk(b"abcdef", false),
            BodyVerdict::Block(block(0, Some("response blocked")))
        );
    }

    #[test]
    fn rewrites_response_body_only_with_inspection_and_rules() {
        assert!(!waf("", BLOCK_SECRET_RESPONSE).rewrites_response_body());
        assert!(!waf("inspect_response_body: true", BLOCK_ADMIN).rewrites_response_body());
        assert!(waf("inspect_response_body: true", BLOCK_SECRET_RESPONSE).rewrites_response_body());
    }

    #[test]
    fn finish_builds_the_audit_entry() {
        let mut tx = waf("", BLOCK_ADMIN).transaction();
        tx.request_headers(request("/admin", &[("user-agent", "curl")]));
        tx.request_body_chunk(b"payload", true);
        let headers = [("content-type".to_string(), "text/plain".to_string())];
        let record = tx.finish(ResponseOutcome {
            status: 418,
            headers: Some(&headers),
            error: None,
        });
        let audit = record.audit.expect("audit entry");
        assert_eq!(audit.request_id, record.access.request_id);
        assert_eq!(audit.waf_action, "block");
        assert_eq!(audit.waf_matched_rules.len(), 1);
        assert_eq!(audit.waf_matched_rules[0].action, "block");
        assert_eq!(audit.request.path, "/admin");
        assert_eq!(audit.request.headers["user-agent"], "curl");
        assert_eq!(audit.request.body.as_deref(), Some("payload"));
        assert_eq!(audit.request.body_size, 7);
        let response = audit.response.expect("response was written");
        assert_eq!(response.status, 418);
        assert_eq!(response.headers["content-type"], "text/plain");
    }

    #[test]
    fn audit_entry_redacts_secrets_and_keeps_repeated_headers() {
        let mut tx = waf("", BLOCK_ADMIN).transaction();
        let mut req = request(
            "/admin",
            &[
                ("authorization", "Bearer s3cr3t-value"),
                ("cookie", "session=abc"),
                ("x-tag", "one"),
                ("x-tag", "two"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
        );
        req.query = "q=1&access_token=zzz".into();
        tx.request_headers(req);
        tx.request_body_chunk(b"user=bob&password=hunter2", true);
        let record = tx.finish(ResponseOutcome {
            status: 403,
            headers: Some(&[("set-cookie".into(), "sid=1".into())]),
            error: None,
        });
        // The request matched a rule, so masked values keep their shape.
        assert_eq!(record.access.query, "q=1&access_token=%5BREDACTED%5D+len%3D3+shape%3Da");
        let audit = record.audit.unwrap();
        let text = serde_json::to_string(&audit).unwrap();
        for secret in ["s3cr3t-value", "session=abc", "hunter2", "zzz", "sid=1"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        assert_eq!(audit.request.headers["x-tag"], "one, two");
    }

    #[test]
    fn redaction_can_be_disabled() {
        let mut tx = waf("redaction: {enabled: false}", BLOCK_ADMIN).transaction();
        tx.request_headers(request("/admin", &[("authorization", "Bearer s3cr3t")]));
        let audit = tx
            .finish(ResponseOutcome {
                status: 403,
                headers: None,
                error: None,
            })
            .audit
            .unwrap();
        assert_eq!(audit.request.headers["authorization"], "Bearer s3cr3t");
    }

    #[test]
    fn finish_runs_logging_phase_rules() {
        let rules = r#"
- id: tail
  phase: logging
  action: log
  expression: 'true'
"#;
        let mut tx = waf("", rules).transaction();
        tx.request_headers(request("/", &[]));
        let audit = tx
            .finish(ResponseOutcome {
                status: 200,
                headers: None,
                error: None,
            })
            .audit
            .expect("logging rule should be recorded");
        assert_eq!(audit.waf_matched_rules[0].id, "tail");
        assert!(audit.response.is_none());
    }

    #[test]
    fn finish_without_a_request_still_logs() {
        let mut tx = waf("", BLOCK_ADMIN).transaction();
        let record = tx.finish(ResponseOutcome {
            status: 0,
            headers: None,
            error: Some("boom".into()),
        });
        assert_eq!(record.access.host, "-");
        assert_eq!(record.access.client_ip, "-");
        assert_eq!(record.access.error.as_deref(), Some("boom"));
    }

    #[test]
    fn external_decision_is_recorded_and_audited() {
        let mut tx = waf("", BLOCK_ADMIN).transaction();
        tx.set_request(request("/", &[]));
        tx.record_external("dynamic:ip_block", "block");
        assert_eq!(tx.action(), "block");
        assert_eq!(tx.matched_rules()[0].0, "dynamic:ip_block");
        let audit = tx
            .finish(ResponseOutcome {
                status: 403,
                headers: None,
                error: None,
            })
            .audit
            .expect("external decision should produce an audit entry");
        assert_eq!(audit.waf_matched_rules[0].id, "dynamic:ip_block");
    }

    #[test]
    fn set_request_logs_without_evaluating() {
        let mut tx = waf("", BLOCK_ADMIN).transaction();
        tx.set_request(request("/admin", &[]));
        assert_eq!(tx.action(), "pass");
        let record = tx.finish(ResponseOutcome {
            status: 302,
            headers: None,
            error: None,
        });
        assert_eq!(record.access.path, "/admin");
        assert!(record.audit.is_none());
    }
}
