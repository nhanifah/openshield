//! The security event: one record per request, built after the response is
//! sent, already redacted.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ai::types::AiVerdict;

fn yes() -> bool {
    true
}

/// A reason the anomaly detector flagged a request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnomalyReason {
    pub kind: String,
    pub detail: String,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Anomaly {
    pub score: f64,
    pub reasons: Vec<AnomalyReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MatchedRule {
    pub id: String,
    pub action: String,
}

/// Everything recorded about one request. Text fields hold redacted,
/// attacker-controlled data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub ts: i64,
    pub client_ip: String,
    pub country: Option<String>,
    pub asn: Option<u32>,
    /// Names and finer location, from the same lookup as `country`.
    #[serde(default, flatten)]
    pub loc: Location,
    pub method: String,
    pub protocol: String,
    pub host: String,
    pub path: String,
    pub query: String,
    pub status: u16,
    pub duration_ms: f64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// `pass`, `allow`, `block` or `challenge`.
    pub action: String,
    /// False when the firewall ran in detection-only mode: `action` is what
    /// would have happened, and the request was forwarded.
    #[serde(default = "yes")]
    pub enforced: bool,
    pub matched_rules: Vec<MatchedRule>,
    pub scores: BTreeMap<String, i64>,
    pub user_agent: String,
    pub content_type: String,
    pub headers: BTreeMap<String, String>,
    pub body_excerpt: Option<String>,
    pub error: Option<String>,
    pub anomaly: Anomaly,
    pub ai: Option<AiVerdict>,
    pub label: Option<String>,
}

/// Where a client is, beyond the country code and ASN.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Location {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
    /// ISO 3166-2, e.g. `ID-JK`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_org: Option<String>,
    /// Private, loopback or link-local address: no public location.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub private_ip: bool,
}

/// The compact form sent to lists and the live stream.
#[derive(Debug, Clone, Serialize)]
pub struct EventSummary {
    pub id: String,
    pub ts: i64,
    pub client_ip: String,
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_org: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub private_ip: bool,
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: String,
    pub status: u16,
    pub duration_ms: f64,
    pub action: String,
    pub enforced: bool,
    pub rules: Vec<String>,
    pub anomaly_score: Option<f64>,
    pub ai: Option<AiBrief>,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiBrief {
    pub category: String,
    pub risk: f64,
    pub confidence: f64,
    pub recommended_action: String,
}

impl AsRef<SecurityEvent> for SecurityEvent {
    fn as_ref(&self) -> &SecurityEvent {
        self
    }
}

impl SecurityEvent {
    /// True when a rule matched and part of the query or body was masked by
    /// redaction, so the value that triggered the rule may be hidden (only
    /// its shape is kept). Labels on such events cannot be checked against
    /// the payload.
    pub fn evidence_redacted(&self) -> bool {
        use openshield_core::redact::contains_mask;
        !self.matched_rules.is_empty()
            && (contains_mask(&self.query) || self.body_excerpt.as_deref().is_some_and(contains_mask))
    }

    pub fn summary(&self) -> EventSummary {
        EventSummary {
            id: self.id.clone(),
            ts: self.ts,
            client_ip: self.client_ip.clone(),
            country: self.country.clone(),
            region: self.loc.region.clone(),
            asn: self.asn,
            as_org: self.loc.as_org.clone(),
            private_ip: self.loc.private_ip,
            method: self.method.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            query: self.query.clone(),
            status: self.status,
            duration_ms: self.duration_ms,
            action: self.action.clone(),
            enforced: self.enforced,
            rules: self.matched_rules.iter().map(|r| r.id.clone()).collect(),
            anomaly_score: if self.anomaly.score > 0.0 {
                Some(self.anomaly.score)
            } else {
                None
            },
            ai: self.ai.as_ref().map(|v| AiBrief {
                category: v.category.as_str().into(),
                risk: v.risk,
                confidence: v.confidence,
                recommended_action: v.recommended_action.as_str().into(),
            }),
            label: self.label.clone(),
        }
    }

    pub fn is_blocked(&self) -> bool {
        self.action == "block"
    }

    /// True when anything about the request deserves attention.
    pub fn is_notable(&self) -> bool {
        !self.matched_rules.is_empty()
            || self.anomaly.score > 0.0
            || self.status >= 500
            || self.error.is_some()
            || self.ai.is_some()
    }

    pub fn path_template(&self) -> String {
        path_template(&self.path)
    }

    /// Stable fingerprint of the request *shape*: method, path template,
    /// query parameter names, rules matched and status class. Requests with
    /// the same fingerprint get the same cached AI verdict and count as
    /// duplicates in datasets. Values are left out on purpose.
    pub fn fingerprint(&self) -> String {
        let mut names: Vec<String> = form_pairs(&self.query).into_iter().map(|(k, _)| k).collect();
        names.sort();
        names.dedup();
        let mut rules: Vec<&str> = self.matched_rules.iter().map(|r| r.id.as_str()).collect();
        rules.sort();
        let mut h = Sha256::new();
        for part in [
            self.method.as_str(),
            &self.path_template(),
            &names.join(","),
            &rules.join(","),
            &format!("{}xx", self.status / 100),
            self.action.as_str(),
            // payload shape: the classes of characters present in the query
            &payload_shape(&self.query),
        ] {
            h.update(part.as_bytes());
            h.update([0u8]);
        }
        hex::encode(&h.finalize()[..12])
    }
}

/// Replace path segments that look like identifiers with `{id}`, so that
/// `/users/123/orders/9f3c...` becomes `/users/{id}/orders/{id}`.
pub fn path_template(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for seg in path.split('/').skip(1) {
        out.push('/');
        if is_identifier(seg) {
            out.push_str("{id}");
        } else {
            out.push_str(seg);
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

fn is_identifier(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    let digits = seg.chars().all(|c| c.is_ascii_digit());
    let hexlike = seg.len() >= 16 && seg.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    digits || hexlike
}

fn form_pairs(q: &str) -> Vec<(String, String)> {
    url_pairs(q)
}

pub(crate) fn url_pairs(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (k.to_string(), v.to_string())
        })
        .collect()
}

/// Which character classes occur in a string: a coarse shape used in the
/// fingerprint so `id=5` and `id=5'--` do not share a verdict.
fn payload_shape(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut shape = String::new();
    for (flag, present) in [
        ('q', s.contains('\'') || s.contains("%27") || s.contains('"') || s.contains("%22")),
        ('l', s.contains('<') || lower.contains("%3c")),
        ('p', s.contains("..") || lower.contains("%2e%2e")),
        ('s', s.contains(';') || lower.contains("%3b") || s.contains('|') || s.contains('`')),
        ('c', s.contains("--") || s.contains("/*") || s.contains('#')),
        ('n', s.contains('\0') || s.contains("%00")),
    ] {
        if present {
            shape.push(flag);
        }
    }
    shape
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    pub(crate) fn sample_event() -> SecurityEvent {
        SecurityEvent {
            id: "e1".into(),
            ts: 1,
            client_ip: "203.0.113.5".into(),
            country: None,
            asn: None,
            loc: Default::default(),
            method: "GET".into(),
            protocol: "HTTP/1.1".into(),
            host: "app.test".into(),
            path: "/users/123/orders".into(),
            query: "id=5".into(),
            status: 200,
            duration_ms: 1.0,
            bytes_in: 0,
            bytes_out: 2,
            action: "pass".into(),
            enforced: true,
            matched_rules: vec![],
            scores: BTreeMap::new(),
            user_agent: "curl".into(),
            content_type: String::new(),
            headers: BTreeMap::new(),
            body_excerpt: None,
            error: None,
            anomaly: Anomaly::default(),
            ai: None,
            label: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::sample_event as sample;
    use super::*;

    #[test]
    fn templates_replace_identifiers() {
        assert_eq!(path_template("/users/123/orders"), "/users/{id}/orders");
        assert_eq!(
            path_template("/o/550e8400-e29b-41d4-a716-446655440000"),
            "/o/{id}"
        );
        assert_eq!(path_template("/"), "/");
        assert_eq!(path_template(""), "/");
        assert_eq!(path_template("/v2/items"), "/v2/items");
    }

    #[test]
    fn fingerprint_ignores_values_but_not_shape() {
        let a = sample();
        let mut b = sample();
        b.path = "/users/999/orders".into();
        b.query = "id=77".into();
        assert_eq!(a.fingerprint(), b.fingerprint());
        let mut c = sample();
        c.query = "id=5'--".into();
        assert_ne!(a.fingerprint(), c.fingerprint());
        let mut d = sample();
        d.matched_rules.push(MatchedRule {
            id: "r".into(),
            action: "block".into(),
        });
        assert_ne!(a.fingerprint(), d.fingerprint());
    }
}
