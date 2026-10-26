//! Redaction of secrets and personal data before anything leaves the request
//! path: the audit log, the security event store, and the AI analysis
//! pipeline all pass through [`Redactor`].
//!
//! Redaction is best effort. It removes the common carriers of credentials
//! (auth headers, cookies, well-known parameter names, tokens and keys with a
//! recognizable shape) and obvious personal data (emails, card numbers). It
//! cannot recognize every secret, so anything sent to an external service
//! should also be limited to the fields that are needed.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;

/// Headers whose values are always replaced.
pub const DEFAULT_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-amz-security-token",
];

/// Query, form and JSON keys whose values are always replaced. Matched
/// case-insensitively, as a substring of the key.
pub const DEFAULT_FIELDS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "session",
    "credential",
    "auth",
    "ssn",
    "card",
    "cvv",
];

/// Placeholder written in place of a redacted value.
pub const MASK: &str = "[REDACTED]";

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedactionConfig {
    /// Replace sensitive values in audit logs and security events.
    pub enabled: bool,
    /// Header names (case-insensitive) whose values are replaced.
    pub headers: Vec<String>,
    /// Substrings of query, form and JSON keys whose values are replaced.
    pub fields: Vec<String>,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            headers: DEFAULT_HEADERS.iter().map(|s| s.to_string()).collect(),
            fields: DEFAULT_FIELDS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

static JWT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*").unwrap());
static BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}").unwrap());
static KEYS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",          // AWS access key id
        r"|\bAIza[0-9A-Za-z_-]{35}\b",           // Google API key
        r"|\bgh[pousr]_[A-Za-z0-9]{36,}\b",      // GitHub token
        r"|\bxox[abprs]-[A-Za-z0-9-]{10,}\b",    // Slack token
        r"|\bsk-[A-Za-z0-9_-]{20,}\b",           // common secret-key prefix
        r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
    ))
    .unwrap()
});
static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}").unwrap());
static CARD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:\d[ -]?){12,18}\d\b").unwrap());

pub struct Redactor {
    enabled: bool,
    headers: HashSet<String>,
    fields: Vec<String>,
    json_fields: Option<Regex>,
}

impl Redactor {
    pub fn new(config: &RedactionConfig) -> Self {
        let fields: Vec<String> = config.fields.iter().map(|f| f.to_ascii_lowercase()).collect();
        let json_fields = if fields.is_empty() {
            None
        } else {
            let alts = fields.iter().map(|f| regex::escape(f)).collect::<Vec<_>>().join("|");
            // "key...": "value" or "key...": number/bool
            Regex::new(&format!(
                r#"(?i)("[^"]*(?:{alts})[^"]*"\s*:\s*)("(?:[^"\\]|\\.)*"|-?[0-9.]+|true|false)"#
            ))
            .ok()
        };
        Self {
            enabled: config.enabled,
            headers: config.headers.iter().map(|h| h.to_ascii_lowercase()).collect(),
            fields,
            json_fields,
        }
    }

    pub fn disabled() -> Self {
        Self::new(&RedactionConfig {
            enabled: false,
            ..Default::default()
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    fn sensitive_field(&self, key: &str) -> bool {
        let key = key.to_ascii_lowercase();
        self.fields.iter().any(|f| key.contains(f.as_str()))
    }

    /// Value to record for a header.
    pub fn header<'a>(&self, name: &str, value: &'a str) -> Cow<'a, str> {
        if !self.enabled {
            return Cow::Borrowed(value);
        }
        if self.headers.contains(&name.to_ascii_lowercase()) {
            return Cow::Owned(format!("{MASK} len={}", value.len()));
        }
        self.text(value)
    }

    /// A query string or `application/x-www-form-urlencoded` body with
    /// sensitive values replaced. Keys and order are kept; the result is
    /// re-encoded.
    pub fn query<'a>(&self, query: &'a str) -> Cow<'a, str> {
        if !self.enabled || query.is_empty() {
            return Cow::Borrowed(query);
        }
        let mut changed = false;
        let mut ser = form_urlencoded::Serializer::new(String::new());
        for (k, v) in form_urlencoded::parse(query.as_bytes()) {
            if self.sensitive_field(&k) {
                changed = true;
                ser.append_pair(&k, MASK);
            } else {
                let r = self.text(&v);
                changed |= matches!(r, Cow::Owned(_));
                ser.append_pair(&k, &r);
            }
        }
        if changed { Cow::Owned(ser.finish()) } else { Cow::Borrowed(query) }
    }

    /// A request or response body, using the content type to pick the
    /// strategy: form fields, JSON keys, then the generic patterns.
    pub fn body<'a>(&self, content_type: Option<&str>, body: &'a str) -> Cow<'a, str> {
        if !self.enabled {
            return Cow::Borrowed(body);
        }
        let ct = content_type.unwrap_or("").to_ascii_lowercase();
        if ct.starts_with("application/x-www-form-urlencoded") {
            return Cow::Owned(self.query(body).into_owned());
        }
        let after_fields: Cow<'a, str> = match &self.json_fields {
            Some(re) if ct.contains("json") || body.trim_start().starts_with('{') => {
                match re.replace_all(body, format!("${{1}}\"{MASK}\"")) {
                    Cow::Borrowed(_) => Cow::Borrowed(body),
                    Cow::Owned(s) => Cow::Owned(s),
                }
            }
            _ => Cow::Borrowed(body),
        };
        match self.text(&after_fields) {
            Cow::Borrowed(_) => after_fields,
            Cow::Owned(s) => Cow::Owned(s),
        }
    }

    /// Replace tokens, keys, emails and card numbers anywhere in free text.
    pub fn text<'a>(&self, s: &'a str) -> Cow<'a, str> {
        if !self.enabled {
            return Cow::Borrowed(s);
        }
        // Cheap checks first: most values (paths, ids, words) cannot hold
        // any of the patterns, and this runs for every logged request.
        if s.len() < 6 {
            return Cow::Borrowed(s);
        }
        let b = s.as_bytes();
        let has_at = b.contains(&b'@');
        let has_jwt = s.contains("eyJ");
        let has_space = b.contains(&b' ');
        let has_key = s.contains("AKIA")
            || s.contains("ASIA")
            || s.contains("AIza")
            || s.contains("gh")
            || s.contains("xox")
            || s.contains("sk-")
            || s.contains("-----BEGIN");
        let digits = b.iter().filter(|c| c.is_ascii_digit()).count();
        if !(has_at || has_jwt || has_space || has_key || digits >= 13) {
            return Cow::Borrowed(s);
        }
        let mut out: Cow<'a, str> = Cow::Borrowed(s);
        for (re, mask, wanted) in [
            (&*KEYS, "[REDACTED:key]", has_key),
            (&*JWT, "[REDACTED:jwt]", has_jwt),
            (&*BEARER, "[REDACTED:credential]", has_space),
            (&*EMAIL, "[REDACTED:email]", has_at),
        ] {
            if wanted && re.is_match(&out) {
                out = Cow::Owned(re.replace_all(&out, mask).into_owned());
            }
        }
        if digits >= 13 && CARD.is_match(&out) {
            let replaced = CARD
                .replace_all(&out, |c: &regex::Captures| {
                    let digits: String = c[0].chars().filter(char::is_ascii_digit).collect();
                    if luhn(&digits) { "[REDACTED:card]".to_string() } else { c[0].to_string() }
                })
                .into_owned();
            if replaced != *out {
                out = Cow::Owned(replaced);
            }
        }
        out
    }
}

fn luhn(digits: &str) -> bool {
    if digits.len() < 13 {
        return false;
    }
    let mut sum = 0;
    for (i, c) in digits.chars().rev().enumerate() {
        let mut d = c.to_digit(10).unwrap_or(0);
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r() -> Redactor {
        Redactor::new(&RedactionConfig::default())
    }

    #[test]
    fn sensitive_headers_are_masked_with_length() {
        assert_eq!(r().header("Authorization", "Bearer abc"), "[REDACTED] len=10");
        assert_eq!(r().header("cookie", "a=b"), "[REDACTED] len=3");
        assert_eq!(r().header("user-agent", "curl/8"), "curl/8");
    }

    #[test]
    fn tokens_inside_other_headers_are_masked() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl"; // gitleaks:allow (fake test token)
        assert_eq!(r().header("x-forwarded-token", jwt), "[REDACTED:jwt]");
    }

    #[test]
    fn query_values_with_sensitive_keys_are_masked() {
        assert_eq!(
            r().query("user=bob&password=hunter2&q=shoes"),
            "user=bob&password=%5BREDACTED%5D&q=shoes"
        );
        assert!(matches!(r().query("q=shoes&page=2"), Cow::Borrowed(_)));
    }

    #[test]
    fn json_body_fields_are_masked() {
        let body = r#"{"user":"bob","password":"hunter2","api_key":12345,"note":"hi"}"#;
        assert_eq!(
            r().body(Some("application/json"), body),
            r#"{"user":"bob","password":"[REDACTED]","api_key":"[REDACTED]","note":"hi"}"#
        );
    }

    #[test]
    fn form_body_fields_are_masked() {
        assert_eq!(
            r().body(Some("application/x-www-form-urlencoded"), "a=1&pass_word=x&passwd=y"),
            "a=1&pass_word=x&passwd=%5BREDACTED%5D"
        );
    }

    #[test]
    fn keys_emails_and_cards_are_masked_in_text() {
        let t = "key AKIAABCDEFGHIJKLMNOP mail bob@example.com card 4111 1111 1111 1111 order 1234567890123"; // gitleaks:allow (fake test values)
        let out = r().text(t);
        assert!(!out.contains("AKIA"), "{out}");
        assert!(!out.contains("bob@example.com"), "{out}");
        assert!(!out.contains("4111 1111"), "{out}");
        // Not a Luhn-valid number: kept.
        assert!(out.contains("1234567890123"), "{out}");
    }

    #[test]
    fn disabled_redactor_changes_nothing() {
        let d = Redactor::disabled();
        assert_eq!(d.header("authorization", "x"), "x");
        assert_eq!(d.query("password=x"), "password=x");
    }
}
