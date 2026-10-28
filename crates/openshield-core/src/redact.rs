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
        self.header_as(name, value, false)
    }

    /// Like [`Redactor::header`], but a masked value keeps its [`shape`].
    /// Used for requests that matched a rule, so the evidence stays readable.
    pub fn header_shaped<'a>(&self, name: &str, value: &'a str) -> Cow<'a, str> {
        self.header_as(name, value, true)
    }

    fn header_as<'a>(&self, name: &str, value: &'a str, shaped: bool) -> Cow<'a, str> {
        if !self.enabled {
            return Cow::Borrowed(value);
        }
        if self.headers.contains(&name.to_ascii_lowercase()) {
            return Cow::Owned(mask_value(value, shaped, true));
        }
        self.text(value)
    }

    /// A query string or `application/x-www-form-urlencoded` body with
    /// sensitive values replaced. Keys and order are kept; the result is
    /// re-encoded.
    pub fn query<'a>(&self, query: &'a str) -> Cow<'a, str> {
        self.query_as(query, false)
    }

    /// Like [`Redactor::query`], but masked values keep their [`shape`].
    pub fn query_shaped<'a>(&self, query: &'a str) -> Cow<'a, str> {
        self.query_as(query, true)
    }

    fn query_as<'a>(&self, query: &'a str, shaped: bool) -> Cow<'a, str> {
        if !self.enabled || query.is_empty() {
            return Cow::Borrowed(query);
        }
        let mut changed = false;
        let mut ser = form_urlencoded::Serializer::new(String::new());
        for (k, v) in form_urlencoded::parse(query.as_bytes()) {
            if self.sensitive_field(&k) {
                let m = mask_value(&v, shaped, false);
                changed |= *m != *v;
                ser.append_pair(&k, &m);
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
        self.body_as(content_type, body, false)
    }

    /// Like [`Redactor::body`], but masked values keep their [`shape`].
    pub fn body_shaped<'a>(&self, content_type: Option<&str>, body: &'a str) -> Cow<'a, str> {
        self.body_as(content_type, body, true)
    }

    fn body_as<'a>(&self, content_type: Option<&str>, body: &'a str, shaped: bool) -> Cow<'a, str> {
        if !self.enabled {
            return Cow::Borrowed(body);
        }
        let ct = content_type.unwrap_or("").to_ascii_lowercase();
        if ct.starts_with("application/x-www-form-urlencoded") {
            return Cow::Owned(self.query_as(body, shaped).into_owned());
        }
        let after_fields: Cow<'a, str> = match &self.json_fields {
            Some(re) if ct.contains("json") || body.trim_start().starts_with('{') => {
                let rep = |c: &regex::Captures| {
                    let raw = c[2].strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(&c[2]);
                    let m = mask_value(raw, shaped, false);
                    format!("{}{}", &c[1], serde_json::Value::String(m))
                };
                match re.replace_all(body, rep) {
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

/// Words kept by [`shape`]: the vocabulary of SQL injection, XSS, command
/// and path attacks. Everything else in a word becomes `a`.
const SHAPE_KEYWORDS: &[&str] = &[
    "select", "union", "all", "insert", "update", "delete", "drop", "from", "where", "or", "and",
    "not", "null", "like", "having", "order", "group", "by", "limit", "into", "values", "exec",
    "execute", "sleep", "benchmark", "waitfor", "delay", "case", "when", "then", "else", "end",
    "concat", "char", "chr", "ascii", "substring", "information", "schema", "table", "tables",
    "load", "file", "outfile", "xp", "cmdshell", "script", "javascript", "alert", "prompt", "eval",
    "onerror", "onload", "img", "svg", "iframe", "src", "document", "cookie", "etc", "passwd",
    "bin", "sh", "bash", "cmd", "curl", "wget", "true", "false",
];

/// Longest shape kept, in bytes.
const SHAPE_MAX: usize = 160;

/// A masked value's structure without its content: every run of letters
/// becomes `a` (unless it is an attack keyword, kept in upper case), every
/// run of digits `9`, and punctuation and spaces are kept. A session token
/// `f3Kx9_q2` becomes `a9a9_a9`; an injection `1' or 1=1--` becomes
/// `9' OR 9=9--`. Secret entropy is gone, attack syntax stays.
pub fn shape(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars().peekable();
    while let Some(&c) = chars.peek() {
        if out.len() >= SHAPE_MAX {
            out.push('…');
            break;
        }
        if c.is_alphabetic() {
            let mut word = String::new();
            while let Some(&c) = chars.peek().filter(|c| c.is_alphabetic()) {
                word.push(c);
                chars.next();
            }
            let lower = word.to_lowercase();
            if SHAPE_KEYWORDS.contains(&lower.as_str()) {
                out.push_str(&lower.to_uppercase());
            } else {
                out.push('a');
            }
        } else if c.is_numeric() {
            while chars.peek().is_some_and(|c| c.is_numeric()) {
                chars.next();
            }
            out.push('9');
        } else {
            chars.next();
            out.push(if c.is_control() { ' ' } else { c });
        }
    }
    out
}

/// The masked form of a sensitive value. A value that is already masked (a
/// stored event redacted again on its way to the AI or a dataset) keeps its
/// mask, with any shape normalized again so that a crafted look-alike cannot
/// smuggle text through.
fn mask_value(value: &str, shaped: bool, with_len: bool) -> String {
    if let Some(rest) = value.strip_prefix(MASK) {
        if rest.is_empty() {
            return MASK.to_string();
        }
        if let Some(rest) = rest.strip_prefix(" len=") {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            let tail = &rest[digits.len()..];
            if !digits.is_empty() && digits.len() < 10 {
                if tail.is_empty() {
                    return format!("{MASK} len={digits}");
                }
                if let Some(sh) = tail.strip_prefix(" shape=") {
                    return format!("{MASK} len={digits} shape={}", shape(sh));
                }
            }
        }
    }
    if shaped {
        format!("{MASK} len={} shape={}", value.len(), shape(value))
    } else if with_len {
        format!("{MASK} len={}", value.len())
    } else {
        MASK.to_string()
    }
}

/// True when `s` holds a masked value with or without a shape.
pub fn contains_mask(s: &str) -> bool {
    s.contains(MASK) || s.contains("%5BREDACTED%5D")
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

    #[test]
    fn shape_keeps_attack_syntax_and_drops_content() {
        assert_eq!(shape("1' or 1=1--"), "9' OR 9=9--");
        assert_eq!(shape("f3Kx9_q2"), "a9a9_a9");
        assert_eq!(shape("x' UNION SELECT pass FROM users"), "a' UNION SELECT a FROM a");
        assert!(shape(&"ab1".repeat(200)).ends_with('…'));
    }

    #[test]
    fn shaped_query_keeps_shape_and_plain_query_does_not() {
        let q = "session_id=abc123%27+or+1%3D1--&q=shoes";
        assert_eq!(r().query(q), "session_id=%5BREDACTED%5D&q=shoes");
        let shaped = r().query_shaped(q).into_owned();
        let pairs: Vec<(String, String)> =
            form_urlencoded::parse(shaped.as_bytes()).into_owned().collect();
        assert_eq!(pairs[0].1, "[REDACTED] len=16 shape=a9' OR 9=9--");
        assert_eq!(pairs[1].1, "shoes");
    }

    #[test]
    fn redacting_again_keeps_the_shape_but_normalizes_it() {
        let once = r().query_shaped("token=a1'+or+1=1").into_owned();
        // A second, plain pass (AI input, dataset export) keeps the shape.
        assert_eq!(r().query(&once), once);
        // A crafted look-alike cannot carry text through.
        let crafted = "token=%5BREDACTED%5D+len%3D3+shape%3Dsecret+text";
        let pairs: Vec<(String, String)> =
            form_urlencoded::parse(r().query(crafted).as_bytes()).into_owned().collect();
        assert_eq!(pairs[0].1, "[REDACTED] len=3 shape=a a");
    }

    #[test]
    fn shaped_json_and_header() {
        let b = r().body_shaped(Some("application/json"), r#"{"password":"x' or 1=1","n":1}"#);
        assert_eq!(b, r#"{"password":"[REDACTED] len=9 shape=a' OR 9=9","n":1}"#);
        assert_eq!(r().header_shaped("cookie", "sid=1;x"), "[REDACTED] len=7 shape=a=9;a");
        assert_eq!(r().header("cookie", &r().header("cookie", "a=b")), "[REDACTED] len=3");
    }
}
