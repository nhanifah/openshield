use std::borrow::Cow;

use super::{AccessLogEntry, AuditLogEntry, Formatter};

/// Make a value safe for one line of a text log: escape control characters
/// (so a value cannot start a new, forged log line) and cut it to at most
/// `max` bytes on a character boundary.
pub fn text_safe(value: &str, max: usize) -> Cow<'_, str> {
    let cut = if value.len() > max {
        let mut end = max;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        &value[..end]
    } else {
        value
    };
    if !cut.chars().any(char::is_control) && cut.len() == value.len() {
        return Cow::Borrowed(value);
    }
    let mut out = String::with_capacity(cut.len() + 8);
    for c in cut.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
            c => out.push(c),
        }
    }
    if cut.len() < value.len() {
        out.push_str("...");
    }
    Cow::Owned(out)
}

const FIELD_MAX: usize = 8192;

/// JSON formatter: one JSON object per line.
pub struct JsonFormatter;

impl Formatter for JsonFormatter {
    fn format_access(&self, entry: &AccessLogEntry) -> Vec<u8> {
        let mut buf = serde_json::to_vec(entry).unwrap_or_default();
        buf.push(b'\n');
        buf
    }

    fn format_audit(&self, entry: &AuditLogEntry) -> Vec<u8> {
        let mut buf = serde_json::to_vec(entry).unwrap_or_default();
        buf.push(b'\n');
        buf
    }
}

/// Human-readable text formatter.
pub struct TextFormatter;

impl Formatter for TextFormatter {
    fn format_access(&self, entry: &AccessLogEntry) -> Vec<u8> {
        let err = entry
            .error
            .as_ref()
            .map(|e| format!(" error={}", text_safe(e, FIELD_MAX)))
            .unwrap_or_default();
        format!(
            "{} [{}] {} {} {} -> {} {:.3}ms{err}\n",
            entry.timestamp,
            entry.request_id,
            entry.client_ip,
            text_safe(&entry.method, 32),
            text_safe(&entry.path, FIELD_MAX),
            entry.status,
            entry.duration_ms,
        )
        .into_bytes()
    }

    fn format_audit(&self, entry: &AuditLogEntry) -> Vec<u8> {
        let mut buf = format!(
            "[AUDIT] {} [{}] action={} rules=[{}] scores=[{}]\n",
            entry.timestamp,
            entry.request_id,
            entry.waf_action,
            entry
                .waf_matched_rules
                .iter()
                .map(|r| format!("{}:{}", text_safe(&r.id, 256), r.action))
                .collect::<Vec<_>>()
                .join(","),
            entry
                .waf_scores
                .iter()
                .map(|(k, v)| format!("{}={v}", text_safe(k, 256)))
                .collect::<Vec<_>>()
                .join(","),
        );
        for (k, v) in &entry.waf_payloads {
            let v = v.to_string();
            buf.push_str(&format!(
                "  payload.{}: {}\n",
                text_safe(k, 256),
                text_safe(&v, FIELD_MAX)
            ));
        }
        for (k, v) in &entry.request.headers {
            buf.push_str(&format!(
                "  req.{}: {}\n",
                text_safe(k, 256),
                text_safe(v, FIELD_MAX)
            ));
        }
        if let Some(ref body) = entry.request.body {
            buf.push_str(&format!("  req.body: {}\n", text_safe(body, 500)));
        }
        if let Some(ref resp) = entry.response {
            for (k, v) in &resp.headers {
                buf.push_str(&format!(
                    "  resp.{}: {}\n",
                    text_safe(k, 256),
                    text_safe(v, FIELD_MAX)
                ));
            }
        }
        buf.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::text_safe;

    #[test]
    fn cuts_on_a_char_boundary() {
        // Regression: `&body[..500]` panicked when byte 500 fell inside a
        // multi-byte character.
        let s = format!("{}é tail", "a".repeat(499));
        let out = text_safe(&s, 500);
        assert!(out.ends_with("a..."), "{out}");
        assert!(out.len() <= 503);
    }

    #[test]
    fn escapes_newlines_so_lines_cannot_be_forged() {
        let out = text_safe("x\n[AUDIT] forged\r\u{1b}[31m", 100);
        assert_eq!(out, "x\\n[AUDIT] forged\\r\\u{001b}[31m");
        assert!(!out.contains('\n'));
    }

    #[test]
    fn plain_values_are_borrowed() {
        assert!(matches!(text_safe("GET /a", 100), std::borrow::Cow::Borrowed(_)));
    }
}
