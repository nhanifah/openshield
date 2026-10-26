//! Pages the proxy sends instead of the site: blocks, rate limits, upstream
//! failures and the challenge.
//!
//! One built-in layout (English or Indonesian, light and dark, no
//! JavaScript, no external requests) with the site's name, support contact
//! and accent colour, or a custom HTML template per page. Every value put
//! into a page is HTML-escaped, and pages are served with a CSP that allows
//! no scripts, so a template cannot run code in visitors' browsers.
//!
//! Clients that ask for JSON (`Accept: application/json` without
//! `text/html`) get `{"error", "message", "status", "request_id"}`; other
//! non-browser clients get plain text.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Response headers for HTML error pages.
pub const PAGE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; \
                            base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const MAX_TEMPLATE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PageKind {
    /// 403 from a rule or a dynamic IP block.
    #[default]
    Blocked,
    /// 403 from a geo or network (ASN) rule.
    Geo,
    /// 429.
    RateLimited,
    /// 413 and 431.
    TooLarge,
    /// 400.
    BadRequest,
    /// 502, 503, 504: the site behind the proxy is down or slow.
    Unavailable,
    /// Anything else (500 and other codes).
    Error,
    /// The Turnstile challenge (text only; the widget is added).
    Challenge,
}

impl PageKind {
    pub const ALL: [PageKind; 8] = [
        PageKind::Blocked,
        PageKind::Geo,
        PageKind::RateLimited,
        PageKind::TooLarge,
        PageKind::BadRequest,
        PageKind::Unavailable,
        PageKind::Error,
        PageKind::Challenge,
    ];

    pub fn for_status(status: u16) -> Self {
        match status {
            403 => PageKind::Blocked,
            429 => PageKind::RateLimited,
            413 | 431 => PageKind::TooLarge,
            400 => PageKind::BadRequest,
            502..=504 => PageKind::Unavailable,
            _ => PageKind::Error,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PageKind::Blocked => "blocked",
            PageKind::Geo => "geo",
            PageKind::RateLimited => "rate_limited",
            PageKind::TooLarge => "too_large",
            PageKind::BadRequest => "bad_request",
            PageKind::Unavailable => "unavailable",
            PageKind::Error => "error",
            PageKind::Challenge => "challenge",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    #[default]
    En,
    Id,
}

/// Text and template for one kind of page; empty fields use the defaults.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PageOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// A whole HTML document with `{{placeholders}}`; see `PLACEHOLDERS`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
}

/// Policy key `error_pages`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ErrorPagesConfig {
    pub language: Language,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support_url: Option<String>,
    /// `#rrggbb`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<String>,
    pub show_request_id: bool,
    pub show_client_ip: bool,
    pub show_powered_by: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub pages: BTreeMap<PageKind, PageOverride>,
}

impl Default for ErrorPagesConfig {
    fn default() -> Self {
        Self {
            language: Language::En,
            site_name: None,
            support_email: None,
            support_url: None,
            accent_color: None,
            show_request_id: true,
            show_client_ip: true,
            show_powered_by: false,
            pages: BTreeMap::new(),
        }
    }
}

/// Placeholders a custom template may use; values are HTML-escaped.
pub const PLACEHOLDERS: &[&str] = &[
    "status",
    "status_text",
    "title",
    "message",
    "request_id",
    "client_ip",
    "time",
    "site_name",
    "support_email",
    "support_url",
];

fn plain(s: &str, max: usize, what: &str) -> Result<(), String> {
    if s.chars().count() > max {
        return Err(format!("{what} is longer than {max} characters"));
    }
    if s.chars().any(|c| c.is_control() && c != '\n') {
        return Err(format!("{what} contains control characters"));
    }
    Ok(())
}

impl ErrorPagesConfig {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(s) = &self.site_name {
            plain(s, 80, "site name")?;
        }
        if let Some(e) = &self.support_email {
            let ok = e.len() <= 254
                && e.split_once('@').is_some_and(|(u, d)| !u.is_empty() && d.contains('.') && !d.starts_with('.'))
                && !e.chars().any(|c| c.is_whitespace() || "<>\"'()".contains(c));
            if !ok {
                return Err("support email is not an email address".into());
            }
        }
        if let Some(u) = &self.support_url
            && (!(u.starts_with("https://") || u.starts_with("http://"))
                || u.len() > 500
                || u.chars().any(|c| c.is_whitespace() || "<>\"'".contains(c)))
        {
            return Err("support URL must be an http(s) address".into());
        }
        if let Some(c) = &self.accent_color
            && !(c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|x| x.is_ascii_hexdigit()))
        {
            return Err("accent colour must look like #2563eb".into());
        }
        for (k, p) in &self.pages {
            if let Some(t) = &p.title {
                plain(t, 120, &format!("{} title", k.as_str()))?;
            }
            if let Some(m) = &p.message {
                plain(m, 600, &format!("{} message", k.as_str()))?;
            }
            if let Some(h) = &p.html {
                if h.len() > MAX_TEMPLATE {
                    return Err(format!("{} template is larger than 64 KB", k.as_str()));
                }
                if *k == PageKind::Challenge && !h.contains("{{challenge_widget}}") {
                    return Err("the challenge template must contain {{challenge_widget}}".into());
                }
            }
        }
        Ok(())
    }

    fn texts(&self, kind: PageKind) -> (String, String) {
        let (t, m) = default_text(self.language, kind);
        let o = self.pages.get(&kind);
        (
            o.and_then(|p| p.title.clone()).filter(|s| !s.trim().is_empty()).unwrap_or_else(|| t.to_string()),
            o.and_then(|p| p.message.clone()).filter(|s| !s.trim().is_empty()).unwrap_or_else(|| m.to_string()),
        )
    }
}

fn default_text(lang: Language, kind: PageKind) -> (&'static str, &'static str) {
    use Language::*;
    use PageKind::*;
    match (lang, kind) {
        (En, Blocked) => ("Access denied", "This request was stopped by the site's security system. If you believe this is a mistake, contact the site owner and include the request ID below."),
        (En, Geo) => ("Not available in your region", "This site can't be reached from your location or network. If you need access, contact the site owner and include the request ID below."),
        (En, RateLimited) => ("Too many requests", "You've sent a lot of requests in a short time. Please wait a minute, then try again."),
        (En, TooLarge) => ("Request too large", "The request sent to this site was larger than it accepts. Try a smaller file, or clear this site's cookies and try again."),
        (En, BadRequest) => ("Bad request", "The site couldn't understand this request. Reload the page and try again."),
        (En, Unavailable) => ("Temporarily unavailable", "The site isn't responding right now. This is usually brief, so please try again in a few minutes."),
        (En, Error) => ("Something went wrong", "The site couldn't complete this request. Please try again later."),
        (En, Challenge) => ("Checking your browser", "This quick check keeps the site safe from automated traffic. It only takes a moment."),
        (Id, Blocked) => ("Akses ditolak", "Permintaan ini dihentikan oleh sistem keamanan situs. Jika menurut Anda ini keliru, hubungi pemilik situs dan sertakan ID permintaan di bawah."),
        (Id, Geo) => ("Tidak tersedia di wilayah Anda", "Situs ini tidak dapat diakses dari lokasi atau jaringan Anda. Jika Anda memerlukan akses, hubungi pemilik situs dan sertakan ID permintaan di bawah."),
        (Id, RateLimited) => ("Terlalu banyak permintaan", "Anda mengirim banyak permintaan dalam waktu singkat. Tunggu sebentar, lalu coba lagi."),
        (Id, TooLarge) => ("Permintaan terlalu besar", "Permintaan yang dikirim melebihi batas yang diterima situs ini. Coba berkas yang lebih kecil, atau hapus cookie situs ini lalu coba lagi."),
        (Id, BadRequest) => ("Permintaan tidak valid", "Situs tidak dapat memahami permintaan ini. Muat ulang halaman, lalu coba lagi."),
        (Id, Unavailable) => ("Sedang tidak tersedia", "Situs sedang tidak merespons. Biasanya hanya sebentar, silakan coba lagi beberapa menit lagi."),
        (Id, Error) => ("Terjadi kesalahan", "Situs tidak dapat menyelesaikan permintaan ini. Silakan coba lagi nanti."),
        (Id, Challenge) => ("Memeriksa browser Anda", "Pemeriksaan singkat ini melindungi situs dari lalu lintas otomatis. Hanya sebentar."),
    }
}

fn labels(lang: Language) -> [&'static str; 6] {
    // request id, your ip, time, need help, contact, protected by
    match lang {
        Language::En => ["Request ID", "Your IP", "Time", "Need help?", "Contact support", "Protected by OpenShield"],
        Language::Id => ["ID permintaan", "IP Anda", "Waktu", "Butuh bantuan?", "Hubungi dukungan", "Dilindungi oleh OpenShield"],
    }
}

fn status_text(status: u16) -> &'static str {
    http_reason(status).unwrap_or("Error")
}

fn http_reason(status: u16) -> Option<&'static str> {
    Some(match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        418 => "I'm a teapot",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => return None,
    })
}

/// What to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub content_type: &'static str,
    pub body: String,
    /// Set for HTML pages.
    pub csp: Option<&'static str>,
}

/// The details of one failed request.
pub struct PageContext<'a> {
    pub status: u16,
    pub kind: PageKind,
    pub request_id: &'a str,
    pub client_ip: Option<&'a str>,
    /// Unix seconds.
    pub now: i64,
}

fn esc(s: &str) -> String {
    html_escape::encode_quoted_attribute(s).into_owned()
}

#[derive(PartialEq, Eq)]
enum Format {
    Html,
    Json,
    Text,
}

fn format_for(accept: Option<&str>) -> Format {
    let a = accept.unwrap_or("").to_ascii_lowercase();
    if a.contains("text/html") || a.contains("application/xhtml") {
        Format::Html
    } else if a.contains("application/json") || a.contains("+json") {
        Format::Json
    } else {
        // Browsers always list text/html; curl and most libraries send */*.
        Format::Text
    }
}

impl ErrorPagesConfig {
    /// Render a page for `cx`, in the format the client asked for.
    pub fn render(&self, cx: &PageContext<'_>, accept: Option<&str>) -> Rendered {
        let (title, message) = self.texts(cx.kind);
        match format_for(accept) {
            Format::Json => Rendered {
                content_type: "application/json",
                body: serde_json::json!({
                    "error": title, "message": message, "status": cx.status,
                    "request_id": if self.show_request_id { Some(cx.request_id) } else { None },
                })
                .to_string(),
                csp: None,
            },
            Format::Text => {
                let mut b = format!("{} {}\n{}\n{}\n", cx.status, status_text(cx.status), title, message);
                if self.show_request_id {
                    b.push_str(&format!("Request ID: {}\n", cx.request_id));
                }
                Rendered { content_type: "text/plain; charset=utf-8", body: b, csp: None }
            }
            Format::Html => Rendered {
                content_type: "text/html; charset=utf-8",
                body: self.html(cx, &title, &message, None),
                csp: Some(PAGE_CSP),
            },
        }
    }

    /// The challenge page: the layout around the Turnstile widget. The page
    /// needs Turnstile's script, so it is served without `PAGE_CSP`.
    pub fn challenge_html(&self, site_key: &str, challenge_path: &str) -> String {
        let (title, message) = self.texts(PageKind::Challenge);
        let widget = format!(
            r#"<form method="POST" action="{}" class="os-challenge"><div class="cf-turnstile" data-sitekey="{}" data-callback="onSuccess"></div><input type="hidden" name="redirect" id="redirect"></form>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<script>document.getElementById('redirect').value = window.location.href; function onSuccess() {{ document.querySelector('form.os-challenge').submit(); }}</script>"#,
            esc(challenge_path),
            esc(site_key)
        );
        let cx = PageContext { status: 403, kind: PageKind::Challenge, request_id: "", client_ip: None, now: 0 };
        self.html(&cx, &title, &message, Some(&widget))
    }

    fn html(&self, cx: &PageContext<'_>, title: &str, message: &str, widget: Option<&str>) -> String {
        let time = chrono::DateTime::from_timestamp(cx.now, 0)
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_default();
        let site = self.site_name.clone().unwrap_or_default();
        if let Some(tpl) = self.pages.get(&cx.kind).and_then(|p| p.html.as_deref()).filter(|t| !t.trim().is_empty()) {
            let vals: [(&str, String); 10] = [
                ("status", cx.status.to_string()),
                ("status_text", status_text(cx.status).to_string()),
                ("title", title.to_string()),
                ("message", message.to_string()),
                ("request_id", cx.request_id.to_string()),
                ("client_ip", cx.client_ip.unwrap_or("").to_string()),
                ("time", time.clone()),
                ("site_name", site.clone()),
                ("support_email", self.support_email.clone().unwrap_or_default()),
                ("support_url", self.support_url.clone().unwrap_or_default()),
            ];
            let mut out = tpl.to_string();
            for (k, v) in vals {
                out = out.replace(&format!("{{{{{k}}}}}"), &esc(&v));
            }
            if let Some(w) = widget {
                out = out.replace("{{challenge_widget}}", w);
            }
            return out;
        }

        let l = labels(self.language);
        let lang = if self.language == Language::Id { "id" } else { "en" };
        let accent = self.accent_color.as_deref().unwrap_or("#2563eb");
        let mut details = String::new();
        if widget.is_none() {
            if self.show_request_id && !cx.request_id.is_empty() {
                details.push_str(&format!("<dt>{}</dt><dd class=\"mono\">{}</dd>", l[0], esc(cx.request_id)));
            }
            if self.show_client_ip
                && let Some(ip) = cx.client_ip
            {
                details.push_str(&format!("<dt>{}</dt><dd class=\"mono\">{}</dd>", l[1], esc(ip)));
            }
            if !time.is_empty() {
                details.push_str(&format!("<dt>{}</dt><dd>{}</dd>", l[2], esc(&time)));
            }
        }
        let details = if details.is_empty() { String::new() } else { format!("<dl>{details}</dl>") };
        let mut help = Vec::new();
        if let Some(e) = &self.support_email {
            help.push(format!("<a href=\"mailto:{}\">{}</a>", esc(e), esc(e)));
        }
        if let Some(u) = &self.support_url {
            help.push(format!("<a href=\"{}\" rel=\"noopener\">{}</a>", esc(u), l[4]));
        }
        let help = if help.is_empty() || widget.is_some() {
            String::new()
        } else {
            format!("<p class=\"help\">{} {}</p>", l[3], help.join(" · "))
        };
        let brand = if site.is_empty() { String::new() } else { format!("<div class=\"brand\">{}</div>", esc(&site)) };
        let code = if widget.is_some() { String::new() } else { format!("<div class=\"code\">{} · {}</div>", cx.status, status_text(cx.status)) };
        let powered = if self.show_powered_by { format!("<footer>{}</footer>", l[5]) } else { String::new() };
        let page_title = if site.is_empty() { esc(title) } else { format!("{} · {}", esc(title), esc(&site)) };
        format!(
            r#"<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{page_title}</title>
<style>
:root {{ --accent: {accent}; --bg: #f6f7f9; --card: #ffffff; --text: #111827; --muted: #4b5563; --line: #e5e7eb; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg: #0f1318; --card: #171c23; --text: #e8ecf1; --muted: #a3adba; --line: #2a313b; }} }}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; height: 100%; }}
body {{ background: var(--bg); color: var(--text); font: 16px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; display: flex; align-items: center; justify-content: center; padding: 24px 16px; }}
main {{ width: 100%; max-width: 520px; background: var(--card); border: 1px solid var(--line); border-top: 4px solid var(--accent); border-radius: 12px; padding: 32px 28px; }}
.brand {{ font-weight: 600; font-size: 14px; color: var(--muted); margin-bottom: 20px; }}
.code {{ font-size: 13px; font-weight: 600; letter-spacing: .02em; color: var(--accent); text-transform: uppercase; }}
h1 {{ font-size: 24px; line-height: 1.25; margin: 6px 0 10px; }}
p {{ margin: 0 0 16px; color: var(--muted); }}
dl {{ display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 20px 0 0; padding: 14px 16px; border: 1px solid var(--line); border-radius: 8px; font-size: 14px; }}
dt {{ color: var(--muted); }}
dd {{ margin: 0; overflow-wrap: anywhere; }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }}
.help {{ margin: 18px 0 0; font-size: 14px; }}
a {{ color: var(--accent); }}
.os-challenge {{ margin-top: 20px; min-height: 70px; }}
footer {{ margin-top: 24px; font-size: 12px; color: var(--muted); }}
</style>
</head>
<body>
<main>
{brand}{code}<h1>{title}</h1>
<p>{message}</p>
{widget}{details}{help}{powered}
</main>
</body>
</html>
"#,
            title = esc(title),
            message = esc(message),
            widget = widget.unwrap_or(""),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cx(kind: PageKind, status: u16) -> PageContext<'static> {
        PageContext { status, kind, request_id: "req-1", client_ip: Some("203.0.113.9"), now: 1_767_225_600 }
    }

    #[test]
    fn format_follows_accept() {
        let c = ErrorPagesConfig::default();
        let html = c.render(&cx(PageKind::Blocked, 403), Some("text/html,application/xhtml+xml,*/*;q=0.8"));
        assert!(html.content_type.starts_with("text/html") && html.csp.is_some());
        assert!(html.body.contains("Access denied") && html.body.contains("req-1") && html.body.contains("203.0.113.9"));
        let json = c.render(&cx(PageKind::Blocked, 403), Some("application/json"));
        let v: serde_json::Value = serde_json::from_str(&json.body).unwrap();
        assert_eq!((v["status"].as_u64(), v["request_id"].as_str()), (Some(403), Some("req-1")));
        let text = c.render(&cx(PageKind::Unavailable, 502), Some("*/*"));
        assert!(text.body.starts_with("502 Bad Gateway\nTemporarily unavailable"));
        assert!(c.render(&cx(PageKind::Blocked, 403), None).content_type.starts_with("text/plain"));
    }

    #[test]
    fn branding_language_and_overrides() {
        let mut c = ErrorPagesConfig {
            language: Language::Id,
            site_name: Some("Kartu <Kenangan>".into()),
            support_email: Some("halo@kartukenangan.id".into()),
            accent_color: Some("#e11d48".into()),
            ..Default::default()
        };
        c.pages.insert(PageKind::Geo, PageOverride { title: Some("Hanya untuk Indonesia".into()), ..Default::default() });
        let b = c.render(&cx(PageKind::Geo, 403), Some("text/html")).body;
        assert!(b.contains("Hanya untuk Indonesia") && b.contains("lang=\"id\"") && b.contains("#e11d48"));
        assert!(b.contains("Kartu &lt;Kenangan&gt;") && !b.contains("<Kenangan>"), "site name is escaped");
        assert!(b.contains("mailto:halo@kartukenangan.id") && b.contains("ID permintaan"));
        let blocked = c.render(&cx(PageKind::Blocked, 403), Some("text/html")).body;
        assert!(blocked.contains("Akses ditolak"));
    }

    #[test]
    fn custom_templates_escape_every_value() {
        let mut c = ErrorPagesConfig::default();
        c.pages.insert(PageKind::Blocked, PageOverride {
            message: Some("<script>alert(1)</script>".into()),
            html: Some("<h1>{{title}}</h1><p>{{message}}</p><code>{{request_id}}</code><i>{{status}} {{status_text}}</i>".into()),
            ..Default::default()
        });
        let r = c.render(&PageContext { request_id: "\"><img src=x>", ..cx(PageKind::Blocked, 403) }, Some("text/html"));
        assert!(r.body.contains("&lt;script&gt;") && !r.body.contains("<script>"));
        assert!(r.body.contains("&quot;&gt;&lt;img") && r.body.contains("403 Forbidden"));
        assert_eq!(r.csp, Some(PAGE_CSP), "custom pages still get the no-script CSP");
    }

    #[test]
    fn challenge_page_keeps_the_widget() {
        let c = ErrorPagesConfig { site_name: Some("Shop".into()), ..Default::default() };
        let h = c.challenge_html("site-key-1", "/__openshield/challenge");
        assert!(h.contains("data-sitekey=\"site-key-1\"") && h.contains("action=\"/__openshield/challenge\""));
        assert!(h.contains("Checking your browser") && h.contains("Shop"));
        let mut bad = ErrorPagesConfig::default();
        bad.pages.insert(PageKind::Challenge, PageOverride { html: Some("<p>no widget</p>".into()), ..Default::default() });
        assert!(bad.validate().is_err());
    }

    #[test]
    fn validation() {
        let ok = |f: &dyn Fn(&mut ErrorPagesConfig)| {
            let mut c = ErrorPagesConfig::default();
            f(&mut c);
            c.validate().is_ok()
        };
        assert!(ok(&|c| c.accent_color = Some("#2563eb".into())));
        assert!(!ok(&|c| c.accent_color = Some("red; background:url(x)".into())));
        assert!(!ok(&|c| c.support_url = Some("javascript:alert(1)".into())));
        assert!(!ok(&|c| c.support_email = Some("a@b".into())));
        assert!(!ok(&|c| c.site_name = Some("x".repeat(81))));
        assert!(ok(&|c| c.support_email = Some("halo@kartukenangan.id".into())));
    }

    #[test]
    fn status_maps_to_a_page() {
        assert_eq!(PageKind::for_status(429), PageKind::RateLimited);
        assert_eq!(PageKind::for_status(431), PageKind::TooLarge);
        assert_eq!(PageKind::for_status(504), PageKind::Unavailable);
        assert_eq!(PageKind::for_status(500), PageKind::Error);
    }
}
