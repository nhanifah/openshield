use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use log::{debug, warn};
use sha1::Sha1;

use crate::config::ChallengeConfig;

type HmacSha1 = Hmac<Sha1>;

pub struct ChallengeManager {
    config: ChallengeConfig,
    challenge_page: String,
    /// Shared client: connection reuse, and a bounded wait on Cloudflare.
    client: reqwest::Client,
}

/// Fields of the form the challenge page posts back.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct VerificationForm {
    pub token: Option<String>,
    pub redirect: Option<String>,
}

impl VerificationForm {
    /// Parse the `application/x-www-form-urlencoded` body of a verification
    /// POST.
    pub fn parse(body: &[u8]) -> Self {
        let mut form = Self::default();
        for (k, v) in form_urlencoded::parse(body) {
            match &*k {
                "cf-turnstile-response" => form.token = Some(v.into_owned()),
                "redirect" => form.redirect = Some(v.into_owned()),
                _ => {}
            }
        }
        form
    }
}

impl ChallengeManager {
    pub fn new(config: &ChallengeConfig) -> Self {
        let challenge_page = if let Some(ref path) = config.custom_page {
            let html = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("Failed to read challenge page {:?}: {}", path, e));
            html.replace("{{turnstile_site_key}}", &config.turnstile_site_key)
                .replace("{{challenge_path}}", &config.challenge_path)
        } else {
            default_challenge_page(&config.turnstile_site_key, &config.challenge_path)
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.turnstile_timeout_ms))
            .connect_timeout(std::time::Duration::from_millis(
                config.turnstile_timeout_ms.min(3000),
            ))
            .build()
            .expect("failed to build HTTP client");
        Self {
            config: config.clone(),
            challenge_page,
            client,
        }
    }

    /// Check if the request has a valid challenge cookie.
    pub fn is_verified(&self, cookie_header: Option<&str>, client_ip: &str) -> bool {
        let Some(cookie_header) = cookie_header else {
            return false;
        };
        let Some(token) = extract_cookie(cookie_header, &self.config.cookie_name) else {
            return false;
        };
        self.verify_cookie(token, client_ip)
    }

    /// Return the challenge HTML page.
    pub fn challenge_page(&self) -> &str {
        &self.challenge_page
    }

    /// Return the challenge POST path.
    pub fn challenge_path(&self) -> &str {
        &self.config.challenge_path
    }

    /// True for the POST the challenge page sends back for verification.
    pub fn is_verification_request(&self, method: &str, path: &str) -> bool {
        method == "POST" && path == self.config.challenge_path
    }

    /// Verify a Turnstile token with Cloudflare's API.
    pub async fn verify_turnstile(&self, token: &str, client_ip: &str) -> bool {
        let resp = self
            .client
            .post(&self.config.turnstile_verify_url)
            .form(&[
                ("secret", self.config.turnstile_secret_key.as_str()),
                ("response", token),
                ("remoteip", client_ip),
            ])
            .send()
            .await;

        match resp {
            Ok(r) => {
                if let Ok(body) = r.json::<serde_json::Value>().await {
                    let success = body
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if !success {
                        debug!("Turnstile verification failed: {:?}", body);
                    }
                    success
                } else {
                    warn!("Failed to parse Turnstile response");
                    false
                }
            }
            Err(e) => {
                warn!("Turnstile API request failed: {}", e);
                false
            }
        }
    }

    /// Create a signed challenge cookie value.
    pub fn create_cookie(&self, client_ip: &str) -> String {
        let ts = now_secs();
        let payload = format!("{client_ip}|{ts}");
        let sig = hmac_sign(&self.config.cookie_secret, payload.as_bytes());
        let value = format!("{payload}|{sig}");
        let encoded = base64_url_encode(value.as_bytes());
        let name = &self.config.cookie_name;
        format!(
            "{name}={encoded}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
            self.config.cookie_ttl
        )
    }

    fn verify_cookie(&self, encoded: &str, client_ip: &str) -> bool {
        let Ok(decoded) = base64_url_decode(encoded) else {
            return false;
        };
        let Ok(value) = std::str::from_utf8(&decoded) else {
            return false;
        };

        let parts: Vec<&str> = value.splitn(3, '|').collect();
        if parts.len() != 3 {
            return false;
        }
        let (ip, ts_str, sig) = (parts[0], parts[1], parts[2]);

        if ip != client_ip {
            return false;
        }

        let Ok(ts) = ts_str.parse::<u64>() else {
            return false;
        };
        if now_secs().saturating_sub(ts) > self.config.cookie_ttl {
            return false;
        }

        let payload = format!("{ip}|{ts_str}");
        let expected_sig = hmac_sign(&self.config.cookie_secret, payload.as_bytes());
        constant_time_eq(sig.as_bytes(), expected_sig.as_bytes())
    }
}

/// Where to send the client after a passed challenge.
///
/// Only same-site targets are allowed: a path (`/a?b`), or an absolute URL
/// whose host equals the request's `Host`, reduced to its path. Anything
/// else (other hosts, `//host`, `/\\host`, other schemes, control
/// characters) becomes `/`, so the challenge cannot be used as an open
/// redirect.
pub fn safe_redirect(target: Option<&str>, request_host: &str) -> String {
    let Some(target) = target else {
        return "/".into();
    };
    if target.is_empty() || target.chars().any(|c| c.is_control() || c == '\\') {
        return "/".into();
    }
    if target.starts_with('/') {
        if target.starts_with("//") {
            return "/".into();
        }
        return target.to_string();
    }
    let rest = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"));
    let Some(rest) = rest else {
        return "/".into();
    };
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.contains('@') || !authority.eq_ignore_ascii_case(request_host) {
        return "/".into();
    }
    if path.starts_with('/') {
        if path.starts_with("//") {
            return "/".into();
        }
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hmac_sign(key: &str, data: &[u8]) -> String {
    let mut mac = HmacSha1::new_from_slice(key.as_bytes()).unwrap();
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data)
}

fn extract_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(name) {
            if let Some(value) = value.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}

fn default_challenge_page(site_key: &str, challenge_path: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Security Check</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
            color: #333;
        }}
        .container {{
            text-align: center;
            padding: 2rem;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{ font-size: 1.5rem; margin-bottom: 1rem; }}
        p {{ color: #666; margin-bottom: 1.5rem; }}
        .cf-turnstile {{ display: inline-block; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Check</h1>
        <p>Please verify you are human to continue.</p>
        <form method="POST" action="{challenge_path}">
            <div class="cf-turnstile" data-sitekey="{site_key}" data-callback="onSuccess"></div>
            <input type="hidden" name="redirect" id="redirect">
        </form>
    </div>
    <script>
        document.getElementById('redirect').value = window.location.href;
        function onSuccess(token) {{
            document.querySelector('form').submit();
        }}
    </script>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::safe_redirect;

    #[test]
    fn same_site_targets_are_kept() {
        assert_eq!(safe_redirect(Some("/account?x=1"), "app.test"), "/account?x=1");
        assert_eq!(
            safe_redirect(Some("https://app.test/cart?id=2"), "app.test"),
            "/cart?id=2"
        );
        assert_eq!(safe_redirect(Some("http://APP.test"), "app.test"), "/");
        assert_eq!(safe_redirect(Some("https://app.test:8443/a"), "app.test:8443"), "/a");
        assert_eq!(safe_redirect(Some("https://app.test?q"), "app.test"), "/?q");
    }

    #[test]
    fn foreign_and_tricky_targets_fall_back_to_root() {
        for t in [
            "https://evil.test/",
            "//evil.test/x",
            "/\\evil.test",
            "javascript:alert(1)",
            "https://app.test@evil.test/",
            "https://evil.test/app.test",
            "https://app.test//evil.test",
            "/a\r\nSet-Cookie: x=1",
            "",
        ] {
            assert_eq!(safe_redirect(Some(t), "app.test"), "/", "{t}");
        }
        assert_eq!(safe_redirect(None, "app.test"), "/");
    }
}
