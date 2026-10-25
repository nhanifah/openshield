//! Gemini API client (`models/{model}:generateContent`).
//!
//! The API key is read from an environment variable when the client is
//! built, sent in the `x-goog-api-key` header (never in the URL, where it
//! could end up in logs), and never logged or serialized.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::prompt;
use super::types::AiInput;

#[derive(Debug, Clone, PartialEq)]
pub enum ProviderError {
    Timeout,
    RateLimited,
    Server(u16),
    Client(u16, String),
    Network(String),
    /// The provider refused to answer (safety filter, empty candidate).
    Refused(String),
    BadResponse(String),
}

impl ProviderError {
    /// Errors worth retrying later, which count toward the circuit breaker.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            ProviderError::Timeout | ProviderError::RateLimited | ProviderError::Server(_) | ProviderError::Network(_)
        )
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderError::Timeout => write!(f, "timeout"),
            ProviderError::RateLimited => write!(f, "rate limited (429)"),
            ProviderError::Server(c) => write!(f, "server error {c}"),
            ProviderError::Client(c, m) => write!(f, "request rejected {c}: {m}"),
            ProviderError::Network(m) => write!(f, "network error: {m}"),
            ProviderError::Refused(m) => write!(f, "refused: {m}"),
            ProviderError::BadResponse(m) => write!(f, "bad response: {m}"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Completion {
    pub text: String,
    pub model_version: String,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub latency_ms: u64,
}

pub struct GeminiClient {
    http: reqwest::Client,
    base_url: String,
    model: String,
    api_key: String,
}

impl GeminiClient {
    pub fn new(base_url: &str, model: &str, api_key: String, timeout: Duration) -> Result<Self, String> {
        if api_key.trim().is_empty() {
            return Err("Gemini API key is empty".into());
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(5)))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            api_key,
        })
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Classify a batch of events with structured JSON output.
    pub async fn classify(&self, inputs: &[AiInput]) -> Result<Completion, ProviderError> {
        let body = json!({
            "systemInstruction": {"parts": [{"text": prompt::SYSTEM_INSTRUCTION}]},
            "contents": [{"role": "user", "parts": [{"text": prompt::user_content(inputs)}]}],
            "generationConfig": {
                "temperature": 0.0,
                "maxOutputTokens": 512 + 256 * inputs.len() as u64,
                "responseMimeType": "application/json",
                "responseSchema": prompt::response_schema(),
            }
        });
        self.generate(body).await
    }

    /// Free-text completion (incident summaries). The caller frames the data
    /// as untrusted.
    pub async fn complete(&self, system: &str, user: &str, max_tokens: u64) -> Result<Completion, ProviderError> {
        let body = json!({
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": max_tokens}
        });
        self.generate(body).await
    }

    async fn generate(&self, body: Value) -> Result<Completion, ProviderError> {
        let url = format!("{}/v1beta/models/{}:generateContent", self.base_url, self.model);
        let start = Instant::now();
        let resp = self
            .http
            .post(&url)
            .header("x-goog-api-key", &self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ProviderError::Timeout
                } else {
                    // reqwest errors can include the URL; it carries no key.
                    ProviderError::Network(e.without_url().to_string())
                }
            })?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| {
            if e.is_timeout() {
                ProviderError::Timeout
            } else {
                ProviderError::Network(e.without_url().to_string())
            }
        })?;
        let latency_ms = start.elapsed().as_millis() as u64;
        match status {
            200 => {}
            429 => return Err(ProviderError::RateLimited),
            500..=599 => return Err(ProviderError::Server(status)),
            _ => {
                let msg = serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|v| v["error"]["message"].as_str().map(str::to_string))
                    .unwrap_or_default();
                return Err(ProviderError::Client(status, super::sanitize::truncate(&msg, 200)));
            }
        }
        parse_response(&text, latency_ms)
    }
}

pub fn parse_response(text: &str, latency_ms: u64) -> Result<Completion, ProviderError> {
    let v: Value = serde_json::from_str(text).map_err(|e| ProviderError::BadResponse(e.to_string()))?;
    if let Some(reason) = v["promptFeedback"]["blockReason"].as_str() {
        return Err(ProviderError::Refused(reason.to_string()));
    }
    let cand = &v["candidates"][0];
    let parts = cand["content"]["parts"]
        .as_array()
        .ok_or_else(|| ProviderError::Refused(cand["finishReason"].as_str().unwrap_or("no content").to_string()))?;
    let text: String = parts.iter().filter_map(|p| p["text"].as_str()).collect();
    if text.is_empty() {
        return Err(ProviderError::Refused("empty text".into()));
    }
    Ok(Completion {
        text,
        model_version: v["modelVersion"].as_str().unwrap_or("").to_string(),
        tokens_in: v["usageMetadata"]["promptTokenCount"].as_u64().unwrap_or(0),
        tokens_out: v["usageMetadata"]["candidatesTokenCount"].as_u64().unwrap_or(0),
        latency_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_text_usage_and_version() {
        let body = r#"{"candidates":[{"content":{"parts":[{"text":"{\"results\":"},{"text":"[]}"}]},"finishReason":"STOP"}],
                      "usageMetadata":{"promptTokenCount":120,"candidatesTokenCount":30},"modelVersion":"m-001"}"#;
        let c = parse_response(body, 5).unwrap();
        assert_eq!(c.text, "{\"results\":[]}");
        assert_eq!((c.tokens_in, c.tokens_out), (120, 30));
        assert_eq!(c.model_version, "m-001");
    }

    #[test]
    fn safety_block_and_empty_candidates_are_refusals() {
        assert!(matches!(
            parse_response(r#"{"promptFeedback":{"blockReason":"SAFETY"}}"#, 0),
            Err(ProviderError::Refused(_))
        ));
        assert!(matches!(
            parse_response(r#"{"candidates":[{"finishReason":"MAX_TOKENS"}]}"#, 0),
            Err(ProviderError::Refused(_))
        ));
        assert!(matches!(parse_response("nope", 0), Err(ProviderError::BadResponse(_))));
    }

    #[test]
    fn empty_key_is_rejected() {
        assert!(GeminiClient::new("https://x", "m", " ".into(), Duration::from_secs(1)).is_err());
    }
}
