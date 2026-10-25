//! AI verdict types. A verdict is advisory: nothing in the request path
//! acts on it.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Expected, legitimate behavior.
    Legitimate,
    /// Unusual or suspicious, but inconclusive.
    Suspicious,
    /// Likely an attack.
    Malicious,
    /// Breaks a stated policy (abuse, scraping, misuse) without being an
    /// exploit attempt.
    PolicyViolation,
    /// Not enough evidence.
    Unknown,
}

impl Category {
    pub const ALL: [Category; 5] = [
        Category::Legitimate,
        Category::Suspicious,
        Category::Malicious,
        Category::PolicyViolation,
        Category::Unknown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Category::Legitimate => "legitimate",
            Category::Suspicious => "suspicious",
            Category::Malicious => "malicious",
            Category::PolicyViolation => "policy_violation",
            Category::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    None,
    Monitor,
    Review,
    Challenge,
    RateLimit,
    /// Suggests blocking. Only an operator can turn this into a block.
    BlockCandidate,
}

impl RecommendedAction {
    pub const ALL: [RecommendedAction; 6] = [
        RecommendedAction::None,
        RecommendedAction::Monitor,
        RecommendedAction::Review,
        RecommendedAction::Challenge,
        RecommendedAction::RateLimit,
        RecommendedAction::BlockCandidate,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RecommendedAction::None => "none",
            RecommendedAction::Monitor => "monitor",
            RecommendedAction::Review => "review",
            RecommendedAction::Challenge => "challenge",
            RecommendedAction::RateLimit => "rate_limit",
            RecommendedAction::BlockCandidate => "block_candidate",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    /// Valid output from the model.
    Ok,
    /// Valid, but flagged for a person: low confidence, disagreement with
    /// the rules, or signs of prompt injection in the input.
    NeedsReview,
}

/// A validated classification of one event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiVerdict {
    pub category: Category,
    /// 0 (harmless) to 1 (certainly harmful).
    pub risk: f64,
    /// The model's stated confidence, 0 to 1. Not calibrated.
    pub confidence: f64,
    pub explanation: String,
    /// Input fields the model cited, from the allowed field list.
    pub evidence: Vec<String>,
    pub recommended_action: RecommendedAction,
    pub status: VerdictStatus,
    /// Why the verdict needs review, if it does.
    pub review_reasons: Vec<String>,
    pub provider: String,
    pub model: String,
    /// Version string reported by the provider.
    pub model_version: String,
    pub prompt_version: String,
    pub ts: i64,
    pub latency_ms: u64,
    pub cached: bool,
}

/// The sanitized view of an event that is sent to the model.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AiInput {
    /// Reference used to match the answer to the event; not the event id.
    pub ref_id: String,
    pub method: String,
    pub path: String,
    pub path_template: String,
    /// Query parameters, values redacted and truncated.
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body_excerpt: Option<String>,
    pub status: u16,
    pub firewall_action: String,
    pub rules_matched: Vec<String>,
    pub scores: Vec<(String, i64)>,
    pub anomaly_score: f64,
    pub anomaly_reasons: Vec<String>,
    /// IP, or a keyed hash of it.
    pub client: String,
    pub country: Option<String>,
    pub asn: Option<u32>,
    /// Deterministic check: the input contains text aimed at an AI model.
    pub prompt_injection_markers: Vec<String>,
}
