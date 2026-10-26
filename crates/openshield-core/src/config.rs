use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// WAF configuration: everything the core needs, and nothing about the
/// server hosting it. Hosts embed this in their own config (for example with
/// `#[serde(flatten)]`) or load it on its own.
#[derive(Debug, Clone, Deserialize)]
pub struct WafConfig {
    #[serde(default)]
    pub detection_only: bool,

    #[serde(default = "default_max_request_body_buffer")]
    pub max_request_body_buffer: usize,

    #[serde(default)]
    pub request_body_limit_action: BodyLimitAction,

    #[serde(default)]
    pub inspect_response_body: bool,

    #[serde(default = "default_max_response_body_buffer")]
    pub max_response_body_buffer: usize,

    #[serde(default)]
    pub response_body_limit_action: BodyLimitAction,

    /// Log the payload values that triggered each matched rule (audit log).
    #[serde(default)]
    pub log_payloads: bool,

    /// What to mask in audit logs and security events.
    #[serde(default)]
    pub redaction: crate::redact::RedactionConfig,

    #[serde(default)]
    pub geoip: Option<GeoIpConfig>,

    /// Country, region and network (ASN) rules, evaluated before every
    /// ruleset. See `GeoAccessConfig`.
    #[serde(default)]
    pub geo_access: GeoAccessConfig,

    #[serde(default)]
    pub scores: Vec<String>,

    #[serde(default)]
    pub lists: Vec<ListConfig>,

    #[serde(default)]
    pub challenge: Option<ChallengeConfig>,

    #[serde(default)]
    pub token_configurations: Vec<TokenConfig>,

    #[serde(default)]
    pub schemas: Vec<SchemaConfig>,

    #[serde(default)]
    pub rulesets: Vec<RulesetConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenConfig {
    pub id: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: Option<String>,
    pub token_sources: Vec<String>,
    pub credentials: TokenCredentials,
}

/// An OpenAPI document that requests to `hosts` are validated against.
#[derive(Debug, Clone, Deserialize)]
pub struct SchemaConfig {
    pub name: String,
    /// OpenAPI 3.0 or 3.1 document, JSON or YAML by extension.
    pub file: PathBuf,
    /// Bare hostnames the schema describes, without port; empty means every
    /// host.
    #[serde(default)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenCredentials {
    pub keys: Vec<jsonwebtoken::jwk::Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RulesetConfig {
    pub name: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub version: Option<String>,
    #[serde(default)]
    pub kind: RulesetKind,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RulesetKind {
    Root,
    #[default]
    Custom,
    Managed,
}

/// Rules on where a request comes from. Each compiles to a request-headers
/// rule with id `geo:<id>` that runs before every ruleset.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct GeoAccessConfig {
    #[serde(default)]
    pub rules: Vec<GeoRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GeoRule {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// `deny`: act on the listed places. `allow_only`: act on everything
    /// else (requests whose location is unknown are left alone).
    #[serde(default)]
    pub mode: GeoMode,
    /// `block`, `challenge` or `log`.
    pub action: Action,
    /// ISO 3166-1 alpha-2 codes, e.g. `ID`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub countries: Vec<String>,
    /// ISO 3166-2 codes, e.g. `ID-JK`, or `CC:Name` (e.g. `ID:Jakarta`)
    /// for databases that name regions without codes (DB-IP Lite).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<String>,
    /// Autonomous system numbers, e.g. `13335`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asns: Vec<u32>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GeoMode {
    #[default]
    Deny,
    AllowOnly,
}

impl GeoRule {
    /// Check codes and shape; returns a message naming the rule.
    pub fn validate(&self) -> Result<(), String> {
        let id_ok = !self.id.is_empty()
            && self.id.len() <= 48
            && self
                .id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
        if !id_ok {
            return Err(format!(
                "geo rule id {:?}: use 1-48 lowercase letters, digits, '-' or '_'",
                self.id
            ));
        }
        if !matches!(self.action, Action::Block | Action::Challenge | Action::Log) {
            return Err(format!(
                "geo rule {}: action must be block, challenge or log",
                self.id
            ));
        }
        if self.countries.is_empty() && self.regions.is_empty() && self.asns.is_empty() {
            return Err(format!(
                "geo rule {}: list at least one country, region or ASN",
                self.id
            ));
        }
        if self.countries.len() + self.regions.len() + self.asns.len() > 500 {
            return Err(format!("geo rule {}: at most 500 entries", self.id));
        }
        for c in &self.countries {
            if !is_country_code(c) {
                return Err(format!(
                    "geo rule {}: {c:?} is not a two-letter country code such as ID",
                    self.id
                ));
            }
        }
        for r in &self.regions {
            if !is_region_code(r) {
                return Err(format!(
                    "geo rule {}: {r:?} is not a region such as ID-JK or ID:Jakarta",
                    self.id
                ));
            }
        }
        if self.asns.contains(&0) {
            return Err(format!("geo rule {}: ASN 0 is not valid", self.id));
        }
        Ok(())
    }

    /// Whether a request from this place would match, exactly as the
    /// compiled expression decides (for impact estimates). `region` is the
    /// region key as events record it: `ID-JK`, or `ID:Jakarta` when the
    /// database has no region codes. Allowlisted addresses aside.
    pub fn matches(&self, country: Option<&str>, region: Option<&str>, asn: Option<u32>) -> bool {
        let listed = country.is_some_and(|c| self.countries.iter().any(|x| x == c))
            || region.is_some_and(|r| self.regions.iter().any(|x| x == r))
            || asn.is_some_and(|a| self.asns.contains(&a));
        match self.mode {
            GeoMode::Deny => listed,
            GeoMode::AllowOnly => {
                let by_place = !(self.countries.is_empty() && self.regions.is_empty());
                let known = match (by_place, self.asns.is_empty()) {
                    (true, true) => country.is_some(),
                    (false, false) => asn.is_some(),
                    _ => country.is_some() || asn.is_some(),
                };
                known && !listed
            }
        }
    }

    /// The rule as a filter expression over `ip.src.*` fields.
    pub fn expression(&self) -> String {
        let mut any = Vec::new();
        if !self.countries.is_empty() {
            let set: Vec<String> = self.countries.iter().map(|c| format!("\"{c}\"")).collect();
            any.push(format!("ip.src.country in {{{}}}", set.join(" ")));
        }
        for r in &self.regions {
            if let Some((cc, name)) = r.split_once(':') {
                any.push(format!(
                    "(ip.src.country == \"{cc}\" and ip.src.region == \"{name}\")"
                ));
            } else {
                let (cc, sub) = r.split_once('-').unwrap_or((r, ""));
                any.push(format!(
                    "(ip.src.country == \"{cc}\" and ip.src.region_code == \"{sub}\")"
                ));
            }
        }
        if !self.asns.is_empty() {
            let set: Vec<String> = self.asns.iter().map(u32::to_string).collect();
            any.push(format!("ip.src.asnum in {{{}}}", set.join(" ")));
        }
        let listed = any.join(" or ");
        // Allowlisted addresses (dashboard IP allows) are never geo-blocked.
        match self.mode {
            GeoMode::Deny => format!("not ip.src.allowlisted and ({listed})"),
            // Only requests with a known location count as "elsewhere":
            // private addresses and missing geo data are left alone.
            GeoMode::AllowOnly => {
                let known = match (self.countries.is_empty() && self.regions.is_empty(), self.asns.is_empty()) {
                    (false, true) => "ip.src.has_country",
                    (true, false) => "ip.src.has_asnum",
                    _ => "(ip.src.has_country or ip.src.has_asnum)",
                };
                format!("not ip.src.allowlisted and {known} and not ({listed})")
            }
        }
    }
}

pub fn is_country_code(c: &str) -> bool {
    c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase())
}

/// `ID-JK` (ISO 3166-2) or `ID:Jakarta` (country and region name).
pub fn is_region_code(r: &str) -> bool {
    if let Some((cc, name)) = r.split_once(':') {
        return is_country_code(cc)
            && !name.is_empty()
            && name.len() <= 80
            && name.trim() == name
            && !name.chars().any(|c| c.is_control() || c == '"' || c == '\\' || c == ':');
    }
    match r.split_once('-') {
        Some((cc, sub)) => {
            is_country_code(cc)
                && (1..=3).contains(&sub.len())
                && sub.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        }
        None => false,
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GeoIpConfig {
    pub city_mmdb: PathBuf,
    pub asn_mmdb: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListConfig {
    pub name: String,
    pub kind: ListKind,
    #[serde(default)]
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ListKind {
    /// IP addresses and CIDRs.
    Ip,
    /// Whole-value string match.
    #[serde(alias = "bytes")]
    String,
    /// Any item anywhere in the value, ASCII case-insensitive.
    Substring,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: Option<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub r#ref: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub version: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_phase")]
    pub phase: Phase,
    pub action: Action,
    pub expression: String,
    #[serde(default)]
    pub action_parameters: Option<ActionParameters>,
    #[serde(default)]
    pub ratelimit: Option<RateLimitConfig>,
    #[serde(default)]
    pub logging: RuleLoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RuleLoggingConfig {
    pub enabled: bool,
}

impl Default for RuleLoggingConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
    Logging,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Block,
    Log,
    Allow,
    Score,
    Challenge,
    Execute,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BodyLimitAction {
    #[default]
    ProcessPartial,
    Reject,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActionParameters {
    #[serde(default)]
    pub response: Option<BlockResponse>,
    #[serde(default)]
    pub scores: Vec<ScoreAction>,
    /// `execute` only: name of the ruleset to run.
    #[serde(default)]
    pub id: Option<String>,
    /// `execute` only: overrides applied to the executed ruleset.
    #[serde(default)]
    pub overrides: Option<Overrides>,
}

/// Overrides for an executed ruleset. Precedence (highest first):
/// `rules` > `categories` > top-level `action` / `enabled`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Overrides {
    /// Action to override all rules with.
    #[serde(default)]
    pub action: Option<Action>,
    /// Whether to enable execution of all rules.
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub categories: Vec<CategoryOverride>,
    #[serde(default)]
    pub rules: Vec<RuleOverride>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CategoryOverride {
    pub category: String,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleOverride {
    pub id: String,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl Overrides {
    /// Resolve the effective (enabled, action) for `rule` under these
    /// overrides. Rule-level wins over category-level, which wins over the
    /// ruleset-wide setting; each layer only replaces what it sets.
    pub fn resolve(&self, rule: &RuleConfig) -> (bool, Action) {
        let mut enabled = self.enabled.unwrap_or(rule.enabled);
        let mut action = self.action.clone().unwrap_or_else(|| rule.action.clone());

        for c in self
            .categories
            .iter()
            .filter(|c| rule.categories.contains(&c.category))
        {
            if let Some(e) = c.enabled {
                enabled = e;
            }
            if let Some(ref a) = c.action {
                action = a.clone();
            }
        }

        if let Some(r) = self.rules.iter().find(|r| r.id == rule.id) {
            if let Some(e) = r.enabled {
                enabled = e;
            }
            if let Some(ref a) = r.action {
                action = a.clone();
            }
        }

        (enabled, action)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockResponse {
    #[serde(default = "default_status_code")]
    pub status_code: u16,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScoreAction {
    pub name: String,
    #[serde(default = "default_increment")]
    pub increment: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChallengeConfig {
    pub turnstile_site_key: String,
    pub turnstile_secret_key: String,
    pub cookie_secret: String,
    #[serde(default = "default_challenge_cookie_ttl")]
    pub cookie_ttl: u64,
    #[serde(default = "default_challenge_cookie_name")]
    pub cookie_name: String,
    #[serde(default = "default_challenge_path")]
    pub challenge_path: String,
    /// Path to custom HTML challenge page. The page must contain
    /// `{{turnstile_site_key}}` placeholder which will be replaced with the
    /// actual site key.
    #[serde(default)]
    pub custom_page: Option<PathBuf>,
    /// Turnstile verification endpoint. Change only to point at a test double.
    #[serde(default = "default_turnstile_verify_url")]
    pub turnstile_verify_url: String,
    /// Timeout for the verification call, in milliseconds.
    #[serde(default = "default_turnstile_timeout_ms")]
    pub turnstile_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub characteristics: Vec<String>,
    #[serde(default)]
    pub period: u64,
    #[serde(default)]
    pub requests_per_period: u64,
    #[serde(default)]
    pub mitigation_timeout: u64,
}

// Defaults
fn default_max_request_body_buffer() -> usize {
    1_048_576
}
fn default_max_response_body_buffer() -> usize {
    1_048_576
}
fn default_true() -> bool {
    true
}
fn default_challenge_cookie_ttl() -> u64 {
    3600
}
fn default_challenge_cookie_name() -> String {
    "oss_challenge".into()
}
fn default_turnstile_verify_url() -> String {
    "https://challenges.cloudflare.com/turnstile/v0/siteverify".into()
}
fn default_turnstile_timeout_ms() -> u64 {
    5000
}
fn default_challenge_path() -> String {
    "/__openshield/challenge".into()
}
fn default_phase() -> Phase {
    Phase::RequestHeaders
}
fn default_status_code() -> u16 {
    403
}
fn default_increment() -> i64 {
    1
}

impl WafConfig {
    pub fn token_ids(&self) -> Vec<String> {
        self.token_configurations
            .iter()
            .map(|t| t.id.clone())
            .collect()
    }

    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml(&content)
    }

    /// Parse and validate a configuration from its YAML text.
    pub fn from_yaml(yaml: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config: WafConfig = serde_yaml::from_str(yaml)?;
        config.validate()?;
        Ok(config)
    }

    /// Check cross-field constraints. `load` and `from_yaml` already call
    /// this; hosts that deserialize the config themselves must call it.
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        for list in &self.lists {
            if list.name.is_empty() {
                return Err("list name is required".into());
            }
            if self.lists.iter().filter(|l| l.name == list.name).count() > 1 {
                return Err(format!("duplicate list name '{}'", list.name).into());
            }
        }
        for tc in &self.token_configurations {
            if tc.id.is_empty() {
                return Err("token configuration id is required".into());
            }
            if self
                .token_configurations
                .iter()
                .filter(|t| t.id == tc.id)
                .count()
                > 1
            {
                return Err(format!("duplicate token configuration id '{}'", tc.id).into());
            }
            if tc.token_sources.is_empty() {
                return Err(format!("token configuration '{}' has no token_sources", tc.id).into());
            }
            if tc.credentials.keys.is_empty() {
                return Err(format!("token configuration '{}' has no keys", tc.id).into());
            }
        }
        for schema in &self.schemas {
            if schema.name.is_empty() {
                return Err("schema name is required".into());
            }
            for host in &schema.hosts {
                let bare = !host.is_empty()
                    && !host.ends_with('.')
                    && !host.contains([':', '/', '[', ' ', '\t']);
                if !bare {
                    return Err(format!(
                        "schema '{}': host '{host}' must be a bare hostname without port",
                        schema.name
                    )
                    .into());
                }
            }
            if self
                .schemas
                .iter()
                .filter(|s| s.name == schema.name)
                .count()
                > 1
            {
                return Err(format!("duplicate schema name '{}'", schema.name).into());
            }
        }
        for rs in &self.rulesets {
            if rs.name.is_empty() {
                return Err("ruleset name is required".into());
            }
            if self.rulesets.iter().filter(|r| r.name == rs.name).count() > 1 {
                return Err(format!("duplicate ruleset name '{}'", rs.name).into());
            }
            for rule in &rs.rules {
                let result = match (&rule.action, rs.kind) {
                    (Action::Execute, RulesetKind::Root) => self.validate_execute(rule),
                    (Action::Execute, _) => Err(format!(
                        "rule '{}': 'execute' is only allowed in a ruleset with 'kind: root'",
                        rule.id
                    )
                    .into()),
                    _ => self.validate_rule(rule, &rule.action),
                };
                result.map_err(|e| format!("ruleset '{}': {}", rs.name, e))?;
            }
        }
        Ok(())
    }

    /// Validate a rule as if it ran with `action` (which may differ from
    /// `rule.action` when an `execute` override is applied).
    fn validate_rule(
        &self,
        rule: &RuleConfig,
        action: &Action,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if rule.id.is_empty() {
            return Err("rule id is required".into());
        }
        if rule.expression.is_empty() {
            return Err(format!("rule '{}' has empty expression", rule.id).into());
        }
        match action {
            Action::Challenge if self.challenge.is_none() => Err(format!(
                "rule '{}' has action 'challenge' but no challenge config",
                rule.id
            )
            .into()),
            Action::Score => {
                let has_scores = rule
                    .action_parameters
                    .as_ref()
                    .is_some_and(|p| !p.scores.is_empty());
                if has_scores {
                    Ok(())
                } else {
                    Err(format!(
                        "rule '{}' has action 'score' but no score parameters",
                        rule.id
                    )
                    .into())
                }
            }
            Action::Execute => Err(format!(
                "rule '{}': 'execute' cannot be used as an override action",
                rule.id
            )
            .into()),
            _ => Ok(()),
        }
    }

    fn validate_execute(&self, rule: &RuleConfig) -> Result<(), Box<dyn std::error::Error>> {
        if rule.id.is_empty() {
            return Err("rule id is required".into());
        }
        if rule.expression.is_empty() {
            return Err(format!("rule '{}' has empty expression", rule.id).into());
        }
        let params = rule.action_parameters.as_ref();
        let Some(id) = params.and_then(|p| p.id.as_deref()) else {
            return Err(format!(
                "rule '{}' has action 'execute' but no action_parameters.id",
                rule.id
            )
            .into());
        };
        let Some(ruleset) = self.rulesets.iter().find(|r| r.name == id) else {
            return Err(format!("rule '{}' executes unknown ruleset '{}'", rule.id, id).into());
        };
        if ruleset.kind == RulesetKind::Root {
            return Err(format!("rule '{}' executes root ruleset '{}'", rule.id, id).into());
        }
        let overrides = params.and_then(|p| p.overrides.clone()).unwrap_or_default();

        for o in &overrides.rules {
            if !ruleset.rules.iter().any(|r| r.id == o.id) {
                return Err(format!(
                    "rule '{}' overrides unknown rule '{}' in ruleset '{}'",
                    rule.id, o.id, id
                )
                .into());
            }
        }
        for o in &overrides.categories {
            if !ruleset
                .rules
                .iter()
                .any(|r| r.categories.contains(&o.category))
            {
                return Err(format!(
                    "rule '{}' overrides unknown category '{}' in ruleset '{}'",
                    rule.id, o.category, id
                )
                .into());
            }
        }

        // Every rule must be valid under the action it will actually run with.
        for rs_rule in &ruleset.rules {
            let (enabled, action) = overrides.resolve(rs_rule);
            if enabled {
                self.validate_rule(rs_rule, &action).map_err(|e| {
                    format!("rule '{}' (via execute '{}'): {}", rs_rule.id, rule.id, e)
                })?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<WafConfig, Box<dyn std::error::Error>> {
        let cfg: WafConfig = serde_yaml::from_str(yaml)?;
        cfg.validate()?;
        Ok(cfg)
    }

    const BASE: &str = r#"
scores: [sqli]
rulesets:
  - name: crs
    description: OWASP Core Rule Set
    version: "4.0.0"
    rules:
      - id: "942100"
        description: SQLi via libinjection
        ref: https://example.com/942100
        version: "4.0.0"
        categories: [attack-sqli, paranoia-level-1]
        action: block
        expression: 'http.request.uri.path contains "sqli"'
      - id: "941100"
        categories: [attack-xss, paranoia-level-1]
        action: log
        expression: 'http.request.uri.path contains "xss"'
      - id: "920100"
        categories: [protocol]
        enabled: false
        action: block
        expression: 'http.request.uri.path contains "proto"'
"#;

    /// `BASE` plus a root ruleset `main` holding `rules` (a YAML list).
    fn with_root(rules: &str) -> String {
        let rules: String = rules
            .trim_matches('\n')
            .lines()
            .map(|l| format!("      {l}\n"))
            .collect();
        format!("{BASE}  - name: main\n    kind: root\n    rules:\n{rules}")
    }

    /// `BASE` plus a root rule executing `crs` with extra `action_parameters`.
    fn with_execute(params: &str) -> String {
        let params: String = params
            .trim_matches('\n')
            .lines()
            .map(|l| format!("    {l}\n"))
            .collect();
        with_root(&format!(
            "- id: run\n  action: execute\n  expression: \"true\"\n  action_parameters:\n    \
             id: crs\n{params}"
        ))
    }

    #[test]
    fn rule_metadata_fields_parse_with_defaults() {
        let cfg = parse(BASE).unwrap();
        let rs = &cfg.rulesets[0];
        assert_eq!(rs.name, "crs");
        assert_eq!(rs.version.as_deref(), Some("4.0.0"));
        assert_eq!(rs.kind, RulesetKind::Custom, "kind defaults to custom");
        let r = &rs.rules[0];
        assert_eq!(r.r#ref.as_deref(), Some("https://example.com/942100"));
        assert_eq!(r.categories, vec!["attack-sqli", "paranoia-level-1"]);
        assert!(r.enabled, "enabled defaults to true");
        assert!(!rs.rules[2].enabled);
    }

    const TOKEN_CONFIG: &str = r#"
token_configurations:
  - id: api
    description: Tokens issued by the auth service
    token_sources:
      - 'http.request.headers["authorization"][0]'
      - 'http.request.cookies["Authorization"][0]'
    credentials:
      keys:
        - kty: EC
          use: sig
          crv: P-256
          kid: ec-1
          x: QG3VFVwUX4IatQvBy7sqBvvmticCZ-eX5-nbtGKBOfI
          y: A3PXCshn7XcG7Ivvd2K_DerW4LHAlIVKdqhrUnczTD0
          alg: ES256
        - {kty: oct, kid: hs-1, alg: HS256, k: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}
"#;

    #[test]
    fn lists_need_a_known_kind_and_unique_names() {
        let cfg = parse(
            "lists:\n  - {name: a, kind: ip, items: [10.0.0.0/8]}\n  - \
             {name: b, kind: bytes}\n  - {name: c, kind: substring, items: [sqlmap]}\n",
        )
        .unwrap();
        assert_eq!(cfg.lists[0].kind, ListKind::Ip);
        assert_eq!(cfg.lists[1].kind, ListKind::String, "bytes is an alias");
        assert_eq!(cfg.lists[2].kind, ListKind::Substring);

        let err = parse("lists:\n  - {name: a, kind: subtring}\n").unwrap_err();
        assert!(
            err.to_string().contains("unknown variant `subtring`"),
            "{err}"
        );

        let err = parse("lists:\n  - {name: a}\n").unwrap_err();
        assert!(err.to_string().contains("missing field `kind`"), "{err}");

        let err =
            parse("lists:\n  - {name: a, kind: ip}\n  - {name: a, kind: string}\n").unwrap_err();
        assert!(err.to_string().contains("duplicate list name 'a'"), "{err}");
    }

    #[test]
    fn schemas_parse_and_need_unique_names() {
        let cfg = parse(
            "schemas:\n  - {name: pets, file: ./pets.yaml, hosts: \
             [api.example.com]}\n  - {name: all, file: all.json}\n",
        )
        .unwrap();
        assert_eq!(cfg.schemas[0].hosts, ["api.example.com"]);
        assert_eq!(cfg.schemas[1].file, PathBuf::from("all.json"));
        assert!(cfg.schemas[1].hosts.is_empty());

        let err = parse(
            "schemas:\n  - {name: pets, file: a.yaml}\n  - {name: pets, \
             file: b.yaml}\n",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("duplicate schema name 'pets'"),
            "{err}"
        );

        for host in ["api.example.com:8443", "api.example.com.", "", "https://x"] {
            let err = parse(&format!(
                "schemas:\n  - {{name: pets, file: a.yaml, hosts: ['{host}']}}\n"
            ))
            .unwrap_err();
            assert!(
                err.to_string().contains("must be a bare hostname"),
                "{host}: {err}"
            );
        }
    }

    #[test]
    fn token_configuration_parses_jwks() {
        use jsonwebtoken::jwk::{AlgorithmParameters, KeyAlgorithm};

        let cfg = parse(TOKEN_CONFIG).unwrap();
        let tc = &cfg.token_configurations[0];
        assert_eq!(tc.id, "api");
        assert_eq!(tc.token_sources.len(), 2);

        let keys = &tc.credentials.keys;
        assert_eq!(keys[0].common.key_id.as_deref(), Some("ec-1"));
        assert_eq!(keys[0].common.key_algorithm, Some(KeyAlgorithm::ES256));
        assert!(matches!(
            keys[0].algorithm,
            AlgorithmParameters::EllipticCurve(_)
        ));
        assert!(matches!(
            keys[1].algorithm,
            AlgorithmParameters::OctetKey(_)
        ));
    }

    #[test]
    fn token_configuration_requires_unique_id_sources_and_keys() {
        let duplicate = format!(
            "{TOKEN_CONFIG}  - id: api\n    token_sources: [http.host]\n    credentials: {{keys: \
             []}}\n"
        );
        let err = parse(&duplicate).unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate token configuration id 'api'"),
            "{err}"
        );

        let base = "token_configurations:\n";
        let err = parse(&format!(
            "{base}  - {{id: x, token_sources: [], credentials: {{keys: []}}}}"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("has no token_sources"), "{err}");

        let err = parse(&format!(
            "{base}  - {{id: x, token_sources: [http.host], credentials: {{keys: []}}}}"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("has no keys"), "{err}");
    }

    #[test]
    fn managed_ruleset_is_executable_but_cannot_execute() {
        let managed = BASE.replace("  - name: crs\n", "  - name: crs\n    kind: managed\n");
        let cfg = parse(&format!(
            "{managed}  - name: main\n    kind: root\n    rules:\n      - {{id: run, action: \
             execute, expression: \"true\", action_parameters: {{id: crs}}}}"
        ))
        .unwrap();
        assert_eq!(cfg.rulesets[0].kind, RulesetKind::Managed);

        let err = parse(
            r#"
rulesets:
  - name: other
  - name: rs
    kind: managed
    rules:
      - {id: x, action: execute, expression: "true", action_parameters: {id: other}}
"#,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("only allowed in a ruleset with 'kind: root'"),
            "{err}"
        );
    }

    #[test]
    fn ruleset_names_must_be_unique() {
        let err = parse(&format!("{BASE}  - name: crs\n    kind: root")).unwrap_err();
        assert!(
            err.to_string().contains("duplicate ruleset name 'crs'"),
            "{err}"
        );
    }

    #[test]
    fn root_ruleset_rules_are_validated() {
        let err = parse(&with_root(
            r#"
- id: c
  action: challenge
  expression: 'http.host == "x"'
"#,
        ))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("ruleset 'main': rule 'c' has action 'challenge'"),
            "{err}"
        );
    }

    #[test]
    fn execute_requires_known_custom_ruleset() {
        let rule = |params: &str| {
            with_root(&format!(
                "- id: run\n  action: execute\n  expression: \"true\"\n{params}"
            ))
        };

        let err = parse(&rule("  action_parameters:\n    id: nope")).unwrap_err();
        assert!(err.to_string().contains("unknown ruleset 'nope'"), "{err}");

        let err = parse(&rule("")).unwrap_err();
        assert!(err.to_string().contains("no action_parameters.id"), "{err}");

        let err = parse(&rule("  action_parameters:\n    id: main")).unwrap_err();
        assert!(
            err.to_string().contains("executes root ruleset 'main'"),
            "{err}"
        );
    }

    #[test]
    fn execute_requires_expression() {
        let err = parse(&with_root(
            "- id: run\n  action: execute\n  action_parameters:\n    id: crs",
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("missing field `expression`"),
            "{err}"
        );
    }

    #[test]
    fn execute_rejects_unknown_override_targets() {
        let err = parse(&with_execute(
            "overrides:\n  rules: [{id: \"000000\", enabled: false}]",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("unknown rule '000000'"), "{err}");

        let err = parse(&with_execute(
            "overrides:\n  categories: [{category: nope, action: log}]",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("unknown category 'nope'"), "{err}");
    }

    #[test]
    fn execute_only_allowed_in_root_ruleset_and_not_as_override_action() {
        let err = parse(
            r#"
rulesets:
  - name: other
  - name: rs
    rules:
      - {id: x, action: execute, expression: "true", action_parameters: {id: other}}
"#,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("only allowed in a ruleset with 'kind: root'"),
            "{err}"
        );

        let err = parse(&with_execute("overrides:\n  action: execute")).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot be used as an override action"),
            "{err}"
        );
    }

    #[test]
    fn override_to_score_validates_score_parameters() {
        // 942100 has no score parameters, so overriding it to `score` is
        // invalid.
        let err = parse(&with_execute(
            "overrides:\n  rules: [{id: \"942100\", action: score}]",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("no score parameters"), "{err}");

        // ...unless that rule is disabled by the same overrides.
        parse(&with_execute(
            "overrides:\n  enabled: false\n  rules: [{id: \"942100\", action: score}]",
        ))
        .unwrap();
    }

    #[test]
    fn override_precedence_rule_over_category_over_global() {
        let cfg = parse(BASE).unwrap();
        let rs = &cfg.rulesets[0];
        let sqli = &rs.rules[0];
        let xss = &rs.rules[1];
        let proto = &rs.rules[2];

        let overrides: Overrides = serde_yaml::from_str(
            r#"
action: log
enabled: false
categories:
  - category: paranoia-level-1
    enabled: true
    action: challenge
  - category: attack-xss
    action: allow
rules:
  - id: "942100"
    action: block
"#,
        )
        .unwrap();

        // rule-level action wins; category-level enabled wins over global.
        let (en, act) = overrides.resolve(sqli);
        assert!(en);
        assert!(matches!(act, Action::Block));

        // both categories match; later category in the list wins for action.
        let (en, act) = overrides.resolve(xss);
        assert!(en);
        assert!(matches!(act, Action::Allow));

        // no category/rule override -> global applies (disabled, log).
        let (en, act) = overrides.resolve(proto);
        assert!(!en);
        assert!(matches!(act, Action::Log));

        // Empty overrides keep the rule's own settings.
        let (en, act) = Overrides::default().resolve(proto);
        assert!(!en);
        assert!(matches!(act, Action::Block));
    }
}
