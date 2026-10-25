use std::collections::HashMap;

use log::{debug, info, warn};
use wirefilter_engine::{ExecutionContext, Filter, LhsValue, Scheme};

use super::payload;
use super::ratelimit::{RateLimitKey, RateLimitManager};

#[derive(Debug, Clone)]
pub enum Action {
    Block {
        status_code: u16,
        content_type: Option<String>,
        content: Option<String>,
    },
    Allow,
    Log,
    Score {
        scores: Vec<(String, i64)>,
    },
    Challenge,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Phase {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
    Logging,
}

pub struct CompiledRule {
    pub id: String,
    pub phase: Phase,
    pub action: Action,
    pub filter: Filter,
    pub ratelimit_characteristics: Option<Vec<String>>,
    pub log_fields: Vec<String>,
    pub logging: bool,
}

pub enum RuleAction {
    Block {
        rule_id: String,
        status_code: u16,
        content_type: Option<String>,
        content: Option<String>,
        log: bool,
    },
    Allow {
        rule_id: String,
        log: bool,
    },
    Challenge {
        rule_id: String,
        log: bool,
    },
    NoMatch,
}

pub struct Engine {
    rules: HashMap<Phase, Vec<CompiledRule>>,
    pub ratelimit_mgr: RateLimitManager,
    log_payloads: bool,
}

impl Engine {
    pub fn new(
        rules: Vec<CompiledRule>,
        ratelimit_mgr: RateLimitManager,
        log_payloads: bool,
    ) -> Self {
        let mut grouped: HashMap<Phase, Vec<CompiledRule>> = HashMap::new();
        for rule in rules {
            grouped.entry(rule.phase.clone()).or_default().push(rule);
        }

        let total: usize = grouped.values().map(|v| v.len()).sum();
        info!("Engine loaded {} rules ({} phases)", total, grouped.len());
        for (phase, phase_rules) in &grouped {
            debug!("  {:?}: {} rules", phase, phase_rules.len());
        }

        Self {
            rules: grouped,
            ratelimit_mgr,
            log_payloads,
        }
    }

    /// Rules in `phase`, in execution order (test introspection).
    #[cfg(test)]
    pub fn rules_in(&self, phase: &Phase) -> &[CompiledRule] {
        self.rules.get(phase).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn evaluate(
        &self,
        phase: &Phase,
        ctx: &ExecutionContext<'_>,
        scores: &mut HashMap<String, i64>,
        matched_rules: &mut Vec<(String, String)>, // (rule_id, action)
        payloads: &mut serde_json::Map<String, serde_json::Value>,
    ) -> RuleAction {
        let Some(phase_rules) = self.rules.get(phase) else {
            return RuleAction::NoMatch;
        };

        for rule in phase_rules {
            let matched = match rule.filter.execute(ctx) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Rule '{}' execution error: {}", rule.id, e);
                    false
                }
            };

            if !matched {
                continue;
            }

            // Rate limit check
            if rule.ratelimit_characteristics.is_some() {
                let key = build_ratelimit_key(rule, ctx);
                let exceeded = self.ratelimit_mgr.check(&rule.id, &key);
                if !exceeded {
                    debug!("Rule '{}' matched but rate limit not exceeded", rule.id);
                    continue;
                }
                debug!("Rule '{}' rate limit exceeded", rule.id);
            }

            debug!("Rule '{}' matched (action: {:?})", rule.id, rule.action);

            if self.log_payloads && rule.logging && !rule.log_fields.is_empty() {
                payload::capture_into(ctx.scheme(), ctx, &rule.log_fields, payloads);
            }

            match &rule.action {
                Action::Block {
                    status_code,
                    content_type,
                    content,
                } => {
                    debug!("BLOCK by rule '{}' (status {})", rule.id, status_code);
                    return RuleAction::Block {
                        rule_id: rule.id.clone(),
                        status_code: *status_code,
                        content_type: content_type.clone(),
                        content: content.clone(),
                        log: rule.logging,
                    };
                }
                Action::Allow => {
                    debug!("ALLOW by rule '{}'", rule.id);
                    return RuleAction::Allow {
                        rule_id: rule.id.clone(),
                        log: rule.logging,
                    };
                }
                Action::Log => {
                    debug!("LOG by rule '{}'", rule.id);
                    if rule.logging {
                        matched_rules.push((rule.id.clone(), "log".into()));
                    }
                }
                Action::Score { scores: score_list } => {
                    for (name, increment) in score_list {
                        let counter = scores.entry(name.clone()).or_insert(0);
                        *counter += increment;
                        debug!("SCORE '{}' += {} (now {})", name, increment, counter);
                    }
                    if rule.logging {
                        matched_rules.push((rule.id.clone(), "score".into()));
                    }
                }
                Action::Challenge => {
                    debug!("CHALLENGE by rule '{}'", rule.id);
                    return RuleAction::Challenge {
                        rule_id: rule.id.clone(),
                        log: rule.logging,
                    };
                }
            }
        }

        RuleAction::NoMatch
    }

    pub fn rule_count(&self) -> usize {
        self.rules.values().map(|v| v.len()).sum()
    }

    pub fn has_phase(&self, phase: &Phase) -> bool {
        self.rules.get(phase).is_some_and(|v| !v.is_empty())
    }
}

fn build_ratelimit_key(rule: &CompiledRule, ctx: &ExecutionContext<'_>) -> RateLimitKey {
    let mut key = RateLimitKey::new();

    let characteristics = rule
        .ratelimit_characteristics
        .as_deref()
        .unwrap_or_default();

    if characteristics.is_empty() {
        if let Ok(field) = ctx.scheme().get_field("ip.src") {
            if let Some(LhsValue::Ip(ip)) = ctx.get_field_value(field) {
                key.push(ip.to_string());
            }
        }
    } else {
        for char_name in characteristics {
            if let Ok(field) = ctx.scheme().get_field(char_name) {
                if let Some(val) = ctx.get_field_value(field) {
                    match val {
                        LhsValue::Ip(ip) => key.push(ip.to_string()),
                        LhsValue::Bytes(b) => key.push(String::from_utf8_lossy(b).into_owned()),
                        LhsValue::Int(i) => key.push(i.to_string()),
                        LhsValue::Bool(b) => key.push(b.to_string()),
                        _ => key.push(format!("{:?}", val)),
                    }
                }
            }
        }
    }

    key
}

pub fn sync_scores(
    ctx: &mut ExecutionContext<'static>,
    scheme: &Scheme,
    scores: &HashMap<String, i64>,
) {
    let mut field_name = String::with_capacity(32);
    for (name, value) in scores {
        field_name.clear();
        field_name.push_str("score.");
        field_name.push_str(name);
        if let Ok(field) = scheme.get_field(&field_name) {
            let _ = ctx.set_field_value(field, LhsValue::Int(*value));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::{Map, Value};
    use wirefilter_engine::{LhsValue, Scheme};

    use super::{Action, CompiledRule, Engine, Phase, RuleAction};
    use crate::config::RateLimitConfig;
    use crate::waf::ratelimit::RateLimitManager;

    const HOST: &str = "http.host";
    const MATCH: &str = r#"http.host == "evil.com""#;

    fn scheme() -> Scheme {
        crate::waf::scheme::build(&["sqli".to_string()], &[])
    }

    fn compile_rule(
        scheme: &Scheme,
        id: &str,
        phase: Phase,
        action: Action,
        expr: &str,
        logging: bool,
        ratelimit_characteristics: Option<Vec<String>>,
    ) -> CompiledRule {
        let ast = scheme.parse(expr).expect("expression should parse");
        let log_fields = crate::waf::payload::referenced_fields(&ast);
        let filter = ast.compile();
        CompiledRule {
            id: id.to_string(),
            phase,
            action,
            filter,
            ratelimit_characteristics,
            log_fields,
            logging,
        }
    }

    struct Outcome {
        action: RuleAction,
        scores: HashMap<String, i64>,
        matched: Vec<(String, String)>,
        payloads: Map<String, Value>,
    }

    /// Run a single phase against the engine with `fields` set on the context.
    fn evaluate_once(
        engine: &Engine,
        scheme: &Scheme,
        phase: Phase,
        fields: &[(&str, &[u8])],
    ) -> Outcome {
        let mut ctx = crate::waf::scheme::new_context(scheme);
        for (name, val) in fields {
            let f = scheme.get_field(name).expect("field should exist");
            ctx.set_field_value(f, LhsValue::Bytes(val.to_vec().into()))
                .expect("set field value");
        }
        let mut scores = HashMap::new();
        let mut matched = Vec::new();
        let mut payloads = Map::new();
        let action = engine.evaluate(&phase, &ctx, &mut scores, &mut matched, &mut payloads);
        Outcome {
            action,
            scores,
            matched,
            payloads,
        }
    }

    fn block_action() -> Action {
        Action::Block {
            status_code: 403,
            content_type: None,
            content: None,
        }
    }

    fn evil_host() -> [(&'static str, &'static [u8]); 1] {
        [(HOST, b"evil.com")]
    }

    #[test]
    fn matching_block_rule_returns_block() {
        let scheme = scheme();
        let rule = compile_rule(
            &scheme,
            "r1",
            Phase::RequestHeaders,
            block_action(),
            MATCH,
            true,
            None,
        );
        let engine = Engine::new(vec![rule], RateLimitManager::new(), false);
        let out = evaluate_once(&engine, &scheme, Phase::RequestHeaders, &evil_host());
        match out.action {
            RuleAction::Block {
                rule_id,
                status_code,
                log,
                ..
            } => {
                assert_eq!(rule_id, "r1");
                assert_eq!(status_code, 403);
                assert!(log, "logging enabled -> hit should be logged");
            }
            _ => panic!("expected Block"),
        }
    }

    #[test]
    fn non_matching_rule_returns_no_match() {
        let scheme = scheme();
        let rule = compile_rule(
            &scheme,
            "r1",
            Phase::RequestHeaders,
            block_action(),
            MATCH,
            true,
            None,
        );
        let engine = Engine::new(vec![rule], RateLimitManager::new(), false);
        let out = evaluate_once(
            &engine,
            &scheme,
            Phase::RequestHeaders,
            &[(HOST, b"good.com")],
        );
        assert!(matches!(out.action, RuleAction::NoMatch));
        assert!(out.matched.is_empty());
    }

    #[test]
    fn log_action_records_matched_rule() {
        let scheme = scheme();
        let rule = compile_rule(
            &scheme,
            "log-rule",
            Phase::RequestHeaders,
            Action::Log,
            MATCH,
            true,
            None,
        );
        let engine = Engine::new(vec![rule], RateLimitManager::new(), false);
        let out = evaluate_once(&engine, &scheme, Phase::RequestHeaders, &evil_host());
        // Log is non-terminal: evaluation continues and returns NoMatch.
        assert!(matches!(out.action, RuleAction::NoMatch));
        assert_eq!(
            out.matched,
            vec![("log-rule".to_string(), "log".to_string())]
        );
    }

    #[test]
    fn score_action_accumulates_and_records() {
        let scheme = scheme();
        let rule = compile_rule(
            &scheme,
            "score-rule",
            Phase::RequestHeaders,
            Action::Score {
                scores: vec![("sqli".to_string(), 10)],
            },
            MATCH,
            true,
            None,
        );
        let engine = Engine::new(vec![rule], RateLimitManager::new(), false);
        let out = evaluate_once(&engine, &scheme, Phase::RequestHeaders, &evil_host());
        assert_eq!(out.scores.get("sqli"), Some(&10));
        assert_eq!(
            out.matched,
            vec![("score-rule".to_string(), "score".to_string())]
        );
    }

    #[test]
    fn logging_false_suppresses_log_record() {
        let scheme = scheme();
        let rule = compile_rule(
            &scheme,
            "quiet-log",
            Phase::RequestHeaders,
            Action::Log,
            MATCH,
            false, // logging disabled
            None,
        );
        let engine = Engine::new(vec![rule], RateLimitManager::new(), false);
        let out = evaluate_once(&engine, &scheme, Phase::RequestHeaders, &evil_host());
        assert!(out.matched.is_empty(), "disabled logging must not record");
    }

    #[test]
    fn logging_false_keeps_score_effect_but_suppresses_record() {
        // The score still accumulates (it's the rule's effect, not logging) —
        // only the audit record of the hit is suppressed.
        let scheme = scheme();
        let rule = compile_rule(
            &scheme,
            "quiet-score",
            Phase::RequestHeaders,
            Action::Score {
                scores: vec![("sqli".to_string(), 10)],
            },
            MATCH,
            false,
            None,
        );
        let engine = Engine::new(vec![rule], RateLimitManager::new(), false);
        let out = evaluate_once(&engine, &scheme, Phase::RequestHeaders, &evil_host());
        assert_eq!(out.scores.get("sqli"), Some(&10), "score still applies");
        assert!(out.matched.is_empty(), "disabled logging must not record");
    }

    #[test]
    fn logging_false_clears_log_flag_on_block() {
        let scheme = scheme();
        let rule = compile_rule(
            &scheme,
            "quiet-block",
            Phase::RequestHeaders,
            block_action(),
            MATCH,
            false,
            None,
        );
        let engine = Engine::new(vec![rule], RateLimitManager::new(), false);
        let out = evaluate_once(&engine, &scheme, Phase::RequestHeaders, &evil_host());
        match out.action {
            RuleAction::Block { log, .. } => {
                assert!(!log, "disabled logging -> Block carries log=false")
            }
            _ => panic!("expected Block"),
        }
    }

    #[test]
    fn rules_evaluate_in_order_non_terminal_before_terminal() {
        // A Log rule (non-terminal) is recorded, then a Block rule (terminal)
        // returns. Insertion order within a phase is preserved.
        let scheme = scheme();
        let log_rule = compile_rule(
            &scheme,
            "first-log",
            Phase::RequestHeaders,
            Action::Log,
            MATCH,
            true,
            None,
        );
        let block_rule = compile_rule(
            &scheme,
            "then-block",
            Phase::RequestHeaders,
            block_action(),
            MATCH,
            true,
            None,
        );
        let engine = Engine::new(vec![log_rule, block_rule], RateLimitManager::new(), false);
        let out = evaluate_once(&engine, &scheme, Phase::RequestHeaders, &evil_host());
        match out.action {
            RuleAction::Block { rule_id, .. } => assert_eq!(rule_id, "then-block"),
            _ => panic!("expected Block"),
        }
        assert_eq!(
            out.matched,
            vec![("first-log".to_string(), "log".to_string())]
        );
    }

    #[test]
    fn only_rules_for_the_requested_phase_run() {
        let scheme = scheme();
        let rule = compile_rule(
            &scheme,
            "resp-rule",
            Phase::ResponseHeaders,
            block_action(),
            MATCH,
            true,
            None,
        );
        let engine = Engine::new(vec![rule], RateLimitManager::new(), false);
        // Running a different phase must not fire the ResponseHeaders rule.
        let out = evaluate_once(&engine, &scheme, Phase::RequestHeaders, &evil_host());
        assert!(matches!(out.action, RuleAction::NoMatch));
    }

    #[test]
    fn payload_captured_when_enabled_and_logging_on() {
        let scheme = scheme();
        let rule = compile_rule(
            &scheme,
            "cap",
            Phase::RequestHeaders,
            Action::Log,
            MATCH,
            true,
            None,
        );
        let engine = Engine::new(
            vec![rule],
            RateLimitManager::new(),
            /* log_payloads */ true,
        );
        let out = evaluate_once(&engine, &scheme, Phase::RequestHeaders, &evil_host());
        assert!(
            out.payloads.contains_key(HOST),
            "referenced field should be captured"
        );
    }

    #[test]
    fn payload_not_captured_when_logging_off() {
        let scheme = scheme();
        let rule = compile_rule(
            &scheme,
            "cap",
            Phase::RequestHeaders,
            Action::Log,
            MATCH,
            false, // logging disabled -> no capture even with log_payloads on
            None,
        );
        let engine = Engine::new(vec![rule], RateLimitManager::new(), true);
        let out = evaluate_once(&engine, &scheme, Phase::RequestHeaders, &evil_host());
        assert!(out.payloads.is_empty());
    }

    fn ratelimit_engine(scheme: &Scheme, requests_per_period: u64) -> Engine {
        let rule = compile_rule(
            scheme,
            "rl",
            Phase::RequestHeaders,
            block_action(),
            MATCH,
            true,
            Some(vec![]), // empty characteristics -> keys on ip.src (unset here)
        );
        let mut mgr = RateLimitManager::new();
        mgr.add_rule(
            "rl",
            &RateLimitConfig {
                characteristics: vec![],
                period: 60,
                requests_per_period,
                mitigation_timeout: 0,
            },
        );
        Engine::new(vec![rule], mgr, false)
    }

    #[test]
    fn ratelimited_rule_fires_when_limit_exceeded() {
        // limit 0 -> the first matching request already exceeds.
        let scheme = scheme();
        let engine = ratelimit_engine(&scheme, 0);
        let out = evaluate_once(&engine, &scheme, Phase::RequestHeaders, &evil_host());
        assert!(matches!(out.action, RuleAction::Block { .. }));
    }

    #[test]
    fn ratelimited_rule_skipped_when_under_limit() {
        // High limit -> a single request stays under and the rule is gated off,
        // even though its expression matches.
        let scheme = scheme();
        let engine = ratelimit_engine(&scheme, 1000);
        let out = evaluate_once(&engine, &scheme, Phase::RequestHeaders, &evil_host());
        assert!(matches!(out.action, RuleAction::NoMatch));
    }
}
