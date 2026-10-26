use std::collections::HashSet;

use log::{debug, warn};
use wirefilter_engine::Scheme;

use crate::config;
use crate::waf::engine::{Action, CompiledRule, Engine, Phase};
use crate::waf::functions::RuleCompiler;
use crate::waf::payload;
use crate::waf::ratelimit::RateLimitManager;

/// Compile the root rulesets from config into an Engine, expanding
/// `execute` rules in place.
pub fn compile(
    config: &config::WafConfig,
    scheme: &Scheme,
    existing_mgr: Option<RateLimitManager>,
) -> Result<Engine, Box<dyn std::error::Error>> {
    let mut rules = Vec::new();
    let mut mgr = existing_mgr.unwrap_or_else(RateLimitManager::new);

    let mut executed = HashSet::new();

    // Geo and network rules run first, in the order listed.
    let mut geo_ids = HashSet::new();
    for g in &config.geo_access.rules {
        g.validate()?;
        if !geo_ids.insert(g.id.as_str()) {
            return Err(format!("duplicate geo rule id {:?}", g.id).into());
        }
        if g.enabled {
            let rule_cfg = geo_rule_config(g);
            rules.push(compile_rule(&rule_cfg, &rule_cfg.action, None, scheme, &mut mgr)?);
        }
    }

    for root in config
        .rulesets
        .iter()
        .filter(|r| r.kind == config::RulesetKind::Root)
    {
        debug!("Compiling root ruleset '{}'", root.name);

        for rule_cfg in &root.rules {
            if !rule_cfg.enabled {
                debug!("Skipping disabled rule '{}'", rule_cfg.id);
                continue;
            }

            if let config::Action::Execute = rule_cfg.action {
                let params = rule_cfg.action_parameters.as_ref();
                let id = params
                    .and_then(|p| p.id.as_deref())
                    .ok_or_else(|| format!("rule '{}': execute requires an id", rule_cfg.id))?;
                let ruleset = config
                    .rulesets
                    .iter()
                    .find(|r| r.name == id)
                    .ok_or_else(|| format!("rule '{}': unknown ruleset '{}'", rule_cfg.id, id))?;
                let overrides = params.and_then(|p| p.overrides.clone()).unwrap_or_default();
                let guard = Some(rule_cfg.expression.as_str());

                debug!("Expanding ruleset '{}' via rule '{}'", id, rule_cfg.id);
                executed.insert(id);
                for rs_rule in &ruleset.rules {
                    let (enabled, action) = overrides.resolve(rs_rule);
                    if !enabled {
                        debug!("  skipping disabled rule '{}'", rs_rule.id);
                        continue;
                    }
                    rules.push(compile_rule(rs_rule, &action, guard, scheme, &mut mgr)?);
                }
                continue;
            }

            rules.push(compile_rule(
                rule_cfg,
                &rule_cfg.action,
                None,
                scheme,
                &mut mgr,
            )?);
        }
    }

    for rs in &config.rulesets {
        if rs.kind != config::RulesetKind::Root && !executed.contains(rs.name.as_str()) {
            warn!(
                "Ruleset '{}' is never executed; its rules will not run",
                rs.name
            );
        }
    }

    Ok(Engine::new(rules, mgr, config.log_payloads))
}

/// Rule id prefix for compiled geo rules.
pub const GEO_RULE_PREFIX: &str = "geo:";

fn geo_rule_config(g: &config::GeoRule) -> config::RuleConfig {
    let response = (g.action == config::Action::Block).then(|| config::ActionParameters {
        response: Some(config::BlockResponse {
            status_code: 403,
            content_type: Some("text/plain; charset=utf-8".into()),
            content: Some("Access from your network or location is not allowed.\n".into()),
        }),
        scores: Vec::new(),
        id: None,
        overrides: None,
    });
    config::RuleConfig {
        id: format!("{GEO_RULE_PREFIX}{}", g.id),
        description: g.description.clone(),
        categories: vec!["geo".into()],
        r#ref: None,
        version: None,
        enabled: true,
        phase: config::Phase::RequestHeaders,
        action: g.action.clone(),
        expression: g.expression(),
        action_parameters: response,
        ratelimit: None,
        logging: config::RuleLoggingConfig::default(),
    }
}

/// Compile a single rule. `action` may differ from `rule_cfg.action` when an
/// `execute` override applies; `guard` is ANDed onto the rule's expression.
fn compile_rule(
    rule_cfg: &config::RuleConfig,
    action: &config::Action,
    guard: Option<&str>,
    scheme: &Scheme,
    mgr: &mut RateLimitManager,
) -> Result<CompiledRule, Box<dyn std::error::Error>> {
    debug!("Compiling rule '{}'", rule_cfg.id);

    let expression = match guard {
        Some(g) => format!("({}) and ({})", g, rule_cfg.expression),
        None => rule_cfg.expression.clone(),
    };
    let ast = scheme
        .parse(&expression)
        .map_err(|e| format!("Failed to parse rule '{}': {}", rule_cfg.id, e))?;
    let log_fields = payload::referenced_fields(&ast);
    let filter = ast.compile_with_compiler(&mut RuleCompiler::new(scheme));

    let phase = convert_phase(&rule_cfg.phase);
    let action = convert_action(rule_cfg, action)?;

    let ratelimit_characteristics = if let Some(ref rl_cfg) = rule_cfg.ratelimit {
        mgr.add_rule(&rule_cfg.id, rl_cfg);
        debug!(
            "  rate limit: {}/{} per {}s",
            rl_cfg.requests_per_period, rl_cfg.period, rl_cfg.mitigation_timeout
        );
        Some(rl_cfg.characteristics.clone())
    } else {
        None
    };

    Ok(CompiledRule {
        id: rule_cfg.id.clone(),
        phase,
        action,
        filter,
        ratelimit_characteristics,
        log_fields,
        logging: rule_cfg.logging.enabled,
    })
}

fn convert_phase(phase: &config::Phase) -> Phase {
    match phase {
        config::Phase::RequestHeaders => Phase::RequestHeaders,
        config::Phase::RequestBody => Phase::RequestBody,
        config::Phase::ResponseHeaders => Phase::ResponseHeaders,
        config::Phase::ResponseBody => Phase::ResponseBody,
        config::Phase::Logging => Phase::Logging,
    }
}

fn convert_action(
    rule: &config::RuleConfig,
    action: &config::Action,
) -> Result<Action, Box<dyn std::error::Error>> {
    Ok(match action {
        config::Action::Block => {
            let (status_code, content_type, content) =
                if let Some(ref params) = rule.action_parameters {
                    if let Some(ref resp) = params.response {
                        (
                            resp.status_code,
                            resp.content_type.clone(),
                            resp.content.clone(),
                        )
                    } else {
                        (403, None, None)
                    }
                } else {
                    (403, None, None)
                };
            Action::Block {
                status_code,
                content_type,
                content,
            }
        }
        config::Action::Allow => Action::Allow,
        config::Action::Log => Action::Log,
        config::Action::Score => {
            let scores = rule
                .action_parameters
                .as_ref()
                .map(|p| {
                    p.scores
                        .iter()
                        .map(|s| (s.name.clone(), s.increment))
                        .collect()
                })
                .unwrap_or_default();
            Action::Score { scores }
        }
        config::Action::Challenge => Action::Challenge,
        config::Action::Execute => {
            return Err(format!("rule '{}': nested execute is not supported", rule.id).into());
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(yaml: &str) -> Result<Engine, Box<dyn std::error::Error>> {
        let cfg: config::WafConfig = serde_yaml::from_str(yaml)?;
        let scheme = crate::waf::scheme::build(&cfg.scores, &cfg.token_ids());
        compile(&cfg, &scheme, None)
    }

    const BASE: &str = r#"
rulesets:
  - name: crs
    rules:
      - id: "1"
        categories: [a]
        action: block
        expression: 'http.request.uri.path contains "1"'
      - id: "2"
        categories: [b]
        action: log
        expression: 'http.request.uri.path contains "2"'
      - id: "3"
        enabled: false
        action: log
        expression: 'http.request.uri.path contains "3"'
"#;

    fn ids(engine: &Engine) -> Vec<String> {
        engine
            .rules_in(&Phase::RequestHeaders)
            .iter()
            .map(|r| r.id.clone())
            .collect()
    }

    #[test]
    fn only_root_rulesets_run_in_config_order() {
        let engine = load(&format!(
            r#"{BASE}
  - name: first
    kind: root
    rules:
      - id: a
        action: log
        expression: 'http.host == "x"'
  - name: second
    kind: root
    rules:
      - id: b
        action: log
        expression: 'http.host == "y"'
"#
        ))
        .unwrap();
        // `crs` is not a root ruleset and is never executed, so none of its
        // rules are loaded.
        assert_eq!(ids(&engine), vec!["a", "b"]);
    }

    #[test]
    fn execute_expands_ruleset_in_place_and_skips_disabled() {
        let engine = load(&format!(
            r#"{BASE}
  - name: main
    kind: root
    rules:
      - id: before
        action: log
        expression: 'http.host == "x"'
      - id: run
        action: execute
        expression: "true"
        action_parameters:
          id: crs
      - id: after
        action: log
        expression: 'http.host == "y"'
      - id: off
        enabled: false
        action: log
        expression: 'http.host == "z"'
"#
        ))
        .unwrap();
        assert_eq!(ids(&engine), vec!["before", "1", "2", "after"]);
    }

    #[test]
    fn execute_applies_action_overrides() {
        let engine = load(&format!(
            r#"{BASE}
  - name: main
    kind: root
    rules:
      - id: run
        action: execute
        expression: "true"
        action_parameters:
          id: crs
          overrides:
            action: log
            categories:
              - category: b
                enabled: false
            rules:
              - id: "3"
                enabled: true
                action: challenge
"#
        ))
        .unwrap();
        let rules = engine.rules_in(&Phase::RequestHeaders);
        assert_eq!(ids(&engine), vec!["1", "3"]);
        assert!(matches!(rules[0].action, Action::Log));
        assert!(matches!(rules[1].action, Action::Challenge));
    }

    #[test]
    fn execute_guard_expression_is_anded_onto_each_rule() {
        let engine = load(&format!(
            r#"{BASE}
  - name: main
    kind: root
    rules:
      - id: run
        action: execute
        expression: 'http.host == "guarded"'
        action_parameters:
          id: crs
"#
        ))
        .unwrap();
        let rules = engine.rules_in(&Phase::RequestHeaders);
        assert_eq!(rules.len(), 2);
        for r in rules {
            assert!(
                r.log_fields.iter().any(|f| f == "http.host"),
                "rule {} should reference guard field: {:?}",
                r.id,
                r.log_fields
            );
        }
    }

    #[test]
    fn execute_with_true_runs_ruleset_unconditionally() {
        let cfg: config::WafConfig = serde_yaml::from_str(&format!(
            r#"{BASE}
  - name: main
    kind: root
    rules:
      - id: run
        action: execute
        expression: "true"
        action_parameters:
          id: crs
"#
        ))
        .unwrap();
        let scheme = crate::waf::scheme::build(&cfg.scores, &cfg.token_ids());
        let engine = compile(&cfg, &scheme, None).unwrap();

        // The constant is not a payload field.
        let rules = engine.rules_in(&Phase::RequestHeaders);
        assert_eq!(rules[0].log_fields, vec!["http.request.uri.path"]);

        let mut ctx = crate::waf::scheme::new_context(&scheme);
        let path = scheme.get_field("http.request.uri.path").unwrap();
        ctx.set_field_value(path, "/a1").unwrap();
        let action = engine.evaluate(
            &Phase::RequestHeaders,
            &ctx,
            &mut Default::default(),
            &mut Vec::new(),
            &mut Default::default(),
        );
        match action {
            crate::waf::engine::RuleAction::Block { rule_id, .. } => assert_eq!(rule_id, "1"),
            _ => panic!("expected Block by rule '1'"),
        }
    }

    fn jwt_config(rules: &str) -> config::WafConfig {
        use crate::waf::jwt::test_support::hs256_config;

        serde_yaml::from_str(&format!(
            "token_configurations:{}rulesets:\n  - name: main\n    kind: \
             root\n    rules:\n{rules}",
            hs256_config("api")
        ))
        .unwrap()
    }

    #[test]
    fn jwt_rules_gate_requests_on_token_and_claims() {
        use serde_json::json;

        use crate::waf::engine::RuleAction;
        use crate::waf::jwt::JwtValidator;
        use crate::waf::jwt::test_support::hs256_token;
        use crate::waf::populate;

        let cfg = jwt_config(
            r#"
      - id: require-jwt
        action: block
        expression: 'not is_jwt_valid("api")'
      - id: admins-only
        action: block
        expression: 'http.request.uri.path == "/admin" and not any(http.request.jwt.claims.aud["api"][*] == "admin")'
"#,
        );
        let scheme = crate::waf::scheme::build(&cfg.scores, &cfg.token_ids());
        let engine = compile(&cfg, &scheme, None).unwrap();
        let jwt = JwtValidator::new(&cfg.token_configurations, &scheme).unwrap();

        // The ID of the rule that blocks the request, if any.
        let blocked_by = |path: &str, authorization: Option<&str>| {
            let mut req = populate::test_support::empty_request();
            req.path = path.into();
            if let Some(value) = authorization {
                req.headers.push(("authorization".into(), value.into()));
            }
            let mut ctx = crate::waf::scheme::new_context(&scheme);
            populate::request_fields(&mut ctx, &scheme, &req);
            let outcomes = jwt.evaluate(&ctx);
            populate::jwt_fields(&mut ctx, &scheme, &outcomes);
            match engine.evaluate(
                &Phase::RequestHeaders,
                &ctx,
                &mut Default::default(),
                &mut Vec::new(),
                &mut Default::default(),
            ) {
                RuleAction::Block { rule_id, .. } => Some(rule_id),
                _ => None,
            }
        };
        let require_jwt = Some("require-jwt".to_string());

        assert_eq!(blocked_by("/", None), require_jwt);
        assert_eq!(blocked_by("/", Some("Bearer junk")), require_jwt);

        let user = format!("Bearer {}", hs256_token(&json!({"aud": "users"})));
        assert_eq!(blocked_by("/", Some(&user)), None);
        assert_eq!(
            blocked_by("/admin", Some(&user)),
            Some("admins-only".to_string())
        );

        let admin = hs256_token(&json!({"aud": ["users", "admin"]}));
        assert_eq!(blocked_by("/admin", Some(&admin)), None);
    }

    #[test]
    fn jwt_rule_with_unknown_token_configuration_fails_to_compile() {
        let cfg = jwt_config(
            "      - id: typo\n        action: block\n        expression: 'not \
             is_jwt_valid(\"apii\")'\n",
        );
        let scheme = crate::waf::scheme::build(&cfg.scores, &cfg.token_ids());
        let err = match compile(&cfg, &scheme, None) {
            Ok(_) => panic!("expected parse error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("Failed to parse rule 'typo'"), "{err}");
        assert!(err.contains("unknown token configuration 'apii'"), "{err}");
    }

    #[test]
    fn execute_guard_parse_error_names_the_rule() {
        let err = match load(&format!(
            r#"{BASE}
  - name: main
    kind: root
    rules:
      - id: run
        action: execute
        expression: 'http.nope == "x"'
        action_parameters:
          id: crs
"#
        )) {
            Ok(_) => panic!("expected parse error"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("Failed to parse rule '1'"),
            "{err}"
        );
    }
}
