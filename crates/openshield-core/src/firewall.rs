//! A configured firewall instance: everything built once from the config and
//! shared by every [`Transaction`].

use std::sync::Arc;

use log::info;
use wirefilter_engine::Scheme;

use crate::challenge::ChallengeManager;
use crate::compiler;
use crate::config::{BodyLimitAction, WafConfig};
use crate::geoip::GeoIp;
use crate::redact::Redactor;
use crate::transaction::Transaction;
use crate::waf::engine::{Engine, Phase};
use crate::waf::jwt::JwtValidator;
use crate::waf::lists::{self, BytesListMatcher, IpListMatcher};
use crate::waf::schema::SchemaValidator;
use crate::waf::scheme;

/// Request-processing settings that apply to every transaction.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Evaluate rules and log, but never block or challenge.
    pub detection_only: bool,
    pub max_request_body_buffer: usize,
    pub request_body_limit_action: BodyLimitAction,
    pub inspect_response_body: bool,
    pub max_response_body_buffer: usize,
    pub response_body_limit_action: BodyLimitAction,
}

impl From<&WafConfig> for Settings {
    fn from(config: &WafConfig) -> Self {
        Self {
            detection_only: config.detection_only,
            max_request_body_buffer: config.max_request_body_buffer,
            request_body_limit_action: config.request_body_limit_action,
            inspect_response_body: config.inspect_response_body,
            max_response_body_buffer: config.max_response_body_buffer,
            response_body_limit_action: config.response_body_limit_action,
        }
    }
}

/// The firewall: compiled rules, validators, lists and lookups.
///
/// Build one with [`Waf::from_config`], wrap it in an [`Arc`], and start a
/// [`Transaction`] per request.
pub struct Waf {
    pub(crate) scheme: Scheme,
    pub(crate) engine: Engine,
    pub(crate) jwt: JwtValidator,
    pub(crate) schemas: SchemaValidator,
    pub(crate) ip_lists: IpListMatcher,
    pub(crate) bytes_lists: BytesListMatcher,
    pub(crate) geoip: Option<GeoIp>,
    pub(crate) challenge: Option<ChallengeManager>,
    pub(crate) error_pages: crate::error_page::ErrorPagesConfig,
    pub(crate) redactor: Redactor,
    pub(crate) settings: Settings,
    pub(crate) has_request_body_rules: bool,
    pub(crate) has_response_body_rules: bool,
}

impl Waf {
    pub fn from_config(config: &WafConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let geoip = match config.geoip.as_ref() {
            Some(geo_cfg) => {
                let g = GeoIp::open(&geo_cfg.city_mmdb, &geo_cfg.asn_mmdb)
                    .map_err(|e| format!("failed to open MaxMind databases: {e}"))?;
                info!(
                    "GeoIP loaded: city={:?}, asn={:?}",
                    geo_cfg.city_mmdb, geo_cfg.asn_mmdb
                );
                Some(g)
            }
            None => None,
        };

        let scheme = scheme::build(&config.scores, &config.token_ids());
        info!("WAF scheme: {} fields", scheme.field_count());

        let engine = compiler::compile(config, &scheme, None)
            .map_err(|e| format!("failed to compile rules: {e}"))?;
        info!("Rules compiled: {}", engine.rule_count());

        let jwt = JwtValidator::new(&config.token_configurations, &scheme)
            .map_err(|e| format!("failed to load token configurations: {e}"))?;
        if !jwt.is_empty() {
            info!(
                "Token configurations: {}",
                config.token_configurations.len()
            );
        }

        let schemas = SchemaValidator::new(&config.schemas)
            .map_err(|e| format!("failed to load schemas: {e}"))?;
        if !schemas.is_empty() {
            info!("Schemas: {}", config.schemas.len());
        }

        let (ip_lists, bytes_lists) = lists::build_from_config(&config.lists)
            .map_err(|e| format!("failed to load lists: {e}"))?;

        config
            .error_pages
            .validate()
            .map_err(|e| format!("error_pages: {e}"))?;
        let challenge = config.challenge.as_ref().map(|cfg| {
            info!("Challenge page enabled (Turnstile)");
            ChallengeManager::new(cfg, &config.error_pages)
        });

        if config.detection_only {
            info!("Detection-only mode: rules evaluate but no requests will be blocked");
        }

        let has_request_body_rules = engine.has_phase(&Phase::RequestBody);
        let has_response_body_rules = engine.has_phase(&Phase::ResponseBody);

        Ok(Self {
            scheme,
            engine,
            jwt,
            schemas,
            ip_lists,
            bytes_lists,
            geoip,
            challenge,
            error_pages: config.error_pages.clone(),
            redactor: Redactor::new(&config.redaction),
            settings: Settings::from(config),
            has_request_body_rules,
            has_response_body_rules,
        })
    }

    /// Start processing a new request.
    pub fn transaction(self: &Arc<Self>) -> Transaction {
        Transaction::new(Arc::clone(self))
    }

    pub fn scheme(&self) -> &Scheme {
        &self.scheme
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// How block, rate-limit and error pages look.
    pub fn error_pages(&self) -> &crate::error_page::ErrorPagesConfig {
        &self.error_pages
    }

    pub fn challenge(&self) -> Option<&ChallengeManager> {
        self.challenge.as_ref()
    }

    /// Masks secrets in anything recorded about a request.
    pub fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    /// True when a response body may be withheld or replaced, so the host
    /// must not promise the upstream `Content-Length` to the client.
    pub fn rewrites_response_body(&self) -> bool {
        self.settings.inspect_response_body && self.has_response_body_rules
    }
}
