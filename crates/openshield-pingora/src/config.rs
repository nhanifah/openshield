//! The proxy's configuration: server settings plus the embedded WAF config.
//!
//! Both live in one YAML file. The server keys are read here; every other
//! key belongs to [`WafConfig`].

use std::path::{Path, PathBuf};

use openshield_core::config::WafConfig;
use openshield_core::logging::LoggingConfig;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    pub upstream: String,

    #[serde(default)]
    pub tls: Option<TlsConfig>,

    #[serde(default)]
    pub workers: Option<usize>,

    #[serde(default = "default_pid_file")]
    pub pid_file: String,

    #[serde(default = "default_upgrade_sock")]
    pub upgrade_sock: String,

    #[serde(default)]
    pub upstream_keepalive_pool: Option<usize>,

    #[serde(default)]
    pub logging: LoggingConfig,

    #[serde(default)]
    pub metrics: Option<MetricsConfig>,

    /// Requests with a larger header block get 431.
    #[serde(default = "default_max_request_header_bytes")]
    pub max_request_header_bytes: usize,

    /// Peers (addresses or CIDRs) allowed to name the client in
    /// `client_ip_header`. Empty: the TCP peer is always the client.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    #[serde(default = "default_client_ip_header")]
    pub client_ip_header: String,

    /// Security events, anomaly detection and AI supervision.
    #[serde(default)]
    pub intel: openshield_intel::config::IntelConfig,

    /// Dashboard and admin API.
    #[serde(default)]
    pub admin: openshield_intel::config::AdminConfig,

    #[serde(flatten)]
    pub waf: WafConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_listen")]
    pub listen: String,
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml(&content)
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config: ServerConfig = serde_yaml::from_str(yaml)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.listen.is_empty() {
            return Err("listen address is required".into());
        }
        if self.upstream.is_empty() {
            return Err("upstream address is required".into());
        }
        crate::parse_upstream(&self.upstream)?;
        crate::proxy::TrustedProxies::new(&self.trusted_proxies, &self.client_ip_header)?;
        if self.max_request_header_bytes < 1024 {
            return Err("max_request_header_bytes must be at least 1024".into());
        }
        self.intel.validate()?;
        self.admin.validate(&self.intel)?;
        self.waf.validate()
    }
}

fn default_max_request_header_bytes() -> usize {
    65536
}
fn default_client_ip_header() -> String {
    "X-Forwarded-For".into()
}
fn default_true() -> bool {
    true
}
fn default_metrics_listen() -> String {
    "127.0.0.1:9090".into()
}
fn default_pid_file() -> String {
    "/tmp/openshield.pid".into()
}
fn default_upgrade_sock() -> String {
    "/tmp/openshield_upgrade.sock".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_and_waf_keys_share_one_file() {
        let cfg = ServerConfig::from_yaml(
            r#"
listen: "127.0.0.1:8080"
upstream: "https://app.internal"
workers: 2
upstream_keepalive_pool: 64
tls: {cert: c.pem, key: k.pem}
logging: {format: text, access_log: /tmp/a.log}
metrics: {listen: "0.0.0.0:9100"}
detection_only: true
max_request_body_buffer: 4096
request_body_limit_action: reject
log_payloads: true
scores: [sqli]
lists:
  - {name: admins, kind: ip, items: ["10.0.0.0/8"]}
rulesets:
  - name: main
    kind: root
    rules:
      - id: r1
        action: block
        expression: 'ip.src in $admins'
"#,
        )
        .unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:8080");
        assert_eq!(cfg.workers, Some(2));
        assert_eq!(cfg.upstream_keepalive_pool, Some(64));
        assert_eq!(cfg.pid_file, "/tmp/openshield.pid");
        assert!(cfg.tls.is_some());
        assert_eq!(cfg.logging.format, "text");
        assert_eq!(cfg.logging.access_log, PathBuf::from("/tmp/a.log"));
        assert_eq!(cfg.logging.audit_log, PathBuf::from("/dev/stderr"));
        let metrics = cfg.metrics.unwrap();
        assert!(metrics.enabled);
        assert_eq!(metrics.listen, "0.0.0.0:9100");

        assert!(cfg.waf.detection_only);
        assert_eq!(cfg.waf.max_request_body_buffer, 4096);
        assert_eq!(cfg.waf.max_response_body_buffer, 1_048_576);
        assert!(cfg.waf.log_payloads);
        assert_eq!(cfg.waf.scores, vec!["sqli"]);
        assert_eq!(cfg.waf.lists.len(), 1);
        assert_eq!(cfg.waf.rulesets[0].rules[0].id, "r1");
    }

    #[test]
    fn minimal_config_needs_only_listen_and_upstream() {
        let cfg = ServerConfig::from_yaml("listen: a\nupstream: b\n").unwrap();
        assert_eq!(cfg.max_request_header_bytes, 65536);
        assert!(cfg.trusted_proxies.is_empty());
        assert!(cfg.waf.rulesets.is_empty());
        assert!(!cfg.waf.log_payloads);
    }

    #[test]
    fn invalid_upstream_and_proxies_are_rejected() {
        assert!(ServerConfig::from_yaml("listen: a\nupstream: 'h:notaport'\n").is_err());
        assert!(
            ServerConfig::from_yaml("listen: a\nupstream: b\ntrusted_proxies: [nope]\n").is_err()
        );
    }

    #[test]
    fn missing_server_keys_are_rejected() {
        assert!(ServerConfig::from_yaml("upstream: b\n").is_err());
        assert!(ServerConfig::from_yaml("listen: ''\nupstream: b\n").is_err());
    }

    #[test]
    fn waf_validation_still_runs() {
        let err = ServerConfig::from_yaml(
            "listen: a\nupstream: b\nlists:\n  - {name: x, kind: ip}\n  - {name: x, kind: ip}\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate list name"), "{err}");
    }

    #[test]
    fn old_logging_log_payloads_key_fails_loudly() {
        let err =
            ServerConfig::from_yaml("listen: a\nupstream: b\nlogging:\n  log_payloads: true\n")
                .unwrap_err();
        assert!(err.to_string().contains("log_payloads"), "{err}");
    }
}
