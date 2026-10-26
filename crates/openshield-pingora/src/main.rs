#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod config;
mod proxy;
mod reload;

use std::sync::Arc;

use clap::Parser;
use config::ServerConfig;
use log::{error, info};
use openshield_core::{Waf, logging};
use pingora::prelude::*;
use pingora::proxy::http_proxy_service;
use pingora::server::configuration::Opt as PingoraOpt;

#[derive(Parser)]
#[command(name = "openshield", version, about = "OpenShield proxy")]
struct Cli {
    /// Path to config file
    #[arg(short = 'c', long = "config", default_value = "config.yaml")]
    config: std::path::PathBuf,

    /// Upgrade from a running instance (receive listening sockets)
    #[arg(short, long)]
    upgrade: bool,

    /// Test config and exit
    #[arg(short, long)]
    test: bool,
}

/// Split an upstream address into host, port and TLS flag.
/// Accepts `host`, `host:port`, `[v6]`, `[v6]:port`, with an optional
/// `http://` or `https://` prefix.
pub(crate) fn parse_upstream(addr: &str) -> Result<(String, u16, bool), String> {
    let (rest, tls) = if let Some(rest) = addr.strip_prefix("https://") {
        (rest, true)
    } else if let Some(rest) = addr.strip_prefix("http://") {
        (rest, false)
    } else {
        (addr, false)
    };
    let rest = rest.trim_end_matches('/');
    let default_port = if tls { 443 } else { 80 };
    let parse_port = |p: &str| {
        p.parse::<u16>()
            .map_err(|_| format!("invalid upstream port in {addr:?}"))
    };
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (h, after) = v6
            .split_once(']')
            .ok_or_else(|| format!("unterminated IPv6 address in {addr:?}"))?;
        match after.strip_prefix(':') {
            Some(p) => (h.to_string(), parse_port(p)?),
            None if after.is_empty() => (h.to_string(), default_port),
            None => return Err(format!("invalid upstream address {addr:?}")),
        }
    } else if let Some((h, p)) = rest.rsplit_once(':') {
        (h.to_string(), parse_port(p)?)
    } else {
        (rest.to_string(), default_port)
    };
    if host.is_empty() {
        return Err(format!("missing upstream host in {addr:?}"));
    }
    Ok((host, port, tls))
}

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("openshield=info,pingora=info"),
    )
    .format_timestamp_millis()
    .init();

    let cli = Cli::parse();

    let config = match ServerConfig::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {:?}: {}", cli.config, e);
            std::process::exit(1);
        }
    };
    info!("Config loaded from {:?}", cli.config);

    // `--test`: compile everything that can be compiled, start nothing.
    if cli.test {
        if let Err(e) = Waf::from_config(&config.waf) {
            error!("Failed to initialize WAF: {}", e);
            std::process::exit(1);
        }
        if config.admin.enabled
            && let Err(e) = openshield_intel::admin::auth::Authenticator::new(&config.admin.users)
        {
            error!("Invalid admin users: {}", e);
            std::process::exit(1);
        }
        info!("Configuration OK");
        std::process::exit(0);
    }

    // With the intelligence layer on, the WAF policy is managed at runtime
    // (versions, API changes, rollback); otherwise it is built once.
    let (waf_source, intel) = if config.intel.enabled {
        let file = std::fs::read_to_string(&cli.config).unwrap_or_default();
        let waf_yaml = match openshield_intel::policy::waf_yaml_from_config_file(&file) {
            Ok(y) => y,
            Err(e) => {
                error!("Failed to read WAF policy from config: {}", e);
                std::process::exit(1);
            }
        };
        match openshield_intel::Intel::start(&config.intel, &config.admin, &waf_yaml) {
            Ok(intel) => (
                proxy::WafSource::Managed(Arc::clone(&intel.policy)),
                Some(intel),
            ),
            Err(e) => {
                error!("Failed to start the intelligence layer: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        match Waf::from_config(&config.waf) {
            Ok(waf) => (proxy::WafSource::Static(Arc::new(waf)), None),
            Err(e) => {
                error!("Failed to initialize WAF: {}", e);
                std::process::exit(1);
            }
        }
    };

    // Logger
    let logger = Arc::new(logging::Logger::new(&config.logging));
    info!(
        "Logging: access={:?}, audit={:?}, format={}",
        config.logging.access_log, config.logging.audit_log, config.logging.format
    );

    // Upstream
    let (upstream_host, upstream_port, upstream_tls) =
        parse_upstream(&config.upstream).expect("upstream validated at load");
    let trusted_proxies =
        proxy::TrustedProxies::new(&config.trusted_proxies, &config.client_ip_header)
            .expect("trusted_proxies validated at load");
    if !trusted_proxies.is_empty() {
        info!(
            "Trusted proxies: {:?} (client IP from {})",
            config.trusted_proxies, config.client_ip_header
        );
    }
    info!(
        "Reverse proxy: {} -> {}:{} (tls={})",
        config.listen, &upstream_host, upstream_port, upstream_tls
    );

    // Server
    let mut conf = pingora::server::configuration::ServerConf::default();
    conf.threads = config.workers.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    if let Some(pool_size) = config.upstream_keepalive_pool {
        conf.upstream_keepalive_pool_size = pool_size;
    }
    conf.pid_file = config.pid_file.clone();
    conf.upgrade_sock = config.upgrade_sock.clone();
    info!(
        "Worker threads: {}, upstream keepalive pool: {}",
        conf.threads, conf.upstream_keepalive_pool_size
    );

    let pingora_opt = PingoraOpt {
        upgrade: cli.upgrade,
        daemon: false,
        nocapture: false,
        test: cli.test,
        conf: None,
    };
    let mut server = Server::new_with_opt_and_conf(Some(pingora_opt), conf);
    server.bootstrap();

    let handler = proxy::ReverseProxyHandler {
        waf: waf_source,
        intel: intel.as_ref().map(|i| Arc::clone(&i.hub)),
        controls: intel.as_ref().map(|i| Arc::clone(&i.controls)),
        geo: intel.as_ref().map(|i| Arc::clone(&i.geo)),
        logger,
        upstream_tls,
        upstream_host,
        upstream_port,
        max_request_header_bytes: config.max_request_header_bytes,
        trusted_proxies,
    };

    let mut proxy_service = http_proxy_service(&server.configuration, handler);
    if let Some(ref tls_cfg) = config.tls {
        use pingora::listeners::tls::TlsSettings;
        let mut tls_settings = TlsSettings::intermediate(
            tls_cfg.cert.to_str().expect("invalid cert path"),
            tls_cfg.key.to_str().expect("invalid key path"),
        )
        .expect("Failed to load TLS cert/key");
        tls_settings.enable_h2();
        proxy_service.add_tls_with_settings(&config.listen, None, tls_settings);
        info!("Listening on {} (TLS)", config.listen);
    } else {
        proxy_service.add_tcp(&config.listen);
        info!("Listening on {} (plain HTTP)", config.listen);
    }
    server.add_service(proxy_service);

    if let Some(ref metrics_cfg) = config.metrics {
        if metrics_cfg.enabled {
            let mut prom_service = pingora_prometheus::prometheus_http_service();
            prom_service.add_tcp(&metrics_cfg.listen);
            server.add_service(prom_service);
            info!("Prometheus metrics at {}", metrics_cfg.listen);
        }
    }

    reload::start_reload_listener(cli.config.clone());

    // Keeps the intelligence runtime alive for the life of the server.
    let _intel = intel;
    server.run_forever();
}

#[cfg(test)]
mod tests {
    use super::parse_upstream;

    #[test]
    fn upstream_forms() {
        assert_eq!(parse_upstream("http://a:81").unwrap(), ("a".into(), 81, false));
        assert_eq!(parse_upstream("https://a").unwrap(), ("a".into(), 443, true));
        assert_eq!(parse_upstream("a").unwrap(), ("a".into(), 80, false));
        assert_eq!(parse_upstream("http://[::1]:8080/").unwrap(), ("::1".into(), 8080, false));
        assert_eq!(parse_upstream("https://[2001:db8::1]").unwrap(), ("2001:db8::1".into(), 443, true));
    }

    #[test]
    fn bad_upstreams_are_errors_not_panics() {
        for a in ["a:xyz", "http://:80", "[::1", "a:99999"] {
            assert!(parse_upstream(a).is_err(), "{a}");
        }
    }
}
