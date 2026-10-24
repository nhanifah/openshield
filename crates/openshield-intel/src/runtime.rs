//! Starting the intelligence layer next to the proxy.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::admin::{self, App, auth::Authenticator};
use crate::ai::gemini::GeminiClient;
use crate::ai::sanitize::Sanitizer;
use crate::ai::supervisor::{Provider, Supervisor};
use crate::config::{AdminConfig, IntelConfig};
use crate::controls::{Controls, parse_target};
use crate::hub::{EventHub, STREAM_MAX};
use crate::policy::PolicyManager;
use crate::store::{Store, now_ms};

/// Everything the proxy needs from the intelligence layer.
pub struct Intel {
    pub hub: Arc<EventHub>,
    pub policy: Arc<PolicyManager>,
    pub controls: Arc<Controls>,
    _runtime: tokio::runtime::Runtime,
}

impl Intel {
    /// Open the store, restore dynamic controls, load the policy, start the
    /// AI supervisor (if enabled), the hub and the admin server, on a
    /// dedicated runtime separate from the proxy's.
    ///
    /// `waf_yaml` is the WAF part of the config file.
    pub fn start(cfg: &IntelConfig, admin_cfg: &AdminConfig, waf_yaml: &str) -> Result<Self, String> {
        cfg.validate()?;
        admin_cfg.validate(cfg)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("openshield-intel")
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;

        let store = Arc::new(Store::open(&cfg.store.path)?);
        log::info!("Intel store: {:?} ({} events)", cfg.store.path, store.event_count().unwrap_or(0));

        let controls = Arc::new(Controls::default());
        let now = now_ms();
        let mut restored = 0;
        for c in store.controls()? {
            if c.expires_at.is_some_and(|t| t <= now) {
                continue;
            }
            if let Ok(net) = parse_target(&c.value) {
                match c.kind.as_str() {
                    "ip_block" => controls.block(net, c.expires_at),
                    "ip_allow" => controls.allow(net, c.expires_at),
                    _ => continue,
                }
                restored += 1;
            }
        }
        if restored > 0 {
            log::info!("Restored {restored} dynamic IP controls");
        }

        let policy = Arc::new(PolicyManager::init(waf_yaml, Some(&store))?);

        // Per-process key for pseudonymizing client IPs sent to the model and
        // written to datasets.
        let ip_key: Vec<u8> = uuid::Uuid::new_v4()
            .as_bytes()
            .iter()
            .chain(uuid::Uuid::new_v4().as_bytes().iter())
            .copied()
            .collect();
        let sanitizer = Arc::new(Sanitizer::new(
            if cfg.ai.pseudonymize_ip { Some(ip_key) } else { None },
            cfg.ai.send_body,
        ));

        STREAM_MAX.store(admin_cfg.stream_max_per_sec as u64, std::sync::atomic::Ordering::Relaxed);

        let cfg2 = cfg.clone();
        let store2 = Arc::clone(&store);
        let controls2 = Arc::clone(&controls);
        let hub = runtime.block_on(async move {
            let (ai, outcomes) = if cfg2.ai.enabled {
                let key = std::env::var(&cfg2.ai.api_key_env)
                    .map_err(|_| format!("AI is enabled but {} is not set", cfg2.ai.api_key_env))?;
                let client = GeminiClient::new(
                    &cfg2.ai.base_url,
                    &cfg2.ai.model,
                    key,
                    Duration::from_millis(cfg2.ai.timeout_ms),
                )?;
                let (tx, rx) = mpsc::unbounded_channel();
                let provider: Arc<dyn Provider> = Arc::new(client);
                log::info!("AI supervision: {} model {} at {}", "gemini", cfg2.ai.model, cfg2.ai.base_url);
                (Some(Supervisor::start(cfg2.ai.clone(), provider, tx)), Some(rx))
            } else {
                (None, None)
            };
            Ok::<_, String>(EventHub::start(cfg2, store2, controls2, ai, outcomes, sanitizer))
        })?;

        {
            let hub = Arc::clone(&hub);
            runtime.spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                loop {
                    tick.tick().await;
                    crate::metrics::update(&hub);
                }
            });
        }

        if admin_cfg.enabled {
            let auth = Authenticator::new(&admin_cfg.users)?;
            let dataset_dir = cfg
                .store
                .path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_default()
                .join("datasets");
            let app = Arc::new(App {
                hub: Arc::clone(&hub),
                policy: Arc::clone(&policy),
                auth,
                cfg: admin_cfg.clone(),
                dataset_dir,
            });
            let listen = admin_cfg.listen.clone();
            // Bind now so a bad address fails startup instead of logging later.
            let std_listener = std::net::TcpListener::bind(&listen).map_err(|e| format!("admin listen {listen}: {e}"))?;
            drop(std_listener);
            runtime.spawn(async move {
                if let Err(e) = admin::serve(app, listen).await {
                    log::error!("admin server stopped: {e}");
                }
            });
        }

        Ok(Self {
            hub,
            policy,
            controls,
            _runtime: runtime,
        })
    }
}
