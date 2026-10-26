//! Starting the intelligence layer next to the proxy.

use std::sync::Arc;
use std::time::Duration;


use crate::admin::{self, App, auth::Authenticator};
use crate::ai::sanitize::Sanitizer;
use crate::config::{AdminConfig, IntelConfig};
use crate::controls::{Controls, parse_target};
use crate::geo::{GeoService, GeoSettings};
use crate::hub::{EventHub, STREAM_MAX};
use crate::policy::PolicyManager;
use crate::settings::Settings;
use crate::store::{Store, now_ms};
use crate::vault::Vault;

/// Everything the proxy needs from the intelligence layer.
pub struct Intel {
    pub hub: Arc<EventHub>,
    pub policy: Arc<PolicyManager>,
    pub controls: Arc<Controls>,
    /// IP location and ASN lookups for the proxy.
    pub geo: Arc<GeoService>,
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
        // Secrets and stored policies are encrypted with this key.
        let vault = Arc::new(Vault::load(&Vault::default_key_file(&cfg.store.path))?);
        log::info!("Secret key: {}", vault.source);
        store.set_vault(Arc::clone(&vault))?;
        let settings = Arc::new(Settings::load(Arc::clone(&store), cfg.clone())?);

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

        // Location databases: optional, re-read when the files change.
        let data_dir = cfg.store.path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        let geo = Arc::new(GeoService::new(GeoSettings::from_config(&cfg.geo, &data_dir), Some(Arc::clone(&store)), data_dir.join("geo")));
        geo.load(true);
        if !geo.loaded() {
            log::warn!("No IP location database loaded: country, region and ASN stay empty and geo rules match nothing. \
                        Download DB-IP Lite under Settings, Geo data, or point intel.geo at GeoLite2 files.");
        }
        {
            let geo = Arc::clone(&geo);
            runtime.spawn(async move {
                let client = reqwest::Client::builder().user_agent("openshield-geo-update").build().ok();
                let mut tick = tokio::time::interval(Duration::from_secs(60));
                loop {
                    tick.tick().await;
                    let g = Arc::clone(&geo);
                    let _ = tokio::task::spawn_blocking(move || g.load(false)).await;
                    if let Some(c) = &client
                        && geo.update_due()
                    {
                        match geo.download_dbip(c).await {
                            Ok(m) => log::info!("Geo databases: {m}"),
                            // Retried on the next tick only after a day, so a
                            // failing mirror is not hammered.
                            Err(e) => {
                                log::warn!("Geo database update failed: {e}");
                                tokio::time::sleep(Duration::from_secs(86_400)).await;
                            }
                        }
                    }
                }
            });
        }

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
        let settings2 = Arc::clone(&settings);
        let hub = runtime.block_on(async move {
            let hub = EventHub::start(cfg2, store2, controls2, settings2, sanitizer);
            // A missing key is not fatal: it can be entered in the dashboard.
            if let Err(e) = hub.reconfigure_ai() {
                log::warn!("AI analysis is off: {e}. Set the API key under Settings in the dashboard.");
            }
            Ok::<_, String>(hub)
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
            let setup_file = Vault::default_key_file(&cfg.store.path).with_file_name("openshield-setup-token");
            let auth = Authenticator::with_store(&admin_cfg.users, Arc::clone(&store), setup_file)?;
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
                vault_source: vault.source.clone(),
                passkeys: Default::default(),
                geo: Arc::clone(&geo),
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
            geo,
            _runtime: runtime,
        })
    }
}
