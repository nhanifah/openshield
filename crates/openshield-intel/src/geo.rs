//! IP location and network (ASN) lookups for the proxy.
//!
//! Loads a location database (City or Country) and an ASN database in
//! MaxMind DB format: DB-IP Lite or MaxMind GeoLite2. Lookups are local; no
//! address ever leaves the server. Missing files are not an error: the
//! proxy keeps running and the location fields stay empty (fail-open), so
//! geo rules never block requests whose location is unknown.
//!
//! Files are re-read when they change on disk (checked every minute), and
//! `download_dbip` fetches the current DB-IP Lite edition on request.
//! Replace files by renaming a finished file over the old one, as
//! `geoipupdate` and the downloader here do.

use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use arc_swap::ArcSwapOption;
use openshield_core::geoip::{GeoDbInfo, GeoIp};
use openshield_core::waf::data::GeoData;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::GeoConfig;
use crate::store::{Store, now_ms};

pub const SETTING_KEY: &str = "geo";
/// Largest compressed download accepted (DB-IP City Lite is about 60 MB).
const MAX_DOWNLOAD: u64 = 200 * 1024 * 1024;
/// Largest database file accepted after decompression.
const MAX_FILE: u64 = 600 * 1024 * 1024;
pub const DBIP_ATTRIBUTION: &str = "IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0";

/// Paths and update policy, editable from the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GeoSettings {
    pub city_mmdb: String,
    pub asn_mmdb: String,
    pub auto_update: bool,
}

impl GeoSettings {
    pub fn from_config(c: &GeoConfig, data_dir: &Path) -> Self {
        let dir = data_dir.join("geo");
        Self {
            city_mmdb: c
                .city_mmdb
                .clone()
                .unwrap_or_else(|| dir.join("dbip-city-lite.mmdb"))
                .display()
                .to_string(),
            asn_mmdb: c
                .asn_mmdb
                .clone()
                .unwrap_or_else(|| dir.join("dbip-asn-lite.mmdb"))
                .display()
                .to_string(),
            auto_update: c.auto_update,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        for (what, p) in [("location database", &self.city_mmdb), ("ASN database", &self.asn_mmdb)] {
            if p.trim().is_empty() || p.len() > 1024 || p.contains('\0') {
                return Err(format!("{what}: enter a file path"));
            }
            if !p.ends_with(".mmdb") {
                return Err(format!("{what}: the file must be a MaxMind DB file ending in .mmdb"));
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct State {
    settings: Option<GeoSettings>,
    stamps: [Option<(SystemTime, u64)>; 2],
    error: Option<String>,
    loaded_ts: Option<i64>,
    info: Vec<GeoDbInfo>,
    updating: bool,
    last_update: Option<(i64, String)>,
}

pub struct GeoService {
    db: ArcSwapOption<GeoIp>,
    state: Mutex<State>,
    defaults: GeoSettings,
    store: Option<Arc<Store>>,
    /// Where DB-IP downloads are written (`<data dir>/geo`). Downloads never
    /// overwrite files configured elsewhere.
    download_dir: PathBuf,
}

fn stamp(p: &Path) -> Option<(SystemTime, u64)> {
    let m = std::fs::metadata(p).ok()?;
    Some((m.modified().ok()?, m.len()))
}

/// Addresses that have no public location.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 carrier-grade NAT
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return is_private(IpAddr::V4(v4));
            }
            let s = v.segments();
            v.is_loopback() || v.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

impl GeoService {
    pub fn new(defaults: GeoSettings, store: Option<Arc<Store>>, download_dir: PathBuf) -> Self {
        Self {
            db: ArcSwapOption::empty(),
            state: Mutex::new(State::default()),
            defaults,
            store,
            download_dir,
        }
    }

    fn dbip_paths(&self) -> (PathBuf, PathBuf) {
        (self.download_dir.join("dbip-city-lite.mmdb"), self.download_dir.join("dbip-asn-lite.mmdb"))
    }

    /// The saved settings, or the config file's.
    pub fn settings(&self) -> (GeoSettings, bool) {
        if let Some(store) = &self.store
            && let Ok(Some((v, _))) = store.setting(SETTING_KEY)
            && let Ok(s) = serde_json::from_str::<GeoSettings>(&v)
        {
            return (s, true);
        }
        (self.defaults.clone(), false)
    }

    pub fn save_settings(&self, s: &GeoSettings, by: &str) -> Result<(), String> {
        s.validate()?;
        let store = self.store.as_ref().ok_or("no store")?;
        store.put_setting(SETTING_KEY, &serde_json::to_string(s).map_err(|e| e.to_string())?, false, by)?;
        self.load(true);
        Ok(())
    }

    pub fn reset_settings(&self) -> Result<(), String> {
        if let Some(store) = &self.store {
            store.delete_setting(SETTING_KEY)?;
        }
        self.load(true);
        Ok(())
    }

    /// (Re)open the databases when the settings or the files changed, or
    /// always with `force`. On failure the previous databases stay in use.
    pub fn load(&self, force: bool) {
        let (s, _) = self.settings();
        let paths = [PathBuf::from(&s.city_mmdb), PathBuf::from(&s.asn_mmdb)];
        let stamps = [stamp(&paths[0]), stamp(&paths[1])];
        {
            let st = self.state.lock();
            if !force && st.settings.as_ref() == Some(&s) && st.stamps == stamps {
                return;
            }
        }
        let city = stamps[0].map(|_| paths[0].as_path());
        let asn = stamps[1].map(|_| paths[1].as_path());
        let result = if city.is_none() && asn.is_none() {
            Ok(None)
        } else {
            GeoIp::open_parts(city, asn).map(Some)
        };
        let mut st = self.state.lock();
        st.settings = Some(s);
        st.stamps = stamps;
        match result {
            Ok(Some(db)) => {
                st.info = db.info();
                st.error = None;
                st.loaded_ts = Some(now_ms());
                let kinds: Vec<_> = st.info.iter().map(|i| format!("{} ({})", i.kind, i.database_type)).collect();
                log::info!("Geo databases loaded: {}", kinds.join(", "));
                self.db.store(Some(Arc::new(db)));
            }
            Ok(None) => {
                st.info.clear();
                st.error = None;
                st.loaded_ts = None;
                self.db.store(None);
            }
            Err(e) => {
                log::warn!("Geo databases not reloaded: {e}");
                st.error = Some(e);
            }
        }
    }

    /// Location of a client address; `None` for private addresses or when
    /// no database knows it.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoData> {
        if is_private(ip) {
            return None;
        }
        let db = self.db.load();
        let g = GeoData::from(&db.as_ref()?.lookup(ip));
        (g.country.is_some() || g.asn.is_some()).then_some(g)
    }

    pub fn loaded(&self) -> bool {
        self.db.load().is_some()
    }

    pub fn status(&self) -> Value {
        let (s, custom) = self.settings();
        let st = self.state.lock();
        let file = |p: &str| {
            let path = Path::new(p);
            match std::fs::metadata(path) {
                Ok(m) => json!({"path": p, "exists": true, "bytes": m.len(),
                    "modified_ts": m.modified().ok().and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()).map(|d| d.as_millis() as i64)}),
                Err(_) => json!({"path": p, "exists": false}),
            }
        };
        json!({
            "loaded": self.loaded(),
            "settings": s,
            "custom": custom,
            "files": {"location": file(&s.city_mmdb), "asn": file(&s.asn_mmdb)},
            "databases": st.info,
            "loaded_ts": st.loaded_ts,
            "error": st.error,
            "updating": st.updating,
            "last_update": st.last_update.as_ref().map(|(ts, msg)| json!({"ts": ts, "result": msg})),
            "attribution": DBIP_ATTRIBUTION,
        })
    }

    /// True when auto-update is on and a file is missing or over 32 days old.
    pub fn update_due(&self) -> bool {
        let (s, _) = self.settings();
        if !s.auto_update {
            return false;
        }
        let month = std::time::Duration::from_secs(32 * 86_400);
        let (c, a) = self.dbip_paths();
        [c, a].iter().any(|p| match stamp(p) {
            Some((t, _)) => t.elapsed().map(|e| e > month).unwrap_or(false),
            None => true,
        })
    }

    /// Download this month's DB-IP Lite City and ASN editions (last month's
    /// if this month's is not published yet) into the data directory, check
    /// them, and switch the settings to them.
    pub async fn download_dbip(self: &Arc<Self>, client: &reqwest::Client) -> Result<String, String> {
        {
            let mut st = self.state.lock();
            if st.updating {
                return Err("a download is already running".into());
            }
            st.updating = true;
        }
        let result = self.download_inner(client).await;
        let mut st = self.state.lock();
        st.updating = false;
        let msg = match &result {
            Ok(m) => m.clone(),
            Err(e) => format!("failed: {e}"),
        };
        st.last_update = Some((now_ms(), msg));
        drop(st);
        if result.is_ok() {
            let (c, a) = self.dbip_paths();
            let (mut s, _) = self.settings();
            let (c, a) = (c.display().to_string(), a.display().to_string());
            if s.city_mmdb != c || s.asn_mmdb != a {
                s.city_mmdb = c;
                s.asn_mmdb = a;
                if let Err(e) = self.save_settings(&s, "geo-update") {
                    log::warn!("Geo databases downloaded but settings not saved: {e}");
                }
            }
            self.load(true);
        }
        result
    }

    async fn download_inner(&self, client: &reqwest::Client) -> Result<String, String> {
        let (city_path, asn_path) = self.dbip_paths();
        use chrono::Datelike;
        let today = chrono::Utc::now().date_naive();
        let this = today.format("%Y-%m").to_string();
        let prev = today
            .with_day(1)
            .and_then(|d| d.pred_opt())
            .map(|d| d.format("%Y-%m").to_string())
            .unwrap_or_else(|| this.clone());
        let mut done = Vec::new();
        for (edition, target) in [("city", city_path), ("asn", asn_path)] {
            let mut last_err = String::new();
            let mut ok = false;
            for month in [&this, &prev] {
                let url = format!("https://download.db-ip.com/free/dbip-{edition}-lite-{month}.mmdb.gz");
                match fetch_gz(client, &url, &target, edition).await {
                    Ok(()) => {
                        done.push(format!("{edition} {month}"));
                        ok = true;
                        break;
                    }
                    Err(e) => last_err = format!("{url}: {e}"),
                }
            }
            if !ok {
                return Err(last_err);
            }
        }
        Ok(format!("downloaded DB-IP Lite {}", done.join(", ")))
    }
}

async fn fetch_gz(client: &reqwest::Client, url: &str, target: &Path, edition: &str) -> Result<(), String> {
    let mut resp = client
        .get(url)
        .timeout(std::time::Duration::from_secs(300))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }
    let mut gz = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        gz.extend_from_slice(&chunk);
        if gz.len() as u64 > MAX_DOWNLOAD {
            return Err("download is larger than expected".into());
        }
    }
    let target = target.to_path_buf();
    let edition = edition.to_string();
    tokio::task::spawn_blocking(move || install(&gz, &target, &edition))
        .await
        .map_err(|e| e.to_string())?
}

/// Decompress to a temporary file next to `target`, check it opens as the
/// right kind of database, then rename it into place.
fn install(gz: &[u8], target: &Path, edition: &str) -> Result<(), String> {
    let dir = target.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = target.with_extension("mmdb.part");
    let mut out = std::fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    let mut dec = flate2::read::GzDecoder::new(gz).take(MAX_FILE + 1);
    let n = std::io::copy(&mut dec, &mut out).map_err(|e| format!("not a gzip file: {e}"))?;
    out.flush().map_err(|e| e.to_string())?;
    drop(out);
    let check = if n > MAX_FILE {
        Err("database is larger than expected".to_string())
    } else if edition == "asn" {
        GeoIp::open_parts(None, Some(&tmp)).map(|_| ())
    } else {
        GeoIp::open_parts(Some(&tmp), None).map(|_| ())
    };
    if let Err(e) = check {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, target).map_err(|e| format!("{}: {e}", target.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_addresses_have_no_location() {
        for ip in ["10.1.2.3", "192.168.0.1", "172.16.5.4", "127.0.0.1", "100.64.1.1", "169.254.1.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "203.0.113.5", "2001:4860::8888", "100.128.0.1"] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }

    fn fixtures() -> GeoSettings {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/geo");
        GeoSettings {
            city_mmdb: dir.join("test-city.mmdb").display().to_string(),
            asn_mmdb: dir.join("test-asn.mmdb").display().to_string(),
            auto_update: false,
        }
    }

    #[test]
    fn test_databases_resolve_country_region_and_asn() {
        let g = GeoService::new(fixtures(), None, PathBuf::from("/nonexistent"));
        g.load(true);
        assert!(g.loaded(), "{}", g.status());
        let jk = g.lookup("203.0.113.10".parse().unwrap()).unwrap();
        assert_eq!(jk.country.as_deref(), Some("ID"));
        assert_eq!(jk.country_name.as_deref(), Some("Indonesia"));
        assert_eq!(jk.region_code.as_deref(), Some("JK"));
        assert_eq!(jk.region.as_deref(), Some("Jakarta"));
        assert_eq!(jk.asn, Some(64500));
        assert_eq!(jk.as_org.as_deref(), Some("Example Telecom ID (test)"));
        let jb = g.lookup("203.0.113.200".parse().unwrap()).unwrap();
        assert_eq!((jb.region_code.as_deref(), jb.asn), (Some("JB"), Some(64501)));
        assert_eq!(g.lookup("198.51.100.7".parse().unwrap()).unwrap().country.as_deref(), Some("CN"));
        assert!(g.lookup("8.8.8.8".parse().unwrap()).is_none(), "not in the test data");
        assert!(g.lookup("10.0.0.1".parse().unwrap()).is_none(), "private");
        let info = &g.status()["databases"];
        assert_eq!(info.as_array().unwrap().len(), 2);
    }

    #[test]
    fn missing_files_are_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let s = GeoSettings::from_config(&GeoConfig::default(), dir.path());
        let g = GeoService::new(s, None, dir.path().join("geo"));
        g.load(true);
        assert!(!g.loaded());
        assert!(g.lookup("8.8.8.8".parse().unwrap()).is_none());
        assert!(g.status()["error"].is_null());
    }

    #[test]
    fn a_file_that_is_not_a_database_is_refused_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        let s = GeoSettings::from_config(&GeoConfig::default(), dir.path());
        std::fs::create_dir_all(dir.path().join("geo")).unwrap();
        std::fs::write(&s.city_mmdb, b"not a database").unwrap();
        let g = GeoService::new(s, None, dir.path().join("geo"));
        g.load(true);
        assert!(!g.loaded());
        assert!(g.status()["error"].as_str().unwrap().contains("dbip-city-lite.mmdb"));
        assert!(install(b"garbage", &dir.path().join("x.mmdb"), "city").is_err());
        assert!(!dir.path().join("x.mmdb").exists());
    }
}
