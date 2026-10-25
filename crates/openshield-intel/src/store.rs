//! Persistent storage (SQLite, WAL mode).
//!
//! Events are written in batches by the hub's writer thread through
//! [`Store::insert_events`]. Everything else (labels, alerts, controls,
//! audit, policy versions) is low-rate and written directly. Readers use a
//! separate connection.

use std::path::Path;
use std::time::Duration;

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::Value;

use crate::ai::types::AiVerdict;
use crate::event::SecurityEvent;

pub type Result<T> = std::result::Result<T, String>;

fn e<E: std::fmt::Display>(err: E) -> String {
    format!("store: {err}")
}

pub struct Store {
    write: Mutex<Connection>,
    read: Mutex<Connection>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    ts INTEGER NOT NULL,
    client_ip TEXT NOT NULL,
    action TEXT NOT NULL,
    status INTEGER NOT NULL,
    path TEXT NOT NULL,
    rules TEXT NOT NULL,
    anomaly REAL NOT NULL,
    ai_category TEXT,
    label TEXT,
    fingerprint TEXT NOT NULL,
    search TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_ip_ts ON events(client_ip, ts);
CREATE INDEX IF NOT EXISTS events_action_ts ON events(action, ts);

CREATE TABLE IF NOT EXISTS ai_verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ai_event ON ai_verdicts(event_id);

CREATE TABLE IF NOT EXISTS labels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    label TEXT NOT NULL,
    source TEXT NOT NULL,
    reviewer TEXT,
    status TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    ts INTEGER NOT NULL,
    decided_ts INTEGER,
    policy_version INTEGER,
    model_version TEXT
);
CREATE INDEX IF NOT EXISTS labels_status ON labels(status, ts);
CREATE INDEX IF NOT EXISTS labels_event ON labels(event_id);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    last_ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT,
    count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS alerts_status ON alerts(status, last_ts);

CREATE TABLE IF NOT EXISTS controls (
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    expires_at INTEGER,
    reason TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (kind, value)
);

CREATE TABLE IF NOT EXISTS admin_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT NOT NULL,
    result TEXT NOT NULL,
    ip TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_versions (
    version INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    comment TEXT NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    yaml TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    rule_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    summary TEXT NOT NULL,
    payload TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL,
    decided_by TEXT,
    decided_ts INTEGER
);

CREATE TABLE IF NOT EXISTS datasets (
    version TEXT PRIMARY KEY,
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    params TEXT NOT NULL,
    stats TEXT NOT NULL,
    dir TEXT NOT NULL
);
"#;

#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub limit: usize,
    pub before: Option<i64>,
    pub since: Option<i64>,
    pub action: Option<String>,
    pub ip: Option<String>,
    pub path: Option<String>,
    pub rule: Option<String>,
    pub q: Option<String>,
    pub min_anomaly: Option<f64>,
    pub ai_category: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Label {
    pub id: i64,
    pub event_id: String,
    pub label: String,
    pub source: String,
    pub reviewer: Option<String>,
    pub status: String,
    pub note: String,
    pub created_by: String,
    pub ts: i64,
    pub decided_ts: Option<i64>,
    pub policy_version: Option<i64>,
    pub model_version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub id: i64,
    pub ts: i64,
    pub last_ts: i64,
    pub kind: String,
    pub subject: String,
    pub severity: String,
    pub detail: Value,
    pub status: String,
    pub summary: Option<String>,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Control {
    #[serde(skip)]
    pub kind: String,
    pub value: String,
    pub expires_at: Option<i64>,
    pub reason: String,
    pub actor: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: i64,
    pub actor: String,
    pub role: String,
    pub action: String,
    pub target: String,
    pub detail: Value,
    pub result: String,
    pub ip: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyVersion {
    pub version: i64,
    pub ts: i64,
    pub actor: String,
    pub comment: String,
    pub source: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yaml: Option<String>,
    #[serde(skip)]
    pub file_hash: String,
    pub rule_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    pub summary: String,
    #[serde(skip)]
    pub payload: Value,
    pub requested_by: String,
    pub status: String,
    pub decided_by: Option<String>,
    pub decided_ts: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DatasetRow {
    pub version: String,
    pub ts: i64,
    pub actor: String,
    pub params: Value,
    pub stats: Value,
    #[serde(skip)]
    pub dir: String,
}

fn open_conn(path: &Path) -> Result<Connection> {
    let c = Connection::open(path).map_err(e)?;
    c.busy_timeout(Duration::from_secs(5)).map_err(e)?;
    c.pragma_update(None, "journal_mode", "WAL").map_err(e)?;
    c.pragma_update(None, "synchronous", "NORMAL").map_err(e)?;
    // Fewer, larger checkpoints: under load the default (1000 pages) made
    // the writer spend about half its time checkpointing and in fsync.
    c.pragma_update(None, "wal_autocheckpoint", 8000).map_err(e)?;
    c.pragma_update(None, "journal_size_limit", 64 * 1024 * 1024).map_err(e)?;
    c.pragma_update(None, "foreign_keys", "ON").map_err(e)?;
    Ok(c)
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir).map_err(e)?;
        }
        let w = open_conn(path)?;
        w.execute_batch(SCHEMA).map_err(e)?;
        // The database holds redacted traffic data: owner-only access.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        let r = open_conn(path)?;
        Ok(Self {
            write: Mutex::new(w),
            read: Mutex::new(r),
        })
    }

    /// In-memory store for tests.
    pub fn memory() -> Self {
        let dir = std::env::temp_dir().join(format!("openshield-test-{}.db", uuid::Uuid::new_v4()));
        Self::open(&dir).expect("temp store")
    }

    pub fn ping(&self) -> bool {
        self.read.lock().query_row("SELECT 1", [], |_| Ok(())).is_ok()
    }

    // ---- events -------------------------------------------------------

    pub fn insert_events<E: AsRef<SecurityEvent>>(&self, events: &[E]) -> Result<()> {
        let mut c = self.write.lock();
        let tx = c.transaction().map_err(e)?;
        {
            let mut st = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO events (id, ts, client_ip, action, status, path, rules, anomaly, \
                     ai_category, label, fingerprint, search, data) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                )
                .map_err(e)?;
            for ev in events {
                let ev = ev.as_ref();
                let rules = format!(
                    ",{},",
                    ev.matched_rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>().join(",")
                );
                let search = format!("{} {} {} {}", ev.path, ev.query, ev.user_agent, ev.host).to_lowercase();
                st.execute(params![
                    ev.id,
                    ev.ts,
                    ev.client_ip,
                    ev.action,
                    ev.status,
                    ev.path,
                    rules,
                    ev.anomaly.score,
                    ev.ai.as_ref().map(|v| v.category.as_str()),
                    ev.label,
                    ev.fingerprint(),
                    search,
                    serde_json::to_string(ev).map_err(e)?,
                ])
                .map_err(e)?;
            }
        }
        tx.commit().map_err(e)
    }

    pub fn get_event(&self, id: &str) -> Result<Option<SecurityEvent>> {
        let c = self.read.lock();
        let data: Option<String> = c
            .query_row("SELECT data FROM events WHERE id = ?1", [id], |r| r.get(0))
            .optional()
            .map_err(e)?;
        data.map(|d| serde_json::from_str(&d).map_err(e)).transpose()
    }

    pub fn query_events(&self, f: &EventFilter) -> Result<Vec<SecurityEvent>> {
        let mut sql = String::from("SELECT data FROM events WHERE 1=1");
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        let mut push = |cond: &str, v: rusqlite::types::Value, escape: bool| {
            args.push(v);
            sql.push_str(&format!(" AND {cond} ?{}", args.len()));
            if escape {
                sql.push_str(" ESCAPE '\\'");
            }
        };
        if let Some(b) = f.before {
            push("ts <", b.into(), false);
        }
        if let Some(s) = f.since {
            push("ts >=", s.into(), false);
        }
        if let Some(a) = &f.action {
            push("action =", a.clone().into(), false);
        }
        if let Some(ip) = &f.ip {
            push("client_ip =", ip.clone().into(), false);
        }
        if let Some(p) = &f.path {
            push("path LIKE", format!("{}%", like_escape(p)).into(), true);
        }
        if let Some(r) = &f.rule {
            push("rules LIKE", format!("%,{},%", like_escape(r)).into(), true);
        }
        if let Some(q) = &f.q {
            push("search LIKE", format!("%{}%", like_escape(&q.to_lowercase())).into(), true);
        }
        if let Some(m) = f.min_anomaly {
            push("anomaly >=", m.into(), false);
        }
        if let Some(c) = &f.ai_category {
            push("ai_category =", c.clone().into(), false);
        }
        sql.push_str(&format!(" ORDER BY ts DESC LIMIT {}", f.limit.clamp(1, 1000)));
        let c = self.read.lock();
        let mut st = c.prepare(&sql).map_err(e)?;
        let rows = st
            .query_map(rusqlite::params_from_iter(args), |r| r.get::<_, String>(0))
            .map_err(e)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row.map_err(e)?).map_err(e)?);
        }
        Ok(out)
    }

    pub fn event_count(&self) -> Result<i64> {
        self.read
            .lock()
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .map_err(e)
    }

    /// Store a verdict and attach it to the event.
    pub fn add_verdict(&self, event_id: &str, v: &AiVerdict) -> Result<()> {
        let c = self.write.lock();
        c.execute(
            "INSERT INTO ai_verdicts (event_id, ts, data) VALUES (?1, ?2, ?3)",
            params![event_id, v.ts, serde_json::to_string(v).map_err(e)?],
        )
        .map_err(e)?;
        let data: Option<String> = c
            .query_row("SELECT data FROM events WHERE id = ?1", [event_id], |r| r.get(0))
            .optional()
            .map_err(e)?;
        if let Some(d) = data {
            let mut ev: SecurityEvent = serde_json::from_str(&d).map_err(e)?;
            ev.ai = Some(v.clone());
            c.execute(
                "UPDATE events SET ai_category = ?1, data = ?2 WHERE id = ?3",
                params![v.category.as_str(), serde_json::to_string(&ev).map_err(e)?, event_id],
            )
            .map_err(e)?;
        }
        Ok(())
    }

    pub fn verdicts(&self, event_id: &str) -> Result<Vec<AiVerdict>> {
        let c = self.read.lock();
        let mut st = c
            .prepare("SELECT data FROM ai_verdicts WHERE event_id = ?1 ORDER BY ts DESC")
            .map_err(e)?;
        let rows = st.query_map([event_id], |r| r.get::<_, String>(0)).map_err(e)?;
        rows.map(|r| serde_json::from_str(&r.map_err(e)?).map_err(e)).collect()
    }

    fn set_event_label(c: &Connection, event_id: &str, label: Option<&str>) -> Result<()> {
        let data: Option<String> = c
            .query_row("SELECT data FROM events WHERE id = ?1", [event_id], |r| r.get(0))
            .optional()
            .map_err(e)?;
        if let Some(d) = data {
            let mut ev: SecurityEvent = serde_json::from_str(&d).map_err(e)?;
            ev.label = label.map(str::to_string);
            c.execute(
                "UPDATE events SET label = ?1, data = ?2 WHERE id = ?3",
                params![label, serde_json::to_string(&ev).map_err(e)?, event_id],
            )
            .map_err(e)?;
        }
        Ok(())
    }

    /// Delete events older than `cutoff_ms` and beyond `max_events`.
    /// Labeled events are kept: they are ground truth for datasets.
    pub fn retain(&self, cutoff_ms: i64, max_events: u64) -> Result<usize> {
        let c = self.write.lock();
        let mut n = c
            .execute("DELETE FROM events WHERE ts < ?1 AND label IS NULL", [cutoff_ms])
            .map_err(e)?;
        let count: i64 = c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0)).map_err(e)?;
        if count as u64 > max_events {
            let excess = count as u64 - max_events;
            n += c
                .execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events WHERE label IS NULL ORDER BY ts ASC LIMIT ?1)",
                    [excess as i64],
                )
                .map_err(e)?;
        }
        c.execute(
            "DELETE FROM ai_verdicts WHERE event_id NOT IN (SELECT id FROM events)",
            [],
        )
        .map_err(e)?;
        Ok(n)
    }

    // ---- labels -------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn add_label(
        &self,
        event_id: &str,
        label: &str,
        source: &str,
        status: &str,
        note: &str,
        created_by: &str,
        policy_version: Option<i64>,
        model_version: Option<&str>,
    ) -> Result<i64> {
        let c = self.write.lock();
        c.execute(
            "INSERT INTO labels (event_id, label, source, status, note, created_by, ts, policy_version, model_version) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![event_id, label, source, status, note, created_by, now_ms(), policy_version, model_version],
        )
        .map_err(e)?;
        let id = c.last_insert_rowid();
        if status == "approved" || source == "operator" {
            Self::set_event_label(&c, event_id, Some(label))?;
        }
        Ok(id)
    }

    pub fn get_label(&self, id: i64) -> Result<Option<Label>> {
        let c = self.read.lock();
        c.query_row(&format!("{LABEL_COLS} WHERE id = ?1"), [id], label_row)
            .optional()
            .map_err(e)
    }

    pub fn labels(&self, status: Option<&str>, limit: usize) -> Result<Vec<Label>> {
        let c = self.read.lock();
        let (sql, arg) = match status {
            Some(s) => (format!("{LABEL_COLS} WHERE status = ?1 ORDER BY ts DESC LIMIT {limit}"), Some(s)),
            None => (format!("{LABEL_COLS} ORDER BY ts DESC LIMIT {limit}"), None),
        };
        let mut st = c.prepare(&sql).map_err(e)?;
        let rows = match arg {
            Some(a) => st.query_map([a], label_row).map_err(e)?.collect::<std::result::Result<Vec<_>, _>>(),
            None => st.query_map([], label_row).map_err(e)?.collect(),
        };
        rows.map_err(e)
    }

    pub fn approved_labels(&self) -> Result<Vec<Label>> {
        self.labels(Some("approved"), 1_000_000)
    }

    pub fn decide_label(&self, id: i64, status: &str, reviewer: &str) -> Result<()> {
        let c = self.write.lock();
        c.execute(
            "UPDATE labels SET status = ?1, reviewer = ?2, decided_ts = ?3 WHERE id = ?4",
            params![status, reviewer, now_ms(), id],
        )
        .map_err(e)?;
        let row: Option<(String, String)> = c
            .query_row("SELECT event_id, label FROM labels WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()
            .map_err(e)?;
        if let Some((event_id, label)) = row
            && status == "approved"
        {
            Self::set_event_label(&c, &event_id, Some(&label))?;
        }
        Ok(())
    }

    pub fn labels_for_event(&self, event_id: &str) -> Result<Vec<Label>> {
        let c = self.read.lock();
        let mut st = c
            .prepare(&format!("{LABEL_COLS} WHERE event_id = ?1 ORDER BY ts DESC"))
            .map_err(e)?;
        let rows = st.query_map([event_id], label_row).map_err(e)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(e)
    }

    // ---- alerts -------------------------------------------------------

    /// Record an alert. An open alert of the same kind and subject seen in
    /// the last 10 minutes is updated instead of duplicated. Returns the
    /// alert and whether it is new.
    pub fn raise_alert(&self, kind: &str, subject: &str, severity: &str, detail: &Value) -> Result<(Alert, bool)> {
        let c = self.write.lock();
        let now = now_ms();
        let existing: Option<i64> = c
            .query_row(
                "SELECT id FROM alerts WHERE kind = ?1 AND subject = ?2 AND status != 'resolved' AND last_ts > ?3",
                params![kind, subject, now - 600_000],
                |r| r.get(0),
            )
            .optional()
            .map_err(e)?;
        let (id, new) = match existing {
            Some(id) => {
                c.execute(
                    "UPDATE alerts SET last_ts = ?1, count = count + 1, detail = ?2 WHERE id = ?3",
                    params![now, detail.to_string(), id],
                )
                .map_err(e)?;
                (id, false)
            }
            None => {
                c.execute(
                    "INSERT INTO alerts (ts, last_ts, kind, subject, severity, detail, status) VALUES (?1,?1,?2,?3,?4,?5,'open')",
                    params![now, kind, subject, severity, detail.to_string()],
                )
                .map_err(e)?;
                (c.last_insert_rowid(), true)
            }
        };
        let a = c
            .query_row(&format!("{ALERT_COLS} WHERE id = ?1"), [id], alert_row)
            .map_err(e)?;
        Ok((a, new))
    }

    pub fn alerts(&self, status: Option<&str>, limit: usize) -> Result<Vec<Alert>> {
        let c = self.read.lock();
        let mut st = c
            .prepare(&format!(
                "{ALERT_COLS} WHERE (?1 IS NULL OR status = ?1) ORDER BY last_ts DESC LIMIT {limit}"
            ))
            .map_err(e)?;
        let rows = st.query_map([status], alert_row).map_err(e)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(e)
    }

    /// Alerts not yet resolved (open or acknowledged), by severity.
    pub fn unresolved_alert_counts(&self) -> Result<std::collections::BTreeMap<String, i64>> {
        let c = self.read.lock();
        let mut st = c
            .prepare("SELECT severity, status, COUNT(*) FROM alerts WHERE status != 'resolved' GROUP BY severity, status")
            .map_err(e)?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)))
            .map_err(e)?;
        let mut out = std::collections::BTreeMap::new();
        for row in rows {
            let (sev, status, n) = row.map_err(e)?;
            if status == "open" {
                *out.entry(sev).or_insert(0) += n;
                *out.entry("open".into()).or_insert(0) += n;
            } else {
                *out.entry("acknowledged".into()).or_insert(0) += n;
            }
        }
        Ok(out)
    }

    pub fn get_alert(&self, id: i64) -> Result<Option<Alert>> {
        let c = self.read.lock();
        c.query_row(&format!("{ALERT_COLS} WHERE id = ?1"), [id], alert_row)
            .optional()
            .map_err(e)
    }

    pub fn set_alert_status(&self, id: i64, status: &str) -> Result<bool> {
        let n = self
            .write
            .lock()
            .execute("UPDATE alerts SET status = ?1 WHERE id = ?2", params![status, id])
            .map_err(e)?;
        Ok(n > 0)
    }

    pub fn set_alert_summary(&self, id: i64, summary: &str) -> Result<()> {
        self.write
            .lock()
            .execute("UPDATE alerts SET summary = ?1 WHERE id = ?2", params![summary, id])
            .map_err(e)?;
        Ok(())
    }

    // ---- controls -----------------------------------------------------

    pub fn put_control(&self, ctl: &Control) -> Result<()> {
        self.write
            .lock()
            .execute(
                "INSERT OR REPLACE INTO controls (kind, value, expires_at, reason, actor, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
                params![ctl.kind, ctl.value, ctl.expires_at, ctl.reason, ctl.actor, ctl.created_at],
            )
            .map_err(e)?;
        Ok(())
    }

    pub fn delete_control(&self, kind: &str, value: &str) -> Result<bool> {
        let n = self
            .write
            .lock()
            .execute("DELETE FROM controls WHERE kind = ?1 AND value = ?2", params![kind, value])
            .map_err(e)?;
        Ok(n > 0)
    }

    pub fn controls(&self) -> Result<Vec<Control>> {
        let c = self.read.lock();
        let mut st = c
            .prepare("SELECT kind, value, expires_at, reason, actor, created_at FROM controls ORDER BY created_at DESC")
            .map_err(e)?;
        let rows = st
            .query_map([], |r| {
                Ok(Control {
                    kind: r.get(0)?,
                    value: r.get(1)?,
                    expires_at: r.get(2)?,
                    reason: r.get(3)?,
                    actor: r.get(4)?,
                    created_at: r.get(5)?,
                })
            })
            .map_err(e)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(e)
    }

    pub fn purge_expired_controls(&self, now: i64) -> Result<usize> {
        self.write
            .lock()
            .execute("DELETE FROM controls WHERE expires_at IS NOT NULL AND expires_at <= ?1", [now])
            .map_err(e)
    }

    // ---- admin audit --------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn audit(
        &self,
        actor: &str,
        role: &str,
        action: &str,
        target: &str,
        detail: &Value,
        result: &str,
        ip: &str,
    ) -> Result<()> {
        self.write
            .lock()
            .execute(
                "INSERT INTO admin_audit (ts, actor, role, action, target, detail, result, ip) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![now_ms(), actor, role, action, target, detail.to_string(), result, ip],
            )
            .map_err(e)?;
        Ok(())
    }

    pub fn audit_entries(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let c = self.read.lock();
        let mut st = c
            .prepare(&format!(
                "SELECT id, ts, actor, role, action, target, detail, result, ip FROM admin_audit ORDER BY id DESC LIMIT {limit}"
            ))
            .map_err(e)?;
        let rows = st
            .query_map([], |r| {
                Ok(AuditEntry {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    actor: r.get(2)?,
                    role: r.get(3)?,
                    action: r.get(4)?,
                    target: r.get(5)?,
                    detail: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or(Value::Null),
                    result: r.get(7)?,
                    ip: r.get(8)?,
                })
            })
            .map_err(e)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(e)
    }

    // ---- policy versions ----------------------------------------------

    pub fn add_policy_version(
        &self,
        actor: &str,
        comment: &str,
        source: &str,
        yaml: &str,
        file_hash: &str,
        rule_count: usize,
    ) -> Result<i64> {
        let mut c = self.write.lock();
        let tx = c.transaction().map_err(e)?;
        tx.execute("UPDATE policy_versions SET status = 'superseded' WHERE status = 'active'", [])
            .map_err(e)?;
        tx.execute(
            "INSERT INTO policy_versions (ts, actor, comment, source, status, yaml, file_hash, rule_count) \
             VALUES (?1,?2,?3,?4,'active',?5,?6,?7)",
            params![now_ms(), actor, comment, source, yaml, file_hash, rule_count as i64],
        )
        .map_err(e)?;
        let v = tx.last_insert_rowid();
        tx.commit().map_err(e)?;
        Ok(v)
    }

    pub fn policy_versions(&self) -> Result<Vec<PolicyVersion>> {
        let c = self.read.lock();
        let mut st = c
            .prepare(
                "SELECT version, ts, actor, comment, source, status, file_hash, rule_count FROM policy_versions ORDER BY version DESC LIMIT 200",
            )
            .map_err(e)?;
        let rows = st
            .query_map([], |r| {
                Ok(PolicyVersion {
                    version: r.get(0)?,
                    ts: r.get(1)?,
                    actor: r.get(2)?,
                    comment: r.get(3)?,
                    source: r.get(4)?,
                    status: r.get(5)?,
                    yaml: None,
                    file_hash: r.get(6)?,
                    rule_count: r.get(7)?,
                })
            })
            .map_err(e)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(e)
    }

    pub fn policy_version(&self, version: i64) -> Result<Option<PolicyVersion>> {
        let c = self.read.lock();
        c.query_row(
            "SELECT version, ts, actor, comment, source, status, yaml, file_hash, rule_count FROM policy_versions WHERE version = ?1",
            [version],
            |r| {
                Ok(PolicyVersion {
                    version: r.get(0)?,
                    ts: r.get(1)?,
                    actor: r.get(2)?,
                    comment: r.get(3)?,
                    source: r.get(4)?,
                    status: r.get(5)?,
                    yaml: Some(r.get(6)?),
                    file_hash: r.get(7)?,
                    rule_count: r.get(8)?,
                })
            },
        )
        .optional()
        .map_err(e)
    }

    pub fn active_policy(&self) -> Result<Option<PolicyVersion>> {
        let v: Option<i64> = self
            .read
            .lock()
            .query_row(
                "SELECT version FROM policy_versions WHERE status = 'active' ORDER BY version DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(e)?;
        match v {
            Some(v) => self.policy_version(v),
            None => Ok(None),
        }
    }

    // ---- pending changes ----------------------------------------------

    pub fn add_change(&self, kind: &str, summary: &str, payload: &Value, requested_by: &str) -> Result<i64> {
        let c = self.write.lock();
        c.execute(
            "INSERT INTO changes (ts, kind, summary, payload, requested_by, status) VALUES (?1,?2,?3,?4,?5,'pending')",
            params![now_ms(), kind, summary, payload.to_string(), requested_by],
        )
        .map_err(e)?;
        Ok(c.last_insert_rowid())
    }

    pub fn changes(&self, status: Option<&str>) -> Result<Vec<Change>> {
        let c = self.read.lock();
        let mut st = c
            .prepare(&format!("{CHANGE_COLS} WHERE (?1 IS NULL OR status = ?1) ORDER BY id DESC LIMIT 200"))
            .map_err(e)?;
        let rows = st.query_map([status], change_row).map_err(e)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(e)
    }

    pub fn get_change(&self, id: i64) -> Result<Option<Change>> {
        self.read
            .lock()
            .query_row(&format!("{CHANGE_COLS} WHERE id = ?1"), [id], change_row)
            .optional()
            .map_err(e)
    }

    /// Move a pending change to `status`. Returns false if it was not
    /// pending (already decided), so a change cannot be applied twice.
    pub fn decide_change(&self, id: i64, status: &str, by: &str) -> Result<bool> {
        let n = self
            .write
            .lock()
            .execute(
                "UPDATE changes SET status = ?1, decided_by = ?2, decided_ts = ?3 WHERE id = ?4 AND status = 'pending'",
                params![status, by, now_ms(), id],
            )
            .map_err(e)?;
        Ok(n > 0)
    }

    // ---- datasets -----------------------------------------------------

    pub fn add_dataset(&self, version: &str, actor: &str, params_v: &Value, stats: &Value, dir: &str) -> Result<()> {
        self.write
            .lock()
            .execute(
                "INSERT INTO datasets (version, ts, actor, params, stats, dir) VALUES (?1,?2,?3,?4,?5,?6)",
                params![version, now_ms(), actor, params_v.to_string(), stats.to_string(), dir],
            )
            .map_err(e)?;
        Ok(())
    }

    pub fn datasets(&self) -> Result<Vec<DatasetRow>> {
        let c = self.read.lock();
        let mut st = c
            .prepare("SELECT version, ts, actor, params, stats, dir FROM datasets ORDER BY ts DESC")
            .map_err(e)?;
        let rows = st
            .query_map([], |r| {
                Ok(DatasetRow {
                    version: r.get(0)?,
                    ts: r.get(1)?,
                    actor: r.get(2)?,
                    params: serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or(Value::Null),
                    stats: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or(Value::Null),
                    dir: r.get(5)?,
                })
            })
            .map_err(e)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(e)
    }

    pub fn dataset(&self, version: &str) -> Result<Option<DatasetRow>> {
        Ok(self.datasets()?.into_iter().find(|d| d.version == version))
    }
}

const LABEL_COLS: &str = "SELECT id, event_id, label, source, reviewer, status, note, created_by, ts, decided_ts, policy_version, model_version FROM labels";

fn label_row(r: &rusqlite::Row) -> rusqlite::Result<Label> {
    Ok(Label {
        id: r.get(0)?,
        event_id: r.get(1)?,
        label: r.get(2)?,
        source: r.get(3)?,
        reviewer: r.get(4)?,
        status: r.get(5)?,
        note: r.get(6)?,
        created_by: r.get(7)?,
        ts: r.get(8)?,
        decided_ts: r.get(9)?,
        policy_version: r.get(10)?,
        model_version: r.get(11)?,
    })
}

const ALERT_COLS: &str = "SELECT id, ts, last_ts, kind, subject, severity, detail, status, summary, count FROM alerts";

fn alert_row(r: &rusqlite::Row) -> rusqlite::Result<Alert> {
    Ok(Alert {
        id: r.get(0)?,
        ts: r.get(1)?,
        last_ts: r.get(2)?,
        kind: r.get(3)?,
        subject: r.get(4)?,
        severity: r.get(5)?,
        detail: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or(Value::Null),
        status: r.get(7)?,
        summary: r.get(8)?,
        count: r.get(9)?,
    })
}

const CHANGE_COLS: &str =
    "SELECT id, ts, kind, summary, payload, requested_by, status, decided_by, decided_ts FROM changes";

fn change_row(r: &rusqlite::Row) -> rusqlite::Result<Change> {
    Ok(Change {
        id: r.get(0)?,
        ts: r.get(1)?,
        kind: r.get(2)?,
        summary: r.get(3)?,
        payload: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or(Value::Null),
        requested_by: r.get(5)?,
        status: r.get(6)?,
        decided_by: r.get(7)?,
        decided_ts: r.get(8)?,
    })
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::MatchedRule;
    use crate::event::tests_support::sample_event;

    fn ev(id: &str, ts: i64, action: &str) -> SecurityEvent {
        let mut e = sample_event();
        e.id = id.into();
        e.ts = ts;
        e.action = action.into();
        if action == "block" {
            e.matched_rules.push(MatchedRule {
                id: "block_sqli".into(),
                action: "block".into(),
            });
        }
        e
    }

    #[test]
    fn events_roundtrip_and_filter() {
        let s = Store::memory();
        s.insert_events(&[ev("a", 1, "pass"), ev("b", 2, "block"), ev("c", 3, "pass")]).unwrap();
        assert_eq!(s.get_event("b").unwrap().unwrap().action, "block");
        let f = EventFilter {
            limit: 10,
            ..Default::default()
        };
        let all = s.query_events(&f).unwrap();
        assert_eq!(all.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), vec!["c", "b", "a"]);
        let blocked = s
            .query_events(&EventFilter {
                limit: 10,
                rule: Some("block_sqli".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(blocked.len(), 1);
        // `_` in the filter is literal, not a wildcard.
        let none = s
            .query_events(&EventFilter {
                limit: 10,
                rule: Some("block_sql_".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(none.is_empty());
        let page = s
            .query_events(&EventFilter {
                limit: 10,
                before: Some(3),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.len(), 2);
    }

    #[test]
    fn filter_values_cannot_inject_sql() {
        let s = Store::memory();
        s.insert_events(&[ev("a", 1, "pass")]).unwrap();
        let r = s
            .query_events(&EventFilter {
                limit: 10,
                ip: Some("x' OR '1'='1".into()),
                q: Some("%' OR 1=1 --".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(r.is_empty());
        assert_eq!(s.event_count().unwrap(), 1);
    }

    #[test]
    fn labels_and_review_flow() {
        let s = Store::memory();
        s.insert_events(&[ev("a", 1, "block")]).unwrap();
        let id = s
            .add_label("a", "MALICIOUS_CONFIRMED", "ai_candidate", "candidate", "", "ai", None, Some("m1"))
            .unwrap();
        assert!(s.get_event("a").unwrap().unwrap().label.is_none(), "candidate does not label the event");
        s.decide_label(id, "approved", "bob").unwrap();
        assert_eq!(s.get_event("a").unwrap().unwrap().label.as_deref(), Some("MALICIOUS_CONFIRMED"));
        assert_eq!(s.approved_labels().unwrap().len(), 1);
    }

    #[test]
    fn alerts_dedupe_while_open() {
        let s = Store::memory();
        let (a, new) = s.raise_alert("rate_spike", "1.1.1.1", "medium", &serde_json::json!({})).unwrap();
        assert!(new);
        let (b, new2) = s.raise_alert("rate_spike", "1.1.1.1", "medium", &serde_json::json!({})).unwrap();
        assert!(!new2);
        assert_eq!(a.id, b.id);
        assert_eq!(b.count, 2);
        s.set_alert_status(a.id, "resolved").unwrap();
        let (_, new3) = s.raise_alert("rate_spike", "1.1.1.1", "medium", &serde_json::json!({})).unwrap();
        assert!(new3);
    }

    #[test]
    fn retention_keeps_labeled_events() {
        let s = Store::memory();
        s.insert_events(&[ev("old", 1, "pass"), ev("old-labeled", 2, "pass"), ev("new", 1000, "pass")]).unwrap();
        s.add_label("old-labeled", "ALLOWED_NORMAL", "operator", "candidate", "", "alice", None, None)
            .unwrap();
        s.retain(500, 1_000_000).unwrap();
        assert!(s.get_event("old").unwrap().is_none());
        assert!(s.get_event("old-labeled").unwrap().is_some());
        assert!(s.get_event("new").unwrap().is_some());
        s.retain(0, 1).unwrap();
        assert_eq!(s.event_count().unwrap(), 1);
    }

    #[test]
    fn changes_are_decided_once() {
        let s = Store::memory();
        let id = s.add_change("policy_apply", "x", &serde_json::json!({}), "alice").unwrap();
        assert!(s.decide_change(id, "approved", "bob").unwrap());
        assert!(!s.decide_change(id, "approved", "bob").unwrap());
    }

    #[test]
    fn policy_versions_have_one_active() {
        let s = Store::memory();
        s.add_policy_version("file", "", "file", "a: 1", "h", 1).unwrap();
        let v2 = s.add_policy_version("alice", "c", "api", "a: 2", "h", 2).unwrap();
        let active = s.active_policy().unwrap().unwrap();
        assert_eq!(active.version, v2);
        assert_eq!(active.yaml.as_deref(), Some("a: 2"));
        assert_eq!(
            s.policy_versions().unwrap().iter().filter(|v| v.status == "active").count(),
            1
        );
    }
}
