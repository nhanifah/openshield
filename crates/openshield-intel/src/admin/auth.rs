//! Bearer-token authentication and role checks for the admin API.
//!
//! Three kinds of account:
//! - from the config file (`admin.users`): fixed, cannot be edited in the
//!   dashboard;
//! - created in the dashboard: stored as SHA-256 digests of the token, so a
//!   database copy does not reveal tokens; a token is shown once, at
//!   creation or rotation;
//! - the first-run setup account: when no admin exists anywhere, a random
//!   token is written to a mode-0600 file next to the database. It keeps
//!   working until an admin created in the dashboard signs in for the first
//!   time (so the new admin's token is never lost between creation and
//!   use); then the file is deleted.
//!
//! Signing in with a passkey issues a session token (`oss_…`) that lives in
//! memory only: it expires after `SESSION_TTL`, on sign-out, when its user
//! is deleted, and on restart. Its role is looked up on every request, so a
//! role change applies at once.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::{AdminUser, Role};
use crate::store::Store;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserSource {
    ConfigFile,
    Dashboard,
    Setup,
}

#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub role: Role,
    pub source: UserSource,
}

impl User {
    pub fn can(&self, role: Role) -> bool {
        self.role >= role
    }
}

#[derive(Clone)]
struct Account {
    name: String,
    role: Role,
    digest: [u8; 32],
    source: UserSource,
}

pub struct Authenticator {
    config_accounts: Vec<Account>,
    db_accounts: RwLock<Vec<Account>>,
    setup: RwLock<Option<(Account, PathBuf)>>,
    store: Option<Arc<Store>>,
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
}

struct Session {
    name: String,
    expires: Instant,
}

/// How long a passkey sign-in lasts.
pub const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
/// Upper bound on live sessions (oldest are dropped first when full).
const MAX_SESSIONS: usize = 10_000;

/// Failed attempts per address per minute before `429`.
pub const MAX_FAILURES_PER_MIN: u32 = 10;

pub const SETUP_USER: &str = "setup";

pub fn parse_role(s: &str) -> Option<Role> {
    match s {
        "viewer" => Some(Role::Viewer),
        "analyst" => Some(Role::Analyst),
        "operator" => Some(Role::Operator),
        "admin" => Some(Role::Admin),
        _ => None,
    }
}

/// A new random token: `osk_` and 64 hex characters (256 bits).
pub fn new_token() -> String {
    let mut b = [0u8; 32];
    aws_lc_rs::rand::fill(&mut b).expect("system random generator");
    format!("osk_{}", hex::encode(b))
}

pub fn token_digest_hex(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn digest_from_hex(h: &str) -> Option<[u8; 32]> {
    hex::decode(h).ok()?.try_into().ok()
}

impl Authenticator {
    /// Accounts from the config file only (used by `--test`).
    pub fn new(users: &[AdminUser]) -> Result<Self, String> {
        let mut accounts = Vec::new();
        for u in users {
            let digest = match (&u.token_sha256, &u.token_env) {
                (Some(h), _) => digest_from_hex(h).ok_or_else(|| format!("user {}: token_sha256 must be 64 hex characters", u.name))?,
                (None, Some(var)) => {
                    let token = std::env::var(var)
                        .map_err(|_| format!("user {}: environment variable {var} is not set", u.name))?;
                    if token.len() < 16 {
                        return Err(format!("user {}: token in {var} must be at least 16 characters", u.name));
                    }
                    Sha256::digest(token.as_bytes()).into()
                }
                (None, None) => return Err(format!("user {}: no token configured", u.name)),
            };
            accounts.push(Account {
                name: u.name.clone(),
                role: u.role,
                digest,
                source: UserSource::ConfigFile,
            });
        }
        Ok(Self {
            config_accounts: accounts,
            db_accounts: RwLock::new(Vec::new()),
            setup: RwLock::new(None),
            store: None,
            failures: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        })
    }

    /// Config accounts plus dashboard accounts from `store`. Creates the
    /// first-run setup token at `setup_file` when no admin exists.
    pub fn with_store(users: &[AdminUser], store: Arc<Store>, setup_file: PathBuf) -> Result<Self, String> {
        let mut a = Self::new(users)?;
        a.store = Some(store);
        a.reload()?;
        if a.admin_count() == 0 {
            // Reuse an unfinished setup token across restarts, so restarting
            // the server mid-setup does not sign the person out.
            let existing = std::fs::read_to_string(&setup_file)
                .ok()
                .map(|t| t.trim().to_string())
                .filter(|t| t.starts_with("osk_") && t.len() == 68);
            let token = match existing {
                Some(t) => t,
                None => {
                    let t = new_token();
                    crate::vault::write_private_file(&setup_file, &format!("{t}\n"))?;
                    t
                }
            };
            log::warn!(
                "No admin user exists. First-run setup token written to {} (mode 0600): sign in to the dashboard with \
                 it and create an admin user. The token stops working once that user exists.",
                setup_file.display()
            );
            *a.setup.write() = Some((
                Account {
                    name: SETUP_USER.into(),
                    role: Role::Admin,
                    digest: Sha256::digest(token.as_bytes()).into(),
                    source: UserSource::Setup,
                },
                setup_file,
            ));
        }
        Ok(a)
    }

    /// Re-read dashboard accounts; end setup mode once an admin exists.
    pub fn reload(&self) -> Result<(), String> {
        let Some(store) = &self.store else { return Ok(()) };
        let mut accounts = Vec::new();
        for u in store.users()? {
            let (Some(role), Some(digest)) = (parse_role(&u.role), digest_from_hex(&u.token_sha256)) else {
                log::error!("skipping malformed admin user {:?}", u.name);
                continue;
            };
            accounts.push(Account {
                name: u.name,
                role,
                digest,
                source: UserSource::Dashboard,
            });
        }
        *self.db_accounts.write() = accounts;
        Ok(())
    }

    /// End setup mode (called when a real admin signs in).
    fn finish_setup(&self) {
        if let Some((_, file)) = self.setup.write().take() {
            let _ = std::fs::remove_file(&file);
            log::warn!("First-run setup finished: an admin signed in; setup token removed");
        }
    }

    pub fn in_setup(&self) -> bool {
        self.setup.read().is_some()
    }

    /// Admins from the config file and the dashboard (not the setup account).
    pub fn admin_count(&self) -> usize {
        self.config_accounts.iter().filter(|a| a.role == Role::Admin).count()
            + self.db_accounts.read().iter().filter(|a| a.role == Role::Admin).count()
    }

    pub fn is_config_user(&self, name: &str) -> bool {
        self.config_accounts.iter().any(|a| a.name == name)
    }

    /// Config users, for listing (no secrets).
    pub fn config_users(&self) -> Vec<(String, Role)> {
        self.config_accounts.iter().map(|a| (a.name.clone(), a.role)).collect()
    }

    /// Current role of a named account (config or dashboard), if it exists.
    pub fn role_of(&self, name: &str) -> Option<(Role, UserSource)> {
        if let Some(a) = self.config_accounts.iter().find(|a| a.name == name) {
            return Some((a.role, a.source));
        }
        let db = self.db_accounts.read();
        db.iter().find(|a| a.name == name).map(|a| (a.role, a.source))
    }

    /// Start a passkey session for `name`; returns its bearer token.
    pub fn issue_session(&self, name: &str) -> String {
        let mut b = [0u8; 32];
        aws_lc_rs::rand::fill(&mut b).expect("system random generator");
        let token = format!("oss_{}", hex::encode(b));
        let mut s = self.sessions.lock();
        s.retain(|_, v| v.expires > Instant::now());
        if s.len() >= MAX_SESSIONS
            && let Some(oldest) = s.iter().min_by_key(|(_, v)| v.expires).map(|(k, _)| *k)
        {
            s.remove(&oldest);
        }
        s.insert(
            Sha256::digest(token.as_bytes()).into(),
            Session {
                name: name.to_string(),
                expires: Instant::now() + SESSION_TTL,
            },
        );
        token
    }

    /// End one session (sign-out). Returns false for non-session tokens.
    pub fn revoke_session(&self, token: &str) -> bool {
        let d: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        self.sessions.lock().remove(&d).is_some()
    }

    /// End every session of a user (user deleted).
    pub fn revoke_user_sessions(&self, name: &str) -> usize {
        let mut s = self.sessions.lock();
        let before = s.len();
        s.retain(|_, v| v.name != name);
        before - s.len()
    }

    /// Count a failed sign-in from `ip` (passkey attempts share the token
    /// lockout).
    pub fn record_failure(&self, ip: IpAddr) {
        let mut f = self.failures.lock();
        if f.len() > 10_000 {
            f.retain(|_, (_, since)| since.elapsed() < Duration::from_secs(60));
        }
        let e = f.entry(ip).or_insert((0, Instant::now()));
        if e.1.elapsed() >= Duration::from_secs(60) {
            *e = (0, Instant::now());
        }
        e.0 += 1;
    }

    fn check_session(&self, token: &str, ip: IpAddr) -> Option<User> {
        let d: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let name = {
            let mut s = self.sessions.lock();
            match s.get(&d) {
                Some(v) if v.expires > Instant::now() => Some(v.name.clone()),
                Some(_) => {
                    s.remove(&d);
                    None
                }
                None => None,
            }
        };
        let found = name.and_then(|n| self.role_of(&n).map(|(role, source)| (n, role, source)));
        match found {
            Some((name, role, source)) => {
                if role == Role::Admin && self.in_setup() {
                    self.finish_setup();
                }
                Some(User { name, role, source })
            }
            None => {
                self.record_failure(ip);
                None
            }
        }
    }

    /// True when `ip` has used up its failed attempts for this minute.
    pub fn locked_out(&self, ip: IpAddr) -> bool {
        let f = self.failures.lock();
        matches!(f.get(&ip), Some((n, since)) if *n >= MAX_FAILURES_PER_MIN && since.elapsed() < Duration::from_secs(60))
    }

    /// Check a bearer token against every account, in constant time per
    /// account, so timing does not reveal which (if any) is close.
    pub fn check(&self, token: &str, ip: IpAddr) -> Option<User> {
        if token.starts_with("oss_") {
            return self.check_session(token, ip);
        }
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut found: Option<Account> = None;
        let db = self.db_accounts.read();
        let setup = self.setup.read();
        let all = self
            .config_accounts
            .iter()
            .chain(db.iter())
            .chain(setup.as_ref().map(|(a, _)| a));
        for a in all {
            if ct_eq(&a.digest, &digest) {
                found = Some(a.clone());
            }
        }
        drop(db);
        drop(setup);
        match found {
            Some(a) => {
                if a.role == Role::Admin && a.source != UserSource::Setup && self.in_setup() {
                    self.finish_setup();
                }
                Some(User {
                    name: a.name,
                    role: a.role,
                    source: a.source,
                })
            }
            None => {
                self.record_failure(ip);
                None
            }
        }
    }
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut d = 0u8;
    for i in 0..32 {
        d |= a[i] ^ b[i];
    }
    d == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_user(name: &str, role: Role, token: &str) -> AdminUser {
        AdminUser {
            name: name.into(),
            role,
            token_sha256: Some(token_digest_hex(token)),
            token_env: None,
        }
    }

    fn auth() -> Authenticator {
        Authenticator::new(&[
            cfg_user("alice", Role::Admin, "alice-token-123456"),
            cfg_user("val", Role::Viewer, "viewer-token-123456"),
        ])
        .unwrap()
    }

    #[test]
    fn valid_tokens_map_to_users() {
        let a = auth();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let u = a.check("alice-token-123456", ip).unwrap();
        assert_eq!(u.name, "alice");
        assert_eq!(u.source, UserSource::ConfigFile);
        assert!(u.can(Role::Operator));
        let v = a.check("viewer-token-123456", ip).unwrap();
        assert!(!v.can(Role::Analyst));
        assert!(a.check("wrong", ip).is_none());
    }

    #[test]
    fn repeated_failures_lock_out_the_address() {
        let a = auth();
        let ip: IpAddr = "10.9.9.9".parse().unwrap();
        for _ in 0..MAX_FAILURES_PER_MIN {
            assert!(!a.locked_out(ip));
            a.check("nope", ip);
        }
        assert!(a.locked_out(ip));
        assert!(!a.locked_out("10.9.9.8".parse().unwrap()));
    }

    #[test]
    fn short_env_tokens_are_rejected() {
        // SAFETY: test-only, single-threaded use of a unique variable name.
        unsafe { std::env::set_var("OPENSHIELD_TEST_SHORT_TOKEN", "short") };
        let r = Authenticator::new(&[AdminUser {
            name: "x".into(),
            role: Role::Admin,
            token_sha256: None,
            token_env: Some("OPENSHIELD_TEST_SHORT_TOKEN".into()),
        }]);
        assert!(r.is_err());
    }

    #[test]
    fn first_run_setup_token_works_until_an_admin_exists() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("setup-token");
        let store = Arc::new(Store::memory());
        let a = Authenticator::with_store(&[], Arc::clone(&store), file.clone()).unwrap();
        assert!(a.in_setup());
        let token = std::fs::read_to_string(&file).unwrap().trim().to_string();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let u = a.check(&token, ip).unwrap();
        assert_eq!((u.name.as_str(), u.role, u.source), (SETUP_USER, Role::Admin, UserSource::Setup));
        // An analyst signing in does not end setup.
        let t1 = new_token();
        store.add_user("ana", "analyst", &token_digest_hex(&t1), "setup").unwrap();
        a.reload().unwrap();
        a.check(&t1, ip).unwrap();
        assert!(a.in_setup());
        // Creating an admin keeps setup working (its token is still being
        // shown to the person who created it)...
        let t2 = new_token();
        store.add_user("boss", "admin", &token_digest_hex(&t2), "setup").unwrap();
        a.reload().unwrap();
        assert!(a.in_setup());
        assert!(a.check(&token, ip).is_some(), "setup token still works until the admin signs in");
        // ...until that admin signs in.
        assert_eq!(a.check(&t2, ip).unwrap().source, UserSource::Dashboard);
        assert!(!a.in_setup());
        assert!(!file.exists(), "setup file is deleted");
        assert!(a.check(&token, ip).is_none(), "setup token no longer works");
    }

    #[test]
    fn setup_token_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("setup-token");
        let store = Arc::new(Store::memory());
        let _a = Authenticator::with_store(&[], Arc::clone(&store), file.clone()).unwrap();
        let first = std::fs::read_to_string(&file).unwrap();
        let b = Authenticator::with_store(&[], store, file.clone()).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), first);
        assert!(b.check(first.trim(), "127.0.0.1".parse().unwrap()).is_some());
    }

    #[test]
    fn no_setup_mode_when_config_has_an_admin() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("setup-token");
        let a = Authenticator::with_store(&[cfg_user("alice", Role::Admin, "alice-token-123456")], Arc::new(Store::memory()), file.clone())
            .unwrap();
        assert!(!a.in_setup());
        assert!(!file.exists());
    }

    #[test]
    fn passkey_sessions_follow_the_user() {
        let a = auth();
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        let t = a.issue_session("alice");
        assert!(t.starts_with("oss_") && t.len() == 68);
        let u = a.check(&t, ip).unwrap();
        assert_eq!((u.name.as_str(), u.role), ("alice", Role::Admin));
        // Unknown users get no session; revoked sessions stop working.
        assert!(a.check(&a.issue_session("nobody"), ip).is_none());
        assert!(a.revoke_session(&t));
        assert!(a.check(&t, ip).is_none());
        let t2 = a.issue_session("alice");
        assert_eq!(a.revoke_user_sessions("alice"), 1);
        assert!(a.check(&t2, ip).is_none());
    }

    #[test]
    fn tokens_are_long_and_random() {
        let a = new_token();
        assert!(a.starts_with("osk_") && a.len() == 68);
        assert_ne!(a, new_token());
    }
}
