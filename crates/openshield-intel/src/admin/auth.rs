//! Bearer-token authentication and role checks for the admin API.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::config::{AdminUser, Role};

#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub role: Role,
}

impl User {
    pub fn can(&self, role: Role) -> bool {
        self.role >= role
    }
}

struct Account {
    name: String,
    role: Role,
    digest: [u8; 32],
}

pub struct Authenticator {
    accounts: Vec<Account>,
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

/// Failed attempts per address per minute before `429`.
pub const MAX_FAILURES_PER_MIN: u32 = 10;

impl Authenticator {
    pub fn new(users: &[AdminUser]) -> Result<Self, String> {
        let mut accounts = Vec::new();
        for u in users {
            let digest = match (&u.token_sha256, &u.token_env) {
                (Some(h), _) => {
                    let bytes = hex::decode(h).map_err(|e| format!("user {}: {e}", u.name))?;
                    bytes
                        .try_into()
                        .map_err(|_| format!("user {}: token_sha256 must be 32 bytes", u.name))?
                }
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
            });
        }
        Ok(Self {
            accounts,
            failures: Mutex::new(HashMap::new()),
        })
    }

    /// True when `ip` has used up its failed attempts for this minute.
    pub fn locked_out(&self, ip: IpAddr) -> bool {
        let f = self.failures.lock();
        matches!(f.get(&ip), Some((n, since)) if *n >= MAX_FAILURES_PER_MIN && since.elapsed() < Duration::from_secs(60))
    }

    /// Check a bearer token. Every account is compared, in constant time,
    /// so timing does not reveal which (if any) account is close.
    pub fn check(&self, token: &str, ip: IpAddr) -> Option<User> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut found: Option<&Account> = None;
        for a in &self.accounts {
            if ct_eq(&a.digest, &digest) {
                found = Some(a);
            }
        }
        match found {
            Some(a) => Some(User {
                name: a.name.clone(),
                role: a.role,
            }),
            None => {
                let mut f = self.failures.lock();
                if f.len() > 10_000 {
                    f.retain(|_, (_, since)| since.elapsed() < Duration::from_secs(60));
                }
                let e = f.entry(ip).or_insert((0, Instant::now()));
                if e.1.elapsed() >= Duration::from_secs(60) {
                    *e = (0, Instant::now());
                }
                e.0 += 1;
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

pub fn token_digest_hex(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Authenticator {
        Authenticator::new(&[
            AdminUser {
                name: "alice".into(),
                role: Role::Admin,
                token_sha256: Some(token_digest_hex("alice-token-123456")),
                token_env: None,
            },
            AdminUser {
                name: "val".into(),
                role: Role::Viewer,
                token_sha256: Some(token_digest_hex("viewer-token-123456")),
                token_env: None,
            },
        ])
        .unwrap()
    }

    #[test]
    fn valid_tokens_map_to_users() {
        let a = auth();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let u = a.check("alice-token-123456", ip).unwrap();
        assert_eq!(u.name, "alice");
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
}
