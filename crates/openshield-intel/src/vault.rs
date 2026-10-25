//! Encryption of secrets at rest (API keys, Turnstile secrets, stored
//! policies).
//!
//! AES-256-GCM with a random 96-bit nonce per value. The name a value is
//! stored under is bound as associated data, so a ciphertext copied to
//! another setting does not decrypt.
//!
//! The master key comes from `OPENSHIELD_SECRET_KEY` (32 bytes, base64)
//! or, when unset, from a key file next to the database, created on first
//! start with mode 0600. Keep the key file out of database backups: a copy
//! of the database alone then reveals no secrets. Losing the key means
//! re-entering the secrets.

use std::path::{Path, PathBuf};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// Prefix of an encrypted value, so encrypted and plain values can be told
/// apart (and old plain values migrated).
pub const PREFIX: &str = "enc:v1:";

pub const KEY_ENV: &str = "OPENSHIELD_SECRET_KEY";

pub struct Vault {
    key: LessSafeKey,
    /// Where the key came from, for the settings page.
    pub source: String,
}

impl Vault {
    pub fn from_bytes(bytes: &[u8], source: impl Into<String>) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err(format!("secret key must be 32 bytes, got {}", bytes.len()));
        }
        let unbound = UnboundKey::new(&AES_256_GCM, bytes).map_err(|_| "invalid secret key".to_string())?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            source: source.into(),
        })
    }

    /// Key from `OPENSHIELD_SECRET_KEY`, else from `key_file` (created if
    /// missing).
    pub fn load(key_file: &Path) -> Result<Self, String> {
        if let Ok(v) = std::env::var(KEY_ENV) {
            let bytes = B64
                .decode(v.trim())
                .map_err(|e| format!("{KEY_ENV} is not valid base64: {e}"))?;
            return Self::from_bytes(&bytes, format!("environment variable {KEY_ENV}"));
        }
        if key_file.exists() {
            let text = std::fs::read_to_string(key_file).map_err(|e| format!("reading {key_file:?}: {e}"))?;
            let bytes = B64
                .decode(text.trim())
                .map_err(|e| format!("{key_file:?} is not valid base64: {e}"))?;
            check_permissions(key_file)?;
            return Self::from_bytes(&bytes, format!("key file {}", key_file.display()));
        }
        let mut bytes = [0u8; 32];
        aws_lc_rs::rand::fill(&mut bytes).map_err(|_| "random generator failed".to_string())?;
        write_private(key_file, &B64.encode(bytes))?;
        log::warn!(
            "Created secret key file {} (mode 0600). Back it up separately from the database: secrets stored in \
             the dashboard cannot be read without it.",
            key_file.display()
        );
        Self::from_bytes(&bytes, format!("key file {}", key_file.display()))
    }

    /// Default key file location for a database path.
    pub fn default_key_file(db: &Path) -> PathBuf {
        let dir = db.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        dir.join("openshield-secret.key")
    }

    pub fn encrypt(&self, name: &str, plaintext: &str) -> Result<String, String> {
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| "random generator failed".to_string())?;
        let mut buf = plaintext.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(name.as_bytes()), &mut buf)
            .map_err(|_| "encryption failed".to_string())?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        Ok(format!("{PREFIX}{}", B64.encode(out)))
    }

    pub fn decrypt(&self, name: &str, stored: &str) -> Result<String, String> {
        let b64 = stored.strip_prefix(PREFIX).ok_or("value is not encrypted")?;
        let raw = B64.decode(b64).map_err(|_| "corrupt encrypted value".to_string())?;
        if raw.len() < NONCE_LEN + 16 {
            return Err("corrupt encrypted value".into());
        }
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| "corrupt encrypted value".to_string())?;
        let mut buf = ct.to_vec();
        let pt = self
            .key
            .open_in_place(nonce, Aad::from(name.as_bytes()), &mut buf)
            .map_err(|_| format!("cannot decrypt {name:?}: wrong secret key or tampered value"))?;
        String::from_utf8(pt.to_vec()).map_err(|_| "decrypted value is not text".to_string())
    }

    pub fn is_encrypted(v: &str) -> bool {
        v.starts_with(PREFIX)
    }
}

fn write_private(path: &Path, content: &str) -> Result<(), String> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {dir:?}: {e}"))?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("creating {path:?}: {e}"))?;
        f.write_all(content.as_bytes()).map_err(|e| format!("writing {path:?}: {e}"))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content).map_err(|e| format!("writing {path:?}: {e}"))
    }
}

/// Refuse a key file others can read.
fn check_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).map_err(|e| e.to_string())?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} is readable by other users (mode {:o}); run: chmod 600 {}",
                path.display(),
                mode & 0o777,
                path.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn write_private_file(path: &Path, content: &str) -> Result<(), String> {
    let _ = std::fs::remove_file(path);
    write_private(path, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> Vault {
        Vault::from_bytes(&[7u8; 32], "test").unwrap()
    }

    #[test]
    fn roundtrip_and_fresh_nonce_each_time() {
        let v = vault();
        let a = v.encrypt("ai.api_key", "AIzaSecretValue").unwrap();
        let b = v.encrypt("ai.api_key", "AIzaSecretValue").unwrap();
        assert!(a.starts_with(PREFIX));
        assert_ne!(a, b, "same plaintext must not give the same ciphertext");
        assert!(!a.contains("AIzaSecretValue"));
        assert_eq!(v.decrypt("ai.api_key", &a).unwrap(), "AIzaSecretValue");
    }

    #[test]
    fn wrong_key_name_or_tampering_fails() {
        let v = vault();
        let c = v.encrypt("ai.api_key", "s3cret").unwrap();
        assert!(v.decrypt("turnstile.secret", &c).is_err(), "bound to its name");
        let other = Vault::from_bytes(&[8u8; 32], "other").unwrap();
        assert!(other.decrypt("ai.api_key", &c).is_err(), "wrong key");
        let mut raw = B64.decode(c.strip_prefix(PREFIX).unwrap()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        let tampered = format!("{PREFIX}{}", B64.encode(raw));
        assert!(v.decrypt("ai.api_key", &tampered).is_err());
        assert!(v.decrypt("ai.api_key", "plain").is_err());
    }

    #[test]
    fn key_file_is_created_private_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.key");
        // SAFETY: test-only; make sure the env var does not take over.
        unsafe { std::env::remove_var(KEY_ENV) };
        let v1 = Vault::load(&path).unwrap();
        let c = v1.encrypt("x", "hello").unwrap();
        let v2 = Vault::load(&path).unwrap();
        assert_eq!(v2.decrypt("x", &c).unwrap(), "hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(Vault::load(&path).is_err(), "a readable key file is refused");
        }
    }

    #[test]
    fn short_keys_are_rejected() {
        assert!(Vault::from_bytes(&[1u8; 16], "x").is_err());
    }
}
