//! Passkey (WebAuthn) verification for dashboard sign-in.
//!
//! Only what a relying party needs: check the browser's client data, parse
//! the authenticator data, read the credential's public key (COSE) at
//! registration and verify assertion signatures at sign-in. Attestation is
//! not requested ("none"): the dashboard trusts the signed-in user who
//! registers a passkey, not the authenticator's maker.
//!
//! Every input comes from the browser and is untrusted: lengths are checked
//! before slicing and the CBOR decoder is strict and depth-limited.

use aws_lc_rs::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// COSE algorithm identifiers we accept.
pub const ES256: i64 = -7;
pub const EDDSA: i64 = -8;
pub const RS256: i64 = -257;
pub const ALGORITHMS: [i64; 3] = [ES256, EDDSA, RS256];

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

pub type Result<T> = std::result::Result<T, String>;

/// Where passkeys are valid: the domain they are bound to and the exact
/// page origins allowed to use them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    pub id: String,
    pub origins: Vec<String>,
}

/// A credential accepted at registration.
#[derive(Debug, Clone)]
pub struct NewCredential {
    pub id: Vec<u8>,
    pub alg: i64,
    /// ES256: uncompressed point (65 bytes); EdDSA: 32 bytes; RS256:
    /// 2-byte length of n, n, then e.
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

pub fn b64url(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn from_b64url(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| "not valid base64url".to_string())
}

/// 32 random bytes, base64url.
pub fn new_challenge() -> String {
    let mut b = [0u8; 32];
    aws_lc_rs::rand::fill(&mut b).expect("system random generator");
    b64url(&b)
}

/// Check that `rp` is usable: a domain (not an IP address) and origins on
/// that domain, https unless the host is localhost.
pub fn validate_rp(rp: &RelyingParty) -> Result<()> {
    let id = rp.id.as_str();
    if id.is_empty() || id.len() > 253 || id.parse::<std::net::IpAddr>().is_ok() {
        return Err("the passkey domain must be a host name such as localhost or console.example.com, not an IP address".into());
    }
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') || id.starts_with('.') || id.ends_with('.') {
        return Err("the passkey domain may contain only letters, digits, '-' and '.'".into());
    }
    if rp.origins.is_empty() || rp.origins.len() > 10 {
        return Err("list between 1 and 10 allowed origins".into());
    }
    for o in &rp.origins {
        let (scheme, rest) = o
            .split_once("://")
            .ok_or_else(|| format!("origin {o:?} must look like https://host[:port]"))?;
        if rest.contains('/') || rest.is_empty() {
            return Err(format!("origin {o:?} must not have a path"));
        }
        let host = match rest.rsplit_once(':') {
            Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => h,
            _ => rest,
        };
        if host != id && !host.ends_with(&format!(".{id}")) {
            return Err(format!("origin {o:?} is not on the passkey domain {id}"));
        }
        let local = host == "localhost" || host.ends_with(".localhost");
        match scheme {
            "https" => {}
            "http" if local => {}
            _ => return Err(format!("origin {o:?} must use https (http is allowed only for localhost)")),
        }
    }
    Ok(())
}

// ---- client data --------------------------------------------------------

/// The challenge in a clientDataJSON, so the caller can find the pending
/// ceremony it belongs to before full verification.
pub fn client_data_challenge(raw: &[u8]) -> Result<String> {
    let v: serde_json::Value = serde_json::from_slice(raw).map_err(|_| "client data is not JSON".to_string())?;
    v.get("challenge")
        .and_then(|c| c.as_str())
        .map(str::to_string)
        .ok_or_else(|| "client data has no challenge".into())
}

fn check_client_data(raw: &[u8], ty: &str, challenge: &str, rp: &RelyingParty) -> Result<()> {
    if raw.len() > 4096 {
        return Err("client data is too large".into());
    }
    let v: serde_json::Value = serde_json::from_slice(raw).map_err(|_| "client data is not JSON".to_string())?;
    if v.get("type").and_then(|t| t.as_str()) != Some(ty) {
        return Err(format!("client data type is not {ty}"));
    }
    if v.get("challenge").and_then(|c| c.as_str()) != Some(challenge) {
        return Err("challenge does not match".into());
    }
    let origin = v.get("origin").and_then(|o| o.as_str()).unwrap_or("");
    if !rp.origins.iter().any(|o| o == origin) {
        return Err(format!(
            "origin {origin:?} is not allowed for passkeys (allowed: {})",
            rp.origins.join(", ")
        ));
    }
    if v.get("crossOrigin").and_then(|c| c.as_bool()) == Some(true) {
        return Err("cross-origin use is not allowed".into());
    }
    Ok(())
}

// ---- authenticator data ---------------------------------------------------

struct AuthData<'a> {
    flags: u8,
    sign_count: u32,
    rest: &'a [u8],
}

fn parse_auth_data<'a>(d: &'a [u8], rp: &RelyingParty) -> Result<AuthData<'a>> {
    if d.len() < 37 {
        return Err("authenticator data is too short".into());
    }
    let rp_hash = Sha256::digest(rp.id.as_bytes());
    if d[..32] != rp_hash[..] {
        return Err(format!("passkey is for another domain (expected {})", rp.id));
    }
    let flags = d[32];
    if flags & FLAG_UP == 0 {
        return Err("user presence was not confirmed".into());
    }
    if flags & FLAG_UV == 0 {
        return Err("the authenticator did not verify the user (PIN or biometric required)".into());
    }
    Ok(AuthData {
        flags,
        sign_count: u32::from_be_bytes([d[33], d[34], d[35], d[36]]),
        rest: &d[37..],
    })
}

// ---- registration -----------------------------------------------------------

/// Verify a `navigator.credentials.create()` response.
pub fn verify_registration(
    rp: &RelyingParty,
    challenge: &str,
    client_data_json: &[u8],
    attestation_object: &[u8],
) -> Result<NewCredential> {
    check_client_data(client_data_json, "webauthn.create", challenge, rp)?;
    if attestation_object.len() > 16 * 1024 {
        return Err("attestation object is too large".into());
    }
    let (att, _) = cbor::decode(attestation_object, 0)?;
    let auth_data = att
        .map_get_text("authData")
        .and_then(|v| v.as_bytes())
        .ok_or("attestation object has no authData")?;
    let ad = parse_auth_data(auth_data, rp)?;
    if ad.flags & FLAG_AT == 0 {
        return Err("authenticator data has no credential".into());
    }
    let r = ad.rest;
    if r.len() < 18 {
        return Err("credential data is too short".into());
    }
    let id_len = u16::from_be_bytes([r[16], r[17]]) as usize;
    if id_len == 0 || id_len > 1023 || r.len() < 18 + id_len {
        return Err("credential id has a bad length".into());
    }
    let id = r[18..18 + id_len].to_vec();
    let (key, _) = cbor::decode(&r[18 + id_len..], 0)?;
    let (alg, public_key) = cose_key(&key)?;
    Ok(NewCredential {
        id,
        alg,
        public_key,
        sign_count: ad.sign_count,
    })
}

fn cose_key(k: &cbor::Value) -> Result<(i64, Vec<u8>)> {
    let int = |key: i64| k.map_get_int(key).and_then(|v| v.as_int());
    let bytes = |key: i64| k.map_get_int(key).and_then(|v| v.as_bytes());
    let alg = int(3).ok_or("public key has no algorithm")?;
    match (int(1), alg) {
        (Some(2), ES256) => {
            if int(-1) != Some(1) {
                return Err("ES256 key is not on curve P-256".into());
            }
            let (x, y) = (bytes(-2).ok_or("EC key has no x")?, bytes(-3).ok_or("EC key has no y")?);
            if x.len() != 32 || y.len() != 32 {
                return Err("EC key coordinates must be 32 bytes".into());
            }
            let mut p = Vec::with_capacity(65);
            p.push(0x04);
            p.extend_from_slice(x);
            p.extend_from_slice(y);
            Ok((ES256, p))
        }
        (Some(1), EDDSA) => {
            if int(-1) != Some(6) {
                return Err("EdDSA key is not Ed25519".into());
            }
            let x = bytes(-2).ok_or("Ed25519 key has no x")?;
            if x.len() != 32 {
                return Err("Ed25519 key must be 32 bytes".into());
            }
            Ok((EDDSA, x.to_vec()))
        }
        (Some(3), RS256) => {
            let (n, e) = (bytes(-1).ok_or("RSA key has no n")?, bytes(-2).ok_or("RSA key has no e")?);
            if n.len() < 256 || n.len() > 1024 || e.is_empty() || e.len() > 8 {
                return Err("RSA key must be 2048 to 8192 bits".into());
            }
            let mut p = Vec::with_capacity(2 + n.len() + e.len());
            p.extend_from_slice(&(n.len() as u16).to_be_bytes());
            p.extend_from_slice(n);
            p.extend_from_slice(e);
            Ok((RS256, p))
        }
        _ => Err(format!("unsupported key type or algorithm {alg} (use ES256, EdDSA or RS256)")),
    }
}

// ---- sign-in ----------------------------------------------------------------

/// Verify a `navigator.credentials.get()` response against a stored
/// credential. Returns the authenticator's new signature counter.
#[allow(clippy::too_many_arguments)]
pub fn verify_assertion(
    rp: &RelyingParty,
    challenge: &str,
    alg: i64,
    public_key: &[u8],
    stored_count: u32,
    client_data_json: &[u8],
    authenticator_data: &[u8],
    sig: &[u8],
) -> Result<u32> {
    check_client_data(client_data_json, "webauthn.get", challenge, rp)?;
    if authenticator_data.len() > 4096 || sig.len() > 1024 {
        return Err("assertion is too large".into());
    }
    let ad = parse_auth_data(authenticator_data, rp)?;
    let mut msg = Vec::with_capacity(authenticator_data.len() + 32);
    msg.extend_from_slice(authenticator_data);
    msg.extend_from_slice(&Sha256::digest(client_data_json));
    let ok = match alg {
        ES256 => UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key)
            .verify(&msg, sig)
            .is_ok(),
        EDDSA => UnparsedPublicKey::new(&signature::ED25519, public_key).verify(&msg, sig).is_ok(),
        RS256 => {
            if public_key.len() < 3 {
                return Err("stored RSA key is malformed".into());
            }
            let n_len = u16::from_be_bytes([public_key[0], public_key[1]]) as usize;
            if public_key.len() <= 2 + n_len {
                return Err("stored RSA key is malformed".into());
            }
            RsaPublicKeyComponents {
                n: &public_key[2..2 + n_len],
                e: &public_key[2 + n_len..],
            }
            .verify(&signature::RSA_PKCS1_2048_8192_SHA256, &msg, sig)
            .is_ok()
        }
        _ => return Err(format!("unsupported algorithm {alg}")),
    };
    if !ok {
        return Err("signature is not valid".into());
    }
    // Synced passkeys always report 0. A counter that does not move forward
    // on an authenticator that does count suggests a cloned key.
    if (ad.sign_count != 0 || stored_count != 0) && ad.sign_count <= stored_count {
        return Err("signature counter did not increase (the passkey may have been cloned)".into());
    }
    Ok(ad.sign_count)
}

// ---- minimal CBOR -------------------------------------------------------------

/// Just enough CBOR (RFC 8949) for attestation objects and COSE keys:
/// definite-length items only, nesting at most 8 deep.
pub(crate) mod cbor {
    use super::Result;

    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        Int(i64),
        Bytes(Vec<u8>),
        Text(String),
        Array(Vec<Value>),
        Map(Vec<(Value, Value)>),
        Simple(u8),
    }

    impl Value {
        pub fn as_int(&self) -> Option<i64> {
            match self {
                Value::Int(i) => Some(*i),
                _ => None,
            }
        }
        pub fn as_bytes(&self) -> Option<&[u8]> {
            match self {
                Value::Bytes(b) => Some(b),
                _ => None,
            }
        }
        pub fn map_get_int(&self, key: i64) -> Option<&Value> {
            match self {
                Value::Map(m) => m.iter().find(|(k, _)| *k == Value::Int(key)).map(|(_, v)| v),
                _ => None,
            }
        }
        pub fn map_get_text(&self, key: &str) -> Option<&Value> {
            match self {
                Value::Map(m) => m
                    .iter()
                    .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
                    .map(|(_, v)| v),
                _ => None,
            }
        }
    }

    const MAX_DEPTH: usize = 8;
    const MAX_ITEMS: u64 = 256;

    /// Decode one item from the start of `b`; returns it and the bytes used.
    pub fn decode(b: &[u8], depth: usize) -> Result<(Value, usize)> {
        if depth > MAX_DEPTH {
            return Err("CBOR nesting is too deep".into());
        }
        let first = *b.first().ok_or("CBOR input ended early")?;
        let major = first >> 5;
        let info = first & 0x1f;
        let (arg, mut pos): (u64, usize) = match info {
            0..=23 => (info as u64, 1),
            24 => (*b.get(1).ok_or("CBOR input ended early")? as u64, 2),
            25 => (u16::from_be_bytes(take::<2>(b, 1)?) as u64, 3),
            26 => (u32::from_be_bytes(take::<4>(b, 1)?) as u64, 5),
            27 => (u64::from_be_bytes(take::<8>(b, 1)?), 9),
            _ => return Err("indefinite-length CBOR is not supported".into()),
        };
        let v = match major {
            0 => Value::Int(i64::try_from(arg).map_err(|_| "CBOR integer is too large")?),
            1 => Value::Int(-1 - i64::try_from(arg).map_err(|_| "CBOR integer is too large")?),
            2 | 3 => {
                let n = usize::try_from(arg).map_err(|_| "CBOR length is too large")?;
                let end = pos.checked_add(n).filter(|&e| e <= b.len()).ok_or("CBOR string runs past the end")?;
                let s = &b[pos..end];
                pos = end;
                if major == 2 {
                    Value::Bytes(s.to_vec())
                } else {
                    Value::Text(String::from_utf8(s.to_vec()).map_err(|_| "CBOR text is not UTF-8")?)
                }
            }
            4 | 5 => {
                if arg > MAX_ITEMS {
                    return Err("CBOR container has too many items".into());
                }
                let mut items = Vec::new();
                let mut pairs = Vec::new();
                for _ in 0..arg {
                    let (k, used) = decode(&b[pos..], depth + 1)?;
                    pos += used;
                    if major == 4 {
                        items.push(k);
                    } else {
                        let (v, used) = decode(&b[pos..], depth + 1)?;
                        pos += used;
                        pairs.push((k, v));
                    }
                }
                if major == 4 { Value::Array(items) } else { Value::Map(pairs) }
            }
            6 => return Err("CBOR tags are not supported".into()),
            _ => match info {
                20..=23 => Value::Simple(info),
                _ => return Err("CBOR floats are not supported".into()),
            },
        };
        Ok((v, pos))
    }

    fn take<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N]> {
        b.get(at..at + N)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| "CBOR input ended early".to_string())
    }
}

// ---- tests --------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair};

    pub fn rp() -> RelyingParty {
        RelyingParty {
            id: "localhost".into(),
            origins: vec!["http://localhost:9091".into()],
        }
    }

    // A tiny CBOR encoder for building test inputs.
    fn head(major: u8, n: u64, out: &mut Vec<u8>) {
        match n {
            0..=23 => out.push((major << 5) | n as u8),
            24..=255 => out.extend([(major << 5) | 24, n as u8]),
            256..=65535 => {
                out.push((major << 5) | 25);
                out.extend((n as u16).to_be_bytes());
            }
            _ => {
                out.push((major << 5) | 26);
                out.extend((n as u32).to_be_bytes());
            }
        }
    }
    fn int(i: i64, out: &mut Vec<u8>) {
        if i >= 0 { head(0, i as u64, out) } else { head(1, (-1 - i) as u64, out) }
    }
    fn bytes(b: &[u8], out: &mut Vec<u8>) {
        head(2, b.len() as u64, out);
        out.extend_from_slice(b);
    }
    fn text(s: &str, out: &mut Vec<u8>) {
        head(3, s.len() as u64, out);
        out.extend_from_slice(s.as_bytes());
    }

    /// A software authenticator: one key pair, a credential id and a counter.
    pub enum Key {
        Ec(EcdsaKeyPair),
        Ed(Ed25519KeyPair),
    }

    pub struct SoftAuthenticator {
        pub key: Key,
        pub id: Vec<u8>,
        pub count: u32,
        pub rp_id: String,
        pub flags: u8,
    }

    impl SoftAuthenticator {
        pub fn es256() -> Self {
            let key = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
            Self::with(Key::Ec(key))
        }
        pub fn ed25519() -> Self {
            Self::with(Key::Ed(Ed25519KeyPair::generate().unwrap()))
        }
        fn with(key: Key) -> Self {
            let mut id = vec![0u8; 16];
            aws_lc_rs::rand::fill(&mut id).unwrap();
            Self {
                key,
                id,
                count: 0,
                rp_id: "localhost".into(),
                flags: FLAG_UP | FLAG_UV,
            }
        }

        pub fn client_data(ty: &str, challenge: &str, origin: &str) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({"type": ty, "challenge": challenge, "origin": origin, "crossOrigin": false}))
                .unwrap()
        }

        fn cose(&self) -> Vec<u8> {
            let mut out = Vec::new();
            match &self.key {
                Key::Ec(k) => {
                    let p = k.public_key().as_ref();
                    head(5, 5, &mut out);
                    int(1, &mut out);
                    int(2, &mut out);
                    int(3, &mut out);
                    int(ES256, &mut out);
                    int(-1, &mut out);
                    int(1, &mut out);
                    int(-2, &mut out);
                    bytes(&p[1..33], &mut out);
                    int(-3, &mut out);
                    bytes(&p[33..65], &mut out);
                }
                Key::Ed(k) => {
                    head(5, 4, &mut out);
                    int(1, &mut out);
                    int(1, &mut out);
                    int(3, &mut out);
                    int(EDDSA, &mut out);
                    int(-1, &mut out);
                    int(6, &mut out);
                    int(-2, &mut out);
                    bytes(k.public_key().as_ref(), &mut out);
                }
            }
            out
        }

        fn auth_data(&self, attested: bool) -> Vec<u8> {
            let mut d = Sha256::digest(self.rp_id.as_bytes()).to_vec();
            d.push(self.flags | if attested { FLAG_AT } else { 0 });
            d.extend(self.count.to_be_bytes());
            if attested {
                d.extend([0u8; 16]);
                d.extend((self.id.len() as u16).to_be_bytes());
                d.extend(&self.id);
                d.extend(self.cose());
            }
            d
        }

        /// (clientDataJSON, attestationObject)
        pub fn register(&self, challenge: &str, origin: &str) -> (Vec<u8>, Vec<u8>) {
            let cd = Self::client_data("webauthn.create", challenge, origin);
            let mut att = Vec::new();
            head(5, 3, &mut att);
            text("fmt", &mut att);
            text("none", &mut att);
            text("attStmt", &mut att);
            head(5, 0, &mut att);
            text("authData", &mut att);
            bytes(&self.auth_data(true), &mut att);
            (cd, att)
        }

        /// (clientDataJSON, authenticatorData, signature)
        pub fn sign_in(&mut self, challenge: &str, origin: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let cd = Self::client_data("webauthn.get", challenge, origin);
            let ad = self.auth_data(false);
            let mut msg = ad.clone();
            msg.extend(Sha256::digest(&cd));
            let sig = match &self.key {
                Key::Ec(k) => k.sign(&SystemRandom::new(), &msg).unwrap().as_ref().to_vec(),
                Key::Ed(k) => k.sign(&msg).as_ref().to_vec(),
            };
            (cd, ad, sig)
        }
    }

    const ORIGIN: &str = "http://localhost:9091";

    fn round_trip(mut a: SoftAuthenticator, alg: i64) {
        let rp = rp();
        let ch = new_challenge();
        let (cd, att) = a.register(&ch, ORIGIN);
        let cred = verify_registration(&rp, &ch, &cd, &att).unwrap();
        assert_eq!(cred.id, a.id);
        assert_eq!(cred.alg, alg);
        let ch2 = new_challenge();
        let (cd, ad, sig) = a.sign_in(&ch2, ORIGIN);
        assert_eq!(verify_assertion(&rp, &ch2, cred.alg, &cred.public_key, 0, &cd, &ad, &sig), Ok(0));
        // A different challenge, or a tampered signature, fails.
        assert!(verify_assertion(&rp, &new_challenge(), cred.alg, &cred.public_key, 0, &cd, &ad, &sig).is_err());
        let mut bad = sig.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(verify_assertion(&rp, &ch2, cred.alg, &cred.public_key, 0, &cd, &ad, &bad).is_err());
    }

    #[test]
    fn es256_and_ed25519_register_and_sign_in() {
        round_trip(SoftAuthenticator::es256(), ES256);
        round_trip(SoftAuthenticator::ed25519(), EDDSA);
    }

    #[test]
    fn wrong_origin_type_or_domain_is_rejected() {
        let rp = rp();
        let a = SoftAuthenticator::es256();
        let ch = new_challenge();
        let (cd, att) = a.register(&ch, "http://evil.localhost:9091");
        assert!(verify_registration(&rp, &ch, &cd, &att).unwrap_err().contains("origin"));
        let (_, att) = a.register(&ch, ORIGIN);
        let cd = SoftAuthenticator::client_data("webauthn.get", &ch, ORIGIN);
        assert!(verify_registration(&rp, &ch, &cd, &att).unwrap_err().contains("type"));
        let mut other = SoftAuthenticator::es256();
        other.rp_id = "example.com".into();
        let (cd, att) = other.register(&ch, ORIGIN);
        assert!(verify_registration(&rp, &ch, &cd, &att).unwrap_err().contains("domain"));
    }

    #[test]
    fn user_verification_is_required() {
        let mut a = SoftAuthenticator::es256();
        a.flags = FLAG_UP;
        let ch = new_challenge();
        let (cd, att) = a.register(&ch, ORIGIN);
        assert!(verify_registration(&rp(), &ch, &cd, &att).unwrap_err().contains("verify the user"));
    }

    #[test]
    fn counter_going_backwards_is_rejected() {
        let rp = rp();
        let mut a = SoftAuthenticator::es256();
        a.count = 5;
        let ch = new_challenge();
        let (cd, att) = a.register(&ch, ORIGIN);
        let cred = verify_registration(&rp, &ch, &cd, &att).unwrap();
        a.count = 6;
        let ch = new_challenge();
        let (cd, ad, sig) = a.sign_in(&ch, ORIGIN);
        assert_eq!(verify_assertion(&rp, &ch, ES256, &cred.public_key, 5, &cd, &ad, &sig), Ok(6));
        assert!(verify_assertion(&rp, &ch, ES256, &cred.public_key, 6, &cd, &ad, &sig).unwrap_err().contains("counter"));
    }

    #[test]
    fn cbor_decoder_rejects_hostile_input() {
        assert!(cbor::decode(&[], 0).is_err());
        assert!(cbor::decode(&[0x5f], 0).is_err()); // indefinite bytes
        assert!(cbor::decode(&[0x5a, 0xff, 0xff, 0xff, 0xff], 0).is_err()); // length past the end
        assert!(cbor::decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0).is_err()); // huge array
        let deep = vec![0x81u8; 20];
        assert!(cbor::decode(&deep, 0).is_err());
        assert_eq!(cbor::decode(&[0x38, 0x18], 0).unwrap().0, cbor::Value::Int(-25));
    }

    #[test]
    fn relying_party_rules() {
        let ok = |id: &str, o: &[&str]| validate_rp(&RelyingParty { id: id.into(), origins: o.iter().map(|s| s.to_string()).collect() });
        assert!(ok("localhost", &["http://localhost:9091"]).is_ok());
        assert!(ok("example.com", &["https://console.example.com"]).is_ok());
        assert!(ok("127.0.0.1", &["http://127.0.0.1:9091"]).is_err());
        assert!(ok("example.com", &["http://console.example.com"]).is_err());
        assert!(ok("example.com", &["https://example.org"]).is_err());
        assert!(ok("example.com", &["https://badexample.com"]).is_err());
        assert!(ok("example.com", &["https://example.com/path"]).is_err());
    }
}
