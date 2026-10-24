//! Client IP resolution behind trusted proxies.
//!
//! By default the client is the TCP peer. When OpenShield runs behind a load
//! balancer, every request would then come from the balancer, so rate limits
//! and IP rules would act on it. With `trusted_proxies` set, a peer inside one
//! of those networks may name the client in a header (default
//! `X-Forwarded-For`): the rightmost address that is not itself trusted is
//! used. Addresses from untrusted peers are never read from headers, so
//! clients cannot spoof their IP.

use std::net::IpAddr;

use ip_network::IpNetwork;

#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    networks: Vec<IpNetwork>,
    header: String,
}

impl TrustedProxies {
    pub fn new(cidrs: &[String], header: &str) -> Result<Self, String> {
        let mut networks = Vec::new();
        for c in cidrs {
            let net = if c.contains('/') {
                c.parse::<IpNetwork>()
                    .map_err(|e| format!("invalid trusted proxy network {c:?}: {e}"))?
            } else {
                let ip: IpAddr = c
                    .parse()
                    .map_err(|e| format!("invalid trusted proxy address {c:?}: {e}"))?;
                IpNetwork::from(ip)
            };
            networks.push(net);
        }
        Ok(Self {
            networks,
            header: header.to_ascii_lowercase(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }

    fn trusted(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|n| n.contains(ip))
    }

    /// The effective client address for a request from `peer`.
    pub fn client_ip(&self, peer: Option<IpAddr>, headers: &http::HeaderMap) -> Option<IpAddr> {
        let peer = peer?;
        if self.networks.is_empty() || !self.trusted(peer) {
            return Some(peer);
        }
        let mut hops: Vec<IpAddr> = Vec::new();
        for value in headers.get_all(self.header.as_str()) {
            let Ok(value) = value.to_str() else {
                return Some(peer);
            };
            for part in value.split(',') {
                match parse_hop(part.trim()) {
                    Some(ip) => hops.push(ip),
                    None => return Some(peer),
                }
            }
        }
        for ip in hops.into_iter().rev() {
            if !self.trusted(ip) {
                return Some(ip);
            }
        }
        Some(peer)
    }
}

fn parse_hop(s: &str) -> Option<IpAddr> {
    if let Ok(ip) = s.parse() {
        return Some(ip);
    }
    // "[v6]:port" or "v4:port"
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next()?.parse().ok();
    }
    s.rsplit_once(':').and_then(|(h, _)| h.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(xff: &str) -> http::HeaderMap {
        let mut m = http::HeaderMap::new();
        m.insert("x-forwarded-for", xff.parse().unwrap());
        m
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn untrusted_peer_cannot_spoof() {
        let t = TrustedProxies::new(&["10.0.0.0/8".into()], "X-Forwarded-For").unwrap();
        assert_eq!(t.client_ip(ip("203.0.113.5"), &h("1.1.1.1")), ip("203.0.113.5"));
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted_hop() {
        let t = TrustedProxies::new(&["10.0.0.0/8".into()], "X-Forwarded-For").unwrap();
        // Client-supplied "6.6.6.6" is left of the real client and ignored.
        assert_eq!(
            t.client_ip(ip("10.0.0.2"), &h("6.6.6.6, 198.51.100.7, 10.0.0.9")),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn malformed_header_falls_back_to_peer() {
        let t = TrustedProxies::new(&["10.0.0.2".into()], "X-Forwarded-For").unwrap();
        assert_eq!(t.client_ip(ip("10.0.0.2"), &h("garbage")), ip("10.0.0.2"));
        assert_eq!(t.client_ip(ip("10.0.0.2"), &http::HeaderMap::new()), ip("10.0.0.2"));
    }

    #[test]
    fn hops_with_ports_are_parsed() {
        let t = TrustedProxies::new(&["10.0.0.0/8".into()], "X-Forwarded-For").unwrap();
        assert_eq!(t.client_ip(ip("10.0.0.2"), &h("198.51.100.7:5555")), ip("198.51.100.7"));
        assert_eq!(t.client_ip(ip("10.0.0.2"), &h("[2001:db8::1]:443")), ip("2001:db8::1"));
    }

    #[test]
    fn disabled_by_default() {
        let t = TrustedProxies::default();
        assert_eq!(t.client_ip(ip("10.0.0.2"), &h("1.1.1.1")), ip("10.0.0.2"));
    }

    #[test]
    fn bad_config_is_an_error() {
        assert!(TrustedProxies::new(&["nope".into()], "X-Forwarded-For").is_err());
    }
}
