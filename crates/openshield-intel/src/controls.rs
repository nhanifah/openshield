//! Dynamic IP blocks and allows, checked on the request path.
//!
//! Lookups take a read lock: one hash probe for single addresses plus a
//! scan over CIDR entries (expected to be few). Expired entries are ignored
//! immediately and swept periodically.

use std::collections::HashMap;
use std::net::IpAddr;

use ip_network::IpNetwork;
use parking_lot::RwLock;

#[derive(Debug, Clone)]
struct Entry {
    expires_at: Option<i64>,
}

#[derive(Default)]
struct Set {
    hosts: HashMap<IpAddr, Entry>,
    nets: Vec<(IpNetwork, Entry)>,
}

impl Set {
    fn contains(&self, ip: IpAddr, now: i64) -> bool {
        let live = |e: &Entry| e.expires_at.is_none_or(|t| t > now);
        if self.hosts.get(&ip).is_some_and(live) {
            return true;
        }
        self.nets.iter().any(|(n, e)| live(e) && n.contains(ip))
    }

    fn insert(&mut self, net: IpNetwork, expires_at: Option<i64>) {
        let entry = Entry { expires_at };
        if is_host(&net) {
            self.hosts.insert(net.network_address(), entry);
        } else {
            self.nets.retain(|(n, _)| *n != net);
            self.nets.push((net, entry));
        }
    }

    fn remove(&mut self, net: &IpNetwork) -> bool {
        if is_host(net) {
            self.hosts.remove(&net.network_address()).is_some()
        } else {
            let before = self.nets.len();
            self.nets.retain(|(n, _)| n != net);
            before != self.nets.len()
        }
    }

    fn sweep(&mut self, now: i64) {
        self.hosts.retain(|_, e| e.expires_at.is_none_or(|t| t > now));
        self.nets.retain(|(_, e)| e.expires_at.is_none_or(|t| t > now));
    }

    fn len(&self) -> usize {
        self.hosts.len() + self.nets.len()
    }
}

fn is_host(n: &IpNetwork) -> bool {
    match n {
        IpNetwork::V4(v) => v.netmask() == 32,
        IpNetwork::V6(v) => v.netmask() == 128,
    }
}

/// Parse `1.2.3.4`, `2001:db8::1` or a CIDR. Host bits in a CIDR are an
/// error, so `10.0.0.5/8` is rejected rather than silently widened.
pub fn parse_target(s: &str) -> Result<IpNetwork, String> {
    let s = s.trim();
    if s.contains('/') {
        let net: IpNetwork = s.parse().map_err(|e| format!("invalid network {s:?}: {e}"))?;
        let min_prefix = match net {
            IpNetwork::V4(_) => 8,
            IpNetwork::V6(_) => 32,
        };
        if net.netmask() < min_prefix {
            return Err(format!("network {s:?} is too broad (minimum /{min_prefix})"));
        }
        Ok(net)
    } else {
        let ip: IpAddr = s.parse().map_err(|_| format!("invalid IP address {s:?}"))?;
        Ok(IpNetwork::from(ip))
    }
}

pub fn canonical(net: &IpNetwork) -> String {
    if is_host(net) {
        net.network_address().to_string()
    } else {
        net.to_string()
    }
}

#[derive(Default)]
pub struct Controls {
    blocks: RwLock<Set>,
    allows: RwLock<Set>,
}

impl Controls {
    /// True when the address is blocked and not allowed.
    pub fn is_blocked(&self, ip: IpAddr, now: i64) -> bool {
        {
            let b = self.blocks.read();
            if b.len() == 0 || !b.contains(ip, now) {
                return false;
            }
        }
        !self.allows.read().contains(ip, now)
    }

    pub fn is_allowed(&self, ip: IpAddr, now: i64) -> bool {
        self.allows.read().contains(ip, now)
    }

    pub fn block(&self, net: IpNetwork, expires_at: Option<i64>) {
        self.blocks.write().insert(net, expires_at);
    }

    pub fn allow(&self, net: IpNetwork, expires_at: Option<i64>) {
        self.allows.write().insert(net, expires_at);
    }

    pub fn unblock(&self, net: &IpNetwork) -> bool {
        self.blocks.write().remove(net)
    }

    pub fn unallow(&self, net: &IpNetwork) -> bool {
        self.allows.write().remove(net)
    }

    pub fn sweep(&self, now: i64) {
        self.blocks.write().sweep(now);
        self.allows.write().sweep(now);
    }

    pub fn counts(&self) -> (usize, usize) {
        (self.blocks.read().len(), self.allows.read().len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn host_and_network_blocks() {
        let c = Controls::default();
        c.block(parse_target("203.0.113.5").unwrap(), None);
        c.block(parse_target("198.51.100.0/24").unwrap(), None);
        assert!(c.is_blocked(ip("203.0.113.5"), 0));
        assert!(c.is_blocked(ip("198.51.100.77"), 0));
        assert!(!c.is_blocked(ip("203.0.113.6"), 0));
    }

    #[test]
    fn expiry_and_sweep() {
        let c = Controls::default();
        c.block(parse_target("203.0.113.5").unwrap(), Some(100));
        assert!(c.is_blocked(ip("203.0.113.5"), 99));
        assert!(!c.is_blocked(ip("203.0.113.5"), 100));
        c.sweep(100);
        assert_eq!(c.counts(), (0, 0));
    }

    #[test]
    fn allow_overrides_block() {
        let c = Controls::default();
        c.block(parse_target("10.0.0.0/8").unwrap(), None);
        c.allow(parse_target("10.1.2.3").unwrap(), None);
        assert!(!c.is_blocked(ip("10.1.2.3"), 0));
        assert!(c.is_blocked(ip("10.1.2.4"), 0));
    }

    #[test]
    fn targets_are_validated() {
        assert!(parse_target("nope").is_err());
        assert!(parse_target("0.0.0.0/0").is_err(), "too broad");
        assert!(parse_target("10.0.0.5/8").is_err(), "host bits set");
        assert_eq!(canonical(&parse_target(" 10.0.0.5 ").unwrap()), "10.0.0.5");
        assert_eq!(canonical(&parse_target("10.0.0.0/24").unwrap()), "10.0.0.0/24");
        c_remove();
    }

    fn c_remove() {
        let c = Controls::default();
        let n = parse_target("10.0.0.0/24").unwrap();
        c.block(n, None);
        assert!(c.unblock(&n));
        assert!(!c.unblock(&n));
    }
}
