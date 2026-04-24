// Copyright (c) 2026 Kantoshi Miyamura

//! Peer discovery and DNS-based bootstrap.

use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAINNET_DNS_SEEDS: &[&str] = &[
    // Hardcoded bootstrap node — always reachable even if DNS is unavailable.
    "178.104.8.137:9000",
    // DNS seeds (resolve when A records are configured).
    "seed.axiom-network.io:9000",
    "seed2.axiom-network.io:9000",
    "seed3.axiom-network.io:9000",
    "seed-eu.axiom-network.io:9000",
    "seed-us.axiom-network.io:9000",
    "seed-ap.axiom-network.io:9000",
];

pub const TESTNET_DNS_SEEDS: &[&str] = &[
    "testnet-seed.axiom-network.io:9000",
    "testnet-seed2.axiom-network.io:9000",
];

// Devnet is isolated by design. No default peers, no DNS seeding.
// Operators wiring multi-node devnets pass peers explicitly via `--peer`.
pub const DEVNET_DNS_SEEDS: &[&str] = &[];

/// Resolve DNS seeds; unreachable hostnames are silently skipped.
pub fn resolve_dns_seeds(hostnames: &[&str]) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    for host in hostnames {
        if let Ok(resolved) = host.to_socket_addrs() {
            addrs.extend(resolved);
        }
    }
    addrs
}

/// Build the set of socket addresses that identify **this node** on the wire.
///
/// The p2p port is the authoritative discriminator; IPs are merely the
/// interfaces we might be reachable at. Any peer list entry matching
/// (self_ip, p2p_port) is a loopback to ourselves and must be skipped.
///
/// Always includes loopback (127.0.0.1, ::1) and `bind_addr` itself. When
/// bind_addr is `0.0.0.0` / `::`, attempts a best-effort outbound-IP probe
/// (UDP `connect` trick) to learn the primary public/LAN IP so a seed list
/// that names our public IP is still filtered.
pub fn self_p2p_addrs(bind_addr: SocketAddr) -> Vec<SocketAddr> {
    let port = bind_addr.port();
    let mut set: HashSet<SocketAddr> = HashSet::new();

    set.insert(bind_addr);
    set.insert(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    set.insert(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port));
    set.insert(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    set.insert(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port));

    if bind_addr.ip().is_unspecified() {
        if let Some(ip) = detect_outbound_ipv4() {
            set.insert(SocketAddr::new(IpAddr::V4(ip), port));
        }
        if let Some(ip) = detect_outbound_ipv6() {
            set.insert(SocketAddr::new(IpAddr::V6(ip), port));
        }
    }

    set.into_iter().collect()
}

/// Best-effort primary IPv4 address for this host.
///
/// Opens a UDP socket and *connects* it to a public address (no packets are
/// actually sent). The kernel then binds the socket to whichever interface it
/// would use to reach that destination, and `local_addr()` reports the IP.
/// Returns `None` in isolated environments (no route to the probe address).
fn detect_outbound_ipv4() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

fn detect_outbound_ipv6() -> Option<Ipv6Addr> {
    let sock = UdpSocket::bind("[::]:0").ok()?;
    sock.connect("[2001:4860:4860::8888]:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V6(v6) if !v6.is_unspecified() => Some(v6),
        _ => None,
    }
}

/// Returns true if `addr` points back at this node.
///
/// Matches on full (IP, port) tuples against the precomputed self-addrs list.
/// An address book entry with the same IP but a different port is a *different*
/// node on the same host and is **not** filtered.
pub fn is_self_addr(addr: &SocketAddr, self_addrs: &[SocketAddr]) -> bool {
    self_addrs.iter().any(|s| s == addr)
}

/// Remove duplicates and entries that point back at this node.
/// Preserves input order so operator-supplied `--peer` entries keep their
/// dial priority over DNS-resolved seeds.
pub fn dedupe_and_filter_self(
    addrs: Vec<SocketAddr>,
    self_addrs: &[SocketAddr],
) -> Vec<SocketAddr> {
    let mut seen: HashSet<SocketAddr> = HashSet::new();
    let mut out: Vec<SocketAddr> = Vec::with_capacity(addrs.len());
    for a in addrs {
        if is_self_addr(&a, self_addrs) {
            continue;
        }
        if seen.insert(a) {
            out.push(a);
        }
    }
    out
}

pub struct PeerDiscovery {
    known_peers: HashSet<SocketAddr>,
    seed_nodes: Vec<SocketAddr>,
    last_discovery: u64,
    discovery_interval: u64,
    /// Addrs that map back to this node; used to reject self entries from
    /// gossip (`Peers` messages) or from handshake-detected self-dials.
    self_addrs: HashSet<SocketAddr>,
}

impl PeerDiscovery {
    pub fn new(seed_nodes: Vec<SocketAddr>) -> Self {
        PeerDiscovery {
            known_peers: HashSet::new(),
            seed_nodes,
            last_discovery: 0,
            discovery_interval: 300,
            self_addrs: HashSet::new(),
        }
    }

    /// Record the addrs that resolve to this node so future gossip
    /// `Peers` messages can be filtered.
    pub fn set_self_addrs(&mut self, self_addrs: Vec<SocketAddr>) {
        self.self_addrs = self_addrs.into_iter().collect();
    }

    /// Mark `addr` as a confirmed self-address (e.g. after a handshake
    /// returned `HandshakeError::SelfConnection`). Idempotent.
    pub fn mark_self(&mut self, addr: SocketAddr) {
        self.self_addrs.insert(addr);
        self.known_peers.remove(&addr);
    }

    pub fn is_self(&self, addr: &SocketAddr) -> bool {
        self.self_addrs.contains(addr)
    }

    pub fn self_addrs(&self) -> Vec<SocketAddr> {
        self.self_addrs.iter().copied().collect()
    }

    pub fn add_peer(&mut self, addr: SocketAddr) {
        if self.self_addrs.contains(&addr) {
            return;
        }
        self.known_peers.insert(addr);
    }

    pub fn get_peers(&self) -> Vec<SocketAddr> {
        self.known_peers.iter().copied().collect()
    }

    pub fn get_seed_nodes(&self) -> Vec<SocketAddr> {
        self.seed_nodes.clone()
    }

    pub fn is_known(&self, addr: &SocketAddr) -> bool {
        self.known_peers.contains(addr)
    }

    pub fn peer_count(&self) -> usize {
        self.known_peers.len()
    }

    pub fn should_discover(&self) -> bool {
        let now = current_timestamp();
        now - self.last_discovery >= self.discovery_interval
    }

    pub fn mark_discovery(&mut self) {
        self.last_discovery = current_timestamp();
    }

    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        self.known_peers.remove(addr);
    }

    pub fn clear_peers(&mut self) {
        self.known_peers.clear();
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

const ADDR_BOOK_CAPACITY: usize = 2048;

/// Fixed-capacity address book with LRU eviction.
pub struct PeerAddressBook {
    addrs: VecDeque<SocketAddr>,
    set: HashSet<SocketAddr>,
}

impl PeerAddressBook {
    pub fn new() -> Self {
        PeerAddressBook {
            addrs: VecDeque::new(),
            set: HashSet::new(),
        }
    }

    /// Add an address, evicting the oldest when at capacity.
    pub fn add_addr(&mut self, addr: SocketAddr) {
        if self.set.contains(&addr) {
            return;
        }
        if self.addrs.len() >= ADDR_BOOK_CAPACITY {
            if let Some(oldest) = self.addrs.pop_front() {
                self.set.remove(&oldest);
            }
        }
        self.addrs.push_back(addr);
        self.set.insert(addr);
    }

    /// Return up to `n` randomly-sampled addresses.
    pub fn sample_addrs(&self, n: usize) -> Vec<SocketAddr> {
        use rand_core::RngCore;
        let all: Vec<SocketAddr> = self.addrs.iter().copied().collect();
        if all.len() <= n {
            return all;
        }
        let mut rng = rand_core::OsRng;
        let mut pool = all;
        for i in 0..n {
            let remaining = pool.len() - i;
            let j = i + (rng.next_u64() as usize % remaining);
            pool.swap(i, j);
        }
        pool.truncate(n);
        pool
    }

    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let addrs: Vec<SocketAddr> = self.addrs.iter().copied().collect();
        let encoded = bincode::serde::encode_to_vec(&addrs, bincode::config::standard())
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        std::fs::write(path, encoded)
    }

    /// Load the address book from disk; returns empty if the file doesn't exist.
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let data = std::fs::read(path)?;
        let (addrs, _): (Vec<SocketAddr>, _) =
            bincode::serde::decode_from_slice(&data, bincode::config::standard())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let mut book = Self::new();
        for addr in addrs {
            book.add_addr(addr);
        }
        Ok(book)
    }
}

impl Default for PeerAddressBook {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_peer_discovery_creation() {
        let seed_nodes = vec![SocketAddr::from_str("127.0.0.1:9100").unwrap()];
        let discovery = PeerDiscovery::new(seed_nodes.clone());
        assert_eq!(discovery.get_seed_nodes(), seed_nodes);
    }

    #[test]
    fn test_add_peer() {
        let discovery = PeerDiscovery::new(vec![]);
        let mut discovery = discovery;
        let addr = SocketAddr::from_str("127.0.0.1:9101").unwrap();

        discovery.add_peer(addr);
        assert!(discovery.is_known(&addr));
        assert_eq!(discovery.peer_count(), 1);
    }

    #[test]
    fn test_remove_peer() {
        let mut discovery = PeerDiscovery::new(vec![]);
        let addr = SocketAddr::from_str("127.0.0.1:9101").unwrap();

        discovery.add_peer(addr);
        assert_eq!(discovery.peer_count(), 1);

        discovery.remove_peer(&addr);
        assert_eq!(discovery.peer_count(), 0);
    }

    #[test]
    fn test_should_discover() {
        let discovery = PeerDiscovery::new(vec![]);
        assert!(discovery.should_discover());
    }

    #[test]
    fn test_clear_peers() {
        let mut discovery = PeerDiscovery::new(vec![]);
        let addr = SocketAddr::from_str("127.0.0.1:9101").unwrap();

        discovery.add_peer(addr);
        assert_eq!(discovery.peer_count(), 1);

        discovery.clear_peers();
        assert_eq!(discovery.peer_count(), 0);
    }

    #[test]
    fn test_address_book_add_and_sample() {
        let mut book = PeerAddressBook::new();
        for port in 9000u16..9010 {
            book.add_addr(SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap());
        }
        assert_eq!(book.len(), 10);

        let sample = book.sample_addrs(5);
        assert_eq!(sample.len(), 5);

        let all = book.sample_addrs(100);
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn test_address_book_dedup() {
        let mut book = PeerAddressBook::new();
        let addr = SocketAddr::from_str("10.0.0.1:9000").unwrap();
        book.add_addr(addr);
        book.add_addr(addr); // duplicate
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn test_address_book_capacity_eviction() {
        let mut book = PeerAddressBook::new();
        // Insert ADDR_BOOK_CAPACITY + 1 unique addresses.
        for i in 0u32..=(ADDR_BOOK_CAPACITY as u32) {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
                1,
            ));
            book.add_addr(SocketAddr::new(ip, 9000));
        }
        assert_eq!(book.len(), ADDR_BOOK_CAPACITY);
    }

    #[test]
    fn test_self_addrs_includes_loopback_and_bind() {
        let bind = SocketAddr::from_str("0.0.0.0:9000").unwrap();
        let self_addrs = self_p2p_addrs(bind);

        assert!(self_addrs.contains(&SocketAddr::from_str("127.0.0.1:9000").unwrap()));
        assert!(self_addrs.contains(&SocketAddr::from_str("0.0.0.0:9000").unwrap()));
        assert!(self_addrs.contains(&SocketAddr::from_str("[::1]:9000").unwrap()));
    }

    #[test]
    fn test_is_self_addr_matches_port_exactly() {
        let bind = SocketAddr::from_str("0.0.0.0:9000").unwrap();
        let self_addrs = self_p2p_addrs(bind);

        // Same IP + same port → self.
        assert!(is_self_addr(
            &SocketAddr::from_str("127.0.0.1:9000").unwrap(),
            &self_addrs
        ));
        // Same IP, DIFFERENT port → not self (different node on same host).
        assert!(!is_self_addr(
            &SocketAddr::from_str("127.0.0.1:9001").unwrap(),
            &self_addrs
        ));
    }

    #[test]
    fn test_dedupe_and_filter_self_preserves_order() {
        let bind = SocketAddr::from_str("0.0.0.0:9000").unwrap();
        let self_addrs = self_p2p_addrs(bind);

        let input = vec![
            SocketAddr::from_str("1.1.1.1:9000").unwrap(),
            SocketAddr::from_str("127.0.0.1:9000").unwrap(), // self — drop
            SocketAddr::from_str("2.2.2.2:9000").unwrap(),
            SocketAddr::from_str("1.1.1.1:9000").unwrap(), // duplicate — drop
            SocketAddr::from_str("0.0.0.0:9000").unwrap(), // self — drop
        ];
        let out = dedupe_and_filter_self(input, &self_addrs);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], SocketAddr::from_str("1.1.1.1:9000").unwrap());
        assert_eq!(out[1], SocketAddr::from_str("2.2.2.2:9000").unwrap());
    }

    #[test]
    fn test_peer_discovery_rejects_self_from_gossip() {
        let mut d = PeerDiscovery::new(vec![]);
        let self_addr = SocketAddr::from_str("178.104.8.137:9000").unwrap();
        d.set_self_addrs(vec![self_addr]);

        d.add_peer(self_addr);
        assert!(!d.is_known(&self_addr));

        let other = SocketAddr::from_str("1.2.3.4:9000").unwrap();
        d.add_peer(other);
        assert!(d.is_known(&other));
    }

    #[test]
    fn test_mark_self_evicts_known_peer() {
        let mut d = PeerDiscovery::new(vec![]);
        let addr = SocketAddr::from_str("10.0.0.1:9000").unwrap();
        d.add_peer(addr);
        assert!(d.is_known(&addr));

        d.mark_self(addr);
        assert!(!d.is_known(&addr));
        assert!(d.is_self(&addr));
    }

    #[test]
    fn test_address_book_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.dat");

        let mut book = PeerAddressBook::new();
        book.add_addr(SocketAddr::from_str("1.2.3.4:9000").unwrap());
        book.add_addr(SocketAddr::from_str("5.6.7.8:9001").unwrap());
        book.save(&path).unwrap();

        let loaded = PeerAddressBook::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
    }
}
