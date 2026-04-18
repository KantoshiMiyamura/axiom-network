// Copyright (c) 2026 Kantoshi Miyamura

//! Peer discovery and DNS-based bootstrap.

use std::collections::{HashSet, VecDeque};
use std::net::{SocketAddr, ToSocketAddrs};
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

pub const DEVNET_DNS_SEEDS: &[&str] = &["devnet-seed.axiom-network.io:9000"];

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

pub struct PeerDiscovery {
    known_peers: HashSet<SocketAddr>,
    seed_nodes: Vec<SocketAddr>,
    last_discovery: u64,
    discovery_interval: u64,
}

impl PeerDiscovery {
    pub fn new(seed_nodes: Vec<SocketAddr>) -> Self {
        PeerDiscovery {
            known_peers: HashSet::new(),
            seed_nodes,
            last_discovery: 0,
            discovery_interval: 300,
        }
    }

    pub fn add_peer(&mut self, addr: SocketAddr) {
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
