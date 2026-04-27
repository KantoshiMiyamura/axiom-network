// Copyright (c) 2026 Kantoshi Miyamura

//! Testnet stability tests.

use axiom_node::network::PeerDiscovery;
use axiom_node::TestnetConfig;
use std::net::SocketAddr;
use std::str::FromStr;

#[test]
fn test_testnet_config_valid() {
    let config = TestnetConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn test_testnet_has_no_default_seed_nodes() {
    // Axiom has no project-operated seed nodes — operators wire peers
    // manually via `--peer ADDR`. A fresh testnet config must be empty.
    let config = TestnetConfig::default();
    assert!(config.get_seed_nodes().is_empty());
}

#[test]
fn test_peer_discovery_bootstrap() {
    let seed_nodes = vec![SocketAddr::from_str("127.0.0.1:9100").unwrap()];
    let discovery = PeerDiscovery::new(seed_nodes.clone());
    assert_eq!(discovery.get_seed_nodes(), seed_nodes);
}

#[test]
fn test_peer_discovery_add_peers() {
    let mut discovery = PeerDiscovery::new(vec![]);
    let peer = SocketAddr::from_str("127.0.0.1:9101").unwrap();

    discovery.add_peer(peer);
    assert!(discovery.is_known(&peer));
}

#[test]
fn test_peer_discovery_peer_count() {
    let mut discovery = PeerDiscovery::new(vec![]);
    let peer1 = SocketAddr::from_str("127.0.0.1:9101").unwrap();
    let peer2 = SocketAddr::from_str("127.0.0.1:9102").unwrap();

    discovery.add_peer(peer1);
    discovery.add_peer(peer2);
    assert_eq!(discovery.peer_count(), 2);
}

#[test]
fn test_peer_discovery_should_discover() {
    let discovery = PeerDiscovery::new(vec![]);
    assert!(discovery.should_discover());
}
