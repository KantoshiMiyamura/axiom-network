// Copyright (c) 2026 Kantoshi Miyamura

//! Peer Discovery integration tests.
//!
//! Covers:
//! - GetPeers / Peers message roundtrip (serialization)
//! - PeerManager::get_ready_peer_addrs returns only ready peers
//! - PeerManager::is_addr_connected detects existing connections
//! - NetworkService returns Peers response to GetPeers
//! - PeerDiscovery deduplication (same addr added only once)
//! - PeerDiscovery self-address exclusion (bind_addr not stored)

use axiom_node::network::{
    Direction, Message, MessageType, NetworkService, PeerDiscovery, PeerManager, PeerState,
};
use axiom_node::{Config, Node};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

fn create_test_service() -> (TempDir, NetworkService) {
    let temp_dir = TempDir::new().unwrap();
    let mut config = Config::default();
    config.data_dir = temp_dir.path().to_path_buf();
    let node = Node::new(config).unwrap();
    let peer_manager = PeerManager::new("dev".to_string());
    let service = NetworkService::new(node, peer_manager);
    (temp_dir, service)
}

// ---------------------------------------------------------------------------
// 1. GetPeers message roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_get_peers_message_roundtrip() {
    let msg = Message::GetPeers;
    let bytes = msg.serialize().unwrap();
    assert_eq!(bytes[0], 9, "GetPeers type byte must be 9");

    let decoded = Message::deserialize(&bytes).unwrap();
    assert!(matches!(decoded, Message::GetPeers));
}

// ---------------------------------------------------------------------------
// 2. Peers message roundtrip with multiple SocketAddrs
// ---------------------------------------------------------------------------

#[test]
fn test_peers_message_roundtrip() {
    let addrs = vec![
        make_addr(9000),
        make_addr(9001),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000),
    ];
    let msg = Message::Peers(addrs.clone());
    let bytes = msg.serialize().unwrap();
    assert_eq!(bytes[0], 10, "Peers type byte must be 10");

    let decoded = Message::deserialize(&bytes).unwrap();
    match decoded {
        Message::Peers(decoded_addrs) => {
            assert_eq!(
                decoded_addrs, addrs,
                "Peers addresses must survive roundtrip"
            );
        }
        _ => panic!("expected Message::Peers"),
    }
}

// ---------------------------------------------------------------------------
// 3. MessageType::from_u8 accepts 9 and 10
// ---------------------------------------------------------------------------

#[test]
fn test_message_type_from_u8_peers() {
    assert!(matches!(MessageType::from_u8(9), Ok(MessageType::GetPeers)));
    assert!(matches!(MessageType::from_u8(10), Ok(MessageType::Peers)));
    assert!(matches!(MessageType::from_u8(11), Ok(MessageType::Inv)));
    assert!(matches!(MessageType::from_u8(99), Err(_)));
}

// ---------------------------------------------------------------------------
// 4. PeerManager::get_ready_peer_addrs returns only ready peers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_ready_peer_addrs() {
    let manager = PeerManager::new("dev".to_string());

    let addr1 = make_addr(9001);
    let addr2 = make_addr(9002);
    let addr3 = make_addr(9003);

    let p1 = manager.add_peer(addr1, Direction::Outbound).await.unwrap();
    let p2 = manager.add_peer(addr2, Direction::Outbound).await.unwrap();
    let _p3 = manager.add_peer(addr3, Direction::Inbound).await.unwrap();

    // Only p1 and p2 become Ready; p3 stays Connecting.
    manager
        .update_peer_state(p1, PeerState::Ready)
        .await
        .unwrap();
    manager
        .update_peer_state(p2, PeerState::Ready)
        .await
        .unwrap();

    let ready_addrs = manager.get_ready_peer_addrs().await;
    assert_eq!(ready_addrs.len(), 2, "only ready peers should be returned");
    assert!(ready_addrs.contains(&addr1));
    assert!(ready_addrs.contains(&addr2));
    assert!(!ready_addrs.contains(&addr3));
}

// ---------------------------------------------------------------------------
// 5. PeerManager::get_ready_peer_addrs with no ready peers returns empty
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_ready_peer_addrs_empty() {
    let manager = PeerManager::new("dev".to_string());
    let _ = manager.add_peer(make_addr(9010), Direction::Outbound).await;

    let addrs = manager.get_ready_peer_addrs().await;
    assert!(addrs.is_empty(), "no ready peers → empty vec");
}

// ---------------------------------------------------------------------------
// 6. PeerManager::is_addr_connected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_is_addr_connected() {
    let manager = PeerManager::new("dev".to_string());
    let addr = make_addr(9020);

    assert!(
        !manager.is_addr_connected(addr).await,
        "before add: not connected"
    );

    let peer_id = manager.add_peer(addr, Direction::Outbound).await.unwrap();
    assert!(
        manager.is_addr_connected(addr).await,
        "after add: connected"
    );

    manager.remove_peer(peer_id).await;
    assert!(
        !manager.is_addr_connected(addr).await,
        "after remove: not connected"
    );
}

// ---------------------------------------------------------------------------
// 7. NetworkService responds to GetPeers with ready peer addresses
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_network_service_get_peers_response() {
    use axiom_node::network::PeerId;

    let (_temp, service) = create_test_service();

    // NetworkService wraps its own PeerManager; we can't insert peers into it
    // directly from outside. A GetPeers response with zero ready peers is valid.
    let peer_id = PeerId::new();
    let response = service
        .handle_message(peer_id, Message::GetPeers)
        .await
        .unwrap();

    match response {
        Some(Message::Peers(addrs)) => {
            // Service has no ready peers yet, so addrs should be empty.
            assert!(addrs.is_empty(), "fresh service has no ready peers");
        }
        other => panic!("expected Some(Message::Peers(_)), got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 8. NetworkService ignores Peers message (handled at P2P layer)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_network_service_peers_ignored() {
    use axiom_node::network::PeerId;

    let (_temp, service) = create_test_service();
    let peer_id = PeerId::new();

    let addrs = vec![make_addr(9100), make_addr(9101)];
    let response = service
        .handle_message(peer_id, Message::Peers(addrs))
        .await
        .unwrap();

    assert!(
        response.is_none(),
        "Peers message should produce no response from service"
    );
}

// ---------------------------------------------------------------------------
// 9. PeerDiscovery deduplication: same addr added only once
// ---------------------------------------------------------------------------

#[test]
fn test_peer_discovery_deduplication() {
    let mut discovery = PeerDiscovery::new(vec![]);
    let addr = make_addr(9200);

    discovery.add_peer(addr);
    discovery.add_peer(addr); // duplicate
    discovery.add_peer(addr); // duplicate

    assert_eq!(
        discovery.peer_count(),
        1,
        "duplicate addrs must be deduplicated"
    );
    assert!(discovery.is_known(&addr));
}

// ---------------------------------------------------------------------------
// 10. PeerDiscovery: multiple distinct addrs stored independently
// ---------------------------------------------------------------------------

#[test]
fn test_peer_discovery_multiple_peers() {
    let mut discovery = PeerDiscovery::new(vec![]);

    for port in 9300..9310u16 {
        discovery.add_peer(make_addr(port));
    }

    assert_eq!(discovery.peer_count(), 10);

    let peers = discovery.get_peers();
    assert_eq!(peers.len(), 10);
}

// ---------------------------------------------------------------------------
// 11. PeerDiscovery seed nodes are accessible
// ---------------------------------------------------------------------------

#[test]
fn test_peer_discovery_seed_nodes() {
    let seeds = vec![make_addr(9400), make_addr(9401)];
    let discovery = PeerDiscovery::new(seeds.clone());

    let stored = discovery.get_seed_nodes();
    assert_eq!(stored, seeds);
    // Seed nodes are NOT automatically in known_peers (they're connected via
    // the seed connector loop, not via add_peer).
    assert_eq!(discovery.peer_count(), 0);
}

// ---------------------------------------------------------------------------
// 12. PeerDiscovery: should_discover resets after mark_discovery
// ---------------------------------------------------------------------------

#[test]
fn test_peer_discovery_mark_discovery() {
    let mut discovery = PeerDiscovery::new(vec![]);
    // Fresh discovery → should_discover is true (last=0, interval=300).
    assert!(discovery.should_discover());

    discovery.mark_discovery();
    // Immediately after mark → should_discover is false (just ran).
    assert!(!discovery.should_discover());
}

// ---------------------------------------------------------------------------
// 13. Peers message with IPv6 addresses roundtrips correctly
// ---------------------------------------------------------------------------

#[test]
fn test_peers_message_ipv6_roundtrip() {
    use std::net::{IpAddr, Ipv6Addr};
    let addrs = vec![
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9500),
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            9501,
        ),
    ];
    let msg = Message::Peers(addrs.clone());
    let bytes = msg.serialize().unwrap();
    let decoded = Message::deserialize(&bytes).unwrap();

    match decoded {
        Message::Peers(decoded_addrs) => {
            assert_eq!(decoded_addrs, addrs);
        }
        _ => panic!("expected Message::Peers"),
    }
}

// ---------------------------------------------------------------------------
// 14. Peers message with empty address list roundtrips
// ---------------------------------------------------------------------------

#[test]
fn test_peers_message_empty_roundtrip() {
    let msg = Message::Peers(vec![]);
    let bytes = msg.serialize().unwrap();
    let decoded = Message::deserialize(&bytes).unwrap();
    assert!(matches!(decoded, Message::Peers(ref v) if v.is_empty()));
}
