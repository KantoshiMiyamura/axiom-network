// Copyright (c) 2026 Kantoshi Miyamura

use axiom_primitives::Hash256;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(u64);

impl Default for PeerId {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerId {
    pub fn new() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        PeerId(timestamp)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Connecting,
    VersionReceived,
    Ready,
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub id: PeerId,
    pub addr: SocketAddr,
    pub direction: Direction,
    pub state: PeerState,
    pub protocol_version: Option<u32>,
    pub network: Option<String>,
    pub best_height: Option<u32>,
    pub best_hash: Option<Hash256>,
    pub connected_at: u64,
    pub last_seen: u64,
}

impl Peer {
    pub fn new(addr: SocketAddr, direction: Direction) -> Self {
        let now = current_timestamp();
        Peer {
            id: PeerId::new(),
            addr,
            direction,
            state: PeerState::Connecting,
            protocol_version: None,
            network: None,
            best_height: None,
            best_hash: None,
            connected_at: now,
            last_seen: now,
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = current_timestamp();
    }

    pub fn is_ready(&self) -> bool {
        self.state == PeerState::Ready
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_peer_creation() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
        let peer = Peer::new(addr, Direction::Outbound);

        assert_eq!(peer.addr, addr);
        assert_eq!(peer.direction, Direction::Outbound);
        assert_eq!(peer.state, PeerState::Connecting);
        assert!(!peer.is_ready());
    }

    #[test]
    fn test_peer_state_transitions() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
        let mut peer = Peer::new(addr, Direction::Inbound);

        assert_eq!(peer.state, PeerState::Connecting);

        peer.state = PeerState::VersionReceived;
        assert_eq!(peer.state, PeerState::VersionReceived);

        peer.state = PeerState::Ready;
        assert!(peer.is_ready());
    }
}
