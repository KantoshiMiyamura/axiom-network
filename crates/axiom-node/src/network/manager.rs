// Copyright (c) 2026 Kantoshi Miyamura

use crate::network::peer::Direction;
use crate::network::{Message, Peer, PeerId, PeerState, ProtocolHandler};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};
use tracing;

pub const MAX_OUTBOUND_PEERS: usize = 16;
pub const MAX_INBOUND_PEERS: usize = 117;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("peer not found: {0:?}")]
    PeerNotFound(PeerId),

    #[error("peer not ready: {0:?}")]
    PeerNotReady(PeerId),

    #[error("transport error: {0}")]
    Transport(#[from] crate::network::transport::TransportError),

    #[error("handshake error: {0}")]
    Handshake(#[from] crate::network::protocol::HandshakeError),

    #[error("send error: {0}")]
    Send(String),

    #[error("peer is banned")]
    Banned,

    #[error("outbound peer limit reached")]
    OutboundLimitReached,

    #[error("subnet peer limit reached (max {0} peers per /24 subnet)")]
    SubnetLimitReached(usize),
}

pub type PeerSender = mpsc::UnboundedSender<Message>;

struct PeerConnection {
    peer: Peer,
    sender: Option<PeerSender>,
}

pub struct PeerManager {
    peers: Arc<RwLock<HashMap<PeerId, PeerConnection>>>,
    protocol: ProtocolHandler,
    banned_peers: Arc<RwLock<HashMap<IpAddr, Instant>>>,
}

impl PeerManager {
    pub fn new(network: String) -> Self {
        PeerManager {
            peers: Arc::new(RwLock::new(HashMap::new())),
            protocol: ProtocolHandler::new(network),
            banned_peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn ban_peer(&self, addr: SocketAddr, duration: Duration) {
        let unban_time = Instant::now() + duration;
        let mut banned = self.banned_peers.write().await;
        banned.insert(addr.ip(), unban_time);
        tracing::info!("banned peer {} for {:?}", addr.ip(), duration);
    }

    pub async fn is_banned(&self, addr: &SocketAddr) -> bool {
        let mut banned = self.banned_peers.write().await;
        let ip = addr.ip();
        if let Some(&unban_time) = banned.get(&ip) {
            if Instant::now() >= unban_time {
                banned.remove(&ip);
                false
            } else {
                true
            }
        } else {
            false
        }
    }

    pub async fn outbound_peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|c| c.peer.direction == Direction::Outbound)
            .count()
    }

    pub async fn add_peer(
        &self,
        addr: SocketAddr,
        direction: Direction,
    ) -> Result<PeerId, NetworkError> {
        if self.is_banned(&addr).await {
            return Err(NetworkError::Banned);
        }

        if direction == Direction::Outbound {
            let outbound = self.outbound_peer_count().await;
            if outbound >= MAX_OUTBOUND_PEERS {
                return Err(NetworkError::OutboundLimitReached);
            }
        }

        // SECURITY: Eclipse-attack mitigation — limit inbound peers per /24 subnet.
        // Without this, an attacker fills all 117 inbound slots from one IP range,
        // partitioning the node from the honest network.
        if direction == Direction::Inbound {
            const MAX_PEERS_PER_SUBNET: usize = 4;
            let peers = self.peers.read().await;
            let subnet = subnet24(addr.ip());
            let peers_in_subnet = peers
                .values()
                .filter(|c| {
                    c.peer.direction == Direction::Inbound && subnet24(c.peer.addr.ip()) == subnet
                })
                .count();
            drop(peers);
            if peers_in_subnet >= MAX_PEERS_PER_SUBNET {
                return Err(NetworkError::SubnetLimitReached(MAX_PEERS_PER_SUBNET));
            }
        }

        let peer = Peer::new(addr, direction);
        let peer_id = peer.id;

        let mut peers = self.peers.write().await;
        peers.insert(peer_id, PeerConnection { peer, sender: None });

        Ok(peer_id)
    }

    pub async fn set_peer_sender(
        &self,
        peer_id: PeerId,
        sender: PeerSender,
    ) -> Result<(), NetworkError> {
        let mut peers = self.peers.write().await;
        let conn = peers
            .get_mut(&peer_id)
            .ok_or(NetworkError::PeerNotFound(peer_id))?;
        conn.sender = Some(sender);
        Ok(())
    }

    pub async fn remove_peer(&self, peer_id: PeerId) {
        let mut peers = self.peers.write().await;
        peers.remove(&peer_id);
    }

    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    pub async fn ready_peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.values().filter(|c| c.peer.is_ready()).count()
    }

    pub async fn get_peer_ids(&self) -> Vec<PeerId> {
        let peers = self.peers.read().await;
        peers.keys().copied().collect()
    }

    pub async fn get_all_peers(&self) -> Vec<PeerId> {
        self.get_peer_ids().await
    }

    pub async fn get_peer(&self, peer_id: PeerId) -> Option<Peer> {
        let peers = self.peers.read().await;
        peers.get(&peer_id).map(|c| c.peer.clone())
    }

    pub async fn update_peer_state(
        &self,
        peer_id: PeerId,
        state: PeerState,
    ) -> Result<(), NetworkError> {
        let mut peers = self.peers.write().await;
        let conn = peers
            .get_mut(&peer_id)
            .ok_or(NetworkError::PeerNotFound(peer_id))?;
        conn.peer.state = state;
        Ok(())
    }

    pub async fn process_handshake(
        &self,
        peer_id: PeerId,
        message: &Message,
    ) -> Result<Option<Message>, NetworkError> {
        let mut peers = self.peers.write().await;
        let conn = peers
            .get_mut(&peer_id)
            .ok_or(NetworkError::PeerNotFound(peer_id))?;

        let response = self.protocol.process_handshake(&mut conn.peer, message)?;
        conn.peer.update_last_seen();

        Ok(response)
    }

    pub fn create_version(&self, best_height: u32) -> Message {
        self.protocol.create_version(best_height)
    }

    pub async fn send_to_peer(
        &self,
        peer_id: PeerId,
        message: Message,
    ) -> Result<(), NetworkError> {
        let peers = self.peers.read().await;
        let conn = peers
            .get(&peer_id)
            .ok_or(NetworkError::PeerNotFound(peer_id))?;

        if !conn.peer.is_ready() {
            return Err(NetworkError::PeerNotReady(peer_id));
        }

        let sender = conn
            .sender
            .as_ref()
            .ok_or_else(|| NetworkError::Send("peer has no sender".to_string()))?;

        sender
            .send(message)
            .map_err(|e| NetworkError::Send(format!("send failed: {}", e)))?;

        Ok(())
    }

    pub async fn broadcast(&self, message: Message) -> Result<usize, NetworkError> {
        let peers = self.peers.read().await;

        if let Message::Block(ref block) = message {
            let block_hash = block.hash();
            let height = block.height().unwrap_or(0);
            let ready_count = peers.values().filter(|c| c.peer.is_ready()).count();
            let total_count = peers.len();
            tracing::info!(
                "BROADCAST_START: hash={}, height={}, ready_peers={}/{}",
                hex::encode(&block_hash.as_bytes()[..8]),
                height,
                ready_count,
                total_count
            );

            for (peer_id, conn) in peers.iter() {
                tracing::debug!(
                    "BROADCAST_PEER_STATE: peer={:?}, state={:?}, has_sender={}",
                    peer_id,
                    conn.peer.state,
                    conn.sender.is_some()
                );
            }
        }

        let mut sent = 0;
        for conn in peers.values() {
            if conn.peer.is_ready() {
                if let Some(sender) = &conn.sender {
                    if sender.send(message.clone()).is_ok() {
                        sent += 1;

                        if let Message::Block(ref block) = message {
                            let block_hash = block.hash();
                            let height = block.height().unwrap_or(0);
                            tracing::info!(
                                "BROADCAST_SENT_TO_PEER: hash={}, height={}, peer={:?}",
                                hex::encode(&block_hash.as_bytes()[..8]),
                                height,
                                conn.peer.id
                            );
                        }
                    } else if let Message::Block(ref block) = message {
                        let block_hash = block.hash();
                        let height = block.height().unwrap_or(0);
                        tracing::warn!(
                            "BROADCAST_CHANNEL_SEND_FAILED: hash={}, height={}, peer={:?}",
                            hex::encode(&block_hash.as_bytes()[..8]),
                            height,
                            conn.peer.id
                        );
                    }
                } else if let Message::Block(ref block) = message {
                    let block_hash = block.hash();
                    let height = block.height().unwrap_or(0);
                    tracing::warn!(
                        "BROADCAST_NO_SENDER: hash={}, height={}, peer={:?}",
                        hex::encode(&block_hash.as_bytes()[..8]),
                        height,
                        conn.peer.id
                    );
                }
            } else if let Message::Block(ref block) = message {
                let block_hash = block.hash();
                let height = block.height().unwrap_or(0);
                tracing::debug!(
                    "BROADCAST_PEER_NOT_READY: hash={}, height={}, peer={:?}, state={:?}",
                    hex::encode(&block_hash.as_bytes()[..8]),
                    height,
                    conn.peer.id,
                    conn.peer.state
                );
            }
        }

        if let Message::Block(ref block) = message {
            let block_hash = block.hash();
            let height = block.height().unwrap_or(0);
            tracing::info!(
                "BROADCAST_COMPLETE: hash={}, height={}, sent={}",
                hex::encode(&block_hash.as_bytes()[..8]),
                height,
                sent
            );
        }

        Ok(sent)
    }

    pub async fn get_ready_peer_addrs(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|c| c.peer.is_ready())
            .map(|c| c.peer.addr)
            .collect()
    }

    pub async fn is_addr_connected(&self, addr: SocketAddr) -> bool {
        let peers = self.peers.read().await;
        peers.values().any(|c| c.peer.addr == addr)
    }

    pub async fn broadcast_except(
        &self,
        exclude_peer: PeerId,
        message: Message,
    ) -> Result<usize, NetworkError> {
        let peers = self.peers.read().await;

        let mut sent = 0;
        for (peer_id, conn) in peers.iter() {
            if *peer_id != exclude_peer && conn.peer.is_ready() {
                if let Some(sender) = &conn.sender {
                    if sender.send(message.clone()).is_ok() {
                        sent += 1;
                    }
                }
            }
        }

        Ok(sent)
    }
}

/// Returns a string key representing the /24 subnet of an IP address.
/// Used for eclipse-attack mitigation: max 4 inbound peers per /24.
fn subnet24(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            // For IPv6 use the first 48 bits (/48 subnet equivalent)
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::", s[0], s[1], s[2])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_peer_manager_add_remove() {
        let manager = PeerManager::new("dev".to_string());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);

        let peer_id = manager.add_peer(addr, Direction::Outbound).await.unwrap();
        assert_eq!(manager.peer_count().await, 1);

        manager.remove_peer(peer_id).await;
        assert_eq!(manager.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_peer_manager_state_update() {
        let manager = PeerManager::new("dev".to_string());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);

        let peer_id = manager.add_peer(addr, Direction::Outbound).await.unwrap();

        manager
            .update_peer_state(peer_id, PeerState::Ready)
            .await
            .unwrap();

        let peer = manager.get_peer(peer_id).await.unwrap();
        assert_eq!(peer.state, PeerState::Ready);
    }

    #[tokio::test]
    async fn test_peer_manager_sender() {
        let manager = PeerManager::new("dev".to_string());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);

        let peer_id = manager.add_peer(addr, Direction::Outbound).await.unwrap();

        let (tx, mut rx) = mpsc::unbounded_channel();
        manager.set_peer_sender(peer_id, tx).await.unwrap();

        manager
            .update_peer_state(peer_id, PeerState::Ready)
            .await
            .unwrap();

        let msg = manager.create_version(0);
        manager.send_to_peer(peer_id, msg.clone()).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert!(matches!(received, Message::Version(_)));
    }

    #[tokio::test]
    async fn test_peer_manager_broadcast() {
        let manager = PeerManager::new("dev".to_string());

        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 8334);
        let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 8335);

        let peer1 = manager.add_peer(addr1, Direction::Outbound).await.unwrap();
        let peer2 = manager.add_peer(addr2, Direction::Outbound).await.unwrap();
        let peer3 = manager.add_peer(addr3, Direction::Outbound).await.unwrap();

        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        let (tx3, mut rx3) = mpsc::unbounded_channel();

        manager.set_peer_sender(peer1, tx1).await.unwrap();
        manager.set_peer_sender(peer2, tx2).await.unwrap();
        manager.set_peer_sender(peer3, tx3).await.unwrap();

        manager
            .update_peer_state(peer1, PeerState::Ready)
            .await
            .unwrap();
        manager
            .update_peer_state(peer2, PeerState::Ready)
            .await
            .unwrap();
        manager
            .update_peer_state(peer3, PeerState::Ready)
            .await
            .unwrap();

        let msg = manager.create_version(0);
        let sent = manager.broadcast(msg).await.unwrap();
        assert_eq!(sent, 3);

        assert!(rx1.recv().await.is_some());
        assert!(rx2.recv().await.is_some());
        assert!(rx3.recv().await.is_some());
    }

    #[tokio::test]
    async fn test_ban_peer_rejects_connection() {
        let manager = PeerManager::new("dev".to_string());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);

        manager.ban_peer(addr, Duration::from_secs(3600)).await;

        let result = manager.add_peer(addr, Direction::Inbound).await;
        assert!(matches!(result, Err(NetworkError::Banned)));
    }

    #[tokio::test]
    async fn test_outbound_limit() {
        let manager = PeerManager::new("dev".to_string());

        for i in 0..MAX_OUTBOUND_PEERS {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, i as u8)), 9000);
            manager.add_peer(addr, Direction::Outbound).await.unwrap();
        }

        let extra = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)), 9000);
        let result = manager.add_peer(extra, Direction::Outbound).await;
        assert!(matches!(result, Err(NetworkError::OutboundLimitReached)));

        let inbound = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)), 9001);
        assert!(manager.add_peer(inbound, Direction::Inbound).await.is_ok());
    }

    #[tokio::test]
    async fn test_is_banned_expires() {
        let manager = PeerManager::new("dev".to_string());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9000);

        manager.ban_peer(addr, Duration::from_secs(0)).await;

        assert!(!manager.is_banned(&addr).await);
    }
}
