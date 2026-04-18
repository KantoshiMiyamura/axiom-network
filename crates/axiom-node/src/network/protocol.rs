// Copyright (c) 2026 Kantoshi Miyamura

use crate::network::{Message, Peer, PeerState, VersionMessage};
use thiserror::Error;

pub const PROTOCOL_VERSION: u32 = 1;

#[allow(dead_code)]
pub const HANDSHAKE_TIMEOUT: u64 = 30;

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u32, actual: u32 },

    #[error("network mismatch: expected {expected}, got {actual}")]
    NetworkMismatch { expected: String, actual: String },

    #[error("handshake timeout")]
    Timeout,

    #[error("invalid handshake state")]
    InvalidState,
}

pub struct ProtocolHandler {
    network: String,
}

impl ProtocolHandler {
    pub fn new(network: String) -> Self {
        ProtocolHandler { network }
    }

    pub fn create_version(&self, best_height: u32) -> Message {
        Message::Version(VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            network: self.network.clone(),
            best_height,
            ..Default::default()
        })
    }

    pub fn validate_version(&self, version: &VersionMessage) -> Result<(), HandshakeError> {
        if version.protocol_version != PROTOCOL_VERSION {
            return Err(HandshakeError::VersionMismatch {
                expected: PROTOCOL_VERSION,
                actual: version.protocol_version,
            });
        }

        if version.network != self.network {
            return Err(HandshakeError::NetworkMismatch {
                expected: self.network.clone(),
                actual: version.network.clone(),
            });
        }

        Ok(())
    }

    pub fn process_handshake(
        &self,
        peer: &mut Peer,
        message: &Message,
    ) -> Result<Option<Message>, HandshakeError> {
        match (peer.state, message) {
            (PeerState::Connecting, Message::Version(v)) => {
                self.validate_version(v)?;
                peer.protocol_version = Some(v.protocol_version);
                peer.network = Some(v.network.clone());
                peer.best_height = Some(v.best_height);
                peer.state = PeerState::VersionReceived;
                Ok(Some(Message::VerAck))
            }
            (PeerState::VersionReceived, Message::VerAck) => {
                peer.state = PeerState::Ready;
                Ok(None)
            }
            _ => Err(HandshakeError::InvalidState),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::peer::Direction;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_version_validation_success() {
        let handler = ProtocolHandler::new("dev".to_string());
        let version = VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            network: "dev".to_string(),
            best_height: 100,
            ..Default::default()
        };

        assert!(handler.validate_version(&version).is_ok());
    }

    #[test]
    fn test_version_mismatch() {
        let handler = ProtocolHandler::new("dev".to_string());
        let version = VersionMessage {
            protocol_version: 999,
            network: "dev".to_string(),
            best_height: 100,
            ..Default::default()
        };

        let result = handler.validate_version(&version);
        assert!(matches!(
            result,
            Err(HandshakeError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn test_network_mismatch() {
        let handler = ProtocolHandler::new("dev".to_string());
        let version = VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            network: "test".to_string(),
            best_height: 100,
            ..Default::default()
        };

        let result = handler.validate_version(&version);
        assert!(matches!(
            result,
            Err(HandshakeError::NetworkMismatch { .. })
        ));
    }

    #[test]
    fn test_handshake_flow() {
        let handler = ProtocolHandler::new("dev".to_string());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
        let mut peer = Peer::new(addr, Direction::Inbound);

        // Receive version
        let version = Message::Version(VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            network: "dev".to_string(),
            best_height: 100,
            ..Default::default()
        });

        let response = handler.process_handshake(&mut peer, &version).unwrap();
        assert!(matches!(response, Some(Message::VerAck)));
        assert_eq!(peer.state, PeerState::VersionReceived);

        // Receive verack
        let verack = Message::VerAck;
        let response = handler.process_handshake(&mut peer, &verack).unwrap();
        assert!(response.is_none());
        assert_eq!(peer.state, PeerState::Ready);
    }
}
