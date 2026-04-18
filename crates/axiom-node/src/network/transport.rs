// Copyright (c) 2026 Kantoshi Miyamura

use crate::network::message::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing;

/// Maximum time to wait for a single message read (header + payload).
/// Prevents slow-loris attacks where an attacker sends 1 byte/sec to hold
/// a peer slot indefinitely, causing memory and connection exhaustion.
const MESSAGE_READ_TIMEOUT: Duration = Duration::from_secs(60);

pub const MAX_P2P_MESSAGE_SIZE: usize = 4_000_000;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("message error: {0}")]
    Message(#[from] crate::network::message::MessageError),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: usize, max: usize },
}

pub struct Connection {
    reader: Arc<Mutex<ReadHalf<TcpStream>>>,
    writer: Arc<Mutex<WriteHalf<TcpStream>>>,
    addr: SocketAddr,
}

impl Connection {
    pub fn new(stream: TcpStream, addr: SocketAddr) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Connection {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            addr,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn clone_writer(&self) -> ConnectionWriter {
        ConnectionWriter {
            writer: self.writer.clone(),
        }
    }

    pub async fn send(&mut self, message: &Message) -> Result<(), TransportError> {
        let bytes = message.serialize()?;
        let msg_size = bytes.len();

        if let Message::Block(ref block) = message {
            let block_hash = block.hash();
            let height = block.height().unwrap_or(0);
            tracing::info!(
                "TRANSPORT_BLOCK_SERIALIZE: hash={}, height={}, size={}",
                hex::encode(&block_hash.as_bytes()[..8]),
                height,
                msg_size
            );
        }

        let mut writer = self.writer.lock().await;
        writer.write_all(&bytes).await?;
        writer.flush().await?;

        if let Message::Block(ref block) = message {
            let block_hash = block.hash();
            let height = block.height().unwrap_or(0);
            tracing::info!(
                "TRANSPORT_BLOCK_WRITTEN: hash={}, height={}, size={}",
                hex::encode(&block_hash.as_bytes()[..8]),
                height,
                msg_size
            );
        }

        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Message, TransportError> {
        let mut reader = self.reader.lock().await;

        // SECURITY: Wrap entire read in a timeout to prevent slow-loris DoS.
        // An attacker who sends 1 byte/sec can hold a peer slot for hours without this.
        let read_result = tokio::time::timeout(MESSAGE_READ_TIMEOUT, async {
            let mut header = [0u8; 5];
            reader.read_exact(&mut header).await?;
            Ok::<[u8; 5], std::io::Error>(header)
        })
        .await
        .map_err(|_| TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "message header read timed out",
        )))??;

        let header = read_result;
        let msg_type = header[0];
        let length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;

        tracing::debug!(
            "TRANSPORT_HEADER_READ: type={}, length={}",
            msg_type,
            length
        );

        if length > MAX_P2P_MESSAGE_SIZE {
            return Err(TransportError::MessageTooLarge {
                size: length,
                max: MAX_P2P_MESSAGE_SIZE,
            });
        }

        if length > crate::network::message::MAX_MESSAGE_SIZE {
            return Err(TransportError::Message(
                crate::network::message::MessageError::MessageTooLarge(length),
            ));
        }

        let mut payload = vec![0u8; length];
        tokio::time::timeout(MESSAGE_READ_TIMEOUT, reader.read_exact(&mut payload))
            .await
            .map_err(|_| TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "message payload read timed out",
            )))??;

        let mut full_message = header.to_vec();
        full_message.extend_from_slice(&payload);

        let message = Message::deserialize(&full_message)?;

        if let Message::Block(ref block) = message {
            let block_hash = block.hash();
            let height = block.height().unwrap_or(0);
            tracing::info!(
                "TRANSPORT_BLOCK_RECEIVED: hash={}, height={}, size={}",
                hex::encode(&block_hash.as_bytes()[..8]),
                height,
                full_message.len()
            );
        }

        Ok(message)
    }
}

pub struct ConnectionWriter {
    writer: Arc<Mutex<WriteHalf<TcpStream>>>,
}

impl ConnectionWriter {
    pub async fn send(&self, message: &Message) -> Result<(), TransportError> {
        let bytes = message.serialize()?;

        if let Message::Block(ref block) = message {
            let block_hash = block.hash();
            let height = block.height().unwrap_or(0);
            tracing::info!(
                "CONNWRITER_BLOCK_SERIALIZE: hash={}, height={}, size={}",
                hex::encode(&block_hash.as_bytes()[..8]),
                height,
                bytes.len()
            );
        }

        let mut writer = self.writer.lock().await;
        writer.write_all(&bytes).await?;
        writer.flush().await?;

        if let Message::Block(ref block) = message {
            let block_hash = block.hash();
            let height = block.height().unwrap_or(0);
            tracing::info!(
                "CONNWRITER_BLOCK_WRITTEN: hash={}, height={}, size={}",
                hex::encode(&block_hash.as_bytes()[..8]),
                height,
                bytes.len()
            );
        }

        Ok(())
    }
}

pub struct Transport {
    listener: Option<TcpListener>,
}

impl Default for Transport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport {
    pub fn new() -> Self {
        Transport { listener: None }
    }

    pub async fn bind(&mut self, addr: SocketAddr) -> Result<(), TransportError> {
        let listener = TcpListener::bind(addr).await?;
        self.listener = Some(listener);
        Ok(())
    }

    pub async fn accept(&mut self) -> Result<Connection, TransportError> {
        let listener = self.listener.as_mut().ok_or_else(|| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "listener not bound",
            ))
        })?;

        let (stream, addr) = listener.accept().await?;
        Ok(Connection::new(stream, addr))
    }

    pub async fn connect(addr: SocketAddr) -> Result<Connection, TransportError> {
        let stream = TcpStream::connect(addr).await?;
        let peer_addr = stream.peer_addr()?;
        Ok(Connection::new(stream, peer_addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::encryption::MAX_ENCRYPTED_FRAME_SIZE;

    #[test]
    fn test_max_p2p_message_size_constant() {
        assert_eq!(MAX_P2P_MESSAGE_SIZE, 4_000_000);
    }

    #[test]
    fn test_max_encrypted_frame_size_is_larger_than_message() {
        assert!(MAX_ENCRYPTED_FRAME_SIZE > MAX_P2P_MESSAGE_SIZE);
    }
}
