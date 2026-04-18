// Copyright (c) 2026 Kantoshi Miyamura

//! X25519 key exchange + ChaCha20-Poly1305 transport encryption.

use super::message::Message;
use super::transport::TransportError;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

const HKDF_INFO: &[u8] = b"axiom-p2p-v1";

// Wire frame: [u32 LE length][12-byte nonce][ciphertext + 16-byte AEAD tag]
pub const MAX_ENCRYPTED_FRAME_SIZE: usize = 4_000_016;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("AEAD error (decrypt failed — possible tampering or wrong key)")]
    AeadError,

    #[error("key derivation error")]
    Kdf,

    #[error("invalid public key length")]
    InvalidPublicKey,

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("encrypted frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: usize, max: usize },
}

/// Encrypted transport: X25519 key exchange + ChaCha20-Poly1305 per-frame encryption.
pub struct EncryptedConnection {
    reader: Arc<Mutex<ReadHalf<TcpStream>>>,
    writer: Arc<Mutex<WriteHalf<TcpStream>>>,
    addr: SocketAddr,
    cipher: ChaCha20Poly1305,
    send_nonce: u64,
    recv_nonce: u64,
}

impl EncryptedConnection {
    fn derive_key(shared_secret: &[u8; 32]) -> Result<ChaCha20Poly1305, EncryptionError> {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);
        let mut okm = [0u8; 32];
        hk.expand(HKDF_INFO, &mut okm)
            .map_err(|_| EncryptionError::Kdf)?;
        Ok(ChaCha20Poly1305::new((&okm).into()))
    }

    fn make_nonce(counter: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        Nonce::from(nonce_bytes)
    }

    /// Initiator side of the X25519 handshake.
    pub async fn negotiate_initiator(
        reader: Arc<Mutex<ReadHalf<TcpStream>>>,
        writer: Arc<Mutex<WriteHalf<TcpStream>>>,
        addr: SocketAddr,
    ) -> Result<Self, EncryptionError> {
        let secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let our_public = X25519PublicKey::from(&secret);

        {
            let mut w = writer.lock().await;
            w.write_all(our_public.as_bytes()).await?;
            w.flush().await?;
        }

        let peer_pub_bytes: [u8; 32] = {
            let mut buf = [0u8; 32];
            let mut r = reader.lock().await;
            r.read_exact(&mut buf).await?;
            buf
        };
        let peer_public = X25519PublicKey::from(peer_pub_bytes);

        let shared = secret.diffie_hellman(&peer_public);
        let cipher = Self::derive_key(shared.as_bytes())?;

        tracing::debug!("ENCRYPT: initiator handshake complete with {}", addr);

        Ok(Self {
            reader,
            writer,
            addr,
            cipher,
            send_nonce: 0,
            recv_nonce: 0,
        })
    }

    /// Responder side of the X25519 handshake.
    pub async fn negotiate_responder(
        reader: Arc<Mutex<ReadHalf<TcpStream>>>,
        writer: Arc<Mutex<WriteHalf<TcpStream>>>,
        addr: SocketAddr,
    ) -> Result<Self, EncryptionError> {
        let peer_pub_bytes: [u8; 32] = {
            let mut buf = [0u8; 32];
            let mut r = reader.lock().await;
            r.read_exact(&mut buf).await?;
            buf
        };
        let peer_public = X25519PublicKey::from(peer_pub_bytes);

        let secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let our_public = X25519PublicKey::from(&secret);
        {
            let mut w = writer.lock().await;
            w.write_all(our_public.as_bytes()).await?;
            w.flush().await?;
        }

        let shared = secret.diffie_hellman(&peer_public);
        let cipher = Self::derive_key(shared.as_bytes())?;

        tracing::debug!("ENCRYPT: responder handshake complete with {}", addr);

        Ok(Self {
            reader,
            writer,
            addr,
            cipher,
            send_nonce: 0,
            recv_nonce: 0,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn send(&mut self, msg: &Message) -> Result<(), EncryptionError> {
        let plaintext = msg
            .serialize()
            .map_err(|e| EncryptionError::Transport(TransportError::Message(e)))?;

        let nonce = Self::make_nonce(self.send_nonce);
        self.send_nonce = self.send_nonce.wrapping_add(1);

        let mut buffer = plaintext;
        self.cipher
            .encrypt_in_place(&nonce, b"", &mut buffer)
            .map_err(|_| EncryptionError::AeadError)?;

        let mut frame = Vec::with_capacity(12 + buffer.len());
        frame.extend_from_slice(nonce.as_slice());
        frame.extend_from_slice(&buffer);

        let frame_len = frame.len() as u32;

        let mut w = self.writer.lock().await;
        w.write_all(&frame_len.to_le_bytes()).await?;
        w.write_all(&frame).await?;
        w.flush().await?;

        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Message, EncryptionError> {
        let mut r = self.reader.lock().await;

        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf).await?;
        let frame_len = u32::from_le_bytes(len_buf) as usize;

        if frame_len > MAX_ENCRYPTED_FRAME_SIZE {
            return Err(EncryptionError::FrameTooLarge {
                size: frame_len,
                max: MAX_ENCRYPTED_FRAME_SIZE,
            });
        }

        if frame_len < 29 {
            return Err(EncryptionError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("encrypted frame length too small: {}", frame_len),
            )));
        }

        let mut frame = vec![0u8; frame_len];
        r.read_exact(&mut frame).await?;

        drop(r);

        if frame.len() < 12 {
            return Err(EncryptionError::InvalidPublicKey);
        }
        let nonce = *Nonce::from_slice(&frame[..12]);

        let expected_nonce = Self::make_nonce(self.recv_nonce);
        if nonce != expected_nonce {
            tracing::warn!(
                "ENCRYPT: nonce mismatch from {}: expected counter {}, frame nonce != expected",
                self.addr,
                self.recv_nonce
            );
            return Err(EncryptionError::AeadError);
        }
        self.recv_nonce = self.recv_nonce.wrapping_add(1);

        let mut ciphertext = frame[12..].to_vec();
        self.cipher
            .decrypt_in_place(&nonce, b"", &mut ciphertext)
            .map_err(|_| EncryptionError::AeadError)?;

        let message = Message::deserialize(&ciphertext)
            .map_err(|e| EncryptionError::Transport(TransportError::Message(e)))?;

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_construction() {
        let n = EncryptedConnection::make_nonce(0);
        assert_eq!(n.as_slice(), &[0u8; 12]);

        let n1 = EncryptedConnection::make_nonce(1);
        let mut expected = [0u8; 12];
        expected[4..12].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(n1.as_slice(), &expected);

        let large = EncryptedConnection::make_nonce(u64::MAX);
        let mut expected_large = [0u8; 12];
        expected_large[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(large.as_slice(), &expected_large);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let secret_bytes = [0xABu8; 32];
        let cipher1 = EncryptedConnection::derive_key(&secret_bytes).unwrap();
        let cipher2 = EncryptedConnection::derive_key(&secret_bytes).unwrap();

        let plaintext = b"axiom-p2p-encryption-test".to_vec();
        let nonce = EncryptedConnection::make_nonce(42);

        let mut buf1 = plaintext.clone();
        cipher1.encrypt_in_place(&nonce, b"", &mut buf1).unwrap();

        let mut buf2 = plaintext.clone();
        cipher2.encrypt_in_place(&nonce, b"", &mut buf2).unwrap();

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secret_bytes = [0x42u8; 32];
        let cipher1 = EncryptedConnection::derive_key(&secret_bytes).unwrap();
        let cipher2 = EncryptedConnection::derive_key(&secret_bytes).unwrap();

        let plaintext = b"hello axiom network".to_vec();
        let nonce = EncryptedConnection::make_nonce(0);

        let mut encrypted = plaintext.clone();
        cipher1
            .encrypt_in_place(&nonce, b"", &mut encrypted)
            .unwrap();
        assert_ne!(encrypted, plaintext);

        let mut decrypted = encrypted;
        cipher2
            .decrypt_in_place(&nonce, b"", &mut decrypted)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let secret_bytes = [0x99u8; 32];
        let cipher = EncryptedConnection::derive_key(&secret_bytes).unwrap();

        let plaintext = b"tamper test".to_vec();
        let nonce = EncryptedConnection::make_nonce(0);

        let mut encrypted = plaintext.clone();
        cipher
            .encrypt_in_place(&nonce, b"", &mut encrypted)
            .unwrap();

        if let Some(byte) = encrypted.first_mut() {
            *byte ^= 0xFF;
        }

        let cipher2 = EncryptedConnection::derive_key(&secret_bytes).unwrap();
        let result = cipher2.decrypt_in_place(&nonce, b"", &mut encrypted);
        assert!(result.is_err(), "tampered ciphertext must fail decryption");
    }
}
