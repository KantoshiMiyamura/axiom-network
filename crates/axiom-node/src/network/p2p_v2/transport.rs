// Copyright (c) 2026 Kantoshi Miyamura

//! v2 encrypted transport. Spec: `V2_PROTOCOL.md §4.4`.
//!
//! Stage 4 of `V2_PROTOCOL.md §8`. Wraps an async byte stream with an
//! authenticated, sequence-numbered AEAD frame layer keyed by
//! [`super::session::SessionKeys`]. **Not yet wired into the runtime** —
//! `service.rs`, `manager.rs`, and `transport.rs` continue to use the v1
//! [`super::super::encryption::EncryptedConnection`]. This module exists
//! so the v2 transport can be exercised end-to-end without the listener.
//!
//! ## Wire frame
//!
//! ```text
//!   [u32 LE  frame_body_len]
//!   [u64 LE  sequence_number]
//!   [N      ciphertext]
//!   [16     AEAD authentication tag]
//! ```
//!
//! `frame_body_len = 8 + ciphertext_len + 16` (excludes the 4-byte length
//! prefix). The receiver length-bounds-checks before allocating the read
//! buffer to keep a malicious peer from prompting a multi-gigabyte
//! `Vec::with_capacity` purely from the wire.
//!
//! The AEAD nonce is **derived** from the on-wire sequence number, not
//! sent twice:
//!
//! ```text
//!   nonce[0..8]  = sequence_number (LE)
//!   nonce[8..24] = 0
//! ```
//!
//! Each direction has its own 32-byte ChaCha20-Poly1305 key (`tx_key`,
//! `rx_key`), produced by the v2 handshake. Different keys per direction
//! mean the (key, nonce) pair is unique per encrypted message even though
//! both sides start their sequence counters at 0.
//!
//! ## Replay / ordering policy
//!
//! Strict-monotonic: a frame with `seq != expected_recv_seq` is an error.
//! TCP guarantees in-order delivery so the only way an out-of-order frame
//! can land is an active attacker reordering bytes — exactly the case we
//! want to refuse. The error is fatal; the caller drops the connection.
//!
//! ## Failure handling
//!
//! Every error from this module is fatal to the connection by design:
//!
//! - decryption failure (tampered ciphertext, wrong tag, wrong key) →
//!   [`TransportV2Error::AeadFailure`]
//! - bad sequence number (replay / reorder) →
//!   [`TransportV2Error::ReplayOrReorder`]
//! - frame larger than [`MAX_FRAME_BODY_BYTES`] →
//!   [`TransportV2Error::FrameTooLarge`]
//! - truncated I/O → [`TransportV2Error::Io`]
//!
//! The caller (transport accept loop, when wired in stage 4 → 5) receives
//! the error, scores down or banlists the peer, and closes the socket.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::session::SessionKeys;

/// Maximum plaintext + ciphertext + tag + seq carried in a single v2 frame
/// body (excludes the 4-byte length prefix). 4 MB matches the v1 cap so v2
/// does not regress the maximum block-relay size.
pub const MAX_FRAME_BODY_BYTES: usize = 4_000_024;

/// AEAD authentication tag length for ChaCha20-Poly1305 (Poly1305 output).
pub const TAG_BYTES: usize = 16;

/// On-wire sequence-number field width.
pub const SEQ_BYTES: usize = 8;

/// XChaCha20-Poly1305 nonce length.
pub const NONCE_BYTES: usize = 24;

/// Per-direction symmetric keys for the AEAD transport. ChaCha20-Poly1305
/// keys are 32 bytes; nonces are framed per-message in the transport
/// layer (see `V2_PROTOCOL.md §4.4`).
#[derive(Error, Debug)]
pub enum TransportV2Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame body too large: {actual} bytes (max {})", MAX_FRAME_BODY_BYTES)]
    FrameTooLarge { actual: usize },

    #[error(
        "frame body too small: {actual} bytes (need at least {})",
        SEQ_BYTES + TAG_BYTES
    )]
    FrameTooSmall { actual: usize },

    #[error("replay or reorder: got seq {got}, expected {expected}")]
    ReplayOrReorder { got: u64, expected: u64 },

    #[error("AEAD authentication failed (tampered ciphertext or wrong key)")]
    AeadFailure,

    #[error("send sequence counter overflow — rotate session keys")]
    SendSequenceOverflow,
}

/// Authenticated, sequence-numbered AEAD wrapper around an async byte stream.
///
/// The connection is single-threaded with respect to send and receive —
/// the caller is expected to either sequence operations or wrap the
/// connection in their own concurrency primitive. This is intentional:
/// the v1 transport's interior `Mutex<ReadHalf>` / `Mutex<WriteHalf>`
/// pattern conflates "transport layer" and "concurrency control"; the v2
/// transport does one thing.
pub struct EncryptedConnectionV2<S> {
    stream: S,
    tx_cipher: XChaCha20Poly1305,
    rx_cipher: XChaCha20Poly1305,
    /// Next sequence number we will use when sending a frame.
    send_seq: u64,
    /// Next sequence number we expect to receive.
    recv_seq: u64,
}

impl<S> EncryptedConnectionV2<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Wrap `stream` with the supplied directional session keys. The keys
    /// are consumed — they cannot be reused for a second connection
    /// without rerunning the handshake. (This mirrors the lifecycle of
    /// `super::session::SessionKeys`, which wipes its key bytes on Drop.)
    pub fn new(stream: S, keys: SessionKeys) -> Self {
        let tx_cipher = XChaCha20Poly1305::new((&keys.tx_key).into());
        let rx_cipher = XChaCha20Poly1305::new((&keys.rx_key).into());
        // Drop `keys` here: tx_cipher and rx_cipher hold the only live
        // copies of the key bytes from this point forward, and `keys` is
        // wiped by its Drop impl as it leaves scope.
        drop(keys);
        EncryptedConnectionV2 {
            stream,
            tx_cipher,
            rx_cipher,
            send_seq: 0,
            recv_seq: 0,
        }
    }

    /// Encrypt + frame `plaintext` and write it to the stream. The plaintext
    /// is consumed in-place — it is overwritten with ciphertext during AEAD,
    /// then framed and sent. After this call there is no in-memory copy of
    /// the plaintext outside the caller's original buffer.
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), TransportV2Error> {
        if plaintext.len() + SEQ_BYTES + TAG_BYTES > MAX_FRAME_BODY_BYTES {
            return Err(TransportV2Error::FrameTooLarge {
                actual: plaintext.len() + SEQ_BYTES + TAG_BYTES,
            });
        }

        let seq = self.send_seq;
        // The seq counter is u64; once it tops out, the (key, nonce) pair
        // becomes unsafe to reuse. The caller must rotate keys before
        // hitting this. At one frame per microsecond u64 overflow takes
        // ~585,000 years — still, surface it explicitly so the transport
        // never silently wraps.
        self.send_seq = self
            .send_seq
            .checked_add(1)
            .ok_or(TransportV2Error::SendSequenceOverflow)?;

        let nonce = make_nonce(seq);

        // Encrypt in place into a fresh buffer (we cannot mutate the
        // caller's slice — it is borrowed read-only). The buffer holds
        // the ciphertext, then the tag is appended.
        let mut buf = Vec::with_capacity(plaintext.len() + TAG_BYTES);
        buf.extend_from_slice(plaintext);
        self.tx_cipher
            .encrypt_in_place(&nonce, b"", &mut buf)
            .map_err(|_| TransportV2Error::AeadFailure)?;

        // Frame body = seq (8 B) || ciphertext+tag.
        let body_len = SEQ_BYTES + buf.len();
        debug_assert!(body_len <= MAX_FRAME_BODY_BYTES);

        let mut frame = Vec::with_capacity(4 + body_len);
        frame.extend_from_slice(&(body_len as u32).to_le_bytes());
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.extend_from_slice(&buf);

        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// Read one framed message from the stream and return its plaintext.
    /// Any error from this function is fatal — the caller MUST close the
    /// connection.
    pub async fn recv(&mut self) -> Result<Vec<u8>, TransportV2Error> {
        // Length prefix.
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let body_len = u32::from_le_bytes(len_buf) as usize;

        if body_len > MAX_FRAME_BODY_BYTES {
            return Err(TransportV2Error::FrameTooLarge { actual: body_len });
        }
        if body_len < SEQ_BYTES + TAG_BYTES {
            return Err(TransportV2Error::FrameTooSmall { actual: body_len });
        }

        let mut body = vec![0u8; body_len];
        self.stream.read_exact(&mut body).await?;

        // seq.
        let mut seq_bytes = [0u8; SEQ_BYTES];
        seq_bytes.copy_from_slice(&body[..SEQ_BYTES]);
        let seq = u64::from_le_bytes(seq_bytes);

        if seq != self.recv_seq {
            return Err(TransportV2Error::ReplayOrReorder {
                got: seq,
                expected: self.recv_seq,
            });
        }
        // Note: we don't increment recv_seq until after the AEAD verifies.
        // Otherwise a tampered frame would advance our counter and skip a
        // legitimate retransmit (TCP would not retransmit, but if the v2
        // transport is ever ported to QUIC/UDP this matters).

        // ciphertext || tag.
        let mut ct = body[SEQ_BYTES..].to_vec();

        let nonce = make_nonce(seq);
        self.rx_cipher
            .decrypt_in_place(&nonce, b"", &mut ct)
            .map_err(|_| TransportV2Error::AeadFailure)?;

        self.recv_seq = self
            .recv_seq
            .checked_add(1)
            .ok_or(TransportV2Error::SendSequenceOverflow)?;

        Ok(ct)
    }

    /// Number of frames sent on this connection so far. Useful in tests
    /// and in any rate-limit telemetry.
    pub fn send_seq(&self) -> u64 {
        self.send_seq
    }

    /// Number of frames received on this connection so far.
    pub fn recv_seq(&self) -> u64 {
        self.recv_seq
    }
}

// ── Internal helpers ────────────────────────────────────────────────────────

fn make_nonce(seq: u64) -> XNonce {
    // XChaCha20-Poly1305 takes a 24-byte nonce. We dedicate the first 8
    // bytes to the LE-encoded sequence number and zero-fill the rest. The
    // direction tag is implicit in the *key* (each direction has its own
    // HKDF-derived ChaCha key), so we don't need to encode the role into
    // the nonce.
    let mut bytes = [0u8; NONCE_BYTES];
    bytes[..SEQ_BYTES].copy_from_slice(&seq.to_le_bytes());
    *XNonce::from_slice(&bytes)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn pair_keys() -> (SessionKeys, SessionKeys) {
        // Two SessionKeys with mirrored tx/rx, exactly what the v2
        // handshake produces for the two peers.
        let init_tx = [0x11u8; 32];
        let resp_tx = [0x22u8; 32];
        let init = SessionKeys {
            tx_key: init_tx,
            rx_key: resp_tx,
        };
        let resp = SessionKeys {
            tx_key: resp_tx,
            rx_key: init_tx,
        };
        (init, resp)
    }

    /// Round-trip: a message sent on one side decrypts cleanly on the other.
    #[tokio::test]
    async fn roundtrip_one_message() {
        let (a, b) = duplex(64 * 1024);
        let (init_keys, resp_keys) = pair_keys();
        let mut alice = EncryptedConnectionV2::new(a, init_keys);
        let mut bob = EncryptedConnectionV2::new(b, resp_keys);

        let payload = b"hello, post-quantum world".to_vec();
        alice.send(&payload).await.expect("send");
        let received = bob.recv().await.expect("recv");
        assert_eq!(received, payload);
        assert_eq!(alice.send_seq(), 1);
        assert_eq!(bob.recv_seq(), 1);
    }

    /// Many sequential messages all decrypt with strictly increasing seq.
    #[tokio::test]
    async fn roundtrip_many_messages_in_order() {
        let (a, b) = duplex(1024 * 1024);
        let (init_keys, resp_keys) = pair_keys();
        let mut alice = EncryptedConnectionV2::new(a, init_keys);
        let mut bob = EncryptedConnectionV2::new(b, resp_keys);

        for i in 0u32..32 {
            let payload = format!("msg #{i}").into_bytes();
            alice.send(&payload).await.expect("send");
        }
        for i in 0u32..32 {
            let r = bob.recv().await.expect("recv");
            assert_eq!(r, format!("msg #{i}").into_bytes());
        }
        assert_eq!(alice.send_seq(), 32);
        assert_eq!(bob.recv_seq(), 32);
    }

    /// Two-way concurrent: both sides send and receive cleanly. Needs
    /// independent send/recv halves which we get by using two duplex
    /// pipes.
    #[tokio::test]
    async fn bidirectional_traffic() {
        let (a, b) = duplex(64 * 1024);
        let (init_keys, resp_keys) = pair_keys();
        let mut alice = EncryptedConnectionV2::new(a, init_keys);
        let mut bob = EncryptedConnectionV2::new(b, resp_keys);

        alice.send(b"alice -> bob").await.expect("send 1");
        let r1 = bob.recv().await.expect("recv 1");
        assert_eq!(r1, b"alice -> bob".to_vec());

        bob.send(b"bob -> alice").await.expect("send 2");
        let r2 = alice.recv().await.expect("recv 2");
        assert_eq!(r2, b"bob -> alice".to_vec());
    }

    /// A peer with the wrong rx_key cannot decrypt — AEAD fails.
    #[tokio::test]
    async fn wrong_key_aead_fails() {
        let (a, b) = duplex(64 * 1024);
        let init_keys = SessionKeys {
            tx_key: [0x33u8; 32],
            rx_key: [0x44u8; 32],
        };
        // Bob has a *different* rx_key — does not match alice's tx_key.
        let bob_keys = SessionKeys {
            tx_key: [0x44u8; 32],
            rx_key: [0xAAu8; 32], // wrong: should be 0x33
        };
        let mut alice = EncryptedConnectionV2::new(a, init_keys);
        let mut bob = EncryptedConnectionV2::new(b, bob_keys);

        alice.send(b"secret").await.expect("send");
        let r = bob.recv().await;
        assert!(matches!(r, Err(TransportV2Error::AeadFailure)));
    }

    /// Tampering a single byte of the ciphertext invalidates the tag.
    /// Achieved by routing the bytes through a buffer we control rather
    /// than through duplex.
    #[tokio::test]
    async fn tampered_ciphertext_aead_fails() {
        let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);

        // Sender: encrypt and write into our intermediate buffer.
        let (alice_keys, _bob_keys) = pair_keys();
        let mut alice =
            EncryptedConnectionV2::new(&mut writer as &mut tokio::io::DuplexStream, alice_keys);
        alice.send(b"important payload").await.expect("send");
        drop(alice);

        // Read everything alice produced.
        let mut buf = vec![0u8; 4096];
        let n = reader.read(&mut buf).await.expect("read");
        let mut frame = buf[..n].to_vec();

        // Locate the ciphertext-or-tag region (after 4-byte length + 8 byte seq).
        let payload_start = 4 + 8;
        assert!(frame.len() > payload_start + 1);
        // Flip a bit in the middle of the ciphertext+tag region.
        let target = payload_start + (frame.len() - payload_start) / 2;
        frame[target] ^= 0x55;

        // Now feed the tampered frame to a fresh receiver.
        let (mut sender_for_bob, receiver_for_bob) = tokio::io::duplex(8192);
        sender_for_bob
            .write_all(&frame)
            .await
            .expect("write tampered");
        sender_for_bob.flush().await.expect("flush");
        drop(sender_for_bob);

        let bob_keys = SessionKeys {
            tx_key: [0x22u8; 32],
            rx_key: [0x11u8; 32],
        };
        let mut bob = EncryptedConnectionV2::new(receiver_for_bob, bob_keys);
        let r = bob.recv().await;
        assert!(matches!(r, Err(TransportV2Error::AeadFailure)));
    }

    /// Replaying a captured frame fails the strict-ordering check.
    /// We capture the bytes alice writes for one message, then write them
    /// twice into the receiver — the second copy must be rejected as
    /// replay.
    #[tokio::test]
    async fn replay_rejected_by_seq_window() {
        // Build a frame externally so we can write it twice.
        let (mut send_to_buf, mut read_from_buf) = tokio::io::duplex(64 * 1024);
        let (alice_keys, _bob_keys) = pair_keys();
        let mut alice = EncryptedConnectionV2::new(&mut send_to_buf, alice_keys);
        alice.send(b"original payload").await.expect("send");
        drop(alice);

        let mut frame_one = vec![0u8; 4096];
        let n = read_from_buf.read(&mut frame_one).await.expect("read");
        let frame_one = &frame_one[..n];

        // Now build a fresh duplex into bob and write the frame twice.
        let (mut s, r) = tokio::io::duplex(64 * 1024);
        s.write_all(frame_one).await.expect("first");
        s.write_all(frame_one).await.expect("second");
        s.flush().await.expect("flush");
        drop(s);

        let bob_keys = SessionKeys {
            tx_key: [0x22u8; 32],
            rx_key: [0x11u8; 32],
        };
        let mut bob = EncryptedConnectionV2::new(r, bob_keys);
        // First copy — accepted.
        let first = bob.recv().await.expect("first recv");
        assert_eq!(first, b"original payload".to_vec());
        // Second copy — same seq=0, but bob's recv_seq has advanced to 1.
        let second = bob.recv().await;
        match second {
            Err(TransportV2Error::ReplayOrReorder {
                got: 0,
                expected: 1,
            }) => {}
            other => panic!("expected ReplayOrReorder, got {other:?}"),
        }
    }

    /// A frame body larger than the cap must be rejected at the length
    /// prefix step, before any allocation.
    #[tokio::test]
    async fn oversized_frame_rejected_pre_alloc() {
        let (mut s, r) = tokio::io::duplex(64);
        let bogus_len = (MAX_FRAME_BODY_BYTES as u32).saturating_add(1);
        s.write_all(&bogus_len.to_le_bytes()).await.expect("write");
        s.flush().await.expect("flush");
        drop(s);

        let bob_keys = SessionKeys {
            tx_key: [0x22u8; 32],
            rx_key: [0x11u8; 32],
        };
        let mut bob = EncryptedConnectionV2::new(r, bob_keys);
        let res = bob.recv().await;
        assert!(matches!(res, Err(TransportV2Error::FrameTooLarge { .. })));
    }

    /// A frame body smaller than `seq + tag` is malformed.
    #[tokio::test]
    async fn undersized_frame_rejected() {
        let (mut s, r) = tokio::io::duplex(64);
        // Body length = 5 bytes — not enough for seq (8) + tag (16).
        s.write_all(&5u32.to_le_bytes()).await.expect("write");
        s.write_all(&[0u8; 5]).await.expect("write body");
        s.flush().await.expect("flush");
        drop(s);

        let bob_keys = SessionKeys {
            tx_key: [0x22u8; 32],
            rx_key: [0x11u8; 32],
        };
        let mut bob = EncryptedConnectionV2::new(r, bob_keys);
        let res = bob.recv().await;
        assert!(matches!(res, Err(TransportV2Error::FrameTooSmall { .. })));
    }

    /// Truncated read inside the frame body propagates as IO error rather
    /// than silently returning an empty plaintext.
    #[tokio::test]
    async fn truncated_frame_propagates_io_error() {
        let (mut s, r) = tokio::io::duplex(64);
        // Promise body of 64 bytes, send only 10.
        s.write_all(&64u32.to_le_bytes()).await.expect("len");
        s.write_all(&[0u8; 10]).await.expect("partial");
        drop(s); // closes the read side at EOF

        let bob_keys = SessionKeys {
            tx_key: [0x22u8; 32],
            rx_key: [0x11u8; 32],
        };
        let mut bob = EncryptedConnectionV2::new(r, bob_keys);
        let res = bob.recv().await;
        assert!(matches!(res, Err(TransportV2Error::Io(_))));
    }

    /// The nonce must be derived deterministically from the seq — sending
    /// the same plaintext twice must produce *different* ciphertexts (so
    /// nonce reuse is impossible across two messages with the same key).
    #[tokio::test]
    async fn same_plaintext_yields_different_ciphertext_per_seq() {
        let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
        let (alice_keys, _bob_keys) = pair_keys();
        let mut alice = EncryptedConnectionV2::new(&mut writer, alice_keys);
        alice.send(b"same").await.expect("first");
        alice.send(b"same").await.expect("second");
        drop(alice);

        let mut buf = vec![0u8; 4096];
        let n = reader.read(&mut buf).await.expect("read");
        let bytes = &buf[..n];

        // Skip the first frame's length prefix + body to find the second
        // frame's body.
        let len1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let frame1 = &bytes[4..4 + len1];
        let frame2_offset = 4 + len1;
        let len2 = u32::from_le_bytes([
            bytes[frame2_offset],
            bytes[frame2_offset + 1],
            bytes[frame2_offset + 2],
            bytes[frame2_offset + 3],
        ]) as usize;
        let frame2 = &bytes[frame2_offset + 4..frame2_offset + 4 + len2];

        // Both frames cover identical plaintext "same" and identical
        // (key, plaintext) pair. The seq is different, so the nonce is
        // different, so the ciphertext+tag region must differ.
        let ct1 = &frame1[SEQ_BYTES..];
        let ct2 = &frame2[SEQ_BYTES..];
        assert_ne!(
            ct1, ct2,
            "same plaintext + same key but different seq must give different ciphertext"
        );
    }

    /// The make_nonce helper places the seq in the first 8 LE bytes and
    /// zero-fills the remaining 16 bytes. Locking this down so a future
    /// refactor cannot silently reshuffle nonce layout (which would break
    /// interop with already-deployed peers).
    #[test]
    fn nonce_layout_is_stable() {
        let n = make_nonce(0x0102030405060708);
        let bytes: &[u8] = n.as_slice();
        assert_eq!(bytes.len(), NONCE_BYTES);
        assert_eq!(&bytes[..SEQ_BYTES], &0x0102030405060708u64.to_le_bytes());
        assert!(bytes[SEQ_BYTES..].iter().all(|b| *b == 0));
    }
}
