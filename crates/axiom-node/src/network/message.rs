// Copyright (c) 2026 Kantoshi Miyamura

use axiom_consensus::{Block, BlockHeader};
use axiom_primitives::Hash256;
use axiom_protocol::Transaction;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use thiserror::Error;

pub const MAX_MESSAGE_SIZE: usize = 2_000_000;
pub const MAX_TXS_PER_MESSAGE: usize = 10_000;
pub const MAX_BLOCKS_PER_RESPONSE: usize = 500;
// CRITICAL FIX: Reduced from 50,000 to 5,000 to prevent DoS.
// Attacker could send 50k inventory items (1.6MB) forcing massive processing.
// With 5,000 limit, max inv message is ~160KB, manageable per peer.
pub const MAX_INV_ITEMS: usize = 5_000; // was 50_000
pub const MAX_HEADERS_PER_MESSAGE: usize = 2000;

/// Maximum length of a community chat message body in bytes.
pub const MAX_CHAT_TEXT_BYTES: usize = 512;
/// Maximum username length in bytes.
pub const MAX_USERNAME_BYTES: usize = 32;

#[derive(Error, Debug)]
pub enum MessageError {
    #[error("message too large: {0} bytes")]
    MessageTooLarge(usize),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("deserialization error: {0}")]
    Deserialization(String),

    #[error("invalid message type: {0}")]
    InvalidType(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Version = 0,
    VerAck = 1,
    Ping = 2,
    Pong = 3,
    GetTip = 4,
    Tip = 5,
    GetBlock = 6,
    Block = 7,
    Tx = 8,
    GetPeers = 9,
    Peers = 10,
    Inv = 11,
    GetData = 12,
    NotFound = 13,
    GetHeaders = 14,
    Headers = 15,
    FeeFilter = 16,
    Reject = 17,
    /// Ephemeral gossip chat message — never written to disk.
    ChatMessage = 18,
    /// A node voting to ban a community member (3 votes → 24 h ban).
    ChatBan = 19,
    /// Announces a username that was registered via on-chain tx.
    UsernameAnnounce = 20,
    /// Compact block announcement (BIP 152-style).
    CompactBlock = 21,
    /// Request missing transactions for compact block reconstruction.
    GetBlockTxns = 22,
    /// Response with requested transactions.
    BlockTxns = 23,
}

impl MessageType {
    pub fn from_u8(value: u8) -> Result<Self, MessageError> {
        match value {
            0 => Ok(MessageType::Version),
            1 => Ok(MessageType::VerAck),
            2 => Ok(MessageType::Ping),
            3 => Ok(MessageType::Pong),
            4 => Ok(MessageType::GetTip),
            5 => Ok(MessageType::Tip),
            6 => Ok(MessageType::GetBlock),
            7 => Ok(MessageType::Block),
            8 => Ok(MessageType::Tx),
            9 => Ok(MessageType::GetPeers),
            10 => Ok(MessageType::Peers),
            11 => Ok(MessageType::Inv),
            12 => Ok(MessageType::GetData),
            13 => Ok(MessageType::NotFound),
            14 => Ok(MessageType::GetHeaders),
            15 => Ok(MessageType::Headers),
            16 => Ok(MessageType::FeeFilter),
            17 => Ok(MessageType::Reject),
            18 => Ok(MessageType::ChatMessage),
            19 => Ok(MessageType::ChatBan),
            20 => Ok(MessageType::UsernameAnnounce),
            21 => Ok(MessageType::CompactBlock),
            22 => Ok(MessageType::GetBlockTxns),
            23 => Ok(MessageType::BlockTxns),
            _ => Err(MessageError::InvalidType(value)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum InvItemType {
    Transaction = 1,
    Block = 2,
    BlockHeader = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvItem {
    pub item_type: InvItemType,
    pub hash: Hash256,
}

// ── Community chat structs ────────────────────────────────────────────────────

/// An ephemeral P2P community chat message.  Relayed by gossip; never persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessagePayload {
    /// Registered username or leading chars of sender address if unregistered.
    pub username: String,
    /// Sender's AXM address — used for ban enforcement and dedup.
    pub sender_address: String,
    /// Message body (≤ MAX_CHAT_TEXT_BYTES, enforced at creation and relay).
    pub text: String,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Random 64-bit nonce — prevents replay and deduplicates gossip.
    pub nonce: u64,
    /// ML-DSA-87 signature over `sha256(username ‖ text ‖ timestamp ‖ nonce)`.
    pub signature: Vec<u8>,
}

/// One node's vote to ban a community member.
/// When **3 distinct nodes** broadcast this for the same `target_address`
/// within a 60-second window the network applies a 24 h chat ban.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatBanPayload {
    /// AXM address of the account to ban.
    pub target_address: String,
    /// Human-readable reason (≤ 256 bytes).
    pub reason: String,
    /// Unix timestamp of the vote.
    pub timestamp: u64,
    /// Voting node's own AXM address.
    pub voter_address: String,
    /// ML-DSA-87 signature of voter over `sha256(target ‖ reason ‖ timestamp)`.
    pub signature: Vec<u8>,
}

/// Gossip announcement of a username that was registered via an on-chain tx.
/// Nodes cache the latest announce per address and serve it via RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameAnnouncePayload {
    /// The claimed username (≤ MAX_USERNAME_BYTES, ASCII alphanumeric + _).
    pub username: String,
    /// Owner's AXM address.
    pub address: String,
    /// Hash of the on-chain `UsernameRegistration` transaction.
    pub registration_tx: [u8; 32],
    /// Unix timestamp of this announcement.
    pub timestamp: u64,
}

// ── Compact block relay (BIP 152-style) ──────────────────────────────────────

/// Compact block announcement.
///
/// The sender hashes all transaction IDs using SipHash-2-4 with a per-block
/// nonce to produce 6-byte short IDs.  The receiver uses its own mempool to
/// reconstruct missing transactions; only missing ones are fetched via
/// `GetBlockTxns` / `BlockTxns`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactBlockMsg {
    /// The block header.
    pub header: BlockHeader,
    /// SipHash nonce; the actual key is `nonce XOR first-8-bytes-of-header-hash`.
    pub nonce: u64,
    /// 6-byte short transaction IDs (one per non-prefilled transaction).
    pub short_ids: Vec<[u8; 6]>,
    /// Transactions the sender expects the receiver may not have
    /// (always includes coinbase at index 0; may include others).
    pub prefilled_txs: Vec<PrefilledTx>,
}

/// A transaction that is sent in full inside a `CompactBlockMsg`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefilledTx {
    /// Position of this transaction within the block (0-based).
    pub index: u16,
    /// The full transaction.
    pub tx: Transaction,
}

/// Request specific transactions from a compact block by position index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBlockTxnsMsg {
    /// Hash of the block whose transactions we need.
    pub block_hash: Hash256,
    /// 0-based positions of the transactions we need.
    pub indexes: Vec<u16>,
}

/// Response to `GetBlockTxns` — the requested transactions in index order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTxnsMsg {
    /// Hash of the block these transactions belong to.
    pub block_hash: Hash256,
    /// The requested transactions in the same order as the `indexes` in `GetBlockTxnsMsg`.
    pub txs: Vec<Transaction>,
}

/// Compute a 6-byte short transaction ID using SipHash-2-4.
///
/// # Arguments
/// * `nonce` — the per-block nonce from `CompactBlockMsg` XOR'd with the
///   first 8 bytes of the block header hash (little-endian).
/// * `txid`  — the 32-byte transaction ID.
///
/// # Returns
/// The low 6 bytes of the SipHash-2-4 output.
#[allow(dead_code)]
pub fn short_tx_id(nonce: u64, txid: &Hash256) -> [u8; 6] {
    // SipHash-2-4 key = nonce split into two 64-bit LE words.
    let k0 = nonce;
    let k1 = nonce.wrapping_add(0x6c62272e07bb0142); // arbitrary second key word

    let hash = siphash24(k0, k1, txid.as_bytes());

    let mut out = [0u8; 6];
    out.copy_from_slice(&hash.to_le_bytes()[..6]);
    out
}

/// Pure-Rust SipHash-2-4 implementation (no external crate needed).
/// Returns the 64-bit hash of `data` under the key `(k0, k1)`.
fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v0: u64 = k0 ^ 0x736f6d6570736575;
    let mut v1: u64 = k1 ^ 0x646f72616e646f6d;
    let mut v2: u64 = k0 ^ 0x6c7967656e657261;
    let mut v3: u64 = k1 ^ 0x7465646279746573;

    #[inline(always)]
    fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
        *v0 = v0.wrapping_add(*v1);
        *v1 = v1.rotate_left(13);
        *v1 ^= *v0;
        *v0 = v0.rotate_left(32);
        *v2 = v2.wrapping_add(*v3);
        *v3 = v3.rotate_left(16);
        *v3 ^= *v2;
        *v0 = v0.wrapping_add(*v3);
        *v3 = v3.rotate_left(21);
        *v3 ^= *v0;
        *v2 = v2.wrapping_add(*v1);
        *v1 = v1.rotate_left(17);
        *v1 ^= *v2;
        *v2 = v2.rotate_left(32);
    }

    let length = data.len();
    let mut chunks = data.chunks_exact(8);

    for chunk in &mut chunks {
        let m = u64::from_le_bytes(chunk.try_into().unwrap());
        v3 ^= m;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    // Process remaining bytes + length byte.
    let remainder = chunks.remainder();
    let mut last: u64 = ((length as u64) & 0xff) << 56;
    for (i, &b) in remainder.iter().enumerate() {
        last |= (b as u64) << (i * 8);
    }

    v3 ^= last;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    v2 ^= 0xff;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

pub const SERVICE_FULL_NODE: u64 = 1 << 0;
pub const SERVICE_BLOOM: u64 = 1 << 1;
pub const SERVICE_COMPACT: u64 = 1 << 2;
pub const SERVICE_LIGHT: u64 = 1 << 3;
pub const SERVICE_AI: u64 = 1 << 4;
pub const SERVICE_ENCRYPTED: u64 = 1 << 5;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionMessage {
    pub protocol_version: u32,
    pub network: String,
    pub best_height: u32,
    #[serde(default)]
    pub services: u64,
    #[serde(default)]
    pub nonce: u64,
    #[serde(default)]
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipMessage {
    pub best_hash: Hash256,
    pub best_height: u32,
}

pub mod reject_code {
    pub const MALFORMED: u8 = 0x01;
    pub const INVALID: u8 = 0x10;
    pub const OBSOLETE: u8 = 0x11;
    pub const DUPLICATE: u8 = 0x12;
    pub const NONSTANDARD: u8 = 0x40;
    pub const DUST: u8 = 0x41;
    pub const INSUFFICIENT_FEE: u8 = 0x42;
    pub const CHECKPOINT: u8 = 0x43;
}

#[derive(Debug, Clone)]
pub enum Message {
    Version(VersionMessage),
    VerAck,
    Ping(u64),
    Pong(u64),
    GetTip,
    Tip(TipMessage),
    GetBlock(Hash256),
    Block(Block),
    Tx(Transaction),
    GetPeers,
    Peers(Vec<SocketAddr>),
    Inv(Vec<InvItem>),
    GetData(Vec<InvItem>),
    NotFound(Vec<InvItem>),
    GetHeaders(Hash256, u32),
    Headers(Vec<BlockHeader>),
    FeeFilter(u64),
    Reject(String, u8, String),
    ChatMessage(ChatMessagePayload),
    ChatBan(ChatBanPayload),
    UsernameAnnounce(UsernameAnnouncePayload),
    /// Compact block announcement (BIP 152-style).
    CompactBlock(CompactBlockMsg),
    /// Request missing transactions for compact block reconstruction.
    GetBlockTxns(GetBlockTxnsMsg),
    /// Response with requested transactions.
    BlockTxns(BlockTxnsMsg),
}

#[derive(Serialize, Deserialize)]
struct GetHeadersPayload {
    from_hash: Hash256,
    max_count: u32,
}

#[derive(Serialize, Deserialize)]
struct RejectPayload {
    id: String,
    code: u8,
    reason: String,
}

impl Message {
    /// Encode as [type:u8][len:u32-LE][payload].
    pub fn serialize(&self) -> Result<Vec<u8>, MessageError> {
        let (msg_type, payload) = match self {
            Message::Version(v) => (
                MessageType::Version,
                bincode::serde::encode_to_vec(v, bincode::config::standard()),
            ),
            Message::VerAck => (MessageType::VerAck, Ok(vec![])),
            Message::Ping(nonce) => (
                MessageType::Ping,
                bincode::serde::encode_to_vec(nonce, bincode::config::standard()),
            ),
            Message::Pong(nonce) => (
                MessageType::Pong,
                bincode::serde::encode_to_vec(nonce, bincode::config::standard()),
            ),
            Message::GetTip => (MessageType::GetTip, Ok(vec![])),
            Message::Tip(tip) => (
                MessageType::Tip,
                bincode::serde::encode_to_vec(tip, bincode::config::standard()),
            ),
            Message::GetBlock(hash) => (
                MessageType::GetBlock,
                bincode::serde::encode_to_vec(hash, bincode::config::standard()),
            ),
            Message::Block(block) => (
                MessageType::Block,
                bincode::serde::encode_to_vec(block, bincode::config::standard()),
            ),
            Message::Tx(tx) => (
                MessageType::Tx,
                bincode::serde::encode_to_vec(tx, bincode::config::standard()),
            ),
            Message::GetPeers => (MessageType::GetPeers, Ok(vec![])),
            Message::Peers(addrs) => (
                MessageType::Peers,
                bincode::serde::encode_to_vec(addrs, bincode::config::standard()),
            ),

            Message::Inv(items) => (
                MessageType::Inv,
                bincode::serde::encode_to_vec(items, bincode::config::standard()),
            ),
            Message::GetData(items) => (
                MessageType::GetData,
                bincode::serde::encode_to_vec(items, bincode::config::standard()),
            ),
            Message::NotFound(items) => (
                MessageType::NotFound,
                bincode::serde::encode_to_vec(items, bincode::config::standard()),
            ),
            Message::GetHeaders(from_hash, max_count) => {
                let p = GetHeadersPayload {
                    from_hash: *from_hash,
                    max_count: *max_count,
                };
                (
                    MessageType::GetHeaders,
                    bincode::serde::encode_to_vec(&p, bincode::config::standard()),
                )
            }
            Message::Headers(headers) => (
                MessageType::Headers,
                bincode::serde::encode_to_vec(headers, bincode::config::standard()),
            ),
            Message::FeeFilter(rate) => (
                MessageType::FeeFilter,
                bincode::serde::encode_to_vec(rate, bincode::config::standard()),
            ),
            Message::Reject(id, code, reason) => {
                let p = RejectPayload {
                    id: id.clone(),
                    code: *code,
                    reason: reason.clone(),
                };
                (
                    MessageType::Reject,
                    bincode::serde::encode_to_vec(&p, bincode::config::standard()),
                )
            }
            Message::ChatMessage(payload) => (
                MessageType::ChatMessage,
                bincode::serde::encode_to_vec(payload, bincode::config::standard()),
            ),
            Message::ChatBan(payload) => (
                MessageType::ChatBan,
                bincode::serde::encode_to_vec(payload, bincode::config::standard()),
            ),
            Message::UsernameAnnounce(payload) => (
                MessageType::UsernameAnnounce,
                bincode::serde::encode_to_vec(payload, bincode::config::standard()),
            ),
            Message::CompactBlock(msg) => (
                MessageType::CompactBlock,
                bincode::serde::encode_to_vec(msg, bincode::config::standard()),
            ),
            Message::GetBlockTxns(msg) => (
                MessageType::GetBlockTxns,
                bincode::serde::encode_to_vec(msg, bincode::config::standard()),
            ),
            Message::BlockTxns(msg) => (
                MessageType::BlockTxns,
                bincode::serde::encode_to_vec(msg, bincode::config::standard()),
            ),
        };

        let payload = payload.map_err(|e| MessageError::Serialization(e.to_string()))?;

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(MessageError::MessageTooLarge(payload.len()));
        }

        let mut bytes = Vec::new();
        bytes.push(msg_type as u8);
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&payload);

        Ok(bytes)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() < 5 {
            return Err(MessageError::Deserialization("message too short".into()));
        }

        let msg_type = MessageType::from_u8(bytes[0])?;
        let length = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;

        if length > MAX_MESSAGE_SIZE {
            return Err(MessageError::MessageTooLarge(length));
        }

        if bytes.len() < 5 + length {
            return Err(MessageError::Deserialization("incomplete message".into()));
        }

        let payload = &bytes[5..5 + length];

        let message = match msg_type {
            MessageType::Version => {
                let v: VersionMessage =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::Version(v)
            }
            MessageType::VerAck => Message::VerAck,
            MessageType::Ping => {
                let nonce: u64 =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::Ping(nonce)
            }
            MessageType::Pong => {
                let nonce: u64 =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::Pong(nonce)
            }
            MessageType::GetTip => Message::GetTip,
            MessageType::Tip => {
                let tip: TipMessage =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::Tip(tip)
            }
            MessageType::GetBlock => {
                let hash: Hash256 =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::GetBlock(hash)
            }
            MessageType::Block => {
                let block: Block =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::Block(block)
            }
            MessageType::Tx => {
                let tx: Transaction =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::Tx(tx)
            }
            MessageType::GetPeers => Message::GetPeers,
            MessageType::Peers => {
                let addrs: Vec<SocketAddr> =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::Peers(addrs)
            }

            MessageType::Inv => {
                let items: Vec<InvItem> =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::Inv(items)
            }
            MessageType::GetData => {
                let items: Vec<InvItem> =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::GetData(items)
            }
            MessageType::NotFound => {
                let items: Vec<InvItem> =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::NotFound(items)
            }
            MessageType::GetHeaders => {
                let p: GetHeadersPayload =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::GetHeaders(p.from_hash, p.max_count)
            }
            MessageType::Headers => {
                let headers: Vec<BlockHeader> =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::Headers(headers)
            }
            MessageType::FeeFilter => {
                let rate: u64 =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::FeeFilter(rate)
            }
            MessageType::Reject => {
                let p: RejectPayload =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::Reject(p.id, p.code, p.reason)
            }
            MessageType::ChatMessage => {
                let p: ChatMessagePayload =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::ChatMessage(p)
            }
            MessageType::ChatBan => {
                let p: ChatBanPayload =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::ChatBan(p)
            }
            MessageType::UsernameAnnounce => {
                let p: UsernameAnnouncePayload =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::UsernameAnnounce(p)
            }
            MessageType::CompactBlock => {
                let msg: CompactBlockMsg =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::CompactBlock(msg)
            }
            MessageType::GetBlockTxns => {
                let msg: GetBlockTxnsMsg =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::GetBlockTxns(msg)
            }
            MessageType::BlockTxns => {
                let msg: BlockTxnsMsg =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| MessageError::Deserialization(e.to_string()))?;
                Message::BlockTxns(msg)
            }
        };

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_message_roundtrip() {
        let version = VersionMessage {
            protocol_version: 1,
            network: "dev".to_string(),
            best_height: 100,
            ..Default::default()
        };

        let msg = Message::Version(version);
        let serialized = msg.serialize().unwrap();
        let deserialized = Message::deserialize(&serialized).unwrap();

        match deserialized {
            Message::Version(v) => {
                assert_eq!(v.protocol_version, 1);
                assert_eq!(v.network, "dev");
                assert_eq!(v.best_height, 100);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_verack_roundtrip() {
        let msg = Message::VerAck;
        let serialized = msg.serialize().unwrap();
        let deserialized = Message::deserialize(&serialized).unwrap();

        assert!(matches!(deserialized, Message::VerAck));
    }

    #[test]
    fn test_ping_pong_roundtrip() {
        let ping = Message::Ping(12345);
        let serialized = ping.serialize().unwrap();
        let deserialized = Message::deserialize(&serialized).unwrap();

        match deserialized {
            Message::Ping(nonce) => assert_eq!(nonce, 12345),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_message_too_large() {
        let large_data = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let mut bytes = vec![0u8]; // Version type
        bytes.extend_from_slice(&(large_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&large_data);

        let result = Message::deserialize(&bytes);
        assert!(matches!(result, Err(MessageError::MessageTooLarge(_))));
    }

    #[test]
    fn test_invalid_message_type() {
        let bytes = vec![99, 0, 0, 0, 0]; // Invalid type
        let result = Message::deserialize(&bytes);
        assert!(matches!(result, Err(MessageError::InvalidType(99))));
    }

    #[test]
    fn test_inv_roundtrip() {
        let items = vec![
            InvItem {
                item_type: InvItemType::Block,
                hash: Hash256::zero(),
            },
            InvItem {
                item_type: InvItemType::Transaction,
                hash: Hash256::zero(),
            },
        ];
        let msg = Message::Inv(items);
        let serialized = msg.serialize().unwrap();
        let deserialized = Message::deserialize(&serialized).unwrap();
        match deserialized {
            Message::Inv(items) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0].item_type, InvItemType::Block);
                assert_eq!(items[1].item_type, InvItemType::Transaction);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_get_headers_roundtrip() {
        let hash = Hash256::zero();
        let msg = Message::GetHeaders(hash, 2000);
        let serialized = msg.serialize().unwrap();
        let deserialized = Message::deserialize(&serialized).unwrap();
        match deserialized {
            Message::GetHeaders(h, count) => {
                assert_eq!(h, Hash256::zero());
                assert_eq!(count, 2000);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_fee_filter_roundtrip() {
        let msg = Message::FeeFilter(1000);
        let serialized = msg.serialize().unwrap();
        let deserialized = Message::deserialize(&serialized).unwrap();
        match deserialized {
            Message::FeeFilter(rate) => assert_eq!(rate, 1000),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_reject_roundtrip() {
        let msg = Message::Reject(
            "abc123".to_string(),
            reject_code::INVALID,
            "bad block".to_string(),
        );
        let serialized = msg.serialize().unwrap();
        let deserialized = Message::deserialize(&serialized).unwrap();
        match deserialized {
            Message::Reject(id, code, reason) => {
                assert_eq!(id, "abc123");
                assert_eq!(code, reject_code::INVALID);
                assert_eq!(reason, "bad block");
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_not_found_roundtrip() {
        let items = vec![InvItem {
            item_type: InvItemType::Block,
            hash: Hash256::zero(),
        }];
        let msg = Message::NotFound(items);
        let serialized = msg.serialize().unwrap();
        let deserialized = Message::deserialize(&serialized).unwrap();
        match deserialized {
            Message::NotFound(items) => {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].item_type, InvItemType::Block);
            }
            _ => panic!("wrong message type"),
        }
    }
}
