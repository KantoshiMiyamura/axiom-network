// Copyright (c) 2026 Kantoshi Miyamura

//! P2P networking layer.

pub mod discovery;
pub mod dos_protection;
pub mod encryption;
pub mod limits;
mod manager;
mod message;
mod peer;
mod protocol;
pub mod scoring;
mod service;
mod transport;

pub use discovery::{
    dedupe_and_filter_self, is_self_addr, resolve_dns_seeds, self_p2p_addrs, PeerAddressBook,
    PeerDiscovery, DEVNET_DNS_SEEDS, MAINNET_DNS_SEEDS, TESTNET_DNS_SEEDS,
};
pub use dos_protection::{DosProtection, MempoolRateLimiter, RateLimiter};
pub use encryption::{EncryptedConnection, EncryptionError};
pub use limits::MAX_RPC_REQUEST_SIZE;
pub use manager::{NetworkError, PeerManager, MAX_INBOUND_PEERS, MAX_OUTBOUND_PEERS};
pub use message::{
    reject_code,
    BlockTxnsMsg,
    ChatBanPayload,
    ChatMessagePayload,
    CompactBlockMsg,
    GetBlockTxnsMsg,
    InvItem,
    InvItemType,
    Message,
    MessageError,
    MessageType,
    PrefilledTx,
    TipMessage,
    UsernameAnnouncePayload,
    VersionMessage,
    short_tx_id,
    MAX_BLOCKS_PER_RESPONSE,
    MAX_CHAT_TEXT_BYTES,
    MAX_HEADERS_PER_MESSAGE,
    MAX_INV_ITEMS,
    MAX_MESSAGE_SIZE,
    MAX_TXS_PER_MESSAGE,
    MAX_USERNAME_BYTES,
    SERVICE_AI,
    SERVICE_BLOOM,
    SERVICE_COMPACT,
    SERVICE_ENCRYPTED,
    SERVICE_FULL_NODE,
    SERVICE_LIGHT,
};
pub use peer::{Direction, Peer, PeerId, PeerState};
pub use protocol::{HandshakeError, ProtocolHandler, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
pub use scoring::{PeerScore, PeerScorer};
pub use service::{NetworkService, ServiceError};
pub use transport::{Connection, Transport};
