// Copyright (c) 2026 Kantoshi Miyamura

//! Regression tests for the v2.0.0-testnet.3 peer-manager-mismatch bug.
//!
//! Symptom in v2.0.0-testnet.3: a fresh Node B dialed a taller Node A;
//! handshake completed; SYNC_CHECK + SYNC_NEEDED both fired; immediately
//! after came `MESSAGE_HANDLER_ERROR: peer not found: PeerId(...)` and the
//! connection dropped. PEER_SEED_RECONNECT looped forever — Node B never
//! advanced past height 0.
//!
//! Root cause: axiom-cli constructed *two* PeerManager instances. The first
//! (`Arc<PeerManager>`) was handed to `P2PNetwork` and held every peer
//! registered via `add_peer` during handshake. The second was constructed
//! inline and handed by value to `NetworkService::with_shared_node`, which
//! wrapped it in a private `Arc` and treated it as authoritative. Every
//! back-channel send from `NetworkService` — `sync_with_peer`'s GetHeaders,
//! `handle_inv`'s GetData, `handle_headers`'s GetData, `handle_received_block`'s
//! Inv relay, `handle_get_data`'s Block reply — looked the peer up in the
//! second (always-empty) map and returned `PeerNotFound`.
//!
//! Fix (v2.0.0-testnet.4): `with_shared_node` now takes `Arc<PeerManager>`
//! and stores it directly. main.rs threads the existing
//! `peer_manager.clone()` through both layers.
//!
//! These tests pin every back-channel path that was silently broken:
//!
//!   * `sync_get_headers_reaches_peer_via_shared_peer_manager` — the path
//!     that produced the visible MESSAGE_HANDLER_ERROR in the field report.
//!   * `inv_triggers_get_data_via_shared_peer_manager` — the path a fresh
//!     node would have used to fetch newly-announced blocks once IBD
//!     finished.
//!   * `accepted_block_relays_inv_to_other_peers_via_shared_peer_manager` —
//!     the path that keeps the network connected; without it accepted
//!     blocks die at the receiving node.
//!   * `get_data_block_reply_reaches_peer_via_shared_peer_manager` — the
//!     symmetric serve path that A would have used to answer B's
//!     GetData requests during IBD.

use axiom_node::{
    network::{
        InvItem, InvItemType, Message, NetworkService, PeerId, PeerManager, PeerState, TipMessage,
    },
    Config, Node,
};
use axiom_primitives::Hash256;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::{mpsc, RwLock};

fn make_node(network: &str) -> (TempDir, Node) {
    let temp_dir = TempDir::new().unwrap();
    let config = Config {
        data_dir: temp_dir.path().to_path_buf(),
        network: axiom_node::Network::parse_str(network).unwrap(),
        ..Default::default()
    };
    let node = Node::new(config).unwrap();
    (temp_dir, node)
}

/// Build a NetworkService whose `peer_manager` field is the **same**
/// `Arc<PeerManager>` we return — that's the invariant the v2.0.0-testnet.4
/// fix restored.
fn make_shared_service(network: &str) -> (TempDir, NetworkService, Arc<PeerManager>) {
    let (tmp, node) = make_node(network);
    let pm = Arc::new(PeerManager::new(network.to_string()));
    let node_arc = Arc::new(RwLock::new(node));
    let svc = NetworkService::with_shared_node(node_arc, pm.clone());
    (tmp, svc, pm)
}

/// Register a peer in `pm` with state = Ready and an mpsc outbound channel.
/// Returns the assigned PeerId and the receiver end of the channel, which
/// the test uses to observe what NetworkService sent through PeerManager.
async fn register_ready_peer(
    pm: &PeerManager,
    addr: SocketAddr,
) -> (PeerId, mpsc::UnboundedReceiver<Message>) {
    use axiom_node::network::Direction;
    let peer_id = pm
        .add_peer(addr, Direction::Inbound)
        .await
        .expect("add_peer");
    let (tx, rx) = mpsc::unbounded_channel::<Message>();
    pm.set_peer_sender(peer_id, tx)
        .await
        .expect("set_peer_sender");
    pm.update_peer_state(peer_id, PeerState::Ready)
        .await
        .expect("update_peer_state");
    (peer_id, rx)
}

/// THE bug: receiving a Tip from a taller peer triggers `sync_with_peer`,
/// which sends `GetHeaders` via `self.peer_manager.send_to_peer`. Under the
/// broken wiring that send returned PeerNotFound and propagated up as
/// `MESSAGE_HANDLER_ERROR`. Under the fix the GetHeaders reaches the peer's
/// mpsc channel.
#[tokio::test]
async fn sync_get_headers_reaches_peer_via_shared_peer_manager() {
    let (_tmp, service, pm) = make_shared_service("dev");
    let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let (peer_id, mut rx) = register_ready_peer(&pm, addr).await;

    // Simulate the taller peer's Tip arriving. local_height=0 so any
    // positive peer height triggers sync.
    let result = service
        .handle_message(
            peer_id,
            Message::Tip(TipMessage {
                best_hash: Hash256::zero(),
                best_height: 1410,
            }),
        )
        .await;

    assert!(
        result.is_ok(),
        "handle_message(Tip) returned an error — peer-manager mismatch back? \
         got {:?}",
        result.err()
    );

    let sent = rx.try_recv().expect(
        "no message arrived at peer's outbound channel — sync_with_peer never \
         reached the shared PeerManager",
    );
    match sent {
        Message::GetHeaders(_, _) => {}
        other => panic!("expected GetHeaders, got {:?}", other),
    }
}

/// `handle_inv` for an unknown block hash must send `GetData` back to the
/// announcing peer through `self.peer_manager.send_to_peer`. Same shared-
/// PeerManager dependency.
#[tokio::test]
async fn inv_triggers_get_data_via_shared_peer_manager() {
    let (_tmp, service, pm) = make_shared_service("dev");
    let addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();
    let (peer_id, mut rx) = register_ready_peer(&pm, addr).await;

    let unknown_hash = {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xAB;
        Hash256::from_bytes(bytes)
    };

    let result = service
        .handle_message(
            peer_id,
            Message::Inv(vec![InvItem {
                item_type: InvItemType::Block,
                hash: unknown_hash,
            }]),
        )
        .await;

    assert!(result.is_ok(), "handle_message(Inv) errored: {:?}", result);

    let sent = rx.try_recv().expect(
        "no GetData arrived on peer channel — handle_inv used the wrong \
         PeerManager",
    );
    match sent {
        Message::GetData(items) => {
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].hash, unknown_hash);
        }
        other => panic!("expected GetData, got {:?}", other),
    }
}

/// When a block arrives from peer A and is accepted, `handle_received_block`
/// announces it via `Inv` to all OTHER peers using `self.peer_manager`.
/// Without the shared Arc the announce silently fails.
#[tokio::test]
async fn accepted_block_relays_inv_to_other_peers_via_shared_peer_manager() {
    // Mine the block on a throw-away service so we have a valid PoW-bearing
    // block, then feed it into a fresh service whose chain is still at
    // genesis. That makes the second service treat the block as a genuine
    // network arrival (not a duplicate already in its store) and gives
    // `handle_received_block` a reason to relay it.
    let (_tmp_miner, miner) = make_shared_service("dev").into_partial();
    let block = miner.build_local_block().await.unwrap();
    drop(miner);

    let (_tmp, service, pm) = make_shared_service("dev");
    let sender_addr: SocketAddr = "127.0.0.1:9003".parse().unwrap();
    let (sender_id, _sender_rx) = register_ready_peer(&pm, sender_addr).await;
    let observer_addr: SocketAddr = "127.0.0.1:9004".parse().unwrap();
    let (_observer_id, mut observer_rx) = register_ready_peer(&pm, observer_addr).await;

    let result = service
        .handle_message(sender_id, Message::Block(block.clone()))
        .await;
    assert!(
        result.is_ok(),
        "handle_message(Block) errored: {:?}",
        result
    );

    let sent = observer_rx
        .try_recv()
        .expect("observer peer never received Inv announce for accepted block");
    match sent {
        Message::Inv(items) => {
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].item_type, InvItemType::Block);
            assert_eq!(items[0].hash, block.hash());
        }
        other => panic!("expected Inv, got {:?}", other),
    }
}

/// Helper trait so the relay test can drop the unused PeerManager handle
/// from `make_shared_service` without an `_` binding cluttering the test.
trait IntoPartial {
    fn into_partial(self) -> (TempDir, NetworkService);
}

impl IntoPartial for (TempDir, NetworkService, Arc<PeerManager>) {
    fn into_partial(self) -> (TempDir, NetworkService) {
        let (tmp, svc, _pm) = self;
        (tmp, svc)
    }
}

/// `handle_get_data` for a known block must send `Block` back to the
/// requester via the shared PeerManager — this is the serve side of IBD,
/// the path A would use to satisfy B's GetData requests for blocks.
#[tokio::test]
async fn get_data_block_reply_reaches_peer_via_shared_peer_manager() {
    let (_tmp, service, pm) = make_shared_service("dev");
    let addr: SocketAddr = "127.0.0.1:9007".parse().unwrap();
    let (peer_id, mut rx) = register_ready_peer(&pm, addr).await;

    let block = service.build_local_block().await.unwrap();
    let block_hash = block.hash();

    let result = service
        .handle_message(
            peer_id,
            Message::GetData(vec![InvItem {
                item_type: InvItemType::Block,
                hash: block_hash,
            }]),
        )
        .await;
    assert!(
        result.is_ok(),
        "handle_message(GetData) errored: {:?}",
        result
    );

    let sent = rx.try_recv().expect(
        "no Block reply arrived on peer channel — handle_get_data used the \
         wrong PeerManager",
    );
    match sent {
        Message::Block(b) => {
            assert_eq!(b.hash(), block_hash);
        }
        other => panic!("expected Block, got {:?}", other),
    }
}
