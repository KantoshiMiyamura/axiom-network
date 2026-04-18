// Copyright (c) 2026 Kantoshi Miyamura
//! Transaction relay pipeline tests.
//!
//! Validates that the transaction relay pipeline is wired correctly:
//!   1. `NetworkService::broadcast_transaction` exists and is callable.
//!   2. `Node::get_mempool_tx` correctly returns `None` for unknown txids.
//!   3. `handle_message(GetData[Tx])` now consults the mempool and returns
//!      `NotFound` (rather than crashing or silently dropping) when the tx is
//!      absent — proving the lookup path is live.
//!   4. `broadcast_transaction` with no peers succeeds with a zero send-count.

use axiom_node::network::PeerId;
use axiom_node::network::{InvItem, InvItemType, Message, NetworkService, PeerManager};
use axiom_node::{Config, Network, Node};
use axiom_primitives::Hash256;
use tempfile::TempDir;

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_node() -> (TempDir, Node) {
    let dir = TempDir::new().unwrap();
    let mut cfg = Config::default();
    cfg.data_dir = dir.path().to_path_buf();
    cfg.network = Network::Dev;
    (dir, Node::new(cfg).unwrap())
}

fn make_service() -> (TempDir, NetworkService) {
    let (dir, node) = make_node();
    let pm = PeerManager::new("dev".to_string());
    let svc = NetworkService::new(node, pm);
    (dir, svc)
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Compile-time proof that `broadcast_transaction` is present on `NetworkService`
/// and that calling it with no peers is safe (returns Ok(0)).
#[tokio::test]
async fn test_broadcast_transaction_no_peers_returns_zero() {
    let (_dir, svc) = make_service();

    let tx = axiom_protocol::Transaction::new_transfer(vec![], vec![], 0, 0);
    let result = svc.broadcast_transaction(tx, None).await;

    assert!(
        result.is_ok(),
        "broadcast_transaction should not error with no peers"
    );
    assert_eq!(
        result.unwrap(),
        0,
        "should send to 0 peers when none are connected"
    );
}

/// `Node::get_mempool_tx` must return `None` for a txid that was never added.
#[test]
fn test_get_mempool_tx_unknown_returns_none() {
    let (_dir, node) = make_node();
    let unknown = Hash256::from_bytes([0xde; 32]);
    assert!(
        node.get_mempool_tx(&unknown).is_none(),
        "get_mempool_tx should return None for unknown txid"
    );
}

/// `handle_message(GetData[Tx])` must attempt a mempool
/// lookup.  When the tx is absent the handler tries to send a `NotFound`
/// message back to the requesting peer.  Because no peer socket is registered
/// in this unit-test setup, `send_to_peer` returns `PeerNotFound`.
///
/// The `PeerNotFound` error proves the code reached the send step, which
/// means the mempool lookup was executed (the old "TX_NOT_SERVED" path that
/// skipped the lookup entirely would never have tried to contact the peer).
#[tokio::test]
async fn test_get_data_tx_missing_from_mempool_attempts_lookup() {
    let (_dir, svc) = make_service();
    let peer_id = PeerId::new();

    let fake_txid = Hash256::from_bytes([0xab; 32]);
    let get_data_msg = Message::GetData(vec![InvItem {
        item_type: InvItemType::Transaction,
        hash: fake_txid,
    }]);

    // The handler will:
    //   1. Look up fake_txid in mempool → None  (new code path)
    //   2. Add it to not_found list
    //   3. Attempt to send NotFound to peer_id → PeerNotFound (no socket registered)
    //
    // PeerNotFound proves steps 2-3 were reached and therefore step 1 was executed.
    let result = svc.handle_message(peer_id, get_data_msg).await;
    let err_str = format!("{:?}", result);
    assert!(
        err_str.contains("PeerNotFound"),
        "expected PeerNotFound error proving mempool lookup path was reached, got: {}",
        err_str
    );
}

/// `broadcast_transaction` with `exclude_peer = Some(id)` also succeeds
/// when no peers are connected.
#[tokio::test]
async fn test_broadcast_transaction_with_exclude_no_peers() {
    let (_dir, svc) = make_service();
    let exclude = PeerId::new();

    let tx = axiom_protocol::Transaction::new_transfer(vec![], vec![], 0, 0);
    let result = svc.broadcast_transaction(tx, Some(exclude)).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

/// `get_mempool_tx` returns `None` for the zero hash (which is never a real tx).
#[test]
fn test_get_mempool_tx_zero_hash_returns_none() {
    let (_dir, node) = make_node();
    assert!(
        node.get_mempool_tx(&Hash256::zero()).is_none(),
        "zero hash should not be in mempool"
    );
}
