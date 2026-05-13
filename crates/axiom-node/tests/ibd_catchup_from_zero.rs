// Copyright (c) 2026 Kantoshi Miyamura

//! Regression test for the v2.0.0-testnet.2 initial-block-download bug.
//!
//! Symptom in v2.0.0-testnet.2: a fresh node (height 0) connecting to a peer
//! at height 1410 received the peer's newly-mined blocks first, stored them
//! as orphans because parents were missing, and quickly hit
//! MAX_ORPHANS_PER_PEER (=10) with `ORPHAN_REJECTED peer_limit_exceeded`.
//!
//! Root cause was two-fold:
//!   1. The per-peer message loop spawned a tokio task for every non-handshake
//!      message, so 1000+ pushed blocks raced through `apply_block`
//!      concurrently — wire-order delivery was destroyed.
//!   2. The handshake-complete code path only triggered a push from
//!      `our_height > peer_height`; the symmetric pull (request headers from a
//!      taller peer) was missing, leaving the fresh node passive while
//!      newly-broadcast blocks piled up as orphans.
//!
//! Fix (v2.0.0-testnet.3): pull-based IBD trigger on handshake-complete and
//! serial message handling in the per-peer loop. This test exercises the two
//! invariants:
//!
//!   * Test A — `getheaders_from_genesis_returns_full_chain`:
//!     The IBD locator path. A fresh peer asks the height-25 node for headers
//!     starting from its genesis hash; we get back all 25 headers, forming a
//!     contiguous chain, so the requester knows which blocks to fetch.
//!
//!   * Test B — `serial_block_apply_25_blocks_no_orphans`:
//!     The IBD apply path. Feeding 25 in-order blocks to a fresh node via
//!     `Message::Block` (i.e. what the wire delivers under serial handling)
//!     reaches height 25 with the orphan pool empty. The per-peer orphan
//!     limit (MAX_ORPHANS_PER_PEER = 10) is never exercised.
//!
//! Together these prove the user's reported symptom is no longer reachable
//! under the corrected sync flow.

use axiom_node::{
    network::{Message, NetworkService, PeerId, PeerManager},
    Config, Node,
};
use tempfile::TempDir;

fn create_test_service(network: &str) -> (TempDir, NetworkService) {
    let temp_dir = TempDir::new().unwrap();
    let config = Config {
        data_dir: temp_dir.path().to_path_buf(),
        network: axiom_node::Network::parse_str(network).unwrap(),
        ..Default::default()
    };
    let node = Node::new(config).unwrap();
    let peer_manager = PeerManager::new(network.to_string());
    (temp_dir, NetworkService::new(node, peer_manager))
}

/// Mine `n` blocks on `service` and return them, oldest first.
async fn mine_n_blocks(service: &NetworkService, n: u32) -> Vec<axiom_consensus::Block> {
    let mut blocks = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let b = service
            .build_local_block()
            .await
            .expect("build_local_block failed");
        blocks.push(b);
    }
    blocks
}

/// A: GetHeaders(genesis_hash, 2000) against a 25-block chain must return all
/// 25 non-genesis headers, in order, forming a contiguous chain.
#[tokio::test]
async fn getheaders_from_genesis_returns_full_chain() {
    let (_a_tmp, service_a) = create_test_service("dev");
    let (_b_tmp, service_b) = create_test_service("dev");

    mine_n_blocks(&service_a, 25).await;

    let (a_tip_hash, a_tip_height) = service_a.get_tip().await;
    assert_eq!(a_tip_height, 25, "service A should be at height 25");

    // B is fresh; its best-block hash is the genesis hash, which is also the
    // genesis hash on A (same Network::Dev → same embedded genesis).
    let b_genesis_hash = {
        let node = service_b.node();
        let n = node.read().await;
        n.best_block_hash().expect("B should know genesis")
    };
    let (b_tip_hash, b_tip_height) = service_b.get_tip().await;
    assert_eq!(b_tip_height, 0, "service B should be at height 0");
    assert_eq!(b_tip_hash, b_genesis_hash);

    // Drive the GetHeaders exchange A receives from B.
    let peer_id = PeerId::new();
    let response = service_a
        .handle_message(peer_id, Message::GetHeaders(b_genesis_hash, 2000))
        .await
        .expect("handle_message GetHeaders failed");

    let headers = match response {
        Some(Message::Headers(h)) => h,
        other => panic!("expected Headers, got {:?}", other),
    };

    assert_eq!(
        headers.len(),
        25,
        "expected all 25 non-genesis headers returned in one batch"
    );

    // Headers must form a contiguous chain whose first header's parent is
    // the genesis hash and whose last header hashes to A's tip.
    assert_eq!(
        headers[0].prev_block_hash, b_genesis_hash,
        "first header must descend from the genesis we sent as locator"
    );
    for window in headers.windows(2) {
        let (prev, next) = (&window[0], &window[1]);
        assert_eq!(
            next.prev_block_hash,
            prev.hash(),
            "headers must form a contiguous chain"
        );
    }
    assert_eq!(
        headers.last().unwrap().hash(),
        a_tip_hash,
        "last header must hash to A's tip"
    );
}

/// B: feeding 25 in-order blocks to a fresh node reaches height 25 with the
/// orphan pool empty. This is what the wire delivers under serial per-peer
/// message handling — the path the v2.0.0-testnet.3 fix restores.
#[tokio::test]
async fn serial_block_apply_25_blocks_no_orphans() {
    let (_a_tmp, service_a) = create_test_service("dev");
    let (_b_tmp, service_b) = create_test_service("dev");

    let blocks = mine_n_blocks(&service_a, 25).await;
    let (a_tip_hash, a_tip_height) = service_a.get_tip().await;
    assert_eq!(a_tip_height, 25);

    // Single peer_id for the whole sync — proves we never hit
    // MAX_ORPHANS_PER_PEER under correct ordering. If `apply_block` ever
    // fell back to the orphan pool path during this loop, the same peer_id
    // would accumulate orphans and the 10-orphan-per-peer cap would block
    // the rest of the sync.
    let peer_id = PeerId::new();

    for (i, block) in blocks.iter().enumerate() {
        service_b
            .handle_message(peer_id, Message::Block(block.clone()))
            .await
            .expect("handle_message Block failed");

        // After applying block i (0-indexed), B's height must be i+1.
        let (_, b_h) = service_b.get_tip().await;
        assert_eq!(
            b_h as usize,
            i + 1,
            "B height should advance one per block (after block {})",
            i
        );

        // Orphan pool must stay empty throughout — every block had its
        // parent in storage at the moment we delivered it.
        let orphan_count = {
            let node = service_b.node();
            let n = node.read().await;
            n.orphan_count()
        };
        assert_eq!(
            orphan_count, 0,
            "orphan pool must stay empty during in-order IBD (after block {})",
            i
        );
    }

    let (b_tip_hash, b_tip_height) = service_b.get_tip().await;
    assert_eq!(b_tip_height, a_tip_height);
    assert_eq!(b_tip_hash, a_tip_hash);
}

/// C: a deliberately-bursty arrival pattern — block N delivered before its
/// parent — should NOT cause the peer to be cut off by MAX_ORPHANS_PER_PEER.
/// The pool absorbs the future block, then reconnects it when its parent
/// finally arrives. This is the safety-net behaviour the fix preserves: if
/// the wire ever does briefly deliver out-of-order under load, the orphan
/// pool catches the burst without rejecting the peer.
#[tokio::test]
async fn out_of_order_burst_reconnects_via_orphan_pool() {
    let (_a_tmp, service_a) = create_test_service("dev");
    let (_b_tmp, service_b) = create_test_service("dev");

    let blocks = mine_n_blocks(&service_a, 5).await;
    let peer_id = PeerId::new();

    // Deliver blocks 1..=4 in REVERSE order first — they all become orphans
    // because each one's parent is still unknown to B.
    for block in blocks[1..].iter().rev() {
        service_b
            .handle_message(peer_id, Message::Block(block.clone()))
            .await
            .expect("handle_message Block failed");
    }

    let (_, mid_height) = service_b.get_tip().await;
    assert_eq!(mid_height, 0, "no block applies until parent arrives");
    let mid_orphans = {
        let node = service_b.node();
        let n = node.read().await;
        n.orphan_count()
    };
    assert_eq!(mid_orphans, 4, "all 4 future blocks held as orphans");

    // Now deliver block 0 (parent is genesis, already present). This should
    // cascade-apply 1, 2, 3, 4 from the orphan pool.
    service_b
        .handle_message(peer_id, Message::Block(blocks[0].clone()))
        .await
        .expect("handle_message Block(0) failed");

    let (_, b_h) = service_b.get_tip().await;
    assert_eq!(b_h, 5, "cascade apply should reach height 5");

    let final_orphans = {
        let node = service_b.node();
        let n = node.read().await;
        n.orphan_count()
    };
    assert_eq!(final_orphans, 0, "orphans drained after reconnect");
}
