// Copyright (c) 2026 Kantoshi Miyamura

//! Regression tests for the v2.0.0-testnet.4 live-broadcast-during-IBD bug.
//!
//! Symptom in v2.0.0-testnet.4: pull-based IBD started correctly
//! (SYNC_CHECK / SYNC_NEEDED fired, GetHeaders went out), but while the
//! header walk was still working its way toward the peer's tip, every
//! newly-mined block A broadcast via Inv was fetched by B, accepted into
//! the orphan pool (parent missing), and counted against
//! MAX_ORPHANS_PER_PEER. After ~10 such broadcasts B's per-peer orphan
//! cap tripped and IBD stalled at height 0.
//!
//! Root cause: no IBD state machine. handle_inv blindly chased every
//! announced block hash; handle_received_block blindly added every
//! parent-less arrival to the orphan pool. Both paths were appropriate
//! during steady-state but ruinous during catch-up.
//!
//! Fix (v2.0.0-testnet.5): NetworkService now tracks ibd_target_height
//! (the highest tip any peer has claimed). `is_in_ibd()` returns true
//! while `local_height + IBD_SYNC_THRESHOLD < ibd_target_height`. While
//! in IBD:
//!
//!   * `handle_inv` skips Block items — the header-driven path will fetch
//!     them in order.
//!   * `handle_received_block` drops unsolicited blocks (not previously
//!     in `in_flight`) whose parent is missing — same rationale.
//!
//! These tests pin each gate plus the end-to-end transition.

use axiom_node::{
    network::{
        Direction, InvItem, InvItemType, Message, NetworkService, PeerId, PeerManager, PeerState,
        TipMessage,
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

fn make_shared_service(network: &str) -> (TempDir, NetworkService, Arc<PeerManager>) {
    let (tmp, node) = make_node(network);
    let pm = Arc::new(PeerManager::new(network.to_string()));
    let node_arc = Arc::new(RwLock::new(node));
    let svc = NetworkService::with_shared_node(node_arc, pm.clone());
    (tmp, svc, pm)
}

async fn register_ready_peer(
    pm: &PeerManager,
    addr: SocketAddr,
) -> (PeerId, mpsc::UnboundedReceiver<Message>) {
    let peer_id = pm.add_peer(addr, Direction::Inbound).await.unwrap();
    let (tx, rx) = mpsc::unbounded_channel::<Message>();
    pm.set_peer_sender(peer_id, tx).await.unwrap();
    pm.update_peer_state(peer_id, PeerState::Ready)
        .await
        .unwrap();
    (peer_id, rx)
}

/// State A: receiving a Tip(height=1410) at local_height=0 records the
/// target and `is_in_ibd()` flips to true.
#[tokio::test]
async fn tip_from_taller_peer_enters_ibd_state() {
    let (_tmp, service, pm) = make_shared_service("dev");
    let addr: SocketAddr = "127.0.0.1:9101".parse().unwrap();
    let (peer_id, _rx) = register_ready_peer(&pm, addr).await;

    assert!(!service.is_in_ibd().await, "starts outside IBD");
    assert_eq!(service.ibd_target().await, 0);

    service
        .handle_message(
            peer_id,
            Message::Tip(TipMessage {
                best_hash: Hash256::zero(),
                best_height: 1410,
            }),
        )
        .await
        .unwrap();

    assert_eq!(service.ibd_target().await, 1410, "target recorded");
    assert!(service.is_in_ibd().await, "now in IBD");
}

/// State A→B: while in IBD, Inv announcements for new blocks are dropped
/// — no GetData goes out. This is the gate that the user's testnet.4
/// log showed missing (TRANSPORT_BLOCK_RECEIVE height=1428 during sync).
#[tokio::test]
async fn inv_for_block_is_suppressed_during_ibd() {
    let (_tmp, service, pm) = make_shared_service("dev");
    let addr: SocketAddr = "127.0.0.1:9102".parse().unwrap();
    let (peer_id, mut rx) = register_ready_peer(&pm, addr).await;

    // Enter IBD: peer claims height 100, we're at 0.
    service
        .handle_message(
            peer_id,
            Message::Tip(TipMessage {
                best_hash: Hash256::zero(),
                best_height: 100,
            }),
        )
        .await
        .unwrap();
    assert!(service.is_in_ibd().await);
    // Drain the GetHeaders that sync_with_peer emitted so the next try_recv
    // is unambiguous.
    let drained = rx.try_recv().expect("expected GetHeaders on sync init");
    assert!(matches!(drained, Message::GetHeaders(_, _)));

    let live_block_hash = {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xDE;
        bytes[1] = 0xAD;
        Hash256::from_bytes(bytes)
    };
    service
        .handle_message(
            peer_id,
            Message::Inv(vec![InvItem {
                item_type: InvItemType::Block,
                hash: live_block_hash,
            }]),
        )
        .await
        .unwrap();

    // No GetData arrived — Inv was suppressed.
    assert!(
        rx.try_recv().is_err(),
        "Inv-driven GetData must NOT be sent during IBD — header walk handles catch-up"
    );
}

/// State A→B: an unsolicited Block (parent missing, not in in_flight)
/// delivered during IBD is silently dropped — does NOT land in the
/// orphan pool. This is the second of the two gates.
#[tokio::test]
async fn unsolicited_orphan_block_is_dropped_during_ibd() {
    let (_tmp_miner, miner, _miner_pm) = make_shared_service("dev");
    // Mine a couple of blocks so we have a block whose parent is NOT the
    // genesis our fresh service knows about. block_a has prev = genesis;
    // block_b has prev = block_a. block_b's parent is unknown to a fresh
    // node, so it would otherwise become an orphan.
    let _block_a = miner.build_local_block().await.unwrap();
    let block_b = miner.build_local_block().await.unwrap();
    drop(miner);

    let (_tmp, service, pm) = make_shared_service("dev");
    let addr: SocketAddr = "127.0.0.1:9103".parse().unwrap();
    let (peer_id, _rx) = register_ready_peer(&pm, addr).await;

    // Enter IBD.
    service
        .handle_message(
            peer_id,
            Message::Tip(TipMessage {
                best_hash: Hash256::zero(),
                best_height: 200,
            }),
        )
        .await
        .unwrap();
    assert!(service.is_in_ibd().await);

    // Deliver block_b unsolicited (not in in_flight). Parent (block_a)
    // is unknown to this service.
    service
        .handle_message(peer_id, Message::Block(block_b.clone()))
        .await
        .unwrap();

    let orphan_count = {
        let node = service.node();
        let n = node.read().await;
        n.orphan_count()
    };
    assert_eq!(
        orphan_count, 0,
        "unsolicited orphan during IBD must be silently dropped, not added to pool"
    );
    let (_, h) = service.get_tip().await;
    assert_eq!(h, 0, "no spurious height advance");
}

/// State A→B exit: when local height catches up to within
/// IBD_SYNC_THRESHOLD of the target, `is_in_ibd()` returns false and
/// the gates re-open.
#[tokio::test]
async fn ibd_exits_when_local_catches_up_to_target() {
    let (_tmp_miner, miner, _miner_pm) = make_shared_service("dev");
    let blocks = {
        let mut v = Vec::new();
        for _ in 0..20 {
            v.push(miner.build_local_block().await.unwrap());
        }
        v
    };
    drop(miner);

    let (_tmp, service, pm) = make_shared_service("dev");
    let addr: SocketAddr = "127.0.0.1:9104".parse().unwrap();
    let (peer_id, mut rx) = register_ready_peer(&pm, addr).await;

    // Enter IBD with target=20.
    service
        .handle_message(
            peer_id,
            Message::Tip(TipMessage {
                best_hash: blocks.last().unwrap().hash(),
                best_height: 20,
            }),
        )
        .await
        .unwrap();
    assert!(service.is_in_ibd().await, "in IBD with target=20, local=0");
    // Drain the GetHeaders so the next try_recv is unambiguous.
    let _ = rx.try_recv().unwrap();

    // Simulate IBD progress: apply blocks 1..=11 in order. After block 11
    // we are at local=11; with target=20 and IBD_SYNC_THRESHOLD=8 the
    // gate condition is `local + 8 < target` → `19 < 20` → still in IBD.
    for b in &blocks[..11] {
        service
            .handle_message(peer_id, Message::Block(b.clone()))
            .await
            .unwrap();
    }
    let (_, h) = service.get_tip().await;
    assert_eq!(h, 11);
    assert!(
        service.is_in_ibd().await,
        "still in IBD at local=11 target=20 (band = 8)"
    );

    // Apply one more block — local=12; condition is `12 + 8 < 20` → `20 <
    // 20` → false → exit IBD.
    service
        .handle_message(peer_id, Message::Block(blocks[11].clone()))
        .await
        .unwrap();
    assert!(
        !service.is_in_ibd().await,
        "exited IBD at local=12, target=20 (threshold = 8)",
    );

    // The Inv gate is now open: an announcement triggers GetData.
    let unknown_hash = {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xBE;
        bytes[1] = 0xEF;
        Hash256::from_bytes(bytes)
    };
    service
        .handle_message(
            peer_id,
            Message::Inv(vec![InvItem {
                item_type: InvItemType::Block,
                hash: unknown_hash,
            }]),
        )
        .await
        .unwrap();

    let sent = rx.try_recv().expect("Inv gate must re-open after IBD exit");
    match sent {
        Message::GetData(items) => assert_eq!(items[0].hash, unknown_hash),
        other => panic!("expected GetData, got {:?}", other),
    }
}

/// End-to-end: A continues mining throughout B's IBD; B catches up
/// without filling the orphan pool. Mirrors the field repro exactly:
/// fresh B at h=0, A taller and still mining, no orphan-cap trip.
#[tokio::test]
async fn end_to_end_ibd_with_concurrent_mining_no_orphan_overflow() {
    // Miner produces an "initial" chain of 20 blocks plus an extra 5 we
    // simulate as arriving via Inv during B's catch-up.
    let (_tmp_miner, miner, _miner_pm) = make_shared_service("dev");
    let mut all_blocks = Vec::new();
    for _ in 0..25 {
        all_blocks.push(miner.build_local_block().await.unwrap());
    }
    let initial_blocks = &all_blocks[..20];
    let live_blocks = &all_blocks[20..];
    let final_tip_hash = all_blocks.last().unwrap().hash();
    drop(miner);

    let (_tmp_b, service_b, pm_b) = make_shared_service("dev");
    let peer_addr: SocketAddr = "127.0.0.1:9105".parse().unwrap();
    let (peer_id, _rx) = register_ready_peer(&pm_b, peer_addr).await;

    // B learns A's tip (20) and enters IBD.
    service_b
        .handle_message(
            peer_id,
            Message::Tip(TipMessage {
                best_hash: initial_blocks.last().unwrap().hash(),
                best_height: 20,
            }),
        )
        .await
        .unwrap();
    assert!(service_b.is_in_ibd().await);

    // Mid-IBD, A "broadcasts" Invs for the 5 new tip blocks. Under the
    // broken testnet.4 behaviour B would have chased these and orphaned
    // every one. Under the fix they are suppressed.
    for b in live_blocks {
        let inv = InvItem {
            item_type: InvItemType::Block,
            hash: b.hash(),
        };
        service_b
            .handle_message(peer_id, Message::Inv(vec![inv]))
            .await
            .unwrap();
    }
    let mid_orphans = {
        let node = service_b.node();
        let n = node.read().await;
        n.orphan_count()
    };
    assert_eq!(
        mid_orphans, 0,
        "live-tip Invs during IBD must not produce orphans (got {})",
        mid_orphans
    );

    // Header-driven IBD delivers the initial 20 blocks in order.
    for b in initial_blocks {
        service_b
            .handle_message(peer_id, Message::Block(b.clone()))
            .await
            .unwrap();
    }
    let (_, after_initial) = service_b.get_tip().await;
    assert_eq!(after_initial, 20);
    // We're now at local=20, target=20 — within threshold, so IBD exits.
    assert!(!service_b.is_in_ibd().await);

    // A re-announces the 5 new tip blocks. Each one is now applied in
    // order through the normal Inv→GetData→Block flow — modelled here
    // by feeding the blocks directly since this test focuses on the
    // gate behaviour, not the GetData round-trip.
    for b in live_blocks {
        service_b
            .handle_message(peer_id, Message::Block(b.clone()))
            .await
            .unwrap();
    }
    let (final_hash, final_h) = service_b.get_tip().await;
    assert_eq!(final_h, 25);
    assert_eq!(final_hash, final_tip_hash);

    let final_orphans = {
        let node = service_b.node();
        let n = node.read().await;
        n.orphan_count()
    };
    assert_eq!(
        final_orphans, 0,
        "orphan pool must be empty at end of catch-up"
    );
}
