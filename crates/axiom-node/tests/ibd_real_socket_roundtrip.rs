// Copyright (c) 2026 Kantoshi Miyamura

//! Real-TCP loopback integration test for the GetTip → Tip → GetHeaders →
//! Headers → GetData → Block round-trip that powers IBD.
//!
//! v2.0.0-testnet.5 live two-node test reported: SYNC_NEEDED fires but
//! HEADERS_RECEIVED, HEADERS_REQUEST_BLOCKS and BLOCK_APPLIED never
//! follow. The wire-level dispatch is suspect.
//!
//! This test stands up two NetworkService instances and connects them
//! through real loopback TCP sockets, then mirrors the axiom-cli p2p
//! peer loop in a stripped-down form: handshake, an outbound mpsc
//! forwarder per side, and a serial inbound reader that dispatches via
//! `handle_message` and writes any synchronous response back to the
//! socket. If the IBD wire dance is structurally broken, this test
//! reproduces it. If it isn't, the test demonstrates the round-trip
//! works end-to-end through the actual Transport.
//!
//! Test:
//!   * `ibd_full_roundtrip_via_real_tcp_loopback` — A mines 20 blocks,
//!     B connects fresh, B sends GetTip, the full pull-IBD runs over
//!     real sockets, B reaches height 20, orphan_count = 0 throughout.

use axiom_node::{
    network::{Connection, Direction, Message, NetworkService, PeerId, PeerManager, Transport},
    Config, Node,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, timeout};

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

fn make_service(network: &str) -> (TempDir, Arc<NetworkService>, Arc<PeerManager>) {
    let (tmp, node) = make_node(network);
    let pm = Arc::new(PeerManager::new(network.to_string()));
    let node_arc = Arc::new(RwLock::new(node));
    let svc = Arc::new(NetworkService::with_shared_node(node_arc, pm.clone()));
    (tmp, svc, pm)
}

/// Run the peer-side message dance for the lifetime of the connection.
/// Mirrors axiom-cli/src/p2p.rs::handle_connection in a stripped-down form
/// (no discovery, no reconnect, no logging mismatch): handshake, an
/// outbound mpsc forwarder, and a serial inbound reader that dispatches
/// via `handle_message` and writes synchronous responses back.
async fn run_peer_loop(
    mut connection: Connection,
    peer_id: PeerId,
    service: Arc<NetworkService>,
    peer_manager: Arc<PeerManager>,
    our_height: u32,
    initial_get_tip: bool,
) {
    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Message>();
    peer_manager
        .set_peer_sender(peer_id, outbound_tx)
        .await
        .expect("set_peer_sender");

    // Send Version.
    let version = peer_manager.create_version(our_height);
    connection.send(&version).await.expect("send version");

    let writer = connection.clone_writer();
    let outbound_handle = tokio::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            if writer.send(&message).await.is_err() {
                break;
            }
        }
    });

    loop {
        let msg = match connection.receive().await {
            Ok(m) => m,
            Err(_) => break,
        };

        if matches!(msg, Message::Version(_) | Message::VerAck) {
            match peer_manager.process_handshake(peer_id, &msg).await {
                Ok(Some(response)) => {
                    if connection.send(&response).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    if matches!(msg, Message::VerAck) && initial_get_tip {
                        // The B-side test driver kicks the sync off explicitly
                        // by asking for the peer's tip — same trigger
                        // axiom-cli/src/p2p.rs installs on HANDSHAKE_COMPLETE.
                        let _ = peer_manager.send_to_peer(peer_id, Message::GetTip).await;
                    }
                }
                Err(_) => break,
            }
            continue;
        }

        let result = service.handle_message(peer_id, msg).await;
        match result {
            Ok(Some(resp)) => {
                if connection.clone_writer().send(&resp).await.is_err() {
                    break;
                }
            }
            Ok(None) => {}
            Err(_) => {}
        }
    }

    outbound_handle.abort();
    peer_manager.remove_peer(peer_id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ibd_full_roundtrip_via_real_tcp_loopback() {
    // Build service A and mine 20 blocks before any peer connects.
    let (_tmp_a, service_a, pm_a) = make_service("dev");
    for _ in 0..20 {
        service_a.build_local_block().await.expect("mine block");
    }
    let (a_tip_hash, a_tip_height) = service_a.get_tip().await;
    assert_eq!(a_tip_height, 20);

    // Build service B, fresh at height 0.
    let (_tmp_b, service_b, pm_b) = make_service("dev");
    let (_, b_initial_height) = service_b.get_tip().await;
    assert_eq!(b_initial_height, 0);

    // Real TCP listener on loopback for A's inbound side.
    let mut a_transport = Transport::new();
    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    a_transport.bind(listen_addr).await.expect("bind");

    // Need a TcpListener whose bound address we can read — Transport hides
    // it. Use a separate listener to grab a free port deterministically.
    let probe_listener = tokio::net::TcpListener::bind(listen_addr).await.unwrap();
    let actual_addr = probe_listener.local_addr().unwrap();
    drop(probe_listener);
    // Re-bind Transport on the resolved port.
    let mut a_transport = Transport::new();
    a_transport.bind(actual_addr).await.expect("bind");

    // Spawn A's accept loop.
    let a_svc = service_a.clone();
    let a_pm = pm_a.clone();
    let a_accept = tokio::spawn(async move {
        let conn = a_transport.accept().await.expect("accept");
        let addr = conn.addr();
        let peer_id = a_pm.add_peer(addr, Direction::Inbound).await.expect("add");
        run_peer_loop(conn, peer_id, a_svc, a_pm, a_tip_height, false).await;
    });

    // B dials A.
    let conn = Transport::connect(actual_addr).await.expect("connect");
    let b_pm_for_loop = pm_b.clone();
    let peer_id_on_b = pm_b
        .add_peer(actual_addr, Direction::Outbound)
        .await
        .expect("add outbound");
    let b_svc = service_b.clone();
    let b_loop = tokio::spawn(async move {
        run_peer_loop(conn, peer_id_on_b, b_svc, b_pm_for_loop, 0, true).await;
    });

    // Wait for B to catch up. With 20 blocks at ~120 bytes each over
    // loopback, the round-trip should complete inside a second; give a
    // generous 10-second budget to cover slow CI.
    let caught_up = timeout(Duration::from_secs(10), async {
        loop {
            let (h_hash, h) = service_b.get_tip().await;
            if h == a_tip_height && h_hash == a_tip_hash {
                return true;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    let (final_hash, final_height) = service_b.get_tip().await;
    let orphans = {
        let node = service_b.node();
        let n = node.read().await;
        n.orphan_count()
    };

    // Tear down both sides.
    b_loop.abort();
    a_accept.abort();

    assert!(
        caught_up.is_ok(),
        "IBD did not complete within 10s — got to height {} (target {}), orphans={}",
        final_height,
        a_tip_height,
        orphans,
    );
    assert_eq!(final_height, a_tip_height);
    assert_eq!(final_hash, a_tip_hash);
    assert_eq!(orphans, 0, "orphan pool must be empty after clean IBD");
}

/// Production reproducer: A mines new blocks AND broadcasts each one via
/// `peer_manager.broadcast(Message::Block(...))` while B is still in IBD.
/// The IBD gate must drop those live broadcasts as unsolicited orphans,
/// and the header-driven catch-up must still reach the (now-moving)
/// target. This mirrors the field setup where A's mining loop on
/// axiom-cli/src/main.rs:975 keeps pushing tip blocks at B.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ibd_completes_while_peer_concurrently_mines_and_broadcasts() {
    let (_tmp_a, service_a, pm_a) = make_service("dev");
    for _ in 0..20 {
        service_a.build_local_block().await.expect("initial mine");
    }
    let (_, initial_height) = service_a.get_tip().await;
    assert_eq!(initial_height, 20);

    let (_tmp_b, service_b, pm_b) = make_service("dev");

    // Pick a free loopback port deterministically (probe-and-drop, then bind).
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let actual_addr = probe.local_addr().unwrap();
    drop(probe);
    let mut a_transport = Transport::new();
    a_transport.bind(actual_addr).await.expect("bind");

    let a_svc = service_a.clone();
    let a_pm = pm_a.clone();
    let a_accept = tokio::spawn(async move {
        let conn = a_transport.accept().await.expect("accept");
        let addr = conn.addr();
        let peer_id = a_pm.add_peer(addr, Direction::Inbound).await.expect("add");
        run_peer_loop(conn, peer_id, a_svc, a_pm, initial_height, false).await;
    });

    let conn = Transport::connect(actual_addr).await.expect("connect");
    let peer_id_on_b = pm_b
        .add_peer(actual_addr, Direction::Outbound)
        .await
        .expect("add outbound");
    let b_svc = service_b.clone();
    let b_pm_for_loop = pm_b.clone();
    let b_loop = tokio::spawn(async move {
        run_peer_loop(conn, peer_id_on_b, b_svc, b_pm_for_loop, 0, true).await;
    });

    // Concurrent miner on A: every 200 ms mine a block and broadcast it
    // as Message::Block to all peers — same call axiom-cli/src/main.rs
    // makes in its mining loop. Cap at 10 extra blocks (target 30 total).
    let a_miner_svc = service_a.clone();
    let a_miner_pm = pm_a.clone();
    let miner_handle = tokio::spawn(async move {
        for _ in 0..10 {
            sleep(Duration::from_millis(200)).await;
            let block = match a_miner_svc.build_local_block().await {
                Ok(b) => b,
                Err(_) => continue,
            };
            let _ = a_miner_pm.broadcast(Message::Block(block)).await;
        }
    });

    // Give A's miner enough wall-clock to ship its 10 blocks (2 s) plus
    // generous IBD slack. Wait until B reaches A's CURRENT tip — which is
    // a moving target throughout the test.
    let caught_up = timeout(Duration::from_secs(20), async {
        loop {
            let (_, b_h) = service_b.get_tip().await;
            let (_, a_h) = service_a.get_tip().await;
            // Miner is done once we've produced 30 blocks; wait for B to
            // reach A's current tip after the miner stops moving it.
            if b_h == a_h && a_h >= 30 {
                return true;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await;

    let (b_final_hash, b_final_height) = service_b.get_tip().await;
    let (a_final_hash, a_final_height) = service_a.get_tip().await;
    let orphans = {
        let node = service_b.node();
        let n = node.read().await;
        n.orphan_count()
    };

    miner_handle.abort();
    b_loop.abort();
    a_accept.abort();

    assert!(
        caught_up.is_ok(),
        "B did not catch up within 20s: b_height={} a_height={} orphans={}",
        b_final_height,
        a_final_height,
        orphans,
    );
    assert_eq!(b_final_height, a_final_height);
    assert_eq!(b_final_hash, a_final_hash);
    // Orphans should be low — the IBD gate suppresses live broadcasts, and
    // the per-peer cap is 10. Any value ≤ a few is acceptable; the field
    // failure mode was unbounded growth and ORPHAN_REJECTED tripping.
    assert!(
        orphans <= 3,
        "orphan pool ballooned during concurrent mining: {}",
        orphans
    );
}
