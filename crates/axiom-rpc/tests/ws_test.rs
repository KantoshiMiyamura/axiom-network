// Copyright (c) 2026 Kantoshi Miyamura

//! Integration tests for the WebSocket subscription endpoint (`GET /ws`).
//!
//! These tests spin up a real TCP listener and connect with a
//! tokio-tungstenite client to verify end-to-end event delivery.

use axiom_node::{Config, Network, Node};
use axiom_rpc::{BlockSummary, RpcServer, WsEvent, WsTxEvent};
use futures_util::StreamExt;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

/// Helper: start RPC server on a random port, return (addr, event_bus).
async fn start_test_server() -> (std::net::SocketAddr, axiom_rpc::EventBus, TempDir) {
    let temp = TempDir::new().unwrap();
    let config = Config {
        network: Network::Dev,
        data_dir: temp.path().to_path_buf(),
        rpc_bind: "127.0.0.1:0".to_string(),
        mempool_max_size: 1_000_000,
        mempool_max_count: 1_000,
        min_fee_rate: 1,
    };
    let node = Node::new(config).unwrap();
    let state = Arc::new(RwLock::new(node));

    // Bind on port 0 so the OS assigns a free port.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = RpcServer::new(addr, state);
    let bus = server.event_bus();

    tokio::spawn(async move {
        let app = server.into_router();
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    // Give the server a moment to start.
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    (addr, bus, temp)
}

fn make_block_summary(height: u32) -> BlockSummary {
    BlockSummary {
        hash: "aa".repeat(32),
        height,
        timestamp: 1_700_000_000 + height,
        prev_block_hash: "bb".repeat(32),
        merkle_root: "cc".repeat(32),
        nonce: height as u64,
        difficulty: 0x1d00_ffff,
        transaction_count: 1,
    }
}

fn make_tx_event() -> WsTxEvent {
    WsTxEvent {
        txid: "dd".repeat(32),
        input_count: 1,
        output_count: 2,
        total_output: 50_000_000_000,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_ws_endpoint_accepts_upgrade() {
    let (addr, _bus, _temp) = start_test_server().await;
    let url = format!("ws://{}/ws", addr);

    let (_, response) = connect_async(&url).await.expect("WS handshake failed");
    assert_eq!(response.status(), 101);
}

#[tokio::test]
async fn test_ws_receives_new_block_event() {
    let (addr, bus, _temp) = start_test_server().await;
    let url = format!("ws://{}/ws", addr);

    let (ws_stream, _) = connect_async(&url).await.unwrap();
    let (_, mut read) = ws_stream.split();

    // Allow a moment for the subscription to register.
    tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;

    let _ = bus.send(WsEvent::NewBlock(make_block_summary(100)));

    let msg = tokio::time::timeout(tokio::time::Duration::from_secs(2), read.next())
        .await
        .expect("timed out waiting for WS message")
        .unwrap()
        .unwrap();

    let text = match msg {
        Message::Text(t) => t,
        other => panic!("expected text frame, got {:?}", other),
    };

    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["type"], "new_block");
    assert_eq!(parsed["data"]["height"], 100);
}

#[tokio::test]
async fn test_ws_receives_new_tx_event() {
    let (addr, bus, _temp) = start_test_server().await;
    let url = format!("ws://{}/ws", addr);

    let (ws_stream, _) = connect_async(&url).await.unwrap();
    let (_, mut read) = ws_stream.split();

    tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;

    let _ = bus.send(WsEvent::NewTx(make_tx_event()));

    let msg = tokio::time::timeout(tokio::time::Duration::from_secs(2), read.next())
        .await
        .expect("timed out")
        .unwrap()
        .unwrap();

    let text = match msg {
        Message::Text(t) => t,
        other => panic!("expected text frame, got {:?}", other),
    };

    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["type"], "new_tx");
    assert_eq!(parsed["data"]["input_count"], 1);
    assert_eq!(parsed["data"]["output_count"], 2);
    assert_eq!(parsed["data"]["total_output"], 50_000_000_000u64);
}

#[tokio::test]
async fn test_ws_multiple_clients_each_receive_event() {
    let (addr, bus, _temp) = start_test_server().await;
    let url = format!("ws://{}/ws", addr);

    let (ws1, _) = connect_async(&url).await.unwrap();
    let (ws2, _) = connect_async(&url).await.unwrap();

    let (_, mut read1) = ws1.split();
    let (_, mut read2) = ws2.split();

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let _ = bus.send(WsEvent::NewBlock(make_block_summary(42)));

    let recv1 = tokio::time::timeout(tokio::time::Duration::from_secs(2), read1.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let recv2 = tokio::time::timeout(tokio::time::Duration::from_secs(2), read2.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    for msg in [recv1, recv2] {
        let text = match msg {
            Message::Text(t) => t,
            other => panic!("expected text, got {:?}", other),
        };
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["type"], "new_block");
        assert_eq!(v["data"]["height"], 42);
    }
}

#[tokio::test]
async fn test_ws_receives_multiple_events_in_order() {
    let (addr, bus, _temp) = start_test_server().await;
    let url = format!("ws://{}/ws", addr);

    let (ws, _) = connect_async(&url).await.unwrap();
    let (_, mut read) = ws.split();

    tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;

    // Send block then tx.
    let _ = bus.send(WsEvent::NewBlock(make_block_summary(1)));
    let _ = bus.send(WsEvent::NewTx(make_tx_event()));

    let msg1 = tokio::time::timeout(tokio::time::Duration::from_secs(2), read.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let msg2 = tokio::time::timeout(tokio::time::Duration::from_secs(2), read.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let text1 = match msg1 {
        Message::Text(t) => t,
        _ => panic!(),
    };
    let text2 = match msg2 {
        Message::Text(t) => t,
        _ => panic!(),
    };

    let v1: serde_json::Value = serde_json::from_str(&text1).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&text2).unwrap();

    assert_eq!(v1["type"], "new_block");
    assert_eq!(v2["type"], "new_tx");
}

#[tokio::test]
async fn test_ws_event_bus_method_on_server() {
    // Verify RpcServer::event_bus() returns a usable bus (unit-level).
    let temp = TempDir::new().unwrap();
    let config = Config {
        network: Network::Dev,
        data_dir: temp.path().to_path_buf(),
        rpc_bind: "127.0.0.1:0".to_string(),
        mempool_max_size: 1_000_000,
        mempool_max_count: 1_000,
        min_fee_rate: 1,
    };
    let node = Node::new(config).unwrap();
    let state = Arc::new(RwLock::new(node));
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = RpcServer::new(addr, state);
    let bus = server.event_bus();

    // No subscribers — send returns Err, which is expected.
    let result = bus.send(WsEvent::NewBlock(make_block_summary(0)));
    assert!(result.is_err());

    // Subscribe then send.
    let mut rx = bus.subscribe();
    let _ = bus.send(WsEvent::NewBlock(make_block_summary(7)));
    let ev = rx.recv().await.unwrap();
    assert!(matches!(ev, WsEvent::NewBlock(b) if b.height == 7));
}
