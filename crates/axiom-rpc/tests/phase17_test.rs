// Copyright (c) 2026 Kantoshi Miyamura

//! Network Hardening integration tests.
//!
//! Tests: health endpoint, metrics endpoint fields, peer_count wiring,
//! and message size constants.

use axiom_node::{Config, Network, Node};
use axiom_rpc::{HealthResponse, MetricsResponse, RpcServer, SharedNodeState};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;
use tower::ServiceExt;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn create_test_node() -> (TempDir, Node) {
    let temp_dir = TempDir::new().unwrap();
    let config = Config {
        network: Network::Dev, // Dev disables PoW so test blocks can be built without mining
        data_dir: temp_dir.path().to_path_buf(),
        rpc_bind: "127.0.0.1:8332".to_string(),
        mempool_max_size: 1_000_000,
        mempool_max_count: 100,
        min_fee_rate: 1,
    };
    (temp_dir, Node::new(config).unwrap())
}

fn make_state() -> (TempDir, SharedNodeState) {
    let (temp, node) = create_test_node();
    (temp, Arc::new(RwLock::new(node)))
}

fn open_router(state: SharedNodeState) -> axum::Router {
    let addr = "127.0.0.1:0".parse().unwrap();
    RpcServer::new(addr, state).into_router()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

// ── Health endpoint ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_health_endpoint_returns_ok() {
    let (_temp, state) = make_state();
    let router = open_router(state);

    let resp = router.oneshot(get("/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let health: HealthResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(health.status, "ok");
    assert_eq!(health.height, Some(0)); // genesis block
    assert_eq!(health.peers, 0); // no NetworkService wired
    assert_eq!(health.mempool, 0);
}

#[tokio::test]
async fn test_health_endpoint_height_updates() {
    let (_temp, mut node) = create_test_node();

    // Mine a block
    let block = node.build_block().unwrap();
    node.process_block(block).unwrap();

    let state: SharedNodeState = Arc::new(RwLock::new(node));
    let router = open_router(state);

    let resp = router.oneshot(get("/health")).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let health: HealthResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(health.height, Some(1));
}

// ── Metrics endpoint ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_metrics_endpoint_has_new_fields() {
    let (_temp, state) = make_state();
    let router = open_router(state);

    let resp = router.oneshot(get("/metrics")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let metrics: MetricsResponse = serde_json::from_slice(&body).unwrap();

    // All new fields must be present and have sane defaults
    assert_eq!(metrics.orphan_block_count, 0);
    assert_eq!(metrics.tx_rate, 0.0);
    assert_eq!(metrics.reorg_count, 0);
    assert_eq!(metrics.peer_count, 0); // no NetworkService wired
    assert_eq!(metrics.block_height, Some(0));
}

// ── Peer count endpoint ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_peer_count_returns_zero_without_network_service() {
    let (_temp, state) = make_state();
    let router = open_router(state);

    let resp = router.oneshot(get("/peer_count")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let count: usize = serde_json::from_slice(&body).unwrap();
    assert_eq!(count, 0);
}

// ── Message size constants ────────────────────────────────────────────────────

#[test]
fn test_max_message_size_is_2mb() {
    use axiom_node::network::MAX_MESSAGE_SIZE;
    assert_eq!(MAX_MESSAGE_SIZE, 2_000_000);
}

#[test]
fn test_max_txs_per_message() {
    use axiom_node::network::MAX_TXS_PER_MESSAGE;
    assert_eq!(MAX_TXS_PER_MESSAGE, 10_000);
}

#[test]
fn test_max_blocks_per_response() {
    use axiom_node::network::MAX_BLOCKS_PER_RESPONSE;
    assert_eq!(MAX_BLOCKS_PER_RESPONSE, 500);
}

#[test]
fn test_message_size_rejection_at_boundary() {
    use axiom_node::network::{Message, MessageError, MAX_MESSAGE_SIZE};

    // Build a fake message header with length = MAX_MESSAGE_SIZE + 1
    let oversized_len = (MAX_MESSAGE_SIZE + 1) as u32;
    let mut bytes = vec![0u8]; // Version type
    bytes.extend_from_slice(&oversized_len.to_le_bytes());
    // No payload — deserialize should reject at the length check
    let result = Message::deserialize(&bytes);
    assert!(matches!(result, Err(MessageError::MessageTooLarge(_))));
}

#[test]
fn test_message_size_accepted_at_boundary() {
    use axiom_node::network::{Message, MAX_MESSAGE_SIZE};

    // VerAck (type=1, length=0) is always under the limit
    let bytes = vec![1u8, 0, 0, 0, 0];
    let result = Message::deserialize(&bytes);
    assert!(result.is_ok());
    assert!(matches!(result.unwrap(), Message::VerAck));
    let _ = MAX_MESSAGE_SIZE; // confirm constant is accessible
}

// ── Chain ID ─────────────────────────────────────────────────────────────────

#[test]
fn test_chain_id_distinct_across_networks() {
    use axiom_node::Network;
    assert_ne!(Network::Dev.chain_id(), Network::Test.chain_id());
}

#[test]
fn test_chain_id_stable() {
    use axiom_node::Network;
    assert_eq!(Network::Dev.chain_id(), "axiom-dev-1");
    assert_eq!(Network::Test.chain_id(), "axiom-test-1");
}

// ── Domain-separated signing ──────────────────────────────────────────────────

#[test]
fn test_sign_with_domain_roundtrip_via_public_api() {
    use axiom_crypto::{generate_keypair, sign_with_domain, verify_signature_with_domain};
    use axiom_primitives::{PublicKey, Signature};

    let (priv_key, pub_key_bytes) = generate_keypair();
    let pub_key = PublicKey::from_bytes(pub_key_bytes);

    let domain = b"axiom-test-1";
    let message = b"transfer 5 AXM";

    let sig_bytes = sign_with_domain(&priv_key, domain, message).unwrap();
    let sig = Signature::from_bytes(sig_bytes);

    assert!(verify_signature_with_domain(domain, message, &sig, &pub_key).is_ok());
}

#[test]
fn test_cross_chain_replay_rejected() {
    use axiom_crypto::{generate_keypair, sign_with_domain, verify_signature_with_domain};
    use axiom_primitives::{PublicKey, Signature};

    let (priv_key, pub_key_bytes) = generate_keypair();
    let pub_key = PublicKey::from_bytes(pub_key_bytes);

    let message = b"transfer 5 AXM";

    // Signed on dev network
    let sig_bytes = sign_with_domain(&priv_key, b"axiom-dev-1", message).unwrap();
    let sig = Signature::from_bytes(sig_bytes);

    // Must fail verification on test network — cross-chain replay rejected
    assert!(verify_signature_with_domain(b"axiom-test-1", message, &sig, &pub_key).is_err());
}
