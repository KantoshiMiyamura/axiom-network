// Copyright (c) 2026 Kantoshi Miyamura

//! Integration tests for the axiom-ai RPC endpoints (Phase AI-1/2/3).
//!
//! Tests run against a real in-process router with real fjall-backed registries
//! so we exercise the full serialization / HTTP / storage round-trip without
//! hitting the network.

use axiom_ai::{InferenceRegistry, ModelRegistry, ReputationRegistry};
use axiom_node::{Config, Network, Node};
use axiom_rpc::{RpcServer, SharedNodeState};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;
use tower::ServiceExt;

// ── Constants ─────────────────────────────────────────────────────────────────

const MODEL_HASH: &str = "a3f1e2d4b5c6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
const REQUESTER: &str = "axm1requester0000000000000000000000000000";
const PROVIDER: &str = "axm1provider00000000000000000000000000000";
const RESULT: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_node(tmp: &TempDir) -> Node {
    let config = Config {
        network: Network::Dev,
        data_dir: tmp.path().to_path_buf(),
        rpc_bind: "127.0.0.1:0".to_string(),
        mempool_max_size: 1_000_000,
        mempool_max_count: 100,
        min_fee_rate: 1,
    };
    Node::new(config).unwrap()
}

struct TestRouter {
    router: axum::Router,
    _tmp: TempDir,
    model_reg: Arc<ModelRegistry>,
    inference_reg: Arc<InferenceRegistry>,
    reputation_reg: Arc<ReputationRegistry>,
}

fn open_router() -> TestRouter {
    let tmp = TempDir::new().unwrap();
    let node = make_node(&tmp);
    let state: SharedNodeState = Arc::new(RwLock::new(node));

    let model_reg = Arc::new(ModelRegistry::open(tmp.path()).unwrap());
    let inference_reg = Arc::new(InferenceRegistry::open(tmp.path()).unwrap());
    let reputation_reg = Arc::new(ReputationRegistry::open(tmp.path()).unwrap());

    let addr = "127.0.0.1:0".parse().unwrap();
    let router = RpcServer::new(addr, state)
        .with_model_registry(model_reg.clone())
        .with_inference_registry(inference_reg.clone())
        .with_reputation_registry(reputation_reg.clone())
        .into_router();

    TestRouter {
        router,
        _tmp: tmp,
        model_reg,
        inference_reg,
        reputation_reg,
    }
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ── Phase AI-1: Model Registry ────────────────────────────────────────────────

#[tokio::test]
async fn test_ai_register_model_201() {
    let t = open_router();
    let resp = t.router.oneshot(post_json(
        "/ai/model/register",
        &format!(r#"{{"model_hash":"{MODEL_HASH}","name":"TestLM","version":"1.0.0","description":"test","registered_by":"{REQUESTER}"}}"#),
    )).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["model_hash"], MODEL_HASH);
    assert_eq!(v["name"], "TestLM");
}

#[tokio::test]
async fn test_ai_register_model_duplicate_rejected() {
    let t = open_router();
    let body = format!(
        r#"{{"model_hash":"{MODEL_HASH}","name":"TestLM","version":"1.0.0","description":"test","registered_by":"{REQUESTER}"}}"#
    );

    // First registration succeeds
    let r1 = t
        .router
        .clone()
        .oneshot(post_json("/ai/model/register", &body))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);

    // Second is a duplicate — must be rejected
    let r2 = t
        .router
        .oneshot(post_json("/ai/model/register", &body))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_ai_get_model_found() {
    let t = open_router();
    t.model_reg
        .register(axiom_ai::ModelRecord {
            model_hash: MODEL_HASH.into(),
            name: "M".into(),
            version: "1.0".into(),
            description: "d".into(),
            registered_by: REQUESTER.into(),
            registered_at: 0,
        })
        .unwrap();

    let resp = t
        .router
        .oneshot(get(&format!("/ai/model/{MODEL_HASH}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["model_hash"], MODEL_HASH);
}

#[tokio::test]
async fn test_ai_get_model_not_found() {
    let t = open_router();
    let hash = "b".repeat(64);
    let resp = t
        .router
        .oneshot(get(&format!("/ai/model/{hash}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_ai_list_recent_models_empty() {
    let t = open_router();
    let resp = t.router.oneshot(get("/ai/models/recent")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert!(v.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_ai_list_recent_models_returns_registered() {
    let t = open_router();
    t.model_reg
        .register(axiom_ai::ModelRecord {
            model_hash: MODEL_HASH.into(),
            name: "M".into(),
            version: "1.0".into(),
            description: "d".into(),
            registered_by: REQUESTER.into(),
            registered_at: 0,
        })
        .unwrap();

    let resp = t.router.oneshot(get("/ai/models/recent")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v.as_array().unwrap().len(), 1);
}

// ── Phase AI-2: Inference Payments ────────────────────────────────────────────

#[tokio::test]
async fn test_ai_request_inference_creates_pending_job() {
    let t = open_router();
    // Model must be registered first
    t.model_reg
        .register(axiom_ai::ModelRecord {
            model_hash: MODEL_HASH.into(),
            name: "M".into(),
            version: "1.0".into(),
            description: "d".into(),
            registered_by: REQUESTER.into(),
            registered_at: 0,
        })
        .unwrap();

    let resp = t.router.oneshot(post_json(
        "/ai/inference/request",
        &format!(r#"{{"model_hash":"{MODEL_HASH}","requester":"{REQUESTER}","provider":"{PROVIDER}","amount_sat":500000}}"#),
    )).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["status"], "Pending");
    assert_eq!(v["amount_sat"], 500_000);
    assert!(v["result_hash"].is_null());
}

#[tokio::test]
async fn test_ai_get_inference_job() {
    let t = open_router();
    let job = t
        .inference_reg
        .create_job(MODEL_HASH.into(), REQUESTER.into(), PROVIDER.into(), 1_000)
        .unwrap();

    let resp = t
        .router
        .oneshot(get(&format!("/ai/inference/{}", job.job_id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["job_id"], job.job_id);
    assert_eq!(v["status"], "Pending");
}

#[tokio::test]
async fn test_ai_get_inference_job_not_found() {
    let t = open_router();
    let resp = t
        .router
        .oneshot(get(&format!("/ai/inference/{}", "0".repeat(64))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_ai_complete_inference_job() {
    let t = open_router();
    let job = t
        .inference_reg
        .create_job(MODEL_HASH.into(), REQUESTER.into(), PROVIDER.into(), 0)
        .unwrap();

    let resp = t
        .router
        .clone()
        .oneshot(post_json(
            "/ai/inference/complete",
            &format!(r#"{{"job_id":"{}","result_hash":"{RESULT}"}}"#, job.job_id),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["status"], "Completed");
    assert_eq!(v["result_hash"], RESULT);
    assert!(!v["completed_at"].is_null());
}

#[tokio::test]
async fn test_ai_complete_increments_reputation_completions() {
    let t = open_router();
    let job = t
        .inference_reg
        .create_job(MODEL_HASH.into(), REQUESTER.into(), PROVIDER.into(), 0)
        .unwrap();

    t.router
        .oneshot(post_json(
            "/ai/inference/complete",
            &format!(r#"{{"job_id":"{}","result_hash":"{RESULT}"}}"#, job.job_id),
        ))
        .await
        .unwrap();

    // The coupling fix: completions must be 1 after complete_job
    let score = t.reputation_reg.get_score(MODEL_HASH).unwrap();
    assert_eq!(
        score.completions, 1,
        "record_completion must be called on job completion"
    );
}

#[tokio::test]
async fn test_ai_cancel_inference_job() {
    let t = open_router();
    let job = t
        .inference_reg
        .create_job(MODEL_HASH.into(), REQUESTER.into(), PROVIDER.into(), 0)
        .unwrap();

    let resp = t
        .router
        .oneshot(post_json(
            "/ai/inference/cancel",
            &format!(r#"{{"job_id":"{}"}}"#, job.job_id),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["status"], "Cancelled");
}

#[tokio::test]
async fn test_ai_complete_already_completed_returns_error() {
    let t = open_router();
    let job = t
        .inference_reg
        .create_job(MODEL_HASH.into(), REQUESTER.into(), PROVIDER.into(), 0)
        .unwrap();
    t.inference_reg
        .complete_job(&job.job_id, RESULT.into())
        .unwrap();

    let resp = t
        .router
        .oneshot(post_json(
            "/ai/inference/complete",
            &format!(r#"{{"job_id":"{}","result_hash":"{RESULT}"}}"#, job.job_id),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_ai_list_jobs_for_address() {
    let t = open_router();
    t.inference_reg
        .create_job(MODEL_HASH.into(), REQUESTER.into(), PROVIDER.into(), 0)
        .unwrap();
    t.inference_reg
        .create_job(MODEL_HASH.into(), REQUESTER.into(), PROVIDER.into(), 0)
        .unwrap();
    // Unrelated job
    t.inference_reg
        .create_job(MODEL_HASH.into(), "other".into(), "other".into(), 0)
        .unwrap();

    let resp = t
        .router
        .oneshot(get(&format!("/ai/inference/jobs/{REQUESTER}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v.as_array().unwrap().len(), 2);
}

// ── Phase AI-3: Reputation & Stake ───────────────────────────────────────────

#[tokio::test]
async fn test_ai_rate_model() {
    let t = open_router();
    let resp = t
        .router
        .oneshot(post_json(
            &format!("/ai/reputation/{MODEL_HASH}/rate"),
            r#"{"rating":5}"#,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["total_ratings"], 1);
    assert_eq!(v["avg_rating"], 5.0);
}

#[tokio::test]
async fn test_ai_rate_model_invalid_rating_rejected() {
    let t = open_router();
    let resp = t
        .router
        .oneshot(post_json(
            &format!("/ai/reputation/{MODEL_HASH}/rate"),
            r#"{"rating":6}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_ai_get_reputation_no_data() {
    let t = open_router();
    let resp = t
        .router
        .oneshot(get(&format!("/ai/reputation/{MODEL_HASH}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["total_ratings"], 0);
    assert_eq!(v["score"], 0.0);
}

#[tokio::test]
async fn test_ai_ranked_models_empty() {
    let t = open_router();
    let resp = t.router.oneshot(get("/ai/models/ranked")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert!(v.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_ai_ranked_models_sorted_desc() {
    let t = open_router();
    let hash_b = "b".repeat(64);

    // MODEL: 5 stars + 2 completions
    t.reputation_reg.record_completion(MODEL_HASH).unwrap();
    t.reputation_reg.record_completion(MODEL_HASH).unwrap();
    t.reputation_reg.rate_model(MODEL_HASH, 5, "").unwrap();

    // hash_b: 3 stars + 1 completion
    t.reputation_reg.record_completion(&hash_b).unwrap();
    t.reputation_reg.rate_model(&hash_b, 3, "").unwrap();

    let resp = t.router.oneshot(get("/ai/models/ranked")).await.unwrap();
    let v = body_json(resp).await;
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    let s0 = arr[0]["score"].as_f64().unwrap();
    let s1 = arr[1]["score"].as_f64().unwrap();
    assert!(s0 >= s1, "ranked list must be sorted descending");
    assert_eq!(arr[0]["model_hash"], MODEL_HASH);
}

#[tokio::test]
async fn test_ai_add_stake() {
    let t = open_router();
    let resp = t
        .router
        .oneshot(post_json(
            "/ai/stake",
            &format!(r#"{{"provider":"{PROVIDER}","amount_sat":1000000}}"#),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["staked_sat"], 1_000_000);
    assert_eq!(v["provider"], PROVIDER);
}

#[tokio::test]
async fn test_ai_get_stake_zero_when_absent() {
    let t = open_router();
    let resp = t
        .router
        .oneshot(get(&format!("/ai/stake/{PROVIDER}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["staked_sat"], 0);
}

#[tokio::test]
async fn test_ai_add_stake_accumulates() {
    let t = open_router();
    t.reputation_reg.add_stake(PROVIDER, 500_000).unwrap();
    t.reputation_reg.add_stake(PROVIDER, 500_000).unwrap();

    let resp = t
        .router
        .oneshot(get(&format!("/ai/stake/{PROVIDER}")))
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["staked_sat"], 1_000_000);
}
