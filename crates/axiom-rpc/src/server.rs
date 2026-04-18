// Copyright (c) 2026 Kantoshi Miyamura

//! RPC server implementation.

use crate::auth::{auth_middleware, AuthConfig};
use crate::handlers::*;
use crate::handlers::{SharedComputeProtocol, SharedGuardState, SharedInferenceRegistry, SharedModelRegistry, SharedMonitorStore, SharedReputationRegistry};
use crate::rate_limiter::{rate_limit_middleware, RpcRateLimiter};
use crate::ws::{create_event_bus, ws_handler, EventBus};
use axiom_node::network::{NetworkService, MAX_RPC_REQUEST_SIZE};
use axum::extract::ConnectInfo;
use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
    Extension, Router,
};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

/// RPC server with bearer-token auth and per-IP rate limiting.
pub struct RpcServer {
    addr: SocketAddr,
    state: SharedNodeState,
    network_service: Option<Arc<RwLock<NetworkService>>>,
    model_registry: Option<SharedModelRegistry>,
    inference_registry: Option<SharedInferenceRegistry>,
    reputation_registry: Option<SharedReputationRegistry>,
    compute_protocol: Option<SharedComputeProtocol>,
    guard: Option<SharedGuardState>,
    monitor_store: Option<SharedMonitorStore>,
    auth_config: Arc<AuthConfig>,
    rate_limiter: Arc<Mutex<RpcRateLimiter>>,
    event_bus: EventBus,
}

impl RpcServer {
    pub fn new(addr: SocketAddr, state: SharedNodeState) -> Self {
        RpcServer {
            addr,
            state,
            network_service: None,
            model_registry: None,
            inference_registry: None,
            reputation_registry: None,
            compute_protocol: None,
            guard: None,
            monitor_store: None,
            auth_config: Arc::new(AuthConfig::open()),
            rate_limiter: Arc::new(Mutex::new(RpcRateLimiter::new())),
            event_bus: create_event_bus(),
        }
    }

    pub fn with_network_service(
        addr: SocketAddr,
        state: SharedNodeState,
        network_service: Arc<RwLock<NetworkService>>,
    ) -> Self {
        RpcServer {
            addr,
            state,
            network_service: Some(network_service),
            model_registry: None,
            inference_registry: None,
            reputation_registry: None,
            compute_protocol: None,
            guard: None,
            monitor_store: None,
            auth_config: Arc::new(AuthConfig::open()),
            rate_limiter: Arc::new(Mutex::new(RpcRateLimiter::new())),
            event_bus: create_event_bus(),
        }
    }

    /// Enables the `/ai/model/*` endpoints.
    pub fn with_model_registry(mut self, registry: SharedModelRegistry) -> Self {
        self.model_registry = Some(registry);
        self
    }

    /// Enables the `/ai/inference/*` endpoints.
    pub fn with_inference_registry(mut self, registry: SharedInferenceRegistry) -> Self {
        self.inference_registry = Some(registry);
        self
    }

    /// Enables the `/ai/reputation/*`, `/ai/models/ranked`, and `/ai/stake/*` endpoints.
    pub fn with_reputation_registry(mut self, registry: SharedReputationRegistry) -> Self {
        self.reputation_registry = Some(registry);
        self
    }

    /// Enables the `/ai/compute/*` endpoints backed by ComputeProtocol.
    pub fn with_compute_protocol(mut self, protocol: SharedComputeProtocol) -> Self {
        self.compute_protocol = Some(protocol);
        self
    }

    /// Enables the `/guard/*` endpoints backed by AxiomMind.
    pub fn with_guard(mut self, guard: SharedGuardState) -> Self {
        self.guard = Some(guard);
        self
    }

    /// Enables the `/monitor/*` endpoints backed by the NetworkMonitorAgent.
    pub fn with_monitor_store(mut self, store: SharedMonitorStore) -> Self {
        self.monitor_store = Some(store);
        self
    }

    /// Clone of the event bus for pushing block/tx events to WebSocket subscribers.
    pub fn event_bus(&self) -> EventBus {
        self.event_bus.clone()
    }

    /// Require a bearer token for every request.
    pub fn with_auth_token(mut self, token: String) -> Self {
        if token.len() < 32 {
            tracing::warn!(
                "RPC auth token is shorter than 32 characters — use a strong random token for mainnet"
            );
        }
        self.auth_config = Arc::new(AuthConfig::with_token(token));
        self
    }

    /// Returns true if the RPC server has an auth token configured.
    pub fn is_auth_configured(&self) -> bool {
        self.auth_config.is_protected()
    }

    fn build_router(&self) -> Router {
        // Write/sensitive endpoints: localhost-only when auth is not configured.
        // This prevents remote unauthenticated transaction submission and
        // protects privacy-sensitive balance/UTXO/nonce queries.
        let mut protected = Router::new()
            .route("/submit_transaction", post(submit_transaction))
            .route("/balance/:address", get(get_balance))
            .route("/nonce/:address", get(get_nonce))
            .route("/utxos/:address", get(get_utxos))
            .route("/address/:address/txs", get(get_address_transactions))
            .route("/community/send", post(community_send_message))
            .route("/ai/model/register", post(ai_register_model))
            .route("/ai/inference/request", post(ai_request_inference))
            .route("/ai/inference/complete", post(ai_complete_inference))
            .route("/ai/inference/cancel", post(ai_cancel_inference))
            .route("/ai/reputation/:model_hash/rate", post(ai_rate_model))
            .route("/ai/stake", post(ai_add_stake))
            .route("/ai/compute/job/submit", post(compute_submit_job))
            .route("/ai/compute/worker/register", post(compute_register_worker))
            .route("/ai/compute/worker/result", post(compute_submit_result))
            .route("/ai/compute/verifier/register", post(compute_register_verifier))
            .route("/ai/compute/dispute/file", post(compute_file_challenge))
            .route("/ai/compute/dispute/resolve", post(compute_resolve_dispute))
            .route("/ai/compute/job/:job_id/finalize", post(compute_finalize_job))
            .route("/axiom/enable", post(crate::axiommind_handlers::set_axiom_mind_enabled));

        // Protected endpoints always require either bearer-token auth or localhost restriction.
        // In open mode (no token configured), restrict to localhost only — never expose
        // write/sensitive endpoints without authentication to the network.
        if self.auth_config.is_open() {
            tracing::warn!(
                "RPC auth token not configured — write endpoints restricted to localhost. \
                 Set RPC_AUTH_TOKEN for mainnet deployment."
            );
            protected = protected.layer(middleware::from_fn(localhost_only));
        }

        // Public read-only endpoints: accessible from anywhere.
        let public = Router::new()
            .route("/status", get(get_status))
            .route("/best_block_hash", get(get_best_block_hash))
            .route("/best_height", get(get_best_height))
            .route("/tip", get(get_tip))
            .route("/block/:hash", get(get_block_by_hash))
            .route("/block/height/:height", get(get_block_by_height))
            .route("/blocks/recent", get(get_recent_blocks))
            .route("/block/:hash/txs", get(get_block_transactions))
            .route("/tx/:txid", get(get_transaction))
            .route("/peers", get(get_peers))
            .route("/peer_count", get(get_peer_count))
            .route("/metrics", get(get_metrics))
            .route("/metrics/prometheus", get(get_metrics_prometheus))
            .route("/health", get(get_health))
            .route("/fee/estimate", get(get_fee_estimate))
            .route("/mempool", get(get_mempool))
            .route("/ai/analysis", get(get_ai_analysis))
            .route("/ai/model/:hash", get(ai_get_model))
            .route("/ai/models/recent", get(ai_list_models))
            .route("/ai/inference/:job_id", get(ai_get_inference_job))
            .route("/ai/inference/jobs/:address", get(ai_list_inference_jobs))
            .route("/ai/reputation/:model_hash", get(ai_get_reputation))
            .route("/ai/models/ranked", get(ai_ranked_models))
            .route("/ai/stake/:address", get(ai_get_stake))
            .route("/ai/compute/job/:job_id", get(compute_get_job))
            .route("/ai/compute/jobs/address/:address", get(compute_list_jobs_for_address))
            .route("/ai/compute/worker/:worker_id", get(compute_get_worker))
            .route("/ai/compute/settlements/recent", get(compute_list_settlements))
            .route("/ai/compute/workers/active", get(compute_list_active_workers))
            .route("/guard/status", get(get_guard_status))
            .route("/guard/alerts", get(get_guard_alerts))
            .route("/analytics", get(get_network_analytics))
            .route("/block/:hash/stats", get(get_block_stats))
            .route("/mempool/stats", get(get_mempool_detail))
            .route("/network/hashrate", get(get_network_hashrate))
            .route("/monitor/report", get(get_monitor_report))
            .route("/monitor/reports", get(get_monitor_reports))
            .route("/monitor/health", get(get_monitor_health))
            .route("/monitor/alerts", get(get_monitor_alerts))
            .route("/monitor/recommendations", get(get_monitor_recommendations))
            .route("/community/messages", get(community_get_messages))
            .route("/community/username/:address", get(community_get_username))
            .route("/axiom/status", get(crate::axiommind_handlers::get_axiom_mind_status))
            .route("/axiom/anomalies", get(crate::axiommind_handlers::get_axiom_mind_anomalies))
            .route("/axiom/audit", get(crate::axiommind_handlers::get_axiom_mind_audit_log))
            .route("/axiom/config", get(crate::axiommind_handlers::get_axiom_mind_config))
            .route("/ws", get(ws_handler));

        public
            .merge(protected)
            .with_state(self.state.clone())
            .layer(Extension(crate::ws::WsConnectionLimiter::new(1000, 5)))
            .layer(Extension(self.event_bus.clone()))
            .layer(Extension(self.network_service.clone()))
            .layer(Extension(self.model_registry.clone()))
            .layer(Extension(self.inference_registry.clone()))
            .layer(Extension(self.reputation_registry.clone()))
            .layer(Extension(self.compute_protocol.clone()))
            .layer(Extension(self.guard.clone()))
            .layer(Extension(self.monitor_store.clone()))
            // middleware order: rate-limit (outer) → auth (inner) → handler
            .layer(middleware::from_fn_with_state(
                self.auth_config.clone(),
                auth_middleware,
            ))
            .layer(middleware::from_fn_with_state(
                self.rate_limiter.clone(),
                rate_limit_middleware,
            ))
            .layer(CorsLayer::new()
                .allow_origin(tower_http::cors::AllowOrigin::predicate(
                    |origin: &axum::http::HeaderValue, _| {
                        origin.as_bytes().starts_with(b"http://localhost")
                            || origin.as_bytes().starts_with(b"http://127.0.0.1")
                            || origin.as_bytes().starts_with(b"http://[::1]")
                            || origin.as_bytes() == b"null" // file:// origins
                    },
                ))
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any))
            .layer(DefaultBodyLimit::max(MAX_RPC_REQUEST_SIZE))
    }
}

/// Reject non-loopback requests — used on sensitive endpoints when auth is not configured.
/// If `ConnectInfo` is missing (e.g. in-process test requests via `oneshot()`), allow through
/// since those are inherently local.
async fn localhost_only(
    conn: Option<ConnectInfo<SocketAddr>>,
    request: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    match conn {
        Some(ConnectInfo(addr)) if addr.ip().is_loopback() => Ok(next.run(request).await),
        None => Ok(next.run(request).await), // in-process (no TCP) — always local
        _ => Err(axum::http::StatusCode::FORBIDDEN),
    }
}

impl RpcServer {
    /// Returns the built router — useful for in-process testing.
    pub fn into_router(self) -> Router {
        self.build_router()
    }

    /// Bind and serve until shutdown.
    pub async fn start(self) -> Result<(), std::io::Error> {
        let app = self.build_router();
        let listener = tokio::net::TcpListener::bind(self.addr).await?;

        println!("RPC server listening on {}", self.addr);

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[test]
    fn test_server_creation() {
        use axiom_node::{Config, Network, Node};
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = Config {
            network: Network::Test,
            data_dir: temp_dir.path().to_path_buf(),
            rpc_bind: "127.0.0.1:8332".to_string(),
            mempool_max_size: 1_000_000,
            mempool_max_count: 100,
            min_fee_rate: 1,
        };

        let node = Node::new(config).unwrap();
        let addr = "127.0.0.1:8332".parse().unwrap();
        let state = Arc::new(RwLock::new(node));
        let server = RpcServer::new(addr, state);
        assert_eq!(server.addr, addr);
        assert!(!server.auth_config.is_protected());
    }

    #[test]
    fn test_server_with_auth_token() {
        use axiom_node::{Config, Network, Node};
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = Config {
            network: Network::Test,
            data_dir: temp_dir.path().to_path_buf(),
            rpc_bind: "127.0.0.1:8332".to_string(),
            mempool_max_size: 1_000_000,
            mempool_max_count: 100,
            min_fee_rate: 1,
        };

        let node = Node::new(config).unwrap();
        let addr = "127.0.0.1:8332".parse().unwrap();
        let state = Arc::new(RwLock::new(node));
        let server = RpcServer::new(addr, state).with_auth_token("s3cr3t".to_string());
        assert!(server.auth_config.is_protected());
    }
}
