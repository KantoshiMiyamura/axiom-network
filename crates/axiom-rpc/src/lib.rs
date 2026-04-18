// Copyright (c) 2026 Kantoshi Miyamura

//! RPC interface for Axiom Network.

pub mod auth;
mod error;
mod handlers;
pub mod rate_limiter;
mod server;
mod types;
pub mod ws;
pub mod axiommind_handlers;

pub use auth::AuthConfig;
pub use error::{Result, RpcError};
pub use handlers::{SharedComputeProtocol, SharedGuardState, SharedMonitorStore, SharedNetworkService, SharedNodeState};
pub use rate_limiter::RpcRateLimiter;
pub use server::RpcServer;
pub use types::*;
pub use ws::{create_event_bus, EventBus, WsEvent, WsTxEvent};
pub use axiommind_handlers::{
    get_axiom_mind_status, get_axiom_mind_anomalies, get_axiom_mind_audit_log,
    set_axiom_mind_enabled, get_axiom_mind_config,
};
