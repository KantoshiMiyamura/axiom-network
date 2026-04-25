// Copyright (c) 2026 Kantoshi Miyamura

//! RPC interface for Axiom Network.

pub mod auth;
pub mod axiommind_handlers;
mod error;
mod handlers;
pub mod rate_limiter;
mod server;
mod types;
pub mod ws;

pub use auth::AuthConfig;
pub use axiommind_handlers::{
    get_axiom_mind_anomalies, get_axiom_mind_audit_log, get_axiom_mind_config,
    get_axiom_mind_status, set_axiom_mind_enabled,
};
pub use error::{Result, RpcError};
pub use handlers::{
    SharedComputeProtocol, SharedGuardState, SharedMonitorStore, SharedNetworkService,
    SharedNodeState,
};
pub use rate_limiter::RpcRateLimiter;
pub use server::RpcServer;
pub use types::*;
pub use ws::{create_event_bus, EventBus, WsEvent, WsTxEvent};
