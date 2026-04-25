// Copyright (c) 2026 Kantoshi Miyamura

//! Axiom Network autonomous AI monitoring agent.

pub mod agent;
pub mod analyzer;
pub mod metrics;
pub mod optimizer;
pub mod types;

pub use agent::NetworkMonitorAgent;
pub use types::{
    AdaptiveBaselines, AgentAlert, MonitorReport, NetworkHealthScore, ParameterRecommendation,
};
