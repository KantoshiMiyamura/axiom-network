// Copyright (c) 2026 Kantoshi Miyamura
// AxiomMind v2 RPC Handlers — backed by real NetworkGuard state

use crate::error::RpcError;
use crate::handlers::SharedGuardState;
use axum::extract::Extension;
use axum::Json;
use serde_json::{json, Value};

pub type Result<T> = std::result::Result<T, RpcError>;

/// Get AxiomMind v2 system status from the live NetworkGuard.
pub async fn get_axiom_mind_status(
    Extension(guard): Extension<Option<SharedGuardState>>,
) -> Result<Json<Value>> {
    let guard = match guard {
        Some(g) => g,
        None => {
            return Ok(Json(json!({
                "status": "unavailable",
                "reason": "AxiomMind guard not initialized on this node",
            })));
        }
    };

    let g = guard.read().await;
    let status = g.status();

    Ok(Json(json!({
        "status": "ok",
        "health": "nominal",
        "active": status.active,
        "threat_level": status.threat_level,
        "threat_color": status.threat_color,
        "threat_emoji": status.threat_emoji,
        "blocks_analyzed": status.blocks_analyzed,
        "threats_detected": status.threats_detected,
        "cognitive_fingerprint_address": status.cognitive_fingerprint_address,
        "baseline_trained": status.baseline_trained,
        "baseline_block_interval_mean": status.baseline_block_interval_mean,
        "baseline_block_interval_std": status.baseline_block_interval_std,
        "peer_trusted_count": status.peer_trusted_count,
        "peer_banned_count": status.peer_banned_count,
        "active_alerts": status.recent_alerts.len(),
    })))
}

/// Get anomaly history from the live NetworkGuard.
pub async fn get_axiom_mind_anomalies(
    Extension(guard): Extension<Option<SharedGuardState>>,
) -> Result<Json<Value>> {
    let guard = match guard {
        Some(g) => g,
        None => {
            return Ok(Json(json!({
                "status": "unavailable",
                "anomalies": [],
                "count": 0,
            })));
        }
    };

    let g = guard.read().await;
    let alerts = g.recent_alerts(100);
    let count = alerts.len();

    // Serialize alerts — GuardAlert derives Serialize
    let anomalies: Vec<Value> = alerts
        .iter()
        .map(|a| {
            json!({
                "id": a.id,
                "code": a.code,
                "kind": a.kind,
                "severity": a.severity,
                "threat_level": a.threat_level,
                "timestamp_unix": a.timestamp_unix,
                "block_height": a.block_height,
                "anomaly_score": a.anomaly_score,
                "description": a.description,
                "details": a.details,
            })
        })
        .collect();

    Ok(Json(json!({
        "status": "ok",
        "anomalies": anomalies,
        "count": count,
        "limit": 100,
    })))
}

/// Get audit log — alerts with severity Warning or Critical.
pub async fn get_axiom_mind_audit_log(
    Extension(guard): Extension<Option<SharedGuardState>>,
) -> Result<Json<Value>> {
    let guard = match guard {
        Some(g) => g,
        None => {
            return Ok(Json(json!({
                "status": "unavailable",
                "events": [],
                "count": 0,
            })));
        }
    };

    let g = guard.read().await;
    let alerts = g.recent_alerts(100);

    let events: Vec<Value> = alerts
        .iter()
        .filter(|a| {
            matches!(
                a.severity,
                axiom_guard::AlertSeverity::Warning | axiom_guard::AlertSeverity::Critical
            )
        })
        .map(|a| {
            json!({
                "id": a.id,
                "code": a.code,
                "kind": a.kind,
                "severity": a.severity,
                "threat_level": a.threat_level,
                "timestamp_unix": a.timestamp_unix,
                "block_height": a.block_height,
                "anomaly_score": a.anomaly_score,
                "description": a.description,
                "details": a.details,
            })
        })
        .collect();

    let count = events.len();

    Ok(Json(json!({
        "status": "ok",
        "events": events,
        "count": count,
        "limit": 100,
    })))
}

/// AxiomMind cannot be disabled — it is a core security component.
pub async fn set_axiom_mind_enabled() -> Result<Json<Value>> {
    Ok(Json(json!({
        "status": "ok",
        "enabled": true,
        "note": "AxiomMind is a core security component and cannot be disabled",
    })))
}

/// Get AxiomMind v2 configuration (static detector thresholds).
pub async fn get_axiom_mind_config() -> Result<Json<Value>> {
    Ok(Json(json!({
        "status": "ok",
        "detectors": {
            "timestamp_drift_secs": 600,
            "rapid_blocks_secs": 30,
            "orphan_rate_max": 0.05,
            "nonce_saturation_threshold": 0.9,
            "mempool_max_size": 100000,
            "invalid_signature_rate_max": 0.01,
            "consensus_drift_blocks": 10,
            "min_peers": 3,
        },
        "features": {
            "anomaly_detection": true,
            "self_healing": true,
            "reinforcement_learning": true,
            "monitoring": true,
        },
    })))
}
