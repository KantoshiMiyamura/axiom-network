// Copyright (c) 2026 Kantoshi Miyamura

//! Fork choice logging: structured logs for chain selection decisions.

use axiom_primitives::Hash256;

/// Log a fork choice candidate evaluation.
#[allow(clippy::too_many_arguments)]
pub fn log_fork_choice_candidate(
    candidate_hash: &Hash256,
    candidate_height: u32,
    candidate_chainwork: u128,
    active_hash: &Hash256,
    active_height: u32,
    active_chainwork: u128,
    decision: &str,
    reason: &str,
) {
    tracing::info!(
        target: "fork_choice",
        candidate_hash = %hex::encode(candidate_hash.as_bytes()),
        candidate_height,
        candidate_chainwork,
        active_hash = %hex::encode(active_hash.as_bytes()),
        active_height,
        active_chainwork,
        decision,
        reason,
        "FORK_CHOICE_CANDIDATE"
    );
}

/// Log a block acceptance.
pub fn log_block_accepted(
    hash: &Hash256,
    height: u32,
    chainwork: u128,
    source: &str,
) {
    tracing::info!(
        target: "block_accepted",
        hash = %hex::encode(hash.as_bytes()),
        height,
        chainwork,
        source,
        "BLOCK_ACCEPTED"
    );
}

/// Log a block rejection.
pub fn log_block_rejected(
    hash: &Hash256,
    height: u32,
    source: &str,
    reason: &str,
) {
    tracing::warn!(
        target: "block_rejected",
        hash = %hex::encode(hash.as_bytes()),
        height,
        source,
        reason,
        "BLOCK_REJECTED"
    );
}

/// Log a tip update.
pub fn log_tip_update(
    old_hash: &Hash256,
    old_height: u32,
    new_hash: &Hash256,
    new_height: u32,
    reason: &str,
) {
    tracing::info!(
        target: "tip_update",
        old_hash = %hex::encode(old_hash.as_bytes()),
        old_height,
        new_hash = %hex::encode(new_hash.as_bytes()),
        new_height,
        reason,
        "TIP_UPDATE"
    );
}

/// Log reorg start.
pub fn log_reorg_start(
    old_tip: &Hash256,
    new_tip: &Hash256,
    fork_ancestor: &Hash256,
    disconnect_count: usize,
    connect_count: usize,
) {
    tracing::warn!(
        target: "reorg",
        old_tip = %hex::encode(old_tip.as_bytes()),
        new_tip = %hex::encode(new_tip.as_bytes()),
        fork_ancestor = %hex::encode(fork_ancestor.as_bytes()),
        disconnect_count,
        connect_count,
        "REORG_START"
    );
}

/// Log reorg disconnect.
pub fn log_reorg_disconnect(hash: &Hash256, height: u32) {
    tracing::debug!(
        target: "reorg",
        hash = %hex::encode(hash.as_bytes()),
        height,
        "REORG_DISCONNECT"
    );
}

/// Log reorg connect.
pub fn log_reorg_connect(hash: &Hash256, height: u32) {
    tracing::debug!(
        target: "reorg",
        hash = %hex::encode(hash.as_bytes()),
        height,
        "REORG_CONNECT"
    );
}

/// Log reorg completion.
pub fn log_reorg_done(active_tip: &Hash256, active_height: u32) {
    tracing::info!(
        target: "reorg",
        active_tip = %hex::encode(active_tip.as_bytes()),
        active_height,
        "REORG_DONE"
    );
}

/// Log mining snapshot creation.
pub fn log_miner_snapshot_created(
    parent_hash: &Hash256,
    parent_height: u32,
    target: u32,
    tx_count: usize,
) {
    tracing::info!(
        target: "mining",
        parent_hash = %hex::encode(parent_hash.as_bytes()),
        parent_height,
        target,
        tx_count,
        "MINER_SNAPSHOT_CREATED"
    );
}

/// Log mining abort due to stale template.
pub fn log_miner_aborted_stale_template(
    old_parent: &Hash256,
    new_parent: &Hash256,
    reason: &str,
) {
    tracing::info!(
        target: "mining",
        old_parent = %hex::encode(old_parent.as_bytes()),
        new_parent = %hex::encode(new_parent.as_bytes()),
        reason,
        "MINER_ABORTED_STALE_TEMPLATE"
    );
}

/// Log peer block received.
pub fn log_peer_block_received(
    peer: &str,
    hash: &Hash256,
    height: u32,
    prev_hash: &Hash256,
) {
    tracing::debug!(
        target: "peer",
        peer,
        hash = %hex::encode(hash.as_bytes()),
        height,
        prev_hash = %hex::encode(prev_hash.as_bytes()),
        "PEER_BLOCK_RECEIVED"
    );
}

/// Log peer score update.
pub fn log_peer_score_update(peer: &str, delta: i32, reason: &str) {
    tracing::debug!(
        target: "peer",
        peer,
        delta,
        reason,
        "PEER_SCORE_UPDATE"
    );
}
