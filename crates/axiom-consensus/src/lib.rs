// Copyright (c) 2026 Kantoshi Miyamura

//! Consensus rules and block structures for Axiom Network.

mod block;
mod consensus;
mod error;
pub mod invariants;
pub mod merkle_proof;
mod pow;
mod validation;

pub use block::{Block, BlockHeader};
pub use consensus::{
    calculate_block_reward, calculate_smooth_reward, compute_merkle_root, ConsensusValidator,
    DECAY_FACTOR, INITIAL_REWARD_SAT, MAX_BLOCK_SIZE, MAX_BLOCK_TRANSACTIONS, MAX_TRANSACTION_SIZE,
    MIN_REWARD_SAT,
};
pub use error::{Error, Result};
pub use invariants::{
    check_coinbase_value, check_supply_transition, check_value_conservation, InvariantError,
};
pub use merkle_proof::{generate_proof, verify_proof, MerkleProof, ProofStep};
pub use pow::{
    calculate_lwma_target, calculate_new_target, calculate_work, check_proof_of_work, mine_block,
    CompactTarget, DIFFICULTY_ADJUSTMENT_INTERVAL, LWMA_WINDOW, MAX_ADJUSTMENT_FACTOR,
    MIN_ADJUSTMENT_FACTOR, TARGET_BLOCK_TIME,
};
pub use validation::validate_block_structure;
