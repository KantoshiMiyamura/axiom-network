// Copyright (c) 2026 Kantoshi Miyamura

// Merkle inclusion proofs for SPV verification.
// Proves a tx is in a block using only the txid, proof path, and block header merkle_root.

use axiom_crypto::double_hash256;
use axiom_primitives::Hash256;
use serde::{Deserialize, Serialize};

/// Merkle inclusion proof for a single transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub txid: Hash256,
    /// Position in block (0 = coinbase).
    pub tx_index: u32,
    /// Sibling hashes from leaf to root.
    pub proof_path: Vec<ProofStep>,
    /// Computed root; must match block header to be valid.
    pub merkle_root: Hash256,
}

/// One node in the proof path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    /// true = sibling is on the right, false = sibling is on the left.
    pub is_right: bool,
    pub hash: Hash256,
}

/// Build a Merkle proof for tx_hashes[tx_index]. Returns None if index is out of bounds.
pub fn generate_proof(tx_hashes: &[Hash256], tx_index: usize) -> Option<MerkleProof> {
    if tx_hashes.is_empty() || tx_index >= tx_hashes.len() {
        return None;
    }

    let txid = tx_hashes[tx_index];
    let mut proof_path = Vec::new();
    let mut level: Vec<Hash256> = tx_hashes.to_vec();
    let mut index = tx_index;

    while level.len() > 1 {
        // Odd length: duplicate last node.
        if !level.len().is_multiple_of(2) {
            let last = *level.last().unwrap();
            level.push(last);
        }

        let sibling_index = if index.is_multiple_of(2) {
            index + 1
        } else {
            index - 1
        };
        let is_right = index.is_multiple_of(2);

        proof_path.push(ProofStep {
            is_right,
            hash: level[sibling_index],
        });

        let mut next_level = Vec::new();
        for i in (0..level.len()).step_by(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(level[i].as_bytes());
            combined[32..].copy_from_slice(level[i + 1].as_bytes());
            next_level.push(double_hash256(&combined));
        }

        level = next_level;
        index /= 2;
    }

    Some(MerkleProof {
        txid,
        tx_index: tx_index as u32,
        proof_path,
        merkle_root: if level.is_empty() {
            Hash256::zero()
        } else {
            level[0]
        },
    })
}

/// Returns true if the proof correctly derives merkle_root from proof.txid.
pub fn verify_proof(proof: &MerkleProof, merkle_root: &Hash256) -> bool {
    let mut current = proof.txid;

    for step in &proof.proof_path {
        let mut combined = [0u8; 64];
        if step.is_right {
            combined[..32].copy_from_slice(current.as_bytes());
            combined[32..].copy_from_slice(step.hash.as_bytes());
        } else {
            combined[..32].copy_from_slice(step.hash.as_bytes());
            combined[32..].copy_from_slice(current.as_bytes());
        }
        current = double_hash256(&combined);
    }

    current == *merkle_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(n: u8) -> Hash256 {
        Hash256::from_slice(&[n; 32]).unwrap()
    }

    #[test]
    fn test_single_tx_proof() {
        let hashes = vec![make_hash(1)];
        let proof = generate_proof(&hashes, 0).unwrap();
        assert_eq!(proof.proof_path.len(), 0);
        assert!(verify_proof(&proof, &proof.merkle_root));
    }

    #[test]
    fn test_two_tx_proof() {
        let hashes = vec![make_hash(1), make_hash(2)];
        let proof0 = generate_proof(&hashes, 0).unwrap();
        let proof1 = generate_proof(&hashes, 1).unwrap();
        assert!(verify_proof(&proof0, &proof0.merkle_root));
        assert!(verify_proof(&proof1, &proof1.merkle_root));
        assert_eq!(proof0.merkle_root, proof1.merkle_root);
    }

    #[test]
    fn test_four_tx_proof() {
        let hashes: Vec<Hash256> = (1..=4).map(make_hash).collect();
        for i in 0..4 {
            let proof = generate_proof(&hashes, i).unwrap();
            assert!(
                verify_proof(&proof, &proof.merkle_root),
                "proof {} failed",
                i
            );
        }
    }

    #[test]
    fn test_proof_rejection_wrong_root() {
        let hashes = vec![make_hash(1), make_hash(2)];
        let proof = generate_proof(&hashes, 0).unwrap();
        let wrong_root = make_hash(99);
        assert!(!verify_proof(&proof, &wrong_root));
    }

    #[test]
    fn test_odd_number_of_txs() {
        let hashes: Vec<Hash256> = (1..=5).map(make_hash).collect();
        for i in 0..5 {
            let proof = generate_proof(&hashes, i).unwrap();
            assert!(
                verify_proof(&proof, &proof.merkle_root),
                "proof {} failed",
                i
            );
        }
    }
}
