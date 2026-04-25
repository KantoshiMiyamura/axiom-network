// Copyright (c) 2026 Kantoshi Miyamura
//
// GuardianReport — signed container for gossip.
//
// PURPOSE: a report is what one node shows the rest of the network about
// its own Guardian view at a given height. Other nodes can verify the
// signature (proving the reporter holds the stated ML-DSA-87 key) and
// recompute the proof (proving the decision is consistent with the declared
// state and model commitment).
//
// INVARIANT: receiving a valid report NEVER causes a receiver to accept or
// reject a block or transaction. Valid reports flow into `aggregation.rs`,
// which produces advisory inputs for local policy only.
//
// DOMAIN SEPARATION: signing uses the `"axiom/guardian/report/v1"` domain so
// a Guardian signature cannot be replayed as a transaction signature or a
// network-layer handshake signature.

use axiom_crypto::{sign_with_domain, verify_signature_with_domain};
use axiom_primitives::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

use super::decision::{GuardianDecision, GuardianProof};
use super::state::DeterministicState;

pub const REPORT_DOMAIN: &[u8] = b"axiom/guardian/report/v1";

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("proof does not bind the declared state, decision, and model")]
    BadProof,
    #[error("internal signing error: {0}")]
    Sign(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianReport {
    pub node_pubkey: Vec<u8>,
    pub height: u64,
    pub timestamp: u64,
    pub state: DeterministicState,
    pub decision: GuardianDecision,
    pub proof: GuardianProof,
    /// The model commitment this report was produced under. Receivers can
    /// cluster reports by commitment to detect nodes running stale or
    /// divergent model versions.
    pub model_commitment: [u8; 32],
    pub signature: Vec<u8>,
}

impl GuardianReport {
    /// Canonical pre-signature bytes. Every field that the signature must
    /// cover is folded in; `signature` itself is excluded.
    fn canonical_message(
        node_pubkey: &[u8],
        height: u64,
        timestamp: u64,
        state: &DeterministicState,
        decision: &GuardianDecision,
        proof: &GuardianProof,
        model_commitment: &[u8; 32],
    ) -> Vec<u8> {
        let mut h = Sha3_256::new();
        h.update(REPORT_DOMAIN);
        h.update((node_pubkey.len() as u32).to_le_bytes());
        h.update(node_pubkey);
        h.update(height.to_le_bytes());
        h.update(timestamp.to_le_bytes());
        h.update(state.0);
        h.update(proof.0);
        h.update(model_commitment);
        h.update(decision.canonical_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out.to_vec()
    }

    /// Sign a fresh report. `timestamp` is passed in rather than read from
    /// the system clock so this function stays deterministic and testable.
    /// In the node integration, the caller uses wall-clock time.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        signing_key: &[u8],
        node_pubkey: Vec<u8>,
        height: u64,
        timestamp: u64,
        state: DeterministicState,
        decision: GuardianDecision,
        proof: GuardianProof,
        model_commitment: [u8; 32],
    ) -> Result<Self, ReportError> {
        let msg = Self::canonical_message(
            &node_pubkey,
            height,
            timestamp,
            &state,
            &decision,
            &proof,
            &model_commitment,
        );
        let signature = sign_with_domain(signing_key, REPORT_DOMAIN, &msg)
            .map_err(|e| ReportError::Sign(format!("{e:?}")))?;
        Ok(GuardianReport {
            node_pubkey,
            height,
            timestamp,
            state,
            decision,
            proof,
            model_commitment,
            signature,
        })
    }

    /// Verify both the ML-DSA-87 signature AND the Guardian proof.
    ///
    /// SECURITY: a receiver MUST call this before feeding the report into
    /// aggregation. Unverified reports are attacker-controlled data.
    pub fn verify(&self, model: &super::model::GuardianModel) -> Result<(), ReportError> {
        // Proof must bind the declared state, decision, and model commitment.
        // We recompute the proof using the declared model_commitment so that
        // a verifier without the model object can still check the binding
        // structurally; then we separately require the verifier's reference
        // model to match the commitment.
        let expected = GuardianProof::compute(&self.state, &self.decision, model);
        if expected.0 != self.proof.0 {
            return Err(ReportError::BadProof);
        }
        if model.commitment != self.model_commitment {
            return Err(ReportError::BadProof);
        }

        let msg = Self::canonical_message(
            &self.node_pubkey,
            self.height,
            self.timestamp,
            &self.state,
            &self.decision,
            &self.proof,
            &self.model_commitment,
        );
        let pk = PublicKey::from_slice(&self.node_pubkey).map_err(|_| ReportError::BadSignature)?;
        let sig = Signature::from_slice(&self.signature).map_err(|_| ReportError::BadSignature)?;
        verify_signature_with_domain(REPORT_DOMAIN, &msg, &sig, &pk)
            .map_err(|_| ReportError::BadSignature)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::agent::GuardianAgent;
    use super::super::model::GuardianModel;
    use super::super::state::{BlockSummary, GuardianObservation, PeerStats, TxPatternStats};
    use super::*;
    use axiom_crypto::generate_keypair;

    fn obs() -> GuardianObservation {
        GuardianObservation {
            height: 42,
            tip_hash: [0xAA; 32],
            block_window: vec![BlockSummary {
                hash: [1u8; 32],
                height: 42,
                tx_count: 1,
                size_bytes: 500,
                timestamp: 100,
            }],
            tx_patterns: TxPatternStats {
                mempool_size: 1,
                avg_fee_rate_millisat: 1000,
                unique_senders: 1,
                dust_count: 0,
            },
            peer_stats: PeerStats {
                peer_count: 4,
                handshake_failures: 0,
                median_latency_ms: 20,
            },
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (sk, vk) = generate_keypair();
        let model = GuardianModel::default_model();
        let agent = GuardianAgent::new(model.clone());
        let r = agent.observe(&obs());
        let report = GuardianReport::sign(
            &sk,
            vk.clone(),
            42,
            123456,
            r.state,
            r.decision,
            r.proof,
            model.commitment,
        )
        .unwrap();
        assert!(report.verify(&model).is_ok());
    }

    #[test]
    fn verify_fails_on_tampered_decision() {
        let (sk, vk) = generate_keypair();
        let model = GuardianModel::default_model();
        let agent = GuardianAgent::new(model.clone());
        let r = agent.observe(&obs());
        let mut report = GuardianReport::sign(
            &sk,
            vk,
            42,
            123456,
            r.state,
            r.decision,
            r.proof,
            model.commitment,
        )
        .unwrap();
        report.decision.anomaly_score += 1;
        assert!(report.verify(&model).is_err());
    }

    #[test]
    fn verify_fails_on_model_commitment_mismatch() {
        let (sk, vk) = generate_keypair();
        let model = GuardianModel::default_model();
        let agent = GuardianAgent::new(model.clone());
        let r = agent.observe(&obs());
        let report = GuardianReport::sign(
            &sk,
            vk,
            42,
            123456,
            r.state,
            r.decision,
            r.proof,
            model.commitment,
        )
        .unwrap();
        // Build a different model; receiver uses it as reference.
        let mut w = model.weights.clone();
        w.bias += 1;
        let other = GuardianModel::new(w, model.version).unwrap();
        assert!(report.verify(&other).is_err());
    }
}
