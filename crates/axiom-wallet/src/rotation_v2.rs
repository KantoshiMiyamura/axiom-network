// Copyright (c) 2026 Kantoshi Miyamura

//! Wallet key rotation. Spec: `docs/V2_PROTOCOL.md §7`.
//!
//! A wallet can rotate its identity to a fresh ML-DSA-87 keypair without
//! ever putting a private key on-chain. Each rotation produces a
//! [`RotationRecord`] signed by the **old** key, authorising the **new**
//! key as the wallet's current public identity. UTXOs sent to the old
//! address remain spendable by the original key indefinitely — the
//! rotation is a wallet-side identity statement, not a chain-level
//! invalidation of historical outputs.
//!
//! Multiple rotations form a chain `A → B → C → …` tracked in
//! [`Linkage`]. The wallet retains every historical keypair so any UTXO
//! from any era is still spendable.
//!
//! INVARIANT: this module does **not** touch consensus. It produces a
//! self-contained cryptographic artifact (`RotationRecord`) plus a
//! local persistence helper (`Linkage`). No transaction, mempool, or
//! validation path consults it. Threading rotation records onto the
//! chain via `tx.v2_extension.rotation_pointer` is a future stage.

use axiom_primitives::{Hash256, PublicKey, Signature};
use thiserror::Error;

use crate::address::Address;
use crate::keypair::KeyPair;

/// Domain-separation tag for the rotation-record signing hash. Bumping
/// this string produces an entirely disjoint signature space — no v1
/// signature can be replayed against a v2-dev rotation verifier.
pub const ROTATION_V2_TAG: &[u8] = b"axiom-rotation-v2";

/// One link in a rotation chain. The signing key is the **old** key
/// (referenced by `predecessor_pubkey`); the **new** key is announced
/// by `successor_pubkey`. `from_address` and `to_address` are the
/// addresses derived from those two keys respectively.
#[derive(Debug, Clone)]
pub struct RotationRecord {
    pub from_address: Address,
    pub to_address: Address,
    /// Old public key (the signer of this record). Carrying it explicitly
    /// makes the record self-verifying — a verifier does not need an
    /// out-of-band lookup to discover which key signed.
    pub predecessor_pubkey: PublicKey,
    /// New public key being announced as the wallet's successor identity.
    pub successor_pubkey: PublicKey,
    /// Block height at which the rotation takes effect for any consumer
    /// that wants to gate UI / display behaviour. Not enforced by the
    /// chain — rotation records are a wallet-side artifact, not a
    /// consensus rule.
    pub effective_height: u32,
    /// ML-DSA-87 signature by the old key over the canonical record body.
    pub signature: Signature,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum RotationError {
    #[error("ML-DSA-87 signing failed during rotation-record build")]
    SigningFailed,
    #[error("ML-DSA-87 signature verification failed for rotation record")]
    SignatureVerifyFailed,
    #[error("predecessor pubkey hash does not match `from_address`")]
    FromAddressMismatch,
    #[error("successor pubkey hash does not match `to_address`")]
    ToAddressMismatch,
    #[error("record's `from_address` does not extend the linkage tip")]
    LinkageTipMismatch,
    #[error("`effective_height` must strictly increase along the linkage")]
    EffectiveHeightNotMonotonic,
    #[error("rotation record carries an empty signature buffer")]
    EmptySignature,
    #[error("rotation record carries an empty pubkey buffer")]
    EmptyPubkey,
}

// ── Canonical signing body ──────────────────────────────────────────────────

/// Canonical bytes that the old key signs. Length-prefixed at every
/// region to eliminate concatenation boundary ambiguity (same rationale
/// as `axiom_crypto::transaction_signing_hash`):
///
/// ```text
///   u32 LE from_addr_len    || from_address.pubkey_hash bytes
///   u32 LE to_addr_len      || to_address.pubkey_hash bytes
///   u32 LE predecessor_len  || predecessor_pubkey bytes
///   u32 LE successor_len    || successor_pubkey bytes
///   u32 LE effective_height
/// ```
fn canonical_body(
    from_address: &Address,
    to_address: &Address,
    predecessor_pubkey: &PublicKey,
    successor_pubkey: &PublicKey,
    effective_height: u32,
) -> Vec<u8> {
    let from_bytes = from_address.pubkey_hash().as_bytes();
    let to_bytes = to_address.pubkey_hash().as_bytes();
    let pred = predecessor_pubkey.as_bytes();
    let succ = successor_pubkey.as_bytes();

    let mut body =
        Vec::with_capacity(20 + from_bytes.len() + to_bytes.len() + pred.len() + succ.len());
    body.extend_from_slice(&(from_bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(from_bytes);
    body.extend_from_slice(&(to_bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(to_bytes);
    body.extend_from_slice(&(pred.len() as u32).to_le_bytes());
    body.extend_from_slice(pred);
    body.extend_from_slice(&(succ.len() as u32).to_le_bytes());
    body.extend_from_slice(succ);
    body.extend_from_slice(&effective_height.to_le_bytes());
    body
}

/// Hash that the old key signs. Domain-separated via `ROTATION_V2_TAG`.
fn signing_hash(
    from_address: &Address,
    to_address: &Address,
    predecessor_pubkey: &PublicKey,
    successor_pubkey: &PublicKey,
    effective_height: u32,
) -> Hash256 {
    let body = canonical_body(
        from_address,
        to_address,
        predecessor_pubkey,
        successor_pubkey,
        effective_height,
    );
    axiom_crypto::tagged_hash(ROTATION_V2_TAG, &body)
}

// ── Build / verify ──────────────────────────────────────────────────────────

/// Build a [`RotationRecord`] signed by the old key.
///
/// The caller supplies the old keypair (for signing), the new public
/// key (announcing the successor), the two addresses derived from
/// those keys, and the advisory `effective_height`. The function
/// computes the canonical signing hash, signs it with the old key's
/// ML-DSA-87 secret, and returns the assembled record.
///
/// **Pre-conditions** that the function checks before signing — these
/// catch the most common caller mistakes:
///
/// - `from_address.pubkey_hash() == hash256(old_keypair.public_key())`
/// - `to_address.pubkey_hash()   == hash256(new_pubkey)`
///
/// Either failing returns `RotationError::FromAddressMismatch` /
/// `RotationError::ToAddressMismatch` rather than producing a record
/// that would be rejected at verification time.
pub fn build_rotation_record(
    old_keypair: &KeyPair,
    new_pubkey: &PublicKey,
    from_address: Address,
    to_address: Address,
    effective_height: u32,
) -> Result<RotationRecord, RotationError> {
    let predecessor_pubkey = old_keypair
        .public_key_struct()
        .map_err(|_| RotationError::EmptyPubkey)?;

    // Refuse to sign a record whose addresses do not match the keys.
    if axiom_crypto::hash256(predecessor_pubkey.as_bytes()) != *from_address.pubkey_hash() {
        return Err(RotationError::FromAddressMismatch);
    }
    if axiom_crypto::hash256(new_pubkey.as_bytes()) != *to_address.pubkey_hash() {
        return Err(RotationError::ToAddressMismatch);
    }

    let digest = signing_hash(
        &from_address,
        &to_address,
        &predecessor_pubkey,
        new_pubkey,
        effective_height,
    );
    let sig_bytes = old_keypair
        .sign(digest.as_bytes())
        .map_err(|_| RotationError::SigningFailed)?;
    let signature = Signature::from_bytes(sig_bytes);

    Ok(RotationRecord {
        from_address,
        to_address,
        predecessor_pubkey,
        successor_pubkey: new_pubkey.clone(),
        effective_height,
        signature,
    })
}

/// Verify a [`RotationRecord`] against the supplied [`Linkage`].
///
/// Steps (each MUST pass for `Ok(())`):
///
/// 1. Both `predecessor_pubkey` and `successor_pubkey` are non-empty.
/// 2. `signature` is non-empty.
/// 3. `hash256(predecessor_pubkey) == from_address.pubkey_hash()`.
/// 4. `hash256(successor_pubkey)   == to_address.pubkey_hash()`.
/// 5. `linkage` extends correctly:
///    - empty linkage → caller must verify `from_address` against the
///      wallet's seed identity separately;
///    - non-empty → `from_address == linkage.records.last().to_address`.
/// 6. `effective_height > linkage.records.last().effective_height` when
///    the linkage is non-empty.
/// 7. ML-DSA-87 signature verifies against `predecessor_pubkey` over the
///    canonical signing hash.
pub fn verify_rotation_record(
    record: &RotationRecord,
    linkage: &Linkage,
) -> Result<(), RotationError> {
    // (1) and (2): non-empty buffers.
    if record.predecessor_pubkey.as_bytes().is_empty()
        || record.successor_pubkey.as_bytes().is_empty()
    {
        return Err(RotationError::EmptyPubkey);
    }
    if record.signature.as_bytes().is_empty() {
        return Err(RotationError::EmptySignature);
    }

    // (3) predecessor_pubkey ↔ from_address.
    if axiom_crypto::hash256(record.predecessor_pubkey.as_bytes())
        != *record.from_address.pubkey_hash()
    {
        return Err(RotationError::FromAddressMismatch);
    }

    // (4) successor_pubkey ↔ to_address.
    if axiom_crypto::hash256(record.successor_pubkey.as_bytes()) != *record.to_address.pubkey_hash()
    {
        return Err(RotationError::ToAddressMismatch);
    }

    // (5) and (6): linkage tip + effective_height.
    if let Some(tip) = linkage.records.last() {
        if record.from_address != tip.to_address {
            return Err(RotationError::LinkageTipMismatch);
        }
        if record.effective_height <= tip.effective_height {
            return Err(RotationError::EffectiveHeightNotMonotonic);
        }
    }

    // (7) signature verifies.
    let digest = signing_hash(
        &record.from_address,
        &record.to_address,
        &record.predecessor_pubkey,
        &record.successor_pubkey,
        record.effective_height,
    );
    axiom_crypto::verify_signature(
        digest.as_bytes(),
        &record.signature,
        &record.predecessor_pubkey,
    )
    .map_err(|_| RotationError::SignatureVerifyFailed)?;

    Ok(())
}

// ── Linkage ─────────────────────────────────────────────────────────────────

/// Ordered chain of rotation records for a single wallet, oldest first.
/// The wallet retains the full history so every historical address
/// remains independently spendable.
#[derive(Debug, Default, Clone)]
pub struct Linkage {
    pub records: Vec<RotationRecord>,
}

impl Linkage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Current canonical address — `to_address` of the latest record,
    /// or `seed` when the chain is empty.
    pub fn current_address(&self, seed: &Address) -> Address {
        self.records
            .last()
            .map(|r| r.to_address.clone())
            .unwrap_or_else(|| seed.clone())
    }

    /// Verify `record` against this linkage and append it on success.
    /// On failure the linkage is left unchanged.
    pub fn apply_record(&mut self, record: RotationRecord) -> Result<(), RotationError> {
        verify_rotation_record(&record, self)?;
        self.records.push(record);
        Ok(())
    }

    /// Serialize the linkage to a JSON `String`. The format is a flat
    /// list of records with binary fields hex-encoded, suitable for
    /// storing alongside the keystore on disk.
    pub fn to_json_string(&self) -> String {
        let records: Vec<serde_json::Value> = self
            .records
            .iter()
            .map(|r| {
                serde_json::json!({
                    "from_address": r.from_address.to_string(),
                    "to_address": r.to_address.to_string(),
                    "predecessor_pubkey": hex::encode(r.predecessor_pubkey.as_bytes()),
                    "successor_pubkey": hex::encode(r.successor_pubkey.as_bytes()),
                    "effective_height": r.effective_height,
                    "signature": hex::encode(r.signature.as_bytes()),
                })
            })
            .collect();
        let envelope = serde_json::json!({
            "version": "axiom-rotation-v2",
            "records": records,
        });
        serde_json::to_string_pretty(&envelope).expect("rotation linkage should always serialise")
    }

    /// Deserialize a linkage from its JSON form. Each record is verified
    /// against the partial linkage built up so far — a tampered file
    /// cannot smuggle in a record that would not have verified at the
    /// time it was originally appended.
    pub fn from_json_str(s: &str) -> Result<Self, RotationError> {
        let value: serde_json::Value =
            serde_json::from_str(s).map_err(|_| RotationError::SignatureVerifyFailed)?;
        let arr = value
            .get("records")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut linkage = Linkage::new();
        for entry in arr {
            let from_address = entry
                .get("from_address")
                .and_then(|v| v.as_str())
                .and_then(|s| Address::from_string(s).ok())
                .ok_or(RotationError::FromAddressMismatch)?;
            let to_address = entry
                .get("to_address")
                .and_then(|v| v.as_str())
                .and_then(|s| Address::from_string(s).ok())
                .ok_or(RotationError::ToAddressMismatch)?;
            let predecessor_bytes = entry
                .get("predecessor_pubkey")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .ok_or(RotationError::EmptyPubkey)?;
            let successor_bytes = entry
                .get("successor_pubkey")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .ok_or(RotationError::EmptyPubkey)?;
            let effective_height = entry
                .get("effective_height")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
                .ok_or(RotationError::EffectiveHeightNotMonotonic)?;
            let signature_bytes = entry
                .get("signature")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .ok_or(RotationError::EmptySignature)?;

            let record = RotationRecord {
                from_address,
                to_address,
                predecessor_pubkey: PublicKey::from_bytes(predecessor_bytes),
                successor_pubkey: PublicKey::from_bytes(successor_bytes),
                effective_height,
                signature: Signature::from_bytes(signature_bytes),
            };
            linkage.apply_record(record)?;
        }
        Ok(linkage)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate a fresh ML-DSA-87 keypair and derive its address.
    fn fresh() -> (KeyPair, PublicKey, Address) {
        let kp = KeyPair::generate().expect("ML-DSA-87 keygen");
        let pk = kp.public_key_struct().expect("public_key_struct");
        let addr = Address::from_pubkey_hash(kp.public_key_hash());
        (kp, pk, addr)
    }

    #[test]
    fn empty_linkage_returns_seed_address() {
        let zero_hash = axiom_primitives::Hash256::zero();
        let seed = Address::from_pubkey_hash(zero_hash);
        let linkage = Linkage::new();
        assert!(linkage.is_empty());
        assert_eq!(linkage.current_address(&seed), seed);
    }

    /// Happy path: build with the old key, verify against an empty
    /// linkage, succeed.
    #[test]
    fn rotation_record_verifies_round_trip() {
        let (old_kp, _old_pk, old_addr) = fresh();
        let (_new_kp, new_pk, new_addr) = fresh();

        let record =
            build_rotation_record(&old_kp, &new_pk, old_addr.clone(), new_addr.clone(), 100)
                .expect("build");

        let linkage = Linkage::new();
        verify_rotation_record(&record, &linkage).expect("verify");
    }

    /// Wrong old key: build with one keypair, but mutate
    /// `predecessor_pubkey` to a different (valid-shaped) key. The
    /// signature was made over the original predecessor; verification
    /// against the new predecessor fails.
    #[test]
    fn wrong_old_key_rejected() {
        let (old_kp, _old_pk, old_addr) = fresh();
        let (_new_kp, new_pk, new_addr) = fresh();

        let mut record =
            build_rotation_record(&old_kp, &new_pk, old_addr, new_addr, 100).expect("build");

        // Substitute a different public key in the predecessor slot. The
        // address already disagrees with the new key, so we expect the
        // address-binding check to fire (which is the cheaper gate).
        let (_other_kp, other_pk, _other_addr) = fresh();
        record.predecessor_pubkey = other_pk;

        let res = verify_rotation_record(&record, &Linkage::new());
        assert!(matches!(res, Err(RotationError::FromAddressMismatch)));
    }

    /// Substituting the predecessor key AND the from_address (so the
    /// address-binding passes) still fails at signature verification —
    /// the substituted key did not sign the canonical body.
    #[test]
    fn wrong_old_key_rejected_at_signature_layer() {
        let (old_kp, _old_pk, old_addr) = fresh();
        let (_new_kp, new_pk, new_addr) = fresh();

        let mut record =
            build_rotation_record(&old_kp, &new_pk, old_addr, new_addr, 100).expect("build");

        let (_other_kp, other_pk, other_addr) = fresh();
        record.predecessor_pubkey = other_pk;
        record.from_address = other_addr;

        let res = verify_rotation_record(&record, &Linkage::new());
        assert!(matches!(res, Err(RotationError::SignatureVerifyFailed)));
    }

    /// Tampering the announced successor pubkey changes the addresses
    /// and breaks the signature. The address-binding gate fires first.
    #[test]
    fn tampered_new_pubkey_rejected() {
        let (old_kp, _old_pk, old_addr) = fresh();
        let (_new_kp, new_pk, new_addr) = fresh();

        let mut record =
            build_rotation_record(&old_kp, &new_pk, old_addr, new_addr, 100).expect("build");

        let (_evil_kp, evil_pk, _evil_addr) = fresh();
        record.successor_pubkey = evil_pk;

        let res = verify_rotation_record(&record, &Linkage::new());
        assert!(matches!(res, Err(RotationError::ToAddressMismatch)));
    }

    /// Bit-flipping any byte of the signature aborts verification with
    /// `SignatureVerifyFailed`.
    #[test]
    fn tampered_signature_rejected() {
        let (old_kp, _old_pk, old_addr) = fresh();
        let (_new_kp, new_pk, new_addr) = fresh();

        let mut record =
            build_rotation_record(&old_kp, &new_pk, old_addr, new_addr, 100).expect("build");

        let mut sig_bytes = record.signature.as_bytes().to_vec();
        sig_bytes[0] ^= 0xFF;
        record.signature = Signature::from_bytes(sig_bytes);

        let res = verify_rotation_record(&record, &Linkage::new());
        assert!(matches!(res, Err(RotationError::SignatureVerifyFailed)));
    }

    /// Linkage A → B → C: each successive record's `from_address` is
    /// the predecessor's `to_address`; `effective_height` strictly
    /// increases. All three records verify and the chain `apply_record`
    /// happily extends the linkage.
    #[test]
    fn linkage_a_b_c_chain_works() {
        let (kp_a, _pk_a, addr_a) = fresh();
        let (kp_b, pk_b, addr_b) = fresh();
        let (_kp_c, pk_c, addr_c) = fresh();

        let rec_ab = build_rotation_record(&kp_a, &pk_b, addr_a.clone(), addr_b.clone(), 10)
            .expect("a→b build");
        let rec_bc = build_rotation_record(&kp_b, &pk_c, addr_b.clone(), addr_c.clone(), 20)
            .expect("b→c build");

        let mut linkage = Linkage::new();
        linkage.apply_record(rec_ab).expect("apply a→b");
        assert_eq!(linkage.len(), 1);
        assert_eq!(linkage.current_address(&addr_a), addr_b);

        linkage.apply_record(rec_bc).expect("apply b→c");
        assert_eq!(linkage.len(), 2);
        assert_eq!(linkage.current_address(&addr_a), addr_c);
    }

    /// A rotation that does not extend the linkage tip is rejected.
    /// Catches an attempt to splice a record in that doesn't follow
    /// the previous `to_address`.
    #[test]
    fn record_that_does_not_extend_tip_is_rejected() {
        let (kp_a, _pk_a, addr_a) = fresh();
        let (kp_b, pk_b, addr_b) = fresh();
        let (_kp_c, pk_c, addr_c) = fresh();

        let rec_ab =
            build_rotation_record(&kp_a, &pk_b, addr_a.clone(), addr_b.clone(), 10).expect("a→b");
        // Now build a record that pretends to start from A again
        // (instead of extending B). Even with a valid signature by A,
        // it does not extend the linkage tip.
        let rec_ax =
            build_rotation_record(&kp_a, &pk_c, addr_a.clone(), addr_c.clone(), 20).expect("a→c");

        let mut linkage = Linkage::new();
        linkage.apply_record(rec_ab).expect("a→b ok");
        let res = linkage.apply_record(rec_ax);
        assert!(matches!(res, Err(RotationError::LinkageTipMismatch)));
        // The linkage was unchanged by the failed apply.
        assert_eq!(linkage.len(), 1);

        let _ = kp_b;
    }

    /// `effective_height` must strictly increase along the chain.
    #[test]
    fn effective_height_must_strictly_increase() {
        let (kp_a, _pk_a, addr_a) = fresh();
        let (kp_b, pk_b, addr_b) = fresh();
        let (_kp_c, pk_c, addr_c) = fresh();

        let rec_ab = build_rotation_record(&kp_a, &pk_b, addr_a, addr_b.clone(), 100).expect("a→b");
        // b→c at the SAME effective height as a→b → reject.
        let rec_bc_same = build_rotation_record(&kp_b, &pk_c, addr_b.clone(), addr_c.clone(), 100)
            .expect("b→c build");

        let mut linkage = Linkage::new();
        linkage.apply_record(rec_ab).expect("a→b ok");
        let res = linkage.apply_record(rec_bc_same);
        assert!(matches!(
            res,
            Err(RotationError::EffectiveHeightNotMonotonic)
        ));
    }

    /// JSON round-trip: serialise a populated linkage, parse the JSON
    /// back, get an equivalent linkage that re-verifies on the way in.
    #[test]
    fn linkage_json_round_trip() {
        let (kp_a, _pk_a, addr_a) = fresh();
        let (kp_b, pk_b, addr_b) = fresh();
        let (_kp_c, pk_c, addr_c) = fresh();

        let mut linkage = Linkage::new();
        linkage
            .apply_record(
                build_rotation_record(&kp_a, &pk_b, addr_a.clone(), addr_b.clone(), 5).unwrap(),
            )
            .unwrap();
        linkage
            .apply_record(
                build_rotation_record(&kp_b, &pk_c, addr_b.clone(), addr_c.clone(), 6).unwrap(),
            )
            .unwrap();

        let json = linkage.to_json_string();
        let parsed = Linkage::from_json_str(&json).expect("round-trip");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.current_address(&addr_a), addr_c);
        // Each record's binary fields survived the hex round-trip exactly.
        for (a, b) in linkage.records.iter().zip(parsed.records.iter()) {
            assert_eq!(a.from_address, b.from_address);
            assert_eq!(a.to_address, b.to_address);
            assert_eq!(
                a.predecessor_pubkey.as_bytes(),
                b.predecessor_pubkey.as_bytes()
            );
            assert_eq!(a.successor_pubkey.as_bytes(), b.successor_pubkey.as_bytes());
            assert_eq!(a.effective_height, b.effective_height);
            assert_eq!(a.signature.as_bytes(), b.signature.as_bytes());
        }
    }

    /// A tampered linkage JSON (one signature byte flipped on the
    /// second record) fails to load — `from_json_str` re-verifies each
    /// record on its way in and rejects the file.
    #[test]
    fn tampered_linkage_json_fails_to_load() {
        let (kp_a, _pk_a, addr_a) = fresh();
        let (kp_b, pk_b, addr_b) = fresh();
        let (_kp_c, pk_c, addr_c) = fresh();

        let mut linkage = Linkage::new();
        linkage
            .apply_record(build_rotation_record(&kp_a, &pk_b, addr_a, addr_b.clone(), 5).unwrap())
            .unwrap();
        linkage
            .apply_record(build_rotation_record(&kp_b, &pk_c, addr_b, addr_c, 6).unwrap())
            .unwrap();

        let mut json = linkage.to_json_string();
        // Find the signature hex string of the SECOND record and flip
        // a single hex digit so the byte-decoded signature differs.
        let last_idx = json.rfind("\"signature\"").expect("signature field");
        let colon = json[last_idx..].find(':').unwrap() + last_idx;
        let q1 = json[colon..].find('"').unwrap() + colon + 1;
        let q2 = json[q1..].find('"').unwrap() + q1;
        let (lhs, rhs) = json.split_at_mut(q1);
        let _ = lhs; // silence unused
        let bytes = unsafe { rhs.as_bytes_mut() };
        // Flip the very first hex character of the signature.
        bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
        // Drop the &mut to satisfy the borrow checker before the next op.
        let _ = q2;

        let res = Linkage::from_json_str(&json);
        assert!(res.is_err(), "tampered signature must fail to load");
    }

    /// "Old address funds remain spendable" — modelled here at the
    /// type level: after a rotation A → B, the wallet still holds the
    /// keypair for A (the caller never destroyed it), and that keypair
    /// can still produce ML-DSA-87 signatures over arbitrary messages.
    /// The chain has no concept of "this address can no longer sign";
    /// rotation is a wallet-side identity statement, not a UTXO-level
    /// invalidation.
    #[test]
    fn old_keypair_remains_able_to_sign_after_rotation() {
        let (kp_a, _pk_a, addr_a) = fresh();
        let (_kp_b, pk_b, addr_b) = fresh();

        let rec = build_rotation_record(&kp_a, &pk_b, addr_a, addr_b, 1).expect("build");
        let mut linkage = Linkage::new();
        linkage.apply_record(rec).expect("apply");

        // Despite the rotation, kp_a is still in the caller's hand and
        // still produces a valid signature. (UTXOs spent later with
        // this signature would be accepted by validation just like any
        // other UTXO spend — the chain does not look at the linkage.)
        let arbitrary_message = b"old address spend";
        let sig = kp_a.sign(arbitrary_message).expect("sign with old key");
        assert!(!sig.is_empty());
        assert!(kp_a.verify(arbitrary_message, &sig).expect("verify"));
    }
}
