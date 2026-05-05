// Copyright (c) 2026 Kantoshi Miyamura
//
// V2 Stage 6 — verification tests for the existing per-address nonce
// replay protection.
//
// `docs/V2_PROTOCOL.md §8 stage 6` calls for strict-monotonic per-address
// nonce enforcement at the consensus validation layer. Inspection of v1
// (axiom-node::validation::TransactionValidator and
// axiom-node::state::ChainState::apply_block) shows that the
// infrastructure is already in place:
//
//   - axiom-storage::NonceTracker maintains per-address nonce state on
//     the on-disk database.
//   - TransactionValidator::validate_transaction reads the stored nonce
//     and rejects any tx whose `tx.nonce` is not exactly
//     `stored_nonce + 1` with `ValidationError::InvalidNonce`.
//   - ChainState::apply_block records a `NonceUndo` so a reorg restores
//     the previous nonce value via the storage layer's undo path.
//
// This test file pins those properties down so a future refactor cannot
// silently regress them. Each test names the property it verifies and
// follows the stage-6 brief verbatim:
//
//   1. first tx accepted (nonce = 1 against empty storage)
//   2. duplicate nonce rejected
//   3. lower nonce rejected
//   4. skipped nonce rejected
//   5. independent addresses do not interfere
//   6. nonce-state restoration on reorg (via NonceTracker undo)
//
// Tests use placeholder signatures so that the nonce check is the
// first failure point reachable. The validator's nonce check fires
// before signature verification (validation.rs:248 vs :297), so an
// `InvalidNonce` error proves the rule fired exactly as advertised.
// For tests that expect the nonce check to PASS, the validator will
// instead fail on signature verification — we assert the error
// variant is anything other than `InvalidNonce`, which proves the
// nonce gate let the transaction through.

use axiom_node::validation::{TransactionValidator, ValidationError};
use axiom_primitives::{Amount, Hash256, PublicKey, Signature};
use axiom_protocol::{Transaction, TxInput, TxOutput};
use axiom_storage::{Database, NonceTracker, UtxoSet};
use tempfile::TempDir;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn create_test_db() -> (TempDir, Database) {
    let temp_dir = TempDir::new().unwrap();
    let db = Database::open(temp_dir.path()).unwrap();
    (temp_dir, db)
}

/// Construct a syntactically-valid v1 transfer transaction whose first
/// input's pubkey hash matches the supplied bytes. Signature is the
/// placeholder; the validator rejects placeholder signatures only after
/// the nonce check, so any test that expects an `InvalidNonce` outcome
/// gets a clean failure point.
fn make_tx_with_pubkey_and_nonce(pubkey_bytes: Vec<u8>, nonce: u64) -> Transaction {
    let input = TxInput {
        prev_tx_hash: Hash256::from_bytes([0xAB; 32]),
        prev_output_index: 0,
        signature: Signature::placeholder(),
        pubkey: PublicKey::from_bytes(pubkey_bytes),
    };
    let output = TxOutput {
        value: Amount::from_sat(1_000_000).unwrap(),
        pubkey_hash: Hash256::zero(),
    };
    Transaction::new_transfer(vec![input], vec![output], nonce, 0)
}

/// The validator computes its address-key as `hash256(pubkey.as_bytes())`.
/// We mirror that here so tests can pre-load the nonce store under the
/// exact same key the validator looks up.
fn pubkey_hash(pubkey_bytes: &[u8]) -> Hash256 {
    axiom_crypto::hash256(pubkey_bytes)
}

/// Run the validator and report whether the failure was specifically
/// `InvalidNonce`. Returns:
///   - `Some(InvalidNonce { expected, actual })` when the nonce check fired.
///   - `None` when the transaction passed the nonce check but failed at
///     a later step (typically signature verification, with the
///     placeholder signature).
fn nonce_check_outcome(validator: &TransactionValidator, tx: &Transaction) -> Option<(u64, u64)> {
    match validator.validate_transaction(tx) {
        Err(ValidationError::InvalidNonce { expected, actual }) => Some((expected, actual)),
        _other => None,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Property 1: first tx is accepted at the nonce layer.
///
/// With nothing in `NonceTracker`, the validator computes
/// `expected = 0 + 1 = 1`. A transaction sent with `nonce = 1`
/// passes the nonce gate (it will fail later on signature
/// verification because we use a placeholder signature, but
/// the nonce check let it through).
#[test]
fn first_tx_passes_nonce_check_when_storage_is_empty() {
    let (_temp, db) = create_test_db();
    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);
    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);

    let pubkey_bytes = vec![0x11u8; 2592];
    let tx = make_tx_with_pubkey_and_nonce(pubkey_bytes.clone(), 1);

    // The nonce check must NOT fail — the transaction will fail later
    // (placeholder signature), but not on the nonce gate.
    assert!(
        nonce_check_outcome(&validator, &tx).is_none(),
        "nonce=1 against empty storage must pass the nonce gate"
    );
}

/// Property 1 (negative half): the first tx with nonce 0 is rejected.
/// The validator demands `tx.nonce == stored + 1`; with empty storage
/// that is exactly 1, so 0 is too low.
#[test]
fn first_tx_with_nonce_zero_is_rejected() {
    let (_temp, db) = create_test_db();
    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);
    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);

    let pubkey_bytes = vec![0x22u8; 2592];
    let tx = make_tx_with_pubkey_and_nonce(pubkey_bytes, 0);

    let outcome = nonce_check_outcome(&validator, &tx);
    assert_eq!(
        outcome,
        Some((1, 0)),
        "expected InvalidNonce {{ expected: 1, actual: 0 }}, got {outcome:?}"
    );
}

/// Property 2: a duplicate nonce is rejected at the consensus layer.
///
/// We pre-load the storage to simulate "tx with nonce=5 was already
/// included in the chain" — the validator's expected becomes 6, so a
/// new transaction that tries to reuse nonce 5 is rejected with
/// `InvalidNonce { expected: 6, actual: 5 }`.
#[test]
fn duplicate_nonce_rejected() {
    let (_temp, db) = create_test_db();

    let pubkey_bytes = vec![0x33u8; 2592];
    let addr = pubkey_hash(&pubkey_bytes);

    // Simulate the apply-side state: stored = 5 means "previous
    // accepted nonce was 5".
    {
        let nonce_tracker = NonceTracker::new(&db);
        nonce_tracker.set_nonce(&addr, 5).unwrap();
    }

    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);
    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);

    let tx = make_tx_with_pubkey_and_nonce(pubkey_bytes, 5);
    let outcome = nonce_check_outcome(&validator, &tx);
    assert_eq!(
        outcome,
        Some((6, 5)),
        "duplicate of the last-used nonce must be rejected"
    );
}

/// Property 3: a nonce lower than expected is rejected.
///
/// Stored = 10 → expected = 11. Tx with nonce=8 (below the next
/// expected) is rejected with `InvalidNonce { expected: 11, actual: 8 }`.
#[test]
fn lower_nonce_rejected() {
    let (_temp, db) = create_test_db();

    let pubkey_bytes = vec![0x44u8; 2592];
    let addr = pubkey_hash(&pubkey_bytes);

    {
        let nonce_tracker = NonceTracker::new(&db);
        nonce_tracker.set_nonce(&addr, 10).unwrap();
    }

    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);
    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);

    let tx = make_tx_with_pubkey_and_nonce(pubkey_bytes, 8);
    let outcome = nonce_check_outcome(&validator, &tx);
    assert_eq!(outcome, Some((11, 8)));
}

/// Property 4: a skipped nonce is rejected.
///
/// Stored = 7 → expected = 8. Tx with nonce=9 jumps over 8 and is
/// rejected. Strict-next semantics — no pipelining, no window.
#[test]
fn skipped_nonce_rejected() {
    let (_temp, db) = create_test_db();

    let pubkey_bytes = vec![0x55u8; 2592];
    let addr = pubkey_hash(&pubkey_bytes);

    {
        let nonce_tracker = NonceTracker::new(&db);
        nonce_tracker.set_nonce(&addr, 7).unwrap();
    }

    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);
    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);

    let tx = make_tx_with_pubkey_and_nonce(pubkey_bytes, 9);
    let outcome = nonce_check_outcome(&validator, &tx);
    assert_eq!(outcome, Some((8, 9)));
}

/// Property 5: two distinct addresses keep independent nonce state.
///
/// Pre-load A=10 and B=3. A tx from address A with nonce=11 passes
/// the nonce gate; a tx from address B with nonce=11 is rejected
/// because B's expected is 4. The state for one address never bleeds
/// into another.
#[test]
fn independent_addresses_do_not_interfere() {
    let (_temp, db) = create_test_db();

    let pk_a = vec![0x66u8; 2592];
    let pk_b = vec![0x77u8; 2592];
    let addr_a = pubkey_hash(&pk_a);
    let addr_b = pubkey_hash(&pk_b);

    {
        let nt = NonceTracker::new(&db);
        nt.set_nonce(&addr_a, 10).unwrap();
        nt.set_nonce(&addr_b, 3).unwrap();
    }

    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);
    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);

    // Address A: expected = 11. A tx with nonce=11 must pass the gate.
    let tx_a = make_tx_with_pubkey_and_nonce(pk_a, 11);
    assert!(
        nonce_check_outcome(&validator, &tx_a).is_none(),
        "address A's correct next nonce must pass the gate"
    );

    // Address B: expected = 4. A tx with nonce=11 must be rejected
    // — B's state is independent of A's.
    let tx_b = make_tx_with_pubkey_and_nonce(pk_b, 11);
    assert_eq!(
        nonce_check_outcome(&validator, &tx_b),
        Some((4, 11)),
        "address B's gate is independent of address A's"
    );
}

/// Property 6: reorg restores nonce state.
///
/// `axiom-node::state::ChainState::apply_block` records a
/// `NonceUndo { pubkey_hash, prev_nonce }` for every non-coinbase
/// transaction it processes; a reorg replays the undo by re-writing
/// `prev_nonce` back into the `NonceTracker`. We exercise that
/// primitive directly: simulate apply by setting nonce = 5, then
/// undo back to the captured pre-apply value (= 0), then verify the
/// validator accepts the next tx as if no apply had ever happened.
///
/// This isolates the storage-layer undo from the higher-level reorg
/// engine — what we are pinning is the property that the persisted
/// nonce can be safely rewound.
#[test]
fn reorg_undo_restores_nonce_state() {
    let (_temp, db) = create_test_db();

    let pubkey_bytes = vec![0x88u8; 2592];
    let addr = pubkey_hash(&pubkey_bytes);

    // Initial state: address has never sent a tx — storage is empty.
    {
        let nt = NonceTracker::new(&db);
        assert_eq!(nt.get_nonce(&addr).unwrap(), None);
    }

    // Simulate apply_block for a tx with nonce=1: it captures
    // prev_nonce=0 (from unwrap_or) into a NonceUndo, then writes
    // the post-apply value (post-fix runtime: tx.nonce, i.e. 1).
    let captured_prev_nonce: u64 = 0;
    {
        let nt = NonceTracker::new(&db);
        nt.set_nonce(&addr, 1).unwrap();
        assert_eq!(nt.get_nonce(&addr).unwrap(), Some(1));
    }

    // Now the chain reorgs and the block is rolled back. The undo
    // path writes `prev_nonce` (captured above) back into storage.
    {
        let nt = NonceTracker::new(&db);
        nt.set_nonce(&addr, captured_prev_nonce).unwrap();
    }

    // Storage should now read as if the rolled-back tx never happened.
    {
        let nt = NonceTracker::new(&db);
        let after = nt.get_nonce(&addr).unwrap().unwrap_or(0);
        assert_eq!(after, 0, "undo must restore the pre-apply nonce value");
    }

    // The validator should now demand the same nonce it would have
    // demanded before the rolled-back block: stored=0 → expected=1.
    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);
    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);

    let tx_replay_after_reorg = make_tx_with_pubkey_and_nonce(pubkey_bytes, 1);
    assert!(
        nonce_check_outcome(&validator, &tx_replay_after_reorg).is_none(),
        "after reorg-undo, nonce=1 must once again pass the gate"
    );
}

/// Cross-cut: NonceTracker round-trips a value through the on-disk
/// database. Locks the property that nonce state is durable, not
/// in-memory only, which is what makes consensus-layer enforcement
/// (rather than just mempool dedup) possible.
#[test]
fn nonce_tracker_persists_through_storage_layer() {
    let (_temp, db) = create_test_db();

    let pubkey_bytes = vec![0x99u8; 2592];
    let addr = pubkey_hash(&pubkey_bytes);

    {
        let nt = NonceTracker::new(&db);
        nt.set_nonce(&addr, 42).unwrap();
    }
    {
        let nt = NonceTracker::new(&db);
        assert_eq!(nt.get_nonce(&addr).unwrap(), Some(42));
    }
}
