// Copyright (c) 2026 Kantoshi Miyamura
//
// V2-dev triage: end-to-end nonce lifecycle.
//
// This test file is a diagnostic, not a verification. It does not assert
// what the chain *should* do — it asserts what the live code paths
// actually do, so a human reading the results can decide whether the
// behaviour is a bug or intentional.
//
// The four code paths under inspection:
//
//   1. axiom-node::state::ChainState::apply_block (state.rs:215-222):
//          batch.put_nonce(&pubkey_hash, tx.nonce.checked_add(1)?);
//      Stores `tx.nonce + 1` per applied non-coinbase transaction.
//
//   2. axiom-node::Node::get_nonce (node.rs:739-742):
//          nonce_tracker.get_nonce(pubkey_hash)?.unwrap_or(0)
//      Returns the raw stored value — no transformation.
//
//   3. axiom-rpc::handlers::get_nonce (handlers.rs:200-216):
//          NonceResponse { nonce: node.get_nonce(...) }
//      Forwards the node's raw stored value.
//
//   4. axiom-cli wallet send path (axiom.rs:883-897):
//          let last_used_nonce: u64 = rpc_response.nonce;
//          let nonce = last_used_nonce.saturating_add(1);
//      Calls the RPC value `last_used_nonce`, then adds 1.
//
//   5. axiom-node::validation::TransactionValidator::validate_transaction
//      (validation.rs:247-262):
//          let last_used_nonce = nonce_tracker.get_nonce(...)?.unwrap_or(0);
//          let expected_nonce = last_used_nonce.checked_add(1)?;
//          require: tx.nonce == expected_nonce
//      Reads the raw stored value, demands tx.nonce == stored + 1.
//
// Composed lifecycle for a sequence of three transactions from the same
// address against an initially-empty NonceTracker:
//
//   Tx 1:
//     RPC returns                       0
//     Wallet computes tx.nonce          0 + 1 = 1
//     Validator stored=0, expected=1, tx.nonce=1 → ACCEPTED
//     Apply writes                      1 + 1 = 2
//
//   Tx 2:
//     RPC returns                       2          (NOT 1)
//     Wallet computes tx.nonce          2 + 1 = 3  (NOT 2)
//     Validator stored=2, expected=3, tx.nonce=3 → ACCEPTED
//     Apply writes                      3 + 1 = 4
//
//   Tx 3:
//     RPC returns                       4          (NOT 2)
//     Wallet computes tx.nonce          4 + 1 = 5  (NOT 3)
//     Validator stored=4, expected=5, tx.nonce=5 → ACCEPTED
//     Apply writes                      5 + 1 = 6
//
// On-chain `tx.nonce` values for successive transactions from the same
// address are therefore **odd-only**: 1, 3, 5, 7, … This is internally
// consistent (every component agrees), but the user-visible nonce field
// jumps by 2 per applied transaction rather than the conventional 1.
//
// The tests in this file pin that observation down so a future fix has
// a regression baseline.

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

fn make_tx(pubkey_bytes: Vec<u8>, nonce: u64) -> Transaction {
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

fn pubkey_hash(pubkey_bytes: &[u8]) -> Hash256 {
    axiom_crypto::hash256(pubkey_bytes)
}

/// Returns `Some((expected, actual))` if validation rejected with
/// `InvalidNonce`. Returns `None` if the nonce gate passed (later
/// failures e.g. signature verification are ignored — they are
/// downstream of the property we are inspecting).
fn nonce_check_outcome(validator: &TransactionValidator, tx: &Transaction) -> Option<(u64, u64)> {
    match validator.validate_transaction(tx) {
        Err(ValidationError::InvalidNonce { expected, actual }) => Some((expected, actual)),
        _ => None,
    }
}

/// Mirror of `axiom-node::state::ChainState::apply_block`'s nonce write
/// (state.rs:215-222). Used to simulate the post-apply storage state
/// without standing up a full block / mining harness.
fn simulate_apply_blocks_nonce_write(db: &Database, addr: &Hash256, tx_nonce: u64) {
    let nt = NonceTracker::new(db);
    nt.set_nonce(addr, tx_nonce + 1).unwrap();
}

/// Mirror of the wallet's nonce-derivation step
/// (axiom-cli/src/bin/axiom.rs:883-897): reads the RPC value (raw
/// stored value) and adds 1.
fn simulate_wallet_picks_next_nonce(db: &Database, addr: &Hash256) -> u64 {
    let nt = NonceTracker::new(db);
    let last_used_nonce_rpc = nt.get_nonce(addr).unwrap().unwrap_or(0);
    last_used_nonce_rpc.saturating_add(1)
}

// ── Triage tests ────────────────────────────────────────────────────────────

/// Property the system implements end-to-end. Three sequential
/// transactions from the same wallet (using the wallet's RPC-driven
/// nonce derivation) ARE all accepted by the validator, **but** the
/// `tx.nonce` field on the wire takes the values 1, 3, 5 — not 1, 2, 3.
///
/// This is the empirical answer to the triage question. The system
/// works as a closed loop; the surprising part is the on-chain
/// representation of the per-account counter.
#[test]
fn three_sequential_txs_are_accepted_with_odd_only_nonces() {
    let (_temp, db) = create_test_db();

    let pubkey_bytes = vec![0x11u8; 2592];
    let addr = pubkey_hash(&pubkey_bytes);

    // ── Tx 1 ─────────────────────────────────────────────────────────────
    let nonce1 = simulate_wallet_picks_next_nonce(&db, &addr);
    assert_eq!(nonce1, 1, "first tx: wallet derives nonce 1");

    let tx1 = make_tx(pubkey_bytes.clone(), nonce1);
    {
        let utxo_set = UtxoSet::new(&db);
        let nonce_tracker = NonceTracker::new(&db);
        let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);
        assert!(
            nonce_check_outcome(&validator, &tx1).is_none(),
            "tx 1 (nonce=1) must pass the nonce gate against empty storage"
        );
    }
    simulate_apply_blocks_nonce_write(&db, &addr, nonce1);
    // Storage now: tx1.nonce + 1 = 2.

    // ── Tx 2 ─────────────────────────────────────────────────────────────
    let nonce2 = simulate_wallet_picks_next_nonce(&db, &addr);
    assert_eq!(
        nonce2, 3,
        "second tx: wallet derives nonce 3 (NOT 2) — wallet reads RPC value 2 and adds 1"
    );

    let tx2 = make_tx(pubkey_bytes.clone(), nonce2);
    {
        let utxo_set = UtxoSet::new(&db);
        let nonce_tracker = NonceTracker::new(&db);
        let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);
        assert!(
            nonce_check_outcome(&validator, &tx2).is_none(),
            "tx 2 (nonce=3) must pass the nonce gate"
        );

        // And the conventional choice — `tx.nonce = 2` — is REJECTED:
        let tx2_naive = make_tx(pubkey_bytes.clone(), 2);
        let outcome = nonce_check_outcome(&validator, &tx2_naive);
        assert_eq!(
            outcome,
            Some((3, 2)),
            "the conventional value tx.nonce=2 (one above the previous tx's nonce=1) is rejected"
        );
    }
    simulate_apply_blocks_nonce_write(&db, &addr, nonce2);
    // Storage now: tx2.nonce + 1 = 4.

    // ── Tx 3 ─────────────────────────────────────────────────────────────
    let nonce3 = simulate_wallet_picks_next_nonce(&db, &addr);
    assert_eq!(
        nonce3, 5,
        "third tx: wallet derives nonce 5 (NOT 3) — odd-only sequence"
    );

    let tx3 = make_tx(pubkey_bytes.clone(), nonce3);
    {
        let utxo_set = UtxoSet::new(&db);
        let nonce_tracker = NonceTracker::new(&db);
        let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);
        assert!(
            nonce_check_outcome(&validator, &tx3).is_none(),
            "tx 3 (nonce=5) must pass the nonce gate"
        );
    }
    simulate_apply_blocks_nonce_write(&db, &addr, nonce3);
    // Storage now: tx3.nonce + 1 = 6.

    // Final storage state is 6 after three applied txs.
    let final_storage = NonceTracker::new(&db)
        .get_nonce(&addr)
        .unwrap()
        .unwrap_or(0);
    assert_eq!(
        final_storage, 6,
        "after three applied txs: storage = (last tx.nonce) + 1 = 5 + 1 = 6"
    );
}

/// Document the exact nonce sequence on the wire for N applied
/// transactions: tx.nonce[i] = 2*i + 1.
#[test]
fn on_chain_tx_nonce_sequence_is_2i_plus_1() {
    let (_temp, db) = create_test_db();
    let pubkey_bytes = vec![0x22u8; 2592];
    let addr = pubkey_hash(&pubkey_bytes);

    let mut wire_nonces = Vec::new();
    for _ in 0..6 {
        let n = simulate_wallet_picks_next_nonce(&db, &addr);
        wire_nonces.push(n);
        simulate_apply_blocks_nonce_write(&db, &addr, n);
    }

    assert_eq!(
        wire_nonces,
        vec![1, 3, 5, 7, 9, 11],
        "the on-wire tx.nonce field takes only odd values (2*i+1) under the current apply/wallet/validator chain"
    );
}

/// Counter-experiment: if `apply_block` wrote `tx.nonce` (not
/// `tx.nonce + 1`), the wallet's `RPC + 1` derivation and the
/// validator's `stored + 1` requirement would give the conventional
/// 1, 2, 3, 4, … sequence with the wire and the wallet aligned.
///
/// We simulate that hypothetical "fix" here so the recommended change
/// is backed by an executable demonstration, not a paper argument.
#[test]
fn hypothetical_apply_writes_raw_nonce_yields_consecutive_sequence() {
    let (_temp, db) = create_test_db();
    let pubkey_bytes = vec![0x33u8; 2592];
    let addr = pubkey_hash(&pubkey_bytes);

    // The hypothetical fix: apply writes `tx.nonce` rather than
    // `tx.nonce + 1`. Everything else (wallet, validator, RPC) is
    // unchanged.
    let hypothetical_apply = |db: &Database, addr: &Hash256, tx_nonce: u64| {
        NonceTracker::new(db).set_nonce(addr, tx_nonce).unwrap();
    };

    let mut wire_nonces = Vec::new();
    for _ in 0..6 {
        // Wallet derivation is unchanged: read RPC value, add 1.
        let n = simulate_wallet_picks_next_nonce(&db, &addr);
        wire_nonces.push(n);

        // Validator check is unchanged: stored + 1 == tx.nonce.
        let tx = make_tx(pubkey_bytes.clone(), n);
        let utxo_set = UtxoSet::new(&db);
        let nonce_tracker = NonceTracker::new(&db);
        let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);
        assert!(
            nonce_check_outcome(&validator, &tx).is_none(),
            "under the hypothetical fix, validator still accepts wallet-derived nonce {n}"
        );

        // Apply writes the raw nonce (the proposed fix).
        hypothetical_apply(&db, &addr, n);
    }

    assert_eq!(
        wire_nonces,
        vec![1, 2, 3, 4, 5, 6],
        "with apply_block writing tx.nonce instead of tx.nonce + 1, the on-wire nonce sequence is 1,2,3,..."
    );

    let final_storage = NonceTracker::new(&db)
        .get_nonce(&addr)
        .unwrap()
        .unwrap_or(0);
    assert_eq!(
        final_storage, 6,
        "after six txs under the hypothetical fix, storage = last_used_nonce = 6"
    );
}

/// Wallet → RPC → storage round-trip. The /nonce endpoint returns the
/// raw stored value; the wallet treats that value as the previous
/// nonce and adds 1. Pin both halves so a future change to either
/// surfaces here.
#[test]
fn rpc_returns_raw_stored_value_and_wallet_adds_one() {
    let (_temp, db) = create_test_db();
    let pubkey_bytes = vec![0x44u8; 2592];
    let addr = pubkey_hash(&pubkey_bytes);

    // Pre-load storage with an arbitrary value as if a tx had been
    // applied. This is a synthetic state; the value 17 doesn't have
    // to be in the odd-or-even sequence — the test pins the round-
    // trip mechanics, not the sequence shape.
    NonceTracker::new(&db).set_nonce(&addr, 17).unwrap();

    // RPC returns the stored value verbatim (Node::get_nonce ⇒
    // axiom_rpc::handlers::get_nonce ⇒ NonceResponse.nonce).
    let rpc_value = NonceTracker::new(&db)
        .get_nonce(&addr)
        .unwrap()
        .unwrap_or(0);
    assert_eq!(rpc_value, 17);

    // Wallet adds 1 (axiom-cli/src/bin/axiom.rs:897 — saturating_add).
    let wallet_nonce = rpc_value.saturating_add(1);
    assert_eq!(wallet_nonce, 18);

    // Validator demands stored + 1.
    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);
    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);
    let tx = make_tx(pubkey_bytes, wallet_nonce);
    assert!(
        nonce_check_outcome(&validator, &tx).is_none(),
        "wallet-derived nonce {wallet_nonce} (= rpc 17 + 1) must pass the gate (validator expects stored + 1 = 18)"
    );
}
