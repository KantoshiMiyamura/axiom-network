// Copyright (c) 2026 Kantoshi Miyamura

// Canonical transaction serialization. Format is fixed; any drift between
// builder and validator silently breaks all signature verification.
//
// Wire format (all integers little-endian):
//   version(4) tx_type(1) input_count(8)
//   per input: prev_tx_hash(32) prev_output_index(4) signature(4627) pubkey(2592)
//   output_count(8)
//   per output: value(8) pubkey_hash(32)
//   nonce(8) locktime(4)
//   has_memo(1) [memo(80)]
//   ConfidentialTransfer only:
//     conf_output_count(8)
//     per conf output: commitment(32) pubkey_hash(32) proof_len(8) range_proof(proof_len)
//     has_balance_commitment(1) [balance_commitment(32)]

use crate::{ConfidentialTxOutput, Error, Result, Transaction, TransactionType, TxInput, TxOutput};
use axiom_primitives::{Amount, Hash256, PublicKey, Signature};

/// Serialize transaction to a deterministic byte representation.
pub fn serialize_transaction(tx: &Transaction) -> Vec<u8> {
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&tx.version.to_le_bytes());

    let tx_type_byte = match tx.tx_type {
        TransactionType::Coinbase => 0u8,
        TransactionType::Transfer => 1u8,
        TransactionType::ConfidentialTransfer => 2u8,
        // UsernameRegistration serializes identically to Transfer;
        // the tx_type byte (3) distinguishes it for validation.
        TransactionType::UsernameRegistration => 3u8,
    };
    bytes.push(tx_type_byte);

    bytes.extend_from_slice(&(tx.inputs.len() as u64).to_le_bytes());

    for input in &tx.inputs {
        bytes.extend_from_slice(input.prev_tx_hash.as_bytes());
        bytes.extend_from_slice(&input.prev_output_index.to_le_bytes());
        bytes.extend_from_slice(input.signature.as_bytes());
        bytes.extend_from_slice(input.pubkey.as_bytes());
    }

    bytes.extend_from_slice(&(tx.outputs.len() as u64).to_le_bytes());

    for output in &tx.outputs {
        bytes.extend_from_slice(&output.value.as_sat().to_le_bytes());
        bytes.extend_from_slice(output.pubkey_hash.as_bytes());
    }

    bytes.extend_from_slice(&tx.nonce.to_le_bytes());
    bytes.extend_from_slice(&tx.locktime.to_le_bytes());

    match &tx.memo {
        Some(memo_bytes) => {
            bytes.push(1u8);
            bytes.extend_from_slice(memo_bytes);
        }
        None => {
            bytes.push(0u8);
        }
    }

    // Confidential fields only appended for ConfidentialTransfer — preserves
    // all existing Coinbase/Transfer transaction hashes.
    if matches!(tx.tx_type, TransactionType::ConfidentialTransfer) {
        bytes.extend_from_slice(&(tx.confidential_outputs.len() as u64).to_le_bytes());
        for out in &tx.confidential_outputs {
            bytes.extend_from_slice(&out.commitment);
            bytes.extend_from_slice(&out.pubkey_hash);
            bytes.extend_from_slice(&(out.range_proof_bytes.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&out.range_proof_bytes);
        }

        match &tx.balance_commitment {
            Some(bc) => {
                bytes.push(1u8);
                bytes.extend_from_slice(bc);
            }
            None => {
                bytes.push(0u8);
            }
        }
    }

    bytes
}

/// Serialize transaction for TXID computation — all signature fields replaced with
/// zero-filled placeholders so that the TXID is independent of the signature bytes.
///
/// TXID malleability fix: Bitcoin-style commitment IDs must not include witness/signature
/// data.  Using the full serialization (with live signature bytes) would allow two
/// otherwise-identical transactions to carry different TXIDs, breaking UTXO lookups and
/// enabling double-spend confusion.
pub fn serialize_transaction_unsigned(tx: &Transaction) -> Vec<u8> {
    let placeholder_sig = Signature::placeholder();
    let unsigned_inputs: Vec<TxInput> = tx
        .inputs
        .iter()
        .map(|i| TxInput {
            prev_tx_hash: i.prev_tx_hash,
            prev_output_index: i.prev_output_index,
            signature: placeholder_sig.clone(),
            pubkey: i.pubkey.clone(),
        })
        .collect();
    let unsigned_tx = Transaction {
        inputs: unsigned_inputs,
        ..tx.clone()
    };
    serialize_transaction(&unsigned_tx)
}

/// Deserialize transaction from canonical bytes.
pub fn deserialize_transaction(bytes: &[u8]) -> Result<Transaction> {
    let mut offset = 0;

    if bytes.len() < offset + 4 {
        return Err(Error::Deserialization(
            "insufficient data for version".into(),
        ));
    }
    let version = u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]);
    offset += 4;

    if bytes.len() < offset + 1 {
        return Err(Error::Deserialization(
            "insufficient data for tx_type".into(),
        ));
    }
    let tx_type = match bytes[offset] {
        0 => TransactionType::Coinbase,
        1 => TransactionType::Transfer,
        2 => {
            #[cfg(not(feature = "axiom-ct"))]
            return Err(Error::Deserialization(
                "ConfidentialTransfer not supported (axiom-ct feature disabled)".into(),
            ));
            #[cfg(feature = "axiom-ct")]
            {
                TransactionType::ConfidentialTransfer
            }
        }
        3 => TransactionType::UsernameRegistration,
        _ => return Err(Error::Deserialization("invalid tx_type".into())),
    };
    offset += 1;

    if bytes.len() < offset + 8 {
        return Err(Error::Deserialization(
            "insufficient data for input_count".into(),
        ));
    }
    let input_count = u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]) as usize;
    offset += 8;

    const MAX_TX_INPUTS: usize = 10_000;
    if input_count > MAX_TX_INPUTS {
        return Err(Error::Deserialization("too many inputs".into()));
    }

    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        // 32 (prev_tx_hash) + 4 (prev_output_index) + 4627 (ML-DSA-87 sig) + 2592 (ML-DSA-87 vk) = 7255
        if bytes.len() < offset + 7255 {
            return Err(Error::Deserialization("insufficient data for input".into()));
        }

        let prev_tx_hash = Hash256::from_slice(&bytes[offset..offset + 32])?;
        offset += 32;

        let prev_output_index = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;

        let signature = Signature::from_slice(&bytes[offset..offset + 4627])?;
        offset += 4627;

        let pubkey = PublicKey::from_slice(&bytes[offset..offset + 2592])?;
        offset += 2592;

        inputs.push(TxInput {
            prev_tx_hash,
            prev_output_index,
            signature,
            pubkey,
        });
    }

    if bytes.len() < offset + 8 {
        return Err(Error::Deserialization(
            "insufficient data for output_count".into(),
        ));
    }
    let output_count = u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]) as usize;
    offset += 8;

    const MAX_TX_OUTPUTS: usize = 10_000;
    if output_count > MAX_TX_OUTPUTS {
        return Err(Error::Deserialization("too many outputs".into()));
    }

    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        if bytes.len() < offset + 40 {
            return Err(Error::Deserialization(
                "insufficient data for output".into(),
            ));
        }

        let value_sat = u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        let value = Amount::from_sat(value_sat)?;
        offset += 8;

        let pubkey_hash = Hash256::from_slice(&bytes[offset..offset + 32])?;
        offset += 32;

        outputs.push(TxOutput { value, pubkey_hash });
    }

    if bytes.len() < offset + 8 {
        return Err(Error::Deserialization("insufficient data for nonce".into()));
    }
    let nonce = u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]);
    offset += 8;

    if bytes.len() < offset + 4 {
        return Err(Error::Deserialization(
            "insufficient data for locktime".into(),
        ));
    }
    let locktime = u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]);
    offset += 4;

    let memo = if bytes.len() > offset {
        let has_memo = bytes[offset];
        offset += 1;
        if has_memo == 1 {
            if bytes.len() < offset + 80 {
                return Err(Error::Deserialization("insufficient data for memo".into()));
            }
            let mut buf = [0u8; 80];
            buf.copy_from_slice(&bytes[offset..offset + 80]);
            offset += 80;
            Some(buf)
        } else {
            None
        }
    } else {
        None
    };

    let mut confidential_outputs: Vec<ConfidentialTxOutput> = Vec::new();
    if matches!(tx_type, TransactionType::ConfidentialTransfer) && bytes.len() > offset {
        if bytes.len() < offset + 8 {
            return Err(Error::Deserialization(
                "insufficient data for conf_output_count".into(),
            ));
        }
        let conf_count = u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]) as usize;
        offset += 8;

        const MAX_CONF_OUTPUTS: usize = 16;
        if conf_count > MAX_CONF_OUTPUTS {
            return Err(Error::Deserialization(
                "too many confidential outputs".into(),
            ));
        }

        confidential_outputs.reserve(conf_count);
        for _ in 0..conf_count {
            if bytes.len() < offset + 72 {
                return Err(Error::Deserialization(
                    "insufficient data for confidential output header".into(),
                ));
            }
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;

            let mut pubkey_hash = [0u8; 32];
            pubkey_hash.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;

            let proof_len = u64::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]) as usize;
            offset += 8;

            if bytes.len() < offset + proof_len {
                return Err(Error::Deserialization(
                    "insufficient data for range proof bytes".into(),
                ));
            }
            let range_proof_bytes = bytes[offset..offset + proof_len].to_vec();
            offset += proof_len;

            confidential_outputs.push(ConfidentialTxOutput {
                commitment,
                range_proof_bytes,
                pubkey_hash,
            });
        }
    }

    let balance_commitment =
        if matches!(tx_type, TransactionType::ConfidentialTransfer) && bytes.len() > offset {
            let has_bc = bytes[offset];
            offset += 1;
            if has_bc == 1 {
                if bytes.len() < offset + 32 {
                    return Err(Error::Deserialization(
                        "insufficient data for balance_commitment".into(),
                    ));
                }
                let mut bc = [0u8; 32];
                bc.copy_from_slice(&bytes[offset..offset + 32]);
                offset += 32;
                Some(bc)
            } else {
                None
            }
        } else {
            None
        };

    let _ = offset;

    Ok(Transaction {
        version,
        tx_type,
        inputs,
        outputs,
        nonce,
        locktime,
        memo,
        confidential_outputs,
        balance_commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_coinbase() {
        let output = TxOutput {
            value: Amount::from_sat(5_000_000_000).unwrap(),
            pubkey_hash: Hash256::zero(),
        };

        let tx = Transaction::new_coinbase(vec![output], 0);
        let serialized = serialize_transaction(&tx);
        let deserialized = deserialize_transaction(&serialized).unwrap();

        assert_eq!(tx, deserialized);
    }

    #[test]
    fn test_serialize_deserialize_transfer() {
        let input = TxInput {
            prev_tx_hash: Hash256::from_bytes([1u8; 32]),
            prev_output_index: 0,
            signature: Signature::from_bytes(vec![2u8; 4627]),
            pubkey: PublicKey::from_bytes(vec![3u8; 2592]),
        };

        let output = TxOutput {
            value: Amount::from_sat(1_000_000).unwrap(),
            pubkey_hash: Hash256::from_bytes([4u8; 32]),
        };

        let tx = Transaction::new_transfer(vec![input], vec![output], 1, 100);
        let serialized = serialize_transaction(&tx);
        let deserialized = deserialize_transaction(&serialized).unwrap();

        assert_eq!(tx, deserialized);
    }

    #[test]
    fn test_serialize_deterministic() {
        let tx = Transaction::new_coinbase(vec![], 0);
        let s1 = serialize_transaction(&tx);
        let s2 = serialize_transaction(&tx);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_deserialize_invalid_data() {
        let short_data = vec![1, 2, 3];
        assert!(deserialize_transaction(&short_data).is_err());
    }
}
