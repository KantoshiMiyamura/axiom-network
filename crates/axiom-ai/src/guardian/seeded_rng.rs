// Copyright (c) 2026 Kantoshi Miyamura
//
// Deterministic hash-counter PRNG for Guardian model exploration.
//
// INVARIANT: output is a pure function of (seed, call-sequence). Two nodes
// constructing a `SeededRng` from the same seed and making the same sequence
// of calls will observe bit-identical output. No OS randomness, no thread
// locals, no wall-clock inputs. This is the ONLY source of "randomness"
// permitted inside the Guardian subsystem.
//
// Construction: state[0..32] = seed, counter=0. `next_u64` returns the first
// 8 bytes of `SHA3-256(state || counter_le)` and increments counter. SHA3 is
// used instead of SHA-256 to get domain separation from block-hash SHA3
// contexts that pass through other parts of the codebase — even though both
// are cryptographically adequate for a non-crypto PRNG role.

use sha3::{Digest, Sha3_256};

pub struct SeededRng {
    state: [u8; 32],
    counter: u64,
}

impl SeededRng {
    pub fn new(seed: [u8; 32]) -> Self {
        SeededRng { state: seed, counter: 0 }
    }

    /// Derive a seed from a block hash + height. Matches the spec's
    /// `seed = Hash(block_hash || height)`. Domain-separated so the seed
    /// cannot collide with any other hash space in the protocol.
    pub fn seed_from_block(block_hash: &[u8; 32], height: u64) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"axiom/guardian/seed/v1");
        h.update(block_hash);
        h.update(height.to_le_bytes());
        let out = h.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&out);
        seed
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut h = Sha3_256::new();
        h.update(b"axiom/guardian/rng/v1");
        h.update(self.state);
        h.update(self.counter.to_le_bytes());
        let out = h.finalize();
        self.counter = self.counter.wrapping_add(1);
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&out[..8]);
        u64::from_le_bytes(buf)
    }

    /// Sample an integer in `[0, n)` without modulo bias when `n` is small
    /// relative to `u64::MAX`. For Guardian use `n` is bounded (action sets,
    /// peer lists); the bias is negligible and we accept the modulo for
    /// simplicity.
    pub fn gen_range(&mut self, n: u64) -> u64 {
        if n == 0 { return 0; }
        self.next_u64() % n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence() {
        let seed = [7u8; 32];
        let mut a = SeededRng::new(seed);
        let mut b = SeededRng::new(seed);
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seed_different_sequence() {
        let mut a = SeededRng::new([1u8; 32]);
        let mut b = SeededRng::new([2u8; 32]);
        // First 8 draws must not all collide.
        let mut collisions = 0;
        for _ in 0..8 {
            if a.next_u64() == b.next_u64() { collisions += 1; }
        }
        assert!(collisions < 8);
    }

    #[test]
    fn seed_from_block_domain_separated() {
        let s1 = SeededRng::seed_from_block(&[0u8; 32], 10);
        let s2 = SeededRng::seed_from_block(&[0u8; 32], 11);
        assert_ne!(s1, s2);
        let s3 = SeededRng::seed_from_block(&[1u8; 32], 10);
        assert_ne!(s1, s3);
    }
}
