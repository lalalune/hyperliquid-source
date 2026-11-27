#![forbid(unsafe_code)]

//! Node #115 HotStuff-2 two-chain commit rule, 128-bit strict 2/3 stake quorum predicate,
//! and block-store registration guards.
//!
//! Anchored to Linux x86-64 node #115 (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`):
//! - `0x2e157c0..0x2e197f5` (16,437 B): HotStuff-2 certified two-chain commit rule
//!   (`0x2e15b9b..0x2e15bb7` zero-hash genesis guard, `0x2e15cfa..0x2e15d4f`
//!   consecutive-round check `r_B == parent_cert_round(P).saturating_add(2)`,
//!   `0x2e15e38..0x2e15e58` `r_P > committed_round` monotonicity check)
//! - `0x4d3e1a0..0x4d3e30d` (365 B): `node/src/consensus/validator_stakes.rs` exact
//!   128-bit integer strict supermajority quorum (`3u128 * signed > 2u128 * total`)
//! - `0x2e1da10..0x2e1f73c` (7,468 B): `register_block` stale (`< min_round`, tag `3`)
//!   and duplicate (`NotNew`, tag `4`) guards
//! - `0x2e1f740..0x2e1f9a5` (613 B): two-tier block/tx hash lookup helper

use std::collections::BTreeMap;

/// Exact node #115 `register_block` status tag for a block below `min_stored_round` (`0x2e1da79`).
pub const REGISTER_TAG_STALE: u8 = 3;
/// Exact node #115 `register_block` status tag for an already-known block hash (`0x2e1dbee`).
pub const REGISTER_TAG_NOT_NEW: u8 = 4;

/// Exact node #115 128-bit strict 2/3 supermajority quorum check (`0x4d3e2e4..0x4d3e304`).
///
/// Mirrors the exact x86-64 sequence:
/// `mulq $3` on `signed_stake` vs `(total_stake << 1)` with 128-bit `cmpq`/`sbbq`/`setb`:
/// returns `true` iff `3 * signed_stake > 2 * total_stake` in exact `u128` arithmetic
/// (overflow-free for all `u64` inputs up to `u64::MAX`, returns `false` when `total_stake == 0`
/// and `signed_stake == 0`).
#[must_use]
pub const fn has_strict_two_thirds_quorum_u128(signed_stake: u64, total_stake: u64) -> bool {
    (signed_stake as u128) * 3 > (total_stake as u128) * 2
}

/// Computes `block_round = parent_cert_round.saturating_add(1)` matching the exact
/// `incq; mov $-1; cmove` saturation sequence at `0x2e15d12..0x2e15d22` and `0x2e1da5d..0x2e1da6d`.
#[must_use]
pub const fn block_round_from_parent_cert(parent_cert_round: u64) -> u64 {
    parent_cert_round.saturating_add(1)
}

/// Minimal certified block record used by the HotStuff-2 two-chain commit rule (`0x2e157c0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedBlockNode {
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    /// Round carried by the block's parent certificate (QC or TC); block round is `parent_cert_round.saturating_add(1)`.
    pub parent_cert_round: u64,
}

impl CertifiedBlockNode {
    /// Block's own round (`parent_cert_round.saturating_add(1)`).
    #[must_use]
    pub const fn round(&self) -> u64 {
        block_round_from_parent_cert(self.parent_cert_round)
    }
}

/// Outcome of `register_block` admission guards (`0x2e1da10`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterBlockOutcome {
    /// Block inserted into the pending block store.
    Registered,
    /// Rejected: `block_round < min_stored_round` (native tag `3` at `0x2e1da79`).
    Stale { tag: u8 },
    /// Rejected: `block_hash` already present in store (native tag `4` at `0x2e1dbee`).
    NotNew { tag: u8 },
}

/// Outcome of evaluating HotStuff-2 certified two-chain commit (`0x2e157c0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwoChainCommitOutcome {
    /// No commit triggered because certified block `B` is missing, has all-zero genesis parent
    /// (`0x2e15b9b..0x2e15bb7`), has missing parent `P`, fails consecutive-round equality
    /// `r_B == parent_cert_round(P).saturating_add(2)` (`0x2e15d3c..0x2e15d4f`), or `r_P <= committed_round`
    /// (`0x2e15e49..0x2e15e58`).
    NoCommit,
    /// Committed `P` and all uncommitted ancestors above the prior `committed_round` in ascending round order.
    Committed {
        new_committed_round: u64,
        committed_blocks: Vec<CertifiedBlockNode>,
    },
}

/// In-memory HotStuff-2 certified block store & two-chain committer (`0x2e157c0`, `0x2e1da10`).
#[derive(Debug, Clone, Default)]
pub struct TwoChainCommitStore {
    pub committed_round: u64,
    pub min_stored_round: u64,
    blocks: BTreeMap<[u8; 32], CertifiedBlockNode>,
}

impl TwoChainCommitStore {
    #[must_use]
    pub fn new(committed_round: u64, min_stored_round: u64) -> Self {
        Self {
            committed_round,
            min_stored_round,
            blocks: BTreeMap::new(),
        }
    }

    /// Registers a block enforcing `0x2e1da10`'s stale (`tag 3`) and duplicate (`tag 4`) checks.
    pub fn register_block(&mut self, block: CertifiedBlockNode) -> RegisterBlockOutcome {
        if block.round() < self.min_stored_round {
            return RegisterBlockOutcome::Stale {
                tag: REGISTER_TAG_STALE,
            };
        }
        if self.blocks.contains_key(&block.block_hash) {
            return RegisterBlockOutcome::NotNew {
                tag: REGISTER_TAG_NOT_NEW,
            };
        }
        self.blocks.insert(block.block_hash, block);
        RegisterBlockOutcome::Registered
    }

    /// Evaluates node #115's exact HotStuff-2 certified two-chain commit rule (`0x2e157c0`)
    /// upon certifying block `certified_hash`.
    ///
    /// Exact binary checks:
    /// 1. Lookup certified block `B` by `certified_hash`.
    /// 2. Genesis guard (`0x2e15b9b..0x2e15bb7`): if `B.parent_hash == [0u8; 32]`, no commit.
    /// 3. Lookup parent block `P` by `B.parent_hash`.
    /// 4. Consecutive two-chain rule (`0x2e15cfa..0x2e15d4f`):
    ///    `B.parent_cert_round.saturating_add(1) == P.parent_cert_round.saturating_add(2)`
    ///    (equivalently `B.round() == P.round() + 1` with `u64` saturation).
    /// 5. Monotonic commit guard (`0x2e15e38..0x2e15e58`):
    ///    `P.round() > self.committed_round`.
    /// 6. Walk uncommitted ancestors from `P` down until `round <= self.committed_round` (or genesis/missing),
    ///    update `self.committed_round = P.round()`, and return committed blocks in ascending round order.
    pub fn try_two_chain_commit(&mut self, certified_hash: &[u8; 32]) -> TwoChainCommitOutcome {
        let Some(b) = self.blocks.get(certified_hash).cloned() else {
            return TwoChainCommitOutcome::NoCommit;
        };
        if b.parent_hash == [0u8; 32] {
            return TwoChainCommitOutcome::NoCommit;
        }
        let Some(p) = self.blocks.get(&b.parent_hash).cloned() else {
            return TwoChainCommitOutcome::NoCommit;
        };
        let r_b = b.parent_cert_round.saturating_add(1);
        let r_p_plus_1 = p.parent_cert_round.saturating_add(2);
        if r_b != r_p_plus_1 {
            return TwoChainCommitOutcome::NoCommit;
        }
        let r_p = p.parent_cert_round.saturating_add(1);
        if r_p <= self.committed_round {
            return TwoChainCommitOutcome::NoCommit;
        }

        let mut chain = Vec::new();
        let mut cursor = Some(p);
        while let Some(node) = cursor {
            if node.round() <= self.committed_round {
                break;
            }
            let parent_hash = node.parent_hash;
            chain.push(node);
            if parent_hash == [0u8; 32] {
                break;
            }
            cursor = self.blocks.get(&parent_hash).cloned();
        }
        chain.reverse();
        self.committed_round = r_p;
        TwoChainCommitOutcome::Committed {
            new_committed_round: r_p,
            committed_blocks: chain,
        }
    }

    #[must_use]
    pub fn get(&self, hash: &[u8; 32]) -> Option<&CertifiedBlockNode> {
        self.blocks.get(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_u128_enforces_strict_two_thirds_without_u64_overflow() {
        assert!(!has_strict_two_thirds_quorum_u128(0, 0));
        assert!(!has_strict_two_thirds_quorum_u128(2, 3));
        assert!(has_strict_two_thirds_quorum_u128(3, 3));
        assert!(!has_strict_two_thirds_quorum_u128(66, 99));
        assert!(has_strict_two_thirds_quorum_u128(67, 99));
        // Near u64::MAX — would overflow u64 multiplication, safe in u128 per 0x4d3e2f6
        let big = u64::MAX;
        let two_thirds = (big / 3) * 2;
        assert!(!has_strict_two_thirds_quorum_u128(two_thirds, big));
        assert!(has_strict_two_thirds_quorum_u128(two_thirds + 1, big));
        assert!(has_strict_two_thirds_quorum_u128(big, big));
    }

    #[test]
    fn two_chain_commit_and_register_guards_match_node115_rules() {
        let mut store = TwoChainCommitStore::new(10, 10);

        // Stale block (round 9 < min_stored_round 10) -> tag 3
        let stale = CertifiedBlockNode {
            block_hash: [0x09; 32],
            parent_hash: [0x08; 32],
            parent_cert_round: 8,
        };
        assert_eq!(
            store.register_block(stale),
            RegisterBlockOutcome::Stale {
                tag: REGISTER_TAG_STALE
            }
        );

        // Build chain: round 11 (parent genesis [0;32]) -> round 12 -> round 14 (gap!) -> round 15
        let b11 = CertifiedBlockNode {
            block_hash: [0x11; 32],
            parent_hash: [0x00; 32],
            parent_cert_round: 10,
        };
        let b12 = CertifiedBlockNode {
            block_hash: [0x12; 32],
            parent_hash: [0x11; 32],
            parent_cert_round: 11,
        };
        let b14 = CertifiedBlockNode {
            block_hash: [0x14; 32],
            parent_hash: [0x12; 32],
            parent_cert_round: 13, // TC skipped round 13 -> round 14 != 12 + 1
        };
        let b15 = CertifiedBlockNode {
            block_hash: [0x15; 32],
            parent_hash: [0x14; 32],
            parent_cert_round: 14, // consecutive with b14!
        };

        assert_eq!(store.register_block(b11.clone()), RegisterBlockOutcome::Registered);
        // Duplicate hash -> tag 4
        assert_eq!(
            store.register_block(b11.clone()),
            RegisterBlockOutcome::NotNew {
                tag: REGISTER_TAG_NOT_NEW
            }
        );
        assert_eq!(store.register_block(b12.clone()), RegisterBlockOutcome::Registered);
        assert_eq!(store.register_block(b14.clone()), RegisterBlockOutcome::Registered);
        assert_eq!(store.register_block(b15.clone()), RegisterBlockOutcome::Registered);

        // Certifying b11 has zero genesis parent -> NoCommit
        assert_eq!(store.try_two_chain_commit(&b11.block_hash), TwoChainCommitOutcome::NoCommit);
        // Certifying b14 has round gap (14 != 12 + 1) -> NoCommit
        assert_eq!(store.try_two_chain_commit(&b14.block_hash), TwoChainCommitOutcome::NoCommit);

        // Certifying b15 (round 15 == b14.round 14 + 1) commits b11, b12, b14 in ascending order!
        assert_eq!(
            store.try_two_chain_commit(&b15.block_hash),
            TwoChainCommitOutcome::Committed {
                new_committed_round: 14,
                committed_blocks: vec![b11, b12.clone(), b14],
            }
        );
        assert_eq!(store.committed_round, 14);

        // Re-certifying b15 or older b12 fails monotonic r_P > committed_round check
        assert_eq!(store.try_two_chain_commit(&b15.block_hash), TwoChainCommitOutcome::NoCommit);
        assert_eq!(store.try_two_chain_commit(&b12.block_hash), TwoChainCommitOutcome::NoCommit);
    }
}
