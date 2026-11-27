//! Independently authored Rust reconstruction of node #115's block validation
//! rules (`0x59d6b80..0x59d70ab`, `node/src/consensus/signed.rs:194`, slot
//! `0x64e64c0`; packet `RE-008-node115-block-rules-and-tc-verify`).

use std::collections::BTreeSet;

use crate::admission::AdmissionPrimitives;
use crate::nested_certificate::{
    Certificate, Context, Output as DecisionOutput, StakeSetProvider, TAG_CONTINUE, Verdict,
    decide_nested, sigmap::Address,
};
use crate::tc_verify::{TcVerifyError, VerifiableTimeoutCertificate, verify_timeout_certificate};

/// Hard cap on transaction hashes per block at `0x59d6f08` (`cmp r14, 0x64`).
pub const MAX_BLOCK_TX_HASHES: usize = 100;

/// Native error tags written by `0x59d6b80`.
pub const TAG_EXTRA_QC_OUT_OF_RANGE: u8 = 0x0c;
pub const TAG_UNEXPECTED_PROPOSER: u8 = 0x0d;
pub const TAG_TOO_MANY_TX_HASHES: u8 = 0x29;
pub const TAG_DUPLICATE_TX_HASH: u8 = 0x2a;

/// Certificate attachment on a consensus block matching `0x59d6b80`'s layout:
/// either a normal QC block (`[block+0x18] == 0x8000000000000001`), or a TC
/// recovery block with an optional `extra_qc` (`[block+0xa8]`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockJustification {
    Qc(Certificate),
    Tc {
        tc: VerifiableTimeoutCertificate,
        extra_qc: Option<Certificate>,
    },
}

/// Consensus block fields validated by `0x59d6b80`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsensusBlock {
    pub proposer: Address,
    pub tx_hashes: Vec<[u8; 32]>,
    pub justification: BlockJustification,
}

impl ConsensusBlock {
    /// Reconstructs `0x59d6b9a..0x59d6bd6`: `parent_round.saturating_add(1)`.
    pub fn block_round(&self) -> u64 {
        let parent_round = match &self.justification {
            BlockJustification::Qc(qc) => qc.f30,
            BlockJustification::Tc { tc, .. } => tc.round,
        };
        parent_round.saturating_add(1)
    }

    /// Reconstructs `0x59d6bd7..0x59d6c15`: stake-set round passed as `rcx` to `0x595cb30`.
    pub fn stake_lookup_round(&self) -> u64 {
        match &self.justification {
            BlockJustification::Qc(qc) => qc.f40,
            BlockJustification::Tc { tc, extra_qc } => match extra_qc {
                Some(extra) => extra.f40,
                None => tc.high_qc.f40,
            },
        }
    }
}

/// Two-round proposer provider boundary matching `0x595cb30` (slot `0x64e86f0`).
pub trait BlockProposerProvider {
    type Error: Clone + Eq + core::fmt::Debug;

    fn proposer_for_block(
        &self,
        block_round: u64,
        stake_lookup_round: u64,
    ) -> Result<Address, Self::Error>;
}

/// Rejection reasons matching `0x59d6b80`'s exact order and native tags.
#[derive(Debug, Eq, PartialEq)]
pub enum BlockRuleError<PE> {
    /// Proposer lookup (`0x595cb30`) returned a non-`0x2e` error.
    ProposerLookup(PE),
    /// Tag `0x0d`: `block.proposer != expected_proposer`.
    UnexpectedProposer {
        proposer: Address,
        expected: Address,
    },
    /// Tag `0x29`: `tx_hashes.len() > 100` (`0x64`).
    TooManyTxHashes { count: usize },
    /// Tag `0x2a`: duplicate 32-byte transaction hash in `tx_hashes`.
    DuplicateTxHash([u8; 32]),
    /// Tag `0x0c`: `extra_qc.f30 <= tc.high_qc.f30` OR `extra_qc.f30 >= tc.round`.
    ExtraQcOutOfRange {
        tc_high_qc_round: u64,
        extra_qc_round: u64,
        tc_round: u64,
    },
    /// Nested `0x5960390` (`verify_timeout_certificate`) rejected `tc`.
    TcRejected(TcVerifyError),
    /// Nested `0x595fd20` (`decide_nested`) rejected primary or extra QC.
    QcRejected(DecisionOutput<Verdict>),
}

impl<PE> BlockRuleError<PE> {
    pub fn tag(&self) -> Option<u8> {
        match self {
            BlockRuleError::ProposerLookup(_) => None,
            BlockRuleError::UnexpectedProposer { .. } => Some(TAG_UNEXPECTED_PROPOSER),
            BlockRuleError::TooManyTxHashes { .. } => Some(TAG_TOO_MANY_TX_HASHES),
            BlockRuleError::DuplicateTxHash(_) => Some(TAG_DUPLICATE_TX_HASH),
            BlockRuleError::ExtraQcOutOfRange { .. } => Some(TAG_EXTRA_QC_OUT_OF_RANGE),
            BlockRuleError::TcRejected(e) => e.tag(),
            BlockRuleError::QcRejected(out) => out.tag(),
        }
    }
}

/// Reconstructs `0x59d6b80` (`Block::verify_rules`, `signed.rs:194`).
pub fn verify_block_rules<P, S, A>(
    block: &ConsensusBlock,
    ctx: &Context,
    proposers: &P,
    stakes: &S,
    primitives: &A,
) -> Result<(), BlockRuleError<P::Error>>
where
    P: BlockProposerProvider,
    S: StakeSetProvider,
    A: AdmissionPrimitives,
{
    // 1 & 2. Compute block_round & stake_lookup_round, verify proposer (`0x64e86f0`).
    let block_round = block.block_round();
    let stake_round = block.stake_lookup_round();
    let expected = proposers
        .proposer_for_block(block_round, stake_round)
        .map_err(BlockRuleError::ProposerLookup)?;
    if block.proposer != expected {
        return Err(BlockRuleError::UnexpectedProposer {
            proposer: block.proposer,
            expected,
        });
    }

    // 3. Enforce max 100 (`0x64`) transaction hashes (`0x59d6f08`).
    if block.tx_hashes.len() > MAX_BLOCK_TX_HASHES {
        return Err(BlockRuleError::TooManyTxHashes {
            count: block.tx_hashes.len(),
        });
    }

    // 4. Enforce transaction hash uniqueness (`0x59d6f50..0x59d6fa5`).
    let mut seen = BTreeSet::new();
    for &h in &block.tx_hashes {
        if !seen.insert(h) {
            return Err(BlockRuleError::DuplicateTxHash(h));
        }
    }

    // 5. Verify justification certificates (`0x59d6fa5..0x59d7089`).
    match &block.justification {
        BlockJustification::Qc(qc) => {
            let out = decide_nested(qc, ctx, stakes, primitives);
            if out.tag() != Some(TAG_CONTINUE) {
                return Err(BlockRuleError::QcRejected(out));
            }
        }
        BlockJustification::Tc { tc, extra_qc } => {
            if let Some(extra) = extra_qc
                && (extra.f30 <= tc.high_qc.f30 || extra.f30 >= tc.round)
            {
                return Err(BlockRuleError::ExtraQcOutOfRange {
                    tc_high_qc_round: tc.high_qc.f30,
                    extra_qc_round: extra.f30,
                    tc_round: tc.round,
                });
            }
            verify_timeout_certificate(tc, ctx, stakes, primitives)
                .map_err(BlockRuleError::TcRejected)?;
            if let Some(extra) = extra_qc {
                let out = decide_nested(extra, ctx, stakes, primitives);
                if out.tag() != Some(TAG_CONTINUE) {
                    return Err(BlockRuleError::QcRejected(out));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nested_certificate::{
        sigmap::{SigMap, Signature},
        signer::{SignaturePrimitives, VoteFrame},
        stake::{StakeMap, StakeSet},
    };
    use crate::tc_verify::TcSignatureEntry;

    struct ConstProposer(Address);
    impl BlockProposerProvider for ConstProposer {
        type Error = u8;
        fn proposer_for_block(&self, _br: u64, _sr: u64) -> Result<Address, Self::Error> {
            Ok(self.0)
        }
    }

    struct FixedStakes {
        round: u64,
        set: StakeSet,
    }
    impl StakeSetProvider for FixedStakes {
        fn stake_set(&self, _ctx: &Context, round: u64) -> Option<&StakeSet> {
            (round == self.round).then_some(&self.set)
        }
    }

    struct KeyedPrimitives;
    impl SignaturePrimitives for KeyedPrimitives {
        fn digest(&self, _variant: u64, _frame: &VoteFrame) -> [u8; 32] {
            [0x33; 32]
        }
        fn recover(&self, signature: &Signature, _digest: &[u8; 32]) -> Option<Address> {
            let mut a = [0u8; 20];
            a[19] = signature[0];
            Some(a)
        }
    }
    impl AdmissionPrimitives for KeyedPrimitives {
        fn digest_payload(&self, _variant: u64, _payload: &[u8]) -> [u8; 32] {
            [0x44; 32]
        }
    }

    fn addr(b: u8) -> Address {
        let mut a = [0u8; 20];
        a[19] = b;
        a
    }

    fn sig_for(b: u8) -> Signature {
        let mut s = [0u8; 65];
        s[0] = b;
        s
    }

    fn genesis_qc(pair: [u64; 2]) -> Certificate {
        Certificate {
            sigs: SigMap::empty_ring(),
            pair,
            f30: pair[1],
            f38: pair[1],
            f40: pair[1],
            hash: [0u8; 32],
        }
    }

    #[test]
    fn block_rules_enforces_proposer_tx_cap_100_dedup_and_extra_qc_bounds() {
        let ctx = Context {
            pair: [1, 10],
            quorum_fraction_bits: 0.0f64.to_bits(),
        };
        let a1 = addr(1);
        let a2 = addr(2);
        let a3 = addr(3);
        let stakes = FixedStakes {
            round: 10,
            set: StakeSet {
                stakes: StakeMap::tree([(a1, 100), (a2, 100), (a3, 100)]),
                validators: BTreeSet::from([a1, a2, a3]),
                validator_count: 3,
            },
        };
        let proposers = ConstProposer(a1);

        // Valid QC block with exactly 100 unique hashes passes.
        let unique_100: Vec<[u8; 32]> = (0u8..100).map(|i| [i; 32]).collect();
        let blk = ConsensusBlock {
            proposer: a1,
            tx_hashes: unique_100,
            justification: BlockJustification::Qc(genesis_qc([1, 10])),
        };
        assert_eq!(blk.block_round(), 11);
        assert_eq!(
            verify_block_rules(&blk, &ctx, &proposers, &stakes, &KeyedPrimitives),
            Ok(())
        );

        // 101 tx hashes -> tag 0x29.
        let mut too_many = blk.clone();
        too_many.tx_hashes.push([250; 32]);
        let e_cap = verify_block_rules(&too_many, &ctx, &proposers, &stakes, &KeyedPrimitives)
            .unwrap_err();
        assert_eq!(e_cap.tag(), Some(TAG_TOO_MANY_TX_HASHES));

        // Duplicate tx hash -> tag 0x2a.
        let mut dup = blk.clone();
        dup.tx_hashes[99] = dup.tx_hashes[0];
        let e_dup =
            verify_block_rules(&dup, &ctx, &proposers, &stakes, &KeyedPrimitives).unwrap_err();
        assert_eq!(e_dup.tag(), Some(TAG_DUPLICATE_TX_HASH));

        // Wrong proposer -> tag 0x0d.
        let mut wrong_p = blk.clone();
        wrong_p.proposer = a2;
        let e_prop = verify_block_rules(&wrong_p, &ctx, &proposers, &stakes, &KeyedPrimitives)
            .unwrap_err();
        assert_eq!(e_prop.tag(), Some(TAG_UNEXPECTED_PROPOSER));

        // TC block with extra_qc.f30 == tc.round -> tag 0x0c (strictly between high_qc.f30 and tc.round).
        let tc = VerifiableTimeoutCertificate {
            high_qc: genesis_qc([1, 10]),
            round: 12,
            signatures: vec![
                TcSignatureEntry { signer: a1, high_qc_round: 10, signature: sig_for(1) },
                TcSignatureEntry { signer: a2, high_qc_round: 10, signature: sig_for(2) },
                TcSignatureEntry { signer: a3, high_qc_round: 10, signature: sig_for(3) },
            ],
        };
        let mut bad_extra = genesis_qc([1, 10]);
        bad_extra.f30 = 12; // == tc.round -> rejected!
        let tc_blk = ConsensusBlock {
            proposer: a1,
            tx_hashes: Vec::new(),
            justification: BlockJustification::Tc {
                tc,
                extra_qc: Some(bad_extra),
            },
        };
        let e_extra = verify_block_rules(&tc_blk, &ctx, &proposers, &stakes, &KeyedPrimitives)
            .unwrap_err();
        assert_eq!(e_extra.tag(), Some(TAG_EXTRA_QC_OUT_OF_RANGE));
    }
}
