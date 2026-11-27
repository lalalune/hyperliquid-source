//! Independently authored Rust reconstruction of node #115 signed block and
//! timeout message admission front ends (`RE-008-signed-message-admission-115`).
//!
//! Target binary anchors (Linux x86-64 node #115):
//! - `0x57e8970`: signed block front end
//! - `0x57e8bd0` (slot `0x64e64b8`): signer membership + digest + recovery check
//! - `0x2786870`: signed block wrapper
//! - `0x2786a20`: timeout message wrapper

use crate::nested_certificate::{
    Certificate, Context, Output as DecisionOutput, StakeSetProvider, TAG_CONTINUE, Verdict,
    decide_nested,
    sigmap::{Address, Signature},
    signer::SignaturePrimitives,
};

/// Niche tag word `0x8000000000000001` read at block `+0x18` and `+0xa8` in `0x57e8970` / `0x2786870`.
pub const BLOCK_CERT_ABSENT_TAG: u64 = 0x8000_0000_0000_0001;

/// Digest variant tags passed to `0x57e8d40` by `0x57e8970`/`0x2786870` (0) and `0x2786a20` (2).
pub const DIGEST_VARIANT_BLOCK: u64 = 0;
pub const DIGEST_VARIANT_TIMEOUT: u64 = 2;

/// Primitives for message-level digest/recovery (variants 0 = block, 2 = timeout),
/// extending [`SignaturePrimitives`] (variant 1 = nested QC vote frame).
pub trait AdmissionPrimitives: SignaturePrimitives {
    /// Computes the 32-byte digest for message `variant` (`0` = block, `2` = timeout).
    fn digest_payload(&self, variant: u64, payload: &[u8]) -> [u8; 32];
}

/// Represents the two certificate slots checked by rule 1 of `0x57e8970` / `0x2786870`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockEnvelope {
    /// Optional primary certificate at block `+0x18` (`None` encodes `0x8000000000000001`).
    pub primary_cert_round: Option<u64>,
    /// Secondary certificate round (`+0x60` when primary absent; `+0xe8` when both present).
    pub secondary_cert_round: Option<u64>,
    /// Fallback round at block `+0x60` when primary is absent (`+0x18 == 0x8000000000000001`).
    pub primary_absent_round: u64,
}

/// Reconstructs rule 1 of `0x57e8970` / `0x2786870`:
/// - If `+0x18 == 0x8000000000000001` (`primary_cert_round` is `None`), use `primary_absent_round` (`+0x60`).
/// - Else if `+0xa8 == 0x8000000000000001` (`secondary_cert_round` is `None`), use `primary_cert_round` (`+0x58`).
/// - Else use `secondary_cert_round` (`+0xe8`).
pub fn select_block_certificate_round(env: &BlockEnvelope) -> u64 {
    match (env.primary_cert_round, env.secondary_cert_round) {
        (None, _) => env.primary_absent_round,
        (Some(primary), None) => primary,
        (Some(_), Some(secondary)) => secondary,
    }
}

/// Input to `admit_signed_block` (`0x57e8970` / `0x2786870`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedBlockInput<B> {
    pub envelope: BlockEnvelope,
    pub proposer: Address,
    pub signature: Signature,
    pub payload_digest_message: Vec<u8>,
    pub block: B,
}

/// Trait boundary for `0x59d6b80` (block rules called through slot `0x64e64c0`).
pub trait BlockRules<B> {
    type Error: Clone + Eq + core::fmt::Debug;

    fn validate_block(&self, block: &B) -> Result<(), Self::Error>;
}

/// Errors produced by `admit_signed_block` (`0x2786870`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockAdmissionError<R> {
    /// Stake-set provider returned tag `0x28` (`MissingRound`).
    MissingStakeSet { round: u64 },
    /// Signer not in stake set, recovery failed, or recovered address != proposer (tag `1`).
    InvalidSigner,
    /// Block rules (`0x59d6b80`) rejected the block.
    BlockRulesRejected(R),
}

/// Reconstructs `0x2786870` (`admit_signed_block`):
/// 1. Selects stake-lookup round via [`select_block_certificate_round`].
/// 2. Queries stake set; missing round propagates immediately.
/// 3. Runs `0x57e8bd0` signer check (stake membership first, then variant-0 digest + recovery).
/// 4. Runs `0x59d6b80` block rules; success moves `block` out.
pub fn admit_signed_block<B, S, P, R>(
    input: SignedBlockInput<B>,
    ctx: &Context,
    stakes: &S,
    primitives: &P,
    rules: &R,
) -> Result<B, BlockAdmissionError<R::Error>>
where
    S: StakeSetProvider,
    P: AdmissionPrimitives,
    R: BlockRules<B>,
{
    let round = select_block_certificate_round(&input.envelope);
    let stake_set = stakes
        .stake_set(ctx, round)
        .ok_or(BlockAdmissionError::MissingStakeSet { round })?;

    // Membership check precedes digest & recovery (`0x57e8bd0`).
    if !stake_set.stakes.contains(&input.proposer) {
        return Err(BlockAdmissionError::InvalidSigner);
    }
    let digest = primitives.digest_payload(DIGEST_VARIANT_BLOCK, &input.payload_digest_message);
    if primitives.recover(&input.signature, &digest).as_ref() != Some(&input.proposer) {
        return Err(BlockAdmissionError::InvalidSigner);
    }

    rules
        .validate_block(&input.block)
        .map_err(BlockAdmissionError::BlockRulesRejected)?;
    Ok(input.block)
}

/// 0x38-byte timeout digest payload constructed by `0x2786a20` (rule 8):
/// `words [+0x68, +0x70, +0x78, +0x30]` followed by 20-byte signer address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutDigestPayload {
    pub hardfork_version: u64,
    pub hardfork_round: u64,
    pub timeout_round: u64,
    pub high_qc_round: u64,
    pub signer: Address,
}

impl TimeoutDigestPayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 * 8 + 20);
        out.extend_from_slice(&self.hardfork_version.to_le_bytes());
        out.extend_from_slice(&self.hardfork_round.to_le_bytes());
        out.extend_from_slice(&self.timeout_round.to_le_bytes());
        out.extend_from_slice(&self.high_qc_round.to_le_bytes());
        out.extend_from_slice(&self.signer);
        out
    }
}

/// Input to `admit_signed_timeout` (`0x2786a20`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedTimeoutInput {
    /// Round at `+0x40` used for stake-set lookup.
    pub stake_lookup_round: u64,
    /// Hardfork pair (`+0x68`, `+0x70`) compared against `ctx.pair`.
    pub hardfork_pair: [u64; 2],
    /// Timeout round (`+0x78`); must strictly exceed `high_qc.f30` (`+0x30`).
    pub timeout_round: u64,
    pub signer: Address,
    pub signature: Signature,
    pub high_qc: Certificate,
}

/// Errors produced by `admit_signed_timeout` (`0x2786a20`, rule 8).
#[derive(Debug, Eq, PartialEq)]
pub enum TimeoutAdmissionError {
    /// Stake-set provider returned tag `0x28`.
    MissingStakeSet { round: u64 },
    /// Signer check `0x57e8bd0` failed (tag `1`).
    InvalidSigner,
    /// Hardfork pair mismatch (tag `0` with four words).
    HardforkMismatch {
        msg_pair: [u64; 2],
        ctx_pair: [u64; 2],
    },
    /// `high_qc.f30 >= timeout_round` (tag `0x0a`).
    RoundOrderInvalid {
        high_qc_round: u64,
        timeout_round: u64,
    },
    /// Nested certificate decision `0x595fd20` did not produce tag `0x2e`.
    NestedCertificateRejected(DecisionOutput<Verdict>),
}

/// Reconstructs `0x2786a20` (`admit_signed_timeout`):
/// 1. Queries stake set for `stake_lookup_round` (`+0x40`).
/// 2. Builds timeout digest payload (variant 2) and verifies signer via `0x57e8bd0`.
/// 3. Checks `hardfork_pair == ctx.pair` (else tag `0`).
/// 4. Checks `high_qc.f30 < timeout_round` (else tag `0x0a`).
/// 5. Verifies nested `high_qc` via `0x595fd20` (`decide_nested`), accepting iff tag == `0x2e`.
pub fn admit_signed_timeout<S, P>(
    input: SignedTimeoutInput,
    ctx: &Context,
    stakes: &S,
    primitives: &P,
) -> Result<SignedTimeoutInput, TimeoutAdmissionError>
where
    S: StakeSetProvider,
    P: AdmissionPrimitives,
{
    let stake_set = stakes
        .stake_set(ctx, input.stake_lookup_round)
        .ok_or(TimeoutAdmissionError::MissingStakeSet {
            round: input.stake_lookup_round,
        })?;

    if !stake_set.stakes.contains(&input.signer) {
        return Err(TimeoutAdmissionError::InvalidSigner);
    }

    let digest_payload = TimeoutDigestPayload {
        hardfork_version: input.hardfork_pair[0],
        hardfork_round: input.hardfork_pair[1],
        timeout_round: input.timeout_round,
        high_qc_round: input.high_qc.f30,
        signer: input.signer,
    };
    let digest = primitives.digest_payload(DIGEST_VARIANT_TIMEOUT, &digest_payload.to_bytes());
    if primitives.recover(&input.signature, &digest).as_ref() != Some(&input.signer) {
        return Err(TimeoutAdmissionError::InvalidSigner);
    }

    if input.hardfork_pair != ctx.pair {
        return Err(TimeoutAdmissionError::HardforkMismatch {
            msg_pair: input.hardfork_pair,
            ctx_pair: ctx.pair,
        });
    }

    if input.high_qc.f30 >= input.timeout_round {
        return Err(TimeoutAdmissionError::RoundOrderInvalid {
            high_qc_round: input.high_qc.f30,
            timeout_round: input.timeout_round,
        });
    }

    let decision = decide_nested(&input.high_qc, ctx, stakes, primitives);
    if decision.tag() != Some(TAG_CONTINUE) {
        return Err(TimeoutAdmissionError::NestedCertificateRejected(decision));
    }

    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nested_certificate::{
        sigmap::SigMap,
        signer::VoteFrame,
        stake::{StakeMap, StakeSet},
    };
    use std::collections::BTreeSet;

    struct SingleStakeProvider {
        round: u64,
        set: StakeSet,
    }
    impl StakeSetProvider for SingleStakeProvider {
        fn stake_set(&self, _ctx: &Context, round: u64) -> Option<&StakeSet> {
            (round == self.round).then_some(&self.set)
        }
    }

    struct EchoPrimitives {
        recovered: Option<Address>,
    }
    impl SignaturePrimitives for EchoPrimitives {
        fn digest(&self, _variant: u64, _frame: &VoteFrame) -> [u8; 32] {
            [0x42; 32]
        }
        fn recover(&self, _signature: &Signature, _digest: &[u8; 32]) -> Option<Address> {
            self.recovered
        }
    }
    impl AdmissionPrimitives for EchoPrimitives {
        fn digest_payload(&self, _variant: u64, _payload: &[u8]) -> [u8; 32] {
            [0x24; 32]
        }
    }

    struct PassRules(bool);
    impl BlockRules<u64> for PassRules {
        type Error = &'static str;
        fn validate_block(&self, _block: &u64) -> Result<(), Self::Error> {
            if self.0 { Ok(()) } else { Err("bad_block") }
        }
    }

    fn addr(b: u8) -> Address {
        let mut a = [0u8; 20];
        a[19] = b;
        a
    }

    fn sig(b: u8) -> Signature {
        [b; 65]
    }

    fn test_stake_set(signer: Address) -> StakeSet {
        let mut validators = BTreeSet::new();
        validators.insert(signer);
        StakeSet {
            stakes: StakeMap::tree([(signer, 100)]),
            validators,
            validator_count: 1,
        }
    }

    #[test]
    fn block_certificate_round_selection_matches_rule1() {
        assert_eq!(
            select_block_certificate_round(&BlockEnvelope {
                primary_cert_round: None,
                secondary_cert_round: Some(99),
                primary_absent_round: 12,
            }),
            12
        );
        assert_eq!(
            select_block_certificate_round(&BlockEnvelope {
                primary_cert_round: Some(34),
                secondary_cert_round: None,
                primary_absent_round: 12,
            }),
            34
        );
        assert_eq!(
            select_block_certificate_round(&BlockEnvelope {
                primary_cert_round: Some(34),
                secondary_cert_round: Some(56),
                primary_absent_round: 12,
            }),
            56
        );
    }

    #[test]
    fn signed_block_admission_enforces_stakes_signer_and_rules() {
        let signer = addr(5);
        let ctx = Context {
            pair: [1, 10],
            quorum_fraction_bits: 0.0f64.to_bits(),
        };
        let stakes = SingleStakeProvider {
            round: 20,
            set: test_stake_set(signer),
        };
        let env = BlockEnvelope {
            primary_cert_round: Some(20),
            secondary_cert_round: None,
            primary_absent_round: 0,
        };
        let ok = admit_signed_block(
            SignedBlockInput {
                envelope: env.clone(),
                proposer: signer,
                signature: sig(7),
                payload_digest_message: b"blk".to_vec(),
                block: 777u64,
            },
            &ctx,
            &stakes,
            &EchoPrimitives {
                recovered: Some(signer),
            },
            &PassRules(true),
        );
        assert_eq!(ok, Ok(777));

        let bad_sig = admit_signed_block(
            SignedBlockInput {
                envelope: env.clone(),
                proposer: signer,
                signature: sig(7),
                payload_digest_message: b"blk".to_vec(),
                block: 777u64,
            },
            &ctx,
            &stakes,
            &EchoPrimitives {
                recovered: Some(addr(9)),
            },
            &PassRules(true),
        );
        assert_eq!(bad_sig, Err(BlockAdmissionError::InvalidSigner));

        let non_member = admit_signed_block(
            SignedBlockInput {
                envelope: env.clone(),
                proposer: addr(99),
                signature: sig(7),
                payload_digest_message: b"blk".to_vec(),
                block: 777u64,
            },
            &ctx,
            &stakes,
            &EchoPrimitives {
                recovered: Some(addr(99)),
            },
            &PassRules(true),
        );
        assert_eq!(non_member, Err(BlockAdmissionError::InvalidSigner));

        let bad_rules = admit_signed_block(
            SignedBlockInput {
                envelope: env,
                proposer: signer,
                signature: sig(7),
                payload_digest_message: b"blk".to_vec(),
                block: 777u64,
            },
            &ctx,
            &stakes,
            &EchoPrimitives {
                recovered: Some(signer),
            },
            &PassRules(false),
        );
        assert_eq!(
            bad_rules,
            Err(BlockAdmissionError::BlockRulesRejected("bad_block"))
        );
    }

    #[test]
    fn signed_timeout_admission_enforces_pair_round_order_and_nested_qc() {
        let signer = addr(3);
        let stakes = SingleStakeProvider {
            round: 10,
            set: test_stake_set(signer),
        };
        let ctx = Context {
            pair: [1, 10],
            quorum_fraction_bits: 0.0f64.to_bits(),
        };
        let genesis_qc = Certificate {
            sigs: SigMap::empty_ring(),
            pair: [1, 10],
            f30: 10,
            f38: 10,
            f40: 10,
            hash: [0u8; 32],
        };

        let ok = admit_signed_timeout(
            SignedTimeoutInput {
                stake_lookup_round: 10,
                hardfork_pair: [1, 10],
                timeout_round: 11,
                signer,
                signature: sig(1),
                high_qc: genesis_qc.clone(),
            },
            &ctx,
            &stakes,
            &EchoPrimitives {
                recovered: Some(signer),
            },
        );
        assert!(ok.is_ok());

        // Equal timeout_round == high_qc.f30 fails with RoundOrderInvalid (tag 0x0a).
        let eq_round = admit_signed_timeout(
            SignedTimeoutInput {
                stake_lookup_round: 10,
                hardfork_pair: [1, 10],
                timeout_round: 10,
                signer,
                signature: sig(1),
                high_qc: genesis_qc.clone(),
            },
            &ctx,
            &stakes,
            &EchoPrimitives {
                recovered: Some(signer),
            },
        );
        assert_eq!(
            eq_round,
            Err(TimeoutAdmissionError::RoundOrderInvalid {
                high_qc_round: 10,
                timeout_round: 10,
            })
        );

        // Hardfork mismatch fails with HardforkMismatch (tag 0).
        let bad_hf = admit_signed_timeout(
            SignedTimeoutInput {
                stake_lookup_round: 10,
                hardfork_pair: [2, 10],
                timeout_round: 11,
                signer,
                signature: sig(1),
                high_qc: genesis_qc,
            },
            &ctx,
            &stakes,
            &EchoPrimitives {
                recovered: Some(signer),
            },
        );
        assert_eq!(
            bad_hf,
            Err(TimeoutAdmissionError::HardforkMismatch {
                msg_pair: [2, 10],
                ctx_pair: [1, 10],
            })
        );
    }
}
