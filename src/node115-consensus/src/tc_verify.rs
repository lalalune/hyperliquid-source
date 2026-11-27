//! Independently authored Rust reconstruction of node #115's TimeoutCertificate
//! verifier (`0x5960390..0x59608a8`; packet `RE-008-node115-block-rules-and-tc-verify`).

use std::collections::BTreeSet;

use crate::admission::{AdmissionPrimitives, DIGEST_VARIANT_TIMEOUT, TimeoutDigestPayload};
use crate::nested_certificate::{
    Certificate, Context, Output as DecisionOutput, StakeSetProvider, TAG_CONTINUE, Verdict,
    decide_nested,
    quorum::quorum,
    sigmap::{Address, Signature},
};

/// Native error tags emitted by `0x5960390`.
pub const TAG_TC_BAD_SIGNATURE: u8 = 0x02;
pub const TAG_TC_QUORUM_FAILED: u8 = 0x08;
pub const TAG_TC_ROUND_MISMATCH: u8 = 0x0b;
pub const TAG_TC_MISSING_STAKE_SET: u8 = 0x28;
pub const TAG_TC_UNKNOWN_SIGNER: u8 = 0x2c;

/// One signer entry in `TimeoutCertificate::signatures` (`0x68`-byte ring row).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcSignatureEntry {
    pub signer: Address,
    pub high_qc_round: u64,
    pub signature: Signature,
}

/// Timeout certificate verified by `0x5960390`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiableTimeoutCertificate {
    pub high_qc: Certificate,
    pub round: u64,
    pub signatures: Vec<TcSignatureEntry>,
}

/// Rejection reasons matching `0x5960390`'s exact tag checks and order.
#[derive(Debug, Eq, PartialEq)]
pub enum TcVerifyError {
    /// Tag `0x28`: stake-set provider had no set for `high_qc.f40`.
    MissingStakeSet { round: u64 },
    /// Tag `0x2c`: signer not present in the stake map (`0x4dffc40`).
    UnknownSigner(Address),
    /// Tag `0x08`: empty signatures or consensus quorum `0x595bc40` returned false.
    QuorumFailed,
    /// Tag `0x0b`: `high_qc.f30 != max_signed_high_qc_round` OR `max_signed_high_qc_round >= tc.round`.
    RoundInvariantViolated {
        high_qc_round: u64,
        max_signed_high_qc_round: u64,
        tc_round: u64,
    },
    /// Nested `decide_nested(&tc.high_qc)` did not produce tag `0x2e`.
    HighQcRejected(DecisionOutput<Verdict>),
    /// Tag `0x02`: one of the timeout signatures failed variant-2 verification (`0x564b510`).
    InvalidTimeoutSignature(Address),
}

impl TcVerifyError {
    pub fn tag(&self) -> Option<u8> {
        match self {
            TcVerifyError::MissingStakeSet { .. } => Some(TAG_TC_MISSING_STAKE_SET),
            TcVerifyError::UnknownSigner(_) => Some(TAG_TC_UNKNOWN_SIGNER),
            TcVerifyError::QuorumFailed => Some(TAG_TC_QUORUM_FAILED),
            TcVerifyError::RoundInvariantViolated { .. } => Some(TAG_TC_ROUND_MISMATCH),
            TcVerifyError::HighQcRejected(out) => out.tag(),
            TcVerifyError::InvalidTimeoutSignature(_) => Some(TAG_TC_BAD_SIGNATURE),
        }
    }
}

/// Reconstructs `0x5960390` (`TimeoutCertificate::verify`) in native execution order:
/// 1. Query stake set for `tc.high_qc.f40` (`0x64e64b0` = `0x595e5c0`).
/// 2. Verify every signer is in `stake_set.stakes` and collect unique signers (`0x4dffc40`).
/// 3. Empty signatures -> `QuorumFailed` (`0x08`); else compute `max_signed_high_qc_round`.
/// 4. Enforce `tc.high_qc.f30 == max_signed_high_qc_round < tc.round`, else `0x0b`.
/// 5. Enforce consensus quorum (`0x595bc40`), else `0x08`.
/// 6. Verify `tc.high_qc` via `decide_nested` (`0x595fd20`), requiring tag `0x2e`.
/// 7. Verify every entry's variant-2 timeout signature (`0x564b510`).
pub fn verify_timeout_certificate<S, P>(
    tc: &VerifiableTimeoutCertificate,
    ctx: &Context,
    stakes: &S,
    primitives: &P,
) -> Result<(), TcVerifyError>
where
    S: StakeSetProvider,
    P: AdmissionPrimitives,
{
    let stake_set = stakes
        .stake_set(ctx, tc.high_qc.f40)
        .ok_or(TcVerifyError::MissingStakeSet {
            round: tc.high_qc.f40,
        })?;

    let mut signers = BTreeSet::new();
    for entry in &tc.signatures {
        if !stake_set.stakes.contains(&entry.signer) {
            return Err(TcVerifyError::UnknownSigner(entry.signer));
        }
        signers.insert(entry.signer);
    }

    if tc.signatures.is_empty() {
        return Err(TcVerifyError::QuorumFailed);
    }

    let max_signed = tc
        .signatures
        .iter()
        .map(|e| e.high_qc_round)
        .max()
        .unwrap_or(0);
    if tc.high_qc.f30 != max_signed || max_signed >= tc.round {
        return Err(TcVerifyError::RoundInvariantViolated {
            high_qc_round: tc.high_qc.f30,
            max_signed_high_qc_round: max_signed,
            tc_round: tc.round,
        });
    }

    if !quorum(ctx.quorum_fraction_bits, stake_set, &signers) {
        return Err(TcVerifyError::QuorumFailed);
    }

    let nested = decide_nested(&tc.high_qc, ctx, stakes, primitives);
    if nested.tag() != Some(TAG_CONTINUE) {
        return Err(TcVerifyError::HighQcRejected(nested));
    }

    for entry in &tc.signatures {
        let payload = TimeoutDigestPayload {
            hardfork_version: ctx.pair[0],
            hardfork_round: ctx.pair[1],
            timeout_round: tc.round,
            high_qc_round: entry.high_qc_round,
            signer: entry.signer,
        };
        let digest = primitives.digest_payload(DIGEST_VARIANT_TIMEOUT, &payload.to_bytes());
        if primitives.recover(&entry.signature, &digest).as_ref() != Some(&entry.signer) {
            return Err(TcVerifyError::InvalidTimeoutSignature(entry.signer));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nested_certificate::{
        sigmap::SigMap,
        signer::{SignaturePrimitives, VoteFrame},
        stake::{StakeMap, StakeSet},
    };

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
            [0x11; 32]
        }
        fn recover(&self, signature: &Signature, _digest: &[u8; 32]) -> Option<Address> {
            let mut a = [0u8; 20];
            a[19] = signature[0];
            Some(a)
        }
    }
    impl AdmissionPrimitives for KeyedPrimitives {
        fn digest_payload(&self, _variant: u64, _payload: &[u8]) -> [u8; 32] {
            [0x22; 32]
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
    fn tc_verify_checks_empty_round_invariant_quorum_nested_qc_and_sigs() {
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

        // Empty signatures -> tag 0x08.
        let empty = VerifiableTimeoutCertificate {
            high_qc: genesis_qc([1, 10]),
            round: 11,
            signatures: Vec::new(),
        };
        assert_eq!(
            verify_timeout_certificate(&empty, &ctx, &stakes, &KeyedPrimitives),
            Err(TcVerifyError::QuorumFailed)
        );

        // Max signed high_qc_round == tc.round -> tag 0x0b.
        let eq_round = VerifiableTimeoutCertificate {
            high_qc: genesis_qc([1, 10]),
            round: 10,
            signatures: vec![
                TcSignatureEntry { signer: a1, high_qc_round: 10, signature: sig_for(1) },
                TcSignatureEntry { signer: a2, high_qc_round: 10, signature: sig_for(2) },
                TcSignatureEntry { signer: a3, high_qc_round: 10, signature: sig_for(3) },
            ],
        };
        let err = verify_timeout_certificate(&eq_round, &ctx, &stakes, &KeyedPrimitives).unwrap_err();
        assert_eq!(err.tag(), Some(TAG_TC_ROUND_MISMATCH));

        // 2/3 exact stake (200/300) fails strict > quorum -> tag 0x08.
        let two_thirds = VerifiableTimeoutCertificate {
            high_qc: genesis_qc([1, 10]),
            round: 11,
            signatures: vec![
                TcSignatureEntry { signer: a1, high_qc_round: 10, signature: sig_for(1) },
                TcSignatureEntry { signer: a2, high_qc_round: 10, signature: sig_for(2) },
            ],
        };
        assert_eq!(
            verify_timeout_certificate(&two_thirds, &ctx, &stakes, &KeyedPrimitives),
            Err(TcVerifyError::QuorumFailed)
        );

        // Valid 300/300 TC passes completely.
        let valid = VerifiableTimeoutCertificate {
            high_qc: genesis_qc([1, 10]),
            round: 11,
            signatures: vec![
                TcSignatureEntry { signer: a1, high_qc_round: 10, signature: sig_for(1) },
                TcSignatureEntry { signer: a2, high_qc_round: 10, signature: sig_for(2) },
                TcSignatureEntry { signer: a3, high_qc_round: 10, signature: sig_for(3) },
            ],
        };
        assert_eq!(
            verify_timeout_certificate(&valid, &ctx, &stakes, &KeyedPrimitives),
            Ok(())
        );

        // Forged signature fails with tag 0x02.
        let mut bad_sig = valid;
        bad_sig.signatures[2].signature = sig_for(99);
        assert_eq!(
            verify_timeout_certificate(&bad_sig, &ctx, &stakes, &KeyedPrimitives),
            Err(TcVerifyError::InvalidTimeoutSignature(a3))
        );
    }
}
