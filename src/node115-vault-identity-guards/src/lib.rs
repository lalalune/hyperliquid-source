//! Ordered identity-policy entry guards from node #115 VA 0x44ae810.

pub const TARGET_SHA256: &str = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";
pub const FAILURE_HEAD: u64 = 0x8000_0000_0000_0019;
pub const MODE_ONE_IDENTITY_MISMATCH: u16 = 0x16;
pub const POLICY_IDENTITY_MISMATCH: u16 = 0x17;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreludeResult {
    ContinueToNextStage,
    Reject { head: u64, reason: u16 },
}

/// Evaluate the two ordered identity guards at the entry prelude.
///
/// `raw_mode` is the context qword at +0. `policy_byte` is the byte at +0xb5.
/// The identity arguments are compared byte-for-byte over all 20 bytes.
/// Continuing means only that these two guards passed, not that the operation
/// was accepted or completed.
pub fn evaluate_prelude(
    raw_mode: u64,
    policy_byte: u8,
    incoming_identity: &[u8; 20],
    retained_identity: &[u8; 20],
) -> PreludeResult {
    let identities_match = incoming_identity == retained_identity;

    if raw_mode == 1 && !identities_match {
        return PreludeResult::Reject {
            head: FAILURE_HEAD,
            reason: MODE_ONE_IDENTITY_MISMATCH,
        };
    }

    if policy_byte == 0 && !identities_match {
        return PreludeResult::Reject {
            head: FAILURE_HEAD,
            reason: POLICY_IDENTITY_MISMATCH,
        };
    }

    PreludeResult::ContinueToNextStage
}

#[cfg(test)]
mod tests {
    use super::{
        evaluate_prelude, PreludeResult, FAILURE_HEAD, MODE_ONE_IDENTITY_MISMATCH,
        POLICY_IDENTITY_MISMATCH,
    };

    fn rejected(reason: u16) -> PreludeResult {
        PreludeResult::Reject {
            head: FAILURE_HEAD,
            reason,
        }
    }

    #[test]
    fn mode_one_mismatch_exits_first_even_with_nonzero_policy() {
        let incoming = [0x11; 20];
        let retained = [0x22; 20];

        assert_eq!(
            evaluate_prelude(1, 0xff, &incoming, &retained),
            rejected(MODE_ONE_IDENTITY_MISMATCH)
        );
    }

    #[test]
    fn zero_policy_requires_identity_when_mode_is_not_one() {
        let incoming = [0x11; 20];
        let retained = [0x22; 20];
        assert_eq!(
            evaluate_prelude(2, 0, &incoming, &retained),
            rejected(POLICY_IDENTITY_MISMATCH)
        );
    }

    #[test]
    fn nonzero_policy_bypasses_identity_only_outside_mode_one() {
        let incoming = [0x11; 20];
        let retained = [0x22; 20];
        assert_eq!(
            evaluate_prelude(2, 1, &incoming, &retained),
            PreludeResult::ContinueToNextStage
        );
    }

    #[test]
    fn every_identity_byte_participates_in_comparison() {
        let incoming = [0x11; 20];
        for changed in [0, 15, 16, 19] {
            let mut retained = incoming;
            retained[changed] ^= 0xff;
            assert_eq!(
                evaluate_prelude(1, 1, &incoming, &retained),
                rejected(MODE_ONE_IDENTITY_MISMATCH),
                "byte {changed} must be included in the full 20-byte comparison"
            );
        }
    }

    #[test]
    fn local_raw_truth_table_matches_the_static_predicate() {
        let equal = [0x33; 20];
        let unequal = [0x44; 20];
        for mode in [0, 1, 2, u64::MAX] {
            for policy in [0, 1, 0xff] {
                for matches in [false, true] {
                    let right = if matches { &equal } else { &unequal };
                    let actual = evaluate_prelude(mode, policy, &equal, right);
                    let expected = if matches || (mode != 1 && policy != 0) {
                        PreludeResult::ContinueToNextStage
                    } else if mode == 1 {
                        rejected(MODE_ONE_IDENTITY_MISMATCH)
                    } else {
                        rejected(POLICY_IDENTITY_MISMATCH)
                    };
                    assert_eq!(
                        actual, expected,
                        "mode={mode}, policy={policy}, matches={matches}"
                    );
                }
            }
        }
    }
}
