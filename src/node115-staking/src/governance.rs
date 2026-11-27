//! Independently authored Rust reconstruction of node #115's staking governance
//! proposal creation gate (`0x3c348b0..0x3c34fca`, slot `0x64e5bd0`; packet
//! `RE-008-node115-staking-delegation`).

use crate::delegation::{StakingChain, add_secs_saturating};
use crate::jailing::JailingTime;

/// Exact native error tags emitted by `0x3c348b0`.
pub const TAG_PROPOSAL_TITLE_LEN: u16 = 0x10f; // 271: 1..=50
pub const TAG_PROPOSAL_DESC_LEN: u16 = 0x110; // 272: 1..=1000
pub const TAG_INSUFFICIENT_DELEGATIONS_TO_PROPOSE: u16 = 0x111; // 273: < 1_000_000_000
pub const TAG_PROPOSAL_ALREADY_EXISTS: u16 = 0x112; // 274
pub const TAG_TOO_MANY_ACTIVE_PROPOSALS: u16 = 0x113; // 275: existing > 2 (limit 3)

/// Verified constants from `0x3c3491e..0x3c3499b` and `0x3c34c26`.
pub const PROPOSAL_TITLE_MIN_LEN: usize = 1;
pub const PROPOSAL_TITLE_MAX_LEN: usize = 50; // 0x32
pub const PROPOSAL_DESC_MIN_LEN: usize = 1;
pub const PROPOSAL_DESC_MAX_LEN: usize = 1_000; // 0x3e8
pub const PROPOSAL_MIN_DELEGATED_STAKE: u64 = 1_000_000_000; // 0x3b9aca00
pub const MAX_ACTIVE_PROPOSALS_PER_USER: usize = 3; // rejects when existing > 2

/// Exact `.rodata` IEEE-754 `f64` voting duration constants at `0x3c34c73..0x3c34cb2`.
pub const PROPOSAL_DURATION_TEST_LONG_BITS: u64 = 0x4072_c000_0000_0000; // 300.0 s @ 0x455bc0
pub const PROPOSAL_DURATION_TEST_SHORT_BITS: u64 = 0x405e_0000_0000_0000; // 120.0 s @ 0x455bc8
pub const PROPOSAL_DURATION_MAIN_LONG_BITS: u64 = 0x411f_a400_0000_0000; // 518,400.0 s @ 0x459418
pub const PROPOSAL_DURATION_MAIN_SHORT_BITS: u64 = 0x40f5_1800_0000_0000; // 86,400.0 s @ 0x459ac0

/// Rejection reasons matching `0x3c348b0`'s exact check order and native tags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposeError {
    TitleLengthOutOfRange { len: usize },
    DescriptionLengthOutOfRange { len: usize },
    InsufficientDelegations { delegated: u64 },
    ProposalAlreadyExists,
    TooManyActiveProposals { existing_for_user: usize },
}

impl ProposeError {
    pub const fn native_tag(self) -> u16 {
        match self {
            Self::TitleLengthOutOfRange { .. } => TAG_PROPOSAL_TITLE_LEN,
            Self::DescriptionLengthOutOfRange { .. } => TAG_PROPOSAL_DESC_LEN,
            Self::InsufficientDelegations { .. } => TAG_INSUFFICIENT_DELEGATIONS_TO_PROPOSE,
            Self::ProposalAlreadyExists => TAG_PROPOSAL_ALREADY_EXISTS,
            Self::TooManyActiveProposals { .. } => TAG_TOO_MANY_ACTIVE_PROPOSALS,
        }
    }
}

/// Voting duration in seconds selected by `0x3c34c73..0x3c34cb2`.
pub const fn proposal_voting_duration_secs(chain: StakingChain, long_window: bool) -> u64 {
    match chain {
        StakingChain::Sandbox | StakingChain::Testnet => {
            if long_window {
                300
            } else {
                120
            }
        }
        StakingChain::Local | StakingChain::Mainnet => {
            if long_window {
                518_400
            } else {
                86_400
            }
        }
    }
}

/// Evaluates `0x3c348b0`'s admission predicates in exact native order and returns
/// the proposal voting deadline (`now + duration`).
#[allow(clippy::too_many_arguments)]
pub fn validate_proposal_creation(
    chain: StakingChain,
    now: JailingTime,
    title: &str,
    description: &str,
    proposer_delegated_stake: u64,
    proposal_id_exists: bool,
    existing_active_for_user: usize,
    long_window: bool,
) -> Result<JailingTime, ProposeError> {
    let title_len = title.len();
    if !(PROPOSAL_TITLE_MIN_LEN..=PROPOSAL_TITLE_MAX_LEN).contains(&title_len) {
        return Err(ProposeError::TitleLengthOutOfRange { len: title_len });
    }
    let desc_len = description.len();
    if !(PROPOSAL_DESC_MIN_LEN..=PROPOSAL_DESC_MAX_LEN).contains(&desc_len) {
        return Err(ProposeError::DescriptionLengthOutOfRange { len: desc_len });
    }
    if proposer_delegated_stake < PROPOSAL_MIN_DELEGATED_STAKE {
        return Err(ProposeError::InsufficientDelegations {
            delegated: proposer_delegated_stake,
        });
    }
    if proposal_id_exists {
        return Err(ProposeError::ProposalAlreadyExists);
    }
    if existing_active_for_user >= MAX_ACTIVE_PROPOSALS_PER_USER {
        return Err(ProposeError::TooManyActiveProposals {
            existing_for_user: existing_active_for_user,
        });
    }
    let duration = proposal_voting_duration_secs(chain, long_window);
    Ok(add_secs_saturating(now, duration))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(days: i32, secs: u32) -> JailingTime {
        JailingTime {
            major: days,
            seconds: secs,
            nanos: 0,
        }
    }

    #[test]
    fn proposal_gate_enforces_exact_order_bounds_and_durations() {
        let ok_title = "HIP-99";
        let ok_desc = "Enable governance parameter update";

        assert_eq!(
            validate_proposal_creation(StakingChain::Mainnet, t(10, 0), "", ok_desc, 0, true, 9, false),
            Err(ProposeError::TitleLengthOutOfRange { len: 0 })
        );
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Mainnet,
                t(10, 0),
                &"a".repeat(51),
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE,
                false,
                0,
                false,
            ),
            Err(ProposeError::TitleLengthOutOfRange { len: 51 })
        );
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Mainnet,
                t(10, 0),
                ok_title,
                &"b".repeat(1001),
                PROPOSAL_MIN_DELEGATED_STAKE,
                false,
                0,
                false,
            ),
            Err(ProposeError::DescriptionLengthOutOfRange { len: 1001 })
        );
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Mainnet,
                t(10, 0),
                ok_title,
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE - 1,
                false,
                0,
                false,
            ),
            Err(ProposeError::InsufficientDelegations {
                delegated: PROPOSAL_MIN_DELEGATED_STAKE - 1,
            })
        );
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Mainnet,
                t(10, 0),
                ok_title,
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE,
                true,
                0,
                false,
            ),
            Err(ProposeError::ProposalAlreadyExists)
        );
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Mainnet,
                t(10, 0),
                ok_title,
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE,
                false,
                3,
                false,
            ),
            Err(ProposeError::TooManyActiveProposals {
                existing_for_user: 3,
            })
        );

        // Existing active == 2 is allowed (3rd proposal); Mainnet long window = 6 days (518,400s)
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Mainnet,
                t(10, 5),
                ok_title,
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE,
                false,
                2,
                true,
            ),
            Ok(t(16, 5))
        );
        // Testnet short window = 120s, long window = 300s
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Testnet,
                t(10, 5),
                ok_title,
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE,
                false,
                0,
                false,
            ),
            Ok(t(10, 125))
        );
        assert_eq!(
            validate_proposal_creation(
                StakingChain::Sandbox,
                t(10, 5),
                ok_title,
                ok_desc,
                PROPOSAL_MIN_DELEGATED_STAKE,
                false,
                0,
                true,
            ),
            Ok(t(10, 305))
        );
    }
}
