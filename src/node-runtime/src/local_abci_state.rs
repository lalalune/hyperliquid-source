//! Startup local ABCI state admission and hardfork-upgrade decision logic
//! matching node #115 `node/src/local_abci_state.rs` (`0x2adce40..0x2ae00f8`).

use net_utils::{GossipStatus, Hardfork};

/// Minimum number of valid remote `GossipStatus` responses required before
/// trusting local ABCI state (`0x605a53`: `"unable to find at least 2 valid rpc statuses"`).
pub const MIN_VALID_RPC_STATUSES: usize = 2;

/// Maximum height lag before local ABCI state is declared stale
/// (`0x2add488..0x2add4ad`: `local_height.saturating_add(0x4e20) <= remote_latest_height`).
pub const MAX_LOCAL_HEIGHT_LAG: u64 = 20_000;

/// Maximum consensus-round distance past `local_hardfork.round` for triggering
/// a frozen hardfork upgrade (`0x2add52c..0x2add54e`: `local_round.saturating_add(0x190)`).
pub const UPGRADE_ROUND_WINDOW: u64 = 400;

/// Observed diagnostic messages in `0x2adce40..0x2ae00f8`.
pub const INSUFFICIENT_RPC_STATUSES_MSG: &str = "unable to find at least 2 valid rpc statuses";
pub const LOCAL_HEIGHT_TOO_FAR_BEHIND_MSG: &str = "local height is too far behind";
pub const LOCAL_HEIGHT_STALE_HARDFORK_MSG: &str = "local height is from stale hardfork";
pub const INITIALIZING_FOR_UPGRADE_MSG: &str = "initializing for network upgrade";
pub const APPLYING_HARDFORK_MSG: &str = "applying hardfork to frozen local abci_state";
pub const INITIALIZING_WITH_LOCAL_STATE_MSG: &str = "initializing with local abci_state";

/// Local on-disk ABCI state summary evaluated at startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalAbciSnapshot {
    pub height: u64,
    pub hardfork: Hardfork,
    pub frozen_for_upgrade: bool,
}

/// Startup decision produced by `node/src/local_abci_state.rs` (`0x2add47d..0x2add6a8`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalStateDecision {
    /// Fewer than `MIN_VALID_RPC_STATUSES` (2) valid peer statuses were obtained.
    InsufficientRpcStatuses,
    /// `local.height.saturating_add(20_000) <= remote.latest_height` (`0x2add488..0x2add4ad`).
    StaleTooFarBehind,
    /// `local.height < remote.hardfork_height` or `local.hardfork < remote.hardfork` (`0x2add4bf..0x2add4ef`).
    StaleHardfork,
    /// Local state is frozen for upgrade and within `UPGRADE_ROUND_WINDOW` (400) rounds (`0x2add516..0x2add554`).
    ApplyHardforkUpgrade,
    /// Local state is fresh and matches current hardfork (`"initializing with local abci_state"`).
    UseLocal,
}

impl LocalStateDecision {
    pub const fn diagnostic_msg(self) -> &'static str {
        match self {
            Self::InsufficientRpcStatuses => INSUFFICIENT_RPC_STATUSES_MSG,
            Self::StaleTooFarBehind => LOCAL_HEIGHT_TOO_FAR_BEHIND_MSG,
            Self::StaleHardfork => LOCAL_HEIGHT_STALE_HARDFORK_MSG,
            Self::ApplyHardforkUpgrade => APPLYING_HARDFORK_MSG,
            Self::UseLocal => INITIALIZING_WITH_LOCAL_STATE_MSG,
        }
    }
}

/// Evaluate whether a local ABCI checkpoint can be used at startup against
/// remote `GossipStatus` samples, reproducing the exact `#115` branch order
/// at `0x2add47d..0x2add554`.
pub fn evaluate_local_abci_state(
    local: LocalAbciSnapshot,
    remote_statuses: &[GossipStatus],
) -> LocalStateDecision {
    if remote_statuses.len() < MIN_VALID_RPC_STATUSES {
        return LocalStateDecision::InsufficientRpcStatuses;
    }

    // Aggregate the highest observed remote view across valid statuses.
    let remote_latest_height = remote_statuses
        .iter()
        .map(|s| s.latest_height)
        .max()
        .unwrap_or(0);
    let remote_hardfork_height = remote_statuses
        .iter()
        .map(|s| s.hardfork_height)
        .max()
        .unwrap_or(0);
    let remote_hardfork = remote_statuses
        .iter()
        .map(|s| s.hardfork)
        .max()
        .unwrap_or_default();
    let remote_latest_consensus_round = remote_statuses
        .iter()
        .filter_map(|s| s.latest_consensus_round)
        .max();

    // 1. 0x2add488..0x2add4ad: local_height.saturating_add(20_000) <= remote_latest_height
    if local.height.saturating_add(MAX_LOCAL_HEIGHT_LAG) <= remote_latest_height {
        return LocalStateDecision::StaleTooFarBehind;
    }

    // 2. 0x2add4bf..0x2add4ef: local_height < remote_hardfork_height || local_hardfork < remote_hardfork
    if local.height < remote_hardfork_height || local.hardfork < remote_hardfork {
        return LocalStateDecision::StaleHardfork;
    }

    // 3. 0x2add516..0x2add554: frozen upgrade gate with 400-round consensus window
    if local.frozen_for_upgrade {
        let within_window = match remote_latest_consensus_round {
            None => true,
            Some(remote_round) => {
                local.hardfork.round.saturating_add(UPGRADE_ROUND_WINDOW) > remote_round
            }
        };
        if within_window {
            return LocalStateDecision::ApplyHardforkUpgrade;
        }
    }

    LocalStateDecision::UseLocal
}
