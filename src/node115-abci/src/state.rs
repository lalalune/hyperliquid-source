//! Node #115 `l1/src/abci/state.rs` checkpoint restore, loader handoff, freeze-height
//! invariant, and block-state progression.
//!
//! Binary anchors (`RE-009-node115-abci-crate-map`):
//! - `0x3c12800..0x3c12af5` (`state.rs:76..82`): persisted height verification `[S+0x28]`
//! - `0x3c13520..0x3c13609` (`state.rs:123:37`): loader handoff tag `1` (`0x3c1353b`)
//! - `0x22ed1f0..0x22ed70a` (`state.rs:201`): `assertion failed: freeze_height >= self.locus.context.height()`
//! - `0x22ec9b0..0x22ed1ec` (`state.rs:460`): action success status `0x1a2` (`0x22ec9c9`)

pub use node115_abci_checkpoint_replay_fixture::{
    ReplayInitializer, RestoreError, RestoredState, restore_checkpoint,
};

/// Action execution success code checked at `0x22ec9c9` (`state.rs:460`).
pub const ACTION_SUCCESS_CODE: u16 = 0x1a2;

/// Loader handoff tag checked at `0x3c1353b` (`state.rs:123:37`).
pub const LOADER_HANDOFF_TAG: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreezeHeightError {
    FreezeHeightBelowCurrent {
        freeze_height: u64,
        current_height: u64,
    },
}

/// Enforces the `l1/src/abci/state.rs:201` invariant (`0x22ed1f0`):
/// `freeze_height >= current_height`.
pub fn validate_freeze_height(
    freeze_height: u64,
    current_height: u64,
) -> Result<(), FreezeHeightError> {
    if freeze_height < current_height {
        return Err(FreezeHeightError::FreezeHeightBelowCurrent {
            freeze_height,
            current_height,
        });
    }
    Ok(())
}

/// Checked wrapper around `RestoredState` supporting saturating height advance (`0x54838d3..0x54838f1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbciState {
    pub inner: RestoredState,
    pub hardfork_height: Option<u64>,
    pub periodic_root_cadence: u64,
}

impl AbciState {
    pub fn new(
        restored: RestoredState,
        periodic_root_cadence: u64,
        hardfork_height: Option<u64>,
    ) -> Self {
        Self {
            inner: restored,
            hardfork_height,
            periodic_root_cadence,
        }
    }

    pub fn height(&self) -> u64 {
        self.inner.height
    }

    pub fn round(&self) -> u64 {
        self.inner.round
    }

    /// Advance `[S + 0x28]` with saturation (`0x54838d3..0x54838e5`) and store new round `[S + 0x30]`.
    pub fn advance_block(&mut self, new_round: u64) {
        self.inner.height = self.inner.height.saturating_add(1);
        self.inner.round = new_round;
    }

    pub fn check_freeze_height(&self, freeze_height: u64) -> Result<(), FreezeHeightError> {
        validate_freeze_height(freeze_height, self.inner.height)
    }
}
