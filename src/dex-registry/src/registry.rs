//! Checked Perp DEX index (`Pdi`) lookup, registry storage, and cross-DEX queries.
//!
//! Anchored to node #115:
//! - `l1/src/dex_registry/perp_dex.rs:29,34` (`0x4201750`, `0x42017d0` — `Vec<PerpDex>` bounds check, stride `0x200`)
//! - `l1/src/dex_registry/clearinghouses.rs:11,17` (`0x2753a70` — `Vec<Clearinghouse>` bounds check, stride `0x510`)
//! - `l1/src/dex_registry/dex_registry.rs:37` (`0x2c774c0` — zipped `(perp_dexes, clearinghouses)` scan)

use std::collections::BTreeMap;

use crate::{
    disabled_state_codec::DisabledState,
    schema::{DexKind, DexMetadata, Hip3Schema},
    sub_deployers::Hip3DeployAction,
    Address,
};

/// Native struct stride observed in `0x420175e` (`shlq $0x9, %rbx` = 512 bytes) for `PerpDex`.
pub const OBSERVED_PERP_DEX_STRIDE: usize = 0x200;

/// Native struct stride observed in `0x2c775a3` (`addq $0x510, %r15` = 1,296 bytes) for `Clearinghouse`.
pub const OBSERVED_CLEARINGHOUSE_STRIDE: usize = 0x510;

/// Perp DEX Index (`0` = Main DEX, `1..` = registered HIP-3 DEXes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pdi(pub usize);

impl Pdi {
    pub const MAIN: Self = Self(0);

    pub const fn is_main(self) -> bool {
        self.0 == 0
    }
}

/// Errors returned by checked DEX registry lookups and registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// Out-of-range PDI (matches `cmpq 0x10(%rdi), %rsi; jae` in `0x4201755` / `0x42017d5`).
    UnknownPdi { pdi: Pdi, len: usize },
    /// Duplicate HIP-3 DEX short name on registration.
    DuplicateDexName(String),
    /// Main DEX already registered at PDI 0, or attempted to register HIP-3 before Main.
    InvalidMainDexOrder,
    /// Caller lacks deployer or sub-deployer authority for the action.
    UnauthorizedDeployer,
    /// DEX is disabled (user or validator disabled).
    DexDisabled(DisabledState),
}

/// One registered perpetual DEX pairing its metadata with its clearinghouse state `C`.
#[derive(Clone, Debug)]
pub struct PerpDexSlot<C> {
    pub pdi: Pdi,
    pub metadata: DexMetadata,
    pub clearinghouse: C,
}

/// Registry holding the Main DEX (`Pdi(0)`) and all HIP-3 DEXes (`Pdi(1..)`),
/// mirroring the parallel `Vec<PerpDex>` + `Vec<Clearinghouse>` layout observed
/// at `0x4201750` and `0x2c774c0`.
#[derive(Clone, Debug)]
pub struct DexRegistry<C> {
    slots: Vec<PerpDexSlot<C>>,
    name_to_pdi: BTreeMap<String, Pdi>,
}

impl<C> Default for DexRegistry<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> DexRegistry<C> {
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            name_to_pdi: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Registers the Main DEX at `Pdi(0)`. Must be registered first.
    pub fn register_main(
        &mut self,
        metadata: DexMetadata,
        clearinghouse: C,
    ) -> Result<Pdi, RegistryError> {
        if !self.slots.is_empty() || metadata.kind() != DexKind::Main {
            return Err(RegistryError::InvalidMainDexOrder);
        }
        let pdi = Pdi::MAIN;
        self.slots.push(PerpDexSlot {
            pdi,
            metadata,
            clearinghouse,
        });
        Ok(pdi)
    }

    /// Registers a HIP-3 DEX at the next sequential `Pdi`.
    pub fn register_hip3(
        &mut self,
        metadata: DexMetadata,
        clearinghouse: C,
    ) -> Result<Pdi, RegistryError> {
        if self.slots.is_empty() {
            return Err(RegistryError::InvalidMainDexOrder);
        }
        let name = match &metadata {
            DexMetadata::Hip3 { schema, .. } => schema.name.clone(),
            DexMetadata::Main { .. } => return Err(RegistryError::InvalidMainDexOrder),
        };
        if self.name_to_pdi.contains_key(&name) {
            return Err(RegistryError::DuplicateDexName(name));
        }
        let pdi = Pdi(self.slots.len());
        self.name_to_pdi.insert(name, pdi);
        self.slots.push(PerpDexSlot {
            pdi,
            metadata,
            clearinghouse,
        });
        Ok(pdi)
    }

    /// Checked lookup by `Pdi` (`perp_dex.rs:29` / `clearinghouses.rs:11`).
    pub fn get(&self, pdi: Pdi) -> Result<&PerpDexSlot<C>, RegistryError> {
        self.slots.get(pdi.0).ok_or(RegistryError::UnknownPdi {
            pdi,
            len: self.slots.len(),
        })
    }

    /// Checked mutable lookup by `Pdi` (`perp_dex.rs:34` / `clearinghouses.rs:17`).
    pub fn get_mut(&mut self, pdi: Pdi) -> Result<&mut PerpDexSlot<C>, RegistryError> {
        let len = self.slots.len();
        self.slots
            .get_mut(pdi.0)
            .ok_or(RegistryError::UnknownPdi { pdi, len })
    }

    /// Lookup a HIP-3 DEX index by its short wire name (`schema.name`).
    pub fn pdi_by_name(&self, name: &str) -> Option<Pdi> {
        if name.is_empty() {
            return (!self.slots.is_empty()).then_some(Pdi::MAIN);
        }
        self.name_to_pdi.get(name).copied()
    }

    /// Checks whether `caller` is authorized to execute `action` on HIP-3 DEX `pdi`
    /// and that the DEX is not disabled (unless the action itself is `DisableDex`).
    pub fn authorize_hip3_action(
        &self,
        pdi: Pdi,
        action: Hip3DeployAction,
        caller: &Address,
    ) -> Result<&Hip3Schema, RegistryError> {
        let slot = self.get(pdi)?;
        match &slot.metadata {
            DexMetadata::Main { .. } => Err(RegistryError::UnauthorizedDeployer),
            DexMetadata::Hip3 { schema, state, .. } => {
                if !schema
                    .sub_deployers
                    .is_authorized(&schema.deployer, action, caller)
                {
                    return Err(RegistryError::UnauthorizedDeployer);
                }
                if state.disabled_state != DisabledState::Na
                    && action != Hip3DeployAction::DisableDex
                {
                    return Err(RegistryError::DexDisabled(state.disabled_state));
                }
                Ok(schema)
            }
        }
    }

    /// Transitions a HIP-3 DEX's [`DisabledState`] after verifying deployer or
    /// `Hip3DeployAction::DisableDex` (selector `0x13`, `0x469e170`) authorization.
    ///
    /// Mirrors node #115's `disableDex` state write (`RE-007-node115-hip3-disabled-state-writer`,
    /// `RE-008-node115-hip3-permission-membership`), setting `DisabledState::UserDisabled`
    /// on deployer/sub-deployer disable or `DisabledState::ValidatorDisabled` on validator override.
    pub fn set_disabled_state(
        &mut self,
        pdi: Pdi,
        caller: &Address,
        new_state: DisabledState,
        is_validator_override: bool,
    ) -> Result<DisabledState, RegistryError> {
        let slot = self.get_mut(pdi)?;
        match &mut slot.metadata {
            DexMetadata::Main { .. } => Err(RegistryError::UnauthorizedDeployer),
            DexMetadata::Hip3 { schema, state, .. } => {
                if !is_validator_override
                    && !schema.sub_deployers.is_authorized(
                        &schema.deployer,
                        Hip3DeployAction::DisableDex,
                        caller,
                    )
                {
                    return Err(RegistryError::UnauthorizedDeployer);
                }
                let prev = state.disabled_state;
                state.disabled_state = new_state;
                Ok(prev)
            }
        }
    }

    /// Scans across all registered DEX slots in PDI order (mirroring `0x2c774c0`
    /// `dex_registry.rs:37`), returning `true` as soon as `predicate` matches.
    pub fn any_slot<F>(&self, predicate: F) -> bool
    where
        F: FnMut(&PerpDexSlot<C>) -> bool,
    {
        self.slots.iter().any(predicate)
    }

    pub fn iter(&self) -> impl Iterator<Item = &PerpDexSlot<C>> {
        self.slots.iter()
    }
}
