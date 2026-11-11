//! Target-bound wire-name / in-memory selector / admission-class binding.
//! Classification is not cryptographic verification or permission to execute an action.
#![no_std]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AdmissionClass {
    ValidatorOnly = 0,
    ValidatorOrListedAddress = 1,
    AnySigner = 2,
    ResolveKnownUser = 3,
    Refused = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Action {
    pub index: u8,
    pub rust_variant: &'static str,
    pub wire_name: &'static str,
    pub admission: AdmissionClass,
}

impl Action {
    /// Nominal in-memory tag, not a wire byte or proof that every bit pattern is valid.
    pub const fn nominal_tag(self) -> u64 {
        0x86 + self.index as u64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InternalBinding {
    pub action: &'static Action,
    /// Below-base in-memory words share index20; their payload validity is not established.
    pub below_base_alias: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutsideRecoveredDomain;

/// Reconstruct the getter's biased selection within its recovered table domain.
/// The native getter has no upper bound check. We reject outside its92 known entries.
pub fn from_internal_word(word: u64) -> Result<InternalBinding, OutsideRecoveredDomain> {
    let (index, below_base_alias) = match word.checked_sub(0x86) {
        None => (20, true),
        Some(index) if index < 92 => (index as usize, false),
        _ => return Err(OutsideRecoveredDomain),
    };
    Ok(InternalBinding {
        action: &ACTIONS[index],
        below_base_alias,
    })
}

/// Exact case-sensitive serializer spelling. This does not decode an action payload.
pub fn from_wire_name(name: &str) -> Option<&'static Action> {
    ACTIONS.iter().find(|action| action.wire_name == name)
}

/// Recovered catalogue/serializer index. This API does not decode a MessagePack integer.
pub fn from_index(index: u64) -> Option<&'static Action> {
    if index < 92 {
        Some(&ACTIONS[index as usize])
    } else {
        None
    }
}

mod table;
pub use table::ACTIONS;
