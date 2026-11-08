//! Owned logical state for node115 referral-code registration and modification.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::{collections::BTreeMap, string::String};
pub type Address = [u8; 20];
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Referrer {
    pub code: String,
    /// Preserved opaque three-word native timestamp payloads.
    pub history: BTreeMap<Address, [u32; 3]>,
    pub remaining: u64,
    pub bucket: u64,
    pub configured_quota: u64,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    /// Native per-user reward row's first raw u64 word, keyed by asset.
    pub volume_rows: BTreeMap<Address, BTreeMap<u64, u64>>,
    pub referrers: BTreeMap<Address, Referrer>,
    pub codes: BTreeMap<String, Address>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Register,
    Modify,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Status {
    Accepted = 0x1a2,
    InsufficientVolume = 0xa9,
    CodeTooLong = 0xa4,
    AlreadyRegistered = 0xa8,
    CodeTaken = 0xa7,
}
/// Apply the complete selected logical-map behavior of 0x3c193d0.
/// `Mode` selects the recovered branch; it does not perform authorization.
pub fn apply(state: &mut State, user: Address, code: &str, quota: u64, mode: Mode) -> Status {
    if mode == Mode::Register {
        let total = state.volume_rows.get(&user).map_or(0, |rows| {
            rows.values().fold(0u64, |sum, &v| sum.saturating_add(v))
        });
        if total < 1_000_000 {
            return Status::InsufficientVolume;
        }
    }
    if code.len() > 100 {
        return Status::CodeTooLong;
    }
    if mode == Mode::Register && state.referrers.contains_key(&user) {
        return Status::AlreadyRegistered;
    }
    if let Some(record) = state.referrers.get_mut(&user) {
        if state.codes.get(code).is_some_and(|owner| *owner != user) {
            return Status::CodeTaken;
        }
        state.codes.remove(&record.code);
        state.codes.insert(code.into(), user);
        record.code = code.into();
        record.configured_quota = quota;
        record.bucket = 0;
        // History and remaining quota are deliberately preserved.
    } else {
        if state.codes.contains_key(code) {
            return Status::CodeTaken;
        }
        state.referrers.insert(
            user,
            Referrer {
                code: code.into(),
                history: BTreeMap::new(),
                remaining: 0,
                bucket: 0,
                configured_quota: quota,
            },
        );
        state.codes.insert(code.into(), user);
    }
    Status::Accepted
}
/// Status/tag projection of the normal registration wrapper 0x285c730.
/// Error allocation, borrowed payloads and native result layout are excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationReply {
    pub tag: u8,
    pub error: Option<u16>,
}
pub fn register(state: &mut State, user: Address, code: &str) -> RegistrationReply {
    if code.len() > 100 {
        return RegistrationReply {
            tag: 0x0f,
            error: Some(0x158),
        };
    }
    let status = apply(state, user, code, 0, Mode::Register);
    if status == Status::Accepted {
        RegistrationReply {
            tag: 0x0e,
            error: None,
        }
    } else {
        RegistrationReply {
            tag: 0x0f,
            error: Some(status as u16),
        }
    }
}
