//! Successful five-field record encoding at node115 0x2bc06a0.
//!
//! Uses the existing validated date/time domain. Native growth failures,
//! partial writes, arbitrary invalid enum bytes and the enclosing DEX variant
//! are outside this owned byte encoding.
#![no_std]
#![forbid(unsafe_code)]

pub use node115_date_time_display::{Date, Time};
use node115_date_time_display::{render_date, render_time};

#[derive(Clone, Copy, Debug)]
pub struct Timestamp {
    pub date: Date,
    pub time: Time,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Array,
    Map,
}

/// The four observed tags, in native table order. `M` is only a wire label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisabledState {
    Na,
    UserDisabled,
    ValidatorDisabled,
    M,
}

#[derive(Clone, Copy, Debug)]
pub struct Record {
    pub last_settlement_time: Timestamp,
    pub deploy_time: Timestamp,
    pub n_reserve_deployments_used: u64,
    pub disabled_state: DisabledState,
    pub m: bool,
}

/// The supported record is at most 174 bytes, including keys and framing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Encoded {
    bytes: [u8; 192],
    len: usize,
}

impl Encoded {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn append(&mut self, bytes: &[u8]) {
        let end = self.len + bytes.len();
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }

    fn string(&mut self, bytes: &[u8]) {
        // All fields are fixed labels or a validated timestamp (at most 32).
        if bytes.len() < 32 {
            self.append(&[0xa0 | bytes.len() as u8]);
        } else {
            self.append(&[0xd9, bytes.len() as u8]);
        }
        self.append(bytes);
    }

    fn timestamp(&mut self, value: Timestamp) {
        let date = render_date(value.date);
        let time = render_time(value.time);
        let mut bytes = [0; 32];
        let d = date.as_bytes();
        let t = time.as_bytes();
        bytes[..d.len()].copy_from_slice(d);
        bytes[d.len()] = b'T';
        bytes[d.len() + 1..d.len() + 1 + t.len()].copy_from_slice(t);
        self.string(&bytes[..d.len() + 1 + t.len()]);
    }

    fn unsigned(&mut self, value: u64) {
        if value < 128 {
            self.append(&[value as u8]);
        } else if let Ok(v) = u8::try_from(value) {
            self.append(&[0xcc, v]);
        } else if let Ok(v) = u16::try_from(value) {
            self.append(&[0xcd]);
            self.append(&v.to_be_bytes());
        } else if let Ok(v) = u32::try_from(value) {
            self.append(&[0xce]);
            self.append(&v.to_be_bytes());
        } else {
            self.append(&[0xcf]);
            self.append(&value.to_be_bytes());
        }
    }
}

/// Encode the complete selected record, with stable fields and mode 0 or 1.
pub fn encode(record: Record, mode: Mode) -> Encoded {
    let mut out = Encoded {
        bytes: [0; 192],
        len: 0,
    };
    let map = mode == Mode::Map;
    out.append(&[if map { 0x85 } else { 0x95 }]);
    if map {
        out.string(b"last_settlement_time");
    }
    out.timestamp(record.last_settlement_time);
    if map {
        out.string(b"deploy_time");
    }
    out.timestamp(record.deploy_time);
    if map {
        out.string(b"n_reserve_deployments_used");
    }
    out.unsigned(record.n_reserve_deployments_used);
    if map {
        out.string(b"disabled_state");
    }
    out.string(match record.disabled_state {
        DisabledState::Na => b"Na",
        DisabledState::UserDisabled => b"UserDisabled",
        DisabledState::ValidatorDisabled => b"ValidatorDisabled",
        DisabledState::M => b"m",
    });
    if map {
        out.string(b"m");
    }
    out.append(&[if record.m { 0xc3 } else { 0xc2 }]);
    out
}
