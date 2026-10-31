//! Safe, allocation-free implementation of the observed node94 reader contract.
//!
//! The cursor and result types are a new Rust interface, not the target ABI.
//! Evidence binds to node94 FDEs 0x466dad0, 0x466be70 and 0x466dac0.
//! The kind byte 5 remains opaque; this does not identify a source Rust type.
#![no_std]
#![forbid(unsafe_code)]

/// Observed outcomes. These Rust discriminants are not target discriminants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Value(u64),
    Missing(u64),
    Tag254,
    Tag255,
    Charge,
}

impl Outcome {
    /// Apply only the writes observed in the packet's 24-byte output window.
    /// Padding and inactive fields retain the caller's original bytes.
    pub fn write_observed(self, output: &mut [u8; 24]) {
        match self {
            Self::Value(value) | Self::Missing(value) => {
                output[0] = if matches!(self, Self::Value(_)) {
                    18
                } else {
                    0
                };
                output[8..16].copy_from_slice(&value.to_le_bytes());
            }
            Self::Tag254 | Self::Tag255 => {
                output[..3].copy_from_slice(&[3, 5, if self == Self::Tag254 { 4 } else { 12 }]);
            }
            Self::Charge => output[0] = 2,
        }
    }
}

/// A slice-backed interface to the observed pointer/remaining cursor.
#[derive(Debug)]
pub struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    /// Read the kind-5 path. Every nonzero endian byte selects swapped payloads.
    /// A present marker is consumed even when the payload is short or rejected.
    pub fn read(&mut self, endian: u8) -> Outcome {
        if self.remaining() == 0 {
            return Outcome::Missing(1);
        }
        let marker = self.input[self.position];
        self.position += 1;
        let width = match marker {
            0..=250 => return Outcome::Value(u64::from(marker)),
            251 => 2,
            252 => 4,
            253 => 8,
            254 => return Outcome::Tag254,
            255 => return Outcome::Tag255,
        };
        if self.remaining() < width {
            return Outcome::Missing((width - self.remaining()) as u64);
        }
        let payload = &self.input[self.position..self.position + width];
        let mut value = 0_u64;
        for i in 0..width {
            let at = if endian == 0 { i } else { width - 1 - i };
            value |= u64::from(payload[at]) << (8 * i);
        }
        self.position += width;
        Outcome::Value(value)
    }

    /// The observed fixed-eight-charge wrapper, including its distinct fast path.
    /// Selector words other than exactly one bypass the charge gate. Those raw
    /// machine-state controls are not a claim about valid source enum values.
    pub fn read_charged(&mut self, state: &mut ChargeState) -> Outcome {
        if state.selector == 1 {
            let Some(next) = state.charged.checked_add(8) else {
                return Outcome::Charge;
            };
            state.charged = next;
            if next > state.limit {
                return Outcome::Charge;
            }
        }
        if self.remaining() > 8 {
            match self.input[self.position] {
                254 => return Outcome::Tag254,
                255 => return Outcome::Tag255,
                _ => {}
            }
        }
        // Both wrapper paths are little-endian, irrespective of an incoming dl.
        self.read(0)
    }
}

/// Fields observed at wrapper state offsets 0, 8 and 32, exposed without ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChargeState {
    pub selector: u32,
    pub limit: u64,
    pub charged: u64,
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
