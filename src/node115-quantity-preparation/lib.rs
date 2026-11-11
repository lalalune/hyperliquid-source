//! Scalar preparation before an opaque node115 formatter, not a recovered ABI.
#![no_std]
#![forbid(unsafe_code)]

pub mod pdi_range;

/// Own research representation of the established coefficient/scale pair.
/// This type's Rust layout is unrelated to the captured stack layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedQuantity {
    pub coefficient: u64,
    pub scale: u8,
}

impl PreparedQuantity {
    /// Values observed at native stack offsets +0x20, +0x24, +0x28, +0x2c.
    /// This is a value projection, not a memory layout or formatter interface.
    pub fn prepared_words(self) -> [u32; 4] {
        [
            (self.scale as u32) << 16,
            0,
            self.coefficient as u32,
            (self.coefficient >> 32) as u32,
        ]
    }
}

/// Outside the sign-clear scalar cut qualified by the retained native proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedDomain;

/// Prepare an unsigned low-63-bit scalar at abstract scale eight.
///
/// Zero maps to (0,0). Other values lose at most eight trailing decimal zeros,
/// preserving coefficient / 10^scale = input / 10^8. No string is rendered.
/// Refusing sign-bit-set words is our safe API policy, not the native error
/// protocol or a production rule about negative quantities.
pub fn prepare_quantity(input: u64) -> Result<PreparedQuantity, UnsupportedDomain> {
    if input >= 1 << 63 {
        return Err(UnsupportedDomain);
    }
    if input == 0 {
        return Ok(PreparedQuantity {
            coefficient: 0,
            scale: 0,
        });
    }
    let mut coefficient = input;
    let mut scale = 8;
    while scale > 0 && coefficient.is_multiple_of(10) {
        coefficient /= 10;
        scale -= 1;
    }
    Ok(PreparedQuantity { coefficient, scale })
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{prepare_quantity, UnsupportedDomain};
    use std::vec::Vec;

    #[test]
    fn frozen_target_grounded_values_and_prepared_words() {
        let mut count = 0;
        for line in include_str!("target-vectors.tsv").lines() {
            let fields: Vec<u64> = line.split('\t').map(|s| s.parse().unwrap()).collect();
            assert_eq!(fields.len(), 7);
            let prepared = prepare_quantity(fields[0]).unwrap();
            assert_eq!(
                (prepared.coefficient, prepared.scale as u64),
                (fields[1], fields[2]),
                "scalar {}",
                fields[0]
            );
            let words = prepared.prepared_words();
            for i in 0..4 {
                assert_eq!(
                    words[i] as u64,
                    fields[i + 3],
                    "input {} word {i}",
                    fields[0]
                );
            }
            count += 1;
        }
        assert_eq!(count, 2540);
    }

    #[test]
    fn own_api_refuses_words_outside_the_qualified_native_cut() {
        for input in [1 << 63, (1 << 63) + 1, u64::MAX] {
            assert_eq!(prepare_quantity(input), Err(UnsupportedDomain));
        }
    }
}
