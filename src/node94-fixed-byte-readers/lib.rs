//! The complete node94 fixed20/fixed32 reader projection, with an own safe API.
//! Result storage must be initialized; unassigned bytes preserve that storage.
//! This is not the original reader/result ABI or an address/hash type claim.
#![no_std]
#![forbid(unsafe_code)]

/// Logical routes, independent of native result discriminants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Value,
    End { additional: u64 },
    Charge,
}

fn charge_permitted(mode: u32, limit: u64, charged: &mut u64, width: u64) -> bool {
    if mode != 1 {
        return true;
    }
    let Some(next) = (*charged).checked_add(width) else {
        return false;
    };
    *charged = next;
    next <= limit
}

/// Read twenty bytes, preserving the native 21-byte initialized write window.
/// Enabled charges survive limit/shortage errors; errors preserve the slice.
pub fn read_20(
    input: &mut &[u8],
    mode: u32,
    limit: u64,
    charged: &mut u64,
    output: &mut [u8; 21],
) -> Outcome {
    if !charge_permitted(mode, limit, charged, 20) {
        output[0] = 2;
        return Outcome::Charge;
    }
    if input.len() < 20 {
        let additional = (20 - input.len()) as u64;
        output[0] = 0;
        output[8..16].copy_from_slice(&additional.to_le_bytes());
        return Outcome::End { additional };
    }
    output[1..21].copy_from_slice(&input[..20]);
    output[0] = 18;
    *input = &input[20..];
    Outcome::Value
}

/// Read thirty-two bytes, preserving its distinct 33-byte result write window.
/// Success has leading byte0; errors have leading byte1 and a code at+8.
pub fn read_32(
    input: &mut &[u8],
    mode: u32,
    limit: u64,
    charged: &mut u64,
    output: &mut [u8; 33],
) -> Outcome {
    if !charge_permitted(mode, limit, charged, 32) {
        output[0] = 1;
        output[8] = 2;
        return Outcome::Charge;
    }
    if input.len() < 32 {
        let additional = (32 - input.len()) as u64;
        output[0] = 1;
        output[8] = 0;
        output[16..24].copy_from_slice(&additional.to_le_bytes());
        return Outcome::End { additional };
    }
    output[1..33].copy_from_slice(&input[..32]);
    output[0] = 0;
    *input = &input[32..];
    Outcome::Value
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{format, string::String, vec::Vec};

    fn bytes(text: &str) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0);
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i+2], 16).unwrap()).collect()
    }

    fn hex(raw: &[u8]) -> String {
        raw.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn twenty_frozen_stimuli_fifty_observations() {
        let mut stimuli = 0;
        let mut observations = 0;
        for line in include_str!("unit-vectors.tsv").lines() {
            let fields: Vec<_> = line.split('|').collect();
            assert_eq!(fields.len(), 9);
            let width: usize = fields[1].parse().unwrap();
            let mode: u32 = fields[2].parse().unwrap();
            let limit = u64::from_str_radix(fields[3], 16).unwrap();
            let mut charged = u64::from_str_radix(fields[4], 16).unwrap();
            let wire = bytes(fields[5]);
            let mut input = wire.as_slice();
            let mut output = bytes(fields[6]);
            let expected: Vec<_> = fields[8].split(';').collect();
            assert_eq!(fields[7].parse::<usize>().unwrap(), expected.len());
            for row in expected {
                let wanted: Vec<_> = row.split(',').collect();
                assert_eq!(wanted.len(), 8);
                let before = input.len();
                let outcome = match width {
                    20 => read_20(&mut input, mode, limit, &mut charged,
                                  output.as_mut_slice().try_into().unwrap()),
                    32 => read_32(&mut input, mode, limit, &mut charged,
                                  output.as_mut_slice().try_into().unwrap()),
                    _ => panic!("unsupported fixed width"),
                };
                let (kind, additional) = match outcome {
                    Outcome::Value => ("value", String::from("-")),
                    Outcome::End { additional } => ("end", format!("{additional}")),
                    Outcome::Charge => ("charge", String::from("-")),
                };
                assert_eq!(kind, wanted[0], "{}", fields[0]);
                assert_eq!(additional, wanted[1], "{}", fields[0]);
                assert_eq!(charged, wanted[2].parse::<u64>().unwrap(), "{}", fields[0]);
                assert_eq!(before-input.len(), wanted[3].parse::<usize>().unwrap());
                assert_eq!(wire.len()-input.len(), wanted[4].parse::<usize>().unwrap());
                assert_eq!(input.len(), wanted[5].parse::<usize>().unwrap());
                assert_eq!(hex(&output), wanted[6], "{}", fields[0]);
                assert_eq!(hex(input), wanted[7], "{}", fields[0]);
                observations += 1;
            }
            stimuli += 1;
        }
        assert_eq!((stimuli, observations), (20, 50));
    }
}
