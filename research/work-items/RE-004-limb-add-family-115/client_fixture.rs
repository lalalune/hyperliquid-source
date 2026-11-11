// Input-only measurement adapter. Synthetic byte layout is not Rust's ABI.
use crate::{add_with_carry, guarded_add};
use std::fmt::Write;
use std::string::{String, ToString};
use std::vec::Vec;

pub fn observe(mode: usize, count: usize, left: [u64; 4], right: [u64; 4]) -> String {
    assert!(mode <= 2 && count <= 8);
    let mut descriptor = [0xa5; 64];
    descriptor[0x28..0x30].copy_from_slice(&0x71001000u64.to_le_bytes());
    descriptor[0x30..0x38].copy_from_slice(&(count as u64).to_le_bytes());
    let mut entries = [[0u64; 4]; 8];
    for (i, entry) in entries.iter_mut().enumerate() {
        for (j, limb) in entry.iter_mut().enumerate() {
            *limb = ((i as u64 + 1) * 0x1020304050607).wrapping_add(j as u64);
        }
    }
    let mut output = [0xa5; 64];
    if mode == 0 && count >= 2 {
        entries[count - 2] = left;
        entries[count - 1] = right;
    } else {
        entries[0] = left;
    }
    let status = if mode == 0 {
        let observation = guarded_add(&mut entries, count).expect("qualified fixture count");
        descriptor[0x30..0x38].copy_from_slice(&(observation.count as u64).to_le_bytes());
        observation.status.to_string()
    } else {
        let observation = add_with_carry(&mut entries[0], right);
        for (j, value) in observation.words.iter().enumerate() {
            output[j * 8..j * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        output[32] = observation.carry;
        String::from("-")
    };
    let mut bytes = Vec::with_capacity(424);
    bytes.extend_from_slice(&descriptor);
    for entry in entries {
        for limb in entry {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }
    for limb in right {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    bytes.extend_from_slice(&output);
    bytes.extend_from_slice(&0x60000000u64.to_le_bytes());
    assert_eq!(bytes.len(), 424);
    let mut text = status;
    text.push(':');
    for byte in bytes {
        write!(text, "{byte:02x}").unwrap();
    }
    text
}
