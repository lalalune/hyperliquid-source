//! Selected normal-success choice/weight MessagePack writer.
//!
//! Raw mode and choice behavior is preserved. This does not implement native
//! buffer growth, returned error objects, an action envelope or signing.
#![no_std]
#![forbid(unsafe_code)]

/// Owned output buffer for the selected two-field record; only `as_slice` is active.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Encoded {
    bytes: [u8; 32],
    len: u8,
}
impl Encoded {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Encode the selected success path. Modes 0/1 yield array/map framing;
/// other raw bytes retain observed bit and key gates without claiming validity.
pub fn encode(mode: u8, choice: u8, weight: u64) -> Encoded {
    let mut output = Encoded {
        bytes: [0; 32],
        len: 0,
    };
    fn append(out: &mut Encoded, part: &[u8]) {
        let start = usize::from(out.len);
        let end = start + part.len();
        out.bytes[start..end].copy_from_slice(part);
        out.len = end as u8;
    }
    append(&mut output, &[((mode ^ 1) << 4) | 0x82]);
    if mode != 0 {
        append(&mut output, b"\xa6choice");
    }
    let label: &[u8] = match choice {
        0 => b"\xa3yes",
        1 => b"\xa2no",
        _ => b"\xa7abstain",
    };
    append(&mut output, label);
    if mode == 1 {
        append(&mut output, b"\xa6weight");
    }
    if weight < 128 {
        append(&mut output, &[weight as u8]);
    } else if weight <= u8::MAX as u64 {
        append(&mut output, &[0xcc, weight as u8]);
    } else if weight <= u16::MAX as u64 {
        append(&mut output, &[0xcd]);
        append(&mut output, &(weight as u16).to_be_bytes());
    } else if weight <= u32::MAX as u64 {
        append(&mut output, &[0xce]);
        append(&mut output, &(weight as u32).to_be_bytes());
    } else {
        append(&mut output, &[0xcf]);
        append(&mut output, &weight.to_be_bytes());
    }
    output
}
