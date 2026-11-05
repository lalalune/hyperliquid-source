#![no_std]
#![forbid(unsafe_code)]
//! Active-field projection of node115 0x46a6860, not an owning/native ABI.
#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    Returned,
    FirstDiagnostic,
    InnerDiagnostic,
    LastDiagnostic,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Observation {
    pub exit: Exit,
    /// None explicitly excludes inactive payload; it is never a zero byte.
    pub output: [Option<u8>; 120],
}
fn word(raw: &[u8; 120], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}
fn put(output: &mut [Option<u8>; 120], at: usize, value: u64) {
    copy(output, at, &value.to_le_bytes());
}
fn copy(output: &mut [Option<u8>; 120], at: usize, bytes: &[u8]) {
    for (slot, byte) in output[at..at + bytes.len()].iter_mut().zip(bytes) {
        *slot = Some(*byte);
    }
}
fn failure(exit: Exit, seed: u8) -> Observation {
    Observation {
        exit,
        output: [Some(seed); 120],
    }
}
/// Checked multiplication order is observable at actual pre-call frontiers.
/// Raw variants are not asserted to be valid original enum/container states.
pub fn scale(raw: &[u8; 120], seed: u8) -> Observation {
    let Some(first) = word(raw, 0x60).checked_mul(100) else {
        return failure(Exit::FirstDiagnostic, seed);
    };
    let Some(second) = word(raw, 0x68).checked_mul(100) else {
        return failure(Exit::FirstDiagnostic, seed);
    };
    let outer = word(raw, 0) == 1;
    let outer_value = if outer {
        let Some(value) = word(raw, 8).checked_mul(100) else {
            return failure(Exit::FirstDiagnostic, seed);
        };
        Some(value)
    } else {
        None
    };
    let inner = word(raw, 0x28) != 0x8000_0000_0000_0000;
    let inner_value = if inner {
        let Some(value) = word(raw, 0x40).checked_mul(100) else {
            return failure(Exit::InnerDiagnostic, seed);
        };
        Some(value)
    } else {
        None
    };
    let Some(last) = word(raw, 0x70).checked_mul(100) else {
        return failure(Exit::LastDiagnostic, seed);
    };
    let mut output = [Some(seed); 120];
    put(&mut output, 0, u64::from(outer));
    if let Some(value) = outer_value {
        put(&mut output, 8, value);
        copy(&mut output, 0x10, &raw[0x10..0x24]);
    } else {
        output[8..36].fill(None);
    }
    copy(&mut output, 0x28, &raw[0x28..0x38]);
    if let Some(value) = inner_value {
        copy(&mut output, 0x38, &raw[0x38..0x40]);
        put(&mut output, 0x40, value);
        copy(&mut output, 0x48, &raw[0x48..0x5c]);
    } else {
        output[56..92].fill(None);
    }
    put(&mut output, 0x60, first);
    put(&mut output, 0x68, second);
    put(&mut output, 0x70, last);
    Observation {
        exit: Exit::Returned,
        output,
    }
}
