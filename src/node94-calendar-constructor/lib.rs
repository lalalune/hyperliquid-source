#![no_std]
#![forbid(unsafe_code)]
//! All-input return-value projection of node94 [0x151f6f0, 0x151f86a).

/// Selected full-width values at normal return, not a recovered native ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    /// PUSH RAX on entry and POP RCX on return preserve incoming RAX here.
    pub rcx: u64,
}

fn leap_prefix(year: u32) -> u32 {
    (year + 3) / 4 - (year + 99) / 100 + (year + 399) / 400
}

/// Convert the signed low32 of incoming RDI into the target's packed-date bits.
///
/// All inputs are admitted. RAX zero is the original routine's out-of-range
/// result, not a new safe-API refusal. Input high32 is ignored. The supplied
/// incoming RAX becomes the returned RCX. Other scratch registers, flags,
/// original pointers, physical stack, ABI and faults are outside this API.
pub fn construct(input: u64, entry_rax: u64) -> Registers {
    let mut result = Registers {
        rax: 0,
        rcx: entry_rax,
    };
    let day = input as u32 as i32;
    let Some(shifted) = day.checked_add(365) else {
        return result;
    };
    let cycle = i64::from(shifted).div_euclid(146_097);
    let remainder = i64::from(shifted).rem_euclid(146_097) as u32;
    let mut year_in_cycle = remainder / 365;
    let residual = remainder % 365;
    if residual < leap_prefix(year_in_cycle) {
        year_in_cycle -= 1;
    }
    let ordinal = remainder - 365 * year_in_cycle - leap_prefix(year_in_cycle) + 1;
    let year = cycle * 400 + i64::from(year_in_cycle);
    if !(-262_143..=262_142).contains(&year) {
        return result;
    }
    let leap = leap_prefix(year_in_cycle + 1) > leap_prefix(year_in_cycle);
    let weekday = 1 + (365 * year_in_cycle + leap_prefix(year_in_cycle) + 3) % 7;
    let flags = weekday | if leap { 0 } else { 8 };
    let packed = ((year as u32) << 13) | (ordinal << 4) | flags;
    result.rax = u64::from(packed);
    result
}
