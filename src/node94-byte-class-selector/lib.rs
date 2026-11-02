#![no_std]
#![forbid(unsafe_code)]
//! Full-RAX projection of node94 ELF VA 0x359be70..0x359bebe.

/// Select or transform according to the first argument's low byte.
///
/// Every u32 pair is admitted. First-derived results retain all first bits;
/// second-derived results retain its upper24 bits and either retain or rewrite
/// the low byte. The returned u64 is the complete zero-extended native RAX.
/// Native high argument bits32..63 do not affect this value. Scratch registers,
/// flags, timing, instruction/control faults and the machine ABI are unclaimed.
/// No text encoding, original source identity or data-pointer premise is inferred.
pub fn select(first: u32, second: u32) -> u64 {
    let upper = second & 0xffff_ff00;
    let value = match first as u8 {
        0xc0..=0xdf => return u64::from(first),
        1..=0x8f => upper | (second & 0x0f) | 0x80,
        0x90 => upper | (second & 0x0f) | 0x90,
        0xa0 => upper | (second & 0x1f) | 0xa0,
        _ => second,
    };
    u64::from(value)
}
