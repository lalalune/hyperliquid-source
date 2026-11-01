//! Safe value projection of node94 ELF VA [0x55c9800, 0x55c9830).
//! The supplied word is a value snapshot, not an emulated pointer or load.
#![no_std]
#![forbid(unsafe_code)]

/// Reasons this new safe API refuses to specify a value.
/// These are not error returns observed in the original machine code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The main path needs a word snapshot, but none was supplied.
    MissingWord,
    /// The main path would run BSR on zero after the u32 increment.
    UndefinedBitScan,
}

/// Project the original low-u32 numeric inputs without dereferencing memory.
///
/// Exactly `flag == 1` bypasses the word and returns 0 or 256 according to
/// whether `refinement` is zero. This includes an absent or MAX word.
/// Otherwise a supplied word is required, and MAX is excluded because its
/// increment wraps to zero before BSR. Both shifts and subtraction retain
/// the target's unsigned 32-bit widths. Argument meanings remain unknown.
pub fn normalize(
    word: Option<u32>,
    value: u32,
    flag: u32,
    refinement: u32,
) -> Result<u32, Refusal> {
    if flag == 1 {
        return Ok(if refinement != 0 { 256 } else { 0 });
    }
    let word = word.ok_or(Refusal::MissingWord)?;
    let incremented = word.wrapping_add(1);
    if incremented == 0 {
        return Err(Refusal::UndefinedBitScan);
    }
    let rank = 31 - incremented.leading_zeros();
    let mut base = rank << 8;
    if refinement != 0 {
        base = base.wrapping_add(incremented.wrapping_shl(8) >> rank);
    }
    Ok(value.wrapping_sub(base))
}
