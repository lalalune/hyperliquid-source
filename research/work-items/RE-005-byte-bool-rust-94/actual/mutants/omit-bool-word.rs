//! Independently authored node #94 one-byte and boolean decoder relations.
//!
//! Scope: complete native leaves at ELF VAs 0x466bbb0..0x466bc09 and
//! 0x466be00..0x466be6c. This is a chosen safe state/result/write projection,
//! not the target's Rust type, ABI, padding, pointer or machine-code identity.

#![no_std]
#![forbid(unsafe_code)]

/// Chosen representation of the observed mode, counter and limit words.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    /// Only the literal word 1 enables charging in these native leaves.
    pub mode_word: u32,
    /// Observed unsigned counter, incremented before a nonoverflow limit test.
    pub counter: u64,
    /// Observed unsigned limit. Its semantic name is an inference.
    pub limit: u64,
}

/// Independently chosen error names; these are not recovered source variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Raw native tag 0, with the observed missing-byte word (always 1 here).
    UnexpectedEnd { needed: u64 },
    /// Raw native tag 2; no input byte has been consumed.
    BudgetExceeded {
        /// The boolean leaf also writes 1 at result offset 8; the u8 leaf
        /// does not write that word. This records the optional observed write
        /// without asserting that the original error type owns a need field.
        word8_write: Option<u64>,
    },
    /// Raw native tag 8 and the consumed byte, which was neither 0 nor 1.
    InvalidBooleanByte { found: u8 },
}

/// Decode one unsigned byte, retaining all 256 possible values.
///
/// A mode-1 budget is charged before even an empty input is inspected. Counter
/// overflow preserves the old counter; other limit failures retain the charge.
/// Budget errors preserve the slice. Empty input needs one byte and consumes
/// none; otherwise exactly one byte is consumed and its suffix is preserved.
pub fn read_u8(input: &mut &[u8], budget: &mut Budget) -> Result<u8, DecodeError> {
    charge_one(budget, None)?;
    take_one(input)
}

/// Decode only 0 as false and 1 as true; every other byte is rejected.
///
/// Budget/empty behavior follows [`read_u8`], with the boolean leaf's additional
/// word-8 write retained in a budget error. Classification happens after byte
/// consumption, so an invalid boolean leaves the complete original suffix.
pub fn read_bool(input: &mut &[u8], budget: &mut Budget) -> Result<bool, DecodeError> {
    charge_one(budget, None)?;
    match take_one(input)? {
        0 => Ok(false),
        1 => Ok(true),
        found => Err(DecodeError::InvalidBooleanByte { found }),
    }
}

fn charge_one(budget: &mut Budget, word8_write: Option<u64>) -> Result<(), DecodeError> {
    if budget.mode_word == 1 {
        let before = budget.counter;
        let Some(after) = before.checked_add(1) else {
            return Err(DecodeError::BudgetExceeded { word8_write });
        };
        budget.counter = after;
        if before >= budget.limit {
            return Err(DecodeError::BudgetExceeded { word8_write });
        }
    }
    Ok(())
}

fn take_one(input: &mut &[u8]) -> Result<u8, DecodeError> {
    let Some((&value, tail)) = input.split_first() else {
        return Err(DecodeError::UnexpectedEnd { needed: 1 });
    };
    *input = tail;
    Ok(value)
}
