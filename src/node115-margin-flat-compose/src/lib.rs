#![no_std]
//! Selected valid-flat node115 margin range and arithmetic composition.
//! The API does not recover the original ABI, financial units or risk policy.
use core::num::NonZeroU8;
use node115_margin_range::{InvalidView, Ring, Row};
pub use node115_margin_row_adapter::Observation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    First,
    Second,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Local view validation, not a native returned error.
    InvalidView(InvalidView),
    /// Native selected empty-range route reaches an opaque diagnostic.
    NoSelectedRow,
    /// Local refusal before native division, not a native error tag.
    ZeroDivisor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub logical_index: usize,
    pub physical_index: usize,
    pub key: u64,
    pub arithmetic: Observation,
}

/// Select the final row whose unsigned key is <= `amount`, then apply one of
/// the existing selected-row arithmetic contracts. Native correspondence is
/// conditional on valid stable flat storage and normal helper returns.
pub fn evaluate(
    rows: &[Row],
    head: usize,
    live: usize,
    amount: u64,
    mode: Mode,
) -> Result<Outcome, Refusal> {
    let ring = Ring::new(rows, head, live).map_err(Refusal::InvalidView)?;
    let selected = ring
        .through(amount)
        .selected
        .ok_or(Refusal::NoSelectedRow)?;
    let divisor = NonZeroU8::new(selected.divisor).ok_or(Refusal::ZeroDivisor)?;
    let arithmetic = match mode {
        Mode::First => {
            node115_margin_row_adapter::first_selected_row(amount, divisor, selected.offset)
        }
        Mode::Second => {
            node115_margin_row_adapter::second_selected_row(amount, divisor, selected.offset)
        }
    };
    Ok(Outcome {
        logical_index: selected.logical_index,
        physical_index: selected.physical_index,
        key: selected.key,
        arithmetic,
    })
}
