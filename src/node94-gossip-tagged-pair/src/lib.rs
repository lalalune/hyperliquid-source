//! Logical normal-return reconstruction of node94 0x466c770..0x466c8ae.
//! Names and safe types are chosen; original type/ABI and inactive bytes are open.
#![forbid(unsafe_code)]

use hl_bincode_varint::{DecodeError, PayloadOrder, ReaderError};

const _: () = assert!(usize::BITS == 64);

/// Exact observed error literal, not proof of recovered source type identity.
pub const OBSERVED_TYPE_NAME: &str = "core::option::Option<node::gossip_rpc::GossipStatus>";
/// Derived from the actual selector comparisons, not an inferred context layout.
pub const ALLOWED_SELECTORS: &[u8] = &[0, 1];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    pub mode_word: u64,
    pub counter: u64,
    pub limit: u64,
}

/// Ordered production counter assignments: selector, first scalar, second scalar.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CounterStores {
    values: [u64; 3],
    len: u8,
}

impl CounterStores {
    pub fn as_slice(&self) -> &[u64] {
        &self.values[..usize::from(self.len)]
    }

    fn assign(&mut self, budget: &mut Budget, value: u64) {
        budget.counter = value;
        self.values[usize::from(self.len)] = value;
        self.len += 1;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarFault {
    Budget,
    Need { additional: usize },
    Type { expected: u8, found: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    Selector(ScalarFault),
    First(ScalarFault),
    Second(ScalarFault),
    InvalidSelector { found: u8 },
}

impl Failure {
    pub fn observed_type_name(&self) -> Option<&'static str> {
        matches!(self, Self::InvalidSelector { .. }).then_some(OBSERVED_TYPE_NAME)
    }

    pub fn allowed_selectors(&self) -> Option<&'static [u8]> {
        matches!(self, Self::InvalidSelector { .. }).then_some(ALLOWED_SELECTORS)
    }
}

/// Observed branch and unsigned payload fields, with no original field labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decoded {
    TagZero,
    TagOne { first: u64, second: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub result: Result<Decoded, Failure>,
    pub counter_stores: CounterStores,
}

fn charge(budget: &mut Budget, stores: &mut CounterStores, amount: u64) -> Result<(), ScalarFault> {
    if budget.mode_word as u32 == 1 {
        let Some(next) = budget.counter.checked_add(amount) else {
            return Err(ScalarFault::Budget);
        };
        stores.assign(budget, next);
        if next > budget.limit {
            return Err(ScalarFault::Budget);
        }
    }
    Ok(())
}

// Private composition of the credited wrapper theorem and genuine accepted
// decoder dependency. No copied PR1365 API/source or new wrapper recovery.
fn scalar(input: &mut &[u8], budget: &mut Budget, stores: &mut CounterStores) -> Result<u64, ScalarFault> {
    charge(budget, stores, 8)?;
    if input.len() > 8 {
        match hl_bincode_varint::decode_u64_slice_fast(input) {
            Ok(decoded) => {
                *input = &input[decoded.consumed..];
                Ok(decoded.value)
            }
            Err(DecodeError::RejectedMarker { marker }) => {
                let found = match marker {
                    0xfe => 4,
                    0xff => 12,
                    _ => unreachable!("accepted decoder rejects only FE/FF"),
                };
                Err(ScalarFault::Type { expected: 2, found })
            }
            Err(DecodeError::FastPathUnavailable { .. }) => {
                unreachable!("accepted fast decoder receives at least9 bytes")
            }
        }
    } else {
        hl_bincode_varint::read_u64(input, PayloadOrder::Little).map_err(|error| match error {
            ReaderError::UnexpectedEnd { needed } => ScalarFault::Need { additional: needed },
            ReaderError::InvalidIntegerType { expected_code, found_code } => {
                ScalarFault::Type { expected: expected_code, found: found_code }
            }
        })
    }
}

fn decode(input: &mut &[u8], budget: &mut Budget, stores: &mut CounterStores) -> Result<Decoded, Failure> {
    charge(budget, stores, 1).map_err(Failure::Selector)?;
    let before_selector = *input;
    let Some((&selector, rest)) = before_selector.split_first() else {
        return Err(Failure::Selector(ScalarFault::Need { additional: 1 }));
    };
    *input = rest;
    match selector {
        0 => Ok(Decoded::TagZero),
        1 => {
            let first = scalar(input, budget, stores).map_err(Failure::First)?;
            let second = scalar(input, budget, stores).map_err(Failure::Second)?;
            Ok(Decoded::TagOne { first, second })
        }
        found => Err(Failure::InvalidSelector { found }),
    }
}

/// Decode one selector and, only on selector1, two sequential little-endian u64s.
///
/// Fixed counter costs are1/8/8 rather than encoded widths. Prior stores and
/// cursor movement survive errors; a failed first scalar prevents the second
/// call, and a failed second scalar does not publish a partial successful value.
/// Inactive native output words and copied padding are deliberately unrepresented.
pub fn decode_tagged_pair(input: &mut &[u8], budget: &mut Budget) -> Outcome {
    let mut stores = CounterStores::default();
    let result = decode(input, budget, &mut stores);
    Outcome { result, counter_stores: stores }
}
