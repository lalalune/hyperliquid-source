#![no_std]
//! Private node115 free-entry prefix, ending before an opaque lookup call.
//! These safe logical names are analysis labels, not original source types.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupLane {
    A,
    B,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frontier {
    Returned2,
    PrimaryGuard {
        index: u64,
        length: u64,
    },
    SecondaryGuard {
        index: u64,
        length: u64,
    },
    Lookup {
        lane: LookupLane,
        primary: u64,
        secondary: u64,
        auxiliary: u64,
        float_bits: u64,
    },
}

/// The indices belong to the selected primary row. Map words remain raw
/// premises; no original container validity or helper behavior is assigned.
pub struct Inputs<'a> {
    pub primary: u64,
    pub primary_len: u64,
    pub indices: &'a [u64],
    pub occupied: &'a [u64],
    pub header: u64,
    pub map_len: u64,
    pub auxiliary: u64,
    pub float_bits: u64,
}

/// None is our finite qualification-domain refusal, not a native error.
/// Lookup/guards stop before actual calls. Only Returned2 denotes a native
/// return; no lookup result, later counter or floating arithmetic is modeled.
pub fn prefix(input: Inputs<'_>) -> Option<Frontier> {
    if input.primary_len > 16 || input.indices.len() > 32 || input.occupied.len() > 16 {
        return None;
    }
    if input.primary == 0 {
        return Some(Frontier::Returned2);
    }
    if input.primary >= input.primary_len {
        return Some(Frontier::PrimaryGuard {
            index: input.primary,
            length: input.primary_len,
        });
    }
    for &secondary in input.indices {
        if secondary >= input.occupied.len() as u64 {
            return Some(Frontier::SecondaryGuard {
                index: secondary,
                length: input.occupied.len() as u64,
            });
        }
        if input.occupied[secondary as usize] == 0 {
            if input.header == 0x8000_0000_0000_0000 && input.map_len == 0 {
                return Some(Frontier::Returned2);
            }
            let lane = if input.header == 0x8000_0000_0000_0000 {
                LookupLane::A
            } else {
                LookupLane::B
            };
            return Some(Frontier::Lookup {
                lane,
                primary: input.primary,
                secondary,
                auxiliary: input.auxiliary,
                float_bits: input.float_bits,
            });
        }
    }
    Some(Frontier::Returned2)
}
