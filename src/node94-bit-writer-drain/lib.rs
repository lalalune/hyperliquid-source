#![no_std]
#![forbid(unsafe_code)]

//! Value and checked-slice reconstruction of node #94 VA 0x5494050.
//! See README.md and the evidence packet for the disjoint, stable memory domain.
//! This is not the original pointer ABI or a recovered source-level return type.

/// Relevant field values; no native layout is claimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct State {
    pub counter: i32,
    pub accumulator: u16,
    pub position: u64,
}

/// Complete value projection. Only the first `emitted_len` bytes are emitted.
/// Remaining entries are zero. `rax` is the observed native register value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transition {
    pub emitted: [u8; 2],
    pub emitted_len: u8,
    pub next: State,
    pub rax: u64,
}

/// Project stable, disjoint state for every i32/u16/u64 input.
/// Position arithmetic wraps at 64 bits; no memory access is performed.
#[must_use]
pub const fn project(state: State) -> Transition {
    if state.counter == 16 {
        Transition {
            emitted: state.accumulator.to_le_bytes(),
            emitted_len: 2,
            next: State {
                counter: 0,
                accumulator: 0,
                position: state.position.wrapping_add(2),
            },
            rax: 0,
        }
    } else if state.counter <= 7 {
        Transition {
            emitted: [0; 2],
            emitted_len: 0,
            next: state,
            rax: state.counter as u32 as u64,
        }
    } else {
        Transition {
            emitted: [state.accumulator as u8, 0],
            emitted_len: 1,
            next: State {
                counter: state.counter.wrapping_sub(8),
                accumulator: state.accumulator >> 8,
                position: state.position.wrapping_add(1),
            },
            rax: state.position,
        }
    }
}

/// The emitted interval cannot be indexed within the supplied output slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputTooSmall;

/// Apply the projection to disjoint state/output. Returns the observed RAX.
///
/// A no-output transition succeeds for any position. Otherwise all conversion,
/// overflow and capacity checks precede writes. An error leaves both arguments
/// unchanged. This refusal policy is additional to the native routine.
pub fn drain(state: &mut State, output: &mut [u8]) -> Result<u64, OutputTooSmall> {
    let transition = project(*state);
    if transition.emitted_len == 0 {
        return Ok(transition.rax);
    }
    let start = usize::try_from(state.position).map_err(|_| OutputTooSmall)?;
    let count = usize::from(transition.emitted_len);
    let end = start.checked_add(count).ok_or(OutputTooSmall)?;
    let destination = output.get_mut(start..end).ok_or(OutputTooSmall)?;
    destination.copy_from_slice(&transition.emitted[..count]);
    *state = transition.next;
    Ok(transition.rax)
}
