#![no_std]
//! Safe logical projection of the Node 115 checked 32-byte read at 0x5821430.
//! This is not the original ABI, a decoder, or a whole-node implementation.

/// State fields observed by the selected leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderState {
    /// The native branch checks whether this low 32-bit mode equals 1.
    pub mode: u32,
    /// Abstract offset of the current input pointer.
    pub pointer_offset: u64,
    /// Number of readable bytes remaining at that pointer.
    pub remaining: u64,
    /// Mode-1 byte counter.
    pub count: u64,
    /// Mode-1 counter limit.
    pub limit: u64,
}

/// Only output fields written by the native leaf are represented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadOutcome {
    pub state: ReaderState,
    /// Native output tag: 0 for success, 1 for either error route.
    pub tag: u8,
    /// Error byte at output +8; untouched on success.
    pub error_code: Option<u8>,
    /// Missing-byte count written at output +0x10 on a short-input return.
    pub additional: Option<u64>,
    /// The 32 bytes copied to output +1 on success.
    pub value: Option<[u8; 32]>,
}

/// Project the observed fixed-width read.
///
/// `readable` is the first 32 bytes at the state's current input pointer. The
/// bytes are ignored on the short-input and error routes. As in the evidence
/// packet, invalid pointers, aliasing, and faults are outside this model.
pub fn read32(mut state: ReaderState, readable: &[u8; 32]) -> ReadOutcome {
    if state.mode == 1 {
        let Some(next) = state.count.checked_add(32) else {
            return error(state, 2);
        };
        // The native function commits this update before checking the limit.
        state.count = next;
        if next > state.limit {
            return error(state, 2);
        }
    }

    if state.remaining < 32 {
        return ReadOutcome {
            state,
            tag: 1,
            error_code: Some(0),
            additional: Some(32 - state.remaining),
            value: None,
        };
    }

    let mut value = [0; 32];
    value.copy_from_slice(readable);
    state.pointer_offset = state.pointer_offset.wrapping_add(32);
    state.remaining -= 32;
    ReadOutcome {
        state,
        tag: 0,
        error_code: None,
        additional: None,
        value: Some(value),
    }
}

fn error(state: ReaderState, code: u8) -> ReadOutcome {
    ReadOutcome {
        state,
        tag: 1,
        error_code: Some(code),
        additional: None,
        value: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(
        mode: u32,
        pointer_offset: u64,
        remaining: u64,
        count: u64,
        limit: u64,
    ) -> ReaderState {
        ReaderState {
            mode,
            pointer_offset,
            remaining,
            count,
            limit,
        }
    }

    fn bytes() -> [u8; 32] {
        core::array::from_fn(|i| i as u8)
    }

    #[test]
    fn mode_one_counter_overflow_returns_before_mutating_state() {
        let initial = state(1, 4, 32, u64::MAX - 31, u64::MAX);
        let result = read32(initial, &bytes());
        assert_eq!(result.state, initial);
        assert_eq!((result.tag, result.error_code), (1, Some(2)));
        assert_eq!(result.additional, None);
    }

    #[test]
    fn mode_one_limit_error_retains_incremented_counter() {
        let result = read32(state(1, 4, 32, 10, 41), &bytes());
        assert_eq!(result.state.count, 42);
        assert_eq!((result.tag, result.error_code), (1, Some(2)));
        assert_eq!(result.state.pointer_offset, 4);
    }

    #[test]
    fn mode_one_checks_counter_before_short_input() {
        let result = read32(state(1, 0, 7, 1, 33), &[0; 32]);
        assert_eq!(result.state.count, 33);
        assert_eq!((result.tag, result.error_code), (1, Some(0)));
        assert_eq!(result.additional, Some(25));
    }

    #[test]
    fn mode_zero_short_read_reports_missing_bytes_without_counting() {
        let initial = state(0, 8, 0, 99, 0);
        let result = read32(initial, &[0; 32]);
        assert_eq!(result.state, initial);
        assert_eq!((result.tag, result.error_code), (1, Some(0)));
        assert_eq!(result.additional, Some(32));
    }

    #[test]
    fn non_one_modes_skip_the_counter_gate() {
        let result = read32(state(2, 8, 32, u64::MAX, 0), &bytes());
        assert_eq!(result.tag, 0);
        assert_eq!(result.state.count, u64::MAX);
        assert_eq!(result.state.pointer_offset, 40);
    }

    #[test]
    fn successful_read_advances_state_and_copies_exactly_32_bytes() {
        let input = bytes();
        let result = read32(state(1, 100, 64, 5, 37), &input);
        assert_eq!(result.state, state(1, 132, 32, 37, 37));
        assert_eq!(result.tag, 0);
        assert_eq!(result.error_code, None);
        assert_eq!(result.additional, None);
        assert_eq!(result.value, Some(input));
    }

    #[test]
    fn limit_equality_is_allowed() {
        let result = read32(state(1, 0, 32, 9, 41), &bytes());
        assert_eq!(result.tag, 0);
        assert_eq!(result.state.count, 41);
    }
}
