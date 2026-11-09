#![no_std]
//! Safe logical projection of the Node 115 gated byte-consume leaf.
//! The original source name, ABI types, and field meanings remain unknown.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorState {
    pub mode: u32,
    pub limit: u64,
    pub pointer: u64,
    pub remaining: u64,
    pub count: u64,
}

/// Definite result writes of the leaf. `None` means the corresponding output
/// field is left untouched on that route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputWrites {
    pub tag: u8,
    pub byte: Option<u8>,
    pub qword_at_plus_8: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepResult {
    pub state: CursorState,
    pub output: OutputWrites,
}

/// Apply one normal-return step of the function at `0x232b1b0`.
///
/// `next_byte` is read only when `state.remaining != 0` and all earlier gates
/// succeed. The caller must supply a readable byte for that route. It is
/// ignored on counter rejection and empty-input paths.
pub fn step(mut state: CursorState, next_byte: u8) -> StepResult {
    if state.mode == 1 {
        if state.count == u64::MAX {
            return result(state, 2, None, None);
        }
        let old_count = state.count;
        state.count += 1;
        if old_count >= state.limit {
            return result(state, 2, None, None);
        }
    }

    if state.remaining == 0 {
        return result(state, 0, None, Some(1));
    }

    state.pointer = state.pointer.wrapping_add(1);
    state.remaining -= 1;
    result(state, 0x12, Some(next_byte), None)
}

const fn result(
    state: CursorState,
    tag: u8,
    byte: Option<u8>,
    qword_at_plus_8: Option<u64>,
) -> StepResult {
    StepResult {
        state,
        output: OutputWrites {
            tag,
            byte,
            qword_at_plus_8,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: u64 = u64::MAX;

    fn state(mode: u32, count: u64, limit: u64, remaining: u64) -> CursorState {
        CursorState {
            mode,
            limit,
            pointer: 0x1234,
            remaining,
            count,
        }
    }

    #[test]
    fn mode_zero_consumes_without_charging_even_at_counter_max() {
        let result = step(state(0, MAX, 0, 1), 0xff);
        assert_eq!(result.state.pointer, 0x1235);
        assert_eq!(result.state.remaining, 0);
        assert_eq!(result.state.count, MAX);
        assert_eq!(
            result.output,
            OutputWrites {
                tag: 0x12,
                byte: Some(0xff),
                qword_at_plus_8: None
            }
        );
    }

    #[test]
    fn mode_one_accepts_old_count_below_limit_and_consumes() {
        let result = step(state(1, 0, 1, 1), 0x7a);
        assert_eq!(result.state.count, 1);
        assert_eq!(result.state.pointer, 0x1235);
        assert_eq!(result.state.remaining, 0);
        assert_eq!(
            result.output,
            OutputWrites {
                tag: 0x12,
                byte: Some(0x7a),
                qword_at_plus_8: None
            }
        );
    }

    #[test]
    fn old_count_equal_to_limit_rejects_after_storing_increment() {
        let initial = state(1, 1, 1, 1);
        let result = step(initial, 0x7a);
        assert_eq!(result.state.count, 2);
        assert_eq!(result.state.pointer, initial.pointer);
        assert_eq!(result.state.remaining, initial.remaining);
        assert_eq!(
            result.output,
            OutputWrites {
                tag: 2,
                byte: None,
                qword_at_plus_8: None
            }
        );
    }

    #[test]
    fn counter_overflow_rejects_without_mutating_state() {
        let initial = state(1, MAX, MAX, 1);
        let result = step(initial, 0x7a);
        assert_eq!(result.state, initial);
        assert_eq!(
            result.output,
            OutputWrites {
                tag: 2,
                byte: None,
                qword_at_plus_8: None
            }
        );
    }

    #[test]
    fn empty_input_preserves_increment_then_reports_one_additional_byte() {
        let result = step(state(1, MAX - 1, MAX, 0), 0x7a);
        assert_eq!(result.state.count, MAX);
        assert_eq!(result.state.pointer, 0x1234);
        assert_eq!(result.state.remaining, 0);
        assert_eq!(
            result.output,
            OutputWrites {
                tag: 0,
                byte: None,
                qword_at_plus_8: Some(1)
            }
        );
    }

    #[test]
    fn zero_limit_rejects_after_increment_even_when_input_is_empty() {
        let result = step(state(1, 0, 0, 0), 0);
        assert_eq!(result.state.count, 1);
        assert_eq!(
            result.output,
            OutputWrites {
                tag: 2,
                byte: None,
                qword_at_plus_8: None
            }
        );
    }

    #[test]
    fn other_modes_leave_counter_unchanged_and_empty_path_writes_need_one() {
        let initial = state(2, 17, 0, 0);
        let result = step(initial, 0);
        assert_eq!(result.state, initial);
        assert_eq!(
            result.output,
            OutputWrites {
                tag: 0,
                byte: None,
                qword_at_plus_8: Some(1)
            }
        );
    }
}
