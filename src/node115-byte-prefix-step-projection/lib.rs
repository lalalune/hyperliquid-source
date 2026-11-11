#![no_std]
//! Logical projection of the Node 115 byte-prefix leaf at 0x5434bb0.
//! This is not an ABI-compatible decoder or a whole-node implementation.

/// Input cursor state accessed by the leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorState {
    pub pointer: u64,
    pub remaining: u64,
}

/// Definite output writes made by the selected leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputWrites {
    /// Always written at output byte 0.
    pub tag: u8,
    /// Bytes 1 and 2 when the leaf writes them; `None` means left untouched.
    pub pair: Option<[u8; 2]>,
    /// Runtime address stored at output +8; `None` means left untouched.
    pub descriptor_pointer: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepResult {
    pub state: CursorState,
    pub output: OutputWrites,
}

/// Apply the observed normal-return behavior to one cursor step.
///
/// `next_byte` is ignored when `remaining == 0`. For nonempty input it is the
/// readable byte at `state.pointer`. `incoming_dl` and the runtime descriptor
/// address are explicit because the empty path preserves register-derived
/// bytes and the leaf stores a relocated pointer without interpreting it.
pub fn step(
    mut state: CursorState,
    next_byte: u8,
    incoming_dl: u8,
    descriptor_pointer: u64,
) -> StepResult {
    if state.remaining == 0 {
        return StepResult {
            state,
            output: OutputWrites {
                tag: 0,
                pair: Some([incoming_dl, state.pointer as u8]),
                descriptor_pointer: Some(descriptor_pointer),
            },
        };
    }

    state.pointer = state.pointer.wrapping_add(1);
    state.remaining -= 1;

    let (tag, pair, descriptor_pointer) = if next_byte == 0xc0 {
        (9, None, None)
    } else {
        let pair = match next_byte {
            0x00..=0x7f => [0x00, next_byte],
            0x80..=0x8f => [0x80, next_byte & 0x0f],
            0x90..=0x9f => [0x90, next_byte & 0x0f],
            0xa0..=0xbf => [0xa0, next_byte & 0x1f],
            0xc1..=0xdf => [next_byte, next_byte & 0x1f],
            0xc0 => unreachable!("handled by the tag-only branch"),
            0xe0..=0xff => [0xe0, next_byte],
        };
        (2, Some(pair), Some(descriptor_pointer))
    };

    StepResult {
        state,
        output: OutputWrites {
            tag,
            pair,
            descriptor_pointer,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESCRIPTOR: u64 = 0x7f00_64b0_2700;

    #[test]
    fn every_nonempty_byte_matches_the_observed_partition() {
        for byte in 0u8..=u8::MAX {
            let state = CursorState {
                pointer: 0x1234,
                remaining: 2,
            };
            let result = step(state, byte, 0x55, DESCRIPTOR);
            assert_eq!(result.state.pointer, 0x1235, "byte={byte:#04x}");
            assert_eq!(result.state.remaining, 1, "byte={byte:#04x}");
            if byte == 0xc0 {
                assert_eq!(
                    result.output,
                    OutputWrites {
                        tag: 9,
                        pair: None,
                        descriptor_pointer: None,
                    },
                    "byte={byte:#04x}"
                );
                continue;
            }
            let pair = match byte {
                0x00..=0x7f => [0x00, byte],
                0x80..=0x8f => [0x80, byte & 0x0f],
                0x90..=0x9f => [0x90, byte & 0x0f],
                0xa0..=0xbf => [0xa0, byte & 0x1f],
                0xc1..=0xdf => [byte, byte & 0x1f],
                0xc0 => unreachable!("handled above"),
                0xe0..=0xff => [0xe0, byte],
            };
            assert_eq!(
                result.output,
                OutputWrites {
                    tag: 2,
                    pair: Some(pair),
                    descriptor_pointer: Some(DESCRIPTOR),
                },
                "byte={byte:#04x}"
            );
        }
    }

    #[test]
    fn empty_path_preserves_cursor_and_register_derived_pair() {
        let initial = CursorState {
            pointer: 0x1234_5678,
            remaining: 0,
        };
        let result = step(initial, 0xc0, 0xa7, DESCRIPTOR);
        assert_eq!(result.state, initial);
        assert_eq!(
            result.output,
            OutputWrites {
                tag: 0,
                pair: Some([0xa7, 0x78]),
                descriptor_pointer: Some(DESCRIPTOR),
            }
        );
    }

    #[test]
    fn special_c0_consumes_input_but_only_writes_tag() {
        let result = step(
            CursorState {
                pointer: 99,
                remaining: 1,
            },
            0xc0,
            0,
            DESCRIPTOR,
        );
        assert_eq!(
            result.state,
            CursorState {
                pointer: 100,
                remaining: 0,
            }
        );
        assert_eq!(
            result.output,
            OutputWrites {
                tag: 9,
                pair: None,
                descriptor_pointer: None,
            }
        );
    }

    #[test]
    fn nonempty_paths_ignore_incoming_register_values() {
        let a = step(
            CursorState {
                pointer: 5,
                remaining: 1,
            },
            0x80,
            0x00,
            DESCRIPTOR,
        );
        let b = step(
            CursorState {
                pointer: 5,
                remaining: 1,
            },
            0x80,
            0xff,
            DESCRIPTOR + 8,
        );
        assert_eq!(a.output.pair, Some([0x80, 0]));
        assert_eq!(b.output.pair, Some([0x80, 0]));
        assert_eq!(a.output.descriptor_pointer, Some(DESCRIPTOR));
        assert_eq!(b.output.descriptor_pointer, Some(DESCRIPTOR + 8));
    }
}
