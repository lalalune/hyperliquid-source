//! Selected post-delegate tail policy, not a JSON parser or original ABI.
#![no_std]
#![forbid(unsafe_code)]

pub const DELEGATE_ERROR_WORD: u64 = 0x8000_0000_0000_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailResult {
    DelegateError { cursor: usize },
    Complete { cursor: usize },
    Trailing { cursor: usize, code: u8 },
}

/// The bound before BT is essential: high byte values must not alias bit 0..63.
pub const fn is_tail_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// Apply only the established tail scan after an opaque delegate has returned.
///
/// The error sentinel bypasses the scan. Otherwise scanning starts at the
/// supplied cursor, never at the beginning or by trimming the input backwards.
/// A cursor at or beyond length takes the observed no-scan exit. This does not
/// establish that an oversized cursor is reachable from the original delegate.
pub fn finish_tail(output_word: u64, input: &[u8], mut cursor: usize) -> TailResult {
    if output_word == DELEGATE_ERROR_WORD {
        return TailResult::DelegateError { cursor };
    }
    while cursor < input.len() {
        if !is_tail_whitespace(input[cursor]) {
            return TailResult::Trailing { cursor, code: 0x16 };
        }
        cursor += 1;
    }
    TailResult::Complete { cursor }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_unconsumed_suffix_is_examined() {
        assert_eq!(
            finish_tail(0, b"not parsed here\t\r\n ", 15),
            TailResult::Complete { cursor: 19 }
        );
        assert_eq!(
            finish_tail(0, b"x \x0c", 1),
            TailResult::Trailing {
                cursor: 2,
                code: 0x16
            }
        );
    }

    #[test]
    fn delegate_error_and_exhausted_cursors_do_not_read_input() {
        assert_eq!(
            finish_tail(DELEGATE_ERROR_WORD, b"x", usize::MAX),
            TailResult::DelegateError { cursor: usize::MAX }
        );
        assert_eq!(
            finish_tail(0, b"x", usize::MAX),
            TailResult::Complete { cursor: usize::MAX }
        );
    }

    #[test]
    fn ascii_whitespace_and_wrapped_bit_indexes_are_not_the_policy() {
        for byte in [0x0b, 0x0c, 0x49, 0x60, 0x89, 0xa0, 0xff] {
            assert!(!is_tail_whitespace(byte));
        }
        assert!(b'\x0c'.is_ascii_whitespace());
    }
}
