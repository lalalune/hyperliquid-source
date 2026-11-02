//! ASCII projection after the node94 restart replacement helper has returned.
//!
//! The input is that returned buffer, not an original command or shell syntax.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;

fn separator(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Remove exact backup-flag tokens and join the surviving ASCII tokens.
///
/// `None` is a new safe API refusal for non-ASCII input. Original Unicode,
/// replacement, allocation/fault behavior and process execution are unproved.
pub fn normalize_ascii(input: &[u8]) -> Option<Vec<u8>> {
    if !input.is_ascii() {
        return None;
    }
    let mut output = Vec::new();
    for token in input.split(|&byte| separator(byte)) {
        if token.is_empty() || token == b"--backup-logs" {
            continue;
        }
        if !output.is_empty() {
            output.push(b' ');
        }
        output.extend_from_slice(token);
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_only_exact_tokens_and_collapses_all_six_separators() {
        assert_eq!(
            normalize_ascii(b"\t--backup-logs\x0bnode\x0c--backup-logs\r --backup-logsX\n"),
            Some(b"node --backup-logsX".to_vec())
        );
    }

    #[test]
    fn quotes_are_literal_bytes_and_nul_is_not_a_separator() {
        assert_eq!(
            normalize_ascii(b"\"--backup-logs\" a\x00b"),
            Some(b"\"--backup-logs\" a\x00b".to_vec())
        );
    }

    #[test]
    fn empty_outputs_and_explicit_non_ascii_refusal() {
        assert_eq!(normalize_ascii(b""), Some(Vec::new()));
        assert_eq!(
            normalize_ascii(b"--backup-logs --backup-logs"),
            Some(Vec::new())
        );
        assert_eq!(normalize_ascii(b"\xc2\xa0"), None);
    }
}
