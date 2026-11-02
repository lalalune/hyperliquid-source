#![no_std]
#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Admission {
    RejectBeforeParser = 0,
    RejectAfterParser = 1,
    AdmitToCollection = 2,
}

/// Supplied parser outcomes only: no endpoint, command or parser runs.
pub fn admission(length: u64, parser_al: u8, remaining: u64) -> Admission {
    if length > 15 {
        Admission::RejectBeforeParser
    } else if parser_al & 1 != 0 && remaining == 0 {
        Admission::AdmitToCollection
    } else {
        Admission::RejectAfterParser
    }
}

/// Whether the selected override word takes the fallback probe branch.
pub fn probe_path(override_word: u64) -> bool {
    override_word == (1 << 63)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn caller_length_limit_and_complete_parse_are_separate_gates() {
        assert_eq!(admission(16, 255, 0), Admission::RejectBeforeParser);
        assert_eq!(admission(15, 255, 0), Admission::AdmitToCollection);
        assert_eq!(admission(15, 255, 1), Admission::RejectAfterParser);
        assert!(!probe_path(u64::MAX));
        assert!(probe_path(1 << 63));
    }
}
