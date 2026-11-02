#![no_std]
#![forbid(unsafe_code)]

/// Byte-substring condition leading to the constructor's guard failure.
/// Input is an already supplied byte slice. No path normalization, filesystem,
/// singleton construction, panic, SIMD overread or native layout is reproduced.
pub fn guard_rejects(path: &[u8]) -> bool {
    path.windows(10).any(|part| part == b"checkpoint")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_substring_is_independent_of_path_components_and_utf8() {
        assert!(guard_rejects(b"\xffprefixcheckpoint\0suffix"));
        assert!(guard_rejects(b"checkpoint"));
        assert!(!guard_rejects(b"CHECKPOINT"));
        assert!(!guard_rejects(b"checkpoin"));
        assert!(!guard_rejects(b""));
    }
}
