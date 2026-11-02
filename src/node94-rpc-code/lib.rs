//! Raw u32 classification recovered at node94 VA 0x15bb930.
//!
//! Numeric kinds only: this is not a JSON number parser, named enum, error
//! constructor or original output layout. The original raw code is preserved.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Classification {
    pub kind: u32,
    pub code: u32,
}

pub const fn classify(raw: u32) -> Classification {
    let kind = match raw as i32 {
        -32700 => 0,
        -32007 => 1,
        -32600 => 2,
        -32601 => 3,
        -32602 => 5,
        -32603 => 6,
        _ => 7,
    };
    Classification { kind, code: raw }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exceptional_codes_preserve_original_bits() {
        for (code, kind) in [
            (-32700i32, 0),
            (-32007, 1),
            (-32600, 2),
            (-32601, 3),
            (-32602, 5),
            (-32603, 6),
        ] {
            assert_eq!(
                classify(code as u32),
                Classification {
                    kind,
                    code: code as u32
                }
            );
        }
    }

    #[test]
    fn default_includes_adjacent_and_full_width_words() {
        for raw in [
            0,
            1,
            u32::MAX,
            0x8000_0000,
            0x7fff_ffff,
            (-32604i32) as u32,
            (-32599i32) as u32,
        ] {
            assert_eq!(classify(raw), Classification { kind: 7, code: raw });
        }
    }
}
