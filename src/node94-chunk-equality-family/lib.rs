#![no_std]
#![forbid(unsafe_code)]
//! Numeric projection of twelve node94 16-byte comparison functions.

/// Index i denotes the complete FDE beginning at 0x14b52b0 + 0x30*i.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Pattern {
    P0,
    P1,
    P2,
    P3,
    P4,
    P5,
    P6,
    P7,
    P8,
    P9,
    P10,
    P11,
}

impl Pattern {
    pub fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::P0),
            1 => Some(Self::P1),
            2 => Some(Self::P2),
            3 => Some(Self::P3),
            4 => Some(Self::P4),
            5 => Some(Self::P5),
            6 => Some(Self::P6),
            7 => Some(Self::P7),
            8 => Some(Self::P8),
            9 => Some(Self::P9),
            10 => Some(Self::P10),
            11 => Some(Self::P11),
            _ => None,
        }
    }
}

const COMPARANDS: [[u8; 16]; 12] = [
    [
        0xf8, 0x6e, 0x51, 0x5c, 0x5a, 0x0d, 0x09, 0x18, 0xc2, 0x0a, 0xc9, 0x5e, 0x03, 0x58, 0x3e,
        0x31,
    ],
    [
        0xe7, 0x3d, 0x5d, 0xa0, 0xde, 0x07, 0x30, 0x90, 0x21, 0x96, 0xb2, 0x80, 0x93, 0x7e, 0x3b,
        0x5b,
    ],
    [
        0x18, 0x97, 0x8b, 0xb2, 0x57, 0xd5, 0xdc, 0x38, 0xa3, 0x9d, 0x96, 0x26, 0xee, 0xf3, 0x30,
        0xcd,
    ],
    [
        0x93, 0x02, 0x58, 0x08, 0x64, 0xd7, 0x61, 0xd5, 0x13, 0x71, 0xd3, 0xc6, 0x34, 0x60, 0x6f,
        0xfb,
    ],
    [
        0xb7, 0x6d, 0x6b, 0x68, 0x3e, 0x7e, 0x14, 0xf2, 0xaf, 0x3e, 0x8f, 0x0b, 0xd8, 0xeb, 0xb8,
        0x3a,
    ],
    [
        0xe4, 0xfb, 0x4a, 0x93, 0xc0, 0xee, 0x9c, 0x44, 0xea, 0x0b, 0x5a, 0x5f, 0x63, 0xe0, 0x80,
        0x0e,
    ],
    [
        0x28, 0x76, 0x15, 0x6f, 0x61, 0x2a, 0x73, 0x61, 0xcc, 0xad, 0xe6, 0x0e, 0x37, 0x5e, 0x72,
        0x6e,
    ],
    [
        0x4b, 0x77, 0xfd, 0x3b, 0xb2, 0x70, 0xb8, 0x0a, 0x74, 0xba, 0xe4, 0x0b, 0xda, 0x04, 0x89,
        0x37,
    ],
    [
        0x6d, 0x5d, 0xcb, 0xd6, 0x2c, 0x50, 0xeb, 0x63, 0x78, 0x41, 0xa6, 0x57, 0x71, 0x1b, 0x8b,
        0xb9,
    ],
    [
        0x50, 0x7e, 0x85, 0xb2, 0xbc, 0x09, 0xf7, 0x46, 0x8f, 0x12, 0x9a, 0x7c, 0x0c, 0xbd, 0x7c,
        0x63,
    ],
    [
        0xd1, 0x6c, 0xaa, 0x81, 0xef, 0xab, 0x68, 0x37, 0x9d, 0x4c, 0x14, 0x6f, 0xcc, 0xa6, 0x8d,
        0x2b,
    ],
    [
        0xe5, 0x0b, 0x9d, 0xb6, 0xf4, 0x9b, 0xdd, 0xdf, 0xff, 0x66, 0xa6, 0x65, 0xd5, 0x39, 0xd4,
        0xbf,
    ],
];

/// All general-purpose registers written by these leaves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub rcx: u64,
}

/// Compare one complete input snapshot and return the numeric register relation.
///
/// `object` is incoming RDI bits. Its derived address is never dereferenced:
/// wrapping to zero is admitted even on a full match. Input is a complete
/// initialized 16-byte snapshot. Correspondence assumes ordinary stable readable
/// memory and the bound readonly comparand; this API does not recreate pointers,
/// the original ABI, XMM0, flags, faults or an access trace.
pub fn compare(pattern: Pattern, input: &[u8; 16], object: u64) -> Registers {
    let mut mask = 0_u16;
    for j in 0..16 {
        mask |= u16::from(input[j] == COMPARANDS[pattern as usize][j]) << j;
    }
    let rdx = object.wrapping_add(56);
    Registers {
        rax: if mask == u16::MAX { rdx } else { 0 },
        rdx,
        rcx: u64::from(mask),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_can_return_zero_with_full_mask() {
        assert_eq!(
            compare(Pattern::P0, &COMPARANDS[0], u64::MAX - 55),
            Registers {
                rax: 0,
                rdx: 0,
                rcx: 65535
            }
        );
    }

    #[test]
    fn mismatch_preserves_derived_address_and_exact_byte_mask() {
        let mut input = COMPARANDS[3];
        input[7] ^= 1;
        assert_eq!(
            compare(Pattern::P3, &input, 123),
            Registers {
                rax: 0,
                rdx: 179,
                rcx: 65535 - 128
            }
        );
    }

    #[test]
    fn each_member_uses_its_own_complete_constant() {
        for i in 0..12 {
            let p = Pattern::from_index(i).unwrap();
            assert_eq!(compare(p, &COMPARANDS[i as usize], 1).rax, 57);
            assert_eq!(compare(p, &COMPARANDS[(i as usize + 1) % 12], 1).rax, 0);
        }
        assert_eq!(Pattern::from_index(12), None);
    }
}
