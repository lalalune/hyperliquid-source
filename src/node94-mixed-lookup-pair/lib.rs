//! Complete node94 mixed-width lookup pair, using immutable recovered data.
#![no_std]
#![forbid(unsafe_code)]

mod tables;

/// Selects which original entrypoint is projected; this is a new API argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    At299e280,
    At29d7fc0,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}

/// Return the full RAX/RDX values from one member's byte-indexed lookup.
///
/// Only the low byte of `index_bits` is read. `load_bias` is added to the
/// linked base for RAX, with wrapping arithmetic. RDX contains raw u64 data.
/// Correspondence requires the original immutable runtime bytes and a valid
/// original read. Returned addresses are numeric values, never dereferenced.
pub fn lookup(member: Member, index_bits: u64, load_bias: u64) -> Registers {
    let index = usize::from(index_bits as u8);
    let (base, words, offsets) = match member {
        Member::At299e280 => (0x3f7ba0u64, &tables::WORDS0, &tables::OFFSETS0),
        Member::At29d7fc0 => (0x402728u64, &tables::WORDS1, &tables::OFFSETS1),
    };
    let displacement = i64::from(offsets[index]) as u64;
    Registers {
        rax: base.wrapping_add(load_bias).wrapping_add(displacement),
        rdx: words[index],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_base_entries() {
        assert_eq!(
            lookup(Member::At299e280, 0, 0),
            Registers {
                rax: 0x3f7520,
                rdx: 6
            }
        );
        assert_eq!(
            lookup(Member::At29d7fc0, 0, 0),
            Registers {
                rax: 0x4019b1,
                rdx: 6
            }
        );
    }

    #[test]
    fn ignored_high_bits_and_address_wrap() {
        assert_eq!(
            lookup(Member::At299e280, 0xffff_ffff_ffff_ff05, 0).rax,
            0x20bfa0
        );
        assert_eq!(
            lookup(Member::At29d7fc0, 5, 0u64.wrapping_sub(0x20bfa0)).rax,
            0
        );
    }

    #[test]
    fn every_byte_index_is_in_bounds() {
        for i in 0..=255 {
            let a = lookup(Member::At299e280, i, 0);
            let b = lookup(Member::At29d7fc0, i, 0);
            assert_eq!(
                lookup(Member::At299e280, i | (1 << 63), 1).rax,
                a.rax.wrapping_add(1)
            );
            assert_eq!(lookup(Member::At29d7fc0, i, u64::MAX).rdx, b.rdx);
        }
    }
}
