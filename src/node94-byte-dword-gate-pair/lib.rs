#![no_std]
#![forbid(unsafe_code)]
//! Safe image projection of the node94 signed gate and its tail entry.
use core::ops::Range;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    Direct,
    Tail,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}
fn span(image: &[u8], base: u64, address: u64, width: usize) -> Option<Range<usize>> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = start.checked_add(width)?;
    (end <= image.len()).then_some(start..end)
}
fn qword(image: &[u8], base: u64, address: u64) -> Option<u64> {
    Some(u64::from_le_bytes(
        image[span(image, base, address, 8)?].try_into().ok()?,
    ))
}
fn dword(image: &[u8], base: u64, address: u64) -> Option<u32> {
    Some(u32::from_le_bytes(
        image[span(image, base, address, 4)?].try_into().ok()?,
    ))
}
/// Return full numeric RAX/RDX under stable ordinary-memory premises.
/// Only reached spans are required. None is a new safe refusal, not a target
/// fault/return. Numeric addresses never become native pointers; see PROOF.md.
pub fn apply(member: Member, image: &[u8], base: u64, object: u64) -> Option<Registers> {
    if u128::from(base) + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    if member == Member::Tail {
        let pointer = qword(image, base, object.wrapping_add(8))?;
        let count = dword(image, base, object.wrapping_add(16))?;
        let extended = i64::from(count as i32) as u64;
        let target = qword(image, base, pointer.wrapping_add(16))?;
        if target != extended {
            return Some(Registers {
                rax: 1,
                rdx: extended,
            });
        }
    }
    let flag = image[span(image, base, object.wrapping_add(21), 1)?.start];
    let count = dword(image, base, object.wrapping_add(16))?;
    let rax = if flag != 0 && (count as i32) > 0 {
        u64::from(flag)
    } else {
        let compared = dword(image, base, object.wrapping_add(4))?;
        u64::from((compared as i32) <= (count as i32))
    };
    Some(Registers {
        rax,
        rdx: u64::from(count),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn short_path_preserves_flag_and_omits_compared_field() {
        let image = [1, 0, 0, 0, 17, 255];
        assert_eq!(
            apply(Member::Direct, &image, 0, 0u64.wrapping_sub(16)),
            Some(Registers { rax: 255, rdx: 1 })
        );
    }
    #[test]
    fn tail_mismatch_does_not_require_flag() {
        let mut image = [0; 20];
        image[8..16].copy_from_slice(&0u64.wrapping_sub(16).to_le_bytes());
        image[16..20].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            apply(Member::Tail, &image, 0, 0),
            Some(Registers { rax: 1, rdx: 1 })
        );
        assert_eq!(apply(Member::Direct, &image, 0, 0), None);
    }
    #[test]
    fn tail_equality_changes_rdx_extension() {
        let mut image = [0; 128];
        image[8..16].copy_from_slice(&48u64.to_le_bytes());
        image[16..20].copy_from_slice(&0x80000000u32.to_le_bytes());
        image[64..72].copy_from_slice(&0xffffffff80000000u64.to_le_bytes());
        assert_eq!(
            apply(Member::Tail, &image, 0, 0),
            Some(Registers {
                rax: 0,
                rdx: 0x80000000
            })
        );
        image[64..72].copy_from_slice(&0x80000000u64.to_le_bytes());
        assert_eq!(
            apply(Member::Tail, &image, 0, 0),
            Some(Registers {
                rax: 1,
                rdx: 0xffffffff80000000
            })
        );
    }
}
