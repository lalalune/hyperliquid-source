//! Full RAX/RDX and byte-image projection of four node94 cursor leaves.
#![no_std]
#![forbid(unsafe_code)]
use core::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Member {
    Span,
    Read,
    Advance,
    Retreat,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}
fn span(image: &[u8], base: u64, address: u64) -> Option<Range<usize>> {
    let begin = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = begin.checked_add(8)?;
    (end <= image.len()).then_some(begin..end)
}
fn word(image: &[u8], base: u64, address: u64) -> Option<u64> {
    Some(u64::from_le_bytes(
        image[span(image, base, address)?].try_into().ok()?,
    ))
}

/// Byte i represents image_base+i in one nonwrapping supplied memory image.
///
/// Only reached reads are required. All reads precede any cursor write, so data
/// aliases are allowed. A new API refusal returns None with every byte unchanged.
/// Original correspondence requires stable ordinary memory and valid control;
/// machine ABI, faults, MMIO, races and code/control aliases are not projected.
pub fn apply(
    member: Member,
    image: &mut [u8],
    image_base: u64,
    object: u64,
    incoming_rdx: u64,
) -> Option<Registers> {
    if let Some(last) = image.len().checked_sub(1) {
        image_base.checked_add(u64::try_from(last).ok()?)?;
    }
    if member == Member::Read {
        let cursor = word(image, image_base, object.wrapping_add(32))?;
        return Some(Registers {
            rax: word(image, image_base, cursor)?,
            rdx: incoming_rdx,
        });
    }
    let bounds = word(image, image_base, object.wrapping_add(16))?;
    if member == Member::Span {
        let last = word(image, image_base, bounds.wrapping_add(8))?;
        let first = word(image, image_base, bounds)?;
        return Some(Registers {
            rax: last.wrapping_sub(first).wrapping_add(40),
            rdx: bounds,
        });
    }
    let cursor_address = object.wrapping_add(32);
    let cursor = word(image, image_base, cursor_address)?;
    let result = match member {
        Member::Advance => {
            let last = word(image, image_base, bounds.wrapping_add(8))?;
            if cursor == last {
                return Some(Registers {
                    rax: cursor,
                    rdx: bounds,
                });
            }
            cursor.wrapping_add(8)
        }
        Member::Retreat => {
            let first = word(image, image_base, bounds)?;
            if cursor == first {
                word(image, image_base, bounds.wrapping_add(8))?
            } else {
                cursor.wrapping_sub(8)
            }
        }
        Member::Span | Member::Read => unreachable!(),
    };
    let destination = span(image, image_base, cursor_address)?;
    image[destination].copy_from_slice(&result.to_le_bytes());
    Some(Registers {
        rax: result,
        rdx: bounds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_skips_bounds_and_preserves_rdx() {
        let mut image = [0u8; 16];
        image[..8].copy_from_slice(&8u64.to_le_bytes());
        image[8..].copy_from_slice(&123u64.to_le_bytes());
        assert_eq!(
            apply(Member::Read, &mut image, 0, 0u64.wrapping_sub(32), u64::MAX),
            Some(Registers {
                rax: 123,
                rdx: u64::MAX
            })
        );
    }
    #[test]
    fn retreat_can_overwrite_its_first_bound() {
        let mut image = [0u8; 64];
        image[16..24].copy_from_slice(&32u64.to_le_bytes());
        image[32..40].copy_from_slice(&9u64.to_le_bytes());
        image[40..48].copy_from_slice(&77u64.to_le_bytes());
        assert_eq!(
            apply(Member::Retreat, &mut image, 0, 0, 0),
            Some(Registers { rax: 77, rdx: 32 })
        );
        assert_eq!(&image[32..40], &77u64.to_le_bytes());
    }
    #[test]
    fn missing_wrap_bound_refuses_without_writing() {
        let mut image = [0u8; 48];
        image[16..24].copy_from_slice(&40u64.to_le_bytes());
        image[32..40].copy_from_slice(&9u64.to_le_bytes());
        image[40..48].copy_from_slice(&9u64.to_le_bytes());
        let before = image;
        assert_eq!(apply(Member::Retreat, &mut image, 0, 0, 0), None);
        assert_eq!(image, before);
    }
}
