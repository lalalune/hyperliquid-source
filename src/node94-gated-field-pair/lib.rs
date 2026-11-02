#![no_std]
#![forbid(unsafe_code)]
//! Numeric image projection of node94's two same-flag copy leaves.
//! Addresses are metadata, never native pointers. See the packet for premises.

use core::ops::Range;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    CopyOut,
    CopyIn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}

fn span(image: &[u8], base: u64, address: u64, size: usize) -> Option<Range<usize>> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = start.checked_add(size)?;
    (end <= image.len()).then_some(start..end)
}

fn word(image: &[u8], base: u64, address: u64) -> Option<u64> {
    let bytes = image.get(span(image, base, address, 8)?)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn enabled(image: &[u8], base: u64, object: u64) -> Option<bool> {
    let field = span(image, base, object.wrapping_add(184), 1)?;
    Some(image[field.start] != 0)
}

/// Project final RAX/RDX and image under stable ordinary-memory premises.
/// The finite image must not wrap. Only the selected path's accesses are needed.
/// `None` is a new API refusal and leaves the image unchanged; it models no fault.
pub fn apply(
    member: Member,
    image: &mut [u8],
    image_base: u64,
    object: u64,
    external: u64,
    incoming: Registers,
) -> Option<Registers> {
    if u128::from(image_base) + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    match member {
        Member::CopyOut => {
            let pointer = word(image, image_base, object.wrapping_add(728))?;
            if pointer == 0 || !enabled(image, image_base, object)? {
                return Some(Registers {
                    rax: pointer,
                    rdx: incoming.rdx,
                });
            }
            let first = word(image, image_base, pointer.wrapping_add(32))?;
            let last = word(image, image_base, pointer.wrapping_add(96))?;
            let first_destination = span(image, image_base, external.wrapping_add(16), 8)?;
            let last_destination = span(image, image_base, external.wrapping_add(24), 8)?;
            image[first_destination].copy_from_slice(&first.to_le_bytes());
            image[last_destination].copy_from_slice(&last.to_le_bytes());
            Some(Registers {
                rax: last,
                rdx: first,
            })
        }
        Member::CopyIn => {
            if !enabled(image, image_base, object)? {
                return Some(incoming);
            }
            let low = word(image, image_base, external.wrapping_add(16))?;
            let high = word(image, image_base, external.wrapping_add(24))?;
            let destination = span(image, image_base, object.wrapping_add(696), 16)?;
            let mut value = [0u8; 16];
            value[..8].copy_from_slice(&low.to_le_bytes());
            value[8..].copy_from_slice(&high.to_le_bytes());
            image[destination].copy_from_slice(&value);
            Some(incoming)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ENTRY: Registers = Registers { rax: 7, rdx: 9 };
    #[test]
    fn null_pointer_does_not_require_gate() {
        let mut image = [0; 8];
        assert_eq!(
            apply(
                Member::CopyOut,
                &mut image,
                0,
                0u64.wrapping_sub(728),
                u64::MAX,
                ENTRY
            ),
            Some(Registers { rax: 0, rdx: 9 })
        );
    }
    #[test]
    fn aliased_second_source_is_snapshotted() {
        let mut image = [0; 800];
        image[728..736].copy_from_slice(&32u64.to_le_bytes());
        image[184] = 128;
        image[64..72].copy_from_slice(&11u64.to_le_bytes());
        image[128..136].copy_from_slice(&22u64.to_le_bytes());
        assert_eq!(
            apply(Member::CopyOut, &mut image, 0, 0, 112, ENTRY),
            Some(Registers { rax: 22, rdx: 11 })
        );
        assert_eq!(
            &image[128..144],
            &[11, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0]
        );
    }
    #[test]
    fn closed_gate_and_refusal_preserve_registers_and_image() {
        let mut image = [0; 185];
        assert_eq!(
            apply(Member::CopyIn, &mut image, 0, 0, u64::MAX, ENTRY),
            Some(ENTRY)
        );
        image[184] = 2;
        let original = image;
        assert_eq!(
            apply(Member::CopyIn, &mut image, 0, 0, u64::MAX, ENTRY),
            None
        );
        assert_eq!(image, original);
    }
}
