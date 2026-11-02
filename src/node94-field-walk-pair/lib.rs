//! Safe register/image projection of two node94 field-derived store leaves.
#![no_std]
#![forbid(unsafe_code)]
use core::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Member {
    ShiftedDifference,
    SignedField,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}
fn span(image: &[u8], base: u64, address: u64, width: usize) -> Option<Range<usize>> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = start.checked_add(width)?;
    (end <= image.len()).then_some(start..end)
}
fn word(image: &[u8], base: u64, address: u64) -> Option<u64> {
    Some(u64::from_le_bytes(
        image[span(image, base, address, 8)?].try_into().ok()?,
    ))
}

/// Project full RAX/RDX and the sole eight-byte data store.
///
/// Image byte i represents image_base+i in one nonwrapping interval. Numeric
/// addresses are metadata, never native pointers. Only reached reads are
/// required; SignedField does not read object. Reads finish before the store,
/// so arbitrary data aliases are admitted. None is a new atomic safe refusal.
/// Correspondence assumes stable ordinary memory and normal control; original
/// faults, MMIO, races, code/control aliases, flags and native ABI are excluded.
pub fn apply(
    member: Member,
    image: &mut [u8],
    image_base: u64,
    object: u64,
    incoming_rdx: u64,
    output: u64,
) -> Option<Registers> {
    if u128::from(image_base) + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    let (value, rdx) = match member {
        Member::ShiftedDifference => {
            let p = word(image, image_base, object.wrapping_add(0x788))?;
            let q = word(image, image_base, p.wrapping_add(0x30))?;
            let a = word(image, image_base, q.wrapping_add(0xb20))?;
            let b = word(image, image_base, q.wrapping_add(0xb18))?;
            let difference = a.wrapping_sub(b) as i64;
            ((difference >> 4) as u64, q)
        }
        Member::SignedField => {
            let address = incoming_rdx.wrapping_add(0x1438);
            let bytes = image[span(image, image_base, address, 4)?]
                .try_into()
                .ok()?;
            let value = i64::from(i32::from_le_bytes(bytes)) as u64;
            (value, incoming_rdx)
        }
    };
    let destination = span(image, image_base, output, 8)?;
    image[destination].copy_from_slice(&value.to_le_bytes());
    Some(Registers { rax: 1, rdx })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn chain() -> [u8; 128] {
        let mut image = [0; 128];
        image[..8].copy_from_slice(&16u64.wrapping_sub(0x30).to_le_bytes());
        image[16..24].copy_from_slice(&64u64.wrapping_sub(0xb18).to_le_bytes());
        image[64..72].copy_from_slice(&1u64.to_le_bytes());
        image
    }
    #[test]
    fn negative_residue_floors_and_snapshot_aliases() {
        let mut image = chain();
        let got = apply(
            Member::ShiftedDifference,
            &mut image,
            0,
            0u64.wrapping_sub(0x788),
            7,
            64,
        );
        assert_eq!(
            got,
            Some(Registers {
                rax: 1,
                rdx: 64u64.wrapping_sub(0xb18)
            })
        );
        assert_eq!(&image[64..72], &u64::MAX.to_le_bytes());
    }
    #[test]
    fn four_byte_field_and_preserved_rdx() {
        let mut image = [0u8; 12];
        image[8..].copy_from_slice(&0x80000001u32.to_le_bytes());
        let rdx = 8u64.wrapping_sub(0x1438);
        assert_eq!(
            apply(Member::SignedField, &mut image, 0, u64::MAX, rdx, 0),
            Some(Registers { rax: 1, rdx })
        );
        assert_eq!(&image[..8], &0xffffffff80000001u64.to_le_bytes());
    }
    #[test]
    fn missing_output_refuses_without_a_partial_write() {
        let mut image = chain();
        let original = image;
        assert_eq!(
            apply(
                Member::ShiftedDifference,
                &mut image,
                0,
                0u64.wrapping_sub(0x788),
                0,
                121
            ),
            None
        );
        assert_eq!(image, original);
    }
}
