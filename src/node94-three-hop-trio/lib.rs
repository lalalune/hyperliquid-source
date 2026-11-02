#![no_std]
#![forbid(unsafe_code)]
//! Complete node94 three-hop field/store trio over safe numeric memory images.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    FieldCd0,
    FieldA70,
    FieldA78,
}
impl Member {
    const fn field(self) -> u64 {
        match self {
            Self::FieldCd0 => 0xcd0,
            Self::FieldA70 => 0xa70,
            Self::FieldA78 => 0xa78,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}
fn offset(image: &[u8], base: u64, address: u64) -> Option<usize> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    (start.checked_add(8)? <= image.len()).then_some(start)
}
fn word(image: &[u8], base: u64, address: u64) -> Option<u64> {
    let start = offset(image, base, address)?;
    Some(u64::from_le_bytes(image[start..start + 8].try_into().ok()?))
}

/// Read all three reached qwords before the sole eight-byte store. All data
/// aliases are admitted; numeric zero bases are not implicit null checks.
/// None is an unchanged-image range refusal. Stable ordinary memory and valid
/// disjoint control/stack storage are premises; native ABI, faults, MMIO and
/// concurrent observations are outside this value projection.
pub fn apply(
    member: Member,
    image: &mut [u8],
    base: u64,
    object: u64,
    destination: u64,
    incoming_rdx: u64,
) -> Option<Registers> {
    if u128::from(base) + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    let output = offset(image, base, destination)?;
    let first = word(image, base, object.wrapping_add(0x788))?;
    let second = word(image, base, first.wrapping_add(0x8e8))?;
    let value = word(image, base, second.wrapping_add(member.field()))?;
    image[output..output + 8].copy_from_slice(&value.to_le_bytes());
    Some(Registers {
        rax: 1,
        rdx: incoming_rdx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put(image: &mut [u8], at: usize, value: u64) {
        image[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    #[test]
    fn destination_can_replace_a_pointer_after_all_reads() {
        let mut image = [0; 128];
        put(&mut image, 0, 32u64.wrapping_sub(0x8e8));
        put(&mut image, 32, 64u64.wrapping_sub(0xcd0));
        put(&mut image, 64, 0x81234567fedcba98);
        let before = image;
        assert_eq!(
            apply(
                Member::FieldCd0,
                &mut image,
                0,
                0u64.wrapping_sub(0x788),
                32,
                99
            ),
            Some(Registers { rax: 1, rdx: 99 })
        );
        assert_eq!(&image[32..40], &before[64..72]);
        assert_eq!(&image[..32], &before[..32]);
        assert_eq!(&image[40..], &before[40..]);
    }
    #[test]
    fn members_select_distinct_final_fields() {
        let mut image = [0; 1024];
        put(&mut image, 0, 32u64.wrapping_sub(0x8e8));
        put(&mut image, 32, 0u64.wrapping_sub(0xa00));
        put(&mut image, 0x2d0, 111);
        put(&mut image, 0x70, 222);
        put(&mut image, 0x78, 333);
        for (member, value) in [
            (Member::FieldCd0, 111u64),
            (Member::FieldA70, 222),
            (Member::FieldA78, 333),
        ] {
            assert!(apply(member, &mut image, 0, 0u64.wrapping_sub(0x788), 64, 0).is_some());
            assert_eq!(&image[64..72], &value.to_le_bytes());
        }
    }
    #[test]
    fn zero_field_base_is_readable_and_missing_spans_are_atomic() {
        let mut image = [0; 1280];
        let base = 0x800;
        put(&mut image, 0, 0);
        put(&mut image, 0xe8, (base + 400u64).wrapping_sub(0xcd0));
        put(&mut image, 400, 77);
        assert!(
            apply(
                Member::FieldCd0,
                &mut image,
                base,
                base - 0x788,
                base + 500,
                0
            )
            .is_some()
        );
        assert_eq!(&image[500..508], &77u64.to_le_bytes());
        let before = image;
        assert_eq!(
            apply(
                Member::FieldCd0,
                &mut image[..407],
                base,
                base - 0x788,
                base + 300,
                0
            ),
            None
        );
        assert_eq!(image, before);
    }
}
