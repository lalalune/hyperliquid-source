#![no_std]
#![forbid(unsafe_code)]
//! Complete node94 range-sum pair with its mandatory shared helper read.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Member {
    HelperSum,
    SlotFieldSum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub rdi: u64,
    pub rsi: u64,
}

fn offset(image: &[u8], base: u64, address: u64) -> Option<usize> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    (start.checked_add(8)? <= image.len()).then_some(start)
}

fn word(image: &[u8], base: u64, address: u64) -> Option<u64> {
    let start = offset(image, base, address)?;
    Some(u64::from_le_bytes(image[start..start + 8].try_into().ok()?))
}

/// Numeric memory projection, including every reached helper input even when
/// its value is discarded. All reads precede the sole output store. None
/// leaves the image unchanged; an unreachable endpoint is a safe refusal.
/// Original stack/control storage must be valid and disjoint from this image.
/// RCX/R8..R15/RBX/RBP are preserved by the complete outer functions.
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
    let container = word(image, base, first.wrapping_add(0x30))?;
    let begin = word(image, base, container.wrapping_add(0xb18))?;
    let end = word(image, base, container.wrapping_add(0xb20))?;
    let distance = end.wrapping_sub(begin);
    if distance & 15 != 0 {
        return None;
    }
    let count = distance / 16;
    // Distinct mandatory entry qwords occupy at least 8*count mapped bytes.
    if u128::from(count) > image.len() as u128 / 8 {
        return None;
    }
    let mut cursor = begin;
    let mut total = 0u64;
    let mut last_argument = object;
    for _ in 0..count {
        let slot = word(image, base, cursor)?;
        let argument = word(image, base, slot)?;
        let helper = word(image, base, argument.wrapping_add(16))?.wrapping_add(62);
        let contribution = match member {
            Member::HelperSum => helper,
            Member::SlotFieldSum => word(image, base, slot.wrapping_add(80))?,
        };
        total = total.wrapping_add(contribution);
        last_argument = argument;
        cursor = cursor.wrapping_add(16);
    }
    image[output..output + 8].copy_from_slice(&total.to_le_bytes());
    Some(Registers {
        rax: 1,
        rdx: incoming_rdx,
        rdi: last_argument,
        rsi: destination,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(image: &mut [u8], offset: usize, value: u64) {
        image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn fixture() -> ([u8; 768], u64) {
        let mut image = [0; 768];
        put(&mut image, 16, 0);
        put(&mut image, 48, 80u64.wrapping_sub(0xb18));
        put(&mut image, 80, 128);
        put(&mut image, 88, 144);
        put(&mut image, 128, 320);
        put(&mut image, 320, 560);
        put(&mut image, 400, 9);
        put(&mut image, 576, u64::MAX);
        (image, 16u64.wrapping_sub(0x788))
    }

    #[test]
    fn distinct_sum_and_live_output_alias() {
        let (mut image, object) = fixture();
        let r = apply(Member::HelperSum, &mut image, 0, object, 128, 71).unwrap();
        assert_eq!(word(&image, 0, 128), Some(61));
        assert_eq!(
            r,
            Registers {
                rax: 1,
                rdx: 71,
                rdi: 560,
                rsi: 128
            }
        );
        let (mut image, object) = fixture();
        apply(Member::SlotFieldSum, &mut image, 0, object, 128, 0).unwrap();
        assert_eq!(word(&image, 0, 128), Some(9));
    }

    #[test]
    fn discarded_helper_still_requires_input() {
        let (mut image, object) = fixture();
        put(&mut image, 320, 900);
        let before = image;
        assert!(apply(Member::SlotFieldSum, &mut image, 0, object, 0, 0).is_none());
        assert_eq!(image, before);
    }

    #[test]
    fn empty_unmapped_endpoints_and_unreachable_end() {
        let (mut image, object) = fixture();
        put(&mut image, 80, u64::MAX);
        put(&mut image, 88, u64::MAX);
        let r = apply(Member::HelperSum, &mut image, 0, object, 0, 0).unwrap();
        assert_eq!(r.rdi, object);
        assert_eq!(word(&image, 0, 0), Some(0));
        put(&mut image, 88, 0);
        let before = image;
        assert!(apply(Member::HelperSum, &mut image, 0, object, 0, 0).is_none());
        assert_eq!(image, before);
    }
}
