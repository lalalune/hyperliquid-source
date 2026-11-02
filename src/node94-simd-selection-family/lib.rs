#![no_std]
#![forbid(unsafe_code)]
//! Six node94 selection leaves, preserving their one-block lookahead on aliases.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    W32,
    W48,
    W96,
    W192,
    W144,
    W288,
}
impl Member {
    pub const fn width(self) -> usize {
        match self {
            Self::W32 => 32,
            Self::W48 => 48,
            Self::W96 => 96,
            Self::W192 => 192,
            Self::W144 => 144,
            Self::W288 => 288,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rcx: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
}
fn span(image: &[u8], base: u64, address: u64, width: usize) -> Option<usize> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = start.checked_add(width)?;
    (end <= image.len()).then_some(start)
}
fn read_pair(image: &[u8], a: usize, b: usize, select_a: bool) -> [u8; 16] {
    let mut left = [0; 16];
    let mut right = [0; 16];
    left.copy_from_slice(&image[a..a + 16]);
    right.copy_from_slice(&image[b..b + 16]);
    if select_a { left } else { right }
}

/// Project complete final data bytes and five numeric GP-register observations.
/// Both source spans are required, including the masked-out one. All data aliases
/// are allowed. None is a new atomic refusal; original faults/ABI, SIMD state,
/// MMIO, concurrent observations and control aliases are outside the projection.
pub fn apply(
    member: Member,
    image: &mut [u8],
    image_base: u64,
    source_a: u64,
    source_b: u64,
    destination: u64,
    control: u64,
    incoming_rax: u64,
) -> Option<Registers> {
    if u128::from(image_base) + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    let width = member.width();
    let a = span(image, image_base, source_a, width)?;
    let b = span(image, image_base, source_b, width)?;
    let d = span(image, image_base, destination, width)?;
    let select_a = control as u32 != 0;
    let mut current = read_pair(image, a, b, select_a);
    for offset in (16..width).step_by(16) {
        let next = read_pair(image, a + offset, b + offset, select_a);
        image[d + offset - 16..d + offset].copy_from_slice(&current);
        current = next;
    }
    image[d + width - 16..d + width].copy_from_slice(&current);
    let advance = (width / 2) as u64;
    Some(Registers {
        rax: incoming_rax,
        rcx: control,
        rdi: destination.wrapping_add(advance),
        rsi: source_a.wrapping_add(advance),
        rdx: source_b.wrapping_add(advance),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn two_blocks_are_loaded_before_the_first_store() {
        let mut image = core::array::from_fn::<_, 64, _>(|i| i as u8);
        let before = image;
        let result = apply(Member::W32, &mut image, 0, 0, 32, 16, 1, 99);
        assert_eq!(
            result,
            Some(Registers {
                rax: 99,
                rcx: 1,
                rdi: 32,
                rsi: 16,
                rdx: 48
            })
        );
        assert_eq!(&image[16..48], &before[..32]);
    }
    #[test]
    fn later_blocks_observe_earlier_stores() {
        let mut image = core::array::from_fn::<_, 256, _>(|i| i as u8);
        assert!(apply(Member::W96, &mut image, 0, 0, 128, 32, 1, 0).is_some());
        for i in 0..96 {
            assert_eq!(image[32 + i], (i % 32) as u8);
        }
    }
    #[test]
    fn unselected_span_and_global_image_bounds_are_required() {
        let mut image = [7; 64];
        let before = image;
        assert_eq!(apply(Member::W32, &mut image, 0, 0, 64, 0, 1, 0), None);
        let base = u64::MAX - 31;
        assert_eq!(
            apply(Member::W32, &mut image, base, base, base, base, 1, 0),
            None
        );
        assert_eq!(image, before);
    }
}
