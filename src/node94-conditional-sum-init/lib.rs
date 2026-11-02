#![no_std]
#![forbid(unsafe_code)]
//! Complete node94 [0x5475e80,0x5475ead) value and output-image projection.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rsi: u64,
    pub rdx: u64,
}

/// Write all four qwords from raw entry RSI/RDX values. Only low32 RDX is
/// sign-extended for the arithmetic; full RDX remains in the observation.
/// Destination32 must fit one nonwrapping numeric image. None leaves it unchanged.
pub fn initialize(
    image: &mut [u8],
    base: u64,
    destination: u64,
    incoming_rsi: u64,
    incoming_rdx: u64,
) -> Option<Registers> {
    if u128::from(base) + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    let start = usize::try_from(destination.checked_sub(base)?).ok()?;
    if start.checked_add(32)? > image.len() {
        return None;
    }
    let extended = incoming_rdx as u32 as i32 as i64 as u64;
    let total = incoming_rsi.wrapping_add(extended);
    let fields = [0, total, 0, extended];
    for (i, value) in fields.iter().enumerate() {
        image[start + 8 * i..start + 8 * i + 8].copy_from_slice(&value.to_le_bytes());
    }
    Some(Registers {
        rax: 1,
        rsi: total,
        rdx: incoming_rdx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negative_low_dword_and_wrapping_sum() {
        let mut image = [0xa5; 32];
        let r = initialize(&mut image, 0, 0, 0, 0x12345678ffffffff).unwrap();
        assert_eq!(
            r,
            Registers {
                rax: 1,
                rsi: u64::MAX,
                rdx: 0x12345678ffffffff
            }
        );
        assert_eq!(&image[..8], &[0; 8]);
        assert_eq!(&image[8..16], &[255; 8]);
        assert_eq!(&image[16..24], &[0; 8]);
        assert_eq!(&image[24..], &[255; 8]);
    }
    #[test]
    fn high_only_rdx_preserves_rsi_and_full_rdx() {
        let mut image = [0xff; 32];
        let r = initialize(&mut image, 0, 0, 91, 1 << 63).unwrap();
        assert_eq!(r.rsi, 91);
        assert_eq!(r.rdx, 1 << 63);
        assert_eq!(&image[24..], &[0; 8]);
    }
    #[test]
    fn unaligned_exact_end_and_atomic_refusal() {
        let mut image = [0x55; 33];
        initialize(&mut image, u64::MAX - 32, u64::MAX - 31, 2, 3).unwrap();
        assert_eq!(image[0], 0x55);
        let before = image;
        assert!(initialize(&mut image, 0, 2, 7, 8).is_none());
        assert_eq!(image, before);
    }
}
