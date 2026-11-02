#![no_std]
#![forbid(unsafe_code)]
//! Complete node94 [0x53cf560,0x53cf57e) value and memory projection.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}

fn offset(image: &[u8], base: u64, address: u64, width: usize) -> Option<usize> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    (start.checked_add(width)? <= image.len()).then_some(start)
}

/// Snapshot the pointer, set the four-byte field to one, then conditionally
/// clear one pointed byte. Every valid alias preserves that store order.
/// Numeric addresses are values, never host pointers. None leaves all bytes
/// unchanged and does not reproduce an original partial-fault execution.
pub fn apply(image: &mut [u8], base: u64, object: u64, incoming_rdx: u64) -> Option<Registers> {
    if u128::from(base) + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    let source = offset(image, base, object.wrapping_add(0x1a0), 8)?;
    let pointer = u64::from_le_bytes(image[source..source + 8].try_into().ok()?);
    let flag = offset(image, base, object.wrapping_add(0x108), 4)?;
    let clear = if pointer == 0 {
        None
    } else {
        Some(offset(image, base, pointer, 1)?)
    };
    image[flag..flag + 4].copy_from_slice(&1u32.to_le_bytes());
    if let Some(at) = clear {
        image[at] = 0;
    }
    Some(Registers {
        rax: pointer,
        rdx: incoming_rdx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(pointer: u64) -> ([u8; 512], u64) {
        let mut image = [0xaa; 512];
        image[300..308].copy_from_slice(&pointer.to_le_bytes());
        (image, 300u64.wrapping_sub(0x1a0))
    }
    #[test]
    fn clear_overwrites_new_flag_and_preserves_pointer_snapshot() {
        let (mut image, object) = fixture(148);
        let r = apply(&mut image, 0, object, 19).unwrap();
        assert_eq!(&image[148..152], &[0; 4]);
        assert_eq!(r, Registers { rax: 148, rdx: 19 });
        let (mut image, object) = fixture(300);
        let r = apply(&mut image, 0, object, 0).unwrap();
        assert_eq!(r.rax, 300);
        assert_eq!(image[300], 0);
        assert_eq!(image[301], 1);
    }
    #[test]
    fn null_pointer_skips_mapped_address_zero() {
        let (mut image, object) = fixture(0);
        assert_eq!(apply(&mut image, 0, object, 0).unwrap().rax, 0);
        assert_eq!(image[0], 0xaa);
        assert_eq!(&image[148..152], &[1, 0, 0, 0]);
    }
    #[test]
    fn missing_clear_refuses_before_flag_store() {
        let (mut image, object) = fixture(512);
        let before = image;
        assert!(apply(&mut image, 0, object, 0).is_none());
        assert_eq!(image, before);
    }
}
