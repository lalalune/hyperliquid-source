#![no_std]
#![forbid(unsafe_code)]
//! Complete node94 conditional two-hop read, without converting numeric fields
//! into host pointers. Only the selected terminal field needs to be mapped.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}

fn word(image: &[u8], base: u64, address: u64) -> Option<u64> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = start.checked_add(8)?;
    Some(u64::from_le_bytes(image.get(start..end)?.try_into().ok()?))
}

/// `image` models stable bytes at [base, base + len), with endpoint at most
/// 2^64. Field addresses wrap modulo 2^64; each reached qword must fit wholly
/// in the image. None is a new safe refusal, not an original return or fault.
/// Zero numeric roots are accepted whenever the reached fields are mapped.
pub fn load(image: &[u8], base: u64, object: u64) -> Option<Registers> {
    if u128::from(base) + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    let first = word(image, base, object.wrapping_add(8))?;
    let second = word(image, base, first.wrapping_add(0x1e0))?;
    let value = if second == 0 {
        word(image, base, first.wrapping_add(0x178))?
    } else {
        word(image, base, second.wrapping_add(8))?
    };
    Some(Registers {
        rax: value,
        rdx: first,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(image: &mut [u8], at: usize, value: u64) {
        image[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn complete_registers_and_wrapped_entry() {
        let mut image = [0; 512];
        let first = 128u64.wrapping_sub(0x1e0);
        put(&mut image, 0, first);
        put(&mut image, 128, 168);
        put(&mut image, 176, 0x87654321fedcba98);
        assert_eq!(
            load(&image, 0, u64::MAX - 7),
            Some(Registers {
                rax: 0x87654321fedcba98,
                rdx: first
            })
        );
    }

    #[test]
    fn unused_terminal_need_not_be_mapped() {
        let mut image = [0; 512];
        put(&mut image, 0, 0x1000 + 128 - 0x1e0);
        put(&mut image, 24, 71);
        assert_eq!(load(&image[..136], 0x1000, 0xff8).unwrap().rax, 71);
        put(&mut image, 0, 16u64.wrapping_sub(0x1e0));
        put(&mut image, 16, 168);
        put(&mut image, 176, 93);
        assert_eq!(load(&image, 0, u64::MAX - 7).unwrap().rax, 93);
    }

    #[test]
    fn mapped_zero_first_pointer_is_valid() {
        let mut image = [0; 512];
        put(&mut image, 376, 0x1122334455667788);
        let result = load(&image, 0, 8).unwrap();
        assert_eq!(result.rdx, 0);
        assert_eq!(result.rax, 0x1122334455667788);
        assert!(load(&image[..487], 0, 8).is_none());
    }
}
