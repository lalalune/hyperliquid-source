#![no_std]
#![forbid(unsafe_code)]
//! Numeric-image projection of the node94 low32 selector and both closed
//! adjusting tail wrappers. Only the final selected qword is read.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Entry {
    /// 0x552cac0: no initial adjustment.
    Direct,
    /// 0x552b280: add 0x18 before the selector.
    Offset24,
    /// 0x54cbd40: add 0x2998, then enter the add-0x18 wrapper.
    Offset10672,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
}

fn word(image: &[u8], base: u64, address: u64) -> Option<u64> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = start.checked_add(8)?;
    Some(u64::from_le_bytes(image.get(start..end)?.try_into().ok()?))
}

/// Model stable bytes at [base, base + len), whose endpoint is at most 2^64.
/// Object/base metadata and the unused candidate need not be mapped. Only the
/// chosen qword must fit all eight bytes. None is a new safe refusal, not an
/// original return or fault-order model. Numeric addresses are not host pointers.
pub fn load(
    entry: Entry,
    image: &[u8],
    base: u64,
    object: u64,
    selector: u64,
) -> Option<Registers> {
    if u128::from(base) + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    let adjusted = match entry {
        Entry::Direct => object,
        Entry::Offset24 => object.wrapping_add(0x18),
        Entry::Offset10672 => object.wrapping_add(0x2998).wrapping_add(0x18),
    };
    let selected = if selector as u32 == 1 {
        adjusted.wrapping_add(0xe518)
    } else {
        adjusted.wrapping_add(0xec10)
    };
    let value = word(image, base, selected.wrapping_add(0x78))?;
    Some(Registers {
        rax: value,
        rdi: selected,
        rsi: selector,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low32_equality_and_full_rsi() {
        let mut image = [0; 2048];
        image[..8].copy_from_slice(&0x8877665544332211u64.to_le_bytes());
        image[1784..1792].copy_from_slice(&9u64.to_le_bytes());
        let r = load(Entry::Direct, &image, 0xe590, 0, 0x100000001).unwrap();
        assert_eq!(r.rax, 0x8877665544332211);
        assert_eq!(r.rdi, 0xe518);
        assert_eq!(r.rsi, 0x100000001);
        assert_eq!(load(Entry::Direct, &image, 0xe590, 0, 257).unwrap().rax, 9);
    }

    #[test]
    fn both_wrapper_adjustments_wrap() {
        let image = 37u64.to_le_bytes();
        for (entry, object) in [
            (Entry::Direct, 0),
            (Entry::Offset24, 0u64.wrapping_sub(24)),
            (Entry::Offset10672, 0u64.wrapping_sub(0x29b0)),
        ] {
            let r = load(entry, &image, 0xe590, object, 1).unwrap();
            assert_eq!(r.rax, 37);
            assert_eq!(r.rdi, 0xe518);
        }
    }

    #[test]
    fn only_final_qword_is_required() {
        let image = 71u64.to_le_bytes();
        let object = 0u64.wrapping_sub(0xe590);
        let r = load(Entry::Direct, &image, 0, object, 1).unwrap();
        assert_eq!(r.rdi, 0u64.wrapping_sub(120));
        assert_eq!(r.rax, 71);
        assert!(load(Entry::Direct, &image, 0, object, 2).is_none());
        let r = load(Entry::Direct, &image, 120, 0u64.wrapping_sub(0xe518), 1).unwrap();
        assert_eq!(r.rdi, 0);
    }
}
