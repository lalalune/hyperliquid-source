//! Safe full-RAX/RDX projection of node94 [0x5172e50, 0x5172e77).
#![no_std]
#![forbid(unsafe_code)]

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

/// Project the self-compare guard and its conditionally reached field chain.
///
/// Byte i represents image_base+i in one nonwrapping numeric memory image.
/// Numeric addresses are not host pointers. The self path requires only the
/// entry field and pointed guard qword; the chain path requires all later reads.
/// None is a new safe refusal, distinct from the valid all-ones return. Stable
/// ordinary memory and normal control are assumed; faults, MMIO, races, flags,
/// control aliases and the original ABI are outside this read-only projection.
pub fn load(image: &[u8], image_base: u64, object: u64) -> Option<Registers> {
    if u128::from(image_base) + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    let pointer = word(image, image_base, object.wrapping_add(8))?;
    let observed = word(image, image_base, pointer)?;
    let value = if observed == pointer {
        u64::MAX
    } else {
        let next = word(image, image_base, pointer.wrapping_add(8))?;
        let field = word(image, image_base, next.wrapping_add(16))?;
        word(image, image_base, field.wrapping_add(0xcb8))?
    };
    Some(Registers {
        rax: value,
        rdx: value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn self_path_does_not_require_the_next_field() {
        let mut image = [0; 24];
        image[..8].copy_from_slice(&16u64.to_le_bytes());
        image[16..].copy_from_slice(&16u64.to_le_bytes());
        assert_eq!(
            load(&image, 0, 0u64.wrapping_sub(8)),
            Some(Registers {
                rax: u64::MAX,
                rdx: u64::MAX
            })
        );
    }
    fn chain() -> [u8; 128] {
        let mut image = [0; 128];
        image[..8].copy_from_slice(&16u64.to_le_bytes());
        image[16..24].copy_from_slice(&(16u64 + (1u64 << 32)).to_le_bytes());
        image[24..32].copy_from_slice(&48u64.to_le_bytes());
        image[64..72].copy_from_slice(&96u64.wrapping_sub(0xcb8).to_le_bytes());
        image[96..104].copy_from_slice(&0x81234567fedcba98u64.to_le_bytes());
        image
    }
    #[test]
    fn full_guard_and_wrapped_deep_address_preserve_both_results() {
        let image = chain();
        assert_eq!(
            load(&image[..104], 0, 0u64.wrapping_sub(8)),
            Some(Registers {
                rax: 0x81234567fedcba98,
                rdx: 0x81234567fedcba98
            })
        );
        assert_eq!(load(&image[..103], 0, 0u64.wrapping_sub(8)), None);
    }
    #[test]
    fn numeric_zero_can_be_a_required_pointer() {
        let mut image = chain();
        image[..8].copy_from_slice(&1u64.to_le_bytes());
        image[8..16].copy_from_slice(&48u64.to_le_bytes());
        image[112..120].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            load(&image, 0, 104),
            Some(Registers {
                rax: 0x81234567fedcba98,
                rdx: 0x81234567fedcba98
            })
        );
    }
}
