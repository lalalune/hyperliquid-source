#![no_std]
#![forbid(unsafe_code)]
//! Three complete node94 object-status leaves, including full partial-AL returns.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    ThreeValued,
    PointerFlag,
    CounterGate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}
fn read<const WIDTH: usize>(image: &[u8], base: u64, address: u64) -> Option<[u8; WIDTH]> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    image.get(start..start.checked_add(WIDTH)?)?.try_into().ok()
}
fn byte(image: &[u8], base: u64, object: u64, offset: u64) -> Option<u8> {
    Some(read::<1>(image, base, object.wrapping_add(offset))?[0])
}
fn dword(image: &[u8], base: u64, object: u64, offset: u64) -> Option<u32> {
    Some(u32::from_le_bytes(read(
        image,
        base,
        object.wrapping_add(offset),
    )?))
}

/// Returns full RAX/RDX over stable immutable image bytes. Only reached fields
/// need exist; arbitrary read-role aliases are allowed. None is a new safe range
/// refusal, not target fault behavior. Addresses are numeric metadata. Native ABI,
/// flags, MMIO, races and control/stack aliases are outside this projection.
pub fn evaluate(
    member: Member,
    image: &[u8],
    base: u64,
    object: u64,
    incoming_rdx: u64,
) -> Option<Registers> {
    if u128::from(base) + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    let mut rdx = incoming_rdx;
    let rax = match member {
        Member::ThreeValued => {
            if byte(image, base, object, 0x28a)? != 0 {
                1
            } else {
                2 * u64::from(dword(image, base, object, 0x28c)? == 1)
            }
        }
        Member::PointerFlag => {
            let pointer = u64::from_le_bytes(read(image, base, object.wrapping_add(0x50))?);
            rdx = pointer;
            if pointer == 0 || byte(image, base, pointer, 0x20)? == 0 {
                0
            } else {
                u64::from(byte(image, base, object, 0x289)?)
            }
        }
        Member::CounterGate => {
            if byte(image, base, object, 0x28a)? != 0 {
                0
            } else {
                let mode = byte(image, base, object, 0x290)?;
                if mode != 0 {
                    u64::from(mode)
                } else if byte(image, base, object, 0x289)? == 0 {
                    0
                } else {
                    let a = dword(image, base, object, 0x98)?;
                    let b = dword(image, base, object, 0x9c)?;
                    u64::from(a & 0xffff_ff00) | u64::from(b < a)
                }
            }
        }
    };
    Some(Registers { rax, rdx })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counter_comparison_preserves_the_upper_three_bytes() {
        let mut image = [0u8; 657];
        image[0x289] = 255;
        image[0x98..0x9c].copy_from_slice(&0x1234abcdu32.to_le_bytes());
        image[0x9c..0xa0].copy_from_slice(&0x1234abccu32.to_le_bytes());
        assert_eq!(
            evaluate(Member::CounterGate, &image, 0, 0, 77),
            Some(Registers {
                rax: 0x1234ab01,
                rdx: 77
            })
        );
    }
    #[test]
    fn suppressed_fields_need_not_exist() {
        assert_eq!(
            evaluate(Member::ThreeValued, &[255], 0, 0u64.wrapping_sub(0x28a), 99),
            Some(Registers { rax: 1, rdx: 99 })
        );
        assert_eq!(
            evaluate(Member::PointerFlag, &[0; 8], 80, 0, 99),
            Some(Registers { rax: 0, rdx: 0 })
        );
    }
    #[test]
    fn reached_missing_bytes_and_wrapping_images_refuse() {
        assert_eq!(
            evaluate(Member::ThreeValued, &[0], 0, 0u64.wrapping_sub(0x28a), 99),
            None
        );
        let base = u64::MAX - 1;
        assert_eq!(
            evaluate(
                Member::ThreeValued,
                &[255; 4],
                base,
                base.wrapping_sub(0x28a),
                99
            ),
            None
        );
    }
}
