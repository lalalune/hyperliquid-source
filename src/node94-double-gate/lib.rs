//! Safe integer-only value projection of node94 [0x5028a40, 0x5028a5b).
#![no_std]
#![forbid(unsafe_code)]

/// The only comparison-control bits needed for this fixed normal 1.0 operand.
/// These booleans describe original execution; they do not change host MXCSR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompareMode {
    pub invalid_masked: bool,
    pub denormal_masked: bool,
    pub denormals_are_zero: bool,
}

/// New refusals, not reconstructed original fault/exception returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    ImageRange,
    PointerField,
    Payload,
    InvalidOperationUnmasked,
    DenormalOperandUnmasked,
}

fn word(image: &[u8], image_base: u64, address: u64) -> Option<u64> {
    let offset = usize::try_from(address.checked_sub(image_base)?).ok()?;
    let end = offset.checked_add(8)?;
    Some(u64::from_le_bytes(image.get(offset..end)?.try_into().ok()?))
}

/// Read object+0xf38, then the pointed eight bytes, and project full RAX.
///
/// The image is stable ordinary memory with a nonwrapping numeric range.
/// Object/payload addresses are numeric metadata, not Rust pointers. On an
/// admitted normal comparison only the low byte of the payload pointer is
/// overwritten. Status flags, XMM state, handlers and original ABI are omitted.
pub fn compare(
    image: &[u8],
    image_base: u64,
    object: u64,
    mode: CompareMode,
) -> Result<u64, Refusal> {
    if u128::from(image_base) + image.len() as u128 > (1u128 << 64) {
        return Err(Refusal::ImageRange);
    }
    let pointer =
        word(image, image_base, object.wrapping_add(0xf38)).ok_or(Refusal::PointerField)?;
    let bits = word(image, image_base, pointer).ok_or(Refusal::Payload)?;
    let magnitude = bits & 0x7fff_ffff_ffff_ffff;
    let nan = magnitude > 0x7ff0_0000_0000_0000;
    let denormal = magnitude != 0 && magnitude < 0x0010_0000_0000_0000;
    if nan && !mode.invalid_masked {
        return Err(Refusal::InvalidOperationUnmasked);
    }
    if denormal && !mode.denormals_are_zero && !mode.denormal_masked {
        return Err(Refusal::DenormalOperandUnmasked);
    }
    let gate = (0x3ff0_0000_0000_0000..=0x7ff0_0000_0000_0000).contains(&bits);
    Ok((pointer & !0xff) | u64::from(gate))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(bits: u64) -> [u8; 128] {
        let mut bytes = [0; 128];
        bytes[16..24].copy_from_slice(&0x1050u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&bits.to_le_bytes());
        bytes
    }
    fn masked() -> CompareMode {
        CompareMode {
            invalid_masked: true,
            denormal_masked: true,
            denormals_are_zero: false,
        }
    }

    #[test]
    fn full_pointer_prefix_and_exact_one() {
        assert_eq!(
            compare(&image(0x3fefffffffffffff), 0x1000, 0xd8, masked()),
            Ok(0x1000)
        );
        assert_eq!(
            compare(&image(0x3ff0000000000000), 0x1000, 0xd8, masked()),
            Ok(0x1001)
        );
        assert_eq!(
            compare(&image(0x7ff0000000000000), 0x1000, 0xd8, masked()),
            Ok(0x1001)
        );
    }

    #[test]
    fn comisd_rejects_both_nan_classes() {
        let unmasked = CompareMode {
            invalid_masked: false,
            ..masked()
        };
        for bits in [0x7ff0000000000001, 0x7ff8000000000000, 0xfff8000000000000] {
            assert_eq!(
                compare(&image(bits), 0x1000, 0xd8, unmasked),
                Err(Refusal::InvalidOperationUnmasked)
            );
            assert_eq!(compare(&image(bits), 0x1000, 0xd8, masked()), Ok(0x1000));
        }
    }

    #[test]
    fn denormal_modes_and_required_memory() {
        let unmasked = CompareMode {
            denormal_masked: false,
            ..masked()
        };
        assert_eq!(
            compare(&image(1), 0x1000, 0xd8, unmasked),
            Err(Refusal::DenormalOperandUnmasked)
        );
        assert_eq!(
            compare(
                &image(1),
                0x1000,
                0xd8,
                CompareMode {
                    denormals_are_zero: true,
                    ..unmasked
                }
            ),
            Ok(0x1000)
        );
        assert_eq!(compare(&image(0), 0x1000, 0xd8, unmasked), Ok(0x1000));
        assert_eq!(
            compare(&image(1)[..80], 0x1000, 0xd8, unmasked),
            Err(Refusal::Payload)
        );
    }
}
