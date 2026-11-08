#![no_std]
#![forbid(unsafe_code)]
//! Safe value projection of the one per-field 0xb0-byte element builder.

pub const ELEMENT_BYTES: usize = 0xb0;
pub const PRODUCT_SCALE: u64 = 100_000_000_000_000;

pub fn build_element(source_tail: &[u8; 32]) -> [u8; ELEMENT_BYTES] {
    let mut element = [0; ELEMENT_BYTES];
    element[0x58..0x60].copy_from_slice(&PRODUCT_SCALE.to_le_bytes());
    element[0x78..0x80].copy_from_slice(&PRODUCT_SCALE.to_le_bytes());
    element[0x80..0xa0].copy_from_slice(source_tail);
    element
}

#[cfg(test)]
mod tests {
    use super::{ELEMENT_BYTES, PRODUCT_SCALE, build_element};

    #[test]
    fn frozen_builder_fields() {
        let mut source = [0; 32];
        for (index, byte) in source.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let element = build_element(&source);
        assert_eq!(element.len(), ELEMENT_BYTES);
        assert_eq!(&element[0x40..0x48], &[0; 8]);
        assert_eq!(&element[0x58..0x60], &PRODUCT_SCALE.to_le_bytes());
        assert_eq!(&element[0x60..0x68], &[0; 8]);
        assert_eq!(&element[0x78..0x80], &PRODUCT_SCALE.to_le_bytes());
        assert_eq!(&element[0x80..0xa0], &source);
    }

    #[test]
    fn builder_does_not_write_other_fields() {
        let element = build_element(&[0xff; 32]);
        for (offset, byte) in element.iter().enumerate() {
            if !matches!(offset, 0x58..=0x5f | 0x78..=0x9f) {
                assert_eq!(*byte, 0, "offset {offset:#x}");
            }
        }
    }
}
