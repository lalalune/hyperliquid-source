#![no_std]
#![forbid(unsafe_code)]
//! Safe logical projection of the node115 storage-key suffix builder.
//! This is not the original Rust ABI or a complete JSON-RPC adapter.

extern crate alloc;

use alloc::vec::Vec;

pub const ADDRESS_BYTES: usize = 20;
pub const SLOT_BYTES: usize = 32;
pub const STORAGE_KEY_SUFFIX_BYTES: usize = 52;

/// Build the selected 52-byte address-and-slot suffix.
///
/// `limbs` are the four source-order qwords loaded from the adapter. The
/// native path byte-swaps each qword and writes limbs 3, 2, 1, 0 after the
/// address. Allocation and the caller-supplied key prefix are outside this
/// bounded relation.
pub fn storage_key_suffix(
    address: &[u8; ADDRESS_BYTES],
    limbs: [u64; 4],
) -> [u8; STORAGE_KEY_SUFFIX_BYTES] {
    let mut suffix = [0; STORAGE_KEY_SUFFIX_BYTES];
    suffix[..ADDRESS_BYTES].copy_from_slice(address);
    for (chunk, limb) in suffix[ADDRESS_BYTES..]
        .chunks_exact_mut(8)
        .zip(limbs.iter().rev())
    {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    suffix
}

/// Compose the caller's dynamic prefix with the selected suffix.
///
/// The native path builds the suffix first and then joins it to a separately
/// allocated prefix. The concrete runtime prefix and allocator behavior are
/// not established by this projection.
pub fn build_storage_key(prefix: &[u8], address: &[u8; ADDRESS_BYTES], limbs: [u64; 4]) -> Vec<u8> {
    let suffix = storage_key_suffix(address, limbs);
    let mut key = Vec::with_capacity(prefix.len() + STORAGE_KEY_SUFFIX_BYTES);
    key.extend_from_slice(prefix);
    key.extend_from_slice(&suffix);
    key
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{build_storage_key, storage_key_suffix};
    use std::string::String;
    use std::vec::Vec;

    fn decode_hex(value: &str) -> Vec<u8> {
        assert!(
            value.len().is_multiple_of(2),
            "odd-length hex field: {value}"
        );
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn reverses_source_limbs_as_big_endian_words() {
        let address = [0x11; 20];
        let limbs = [
            0x0001_0203_0405_0607,
            0x0809_0a0b_0c0d_0e0f,
            0x1011_1213_1415_1617,
            0x1819_1a1b_1c1d_1e1f,
        ];
        let suffix = storage_key_suffix(&address, limbs);

        assert_eq!(&suffix[..20], &address);
        assert_eq!(
            &suffix[20..],
            &[
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
            ]
        );
    }

    #[test]
    fn composes_dynamic_prefix_without_normalizing_it() {
        let address = [0xa5; 20];
        let limbs = [1, 2, 3, 4];
        let suffix = storage_key_suffix(&address, limbs);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x00prefix\xff");
        expected.extend_from_slice(&suffix);

        assert_eq!(
            build_storage_key(b"\x00prefix\xff", &address, limbs),
            expected
        );
    }

    #[test]
    fn all_node115_key_vectors() {
        let text =
            include_str!("../../research/work-items/RE-011-storage-read-115/key-vectors.tsv");
        let mut rows = 0;
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 5, "malformed key vector: {line}");
            let address_bytes = decode_hex(fields[1]);
            let address: [u8; 20] = address_bytes.as_slice().try_into().unwrap();
            let limb_fields: Vec<&str> = fields[2].split(',').collect();
            assert_eq!(limb_fields.len(), 4, "malformed limbs: {line}");
            let mut limbs = [0; 4];
            for (limb, field) in limbs.iter_mut().zip(limb_fields) {
                assert_eq!(field.len(), 16, "malformed limb width: {line}");
                *limb = u64::from_str_radix(field, 16).unwrap();
            }

            let suffix = storage_key_suffix(&address, limbs);
            assert_eq!(encode_hex(&suffix), fields[3], "suffix mismatch: {line}");

            let prefix = decode_hex("4573");
            let full_key = build_storage_key(&prefix, &address, limbs);
            assert_eq!(
                encode_hex(&full_key),
                fields[4],
                "full-key mismatch: {line}"
            );
            rows += 1;
        }
        assert_eq!(rows, 258);
    }

    fn encode_hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write;
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }
}
