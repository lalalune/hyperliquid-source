//! Independently authored encoder for the selected node #115 tag-5 bridge
//! request tuple layout. It does not implement signing or hashing.
#![no_std]
#![forbid(unsafe_code)]

pub const REQUEST_LABEL: &[u8; 17] = b"requestWithdrawal";
pub const ENCODED_LEN: usize = 224;
pub const DYNAMIC_OFFSET: u32 = 160;

/// Encode the observed five-token request shape as seven 32-byte ABI words.
///
/// The 20-byte and 64-bit input widths match the selected native token
/// producers. Their public argument names are intentionally left unresolved.
pub fn encode_request_withdrawal(
    address0: &[u8; 20],
    address1: &[u8; 20],
    scalar0: u64,
    scalar1: u64,
) -> [u8; ENCODED_LEN] {
    let mut out = [0u8; ENCODED_LEN];

    // Five 32-byte head words precede the dynamic string tail.
    out[28..32].copy_from_slice(&DYNAMIC_OFFSET.to_be_bytes());

    // The type-0 paths write twelve zero bytes followed by twenty source bytes.
    out[32 + 12..64].copy_from_slice(address0);
    out[64 + 12..96].copy_from_slice(address1);

    // The type-4 paths byte-swap the populated source qword into the low 8
    // bytes of the 32-byte word; the other 24 bytes are zero.
    out[120..128].copy_from_slice(&scalar0.to_be_bytes());
    out[152..160].copy_from_slice(&scalar1.to_be_bytes());

    // The type-6 path appends a length word followed by the string and zero pad.
    out[188..192].copy_from_slice(&(REQUEST_LABEL.len() as u32).to_be_bytes());
    out[192..209].copy_from_slice(REQUEST_LABEL);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_head_and_dynamic_tail_offsets() {
        let a = [0x11; 20];
        let b = [0x22; 20];
        let out = encode_request_withdrawal(&a, &b, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718);

        assert_eq!(out.len(), 224);
        assert_eq!(&out[28..32], &160u32.to_be_bytes());
        assert_eq!(&out[32..44], &[0; 12]);
        assert_eq!(&out[44..64], &a);
        assert_eq!(&out[64..76], &[0; 12]);
        assert_eq!(&out[76..96], &b);
        assert_eq!(&out[96..120], &[0; 24]);
        assert_eq!(&out[120..128], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&out[128..152], &[0; 24]);
        assert_eq!(&out[152..160], &0x1112_1314_1516_1718u64.to_be_bytes());
        assert_eq!(&out[160..188], &[0; 28]);
        assert_eq!(&out[188..192], &17u32.to_be_bytes());
        assert_eq!(&out[192..209], REQUEST_LABEL);
        assert_eq!(&out[209..224], &[0; 15]);
    }

    #[test]
    fn every_fixed_input_byte_lands_at_its_observed_word_offset() {
        for i in 0..20 {
            let mut a = [0; 20];
            a[i] = 0x80;
            let out = encode_request_withdrawal(&a, &[0; 20], 0, 0);
            assert_eq!(out[44 + i], 0x80);
            assert_eq!(out.iter().filter(|byte| **byte == 0x80).count(), 1);

            let mut b = [0; 20];
            b[i] = 0x80;
            let out = encode_request_withdrawal(&[0; 20], &b, 0, 0);
            assert_eq!(out[76 + i], 0x80);
            assert_eq!(out.iter().filter(|byte| **byte == 0x80).count(), 1);
        }
    }

    #[test]
    fn scalar_bytes_are_big_endian_and_do_not_overlap_adjacent_fields() {
        let out = encode_request_withdrawal(&[0; 20], &[0; 20], u64::MAX, 1);
        assert_eq!(&out[120..128], &[0xff; 8]);
        assert_eq!(&out[152..160], &[0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&out[128..152], &[0; 24]);
    }

    #[test]
    fn zero_inputs_preserve_the_literal_tail() {
        let out = encode_request_withdrawal(&[0; 20], &[0; 20], 0, 0);
        assert_eq!(&out[192..209], b"requestWithdrawal");
        assert_eq!(&out[209..], &[0; 15]);
    }
}
