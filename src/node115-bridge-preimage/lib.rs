//! Selected bridge builder's complete 64-byte preimage and bounded inner digest.
//! Input fields are opaque bytes already produced by the native caller.
#![no_std]
#![forbid(unsafe_code)]

/// Exact selected two-word encoding: twelve zero bytes, input20, then input32.
pub fn preimage(input20: &[u8; 20], input32: &[u8; 32]) -> [u8; 64] {
    let mut bytes = [0; 64];
    bytes[12..32].copy_from_slice(input20);
    bytes[32..64].copy_from_slice(input32);
    bytes
}

/// Hash the selected preimage with the native rate136/suffix1/output32 relation.
/// This bounded function does not implement general streaming or signing.
pub fn inner_digest(input20: &[u8; 20], input32: &[u8; 32]) -> [u8; 32] {
    let mut block = [0u8; 200];
    block[..64].copy_from_slice(&preimage(input20, input32));
    block[64] = 1;
    block[135] = 0x80;
    let mut lanes = [0u64; 25];
    for (lane, bytes) in lanes.iter_mut().zip(block.chunks_exact(8)) {
        *lane = u64::from_le_bytes(bytes.try_into().expect("eight-byte lane"));
    }
    node115_bridge_permutation::permute(&mut lanes);
    let mut output = [0; 32];
    for (bytes, lane) in output.chunks_exact_mut(8).zip(lanes) {
        bytes.copy_from_slice(&lane.to_le_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{inner_digest, preimage};
    #[test]
    fn field_order_and_padding() {
        let first = core::array::from_fn(|i| i as u8 + 1);
        let second = core::array::from_fn(|i| 255 - i as u8);
        let bytes = preimage(&first, &second);
        assert_eq!(&bytes[..12], &[0; 12]);
        assert_eq!(&bytes[12..32], &first);
        assert_eq!(&bytes[32..], &second);
    }
    fn decode<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }
    #[test]
    fn independently_generated_openssl_vectors() {
        let mut cases = 0;
        for line in include_str!("tests/openssl-vectors.txt").lines() {
            let mut fields = line.split_whitespace();
            let first = decode::<20>(fields.next().unwrap());
            let second = decode::<32>(fields.next().unwrap());
            let expected_preimage = decode::<64>(fields.next().unwrap());
            let expected_digest = decode::<32>(fields.next().unwrap());
            assert!(fields.next().is_none());
            assert_eq!(preimage(&first, &second), expected_preimage);
            assert_eq!(inner_digest(&first, &second), expected_digest);
            cases += 1;
        }
        assert_eq!(cases, 64);
    }
}
