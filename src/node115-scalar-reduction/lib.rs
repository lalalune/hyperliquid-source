//! Value contract of node #115 helpers at 0x6321680 and 0x6330f50.
//! This safe API does not reproduce the original pointer ABI or alias behavior.

/// Four little-endian u64 limbs and the pre-reduction overflow flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReducedScalar {
    pub limbs: [u64; 4],
    pub overflow: bool,
}

/// Read a big-endian 256-bit integer and reduce it modulo the observed order.
///
/// Zero is accepted. `overflow` means the input was at least the order;
/// it does not mean invalid input or a signature-verification failure.
pub fn reduce_be(input: &[u8; 32]) -> ReducedScalar {
    const ORDER: [u64; 4] = [
        0xbfd2_5e8c_d036_4141,
        0xbaae_dce6_af48_a03b,
        0xffff_ffff_ffff_fffe,
        0xffff_ffff_ffff_ffff,
    ];
    let mut original = [0u64; 4];
    for (i, limb) in original.iter_mut().enumerate() {
        let offset = 24 - 8 * i;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&input[offset..offset + 8]);
        *limb = u64::from_be_bytes(bytes);
    }
    let mut difference = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (partial, first_borrow) = original[i].overflowing_sub(ORDER[i]);
        let (value, second_borrow) = partial.overflowing_sub(u64::from(borrow));
        difference[i] = value;
        borrow = first_borrow || second_borrow;
    }
    ReducedScalar {
        limbs: if borrow { original } else { difference },
        overflow: !borrow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64);
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn target_expression_boundaries_and_every_input_bit() {
        // Frozen decoded-instruction expressions, separately checked with
        // Python's arbitrary-precision remainder. This is not a target run.
        let corpus = include_str!(
            "../../research/work-items/RE-001-node115-scalar-reduction/observed/boundaries.tsv"
        );
        let mut count = 0;
        for row in corpus.lines().skip(1) {
            let fields: Vec<_> = row.split('\t').collect();
            assert_eq!(fields.len(), 3);
            let result = reduce_be(&bytes(fields[0]));
            let mut actual = [0u8; 32];
            for (chunk, limb) in actual.chunks_exact_mut(8).zip(result.limbs) {
                chunk.copy_from_slice(&limb.to_le_bytes());
            }
            assert_eq!(actual, bytes(fields[1]), "{}", fields[0]);
            assert_eq!(result.overflow, fields[2] == "1", "{}", fields[0]);
            count += 1;
        }
        assert_eq!(count, 281);
    }
}
