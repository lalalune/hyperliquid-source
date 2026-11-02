//! Returned-value reconstruction of node94 ELF VA 0x4b27620..0x4b27669.
#![no_std]
#![forbid(unsafe_code)]

fn folded_product(left: u64, right: u64) -> u64 {
    let product = u128::from(left) * u128::from(right);
    (product as u64) ^ ((product >> 64) as u64)
}

/// Mix a prefix word, twenty bytes and two explicit runtime seed snapshots.
///
/// The target reads overlapping little-endian qwords at offsets 0, 4, 8, 12.
/// All supplied bit patterns are admitted. This safe value API assumes stable
/// ordinary input memory and does not reproduce its pointers or global seed
/// initialization. Only the returned RAX value is projected, not scratch RDX.
pub fn mix(prefix: u64, data: &[u8; 20], seeds: [u64; 2]) -> u64 {
    let read = |offset: usize| {
        u64::from_le_bytes(
            data[offset..offset + 8]
                .try_into()
                .expect("fixed read bounds"),
        )
    };
    let first = folded_product(read(8) ^ seeds[1], read(12) ^ seeds[0]);
    let second = folded_product(read(0) ^ prefix, read(4) ^ seeds[0]);
    folded_product(first ^ second ^ 20, seeds[0])
}

#[cfg(test)]
mod tests {
    use super::{folded_product, mix};

    #[test]
    fn observed_sample_and_zero_seed() {
        let data = core::array::from_fn(|i| i as u8);
        assert_eq!(
            mix(
                0x0706_0504_0302_0100,
                &data,
                [0xdead_beef_cafe_f00d, 0x1234_5678_9abc_def0]
            ),
            0x9c4e_42a7_cec1_1b69
        );
        assert_eq!(mix(u64::MAX, &data, [0, u64::MAX]), 0);
        assert_eq!(mix(0, &[0; 20], [1, 0]), 20);
    }

    #[test]
    fn product_high_half_is_observable() {
        assert_eq!(folded_product(1 << 63, 2), 1);
        assert_eq!(folded_product(u64::MAX, u64::MAX), u64::MAX);
    }
}
