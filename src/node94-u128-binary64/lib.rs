#![no_std]
#![forbid(unsafe_code)]

/// Return nearest-even binary64 bits for every unsigned128 integer.
///
/// Integer-only numerical projection of the proven node94 leaf. This does not
/// claim its original calling convention or physical register side effects.
#[inline(never)]
pub const fn binary64_bits(n: u128) -> u64 {
    if n == 0 {
        return 0;
    }

    // Determine the integer binade without any floating conversion.
    let mut exponent = 0_u32;
    let mut probe = n;
    while probe > 1 {
        probe >>= 1;
        exponent += 1;
    }

    let mut significand: u64;
    if exponent <= 52 {
        significand = (n as u64) << (52 - exponent);
    } else {
        let discarded_bits = exponent - 52;
        let retained = n >> discarded_bits;
        let residue = n - (retained << discarded_bits);
        let halfway = 1_u128 << (discarded_bits - 1);
        significand = retained as u64;
        if residue > halfway || (residue == halfway && significand & 1 != 0) {
            significand += 1;
        }
    }

    if significand == 1_u64 << 53 {
        significand >>= 1;
        exponent += 1;
    }
    (((exponent as u64) + 1023) << 52) | (significand & ((1_u64 << 52) - 1))
}

#[cfg(test)]
mod tests {
    use super::binary64_bits;

    #[test]
    fn independent_pre_source_twenty_vectors() {
        let mut count = 0;
        for line in include_str!("unit-vectors.tsv").lines() {
            let mut fields = line.split('|');
            let id = fields.next().unwrap();
            let n = u128::from_str_radix(fields.next().unwrap(), 16).unwrap();
            let expected = u64::from_str_radix(fields.next().unwrap(), 16).unwrap();
            assert!(fields.next().is_none());
            assert_eq!(binary64_bits(n), expected, "case {id}");
            count += 1;
        }
        assert_eq!(count, 20);
    }
}
