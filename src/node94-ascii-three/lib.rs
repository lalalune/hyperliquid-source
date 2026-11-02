//! Value reconstruction of node94 ELF VA 0x151a4a0..0x151a52f.
#![no_std]
#![forbid(unsafe_code)]

fn fold(byte: u8) -> u8 {
    if (b'A'..=b'Z').contains(&byte) {
        byte + 32
    } else {
        byte
    }
}

/// Compare three bytes under ASCII letter case folding, gated by raw length.
///
/// All u64 lengths and byte values are admitted. The target reads no bytes
/// when length differs from three and otherwise stops after the first unequal
/// pair. These safe snapshots describe stable ordinary input memory; they do
/// not reproduce pointer faults, timing, volatile reads or an original ABI.
pub fn equal(length: u64, left: &[u8; 3], right: &[u8; 3]) -> bool {
    if length != 3 {
        return false;
    }
    for position in 0..3 {
        if fold(left[position]) != fold(right[position]) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::equal;

    #[test]
    fn ascii_letters_only() {
        assert!(equal(3, b"AzZ", b"aZz"));
        assert!(!equal(3, b"@[\\", b"`{|"));
        assert!(equal(3, &[0, 128, 255], &[0, 128, 255]));
        assert!(!equal(3, &[0, 128, 255], &[0, 160, 255]));
    }

    #[test]
    fn full_length_and_each_position() {
        for length in [0, 2, 4, 259, (1_u64 << 32) + 3, u64::MAX] {
            assert!(!equal(length, b"ABC", b"abc"));
        }
        for right in [b"xbc", b"axc", b"abx"] {
            assert!(!equal(3, b"ABC", right));
        }
    }
}
