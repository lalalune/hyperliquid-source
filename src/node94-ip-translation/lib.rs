//! Independently authored, static-evidence-bounded node94 address projection.
//! See README.md for the original packed-word contract and excluded initialization.
#![no_std]

/// Eight ordered records constructed at node94 VA 0x45be020.
/// Each row is four private-side octets followed by four public-side octets.
/// These are historical binary data, not a list of current network endpoints.
pub const CAPTURED_PAIRS: [[u8; 8]; 8] = [
    [172, 31, 8, 148, 43, 206, 47, 239],
    [172, 31, 8, 11, 3, 115, 82, 128],
    [172, 31, 0, 143, 54, 250, 198, 159],
    [172, 31, 5, 30, 54, 64, 115, 135],
    [172, 31, 3, 250, 18, 177, 47, 248],
    [172, 31, 1, 142, 18, 182, 46, 12],
    [172, 31, 14, 167, 43, 206, 157, 116],
    [172, 31, 12, 35, 43, 207, 136, 220],
];

const LOW_FIVE_BYTES: u64 = (1 << 40) - 1;

fn private_prefix(first: u8, second: u8) -> bool {
    first == 10 || (first == 172 && (16..32).contains(&second)) || (first == 192 && second == 168)
}

fn with_pairs(packed: u64, mode: u8, pairs: &[[u8; 8]]) -> u64 {
    let unchanged = packed & LOW_FIVE_BYTES;
    let bytes = packed.to_le_bytes();
    if bytes[0] & 1 != 0 || private_prefix(bytes[1], bytes[2]) == (mode != 0) {
        return unchanged;
    }
    let (key, value) = if mode == 0 { (0, 4) } else { (4, 0) };
    for pair in pairs {
        if bytes[1..5] == pair[key..key + 4] {
            let mapped = u32::from_le_bytes(pair[value..value + 4].try_into().unwrap());
            return u64::from(mapped) << 8;
        }
    }
    unchanged
}

/// Project the helper's returned word after its captured table is initialized.
///
/// Byte 0 is a tag; bytes 1..=4 are IPv4 octets in written order. Higher bytes
/// are discarded. Odd tags bypass translation. Mode zero translates private
/// inputs toward column 1; any nonzero mode translates other inputs toward
/// column 0. A match clears the tag, while a miss preserves its original byte.
///
/// This numeric API is newly chosen. It does not reproduce Rust's original ABI,
/// lazy initialization, allocation, synchronization, or the caller's collection.
pub fn translate_packed(packed: u64, mode: u8) -> u64 {
    with_pairs(packed, mode, &CAPTURED_PAIRS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(tag: u8, octets: &[u8]) -> u64 {
        u64::from(tag) | (u64::from(u32::from_le_bytes(octets.try_into().unwrap())) << 8)
    }

    #[test]
    fn both_directions_for_all_captured_rows_and_mode_bytes() {
        for row in CAPTURED_PAIRS {
            let private = pack(0, &row[..4]);
            let public = pack(0, &row[4..]);
            assert_eq!(translate_packed(private, 0), public);
            assert_eq!(translate_packed(public, 0), public);
            for mode in 1..=255 {
                assert_eq!(translate_packed(private, mode), private);
                assert_eq!(translate_packed(public, mode), private);
            }
        }
    }

    #[test]
    fn every_tag_and_ignored_upper_byte() {
        let row = CAPTURED_PAIRS[0];
        for tag in 0..=255 {
            let input = pack(tag, &row[..4]);
            let expected = if tag & 1 == 0 {
                pack(0, &row[4..])
            } else {
                input
            };
            for high in [0, 1 << 40, 0xabcdef0000000000, 0xffffff0000000000] {
                assert_eq!(translate_packed(input | high, 0), expected);
            }
        }
        // The caller separately recognizes result tag 2. Do not reinterpret it
        // as an IPv6 discriminant: on a miss this helper preserves it.
        assert_eq!(
            translate_packed(pack(2, &[172, 16, 0, 1]), 0),
            pack(2, &[172, 16, 0, 1])
        );
    }

    #[test]
    fn all_first_two_octets_match_the_instruction_mask_partition() {
        // Independent expression of the observed CMP/AND gates: the 172 arm
        // tests the second octet's upper nibble against 0x10.
        for prefix in 0u32..=65535 {
            let first = (prefix >> 8) as u8;
            let second = prefix as u8;
            let from_masks = first == 0x0a
                || (first == 0xac && (second & 0xf0) == 0x10)
                || (first == 0xc0 && second == 0xa8);
            assert_eq!(private_prefix(first, second), from_masks);
        }
    }

    #[test]
    fn forward_and_reverse_search_stop_at_first_matching_row() {
        // Synthetic tables exercise the observed linear loop. The captured
        // table itself has no duplicate column values.
        let forward = [[10, 1, 2, 3, 8, 8, 8, 8], [10, 1, 2, 3, 9, 9, 9, 9]];
        assert_eq!(
            with_pairs(pack(0, &[10, 1, 2, 3]), 0, &forward),
            pack(0, &[8, 8, 8, 8])
        );
        let reverse = [[10, 1, 2, 3, 8, 8, 8, 8], [10, 4, 5, 6, 8, 8, 8, 8]];
        assert_eq!(
            with_pairs(pack(0, &[8, 8, 8, 8]), 1, &reverse),
            pack(0, &[10, 1, 2, 3])
        );
        assert_eq!(
            with_pairs(pack(0, &[10, 1, 2, 3]), 0, &[]),
            pack(0, &[10, 1, 2, 3])
        );
    }

    #[test]
    fn prefix_boundaries_and_no_extra_special_address_rules() {
        for (ip, private) in [
            ([9, 255, 255, 255], false),
            ([10, 0, 0, 0], true),
            ([10, 255, 255, 255], true),
            ([11, 0, 0, 0], false),
            ([172, 15, 255, 255], false),
            ([172, 16, 0, 0], true),
            ([172, 31, 255, 255], true),
            ([172, 32, 0, 0], false),
            ([192, 167, 255, 255], false),
            ([192, 168, 0, 0], true),
            ([192, 168, 255, 255], true),
            ([192, 169, 0, 0], false),
            ([127, 0, 0, 1], false),
            ([169, 254, 1, 2], false),
            ([0, 0, 0, 0], false),
            ([255, 255, 255, 255], false),
        ] {
            let pair = [[ip[0], ip[1], ip[2], ip[3], ip[0], ip[1], ip[2], ip[3]]];
            // A successful table lookup clears this even tag. The opposite
            // direction must bypass the table and preserve it.
            assert_eq!(
                with_pairs(pack(2, &ip), u8::from(!private), &pair),
                pack(0, &ip)
            );
            assert_eq!(
                with_pairs(pack(2, &ip), u8::from(private), &pair),
                pack(2, &ip)
            );
        }
    }
}
