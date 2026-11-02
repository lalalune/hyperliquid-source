use super::{alias10, inline_carrier, key_hash, AliasFeed};

fn bytes(hex: &str) -> Vec<u8> {
    if hex == "-" {
        return Vec::new();
    }
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// This fixture is regenerated from decoded instruction transfers, not Rust or
/// the independent word model. The Python verifier refuses any changed byte.
const VECTORS: &str = include_str!("../evidence/contract-vectors.txt");

/// Frozen before the inline implementation, from the native two-u64 recurrence.
const INLINE_VECTORS: &str = include_str!("../evidence/inline-carrier-vectors.tsv");

/// Frozen before key_hash was written, from the complete native wrappers.
const KEY_HASH_VECTORS: &str = include_str!("../evidence/key-hash-vectors.tsv");

#[test]
fn key_hash_matches_frozen_borrowed_and_copied_key_results() {
    let mut rows = 0;
    for line in KEY_HASH_VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 5);
        let seed = [
            u64::from_str_radix(fields[1], 16).unwrap(),
            u64::from_str_radix(fields[2], 16).unwrap(),
        ];
        let input = bytes(fields[3]);
        let expected = u64::from_str_radix(fields[4], 16).unwrap();
        assert_eq!(key_hash(seed, &input), expected, "{} borrowed", fields[0]);
        for extra_capacity in [0, 1, 16] {
            let mut copied = Vec::with_capacity(input.len() + extra_capacity);
            copied.extend_from_slice(&input);
            assert_eq!(key_hash(seed, &copied), expected, "{} copied", fields[0]);
        }
        rows += 1;
    }
    assert_eq!(rows, 48);
}

#[test]
fn inline_carrier_matches_frozen_native_halves_and_api_only_refusals() {
    let mut counts = (0, 0);
    for line in INLINE_VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 5);
        let input = bytes(fields[2]);
        let actual = inline_carrier(&input);
        match fields[0] {
            "native" => {
                let carrier = actual.expect(fields[1]);
                assert_eq!(
                    carrier as u64,
                    u64::from_str_radix(fields[3], 16).unwrap(),
                    "{} RAX",
                    fields[1]
                );
                assert_eq!(
                    (carrier >> 64) as u64,
                    u64::from_str_radix(fields[4], 16).unwrap(),
                    "{} RDX",
                    fields[1]
                );
                counts.0 += 1;
            }
            "api" => {
                assert_eq!(actual, None, "{} chosen API refusal", fields[1]);
                counts.1 += 1;
            }
            other => panic!("unknown fixture partition: {other}"),
        }
    }
    assert_eq!(counts, (156, 2));
}

#[test]
fn inline_carrier_has_no_length_field_or_utf8_admission_policy() {
    assert_eq!(inline_carrier(b"A"), inline_carrier(b"A\0"));
    assert_eq!(inline_carrier(&[0xff]), Some(255));
    assert_eq!(inline_carrier(&[]), Some(0));
    assert_eq!(inline_carrier(&[0xff; 16]), Some(u128::MAX));
}

#[test]
fn alias_and_full_counter_hashes_match_instruction_transfers() {
    let mut counts = (0, 0);
    for line in VECTORS.lines().filter(|line| line.starts_with("a|")) {
        let fields: Vec<_> = line.split('|').collect();
        assert_eq!(fields.len(), 4);
        let input = bytes(fields[1]);
        assert_eq!(
            alias10(&input).as_slice(),
            bytes(fields[2]),
            "{}",
            fields[1]
        );
        let hashes: Vec<_> = fields[3].split(',').collect();
        assert_eq!(hashes.len(), 10);
        for (counter, expected) in hashes.iter().enumerate() {
            let mut state = AliasFeed::new();
            state.write(&input);
            state.write(&[0xff]);
            state.write(&(counter as u32).to_le_bytes());
            assert_eq!(state.finish(), u64::from_str_radix(expected, 16).unwrap());
            counts.1 += 1;
        }
        counts.0 += 1;
    }
    assert_eq!(counts, (78, 780));
}

#[test]
fn every_streaming_state_matches_instruction_transfers() {
    let mut counts = (0, 0);
    for line in VECTORS.lines().filter(|line| line.starts_with("f|")) {
        let fields: Vec<_> = line.split('|').collect();
        assert_eq!(fields.len(), 3);
        let chunks: Vec<_> = fields[1].split(',').collect();
        let states: Vec<_> = fields[2].split(';').collect();
        assert_eq!(chunks.len(), 4);
        assert_eq!(states.len(), 4);
        let mut state = AliasFeed::default();
        for (chunk, expected) in chunks.into_iter().zip(states) {
            state.write(&bytes(chunk));
            let expected: Vec<_> = expected
                .split(',')
                .map(|word| u64::from_str_radix(word, 16).unwrap())
                .collect();
            assert_eq!(expected.len(), 7);
            assert_eq!(state.words, expected[..4]);
            assert_eq!(state.length, expected[4]);
            assert_eq!(state.tail, expected[5]);
            assert_eq!(u64::from(state.tail_len), expected[6]);
            counts.1 += 1;
        }
        counts.0 += 1;
    }
    assert_eq!(counts, (264, 1056));
}
