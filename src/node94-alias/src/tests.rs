use super::{alias10, AliasFeed};

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
