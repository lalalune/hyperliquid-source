#![cfg(feature = "checkpoint-hash")]

use node94_tcp_frame::checkpoint_hash::{compute, encode_records};
use node94_tcp_frame::greeting::reply::FixedRecord;
use std::{fs, path::Path};

fn records(first: u64, second: u64) -> [FixedRecord; 3] {
    std::array::from_fn(|record| FixedRecord {
        first,
        second,
        bytes: std::array::from_fn(|i| (i.wrapping_mul(17) + record * 71) as u8),
    })
}

// These explicit encodings follow the target's integer width branches. They do
// not call a test-side encoder that could repeat an implementation mistake.
const BOUNDARIES: &[(u64, &[u8])] = &[
    (0, &[0]),
    (1, &[1]),
    (127, &[0x7f]),
    (128, &[0xcc, 0x80]),
    (255, &[0xcc, 0xff]),
    (256, &[0xcd, 0x01, 0x00]),
    (65535, &[0xcd, 0xff, 0xff]),
    (65536, &[0xce, 0x00, 0x01, 0x00, 0x00]),
    (0x1234_5678, &[0xce, 0x12, 0x34, 0x56, 0x78]),
    (u32::MAX as u64, &[0xce, 0xff, 0xff, 0xff, 0xff]),
    (
        1 << 32,
        &[0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
    ),
    (
        0x0123_4567_89ab_cdef,
        &[0xcf, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
    ),
    (
        u64::MAX,
        &[0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ),
];

#[test]
fn complete_wire_bytes_cover_integer_boundaries_and_all_hash_bytes() {
    for &(first, first_wire) in BOUNDARIES {
        for &(second, second_wire) in BOUNDARIES {
            let input = records(first, second);
            let mut expected = vec![0x83];
            for (key, record) in [
                b"\xadaccounts_hash".as_slice(),
                b"\xaecontracts_hash".as_slice(),
                b"\xacstorage_hash".as_slice(),
            ]
            .into_iter()
            .zip(&input)
            {
                expected.extend_from_slice(key);
                expected.extend_from_slice(b"\x83\xaan_elements");
                expected.extend_from_slice(first_wire);
                expected.extend_from_slice(b"\xa7n_bytes");
                expected.extend_from_slice(second_wire);
                expected.extend_from_slice(b"\xa4hash\xc5\x08\x00");
                expected.extend_from_slice(&record.bytes);
            }
            let actual = encode_records(&input);
            assert_eq!(actual, expected, "first={first}, second={second}");
            assert_eq!(
                actual.len(),
                6271 + 3 * (first_wire.len() + second_wire.len())
            );
        }
    }
}

#[test]
fn records_keep_their_assigned_outer_key_order() {
    let mut input = records(0, 0);
    let original = encode_records(&input);
    input.swap(0, 1);
    let swapped = encode_records(&input);
    assert_ne!(original, swapped);

    // With one-byte counters each value is 2,078 bytes. Its payload starts
    // after the outer key and the record's 30-byte map/counter/bin header.
    for (record, payload_at) in [(0, 45), (1, 2138), (2, 4229)] {
        assert_eq!(
            &original[payload_at..payload_at + 2048],
            &records(0, 0)[record].bytes
        );
        assert_eq!(
            &swapped[payload_at..payload_at + 2048],
            &input[record].bytes
        );
    }
}

#[test]
fn zero_counters_do_not_shorten_the_raw_hash() {
    let input = records(0, 0);
    assert_eq!(encode_records(&input).len(), 6277);
    let mut changed = input.clone();
    for record in 0..3 {
        changed[record].bytes[2047] ^= 1;
        assert_ne!(
            compute(b"canonical prefix", &input),
            compute(b"canonical prefix", &changed)
        );
        changed[record].bytes[2047] ^= 1;
    }
}

#[test]
fn prefix_and_every_record_component_affect_the_digest() {
    let input = records(17, 256);
    let prefix = b"\x00already serialized\xffstate";
    let baseline = compute(prefix, &input);
    assert_ne!(baseline, compute(b"", &input));
    assert_ne!(
        baseline,
        compute(b"\x00already serialized\xffstatf", &input)
    );

    for record in 0..3 {
        let mut changed = input.clone();
        changed[record].first += 1;
        assert_ne!(baseline, compute(prefix, &changed));
        changed = input.clone();
        changed[record].second += 1;
        assert_ne!(baseline, compute(prefix, &changed));
        for offset in [0, 1024, 2047] {
            changed = input.clone();
            changed[record].bytes[offset] ^= 1;
            assert_ne!(baseline, compute(prefix, &changed));
        }
    }
    let mut changed = input;
    changed.swap(0, 2);
    assert_ne!(baseline, compute(prefix, &changed));
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "fixture hex must have whole bytes");
    (0..input.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&input[offset..offset + 2], 16).unwrap())
        .collect()
}

#[test]
fn independently_frozen_messagepack_and_blake3_corpus() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../research/work-items/RE-012-checkpoint-hash-94/fixtures");
    let cases = fs::read_to_string(directory.join("cases.tsv")).unwrap();
    let mut count = 0;
    for line in cases
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 6, "fixture row has six fields");
        let name = fields[0];
        let prefix = decode_hex(fields[1]);
        let values: Vec<u64> = fields[2]
            .split(',')
            .map(|value| value.parse().unwrap())
            .collect();
        let seeds: Vec<u8> = fields[3]
            .split(',')
            .map(|value| value.parse().unwrap())
            .collect();
        assert_eq!(values.len(), 6, "{name}: six counters");
        assert_eq!(seeds.len(), 3, "{name}: three byte seeds");
        let input = std::array::from_fn(|record| FixedRecord {
            first: values[record * 2],
            second: values[record * 2 + 1],
            bytes: std::array::from_fn(|i| ((i * 17) + usize::from(seeds[record]) * 31) as u8),
        });
        let expected_wire = fs::read(directory.join(fields[5])).unwrap();
        assert_eq!(
            encode_records(&input),
            expected_wire,
            "{name}: full encoding"
        );
        let expected_digest: [u8; 32] = decode_hex(fields[4]).try_into().unwrap();
        assert_eq!(compute(&prefix, &input), expected_digest, "{name}: digest");
        count += 1;
    }
    assert_eq!(count, 13, "all frozen cases must run");
}
