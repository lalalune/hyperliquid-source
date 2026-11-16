use node115_greeting_encoder::*;
use std::collections::BTreeMap;
const BOUNDS: [u64; 8] = [
    0,
    250,
    251,
    65535,
    65536,
    u32::MAX as u64,
    1 << 32,
    u64::MAX,
];
fn sig(seed: usize) -> Signature {
    let mut s = [0; 65];
    for i in 0..8 {
        s[i * 8..i * 8 + 8].copy_from_slice(&BOUNDS[(seed + i) % 8].to_le_bytes());
    }
    s[64] = (seed * 31) as u8;
    s
}
fn map(keys: &[u8], seed: usize, ring: bool, head: usize) -> SigMap {
    let logical: Vec<_> = keys
        .iter()
        .map(|&key| SigRow {
            key: [key; 20],
            sig: sig(seed + key as usize),
        })
        .collect();
    if !ring {
        return SigMap::Tree(
            logical
                .into_iter()
                .map(|r| (r.key, r.sig))
                .collect::<BTreeMap<_, _>>(),
        );
    }
    let cap = keys.len() + 3;
    let mut rows: Vec<_> = (0..cap)
        .map(|_| SigRow {
            key: [255; 20],
            sig: [255; 65],
        })
        .collect();
    for (i, row) in logical.into_iter().enumerate() {
        rows[(head + i) % cap] = row;
    }
    // Same valid sorted logical entries at every physical ring rotation.
    SigMap::Ring {
        rows,
        head,
        len: keys.len(),
    }
}
fn input(kind: &str, seed: usize, modes: usize, head: usize) -> Greeting {
    if kind == "summary" {
        return Greeting::Kind1 {
            at_18: BOUNDS[seed % 8],
            at_8: BOUNDS[(seed + 1) % 8],
            at_10: BOUNDS[(seed + 2) % 8],
        };
    }
    let detail = match kind {
        "vectors" => Detail::Signatures {
            first: [seed as u8; 32],
            left: vec![sig(seed), sig(seed + 1)],
            right: vec![sig(seed + 2)],
            last: [seed as u8 + 1; 32],
        },
        "maps" => Detail::Maps {
            first: [seed as u8; 32],
            left: map(&[1, 3, 7], seed, modes & 1 != 0, head % 6),
            right: map(&[2, 4], seed, modes & 2 != 0, head % 5),
            last: [seed as u8 + 1; 32],
        },
        "fixed" => Detail::Fixed(Box::new(std::array::from_fn(|i| FixedPart {
            at_800: BOUNDS[(seed + i) % 8],
            at_808: BOUNDS[(seed + i + 3) % 8],
            bytes: std::array::from_fn(|j| (j + i + seed) as u8),
        }))),
        _ => panic!("unknown fixture"),
    };
    Greeting::Kind0 {
        blob: (0..[0, 1, 250, 251][seed % 4])
            .map(|i| (i + seed) as u8)
            .collect(),
        at_98: BOUNDS[seed % 8],
        detail: Box::new(detail),
    }
}
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn independent_schema_fixtures_all_variants_and_map_representations() {
    let mut count = 0;
    for line in include_str!("schema.tsv")
        .lines()
        .filter(|x| !x.starts_with('#'))
    {
        let cols: Vec<_> = line.split('\t').collect();
        let seed = cols[1].parse().unwrap();
        let expected = unhex(cols[2]);
        for modes in 0..4 {
            for head in 0..30 {
                assert_eq!(
                    encode(&input(cols[0], seed, modes, head)).unwrap(),
                    expected,
                    "{} seed={seed} modes={modes} head={head}",
                    cols[0]
                );
            }
        }
        count += 1;
    }
    assert_eq!(count, 26);
}
#[test]
fn empty_children_have_counts_and_unit_variants_have_no_payload() {
    for (value, tag) in [
        (Greeting::Kind2, 2),
        (Greeting::Kind3, 3),
        (Greeting::Kind4, 4),
        (Greeting::Kind5, 5),
    ] {
        assert_eq!(encode(&value).unwrap(), vec![tag]);
    }
    for detail in [
        Detail::Signatures {
            first: [0; 32],
            left: vec![],
            right: vec![],
            last: [0; 32],
        },
        Detail::Maps {
            first: [0; 32],
            left: SigMap::Tree(BTreeMap::new()),
            right: SigMap::Tree(BTreeMap::new()),
            last: [0; 32],
        },
    ] {
        let mut expected = vec![0; 70];
        expected[3] = if matches!(detail, Detail::Maps { .. }) {
            1
        } else {
            0
        };
        assert_eq!(
            encode(&Greeting::Kind0 {
                blob: vec![],
                at_98: 0,
                detail: Box::new(detail)
            })
            .unwrap(),
            expected
        );
    }
}
#[test]
fn recovery_byte_is_raw_and_not_validated_or_integer_encoded() {
    for recovery in 0..=255u8 {
        let mut s = [0; 65];
        s[64] = recovery;
        let out = encode(&Greeting::Kind0 {
            blob: vec![],
            at_98: 0,
            detail: Box::new(Detail::Signatures {
                first: [0; 32],
                left: vec![s],
                right: vec![],
                last: [0; 32],
            }),
        })
        .unwrap();
        assert_eq!(out.len(), 79);
        assert_eq!(out[45], recovery);
    }
}
