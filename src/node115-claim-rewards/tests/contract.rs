use node115_claim_rewards::{Fault, Metadata, Outcome, Row, claim};
use std::collections::BTreeMap;

fn run(rows: &mut [Row], meta: &[Metadata]) -> Result<Outcome, Fault> {
    let key = [1; 20];
    let mut users = BTreeMap::from([(key, rows.to_vec())]);
    let out = claim(&mut users, &key, meta);
    rows.copy_from_slice(&users[&key]);
    out
}

#[test]
fn status_and_mutation_order() {
    let meta = [
        Metadata {
            decimals: 2,
            width: 4,
        },
        Metadata {
            decimals: 2,
            width: 5,
        },
        Metadata {
            decimals: 2,
            width: 4,
        },
    ];
    assert_eq!(
        claim(&mut BTreeMap::new(), &[1; 20], &[]).unwrap().status,
        0xaa
    );
    let mut rows = [
        Row {
            key: 0,
            pending: 0,
            claimed: 4,
        },
        Row {
            key: 1,
            pending: 99_999_999,
            claimed: 7,
        },
        Row {
            key: 2,
            pending: 100_000_000,
            claimed: u64::MAX - 2,
        },
    ];
    let out = run(&mut rows, &meta).unwrap();
    assert_eq!(out.status, 0x1a2);
    assert_eq!(out.claims, [(2, 100_000_000)]);
    assert_eq!(rows[1].pending, 99_999_999);
    assert_eq!((rows[2].pending, rows[2].claimed), (0, u64::MAX));
    let mut rejected = [Row {
        key: 1,
        pending: 1,
        claimed: 0,
    }];
    assert_eq!(run(&mut rejected, &meta).unwrap().status, 0xab);
    let mut after_success = [
        Row {
            key: 0,
            pending: 100_000_000,
            claimed: 0,
        },
        Row {
            key: 1,
            pending: 1,
            claimed: 0,
        },
    ];
    assert_eq!(run(&mut after_success, &meta).unwrap().status, 0x1a2);
    let mut users = BTreeMap::from([(
        [1; 20],
        vec![Row {
            key: 0,
            pending: 100_000_000,
            claimed: 0,
        }],
    )]);
    let mut other = [1; 20];
    other[19] = 2;
    assert_eq!(claim(&mut users, &other, &meta).unwrap().status, 0xaa);
    assert_eq!(users[&[1; 20]][0].pending, 100_000_000);
}

#[test]
fn fault_keeps_earlier_writes() {
    let meta = [Metadata {
        decimals: 0,
        width: 0,
    }];
    let mut rows = [
        Row {
            key: 0,
            pending: 100_000_000,
            claimed: 1,
        },
        Row {
            key: 9,
            pending: 1,
            claimed: 2,
        },
    ];
    assert_eq!(run(&mut rows, &meta), Err(Fault::MissingMetadata));
    assert_eq!((rows[0].pending, rows[0].claimed), (0, 100_000_001));
    assert_eq!((rows[1].pending, rows[1].claimed), (1, 2));
    let mut bad = [Row {
        key: 0,
        pending: 1,
        claimed: 0,
    }];
    assert_eq!(
        run(
            &mut bad,
            &[Metadata {
                decimals: 20,
                width: 0
            }]
        ),
        Err(Fault::InvalidExponent)
    );
}

#[test]
fn wide_quotient_and_boundaries() {
    for exp in 0..=19 {
        let meta = [
            Metadata {
                decimals: 0,
                width: 0,
            },
            Metadata {
                decimals: 0,
                width: exp,
            },
        ];
        let wide = 100_000_000u128 * 10u128.pow(u32::from(exp));
        let floor = u64::try_from(wide).ok();
        for amount in [
            1,
            floor.unwrap_or(u64::MAX).saturating_sub(1),
            floor.unwrap_or(u64::MAX),
            u64::MAX,
        ] {
            if amount == 0 {
                continue;
            }
            let mut row = [Row {
                key: 1,
                pending: amount,
                claimed: 0,
            }];
            let out = run(&mut row, &meta).unwrap();
            assert_eq!(out.status == 0x1a2, floor.is_some_and(|f| amount >= f));
        }
    }
}

#[test]
fn independent_integer_cases() {
    for line in include_str!("reference-vectors.txt").lines() {
        let fields: Vec<u64> = line
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        let meta = [
            Metadata {
                decimals: 0,
                width: fields[1] as u8,
            },
            Metadata {
                decimals: fields[0] as u8,
                width: fields[2] as u8,
            },
        ];
        let mut rows = [Row {
            key: 1,
            pending: fields[3],
            claimed: fields[4],
        }];
        let out = run(&mut rows, &meta).unwrap();
        let success = fields[5] == 1;
        assert_eq!(
            out.status,
            if success {
                0x1a2
            } else if fields[3] == 0 {
                0xaa
            } else {
                0xab
            }
        );
        assert_eq!(rows[0].pending, if success { 0 } else { fields[3] });
        assert_eq!(
            rows[0].claimed,
            if success {
                fields[4].saturating_add(fields[3])
            } else {
                fields[4]
            }
        );
    }
}
