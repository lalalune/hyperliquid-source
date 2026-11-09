use node115_funding_premium::{Book, Config, Fault, Level, Market, Slot, impact, premium};
use std::collections::{BTreeMap, BTreeSet};

fn book<'a>(levels: &'a [Level], orders: &'a [Slot]) -> Book<'a> {
    Book { levels, orders }
}
fn one(price: i64) -> [Level; 1] {
    [Level {
        signed_price: price,
        head: Some(0),
    }]
}

#[test]
fn links_partial_fill_and_failure_sentinels() {
    let orders = [
        Slot::Order {
            quantity: 3,
            next: Some(1),
        },
        Slot::Order {
            quantity: 4,
            next: Some(99),
        },
        Slot::Vacant,
    ];
    assert_eq!(impact(book(&one(-10), &orders), 65), Ok(10));
    assert_eq!(impact(book(&one(10), &orders), 71), Ok(0));
    assert_eq!(impact(book(&one(10), &orders), 0), Ok(0));
    assert_eq!(
        impact(book(&one(0), &orders), 0),
        Err(Fault::ZeroPriceDivision)
    );
    assert_eq!(impact(book(&one(0), &orders), 1), Ok(0));
    assert_eq!(impact(book(&one(10), &[Slot::Vacant]), 1), Ok(0));
    assert_eq!(
        impact(
            book(
                &[Level {
                    signed_price: 1,
                    head: None
                }],
                &orders
            ),
            1
        ),
        Ok(0)
    );
    assert_eq!(
        impact(
            book(
                &[Level {
                    signed_price: 1,
                    head: Some(99)
                }],
                &orders
            ),
            1
        ),
        Ok(0)
    );
    assert_eq!(
        impact(
            book(
                &one(10),
                &[Slot::Order {
                    quantity: 1,
                    next: Some(0)
                }]
            ),
            1
        ),
        Err(Fault::CyclicChain)
    );
    let levels = [
        Level {
            signed_price: -10,
            head: Some(0),
        },
        Level {
            signed_price: 20,
            head: Some(2),
        },
    ];
    let slots = [
        Slot::Order {
            quantity: 1,
            next: Some(1),
        },
        Slot::Vacant,
        Slot::Order {
            quantity: 5,
            next: None,
        },
    ];
    // 10 notional + floor((31-10)/20)=1 unit at 20 -> floor(30/2)=15.
    assert_eq!(impact(book(&levels, &slots), 31), Ok(15));
}

#[test]
fn zero_price_before_positive_level_and_signed_cap() {
    let levels = [
        Level {
            signed_price: 0,
            head: Some(0),
        },
        Level {
            signed_price: 10,
            head: Some(1),
        },
    ];
    let slots = [
        Slot::Order {
            quantity: 2,
            next: None,
        },
        Slot::Order {
            quantity: 3,
            next: None,
        },
    ];
    assert_eq!(impact(book(&levels, &slots), 30), Ok(6));
    let quantity = [Slot::Order {
        quantity: 1,
        next: None,
    }];
    assert_eq!(
        impact(book(&one(i64::MAX - 1), &quantity), (i64::MAX - 1) as u64),
        Ok((i64::MAX - 1) as u64)
    );
    assert_eq!(impact(book(&one(i64::MAX), &quantity), 1), Ok(0));
    assert_eq!(impact(book(&one(i64::MIN), &quantity), 1), Ok(0));
    let saturating = [
        Slot::Order {
            quantity: u64::MAX,
            next: Some(1),
        },
        Slot::Order {
            quantity: 1,
            next: None,
        },
    ];
    assert_eq!(impact(book(&one(1), &saturating), 1), Ok(0));
}

#[test]
fn metadata_oracle_and_two_helper_order() {
    let overrides = BTreeMap::new();
    let divided = BTreeSet::new();
    let config = Config {
        default_notional: 0,
        notional_overrides: &overrides,
        divide_by_hundred: &divided,
        impact_mode: true,
    };
    let one_order = [Slot::Order {
        quantity: 1,
        next: None,
    }];
    let empty = book(&[], &[]);
    let bad_levels = one(0);
    let bad = book(&bad_levels, &one_order);
    assert_eq!(
        premium(
            0,
            0,
            Market {
                dex: 1,
                decimals: &[6]
            },
            config,
            empty,
            bad
        ),
        Err(Fault::Market)
    );
    assert_eq!(
        premium(
            0,
            0,
            Market {
                dex: 0,
                decimals: &[7]
            },
            config,
            empty,
            bad
        ),
        Err(Fault::Decimals)
    );
    assert_eq!(
        premium(
            0,
            0,
            Market {
                dex: 0,
                decimals: &[6]
            },
            config,
            empty,
            bad
        ),
        Ok(None)
    );
    // An empty first book does not suppress the second helper's division fault.
    assert_eq!(
        premium(
            0,
            1,
            Market {
                dex: 0,
                decimals: &[6]
            },
            config,
            empty,
            bad
        ),
        Err(Fault::ZeroPriceDivision)
    );
}

#[test]
fn per_asset_override_divides_before_clamp() {
    let mut overrides = BTreeMap::new();
    overrides.insert(10000, 100);
    let mut divided = BTreeSet::new();
    divided.insert(10000);
    let config = Config {
        default_notional: 0,
        notional_overrides: &overrides,
        divide_by_hundred: &divided,
        impact_mode: true,
    };
    let slots = [Slot::Order {
        quantity: 100,
        next: None,
    }];
    let levels = one(10);
    let p = premium(
        10000,
        1,
        Market {
            dex: 1,
            decimals: &[6],
        },
        config,
        book(&levels, &slots),
        book(&levels, &slots),
    )
    .unwrap()
    .unwrap();
    assert_eq!(p.first_impact, 10);
    assert_eq!(p.second_impact, 10);
    assert_eq!(p.value.to_bits(), 0.09f64.to_bits());
}

#[test]
fn flattened_book_and_exact_binary64_reference() {
    let mut count = 0;
    for line in include_str!("reference-vectors.txt")
        .lines()
        .filter(|s| !s.starts_with('#'))
    {
        let c: Vec<_> = line.split_whitespace().collect();
        let n: Vec<u64> = c[..19].iter().map(|x| x.parse().unwrap()).collect();
        let make = |start: usize| {
            let mut levels = Vec::new();
            let mut slots = Vec::new();
            for k in 0..3 {
                let price = n[start + 2 * k] as i64;
                let q = n[start + 2 * k + 1];
                let head = slots.len();
                levels.push(Level {
                    signed_price: if k % 2 == 0 { -price } else { price },
                    head: Some(head),
                });
                slots.push(Slot::Order {
                    quantity: q / 2,
                    next: Some(head + 1),
                });
                slots.push(Slot::Order {
                    quantity: q - q / 2,
                    next: None,
                });
            }
            (levels, slots)
        };
        let (a, ao) = make(5);
        let (b, bo) = make(11);
        let overrides = BTreeMap::new();
        let mut divided = BTreeSet::new();
        if n[2] != 0 {
            divided.insert(0);
        }
        let config = Config {
            default_notional: n[4],
            notional_overrides: &overrides,
            divide_by_hundred: &divided,
            impact_mode: n[1] != 0,
        };
        let result = premium(
            0,
            n[3],
            Market {
                dex: 0,
                decimals: &[n[0] as u8],
            },
            config,
            book(&a, &ao),
            book(&b, &bo),
        )
        .unwrap();
        if c[19] == "none" {
            assert_eq!(result, None, "case {count}");
        } else {
            let p = result.unwrap();
            assert_eq!(
                (p.first_impact, p.second_impact),
                (n[17], n[18]),
                "case {count}"
            );
            assert_eq!(
                p.value.to_bits(),
                u64::from_str_radix(c[19], 16).unwrap(),
                "case {count}"
            );
        }
        count += 1;
    }
    assert_eq!(count, 10000);
}
