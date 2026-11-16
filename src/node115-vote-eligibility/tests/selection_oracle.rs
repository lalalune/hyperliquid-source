use node115_vote_eligibility::{Address, History, Key, KeySet, Lookup, Snapshot};

fn key(n: u8) -> Key {
    let mut x = [0; 32];
    x[31] = n;
    x
}
fn address(n: u8) -> Address {
    let mut x = [0; 20];
    x[19] = n;
    x
}
fn inner(entries: &[(Key, Address)], use_ring: bool, head: usize) -> KeySet {
    if !use_ring {
        return KeySet::Tree(entries.iter().copied().collect());
    }
    let capacity = entries.len() + 2;
    let mut physical = vec![(key(255), address(255)); capacity];
    for (i, row) in entries.iter().enumerate() {
        physical[(head + i) % capacity] = *row;
    }
    KeySet::ring(physical, head, entries.len()).unwrap()
}

#[test]
fn all_representations_and_rotations_match_a_linear_exact_selection_oracle() {
    // Every key/address differs only at the final byte. Padding deliberately matches
    // a query, but is not a live row. IDs exercise both endpoints and an interior gap.
    let logical = [
        (
            0,
            vec![
                (key(0), address(1)),
                (key(2), address(1)),
                (key(8), address(2)),
            ],
        ),
        (8, vec![]),
        (u64::MAX, vec![(key(5), address(3)), (key(9), address(3))]),
    ];
    for outer_ring in [false, true] {
        for inner_ring in [false, true] {
            for outer_head in 0..5 {
                for inner_head_seed in 0..5 {
                    let rows: Vec<_> = logical
                        .iter()
                        .map(|(id, entries)| {
                            (
                                *id,
                                inner(entries, inner_ring, inner_head_seed % (entries.len() + 2)),
                            )
                        })
                        .collect();
                    let history = if outer_ring {
                        let mut physical =
                            vec![(7, inner(&[(key(255), address(255))], false, 0)); 5];
                        for (i, row) in rows.iter().enumerate() {
                            physical[(outer_head + i) % 5] = row.clone();
                        }
                        History::ring(physical, outer_head, 3).unwrap()
                    } else {
                        History::Tree(rows.into_iter().collect())
                    };
                    for selector in [0, 1, 7, 8, 9, u64::MAX - 1, u64::MAX] {
                        let snapshot = Snapshot {
                            selector,
                            history: history.clone(),
                        };
                        let expected_row = logical.iter().find(|(id, _)| *id == selector);
                        for n in [0, 1, 2, 3, 4, 255] {
                            let wanted = address(n);
                            let expected = match expected_row {
                                None => Lookup::MissingHistory,
                                Some((_, entries)) => {
                                    let mut result = Lookup::MissingAddress;
                                    for (k, a) in entries {
                                        if *a == wanted {
                                            result = Lookup::Found(*k);
                                        }
                                    }
                                    result
                                }
                            };
                            assert_eq!(snapshot.key_for_address(&wanted), expected);
                            if let Lookup::Found(k) = expected {
                                assert!(snapshot.eligible(&k));
                            }
                        }
                        for n in 0..=255 {
                            let wanted = key(n);
                            let expected = expected_row.is_some_and(|(_, entries)| {
                                entries.iter().any(|(k, _)| *k == wanted)
                            });
                            assert_eq!(snapshot.eligible(&wanted), expected);
                        }
                    }
                }
            }
        }
    }
}
