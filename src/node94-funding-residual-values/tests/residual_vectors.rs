use node94_funding_residual_values::*;

fn address(last: u8) -> Address {
    let mut raw = [0; 20];
    raw[19] = last;
    Address(raw)
}
fn record(fill: u8, marker: u32) -> Record {
    let mut raw = [fill; 72];
    raw[60..64].copy_from_slice(&marker.to_le_bytes());
    Record(raw)
}
fn summary(key: u8, total: i64, selection: Option<(u64, u64)>) -> Summary {
    Summary {
        address: address(key),
        total,
        selection: selection.map(|(asset, magnitude)| Selection { asset, magnitude }),
        records: Vec::new(),
    }
}
fn state(mode: u32, balance: i64, margin: i64, size: i64) -> State {
    let position = Position {
        raw_mode: mode,
        leverage: 3,
        margin,
        size,
    };
    State {
        users: [(
            address(1),
            User {
                cross_balance: balance,
                position_count: 1,
                positions: [(7, position)].into(),
            },
        )]
        .into(),
        users_with_positions: [address(1)].into(),
        ..State::default()
    }
}

#[test]
fn empty_is_a_complete_identity() {
    let mut s = state(1, 50, 60, i64::MIN);
    let before = s.clone();
    assert_eq!(
        apply_supplied_summaries(Vec::new(), &mut s),
        Ok(Applied {
            total: 0,
            winner: None,
            records: Vec::new()
        })
    );
    assert_eq!(s, before);
}

#[test]
fn ordered_saturation_is_not_input_order_or_final_clamp() {
    let mut s = State::default();
    let out = apply_supplied_summaries(
        vec![
            summary(3, -1, None),
            summary(2, 1, None),
            summary(1, i64::MAX, None),
        ],
        &mut s,
    )
    .unwrap();
    assert_eq!(out.total, i64::MAX - 1);
    assert_eq!(s, State::default());
    let out = apply_supplied_summaries(
        vec![
            summary(1, i64::MIN, None),
            summary(2, -1, None),
            summary(3, 1, None),
        ],
        &mut s,
    )
    .unwrap();
    assert_eq!(out.total, i64::MIN + 1);
}

#[test]
fn unsigned_max_and_first_tie_include_zero() {
    let mut s = state(0, 10, 20, 0);
    let out = apply_supplied_summaries(
        vec![
            summary(2, 0, Some((8, 1))),
            summary(1, 1, Some((7, 1_u64 << 63))),
        ],
        &mut s,
    )
    .unwrap();
    assert_eq!(out.winner.unwrap().address, address(1));
    let mut s = state(0, 10, 20, 0);
    let out = apply_supplied_summaries(
        vec![summary(2, 0, Some((8, 0))), summary(1, 1, Some((7, 0)))],
        &mut s,
    )
    .unwrap();
    assert_eq!(
        out.winner,
        Some(Winner {
            address: address(1),
            asset: 7,
            magnitude: 0
        })
    );
    assert_eq!(s.users[&address(1)].cross_balance, 9);
}

#[test]
fn marker_is_exact_u32_and_suffix_is_per_inner_vector() {
    let mut first = summary(1, 0, None);
    first.records = vec![record(9, 0x100), record(8, 0), record(7, 1)];
    let mut second = summary(2, 0, None);
    second.records = vec![record(6, 1), record(5, 0), record(4, 1)];
    let out = apply_supplied_summaries(vec![second, first], &mut State::default()).unwrap();
    assert_eq!(out.records, vec![record(9, 0x100), record(6, 1)]);
}

#[test]
fn only_raw_mode_one_debits_margin() {
    for mode in [0, 1, 2, u32::MAX] {
        let mut s = state(mode, 10, 20, -5);
        let before = s.clone();
        apply_supplied_summaries(vec![summary(1, 3, Some((7, 4)))], &mut s).unwrap();
        let user = &s.users[&address(1)];
        assert_eq!(user.cross_balance, if mode == 1 { 10 } else { 7 });
        assert_eq!(user.positions[&7].margin, if mode == 1 { 17 } else { 20 });
        assert_eq!(user.positions[&7].size, -5);
        assert_eq!(user.positions[&7].leverage, 3);
        assert_eq!(user.position_count, 1);
        assert_eq!(s.users_with_positions, before.users_with_positions);
        assert!(s.aru.contains(&address(1)));
        assert_eq!(s.auxiliary, [(7, 0)].into());
    }
}

#[test]
fn debit_saturates_both_directions() {
    for mode in [0, 1] {
        for (old, total, expected) in [
            (i64::MIN, 1, i64::MIN),
            (i64::MAX, -1, i64::MAX),
            (i64::MIN, i64::MIN, 0),
            (-1, i64::MIN, i64::MAX),
            (i64::MAX, i64::MAX, 0),
        ] {
            let mut s = state(mode, old, old, 1);
            apply_supplied_summaries(vec![summary(1, total, Some((7, 1)))], &mut s).unwrap();
            let user = &s.users[&address(1)];
            assert_eq!(
                if mode == 1 {
                    user.positions[&7].margin
                } else {
                    user.cross_balance
                },
                expected
            );
        }
    }
}

#[test]
fn auxiliary_equal_size_is_not_identity() {
    for size in [1, -1, i64::MAX, -i64::MAX] {
        let mut s = state(1, 9, 10, size);
        s.auxiliary.insert(7, i64::MIN);
        apply_supplied_summaries(vec![summary(1, 1, Some((7, 3)))], &mut s).unwrap();
        assert_eq!(
            s.auxiliary[&7],
            if size == 1 || size == -1 {
                i64::MIN + 1
            } else {
                -1
            }
        );
    }
}

#[test]
fn auxiliary_zero_size_still_inserts_and_other_keys_survive() {
    let mut s = state(1, 9, 10, 0);
    s.auxiliary.insert(8, i64::MIN);
    apply_supplied_summaries(vec![summary(1, 1, Some((7, 1)))], &mut s).unwrap();
    assert_eq!(s.auxiliary, [(7, 0), (8, i64::MIN)].into());
}

#[test]
fn inactive_paths_never_require_selected_state() {
    let mut s = State::default();
    let out = apply_supplied_summaries(vec![summary(1, 0, Some((7, u64::MAX)))], &mut s).unwrap();
    assert!(out.winner.is_some());
    let out = apply_supplied_summaries(vec![summary(1, i64::MAX, None)], &mut s).unwrap();
    assert_eq!(out.total, i64::MAX);
    assert_eq!(s, State::default());
    let mut s = state(1, 9, 10, i64::MIN);
    let before = s.clone();
    apply_supplied_summaries(vec![summary(1, 0, Some((7, 1)))], &mut s).unwrap();
    assert_eq!(s, before);
}

#[test]
fn typed_errors_preserve_state_and_duplicate_precedes_lookup() {
    let mut s = State::default();
    let duplicate = vec![summary(1, 1, Some((7, 1))), summary(1, 0, None)];
    assert_eq!(
        apply_supplied_summaries(duplicate, &mut s),
        Err(Error::DuplicateSummary)
    );
    assert_eq!(
        apply_supplied_summaries(vec![summary(1, 1, Some((7, 1)))], &mut s),
        Err(Error::MissingUser)
    );
    assert_eq!(s, State::default());
    let mut s = state(1, 9, 10, i64::MIN);
    let before = s.clone();
    assert_eq!(
        apply_supplied_summaries(vec![summary(1, 1, Some((8, 1)))], &mut s),
        Err(Error::MissingPosition)
    );
    assert_eq!(s, before);
    assert_eq!(
        apply_supplied_summaries(vec![summary(1, 1, Some((7, 1)))], &mut s),
        Err(Error::SizeMagnitude)
    );
    assert_eq!(s, before);
}

#[test]
fn all_represented_unselected_state_is_preserved() {
    let mut s = state(0, 100, i64::MIN, 2);
    s.users.insert(
        address(9),
        User {
            cross_balance: i64::MIN,
            position_count: u64::MAX,
            positions: [(
                99,
                Position {
                    raw_mode: u32::MAX,
                    leverage: u32::MAX,
                    margin: i64::MIN,
                    size: i64::MIN,
                },
            )]
            .into(),
        },
    );
    s.users.get_mut(&address(1)).unwrap().positions.insert(
        8,
        Position {
            raw_mode: 1,
            leverage: 2,
            margin: 3,
            size: i64::MIN,
        },
    );
    s.aru.insert(address(8));
    s.users_with_positions.insert(address(7));
    s.auxiliary.insert(99, i64::MAX);
    let mut expected = s.clone();
    expected.users.get_mut(&address(1)).unwrap().cross_balance = 93;
    expected.aru.insert(address(1));
    expected.auxiliary.insert(7, 0);
    apply_supplied_summaries(vec![summary(1, 7, Some((7, 0)))], &mut s).unwrap();
    assert_eq!(s, expected);
}

#[test]
fn count_admission_uses_native_provenance_not_rust_layout() {
    let limit = i64::MAX as u64;
    assert_eq!(checked_counts(limit / 104, limit / 72), Ok(()));
    assert_eq!(checked_counts(limit / 104 + 1, 0), Err(Error::Span));
    assert_eq!(checked_counts(0, limit / 72 + 1), Err(Error::Span));
    assert_eq!(checked_counts(u64::MAX, u64::MAX), Err(Error::Span));
    assert_eq!(checked_counts(0, 0), Ok(()));
}

#[test]
fn frozen_case_c000001_debits_minimum_by_minimum() {
    // Exact first nonempty pre-Rust case; full records are opaque.
    let hex = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52dd010000006b86b273ff34fce1";
    let mut raw = [0; 72];
    for (i, byte) in raw.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    let row = Record(raw);
    let mut input = summary(1, i64::MIN, Some((7, 1)));
    input.records.push(row.clone());
    let mut s = state(0, i64::MIN, i64::MIN, 1);
    let mut expected_state = s.clone();
    expected_state
        .users
        .get_mut(&address(1))
        .unwrap()
        .cross_balance = 0;
    expected_state.auxiliary.insert(7, 0);
    expected_state.aru.insert(address(1));
    let out = apply_supplied_summaries(vec![input], &mut s).unwrap();
    assert_eq!(
        out,
        Applied {
            total: i64::MIN,
            winner: Some(Winner {
                address: address(1),
                asset: 7,
                magnitude: 1
            }),
            records: vec![row]
        }
    );
    assert_eq!(s, expected_state);
}
