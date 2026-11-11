use node115_leverage_aggregate::*;
use std::collections::BTreeMap;
#[test]
fn independent_integer_reference() {
    let mut counts = [0; 3];
    for (case, line) in include_str!("reference.tsv").lines().enumerate() {
        let v: Vec<_> = line.split('\t').collect();
        assert_eq!(v.len(), 14);
        let user_key = [5; 20];
        let queried_user = if v[0] == "1" { user_key } else { [6; 20] };
        let asset = if v[1] == "1" { 10001 } else { 1 };
        let row = Row {
            price: v[3].parse().unwrap(),
            side_values: [v[4].parse().unwrap(), v[5].parse().unwrap()],
            side_quantities: [v[6].parse().unwrap(), v[7].parse().unwrap()],
            size: v[8].parse().unwrap(),
            leverage: v[9].parse().unwrap(),
        };
        let unrelated = Row {
            price: 1,
            side_values: [7, 8],
            side_quantities: [2, 3],
            size: 1,
            leverage: 2,
        };
        let mut users = BTreeMap::from([(
            user_key,
            User {
                assets: BTreeMap::from([(10001, row.clone()), (u64::MAX, unrelated.clone())]),
                aggregate: v[2].parse().unwrap(),
            },
        )]);
        let result = update(&mut users, &queried_user, asset, v[10].parse().unwrap());
        let expected = match v[11] {
            "ok" => {
                counts[0] += 1;
                Ok(())
            }
            "oldzero" => {
                counts[1] += 1;
                Err(Fault::OldLeverageZero)
            }
            "newzero" => {
                counts[2] += 1;
                Err(Fault::NewLeverageZero)
            }
            _ => panic!(),
        };
        assert_eq!(result, expected, "result case{case}");
        assert_eq!(
            users[&user_key].aggregate,
            v[12].parse::<u64>().unwrap(),
            "aggregate case{case}"
        );
        let mut expected_row = row;
        expected_row.leverage = v[13].parse().unwrap();
        assert_eq!(
            users[&user_key].assets[&10001], expected_row,
            "row case{case}"
        );
        assert_eq!(users[&user_key].assets[&u64::MAX], unrelated);
        assert_eq!(users.len(), 1);
        assert_eq!(users[&user_key].assets.len(), 2);
    }
    assert_eq!(counts.iter().sum::<usize>(), 12000);
    assert!(counts.iter().all(|&n| n > 100));
}
fn run(row: Row, aggregate: u64, new: u32) -> (Result<(), Fault>, User) {
    let mut users = BTreeMap::from([(
        [0; 20],
        User {
            assets: BTreeMap::from([(1, row)]),
            aggregate,
        },
    )]);
    let result = update(&mut users, &[0; 20], 1, new);
    (result, users.remove(&[0; 20]).unwrap())
}
#[test]
fn directional_selection_and_two_separate_saturations() {
    let row = Row {
        price: 10,
        side_values: [100, 1000],
        side_quantities: [10, 100],
        size: 1,
        leverage: 2,
    };
    // opposite average10, remaining qty98 and value980 =>selected980.
    let (result, user) = run(row.clone(), 1, 1);
    assert_eq!(result, Ok(()));
    assert_eq!(user.aggregate, 980);
    let (_, user) = run(row, u64::MAX, 1);
    assert_eq!(user.aggregate, u64::MAX);
}
#[test]
fn zero_size_uses_nonpositive_side_and_division_fault_write_order() {
    let row = Row {
        price: u64::MAX,
        side_values: [9, 30],
        side_quantities: [0, 0],
        size: 0,
        leverage: 3,
    };
    let (_, user) = run(row.clone(), 100, 2);
    assert_eq!(user.aggregate, 105);
    let (result, user) = run(row.clone(), 100, 0);
    assert_eq!(result, Err(Fault::NewLeverageZero));
    assert_eq!(user.aggregate, 100);
    assert_eq!(user.assets[&1].leverage, 0);
    let mut zero = row;
    zero.leverage = 0;
    let (result, user) = run(zero.clone(), 100, 3);
    assert_eq!(result, Err(Fault::OldLeverageZero));
    assert_eq!(user.assets[&1].leverage, 0);
    assert_eq!(run(zero, 100, 0).0, Ok(()));
}
