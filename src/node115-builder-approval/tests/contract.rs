use node115_builder_approval::*;
fn address(n: u64) -> Address {
    let mut a = [0; 20];
    a[12..].copy_from_slice(&n.to_be_bytes());
    a
}
#[test]
fn exact_ten_boundary_and_update_rejection() {
    let mut users = Users::new();
    let u = address(1);
    for n in 0..11 {
        assert_eq!(approve(&mut users, u, address(n), 1), Status::Accepted);
    }
    assert_eq!(users[&u].len(), 11);
    assert_eq!(
        approve(&mut users, u, address(0), u64::MAX),
        Status::TooMany
    );
    assert_eq!(users[&u][&address(0)], 1);
    assert_eq!(approve(&mut users, u, address(99), 1), Status::TooMany);
    assert_eq!(approve(&mut users, u, address(0), 0), Status::Accepted);
    assert_eq!(users[&u].len(), 10);
    assert_eq!(
        approve(&mut users, u, address(1), u64::MAX),
        Status::Accepted
    );
    assert_eq!(users[&u][&address(1)], u64::MAX);
    assert_eq!(users[&u].len(), 10);
}
#[test]
fn missing_user_zero_creates_map_and_full_keys_are_distinct() {
    let mut users = Users::new();
    let u = address(1);
    let b = address(2);
    assert_eq!(approve(&mut users, u, b, 0), Status::Accepted);
    assert!(users.contains_key(&u));
    assert!(users[&u].is_empty());
    let mut other = b;
    other[19] ^= 1;
    let mut other_user = u;
    other_user[0] = 1;
    approve(&mut users, u, b, 7);
    approve(&mut users, u, other, 9);
    approve(&mut users, other_user, b, 11);
    assert_eq!(users[&u].len(), 2);
    assert_eq!(users[&other_user][&b], 11);
    approve(&mut users, u, b, 0);
    assert_eq!(users[&u][&other], 9);
    assert_eq!(users[&other_user][&b], 11);
}
#[test]
fn independent_sequence_reference() {
    let mut users = Users::new();
    let mut actions = 0;
    let mut scenarios = 0;
    for line in include_str!("reference.tsv").lines() {
        let v: Vec<_> = line.split('\t').collect();
        if v[0] == "I" {
            scenarios += 1;
            users.clear();
            let n: u64 = v[1].parse().unwrap();
            users.insert(
                address(1),
                (0..n).map(|i| (address(i + 10), 100 + i)).collect(),
            );
            continue;
        }
        let status = approve(
            &mut users,
            address(v[1].parse().unwrap()),
            address(v[2].parse().unwrap()),
            v[3].parse().unwrap(),
        );
        assert_eq!(
            status as u16,
            v[4].parse::<u16>().unwrap(),
            "action{actions}"
        );
        let mut expected = Users::new();
        for entry in v[5].split(';') {
            let (u, rows) = entry.split_once(':').unwrap();
            let mut approvals = Approvals::new();
            if rows != "-" {
                for item in rows.split(',') {
                    let (k, val) = item.split_once('=').unwrap();
                    approvals.insert(address(k.parse().unwrap()), val.parse().unwrap());
                }
            }
            expected.insert(address(u.parse().unwrap()), approvals);
        }
        assert_eq!(users, expected, "action{actions}");
        actions += 1;
    }
    assert_eq!(scenarios, 142);
    assert_eq!(actions, 5680);
}
