use node115_display_name_state::{Status, set_name};
use std::collections::BTreeMap;

#[test]
fn boundaries_and_own_duplicate() {
    let user = [1; 20];
    let mut names = BTreeMap::new();
    assert_eq!(set_name(&mut names, user, "ab".into()), Status::TooShort);
    assert_eq!(set_name(&mut names, user, "a".repeat(21)), Status::TooLong);
    assert_eq!(set_name(&mut names, user, "abc".into()), Status::Accepted);
    assert_eq!(set_name(&mut names, user, "abc".into()), Status::Duplicate);
    assert_eq!(
        set_name(&mut names, [2; 20], "abc".into()),
        Status::Duplicate
    );
    assert_eq!(
        set_name(&mut names, [2; 20], "ABC".into()),
        Status::Accepted
    );
    assert_eq!(set_name(&mut names, user, "".into()), Status::Accepted);
    assert!(!names.contains_key(&user));
}

#[test]
fn byte_length_and_replacement() {
    let mut names = BTreeMap::new();
    let user = [4; 20];
    assert_eq!(set_name(&mut names, user, "é".into()), Status::TooShort);
    assert_eq!(set_name(&mut names, user, "éa".into()), Status::Accepted);
    assert_eq!(set_name(&mut names, user, "😀".repeat(5)), Status::Accepted);
    assert_eq!(set_name(&mut names, user, "😀".repeat(6)), Status::TooLong);
    assert_eq!(names[&user], "😀".repeat(5));
}

#[test]
fn list_based_reference_sequences() {
    let mut state = BTreeMap::new();
    let mut reference: Vec<([u8; 20], String)> = Vec::new();
    for step in 0..12000u32 {
        let mut user = [0; 20];
        user[19] = (step % 19) as u8;
        let value = match step % 7 {
            0 => String::new(),
            1 => "ab".into(),
            2 => "x".repeat(21),
            3 => "éa".into(),
            _ => format!("name{}", step % 23),
        };
        let status = if value.is_empty() {
            reference.retain(|(k, _)| *k != user);
            Status::Accepted
        } else if value.len() > 20 {
            Status::TooLong
        } else if value.len() < 3 {
            Status::TooShort
        } else if reference
            .iter()
            .any(|(_, v)| v.as_bytes() == value.as_bytes())
        {
            Status::Duplicate
        } else {
            reference.retain(|(k, _)| *k != user);
            reference.push((user, value.clone()));
            Status::Accepted
        };
        assert_eq!(set_name(&mut state, user, value), status);
        let expected: BTreeMap<_, _> = reference.iter().cloned().collect();
        assert_eq!(state, expected);
    }
}
