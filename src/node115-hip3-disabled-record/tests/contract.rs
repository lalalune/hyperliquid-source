use node115_hip3_disabled_record::{Date, DisabledState, Mode, Record, Time, Timestamp, encode};

fn stamp(year: i32, ordinal: u16, seconds: u32, nanos: u32) -> Timestamp {
    Timestamp {
        date: Date::new(year, ordinal).unwrap(),
        time: Time::new(seconds, nanos).unwrap(),
    }
}

#[test]
fn exact_array_timestamps_and_boolean() {
    let value = Record {
        last_settlement_time: stamp(2024, 60, 59, 1_001_000_000),
        deploy_time: stamp(2000, 1, 0, 0),
        n_reserve_deployments_used: 128,
        disabled_state: DisabledState::Na,
        m: false,
    };
    assert_eq!(
        encode(value, Mode::Array).as_bytes(),
        b"\x95\xb72024-02-29T00:00:60.001\xb32000-01-01T00:00:00\xcc\x80\xa2Na\xc2"
    );
    let mut changed = value;
    changed.m = true;
    let original = encode(value, Mode::Map);
    let new = encode(changed, Mode::Map);
    assert_eq!(original.as_bytes().len(), new.as_bytes().len());
    assert_eq!(
        &original.as_bytes()[..original.as_bytes().len() - 1],
        &new.as_bytes()[..new.as_bytes().len() - 1]
    );
    assert_eq!(*new.as_bytes().last().unwrap(), 0xc3);
}

#[test]
fn maximum_record_reaches_str8_and_preserves_field_order() {
    let long = stamp(-262143, 365, 86399, 999999999);
    let value = Record {
        last_settlement_time: long,
        deploy_time: long,
        n_reserve_deployments_used: u64::MAX,
        disabled_state: DisabledState::ValidatorDisabled,
        m: true,
    };
    let result = encode(value, Mode::Map);
    assert_eq!(result.as_bytes().len(), 174);
    assert!(result.as_bytes().starts_with(b"\x85\xb4last_settlement_time\xd9\x20-262143-12-31T23:59:59.999999999\xabdeploy_time\xd9\x20"));
    assert!(
        result
            .as_bytes()
            .ends_with(b"\xaedisabled_state\xb1ValidatorDisabled\xa1m\xc3")
    );
}

#[test]
fn independent_object_packing_reference() {
    let mut count = 0;
    for line in include_str!("reference-vectors.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let v: Vec<_> = line.split_whitespace().collect();
        let timestamp = |start: usize| {
            stamp(
                v[start].parse().unwrap(),
                v[start + 1].parse().unwrap(),
                v[start + 2].parse().unwrap(),
                v[start + 3].parse().unwrap(),
            )
        };
        let value = Record {
            last_settlement_time: timestamp(4),
            deploy_time: timestamp(8),
            n_reserve_deployments_used: v[3].parse().unwrap(),
            disabled_state: [
                DisabledState::Na,
                DisabledState::UserDisabled,
                DisabledState::ValidatorDisabled,
                DisabledState::M,
            ][v[1].parse::<usize>().unwrap()],
            m: v[2] == "1",
        };
        let mode = if v[0] == "0" { Mode::Array } else { Mode::Map };
        let expected: Vec<_> = v[12]
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(core::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(encode(value, mode).as_bytes(), expected, "fixture {count}");
        count += 1;
    }
    assert_eq!(count, 3520);
}
