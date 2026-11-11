use node115_vault_redistribution::reweight_value;

#[test]
fn selected_delta_and_existing_entry() {
    assert_eq!(reweight_value(2_000_000, 1_000_000, 0.25, false), 0.5 / 3.0);
    assert_eq!(reweight_value(2_000_000, 1_000_000, 0.25, true), 1.5 / 3.0);
    assert_eq!(reweight_value(0, 1_000_000, 0.0, true), 1.0);
    assert_eq!(
        reweight_value(1_000_000, -1_000_000, 1.0, true).to_bits(),
        0
    );
}

#[test]
fn guards_return_positive_zero() {
    for weight in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, -0.0, 0.0] {
        assert_eq!(reweight_value(1_000_000, 0, weight, false).to_bits(), 0);
    }
    assert_eq!(
        reweight_value(1_000_000, 0, 1e-7, false).to_bits(),
        1e-7f64.to_bits()
    );
    assert_eq!(
        reweight_value(1_000_000, 0, f64::from_bits(1e-7f64.to_bits() - 1), false).to_bits(),
        0
    );
    // A finite admitted numerator can overflow in the final division.
    assert_eq!(
        reweight_value(1_000_000, -999_999, f64::MAX, false).to_bits(),
        0
    );
}

#[test]
fn exact_rational_binary64_vectors() {
    let mut count = 0;
    for line in include_str!("rational-vectors.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 5);
        let prior: i64 = fields[0].parse().unwrap();
        let delta: i64 = fields[1].parse().unwrap();
        let weight = f64::from_bits(u64::from_str_radix(fields[2], 16).unwrap());
        let selected = fields[3] == "1";
        let expected = u64::from_str_radix(fields[4], 16).unwrap();
        assert_eq!(
            reweight_value(prior, delta, weight, selected).to_bits(),
            expected,
            "case {count}: {line}"
        );
        count += 1;
    }
    assert_eq!(count, 18432);
}
