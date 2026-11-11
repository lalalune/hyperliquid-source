use node115_spot_price_band::{
    Decision, EXEMPT_KEYS, InvalidIndex, SpotMetadata, band, perp, spot,
};

fn s(status: u16) -> Decision {
    Decision {
        status,
        band_percent: None,
    }
}

#[test]
fn strict_lower_and_inclusive_upper_edges() {
    assert_eq!(band(50, 100, 0.5).status, 0x63);
    assert_eq!(band(51, 100, 0.5), s(0x1a2));
    assert_eq!(band(200, 100, 0.5), s(0x1a2));
    assert_eq!(band(201, 100, 0.5).status, 0x63);
    assert_eq!(band(1, 0, 0.5).status, 0x63);
    assert_eq!(band(0, 0, 0.5).status, 0x63);
    assert_eq!(band(100, 100, f64::NAN).status, 0x63);
    assert_eq!(band(100, 100, f64::INFINITY), s(0x1a2));
}

#[test]
fn spot_gate_order_and_routing() {
    let m = SpotMetadata {
        tokens: &[10, 20, 30, 40],
        excluded: &[10],
        routes: &[(10, 1), (20, 2), (30, 3)],
        available: &[1, 2],
    };
    assert_eq!(spot(&m, 4, 1, 1, 1.0), Err(InvalidIndex));
    assert_eq!(spot(&m, 0, 1, 1, 1.0), Ok(s(0x195)));
    assert_eq!(spot(&m, 1, 99_999_000, 0, f64::NAN), Ok(s(0x1a2)));
    assert_eq!(spot(&m, 1, 99_999_001, 1, 1.0), Ok(s(0x100)));
    assert_eq!(spot(&m, 2, 1, 1, 1.0), Ok(s(0x195)));
    assert_eq!(spot(&m, 3, 1, 1, 0.5), Ok(s(0x1a2)));
    assert_eq!(spot(&m, 3, 50, 100, 0.5).unwrap().band_percent, Some(50.0));
}

#[test]
fn actual_perp_exemptions_and_all_byte_mutations() {
    for key in EXEMPT_KEYS {
        assert_eq!(perp(&key, 0, 0, f64::NAN), s(0x1a2));
        for i in 0..20 {
            let mut changed = key;
            changed[i] ^= 1;
            assert_eq!(perp(&changed, 0, 0, 0.5).status, 0x63);
        }
    }
    assert_eq!(perp(&[0; 20], 0, 0, 0.5).status, 0x63);
}

#[test]
fn independent_python_binary64_cases() {
    let mut count = 0;
    for line in include_str!("reference-vectors.txt")
        .lines()
        .filter(|x| !x.starts_with('#'))
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        let a = fields[0].parse().unwrap();
        let b = fields[1].parse().unwrap();
        let p = f64::from_bits(u64::from_str_radix(fields[2], 16).unwrap());
        let expected = u16::from_str_radix(fields[3], 16).unwrap();
        let payload = f64::from_bits(u64::from_str_radix(fields[4], 16).unwrap());
        let got = band(a, b, p);
        assert_eq!(got.status, expected, "case {count}");
        if let Some(actual) = got.band_percent {
            if payload.is_nan() {
                assert!(actual.is_nan(), "case {count}");
            } else {
                assert_eq!(actual.to_bits(), payload.to_bits(), "case {count}");
            }
        } else {
            assert_eq!(expected, 0x1a2);
        }
        count += 1;
    }
    assert_eq!(count, 10000);
}
