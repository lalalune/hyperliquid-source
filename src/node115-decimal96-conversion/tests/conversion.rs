use node115_decimal96_conversion::{Decimal96, InvalidScale};

#[test]
fn independently_rounded_binary64_fixtures() {
    let mut count = 0;
    for line in include_str!("fixtures.tsv")
        .lines()
        .filter(|s| !s.starts_with('#'))
    {
        let cells: Vec<_> = line.split('\t').collect();
        let coefficient: u128 = cells[0].parse().unwrap();
        let scale: u8 = cells[1].parse().unwrap();
        let negative = cells[2] == "1";
        let expected = u64::from_str_radix(cells[3], 16).unwrap();
        let value = Decimal96::new(
            coefficient as u64,
            (coefficient >> 64) as u32,
            scale,
            negative,
        )
        .unwrap();
        assert_eq!(value.to_f64().to_bits(), expected, "{line}");
        count += 1;
    }
    assert!(count > 2_000);
}

#[test]
fn raw_zero_sign_and_invalid_scale_are_explicit() {
    for scale in 0..=28 {
        assert_eq!(
            Decimal96::new(0, 0, scale, false)
                .unwrap()
                .to_f64()
                .to_bits(),
            0
        );
        let expected = if scale == 0 { 0 } else { 1_u64 << 63 };
        assert_eq!(
            Decimal96::new(0, 0, scale, true)
                .unwrap()
                .to_f64()
                .to_bits(),
            expected
        );
    }
    for scale in 29..=255 {
        assert_eq!(
            Decimal96::new(u64::MAX, u32::MAX, scale, false),
            Err(InvalidScale)
        );
    }
}
