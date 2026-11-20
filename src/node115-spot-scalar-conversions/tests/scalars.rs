use node115_spot_scalar_conversions::{Decimals, Metadata, Stop};
use std::process::Command;

#[test]
fn compares_both_conversions_with_arbitrary_precision() {
    let output = Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference.py"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let rows = String::from_utf8(output.stdout).unwrap();
    assert!(rows.lines().count() > 2_500);
    for line in rows.lines() {
        let values: Vec<u64> = line
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        let [exp, a, b, ratio, product] = values[..] else {
            panic!("{line}")
        };
        let tokens = [Decimals {
            field_48: 4,
            field_49: 4 + exp as u8,
        }];
        let meta = Metadata {
            tokens: &tokens,
            pair_tokens: &[0],
        };
        assert_eq!(meta.scaled_ratio(a, 0, b), Ok(ratio), "{line}");
        assert_eq!(meta.unscale_product(a, b, 0), Ok(product), "{line}");
    }
}

#[test]
fn checks_metadata_before_zero_or_overflow_can_hide_an_error() {
    let tokens = [
        Decimals {
            field_48: 3,
            field_49: 2,
        },
        Decimals {
            field_48: 1,
            field_49: 21,
        },
        Decimals {
            field_48: 2,
            field_49: 4,
        },
    ];
    let meta = Metadata {
        tokens: &tokens,
        pair_tokens: &[2, 1, 7, 0],
    };
    assert_eq!(meta.unscale_product(10, 50, 0), Ok(5));
    assert_eq!(meta.scaled_ratio(10, 2, 50), Ok(20));
    assert_eq!(meta.unscale_product(0, 0, 1), Err(Stop::DecimalScale));
    assert_eq!(meta.unscale_product(0, 0, 2), Err(Stop::TokenIndex));
    assert_eq!(meta.unscale_product(0, 0, 3), Err(Stop::DecimalScale));
    assert_eq!(meta.unscale_product(0, 0, 4), Err(Stop::PairIndex));
    assert_eq!(meta.scaled_ratio(0, 0, 0), Err(Stop::DecimalScale));
    assert_eq!(meta.scaled_ratio(0, 3, 0), Err(Stop::TokenIndex));
}

#[test]
fn distinguishes_reordered_arithmetic_and_zero_policies() {
    let rows = [Decimals {
        field_48: 0,
        field_49: 1,
    }];
    let m = Metadata {
        tokens: &rows,
        pair_tokens: &[0],
    };
    let divisor = (1 << 63) + 1;
    assert_eq!(m.scaled_ratio(u64::MAX, 0, divisor), Ok(10));
    assert_eq!(u128::from(u64::MAX) * 10 / u128::from(divisor), 19);
    let operand = 4_500_000_003_u64;
    let wide_quotient = u128::from(operand).pow(2) / 10;
    let native = m.unscale_product(operand, operand, 0).unwrap();
    assert_eq!(native, (operand / 10) * operand);
    assert_ne!(u128::from(native), wide_quotient);
    assert_eq!(m.scaled_ratio(0, 0, 1), Ok(1));
    assert_eq!(m.scaled_ratio(0, 0, 0), Ok(0));
    assert_eq!(m.unscale_product(0, 1, 0), Ok(0));
}
