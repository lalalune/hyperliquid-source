use node115_funding_rate::{Config, rate};
use std::collections::BTreeMap;

fn evaluate(samples: Vec<f64>, baseline: f64, bound: f64, multiplier: f64) -> f64 {
    let values = BTreeMap::from([(17, samples)]);
    let baselines = BTreeMap::from([(17, baseline)]);
    let bounds = BTreeMap::from([(17, bound)]);
    let multipliers = BTreeMap::from([(17, multiplier)]);
    rate(
        17,
        &values,
        &Config {
            baselines: &baselines,
            correction_bounds: &bounds,
            default_correction_bound: 0.0,
            multipliers: &multipliers,
        },
    )
    .unwrap()
}

#[test]
fn ordered_negative_zero_and_clamp_ties() {
    assert_eq!(
        evaluate(vec![-0.0], -1.0, 0.0, 1.0).to_bits(),
        (-0.0f64).to_bits()
    );
    assert_eq!(
        evaluate(vec![-0.0], -1.0, -0.0, 1.0).to_bits(),
        0.0f64.to_bits()
    );
    assert_ne!(
        evaluate(vec![1e16, -1e16, 1.0], 0.0, 0.0, 0.001).to_bits(),
        evaluate(vec![1.0, -1e16, 1e16], 0.0, 0.0, 0.001).to_bits()
    );
    assert_eq!(evaluate(vec![1.0], 0.0, 0.0, 1.0), 0.005);
    assert_eq!(evaluate(vec![-1.0], 0.0, 0.0, 1.0), -0.005);
}

#[test]
fn finite_guards_and_nonfinite_outcomes() {
    assert!(evaluate(vec![f64::INFINITY], 0.0, 0.0, 1.0).is_nan());
    assert_eq!(evaluate(vec![1.0], 0.0, 0.0, f64::INFINITY), f64::INFINITY);
    assert_eq!(evaluate(vec![1.0], 10.0, f64::NAN, 1.0), 0.005);
    assert_eq!(evaluate(vec![1.0], 10.0, f64::INFINITY, 1.0), 0.005);
    assert!(evaluate(vec![f64::MAX, f64::MAX, -f64::MAX], 0.0, 0.0, 1.0).is_nan());
}

#[test]
fn logical_map_absence_and_defaults() {
    let empty = BTreeMap::new();
    let config = Config {
        baselines: &empty,
        correction_bounds: &empty,
        default_correction_bound: 0.0005,
        multipliers: &empty,
    };
    let mut samples = BTreeMap::new();
    assert_eq!(rate(17, &samples, &config), None);
    samples.insert(17, vec![]);
    assert_eq!(rate(17, &samples, &config), None);
    samples.insert(17, vec![0.0]);
    assert_eq!(rate(17, &samples, &config), Some(0.0000125));
    samples.insert(18, vec![1.0]);
    assert_eq!(rate(17, &samples, &config), Some(0.0000125));
    assert_eq!(rate(18, &samples, &config), Some(0.005));
}

#[test]
fn ordered_ieee_reference_cases() {
    let mut count = 0;
    for line in include_str!("reference-vectors.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let c: Vec<_> = line.split_whitespace().collect();
        let f = |i: usize| f64::from_bits(u64::from_str_radix(c[i], 16).unwrap());
        let n: usize = c[8].parse().unwrap();
        let mut values = BTreeMap::from([(18, vec![2.0])]);
        if c[0] == "1" {
            values.insert(17, (9..9 + n).map(f).collect());
        }
        let mut baselines = BTreeMap::from([(18, 123.0)]);
        let mut bounds = BTreeMap::from([(18, 456.0)]);
        let mut multipliers = BTreeMap::from([(18, 789.0)]);
        if c[1] == "1" {
            baselines.insert(17, f(5));
        }
        if c[2] == "1" {
            bounds.insert(17, f(6));
        }
        if c[3] == "1" {
            multipliers.insert(17, f(7));
        }
        let config = Config {
            baselines: &baselines,
            correction_bounds: &bounds,
            default_correction_bound: f(4),
            multipliers: &multipliers,
        };
        let result = rate(17, &values, &config);
        if c[9 + n] == "none" {
            assert_eq!(result, None, "case {count}");
        } else {
            let expected = f(9 + n);
            let got = result.unwrap();
            if expected.is_nan() {
                assert!(got.is_nan(), "case {count}");
            } else {
                assert_eq!(got.to_bits(), expected.to_bits(), "case {count}");
            }
        }
        count += 1;
    }
    assert_eq!(count, 12000);
}
