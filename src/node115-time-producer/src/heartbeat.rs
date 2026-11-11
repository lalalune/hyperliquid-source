//! Safe logical projection of the selected node115 heartbeat row classifier.

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HeartbeatClass {
    Missing,
    Ratio(f64),
    Age(f64),
    Skip,
}

impl HeartbeatClass {
    pub const fn raw_tag(self) -> u8 {
        match self {
            Self::Missing => 0,
            Self::Ratio(_) => 2,
            Self::Age(_) => 1,
            Self::Skip => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeartbeatError {
    DenominatorNotPositive,
}

fn sanitize_ratio(value: f64) -> f64 {
    if value == 0.0 || (value > 0.0 && value.is_finite()) {
        value
    } else {
        0.0
    }
}

pub fn classify(
    found: bool,
    numerator: f64,
    denominator: f64,
    threshold: f64,
    config_flag: bool,
    age: f64,
) -> Result<HeartbeatClass, HeartbeatError> {
    if !found {
        return Ok(HeartbeatClass::Missing);
    }
    let ratio = if denominator == 0.0 {
        0.0
    } else if denominator <= 0.0 || denominator.is_nan() {
        return Err(HeartbeatError::DenominatorNotPositive);
    } else {
        numerator / denominator
    };
    let ratio = sanitize_ratio(ratio);
    if ratio > threshold && !config_flag {
        return Ok(HeartbeatClass::Ratio(ratio));
    }
    if age > 180.0 {
        return Ok(HeartbeatClass::Age(age));
    }
    Ok(HeartbeatClass::Skip)
}

#[cfg(test)]
mod tests {
    use super::{HeartbeatClass, HeartbeatError, classify, sanitize_ratio};
    use std::vec::Vec;

    #[test]
    fn frozen_heartbeat_vectors() {
        let text = include_str!(
            "../../../research/work-items/RE-008-node115-heartbeat-query-static/heartbeat-vectors.tsv"
        );
        let mut rows = 0;
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 8, "malformed vector: {line}");
            let result = classify(
                fields[0] == "1",
                f64::from_bits(fields[1].parse().unwrap()),
                f64::from_bits(fields[2].parse().unwrap()),
                f64::from_bits(fields[3].parse().unwrap()),
                fields[4] == "1",
                f64::from_bits(fields[5].parse().unwrap()),
            );

            match fields[6] {
                "missing" => assert_eq!(result, Ok(HeartbeatClass::Missing), "{line}"),
                "error" => assert_eq!(
                    result,
                    Err(HeartbeatError::DenominatorNotPositive),
                    "{line}"
                ),
                "ratio" => {
                    let expected = f64::from_bits(fields[7].parse().unwrap());
                    assert_eq!(result, Ok(HeartbeatClass::Ratio(expected)), "{line}");
                }
                "age" => {
                    let expected = f64::from_bits(fields[7].parse().unwrap());
                    assert_eq!(result, Ok(HeartbeatClass::Age(expected)), "{line}");
                }
                "skip" => assert_eq!(result, Ok(HeartbeatClass::Skip), "{line}"),
                other => panic!("unknown result {other}: {line}"),
            }
            rows += 1;
        }
        assert_eq!(rows, 1025);
    }

    #[test]
    fn denominator_and_sanitize_boundaries() {
        assert_eq!(
            classify(true, 9.0, 0.0, 0.5, false, 0.0).unwrap().raw_tag(),
            3
        );
        assert_eq!(
            classify(true, 9.0, -0.0, 0.5, false, 0.0)
                .unwrap()
                .raw_tag(),
            3
        );
        assert_eq!(
            classify(true, 9.0, -1.0, 0.5, false, 0.0),
            Err(HeartbeatError::DenominatorNotPositive)
        );
        assert!(sanitize_ratio(-0.0).is_sign_negative());
        assert_eq!(sanitize_ratio(f64::INFINITY), 0.0);
        assert_eq!(sanitize_ratio(f64::NAN), 0.0);
    }

    #[test]
    fn threshold_configuration_and_age_order() {
        let over = classify(true, 2.0, 1.0, 1.0, false, 200.0).unwrap();
        assert_eq!(over.raw_tag(), 2);
        let gated = classify(true, 2.0, 1.0, 1.0, true, 200.0).unwrap();
        assert_eq!(gated.raw_tag(), 1);
        assert_eq!(
            classify(true, 2.0, 1.0, 1.0, true, f64::NAN)
                .unwrap()
                .raw_tag(),
            3
        );
    }

    #[test]
    fn missing_ignores_invalid_denominator_and_age() {
        assert_eq!(
            classify(false, f64::NAN, f64::NAN, f64::NAN, false, f64::NAN),
            Ok(HeartbeatClass::Missing)
        );
    }
}
