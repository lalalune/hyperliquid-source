//! Independently authored raw-word projection; see RE-014-packed-millis-115.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Milliseconds {
    pub raw: i64,
    pub clamped: u64,
}
/// Convert raw machine-boundary words, without claiming date validity or ABI.
pub fn convert(date_word: u32, seconds_word: u32, nanos_word: u32) -> Milliseconds {
    let year = i64::from((date_word as i32) >> 13);
    let ordinal = i64::from((date_word >> 4) & 511);
    let previous = year - 1;
    // Euclidean division preserves the native negative-year cycle correction.
    let days = previous * 365 + previous.div_euclid(4) - previous.div_euclid(100)
        + previous.div_euclid(400)
        + ordinal
        - 719_163;
    // All intermediates fit these widths throughout the three-u32 raw domain.
    let raw = (days * 86_400 + i64::from(seconds_word)) * 1_000 + i64::from(nanos_word) / 1_000_000;
    Milliseconds {
        raw,
        clamped: raw.max(0) as u64,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_native_rows_across_five_instances() {
        for line in
            include_str!("../../research/work-items/RE-014-packed-millis-115/target-smoke.tsv")
                .lines()
        {
            let f: Vec<_> = line.split('\t').collect();
            assert_eq!(f.len(), 6);
            assert!(f[0].parse::<u8>().unwrap() < 5);
            let actual = convert(
                f[1].parse().unwrap(),
                f[2].parse().unwrap(),
                f[3].parse().unwrap(),
            );
            assert_eq!(
                actual,
                Milliseconds {
                    raw: f[4].parse().unwrap(),
                    clamped: f[5].parse().unwrap()
                }
            );
        }
    }
}
