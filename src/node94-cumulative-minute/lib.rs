//! Raw local conversion guards, not a valid timestamp constructor or original ABI.
#![no_std]
#![forbid(unsafe_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalMinute {
    Accepted(u16),
    NarrowingExit,
    AssertionExit,
}

pub fn classify_raw_word(raw: u32) -> LocalMinute {
    let minute = raw / 60;
    if minute > 65535 {
        LocalMinute::NarrowingExit
    } else if minute >= 1441 {
        LocalMinute::AssertionExit
    } else {
        LocalMinute::Accepted(minute as u16)
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;
    #[test]
    fn frozen_native_rows() {
        for row in include_str!("target-smoke.tsv").lines() {
            let f: Vec<_> = row.split('\t').collect();
            let answer = classify_raw_word(f[0].parse().unwrap());
            match answer {
                LocalMinute::Accepted(v) => {
                    assert_eq!(f[1], "V", "{row}");
                    assert_eq!(v, f[2].parse::<u16>().unwrap(), "{row}");
                }
                LocalMinute::NarrowingExit => assert_eq!(f[1], "N", "{row}"),
                LocalMinute::AssertionExit => assert_eq!(f[1], "A", "{row}"),
            }
        }
    }
}
