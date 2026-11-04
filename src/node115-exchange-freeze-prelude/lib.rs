//! Scalar projection of the selected node115 exchange preparation prelude.
//! No original enum/ABI, helper effects, completed return or snapshot claim.
#![no_std]
#![forbid(unsafe_code)]

use core::num::NonZeroU64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    PastTargetBoundary,
    SentinelHandoff,
    Prepare { requested: bool, freeze_equal: bool },
    SkipContinuation,
}

pub fn basic(outer_tag: u32, freeze_tag: u32, height: u64, target: u64) -> Selection {
    classify(outer_tag, freeze_tag, height, target, None)
}

/// The qualified secondary domain excludes zero-divisor/trap semantics.
pub fn secondary(
    outer_tag: u32,
    freeze_tag: u32,
    height: u64,
    target: u64,
    cadence: NonZeroU64,
) -> Selection {
    classify(outer_tag, freeze_tag, height, target, Some(cadence))
}

fn classify(
    outer_tag: u32,
    freeze_tag: u32,
    height: u64,
    target: u64,
    secondary: Option<NonZeroU64>,
) -> Selection {
    let fixed = height.is_multiple_of(10_000);
    let past = freeze_tag == 1 && target < height;
    if !fixed && past {
        return Selection::PastTargetBoundary;
    }
    if outer_tag == 2 {
        return Selection::SentinelHandoff;
    }
    if past {
        return Selection::PastTargetBoundary;
    }
    let freeze_equal = freeze_tag == 1 && target == height;
    let requested = fixed || freeze_equal;
    if requested || secondary.is_some_and(|cadence| height.is_multiple_of(cadence.get())) {
        Selection::Prepare {
            requested,
            freeze_equal,
        }
    } else {
        Selection::SkipContinuation
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{basic, secondary, NonZeroU64, Selection};
    #[test]
    fn frozen_native_rows() {
        for line in include_str!("target-smoke.tsv").lines() {
            let f: std::vec::Vec<_> = line.split('\t').collect();
            let lane: u8 = f[0].parse().unwrap();
            let args = (
                f[1].parse().unwrap(),
                f[2].parse().unwrap(),
                f[3].parse().unwrap(),
                f[4].parse().unwrap(),
            );
            let actual = if lane == 0 {
                basic(args.0, args.1, args.2, args.3)
            } else {
                secondary(
                    args.0,
                    args.1,
                    args.2,
                    args.3,
                    NonZeroU64::new(f[5].parse().unwrap()).unwrap(),
                )
            };
            let expected = match f[6] {
                "X" => Selection::PastTargetBoundary,
                "R" => Selection::SentinelHandoff,
                "K" => Selection::SkipContinuation,
                "P" => Selection::Prepare {
                    requested: f[7] == "1",
                    freeze_equal: f[8] == "1",
                },
                _ => panic!("unknown native outcome"),
            };
            assert_eq!(actual, expected, "{line}");
        }
    }
}
