//! Selected node115 wrapper routes and ordinary-memory bucket word update.
//! Own boundary API: DirectHandoff and ZeroDivisorBoundary are not native returns.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    DirectHandoff,
    ZeroDivisorBoundary,
    Timed { bucket: u64, active: bool },
}

/// Project the supplied post-helper byte and post-conversion field snapshot.
/// No calendar conversion, opaque call, timer effect or concurrency is modeled.
/// `previous` is own ordinary memory, not a claim about the native object ABI.
pub fn project(bypass: u8, raw_word: u64, divisor: u64, previous: &mut u64) -> Route {
    if bypass != 0 {
        return Route::DirectHandoff;
    }
    if divisor == 0 {
        return Route::ZeroDivisorBoundary;
    }
    let nonnegative = (raw_word as i64).max(0) as u64;
    let bucket = nonnegative / divisor;
    let active = bucket > *previous;
    if active {
        *previous = bucket;
    }
    Route::Timed { bucket, active }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;
    #[test]
    fn frozen_native_rows() {
        for line in
            include_str!("../../research/work-items/RE-014-liquidity-bucket-115/target-smoke.tsv")
                .lines()
        {
            let f: Vec<_> = line.split('\t').collect();
            let mut previous: u64 = f[4].parse().unwrap();
            let original = previous;
            let result = project(
                f[1].parse().unwrap(),
                f[2].parse().unwrap(),
                f[3].parse().unwrap(),
                &mut previous,
            );
            match result {
                Route::DirectHandoff => {
                    assert_eq!(f[5], "D", "{line}");
                    assert_eq!(previous, original);
                }
                Route::ZeroDivisorBoundary => {
                    assert_eq!(f[5], "Z", "{line}");
                    assert_eq!(previous, original);
                }
                Route::Timed { bucket, active } => {
                    assert_eq!(f[5], "T", "{line}");
                    assert_eq!(bucket, f[6].parse::<u64>().unwrap(), "{line}");
                    assert_eq!(previous, f[7].parse::<u64>().unwrap(), "{line}");
                    assert_eq!(u8::from(active), f[8].parse::<u8>().unwrap(), "{line}");
                }
            }
        }
    }
}
