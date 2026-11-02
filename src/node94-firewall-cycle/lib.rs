//! Conditional node94 firewall-cycle decisions over supplied helper results.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub maybe_update: bool,
    pub compute: bool,
    pub check: bool,
    pub update: bool,
    pub loader_flag: u8,
}

/// Project only the established gates before the loader call at 0x28f6d7b.
///
/// Supply the raw skip byte and prior timestamp tag, the elapsed helper's
/// returned seconds, interval, and the three equality results. The helpers,
/// IP collections, locks, timestamp writes and loader are not executed here.
pub fn plan(
    skip_byte: u8,
    last_word: u32,
    elapsed: f64,
    interval: f64,
    equalities: [bool; 3],
) -> Plan {
    if skip_byte == 1 {
        return Plan {
            maybe_update: false,
            compute: false,
            check: false,
            update: false,
            loader_flag: 0,
        };
    }
    let maybe_update = last_word == 0 || elapsed > interval;
    Plan {
        maybe_update,
        compute: true,
        check: true,
        update: !equalities.into_iter().all(|same| same),
        loader_flag: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_raw_one_skips_the_sections() {
        assert_eq!(plan(1, 0, 0.0, 1.0, [false; 3]).loader_flag, 0);
        assert!(plan(2, 0, 0.0, 1.0, [false; 3]).compute);
    }

    #[test]
    fn throttled_check_still_requests_changed_value_update() {
        let result = plan(0, 1, 5.0, 5.0, [true, false, true]);
        assert!(!result.maybe_update);
        assert!(result.compute && result.check && result.update);
        assert_eq!(result.loader_flag, 1);
    }

    #[test]
    fn unordered_comparison_and_absent_timestamp() {
        assert!(!plan(0, 1, f64::NAN, 1.0, [true; 3]).maybe_update);
        assert!(plan(0, 0, f64::NAN, f64::NAN, [true; 3]).maybe_update);
        assert!(!plan(0, 1, 2.0, 1.0, [true; 3]).update);
    }
}
