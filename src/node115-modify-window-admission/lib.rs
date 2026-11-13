//! Native 0x420bdc0 window updates composed in 0x5591630's selected admission arm.
//! Does not implement order placement, rollback, account lookup or persistence.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedTime {
    /// Signed year in bits31..13, ordinal in bits12..4; low four bits ignored.
    pub year_ordinal_flags: u32,
    pub seconds: u32,
    pub nanos: u32,
}

impl PackedTime {
    /// Native arithmetic over the packed words, not calendar-input validation.
    pub fn clamped_millis(self) -> u64 {
        let year = (self.year_ordinal_flags as i32 >> 13) as i64;
        let ordinal = ((self.year_ordinal_flags >> 4) & 0x1ff) as i64;
        let previous_year = year - 1;
        let days = 365 * previous_year + previous_year.div_euclid(4)
            - previous_year.div_euclid(100) + previous_year.div_euclid(400)
            + ordinal - 719_163;
        let millis = (days * 86_400 + i64::from(self.seconds)) * 1000
            + i64::from(self.nanos / 1_000_000);
        millis.max(0) as u64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub count: u64,
    pub time: PackedTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZeroPeriod;

/// The native period must be nonzero. This safe boundary rejects a zero period
/// without emulating its division fault. At every admitted call, even a false
/// result has already updated both count and saved time.
pub fn update(window: &mut Window, now: PackedTime, period_ms: u64, maximum: u64)
    -> Result<bool, ZeroPeriod>
{
    if period_ms == 0 {
        return Err(ZeroPeriod);
    }
    let previous_bucket = window.time.clamped_millis() / period_ms;
    let current_bucket = now.clamped_millis() / period_ms;
    window.count = if previous_bucket < current_bucket {
        1
    } else {
        window.count.saturating_add(1)
    };
    window.time = now;
    Ok(window.count <= maximum)
}

/// Both windows are evaluated in order; their admission booleans are ORed.
/// Nonzero periods are an explicit domain requirement for the native pair.
pub fn update_pair(windows: &mut [Window; 2], now: PackedTime,
    periods: [u64; 2], maxima: [u64; 2]) -> Result<bool, ZeroPeriod>
{
    if periods.contains(&0) {
        return Err(ZeroPeriod);
    }
    let first = update(&mut windows[0], now, periods[0], maxima[0])?;
    let second = update(&mut windows[1], now, periods[1], maxima[1])?;
    Ok(first | second)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn time(year: i32, ordinal: u32, seconds: u32, nanos: u32) -> PackedTime {
        PackedTime { year_ordinal_flags: ((year as u32) << 13) | (ordinal << 4), seconds, nanos }
    }
    #[test]
    fn packed_time_known_epoch_and_leap_boundaries() {
        assert_eq!(time(1970, 1, 0, 0).clamped_millis(), 0);
        assert_eq!(time(1969, 365, 86399, 999_999_999).clamped_millis(), 0);
        assert_eq!(time(1970, 1, 0, 999_999).clamped_millis(), 0);
        assert_eq!(time(1970, 1, 0, 1_000_000).clamped_millis(), 1);
        assert_eq!(time(2000, 60, 0, 0).clamped_millis(), 951_782_400_000);
        assert_eq!(time(2024, 60, 0, 0).clamped_millis(), 1_709_164_800_000);
        assert_eq!(time(0, 1, 0, 0).clamped_millis(), 0);
        assert_eq!(time(-262144, 1, 0, 0).clamped_millis(), 0);
        let base = time(2024, 60, 0, 0);
        for flags in 0..16 {
            assert_eq!(PackedTime { year_ordinal_flags: base.year_ordinal_flags | flags, ..base }.clamped_millis(), base.clamped_millis());
        }
    }
    #[test]
    fn packed_time_against_year_by_year_calendar() {
        let mut days_before_year = 0u64;
        for year in 1970..=9999 {
            let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
            for ordinal in [1, 60, 365] {
                assert_eq!(time(year, ordinal, 43210, 987_654_321).clamped_millis(),
                    (days_before_year + u64::from(ordinal) - 1) * 86_400_000 + 43_210_987);
            }
            days_before_year += if leap { 366 } else { 365 };
        }
    }
    #[test]
    fn rejected_pair_still_writes_both_windows() {
        let old = time(2024, 60, 1, 0);
        let now = time(2024, 60, 2, 0);
        let mut windows = [Window { count: 1, time: old }, Window { count: 2, time: old }];
        assert_eq!(update_pair(&mut windows, now, [60_000, 3_600_000], [1, 2]), Ok(false));
        assert_eq!(windows, [Window { count: 2, time: now }, Window { count: 3, time: now }]);
        // Even if the first permits admission, the second is updated too.
        assert_eq!(update_pair(&mut windows, now, [60_000, 3_600_000], [3, 0]), Ok(true));
        assert_eq!([windows[0].count, windows[1].count], [3, 4]);
    }
    #[test]
    fn reset_saturation_regression_and_exact_limit() {
        let old = time(2024, 60, 59, 999_000_000);
        let now = time(2024, 60, 60, 0);
        let mut window = Window { count: u64::MAX, time: old };
        assert_eq!(update(&mut window, now, 60_000, 1), Ok(true));
        assert_eq!(window.count, 1);
        assert_eq!(update(&mut window, old, 60_000, 1), Ok(false));
        assert_eq!(window, Window { count: 2, time: old });
        window.count = u64::MAX;
        assert_eq!(update(&mut window, old, 60_000, u64::MAX), Ok(true));
        assert_eq!(window.count, u64::MAX);
        let before = window;
        assert_eq!(update(&mut window, now, 0, 1), Err(ZeroPeriod));
        assert_eq!(window, before);
    }
}
