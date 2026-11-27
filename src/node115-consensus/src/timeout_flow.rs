//! Independently authored Rust reconstruction of node #115's first-timer poll
//! selector (`0x2cdca20`) and saturating timeout counter (`0x2e098e0` arm
//! `0x8000000000000006`), from `RE-008-consensus-timeout-flow-115`.

/// Selector tags observed in `0x2cdca20`.
pub const TAG_FIRST_TIMER: u64 = 0x8000_0000_0000_0006;
pub const TAG_SECOND_TIMER: u64 = 0x8000_0000_0000_0007;
pub const TAG_ALL_COMPLETE: u64 = 0x8000_0000_0000_000a;
pub const TAG_PENDING: u64 = 0x8000_0000_0000_000b;

/// Done-mask bits for the two timer arms in `0x2cdca20`.
pub const FIRST_TIMER_DONE_BIT: u16 = 0x20;
pub const SECOND_TIMER_DONE_BIT: u16 = 0x40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerArm {
    First,
    Second,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerState {
    pub enabled: bool,
    pub done: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorOutcome {
    Fired(TimerArm, u64),
    Pending,
    AllComplete,
}

/// Polls the two timer arms (`0x2cdca20`) given their ready bytes (`0` = ready,
/// non-zero = pending) and whether any non-timer arm is pending.
pub fn poll_timer_arms(
    first: &mut TimerState,
    second: &mut TimerState,
    first_poll_byte: u8,
    second_poll_byte: u8,
    other_arm_pending: bool,
) -> SelectorOutcome {
    let mut any_pending = other_arm_pending;

    if !first.done && first.enabled {
        if first_poll_byte == 0 {
            first.enabled = false;
            first.done = true;
            return SelectorOutcome::Fired(TimerArm::First, TAG_FIRST_TIMER);
        }
        any_pending = true;
    }

    if !second.done && second.enabled {
        if second_poll_byte == 0 {
            second.enabled = false;
            second.done = true;
            return SelectorOutcome::Fired(TimerArm::Second, TAG_SECOND_TIMER);
        }
        any_pending = true;
    }

    if any_pending {
        SelectorOutcome::Pending
    } else {
        SelectorOutcome::AllComplete
    }
}

/// Outcome of the saturating timeout counter tick at `0x2e09a01..0x2e09a4c`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutCounterOutcome {
    pub new_count: u64,
    /// True when `new_count > 1` (`cmp rbx, 1; jbe 0x2e09a4c`).
    pub exceeds_initial_threshold: bool,
}

/// Reconstructs `inc rax; cmovne rbx, rax; cmp rbx, 1; jbe ...` at `0x2e09a01`.
pub fn saturating_timeout_tick(current: u64) -> TimeoutCounterOutcome {
    let new_count = current.saturating_add(1);
    TimeoutCounterOutcome {
        new_count,
        exceeds_initial_threshold: new_count > 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_selector_clears_enabled_sets_done_and_reports_pending_or_complete() {
        let mut first = TimerState {
            enabled: true,
            done: false,
        };
        let mut second = TimerState {
            enabled: true,
            done: false,
        };
        assert_eq!(
            poll_timer_arms(&mut first, &mut second, 1, 1, false),
            SelectorOutcome::Pending
        );
        assert!(first.enabled && !first.done);

        assert_eq!(
            poll_timer_arms(&mut first, &mut second, 0, 1, false),
            SelectorOutcome::Fired(TimerArm::First, TAG_FIRST_TIMER)
        );
        assert!(!first.enabled && first.done);

        assert_eq!(
            poll_timer_arms(&mut first, &mut second, 0, 0, false),
            SelectorOutcome::Fired(TimerArm::Second, TAG_SECOND_TIMER)
        );
        assert!(!second.enabled && second.done);

        assert_eq!(
            poll_timer_arms(&mut first, &mut second, 0, 0, false),
            SelectorOutcome::AllComplete
        );
    }

    #[test]
    fn saturating_timeout_counter_thresholds_and_u64_max() {
        assert_eq!(
            saturating_timeout_tick(0),
            TimeoutCounterOutcome {
                new_count: 1,
                exceeds_initial_threshold: false,
            }
        );
        assert_eq!(
            saturating_timeout_tick(1),
            TimeoutCounterOutcome {
                new_count: 2,
                exceeds_initial_threshold: true,
            }
        );
        assert_eq!(
            saturating_timeout_tick(u64::MAX),
            TimeoutCounterOutcome {
                new_count: u64::MAX,
                exceeds_initial_threshold: true,
            }
        );
    }
}
