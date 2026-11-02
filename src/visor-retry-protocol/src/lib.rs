//! Supplied-callback retry and owned cleanup values, qualified by RE-013.
//!
//! This module does not execute commands, sleep, access files or read a clock.
//! Callback normal return, unique ownership and preserved borrows are premises.
#![forbid(unsafe_code)]

use visor_duration_value::convert_bits;

const BILLION: i64 = 1_000_000_000;
const CHUNK_LIMIT: u64 = i64::MAX as u64;
const DEFAULT_DELAYS: [u64; 3] = [
    0x3f50_624d_d2f1_a9fc,
    0x3fa9_9999_9999_999a,
    0x3ff0_0000_0000_0000,
];
const OWNED_DELAYS: [u64; 3] = [
    0x3ff0_0000_0000_0000,
    0x4008_0000_0000_0000,
    0x4024_0000_0000_0000,
];

/// Canonical numeric request for a supplied sleeper; never an OS call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SleepRequest {
    seconds: u64,
    nanoseconds: u32,
}

impl SleepRequest {
    /// Whole seconds, at most `i64::MAX`.
    pub const fn seconds(self) -> u64 {
        self.seconds
    }

    /// Nanoseconds, strictly below one billion.
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }

    /// The observed raw clock selector, without inferring a host clock.
    pub const fn clock(self) -> i32 {
        1
    }

    /// The observed raw flags.
    pub const fn flags(self) -> i32 {
        0
    }
}

/// Supplied raw return and remainder. Code zero ignores both remainder fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SleepReply {
    pub code: i32,
    pub remaining_seconds: i64,
    pub remaining_nanoseconds: i64,
}

/// New safe policies for native nonordinary or excluded callback inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleepRefusal {
    InvalidRemainder,
    UnexpectedSleepCode(i32),
}

/// The terminal value is returned with its original ownership and identity.
#[derive(Debug, Eq, PartialEq)]
pub enum RetryOutcome<T> {
    Succeeded,
    Exhausted(T),
    Refused(SleepRefusal),
}

fn wait<F>(bits: u64, sleep: &mut F) -> Result<(), SleepRefusal>
where
    F: FnMut(SleepRequest) -> SleepReply,
{
    let duration = convert_bits(bits);
    let mut seconds = duration.seconds();
    let mut nanoseconds = duration.nanoseconds();
    while seconds != 0 || nanoseconds != 0 {
        let requested_seconds = seconds.min(CHUNK_LIMIT);
        let unrequested_seconds = seconds - requested_seconds;
        let reply = sleep(SleepRequest {
            seconds: requested_seconds,
            nanoseconds,
        });
        match reply.code {
            0 => {
                seconds = unrequested_seconds;
                nanoseconds = 0;
            }
            4 => {
                if reply.remaining_seconds < 0
                    || !(0..BILLION).contains(&reply.remaining_nanoseconds)
                    || reply.remaining_seconds as u64 > requested_seconds
                    || (reply.remaining_seconds as u64 == requested_seconds
                        && reply.remaining_nanoseconds as u32 > nanoseconds)
                {
                    return Err(SleepRefusal::InvalidRemainder);
                }
                seconds = unrequested_seconds + reply.remaining_seconds as u64;
                nanoseconds = reply.remaining_nanoseconds as u32;
            }
            code => return Err(SleepRefusal::UnexpectedSleepCode(code)),
        }
    }
    Ok(())
}

/// Retry the same borrowed request, then build one owned terminal on exhaustion.
///
/// The initial attempt precedes schedule selection. `None` selects the observed
/// default words; `Some(&[])` exhausts after that first failed attempt. Delays
/// are converted only as reached. A replacement error is obtained while the
/// preceding error is alive. The builder borrows the complete original selected
/// slice and last error, and the last error is dropped after the builder returns.
/// All callbacks and destructors must return normally for the native relation.
pub fn retry<R: ?Sized, E, T, A, S, B>(
    request: &R,
    description: &str,
    delays: Option<&[u64]>,
    mut attempt: A,
    mut sleep: S,
    terminal: B,
) -> RetryOutcome<T>
where
    A: FnMut(&R) -> Result<(), E>,
    S: FnMut(SleepRequest) -> SleepReply,
    B: FnOnce(&str, &[u64], &E) -> T,
{
    let mut current = match attempt(request) {
        Ok(()) => return RetryOutcome::Succeeded,
        Err(error) => error,
    };
    let selected = delays.unwrap_or(&DEFAULT_DELAYS);
    for &bits in selected {
        if let Err(refusal) = wait(bits, &mut sleep) {
            drop(current);
            return RetryOutcome::Refused(refusal);
        }
        match attempt(request) {
            Ok(()) => {
                drop(current);
                return RetryOutcome::Succeeded;
            }
            Err(next) => {
                drop(current);
                current = next;
            }
        }
    }
    let result = terminal(description, selected, &current);
    drop(current);
    RetryOutcome::Exhausted(result)
}

/// Consume a command and optional cleanup value using the observed fixed retry.
///
/// Attempts receive raw option zero. The retry result survives command disposal
/// and optional cleanup. A cleanup error is dropped before its cleanup value.
/// On the two new refusal policies, command and optional cleanup ownership end
/// in that order, without invoking cleanup. `Some` of an empty value is present.
pub fn retry_owned<C, P, E, CE, T, A, S, B, K>(
    command: C,
    cleanup_value: Option<P>,
    mut attempt: A,
    sleep: S,
    terminal: B,
    cleanup: K,
) -> RetryOutcome<T>
where
    A: FnMut(&C, u8) -> Result<(), E>,
    S: FnMut(SleepRequest) -> SleepReply,
    B: FnOnce(&str, &[u64], &E) -> T,
    K: FnOnce(&P) -> Result<(), CE>,
{
    let result = retry(
        &command,
        "shell::wait_retry",
        Some(&OWNED_DELAYS),
        |value| attempt(value, 0),
        sleep,
        terminal,
    );
    drop(command);
    if matches!(&result, RetryOutcome::Refused(_)) {
        drop(cleanup_value);
        return result;
    }
    if let Some(value) = cleanup_value {
        drop(cleanup(&value));
        drop(value);
    }
    result
}
