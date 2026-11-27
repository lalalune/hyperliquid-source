//! HTTP endpoint, timing, localhost access, future-resume state, and snapshot-guard
//! invariants observed in node #115 `info_server`:
//! - `/info` & `Web /info` (`0x605aec`, `0x2aedea1`)
//! - `0x2e3ed10..0x2e414d3` (`router.rs`, `handler.rs`, `handle_request.rs`, `user_ip.rs`)
//! - `0x2979780` (Info API future resume state byte `+0x18`)
//! - `0x29698d0` (conditional second-query tag dispatch)
//! - `0x2a52620` & `0x2a3ceb0` (per-query `S+0x6a8` snapshot reader-count guard)

use std::net::IpAddr;

use crate::request::InfoRequestKind;

/// HTTP POST route path observed at `.rodata` `0x605aec`.
pub const INFO_HTTP_PATH: &str = "/info";

/// Service banner label observed at `.rodata` `0x605af1`.
pub const WEB_INFO_SERVICE_LABEL: &str = "Web /info";

/// Rate-limiter metric cell label observed at `.rodata` `0x644408` and passed in `0x2e3fd4b`.
pub const HANDLE_REQUEST_RATE_LIMITER: &str = "handle_request_rate_limiter";

/// HTTP status codes explicitly materialized in `0x2e3ed10..0x2e414d3`.
pub const HTTP_STATUS_OK: u16 = 200;
pub const HTTP_STATUS_INTERNAL_ERROR: u16 = 500;

/// Dormant inner-future sleep duration (`0x3f8cac083126e979`, `0.014` seconds) stored at
/// `0x2e3fd79` in `0x2e3ed10`. In node #115 the gating flag `bpl` at `0x2e3fd51` is always 0.
pub const USER_IP_INNER_SLEEP_SECS: f64 = 0.014;
pub const USER_IP_INNER_SLEEP_BITS: u64 = 0x3f8c_ac08_3126_e979;

/// Exact elapsed-seconds sanitization performed by `0x2e3fca7..0x2e3fd2b` before passing
/// the duration to `handle_request_rate_limiter`:
/// - negative durations (clock tag != 0) map to `0.0`
/// - `+inf` (compared against `0x459010`) and non-finite values map to `0.0`
#[must_use]
pub fn sanitize_elapsed_secs(elapsed_secs: f64) -> f64 {
    if !elapsed_secs.is_finite() || elapsed_secs < 0.0 {
        0.0
    } else {
        elapsed_secs
    }
}

/// Access decision for `InfoRequestKind` requests given the peer IP address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestAccess {
    Allowed,
    RejectedNotLocalhost,
}

/// Enforce the `fileSnapshot` localhost gate (`not from localhost: ` at `.rodata` `0x4359a1`).
#[must_use]
pub fn check_request_access(kind: InfoRequestKind, peer_ip: IpAddr) -> RequestAccess {
    if kind.requires_localhost() && !peer_ip.is_loopback() {
        RequestAccess::RejectedNotLocalhost
    } else {
        RequestAccess::Allowed
    }
}

/// Exact resume-state byte (`+0x18`) of the Info API future at `0x2979780`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FutureResumeState {
    Initial = 0,
    Completed = 1,
    Panicked = 2,
}

/// Exact panic message emitted when resuming a future in state `1` (`0x46f2ed`, len 35).
pub const PANIC_RESUMED_AFTER_COMPLETION: &str = "`async fn` resumed after completion";

/// Exact panic message emitted when resuming a future in state `2` (`0x46f310`, len 34).
pub const PANIC_RESUMED_AFTER_PANICKING: &str = "`async fn` resumed after panicking";

impl FutureResumeState {
    #[must_use]
    pub const fn resume_panic_message(self) -> Option<&'static str> {
        match self {
            Self::Initial => None,
            Self::Completed => Some(PANIC_RESUMED_AFTER_COMPLETION),
            Self::Panicked => Some(PANIC_RESUMED_AFTER_PANICKING),
        }
    }
}

/// First-stage tag dispatch decision observed in `0x29698d0` (`abci_state_info_handler.rs:714`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirstStageDecision {
    /// Tag `0`: skip second query, emit outer tag `2` with saved first-stage payload.
    SkipSecondEmitTag2,
    /// Tag `1`: construct and poll the second query future.
    PollSecondQuery,
    /// Tags `2` or `3`: short-circuit directly to outer tag `3`.
    ShortCircuitTag3,
    /// Tag `4`: pending, preserve first future with continuation `3`.
    PendingContinuation3,
}

/// Classify a first-stage result tag (`result+0xc0`) per `0x29698d0`.
#[must_use]
pub const fn classify_first_stage_tag(tag: u32) -> Option<FirstStageDecision> {
    match tag {
        0 => Some(FirstStageDecision::SkipSecondEmitTag2),
        1 => Some(FirstStageDecision::PollSecondQuery),
        2 | 3 => Some(FirstStageDecision::ShortCircuitTag3),
        4 => Some(FirstStageDecision::PendingContinuation3),
        _ => None,
    }
}

/// Atomic reader-count guard protocol observed at `S+0x6a8` in `0x2a52620` and `0x2a3ceb0`.
///
/// - Fast-path acquire increments the guard word by `READER_STEP` (`16`) iff bit 3 is clear
///   and `word < READER_LIMIT` (`usize::MAX - 15`, unsigned `-16`).
/// - Release subtracts `READER_STEP` (`16`) and wakes waiters iff `(old & WAKE_MASK) == WAKE_MATCH`
///   (`(old & !13) == 18`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotGuardWord(pub u64);

impl SnapshotGuardWord {
    pub const READER_STEP: u64 = 16;
    pub const DISALLOWED_BIT: u64 = 1 << 3;
    pub const READER_LIMIT: u64 = u64::MAX - 15;
    pub const WAKE_MASK: u64 = !13u64;
    pub const WAKE_MATCH: u64 = 18;

    /// Attempt fast-path read-guard acquisition. Returns `None` when the slow path (`0x5bb1a60`)
    /// is required.
    #[must_use]
    pub const fn try_acquire_fast(self) -> Option<Self> {
        if (self.0 & Self::DISALLOWED_BIT) != 0 || self.0 >= Self::READER_LIMIT {
            None
        } else {
            Some(Self(self.0 + Self::READER_STEP))
        }
    }

    /// Release one reader count (`lock xadd -16`), returning `(new_word, should_wake)`.
    #[must_use]
    pub const fn release(self) -> (Self, bool) {
        let should_wake = (self.0 & Self::WAKE_MASK) == Self::WAKE_MATCH;
        (Self(self.0.wrapping_sub(Self::READER_STEP)), should_wake)
    }
}
