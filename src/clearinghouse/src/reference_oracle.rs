//! Binary-verified node #115 reference oracle deviation monitor and `OracleKind`
//! (`l1/src/clearinghouse/oracle/{oracle_kind.rs:3,reference_oracle.rs:211}`, `RE-007`).
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
//!
//! Static FDE provenance:
//! - `0x3db4e40..0x3db50ed` (685 B): 3-variant `OracleKind` iterator/collector (`oracle_kind.rs:3:105`)
//! - `0x366f900..0x366fbe4` (740 B): `ReferenceOracle::evaluate` (`reference_oracle.rs:211:25`)
//!   - Computes relative deviation `(max(ref_px, cur_px) as f64) / (min(ref_px, cur_px) as f64) - 1.0`
//!     (`.rodata 0x458dc8 = -1.0_f64`)
//!   - Clears tracker and returns `false` when `cur_px` is present (`0x1a2`), `ref_px != 0`, and
//!     `deviation < max_diff.max(0.0)`
//!   - Otherwise records `(first_violation_secs, last_violation_secs)`, computes elapsed seconds
//!     (`.rodata 0x458d50 = 1e9_f64`, `+inf -> 0.0`), triggers alert (`edi = 8` at `0x366fbc5`) when
//!     `alert_enabled && elapsed > max_duration_secs`, and returns `alert_enabled`.

/// Three-variant `OracleKind` enum (`cmpq $3, %rax` in `0x3db4e40`, `oracle_kind.rs:3:105`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OracleKind {
    Spot = 0,
    Mark = 1,
    External = 2,
}

impl OracleKind {
    /// All 3 variants in #115 iteration order (`0..3`).
    pub const ALL: [Self; 3] = [Self::Spot, Self::Mark, Self::External];
}

/// Policy variant returned by `0x64e8cc0` inside `0x366f900`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReferenceOraclePolicy {
    /// Mode `0` (`0x366f988`): deviation check with configurable `alert_enabled` flag (`+0x49`).
    Active {
        max_diff: f64,
        alert_enabled: bool,
    },
    /// Mode `1` (`0x366f97e`): deviation check with `alert_enabled = false`.
    Passive { max_diff: f64 },
    /// Mode `>= 2` (`0x366f978 -> 0x366faeb`): early exit returning `false`.
    Disabled,
}

/// Violation tracker entry stored per asset at `self+0x78` (`0x366faf2..0x366fb44`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReferenceOracleTracker {
    pub max_duration_secs: f64,
    pub first_violation_ns: Option<i128>,
    pub last_violation_ns: Option<i128>,
}

impl ReferenceOracleTracker {
    pub const fn new(max_duration_secs: f64) -> Self {
        Self {
            max_duration_secs,
            first_violation_ns: None,
            last_violation_ns: None,
        }
    }
}

/// Outcome of `evaluate_reference_oracle` (`0x366f900`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceOracleEval {
    /// Boolean returned in `%al` by `0x366f900`.
    pub flagged: bool,
    /// `true` iff the alert hook at `0x366fbbe` (`reference_oracle.rs:211:25`, `edi = 8`) fired.
    pub alert_fired: bool,
    /// `true` iff the violation tracker was cleared (`0x3ce7650` at `0x366fae6`).
    pub tracker_cleared: bool,
}

/// Relative price deviation matching `0x366fa60..0x366facf`:
/// `(max(a, b) as f64) / (min(a, b) as f64) + (-1.0)`.
pub fn reference_price_deviation(ref_px: u64, cur_px: u64) -> Option<f64> {
    if ref_px == 0 || cur_px == 0 {
        return None;
    }
    let hi = ref_px.max(cur_px) as f64;
    let lo = ref_px.min(cur_px) as f64;
    Some((hi / lo) + (-1.0))
}

/// Reconstructs `ReferenceOracle::evaluate` (`0x366f900`, `reference_oracle.rs:211:25`).
pub fn evaluate_reference_oracle(
    policy: ReferenceOraclePolicy,
    ref_px: Option<u64>,
    cur_px: Option<u64>,
    now_ns: i128,
    tracker: &mut ReferenceOracleTracker,
) -> ReferenceOracleEval {
    let (max_diff, alert_enabled) = match policy {
        ReferenceOraclePolicy::Active {
            max_diff,
            alert_enabled,
        } => (max_diff, alert_enabled),
        ReferenceOraclePolicy::Passive { max_diff } => (max_diff, false),
        ReferenceOraclePolicy::Disabled => {
            return ReferenceOracleEval {
                flagged: false,
                alert_fired: false,
                tracker_cleared: false,
            };
        }
    };

    if let (Some(r), Some(c)) = (ref_px, cur_px) {
        if r != 0 {
            if let Some(dev) = reference_price_deviation(r, c) {
                let threshold = max_diff.max(0.0);
                // `0x366facf`: ucomisd dev, threshold; jbe violation -> within tolerance iff threshold > dev.
                if threshold > dev {
                    tracker.first_violation_ns = None;
                    tracker.last_violation_ns = None;
                    return ReferenceOracleEval {
                        flagged: false,
                        alert_fired: false,
                        tracker_cleared: true,
                    };
                }
            }
        }
    }

    let first = *tracker.first_violation_ns.get_or_insert(now_ns);
    tracker.last_violation_ns = Some(now_ns);

    let delta_ns = now_ns.saturating_sub(first);
    let secs = (delta_ns / 1_000_000_000) as f64;
    let rem_ns = (delta_ns % 1_000_000_000) as f64;
    let mut elapsed = (secs + rem_ns / 1_000_000_000.0).max(0.0);
    if elapsed == f64::INFINITY {
        elapsed = 0.0;
    }

    let exceeded = elapsed > tracker.max_duration_secs;
    let alert_fired = exceeded && alert_enabled;

    ReferenceOracleEval {
        flagged: alert_enabled,
        alert_fired,
        tracker_cleared: false,
    }
}
