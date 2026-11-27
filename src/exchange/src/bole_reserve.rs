//! Node #115 Borrow-Lend (`bole`) `Reserve` fixed-point accounting, kinked
//! interest-rate curve, interest accrual, protocol equity/solvency check, and
//! target-utilization liquidity bounds.
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
//!
//! Anchored FDEs in `artifacts/node/115/hl-node` (`work/index/node-115-fde.tsv`
//! #53062..#53069 + #53017, all pure fixed-point math):
//! - `0x369ff10..0x36a003e` (302 B): `Reserve::utilization_scaled` (`0..=10^14`)
//! - `0x36a0040..0x36a01f9` (441 B): `Reserve::protocol_equity_and_solvency_check`
//! - `0x36a0200..0x36a08ad` (1,709 B): `Reserve::accrue_interest`
//! - `0x36a08b0..0x36a09e8` (312 B): `Reserve::utilization_bps` (`0..=10_000`)
//! - `0x36a09f0..0x36a0b25` (309 B): `Reserve::utilization_f64` (`0.0..=1.0`)
//! - `0x36a0b30..0x36a0d72` (578 B): `Reserve::yearly_borrow_rate_bps`
//! - `0x36a0d80..0x36a0fd6` (598 B): `Reserve::yearly_borrow_rate_f64`
//! - `0x36a0fe0..0x36a1327` (839 B): `Reserve::max_delta_wei_for_target_utilization`
//! - `0x36939f0..0x3693bc1` (465 B): user leg minimum-notional dust check (`$100` = `0x5f5e100`)

#![forbid(unsafe_code)]

/// Fixed-point index and rate scale `10^14` (`0x5af3107a4000`), verified at
/// `0x369ff32`, `0x36a0062`, `0x36a0294`, `0x36a0680`, `0x36a08d2`, `0x36a0a12`,
/// `0x36a0b4f`, `0x36a0e52`, `0x36a1015`, and `.rodata 0x459378` (`1e14_f64`).
pub const BOLE_SCALE: u64 = 100_000_000_000_000;

/// Divisor `10^10` converting `BOLE_SCALE` (`10^14`) fractions to basis points
/// (`10^4`), implemented via magic multipliers `0x6df37f675ef7 >> 80` at
/// `0x36a09bb..0x36a09cb` and `0xdbe6fecebdedd5bf >> 97` at `0x36a0ce1..0x36a0cf4`.
pub const BOLE_BPS_DIVISOR: u64 = 10_000_000_000;

/// Milliseconds per Julian year (`365.25 * 86_400 * 1_000 = 31_557_600_000 =
/// 0x758fac300`), verified at `0x36a062e` in `Reserve::accrue_interest`.
pub const BOLE_YEAR_MS: u64 = 31_557_600_000;

/// Minimum non-zero leg notional constant `0x5f5e100` (`100_000_000` in 1e-6 USD
/// = `$100`), passed to `0x4217e60` at `0x3693b7c`.
pub const BOLE_MIN_LEG_NTL: u64 = 100_000_000;

/// Error tags returned by node #115 `Reserve` fixed-point methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BoleMathError {
    /// Tag `0x02`: non-zero rounded output from zero input shares.
    ZeroInputNonZeroOutput = 0x02,
    /// Tag `0x03`: `u64` / `u128` arithmetic overflow (`> u64::MAX`).
    Overflow = 0x03,
    /// Tag `0x06`: division by zero (`target_utilization == 0` or `index == 0`).
    DivisionByZero = 0x06,
    /// Tag `0x07`: non-zero leg value below minimum notional (`0x3693ba1`).
    BelowMinNotional = 0x07,
    /// Tag `0x10`: pool insolvency (`pool_cash + borrow_wei < supply_wei + pending_fee`,
    /// verified at `0x36a0123..0x36a0128`).
    Insolvency = 0x10,
}

/// Piecewise-linear kinked yearly borrow-rate curve (`Reserve` offsets `0x80..0xa0`),
/// all values scaled by [`BOLE_SCALE`] (`10^14` = 100%).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YearlyRateCurve {
    /// Offset `0x80`: yearly rate at 0% utilization.
    pub base_rate: u64,
    /// Offset `0x88`: yearly rate at 100% utilization.
    pub max_rate: u64,
    /// Offset `0x90`: yearly rate at the kink (`optimal_utilization`).
    pub kink_rate: u64,
    /// Offset `0x98`: utilization kink (`0..=BOLE_SCALE`).
    pub optimal_utilization: u64,
}

impl YearlyRateCurve {
    /// Evaluates the exact piecewise-linear yearly borrow rate (scaled by
    /// [`BOLE_SCALE`]) at utilization `util_scaled` (`0..=BOLE_SCALE`), matching
    /// `0x36a0387..0x36a04bc`, `0x36a0c50..0x36a0d70`, and `0x36a0eaa..0x36a0fd1`.
    pub fn evaluate_scaled(&self, util_scaled: u64) -> u64 {
        let scale = BOLE_SCALE as u128;
        if util_scaled == self.optimal_utilization {
            return self.kink_rate;
        }
        if util_scaled < self.optimal_utilization {
            // Segment 1: util < optimal_utilization
            // slope_frac = floor(util * 1e14 / optimal_utilization)
            // rate = base_rate + floor(slope_frac * (kink_rate - base_rate) / 1e14)
            let Some(delta_rate) = self.kink_rate.checked_sub(self.base_rate) else {
                return self.kink_rate;
            };
            let frac = (util_scaled as u128 * scale) / (self.optimal_utilization as u128);
            if frac > u64::MAX as u128 {
                return self.kink_rate;
            }
            let prod = frac * (delta_rate as u128);
            if prod / scale > u64::MAX as u128 {
                return self.kink_rate;
            }
            let inc = (prod / scale) as u64;
            self.base_rate.checked_add(inc).unwrap_or(self.kink_rate)
        } else {
            // Segment 2: util > optimal_utilization
            // If optimal_utilization >= BOLE_SCALE, clamp to max_rate (0x36a0439).
            if self.optimal_utilization >= BOLE_SCALE {
                return self.max_rate;
            }
            let denom = (BOLE_SCALE - self.optimal_utilization) as u128;
            let excess = (util_scaled - self.optimal_utilization) as u128;
            let frac = (excess * scale) / denom;
            let Some(delta_rate) = self.max_rate.checked_sub(self.kink_rate) else {
                return self.max_rate;
            };
            if frac > u64::MAX as u128 {
                return self.max_rate;
            }
            let prod = frac * (delta_rate as u128);
            if prod / scale > u64::MAX as u128 {
                return self.max_rate;
            }
            let inc = (prod / scale) as u64;
            self.kink_rate.checked_add(inc).unwrap_or(self.max_rate)
        }
    }
}

/// Core 176-byte (`0xb0`) node #115 Bole `Reserve` state fields anchored across
/// `0x369ff10..0x36a1327`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoleReserve {
    /// Offset `0x10`: spot oracle price used for leg valuation.
    pub oracle_px: u64,
    /// Offset `0x18`: unborrowed pool cash balance (wei).
    pub pool_cash_wei: u64,
    /// Offset `0x20`: realized protocol fee balance already swept (wei).
    pub realized_protocol_fee_wei: u64,
    /// Offset `0x28`: accrued protocol fee pending cash sweep (wei).
    pub pending_protocol_fee_wei: u64,
    /// Offset `0x40`: total outstanding borrow basis shares.
    pub total_borrow_shares: u64,
    /// Offset `0x58`: cumulative borrow index (scaled by [`BOLE_SCALE`]).
    pub borrow_index: u64,
    /// Offset `0x60`: total outstanding supply basis shares.
    pub total_supply_shares: u64,
    /// Offset `0x78`: cumulative supply index (scaled by [`BOLE_SCALE`]).
    pub supply_index: u64,
    /// Offsets `0x80..0xa0`: kinked piecewise-linear yearly borrow rate curve.
    pub rate_curve: YearlyRateCurve,
    /// Offsets `0xa0..0xac`: timestamp of last interest accrual in milliseconds.
    pub last_accrual_ms: u64,
}

/// Exact `ceil(shares * index / BOLE_SCALE)` conversion used for borrow legs
/// (`0x369ff1e..0x369ff90`, `0x36a004e..0x36a00bf`, `0x36a027e..0x36a02f0`).
pub fn shares_to_wei_ceil(shares: u64, index: u64) -> Result<u64, BoleMathError> {
    let scale = BOLE_SCALE as u128;
    let prod = (shares as u128) * (index as u128);
    let q = prod / scale;
    let r = prod % scale;
    let rounded = q + u128::from(r != 0);
    if rounded > u64::MAX as u128 {
        return Err(BoleMathError::Overflow);
    }
    let out = rounded as u64;
    if shares == 0 && out != 0 {
        return Err(BoleMathError::ZeroInputNonZeroOutput);
    }
    Ok(out)
}

/// Exact `floor(shares * index / BOLE_SCALE)` conversion used for supply legs
/// (`0x369ff92..0x369ffc8`, `0x36a00c2..0x36a00f2`, `0x36a0301..0x36a033f`).
pub fn shares_to_wei_floor(shares: u64, index: u64) -> Result<u64, BoleMathError> {
    let scale = BOLE_SCALE as u128;
    let prod = (shares as u128) * (index as u128);
    let q = prod / scale;
    if q > u64::MAX as u128 {
        return Err(BoleMathError::Overflow);
    }
    Ok(q as u64)
}

impl BoleReserve {
    /// Total borrowed wei rounded UP (`ceil(borrow_shares * borrow_index / 1e14)`).
    pub fn total_borrowed_wei(&self) -> Result<u64, BoleMathError> {
        shares_to_wei_ceil(self.total_borrow_shares, self.borrow_index)
    }

    /// Total supplied wei rounded DOWN (`floor(supply_shares * supply_index / 1e14)`).
    pub fn total_supplied_wei(&self) -> Result<u64, BoleMathError> {
        shares_to_wei_floor(self.total_supply_shares, self.supply_index)
    }

    /// Exact reconstruction of `0x369ff10..0x36a003e` (`302 B`):
    /// utilization scaled by [`BOLE_SCALE`] (`0..=BOLE_SCALE`), returning `0`
    /// when `total_supplied_wei == 0` and clamping at `BOLE_SCALE`.
    pub fn utilization_scaled(&self) -> Result<u64, BoleMathError> {
        let borrow_wei = self.total_borrowed_wei()?;
        let supply_wei = self.total_supplied_wei()?;
        if supply_wei == 0 {
            return Ok(0);
        }
        let util = ((borrow_wei as u128) * (BOLE_SCALE as u128)) / (supply_wei as u128);
        if util > u64::MAX as u128 {
            return Err(BoleMathError::Overflow);
        }
        Ok((util as u64).min(BOLE_SCALE))
    }

    /// Exact reconstruction of `0x36a08b0..0x36a09e8` (`312 B`):
    /// utilization in basis points (`0..=10_000`), computed as
    /// `utilization_scaled() / 10^10`.
    pub fn utilization_bps(&self) -> Result<u64, BoleMathError> {
        Ok(self.utilization_scaled()? / BOLE_BPS_DIVISOR)
    }

    /// Exact reconstruction of `0x36a09f0..0x36a0b25` (`309 B`):
    /// utilization as `f64` (`0.0..=1.0`), dividing `utilization_scaled()` by
    /// `1e14` (`.rodata 0x459378`).
    pub fn utilization_f64(&self) -> Result<f64, BoleMathError> {
        Ok(self.utilization_scaled()? as f64 / (BOLE_SCALE as f64))
    }

    /// Exact reconstruction of `0x36a0b30..0x36a0d72` (`578 B`):
    /// yearly borrow rate in basis points (`rate_scaled / 10^10`).
    /// Falls back to `util = 0` on utilization calculation error, matching
    /// `0x36a0bd5..0x36a0c4a`.
    pub fn yearly_borrow_rate_bps(&self) -> u64 {
        let util = self.utilization_scaled().unwrap_or(0);
        self.rate_curve.evaluate_scaled(util) / BOLE_BPS_DIVISOR
    }

    /// Exact reconstruction of `0x36a0d80..0x36a0fd6` (`598 B`):
    /// yearly borrow rate as `f64` (`rate_scaled as f64 / 1e14`).
    pub fn yearly_borrow_rate_f64(&self) -> f64 {
        let util = self.utilization_scaled().unwrap_or(0);
        self.rate_curve.evaluate_scaled(util) as f64 / (BOLE_SCALE as f64)
    }

    /// Exact reconstruction of `0x36a0040..0x36a01f9` (`441 B`):
    /// checks pool solvency (`pool_cash + borrow_wei >= supply_wei + pending_fee`),
    /// returning [`BoleMathError::Insolvency`] (`0x10`) if insolvent, or total
    /// protocol equity (`realized_fee + pending_fee + surplus`, saturating on
    /// `u64` add overflow after logging, matching `0x36a0131..0x36a01f7`).
    pub fn protocol_equity_and_solvency_check(&self) -> Result<u64, BoleMathError> {
        let borrow_wei = self.total_borrowed_wei()?;
        let supply_wei = self.total_supplied_wei()?;
        let assets = self.pool_cash_wei.saturating_add(borrow_wei);
        let liabilities = self.pending_protocol_fee_wei.saturating_add(supply_wei);
        let surplus = assets
            .checked_sub(liabilities)
            .ok_or(BoleMathError::Insolvency)?;
        let fees = self
            .realized_protocol_fee_wei
            .saturating_add(self.pending_protocol_fee_wei);
        Ok(fees.saturating_add(surplus))
    }

    /// Sweeps `min(pool_cash_wei, pending_protocol_fee_wei)` into
    /// `realized_protocol_fee_wei` (saturating on overflow), matching
    /// `0x36a0237..0x36a026b`.
    pub fn sweep_pending_protocol_fees(&mut self) -> u64 {
        let settled = self.pool_cash_wei.min(self.pending_protocol_fee_wei);
        self.pool_cash_wei -= settled;
        self.pending_protocol_fee_wei -= settled;
        self.realized_protocol_fee_wei = self.realized_protocol_fee_wei.saturating_add(settled);
        settled
    }

    /// Exact reconstruction of `0x36a0200..0x36a08ad` (`1,709 B`):
    /// accrues borrow & supply interest across `dt_ms = cur_time_ms - last_accrual_ms`
    /// using [`BOLE_YEAR_MS`] (`31_557_600_000` ms = 365.25 days) and
    /// `protocol_fee_rate_scaled` (scaled by [`BOLE_SCALE`]), then sweeps
    /// pending protocol fees from `pool_cash_wei`.
    ///
    /// Returns `true` if interest accrual updated the timestamp & indices, or
    /// `false` if skipped (`cur_time_ms <= last_accrual_ms`, `dt_ms > BOLE_YEAR_MS`,
    /// or any intermediate overflow guard triggered).
    pub fn accrue_interest(&mut self, cur_time_ms: u64, protocol_fee_rate_scaled: u64) -> bool {
        if cur_time_ms == self.last_accrual_ms {
            self.sweep_pending_protocol_fees();
            return false;
        }
        let Ok(util) = self.utilization_scaled() else {
            return false;
        };
        let yearly_rate = self.rate_curve.evaluate_scaled(util);
        if cur_time_ms < self.last_accrual_ms {
            return false;
        }
        let dt_ms = cur_time_ms - self.last_accrual_ms;
        // 0x36a062e..0x36a063b: reject elapsed duration > 1 Julian year (0x758fac300 ms).
        if dt_ms > BOLE_YEAR_MS {
            return false;
        }

        let scale = BOLE_SCALE as u128;
        // period_rate = floor(dt_ms * yearly_rate / BOLE_YEAR_MS)
        let period_rate = ((dt_ms as u128) * (yearly_rate as u128)) / (BOLE_YEAR_MS as u128);
        // borrow_index_delta = floor(period_rate * borrow_index / 1e14)
        let borrow_delta_num = period_rate * (self.borrow_index as u128);
        if borrow_delta_num / scale > u64::MAX as u128 {
            return false;
        }
        let borrow_index_delta = (borrow_delta_num / scale) as u64;

        // share_ratio = floor(total_borrow_shares * 1e14 / total_supply_shares), or 0 if supply == 0
        let share_ratio: u128 = if self.total_supply_shares == 0 {
            0
        } else {
            let r = ((self.total_borrow_shares as u128) * scale)
                / (self.total_supply_shares as u128);
            if r > u64::MAX as u128 {
                return false;
            }
            r
        };

        // gross_supply_delta = floor(borrow_index_delta * share_ratio / 1e14)
        let gross_supply_num = (borrow_index_delta as u128) * share_ratio;
        if gross_supply_num / scale > u64::MAX as u128 {
            return false;
        }
        let gross_supply_delta = (gross_supply_num / scale) as u64;

        // protocol_fee_delta = floor(gross_supply_delta * protocol_fee_rate / 1e14)
        let fee_delta_num = (gross_supply_delta as u128) * (protocol_fee_rate_scaled as u128);
        if fee_delta_num / scale > u64::MAX as u128 {
            return false;
        }
        let protocol_fee_delta = (fee_delta_num / scale) as u64;

        // protocol_fee_wei = floor(protocol_fee_delta * total_supply_shares / 1e14)
        let fee_wei_num = (protocol_fee_delta as u128) * (self.total_supply_shares as u128);
        if fee_wei_num / scale > u64::MAX as u128 {
            return false;
        }
        let protocol_fee_wei = (fee_wei_num / scale) as u64;
        if self.total_supply_shares == 0 && protocol_fee_wei != 0 {
            return false;
        }

        let Some(net_supply_delta) = gross_supply_delta.checked_sub(protocol_fee_delta) else {
            return false;
        };
        let Some(new_borrow_index) = self.borrow_index.checked_add(borrow_index_delta) else {
            return false;
        };
        let Some(new_supply_index) = self.supply_index.checked_add(net_supply_delta) else {
            return false;
        };

        self.last_accrual_ms = cur_time_ms;
        self.borrow_index = new_borrow_index;
        self.supply_index = new_supply_index;
        self.pending_protocol_fee_wei = self
            .pending_protocol_fee_wei
            .saturating_add(protocol_fee_wei);
        self.sweep_pending_protocol_fees();
        true
    }

    /// Exact reconstruction of `0x36a0fe0..0x36a1327` (`839 B`):
    /// computes the maximum additional borrowable wei (`is_borrow == true`) or
    /// maximum withdrawable supply wei (`is_borrow == false`) permitted while
    /// keeping reserve utilization `<= target_util_scaled`.
    pub fn max_delta_wei_for_target_utilization(
        &self,
        is_borrow: bool,
        target_util_scaled: u64,
    ) -> Result<u64, BoleMathError> {
        let borrow_wei = self.total_borrowed_wei()?;
        let supply_wei = self.total_supplied_wei()?;
        let scale = BOLE_SCALE as u128;

        if is_borrow {
            // 0x36a10fa..0x36a11af: max additional borrowable wei.
            let target_borrow_num = (supply_wei as u128) * (target_util_scaled as u128);
            if target_borrow_num / scale > u64::MAX as u128 {
                return Err(BoleMathError::Overflow);
            }
            let target_borrow_wei = (target_borrow_num / scale) as u64;
            if supply_wei == 0 && target_borrow_wei != 0 {
                return Err(BoleMathError::ZeroInputNonZeroOutput);
            }
            if self.borrow_index == 0 {
                return Err(BoleMathError::DivisionByZero);
            }
            let target_shares_u128 =
                ((target_borrow_wei as u128) * scale) / (self.borrow_index as u128);
            if target_shares_u128 > u64::MAX as u128 {
                return Err(BoleMathError::Overflow);
            }
            let target_shares = target_shares_u128 as u64;
            if target_borrow_wei == 0 && target_shares != 0 {
                return Err(BoleMathError::ZeroInputNonZeroOutput);
            }
            let delta_shares = target_shares.saturating_sub(self.total_borrow_shares);
            shares_to_wei_floor(delta_shares, self.borrow_index)
        } else {
            // 0x36a11b4..0x36a129c: max withdrawable supply wei.
            if target_util_scaled == 0 {
                return Err(BoleMathError::DivisionByZero);
            }
            let min_sup_num = (borrow_wei as u128) * scale;
            let min_sup_q = min_sup_num / (target_util_scaled as u128);
            let min_sup_r = min_sup_num % (target_util_scaled as u128);
            let min_sup_wei = min_sup_q + u128::from(min_sup_r != 0);
            if min_sup_wei > u64::MAX as u128 {
                return Err(BoleMathError::Overflow);
            }
            let min_sup_wei = min_sup_wei as u64;
            if borrow_wei == 0 && min_sup_wei != 0 {
                return Err(BoleMathError::ZeroInputNonZeroOutput);
            }
            if self.supply_index == 0 {
                return Err(BoleMathError::DivisionByZero);
            }
            let min_sh_num = (min_sup_wei as u128) * scale;
            let min_sh_q = min_sh_num / (self.supply_index as u128);
            let min_sh_r = min_sh_num % (self.supply_index as u128);
            let min_shares = min_sh_q + u128::from(min_sh_r != 0);
            if min_shares > u64::MAX as u128 {
                return Err(BoleMathError::Overflow);
            }
            let min_shares = min_shares as u64;
            if min_sup_wei == 0 && min_shares != 0 {
                return Err(BoleMathError::ZeroInputNonZeroOutput);
            }
            let delta_shares = self.total_supply_shares.saturating_sub(min_shares);
            shares_to_wei_floor(delta_shares, self.supply_index)
        }
    }
}

/// Checks a user's single borrow/supply leg against `min_leg_wei` (anchored to
/// `0x36939f0..0x3693bc1`, where `min_leg_wei` is computed from `BOLE_MIN_LEG_NTL`
/// = `0x5f5e100` = `$100`). Zero wei is always allowed; non-zero wei strictly
/// below `min_leg_wei` returns [`BoleMathError::BelowMinNotional`] (`0x07`).
pub fn check_user_leg_min_wei(
    user_shares: u64,
    index: u64,
    is_borrow: bool,
    min_leg_wei: u64,
) -> Result<(), BoleMathError> {
    let user_wei = if is_borrow {
        shares_to_wei_ceil(user_shares, index)?
    } else {
        shares_to_wei_floor(user_shares, index)?
    };
    if user_wei == 0 {
        return Ok(());
    }
    if min_leg_wei > user_wei {
        return Err(BoleMathError::BelowMinNotional);
    }
    Ok(())
}
