//! Binary-verified node #115 clearinghouse margin table, position margin summary,
//! user available margin, and spot existing-token balance routines (`RE-007`).
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
//!
//! Static FDE provenance:
//! - `0x38b4e20..0x38b4f7a`: `MarginTable::first_tier` (`l1/src/clearinghouse/margin_table.rs:139:57`)
//! - `0x38b54b0..0x38b55f3`: `MarginTable::maintenance_margin` (`margin_table.rs:145:105`)
//! - `0x38b5300..0x38b54a9`: `MarginTable::backstop_margin` (`margin_table.rs:145:105`, exact `2/3` integer formula)
//! - `0x3c43150..0x3c432f4`: `MarginTableStore::get` (`id < 50` built-in vs `id >= 50` custom table)
//! - `0x448b800..0x448b967`: `Position::margin_summary` (`position.rs:204:57`, 5-arm jump table `0x7cf4cc`)
//! - `0x3beb700..0x3beb972`: `UserState::available_margin` (`user_state.rs:89:60`, `oracle.rs:433:18`)
//! - `0x3d5e540..0x3d5e817`: `SpotClearinghouse::compute_existing_token_balances` (`spot_clearinghouse.rs:959:98`)

use std::collections::BTreeMap;

/// Built-in single-tier leverage margin table ID upper bound (`cmpl $0x32, %edx` in `0x3c43150`).
pub const BUILTIN_MARGIN_TABLE_ID_LIMIT: u32 = 50;

/// Perp DEX asset index stride (`0x346dc5d63886594b >> 11` / `imul $0x2710` in `0x3beb700`).
pub const HIP3_PERP_ASSET_STRIDE: usize = 10_000;

/// Upper bound on pro-rata token balance ratio (`0x4590b8` = `1.01_f64` in `0x3d5e540`).
pub const EXISTING_BALANCE_RATIO_MAX: f64 = 1.01;

/// Error tag emitted on `u64` overflow in `0x3d5e540` (`movw $0x109, (%rdx)`).
pub const TAG_EXISTING_TOKEN_BALANCE_OVERFLOW: u16 = 0x109;

/// Single notional tier inside a #115 `MarginTable`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarginTier {
    /// Inclusive lower notional bound (`lower_bound <= ntl`).
    pub lower_bound: u64,
    /// Maximum leverage allowed in this tier (`u8`, offset `-0x8` in tier value).
    pub max_leverage: u8,
    /// Maintenance margin deduction (`u64`, offset `-0x10` in tier value).
    pub maintenance_deduction: u64,
}

/// Errors returned by margin-table and position-margin routines instead of panicking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarginStateError {
    /// Empty margin table (`l1/src/clearinghouse/margin_table.rs:139:57`).
    EmptyMarginTable,
    /// No tier with `lower_bound <= ntl` (`l1/src/clearinghouse/margin_table.rs:145:105`).
    NoMatchingTier { ntl: u64 },
    /// Custom margin table ID not found (`0x3c43150`).
    UnknownMarginTableId(u32),
    /// Zero leverage divisor (`max_leverage == 0` or `leverage == 0`).
    ZeroLeverage,
    /// Negative mark price or `mark_px * szi` signed overflow (`l1/src/clearinghouse/position.rs:204:57`).
    InvalidMarkOrNotionalOverflow,
    /// Local perp asset index (`asset % 10_000`) out of `oracle_pxs` bounds (`oracle.rs:433:18`).
    OracleIndexOutOfBounds { local_index: usize, len: usize },
    /// Expected isolated position summary in isolated available-margin path (`user_state.rs:89:60`).
    ExpectedIsolatedPosition,
    /// Negative margin used (`qtys/mod.rs:847:1`).
    NegativeMarginUsed(i64),
}

/// Tiered margin table matching node #115 (`0x38b4e20`, `0x38b54b0`, `0x38b5300`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarginTable {
    tiers: BTreeMap<u64, (u64, u8)>,
}

impl MarginTable {
    /// Construct a margin table from tier definitions.
    pub fn from_tiers(tiers: impl IntoIterator<Item = MarginTier>) -> Result<Self, MarginStateError> {
        let mut map = BTreeMap::new();
        for t in tiers {
            if t.max_leverage == 0 {
                return Err(MarginStateError::ZeroLeverage);
            }
            map.insert(t.lower_bound, (t.maintenance_deduction, t.max_leverage));
        }
        if map.is_empty() {
            return Err(MarginStateError::EmptyMarginTable);
        }
        Ok(Self { tiers: map })
    }

    /// Construct a single-tier simple leverage table (`lower_bound = 0`, `deduction = 0`).
    pub fn simple(max_leverage: u8) -> Result<Self, MarginStateError> {
        Self::from_tiers([MarginTier {
            lower_bound: 0,
            max_leverage,
            maintenance_deduction: 0,
        }])
    }

    /// Return the first (lowest `lower_bound`) tier (`0x38b4e20`, `margin_table.rs:139:57`).
    pub fn first_tier(&self) -> Result<MarginTier, MarginStateError> {
        self.tiers
            .iter()
            .next()
            .map(|(&lower_bound, &(maintenance_deduction, max_leverage))| MarginTier {
                lower_bound,
                max_leverage,
                maintenance_deduction,
            })
            .ok_or(MarginStateError::EmptyMarginTable)
    }

    /// Look up the highest tier with `lower_bound <= ntl` (`..=ntl` `.next_back()`).
    pub fn tier_for_ntl(&self, ntl: u64) -> Result<MarginTier, MarginStateError> {
        self.tiers
            .range(..=ntl)
            .next_back()
            .map(|(&lower_bound, &(maintenance_deduction, max_leverage))| MarginTier {
                lower_bound,
                max_leverage,
                maintenance_deduction,
            })
            .ok_or(MarginStateError::NoMatchingTier { ntl })
    }

    /// Exact #115 tiered maintenance margin (`0x38b54b0`):
    /// `(ntl / (2 * max_leverage)).saturating_sub(maintenance_deduction)`.
    ///
    /// Returns `(margin, saturated)` where `saturated` mirrors the `impl_ntl.rs:26` alert hook.
    pub fn maintenance_margin(&self, ntl: u64) -> Result<(u64, bool), MarginStateError> {
        let tier = self.tier_for_ntl(ntl)?;
        let denom = u64::from(tier.max_leverage) * 2;
        if denom == 0 {
            return Err(MarginStateError::ZeroLeverage);
        }
        let raw = ntl / denom;
        match raw.checked_sub(tier.maintenance_deduction) {
            Some(v) => Ok((v, false)),
            None => Ok((0, true)),
        }
    }

    /// Exact #115 tiered backstop/liquidation margin (`0x38b5300`):
    /// `((2 * ntl) - (4 * max_leverage * maintenance_deduction)) / (6 * max_leverage)`,
    /// which is integer `2/3` of maintenance margin with exact #115 saturation semantics.
    ///
    /// Returns `(margin, saturated)` where `saturated` mirrors the `impl_ntl.rs:26` alert hooks.
    pub fn backstop_margin(&self, ntl: u64) -> Result<(u64, bool), MarginStateError> {
        let tier = self.tier_for_ntl(ntl)?;
        let lev = u64::from(tier.max_leverage);
        if lev == 0 {
            return Err(MarginStateError::ZeroLeverage);
        }
        let mut saturated = false;
        let two_ntl = match ntl.checked_mul(2) {
            Some(v) => v,
            None => {
                saturated = true;
                u64::MAX
            }
        };
        let four_lev = lev * 4;
        let ded_term = four_lev.saturating_mul(tier.maintenance_deduction);
        let num = match two_ntl.checked_sub(ded_term) {
            Some(v) => v,
            None => {
                saturated = true;
                0
            }
        };
        let denom = lev * 6;
        Ok((num / denom, saturated))
    }
}

/// Margin table registry mirroring `0x3c43150`:
/// - `id < 50`: built-in single-tier table with `max_leverage = id as u8` (for `id >= 1`).
/// - `id >= 50`: custom tiered table from the B-tree map.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MarginTableStore {
    custom: BTreeMap<u32, MarginTable>,
}

impl MarginTableStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_custom(&mut self, id: u32, table: MarginTable) {
        self.custom.insert(id, table);
    }

    /// Resolve a `MarginTableId` (`0x3c43150`).
    pub fn resolve(&self, id: u32) -> Result<MarginTable, MarginStateError> {
        if id < BUILTIN_MARGIN_TABLE_ID_LIMIT {
            let lev = u8::try_from(id).map_err(|_| MarginStateError::UnknownMarginTableId(id))?;
            if lev == 0 {
                return Err(MarginStateError::ZeroLeverage);
            }
            MarginTable::simple(lev)
        } else {
            self.custom
                .get(&id)
                .cloned()
                .ok_or(MarginStateError::UnknownMarginTableId(id))
        }
    }
}

/// Five-arm `MarginRequirement` enum matching jump table `0x7cf4cc` in `0x448b800`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MarginRequirement {
    /// Arm 0 (`0x448b8b0`): zero required margin.
    Zero = 0,
    /// Arm 1 (`0x448b847`): `ntl / pos.leverage`.
    Initial = 1,
    /// Arm 2 (`0x448b890`): `table(pos.margin_table_id).maintenance_margin(ntl)` (`0x38b54b0`).
    Maintenance = 2,
    /// Arm 3 (`0x448b8df`): `table(pos.margin_table_id).backstop_margin(ntl)` (`0x38b5300`).
    Backstop = 3,
    /// Arm 4 (`0x448b868`): `ntl / pos.leverage.min(max_leverage)`.
    InitialCapped = 4,
}

/// Position fields consumed by `0x448b800` (`Position::margin_summary`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PositionMarginInput {
    /// `true` => Isolated (`tag == 1` at `+0x0`), `false` => Cross (`tag == 0`).
    pub is_isolated: bool,
    /// Position leverage (`+0x4`, `u32`).
    pub leverage: u32,
    /// Isolated raw USD balance (`+0x8`, `i64`; ignored for Cross).
    pub raw_usd: i64,
    /// Signed position size (`+0x10`, `i64`).
    pub szi: i64,
    /// Margin table ID (`+0x38`, `u32`).
    pub margin_table_id: u32,
}

/// Output enum of `0x448b800` (`Position::margin_summary`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PositionMarginSummary {
    /// Cross position summary (`tag = 0` at `out+0x0`).
    Cross {
        ntli: i64,
        margin_required: u64,
        ntl: u64,
    },
    /// Isolated position summary (`tag = 1` at `out+0x0`).
    Isolated {
        account_value: i64,
        margin_used: i64,
        ntl: u64,
        raw_usd: i64,
        margin_required: u64,
        saturated_account_value: bool,
    },
}

/// Reconstructs `0x448b800` (`l1/src/clearinghouse/position.rs:204:57`).
pub fn position_margin_summary(
    pos: &PositionMarginInput,
    mark_px: i64,
    requirement: MarginRequirement,
    max_leverage: u8,
    tables: &MarginTableStore,
) -> Result<PositionMarginSummary, MarginStateError> {
    if mark_px < 0 {
        return Err(MarginStateError::InvalidMarkOrNotionalOverflow);
    }
    let ntli = mark_px
        .checked_mul(pos.szi)
        .ok_or(MarginStateError::InvalidMarkOrNotionalOverflow)?;
    let ntl = ntli.unsigned_abs();

    let margin_required = match requirement {
        MarginRequirement::Zero => 0,
        MarginRequirement::Initial => {
            if pos.leverage == 0 {
                return Err(MarginStateError::ZeroLeverage);
            }
            ntl / u64::from(pos.leverage)
        }
        MarginRequirement::InitialCapped => {
            let eff = pos.leverage.min(u32::from(max_leverage));
            if eff == 0 {
                return Err(MarginStateError::ZeroLeverage);
            }
            ntl / u64::from(eff)
        }
        MarginRequirement::Maintenance => {
            let table = tables.resolve(pos.margin_table_id)?;
            table.maintenance_margin(ntl)?.0
        }
        MarginRequirement::Backstop => {
            let table = tables.resolve(pos.margin_table_id)?;
            table.backstop_margin(ntl)?.0
        }
    };

    if pos.is_isolated {
        let (account_value, saturated_account_value) = match pos.raw_usd.checked_add(ntli) {
            Some(v) => (v, false),
            None => (pos.raw_usd.saturating_add(ntli), true),
        };
        let margin_used = account_value.max(0);
        Ok(PositionMarginSummary::Isolated {
            account_value,
            margin_used,
            ntl,
            raw_usd: pos.raw_usd,
            margin_required,
            saturated_account_value,
        })
    } else {
        Ok(PositionMarginSummary::Cross {
            ntli,
            margin_required,
            ntl,
        })
    }
}

/// Reconstructs the isolated path of `0x3beb700` (`l1/src/clearinghouse/user_state.rs:89:60`).
///
/// Uses exact HIP-3 perp `local_index = asset % 10_000` indexing into `oracle_pxs`,
/// calls `0x448b800` (`position_margin_summary`), verifies isolated tag and `margin_required >= 0`,
/// and returns `(available_margin, saturated_sub)`.
pub fn available_margin_isolated(
    asset: usize,
    pos: Option<&PositionMarginInput>,
    oracle_pxs: &[i64],
    requirement: MarginRequirement,
    max_leverage: u8,
    tables: &MarginTableStore,
) -> Result<(i64, bool), MarginStateError> {
    let Some(pos) = pos else {
        return Ok((0, false));
    };
    let local_index = asset % HIP3_PERP_ASSET_STRIDE;
    let mark_px = *oracle_pxs
        .get(local_index)
        .ok_or(MarginStateError::OracleIndexOutOfBounds {
            local_index,
            len: oracle_pxs.len(),
        })?;
    let summary = position_margin_summary(pos, mark_px, requirement, max_leverage, tables)?;
    let PositionMarginSummary::Isolated {
        account_value,
        margin_required,
        ..
    } = summary
    else {
        return Err(MarginStateError::ExpectedIsolatedPosition);
    };
    let margin_i64 = i64::try_from(margin_required)
        .map_err(|_| MarginStateError::NegativeMarginUsed(margin_required as i64))?;
    available_margin_cross(account_value, margin_i64)
}

/// Reconstructs the cross subtraction core of `0x3beb700` (`qtys/mod.rs:847:1` + `impl_ntl.rs:70:1`).
pub fn available_margin_cross(
    account_value: i64,
    margin_used: i64,
) -> Result<(i64, bool), MarginStateError> {
    if margin_used < 0 {
        return Err(MarginStateError::NegativeMarginUsed(margin_used));
    }
    match account_value.checked_sub(margin_used) {
        Some(v) => Ok((v, false)),
        None => Ok((account_value.saturating_sub(margin_used), true)),
    }
}

/// Output entry of `0x3d5e540` (`SpotClearinghouse::compute_existing_token_balances`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenBalanceAllocation {
    pub user: [u8; 20],
    pub wei: u64,
}

/// Error returned by `compute_existing_token_balances` (`0x3d5e540`).
#[derive(Clone, Debug, PartialEq)]
pub enum ExistingTokenBalanceError {
    /// Ratio outside `[0.0, 1.01]` (`l1/src/spot_clearinghouse/spot_clearinghouse.rs:959:98`).
    RatioOutOfBounds { ratio: f64 },
    /// `total_wei + marginal_wei` overflowed `u64` (tag `0x109`, format string `0x444ed0`).
    TotalWeiOverflow {
        tag: u16,
        total_wei: u64,
        marginal_wei: u64,
        message: String,
    },
}

/// Reconstructs `0x3d5e540` (`l1/src/spot_clearinghouse/spot_clearinghouse.rs:959:98`).
///
/// Distributes `alloc_wei` pro-rata across existing holder entries (`existing_wei / total_existing`),
/// asserting `0.0 <= ratio <= 1.01` (`0x4590b8`), mapping `+inf` to `0`, saturating to `u64::MAX`,
/// filtering entries below `min_balance`, and checking `total_wei` addition against `u64` overflow.
pub fn compute_existing_token_balances(
    entries: &[([u8; 20], u64)],
    total_existing: u64,
    alloc_wei: u64,
    min_balance: u64,
    total_wei: &mut u64,
) -> Result<Vec<TokenBalanceAllocation>, ExistingTokenBalanceError> {
    let mut out = Vec::new();
    let total_existing_f = total_existing as f64;
    let alloc_f = alloc_wei as f64;
    const TWO_POW_64: f64 = 18_446_744_073_709_551_616.0;

    for &(user, existing_wei) in entries {
        let ratio = (existing_wei as f64) / total_existing_f;
        // Binary `0x3d5e640..0x3d5e650`: ucomisd 0.0 -> jb panic; ucomisd ratio, 1.01 -> jb panic.
        // Note: NaN sets CF=1, so both `jb` branches panic on NaN too.
        if !(0.0..=EXISTING_BALANCE_RATIO_MAX).contains(&ratio) {
            return Err(ExistingTokenBalanceError::RatioOutOfBounds { ratio });
        }
        let mut scaled = ratio * alloc_f;
        if scaled == f64::INFINITY {
            scaled = 0.0;
        } else if scaled > TWO_POW_64 {
            scaled = TWO_POW_64;
        }
        let marginal_wei = scaled as u64;
        if marginal_wei < min_balance {
            continue;
        }
        match total_wei.checked_add(marginal_wei) {
            Some(next) => {
                *total_wei = next;
                out.push(TokenBalanceAllocation {
                    user,
                    wei: marginal_wei,
                });
            }
            None => {
                return Err(ExistingTokenBalanceError::TotalWeiOverflow {
                    tag: TAG_EXISTING_TOKEN_BALANCE_OVERFLOW,
                    total_wei: *total_wei,
                    marginal_wei,
                    message: format!(
                        "error while computing existing token balances total_wei={} marginal_wei={}",
                        *total_wei, marginal_wei
                    ),
                });
            }
        }
    }
    Ok(out)
}
