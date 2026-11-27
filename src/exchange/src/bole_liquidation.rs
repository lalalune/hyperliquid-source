//! Binary-verified node #115 borrow-lend (`bole`) liquidation spot order construction
//! (`0x2c80670`, `l1/src/exchange/impl_bole.rs:384:35`) and `begin_block` 7-phase periodic
//! lifecycle (`0x2bdf8f0`) / `end_block` action router handoff (`0x2c71250`, `RE-010`).
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

use crate::Address;

/// Hardcoded node #115 borrow-lend (`bole`) liquidator sentinel address
/// (`0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`, observed at `.rodata 0x60e1c7` and
/// `0x2c80904..0x2c80913` via `0x4518f0` + `movl $0xbbbbbbbb`).
pub const BOLE_LIQUIDATOR_ADDRESS: Address = [0xbb; 20];

/// Exact #115 `begin_block` (`0x2bdf8f0`) 7 periodic phase identifiers in VA execution order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeginBlockPhase {
    /// `0x2bdfb11` (`0x60e19e`), bucket guard `(0.35, 0.05)` (`0x453890`).
    DistributeFunding,
    /// `0x2be0732` (`0x60e1db`), bucket guard `(0.01, 0.05)` (`0x453530`).
    UpdateFundingRates,
    /// `0x2be11a0` (`0x60e23a`), bucket guard `(0.01, 0.05)` (`0x453530`).
    CancelAggressiveOrdersAtOiCap,
    /// `0x2be191a` (`0x60e21e`), bucket guard `(0.05, 0.05)` (`0x453520`).
    PruneBookEmptyUserStates,
    /// `0x2be66b6` (`0x60e25c`, alert `begin_block.rs:266:51`), bucket guard `(0.01, 0.05)` (`0x453530`).
    RefreshMainPerpDexStaleOracle,
    /// `0x2be6cb5` (`0x60e203`), bucket guard `(0.01, 0.05)` (`0x453530`).
    RefreshHip3StaleMarkPxs,
    /// `0x2be7ab5` (`0x60e1b0`, sentinel `0xbb * 20` at `0x60e1c7`), bucket guard `(0.01, 0.05)` (`0x453530`).
    ApplyBoleLiquidations,
}

impl BeginBlockPhase {
    /// Exact #115 execution order inside `0x2bdf8f0`.
    pub const SCHEDULE_ORDER: [Self; 7] = [
        Self::DistributeFunding,
        Self::UpdateFundingRates,
        Self::CancelAggressiveOrdersAtOiCap,
        Self::PruneBookEmptyUserStates,
        Self::RefreshMainPerpDexStaleOracle,
        Self::RefreshHip3StaleMarkPxs,
        Self::ApplyBoleLiquidations,
    ];

    /// Exact `.rodata` phase name string in node #115.
    pub const fn name(self) -> &'static str {
        match self {
            Self::DistributeFunding => "distribute_funding",
            Self::UpdateFundingRates => "update_funding_rates",
            Self::CancelAggressiveOrdersAtOiCap => "cancel_aggressive_orders_at_oi_cap",
            Self::PruneBookEmptyUserStates => "prune_book_empty_user_states",
            Self::RefreshMainPerpDexStaleOracle => "refresh_main_perp_dex_stale_oracle",
            Self::RefreshHip3StaleMarkPxs => "refresh_hip3_stale_mark_pxs",
            Self::ApplyBoleLiquidations => "apply_bole_liquidations",
        }
    }

    /// Exact `.rodata` bucket-guard `(f64, f64)` thresholds loaded before each phase.
    pub const fn bucket_guard(self) -> (f64, f64) {
        match self {
            Self::DistributeFunding => (0.35, 0.05),
            Self::PruneBookEmptyUserStates => (0.05, 0.05),
            Self::UpdateFundingRates
            | Self::CancelAggressiveOrdersAtOiCap
            | Self::RefreshMainPerpDexStaleOracle
            | Self::RefreshHip3StaleMarkPxs
            | Self::ApplyBoleLiquidations => (0.01, 0.05),
        }
    }
}

/// Spot pair summary (`SpotInfo` stride `0x20`, `quote_token` at `+0x8`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpotPairMeta {
    pub spot_id: usize,
    pub base_token: usize,
    pub quote_token: usize,
}

/// Constructed forced IOC liquidation cross emitted by `0x2c80670` (`impl_bole.rs:384:35`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoleLiquidationCrossOrder {
    pub oid: u64,
    pub spot_id: usize,
    pub token: usize,
    pub liquidator: Address,
    pub liquidated_user: Address,
    /// Rounded, floor-1 execution limit price (`>= 1`).
    pub limit_px: u64,
    pub size_sz: u64,
    /// Forced IOC (`tif = 1` at `0x2c809a4`).
    pub tif: u8,
    /// Original spot oracle/mark price from `Exchange+0x6c8`.
    pub reference_spot_px: u64,
}

/// Exact #115 `0x2c807df..0x2c808b2` price rounding (`0x63efe40` = `f64::round`),
/// saturating `u64` cast, and `0 -> 1` floor (`cmpq $1, %r8; adcq $0, %r8`).
pub fn compute_bole_liquidation_limit_px(spot_px: u64, price_multiplier: f64) -> u64 {
    let eff_mult = (price_multiplier + (-1.0)) + 1.0;
    let raw = ((spot_px as f64) * eff_mult).round();
    let clamped = raw.max(0.0);
    let px = if !clamped.is_finite() {
        0u64
    } else if clamped >= (u64::MAX as f64) {
        u64::MAX
    } else {
        clamped as u64
    };
    px.max(1)
}

/// Reconstructs `0x2c80670` (`l1/src/exchange/impl_bole.rs:384:35`).
///
/// Rejects `token == 0` (USDC), finds the first spot market with `quote_token == 0` for `token`,
/// requires a present `spot_px`, increments `next_oid` saturating at `u64::MAX`, computes the
/// rounded floor-1 limit price, and returns the forced IOC cross order between
/// `BOLE_LIQUIDATOR_ADDRESS` (`0xbb * 20`) and `liquidated_user`.
pub fn build_bole_liquidation_spot_order(
    token: usize,
    size_sz: u64,
    price_multiplier: f64,
    liquidated_user: Address,
    token_spots: &[SpotPairMeta],
    spot_px: Option<u64>,
    next_oid: &mut u64,
) -> Option<BoleLiquidationCrossOrder> {
    if token == 0 {
        return None;
    }
    let spot = token_spots
        .iter()
        .find(|s| s.base_token == token && s.quote_token == 0)?;
    let reference_spot_px = spot_px?;

    let oid = *next_oid;
    *next_oid = next_oid.saturating_add(1);

    let limit_px = compute_bole_liquidation_limit_px(reference_spot_px, price_multiplier);

    Some(BoleLiquidationCrossOrder {
        oid,
        spot_id: spot.spot_id,
        token,
        liquidator: BOLE_LIQUIDATOR_ADDRESS,
        liquidated_user,
        limit_px,
        size_sz,
        tif: 1,
        reference_spot_px,
    })
}
