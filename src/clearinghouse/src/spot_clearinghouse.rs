//! Node #115 `l1/src/spot_clearinghouse` core accounting, genesis validation,
//! pro-rata existing-token distribution, balance/entry-notional updates, and
//! fill settlement delta accumulation.
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
//!
//! # Anchored Node #115 FDEs (9 FDEs = 12,360 B)
//! - `#66488` `0x3bf5120..0x3bf5fb3` (3,731 B): `validate_genesis_supply_and_hyperliquidity`
//!   (`100_000_000` lots minimum, `1%` Hyperliquidity minimum exempting `"HYPE"`,
//!   `no_hyperliquidity` zero check, `[0xff; 20]` Hyperliquidity system address, exact max supply).
//! - `#66499` `0x3bfa400..0x3bfa80f` (1,039 B): `validate_token_genesis_update`
//!   (`<= 1000` blacklist batch limit, mutual exclusion with balance updates, blacklist conflict check).
//! - `#66500` `0x3bfa810..0x3bfa90d` (253 B): `validate_token_before_genesis`
//!   (token bounds `0xfa`, USDC `token == 0` rejection, `token_to_max_supply` duplicate check).
//! - `#66501` `0x3bfa910..0x3bfac09` (761 B): `SpotBalance::apply_delta` (`types.rs:159:50`,
//!   checked total debit / saturating hold debit / saturating total credit + proportional `entry_ntl`
//!   with `0x028f5c28f5c28f5c = u64::MAX / 100` guard).
//! - `#66504` `0x3bfb650..0x3bfbeee` (2,206 B): `distribute_to_existing_token_holders`
//!   (`existing_token_max_supply * 1e-6` dust threshold `0x459130`, `0.01` max clawback `0x458e48`).
//! - `#66510` `0x3bfd020..0x3bfd340` (800 B): `SpotClearinghouse::fmt` (`Debug` struct layout map).
//! - `#66512` `0x3bfd3c0..0x3bfdb3c` (1,916 B): `reconcile_pro_rata_distribution`
//!   (shortfall top-up to index 0, `max_clawback_frac` excess trim, final checked-sum invariant).
//! - `#69259` `0x3d5e540..0x3d5e817` (727 B): `compute_pro_rata_allocations`
//!   (`spot_clearinghouse.rs:959:98`, `0.0 <= ratio <= 1.01` `0x4590b8`, `min_alloc_wei` filter,
//!   checked running-total overflow error `0x444ed0`).
//! - `#69050` `0x3d4e560..0x3d4e8ff` (927 B): `SpotFillDeltaAccumulator::record_fill`
//!   (`spot_clearinghouse/cl_trait.rs:940,995,1003,1015,1023,1031`, 128-bit scaled base/quote
//!   credit/debit + fee/builder-fee accumulation).

use std::collections::{BTreeMap, BTreeSet};

use crate::Address;

/// Hyperliquidity system address embedded at `.rodata 0x7baea9` (20 bytes of `0xff`).
pub const HYPERLIQUIDITY_ADDRESS: Address = [0xff; 20];

/// Native USDC spot token index (genesis-locked at `0x3bfa825`).
pub const USDC_TOKEN: usize = 0;

/// Minimum genesis max supply in lots (`0x5f5e100 = 100_000_000` at `0x3bf5188`).
pub const MIN_GENESIS_MAX_SUPPLY_LOTS: u64 = 100_000_000;

/// Maximum number of blacklist users per `TokenGenesis` update (`0x3e8 = 1000` at `0x3bfa429`).
pub const MAX_GENESIS_BLACKLIST_UPDATE_LEN: usize = 1000;

/// Existing-token dust threshold multiplier (`1e-6_f64` at `.rodata 0x459130`, `0x3bfba80`).
pub const EXISTING_TOKEN_DUST_FRACTION: f64 = 1e-6;

/// Default maximum per-holder clawback fraction during rounding reconciliation
/// (`0.01_f64` at `.rodata 0x458e48`, `0x3bfbc83`).
pub const DEFAULT_GENESIS_MAX_CLAWBACK_FRACTION: f64 = 0.01;

/// Upper bound assertion for pro-rata ratio and clawback fraction
/// (`1.01_f64` at `.rodata 0x4590b8`, `0x3d5e64b` and `0x3bfd553`).
pub const PRO_RATA_RATIO_MAX: f64 = 1.01;

/// Upper guard on `entry_ntl` before proportional debit scaling
/// (`0x028f5c28f5c28f5c = 184_467_440_737_095_516 = u64::MAX / 100` at `0x3bfaab3`).
pub const ENTRY_NTL_PROPORTIONAL_SCALE_LIMIT: u64 = 0x028f_5c28_f5c2_8f5c;

/// Exact node #115 `.rodata` error strings from `l1/src/spot_clearinghouse`.
pub const ERR_GENESIS_SUPPLY: &str = "genesis supply error";
pub const ERR_HYPERLIQUIDITY_MIN_1PCT: &str = "Hyperliquidity must be at least 1% of max supply";
pub const ERR_HYPERLIQUIDITY_NONZERO_WHEN_DISABLED: &str =
    "Hyperliquidity balance should be 0 if no hyperliquidity is set.";
pub const ERR_GENESIS_MAX_SUPPLY_INCORRECT: &str = "genesis max supply incorrect";
pub const ERR_MISSING_TOKEN_GENESIS_INFO: &str = "missing token genesis information";
pub const ERR_MAX_SUPPLY_MIN_100M_LOTS: &str = "max supply must be at least 100M lots";
pub const ERR_BLACKLIST_WITH_BALANCES: &str =
    "cannot update blacklist users when either user_and_wei or existing_token_and_wei is non-empty";
pub const ERR_BLACKLIST_EXCEEDS_1000: &str = "blacklist users to update exceeds 1000";
pub const ERR_BLACKLISTED_USER_BALANCE_UPDATE: &str = "cannot update token genesis balance for blacklisted user(s), either remove blacklisted user(s) from user_and_wei or remove the relevant user(s) from the blacklist";
pub const ERR_GENESIS_ALREADY_HAPPENED: &str = "genesis already happened";
pub const ERR_UNABLE_TO_DISTRIBUTE_GENESIS: &str = "unable to distribute genesis tokens to users";
pub const ERR_INVALID_GENESIS_DISTRIBUTION: &str = "invalid genesis distribution";
pub const ERR_EXISTING_TOKEN_MISSING_MAX_SUPPLY: &str = "existing token missing max supply";
pub const ERR_TOTAL_BALANCE_ZERO: &str = "total balance of token is zero";
pub const ERR_NO_USER_HAS_WEI_AFTER_DISTRIBUTING: &str = "no user has wei after distributing";

/// Observed `SpotClearinghouse` field names and struct byte offsets from `#66510` (`0x3bfd020`).
pub const SPOT_CLEARINGHOUSE_DEBUG_FIELDS: &[(&str, usize)] = &[
    ("meta", 0x010),
    ("user_states", 0x370),
    ("daily_exchange_scaled_and_raw_vlms", 0x4d0),
    ("token_to_genesis", 0x4f0),
    ("token_to_max_supply", 0x510),
    ("token_fees_collected", 0x530),
    ("evm_transfer_escrows", 0x5b0),
    ("spot_dusting_opted_out_users", 0x5c8),
];

/// Observed 24-byte `SpotBalance` (`total`, `hold`, `entry_ntl`) updated by `#66501` (`0x3bfa910`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpotBalance {
    /// `+0x00`: Total token balance in wei.
    pub total: u64,
    /// `+0x08`: Held (locked in open orders) token balance in wei.
    pub hold: u64,
    /// `+0x10`: Cost-basis notional (`entry_ntl`) for non-USDC spot tokens.
    pub entry_ntl: u64,
}

/// Diagnostic side effects observed in `#66501` (`0x3bfa910`) when saturating fallbacks fire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BalanceUpdateOutcome {
    /// True if debiting `hold` underflowed and was clamped to `0` (`0x3bfaa19`).
    pub hold_underflow_clamped: bool,
    /// True if crediting `total` overflowed and saturated to `u64::MAX` (`0x3bfabe7`).
    pub total_overflow_saturated: bool,
}

/// Token decimal metadata needed for genesis validation (`#66488` `0x3bf5120`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpotTokenSpec {
    pub name: String,
    pub sz_decimals: u8,
    pub wei_decimals: u8,
}

impl SpotTokenSpec {
    /// `10^(wei_decimals - sz_decimals)` as computed by binary exponentiation at `0x3bf516e..0x3bf52ac`.
    pub fn wei_per_lot(&self) -> Result<u64, SpotClearinghouseError> {
        let diff = self
            .wei_decimals
            .checked_sub(self.sz_decimals)
            .ok_or(SpotClearinghouseError::InvalidDecimals)?;
        10u64
            .checked_pow(u32::from(diff))
            .ok_or(SpotClearinghouseError::ArithmeticOverflow)
    }

    /// Minimum genesis max supply in wei: `100_000_000 * 10^(wei_decimals - sz_decimals)`.
    pub fn min_genesis_max_supply_wei(&self) -> Result<u64, SpotClearinghouseError> {
        self.wei_per_lot()?
            .checked_mul(MIN_GENESIS_MAX_SUPPLY_LOTS)
            .ok_or(SpotClearinghouseError::ArithmeticOverflow)
    }
}

/// Staged pre-genesis allocation configuration (`#66514` `0x3bfdf80`: `user_balances`,
/// `existing_token_balances`, `blacklist_users`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenGenesis {
    pub user_balances: BTreeMap<Address, u64>,
    pub existing_token_balances: BTreeMap<usize, u64>,
    pub blacklist_users: BTreeSet<Address>,
}

/// Errors emitted by `SpotClearinghouse` accounting and genesis checks (preserving node #115 tags).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpotClearinghouseError {
    /// Tag `0xfa` (`0x3bfa8ad`): token index out of `meta.tokens` bounds.
    InvalidToken(usize),
    /// Tag `0xee` (`0x3bfa437`, `0x3bfa4f5`, `0x3bfa719`): genesis update validation failure.
    GenesisUpdateRejected(&'static str),
    /// Tag `0xf9` (`0x3bf51ad`, `0x3bf56e2`, `0x3bfa8ed`, `0x3bfb75d`, `0x3bfbd00`): genesis failure.
    GenesisFailed(&'static str),
    /// Tag `0x109` (`0x3d5e772`, `0x3bfd6c3`, `0x3bfd820`, `0x3bfd8c4`, `0x3bfd9d2`): internal bug/distribution error.
    DistributionInvariant(String),
    /// Panic site `l1/src/spot_clearinghouse/types.rs:159:50` (`0x3bfabda`): debit exceeds `total`.
    InsufficientBalance { total: u64, debit: u64 },
    /// Panic site `l1/src/spot_clearinghouse/spot_clearinghouse.rs:959:98` (`0x3d5e7bd`).
    RatioOutOfBounds,
    /// `wei_decimals < sz_decimals` (`0x3bf5177`).
    InvalidDecimals,
    /// Tag `0xc3` (`0x3bfda3f`, `0x3d4e7d5..0x3d4e888`): checked integer overflow.
    ArithmeticOverflow,
}

impl SpotBalance {
    /// Reconstructs `#66501` (`0x3bfa910..0x3bfac09`, `types.rs:159:50`):
    /// updates `total`, `hold`, and (for non-USDC tokens when `price_wei_to_ntl` is provided)
    /// `entry_ntl` proportionally on debit or additively on credit.
    pub fn apply_delta<F>(
        &mut self,
        token: usize,
        is_debit: bool,
        delta: u64,
        track_entry_ntl: bool,
        mut price_wei_to_ntl: F,
    ) -> Result<BalanceUpdateOutcome, SpotClearinghouseError>
    where
        F: FnMut(u64) -> Option<u64>,
    {
        let old_total = self.total;
        let mut outcome = BalanceUpdateOutcome::default();

        if is_debit {
            let new_total = old_total
                .checked_sub(delta)
                .ok_or(SpotClearinghouseError::InsufficientBalance {
                    total: old_total,
                    debit: delta,
                })?;
            self.total = new_total;
            match self.hold.checked_sub(delta) {
                Some(h) => self.hold = h,
                None => {
                    outcome.hold_underflow_clamped = true;
                    self.hold = 0;
                }
            }
        } else {
            match old_total.checked_add(delta) {
                Some(t) => self.total = t,
                None => {
                    outcome.total_overflow_saturated = true;
                    self.total = u64::MAX;
                }
            }
        }

        if !track_entry_ntl || token == USDC_TOKEN {
            return Ok(outcome);
        }

        if is_debit {
            let new_total = old_total.saturating_sub(delta);
            if self.entry_ntl == 0 {
                self.entry_ntl = price_wei_to_ntl(new_total).unwrap_or(0);
            } else if self.entry_ntl < ENTRY_NTL_PROPORTIONAL_SCALE_LIMIT {
                let ratio = if old_total == 0 {
                    0.0
                } else {
                    (new_total as f64) / (old_total as f64)
                };
                let scaled = (self.entry_ntl as f64) * ratio;
                self.entry_ntl = clamp_f64_to_i64_nonneg(scaled);
            }
        } else {
            let wei_to_price = if self.entry_ntl != 0 {
                delta
            } else {
                match old_total.checked_add(delta) {
                    Some(sum) => sum,
                    None => delta,
                }
            };
            if let Some(delta_ntl) = price_wei_to_ntl(wei_to_price) {
                if let Some(new_ntl) = self.entry_ntl.checked_add(delta_ntl) {
                    self.entry_ntl = new_ntl;
                }
            }
        }

        Ok(outcome)
    }
}

/// Saturating `f64 -> u64` matching the IEEE-754 `0x459010`/`0x459090`/`0x458d58` guard in
/// `0x3d5e678..0x3d5e6d0`, `0x3bfba8c..0x3bfbaf0`, and `0x3bfd5ac..0x3bfd640`.
pub fn saturating_floor_u64(v: f64) -> u64 {
    if !v.is_finite() || v <= 0.0 {
        return 0;
    }
    if v >= (u64::MAX as f64) {
        return u64::MAX;
    }
    v as u64
}

/// Saturating `f64 -> [0, i64::MAX] as u64` matching `0x3bfab25..0x3bfab7e` in `#66501`.
fn clamp_f64_to_i64_nonneg(v: f64) -> u64 {
    if !v.is_finite() || v <= 0.0 {
        return 0;
    }
    if v >= (i64::MAX as f64) {
        return i64::MAX as u64;
    }
    (v as i64).max(0) as u64
}

/// Reconstructs `#69259` (`0x3d5e540..0x3d5e817`, `l1/src/spot_clearinghouse/spot_clearinghouse.rs:959:98`):
/// computes pro-rata `alloc = floor((holder_wei / total_holder_wei) * target_wei_to_distribute)`,
/// asserting `0.0 <= ratio <= 1.01`, filtering `alloc >= min_alloc_wei`, and checked-summing `running_total`.
pub fn compute_pro_rata_allocations(
    holders: &[(Address, u64)],
    total_holder_wei: u64,
    target_wei_to_distribute: u64,
    min_alloc_wei: u64,
) -> Result<(Vec<(Address, u64)>, u64), SpotClearinghouseError> {
    let mut out = Vec::with_capacity(holders.len());
    let mut running_total = 0u64;
    let total_f = total_holder_wei as f64;
    let target_f = target_wei_to_distribute as f64;

    for &(user, holder_wei) in holders {
        let ratio = (holder_wei as f64) / total_f;
        if !(0.0..=PRO_RATA_RATIO_MAX).contains(&ratio) {
            return Err(SpotClearinghouseError::RatioOutOfBounds);
        }
        let alloc = saturating_floor_u64(ratio * target_f);
        if alloc < min_alloc_wei {
            continue;
        }
        running_total = running_total.checked_add(alloc).ok_or_else(|| {
            SpotClearinghouseError::DistributionInvariant(format!(
                "error while computing existing token balances total_wei={running_total} marginal_wei={alloc}"
            ))
        })?;
        out.push((user, alloc));
    }

    Ok((out, running_total))
}

/// Reconstructs `#66512` (`0x3bfd3c0..0x3bfdb3c`):
/// sorts holders descending by balance, validates non-zero total, computes pro-rata allocations
/// via `#69259` (`0x3d5e540`), reconciles any shortfall (added to index 0) or overshoot
/// (clawed back up to `max_clawback_frac` per recipient), and verifies the final checked sum
/// equals `target_wei_to_distribute` exactly.
pub fn reconcile_pro_rata_distribution(
    mut holders: Vec<(Address, u64)>,
    target_wei_to_distribute: u64,
    min_alloc_wei: u64,
    max_clawback_frac: f64,
) -> Result<Vec<(Address, u64)>, SpotClearinghouseError> {
    if holders.len() >= 2 {
        holders.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    }

    let mut total_holder_wei = 0u64;
    for &(_, wei) in &holders {
        match total_holder_wei.checked_add(wei) {
            Some(sum) => total_holder_wei = sum,
            None => {
                return Err(SpotClearinghouseError::DistributionInvariant(
                    ERR_TOTAL_BALANCE_ZERO.to_string(),
                ));
            }
        }
    }
    if total_holder_wei == 0 {
        return Err(SpotClearinghouseError::DistributionInvariant(
            ERR_TOTAL_BALANCE_ZERO.to_string(),
        ));
    }

    let (mut recipients, running_total) = compute_pro_rata_allocations(
        &holders,
        total_holder_wei,
        target_wei_to_distribute,
        min_alloc_wei,
    )?;

    if recipients.is_empty() {
        return Err(SpotClearinghouseError::DistributionInvariant(
            ERR_NO_USER_HAS_WEI_AFTER_DISTRIBUTING.to_string(),
        ));
    }

    if running_total <= target_wei_to_distribute {
        let deficit = target_wei_to_distribute - running_total;
        recipients[0].1 = recipients[0]
            .1
            .checked_add(deficit)
            .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;
    } else {
        if !(0.0..=PRO_RATA_RATIO_MAX).contains(&max_clawback_frac) {
            return Err(SpotClearinghouseError::RatioOutOfBounds);
        }
        let mut excess_remaining = running_total - target_wei_to_distribute;
        for (_, alloc) in &mut recipients {
            let max_take = saturating_floor_u64((*alloc as f64) * max_clawback_frac);
            let take = excess_remaining.min(max_take);
            *alloc = alloc.saturating_sub(take);
            excess_remaining -= take;
            if excess_remaining == 0 {
                break;
            }
        }
        if excess_remaining != 0 {
            return Err(SpotClearinghouseError::DistributionInvariant(format!(
                "could not distribute remainder={excess_remaining} to match exactly"
            )));
        }
    }

    let mut final_sum = 0u64;
    for &(_, alloc) in &recipients {
        final_sum = final_sum.checked_add(alloc).ok_or_else(|| {
            SpotClearinghouseError::DistributionInvariant(format!(
                "BUG: distributing to existing token final_allocation_check=None target_wei_to_distribute={target_wei_to_distribute}"
            ))
        })?;
    }
    if final_sum != target_wei_to_distribute {
        return Err(SpotClearinghouseError::DistributionInvariant(format!(
            "BUG: distributing to existing token final_allocation_check=Some({final_sum}) target_wei_to_distribute={target_wei_to_distribute}"
        )));
    }

    Ok(recipients)
}

/// Core `SpotClearinghouse` accounting model covering the verified node #115 state machines.
#[derive(Debug, Clone, Default)]
pub struct SpotClearinghouse {
    pub tokens: Vec<SpotTokenSpec>,
    pub user_states: BTreeMap<Address, BTreeMap<usize, SpotBalance>>,
    pub token_to_genesis: BTreeMap<usize, TokenGenesis>,
    pub token_to_max_supply: BTreeMap<usize, u64>,
    pub token_fees_collected: BTreeMap<usize, u64>,
    pub spot_dusting_opted_out_users: BTreeSet<Address>,
}

impl SpotClearinghouse {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconstructs `#66500` (`0x3bfa810..0x3bfa90d`): verifies token exists, is not USDC (`0`),
    /// and has not already completed genesis (absent from `token_to_max_supply`).
    pub fn validate_token_before_genesis(
        &self,
        token: usize,
    ) -> Result<usize, SpotClearinghouseError> {
        if token >= self.tokens.len() {
            return Err(SpotClearinghouseError::InvalidToken(token));
        }
        if token == USDC_TOKEN || self.token_to_max_supply.contains_key(&token) {
            return Err(SpotClearinghouseError::GenesisFailed(
                ERR_GENESIS_ALREADY_HAPPENED,
            ));
        }
        Ok(token)
    }

    /// Reconstructs `#66499` (`0x3bfa400..0x3bfa80f`): validates a `TokenGenesis` update batch.
    pub fn validate_token_genesis_update(
        &self,
        token: usize,
        user_and_wei: &[(Address, u64)],
        existing_token_and_wei: &[(usize, u64)],
        blacklist_users_update: Option<&[(Address, bool)]>,
    ) -> Result<(), SpotClearinghouseError> {
        if let Some(blacklist_updates) = blacklist_users_update {
            if blacklist_updates.len() > MAX_GENESIS_BLACKLIST_UPDATE_LEN {
                return Err(SpotClearinghouseError::GenesisUpdateRejected(
                    ERR_BLACKLIST_EXCEEDS_1000,
                ));
            }
            if !user_and_wei.is_empty() || !existing_token_and_wei.is_empty() {
                return Err(SpotClearinghouseError::GenesisUpdateRejected(
                    ERR_BLACKLIST_WITH_BALANCES,
                ));
            }
            return Ok(());
        }

        if let Some(genesis) = self.token_to_genesis.get(&token) {
            if !genesis.blacklist_users.is_empty() {
                for &(user, _) in user_and_wei {
                    if genesis.blacklist_users.contains(&user) {
                        return Err(SpotClearinghouseError::GenesisUpdateRejected(
                            ERR_BLACKLISTED_USER_BALANCE_UPDATE,
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Reconstructs `#66488` (`0x3bf5120..0x3bf5fb3`): validates genesis max supply (`>= 100M lots`),
    /// staged genesis existence, Hyperliquidity rules (`[0xff; 20]` == 0 if `no_hyperliquidity`,
    /// else `>= max_supply / 100` unless token name is `"HYPE"`), and exact total supply equality.
    pub fn validate_genesis_supply_and_hyperliquidity(
        &self,
        token: usize,
        max_supply_wei: u64,
        no_hyperliquidity: bool,
        enforce_hyperliquidity_min: bool,
    ) -> Result<(), SpotClearinghouseError> {
        let spec = self
            .tokens
            .get(token)
            .ok_or(SpotClearinghouseError::InvalidToken(token))?;
        let min_supply = spec.min_genesis_max_supply_wei()?;
        if max_supply_wei < min_supply {
            return Err(SpotClearinghouseError::GenesisFailed(
                ERR_MAX_SUPPLY_MIN_100M_LOTS,
            ));
        }

        let genesis = self.token_to_genesis.get(&token).ok_or(
            SpotClearinghouseError::GenesisFailed(ERR_MISSING_TOKEN_GENESIS_INFO),
        )?;

        let hl_balance = genesis
            .user_balances
            .get(&HYPERLIQUIDITY_ADDRESS)
            .copied()
            .unwrap_or(0);

        if no_hyperliquidity {
            if hl_balance != 0 {
                return Err(SpotClearinghouseError::GenesisFailed(
                    ERR_HYPERLIQUIDITY_NONZERO_WHEN_DISABLED,
                ));
            }
        } else if enforce_hyperliquidity_min {
            let min_hl = max_supply_wei / 100;
            if hl_balance < min_hl && spec.name != "HYPE" {
                return Err(SpotClearinghouseError::GenesisFailed(
                    ERR_HYPERLIQUIDITY_MIN_1PCT,
                ));
            }
        }

        let mut total = 0u64;
        for &wei in genesis.user_balances.values() {
            total = total.checked_add(wei).ok_or(
                SpotClearinghouseError::GenesisFailed(ERR_GENESIS_SUPPLY),
            )?;
        }
        for &wei in genesis.existing_token_balances.values() {
            total = total.checked_add(wei).ok_or(
                SpotClearinghouseError::GenesisFailed(ERR_GENESIS_SUPPLY),
            )?;
        }
        if total != max_supply_wei {
            return Err(SpotClearinghouseError::GenesisFailed(
                ERR_GENESIS_MAX_SUPPLY_INCORRECT,
            ));
        }

        Ok(())
    }

    /// Reconstructs `#66504` (`0x3bfb650..0x3bfbeee`) + `#66512` (`0x3bfd3c0`) + `#69259` (`0x3d5e540`):
    /// computes the pro-rata distribution of `target_wei_to_distribute` of `new_token` across
    /// non-blacklisted holders of `existing_token` whose existing balance meets the `1e-6 * max_supply`
    /// dust threshold, reconciling rounding error with `max_clawback_frac = 0.01`.
    pub fn distribute_to_existing_token_holders(
        &self,
        new_token: usize,
        existing_token: usize,
        target_wei_to_distribute: u64,
        min_alloc_wei: u64,
    ) -> Result<Vec<(Address, u64)>, SpotClearinghouseError> {
        let existing_max_supply = *self.token_to_max_supply.get(&existing_token).ok_or(
            SpotClearinghouseError::GenesisFailed(ERR_EXISTING_TOKEN_MISSING_MAX_SUPPLY),
        )?;
        let blacklist = self
            .token_to_genesis
            .get(&new_token)
            .map(|g| &g.blacklist_users);

        let min_existing_wei =
            saturating_floor_u64((existing_max_supply as f64) * EXISTING_TOKEN_DUST_FRACTION);

        let mut eligible = Vec::new();
        for (&user, balances) in &self.user_states {
            if blacklist.is_some_and(|bl| bl.contains(&user)) {
                continue;
            }
            if let Some(bal) = balances.get(&existing_token) {
                if bal.total >= min_existing_wei && bal.total > 0 {
                    eligible.push((user, bal.total));
                }
            }
        }

        reconcile_pro_rata_distribution(
            eligible,
            target_wei_to_distribute,
            min_alloc_wei,
            DEFAULT_GENESIS_MAX_CLAWBACK_FRACTION,
        )
        .map_err(|_| SpotClearinghouseError::GenesisFailed(ERR_UNABLE_TO_DISTRIBUTE_GENESIS))
    }
}

/// Four-slot spot fill settlement delta accumulator (`#69050` `0x3d4e560..0x3d4e8ff`,
/// `l1/src/spot_clearinghouse/cl_trait.rs:940,995,1003,1015,1023,1031`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpotFillDeltaAccumulator {
    /// `+0x00`: Base token credited.
    pub base_credit: u64,
    /// `+0x08`: Quote token credited.
    pub quote_credit: u64,
    /// `+0x10`: Base token debited (including fees when bid side pays base/quote).
    pub base_debit: u64,
    /// `+0x18`: Quote token debited (including fees when ask/bid pays quote).
    pub quote_debit: u64,
}

/// Fill inputs consumed by `#69050` (`0x3d4e560`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpotFillDeltaInput {
    pub is_bid: bool,
    /// Scaled fill notional (`+0x60`) converted via `mul_scale / div_scale` on ask side.
    pub credit_raw: u64,
    /// Scaled fill quantity (`+0x68`) converted via `mul_scale / div_scale` on bid side.
    pub debit_raw: u64,
    pub mul_scale: u64,
    pub div_scale: u64,
    /// Optional primary fee (`+0x00` flag, `+0x08` amount).
    pub primary_fee: Option<u64>,
    /// Optional secondary/protocol fee (`+0x28` flag, `+0x40` amount).
    pub secondary_fee: Option<u64>,
    /// Optional builder fee (`+0x70`).
    pub builder_fee: u64,
}

/// Result flags returned in `(%rbx)` by `#69050` (`0x3d4e766`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpotFillRecordFlags {
    pub credited: bool,
    pub debited: bool,
}

fn scale_u64_exact(val: u64, mul_scale: u64, div_scale: u64) -> Result<u64, SpotClearinghouseError> {
    if div_scale == 0 {
        return Err(SpotClearinghouseError::ArithmeticOverflow);
    }
    let prod = u128::from(val) * u128::from(mul_scale);
    let q = prod / u128::from(div_scale);
    u64::try_from(q).map_err(|_| SpotClearinghouseError::ArithmeticOverflow)
}

impl SpotFillDeltaAccumulator {
    /// Reconstructs `#69050` (`0x3d4e560..0x3d4e8ff`):
    /// - When `credit_raw != 0`: on bid (`is_bid=true`) adds directly to `quote_credit` (`+0x08`);
    ///   on ask (`is_bid=false`) scales by `mul_scale / div_scale` (`u128` mul+div, checking high 64 bits == 0)
    ///   and adds to `base_credit` (`+0x00`).
    /// - When `debit_raw != 0`: on ask (`is_bid=false`) adds directly to `quote_debit` (`+0x18`);
    ///   on bid (`is_bid=true`) scales by `mul_scale / div_scale` and adds to `base_debit` (`+0x10`).
    /// - Adds `primary_fee`, `secondary_fee`, and `builder_fee` into `debit[is_bid as usize]`
    ///   (`+0x10` for ask `0`, `+0x18` for bid `1`), returning `ArithmeticOverflow` (`0xc3`) on any carry.
    pub fn record_fill(
        &mut self,
        input: &SpotFillDeltaInput,
    ) -> Result<SpotFillRecordFlags, SpotClearinghouseError> {
        let mut credited = false;
        if input.credit_raw != 0 {
            if input.is_bid {
                self.quote_credit = self
                    .quote_credit
                    .checked_add(input.credit_raw)
                    .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;
            } else {
                let scaled = scale_u64_exact(input.credit_raw, input.mul_scale, input.div_scale)?;
                self.base_credit = self
                    .base_credit
                    .checked_add(scaled)
                    .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;
            }
            credited = true;
        }

        let mut debited = false;
        if input.debit_raw != 0 {
            if input.is_bid {
                let scaled = scale_u64_exact(input.debit_raw, input.mul_scale, input.div_scale)?;
                self.base_debit = self
                    .base_debit
                    .checked_add(scaled)
                    .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;
            } else {
                self.quote_debit = self
                    .quote_debit
                    .checked_add(input.debit_raw)
                    .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;
            }
            debited = true;
        }

        let fee_slot = if input.is_bid {
            &mut self.quote_debit
        } else {
            &mut self.base_debit
        };
        if let Some(fee) = input.primary_fee {
            *fee_slot = fee_slot
                .checked_add(fee)
                .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;
        }
        if let Some(fee) = input.secondary_fee {
            *fee_slot = fee_slot
                .checked_add(fee)
                .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;
        }
        if input.builder_fee != 0 {
            *fee_slot = fee_slot
                .checked_add(input.builder_fee)
                .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;
        }

        Ok(SpotFillRecordFlags { credited, debited })
    }
}
