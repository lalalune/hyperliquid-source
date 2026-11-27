//! Perpetual and spot asset metadata grounded in node #115.
//!
//! Binary evidence:
//! - `0x22e4810` (`l1/src/perp_meta.rs:163,287`):
//!   splits `perp_id` by `10_000`, checks `pdi == meta.pdi`, `local < universe.len()`,
//!   loads `sz_decimals` (byte at `universe[local] + 0x1d`, stride `0x20`), enforces
//!   `sz_decimals < 7`, and scales raw prices by `1 / POW10_F64[6 - sz_decimals]`.
//! - `0x22f5de0` (`l1/src/spot_meta.rs:119,590,1055`):
//!   for a `(bid, ask)` pair of raw u64 prices, zero values short-circuit to `0.0` without
//!   touching metadata; nonzero values bounds-check `pair < universe.len()`, load `(base, quote)`
//!   at `universe[pair] + 0x00/+0x08` (stride `0x20`), bounds-check both tokens against
//!   `tokens.len()`, load `quote.wei_decimals` (`+0x49`) and `base.sz_decimals` (`+0x48`,
//!   stride `0x158`), check `quote.wei_decimals >= base.sz_decimals`, and divide by
//!   `POW10_F64[quote.wei_decimals - base.sz_decimals]`.

//! - `0x3d19800` (`l1/src/perp_meta.rs:163,287`), `0x50bea90`, `0x50beb30`:
//!   `px_decimals = 6 - sz_decimals`, `px_to_f64` (`POW10_F64` at `0x91b7c0`), and
//!   zero-short-circuiting `sz_to_f64_zero_fast`.
//! - `0x50be9e0`, `0x3c47660`, `0x3c47ae0`, `0x3c49df0`, `0x3c49360`, `0x3c4b280`, `0x3c4b1a0`:
//!   spot price conversion, token->spot lookup, USDC spot predicate, `10^(wei - sz)` scaling,
//!   and checked `sz -> wei` multiplication (`l1/src/spot_meta.rs:119,590,1055,1074,1206`).
//! - `0x2c58880` (`l1/src/spot_meta.rs:125`):
//!   `set_deployer_trading_fee_share` (`<= 100_000`, strictly decreasing, plus legacy Mainnet
//!   `token <= 195 && chain == 3` one-time init from `0` and no-reset-to-zero rule).

use crate::pdi::{Pdi, PerpAsset, SpotAsset, Token};
use crate::qtys::{MAX_PERP_SZ_DECIMALS, POW10_F64, Px};

/// Maximum deployer trading fee share in `1e-5` units (`100_000 == 100%`, `#115` `0x2c5888d`).
pub const MAX_DEPLOYER_TRADING_FEE_SHARE_E5: u64 = 100_000;

/// Maximum token index eligible for the `#115` Mainnet legacy fee-share rule (`0xc3 == 195`, `0x2c588c8`).
pub const LEGACY_MAINNET_TOKEN_MAX: u64 = 195;

/// Chain discriminant checked at `[rsi + 0xb9a]` in `#115` `0x2c588d1` (`3 == Mainnet`).
pub const MAINNET_CHAIN_TAG: u8 = 3;

/// Errors produced by `#115` `0x2c58880` (`SpotMeta::set_deployer_trading_fee_share`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeployerFeeShareError {
    ExceedsMax,
    CannotResetLegacy,
    CannotIncrease,
}

impl DeployerFeeShareError {
    /// Exact `#115` `.rodata` error string (`0x7bc1d5`, `0x7bc389`, `0x7bc3ac`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExceedsMax => "deployer trading fee share cannot be more than 100%",
            Self::CannotResetLegacy => "cannot reset legacy token fee share",
            Self::CannotIncrease => "deployer trading fee share cannot increase",
        }
    }
}

/// Pure transition rule matching `#115` `0x2c58880` (`l1/src/spot_meta.rs:125`).
///
/// Enforces:
/// - `new_share_e5 <= 100_000` (`MAX_DEPLOYER_TRADING_FEE_SHARE_E5`),
/// - for Mainnet (`chain_tag == 3`) legacy tokens (`token_idx <= 195`):
///   - if `current_share_e5 == 0`, allows setting any valid `new_share_e5`,
///   - else requires `0 < new_share_e5 < current_share_e5` (rejecting increases and resets to `0`),
/// - for all other tokens/chains: requires strictly decreasing `new_share_e5 < current_share_e5`.
pub const fn update_deployer_trading_fee_share(
    token_idx: u64,
    current_share_e5: u64,
    new_share_e5: u64,
    chain_tag: u8,
) -> Result<u64, DeployerFeeShareError> {
    if new_share_e5 > MAX_DEPLOYER_TRADING_FEE_SHARE_E5 {
        return Err(DeployerFeeShareError::ExceedsMax);
    }
    if token_idx <= LEGACY_MAINNET_TOKEN_MAX && chain_tag == MAINNET_CHAIN_TAG {
        if current_share_e5 == 0 {
            return Ok(new_share_e5);
        }
        if current_share_e5 <= new_share_e5 {
            return Err(DeployerFeeShareError::CannotIncrease);
        }
        if new_share_e5 == 0 {
            return Err(DeployerFeeShareError::CannotResetLegacy);
        }
        return Ok(new_share_e5);
    }
    if current_share_e5 <= new_share_e5 {
        return Err(DeployerFeeShareError::CannotIncrease);
    }
    Ok(new_share_e5)
}

/// Errors produced by `#115` perp/spot metadata lookup and decimal scaling checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaError {
    PdiMismatch { expected: Pdi, actual: Pdi },
    PerpOutOfBounds { index: u64, len: usize },
    InvalidPerpSzDecimals(u8),
    SpotPairOutOfBounds { pair: u64, len: usize },
    SpotTokenOutOfBounds { token: u64, len: usize },
    SpotDecimalUnderflow { quote_wei_decimals: u8, base_sz_decimals: u8 },
    TokenDecimalUnderflow { wei_decimals: u8, sz_decimals: u8 },
    Pow10Overflow(u8),
    ExponentOutOfRange(u8),
}

/// Per-asset perpetual metadata record (fields proven in `#115` `0x22e4810`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerpAssetMeta {
    pub name: String,
    pub sz_decimals: u8,
    pub max_leverage: u32,
}

/// Perpetual DEX metadata (`l1/src/perp_meta.rs`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PerpMeta {
    pub pdi: Pdi,
    pub universe: Vec<PerpAssetMeta>,
}

impl PerpMeta {
    pub fn new(pdi: Pdi, universe: Vec<PerpAssetMeta>) -> Self {
        Self { pdi, universe }
    }

    /// Lookup `sz_decimals` for `asset` with the exact `#115` `0x22e485d..0x22e4890` checks.
    pub fn sz_decimals(&self, asset: PerpAsset) -> Result<u8, MetaError> {
        let (pdi, local) = asset.split();
        if pdi != self.pdi {
            return Err(MetaError::PdiMismatch {
                expected: self.pdi,
                actual: pdi,
            });
        }
        let idx = usize::try_from(local).map_err(|_| MetaError::PerpOutOfBounds {
            index: local,
            len: self.universe.len(),
        })?;
        let row = self.universe.get(idx).ok_or(MetaError::PerpOutOfBounds {
            index: local,
            len: self.universe.len(),
        })?;
        if row.sz_decimals > MAX_PERP_SZ_DECIMALS {
            return Err(MetaError::InvalidPerpSzDecimals(row.sz_decimals));
        }
        Ok(row.sz_decimals)
    }

    /// Return price decimals `6 - sz_decimals` matching `#115` `0x3d19800`
    /// (`l1/src/perp_meta.rs:163,287`).
    pub fn px_decimals(&self, asset: PerpAsset) -> Result<u8, MetaError> {
        let sz_dec = self.sz_decimals(asset)?;
        Ok(MAX_PERP_SZ_DECIMALS - sz_dec)
    }

    /// Convert raw fixed-point perp price to `f64` matching `#115` `0x22e48a8..0x22e48de`
    /// and `0x50bea90`: `raw_px as f64 / POW10_F64[6 - sz_decimals]`.
    pub fn px_to_f64(&self, asset: PerpAsset, px: Px) -> Result<f64, MetaError> {
        let px_dec = usize::from(self.px_decimals(asset)?);
        Ok((px.raw() as f64) / POW10_F64[px_dec])
    }

    /// Convert raw fixed-point perp size to `f64` (`raw_sz as f64 / POW10_F64[sz_decimals]`).
    pub fn sz_to_f64(&self, asset: PerpAsset, raw_sz: u64) -> Result<f64, MetaError> {
        let sz_dec = self.sz_decimals(asset)?;
        Ok((raw_sz as f64) / POW10_F64[usize::from(sz_dec)])
    }

    /// Zero-short-circuiting size conversion matching `#115` `0x50beb30` (`test rdi, rdi; je`):
    /// returns `Ok(0.0)` immediately when `raw_sz == 0` without touching metadata.
    pub fn sz_to_f64_zero_fast(&self, asset: PerpAsset, raw_sz: u64) -> Result<f64, MetaError> {
        if raw_sz == 0 {
            return Ok(0.0);
        }
        self.sz_to_f64(asset, raw_sz)
    }
}

/// Spot token decimal metadata (`tokens` row `+0x48` = `sz_decimals`, `+0x49` = `wei_decimals`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpotTokenMeta {
    pub sz_decimals: u8,
    pub wei_decimals: u8,
}

impl SpotTokenMeta {
    /// Exact `10^(wei_decimals - sz_decimals)` matching `#115` `0x3c4b280`
    /// (`l1/src/spot_meta.rs:1206:57`).
    pub fn wei_per_sz(self) -> Result<u64, MetaError> {
        let diff = self
            .wei_decimals
            .checked_sub(self.sz_decimals)
            .ok_or(MetaError::TokenDecimalUnderflow {
                wei_decimals: self.wei_decimals,
                sz_decimals: self.sz_decimals,
            })?;
        10_u64
            .checked_pow(u32::from(diff))
            .ok_or(MetaError::Pow10Overflow(diff))
    }

    /// Checked `raw_sz * wei_per_sz` matching `#115` `0x3c4b1a0` (`mul rcx; setno`).
    pub fn checked_sz_to_wei(self, raw_sz: u64) -> Result<Option<u64>, MetaError> {
        let scale = self.wei_per_sz()?;
        Ok(raw_sz.checked_mul(scale))
    }
}

/// Spot market pair metadata (`universe` row `+0x00` = `base`, `+0x08` = `quote`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpotPairMeta {
    pub base: Token,
    pub quote: Token,
}

/// Spot metadata (`l1/src/spot_meta.rs`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpotMeta {
    pub universe: Vec<SpotPairMeta>,
    pub tokens: Vec<SpotTokenMeta>,
}

impl SpotMeta {
    pub fn new(universe: Vec<SpotPairMeta>, tokens: Vec<SpotTokenMeta>) -> Self {
        Self { universe, tokens }
    }

    /// Computes `quote.wei_decimals - base.sz_decimals` with all `#115` `0x22f5df9..0x22f5e56`
    /// bounds and underflow checks.
    pub fn pair_price_decimals(&self, pair: SpotAsset) -> Result<u8, MetaError> {
        let pair_idx = usize::try_from(pair.0).map_err(|_| MetaError::SpotPairOutOfBounds {
            pair: pair.0,
            len: self.universe.len(),
        })?;
        let entry = self
            .universe
            .get(pair_idx)
            .ok_or(MetaError::SpotPairOutOfBounds {
                pair: pair.0,
                len: self.universe.len(),
            })?;
        let quote_idx =
            usize::try_from(entry.quote.0).map_err(|_| MetaError::SpotTokenOutOfBounds {
                token: entry.quote.0,
                len: self.tokens.len(),
            })?;
        let quote = self
            .tokens
            .get(quote_idx)
            .ok_or(MetaError::SpotTokenOutOfBounds {
                token: entry.quote.0,
                len: self.tokens.len(),
            })?;
        let base_idx =
            usize::try_from(entry.base.0).map_err(|_| MetaError::SpotTokenOutOfBounds {
                token: entry.base.0,
                len: self.tokens.len(),
            })?;
        let base = self
            .tokens
            .get(base_idx)
            .ok_or(MetaError::SpotTokenOutOfBounds {
                token: entry.base.0,
                len: self.tokens.len(),
            })?;
        let exp = quote.wei_decimals.checked_sub(base.sz_decimals).ok_or(
            MetaError::SpotDecimalUnderflow {
                quote_wei_decimals: quote.wei_decimals,
                base_sz_decimals: base.sz_decimals,
            },
        )?;
        if usize::from(exp) >= POW10_F64.len() {
            return Err(MetaError::ExponentOutOfRange(exp));
        }
        Ok(exp)
    }

    /// Exact `#115` `0x22f5de0` (`spot_meta.rs:119,590,1055`) dual-price conversion:
    /// each raw price independently short-circuits `0 -> 0.0` before metadata lookup,
    /// while nonzero values validate pair/tokens and divide by `POW10_F64[quote.wei_decimals - base.sz_decimals]`.
    pub fn raw_pair_prices_to_f64(
        &self,
        pair: SpotAsset,
        first_raw: u64,
        second_raw: u64,
    ) -> Result<(f64, f64), MetaError> {
        let first = if first_raw == 0 {
            0.0
        } else {
            let exp = self.pair_price_decimals(pair)?;
            (first_raw as f64) / POW10_F64[usize::from(exp)]
        };
        let second = if second_raw == 0 {
            0.0
        } else {
            let exp = self.pair_price_decimals(pair)?;
            (second_raw as f64) / POW10_F64[usize::from(exp)]
        };
        Ok((first, second))
    }

    /// Convert raw spot size to `f64` using `base.sz_decimals`.
    pub fn pair_base_sz_decimals(&self, pair: SpotAsset) -> Result<u8, MetaError> {
        let pair_idx = usize::try_from(pair.0).map_err(|_| MetaError::SpotPairOutOfBounds {
            pair: pair.0,
            len: self.universe.len(),
        })?;
        let entry = self
            .universe
            .get(pair_idx)
            .ok_or(MetaError::SpotPairOutOfBounds {
                pair: pair.0,
                len: self.universe.len(),
            })?;
        let base_idx =
            usize::try_from(entry.base.0).map_err(|_| MetaError::SpotTokenOutOfBounds {
                token: entry.base.0,
                len: self.tokens.len(),
            })?;
        let base = self
            .tokens
            .get(base_idx)
            .ok_or(MetaError::SpotTokenOutOfBounds {
                token: entry.base.0,
                len: self.tokens.len(),
            })?;
        Ok(base.sz_decimals)
    }

    /// Single-price spot conversion matching `#115` `0x50be9e0` (`l1/src/spot_meta.rs:119,590,1055`).
    pub fn px_to_f64(&self, pair: SpotAsset, px: Px) -> Result<f64, MetaError> {
        let exp = self.pair_price_decimals(pair)?;
        Ok((px.raw() as f64) / POW10_F64[usize::from(exp)])
    }

    /// First listed spot market for `base_token`, matching `#115` `0x3c47660`
    /// (`l1/src/spot_meta.rs:119`).
    pub fn first_spot_for_token(&self, base_token: Token) -> Result<Option<SpotAsset>, MetaError> {
        let idx = usize::try_from(base_token.0).map_err(|_| MetaError::SpotTokenOutOfBounds {
            token: base_token.0,
            len: self.tokens.len(),
        })?;
        if idx >= self.tokens.len() {
            return Err(MetaError::SpotTokenOutOfBounds {
                token: base_token.0,
                len: self.tokens.len(),
            });
        }
        Ok(self
            .universe
            .iter()
            .position(|p| p.base == base_token)
            .map(|i| SpotAsset(i as u64)))
    }

    /// Lookup spot market pairing `base_token` with `quote_token`, matching `#115` `0x3c47ae0`
    /// (`l1/src/spot_meta.rs:119,590`).
    pub fn spot_for_token_and_quote(
        &self,
        base_token: Token,
        quote_token: Token,
    ) -> Result<Option<SpotAsset>, MetaError> {
        let idx = usize::try_from(base_token.0).map_err(|_| MetaError::SpotTokenOutOfBounds {
            token: base_token.0,
            len: self.tokens.len(),
        })?;
        if idx >= self.tokens.len() {
            return Err(MetaError::SpotTokenOutOfBounds {
                token: base_token.0,
                len: self.tokens.len(),
            });
        }
        Ok(self
            .universe
            .iter()
            .position(|p| p.base == base_token && p.quote == quote_token)
            .map(|i| SpotAsset(i as u64)))
    }

    /// Predicate checking whether `base_token` has a USDC (`Token(0)`) spot market,
    /// matching `#115` `0x3c49df0`.
    pub fn has_usdc_spot(&self, base_token: Token) -> Result<bool, MetaError> {
        Ok(self
            .spot_for_token_and_quote(base_token, Token(0))?
            .is_some())
    }

    /// Exact `10^(tokens[0].wei_decimals - tokens[base_token].sz_decimals)` matching `#115`
    /// `0x3c49360` (`l1/src/spot_meta.rs:119,1055,1074`).
    pub fn usdc_wei_per_base_sz(&self, base_token: Token) -> Result<u64, MetaError> {
        let usdc = self.tokens.first().ok_or(MetaError::SpotTokenOutOfBounds {
            token: 0,
            len: 0,
        })?;
        let idx = usize::try_from(base_token.0).map_err(|_| MetaError::SpotTokenOutOfBounds {
            token: base_token.0,
            len: self.tokens.len(),
        })?;
        let base = self.tokens.get(idx).ok_or(MetaError::SpotTokenOutOfBounds {
            token: base_token.0,
            len: self.tokens.len(),
        })?;
        let diff = usdc.wei_decimals.checked_sub(base.sz_decimals).ok_or(
            MetaError::SpotDecimalUnderflow {
                quote_wei_decimals: usdc.wei_decimals,
                base_sz_decimals: base.sz_decimals,
            },
        )?;
        10_u64
            .checked_pow(u32::from(diff))
            .ok_or(MetaError::Pow10Overflow(diff))
    }

    /// Checked `raw_sz -> wei` conversion for `token`, matching `#115` `0x3c4b1a0`
    /// (`l1/src/spot_meta.rs:119,1206`).
    pub fn checked_sz_to_wei(&self, token: Token, raw_sz: u64) -> Result<Option<u64>, MetaError> {
        let idx = usize::try_from(token.0).map_err(|_| MetaError::SpotTokenOutOfBounds {
            token: token.0,
            len: self.tokens.len(),
        })?;
        let meta = self.tokens.get(idx).ok_or(MetaError::SpotTokenOutOfBounds {
            token: token.0,
            len: self.tokens.len(),
        })?;
        meta.checked_sz_to_wei(raw_sz)
    }

    /// Build a `node115-spot-scalar-conversions::Metadata` view over this `SpotMeta`'s
    /// base-token indices and `(sz_decimals, wei_decimals)` table.
    pub fn to_scalar_conversion_tables(
        &self,
    ) -> (Vec<u64>, Vec<node115_spot_scalar_conversions::Decimals>) {
        let pair_tokens = self.universe.iter().map(|p| p.base.0).collect();
        let tokens = self
            .tokens
            .iter()
            .map(|t| node115_spot_scalar_conversions::Decimals {
                field_48: t.sz_decimals,
                field_49: t.wei_decimals,
            })
            .collect();
        (pair_tokens, tokens)
    }
}
