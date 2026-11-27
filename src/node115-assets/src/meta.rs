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

use crate::pdi::{Pdi, PerpAsset, SpotAsset, Token};
use crate::qtys::{MAX_PERP_SZ_DECIMALS, POW10_F64, Px};

/// Errors produced by `#115` perp/spot metadata lookup and decimal scaling checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaError {
    PdiMismatch { expected: Pdi, actual: Pdi },
    PerpOutOfBounds { index: u64, len: usize },
    InvalidPerpSzDecimals(u8),
    SpotPairOutOfBounds { pair: u64, len: usize },
    SpotTokenOutOfBounds { token: u64, len: usize },
    SpotDecimalUnderflow { quote_wei_decimals: u8, base_sz_decimals: u8 },
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

    /// Convert raw fixed-point perp price to `f64` matching `#115` `0x22e48a8..0x22e48de`:
    /// `raw_px as f64 / POW10_F64[6 - sz_decimals]`.
    pub fn px_to_f64(&self, asset: PerpAsset, px: Px) -> Result<f64, MetaError> {
        let sz_dec = self.sz_decimals(asset)?;
        let px_dec = usize::from(MAX_PERP_SZ_DECIMALS - sz_dec);
        Ok((px.raw() as f64) / POW10_F64[px_dec])
    }

    /// Convert raw fixed-point perp size to `f64` (`raw_sz as f64 / POW10_F64[sz_decimals]`).
    pub fn sz_to_f64(&self, asset: PerpAsset, raw_sz: u64) -> Result<f64, MetaError> {
        let sz_dec = self.sz_decimals(asset)?;
        Ok((raw_sz as f64) / POW10_F64[usize::from(sz_dec)])
    }
}

/// Spot token decimal metadata (`tokens` row `+0x48` = `sz_decimals`, `+0x49` = `wei_decimals`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpotTokenMeta {
    pub sz_decimals: u8,
    pub wei_decimals: u8,
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
