//! Hyperliquidity price tick (`0x3be2a50`), ladder generator (`0x38bddf0`),
//! funding cost (`0x38bcb80`), market-cap band (`0x38bcaa0`), and seed validation
//! (`0x38bc000`, `l1/src/hyperliquidity.rs:360`).
//!
//! Anchored to node #115 evidence packets:
//! - `research/work-items/exchange-hyperliquidity-ladder-115`
//! - `research/work-items/exchange-hyperliquidity-seed-115`

/// Maximum allowed Hyperliquidity order levels (`0x38bc000` step 1).
pub const MAX_LEVELS: u64 = 4_000;

/// Minimum allowed non-empty Hyperliquidity order levels (`0x38bc000` step 4).
pub const MIN_LEVELS: u64 = 10;

/// Price step multiplier (`1.003` = +0.3% per level).
pub const LADDER_MULTIPLIER: f64 = 1.003;

/// Maximum product cap (`0x1999_9999_9999_9999`).
pub const CONFIG_PRODUCT_CAP: u64 = 0x1999_9999_9999_9999;

/// Maximum `ceil(1.003^levels)` count cap (`1_000_000`).
pub const MAX_RATIO_COUNT: u64 = 1_000_000;

/// Minimum starting order notional value in 1e6 USDC units (`1_000_000` = $1.00).
pub const MIN_START_ORDER_NOTIONAL: u64 = 1_000_000;

/// Maximum valid ladder price (`1e15`).
pub const MAX_LADDER_PRICE: u64 = 1_000_000_000_000_000;

/// Maximum per-level product in funding cost sum (`0x7fff_ffff_ffff_fffe`).
pub const MAX_COST_PRODUCT: u64 = 0x7fff_ffff_ffff_fffe;

/// End-price market-cap band (`[1e9, 1e11]` USDC).
pub const END_MARKET_CAP_BAND: (u64, u64) = (1_000_000_000, 100_000_000_000);

/// Start-price market-cap band (`[0, 1e7]` USDC).
pub const START_MARKET_CAP_BAND: (u64, u64) = (0, 10_000_000);

/// Fixed tick returned for members of the special token set (`0x3be2a50`).
pub const SPECIAL_TOKEN_TICK: u64 = 1_000;

/// Exact 5-significant-digit tick rule from `0x3be2a50`, clamped to `10^decimals_diff`.
pub fn price_tick(price: u64, decimals_diff: u8, is_special_token: bool) -> u64 {
    if is_special_token {
        return SPECIAL_TOKEN_TICK;
    }
    let digit_tick: u64 = if price < 100_000 {
        1
    } else if price < 1_000_000 {
        10
    } else if price < 10_000_000 {
        100
    } else if price < 100_000_000 {
        1_000
    } else if price < 1_000_000_000 {
        10_000
    } else if price < 10_000_000_000 {
        100_000
    } else if price < 100_000_000_000 {
        1_000_000
    } else if price < 1_000_000_000_000 {
        10_000_000
    } else if price < 10_000_000_000_000 {
        100_000_000
    } else if price < 100_000_000_000_000 {
        1_000_000_000
    } else if price < 1_000_000_000_000_000 {
        10_000_000_000
    } else if price < 10_000_000_000_000_000 {
        100_000_000_000
    } else if price < 100_000_000_000_000_000 {
        1_000_000_000_000
    } else if price < 1_000_000_000_000_000_000 {
        10_000_000_000_000
    } else if price < 10_000_000_000_000_000_000 {
        100_000_000_000_000
    } else {
        1_000_000_000_000_000
    };

    if decimals_diff >= 20 {
        digit_tick
    } else {
        digit_tick.min(10u64.pow(u32::from(decimals_diff)))
    }
}

/// Generates `count` Hyperliquidity ladder prices (`0x38bddf0`).
///
/// Caller must ensure `count > 0` (empty ladder returns `Vec::new()`).
pub fn generate_ladder(
    start_price: u64,
    count: usize,
    decimals_diff: u8,
    is_special_token: bool,
) -> Vec<u64> {
    if count == 0 {
        return Vec::new();
    }
    let init_tick = price_tick(start_price, decimals_diff, is_special_token);
    let mut price = ((start_price / init_tick) * init_tick).max(1);
    let mut levels = Vec::with_capacity(count);

    for _ in 0..count {
        levels.push(price);
        let scaled = (price as f64) * LADDER_MULTIPLIER;
        // Matches libm `round` (0x63efe40: round half away from zero) + saturating u64 cast.
        let rounded = if !scaled.is_finite() || scaled <= 0.0 {
            0u64
        } else {
            scaled.round() as u64
        };
        let next_raw = rounded.max(1);
        let tick = price_tick(next_raw, decimals_diff, is_special_token);
        price = ((next_raw / tick) * tick).max(1);
    }
    levels
}

/// Sums `price * size` over the first `take` ladder levels (`0x38bcb80`).
///
/// Returns `Ok(total)` or `Err(partial_sum_before_failing_level)` if any product
/// overflows, exceeds [`MAX_COST_PRODUCT`], or overflows the `u64` accumulator.
pub fn funding_cost(levels: &[u64], take: usize, size: u64) -> Result<u64, u64> {
    let mut sum = 0u64;
    for &price in levels.iter().take(take) {
        let Some(prod) = price.checked_mul(size) else {
            return Err(sum);
        };
        if prod > MAX_COST_PRODUCT {
            return Err(sum);
        }
        let Some(next) = sum.checked_add(prod) else {
            return Err(sum);
        };
        sum = next;
    }
    Ok(sum)
}

/// Market-cap band helper `0x38bcaa0`:
/// `lo * 700_000 * 100 <= cap <= hi * 1_300_000 * 100` (all multiplications overflow-checked).
pub fn market_cap_in_band(cap: u64, lo: u64, hi: u64) -> bool {
    let Some(lo_min) = lo.checked_mul(700_000).and_then(|v| v.checked_mul(100)) else {
        return false;
    };
    let Some(hi_max) = hi.checked_mul(1_300_000).and_then(|v| v.checked_mul(100)) else {
        return false;
    };
    cap >= lo_min && cap <= hi_max
}

/// Inputs to [`validate_hyperliquidity_seed`] (`0x38bc000`).
#[derive(Clone, Debug)]
pub struct SeedCheckInput<'a> {
    pub start_price: u64,
    pub order_size: u64,
    pub levels: u64,
    pub seeded_levels: u64,
    pub funding_cap: u64,
    pub already_exists: bool,
    pub held_balance: u64,
    pub has_token_hold: bool,
    pub quote_is_usdc: bool,
    pub has_max_supply: bool,
    pub available_token_balance: Option<u64>,
    pub decimals_diff: u8,
    pub is_special_token: bool,
    pub token_name: &'a str,
}

/// Successful Hyperliquidity seed validation result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedValidated {
    pub levels: Vec<u64>,
    pub cost: u64,
}

/// Reconstructs the ordered validation checks and exact refusal texts of node #115
/// `0x38bc000` (`l1/src/hyperliquidity.rs:360`).
///
/// `market_cap_of(price)` returns `Some(cap)` matching helper `0x434f660`.
pub fn validate_hyperliquidity_seed<M>(
    input: &SeedCheckInput<'_>,
    mut market_cap_of: M,
) -> Result<SeedValidated, &'static str>
where
    M: FnMut(u64) -> Option<u64>,
{
    if input.levels > MAX_LEVELS {
        return Err("too many Hyperliquidity orders");
    }
    if input.levels < input.seeded_levels {
        return Err("cannot seed more levels than exist");
    }
    if input.already_exists {
        return Err("Hyperliquidity already exists");
    }

    // Step 4: empty path when held == 0 and levels == 0.
    if input.held_balance == 0 && input.levels == 0 {
        return Ok(SeedValidated {
            levels: Vec::new(),
            cost: 0,
        });
    }
    if input.has_token_hold {
        return Err("Hyperliquidity already has token hold");
    }
    if !input.quote_is_usdc {
        return Err("quote token must be USDC for Hyperliquidity");
    }
    if !input.has_max_supply {
        return Err("Hyperliquidity missing max supply");
    }
    if input.levels < MIN_LEVELS {
        return Err("too few Hyperliquidity orders");
    }

    // Step 5: 1.003^levels, ceil -> u64, overflow-checked product caps.
    let mut factor = 1.0_f64;
    for _ in 0..input.levels {
        factor *= LADDER_MULTIPLIER;
    }
    let ratio_count = if !factor.is_finite() || factor <= 0.0 {
        0u64
    } else {
        factor.ceil() as u64
    };
    let prod_levels_size = input.levels.checked_mul(input.order_size);
    let prod_price_count = input.start_price.checked_mul(ratio_count);
    let prod_all = prod_price_count.and_then(|v| v.checked_mul(input.order_size));
    let invalid_cfg = prod_levels_size.is_none_or(|v| v > CONFIG_PRODUCT_CAP)
        || ratio_count > MAX_RATIO_COUNT
        || prod_price_count.is_none_or(|v| v > CONFIG_PRODUCT_CAP)
        || prod_all.is_none_or(|v| v > CONFIG_PRODUCT_CAP);
    if invalid_cfg {
        return Err("Hyperliquidity configuration invalid");
    }
    if input.order_size == 0 {
        return Err("zero Hyperliquidity order size");
    }

    // Step 6: token balance must match size * (levels - seeded).
    let expected_tokens = input
        .order_size
        .saturating_mul(input.levels - input.seeded_levels);
    if input.available_token_balance != Some(expected_tokens) {
        return Err("Hyperliquidity has incorrect balance");
    }

    // Step 7: build ladder and check starting order value + price spread.
    let ladder = generate_ladder(
        input.start_price,
        input.levels as usize,
        input.decimals_diff,
        input.is_special_token,
    );
    let first = *ladder.first().expect("levels >= 10");
    let last = *ladder.last().expect("levels >= 10");
    if let Some(start_ntl) = first.checked_mul(input.order_size) {
        if start_ntl < MIN_START_ORDER_NOTIONAL {
            return Err("Hyperliquidity starting order value must be at least 1 USDC");
        }
    }
    if first == last {
        return Err("Hyperliquidity starting price too small");
    }

    // Step 8: end-price band [1B, 100B] then start-price band [0, 10M], HYPE exempt.
    let checks = [(last, END_MARKET_CAP_BAND), (first, START_MARKET_CAP_BAND)];
    for (px, (lo, hi)) in checks {
        if px == 0 {
            break;
        }
        let tick = price_tick(px, input.decimals_diff, input.is_special_token);
        if px > MAX_LADDER_PRICE || px % tick != 0 {
            return Err("Hyperliquidity price is invalid");
        }
        let in_band = market_cap_of(px).is_some_and(|cap| market_cap_in_band(cap, lo, hi));
        if !in_band && input.token_name != "HYPE" {
            return Err(
                "market cap must be in range [1B, 100B] USDC at Hyperliquidity end price and [0, 10M] USDC at Hyperliquidity start price",
            );
        }
    }

    // Step 10: funding cost <= funding_cap.
    let cost = funding_cost(&ladder, input.seeded_levels as usize, input.order_size)
        .map_err(|_| "insufficient usdc for seeding hyperliquidity")?;
    if cost > input.funding_cap {
        return Err("insufficient usdc for seeding hyperliquidity");
    }

    Ok(SeedValidated {
        levels: ladder,
        cost,
    })
}
