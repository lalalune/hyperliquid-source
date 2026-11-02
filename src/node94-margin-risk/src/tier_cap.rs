use crate::{MAX_LEVERAGE, MarginTable, select_tier};

// Native upper-included queries admit at most this scalar product. The next
// value switches the query to upper-unbounded even without u64 overflow.
const SIGNED_RANGE_MAX: u64 = i64::MAX as u64 - 1;

/// Return the tier cap established by node94's `0x3333580` normal path.
///
/// `price_word` is the unsigned raw argument; `signed_size` is the signed raw
/// argument. No decimal denomination or signed-price admission is imposed here.
/// A validated table supplies one through three ordered tiers. `None` is this
/// safe API's marker for the native null-root branch, which returns byte50
/// before multiplication. This owned API does not reproduce the native holder,
/// B-tree layout, calling convention or complete leverage-update admission.
///
/// A wide product or a low product above `i64::MAX - 1` uses the final tier.
/// Otherwise the included upper bound selects the last lower bound at or below
/// the product. `i64::MIN` has unsigned magnitude `1 << 63`.
#[must_use]
pub fn position_leverage_cap(
    table: Option<&MarginTable>,
    price_word: u64,
    signed_size: i64,
) -> u8 {
    let Some(table) = table else {
        return MAX_LEVERAGE;
    };
    let magnitude = signed_size.unsigned_abs();
    let (low, wide_overflow) = price_word.overflowing_mul(magnitude);
    if wide_overflow || low > SIGNED_RANGE_MAX {
        table.tiers().last().expect("validated table is nonempty").max_leverage()
    } else {
        select_tier(table, low).max_leverage()
    }
}
