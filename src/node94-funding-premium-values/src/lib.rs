//! Supplied shared-slab impact and premium values qualified by RE-007 evidence.
//!
//! Authored reconstruction under the repository's MIT license. This is a new
//! safe value API, not recovered native types, layout, scheduler or economics.
//! Integer arithmetic implements the proved finite binary64 operation sequence;
//! no host floating state, allocation, callback or captured executable is used.
#![forbid(unsafe_code)]

const SIGN: u64 = 1 << 63;
const FRACTION: u64 = (1 << 52) - 1;
const LEADING: u128 = 1 << 52;
const PRODUCT_CAP: u128 = (1 << 63) - 2;
const ONE: u64 = 0x3ff0_0000_0000_0000;
const HALF: u64 = 0x3fe0_0000_0000_0000;
const HUNDRED: u64 = 0x4059_0000_0000_0000;

/// One entry in the actual tree's in-order sequence; the API never sorts it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    pub key: i64,
    pub active: u8,
    pub head: u64,
}

/// Only these native-width slot fields participate in the supplied relation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot {
    pub tag: u32,
    pub quantity: u64,
    pub continuation: u64,
    pub next: u64,
}

/// Both ordered entry sequences address the same slot slice and common bound.
#[derive(Clone, Copy, Debug)]
pub struct Book<'a> {
    pub first: &'a [Entry],
    pub second: &'a [Entry],
    pub slots: &'a [Slot],
}

/// Already-selected values; metadata/hash/set lookups are outside this API.
#[derive(Clone, Copy, Debug)]
pub struct Input<'a> {
    pub asset: u64,
    pub oracle: u64,
    pub target: u64,
    pub scale: u8,
    pub mode: u8,
    pub divide_by_100: bool,
    pub book: Book<'a>,
}

/// New safe policy outside the corresponding native ordinary-return premises.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    InvalidScale,
    ZeroTarget,
    CycleFirst,
    CycleSecond,
}

/// The three active fields of a successful premium result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Premium {
    pub bits: u64,
    pub first_impact: u64,
    pub second_impact: u64,
}

/// One selected producer record; this does not imply producer completeness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    pub asset: u64,
    pub tag: u64,
    pub payload: u64,
}

/// Absence leaves native inactive words unrepresented and preserves raw fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Evaluation {
    pub premium: Option<Premium>,
    pub record: Record,
}

fn absent(asset: u64, oracle: u64) -> Evaluation {
    Evaluation {
        premium: None,
        record: Record {
            asset,
            tag: 1,
            payload: oracle,
        },
    }
}

fn index(raw: u64, length: usize) -> Option<usize> {
    usize::try_from(raw).ok().filter(|&value| value < length)
}

fn impact(entries: &[Entry], slots: &[Slot], target: u64) -> Result<u64, ()> {
    let mut cost = 0_u64;
    let mut quantity = 0_u64;
    for entry in entries {
        if entry.active & 1 == 0 {
            return Ok(0);
        }
        let Some(mut cursor) = index(entry.head, slots.len()) else {
            return Ok(0);
        };
        let mut budget = slots.len();
        let mut level_quantity = 0_u64;
        loop {
            if budget == 0 {
                return Err(());
            }
            budget -= 1;
            let slot = slots[cursor];
            if slot.tag == 2 {
                break;
            }
            level_quantity = level_quantity.saturating_add(slot.quantity);
            if slot.continuation == 0 {
                break;
            }
            let Some(next) = index(slot.next, slots.len()) else {
                break;
            };
            cursor = next;
        }
        if level_quantity == 0 {
            return Ok(0);
        }
        let price = entry.key.unsigned_abs();
        let whole = u128::from(price) * u128::from(level_quantity);
        if whole > PRODUCT_CAP {
            return Ok(0);
        }
        let candidate = cost.saturating_add(whole as u64);
        if candidate < target {
            cost = candidate;
            quantity = quantity.saturating_add(level_quantity);
            continue;
        }
        // The positive-target continuation invariant is cost < target. A
        // crossing therefore has price > 0 and partial <= level_quantity.
        let partial = (target - cost) / price;
        let final_cost = cost + price * partial;
        let final_quantity = quantity.saturating_add(partial);
        if final_quantity == 0 || final_quantity > final_cost {
            return Ok(0);
        }
        return Ok(final_cost / final_quantity);
    }
    Ok(0)
}

// These private operations only see the proved normal-or-zero finite domain.
// They are not a generic floating-point API. SOURCE-PROOF gives the independent
// integer width, exact alignment and positive binary64-divisor arguments.
fn parts(word: u64) -> (u64, i32) {
    (
        (word & FRACTION) | (1 << 52),
        ((word >> 52) & 2047) as i32 - 1075,
    )
}

fn encode(sign: u64, mut significand: u128, mut power: i32) -> u64 {
    if significand == LEADING << 1 {
        significand >>= 1;
        power += 1;
    }
    sign | (((power + 1075) as u64) << 52) | ((significand as u64) & FRACTION)
}

fn round_scaled(sign: u64, exact: u128, power: i32) -> u64 {
    if exact == 0 {
        return 0;
    }
    let width = 128 - exact.leading_zeros();
    if width <= 53 {
        let shift = 53 - width;
        return encode(sign, exact << shift, power - shift as i32);
    }
    let lost = width - 53;
    let lower = exact >> lost;
    let remainder = exact & ((1_u128 << lost) - 1);
    let halfway = 1_u128 << (lost - 1);
    let rounded =
        lower + u128::from(remainder > halfway || (remainder == halfway && lower & 1 == 1));
    encode(sign, rounded, power + lost as i32)
}

fn unsigned_bits(value: u64) -> u64 {
    round_scaled(0, u128::from(value), 0)
}

fn finite_add(a: u64, b: u64) -> u64 {
    let am = a & !SIGN;
    let bm = b & !SIGN;
    if am == 0 && bm == 0 {
        return a & b & SIGN;
    }
    if am == 0 {
        return b;
    }
    if bm == 0 {
        return a;
    }
    let (large, small) = if am >= bm { (a, b) } else { (b, a) };
    let (lm, lp) = parts(large);
    let (sm, sp) = parts(small);
    let distance = (lp - sp) as u32;
    if distance > 75 {
        // The smaller magnitude is below 2^-23 large-format ulps, strictly
        // below even the quarter-ulp midpoint beside a power-of-two boundary.
        return large;
    }
    let aligned = u128::from(lm) << distance;
    let exact = if (large ^ small) & SIGN == 0 {
        aligned + u128::from(sm)
    } else {
        aligned - u128::from(sm)
    };
    round_scaled(large & SIGN, exact, sp)
}

fn finite_sub(a: u64, b: u64) -> u64 {
    finite_add(a, b ^ SIGN)
}

fn positive_divisor_div(a: u64, b: u64) -> u64 {
    if a & !SIGN == 0 {
        return a & SIGN;
    }
    let (am, ap) = parts(a);
    let (bm, bp) = parts(b);
    // Both normalized significands have53 bits. This is a general positive
    // finite binary64 denominator, not the older integer-count-only relation.
    let shift = if am < bm { 53 } else { 52 };
    let numerator = u128::from(am) << shift;
    let divisor = u128::from(bm);
    let lower = numerator / divisor;
    let remainder = numerator % divisor;
    let twice = remainder * 2;
    let rounded = lower + u128::from(twice > divisor || (twice == divisor && lower & 1 == 1));
    encode(a & SIGN, rounded, ap - bp - shift)
}

fn less(a: u64, b: u64) -> bool {
    if a & !SIGN == 0 && b & !SIGN == 0 {
        return false;
    }
    if (a ^ b) & SIGN != 0 {
        return a & SIGN != 0;
    }
    if a & SIGN != 0 { a > b } else { a < b }
}

fn source_max(a: u64, b: u64) -> u64 {
    if less(b, a) { a } else { b }
}

fn source_min(a: u64, b: u64) -> u64 {
    if less(a, b) { a } else { b }
}

/// Evaluate the complete frozen supplied-state value relation.
///
/// Scale admission precedes the zero-oracle bypass. For nonzero oracle, target
/// zero and reached cycles are new safe refusals. Both ordinary impact values
/// are computed before either is tested for zero. Native correspondence remains
/// conditional on the packet's stable-view/lookup/helper/frame/ISA premises.
pub fn evaluate(input: Input<'_>) -> Result<Evaluation, Refusal> {
    if input.scale > 6 {
        return Err(Refusal::InvalidScale);
    }
    if input.oracle == 0 {
        return Ok(absent(input.asset, input.oracle));
    }
    if input.target == 0 {
        return Err(Refusal::ZeroTarget);
    }
    let divisor = unsigned_bits(10_u64.pow(u32::from(6 - input.scale)));
    let oracle = positive_divisor_div(unsigned_bits(input.oracle), divisor);
    let first = impact(input.book.first, input.book.slots, input.target)
        .map_err(|()| Refusal::CycleFirst)?;
    let second = impact(input.book.second, input.book.slots, input.target)
        .map_err(|()| Refusal::CycleSecond)?;
    if first == 0 || second == 0 {
        return Ok(absent(input.asset, input.oracle));
    }
    let a = positive_divisor_div(unsigned_bits(first), divisor);
    let b = positive_divisor_div(unsigned_bits(second), divisor);
    let mut value = if input.mode != 0 {
        let right = finite_sub(b, oracle) ^ SIGN;
        let left = finite_sub(a, oracle);
        positive_divisor_div(
            finite_sub(source_max(left, 0), source_max(right, 0)),
            oracle,
        )
    } else {
        let total = finite_add(a, b);
        // The proved sum is positive normal and at most2^65. Halving is exact
        // and stays normal; the native overflow-avoidance fallback is unreachable.
        let midpoint = total - (1 << 52);
        finite_sub(positive_divisor_div(midpoint, oracle), ONE)
    };
    if input.divide_by_100 {
        value = positive_divisor_div(value, HUNDRED);
    }
    value = source_min(HALF, source_max(HALF | SIGN, value));
    Ok(Evaluation {
        premium: Some(Premium {
            bits: value,
            first_impact: first,
            second_impact: second,
        }),
        record: Record {
            asset: input.asset,
            tag: 0,
            payload: value,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_ties_and_rounding_carry() {
        assert_eq!(unsigned_bits((1 << 53) + 1), 0x4340_0000_0000_0000);
        assert_eq!(unsigned_bits((1 << 53) + 3), 0x4340_0000_0000_0002);
        assert_eq!(unsigned_bits(u64::MAX), 0x43f0_0000_0000_0000);
    }

    #[test]
    fn exact_alignment_and_strict_small_operand_bound() {
        let largest_significand = 0x3fff_ffff_ffff_ffff;
        let same_significand_gap75 = 0x3b4f_ffff_ffff_ffff;
        assert_eq!(
            finite_add(largest_significand, same_significand_gap75),
            largest_significand
        );
        let gap76 = 0x3b30_0000_0000_0000;
        assert_eq!(finite_add(ONE, gap76), ONE);
        assert_eq!(finite_sub(ONE, gap76), ONE);
        assert_eq!(finite_add(ONE | SIGN, gap76), ONE | SIGN);
        assert_eq!(finite_sub(ONE, ONE), 0);
    }

    #[test]
    fn fractional_positive_denominator_and_source_zero_equality() {
        let one_and_half = 0x3ff8_0000_0000_0000;
        assert_eq!(
            positive_divisor_div(ONE, one_and_half),
            0x3fe5_5555_5555_5555
        );
        assert_eq!(
            positive_divisor_div(ONE | SIGN, one_and_half),
            0xbfe5_5555_5555_5555
        );
        assert_eq!(source_max(SIGN, 0), 0);
        assert_eq!(source_min(0, SIGN), SIGN);
    }
}
