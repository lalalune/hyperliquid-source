#![no_std]
//! Conditional value/request projection of node115's cap helper at 0x447c620.
//! The API describes requests; it neither invokes native callbacks nor renders
//! the result string. See the evidence packet for caller and FP premises.

/// Inputs supplied to the native helper, plus the later context observation.
#[derive(Clone, Copy, Debug)]
pub struct Input {
    pub sum_left: i64,
    pub sum_right: i64,
    pub multiplier: i64,
    pub key: u64,
    pub selector: u8,
    /// Context+0x378 as observed after the possible sum-overflow callback.
    /// An entry snapshot is sufficient only if that callback preserves it.
    pub observed_cap_word: i64,
}

/// A safe host admission refusal, not a recovered native error discriminant.
/// The native negative-addend branch reaches an opaque unwrap boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegativeAddend;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outcome {
    /// The helper writes I64_MIN to output[0]. Other output bytes are unknown.
    SentinelOnly,
    /// Values passed to the formatting boundary, not its rendered output.
    Format {
        mapped_key: u32,
        selector: u8,
        open_interest: f64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Projection {
    /// Selector0 request at Location0x648ba08, before multiplication.
    pub sum_overflow_request: bool,
    /// Selector1 request with the caller's Location, after the first request.
    pub cap_request: bool,
    pub outcome: Outcome,
}

/// Project the complete nonnegative-addend local decision and format arguments.
///
/// Continuation past each reported diagnostic assumes it returns and preserves
/// the native saved inputs and output. `observed_cap_word` is the value at the
/// later load, not necessarily the value on entry. Floating results assume the
/// target's nearest-even rounding and masked precision exception (e.g. MXCSR
/// 0x1f80), preserved by preceding callbacks. Sticky FP flags are not projected.
pub fn project(input: Input) -> Result<Projection, NegativeAddend> {
    if input.sum_right < 0 {
        return Err(NegativeAddend);
    }
    let (sum, sum_overflow_request) = match input.sum_left.checked_add(input.sum_right) {
        Some(value) => (value, false),
        // A nonnegative right operand can overflow only toward I64_MAX.
        None => (i64::MAX, true),
    };
    let product = if input.multiplier < 0 {
        None
    } else {
        input.multiplier.checked_mul(sum)
    };
    let cap_request = !product.is_some_and(|value| value < 184_467_440_737_095_517)
        && input.observed_cap_word == i64::MIN;
    let outcome = match product {
        Some(value) if value < 1_844_674_407_370_955_162 => Outcome::SentinelOnly,
        _ => {
            let mapped_key = match input.key {
                0..=9_999 => input.key as u32,
                10_000..=99_899_999 => (input.key + 100_000) as u32,
                _ => u32::MAX,
            };
            // Preserve the two distinct native rounding operations:
            // CVTSI2SD, then DIVSD by the exact binary64 value 1_000_000.
            let open_interest = match product {
                Some(value) => (value as f64) / 1_000_000.0,
                None => 0.0,
            };
            Outcome::Format {
                mapped_key,
                selector: input.selector,
                open_interest,
            }
        }
    };
    Ok(Projection {
        sum_overflow_request,
        cap_request,
        outcome,
    })
}
