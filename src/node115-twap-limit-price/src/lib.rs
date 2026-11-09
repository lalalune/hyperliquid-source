//! Limit-price construction for the node #115 TWAP order-producing path.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarketFamily {
    Perp,
    Spot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriceInputs {
    pub family: MarketFamily,
    pub side: u8,
    pub top_bid: u64,
    pub top_ask: u64,
    pub spot_mid: u64,
    pub tick: u64,
}

/// Build a TWAP limit price from the selected market reference and tick size.
///
/// `None` indicates that no nonzero reference or usable tick was supplied.
/// The market lookup and its error branches belong to the caller.
pub fn limit_price(input: PriceInputs) -> Option<u64> {
    if input.tick == 0 {
        return None;
    }

    let reference = match input.family {
        MarketFamily::Perp => {
            if input.top_bid == 0 || input.top_ask == 0 {
                return None;
            }
            (input.top_bid & input.top_ask).wrapping_add((input.top_bid ^ input.top_ask) >> 1)
        }
        MarketFamily::Spot => input.spot_mid,
    };
    if reference == 0 {
        return None;
    }

    let factor = if input.side != 0 { 0.97 } else { 1.03 };
    let price = saturate((factor * reference as f64).round()).max(1);
    let mut units = price / input.tick;
    if input.side != 0 {
        units = units.saturating_add(1);
    }
    Some(units.saturating_mul(input.tick).max(1))
}

fn saturate(value: f64) -> u64 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else if value >= u64::MAX as f64 {
        u64::MAX
    } else {
        value as u64
    }
}

#[cfg(test)]
mod tests {
    use super::{limit_price, MarketFamily, PriceInputs};

    const VECTORS: &str = include_str!("../price-vectors.tsv");

    #[test]
    fn matches_price_outputs_from_all_four_copy_case_sets() {
        let mut checked = 0;
        for line in VECTORS.lines().skip(1) {
            let c: Vec<_> = line.split('\t').collect();
            let family = match c[0] {
                "perp" => MarketFamily::Perp,
                "spot" => MarketFamily::Spot,
                other => panic!("unknown family {other}"),
            };
            let parse = |value: &str| value.parse::<u64>().unwrap();
            let input = PriceInputs {
                family,
                side: c[1].parse().unwrap(),
                top_bid: parse(c[2]),
                top_ask: parse(c[3]),
                spot_mid: parse(c[4]),
                tick: parse(c[5]),
            };
            let expected = parse(c[6]);
            assert_eq!(limit_price(input), Some(expected), "vector {checked}");
            checked += 1;
        }
        assert_eq!(checked, 3_510);
    }

    #[test]
    fn missing_reference_or_tick_produces_no_price() {
        let valid = PriceInputs {
            family: MarketFamily::Perp,
            side: 0,
            top_bid: 1_000_000,
            top_ask: 1_000_200,
            spot_mid: 1_000_100,
            tick: 100,
        };
        assert_eq!(
            limit_price(PriceInputs {
                top_bid: 0,
                ..valid
            }),
            None
        );
        assert_eq!(limit_price(PriceInputs { tick: 0, ..valid }), None);
        assert_eq!(
            limit_price(PriceInputs {
                family: MarketFamily::Spot,
                spot_mid: 0,
                ..valid
            }),
            None
        );
    }
}
