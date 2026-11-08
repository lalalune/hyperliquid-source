#![no_std]
//! Logical model of the node #115 order-price band and spot admission gates.
//! Lookup callees remain explicit inputs; no source types or protocol roles
//! beyond the static evidence are inferred.

pub const STATUS_BAND: u16 = 0x0063;
pub const STATUS_TOO_LARGE: u16 = 0x0100;
pub const STATUS_INVALID_SPOT: u16 = 0x0195;
pub const STATUS_ACCEPTED: u16 = 0x01a2;
pub const SPOT_PRICE_CAP: u64 = 99_999_000;
pub const BAND_PAYLOAD_SCALE: f64 = 100.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanicSite {
    SpotMetadataBounds,
    IndexMapBounds,
}

impl PanicSite {
    pub const fn address(self) -> u64 {
        match self {
            Self::SpotMetadataBounds => 0x6476678,
            Self::IndexMapBounds => 0x6493b30,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateOutcome {
    Accepted,
    BandRefused { payload_bits: u64 },
    InvalidSpot,
    PriceTooLarge,
    Panic(PanicSite),
}

impl GateOutcome {
    pub const fn status(self) -> Option<u16> {
        match self {
            Self::Accepted => Some(STATUS_ACCEPTED),
            Self::BandRefused { .. } => Some(STATUS_BAND),
            Self::InvalidSpot => Some(STATUS_INVALID_SPOT),
            Self::PriceTooLarge => Some(STATUS_TOO_LARGE),
            Self::Panic(_) => None,
        }
    }

    pub const fn payload_bits(self) -> Option<u64> {
        match self {
            Self::BandRefused { payload_bits } => Some(payload_bits),
            _ => None,
        }
    }
}

/// The packet's binary64 decision formula, in the same operation order.
pub fn band_admits(price: u64, reference: u64, distance: f64) -> bool {
    let ratio = (price as f64) / (reference as f64) - 1.0;
    if ratio.abs() < distance {
        return true;
    }
    distance < 1.0 && ratio > 0.0 && (1.0 / (1.0 - distance) - 1.0) >= ratio
}

pub fn band_outcome(price: u64, reference: u64, distance: f64) -> GateOutcome {
    if band_admits(price, reference, distance) {
        GateOutcome::Accepted
    } else {
        GateOutcome::BandRefused {
            payload_bits: (distance * BAND_PAYLOAD_SCALE).to_bits(),
        }
    }
}

/// Model the perp gate's low-byte exemption before the shared band rule.
pub fn perp_outcome(exemption: u64, price: u64, reference: u64, distance: f64) -> GateOutcome {
    if exemption & 0xff != 0 {
        GateOutcome::Accepted
    } else {
        band_outcome(price, reference, distance)
    }
}

/// Abstract result of the first spot-token map probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirstMapProbe {
    Empty,
    Miss,
    Hit,
    IndexOutOfBounds,
}

/// Abstract result of the second spot-token map probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecondMapProbe {
    Empty,
    Miss,
    Hit,
    IndexOutOfBounds,
    NullEntries,
}

/// Inputs supplied to the bounded spot-admission chain. The B-tree and map
/// lookup internals are represented by their observed hit/miss/panic outcomes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SpotInput {
    pub token_index: u64,
    pub token_count: u64,
    pub tree_contains: bool,
    pub first_map: FirstMapProbe,
    pub second_map: SecondMapProbe,
    pub price: u64,
    pub reference: u64,
    pub distance: f64,
}

pub fn spot_outcome(input: SpotInput) -> GateOutcome {
    if input.token_index >= input.token_count {
        return GateOutcome::Panic(PanicSite::SpotMetadataBounds);
    }
    if input.tree_contains {
        return GateOutcome::InvalidSpot;
    }

    match input.first_map {
        FirstMapProbe::Empty | FirstMapProbe::Miss => {
            band_outcome(input.price, input.reference, input.distance)
        }
        FirstMapProbe::IndexOutOfBounds => GateOutcome::Panic(PanicSite::IndexMapBounds),
        FirstMapProbe::Hit => match input.second_map {
            SecondMapProbe::Empty | SecondMapProbe::Miss | SecondMapProbe::NullEntries => {
                GateOutcome::InvalidSpot
            }
            SecondMapProbe::IndexOutOfBounds => GateOutcome::Panic(PanicSite::IndexMapBounds),
            SecondMapProbe::Hit => cap_outcome(input.price),
        },
    }
}

pub fn cap_outcome(price: u64) -> GateOutcome {
    if price <= SPOT_PRICE_CAP {
        GateOutcome::Accepted
    } else {
        GateOutcome::PriceTooLarge
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_edges_are_strict_below_and_inclusive_above() {
        assert_eq!(band_outcome(50, 100, 0.5).status(), Some(STATUS_BAND));
        assert_eq!(band_outcome(51, 100, 0.5), GateOutcome::Accepted);
        assert_eq!(band_outcome(200, 100, 0.5), GateOutcome::Accepted);
        assert_eq!(band_outcome(201, 100, 0.5).status(), Some(STATUS_BAND));
    }

    #[test]
    fn zero_reference_and_nan_distance_refuse_with_scaled_payload() {
        let outcome = band_outcome(100, 0, 0.5);
        assert_eq!(outcome.status(), Some(STATUS_BAND));
        assert_eq!(outcome.payload_bits(), Some(50.0f64.to_bits()));
        assert_eq!(band_outcome(0, 0, 0.5).status(), Some(STATUS_BAND));
        let nan = f64::from_bits(0x7ff8_0000_0000_0000);
        assert_eq!(band_outcome(100, 100, nan).status(), Some(STATUS_BAND));
    }

    #[test]
    fn distance_one_and_above_follow_the_ordered_second_arm() {
        assert_eq!(band_outcome(200, 100, 1.0).status(), Some(STATUS_BAND));
        assert_eq!(band_outcome(250, 100, 2.0), GateOutcome::Accepted);
    }

    #[test]
    fn perp_exemption_uses_only_the_low_byte() {
        assert_eq!(perp_outcome(1, 300, 100, 0.5), GateOutcome::Accepted);
        assert_eq!(perp_outcome(0x101, 300, 100, 0.5), GateOutcome::Accepted);
        assert_eq!(
            perp_outcome(0x100, 300, 100, 0.5).status(),
            Some(STATUS_BAND)
        );
    }

    fn spot(first: FirstMapProbe, second: SecondMapProbe) -> SpotInput {
        SpotInput {
            token_index: 1,
            token_count: 3,
            tree_contains: false,
            first_map: first,
            second_map: second,
            price: 100,
            reference: 100,
            distance: 0.5,
        }
    }

    #[test]
    fn spot_chain_preserves_order_and_short_circuit_results() {
        let mut input = spot(FirstMapProbe::Empty, SecondMapProbe::Hit);
        input.tree_contains = true;
        assert_eq!(spot_outcome(input), GateOutcome::InvalidSpot);

        let input = SpotInput {
            token_index: 3,
            tree_contains: true,
            ..spot(FirstMapProbe::Hit, SecondMapProbe::Hit)
        };
        assert_eq!(
            spot_outcome(input),
            GateOutcome::Panic(PanicSite::SpotMetadataBounds)
        );

        assert_eq!(
            spot_outcome(spot(FirstMapProbe::Empty, SecondMapProbe::Hit)),
            GateOutcome::Accepted
        );
        assert_eq!(
            spot_outcome(spot(FirstMapProbe::Miss, SecondMapProbe::Hit)),
            GateOutcome::Accepted
        );
        assert_eq!(
            spot_outcome(spot(FirstMapProbe::Hit, SecondMapProbe::Miss)),
            GateOutcome::InvalidSpot
        );
        assert_eq!(
            spot_outcome(spot(FirstMapProbe::Hit, SecondMapProbe::NullEntries)),
            GateOutcome::InvalidSpot
        );
        assert_eq!(
            spot_outcome(spot(FirstMapProbe::Hit, SecondMapProbe::Hit)),
            GateOutcome::Accepted
        );
    }

    #[test]
    fn spot_bounds_and_price_cap_keep_distinct_raw_outcomes() {
        assert_eq!(
            spot_outcome(spot(FirstMapProbe::IndexOutOfBounds, SecondMapProbe::Empty)),
            GateOutcome::Panic(PanicSite::IndexMapBounds)
        );
        assert_eq!(
            spot_outcome(spot(FirstMapProbe::Hit, SecondMapProbe::IndexOutOfBounds)),
            GateOutcome::Panic(PanicSite::IndexMapBounds)
        );
        let mut input = spot(FirstMapProbe::Hit, SecondMapProbe::Hit);
        input.price = SPOT_PRICE_CAP;
        assert_eq!(spot_outcome(input), GateOutcome::Accepted);
        input.price += 1;
        assert_eq!(spot_outcome(input), GateOutcome::PriceTooLarge);
    }
}
