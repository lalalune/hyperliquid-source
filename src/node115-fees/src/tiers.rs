//! Node #115 fee schedule tiers (VIP volume tiers, MM maker-fraction tiers,
//! staking discount tiers, referral discounts/rebates, spot vs perp rates,
//! and builder fee approval/splits).
//!
//! Binary evidence:
//! - `.rodata` `0x5c92f9` / `0x5f67be`: `struct FeeSchedule` (8 fields: `rates`, `tiers`,
//!   `referral_discount`, `referrer_keep`, `destination`, `extra_destination_fractions`,
//!   `stake_discount_tiers`, `weigh_spot_volume_double`).
//! - `.rodata` `0x5e67c1` / `0x641b7a`: `perpCrossBaseRate`, `perpAddBaseRate`,
//!   `spotCrossBaseRate`, `spotAddBaseRate`, `ntlCutoff`, `cross`, `add`, `spotCross`,
//!   `spotAdd`, `vip`, `mm`, `userCrossRate`, `userAddRate`, `userSpotCrossRate`,
//!   `userSpotAddRate`, `activeReferralDiscount`.
//! - `.rodata` `0x5c94e6` / `0x5f70ab`: `struct StakeDiscount` (`bps_of_max_supply_staked`,
//!   `discount`), `struct StakeDiscountTiers`.
//! - `.rodata` `0x5e6ca4`: `struct ApproveBuilderFeeAction` (`maxFeeRate`),
//!   `0x5c967a`: `collected_builder_fees`, `total_fees_collected`, `total_spot_fees_collected`.
//! - `node115-fee-schedule-compose`: enforces exact `#115` schedule monotonicity,
//!   staking bounds (`<= 5.0`, `<= 0.5`), range bounds (`[0.0, 1.0]`), extra destination sum
//!   (`<= 1.0`), and rate windows (`cross` in `{0} U [0.0001, 0.001]`, `add` in `[-0.001, 0] U [0.0001, 0.001]`).

use std::collections::BTreeMap;

use crate::UserAddress;
use node115_fee_schedule_compose as compose;

/// Base maker/taker rates for perp and spot markets (`0x5e67c1`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BaseFeeRates {
    pub perp_cross: f64,
    pub perp_add: f64,
    pub spot_cross: f64,
    pub spot_add: f64,
}

impl BaseFeeRates {
    #[inline]
    pub const fn as_array(self) -> [f64; 4] {
        [self.perp_cross, self.perp_add, self.spot_cross, self.spot_add]
    }
}

/// Volume-qualified VIP tier (`0x641b7a`: `ntlCutoff`, `cross`, `add`, `spotCross`, `spotAdd`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VipFeeTier {
    pub ntl_cutoff: u64,
    pub cross: f64,
    pub add: f64,
    pub spot_cross: f64,
    pub spot_add: f64,
    /// Optional tier tail multiplier (`<= 1.0`, non-increasing per `node115-fee-schedule-compose`).
    pub tail: f64,
}

/// Maker-fraction rebate tier (`0x641b7a`: `mm` -> `maker_fraction_cutoff`, `add`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MmFeeTier {
    pub maker_fraction_cutoff: f64,
    pub add: f64,
}

/// Staking discount tier (`0x5f70ab`: `bps_of_max_supply_staked`, `discount`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StakeDiscountTier {
    pub bps_of_max_supply_staked: f64,
    pub discount: f64,
}

/// Full `#115` 8-field `struct FeeSchedule` (`0x5c92f9`).
#[derive(Clone, Debug, PartialEq)]
pub struct FeeSchedule {
    pub rates: BaseFeeRates,
    pub vip_tiers: Vec<VipFeeTier>,
    pub mm_tiers: Vec<MmFeeTier>,
    pub referral_discount: f64,
    pub referrer_keep: f64,
    pub destination: UserAddress,
    pub extra_destination_fractions: Vec<(UserAddress, f64)>,
    pub stake_discount_tiers: Vec<StakeDiscountTier>,
    pub weigh_spot_volume_double: bool,
}

/// Resolved effective fee rates for one user (`0x641b7a`: `userCrossRate`, `userAddRate`,
/// `userSpotCrossRate`, `userSpotAddRate`, `activeReferralDiscount`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UserFeeRates {
    pub perp_cross: f64,
    pub perp_add: f64,
    pub spot_cross: f64,
    pub spot_add: f64,
    pub active_referral_discount: f64,
    pub active_stake_discount: f64,
}

/// Computed fee breakdown for a single trade fill (`gross`, `referrer_rebate`, `builder_fee`,
/// `net_protocol_fee`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TradeFeeBreakdown {
    /// Positive fee charged to user (or `0` when maker earns rebate).
    pub user_fee: u64,
    /// Positive rebate credited to maker when rate `< 0.0`.
    pub maker_rebate: u64,
    /// Portion of positive `user_fee` routed to the referrer (`referrer_keep`).
    pub referrer_reward: u64,
    /// Optional builder fee charged on top (capped by user's `ApproveBuilderFeeAction`).
    pub builder_fee: u64,
    /// Protocol net fee (`user_fee - referrer_reward`).
    pub protocol_fee: u64,
}

#[inline]
fn apply_positive_discounts(rate: f64, stake_discount: f64, referral_discount: f64) -> f64 {
    if rate <= 0.0 {
        rate
    } else {
        rate * (1.0 - stake_discount) * (1.0 - referral_discount)
    }
}

impl FeeSchedule {
    /// Validate this schedule against `#115` `node115-fee-schedule-compose::evaluate`.
    pub fn validate(&self) -> compose::Outcome {
        let tiers: Vec<compose::Tier> = self
            .vip_tiers
            .iter()
            .map(|t| compose::Tier {
                values: [t.cross, t.add, t.spot_cross, t.spot_add],
                cutoff: t.ntl_cutoff,
                tail: t.tail,
            })
            .collect();
        let secondary: Vec<compose::Secondary> = self
            .mm_tiers
            .iter()
            .map(|m| compose::Secondary {
                first: m.maker_fraction_cutoff,
                second: m.add,
            })
            .collect();
        let stake_pairs: Vec<(f64, f64)> = self
            .stake_discount_tiers
            .iter()
            .map(|s| (s.bps_of_max_supply_staked, s.discount))
            .collect();
        let extra_values: Vec<f64> = self
            .extra_destination_fractions
            .iter()
            .map(|&(_, f)| f)
            .collect();
        let sched = compose::Schedule {
            seeds: self.rates.as_array(),
            tiers: &tiers,
            secondary: &secondary,
            stake_pairs: &stake_pairs,
            extra_values: &extra_values,
            ranges: [self.referral_discount, self.referrer_keep],
        };
        compose::evaluate(&sched, |_, _, _| true)
    }

    /// Full `#115` `0x36a1c20` + `0x36a58d0` validation combining `node115-fee-schedule-compose`
    /// with the exact 6-scale `5e-6` net-protocol-fee solvency floor callback for both perp and spot.
    pub fn validate_with_solvency(&self, trial_discount: f64) -> compose::Outcome {
        let tiers: Vec<compose::Tier> = self
            .vip_tiers
            .iter()
            .map(|t| compose::Tier {
                values: [t.cross, t.add, t.spot_cross, t.spot_add],
                cutoff: t.ntl_cutoff,
                tail: t.tail,
            })
            .collect();
        let secondary: Vec<compose::Secondary> = self
            .mm_tiers
            .iter()
            .map(|m| compose::Secondary {
                first: m.maker_fraction_cutoff,
                second: m.add,
            })
            .collect();
        let stake_pairs: Vec<(f64, f64)> = self
            .stake_discount_tiers
            .iter()
            .map(|s| (s.bps_of_max_supply_staked, s.discount))
            .collect();
        let extra_values: Vec<f64> = self
            .extra_destination_fractions
            .iter()
            .map(|&(_, f)| f)
            .collect();
        let sched = compose::Schedule {
            seeds: self.rates.as_array(),
            tiers: &tiers,
            secondary: &secondary,
            stake_pairs: &stake_pairs,
            extra_values: &extra_values,
            ranges: [self.referral_discount, self.referrer_keep],
        };
        let perp_vip_adds: Vec<f64> = self.vip_tiers.iter().map(|t| t.add).collect();
        let perp_vip_crosses: Vec<f64> = self.vip_tiers.iter().map(|t| t.cross).collect();
        let spot_vip_adds: Vec<f64> = self.vip_tiers.iter().map(|t| t.spot_add).collect();
        let spot_vip_crosses: Vec<f64> = self.vip_tiers.iter().map(|t| t.spot_cross).collect();
        let mm_adds: Vec<f64> = self.mm_tiers.iter().map(|m| m.add).collect();
        compose::evaluate(&sched, |side, _, max_stake_discount| {
            let (vip_adds, vip_crosses, base_add, base_cross) = match side {
                compose::FloorSide::First => (
                    perp_vip_adds.as_slice(),
                    perp_vip_crosses.as_slice(),
                    self.rates.perp_add,
                    self.rates.perp_cross,
                ),
                compose::FloorSide::Second => (
                    spot_vip_adds.as_slice(),
                    spot_vip_crosses.as_slice(),
                    self.rates.spot_add,
                    self.rates.spot_cross,
                ),
            };
            crate::solvency::check_net_fee_solvency_0x36a58d0(
                crate::solvency::SolvencyCheckInputs {
                    vip_adds,
                    mm_adds: &mm_adds,
                    vip_crosses,
                    base_add,
                    base_cross,
                    max_staking_discount: max_stake_discount,
                    referral_discount: self.referral_discount,
                    trial_discount,
                    referrer_keep: self.referrer_keep,
                },
            )
        })
    }

    /// Computes weighted 14-day qualifying volume using `weigh_spot_volume_double`.
    #[inline]
    pub const fn weighted_volume(&self, perp_vlm: u64, spot_vlm: u64) -> u64 {
        let spot_weighted = if self.weigh_spot_volume_double {
            spot_vlm.saturating_mul(2)
        } else {
            spot_vlm
        };
        perp_vlm.saturating_add(spot_weighted)
    }

    /// Resolve effective maker/taker perp & spot fee rates for a user.
    pub fn user_fee_rates(
        &self,
        perp_vlm_14d: u64,
        spot_vlm_14d: u64,
        maker_fraction_14d: f64,
        staked_bps: f64,
        has_active_referrer: bool,
    ) -> UserFeeRates {
        let weighted = self.weighted_volume(perp_vlm_14d, spot_vlm_14d);

        let mut perp_cross = self.rates.perp_cross;
        let mut perp_add = self.rates.perp_add;
        let mut spot_cross = self.rates.spot_cross;
        let mut spot_add = self.rates.spot_add;

        for tier in &self.vip_tiers {
            if weighted >= tier.ntl_cutoff {
                perp_cross = tier.cross;
                perp_add = tier.add;
                spot_cross = tier.spot_cross;
                spot_add = tier.spot_add;
            }
        }

        for mm in &self.mm_tiers {
            if maker_fraction_14d >= mm.maker_fraction_cutoff {
                perp_add = perp_add.min(mm.add);
                spot_add = spot_add.min(mm.add);
            }
        }

        let mut stake_discount = 0.0_f64;
        for st in &self.stake_discount_tiers {
            if staked_bps >= st.bps_of_max_supply_staked {
                stake_discount = st.discount;
            }
        }

        let ref_disc = if has_active_referrer {
            self.referral_discount
        } else {
            0.0
        };

        UserFeeRates {
            perp_cross: apply_positive_discounts(perp_cross, stake_discount, ref_disc),
            perp_add: apply_positive_discounts(perp_add, stake_discount, ref_disc),
            spot_cross: apply_positive_discounts(spot_cross, stake_discount, ref_disc),
            spot_add: apply_positive_discounts(spot_add, stake_discount, ref_disc),
            active_referral_discount: ref_disc,
            active_stake_discount: stake_discount,
        }
    }

    /// Compute exact integer fee breakdown for a fill of `notional` (in raw fixed-point units).
    /// `builder_fee_tenths_bps` is denominated in tenths of a basis point (`100_000` = 100%,
    /// so `10` = 1 bp = `0.0001`).
    pub fn compute_trade_fee(
        &self,
        notional: u64,
        is_spot: bool,
        is_taker: bool,
        rates: UserFeeRates,
        has_active_referrer: bool,
        builder_fee_rate: Option<f64>,
    ) -> TradeFeeBreakdown {
        let rate = match (is_spot, is_taker) {
            (false, true) => rates.perp_cross,
            (false, false) => rates.perp_add,
            (true, true) => rates.spot_cross,
            (true, false) => rates.spot_add,
        };
        let ntl_f = notional as f64;
        let (user_fee, maker_rebate) = if rate >= 0.0 {
            let f = (ntl_f * rate).floor();
            let u = if f.is_finite() && f > 0.0 { f as u64 } else { 0 };
            (u, 0)
        } else {
            let r = (ntl_f * (-rate)).floor();
            let u = if r.is_finite() && r > 0.0 { r as u64 } else { 0 };
            (0, u)
        };
        let referrer_reward = if has_active_referrer && user_fee > 0 {
            let rr = ((user_fee as f64) * self.referrer_keep).floor();
            if rr.is_finite() && rr > 0.0 {
                (rr as u64).min(user_fee)
            } else {
                0
            }
        } else {
            0
        };
        let builder_fee = match builder_fee_rate {
            Some(br) if br > 0.0 && br.is_finite() => {
                let bf = (ntl_f * br).floor();
                if bf.is_finite() && bf > 0.0 { bf as u64 } else { 0 }
            }
            _ => 0,
        };
        TradeFeeBreakdown {
            user_fee,
            maker_rebate,
            referrer_reward,
            builder_fee,
            protocol_fee: user_fee.saturating_sub(referrer_reward),
        }
    }
}

/// Per-user builder fee approval registry (`ApproveBuilderFeeAction` `0x5e6ca4`,
/// `collected_builder_fees` `0x5c967a`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BuilderFeeRegistry {
    /// Approved maximum fee rate (in decimal fraction, e.g. `0.001` = 10 bps) per `(user, builder)`.
    pub approvals: BTreeMap<(UserAddress, UserAddress), f64>,
    /// Cumulative collected builder fees per builder (`collected_builder_fees`).
    pub collected_builder_fees: BTreeMap<UserAddress, u64>,
}

/// Errors returned by `BuilderFeeRegistry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuilderFeeError {
    InvalidRate,
    ExceedsProtocolMax,
    NotApproved,
    ExceedsUserApproval,
}

/// Maximum protocol-allowed builder fee rates: 0.1% (10 bps) for perp, 1.0% (100 bps) for spot.
pub const MAX_PERP_BUILDER_FEE_RATE: f64 = 0.001;
pub const MAX_SPOT_BUILDER_FEE_RATE: f64 = 0.01;

impl BuilderFeeRegistry {
    /// Record or update a user's `ApproveBuilderFeeAction` (`max_fee_rate` in `[0.0, 0.01]`).
    pub fn approve(
        &mut self,
        user: UserAddress,
        builder: UserAddress,
        max_fee_rate: f64,
    ) -> Result<(), BuilderFeeError> {
        if !max_fee_rate.is_finite() || max_fee_rate < 0.0 {
            return Err(BuilderFeeError::InvalidRate);
        }
        if max_fee_rate > MAX_SPOT_BUILDER_FEE_RATE {
            return Err(BuilderFeeError::ExceedsProtocolMax);
        }
        if max_fee_rate == 0.0 {
            self.approvals.remove(&(user, builder));
        } else {
            self.approvals.insert((user, builder), max_fee_rate);
        }
        Ok(())
    }

    /// Validate a requested builder fee rate against both protocol market cap and user approval.
    pub fn validate_charge(
        &self,
        user: &UserAddress,
        builder: &UserAddress,
        requested_rate: f64,
        is_spot: bool,
    ) -> Result<f64, BuilderFeeError> {
        if !requested_rate.is_finite() || requested_rate < 0.0 {
            return Err(BuilderFeeError::InvalidRate);
        }
        let protocol_max = if is_spot {
            MAX_SPOT_BUILDER_FEE_RATE
        } else {
            MAX_PERP_BUILDER_FEE_RATE
        };
        if requested_rate > protocol_max {
            return Err(BuilderFeeError::ExceedsProtocolMax);
        }
        let &approved = self
            .approvals
            .get(&(*user, *builder))
            .ok_or(BuilderFeeError::NotApproved)?;
        if requested_rate > approved {
            return Err(BuilderFeeError::ExceedsUserApproval);
        }
        Ok(requested_rate)
    }

    /// Credit collected builder fees (saturating).
    pub fn record_collected(&mut self, builder: UserAddress, amount: u64) {
        let entry = self.collected_builder_fees.entry(builder).or_insert(0);
        *entry = entry.saturating_add(amount);
    }
}
