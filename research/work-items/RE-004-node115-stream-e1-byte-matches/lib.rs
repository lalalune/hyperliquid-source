#![forbid(unsafe_code)]

//! Independently authored first-party node #115 `assets`, `fees`, and `orderbook` functions
//! verified to 100.00% relocation-qualified compiled-byte identity under
//! `rustc 1.95.0 (59807616e 2026-04-14) --edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes`.

// ---------------------------------------------------------------------------
// assets: 8 real PerpMeta / SpotMeta / TokenSpec business-logic FDEs (1,016 B)
// ---------------------------------------------------------------------------

static POW10_256: [f64; 256] = {
    let mut a = [1.0; 256];
    let mut i = 1;
    while i < 256 {
        a[i] = a[i - 1] * 10.0;
        i += 1;
    }
    a
};

#[repr(C)]
pub struct TokenSpec {
    pub _pad: [u8; 0x18],
    pub sz_decimals: u8,
    pub wei_decimals: u8,
}

#[inline(never)]
pub fn assets_token_wei_per_sz(spec: &TokenSpec) -> u64 {
    fn inner(spec: &TokenSpec) -> Option<u64> {
        let diff = spec.wei_decimals.checked_sub(spec.sz_decimals)?;
        10_u64.checked_pow(u32::from(diff))
    }
    inner(spec).unwrap()
}

#[repr(C)]
pub struct SpotInfo {
    pub tokens: [usize; 2],
    pub _pad: [u8; 0x10],
}

#[repr(C)]
pub struct TokenInfo {
    pub _pad0: [u8; 0x38],
    pub name_ptr: usize,
    pub name_len: usize,
    pub sz_decimals: u8,
    pub wei_decimals: u8,
    pub _pad1: [u8; 6],
    pub spots: Vec<usize>,
    pub _pad2: [u8; 0x158 - 0x68],
}

#[repr(C)]
pub struct SpotMeta {
    pub universe: Vec<SpotInfo>,
    pub token_infos: Vec<TokenInfo>,
}

#[inline(always)]
fn spot_token_info(meta: &SpotMeta, token: usize) -> &TokenInfo {
    meta.token_infos.get(token).unwrap()
}

#[inline(never)]
pub fn assets_first_spot_for_token(meta: &SpotMeta, token: usize) -> Option<usize> {
    spot_token_info(meta, token).spots.first().copied()
}

#[inline(never)]
pub fn assets_spot_for_quote(
    meta: &SpotMeta,
    base_token: usize,
    quote_token: usize,
) -> Option<usize> {
    for &spot in &spot_token_info(meta, base_token).spots {
        if meta.universe[spot].tokens[1] == quote_token {
            return Some(spot);
        }
    }
    None
}

#[inline(never)]
pub fn assets_quote_name_pair(meta: &SpotMeta, spot: usize) -> (usize, usize) {
    let quote = meta.universe[spot].tokens[1];
    let info = spot_token_info(meta, quote);
    (info.name_ptr, info.name_len)
}

#[inline(never)]
pub fn assets_checked_sz_to_wei(meta: &SpotMeta, token: usize, sz: u64) -> Option<u64> {
    fn inner(info: &TokenInfo) -> Option<u64> {
        let diff = info.wei_decimals.checked_sub(info.sz_decimals)?;
        10_u64.checked_pow(u32::from(diff))
    }
    let scale = inner(spot_token_info(meta, token)).unwrap();
    sz.checked_mul(scale)
}

#[repr(C)]
pub struct PerpAssetInfo {
    pub _pad0: [u8; 0x1d],
    pub sz_decimals: u8,
    pub _pad1: [u8; 2],
}

#[repr(C)]
pub struct PerpMeta {
    pub universe: Vec<PerpAssetInfo>,
    pub _pad1: [u8; 0x50 - 24],
    pub pdi: usize,
}

#[inline(never)]
pub fn assets_perp_px_decimals(meta: &PerpMeta, asset: usize) -> u8 {
    let pdi = asset / 10_000;
    let local = asset % 10_000;
    let info = if pdi == meta.pdi {
        meta.universe.get(local)
    } else {
        None
    }
    .unwrap();
    6_u8 - info.sz_decimals
}

#[inline(never)]
pub fn assets_perp_sz_to_f64(raw: u64, asset: usize, meta: &PerpMeta) -> f64 {
    if raw == 0 {
        return 0.0;
    }
    let pdi = asset / 10_000;
    let local = asset % 10_000;
    let info = if pdi == meta.pdi {
        meta.universe.get(local)
    } else {
        None
    }
    .unwrap();
    (raw as f64) / POW10_256[usize::from(info.sz_decimals)]
}

#[inline(never)]
pub fn assets_perp_px_to_f64(raw: u64, asset: usize, meta: &PerpMeta) -> f64 {
    let pdi = asset / 10_000;
    let local = asset % 10_000;
    let info = if pdi == meta.pdi {
        meta.universe.get(local)
    } else {
        None
    }
    .unwrap();
    let px_dec = 6_u8 - info.sz_decimals;
    (raw as f64) / POW10_256[usize::from(px_dec)]
}

// ---------------------------------------------------------------------------
// Visitor::expecting (25 B each) across assets, fees, and orderbook
// ---------------------------------------------------------------------------

macro_rules! def_expecting {
    ($( ($fn_name:ident, $msg:literal) ),+ $(,)?) => {
        $(
            #[inline(never)]
            pub fn $fn_name(_self: &(), f: &mut &mut dyn core::fmt::Write) -> core::fmt::Result {
                f.write_str($msg)
            }
        )+
    };
}

def_expecting!(
    // assets (23 distinct types -> 69 FDEs, 1,725 B)
    (assets_expecting_side, "enum Side"),
    (assets_expecting_perp_asset_info, "struct PerpAssetInfo"),
    (assets_expecting_perp_meta, "struct PerpMeta"),
    (assets_expecting_spot_info, "struct SpotInfo"),
    (assets_expecting_spot_meta, "struct SpotMeta"),
    (assets_expecting_token_info, "struct TokenInfo"),
    (assets_expecting_token_spec, "struct TokenSpec"),
    (assets_expecting_aqav2_token_info, "struct Aqav2TokenInfo"),
    (assets_expecting_token_infos, "tuple struct TokenInfos"),
    (assets_expecting_pdi, "tuple struct Pdi"),
    (assets_expecting_px, "tuple struct Px"),
    (assets_expecting_sz, "tuple struct Sz"),
    (assets_expecting_szi, "tuple struct Szi"),
    (assets_expecting_ntl, "tuple struct Ntl"),
    (assets_expecting_ntli, "tuple struct Ntli"),
    (assets_expecting_wei, "tuple struct Wei"),
    (assets_expecting_side_map, "tuple struct SideMap"),
    (assets_expecting_usdc_px, "tuple struct UsdcPx"),
    (assets_expecting_usdc_ntl, "tuple struct UsdcNtl"),
    (assets_expecting_usdc_ntli, "tuple struct UsdcNtli"),
    (assets_expecting_usdc_big_spot_ntl, "tuple struct UsdcBigSpotNtl"),
    (assets_expecting_usdc_ntl_scale_serde, "tuple struct UsdcNtlScaleSerde"),
    (assets_expecting_usdc_rough_ntli, "tuple struct UsdcRoughNtli"),
    // fees (20 distinct types -> 59 FDEs, 1,475 B)
    (fees_expecting_fee_schedule, "struct FeeSchedule"),
    (fees_expecting_new_fee_schedule, "struct NewFeeSchedule"),
    (fees_expecting_fee_tiers, "struct FeeTiers"),
    (fees_expecting_fee_tracker, "struct FeeTracker"),
    (fees_expecting_fee_trial, "struct FeeTrial"),
    (fees_expecting_vip_fees, "struct VipFees"),
    (fees_expecting_mm_fees, "struct MmFees"),
    (fees_expecting_user_fee_state, "struct UserFeeState"),
    (fees_expecting_referral_state, "struct ReferralState"),
    (fees_expecting_referrer_state, "struct ReferrerState"),
    (fees_expecting_stake_discount, "struct StakeDiscount"),
    (fees_expecting_stake_discount_tiers, "struct StakeDiscountTiers"),
    (fees_expecting_collected_builder_fees, "tuple struct CollectedBuilderFees"),
    (fees_expecting_unvalidated_hip3_deployer_fee, "struct UnvalidatedHip3DeployerFee"),
    (fees_expecting_add_cross_scaled_vlm, "struct AddCrossScaledVlm"),
    (fees_expecting_scaled_and_raw_vlm, "struct ScaledAndRawVlm"),
    (fees_expecting_daily_scaled_vlms, "tuple struct DailyScaledVlms"),
    (fees_expecting_fee_rate_map_serde, "tuple struct FeeRateMapSerde"),
    (fees_expecting_raw_vlm, "tuple struct RawVlm"),
    (fees_expecting_scaled_vlm, "tuple struct ScaledVlm"),
    // orderbook (36 distinct types -> 107 FDEs, 2,675 B)
    (orderbook_expecting_tpsl, "enum Tpsl"),
    (orderbook_expecting_order_description, "enum OrderDescription"),
    (orderbook_expecting_untriggered_order, "enum UntriggeredOrder"),
    (orderbook_expecting_book, "struct Book"),
    (orderbook_expecting_book_order, "struct BookOrder"),
    (orderbook_expecting_book_order_key, "tuple struct BookOrderKey"),
    (orderbook_expecting_book_orders, "tuple struct BookOrders"),
    (orderbook_expecting_books, "tuple struct Books"),
    (orderbook_expecting_level, "struct Level"),
    (orderbook_expecting_level_summary, "struct LevelSummary"),
    (orderbook_expecting_slab, "struct Slab"),
    (orderbook_expecting_order_core, "struct OrderCore"),
    (orderbook_expecting_order_wire_serde, "struct OrderWireSerde"),
    (orderbook_expecting_order_builder_info, "struct OrderBuilderInfo"),
    (orderbook_expecting_open_order_tracker, "struct OpenOrderTracker"),
    (orderbook_expecting_cancel, "struct Cancel"),
    (orderbook_expecting_cancel_by_cloid, "struct CancelByCloid"),
    (orderbook_expecting_cloid, "tuple struct Cloid"),
    (orderbook_expecting_cloid_tracker, "struct CloidTracker"),
    (orderbook_expecting_user_cloid_tracker, "struct UserCloidTracker"),
    (orderbook_expecting_modify_wire, "struct ModifyWire"),
    (orderbook_expecting_scheduled_cancel, "struct ScheduledCancel"),
    (orderbook_expecting_trigger, "struct Trigger"),
    (orderbook_expecting_trigger_order, "struct TriggerOrder"),
    (orderbook_expecting_trigger_wire_serde, "struct TriggerWireSerde"),
    (orderbook_expecting_trailing_stop_order, "struct TrailingStopOrder"),
    (orderbook_expecting_twap_id, "tuple struct TwapId"),
    (orderbook_expecting_twap_details_wire, "struct TwapDetailsWire"),
    (orderbook_expecting_twap_heap_key, "struct TwapHeapKey"),
    (orderbook_expecting_twap_schedule, "struct TwapSchedule"),
    (orderbook_expecting_twap_state, "struct TwapState"),
    (orderbook_expecting_twap_tracker, "struct TwapTracker"),
    (orderbook_expecting_twap_trigger, "struct TwapTrigger"),
    (orderbook_expecting_twap_trigger_wire, "struct TwapTriggerWire"),
    (orderbook_expecting_twap_wire_serde, "struct TwapWireSerde"),
    (orderbook_expecting_waiting_twap, "struct WaitingTwap"),
);
