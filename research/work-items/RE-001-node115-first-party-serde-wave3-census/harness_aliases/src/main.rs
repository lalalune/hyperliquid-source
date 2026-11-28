#![forbid(unsafe_code)]
#![allow(dead_code)]
use tikv_jemallocator::Jemalloc;
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;
#[derive(serde::Deserialize, Debug)]
enum AliasEnum0 {
    #[serde(rename = "l", alias = "limit")] V0,
    #[serde(rename = "m", alias = "market")] V1,
    #[serde(rename = "T", alias = "takeProfitMarket")] V2,
    #[serde(rename = "t", alias = "takeProfitLimit")] V3,
    #[serde(rename = "S", alias = "stopMarket")] V4,
    #[serde(rename = "s", alias = "stopLimit")] V5,
    #[serde(rename = "closeForVaultWithdrawal", alias = "v")] V6,
    #[serde(rename = "d", alias = "spotDustConversion")] V7,
    #[serde(rename = "b", alias = "borrowLendLiquidation")] V8,
    #[serde(rename = "twapSlice", alias = "w")] V9,
    #[serde(rename = "trailingStopMarket", alias = "z")] V10,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasEnum0 { A { v: AliasEnum0 } }
#[derive(serde::Deserialize, Debug)]
enum ExtAliasEnum0 {
    #[serde(rename = "l", alias = "limit")] V0(u8),
    #[serde(rename = "m", alias = "market")] V1(u8),
    #[serde(rename = "T", alias = "takeProfitMarket")] V2(u8),
    #[serde(rename = "t", alias = "takeProfitLimit")] V3(u8),
    #[serde(rename = "S", alias = "stopMarket")] V4(u8),
    #[serde(rename = "s", alias = "stopLimit")] V5(u8),
    #[serde(rename = "closeForVaultWithdrawal", alias = "v")] V6(u8),
    #[serde(rename = "d", alias = "spotDustConversion")] V7(u8),
    #[serde(rename = "b", alias = "borrowLendLiquidation")] V8(u8),
    #[serde(rename = "twapSlice", alias = "w")] V9(u8),
    #[serde(rename = "trailingStopMarket", alias = "z")] V10(u8),
}
#[derive(serde::Deserialize, Debug)]
enum AliasEnum1 {
    #[serde(rename = "d", alias = "default", alias = "dexAbstraction", alias = "e")] V0,
    #[serde(rename = "disabled", alias = "i")] V1,
    #[serde(rename = "z")] V2,
    #[serde(rename = "u", alias = "unifiedAccount")] V3,
    #[serde(rename = "p", alias = "portfolioMargin")] V4,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasEnum1 { A { v: AliasEnum1 } }
#[derive(serde::Deserialize, Debug)]
enum ExtAliasEnum1 {
    #[serde(rename = "d", alias = "default", alias = "dexAbstraction", alias = "e")] V0(u8),
    #[serde(rename = "disabled", alias = "i")] V1(u8),
    #[serde(rename = "z")] V2(u8),
    #[serde(rename = "u", alias = "unifiedAccount")] V3(u8),
    #[serde(rename = "p", alias = "portfolioMargin")] V4(u8),
}
#[derive(serde::Deserialize, Debug)]
enum AliasEnum2 {
    #[serde(rename = "C", alias = "Cross")] V0,
    #[serde(rename = "I", alias = "Isolated")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasEnum2 { A { v: AliasEnum2 } }
#[derive(serde::Deserialize, Debug)]
enum ExtAliasEnum2 {
    #[serde(rename = "C", alias = "Cross")] V0(u8),
    #[serde(rename = "I", alias = "Isolated")] V1(u8),
}
#[derive(serde::Deserialize, Debug)]
enum AliasEnum3 {
    #[serde(rename = "registerToken")] V0,
    #[serde(rename = "registerToken2")] V1,
    #[serde(rename = "userGenesis")] V2,
    #[serde(rename = "genesis")] V3,
    #[serde(rename = "registerSpot")] V4,
    #[serde(rename = "registerHyperliquidity")] V5,
    #[serde(rename = "requestEvmContract")] V6,
    #[serde(rename = "setFullName")] V7,
    #[serde(rename = "setTokenAnnotation")] V8,
    #[serde(rename = "setDeployerTradingFeeShare")] V9,
    #[serde(rename = "setDeployerLabel")] V10,
    #[serde(rename = "enableFreezePrivilege")] V11,
    #[serde(rename = "freezeUser")] V12,
    #[serde(rename = "revokeFreezePrivilege")] V13,
    #[serde(rename = "enableQuoteToken")] V14,
    #[serde(rename = "disableQuoteToken")] V15,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasEnum3 { A { v: AliasEnum3 } }
#[derive(serde::Deserialize, Debug)]
enum ExtAliasEnum3 {
    #[serde(rename = "registerToken")] V0(u8),
    #[serde(rename = "registerToken2")] V1(u8),
    #[serde(rename = "userGenesis")] V2(u8),
    #[serde(rename = "genesis")] V3(u8),
    #[serde(rename = "registerSpot")] V4(u8),
    #[serde(rename = "registerHyperliquidity")] V5(u8),
    #[serde(rename = "requestEvmContract")] V6(u8),
    #[serde(rename = "setFullName")] V7(u8),
    #[serde(rename = "setTokenAnnotation")] V8(u8),
    #[serde(rename = "setDeployerTradingFeeShare")] V9(u8),
    #[serde(rename = "setDeployerLabel")] V10(u8),
    #[serde(rename = "enableFreezePrivilege")] V11(u8),
    #[serde(rename = "freezeUser")] V12(u8),
    #[serde(rename = "revokeFreezePrivilege")] V13(u8),
    #[serde(rename = "enableQuoteToken")] V14(u8),
    #[serde(rename = "disableQuoteToken")] V15(u8),
}
#[derive(serde::Deserialize, Debug)]
enum AliasEnum4 {
    #[serde(rename = "registerAsset")] V0,
    #[serde(rename = "registerAsset2")] V1,
    #[serde(rename = "setOracle")] V2,
    #[serde(rename = "haltTrading")] V3,
    #[serde(rename = "insertMarginTable")] V4,
    #[serde(rename = "setFeeRecipient")] V5,
    #[serde(rename = "setMarginTableIds")] V6,
    #[serde(rename = "setOpenInterestCaps")] V7,
    #[serde(rename = "setFundingMultipliers")] V8,
    #[serde(rename = "setFundingInterestRates")] V9,
    #[serde(rename = "setFundingClamps")] V10,
    #[serde(rename = "setSubDeployers")] V11,
    #[serde(rename = "setMarginModes")] V12,
    #[serde(rename = "setDeployerFees")] V13,
    #[serde(rename = "disableDex")] V14,
    #[serde(rename = "setPerpAnnotation")] V15,
    #[serde(rename = "migrateDexQuoteToken")] V16,
    #[serde(rename = "star")] V17,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasEnum4 { A { v: AliasEnum4 } }
#[derive(serde::Deserialize, Debug)]
enum ExtAliasEnum4 {
    #[serde(rename = "registerAsset")] V0(u8),
    #[serde(rename = "registerAsset2")] V1(u8),
    #[serde(rename = "setOracle")] V2(u8),
    #[serde(rename = "haltTrading")] V3(u8),
    #[serde(rename = "insertMarginTable")] V4(u8),
    #[serde(rename = "setFeeRecipient")] V5(u8),
    #[serde(rename = "setMarginTableIds")] V6(u8),
    #[serde(rename = "setOpenInterestCaps")] V7(u8),
    #[serde(rename = "setFundingMultipliers")] V8(u8),
    #[serde(rename = "setFundingInterestRates")] V9(u8),
    #[serde(rename = "setFundingClamps")] V10(u8),
    #[serde(rename = "setSubDeployers")] V11(u8),
    #[serde(rename = "setMarginModes")] V12(u8),
    #[serde(rename = "setDeployerFees")] V13(u8),
    #[serde(rename = "disableDex")] V14(u8),
    #[serde(rename = "setPerpAnnotation")] V15(u8),
    #[serde(rename = "migrateDexQuoteToken")] V16(u8),
    #[serde(rename = "star")] V17(u8),
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct0 {
    #[serde(rename = "a", alias = "asset")] f0: u8,
    #[serde(rename = "t", alias = "twapId")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct0 { #[serde(rename = "v")] V(AliasStruct0) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct1 {
    #[serde(rename = "a", alias = "asset")] f0: u8,
    #[serde(rename = "o", alias = "oid")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct1 { #[serde(rename = "v")] V(AliasStruct1) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct2 {
    #[serde(rename = "a", alias = "asset")] f0: u8,
    #[serde(rename = "b", alias = "isBuy")] f1: u8,
    #[serde(rename = "s", alias = "sz")] f2: u8,
    #[serde(rename = "r", alias = "reduceOnly")] f3: u8,
    #[serde(rename = "m", alias = "minutes")] f4: u8,
    #[serde(rename = "randomize", alias = "t")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct2 { #[serde(rename = "v")] V(AliasStruct2) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct3 {
    #[serde(rename = "a", alias = "asset")] f0: u8,
    #[serde(rename = "b", alias = "isBuy")] f1: u8,
    #[serde(rename = "limitPx", alias = "p")] f2: u8,
    #[serde(rename = "s", alias = "sz")] f3: u8,
    #[serde(rename = "r", alias = "reduceOnly")] f4: u8,
    #[serde(rename = "orderType", alias = "t")] f5: u8,
    #[serde(rename = "c", alias = "cloid")] f6: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct3 { #[serde(rename = "v")] V(AliasStruct3) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct4 {
    #[serde(rename = "c", alias = "core")] f0: u8,
    #[serde(rename = "t", alias = "trigger")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct4 { #[serde(rename = "v")] V(AliasStruct4) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct5 {
    #[serde(rename = "p", alias = "prev_key")] f0: u8,
    #[serde(rename = "n", alias = "next_key")] f1: u8,
    #[serde(rename = "i", alias = "is_position_tpsl")] f2: u8,
    #[serde(rename = "r", alias = "resting_sz")] f3: u8,
    #[serde(rename = "O", alias = "orig_sz")] f4: u8,
    #[serde(rename = "P", alias = "priority_rate")] f5: u8,
    #[serde(rename = "u", alias = "user")] f6: u8,
    #[serde(rename = "t", alias = "tif")] f7: u8,
    #[serde(rename = "c", alias = "core")] f8: u8,
    #[serde(rename = "o", alias = "oid")] f9: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct5 { #[serde(rename = "v")] V(AliasStruct5) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct6 {
    #[serde(rename = "l", alias = "last_update_time")] f0: u8,
    #[serde(rename = "c", alias = "category")] f1: u8,
    #[serde(rename = "d", alias = "description")] f2: u8,
    #[serde(rename = "display_name", alias = "n")] f3: u8,
    #[serde(rename = "k", alias = "keywords")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct6 { #[serde(rename = "v")] V(AliasStruct6) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct7 {
    #[serde(rename = "l", alias = "leverage")] f0: u8,
    #[serde(rename = "raw_usd", alias = "u")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct7 { #[serde(rename = "v")] V(AliasStruct7) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct8 {
    #[serde(rename = "n", alias = "name")] f0: u8,
    #[serde(rename = "s", alias = "sub_account_user")] f1: u8,
    #[serde(rename = "m", alias = "master")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct8 { #[serde(rename = "v")] V(AliasStruct8) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct9 {
    #[serde(rename = "n", alias = "name")] f0: u8,
    #[serde(rename = "v", alias = "validUntil")] f1: u8,
    #[serde(rename = "a", alias = "address")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct9 { #[serde(rename = "v")] V(AliasStruct9) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct10 {
    #[serde(rename = "au", alias = "authorizedUsers", alias = "authorized_users")] f0: u8,
    #[serde(rename = "threshold")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct10 { #[serde(rename = "v")] V(AliasStruct10) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct11 {
    #[serde(rename = "boms", alias = "boms_staked", alias = "bps_of_max_supply_staked")] f0: u8,
    #[serde(rename = "discount")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct11 { #[serde(rename = "v")] V(AliasStruct11) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct12 {
    #[serde(rename = "index", alias = "validatorIndex")] f0: u8,
    #[serde(rename = "address")] f1: u8,
    #[serde(rename = "amount")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct12 { #[serde(rename = "v")] V(AliasStruct12) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct13 {
    #[serde(rename = "activate")] f0: u8,
    #[serde(rename = "deactivate")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct13 { #[serde(rename = "v")] V(AliasStruct13) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct14 {
    #[serde(rename = "proxy")] f0: u8,
    #[serde(rename = "setOracle")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct14 { #[serde(rename = "v")] V(AliasStruct14) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct15 {
    #[serde(rename = "hex")] f0: u8,
    #[serde(rename = "base58")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct15 { #[serde(rename = "v")] V(AliasStruct15) }
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AliasStruct16 {
    #[serde(rename = "Enabled")] f0: u8,
    #[serde(rename = "Disabled")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapAliasStruct16 { #[serde(rename = "v")] V(AliasStruct16) }
fn main() {
    let s = std::env::args().nth(1).unwrap_or_default();
    let b = s.as_bytes();
    let v = serde_json::from_slice::<serde_json::Value>(b).unwrap_or(serde_json::Value::Null);
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasEnum0>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasEnum0>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasEnum0>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasEnum0>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasEnum0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasEnum0>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<ExtAliasEnum0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<ExtAliasEnum0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasEnum1>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasEnum1>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasEnum1>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasEnum1>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasEnum1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasEnum1>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<ExtAliasEnum1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<ExtAliasEnum1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasEnum2>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasEnum2>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasEnum2>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasEnum2>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasEnum2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasEnum2>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<ExtAliasEnum2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<ExtAliasEnum2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasEnum3>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasEnum3>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasEnum3>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasEnum3>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasEnum3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasEnum3>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<ExtAliasEnum3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<ExtAliasEnum3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasEnum4>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasEnum4>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasEnum4>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasEnum4>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasEnum4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasEnum4>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<ExtAliasEnum4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<ExtAliasEnum4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct0>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct0>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct0>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct0>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct1>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct1>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct1>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct1>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct2>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct2>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct2>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct2>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct3>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct3>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct3>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct3>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct4>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct4>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct4>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct4>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct5>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct5>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct5>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct5>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct6>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct6>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct6>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct6>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct7>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct7>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct7>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct7>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct8>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct8>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct8>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct8>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct9>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct9>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct9>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct9>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct10>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct10>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct10>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct10>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct11>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct11>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct11>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct11>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct11>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct11>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct12>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct12>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct12>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct12>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct13>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct13>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct13>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct13>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct14>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct14>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct14>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct14>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct15>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct15>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct15>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct15>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<AliasStruct16>(b));
    let _ = core::hint::black_box(serde_json::from_str::<AliasStruct16>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<AliasStruct16>(b));
    let _ = core::hint::black_box(serde_json::from_value::<AliasStruct16>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapAliasStruct16>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapAliasStruct16>(b));
}
