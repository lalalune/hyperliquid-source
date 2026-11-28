#![forbid(unsafe_code)]
#![allow(dead_code, non_camel_case_types, non_snake_case)]
use serde::Deserialize;
use core::hint::black_box;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Deserialize)]
enum E0 {
    #[serde(rename = "Perp")] V0,
    #[serde(rename = "Spot")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE0 { A { x: E0 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE0 { A(E0), B(u64) }
#[inline(never)] fn run_0(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E0>(s));
    let _ = black_box(serde_json::from_slice::<E0>(b));
    let _ = black_box(rmp_serde::from_slice::<E0>(b));
    let _ = black_box(serde_json::from_slice::<TagE0>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE0>(b));
    let _ = black_box(serde_json::from_slice::<UntagE0>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE0>(b));
}
#[derive(Deserialize)]
enum E1 {
    #[serde(rename = "Pct")] V0,
    #[serde(rename = "Px")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE1 { A { x: E1 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE1 { A(E1), B(u64) }
#[inline(never)] fn run_1(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E1>(s));
    let _ = black_box(serde_json::from_slice::<E1>(b));
    let _ = black_box(rmp_serde::from_slice::<E1>(b));
    let _ = black_box(serde_json::from_slice::<TagE1>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE1>(b));
    let _ = black_box(serde_json::from_slice::<UntagE1>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE1>(b));
}
#[derive(Deserialize)]
enum E2 {
    #[serde(rename = "technical")] V0,
    #[serde(rename = "treasury")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE2 { A { x: E2 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE2 { A(E2), B(u64) }
#[inline(never)] fn run_2(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E2>(s));
    let _ = black_box(serde_json::from_slice::<E2>(b));
    let _ = black_box(rmp_serde::from_slice::<E2>(b));
    let _ = black_box(serde_json::from_slice::<TagE2>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE2>(b));
    let _ = black_box(serde_json::from_slice::<UntagE2>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE2>(b));
}
#[derive(Deserialize)]
enum E3 {
    #[serde(rename = "destination")] V0,
    #[serde(rename = "usd")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE3 { A { x: E3 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE3 { A(E3), B(u64) }
#[inline(never)] fn run_3(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E3>(s));
    let _ = black_box(serde_json::from_slice::<E3>(b));
    let _ = black_box(rmp_serde::from_slice::<E3>(b));
    let _ = black_box(serde_json::from_slice::<TagE3>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE3>(b));
    let _ = black_box(serde_json::from_slice::<UntagE3>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE3>(b));
}
#[derive(Deserialize)]
enum E4 {
    #[serde(rename = "user")] V0,
    #[serde(rename = "usd")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE4 { A { x: E4 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE4 { A(E4), B(u64) }
#[inline(never)] fn run_4(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E4>(s));
    let _ = black_box(serde_json::from_slice::<E4>(b));
    let _ = black_box(rmp_serde::from_slice::<E4>(b));
    let _ = black_box(serde_json::from_slice::<TagE4>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE4>(b));
    let _ = black_box(serde_json::from_slice::<UntagE4>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE4>(b));
}
#[derive(Deserialize)]
enum E5 {
    #[serde(rename = "d")] V0,
    #[serde(rename = "v")] V1,
    #[serde(rename = "l")] V2,
    #[serde(rename = "a")] V3,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE5 { A { x: E5 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE5 { A(E5), B(u64) }
#[inline(never)] fn run_5(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E5>(s));
    let _ = black_box(serde_json::from_slice::<E5>(b));
    let _ = black_box(rmp_serde::from_slice::<E5>(b));
    let _ = black_box(serde_json::from_slice::<TagE5>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE5>(b));
    let _ = black_box(serde_json::from_slice::<UntagE5>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE5>(b));
}
#[derive(Deserialize)]
enum E6 {
    #[serde(rename = "tp")] V0,
    #[serde(rename = "sl")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE6 { A { x: E6 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE6 { A(E6), B(u64) }
#[inline(never)] fn run_6(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E6>(s));
    let _ = black_box(serde_json::from_slice::<E6>(b));
    let _ = black_box(rmp_serde::from_slice::<E6>(b));
    let _ = black_box(serde_json::from_slice::<TagE6>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE6>(b));
    let _ = black_box(serde_json::from_slice::<UntagE6>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE6>(b));
}
#[derive(Deserialize)]
enum E7 {
    #[serde(rename = "H")] V0,
    #[serde(rename = "R")] V1,
    #[serde(rename = "S")] V2,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE7 { A { x: E7 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE7 { A(E7), B(u64) }
#[inline(never)] fn run_7(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E7>(s));
    let _ = black_box(serde_json::from_slice::<E7>(b));
    let _ = black_box(rmp_serde::from_slice::<E7>(b));
    let _ = black_box(serde_json::from_slice::<TagE7>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE7>(b));
    let _ = black_box(serde_json::from_slice::<UntagE7>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE7>(b));
}
#[derive(Deserialize)]
enum E8 {
    #[serde(rename = "e")] V0,
    #[serde(rename = "x")] V1,
    #[serde(rename = "d")] V2,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE8 { A { x: E8 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE8 { A(E8), B(u64) }
#[inline(never)] fn run_8(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E8>(s));
    let _ = black_box(serde_json::from_slice::<E8>(b));
    let _ = black_box(rmp_serde::from_slice::<E8>(b));
    let _ = black_box(serde_json::from_slice::<TagE8>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE8>(b));
    let _ = black_box(serde_json::from_slice::<UntagE8>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE8>(b));
}
#[derive(Deserialize)]
enum E9 {
    #[serde(rename = "Main")] V0,
    #[serde(rename = "Hip3")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE9 { A { x: E9 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE9 { A(E9), B(u64) }
#[inline(never)] fn run_9(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E9>(s));
    let _ = black_box(serde_json::from_slice::<E9>(b));
    let _ = black_box(rmp_serde::from_slice::<E9>(b));
    let _ = black_box(serde_json::from_slice::<TagE9>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE9>(b));
    let _ = black_box(serde_json::from_slice::<UntagE9>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE9>(b));
}
#[derive(Deserialize)]
enum E10 {
    #[serde(rename = "Q")] V0,
    #[serde(rename = "N")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE10 { A { x: E10 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE10 { A(E10), B(u64) }
#[inline(never)] fn run_10(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E10>(s));
    let _ = black_box(serde_json::from_slice::<E10>(b));
    let _ = black_box(rmp_serde::from_slice::<E10>(b));
    let _ = black_box(serde_json::from_slice::<TagE10>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE10>(b));
    let _ = black_box(serde_json::from_slice::<UntagE10>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE10>(b));
}
#[derive(Deserialize)]
enum E11 {
    #[serde(rename = "l")] V0,
    #[serde(rename = "leverage")] V1,
    #[serde(rename = "raw_usd")] V2,
    #[serde(rename = "u")] V3,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE11 { A { x: E11 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE11 { A(E11), B(u64) }
#[inline(never)] fn run_11(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E11>(s));
    let _ = black_box(serde_json::from_slice::<E11>(b));
    let _ = black_box(rmp_serde::from_slice::<E11>(b));
    let _ = black_box(serde_json::from_slice::<TagE11>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE11>(b));
    let _ = black_box(serde_json::from_slice::<UntagE11>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE11>(b));
}
#[derive(Deserialize)]
enum E12 {
    #[serde(rename = "token")] V0,
    #[serde(rename = "system_address")] V1,
    #[serde(rename = "contract")] V2,
    #[serde(rename = "wei")] V3,
    #[serde(rename = "user")] V4,
    #[serde(rename = "send_to_evm_data")] V5,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE12 { A { x: E12 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE12 { A(E12), B(u64) }
#[inline(never)] fn run_12(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E12>(s));
    let _ = black_box(serde_json::from_slice::<E12>(b));
    let _ = black_box(rmp_serde::from_slice::<E12>(b));
    let _ = black_box(serde_json::from_slice::<TagE12>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE12>(b));
    let _ = black_box(serde_json::from_slice::<UntagE12>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE12>(b));
}
#[derive(Deserialize)]
enum E13 {
    #[serde(rename = "a")] V0,
    #[serde(rename = "asset")] V1,
    #[serde(rename = "b")] V2,
    #[serde(rename = "isBuy")] V3,
    #[serde(rename = "limitPx")] V4,
    #[serde(rename = "p")] V5,
    #[serde(rename = "s")] V6,
    #[serde(rename = "sz")] V7,
    #[serde(rename = "r")] V8,
    #[serde(rename = "reduceOnly")] V9,
    #[serde(rename = "orderType")] V10,
    #[serde(rename = "t")] V11,
    #[serde(rename = "c")] V12,
    #[serde(rename = "cloid")] V13,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE13 { A { x: E13 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE13 { A(E13), B(u64) }
#[inline(never)] fn run_13(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E13>(s));
    let _ = black_box(serde_json::from_slice::<E13>(b));
    let _ = black_box(rmp_serde::from_slice::<E13>(b));
    let _ = black_box(serde_json::from_slice::<TagE13>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE13>(b));
    let _ = black_box(serde_json::from_slice::<UntagE13>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE13>(b));
}
#[derive(Deserialize)]
enum E14 {
    #[serde(rename = "ntl_cutoff")] V0,
    #[serde(rename = "rates")] V1,
    #[serde(rename = "staking_keep_frac_for_referrer")] V2,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE14 { A { x: E14 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE14 { A(E14), B(u64) }
#[inline(never)] fn run_14(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E14>(s));
    let _ = black_box(serde_json::from_slice::<E14>(b));
    let _ = black_box(rmp_serde::from_slice::<E14>(b));
    let _ = black_box(serde_json::from_slice::<TagE14>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE14>(b));
    let _ = black_box(serde_json::from_slice::<UntagE14>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE14>(b));
}
#[derive(Deserialize)]
enum E15 {
    #[serde(rename = "Legacy")] V0,
    #[serde(rename = "Eip2930")] V1,
    #[serde(rename = "Eip1559")] V2,
    #[serde(rename = "Eip4844")] V3,
    #[serde(rename = "Eip7702")] V4,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE15 { A { x: E15 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE15 { A(E15), B(u64) }
#[inline(never)] fn run_15(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E15>(s));
    let _ = black_box(serde_json::from_slice::<E15>(b));
    let _ = black_box(rmp_serde::from_slice::<E15>(b));
    let _ = black_box(serde_json::from_slice::<TagE15>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE15>(b));
    let _ = black_box(serde_json::from_slice::<UntagE15>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE15>(b));
}
#[derive(Deserialize)]
enum E16 {
    #[serde(rename = "parentHash")] V0,
    #[serde(rename = "ommersHash")] V1,
    #[serde(rename = "sha3Uncles")] V2,
    #[serde(rename = "beneficiary")] V3,
    #[serde(rename = "miner")] V4,
    #[serde(rename = "stateRoot")] V5,
    #[serde(rename = "transactionsRoot")] V6,
    #[serde(rename = "receiptsRoot")] V7,
    #[serde(rename = "logsBloom")] V8,
    #[serde(rename = "difficulty")] V9,
    #[serde(rename = "number")] V10,
    #[serde(rename = "gasLimit")] V11,
    #[serde(rename = "gasUsed")] V12,
    #[serde(rename = "timestamp")] V13,
    #[serde(rename = "extraData")] V14,
    #[serde(rename = "mixHash")] V15,
    #[serde(rename = "nonce")] V16,
    #[serde(rename = "baseFeePerGas")] V17,
    #[serde(rename = "withdrawalsRoot")] V18,
    #[serde(rename = "blobGasUsed")] V19,
    #[serde(rename = "excessBlobGas")] V20,
    #[serde(rename = "parentBeaconBlockRoot")] V21,
    #[serde(rename = "requestsHash")] V22,
    #[serde(rename = "blockAccessListHash")] V23,
    #[serde(rename = "slotNumber")] V24,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE16 { A { x: E16 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE16 { A(E16), B(u64) }
#[inline(never)] fn run_16(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E16>(s));
    let _ = black_box(serde_json::from_slice::<E16>(b));
    let _ = black_box(rmp_serde::from_slice::<E16>(b));
    let _ = black_box(serde_json::from_slice::<TagE16>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE16>(b));
    let _ = black_box(serde_json::from_slice::<UntagE16>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE16>(b));
}
#[derive(Deserialize)]
enum E17 {
    #[serde(rename = "s")] V0,
    #[serde(rename = "v")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE17 { A { x: E17 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE17 { A(E17), B(u64) }
#[inline(never)] fn run_17(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E17>(s));
    let _ = black_box(serde_json::from_slice::<E17>(b));
    let _ = black_box(rmp_serde::from_slice::<E17>(b));
    let _ = black_box(serde_json::from_slice::<TagE17>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE17>(b));
    let _ = black_box(serde_json::from_slice::<UntagE17>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE17>(b));
}
#[derive(Deserialize)]
enum E18 {
    #[serde(rename = "signature")] V0,
    #[serde(rename = "transaction")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE18 { A { x: E18 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE18 { A(E18), B(u64) }
#[inline(never)] fn run_18(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E18>(s));
    let _ = black_box(serde_json::from_slice::<E18>(b));
    let _ = black_box(rmp_serde::from_slice::<E18>(b));
    let _ = black_box(serde_json::from_slice::<TagE18>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE18>(b));
    let _ = black_box(serde_json::from_slice::<UntagE18>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE18>(b));
}
#[derive(Deserialize)]
enum E19 {
    #[serde(rename = "id")] V0,
    #[serde(rename = "keywordToValue")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE19 { A { x: E19 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE19 { A(E19), B(u64) }
#[inline(never)] fn run_19(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E19>(s));
    let _ = black_box(serde_json::from_slice::<E19>(b));
    let _ = black_box(rmp_serde::from_slice::<E19>(b));
    let _ = black_box(serde_json::from_slice::<TagE19>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE19>(b));
    let _ = black_box(serde_json::from_slice::<UntagE19>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE19>(b));
}
#[derive(Deserialize)]
enum E20 {
    #[serde(rename = "user")] V0,
    #[serde(rename = "action")] V1,
    #[serde(rename = "id")] V2,
    #[serde(rename = "is_frontend")] V3,
    #[serde(rename = "expires_after")] V4,
    #[serde(rename = "broadcaster")] V5,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE20 { A { x: E20 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE20 { A(E20), B(u64) }
#[inline(never)] fn run_20(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E20>(s));
    let _ = black_box(serde_json::from_slice::<E20>(b));
    let _ = black_box(rmp_serde::from_slice::<E20>(b));
    let _ = black_box(serde_json::from_slice::<TagE20>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE20>(b));
    let _ = black_box(serde_json::from_slice::<UntagE20>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE20>(b));
}
#[derive(Deserialize)]
enum E21 {
    #[serde(rename = "meta")] V0,
    #[serde(rename = "user_states")] V1,
    #[serde(rename = "oracle")] V2,
    #[serde(rename = "total_net_deposit")] V3,
    #[serde(rename = "total_non_bridge_deposit")] V4,
    #[serde(rename = "perform_auto_deleveraging")] V5,
    #[serde(rename = "adl_shortfall_remaining")] V6,
    #[serde(rename = "bridge2_withdraw_fee")] V7,
    #[serde(rename = "daily_exchange_scaled_and_raw_vlms")] V8,
    #[serde(rename = "halted_assets")] V9,
    #[serde(rename = "override_max_signed_distances_from_oracle")] V10,
    #[serde(rename = "max_withdraw_leverage")] V11,
    #[serde(rename = "last_set_global_time")] V12,
    #[serde(rename = "lnsgt")] V13,
    #[serde(rename = "usdc_ntl_scale")] V14,
    #[serde(rename = "isolated_external")] V15,
    #[serde(rename = "isolated_oracle")] V16,
    #[serde(rename = "moh")] V17,
    #[serde(rename = "znfn")] V18,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE21 { A { x: E21 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE21 { A(E21), B(u64) }
#[inline(never)] fn run_21(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E21>(s));
    let _ = black_box(serde_json::from_slice::<E21>(b));
    let _ = black_box(rmp_serde::from_slice::<E21>(b));
    let _ = black_box(serde_json::from_slice::<TagE21>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE21>(b));
    let _ = black_box(serde_json::from_slice::<UntagE21>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE21>(b));
}
#[derive(Deserialize)]
enum E22 {
    #[serde(rename = "deployer")] V0,
    #[serde(rename = "spec")] V1,
    #[serde(rename = "spots")] V2,
    #[serde(rename = "deploy_time")] V3,
    #[serde(rename = "deploy_gas_wei")] V4,
    #[serde(rename = "deploy_gas_token")] V5,
    #[serde(rename = "evm_contract")] V6,
    #[serde(rename = "full_name")] V7,
    #[serde(rename = "seeded_usdc")] V8,
    #[serde(rename = "non_circulating_users")] V9,
    #[serde(rename = "deployer_trading_fee_share")] V10,
    #[serde(rename = "frozen_users")] V11,
    #[serde(rename = "annotation")] V12,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE22 { A { x: E22 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE22 { A(E22), B(u64) }
#[inline(never)] fn run_22(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E22>(s));
    let _ = black_box(serde_json::from_slice::<E22>(b));
    let _ = black_box(rmp_serde::from_slice::<E22>(b));
    let _ = black_box(serde_json::from_slice::<TagE22>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE22>(b));
    let _ = black_box(serde_json::from_slice::<UntagE22>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE22>(b));
}
#[derive(Deserialize)]
enum E23 {
    #[serde(rename = "books")] V0,
    #[serde(rename = "funding_tracker")] V1,
    #[serde(rename = "twap_tracker")] V2,
    #[serde(rename = "perp_to_annotation")] V3,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE23 { A { x: E23 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE23 { A(E23), B(u64) }
#[inline(never)] fn run_23(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E23>(s));
    let _ = black_box(serde_json::from_slice::<E23>(b));
    let _ = black_box(rmp_serde::from_slice::<E23>(b));
    let _ = black_box(serde_json::from_slice::<TagE23>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE23>(b));
    let _ = black_box(serde_json::from_slice::<UntagE23>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE23>(b));
}
#[derive(Deserialize)]
enum E24 {
    #[serde(rename = "chainId")] V0,
    #[serde(rename = "address")] V1,
    #[serde(rename = "nonce")] V2,
    #[serde(rename = "yParity")] V3,
    #[serde(rename = "r")] V4,
    #[serde(rename = "s")] V5,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE24 { A { x: E24 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE24 { A(E24), B(u64) }
#[inline(never)] fn run_24(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E24>(s));
    let _ = black_box(serde_json::from_slice::<E24>(b));
    let _ = black_box(rmp_serde::from_slice::<E24>(b));
    let _ = black_box(serde_json::from_slice::<TagE24>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE24>(b));
    let _ = black_box(serde_json::from_slice::<UntagE24>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE24>(b));
}
#[derive(Deserialize)]
enum E25 {
    #[serde(rename = "maker_fraction_cutoff")] V0,
    #[serde(rename = "add")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE25 { A { x: E25 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE25 { A(E25), B(u64) }
#[inline(never)] fn run_25(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E25>(s));
    let _ = black_box(serde_json::from_slice::<E25>(b));
    let _ = black_box(rmp_serde::from_slice::<E25>(b));
    let _ = black_box(serde_json::from_slice::<TagE25>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE25>(b));
    let _ = black_box(serde_json::from_slice::<UntagE25>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE25>(b));
}
#[derive(Deserialize)]
enum E26 {
    #[serde(rename = "n")] V0,
    #[serde(rename = "name")] V1,
    #[serde(rename = "s")] V2,
    #[serde(rename = "sub_account_user")] V3,
    #[serde(rename = "m")] V4,
    #[serde(rename = "master")] V5,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE26 { A { x: E26 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE26 { A(E26), B(u64) }
#[inline(never)] fn run_26(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E26>(s));
    let _ = black_box(serde_json::from_slice::<E26>(b));
    let _ = black_box(rmp_serde::from_slice::<E26>(b));
    let _ = black_box(serde_json::from_slice::<TagE26>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE26>(b));
    let _ = black_box(serde_json::from_slice::<UntagE26>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE26>(b));
}
#[derive(Deserialize)]
enum E27 {
    #[serde(rename = "hv")] V0,
    #[serde(rename = "bh")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE27 { A { x: E27 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE27 { A(E27), B(u64) }
#[inline(never)] fn run_27(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E27>(s));
    let _ = black_box(serde_json::from_slice::<E27>(b));
    let _ = black_box(rmp_serde::from_slice::<E27>(b));
    let _ = black_box(serde_json::from_slice::<TagE27>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE27>(b));
    let _ = black_box(serde_json::from_slice::<UntagE27>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE27>(b));
}
#[derive(Deserialize)]
enum E28 {
    #[serde(rename = "n")] V0,
    #[serde(rename = "bh")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE28 { A { x: E28 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE28 { A(E28), B(u64) }
#[inline(never)] fn run_28(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E28>(s));
    let _ = black_box(serde_json::from_slice::<E28>(b));
    let _ = black_box(rmp_serde::from_slice::<E28>(b));
    let _ = black_box(serde_json::from_slice::<TagE28>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE28>(b));
    let _ = black_box(serde_json::from_slice::<UntagE28>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE28>(b));
}
#[derive(Deserialize)]
enum E29 {
    #[serde(rename = "hv")] V0,
    #[serde(rename = "bh")] V1,
    #[serde(rename = "ha")] V2,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE29 { A { x: E29 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE29 { A(E29), B(u64) }
#[inline(never)] fn run_29(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E29>(s));
    let _ = black_box(serde_json::from_slice::<E29>(b));
    let _ = black_box(rmp_serde::from_slice::<E29>(b));
    let _ = black_box(serde_json::from_slice::<TagE29>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE29>(b));
    let _ = black_box(serde_json::from_slice::<UntagE29>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE29>(b));
}
#[derive(Deserialize)]
enum E30 {
    #[serde(rename = "vts")] V0,
    #[serde(rename = "hf")] V1,
    #[serde(rename = "oqf")] V2,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE30 { A { x: E30 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE30 { A(E30), B(u64) }
#[inline(never)] fn run_30(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E30>(s));
    let _ = black_box(serde_json::from_slice::<E30>(b));
    let _ = black_box(rmp_serde::from_slice::<E30>(b));
    let _ = black_box(serde_json::from_slice::<TagE30>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE30>(b));
    let _ = black_box(serde_json::from_slice::<UntagE30>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE30>(b));
}
#[derive(Deserialize)]
enum E31 {
    #[serde(rename = "n")] V0,
    #[serde(rename = "name")] V1,
    #[serde(rename = "v")] V2,
    #[serde(rename = "validUntil")] V3,
    #[serde(rename = "a")] V4,
    #[serde(rename = "address")] V5,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE31 { A { x: E31 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE31 { A(E31), B(u64) }
#[inline(never)] fn run_31(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E31>(s));
    let _ = black_box(serde_json::from_slice::<E31>(b));
    let _ = black_box(rmp_serde::from_slice::<E31>(b));
    let _ = black_box(serde_json::from_slice::<TagE31>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE31>(b));
    let _ = black_box(serde_json::from_slice::<UntagE31>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE31>(b));
}
#[derive(Deserialize)]
enum E32 {
    #[serde(rename = "bridge-voter")] V0,
    #[serde(rename = "reference-oracle-publisher")] V1,
    #[serde(rename = "outcome-voter")] V2,
    #[serde(rename = "visor")] V3,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE32 { A { x: E32 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE32 { A(E32), B(u64) }
#[inline(never)] fn run_32(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E32>(s));
    let _ = black_box(serde_json::from_slice::<E32>(b));
    let _ = black_box(rmp_serde::from_slice::<E32>(b));
    let _ = black_box(serde_json::from_slice::<TagE32>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE32>(b));
    let _ = black_box(serde_json::from_slice::<UntagE32>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE32>(b));
}
#[derive(Deserialize)]
enum E33 {
    #[serde(rename = "s")] V0,
    #[serde(rename = "v")] V1,
    #[serde(rename = "code")] V2,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE33 { A { x: E33 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE33 { A(E33), B(u64) }
#[inline(never)] fn run_33(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E33>(s));
    let _ = black_box(serde_json::from_slice::<E33>(b));
    let _ = black_box(rmp_serde::from_slice::<E33>(b));
    let _ = black_box(serde_json::from_slice::<TagE33>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE33>(b));
    let _ = black_box(serde_json::from_slice::<UntagE33>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE33>(b));
}
#[derive(Deserialize)]
enum E34 {
    #[serde(rename = "szDecimals")] V0,
    #[serde(rename = "name")] V1,
    #[serde(rename = "marginTableId")] V2,
    #[serde(rename = "marginMode")] V3,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE34 { A { x: E34 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE34 { A(E34), B(u64) }
#[inline(never)] fn run_34(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E34>(s));
    let _ = black_box(serde_json::from_slice::<E34>(b));
    let _ = black_box(rmp_serde::from_slice::<E34>(b));
    let _ = black_box(serde_json::from_slice::<TagE34>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE34>(b));
    let _ = black_box(serde_json::from_slice::<UntagE34>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE34>(b));
}
#[derive(Deserialize)]
enum E35 {
    #[serde(rename = "variant")] V0,
    #[serde(rename = "user")] V1,
    #[serde(rename = "allowed")] V2,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE35 { A { x: E35 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE35 { A(E35), B(u64) }
#[inline(never)] fn run_35(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E35>(s));
    let _ = black_box(serde_json::from_slice::<E35>(b));
    let _ = black_box(rmp_serde::from_slice::<E35>(b));
    let _ = black_box(serde_json::from_slice::<TagE35>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE35>(b));
    let _ = black_box(serde_json::from_slice::<UntagE35>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE35>(b));
}
#[derive(Deserialize)]
enum E36 {
    #[serde(rename = "r")] V0,
    #[serde(rename = "b")] V1,
    #[serde(rename = "t")] V2,
    #[serde(rename = "s")] V3,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE36 { A { x: E36 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE36 { A(E36), B(u64) }
#[inline(never)] fn run_36(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E36>(s));
    let _ = black_box(serde_json::from_slice::<E36>(b));
    let _ = black_box(rmp_serde::from_slice::<E36>(b));
    let _ = black_box(serde_json::from_slice::<TagE36>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE36>(b));
    let _ = black_box(serde_json::from_slice::<UntagE36>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE36>(b));
}
#[derive(Deserialize)]
enum E37 {
    #[serde(rename = "l1")] V0,
    #[serde(rename = "begin_block")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE37 { A { x: E37 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE37 { A(E37), B(u64) }
#[inline(never)] fn run_37(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E37>(s));
    let _ = black_box(serde_json::from_slice::<E37>(b));
    let _ = black_box(rmp_serde::from_slice::<E37>(b));
    let _ = black_box(serde_json::from_slice::<TagE37>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE37>(b));
    let _ = black_box(serde_json::from_slice::<UntagE37>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE37>(b));
}
#[derive(Deserialize)]
enum E38 {
    #[serde(rename = "l")] V0,
    #[serde(rename = "last_update_time")] V1,
    #[serde(rename = "c")] V2,
    #[serde(rename = "category")] V3,
    #[serde(rename = "d")] V4,
    #[serde(rename = "description")] V5,
    #[serde(rename = "display_name")] V6,
    #[serde(rename = "n")] V7,
    #[serde(rename = "k")] V8,
    #[serde(rename = "keywords")] V9,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE38 { A { x: E38 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE38 { A(E38), B(u64) }
#[inline(never)] fn run_38(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E38>(s));
    let _ = black_box(serde_json::from_slice::<E38>(b));
    let _ = black_box(rmp_serde::from_slice::<E38>(b));
    let _ = black_box(serde_json::from_slice::<TagE38>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE38>(b));
    let _ = black_box(serde_json::from_slice::<UntagE38>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE38>(b));
}
#[derive(Deserialize)]
enum E39 {
    #[serde(rename = "r")] V0,
    #[serde(rename = "s")] V1,
    #[serde(rename = "v")] V2,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE39 { A { x: E39 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE39 { A(E39), B(u64) }
#[inline(never)] fn run_39(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E39>(s));
    let _ = black_box(serde_json::from_slice::<E39>(b));
    let _ = black_box(rmp_serde::from_slice::<E39>(b));
    let _ = black_box(serde_json::from_slice::<TagE39>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE39>(b));
    let _ = black_box(serde_json::from_slice::<UntagE39>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE39>(b));
}
#[derive(Deserialize)]
enum E40 {
    #[serde(rename = "b")] V0,
    #[serde(rename = "n")] V1,
    #[serde(rename = "e")] V2,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE40 { A { x: E40 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE40 { A(E40), B(u64) }
#[inline(never)] fn run_40(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E40>(s));
    let _ = black_box(serde_json::from_slice::<E40>(b));
    let _ = black_box(rmp_serde::from_slice::<E40>(b));
    let _ = black_box(serde_json::from_slice::<TagE40>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE40>(b));
    let _ = black_box(serde_json::from_slice::<UntagE40>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE40>(b));
}
#[derive(Deserialize)]
enum E41 {
    #[serde(rename = "UserRole")] V0,
    #[serde(rename = "missing")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE41 { A { x: E41 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE41 { A(E41), B(u64) }
#[inline(never)] fn run_41(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E41>(s));
    let _ = black_box(serde_json::from_slice::<E41>(b));
    let _ = black_box(rmp_serde::from_slice::<E41>(b));
    let _ = black_box(serde_json::from_slice::<TagE41>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE41>(b));
    let _ = black_box(serde_json::from_slice::<UntagE41>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE41>(b));
}
#[derive(Deserialize)]
enum E42 {
    #[serde(rename = "UserRole")] V0,
    #[serde(rename = "subAccount")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE42 { A { x: E42 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE42 { A(E42), B(u64) }
#[inline(never)] fn run_42(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E42>(s));
    let _ = black_box(serde_json::from_slice::<E42>(b));
    let _ = black_box(rmp_serde::from_slice::<E42>(b));
    let _ = black_box(serde_json::from_slice::<TagE42>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE42>(b));
    let _ = black_box(serde_json::from_slice::<UntagE42>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE42>(b));
}
#[derive(Deserialize)]
enum E43 {
    #[serde(rename = "UserRole")] V0,
    #[serde(rename = "agent")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE43 { A { x: E43 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE43 { A(E43), B(u64) }
#[inline(never)] fn run_43(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E43>(s));
    let _ = black_box(serde_json::from_slice::<E43>(b));
    let _ = black_box(rmp_serde::from_slice::<E43>(b));
    let _ = black_box(serde_json::from_slice::<TagE43>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE43>(b));
    let _ = black_box(serde_json::from_slice::<UntagE43>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE43>(b));
}
#[derive(Deserialize)]
enum E44 {
    #[serde(rename = "UserRole")] V0,
    #[serde(rename = "vault")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE44 { A { x: E44 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE44 { A(E44), B(u64) }
#[inline(never)] fn run_44(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E44>(s));
    let _ = black_box(serde_json::from_slice::<E44>(b));
    let _ = black_box(rmp_serde::from_slice::<E44>(b));
    let _ = black_box(serde_json::from_slice::<TagE44>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE44>(b));
    let _ = black_box(serde_json::from_slice::<UntagE44>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE44>(b));
}
#[derive(Deserialize)]
enum E45 {
    #[serde(rename = "UserRole")] V0,
    #[serde(rename = "user")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE45 { A { x: E45 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE45 { A(E45), B(u64) }
#[inline(never)] fn run_45(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E45>(s));
    let _ = black_box(serde_json::from_slice::<E45>(b));
    let _ = black_box(rmp_serde::from_slice::<E45>(b));
    let _ = black_box(serde_json::from_slice::<TagE45>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE45>(b));
    let _ = black_box(serde_json::from_slice::<UntagE45>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE45>(b));
}
#[derive(Deserialize)]
enum E46 {
    #[serde(rename = "destination_recipient")] V0,
    #[serde(rename = "destination_chain_id")] V1,
    #[serde(rename = "gas_limit")] V2,
    #[serde(rename = "nonce")] V3,
    #[serde(rename = "data")] V4,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE46 { A { x: E46 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE46 { A(E46), B(u64) }
#[inline(never)] fn run_46(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E46>(s));
    let _ = black_box(serde_json::from_slice::<E46>(b));
    let _ = black_box(rmp_serde::from_slice::<E46>(b));
    let _ = black_box(serde_json::from_slice::<TagE46>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE46>(b));
    let _ = black_box(serde_json::from_slice::<UntagE46>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE46>(b));
}
#[derive(Deserialize)]
enum E47 {
    #[serde(rename = "min_rate")] V0,
    #[serde(rename = "max_rate")] V1,
    #[serde(rename = "kink_rate")] V2,
    #[serde(rename = "kink_utilization")] V3,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE47 { A { x: E47 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE47 { A(E47), B(u64) }
#[inline(never)] fn run_47(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E47>(s));
    let _ = black_box(serde_json::from_slice::<E47>(b));
    let _ = black_box(rmp_serde::from_slice::<E47>(b));
    let _ = black_box(serde_json::from_slice::<TagE47>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE47>(b));
    let _ = black_box(serde_json::from_slice::<UntagE47>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE47>(b));
}
#[derive(Deserialize)]
enum E48 {
    #[serde(rename = "normal")] V0,
    #[serde(rename = "noCross")] V1,
    #[serde(rename = "strictIsolated")] V2,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE48 { A { x: E48 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE48 { A(E48), B(u64) }
#[inline(never)] fn run_48(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E48>(s));
    let _ = black_box(serde_json::from_slice::<E48>(b));
    let _ = black_box(rmp_serde::from_slice::<E48>(b));
    let _ = black_box(serde_json::from_slice::<TagE48>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE48>(b));
    let _ = black_box(serde_json::from_slice::<UntagE48>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE48>(b));
}
#[derive(Deserialize)]
enum E49 {
    #[serde(rename = "B")] V0,
    #[serde(rename = "Bid")] V1,
    #[serde(rename = "A")] V2,
    #[serde(rename = "Ask")] V3,
    #[serde(rename = "Ip")] V4,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE49 { A { x: E49 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE49 { A(E49), B(u64) }
#[inline(never)] fn run_49(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E49>(s));
    let _ = black_box(serde_json::from_slice::<E49>(b));
    let _ = black_box(rmp_serde::from_slice::<E49>(b));
    let _ = black_box(serde_json::from_slice::<TagE49>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE49>(b));
    let _ = black_box(serde_json::from_slice::<UntagE49>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE49>(b));
}
#[derive(Deserialize)]
enum E50 {
    #[serde(rename = "B")] V0,
    #[serde(rename = "Bid")] V1,
    #[serde(rename = "A")] V2,
    #[serde(rename = "Ask")] V3,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE50 { A { x: E50 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE50 { A(E50), B(u64) }
#[inline(never)] fn run_50(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E50>(s));
    let _ = black_box(serde_json::from_slice::<E50>(b));
    let _ = black_box(rmp_serde::from_slice::<E50>(b));
    let _ = black_box(serde_json::from_slice::<TagE50>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE50>(b));
    let _ = black_box(serde_json::from_slice::<UntagE50>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE50>(b));
}
#[derive(Deserialize)]
enum E51 {
    #[serde(rename = "index")] V0,
    #[serde(rename = "validatorIndex")] V1,
    #[serde(rename = "address")] V2,
    #[serde(rename = "amount")] V3,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE51 { A { x: E51 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE51 { A(E51), B(u64) }
#[inline(never)] fn run_51(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E51>(s));
    let _ = black_box(serde_json::from_slice::<E51>(b));
    let _ = black_box(rmp_serde::from_slice::<E51>(b));
    let _ = black_box(serde_json::from_slice::<TagE51>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE51>(b));
    let _ = black_box(serde_json::from_slice::<UntagE51>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE51>(b));
}
#[derive(Deserialize)]
enum E52 {
    #[serde(rename = "na")] V0,
    #[serde(rename = "normalTpsl")] V1,
    #[serde(rename = "positionTpsl")] V2,
    #[serde(rename = "p")] V3,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE52 { A { x: E52 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE52 { A(E52), B(u64) }
#[inline(never)] fn run_52(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E52>(s));
    let _ = black_box(serde_json::from_slice::<E52>(b));
    let _ = black_box(rmp_serde::from_slice::<E52>(b));
    let _ = black_box(serde_json::from_slice::<TagE52>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE52>(b));
    let _ = black_box(serde_json::from_slice::<UntagE52>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE52>(b));
}
#[derive(Deserialize)]
enum E53 {
    #[serde(rename = "wei")] V0,
    #[serde(rename = "user")] V1,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE53 { A { x: E53 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE53 { A(E53), B(u64) }
#[inline(never)] fn run_53(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E53>(s));
    let _ = black_box(serde_json::from_slice::<E53>(b));
    let _ = black_box(rmp_serde::from_slice::<E53>(b));
    let _ = black_box(serde_json::from_slice::<TagE53>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE53>(b));
    let _ = black_box(serde_json::from_slice::<UntagE53>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE53>(b));
}
#[derive(Deserialize)]
enum E54 {
    #[serde(rename = "lower_bound")] V0,
    #[serde(rename = "max_leverage")] V1,
    #[serde(rename = "maintenance_deduction")] V2,
}
#[derive(Deserialize)] #[serde(tag = "type")] enum TagE54 { A { x: E54 } }
#[derive(Deserialize)] #[serde(untagged)] enum UntagE54 { A(E54), B(u64) }
#[inline(never)] fn run_54(s: &str, b: &[u8]) {
    let _ = black_box(serde_json::from_str::<E54>(s));
    let _ = black_box(serde_json::from_slice::<E54>(b));
    let _ = black_box(rmp_serde::from_slice::<E54>(b));
    let _ = black_box(serde_json::from_slice::<TagE54>(b));
    let _ = black_box(rmp_serde::from_slice::<TagE54>(b));
    let _ = black_box(serde_json::from_slice::<UntagE54>(b));
    let _ = black_box(rmp_serde::from_slice::<UntagE54>(b));
}
fn main() {
    let s = std::env::args().nth(1).unwrap_or_default();
    let b = s.as_bytes();
    run_0(&s, b);
    run_1(&s, b);
    run_2(&s, b);
    run_3(&s, b);
    run_4(&s, b);
    run_5(&s, b);
    run_6(&s, b);
    run_7(&s, b);
    run_8(&s, b);
    run_9(&s, b);
    run_10(&s, b);
    run_11(&s, b);
    run_12(&s, b);
    run_13(&s, b);
    run_14(&s, b);
    run_15(&s, b);
    run_16(&s, b);
    run_17(&s, b);
    run_18(&s, b);
    run_19(&s, b);
    run_20(&s, b);
    run_21(&s, b);
    run_22(&s, b);
    run_23(&s, b);
    run_24(&s, b);
    run_25(&s, b);
    run_26(&s, b);
    run_27(&s, b);
    run_28(&s, b);
    run_29(&s, b);
    run_30(&s, b);
    run_31(&s, b);
    run_32(&s, b);
    run_33(&s, b);
    run_34(&s, b);
    run_35(&s, b);
    run_36(&s, b);
    run_37(&s, b);
    run_38(&s, b);
    run_39(&s, b);
    run_40(&s, b);
    run_41(&s, b);
    run_42(&s, b);
    run_43(&s, b);
    run_44(&s, b);
    run_45(&s, b);
    run_46(&s, b);
    run_47(&s, b);
    run_48(&s, b);
    run_49(&s, b);
    run_50(&s, b);
    run_51(&s, b);
    run_52(&s, b);
    run_53(&s, b);
    run_54(&s, b);
}
