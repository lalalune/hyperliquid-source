#![forbid(unsafe_code)]
#![allow(dead_code, non_camel_case_types, non_snake_case)]
use serde::Deserialize;
use core::hint::black_box;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Deserialize)]
enum E0 {
    #[serde(rename = "s")] V0,
    #[serde(rename = "t")] V1,
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
    #[serde(rename = "token")] V0,
    #[serde(rename = "technicalStaker")] V1,
    #[serde(rename = "treasuryStaker")] V2,
    #[serde(rename = "treasuryEvmAddress")] V3,
    #[serde(rename = "evmRebalanceContract")] V4,
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
    #[serde(rename = "i")] V0,
    #[serde(rename = "sh")] V1,
    #[serde(rename = "eh")] V2,
    #[serde(rename = "rc")] V3,
    #[serde(rename = "sl")] V4,
    #[serde(rename = "el")] V5,
    #[serde(rename = "nf")] V6,
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
    #[serde(rename = "amount")] V1,
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
    #[serde(rename = "e")] V0,
    #[serde(rename = "n")] V1,
    #[serde(rename = "t")] V2,
    #[serde(rename = "m")] V3,
    #[serde(rename = "wei")] V4,
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
    #[serde(rename = "dateTime")] V0,
    #[serde(rename = "date")] V1,
    #[serde(rename = "string")] V2,
    #[serde(rename = "shortString")] V3,
    #[serde(rename = "hlPerp")] V4,
    #[serde(rename = "uInt")] V5,
    #[serde(rename = "uDecimal")] V6,
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
    #[serde(rename = "v")] V0,
    #[serde(rename = "o")] V1,
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
    #[serde(rename = "VaultRelationship")] V0,
    #[serde(rename = "child")] V1,
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
    #[serde(rename = "VaultRelationship")] V0,
    #[serde(rename = "normal")] V1,
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
    #[serde(rename = "VaultRelationship")] V0,
    #[serde(rename = "parent")] V1,
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
    #[serde(rename = "optOut")] V0,
    #[serde(rename = "toggleSpotDusting")] V1,
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
    #[serde(rename = "Requested")] V0,
    #[serde(rename = "TradingUser")] V1,
    #[serde(rename = "StakingUser")] V2,
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
    #[serde(rename = "c")] V0,
    #[serde(rename = "core")] V1,
    #[serde(rename = "t")] V2,
    #[serde(rename = "trigger")] V3,
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
    #[serde(rename = "b")] V1,
    #[serde(rename = "c")] V2,
    #[serde(rename = "r")] V3,
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
    #[serde(rename = "i")] V0,
    #[serde(rename = "a")] V1,
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
    #[serde(rename = "p")] V0,
    #[serde(rename = "prev_key")] V1,
    #[serde(rename = "n")] V2,
    #[serde(rename = "next_key")] V3,
    #[serde(rename = "i")] V4,
    #[serde(rename = "is_position_tpsl")] V5,
    #[serde(rename = "r")] V6,
    #[serde(rename = "resting_sz")] V7,
    #[serde(rename = "O")] V8,
    #[serde(rename = "orig_sz")] V9,
    #[serde(rename = "P")] V10,
    #[serde(rename = "priority_rate")] V11,
    #[serde(rename = "u")] V12,
    #[serde(rename = "user")] V13,
    #[serde(rename = "t")] V14,
    #[serde(rename = "tif")] V15,
    #[serde(rename = "c")] V16,
    #[serde(rename = "core")] V17,
    #[serde(rename = "o")] V18,
    #[serde(rename = "oid")] V19,
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
    #[serde(rename = "D")] V0,
    #[serde(rename = "E")] V1,
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
    #[serde(rename = "token")] V0,
    #[serde(rename = "user")] V1,
    #[serde(rename = "freeze")] V2,
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
    #[serde(rename = "token")] V0,
    #[serde(rename = "share")] V1,
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
    #[serde(rename = "token")] V0,
    #[serde(rename = "userAndWei")] V1,
    #[serde(rename = "existingTokenAndWei")] V2,
    #[serde(rename = "blacklistUsers")] V3,
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
    #[serde(rename = "token")] V0,
    #[serde(rename = "maxSupply")] V1,
    #[serde(rename = "noHyperliquidity")] V2,
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
    #[serde(rename = "token")] V0,
    #[serde(rename = "fullName")] V1,
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
    #[serde(rename = "spec")] V0,
    #[serde(rename = "maxGas")] V1,
    #[serde(rename = "fullName")] V2,
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
    #[serde(rename = "spot")] V0,
    #[serde(rename = "startPx")] V1,
    #[serde(rename = "orderSz")] V2,
    #[serde(rename = "nOrders")] V3,
    #[serde(rename = "nSeededLevels")] V4,
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
    #[serde(rename = "token")] V0,
    #[serde(rename = "address")] V1,
    #[serde(rename = "evmExtraWeiDecimals")] V2,
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
    #[serde(rename = "token")] V0,
    #[serde(rename = "annotation")] V1,
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
    #[serde(rename = "registerAndAssociateNamedOutcomeFromTemplate")] V0,
    #[serde(rename = "registerQuestionFromTemplate")] V1,
    #[serde(rename = "registerStandaloneOutcomeFromTemplate")] V2,
    #[serde(rename = "settleOutcome")] V3,
    #[serde(rename = "settleQuestion")] V4,
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
    #[serde(rename = "Enabled")] V0,
    #[serde(rename = "Disabled")] V1,
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
    #[serde(rename = "chainId")] V0,
    #[serde(rename = "nonce")] V1,
    #[serde(rename = "gasPrice")] V2,
    #[serde(rename = "gas")] V3,
    #[serde(rename = "gasLimit")] V4,
    #[serde(rename = "to")] V5,
    #[serde(rename = "value")] V6,
    #[serde(rename = "input")] V7,
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
    #[serde(rename = "chainId")] V0,
    #[serde(rename = "nonce")] V1,
    #[serde(rename = "gas")] V2,
    #[serde(rename = "gasLimit")] V3,
    #[serde(rename = "maxFeePerGas")] V4,
    #[serde(rename = "maxPriorityFeePerGas")] V5,
    #[serde(rename = "to")] V6,
    #[serde(rename = "value")] V7,
    #[serde(rename = "accessList")] V8,
    #[serde(rename = "authorizationList")] V9,
    #[serde(rename = "input")] V10,
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
    #[serde(rename = "chainId")] V0,
    #[serde(rename = "nonce")] V1,
    #[serde(rename = "gas")] V2,
    #[serde(rename = "gasLimit")] V3,
    #[serde(rename = "maxFeePerGas")] V4,
    #[serde(rename = "maxPriorityFeePerGas")] V5,
    #[serde(rename = "to")] V6,
    #[serde(rename = "value")] V7,
    #[serde(rename = "accessList")] V8,
    #[serde(rename = "input")] V9,
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
    #[serde(rename = "chainId")] V0,
    #[serde(rename = "nonce")] V1,
    #[serde(rename = "gas")] V2,
    #[serde(rename = "gasLimit")] V3,
    #[serde(rename = "maxFeePerGas")] V4,
    #[serde(rename = "maxPriorityFeePerGas")] V5,
    #[serde(rename = "to")] V6,
    #[serde(rename = "value")] V7,
    #[serde(rename = "accessList")] V8,
    #[serde(rename = "blobVersionedHashes")] V9,
    #[serde(rename = "maxFeePerBlobGas")] V10,
    #[serde(rename = "input")] V11,
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
    #[serde(rename = "chainId")] V0,
    #[serde(rename = "nonce")] V1,
    #[serde(rename = "gasPrice")] V2,
    #[serde(rename = "gas")] V3,
    #[serde(rename = "gasLimit")] V4,
    #[serde(rename = "to")] V5,
    #[serde(rename = "value")] V6,
    #[serde(rename = "accessList")] V7,
    #[serde(rename = "input")] V8,
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
    #[serde(rename = "halfs")] V0,
    #[serde(rename = "oid_to_key")] V1,
    #[serde(rename = "cloid_tracker")] V2,
    #[serde(rename = "bod")] V3,
    #[serde(rename = "asset")] V4,
    #[serde(rename = "user_states")] V5,
    #[serde(rename = "last_trade_px")] V6,
    #[serde(rename = "total_sz")] V7,
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
    #[serde(rename = "e")] V0,
    #[serde(rename = "a")] V1,
    #[serde(rename = "d")] V2,
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
    #[serde(rename = "D")] V0,
    #[serde(rename = "U")] V1,
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
    #[serde(rename = "header")] V0,
    #[serde(rename = "body")] V1,
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
    #[serde(rename = "node_ip")] V0,
    #[serde(rename = "name")] V1,
    #[serde(rename = "description")] V2,
    #[serde(rename = "unjailed")] V3,
    #[serde(rename = "disable_delegations")] V4,
    #[serde(rename = "commission_bps")] V5,
    #[serde(rename = "signer")] V6,
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
    #[serde(rename = "Spot")] V0,
    #[serde(rename = "Mark")] V1,
    #[serde(rename = "ExternalPerp")] V2,
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
    #[serde(rename = "Evm")] V0,
    #[serde(rename = "Broadcaster")] V1,
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
    #[serde(rename = "hyperliquid_index")] V0,
    #[serde(rename = "c")] V1,
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
    #[serde(rename = "a")] V0,
    #[serde(rename = "asset")] V1,
    #[serde(rename = "b")] V2,
    #[serde(rename = "isBuy")] V3,
    #[serde(rename = "s")] V4,
    #[serde(rename = "sz")] V5,
    #[serde(rename = "r")] V6,
    #[serde(rename = "reduceOnly")] V7,
    #[serde(rename = "m")] V8,
    #[serde(rename = "minutes")] V9,
    #[serde(rename = "randomize")] V10,
    #[serde(rename = "t")] V11,
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
    #[serde(rename = "StandaloneOutcome")] V0,
    #[serde(rename = "Question")] V1,
    #[serde(rename = "QuestionOutcome")] V2,
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
    #[serde(rename = "standaloneOutcome")] V0,
    #[serde(rename = "question")] V1,
    #[serde(rename = "questionOutcome")] V2,
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
    #[serde(rename = "C")] V0,
    #[serde(rename = "Cross")] V1,
    #[serde(rename = "I")] V2,
    #[serde(rename = "Isolated")] V3,
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
    #[serde(rename = "FReferrerState")] V0,
    #[serde(rename = "needToCreateCode")] V1,
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
    #[serde(rename = "FReferrerState")] V0,
    #[serde(rename = "needToTrade")] V1,
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
    #[serde(rename = "FReferrerState")] V0,
    #[serde(rename = "ready")] V1,
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
    #[serde(rename = "asset_to_recent_oi")] V0,
    #[serde(rename = "override_max_oi_per_second")] V1,
    #[serde(rename = "reset_recent_oi_bucket_guard")] V2,
    #[serde(rename = "assets_at_open_interest_cap")] V3,
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
    #[serde(rename = "limits")] V0,
    #[serde(rename = "schema")] V1,
    #[serde(rename = "state")] V2,
    #[serde(rename = "hip3_backstop_liquidator_state")] V3,
    #[serde(rename = "ss")] V4,
    #[serde(rename = "df")] V5,
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
    #[serde(rename = "yes")] V0,
    #[serde(rename = "no")] V1,
    #[serde(rename = "abstain")] V2,
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
    #[serde(rename = "enabled")] V0,
    #[serde(rename = "disabled")] V1,
    #[serde(rename = "blocked")] V2,
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
    #[serde(rename = "node_ip")] V0,
    #[serde(rename = "name")] V1,
    #[serde(rename = "description")] V2,
    #[serde(rename = "unjailed")] V3,
    #[serde(rename = "disable_delegations")] V4,
    #[serde(rename = "commission_bps")] V5,
    #[serde(rename = "signer")] V6,
    #[serde(rename = "data")] V7,
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
    #[serde(rename = "Oracle")] V0,
    #[serde(rename = "ReferenceOracle")] V1,
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
    #[serde(rename = "Ok")] V0,
    #[serde(rename = "OutOfGas")] V1,
    #[serde(rename = "Error")] V2,
    #[serde(rename = "UnexpectedError")] V3,
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
