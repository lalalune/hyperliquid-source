#![forbid(unsafe_code)]
#![allow(dead_code, non_camel_case_types)]
use serde::ser::SerializeStruct;
use std::io::BufWriter;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Debug)]
struct O8<const N: usize>([u64; N]);
impl<const N: usize> serde::Serialize for O8<N> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.0[0])
    }
}
#[derive(Debug)]
struct O4<const N: usize>([u32; N]);
impl<const N: usize> serde::Serialize for O4<N> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.0[0] as u64)
    }
}

#[derive(serde::Serialize, Debug)]
struct SerStructFam0 {
    #[serde(rename = "usdtUsdcPx")] f0: String,
    #[serde(rename = "nativePx")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam1 {
    #[serde(rename = "scale")] f0: String,
    #[serde(rename = "growthMode")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam2 {
    #[serde(rename = "height")] f0: u64,
    #[serde(rename = "tx_index")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam3 {
    #[serde(rename = "vip")] f0: String,
    #[serde(rename = "mm")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam4 {
    #[serde(rename = "lowerBound")] f0: u64,
    #[serde(rename = "maxLeverage")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam5 {
    #[serde(rename = "maker_fraction_cutoff")] f0: u64,
    #[serde(rename = "add")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam6 {
    #[serde(rename = "last_bucket")] f0: u32,
    #[serde(rename = "bucket_millis")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam7 {
    #[serde(rename = "order_sz")] f0: u32,
    #[serde(rename = "points")] f1: String,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam8 {
    #[serde(rename = "profiles")] f0: String,
    #[serde(rename = "epoch")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam9 {
    #[serde(rename = "version")] f0: u64,
    #[serde(rename = "round")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam10 {
    #[serde(rename = "id")] f0: String,
    #[serde(rename = "keywordToValue")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam11 {
    #[serde(rename = "min_rate")] f0: String,
    #[serde(rename = "max_rate")] f1: String,
    #[serde(rename = "kink_rate")] f2: String,
    #[serde(rename = "kink_utilization")] f3: String,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam12 {
    #[serde(rename = "lower_bound")] f0: u64,
    #[serde(rename = "max_leverage")] f1: u32,
    #[serde(rename = "maintenance_deduction")] f2: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam13 {
    #[serde(rename = "description")] f0: String,
    #[serde(rename = "marginTiers")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam14 {
    #[serde(rename = "oid")] f0: String,
    #[serde(rename = "order")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam15 {
    #[serde(rename = "borrow")] f0: String,
    #[serde(rename = "supply")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam16 {
    #[serde(rename = "authorizedUsers")] f0: String,
    #[serde(rename = "threshold")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam17 {
    #[serde(rename = "address")] f0: u32,
    #[serde(rename = "name")] f1: String,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam18 {
    #[serde(rename = "vks")] f0: [u64; 4],
    #[serde(rename = "hvs")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam19 {
    #[serde(rename = "name")] f0: String,
    #[serde(rename = "szDecimals")] f1: u8,
    #[serde(rename = "weiDecimals")] f2: u8,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam20 {
    #[serde(rename = "R_bytes")] f0: [u64; 4],
    #[serde(rename = "s_bytes")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam21 {
    #[serde(rename = "id")] f0: [u64; 3],
    #[serde(rename = "keywordToValue")] f1: u32,
    #[serde(rename = "deployerFeeScale")] f2: [u64; 3],
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam22 {
    #[serde(rename = "address_to_txs")] f0: [u64; 4],
    #[serde(rename = "len")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam23 {
    #[serde(rename = "queue")] f0: [u64; 4],
    #[serde(rename = "user_to_total_withdrawal")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam24 {
    #[serde(rename = "vas")] f0: [u64; 4],
    #[serde(rename = "qsf")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam25 {
    #[serde(rename = "ntl_cutoff")] f0: u64,
    #[serde(rename = "rates")] f1: [u128; 2],
    #[serde(rename = "staking_keep_frac_for_referrer")] f2: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam26 {
    #[serde(rename = "initial_round")] f0: u32,
    #[serde(rename = "round_to_val")] f1: [u64; 4],
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam27 {
    #[serde(rename = "mptc")] f0: u64,
    #[serde(rename = "ptc")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam28 {
    #[serde(rename = "user_to_delegations")] f0: [u64; 4],
    #[serde(rename = "validator_to_state")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam29 {
    #[serde(rename = "total_delegated")] f0: u32,
    #[serde(rename = "delegator_to_epoch_delegation")] f1: [u64; 4],
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam30 {
    #[serde(rename = "variant")] f0: u8,
    #[serde(rename = "user")] f1: [u8; 20],
    #[serde(rename = "allowed")] f2: bool,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam31 {
    #[serde(rename = "name")] f0: [u64; 3],
    #[serde(rename = "address")] f1: u32,
    #[serde(rename = "validUntil")] f2: [u128; 1],
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam32 {
    #[serde(rename = "wei")] f0: u64,
    #[serde(rename = "n")] f1: u64,
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam33 {
    a: O8<3>,
    b: O8<4>,
    c: u64,
}
impl serde::Serialize for SerStructFam33 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam33", 3)?;
        st.serialize_field("name", &self.a)?;
        st.serialize_field("hsc", &self.c)?;
        st.serialize_field("i", &self.b)?;
        st.end()
    }
}
#[repr(C)]
#[derive(serde::Serialize, Debug)]
struct SerStructFam34 {
    #[serde(rename = "running_heap")] f0: [u64; 3],
    #[serde(rename = "user_to_id_to_state")] f1: [u64; 4],
    #[serde(rename = "user_to_id_to_waiting")] f2: u64,
}
#[repr(C)]
#[derive(serde::Serialize, Debug)]
struct SerStructFam35 {
    #[serde(rename = "max_n_validators")] f0: [u64; 2],
    #[serde(rename = "validator_to_stake")] f1: [u64; 4],
    #[serde(rename = "hv")] f2: u64,
}
#[repr(C)]
#[derive(serde::Serialize, Debug)]
struct SerStructFam36 {
    #[serde(rename = "evm_db")] f0: O8<868>,
    #[serde(rename = "block_hashes")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam37 {
    #[serde(rename = "quoteToken")] f0: u16,
    #[serde(rename = "nameAndDescription")] f1: O8<6>,
    #[serde(rename = "sideNames")] f2: O4<12>,
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam38 {
    a: u64,
    b: O8<8>,
    c: u64,
}
impl serde::Serialize for SerStructFam38 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam38", 3)?;
        st.serialize_field("user", &self.c)?;
        st.serialize_field("usd", &self.a)?;
        st.serialize_field("ethId", &self.b)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam39 {
    a: u64,
    b: u64,
    c: u64,
}
impl serde::Serialize for SerStructFam39 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam39", 3)?;
        st.serialize_field("height", &self.b)?;
        st.serialize_field("abci_digest", &self.c)?;
        st.serialize_field("exchange_abci_hash", &self.a)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam40 {
    a: O8<3>,
    b: u64,
    c: u64,
}
impl serde::Serialize for SerStructFam40 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam40", 3)?;
        st.serialize_field("operation", &self.c)?;
        st.serialize_field("token", &self.b)?;
        st.serialize_field("amount", &self.a)?;
        st.end()
    }
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam41 {
    #[serde(rename = "multiSigUser")] f0: [u32; 5],
    #[serde(rename = "outerSigner")] f1: u16,
    #[serde(rename = "action")] f2: u64,
}
#[repr(C)]
#[derive(serde::Serialize, Debug)]
struct SerStructFam42 {
    #[serde(rename = "user_to_sub_accounts")] f0: O8<9>,
    #[serde(rename = "sub_account_to_master")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam43 {
    #[serde(rename = "px")] f0: u64,
    #[serde(rename = "above")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam44 {
    #[serde(rename = "after_round")] f0: u32,
    #[serde(rename = "until_block_hash")] f1: [u64; 4],
}
#[repr(C)]
#[derive(serde::Serialize, Debug)]
struct SerStructFam45 {
    #[serde(rename = "err_duration")] f0: O8<1>,
    #[serde(rename = "first_err_time")] f1: O4<3>,
    #[serde(rename = "last_err_time")] f2: O4<1>,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam46 {
    #[serde(rename = "time")] f0: u32,
    #[serde(rename = "n")] f1: u64,
    #[serde(rename = "delta")] f2: u64,
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam47 {
    a: O8<2>,
    b: O8<4>,
    c: u64,
}
impl serde::Serialize for SerStructFam47 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam47", 3)?;
        st.serialize_field("since_last_success", &self.c)?;
        st.serialize_field("last_ack_duration", &self.a)?;
        st.serialize_field("reported_horizon_status", &self.b)?;
        st.end()
    }
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam48 {
    #[serde(rename = "validator")] f0: u32,
    #[serde(rename = "amount")] f1: u64,
    #[serde(rename = "lockedUntilTimestamp")] f2: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam49 {
    #[serde(rename = "id")] f0: [u64; 4],
    #[serde(rename = "choice")] f1: u16,
    #[serde(rename = "amount")] f2: [u32; 2],
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam50 {
    #[serde(rename = "vaultAddress")] f0: u32,
    #[serde(rename = "equity")] f1: u64,
    #[serde(rename = "lockedUntilTimestamp")] f2: u64,
}
#[repr(C)]
#[derive(serde::Serialize, Debug)]
struct SerStructFam51 {
    #[serde(rename = "coin")] f0: [u64; 3],
    #[serde(rename = "token")] f1: u64,
    #[serde(rename = "total")] f2: u64,
}
#[repr(C)]
#[derive(serde::Serialize, Debug)]
struct SerStructFam52 {
    #[serde(rename = "question")] f0: [u64; 2],
    #[serde(rename = "name")] f1: [u64; 3],
    #[serde(rename = "description")] f2: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam53 {
    #[serde(rename = "px")] f0: u64,
    #[serde(rename = "last_update_time")] f1: u32,
    #[serde(rename = "daily_px")] f2: u64,
}
#[repr(C)]
#[derive(serde::Serialize, Debug)]
struct SerStructFam54 {
    #[serde(rename = "coin_to_mark_px")] f0: [u64; 4],
    #[serde(rename = "coin_to_oracle_px")] f1: [u64; 4],
    #[serde(rename = "coin_to_external_perp_px")] f2: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam55 {
    #[serde(rename = "signed_actions")] f0: [u64; 3],
    #[serde(rename = "broadcaster")] f1: u16,
    #[serde(rename = "broadcaster_nonce")] f2: [u32; 2],
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam56 {
    #[serde(rename = "time")] f0: u32,
    #[serde(rename = "round")] f1: u64,
    #[serde(rename = "latency")] f2: u64,
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam57 {
    a: O8<2>,
    b: O8<4>,
    c: u64,
}
impl serde::Serialize for SerStructFam57 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam57", 3)?;
        st.serialize_field("tokenToState", &self.b)?;
        st.serialize_field("health", &self.c)?;
        st.serialize_field("healthFactor", &self.a)?;
        st.end()
    }
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam58 {
    #[serde(rename = "validator_to_stake")] f0: [u64; 4],
    #[serde(rename = "hard_validators")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam59 {
    #[serde(rename = "horizon_margin")] f0: u64,
    #[serde(rename = "n_queries_beyond_horizon")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam60 {
    #[serde(rename = "n_bytes")] f0: u64,
    #[serde(rename = "weight")] f1: u64,
}
#[repr(C)]
#[derive(serde::Serialize, Debug)]
struct SerStructFam61 {
    #[serde(rename = "address")] f0: [u8; 20],
    #[serde(rename = "evm_extra_wei_decimals")] f1: i8,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam62 {
    #[serde(rename = "specialStatuses")] f0: String,
    #[serde(rename = "time")] f1: u64,
}
#[repr(C)]
#[derive(serde::Serialize, Debug)]
struct SerStructFam63 {
    #[serde(rename = "userState")] f0: O8<10>,
    #[serde(rename = "perpDexStates")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam64 {
    #[serde(rename = "universe")] f0: String,
    #[serde(rename = "tokens")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam65 {
    #[serde(rename = "coin")] f0: String,
    #[serde(rename = "szi")] f1: u64,
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam66 {
    #[serde(rename = "round")] f0: u32,
    #[serde(rename = "horizon_status")] f1: [u64; 2],
}
#[derive(serde::Serialize, Debug)]
struct SerStructFam67 {
    #[serde(rename = "states")] f0: u32,
    #[serde(rename = "gasAuction")] f1: O8<7>,
}

struct CollectStrTrigger(u64);
impl serde::Serialize for CollectStrTrigger {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("0x{:x}", self.0))
    }
}

#[inline(never)]
fn pin_ser<T: serde::Serialize, S: serde::Serializer>() {
    let f: fn(&T, S) -> Result<S::Ok, S::Error> = <T as serde::Serialize>::serialize::<S>;
    core::hint::black_box(f);
}

#[inline(never)]
fn exercise_collect_str(n: u64) {
    use serde_json::ser::PrettyFormatter;
    let c = CollectStrTrigger(n);
    pin_ser::<CollectStrTrigger, &mut serde_json::Serializer<&mut Vec<u8>>>();
    pin_ser::<CollectStrTrigger, &mut serde_json::Serializer<Vec<u8>>>();
    pin_ser::<CollectStrTrigger, &mut serde_json::Serializer<&mut Vec<u8>, PrettyFormatter<'_>>>();
    pin_ser::<CollectStrTrigger, &mut serde_json::Serializer<Vec<u8>, PrettyFormatter<'_>>>();
    let _ = core::hint::black_box(serde_json::to_vec(&c));
    let _ = core::hint::black_box(serde_json::to_vec_pretty(&c));
}

#[inline(never)]
fn exercise_ser_struct<T: serde::Serialize>() {
    use rmp_serde::config::{DefaultConfig, HumanReadableConfig, StructMapConfig};
    use serde_json::ser::PrettyFormatter;
    pin_ser::<T, &mut serde_json::Serializer<&mut Vec<u8>>>();
    pin_ser::<T, &mut serde_json::Serializer<Vec<u8>>>();
    pin_ser::<T, &mut serde_json::Serializer<&mut Vec<u8>, PrettyFormatter<'_>>>();
    pin_ser::<T, &mut serde_json::Serializer<Vec<u8>, PrettyFormatter<'_>>>();
    pin_ser::<T, &mut serde_json::Serializer<&mut BufWriter<std::fs::File>>>();
    pin_ser::<T, serde_json::value::Serializer>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut Vec<u8>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<Vec<u8>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut Vec<u8>, StructMapConfig<DefaultConfig>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<Vec<u8>, StructMapConfig<DefaultConfig>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut Vec<u8>, HumanReadableConfig<StructMapConfig<DefaultConfig>>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut BufWriter<std::fs::File>, StructMapConfig<DefaultConfig>>>();
}

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    if n == 0 { return; }
    exercise_collect_str(n as u64);
    exercise_ser_struct::<SerStructFam0>();
    exercise_ser_struct::<SerStructFam1>();
    exercise_ser_struct::<SerStructFam2>();
    exercise_ser_struct::<SerStructFam3>();
    exercise_ser_struct::<SerStructFam4>();
    exercise_ser_struct::<SerStructFam5>();
    exercise_ser_struct::<SerStructFam6>();
    exercise_ser_struct::<SerStructFam7>();
    exercise_ser_struct::<SerStructFam8>();
    exercise_ser_struct::<SerStructFam9>();
    exercise_ser_struct::<SerStructFam10>();
    exercise_ser_struct::<SerStructFam11>();
    exercise_ser_struct::<SerStructFam12>();
    exercise_ser_struct::<SerStructFam13>();
    exercise_ser_struct::<SerStructFam14>();
    exercise_ser_struct::<SerStructFam15>();
    exercise_ser_struct::<SerStructFam16>();
    exercise_ser_struct::<SerStructFam17>();
    exercise_ser_struct::<SerStructFam18>();
    exercise_ser_struct::<SerStructFam19>();
    exercise_ser_struct::<SerStructFam20>();
    exercise_ser_struct::<SerStructFam21>();
    exercise_ser_struct::<SerStructFam22>();
    exercise_ser_struct::<SerStructFam23>();
    exercise_ser_struct::<SerStructFam24>();
    exercise_ser_struct::<SerStructFam25>();
    exercise_ser_struct::<SerStructFam26>();
    exercise_ser_struct::<SerStructFam27>();
    exercise_ser_struct::<SerStructFam28>();
    exercise_ser_struct::<SerStructFam29>();
    exercise_ser_struct::<SerStructFam30>();
    exercise_ser_struct::<SerStructFam31>();
    exercise_ser_struct::<SerStructFam32>();
    exercise_ser_struct::<SerStructFam33>();
    exercise_ser_struct::<SerStructFam34>();
    exercise_ser_struct::<SerStructFam35>();
    exercise_ser_struct::<SerStructFam36>();
    exercise_ser_struct::<SerStructFam37>();
    exercise_ser_struct::<SerStructFam38>();
    exercise_ser_struct::<SerStructFam39>();
    exercise_ser_struct::<SerStructFam40>();
    exercise_ser_struct::<SerStructFam41>();
    exercise_ser_struct::<SerStructFam42>();
    exercise_ser_struct::<SerStructFam43>();
    exercise_ser_struct::<SerStructFam44>();
    exercise_ser_struct::<SerStructFam45>();
    exercise_ser_struct::<SerStructFam46>();
    exercise_ser_struct::<SerStructFam47>();
    exercise_ser_struct::<SerStructFam48>();
    exercise_ser_struct::<SerStructFam49>();
    exercise_ser_struct::<SerStructFam50>();
    exercise_ser_struct::<SerStructFam51>();
    exercise_ser_struct::<SerStructFam52>();
    exercise_ser_struct::<SerStructFam53>();
    exercise_ser_struct::<SerStructFam54>();
    exercise_ser_struct::<SerStructFam55>();
    exercise_ser_struct::<SerStructFam56>();
    exercise_ser_struct::<SerStructFam57>();
    exercise_ser_struct::<SerStructFam58>();
    exercise_ser_struct::<SerStructFam59>();
    exercise_ser_struct::<SerStructFam60>();
    exercise_ser_struct::<SerStructFam61>();
    exercise_ser_struct::<SerStructFam62>();
    exercise_ser_struct::<SerStructFam63>();
    exercise_ser_struct::<SerStructFam64>();
    exercise_ser_struct::<SerStructFam65>();
    exercise_ser_struct::<SerStructFam66>();
    exercise_ser_struct::<SerStructFam67>();
}
