#![forbid(unsafe_code)]
#![allow(dead_code, non_camel_case_types)]
use serde::ser::SerializeStruct;
use std::io::BufWriter;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[repr(transparent)]
#[derive(Debug)]
struct K1(u8);
impl serde::Serialize for K1 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.0 as u64)
    }
}
#[repr(transparent)]
#[derive(Debug)]
struct K2(u8);
impl serde::Serialize for K2 {
    #[inline(never)]
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if core::hint::black_box(self.0) == 255 {
            return Err(serde::ser::Error::custom("e"));
        }
        s.serialize_u64(self.0 as u64)
    }
}
#[repr(transparent)]
#[derive(Debug)]
struct K2S(u8);
#[inline(never)]
fn k2s_helper<S: serde::Serializer>(s: S, v: &K2S) -> Result<S::Ok, S::Error> {
    if core::hint::black_box(v.0) == 255 {
        return Err(serde::ser::Error::custom("e"));
    }
    s.serialize_u64(v.0 as u64)
}
impl serde::Serialize for K2S {
    #[inline(always)]
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        k2s_helper(s, self)
    }
}

#[repr(C)]
#[derive(Debug)]
struct SerStructFam0 {
    f1: K1,
    _p0: [u8; 31],
    f0: K2,
}
impl serde::Serialize for SerStructFam0 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam0", 2)?;
        st.serialize_field("qst", &self.f0)?;
        st.serialize_field("vts", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam1 {
    f0: K1,
    _p0: [u8; 23],
    f2: K1,
    _p1: [u8; 31],
    f1: K2,
}
impl serde::Serialize for SerStructFam1 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam1", 3)?;
        st.serialize_field("name", &self.f0)?;
        st.serialize_field("hsc", &self.f1)?;
        st.serialize_field("i", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam2 {
    f0: K2,
    _p0: [u8; 39],
    f1: K1,
}
impl serde::Serialize for SerStructFam2 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam2", 2)?;
        st.serialize_field("qst", &self.f0)?;
        st.serialize_field("vts", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam3 {
    f0: K1,
    _p0: [u8; 23],
    f1: K1,
    _p1: [u8; 7],
    f2: K1,
}
impl serde::Serialize for SerStructFam3 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam3", 3)?;
        st.serialize_field("e", &self.f0)?;
        st.serialize_field("l", &self.f1)?;
        st.serialize_field("n", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam4 {
    f3: K1,
    _p0: [u8; 23],
    f2: K1,
    _p1: [u8; 7],
    f0: K1,
    _p2: [u8; 11],
    f1: K1,
}
impl serde::Serialize for SerStructFam4 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam4", 4)?;
        st.serialize_field("local_time", &self.f0)?;
        st.serialize_field("block_time", &self.f1)?;
        st.serialize_field("block_number", &self.f2)?;
        st.serialize_field("events", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam5 {
    f2: K1,
    _p0: [u8; 887],
    f0: K2,
    _p1: [u8; 39],
    f1: K2,
}
impl serde::Serialize for SerStructFam5 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam5", 3)?;
        st.serialize_field("mempool", &self.f0)?;
        st.serialize_field("bucket_guard", &self.f1)?;
        st.serialize_field("latest_block", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam6 {
    f0: K2,
    _p0: [u8; 71],
    f1: K2,
}
impl serde::Serialize for SerStructFam6 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam6", 2)?;
        st.serialize_field("u", &self.f0)?;
        st.serialize_field("l", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam7 {
    f0: K2S,
    _p0: [u8; 23],
    f1: K1,
}
impl serde::Serialize for SerStructFam7 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam7", 2)?;
        st.serialize_field("authorizedUsers", &self.f0)?;
        st.serialize_field("threshold", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam8 {
    f0: K2,
    _p0: [u8; 239],
    f1: K1,
}
impl serde::Serialize for SerStructFam8 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam8", 2)?;
        st.serialize_field("qst", &self.f0)?;
        st.serialize_field("vts", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam9 {
    f0: K2,
    _p0: [u8; 15],
    f1: K1,
}
impl serde::Serialize for SerStructFam9 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam9", 2)?;
        st.serialize_field("df", &self.f0)?;
        st.serialize_field("lct", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam10 {
    f0: K1,
    _p0: [u8; 23],
    f1: K2,
}
impl serde::Serialize for SerStructFam10 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam10", 2)?;
        st.serialize_field("oid", &self.f0)?;
        st.serialize_field("order", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam11 {
    f0: K1,
    _p0: [u8; 7],
    f1: K2,
}
impl serde::Serialize for SerStructFam11 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam11", 2)?;
        st.serialize_field("fs", &self.f0)?;
        st.serialize_field("gm", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam12 {
    f0: K1,
    _p0: [u8; 31],
    f1: K2,
}
impl serde::Serialize for SerStructFam12 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam12", 2)?;
        st.serialize_field("e", &self.f0)?;
        st.serialize_field("g", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam13 {
    f0: K1,
    _p0: [u8; 31],
    f1: K2,
}
impl serde::Serialize for SerStructFam13 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam13", 2)?;
        st.serialize_field("spot_to_range", &self.f0)?;
        st.serialize_field("ensure_order_bucket_guard", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam14 {
    f1: K1,
    _p0: [u8; 7],
    f0: K2,
}
impl serde::Serialize for SerStructFam14 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam14", 2)?;
        st.serialize_field("choice", &self.f0)?;
        st.serialize_field("weight", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam15 {
    f1: K1,
    _p0: [u8; 31],
    f0: K2,
}
impl serde::Serialize for SerStructFam15 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam15", 2)?;
        st.serialize_field("d", &self.f0)?;
        st.serialize_field("kto", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam16 {
    f0: K2,
    _p0: [u8; 63],
    f1: K1,
    _p1: [u8; 4],
    f2: K1,
}
impl serde::Serialize for SerStructFam16 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam16", 3)?;
        st.serialize_field("a", &self.f0)?;
        st.serialize_field("cw", &self.f1)?;
        st.serialize_field("pw", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam17 {
    f0: K1,
    _p0: [u8; 31],
    f1: K1,
    _p1: [u8; 31],
    f2: K2S,
}
impl serde::Serialize for SerStructFam17 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam17", 3)?;
        st.serialize_field("user_balances", &self.f0)?;
        st.serialize_field("existing_token_balances", &self.f1)?;
        st.serialize_field("blacklist_users", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam18 {
    f0: K2,
    _p0: [u8; 39],
    f2: K1,
    _p1: [u8; 7],
    f1: K2,
    _p2: [u8; 23],
    f3: K1,
    _p3: [u8; 7],
    f4: K1,
}
impl serde::Serialize for SerStructFam18 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam18", 5)?;
        st.serialize_field("epoch_values", &self.f0)?;
        st.serialize_field("current", &self.f1)?;
        st.serialize_field("period", &self.f2)?;
        st.serialize_field("n_keep", &self.f3)?;
        st.serialize_field("current_round", &self.f4)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam19 {
    f0: K1,
    _p0: [u8; 7],
    f1: K1,
}
impl serde::Serialize for SerStructFam19 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam19", 2)?;
        st.serialize_field("q", &self.f0)?;
        st.serialize_field("i", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam20 {
    f1: K1,
    _p0: [u8; 31],
    f0: K2,
    _p1: [u8; 15],
    f3: K2,
    _p2: [u8; 15],
    f2: K1,
}
impl serde::Serialize for SerStructFam20 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam20", 4)?;
        st.serialize_field("prune_bucket_guard", &self.f0)?;
        st.serialize_field("at2", &self.f1)?;
        st.serialize_field("active", &self.f2)?;
        st.serialize_field("hc", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam21 {
    f0: K2S,
    _p0: [u8; 71],
    f1: K2S,
}
impl serde::Serialize for SerStructFam21 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam21", 2)?;
        st.serialize_field("user_to_sub_accounts", &self.f0)?;
        st.serialize_field("sub_account_to_master", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam22 {
    f1: K1,
    _p0: [u8; 23],
    f2: K1,
    _p1: [u8; 3],
    f3: K2,
    f0: K1,
}
impl serde::Serialize for SerStructFam22 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam22", 4)?;
        st.serialize_field("szDecimals", &self.f0)?;
        st.serialize_field("name", &self.f1)?;
        st.serialize_field("marginTableId", &self.f2)?;
        st.serialize_field("marginMode", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam23 {
    f3: K2,
    _p0: [u8; 63],
    f2: K2S,
    _p1: [u8; 71],
    f0: K1,
    _p2: [u8; 23],
    f1: K2,
    _p3: [u8; 7],
    f4: K1,
}
impl serde::Serialize for SerStructFam23 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam23", 5)?;
        st.serialize_field("gpa", &self.f0)?;
        st.serialize_field("gpc", &self.f1)?;
        st.serialize_field("pgp", &self.f2)?;
        st.serialize_field("prp", &self.f3)?;
        st.serialize_field("mdb", &self.f4)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam24 {
    f0: K1,
    _p0: [u8; 23],
    f1: K2S,
}
impl serde::Serialize for SerStructFam24 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam24", 2)?;
        st.serialize_field("description", &self.f0)?;
        st.serialize_field("marginTiers", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam25 {
    f2: K1,
    _p0: [u8; 23],
    f1: K1,
    _p1: [u8; 7],
    f0: K2,
}
impl serde::Serialize for SerStructFam25 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam25", 3)?;
        st.serialize_field("operation", &self.f0)?;
        st.serialize_field("token", &self.f1)?;
        st.serialize_field("amount", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam26 {
    f0: K2,
    _p0: [u8; 7],
    f1: K1,
    _p1: [u8; 11],
    f2: K1,
}
impl serde::Serialize for SerStructFam26 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam26", 3)?;
        st.serialize_field("err_duration", &self.f0)?;
        st.serialize_field("first_err_time", &self.f1)?;
        st.serialize_field("last_err_time", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam27 {
    f3: K1,
    _p0: [u8; 15],
    f0: K1,
    _p1: [u8; 7],
    f1: K1,
    _p2: [u8; 7],
    f2: K1,
    _p3: [u8; 7],
    f4: K1,
    _p4: [u8; 11],
    f5: K1,
}
impl serde::Serialize for SerStructFam27 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam27", 6)?;
        st.serialize_field("hardfork_version", &self.f0)?;
        st.serialize_field("initial_height", &self.f1)?;
        st.serialize_field("height", &self.f2)?;
        st.serialize_field("scheduled_freeze_height", &self.f3)?;
        st.serialize_field("consensus_time", &self.f4)?;
        st.serialize_field("wall_clock_time", &self.f5)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam28 {
    f0: K1,
    _p0: [u8; 31],
    f1: K1,
    _p1: [u8; 31],
    f2: K1,
    _p2: [u8; 31],
    f3: K1,
    _p3: [u8; 7],
    f4: K1,
    _p4: [u8; 7],
    f5: K1,
}
impl serde::Serialize for SerStructFam28 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam28", 6)?;
        st.serialize_field("delayed_actions", &self.f0)?;
        st.serialize_field("user_to_n_delayed_actions", &self.f1)?;
        st.serialize_field("ldb", &self.f2)?;
        st.serialize_field("n_total_delayed_actions", &self.f3)?;
        st.serialize_field("max_n_delayed_actions", &self.f4)?;
        st.serialize_field("delay_scale", &self.f5)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam29 {
    f0: K1,
    _p0: [u8; 23],
    f2: K2,
    _p1: [u8; 47],
    f3: K1,
    _p2: [u8; 31],
    f1: K2,
}
impl serde::Serialize for SerStructFam29 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam29", 4)?;
        st.serialize_field("id", &self.f0)?;
        st.serialize_field("role", &self.f1)?;
        st.serialize_field("nameAndDescription", &self.f2)?;
        st.serialize_field("keywordToHint", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam30 {
    f2: K1,
    _p0: [u8; 15],
    f0: K2,
    _p1: [u8; 15],
    f4: K1,
    _p2: [u8; 7],
    f1: K1,
    _p3: [u8; 7],
    f3: K1,
    _p4: [u8; 7],
    f5: K1,
}
impl serde::Serialize for SerStructFam30 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam30", 6)?;
        st.serialize_field("bucket_guard", &self.f0)?;
        st.serialize_field("start_gas_wei", &self.f1)?;
        st.serialize_field("end_gas_wei", &self.f2)?;
        st.serialize_field("token", &self.f3)?;
        st.serialize_field("initial_gas_to_last_auction_gas_ratio", &self.f4)?;
        st.serialize_field("min_gas", &self.f5)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam31 {
    f0: K1,
    _p0: [u8; 7],
    f1: K1,
    _p1: [u8; 7],
    f2: K2,
    _p2: [u8; 7],
    f4: K1,
    _p3: [u8; 7],
    f3: K1,
}
impl serde::Serialize for SerStructFam31 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam31", 5)?;
        st.serialize_field("num", &self.f0)?;
        st.serialize_field("denom", &self.f1)?;
        st.serialize_field("decay_duration", &self.f2)?;
        st.serialize_field("last_sample_time", &self.f3)?;
        st.serialize_field("n_samples", &self.f4)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam32 {
    f3: K2,
    _p0: [u8; 47],
    f0: K1,
    _p1: [u8; 7],
    f1: K1,
    _p2: [u8; 7],
    f2: K1,
}
impl serde::Serialize for SerStructFam32 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam32", 4)?;
        st.serialize_field("spot", &self.f0)?;
        st.serialize_field("order_ntl", &self.f1)?;
        st.serialize_field("max_px", &self.f2)?;
        st.serialize_field("ema", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam33 {
    f1: K1,
    _p0: [u8; 15],
    f2: K1,
    _p1: [u8; 7],
    f3: K1,
    _p2: [u8; 7],
    f0: K2,
}
impl serde::Serialize for SerStructFam33 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam33", 4)?;
        st.serialize_field("m", &self.f0)?;
        st.serialize_field("half_life", &self.f1)?;
        st.serialize_field("max_slippage", &self.f2)?;
        st.serialize_field("max_n_depositors", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam34 {
    f1: K1,
    _p0: [u8; 7],
    f0: K1,
}
impl serde::Serialize for SerStructFam34 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam34", 2)?;
        st.serialize_field("a", &self.f0)?;
        st.serialize_field("o", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam35 {
    f4: K1,
    _p0: [u8; 7],
    f0: K1,
    _p1: [u8; 7],
    f1: K1,
    _p2: [u8; 7],
    f2: K1,
    _p3: [u8; 7],
    f3: K1,
    _p4: [u8; 7],
    f5: K1,
}
impl serde::Serialize for SerStructFam35 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam35", 6)?;
        st.serialize_field("total_oi_cap2", &self.f0)?;
        st.serialize_field("oi_sz_cap_per_perp", &self.f1)?;
        st.serialize_field("max_transfer_ntl2", &self.f2)?;
        st.serialize_field("max_under_initial_margin_transfer_ntl2", &self.f3)?;
        st.serialize_field("daily_px_range", &self.f4)?;
        st.serialize_field("max_n_users_with_positions", &self.f5)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam36 {
    f0: K2,
    _p0: [u8; 7],
    f1: K2,
    _p1: [u8; 7],
    f2: K2,
}
impl serde::Serialize for SerStructFam36 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam36", 3)?;
        st.serialize_field("cumVlm", &self.f0)?;
        st.serialize_field("cumRewardedFeesSinceReferred", &self.f1)?;
        st.serialize_field("cumFeesRewardedToReferrer", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam37 {
    f0: K2,
    _p0: [u8; 2063],
    f1: K2,
    _p1: [u8; 2063],
    f2: K2,
}
impl serde::Serialize for SerStructFam37 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam37", 3)?;
        st.serialize_field("accounts_hash", &self.f0)?;
        st.serialize_field("contracts_hash", &self.f1)?;
        st.serialize_field("storage_hash", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam38 {
    f1: K2,
    _p0: [u8; 47],
    f2: K2,
    _p1: [u8; 47],
    f0: K1,
}
impl serde::Serialize for SerStructFam38 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam38", 3)?;
        st.serialize_field("quoteToken", &self.f0)?;
        st.serialize_field("nameAndDescription", &self.f1)?;
        st.serialize_field("sideNames", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam39 {
    f0: K1,
    _p0: [u8; 23],
    f4: K1,
    _p1: [u8; 23],
    f2: K1,
    _p2: [u8; 31],
    f1: K1,
    _p3: [u8; 7],
    f3: K1,
}
impl serde::Serialize for SerStructFam39 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam39", 5)?;
        st.serialize_field("universe", &self.f0)?;
        st.serialize_field("pdi", &self.f1)?;
        st.serialize_field("marginTableIdToMarginTable", &self.f2)?;
        st.serialize_field("collateralToken", &self.f3)?;
        st.serialize_field("collateralTokenName", &self.f4)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam40 {
    f0: K2,
    _p0: [u8; 167],
    f1: K1,
}
impl serde::Serialize for SerStructFam40 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam40", 2)?;
        st.serialize_field("dbOrder", &self.f0)?;
        st.serialize_field("priorityRate", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam41 {
    f1: K2,
    _p0: [u8; 47],
    f2: K1,
    _p1: [u8; 47],
    f0: K1,
}
impl serde::Serialize for SerStructFam41 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam41", 3)?;
        st.serialize_field("quoteToken", &self.f0)?;
        st.serialize_field("nameAndDescription", &self.f1)?;
        st.serialize_field("sideNames", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam42 {
    f0: K1,
    _p0: [u8; 7],
    f1: K1,
    _p1: [u8; 7],
    f2: K1,
    _p2: [u8; 7],
    f3: K1,
}
impl serde::Serialize for SerStructFam42 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam42", 4)?;
        st.serialize_field("accountValue", &self.f0)?;
        st.serialize_field("totalNtlPos", &self.f1)?;
        st.serialize_field("totalRawUsd", &self.f2)?;
        st.serialize_field("totalMarginUsed", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam43 {
    f0: K1,
    _p0: [u8; 7],
    f1: K2,
    _p1: [u8; 7],
    f2: K1,
    _p2: [u8; 7],
    f3: K2,
}
impl serde::Serialize for SerStructFam43 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam43", 4)?;
        st.serialize_field("max_concurrent_expensive_calls", &self.f0)?;
        st.serialize_field("expensive_call_time_limit", &self.f1)?;
        st.serialize_field("max_concurrent_get_logs_calls", &self.f2)?;
        st.serialize_field("get_logs_time_limit", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam44 {
    f2: K1,
    _p0: [u8; 2047],
    f0: K1,
    _p1: [u8; 7],
    f1: K1,
}
impl serde::Serialize for SerStructFam44 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam44", 3)?;
        st.serialize_field("n_elements", &self.f0)?;
        st.serialize_field("n_bytes", &self.f1)?;
        st.serialize_field("hash", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam45 {
    f7: K1,
    _p0: [u8; 15],
    f1: K1,
    _p1: [u8; 7],
    f2: K1,
    _p2: [u8; 7],
    f3: K1,
    _p3: [u8; 7],
    f4: K1,
    _p4: [u8; 7],
    f5: K1,
    _p5: [u8; 7],
    f6: K1,
    _p6: [u8; 7],
    f0: K1,
}
impl serde::Serialize for SerStructFam45 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam45", 8)?;
        st.serialize_field("time", &self.f0)?;
        st.serialize_field("n", &self.f1)?;
        st.serialize_field("n_orig", &self.f2)?;
        st.serialize_field("median", &self.f3)?;
        st.serialize_field("mean", &self.f4)?;
        st.serialize_field("p95", &self.f5)?;
        st.serialize_field("max", &self.f6)?;
        st.serialize_field("work_frac", &self.f7)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam46 {
    f0: K1,
    _p0: [u8; 7],
    f1: K1,
    _p1: [u8; 7],
    f3: K1,
    _p2: [u8; 7],
    f4: K1,
    _p3: [u8; 31],
    f2: K2,
}
impl serde::Serialize for SerStructFam46 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam46", 5)?;
        st.serialize_field("b", &self.f0)?;
        st.serialize_field("t", &self.f1)?;
        st.serialize_field("e", &self.f2)?;
        st.serialize_field("i", &self.f3)?;
        st.serialize_field("h", &self.f4)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam47 {
    f1: K1,
    _p0: [u8; 23],
    f2: K1,
    _p1: [u8; 15],
    f3: K1,
    _p2: [u8; 15],
    f4: K1,
    _p3: [u8; 15],
    f5: K1,
    _p4: [u8; 7],
    f0: K1,
}
impl serde::Serialize for SerStructFam47 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam47", 6)?;
        st.serialize_field("user", &self.f0)?;
        st.serialize_field("coin", &self.f1)?;
        st.serialize_field("leverage", &self.f2)?;
        st.serialize_field("maxTradeSzs", &self.f3)?;
        st.serialize_field("availableToTrade", &self.f4)?;
        st.serialize_field("markPx", &self.f5)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam48 {
    f0: K1,
    _p0: [u8; 7],
    f1: K1,
    _p1: [u8; 7],
    f2: K1,
    _p2: [u8; 7],
    f3: K1,
    _p3: [u8; 7],
    f4: K1,
}
impl serde::Serialize for SerStructFam48 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam48", 5)?;
        st.serialize_field("ntlCutoff", &self.f0)?;
        st.serialize_field("cross", &self.f1)?;
        st.serialize_field("add", &self.f2)?;
        st.serialize_field("spotCross", &self.f3)?;
        st.serialize_field("spotAdd", &self.f4)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam49 {
    f0: K1,
    _p0: [u8; 7],
    f1: K1,
    _p1: [u8; 7],
    f2: K1,
    _p2: [u8; 7],
    f3: K1,
    _p3: [u8; 7],
    f4: K1,
}
impl serde::Serialize for SerStructFam49 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam49", 5)?;
        st.serialize_field("perpCrossBaseRate", &self.f0)?;
        st.serialize_field("perpAddBaseRate", &self.f1)?;
        st.serialize_field("spotCrossBaseRate", &self.f2)?;
        st.serialize_field("spotAddBaseRate", &self.f3)?;
        st.serialize_field("endTimestamp", &self.f4)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam50 {
    f3: K1,
    _p0: [u8; 15],
    f4: K1,
    _p1: [u8; 15],
    f0: K1,
    _p2: [u8; 7],
    f1: K1,
    _p3: [u8; 7],
    f2: K1,
}
impl serde::Serialize for SerStructFam50 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam50", 5)?;
        st.serialize_field("startTimeSeconds", &self.f0)?;
        st.serialize_field("durationSeconds", &self.f1)?;
        st.serialize_field("startGas", &self.f2)?;
        st.serialize_field("currentGas", &self.f3)?;
        st.serialize_field("endGas", &self.f4)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam51 {
    f1: K1,
    _p0: [u8; 23],
    f2: K1,
    _p1: [u8; 23],
    f0: K1,
    _p2: [u8; 7],
    f3: K1,
    _p3: [u8; 7],
    f4: K1,
}
impl serde::Serialize for SerStructFam51 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam51", 5)?;
        st.serialize_field("question", &self.f0)?;
        st.serialize_field("name", &self.f1)?;
        st.serialize_field("description", &self.f2)?;
        st.serialize_field("fallbackOutcome", &self.f3)?;
        st.serialize_field("namedOutcomes", &self.f4)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam52 {
    f1: K1,
    _p0: [u8; 23],
    f2: K1,
    _p1: [u8; 7],
    f3: K1,
    _p2: [u8; 7],
    f4: K1,
    _p3: [u8; 7],
    f0: K1,
}
impl serde::Serialize for SerStructFam52 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam52", 5)?;
        st.serialize_field("user", &self.f0)?;
        st.serialize_field("coin", &self.f1)?;
        st.serialize_field("funding_amount", &self.f2)?;
        st.serialize_field("szi", &self.f3)?;
        st.serialize_field("funding_rate", &self.f4)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam53 {
    f3: K1,
    _p0: [u8; 15],
    f1: K1,
    _p1: [u8; 7],
    f2: K1,
    _p2: [u8; 7],
    f0: K1,
    _p3: [u8; 19],
    f4: K1,
}
impl serde::Serialize for SerStructFam53 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam53", 5)?;
        st.serialize_field("user", &self.f0)?;
        st.serialize_field("start_pos", &self.f1)?;
        st.serialize_field("oid", &self.f2)?;
        st.serialize_field("twap_id", &self.f3)?;
        st.serialize_field("cloid", &self.f4)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam54 {
    f0: K1,
    _p0: [u8; 7],
    f1: K1,
    _p1: [u8; 7],
    f2: K1,
    _p2: [u8; 7],
    f4: K1,
    _p3: [u8; 7],
    f3: K1,
}
impl serde::Serialize for SerStructFam54 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam54", 5)?;
        st.serialize_field("num", &self.f0)?;
        st.serialize_field("denom", &self.f1)?;
        st.serialize_field("decay_duration", &self.f2)?;
        st.serialize_field("last_sample_time", &self.f3)?;
        st.serialize_field("n_samples", &self.f4)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam55 {
    f2: K1,
    _p0: [u8; 31],
    f1: K1,
    _p1: [u8; 175],
    f0: K1,
    _p2: [u8; 7],
    f3: K1,
}
impl serde::Serialize for SerStructFam55 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam55", 4)?;
        st.serialize_field("expireTime", &self.f0)?;
        st.serialize_field("action", &self.f1)?;
        st.serialize_field("votes", &self.f2)?;
        st.serialize_field("quorumReached", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam56 {
    f2: K1,
    _p0: [u8; 119],
    f3: K1,
    _p1: [u8; 23],
    f1: K1,
    _p2: [u8; 7],
    f0: K1,
}
impl serde::Serialize for SerStructFam56 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam56", 4)?;
        st.serialize_field("time", &self.f0)?;
        st.serialize_field("twap_id", &self.f1)?;
        st.serialize_field("state", &self.f2)?;
        st.serialize_field("status", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam57 {
    f3: K1,
    _p0: [u8; 239],
    f1: K1,
    _p1: [u8; 7],
    f2: K1,
    _p2: [u8; 31],
    f0: K1,
}
impl serde::Serialize for SerStructFam57 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam57", 4)?;
        st.serialize_field("user", &self.f0)?;
        st.serialize_field("nonce", &self.f1)?;
        st.serialize_field("evm_tx_hash", &self.f2)?;
        st.serialize_field("action", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam58 {
    f3: K1,
    _p0: [u8; 231],
    f2: K1,
    _p1: [u8; 7],
    f0: K1,
    _p2: [u8; 11],
    f1: K1,
}
impl serde::Serialize for SerStructFam58 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam58", 4)?;
        st.serialize_field("local_time", &self.f0)?;
        st.serialize_field("block_time", &self.f1)?;
        st.serialize_field("block_number", &self.f2)?;
        st.serialize_field("events", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam59 {
    f3: K1,
    _p0: [u8; 199],
    f2: K1,
    _p1: [u8; 7],
    f0: K1,
    _p2: [u8; 11],
    f1: K1,
}
impl serde::Serialize for SerStructFam59 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam59", 4)?;
        st.serialize_field("local_time", &self.f0)?;
        st.serialize_field("block_time", &self.f1)?;
        st.serialize_field("block_number", &self.f2)?;
        st.serialize_field("events", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam60 {
    f3: K1,
    _p0: [u8; 303],
    f2: K1,
    _p1: [u8; 7],
    f0: K1,
    _p2: [u8; 11],
    f1: K1,
}
impl serde::Serialize for SerStructFam60 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam60", 4)?;
        st.serialize_field("local_time", &self.f0)?;
        st.serialize_field("block_time", &self.f1)?;
        st.serialize_field("block_number", &self.f2)?;
        st.serialize_field("events", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam61 {
    f3: K1,
    _p0: [u8; 319],
    f2: K1,
    _p1: [u8; 7],
    f0: K1,
    _p2: [u8; 11],
    f1: K1,
}
impl serde::Serialize for SerStructFam61 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam61", 4)?;
        st.serialize_field("local_time", &self.f0)?;
        st.serialize_field("block_time", &self.f1)?;
        st.serialize_field("block_number", &self.f2)?;
        st.serialize_field("events", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam62 {
    f3: K1,
    _p0: [u8; 247],
    f2: K1,
    _p1: [u8; 7],
    f0: K1,
    _p2: [u8; 11],
    f1: K1,
}
impl serde::Serialize for SerStructFam62 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam62", 4)?;
        st.serialize_field("local_time", &self.f0)?;
        st.serialize_field("block_time", &self.f1)?;
        st.serialize_field("block_number", &self.f2)?;
        st.serialize_field("events", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam63 {
    f3: K1,
    _p0: [u8; 167],
    f2: K1,
    _p1: [u8; 7],
    f0: K1,
    _p2: [u8; 11],
    f1: K1,
}
impl serde::Serialize for SerStructFam63 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam63", 4)?;
        st.serialize_field("local_time", &self.f0)?;
        st.serialize_field("block_time", &self.f1)?;
        st.serialize_field("block_number", &self.f2)?;
        st.serialize_field("events", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam64 {
    f3: K1,
    _p0: [u8; 295],
    f2: K1,
    _p1: [u8; 7],
    f0: K1,
    _p2: [u8; 11],
    f1: K1,
}
impl serde::Serialize for SerStructFam64 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam64", 4)?;
        st.serialize_field("local_time", &self.f0)?;
        st.serialize_field("block_time", &self.f1)?;
        st.serialize_field("block_number", &self.f2)?;
        st.serialize_field("events", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam65 {
    f0: K1,
    _p0: [u8; 7],
    f1: K1,
    _p1: [u8; 7],
    f2: K1,
    _p2: [u8; 7],
    f3: K1,
}
impl serde::Serialize for SerStructFam65 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam65", 4)?;
        st.serialize_field("cumVlm", &self.f0)?;
        st.serialize_field("nRequestsUsed", &self.f1)?;
        st.serialize_field("nRequestsCap", &self.f2)?;
        st.serialize_field("nRequestsSurplus", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam66 {
    f1: K1,
    _p0: [u8; 7],
    f2: K1,
    _p1: [u8; 7],
    f3: K1,
    _p2: [u8; 7],
    f0: K1,
}
impl serde::Serialize for SerStructFam66 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam66", 4)?;
        st.serialize_field("date", &self.f0)?;
        st.serialize_field("userCross", &self.f1)?;
        st.serialize_field("userAdd", &self.f2)?;
        st.serialize_field("exchange", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam67 {
    f0: K1,
    _p0: [u8; 7],
    f1: K1,
    _p1: [u8; 7],
    f2: K1,
    _p2: [u8; 7],
    f3: K1,
}
impl serde::Serialize for SerStructFam67 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam67", 4)?;
        st.serialize_field("delegated", &self.f0)?;
        st.serialize_field("undelegated", &self.f1)?;
        st.serialize_field("totalPendingWithdrawal", &self.f2)?;
        st.serialize_field("nPendingWithdrawals", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam68 {
    f0: K1,
    _p0: [u8; 7],
    f1: K1,
    _p1: [u8; 7],
    f2: K1,
    _p2: [u8; 7],
    f3: K1,
}
impl serde::Serialize for SerStructFam68 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam68", 4)?;
        st.serialize_field("usdcSupply", &self.f0)?;
        st.serialize_field("effectiveRate", &self.f1)?;
        st.serialize_field("interest", &self.f2)?;
        st.serialize_field("active", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam69 {
    f1: K1,
    _p0: [u8; 23],
    f0: K1,
    _p1: [u8; 15],
    f2: K1,
    _p2: [u8; 7],
    f3: K1,
}
impl serde::Serialize for SerStructFam69 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam69", 4)?;
        st.serialize_field("tokens", &self.f0)?;
        st.serialize_field("name", &self.f1)?;
        st.serialize_field("index", &self.f2)?;
        st.serialize_field("isCanonical", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam70 {
    f3: K1,
    _p0: [u8; 31],
    f0: K1,
    _p1: [u8; 7],
    f1: K1,
    _p2: [u8; 7],
    f2: K1,
}
impl serde::Serialize for SerStructFam70 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam70", 4)?;
        st.serialize_field("totalOiCap", &self.f0)?;
        st.serialize_field("oiSzCapPerPerp", &self.f1)?;
        st.serialize_field("maxTransferNtl", &self.f2)?;
        st.serialize_field("coinToOiCap", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam71 {
    f3: K1,
    _p0: [u8; 87],
    f2: K1,
    _p1: [u8; 7],
    f0: K1,
    _p2: [u8; 11],
    f1: K1,
}
impl serde::Serialize for SerStructFam71 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam71", 4)?;
        st.serialize_field("local_time", &self.f0)?;
        st.serialize_field("block_time", &self.f1)?;
        st.serialize_field("block_number", &self.f2)?;
        st.serialize_field("events", &self.f3)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam72 {
    f2: K1,
    _p0: [u8; 199],
    f1: K1,
    _p1: [u8; 31],
    f0: K1,
}
impl serde::Serialize for SerStructFam72 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam72", 3)?;
        st.serialize_field("time", &self.f0)?;
        st.serialize_field("hash", &self.f1)?;
        st.serialize_field("inner", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam73 {
    f0: K1,
    _p0: [u8; 7],
    f1: K1,
    _p1: [u8; 7],
    f2: K1,
}
impl serde::Serialize for SerStructFam73 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam73", 3)?;
        st.serialize_field("n", &self.f0)?;
        st.serialize_field("total", &self.f1)?;
        st.serialize_field("max", &self.f2)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam74 {
    f0: K1,
    _p0: [u8; 7],
    f1: K1,
}
impl serde::Serialize for SerStructFam74 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam74", 2)?;
        st.serialize_field("n", &self.f0)?;
        st.serialize_field("last_block_hash", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam75 {
    f1: K1,
    _p0: [u8; 11],
    f0: K1,
}
impl serde::Serialize for SerStructFam75 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam75", 2)?;
        st.serialize_field("deployer", &self.f0)?;
        st.serialize_field("deployTime", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam76 {
    f1: K1,
    _p0: [u8; 15],
    f0: K1,
}
impl serde::Serialize for SerStructFam76 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam76", 2)?;
        st.serialize_field("delayedUntil", &self.f0)?;
        st.serialize_field("id", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam77 {
    f1: K1,
    _p0: [u8; 7],
    f0: K1,
}
impl serde::Serialize for SerStructFam77 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam77", 2)?;
        st.serialize_field("verified", &self.f0)?;
        st.serialize_field("connection_count", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam78 {
    f1: K1,
    _p0: [u8; 15],
    f0: K1,
}
impl serde::Serialize for SerStructFam78 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam78", 2)?;
        st.serialize_field("asset", &self.f0)?;
        st.serialize_field("cloid", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam79 {
    f1: K1,
    _p0: [u8; 39],
    f0: K1,
}
impl serde::Serialize for SerStructFam79 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam79", 2)?;
        st.serialize_field("user", &self.f0)?;
        st.serialize_field("res", &self.f1)?;
        st.end()
    }
}
#[repr(C)]
#[derive(Debug)]
struct SerStructFam80 {
    f1: K1,
    _p0: [u8; 15],
    f0: K1,
}
impl serde::Serialize for SerStructFam80 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("SerStructFam80", 2)?;
        st.serialize_field("tx_hash", &self.f0)?;
        st.serialize_field("signed_actions", &self.f1)?;
        st.end()
    }
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
    use rmp_serde::config::{DefaultConfig, StructMapConfig};
    use serde_json::ser::PrettyFormatter;
    pin_ser::<T, &mut serde_json::Serializer<&mut Vec<u8>>>();
    pin_ser::<T, &mut serde_json::Serializer<Vec<u8>>>();
    pin_ser::<T, &mut serde_json::Serializer<&mut Vec<u8>, PrettyFormatter<'_>>>();
    pin_ser::<T, &mut serde_json::Serializer<Vec<u8>, PrettyFormatter<'_>>>();
    pin_ser::<T, &mut serde_json::Serializer<&mut BufWriter<std::fs::File>>>();
    pin_ser::<T, serde_json::value::Serializer>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut Vec<u8>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut Vec<u8>, StructMapConfig<DefaultConfig>>>();
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
    exercise_ser_struct::<SerStructFam68>();
    exercise_ser_struct::<SerStructFam69>();
    exercise_ser_struct::<SerStructFam70>();
    exercise_ser_struct::<SerStructFam71>();
    exercise_ser_struct::<SerStructFam72>();
    exercise_ser_struct::<SerStructFam73>();
    exercise_ser_struct::<SerStructFam74>();
    exercise_ser_struct::<SerStructFam75>();
    exercise_ser_struct::<SerStructFam76>();
    exercise_ser_struct::<SerStructFam77>();
    exercise_ser_struct::<SerStructFam78>();
    exercise_ser_struct::<SerStructFam79>();
    exercise_ser_struct::<SerStructFam80>();
}
