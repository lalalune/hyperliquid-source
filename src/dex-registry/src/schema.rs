//! Main / HIP-3 per-DEX state envelope and `limits` / `schema` / `state` codecs.
//!
//! Anchored to node #115 evidence packets:
//! - `research/work-items/dex-registry-main-hip3-state-codec-115` (`0x2bc2700`, `0x2b94d80`)
//! - `research/work-items/dex-registry-hip3-limits-schema-state-115` (`0x2bc1190`, `0x2bc17c0`, `0x2bc0900`)
//! - `research/work-items/dex-registry-hip3-subrecord-helpers-115` (`0x2ce96a0`, `0x2ce6f90`, `0x2cea920`)
//! - `src/node115-hip3-disabled-record` (`0x2bc06a0`)
//! - `src/node115-hip3-disabled-state-codec`

use std::collections::BTreeMap;

use node115_hip3_disabled_record::{
    encode as encode_state_record, DisabledState as RecordDisabledState, Mode as RecordMode,
    Record as StateRecord, Timestamp,
};
use node115_hip3_disabled_state_codec::DisabledState;

use crate::{format_address_hex, msgpack, sub_deployers::SubDeployers, Address};

/// Serialization layout flag (`+0x1b` on the rmp-serde writer):
/// `false` (`0`) = compact array, `true` (`1`) = named map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireMode {
    Array,
    Map,
}

impl WireMode {
    const fn is_map(self) -> bool {
        matches!(self, Self::Map)
    }

    const fn record_mode(self) -> RecordMode {
        match self {
            Self::Array => RecordMode::Array,
            Self::Map => RecordMode::Map,
        }
    }
}

/// Top-level per-DEX kind tag observed in exact-name visitor `0x2b94d80`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DexKind {
    Main = 0,
    Hip3 = 1,
}

impl DexKind {
    /// Exact 4-byte case-sensitive variant visitor from `0x2b94d80` / `0x4440220` / `0x5469f10`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Main" => Some(Self::Main),
            "Hip3" => Some(Self::Hip3),
            _ => None,
        }
    }

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Main => "Main",
            Self::Hip3 => "Hip3",
        }
    }

    /// Tagged visitor word observed at `0x2b94d96` (`0x0009` for `Main`, `0x0109` for `Hip3`).
    pub const fn visitor_result_word(self) -> u16 {
        0x0009 | ((self as u16) << 8)
    }
}

/// HIP-3 `limits` record (6 fields in exact `0x2bc1190` wire order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hip3Limits {
    pub total_oi_cap2: u64,
    pub oi_sz_cap_per_perp: u64,
    pub max_transfer_ntl2: u64,
    pub max_under_initial_margin_transfer_ntl2: u64,
    pub daily_px_range: u64,
    pub max_n_users_with_positions: u64,
}

impl Hip3Limits {
    /// Encodes `limits` in exact node #115 MessagePack wire order (`0x86` map / `0x96` array).
    pub fn encode_msgpack(&self, mode: WireMode, out: &mut Vec<u8>) {
        let map = mode.is_map();
        out.push(if map { 0x86 } else { 0x96 });
        if map {
            msgpack::write_str(out, b"total_oi_cap2");
        }
        msgpack::write_u64(out, self.total_oi_cap2);
        if map {
            msgpack::write_str(out, b"oi_sz_cap_per_perp");
        }
        msgpack::write_u64(out, self.oi_sz_cap_per_perp);
        if map {
            msgpack::write_str(out, b"max_transfer_ntl2");
        }
        msgpack::write_u64(out, self.max_transfer_ntl2);
        if map {
            msgpack::write_str(out, b"max_under_initial_margin_transfer_ntl2");
        }
        msgpack::write_u64(out, self.max_under_initial_margin_transfer_ntl2);
        if map {
            msgpack::write_str(out, b"daily_px_range");
        }
        msgpack::write_u64(out, self.daily_px_range);
        if map {
            msgpack::write_str(out, b"max_n_users_with_positions");
        }
        msgpack::write_u64(out, self.max_n_users_with_positions);
    }
}

/// HIP-3 `schema` record (7 fields in exact `0x2bc17c0` wire order).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hip3Schema {
    pub name: String,
    pub full_name: String,
    pub deployer: Address,
    pub oracle_updater: Option<Address>,
    pub fee_recipient: Option<Address>,
    pub asset_to_oi_cap: BTreeMap<u32, u64>,
    pub sub_deployers: SubDeployers,
}

impl Hip3Schema {
    /// Encodes `schema` in exact node #115 MessagePack wire order (`0x87` map / `0x97` array).
    pub fn encode_msgpack(&self, mode: WireMode, out: &mut Vec<u8>) {
        let map = mode.is_map();
        out.push(if map { 0x87 } else { 0x97 });

        if map {
            msgpack::write_str(out, b"name");
        }
        msgpack::write_str(out, self.name.as_bytes());

        if map {
            msgpack::write_str(out, b"full_name");
        }
        msgpack::write_str(out, self.full_name.as_bytes());

        if map {
            msgpack::write_str(out, b"deployer");
        }
        msgpack::write_str(out, format_address_hex(&self.deployer).as_bytes());

        if map {
            msgpack::write_str(out, b"oracle_updater");
        }
        encode_opt_address(self.oracle_updater, out);

        if map {
            msgpack::write_str(out, b"fee_recipient");
        }
        encode_opt_address(self.fee_recipient, out);

        if map {
            msgpack::write_str(out, b"asset_to_oi_cap");
        }
        msgpack::write_map_len(out, self.asset_to_oi_cap.len());
        for (&asset, &cap) in &self.asset_to_oi_cap {
            msgpack::write_u64(out, u64::from(asset));
            msgpack::write_u64(out, cap);
        }

        if map {
            msgpack::write_str(out, b"sub_deployers");
        }
        self.sub_deployers.encode_msgpack(out);
    }
}

fn encode_opt_address(addr: Option<Address>, out: &mut Vec<u8>) {
    match addr {
        Some(a) => msgpack::write_str(out, format_address_hex(&a).as_bytes()),
        None => out.push(0xc0), // msgpack nil
    }
}

/// Converts between `node115-hip3-disabled-state-codec` and `node115-hip3-disabled-record`.
pub const fn to_record_disabled_state(s: DisabledState) -> RecordDisabledState {
    match s {
        DisabledState::Na => RecordDisabledState::Na,
        DisabledState::UserDisabled => RecordDisabledState::UserDisabled,
        DisabledState::ValidatorDisabled => RecordDisabledState::ValidatorDisabled,
        DisabledState::M => RecordDisabledState::M,
    }
}

/// HIP-3 `state` record (5 fields in exact `0x2bc0900` / `0x2bc06a0` wire order).
#[derive(Clone, Copy, Debug)]
pub struct Hip3State {
    pub last_settlement_time: Timestamp,
    pub deploy_time: Timestamp,
    pub n_reserve_deployments_used: u64,
    pub disabled_state: DisabledState,
    pub m: bool,
}

impl Hip3State {
    /// Encodes `state` by delegating to the validated `node115-hip3-disabled-record` encoder.
    pub fn encode_msgpack(&self, mode: WireMode, out: &mut Vec<u8>) {
        let rec = StateRecord {
            last_settlement_time: self.last_settlement_time,
            deploy_time: self.deploy_time,
            n_reserve_deployments_used: self.n_reserve_deployments_used,
            disabled_state: to_record_disabled_state(self.disabled_state),
            m: self.m,
        };
        let encoded = encode_state_record(rec, mode.record_mode());
        out.extend_from_slice(encoded.as_bytes());
    }
}

/// Per-DEX metadata envelope (`0x2bc2700` `Main` vs `Hip3`).
///
/// The optional trailing HIP-3 fields (`hip3_backstop_liquidator_state`, `ss`,
/// `df`) are represented as raw opaque MessagePack byte slices until their
/// inner payload layouts are individually closed.
#[derive(Clone, Debug)]
pub enum DexMetadata {
    Main {
        asset_to_recent_oi: Vec<u8>,
        override_max_oi_per_second: Vec<u8>,
        reset_recent_oi_bucket_guard: Vec<u8>,
        assets_at_open_interest_cap: Vec<u8>,
    },
    Hip3 {
        limits: Hip3Limits,
        schema: Box<Hip3Schema>,
        state: Hip3State,
        backstop_liquidator_state: Option<Vec<u8>>,
        ss: Option<Vec<u8>>,
        df: Option<Vec<u8>>,
    },
}

impl DexMetadata {
    pub const fn kind(&self) -> DexKind {
        match self {
            Self::Main { .. } => DexKind::Main,
            Self::Hip3 { .. } => DexKind::Hip3,
        }
    }

    /// Computes the exact dynamic HIP-3 field count (`3..=6`) observed at `0x2bc2700`.
    pub fn hip3_field_count(&self) -> Option<usize> {
        match self {
            Self::Main { .. } => None,
            Self::Hip3 {
                backstop_liquidator_state,
                ss,
                df,
                ..
            } => Some(
                3 + usize::from(backstop_liquidator_state.is_some())
                    + usize::from(ss.is_some())
                    + usize::from(df.is_some()),
            ),
        }
    }

    /// Encodes the `{"Main": ...}` or `{"Hip3": ...}` envelope matching `0x2bc2700`.
    pub fn encode_msgpack(&self, mode: WireMode, out: &mut Vec<u8>) {
        let map = mode.is_map();
        out.push(0x81); // fixmap(1)
        msgpack::write_str(out, self.kind().wire_name().as_bytes());

        match self {
            Self::Main {
                asset_to_recent_oi,
                override_max_oi_per_second,
                reset_recent_oi_bucket_guard,
                assets_at_open_interest_cap,
            } => {
                out.push(if map { 0x84 } else { 0x94 });
                if map {
                    msgpack::write_str(out, b"asset_to_recent_oi");
                }
                out.extend_from_slice(asset_to_recent_oi);
                if map {
                    msgpack::write_str(out, b"override_max_oi_per_second");
                }
                out.extend_from_slice(override_max_oi_per_second);
                if map {
                    msgpack::write_str(out, b"reset_recent_oi_bucket_guard");
                }
                out.extend_from_slice(reset_recent_oi_bucket_guard);
                if map {
                    msgpack::write_str(out, b"assets_at_open_interest_cap");
                }
                out.extend_from_slice(assets_at_open_interest_cap);
            }
            Self::Hip3 {
                limits,
                schema,
                state,
                backstop_liquidator_state,
                ss,
                df,
            } => {
                let count = self.hip3_field_count().unwrap_or(3);
                if map {
                    msgpack::write_map_len(out, count);
                } else {
                    msgpack::write_array_len(out, count);
                }
                if map {
                    msgpack::write_str(out, b"limits");
                }
                limits.encode_msgpack(mode, out);
                if map {
                    msgpack::write_str(out, b"schema");
                }
                schema.encode_msgpack(mode, out);
                if map {
                    msgpack::write_str(out, b"state");
                }
                state.encode_msgpack(mode, out);
                if let Some(raw) = backstop_liquidator_state {
                    if map {
                        msgpack::write_str(out, b"hip3_backstop_liquidator_state");
                    }
                    out.extend_from_slice(raw);
                }
                if let Some(raw) = ss {
                    if map {
                        msgpack::write_str(out, b"ss");
                    }
                    out.extend_from_slice(raw);
                }
                if let Some(raw) = df {
                    if map {
                        msgpack::write_str(out, b"df");
                    }
                    out.extend_from_slice(raw);
                }
            }
        }
    }
}
