#![forbid(unsafe_code)]

//! Independently authored Stream C (`serialization`, `transport`, `node-runtime`)
//! first-party node #115 functions for compiled-byte verification with
//! `rustc 1.95.0 (59807616e 2026-04-14) --edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes`.

use core::fmt;

// ---------------------------------------------------------------------------
// Component: serialization (`z_forks/bincode-fork`)
// ---------------------------------------------------------------------------

/// Exact 13-variant `bincode_fork::error::IntegerType` (`.rodata 0x46aa30`, `.data.rel.ro 0x6403308`).
#[derive(Copy, Clone)]
pub enum IntegerType {
    U8,
    U16,
    U32,
    U64,
    U128,
    Usize,
    I8,
    I16,
    I32,
    I64,
    I128,
    Isize,
    Reserved,
}

impl IntegerType {
    #[inline(always)]
    fn as_str(self) -> &'static str {
        match self {
            Self::U8 => "U8",
            Self::U16 => "U16",
            Self::U32 => "U32",
            Self::U64 => "U64",
            Self::U128 => "U128",
            Self::Usize => "Usize",
            Self::I8 => "I8",
            Self::I16 => "I16",
            Self::I32 => "I32",
            Self::I64 => "I64",
            Self::I128 => "I128",
            Self::Isize => "Isize",
            Self::Reserved => "Reserved",
        }
    }
}

/// `<bincode_fork::error::IntegerType as Debug>::fmt` (`0x1609a40`, 44 B).
#[inline(never)]
pub fn fp_bincode_integer_type_fmt(v: &IntegerType, f: &mut &mut dyn fmt::Write) -> fmt::Result {
    let s = v.as_str();
    f.write_str(s)
}

/// `<&bincode_fork::error::IntegerType as Debug>::fmt` (`0x1609930`, 47 B).
#[inline(never)]
pub fn fp_bincode_integer_type_ref_fmt(
    v: &&IntegerType,
    f: &mut &mut dyn fmt::Write,
) -> fmt::Result {
    let s = v.as_str();
    f.write_str(s)
}

// ---------------------------------------------------------------------------
// Component: node-runtime (`node/src/*`)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Hardfork {
    pub version: u64,
    pub round: u64,
}

#[derive(Debug)]
pub struct GossipStatus {
    pub hardfork_height: u64,
    pub latest_height: u64,
    pub hardfork: Hardfork,
    pub latest_consensus_round: Option<u64>,
}

/// `<&node::gossip_rpc::GossipStatus as Debug>::fmt` (`0x2c7c740` & `0x5a2e380`, 156 B x 2).
#[inline(never)]
pub fn fp_node_gossip_status_ref_fmt(v: &&GossipStatus, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt::Debug::fmt(*v, f)
}

#[derive(Copy, Clone)]
pub enum VisorKind {
    HlVisor,
    PublisherVisor,
}

/// `<&node::visor_time_lock::VisorKind as Debug>::fmt` (`0x5a2e340`, 54 B).
#[inline(never)]
pub fn fp_node_visor_kind_ref_fmt(v: &&VisorKind, f: &mut &mut dyn fmt::Write) -> fmt::Result {
    let s = match **v {
        VisorKind::HlVisor => "HlVisor",
        VisorKind::PublisherVisor => "PublisherVisor",
    };
    f.write_str(s)
}

macro_rules! expecting_fn {
    ($name:ident, $lit:literal) => {
        #[inline(never)]
        pub fn $name(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
            f.write_str($lit)
        }
    };
}

// Component: transport (`net_utils/src/rate_limiter.rs`)
expecting_fn!(fp_transport_alert_config_expecting, "struct AlertConfig");
expecting_fn!(fp_transport_alert_config_field_expecting, "field identifier");

// Component: node-runtime (`node/src/{gossip_config,firewall_ips,visor_time_lock,hl_node,artifact}.rs`)
expecting_fn!(fp_node_gossip_config_inner_expecting, "struct GossipConfigInner");
expecting_fn!(fp_node_firewall_entry_expecting, "struct FirewallEntry");
expecting_fn!(fp_node_visor_time_lock_expecting, "struct VisorTimeLock");
expecting_fn!(fp_node_ip_parse_error_fmt, "NodeIpParseError");
expecting_fn!(fp_node_enum_node_ip_expecting, "enum NodeIp");
expecting_fn!(fp_node_struct_hardfork_expecting, "struct Hardfork");
expecting_fn!(fp_node_gossip_prio_config_expecting, "struct NodeGossipPriorityConfig");
expecting_fn!(fp_node_visor_metadata_expecting, "struct VisorMetadata");
expecting_fn!(fp_node_node_metadata_expecting, "struct NodeMetadata");
expecting_fn!(fp_node_hotfix_args_expecting, "struct HotfixArgs");
expecting_fn!(fp_node_hotfix_metadata_expecting, "struct HotfixMetadata");
expecting_fn!(fp_node_publisher_binary_metadata_expecting, "struct PublisherBinaryMetadata");
expecting_fn!(fp_node_err_dur_guard_expecting, "struct ErrDurGuard");

/// Keeps every exported Stream C entry point reachable in the compiled object.
#[allow(clippy::too_many_arguments)]
pub fn retain_all(
    it: &IntegerType,
    rit: &&IntegerType,
    gs: &&GossipStatus,
    vk: &&VisorKind,
    fmt_ref: &mut fmt::Formatter<'_>,
    w: &mut &mut dyn fmt::Write,
) -> fmt::Result {
    let _ = fp_bincode_integer_type_fmt(it, w);
    let _ = fp_bincode_integer_type_ref_fmt(rit, w);
    let _ = fp_node_gossip_status_ref_fmt(gs, fmt_ref);
    let _ = fp_node_visor_kind_ref_fmt(vk, w);
    let _ = fp_transport_alert_config_expecting(&(), w);
    let _ = fp_transport_alert_config_field_expecting(&(), w);
    let _ = fp_node_gossip_config_inner_expecting(&(), w);
    let _ = fp_node_firewall_entry_expecting(&(), w);
    let _ = fp_node_visor_time_lock_expecting(&(), w);
    let _ = fp_node_ip_parse_error_fmt(&(), w);
    let _ = fp_node_enum_node_ip_expecting(&(), w);
    let _ = fp_node_struct_hardfork_expecting(&(), w);
    let _ = fp_node_gossip_prio_config_expecting(&(), w);
    let _ = fp_node_visor_metadata_expecting(&(), w);
    let _ = fp_node_node_metadata_expecting(&(), w);
    let _ = fp_node_hotfix_args_expecting(&(), w);
    let _ = fp_node_hotfix_metadata_expecting(&(), w);
    let _ = fp_node_publisher_binary_metadata_expecting(&(), w);
    fp_node_err_dur_guard_expecting(&(), w)
}
