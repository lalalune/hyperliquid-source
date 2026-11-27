#!/usr/bin/env python3
"""Verify the final 2 first-party global_constants CGU FDEs (home_dir 253 B + read_aws_name 429 B = 682 B),
achieving 12/12 (100.00%, 12,753/12,753 B) first-party global_constants CGU compiled-byte identity and
38/40 (99.25%, 22,877/23,050 B) total CGU FDE reproduction in one unmodified offline ThinLTO+jemalloc build."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
RECORDS_PATH = PACKET_DIR / "records.json"
BODIES_PATH = PACKET_DIR / "bodies.bin"

sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "research" / "work-items" / "RE-002-node115-std-census"))
from byte_progress import compare  # noqa: E402
from census import object_functions  # noqa: E402
from elf_index import sections  # noqa: E402

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032

# 2 brand-new, zero-overlap, 100% pure first-party global_constants logic FDEs (682 B)
NEW_WINDOWS = [
    (
        0x17782E0,
        0x17783DD,
        "first_party_logic",
        "constants global_constants::static_config::home_dir (0x17782e0)",
    ),
    (
        0x17783E0,
        0x177858D,
        "first_party_logic",
        "constants global_constants::static_config::read_aws_name (0x17783e0)",
    ),
]

# Complete 12/12 first-party global_constants CGU FDEs (12,753 B)
ALL_FIRST_PARTY_CGU_FDES = [
    (0x1772FA0, 0x1773069),  # aws_name::aws_name_path (201 B)
    (0x1773070, 0x1773FC4),  # AwsName::deserialize (3,924 B)
    (0x1773FD0, 0x17740FE),  # aws_name::read_aws_name_fallback (302 B)
    (0x1774100, 0x1774BE1),  # AwsName::__FieldVisitor::visit_str (2,785 B)
    (0x1774E40, 0x1774E59),  # VariantNotFound::fmt (25 B)
    (0x1774E60, 0x17754F1),  # AwsName::fmt Display (1,681 B)
    (0x1775500, 0x1775DC6),  # AwsName::from_str (2,246 B)
    (0x17780C0, 0x1778265),  # static_config::cham_dir (421 B)
    (0x1778270, 0x17782D7),  # static_config::cham_dir::{{closure}} (103 B)
    (0x17782E0, 0x17783DD),  # static_config::home_dir (253 B) [NEW]
    (0x17783E0, 0x177858D),  # static_config::read_aws_name (429 B) [NEW]
    (0x17785F0, 0x177876F),  # static_config::new_static_config (383 B)
]

# All 36 previously matched CGU FDEs also reproduced simultaneously by this exact build (38/40 total)
PREVIOUSLY_MATCHED_CGU = [
    (0x1772F80, 0x1772F94),
    (0x1772FA0, 0x1773069),
    (0x1773070, 0x1773FC4),
    (0x1773FD0, 0x17740FE),
    (0x1774100, 0x1774BE1),
    (0x1774BF0, 0x1774C56),
    (0x1774C60, 0x1774C79),
    (0x1774C80, 0x1774CE6),
    (0x1774CF0, 0x1774DC1),
    (0x1774DD0, 0x1774E37),
    (0x1774E40, 0x1774E59),
    (0x1774E60, 0x17754F1),
    (0x1775500, 0x1775DC6),
    (0x1775DD0, 0x1775EDE),
    (0x1775F50, 0x1776292),
    (0x17762A0, 0x1776427),
    (0x1776430, 0x177667A),
    (0x1776680, 0x1776908),
    (0x1776910, 0x1776C17),
    (0x1776C70, 0x1776CBE),
    (0x1776CC0, 0x1776DB2),
    (0x1776DC0, 0x1776F41),
    (0x1776F50, 0x177707A),
    (0x1777080, 0x17771A3),
    (0x17771B0, 0x1777FAF),
    (0x1777FB0, 0x1777FC4),
    (0x1777FD0, 0x177805B),
    (0x1778060, 0x17780B5),
    (0x17780C0, 0x1778265),
    (0x1778270, 0x17782D7),
    (0x1778590, 0x17785A3),
    (0x17785B0, 0x17785C9),
    (0x17785D0, 0x17785E9),
    (0x17785F0, 0x177876F),
    (0x1778770, 0x177883E),
    (0x1778840, 0x1778AD7),
]

# Remaining 2/40 CGU FDEs: third-party serde_json monomorphizations (173 B = 0.75% of CGU)
RESIDUAL_THIRD_PARTY_CGU = [
    {
        "start": "0x1775ee0",
        "end": "0x1775f46",
        "bytes": 102,
        "defining_crate": "serde_json",
        "function": "serde_json::de::Deserializer<R>::peek_error",
        "root_cause": (
            "Node #115 z_vendor/serde_json combines 1.0.140..1.0.149 src/read.rs (lines 422/427/428/580, "
            "2 callers of SliceRead::position_of_index) with 1.0.145+ src/de.rs MapKey fix and memchr 2.7.x "
            "(before memchr 2.8.x added unreachable_unchecked() in search_slice_with_raw). That keeps "
            "SliceRead::position_of_index (0x5c56920, 184 B) out-of-line with LLVM ArgumentPromotion "
            "(slice.ptr, slice.len, i). Offline crates.io cache carries unmodified memchr 2.8.3 and "
            "serde_json 1.0.140 / 1.0.154, so we do not patch registry crates to claim these 2 third-party FDEs."
        ),
    },
    {
        "start": "0x1776c20",
        "end": "0x1776c67",
        "bytes": 71,
        "defining_crate": "serde_json",
        "function": "serde_json::de::Deserializer<R>::error",
        "root_cause": (
            "Same z_vendor/serde_json (1.0.145..1.0.149) + memchr 2.7.x out-of-line call to "
            "SliceRead::position_of_index (0x5c56920, 184 B)."
        ),
    },
]

# All 5 .data.rel.ro Location records referencing global_constants/ across the entire node #115 binary
EXPECTED_GLOBAL_CONSTANTS_LOCATIONS = [
    (0x64111D8, "global_constants/src/aws_name.rs", 295, 44, "0x1773fd0..0x17740fe (in-CGU, matched)"),
    (0x64111F0, "global_constants/src/aws_name.rs", 295, 68, "0x1773fd0..0x17740fe (in-CGU, matched)"),
    (0x6411208, "global_constants/src/aws_name.rs", 213, 29, "0x2e11b00..0x2e13c3a (cross-CGU caller inlining unimplemented!())"),
    (0x6411420, "global_constants/src/static_config.rs", 61, 17, "0x1778270..0x17782d7 (in-CGU, matched)"),
    (0x6411438, "global_constants/src/static_config.rs", 24, 9, "0x17785f0..0x177876f (in-CGU, matched)"),
]

AWS_NAME_RS = r"""#![forbid(unsafe_code)]
use serde::Deserialize;
use std::fmt;
use std::fs;
use std::str::FromStr;
use crate::static_config::{cham_dir, home_dir};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VariantNotFound;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[repr(u8)]
pub enum AwsName {
    Ec = 0, DummyTokyo = 1, DummyTokyo2 = 2, GaOnchain = 3, GbOnchain = 4,
    NodeTestnet = 5, NodeTestnet2 = 6, NodeTestnet3 = 7, NodeTestnet4 = 8,
    Ea = 9, Ea2 = 10, Ea3 = 11, EaMm = 12, EaTx = 13,
    HeavyTestnet = 14, HeavyMainnet = 15, Eb = 16, Ed = 17, Ee = 18,
    SoloTestnet = 19, SoloMainnet = 20, LockerTestnet = 21, LockerMainnet = 22,
    RpcTestnet = 23, RpcSandbox = 24, RpcMainnet = 25, RpcMainnet2 = 26,
    Sa = 27, Sb = 28, Sc = 29, Sd = 30, WebSandbox = 31, SoloSandbox = 32,
    NvTestnet = 33, NvTestnet2 = 34, NvMainnet = 35, NvMainnet2 = 36, NvMainnet3 = 37,
    JoinMainnet = 38, DummyNv = 39,
    FBinSpot = 40, FBinSpot2 = 41, FBinSpot3 = 42, FBinSpot4 = 43,
    FBinSpot5 = 44, FBinSpot6 = 45, FBinSpot7 = 46, FBinSpot8 = 47,
    FBinPerp = 48, FBinPerp2 = 49,
    FOkexSpot = 50, FOkexSpot2 = 51, FOkexPerp = 52,
    FHuobiSpot = 53, FHuobiSpot2 = 54, FHuobiSpot3 = 55, FHuobiSpot4 = 56,
    FHuobiPi = 57, FHuobiPerp = 58,
    FCobSpot = 59, FKraSpot = 60, FBybitSpot = 61,
    ScratchDummy = 62, ScratchCron = 63, OBinSpot = 64, FHlPerp = 65,
    GaHlPerp = 66, GaHlPerp2 = 67, GaHlPerp3 = 68,
    GbHlPerp = 69, GbHlPerp2 = 70, GbHlPerp3 = 71,
    GcHlPerp = 72, GcHlPerp2 = 73,
    GdHlPerp = 74, GdHlPerp2 = 75,
    GsHlPerp = 76, EaHlPerp = 77, EbHlPerp = 78,
}

impl fmt::Display for AwsName {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ec => f.pad("Ec"), Self::DummyTokyo => f.pad("DummyTokyo"),
            Self::DummyTokyo2 => f.pad("DummyTokyo2"), Self::GaOnchain => f.pad("GaOnchain"),
            Self::GbOnchain => f.pad("GbOnchain"), Self::NodeTestnet => f.pad("NodeTestnet"),
            Self::NodeTestnet2 => f.pad("NodeTestnet2"), Self::NodeTestnet3 => f.pad("NodeTestnet3"),
            Self::NodeTestnet4 => f.pad("NodeTestnet4"), Self::Ea => f.pad("Ea"),
            Self::Ea2 => f.pad("Ea2"), Self::Ea3 => f.pad("Ea3"),
            Self::EaMm => f.pad("EaMm"), Self::EaTx => f.pad("EaTx"),
            Self::HeavyTestnet => f.pad("HeavyTestnet"), Self::HeavyMainnet => f.pad("HeavyMainnet"),
            Self::Eb => f.pad("Eb"), Self::Ed => f.pad("Ed"), Self::Ee => f.pad("Ee"),
            Self::SoloTestnet => f.pad("SoloTestnet"), Self::SoloMainnet => f.pad("SoloMainnet"),
            Self::LockerTestnet => f.pad("LockerTestnet"), Self::LockerMainnet => f.pad("LockerMainnet"),
            Self::RpcTestnet => f.pad("RpcTestnet"), Self::RpcSandbox => f.pad("RpcSandbox"),
            Self::RpcMainnet => f.pad("RpcMainnet"), Self::RpcMainnet2 => f.pad("RpcMainnet2"),
            Self::Sa => f.pad("Sa"), Self::Sb => f.pad("Sb"),
            Self::Sc => f.pad("Sc"), Self::Sd => f.pad("Sd"),
            Self::WebSandbox => f.pad("WebSandbox"), Self::SoloSandbox => f.pad("SoloSandbox"),
            Self::NvTestnet => f.pad("NvTestnet"), Self::NvTestnet2 => f.pad("NvTestnet2"),
            Self::NvMainnet => f.pad("NvMainnet"), Self::NvMainnet2 => f.pad("NvMainnet2"),
            Self::NvMainnet3 => f.pad("NvMainnet3"), Self::JoinMainnet => f.pad("JoinMainnet"),
            Self::DummyNv => f.pad("DummyNv"),
            Self::FBinSpot => f.pad("FBinSpot"), Self::FBinSpot2 => f.pad("FBinSpot2"),
            Self::FBinSpot3 => f.pad("FBinSpot3"), Self::FBinSpot4 => f.pad("FBinSpot4"),
            Self::FBinSpot5 => f.pad("FBinSpot5"), Self::FBinSpot6 => f.pad("FBinSpot6"),
            Self::FBinSpot7 => f.pad("FBinSpot7"), Self::FBinSpot8 => f.pad("FBinSpot8"),
            Self::FBinPerp => f.pad("FBinPerp"), Self::FBinPerp2 => f.pad("FBinPerp2"),
            Self::FOkexSpot => f.pad("FOkexSpot"), Self::FOkexSpot2 => f.pad("FOkexSpot2"),
            Self::FOkexPerp => f.pad("FOkexPerp"),
            Self::FHuobiSpot => f.pad("FHuobiSpot"), Self::FHuobiSpot2 => f.pad("FHuobiSpot2"),
            Self::FHuobiSpot3 => f.pad("FHuobiSpot3"), Self::FHuobiSpot4 => f.pad("FHuobiSpot4"),
            Self::FHuobiPi => f.pad("FHuobiPi"), Self::FHuobiPerp => f.pad("FHuobiPerp"),
            Self::FCobSpot => f.pad("FCobSpot"), Self::FKraSpot => f.pad("FKraSpot"),
            Self::FBybitSpot => f.pad("FBybitSpot"),
            Self::ScratchDummy => f.pad("ScratchDummy"), Self::ScratchCron => f.pad("ScratchCron"),
            Self::OBinSpot => f.pad("OBinSpot"), Self::FHlPerp => f.pad("FHlPerp"),
            Self::GaHlPerp => f.pad("GaHlPerp"), Self::GaHlPerp2 => f.pad("GaHlPerp2"),
            Self::GaHlPerp3 => f.pad("GaHlPerp3"),
            Self::GbHlPerp => f.pad("GbHlPerp"), Self::GbHlPerp2 => f.pad("GbHlPerp2"),
            Self::GbHlPerp3 => f.pad("GbHlPerp3"),
            Self::GcHlPerp => f.pad("GcHlPerp"), Self::GcHlPerp2 => f.pad("GcHlPerp2"),
            Self::GdHlPerp => f.pad("GdHlPerp"), Self::GdHlPerp2 => f.pad("GdHlPerp2"),
            Self::GsHlPerp => f.pad("GsHlPerp"), Self::EaHlPerp => f.pad("EaHlPerp"),
            Self::EbHlPerp => f.pad("EbHlPerp"),
        }
    }
}

impl FromStr for AwsName {
    type Err = VariantNotFound;
    #[inline(never)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s {
            "Ec" => Self::Ec, "DummyTokyo" => Self::DummyTokyo, "DummyTokyo2" => Self::DummyTokyo2,
            "GaOnchain" => Self::GaOnchain, "GbOnchain" => Self::GbOnchain,
            "NodeTestnet" => Self::NodeTestnet, "NodeTestnet2" => Self::NodeTestnet2,
            "NodeTestnet3" => Self::NodeTestnet3, "NodeTestnet4" => Self::NodeTestnet4,
            "Ea" => Self::Ea, "Ea2" => Self::Ea2, "Ea3" => Self::Ea3, "EaMm" => Self::EaMm, "EaTx" => Self::EaTx,
            "HeavyTestnet" => Self::HeavyTestnet, "HeavyMainnet" => Self::HeavyMainnet,
            "Eb" => Self::Eb, "Ed" => Self::Ed, "Ee" => Self::Ee,
            "SoloTestnet" => Self::SoloTestnet, "SoloMainnet" => Self::SoloMainnet,
            "LockerTestnet" => Self::LockerTestnet, "LockerMainnet" => Self::LockerMainnet,
            "RpcTestnet" => Self::RpcTestnet, "RpcSandbox" => Self::RpcSandbox,
            "RpcMainnet" => Self::RpcMainnet, "RpcMainnet2" => Self::RpcMainnet2,
            "Sa" => Self::Sa, "Sb" => Self::Sb, "Sc" => Self::Sc, "Sd" => Self::Sd,
            "WebSandbox" => Self::WebSandbox, "SoloSandbox" => Self::SoloSandbox,
            "NvTestnet" => Self::NvTestnet, "NvTestnet2" => Self::NvTestnet2,
            "NvMainnet" => Self::NvMainnet, "NvMainnet2" => Self::NvMainnet2, "NvMainnet3" => Self::NvMainnet3,
            "JoinMainnet" => Self::JoinMainnet, "DummyNv" => Self::DummyNv,
            "FBinSpot" => Self::FBinSpot, "FBinSpot2" => Self::FBinSpot2, "FBinSpot3" => Self::FBinSpot3,
            "FBinSpot4" => Self::FBinSpot4, "FBinSpot5" => Self::FBinSpot5, "FBinSpot6" => Self::FBinSpot6,
            "FBinSpot7" => Self::FBinSpot7, "FBinSpot8" => Self::FBinSpot8,
            "FBinPerp" => Self::FBinPerp, "FBinPerp2" => Self::FBinPerp2,
            "FOkexSpot" => Self::FOkexSpot, "FOkexSpot2" => Self::FOkexSpot2, "FOkexPerp" => Self::FOkexPerp,
            "FHuobiSpot" => Self::FHuobiSpot, "FHuobiSpot2" => Self::FHuobiSpot2,
            "FHuobiSpot3" => Self::FHuobiSpot3, "FHuobiSpot4" => Self::FHuobiSpot4,
            "FHuobiPi" => Self::FHuobiPi, "FHuobiPerp" => Self::FHuobiPerp,
            "FCobSpot" => Self::FCobSpot, "FKraSpot" => Self::FKraSpot, "FBybitSpot" => Self::FBybitSpot,
            "ScratchDummy" => Self::ScratchDummy, "ScratchCron" => Self::ScratchCron,
            "OBinSpot" => Self::OBinSpot, "FHlPerp" => Self::FHlPerp,
            "GaHlPerp" => Self::GaHlPerp, "GaHlPerp2" => Self::GaHlPerp2, "GaHlPerp3" => Self::GaHlPerp3,
            "GbHlPerp" => Self::GbHlPerp, "GbHlPerp2" => Self::GbHlPerp2, "GbHlPerp3" => Self::GbHlPerp3,
            "GcHlPerp" => Self::GcHlPerp, "GcHlPerp2" => Self::GcHlPerp2,
            "GdHlPerp" => Self::GdHlPerp, "GdHlPerp2" => Self::GdHlPerp2,
            "GsHlPerp" => Self::GsHlPerp, "EaHlPerp" => Self::EaHlPerp, "EbHlPerp" => Self::EbHlPerp,
            _ => return Err(VariantNotFound),
        };
        Ok(v)
    }
}

#[inline(never)]
pub fn aws_name_path() -> String {
    let home = home_dir();
    let cham = cham_dir(&home);
    format!("{cham}/aws_name")
}

#[inline(never)]
pub fn read_aws_name_fallback() -> AwsName {
    fs::read_to_string(aws_name_path()).unwrap().trim().parse().unwrap()
}
"""

STATIC_CONFIG_RS = r"""#![forbid(unsafe_code)]
use serde::Deserialize;
use std::fs;
use std::sync::LazyLock;
use crate::aws_name::{read_aws_name_fallback, AwsName};

#[derive(Debug)]
pub struct StaticConfig {
    pub home_dir: String,
    pub cham_dir: String,
    pub code_dir: String,
    pub aws_name: AwsName,
}

mod file_repr {
    use super::*;
    #[derive(Deserialize)]
    pub struct StaticConfig {
        #[serde(default = "read_aws_name_fallback")]
        pub aws_name: AwsName,
    }
}

#[inline(never)]
pub fn home_dir() -> String {
    fn inner() -> Option<String> {
        #[allow(deprecated)]
        let p = std::env::home_dir()?;
        Some(p.to_str()?.to_string())
    }
    inner().unwrap_or_default()
}

#[inline(never)]
pub fn cham_dir(home_dir: &str) -> String {
    let cham = format!("{home_dir}/cham");
    if fs::metadata(&cham).map(|m| m.is_dir()).unwrap_or(false) {
        cham
    } else {
        let hl = format!("{home_dir}/hl");
        if !fs::metadata(&hl).map(|m| m.is_dir()).unwrap_or(false) {
            fs::create_dir_all(&hl).unwrap_or_else(|err| panic!("could not create {hl}: {err}"));
        }
        hl
    }
}

#[inline(never)]
pub fn read_aws_name(code_dir: &str) -> AwsName {
    let path = format!("{code_dir}/static_config");
    fs::read_to_string(&path)
        .ok()
        .and_then(|c| serde_json::from_str::<file_repr::StaticConfig>(&c).ok())
        .map(|cfg| cfg.aws_name)
        .unwrap_or(AwsName::NvTestnet)
}

#[inline(never)]
pub fn new_static_config() -> StaticConfig {
    let home = home_dir();
    let cham = cham_dir(&home);
    assert!(
        fs::metadata(&cham).map(|m| m.is_dir()).unwrap_or(false),
        "cham_dir does not exist: {cham}"
    );
    let code = format!("{cham}/code");
    let aws_name = read_aws_name(&code);
    StaticConfig { home_dir: home, cham_dir: cham, code_dir: code, aws_name }
}

pub static STATIC_CONFIG: LazyLock<StaticConfig> = LazyLock::new(new_static_config);
"""


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    if not FDE_TSV.exists():
        return fdes
    with FDE_TSV.open("r", encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                s = int(parts[0], 16) if parts[0].startswith("0x") else int(parts[0])
                e = int(parts[1], 16) if parts[1].startswith("0x") else int(parts[1])
                fdes[s] = e
    return fdes


def _make_va_to_off(data: bytes):
    secs = {s["name"]: s for s in sections(data)}

    def va_to_off(va: int) -> int:
        for s in secs.values():
            if s["address"] <= va < s["address"] + s["size"]:
                return s["offset"] + (va - s["address"])
        raise AssertionError(f"VA {hex(va)} not mapped")

    return va_to_off, secs


def verify_locations(data: bytes) -> list[dict]:
    va_to_off, secs = _make_va_to_off(data)
    rela = secs[".rela.dyn"]
    relmap: dict[int, int] = {}
    for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
        r_offset, _r_info, r_addend = struct.unpack_from("<QQq", data, off)
        relmap[r_offset] = r_addend

    verified = []
    for loc_va, exp_path, exp_line, exp_col, scope in EXPECTED_GLOBAL_CONSTANTS_LOCATIONS:
        foff = va_to_off(loc_va)
        ptr = relmap.get(loc_va)
        if ptr is None:
            raise AssertionError(f"missing .rela.dyn entry for Location {hex(loc_va)}")
        ln, line, col = struct.unpack_from("<QII", data, foff + 8)
        path_str = data[va_to_off(ptr) : va_to_off(ptr) + ln].decode("utf-8")
        if (path_str, line, col) != (exp_path, exp_line, exp_col):
            raise AssertionError(
                f"Location {hex(loc_va)} mismatch: got {(path_str, line, col)}, expected {(exp_path, exp_line, exp_col)}"
            )
        verified.append(
            {
                "location_va": hex(loc_va),
                "file": path_str,
                "line": line,
                "col": col,
                "scope": scope,
            }
        )
    return verified


def compile_thinlto_workspace(
    target_dir: Path | None = None,
) -> tuple[list[tuple[str, bytes, list[dict]]], str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "global_constants" / "src").mkdir(parents=True)
        (root / "app" / "src").mkdir(parents=True)

        (root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["global_constants", "app"]\nresolver = "2"\n\n'
            '[profile.release]\nopt-level = 3\nlto = "thin"\noverflow-checks = true\n',
            encoding="utf-8",
        )
        (root / "global_constants" / "Cargo.toml").write_text(
            '[package]\nname = "global_constants"\nversion = "0.1.0"\nedition = "2021"\n\n'
            '[dependencies]\nserde = { version = "=1.0.229", features = ["derive"] }\n'
            'serde_json = { version = "=1.0.154", features = ["raw_value", "unbounded_depth"] }\n',
            encoding="utf-8",
        )
        (root / "app" / "Cargo.toml").write_text(
            '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n'
            '[dependencies]\nglobal_constants = { path = "../global_constants" }\n'
            'serde_json = { version = "=1.0.154", features = ["raw_value", "unbounded_depth"] }\n'
            'tikv-jemallocator = "=0.6.0"\n',
            encoding="utf-8",
        )
        (root / "global_constants" / "src" / "lib.rs").write_text(
            "#![forbid(unsafe_code)]\npub mod aws_name;\npub mod static_config;\n"
            "pub use aws_name::{aws_name_path, read_aws_name_fallback, AwsName, VariantNotFound};\n"
            "pub use static_config::{cham_dir, home_dir, read_aws_name, StaticConfig, STATIC_CONFIG};\n",
            encoding="utf-8",
        )
        (root / "global_constants" / "src" / "aws_name.rs").write_text(AWS_NAME_RS, encoding="utf-8")
        (root / "global_constants" / "src" / "static_config.rs").write_text(
            STATIC_CONFIG_RS, encoding="utf-8"
        )
        (root / "app" / "src" / "main.rs").write_text(
            "#[global_allocator]\nstatic ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;\n"
            "fn main() {\n"
            "    let cfg = &*global_constants::STATIC_CONFIG;\n"
            '    println!("{} {} {} {}", cfg.home_dir, cfg.cham_dir, cfg.code_dir, cfg.aws_name);\n'
            "    let _ = std::hint::black_box(global_constants::aws_name_path());\n"
            "    let _ = std::hint::black_box(global_constants::read_aws_name_fallback());\n"
            "    let _ = std::hint::black_box(global_constants::home_dir());\n"
            '    let _ = std::hint::black_box(global_constants::cham_dir("/tmp"));\n'
            '    let _ = std::hint::black_box(global_constants::read_aws_name("/tmp"));\n'
            '    let s = std::hint::black_box(String::from("{}"));\n'
            "    let _ = std::hint::black_box(serde_json::from_str::<serde_json::Value>(&s));\n"
            "}\n",
            encoding="utf-8",
        )

        tdir = target_dir if target_dir is not None else (root / "target")
        deps = tdir / "release" / "deps"
        if deps.exists():
            for old_o in deps.glob("app-*.o"):
                old_o.unlink()

        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(tdir)
        env["CARGO_BUILD_JOBS"] = env.get("CARGO_BUILD_JOBS", "4")
        env["RUSTFLAGS"] = "-C save-temps"
        subprocess.run(
            [
                "cargo",
                "+1.95.0",
                "build",
                "--offline",
                "--release",
                "--manifest-path",
                str(root / "Cargo.toml"),
            ],
            env=env,
            check=True,
        )

        app_objs = sorted(deps.glob("app-*.o"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not app_objs:
            raise AssertionError("no ThinLTO object files emitted")
        newest_prefix = app_objs[0].name.split(".")[0]
        compiled = []
        for obj_path in sorted(deps.glob(f"{newest_prefix}.*.o")):
            for syms, c_bytes, rels in object_functions(obj_path.read_bytes()):
                rel_dicts = [
                    {"offset": r[0], "type": r[1], "addend": r[2], "width": 4}
                    for r in rels
                ]
                compiled.append((syms[0] if syms else "", c_bytes, rel_dicts))
        return compiled, ver


def _assert_first_party_symbol(sym: str) -> None:
    if "global_constants" not in sym:
        raise AssertionError(f"symbol is not first-party global_constants: {sym}")
    for forbidden in ("4core", "5alloc", "3std", "10serde_json", "10serde_core"):
        if sym.startswith(f"_ZN{forbidden}") or sym.startswith("_RNvNtC"):
            raise AssertionError(f"stdlib/dependency symbol not allowed in first-party rows: {sym}")


def build_records(data: bytes, target_dir: Path | None = None) -> tuple[dict, bytes]:
    if len(data) != EXPECTED_BINARY_SIZE:
        raise AssertionError(f"size mismatch: {len(data)}")
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_BINARY_SHA256:
        raise AssertionError(f"sha256 mismatch: {sha}")

    va_to_off, _ = _make_va_to_off(data)
    fdes = load_fde_map()
    verified_locs = verify_locations(data)
    compiled, rustc_version = compile_thinlto_workspace(target_dir=target_dir)

    def match_target(start_va: int, end_va: int):
        if fdes and fdes.get(start_va) != end_va:
            raise AssertionError(
                f"FDE mismatch at {hex(start_va)}: expected {hex(end_va)}, got {fdes.get(start_va)}"
            )
        t_bytes = data[va_to_off(start_va) : va_to_off(end_va)]
        for sym, c_bytes, rels in compiled:
            if len(c_bytes) == len(t_bytes):
                cmp_res = compare(c_bytes, t_bytes, rels)
                if cmp_res["relocation_qualified"] and not cmp_res["non_relocation_difference_offsets"]:
                    return sym, t_bytes, c_bytes, rels, cmp_res
        raise AssertionError(
            f"no relocation-qualified compiled match for {hex(start_va)}..{hex(end_va)} ({end_va - start_va} B)"
        )

    # Audit that all 36 previously matched CGU FDEs AND all 12/12 first-party CGU FDEs reproduce together
    reproduced_prev = 0
    for sva, eva in PREVIOUSLY_MATCHED_CGU:
        match_target(sva, eva)
        reproduced_prev += 1

    fp_reproduced = 0
    fp_bytes = 0
    for sva, eva in ALL_FIRST_PARTY_CGU_FDES:
        sym, _, _, _, _ = match_target(sva, eva)
        _assert_first_party_symbol(sym)
        fp_reproduced += 1
        fp_bytes += eva - sva

    bodies = bytearray()
    rows = []
    total_bytes = 0
    total_raw_equal = 0

    for start_va, end_va, attr, label in NEW_WINDOWS:
        sym, t_bytes, c_bytes, rels, cmp_res = match_target(start_va, end_va)
        _assert_first_party_symbol(sym)
        sz = end_va - start_va
        src_off = len(bodies)
        bodies.extend(c_bytes)
        total_bytes += sz
        total_raw_equal += cmp_res["raw_equal_bytes"]
        rows.append(
            {
                "component": "constants",
                "attribution": attr,
                "symbol": sym,
                "start": hex(start_va),
                "end": hex(end_va),
                "bytes": sz,
                "source_offset": src_off,
                "label": label,
                "target_body_sha256": hashlib.sha256(t_bytes).hexdigest(),
                "compiled_body_sha256": hashlib.sha256(c_bytes).hexdigest(),
                "raw_equal_bytes": cmp_res["raw_equal_bytes"],
                "relocation_bytes": cmp_res["relocation_bytes"],
                "relocation_qualified": True,
                "relocations": rels,
            }
        )

    bodies_bytes = bytes(bodies)
    records = {
        "work_item": "RE-015-node115-constants-first-party-100pct-byte-matches",
        "target_path": "artifacts/node/115/hl-node",
        "target_sha256": sha,
        "rustc_version": rustc_version,
        "build_profile": {
            "opt_level": 3,
            "lto": "thin",
            "overflow_checks": True,
            "global_allocator": "tikv-jemallocator 0.6.0",
            "serde": "1.0.229 (derive)",
            "serde_json": "1.0.154 (raw_value, unbounded_depth)",
            "unmodified_registry_crates": True,
        },
        "bodies_sha256": hashlib.sha256(bodies_bytes).hexdigest(),
        "summary": {
            "windows": len(rows),
            "total_bytes": total_bytes,
            "raw_equal_bytes": total_raw_equal,
            "relocation_qualified_windows": len(rows),
            "first_party_cgu_matched_fdes": fp_reproduced,
            "first_party_cgu_total_fdes": len(ALL_FIRST_PARTY_CGU_FDES),
            "first_party_cgu_matched_bytes": fp_bytes,
            "first_party_cgu_total_bytes": sum(e - s for s, e in ALL_FIRST_PARTY_CGU_FDES),
            "cgu_previously_matched_reproduced": reproduced_prev,
            "cgu_total_matched_fdes": len(rows) + reproduced_prev,
            "cgu_total_fdes": 40,
            "cgu_total_matched_bytes": total_bytes + sum(e - s for s, e in PREVIOUSLY_MATCHED_CGU),
            "cgu_total_bytes": 23050,
            "global_constants_locations_verified": len(verified_locs),
            "identity_gate_satisfied": False,
        },
        "global_constants_locations": verified_locs,
        "residual_third_party_cgu_fdes": RESIDUAL_THIRD_PARTY_CGU,
        "windows": rows,
    }
    return records, bodies_bytes


def verify_records(
    records: dict,
    data: bytes,
    bodies: bytes,
    rebuild: bool = False,
    target_dir: Path | None = None,
) -> None:
    if records.get("target_sha256") != EXPECTED_BINARY_SHA256:
        raise AssertionError("target_sha256 mismatch in records")
    if len(data) != EXPECTED_BINARY_SIZE or hashlib.sha256(data).hexdigest() != EXPECTED_BINARY_SHA256:
        raise AssertionError("binary authentication failed")
    if hashlib.sha256(bodies).hexdigest() != records.get("bodies_sha256"):
        raise AssertionError("bodies.bin sha256 mismatch")

    va_to_off, _ = _make_va_to_off(data)
    fdes = load_fde_map()
    verified_locs = verify_locations(data)
    if records.get("global_constants_locations") != verified_locs:
        raise AssertionError("global_constants_locations mismatch")

    seen = set()
    tot_b = 0
    tot_raw = 0
    for row in records["windows"]:
        _assert_first_party_symbol(row["symbol"])
        s = int(row["start"], 16)
        e = int(row["end"], 16)
        if s in seen:
            raise AssertionError(f"duplicate start {hex(s)}")
        seen.add(s)
        if fdes and fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch at {hex(s)}: expected {hex(e)}, got {fdes.get(s)}")
        sz = e - s
        if sz != row["bytes"]:
            raise AssertionError(f"size mismatch at {hex(s)}")
        t_bytes = data[va_to_off(s) : va_to_off(e)]
        if hashlib.sha256(t_bytes).hexdigest() != row["target_body_sha256"]:
            raise AssertionError(f"target body sha mismatch at {hex(s)}")
        off = row["source_offset"]
        c_bytes = bodies[off : off + sz]
        if len(c_bytes) != sz or hashlib.sha256(c_bytes).hexdigest() != row["compiled_body_sha256"]:
            raise AssertionError(f"compiled body sha mismatch at {hex(s)}")
        cmp_res = compare(c_bytes, t_bytes, row["relocations"])
        if not cmp_res["relocation_qualified"] or cmp_res["non_relocation_difference_offsets"]:
            raise AssertionError(f"not relocation-qualified at {hex(s)}: {cmp_res}")
        if cmp_res["raw_equal_bytes"] != row["raw_equal_bytes"]:
            raise AssertionError(f"raw_equal_bytes mismatch at {hex(s)}")
        tot_b += sz
        tot_raw += cmp_res["raw_equal_bytes"]

    if tot_b != records["summary"]["total_bytes"] or tot_raw != records["summary"]["raw_equal_bytes"]:
        raise AssertionError("summary totals mismatch")

    if rebuild:
        fresh_recs, fresh_bodies = build_records(data, target_dir=target_dir)
        if fresh_bodies != bodies:
            raise AssertionError("rebuilt bodies.bin differs from committed bodies.bin")
        if fresh_recs["summary"] != records["summary"]:
            raise AssertionError("rebuilt summary differs from committed records.json")
        if len(fresh_recs["windows"]) != len(records["windows"]):
            raise AssertionError("rebuilt window count mismatch")
        for fw, cw in zip(fresh_recs["windows"], records["windows"]):
            for k in (
                "start",
                "end",
                "bytes",
                "source_offset",
                "target_body_sha256",
                "compiled_body_sha256",
                "raw_equal_bytes",
                "relocations",
            ):
                if fw[k] != cw[k]:
                    raise AssertionError(f"rebuilt mismatch on {cw['start']} field {k}")


def run_negative_controls(records: dict, data: bytes, bodies: bytes) -> int:
    rejected = 0

    # 1. Tampered target_sha256
    bad1 = copy.deepcopy(records)
    bad1["target_sha256"] = "0" * 64
    try:
        verify_records(bad1, data, bodies, rebuild=False)
    except AssertionError:
        rejected += 1

    # 2. Tampered target_body_sha256 on read_aws_name (0x17783e0)
    bad2 = copy.deepcopy(records)
    bad2["windows"][1]["target_body_sha256"] = "f" * 64
    try:
        verify_records(bad2, data, bodies, rebuild=False)
    except AssertionError:
        rejected += 1

    # 3. Single unmasked non-relocation byte flip in compiled body (home_dir)
    row = records["windows"][0]
    masked = set()
    for rel in row["relocations"]:
        masked.update(range(rel["offset"], rel["offset"] + rel["width"]))
    unmasked_idx = next(i for i in range(row["bytes"]) if i not in masked)
    bad_bodies = bytearray(bodies)
    bad_bodies[row["source_offset"] + unmasked_idx] ^= 0xFF
    bad3 = copy.deepcopy(records)
    bad3["bodies_sha256"] = hashlib.sha256(bytes(bad_bodies)).hexdigest()
    bad3["windows"][0]["compiled_body_sha256"] = hashlib.sha256(
        bytes(bad_bodies[row["source_offset"] : row["source_offset"] + row["bytes"]])
    ).hexdigest()
    try:
        verify_records(bad3, data, bytes(bad_bodies), rebuild=False)
    except AssertionError:
        rejected += 1

    # 4. Dropped relocation entry on read_aws_name breaks qualification
    bad4 = copy.deepcopy(records)
    bad4["windows"][1]["relocations"] = bad4["windows"][1]["relocations"][1:]
    try:
        verify_records(bad4, data, bodies, rebuild=False)
    except AssertionError:
        rejected += 1

    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--rebuild", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--target-dir", type=Path, default=None)
    args = ap.parse_args()

    data = BINARY_PATH.read_bytes()
    if args.generate:
        recs, bodies = build_records(data, target_dir=args.target_dir)
        BODIES_PATH.write_bytes(bodies)
        RECORDS_PATH.write_text(json.dumps(recs, indent=2) + "\n", encoding="utf-8")
        s = recs["summary"]
        print(
            f"Generated {s['windows']} new first-party windows ({s['total_bytes']} B, "
            f"{s['raw_equal_bytes']} raw-equal; first-party CGU "
            f"{s['first_party_cgu_matched_fdes']}/{s['first_party_cgu_total_fdes']} = "
            f"{s['first_party_cgu_matched_bytes']}/{s['first_party_cgu_total_bytes']} B; "
            f"total CGU {s['cgu_total_matched_fdes']}/{s['cgu_total_fdes']} = "
            f"{s['cgu_total_matched_bytes']}/{s['cgu_total_bytes']} B)"
        )
        return 0

    recs = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    bodies = BODIES_PATH.read_bytes()
    verify_records(recs, data, bodies, rebuild=args.rebuild, target_dir=args.target_dir)
    if args.self_test:
        rej = run_negative_controls(recs, data, bodies)
        if rej != 4:
            raise AssertionError(f"expected 4 rejected negative controls, got {rej}")
        s = recs["summary"]
        print(
            f"SELF-TEST OK: {s['windows']}/{s['windows']} first-party relocation-qualified "
            f"({s['total_bytes']} B, {s['raw_equal_bytes']} raw-equal; "
            f"first-party CGU {s['first_party_cgu_matched_fdes']}/{s['first_party_cgu_total_fdes']} = "
            f"{s['first_party_cgu_matched_bytes']}/{s['first_party_cgu_total_bytes']} B; "
            f"total CGU {s['cgu_total_matched_fdes']}/{s['cgu_total_fdes']} = "
            f"{s['cgu_total_matched_bytes']}/{s['cgu_total_bytes']} B; "
            f"5/5 Locations verified; rebuild={args.rebuild}), 4/4 negative controls rejected"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
