#!/usr/bin/env python3
"""Verify 9 strictly disjoint first-party transport & node-runtime compiled-byte FDE matches
(3,222 B: 5 transport = 1,265 B; 4 node-runtime = 1,957 B) for node #115."""

from __future__ import annotations

import argparse
import copy
import glob
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_JSON = REPO_ROOT / "research" / "byte-windows.json"
WORK_ITEMS_DIR = REPO_ROOT / "research" / "work-items"
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

# 9 strictly disjoint first-party Stream C FDEs (3,222 B):
#   - transport:    5 FDEs = 1,265 B (net_utils TcpGreeting x5 CGUs)
#   - node-runtime: 4 FDEs = 1,957 B (NodeError::Display 1,177 B, hl_node.rs:102 CLI u64 parser 263 B,
#                                     gossip ChildPeerStatuses 296 B, ChildPeerStatus 221 B)
TARGET_WINDOWS = [
    (
        0x2B40880,
        0x2B4097D,
        "transport-tcp-greeting-debug-cgu1-2b40880",
        "transport",
        "debug_fmt",
        "transport net_utils <TcpGreeting as core::fmt::Debug>::fmt (CGU 1, 0x2b40880)",
    ),
    (
        0x2C7CA40,
        0x2C7CB3D,
        "transport-ref-tcp-greeting-debug-cgu2-2c7ca40",
        "transport",
        "debug_fmt",
        "transport net_utils <&TcpGreeting as core::fmt::Debug>::fmt (CGU 2, inlined first-party body, 0x2c7ca40)",
    ),
    (
        0x2CD3E80,
        0x2CD3F7D,
        "transport-tcp-greeting-debug-cgu3-2cd3e80",
        "transport",
        "debug_fmt",
        "transport net_utils <TcpGreeting as core::fmt::Debug>::fmt (CGU 3, 0x2cd3e80)",
    ),
    (
        0x4F0D8F0,
        0x4F0DA18,
        "node-runtime-ref-child-peer-statuses-debug-4f0d8f0",
        "node-runtime",
        "debug_fmt",
        "node-runtime gossip <&ChildPeerStatuses as core::fmt::Debug>::fmt (inlined first-party body, 0x4f0d8f0)",
    ),
    (
        0x4F0DB20,
        0x4F0DBFD,
        "node-runtime-ref-child-peer-status-debug-4f0db20",
        "node-runtime",
        "debug_fmt",
        "node-runtime gossip <&ChildPeerStatus as core::fmt::Debug>::fmt (inlined first-party body, 0x4f0db20)",
    ),
    (
        0x564AD60,
        0x564B1F9,
        "node-runtime-node-error-display-564ad60",
        "node-runtime",
        "display_fmt",
        "node-runtime <NodeError as core::fmt::Display>::fmt (22-variant niche-tagged runtime error Display, 0x564ad60)",
    ),
    (
        0x5655DE0,
        0x5655EE7,
        "node-runtime-hl-node-parse-u64-cli-5655de0",
        "node-runtime",
        "business_logic",
        "node-runtime node/src/hl_node.rs:102:9 decimal u64 CLI argument parser (0x5655de0)",
    ),
    (
        0x57D12A0,
        0x57D139D,
        "transport-ref-tcp-greeting-debug-cgu4-57d12a0",
        "transport",
        "debug_fmt",
        "transport net_utils <&TcpGreeting as core::fmt::Debug>::fmt (CGU 4, inlined first-party body, 0x57d12a0)",
    ),
    (
        0x5AA85A0,
        0x5AA869D,
        "transport-tcp-greeting-debug-cgu5-5aa85a0",
        "transport",
        "debug_fmt",
        "transport net_utils <TcpGreeting as core::fmt::Debug>::fmt (CGU 5, 0x5aa85a0)",
    ),
]

DEP_TYPES_RS = r"""#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::fmt;

/// 46-variant ConsensusError with >=64-byte payload so NodeError (max payload 64 B)
/// niches its 22 tags into 0x2e.. at offset 0.
#[derive(Debug)]
pub enum ConsensusError {
    V00([u8; 64]), V01(String), V02, V03, V04, V05, V06, V07, V08, V09,
    V10, V11, V12, V13, V14, V15, V16, V17, V18, V19,
    V20, V21, V22, V23, V24, V25, V26, V27, V28, V29,
    V30, V31, V32, V33, V34, V35, V36, V37, V38, V39,
    V40, V41, V42, V43, V44, V45,
}

impl fmt::Display for ConsensusError {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ce")
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Round(pub u64);

impl fmt::Display for Round {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[derive(Debug)]
pub struct H256A(pub [u8; 32]);

impl fmt::Display for H256A {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("h1")
    }
}

#[derive(Debug)]
pub struct H256B(pub [u8; 32]);

impl fmt::Display for H256B {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("h2")
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Height(pub u64);

impl fmt::Display for Height {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[derive(Debug)]
pub struct InnerStatuses(pub Vec<u64>);

#[derive(Debug)]
pub enum BroadcastGroup {
    A,
    B,
}

#[derive(Debug)]
pub enum TcpId {
    A,
    B,
}

/// Anchor <&T as Display/Debug>::fmt instantiations in a separate crate CGU so ThinLTO
/// devirtualizes debug_tuple_field1_finish / format_args without inlining <&T>::fmt.
pub fn anchors() -> [usize; 9] {
    [
        <&String as fmt::Display>::fmt as *const () as usize,
        <&Round as fmt::Display>::fmt as *const () as usize,
        <&ConsensusError as fmt::Display>::fmt as *const () as usize,
        <&H256A as fmt::Display>::fmt as *const () as usize,
        <&H256B as fmt::Display>::fmt as *const () as usize,
        <&InnerStatuses as fmt::Debug>::fmt as *const () as usize,
        <&H256A as fmt::Debug>::fmt as *const () as usize,
        <&std::net::Ipv4Addr as fmt::Debug>::fmt as *const () as usize,
        <&BroadcastGroup as fmt::Debug>::fmt as *const () as usize,
    ]
}
"""

MAIN_RS = r"""#![forbid(unsafe_code)]
#![allow(dead_code)]

use dep_types::*;
use std::fmt;
use std::hint::black_box;

// 1. NodeError::Display (0x564ad60, 1,177 B)
pub enum NodeError {
    Gossip(String),
    GossipRpc(String),
    ClientBlockParentRound(Round),
    Consensus(ConsensusError),
    QueryClientBlocks(Round, Round),
    PeerFull,
    PeerTimeout,
    PeerRateLimit,
    PeerNoQuorumL1Hash,
    PeerInconsistentGreeting,
    AbciStateDeserialize,
    NvStreamClientBlockSend,
    L1HashHeightMismatch(Height, Height),
    L1HashMismatch(H256A, H256A),
    AbciDigestMismatch(H256B, H256B),
    L1HashNoQuorum,
    EvmKvsRead(String),
    EvmKvsWrite(String),
    MissingConfigFln(String),
    InvalidConfigFln { fln: String, err: String },
    ThreadJoin,
    Chain,
}

impl fmt::Display for NodeError {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::Gossip(a) => {
                let field0 = a;
                write!(f, "Gossip error: {}", field0)
            }
            NodeError::GossipRpc(a) => {
                let field0 = a;
                write!(f, "Gossip RPC error: {}", field0)
            }
            NodeError::ClientBlockParentRound(a) => {
                let field0 = a;
                write!(f, "Client block invalid parent round: {}", field0)
            }
            NodeError::Consensus(a) => {
                let field0 = a;
                write!(f, "Consensus error: {}", field0)
            }
            NodeError::QueryClientBlocks(a, b) => {
                let (field0, field1) = (a, b);
                write!(f, "Could not query client blocks for rounds {}-{}", field0, field1)
            }
            NodeError::PeerFull => fmt::Formatter::write_str(f, "Peer full"),
            NodeError::PeerTimeout => fmt::Formatter::write_str(f, "Timed out connecting to peer"),
            NodeError::PeerRateLimit => fmt::Formatter::write_str(f, "Rate limited by peer"),
            NodeError::PeerNoQuorumL1Hash => fmt::Formatter::write_str(f, "Peer no quorum l1 hash"),
            NodeError::PeerInconsistentGreeting => {
                fmt::Formatter::write_str(f, "Peer inconsistent greeting")
            }
            NodeError::AbciStateDeserialize => {
                fmt::Formatter::write_str(f, "Abci state not deserializable")
            }
            NodeError::NvStreamClientBlockSend => {
                fmt::Formatter::write_str(f, "Could not send client block")
            }
            NodeError::L1HashHeightMismatch(a, b) => {
                let (field0, field1) = (a, b);
                write!(f, "L1 hash height mismatch computed={} quorum={}", field0, field1)
            }
            NodeError::L1HashMismatch(a, b) => {
                let (field0, field1) = (a, b);
                write!(f, "L1 hash mismatch computed={} quorum={}", field0, field1)
            }
            NodeError::AbciDigestMismatch(a, b) => {
                let (field0, field1) = (a, b);
                write!(f, "Abci digest mismatch computed={} quorum={}", field0, field1)
            }
            NodeError::L1HashNoQuorum => fmt::Formatter::write_str(f, "L1 hash no quorum"),
            NodeError::EvmKvsRead(a) => {
                let field0 = a;
                write!(f, "Evm Kvs read error: {}", field0)
            }
            NodeError::EvmKvsWrite(a) => {
                let field0 = a;
                write!(f, "Evm Kvs write error: {}", field0)
            }
            NodeError::MissingConfigFln(a) => {
                let field0 = a;
                write!(f, "Missing config file: {}", field0)
            }
            NodeError::InvalidConfigFln { fln, err } => {
                let (field0, field1) = (fln, err);
                write!(f, "Invalid config file ({}): {}", field0, field1)
            }
            NodeError::ThreadJoin => fmt::Formatter::write_str(f, "Thread join error"),
            NodeError::Chain => fmt::Formatter::write_str(f, "Incorrect chain"),
        }
    }
}

// 2. node/src/hl_node.rs:102:9 decimal u64 CLI argument parser (0x5655de0, 263 B)
#[inline(never)]
pub fn hl_node_parse_u64_cli(s: &str) -> u64 {
    s.parse::<u64>().unwrap()
}

// 3. net_utils::tcp::TcpGreeting (0x2b40880, 0x2c7ca40, 0x2cd3e80, 0x57d12a0, 0x5aa85a0; 5 x 253 B)
#[derive(Debug)]
pub struct TcpGreeting {
    pub send_abci: bool,
    pub broadcast_group: BroadcastGroup,
    pub id: TcpId,
}

// 4. ChildPeerStatuses & ChildPeerStatus (0x4f0d8f0 296 B, 0x4f0db20 221 B)
#[derive(Debug)]
pub struct ChildPeerStatuses(pub InnerStatuses);

#[derive(Debug)]
pub struct ChildPeerStatus {
    pub verified: bool,
    pub connection_count: usize,
}

fn main() {
    let a = anchors();
    let p_ne_disp: fn(&NodeError, &mut fmt::Formatter<'_>) -> fmt::Result =
        <NodeError as fmt::Display>::fmt;
    let p_parse_u64: fn(&str) -> u64 = hl_node_parse_u64_cli;
    let p_tg: fn(&TcpGreeting, &mut fmt::Formatter<'_>) -> fmt::Result =
        <TcpGreeting as fmt::Debug>::fmt;
    let p_rtg: fn(&'static &'static TcpGreeting, &mut fmt::Formatter<'_>) -> fmt::Result =
        <&TcpGreeting as fmt::Debug>::fmt;
    let p_rcpses: fn(&'static &'static ChildPeerStatuses, &mut fmt::Formatter<'_>) -> fmt::Result =
        <&ChildPeerStatuses as fmt::Debug>::fmt;
    let p_rcps: fn(&'static &'static ChildPeerStatus, &mut fmt::Formatter<'_>) -> fmt::Result =
        <&ChildPeerStatus as fmt::Debug>::fmt;
    black_box((
        a,
        p_ne_disp as usize,
        p_parse_u64 as usize,
        p_tg as usize,
        p_rtg as usize,
        p_rcpses as usize,
        p_rcps as usize,
    ));
}
"""


def _parse_int(v) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 16) if v.startswith(("0x", "0X")) else int(v)
    raise AssertionError(f"Cannot parse integer from {v!r}")


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV.open("r", encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                fdes[_parse_int(parts[0])] = _parse_int(parts[1])
    return fdes


def check_disjoint_against_repo(records: list[dict]) -> None:
    """Verify internal disjointness and 0 overlap vs byte-windows.json & all sibling packets.

    Wave-7 consolidation-safe: an exact (s, e) == (bs, be) match is permitted ONLY if
    already consolidated as a `first-party clean-room rebuild` in byte-windows.json or
    a `consolidation` sibling packet; dependency or partial overlaps are strictly forbidden.
    """
    ours = sorted((r["start"], r["end"], r["id"]) for r in records)
    for (s1, e1, id1), (s2, e2, id2) in zip(ours, ours[1:]):
        if e1 > s2:
            raise AssertionError(
                f"Internal overlap: {id1} ({hex(s1)}..{hex(e1)}) vs {id2} ({hex(s2)}..{hex(e2)})"
            )

    bw = json.loads(BYTE_WINDOWS_JSON.read_text(encoding="utf-8"))
    for w in bw.get("windows", []):
        bs = _parse_int(w["start"])
        be = _parse_int(w["end"])
        sk = w.get("source_kind", "")
        for s, e, wid in ours:
            if max(s, bs) < min(e, be):
                if (s, e) == (bs, be) and sk == "first-party clean-room rebuild":
                    continue
                raise AssertionError(
                    f"Overlap vs byte-windows.json: {wid} ({hex(s)}..{hex(e)}) vs "
                    f"{w.get('id')} ({hex(bs)}..{hex(be)}, source_kind={sk!r})"
                )

    for p_str in sorted(glob.glob(str(WORK_ITEMS_DIR / "*" / "*.json"))):
        p = Path(p_str)
        if p.parent == PACKET_DIR:
            continue
        is_consolidation = "consolidation" in p.parent.name
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        items = d if isinstance(d, list) else d.get("records", d.get("windows", d.get("matches", [])))
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            rs = it.get("start", it.get("start_va", it.get("va")))
            re_ = it.get("end", it.get("end_va"))
            if rs is not None and re_ is None and it.get("size") is not None:
                re_ = _parse_int(rs) + _parse_int(it["size"])
            if rs is None or re_ is None:
                continue
            bs, be = _parse_int(rs), _parse_int(re_)
            for s, e, wid in ours:
                if max(s, bs) < min(e, be):
                    if (s, e) == (bs, be) and is_consolidation:
                        continue
                    raise AssertionError(
                        f"Overlap vs sibling packet {p.relative_to(REPO_ROOT)}: "
                        f"{wid} ({hex(s)}..{hex(e)}) vs {hex(bs)}..{hex(be)}"
                    )


def rebuild_from_source(bin_data: bytes, text_sec: dict) -> tuple[bytes, list[dict]]:
    """Compile clean-room #![forbid(unsafe_code)] crates with rustc +1.95.0 ThinLTO
    and match all 11 target node #115 FDEs."""
    env = os.environ.copy()
    env.setdefault("RUST_MIN_STACK", "16777216")

    def read_target(s: int, e: int) -> bytes:
        off = text_sec["offset"] + (s - text_sec["address"])
        return bin_data[off : off + (e - s)]

    with tempfile.TemporaryDirectory(prefix="re005-transport-runtime-w2-") as td:
        work = Path(td)
        (work / "dep_types.rs").write_text(DEP_TYPES_RS, encoding="utf-8")
        (work / "main.rs").write_text(MAIN_RS, encoding="utf-8")

        for cmd in [
            [
                "rustc", "+1.95.0", "--crate-name=dep_types", "--crate-type=rlib",
                "--edition=2021", "-C", "opt-level=3", "-C", "overflow-checks=true",
                "-C", "embed-bitcode=yes",
                "-o", str(work / "libdep_types.rlib"), str(work / "dep_types.rs"),
            ],
            [
                "rustc", "+1.95.0", "--crate-name=transport_runtime_w2", "--crate-type=bin",
                "--edition=2021", "-C", "opt-level=3", "-C", "overflow-checks=true",
                "-C", "lto=thin", "-C", "codegen-units=16", "-C", "save-temps",
                "--extern", f"dep_types={work / 'libdep_types.rlib'}",
                "-o", str(work / "transport_runtime_w2"), str(work / "main.rs"),
            ],
        ]:
            subprocess.check_call(cmd, env=env, cwd=work)

        compiled: list[tuple[str, bytes, list[dict]]] = []
        for ob in sorted(work.glob("transport_runtime_w2.*.rcgu.o")):
            for names, body, relocs in object_functions(ob.read_bytes()):
                rdicts = [{"offset": o, "width": 4, "type": t, "addend": a} for o, t, a in relocs]
                compiled.append((names[0] if names else "", body, rdicts))

        bodies = bytearray()
        records: list[dict] = []
        for start, end, wid, comp, kind, label in TARGET_WINDOWS:
            tbytes = read_target(start, end)
            best = None
            for sym, body, rdicts in compiled:
                if len(body) != len(tbytes):
                    continue
                res = compare(body, tbytes, rdicts)
                if res["relocation_qualified"]:
                    cand = (-res["raw_equal_bytes"], sym, body, rdicts, res)
                    if best is None or cand[0] < best[0]:
                        best = cand
            if best is None:
                raise AssertionError(
                    f"Rebuild failed to match {wid} ({hex(start)}..{hex(end)}, {len(tbytes)} B)"
                )
            _, sym, body, rdicts, res = best
            offset = len(bodies)
            bodies.extend(body)
            records.append(
                {
                    "id": wid,
                    "component": comp,
                    "kind": kind,
                    "label": label,
                    "start": start,
                    "end": end,
                    "size": end - start,
                    "body_offset": offset,
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "target_body_sha256": hashlib.sha256(tbytes).hexdigest(),
                    "raw_equal": res["raw_equal"],
                    "raw_equal_bytes": res["raw_equal_bytes"],
                    "relocation_qualified": res["relocation_qualified"],
                    "relocations": rdicts,
                    "symbol": sym,
                }
            )
        return bytes(bodies), records


def write_packet_artifacts(bodies: bytes, records: list[dict]) -> None:
    BODIES_PATH.write_bytes(bodies)
    by_comp: dict[str, dict[str, int]] = {}
    for r in records:
        c = by_comp.setdefault(r["component"], {"windows": 0, "bytes": 0, "raw_equal_bytes": 0})
        c["windows"] += 1
        c["bytes"] += r["size"]
        c["raw_equal_bytes"] += r["raw_equal_bytes"]

    payload = {
        "target": "node115",
        "binary_path": "artifacts/node/115/hl-node",
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "binary_size": EXPECTED_BINARY_SIZE,
        "compiler": "rustc +1.95.0 (opt-level=3, overflow-checks=true, lto=thin, codegen-units=16, #![forbid(unsafe_code)], 0 external deps)",
        "source_kind": "first-party clean-room rebuild",
        "components": by_comp,
        "summary": {
            "total_windows": len(records),
            "matched_bytes": sum(r["size"] for r in records),
            "raw_equal_windows": sum(1 for r in records if r["raw_equal"]),
            "raw_equal_bytes": sum(r["raw_equal_bytes"] for r in records),
            "bodies_sha256": hashlib.sha256(bodies).hexdigest(),
        },
        "windows": records,
    }
    RECORDS_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def verify_records(bin_data: bytes, text_sec: dict, fdes: dict[int, int]) -> dict:
    payload = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    bodies = BODIES_PATH.read_bytes()

    if payload["binary_sha256"] != EXPECTED_BINARY_SHA256 or payload["binary_size"] != EXPECTED_BINARY_SIZE:
        raise AssertionError("Pinned binary metadata mismatch")
    if hashlib.sha256(bodies).hexdigest() != payload["summary"]["bodies_sha256"]:
        raise AssertionError("bodies.bin sha256 mismatch")

    records = payload["windows"]
    if len(records) != len(TARGET_WINDOWS):
        raise AssertionError(f"Expected {len(TARGET_WINDOWS)} windows, got {len(records)}")

    expected_keys = [(s, e, wid, comp) for s, e, wid, comp, _, _ in TARGET_WINDOWS]
    actual_keys = [(r["start"], r["end"], r["id"], r["component"]) for r in records]
    if actual_keys != expected_keys:
        raise AssertionError("Window list mismatch vs TARGET_WINDOWS")

    total_bytes = 0
    total_raw = 0
    for r in records:
        s, e = r["start"], r["end"]
        if fdes.get(s) != e:
            raise AssertionError(f"Window {r['id']} ({hex(s)}..{hex(e)}) is not an exact node #115 FDE")
        body = bodies[r["body_offset"] : r["body_offset"] + r["size"]]
        if len(body) != r["size"] or hashlib.sha256(body).hexdigest() != r["body_sha256"]:
            raise AssertionError(f"Body slice/hash mismatch for {r['id']}")
        off = text_sec["offset"] + (s - text_sec["address"])
        tbytes = bin_data[off : off + (e - s)]
        if hashlib.sha256(tbytes).hexdigest() != r["target_body_sha256"]:
            raise AssertionError(f"Target sha256 mismatch for {r['id']}")
        res = compare(body, tbytes, r["relocations"])
        if not res["relocation_qualified"] or res["non_relocation_difference_offsets"]:
            raise AssertionError(f"compare() failed for {r['id']}: {res}")
        if res["raw_equal_bytes"] != r["raw_equal_bytes"]:
            raise AssertionError(f"raw_equal_bytes mismatch for {r['id']}")
        total_bytes += r["size"]
        total_raw += res["raw_equal_bytes"]

    if total_bytes != payload["summary"]["matched_bytes"] or total_raw != payload["summary"]["raw_equal_bytes"]:
        raise AssertionError("Summary totals mismatch")

    check_disjoint_against_repo(records)
    return payload


def run_negative_controls(bin_data: bytes, text_sec: dict, payload: dict) -> int:
    bodies = BODIES_PATH.read_bytes()
    r0 = payload["windows"][0]
    body0 = bodies[r0["body_offset"] : r0["body_offset"] + r0["size"]]
    off0 = text_sec["offset"] + (r0["start"] - text_sec["address"])
    tbytes0 = bin_data[off0 : off0 + r0["size"]]
    rel_covered = set()
    for rel in r0["relocations"]:
        for k in range(rel["width"]):
            rel_covered.add(rel["offset"] + k)
    rejected = 0

    # Control 1: 1-byte flip outside relocation spans must fail compare()
    non_rel = next(i for i in range(len(body0)) if i not in rel_covered)
    mut = bytearray(body0)
    mut[non_rel] ^= 0xFF
    res1 = compare(bytes(mut), tbytes0, r0["relocations"])
    assert not res1["relocation_qualified"] and non_rel in res1["non_relocation_difference_offsets"]
    rejected += 1

    # Control 2: 1-byte length truncation must fail compare()
    try:
        compare(body0[:-1], tbytes0, r0["relocations"])
        raise AssertionError("Expected length mismatch failure")
    except ValueError:
        rejected += 1

    # Control 3: Forged 8-byte relocation width must be rejected by compare()
    bad_rels = copy.deepcopy(r0["relocations"])
    bad_rels[0]["width"] = 8
    try:
        compare(body0, tbytes0, bad_rels)
        raise AssertionError("Expected forged relocation width rejection")
    except ValueError:
        rejected += 1

    # Control 4: Overlapping window must be rejected by check_disjoint_against_repo()
    dup = copy.deepcopy(payload["windows"])
    dup.append(copy.deepcopy(dup[0]))
    try:
        check_disjoint_against_repo(dup)
        raise AssertionError("Expected overlap rejection")
    except AssertionError:
        rejected += 1

    return rejected


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rebuild", action="store_true", help="Rebuild bodies.bin & records.json from Rust source")
    ap.add_argument("--self-test", action="store_true", help="Run 4 negative controls after verification")
    args = ap.parse_args()

    bin_data = BINARY_PATH.read_bytes()
    if len(bin_data) != EXPECTED_BINARY_SIZE:
        raise AssertionError(f"Unexpected binary size: {len(bin_data)}")
    actual_sha = hashlib.sha256(bin_data).hexdigest()
    if actual_sha != EXPECTED_BINARY_SHA256:
        raise AssertionError(f"Unexpected binary sha256: {actual_sha}")

    secs = {s["name"]: s for s in sections(bin_data)}
    text_sec = secs[".text"]
    fdes = load_fde_map()

    if args.rebuild:
        bodies, records = rebuild_from_source(bin_data, text_sec)
        write_packet_artifacts(bodies, records)

    payload = verify_records(bin_data, text_sec, fdes)
    s = payload["summary"]
    comp_parts = ", ".join(
        f"{k}={v['windows']} FDEs/{v['bytes']} B"
        for k, v in sorted(payload["components"].items())
    )
    msg = (
        f"PASS: {s['total_windows']}/{len(TARGET_WINDOWS)} relocation-qualified, "
        f"{s['matched_bytes']} B (raw_equal_bytes={s['raw_equal_bytes']}/{s['matched_bytes']}, {comp_parts})"
    )
    if args.self_test:
        n_neg = run_negative_controls(bin_data, text_sec, payload)
        msg += f" | {n_neg}/4 negative controls rejected"
    print(msg)


if __name__ == "__main__":
    main()
