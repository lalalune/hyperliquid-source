#!/usr/bin/env python3
"""Verify 7 strictly disjoint first-party ThinLTO + tikv-jemallocator storage & abci business-logic FDEs (1,404 B)."""

from __future__ import annotations

import argparse
import copy
import glob
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
RECORDS_PATH = HERE / "records.json"
BODIES_PATH = HERE / "bodies.bin"
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_PATH = REPO / "research" / "byte-windows.json"

EXPECTED_BINARY_PATH = "artifacts/node/115/hl-node"
EXPECTED_BINARY_SIZE = 105896032
EXPECTED_BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOW_SPECS = [
    ("storage", "db_hub_evm_fast_dir_16928b0", "db/src/db_hub.rs evm_db_hub_fast_dir", 0x16928B0, 0x16929AE),
    ("storage", "db_hub_evm_slow_dir_16929b0", "db/src/db_hub.rs evm_db_hub_slow_dir", 0x16929B0, 0x1692AAE),
    ("storage", "db_home_checkpoint_dir_for_height_1692ab0", "db/src/db_home.rs checkpoint_dir_for_height", 0x1692AB0, 0x1692B79),
    ("storage", "db_owned_dir_display_1692bf0", "db/src/owned_db_home.rs <&OwnedDbDir as Display>::fmt", 0x1692BF0, 0x1692C2D),
    ("storage", "db_rocks_write_checkpoint_marker_1696b10", "db/src/rocks_db.rs write_checkpoint_complete_marker", 0x1696B10, 0x1696B90),
    ("abci", "abci_tracker_watermark_seal_prune_live1_27604d0", "l1/src/abci/hash_signature_tracker.rs tracker_watermark_seal_prune (live #1)", 0x27604D0, 0x27605CD),
    ("abci", "abci_tracker_watermark_seal_prune_live2_27605d0", "l1/src/abci/hash_signature_tracker.rs tracker_watermark_seal_prune (live #2)", 0x27605D0, 0x27606CD),
]

RODATA_ANCHORS = [
    ("hyperliquid_data_subdir", 0x44D724, "/hyperliquid_data"),
    ("evm_db_hub_fast_subdir", 0x4401D0, "/evm_db_hub_fast"),
    ("evm_db_hub_slow_subdir", 0x43DDEB, "/evm_db_hub_slow"),
    ("checkpoint_subdir", 0x43473B, "/checkpoint"),
]

BASE_RS = r"""#![forbid(unsafe_code)]
use std::sync::LazyLock;

#[repr(C)]
pub struct GlobalHome {
    pub prefix: [u8; 0x18],
    pub home: String,
    pub tail: [u8; 0x20],
}

pub static GLOBAL_HOME: LazyLock<GlobalHome> = LazyLock::new(|| {
    if std::hint::black_box(false) {
        panic!("init");
    }
    GlobalHome {
        prefix: [0; 0x18],
        home: std::env::var("HOME").unwrap_or_default(),
        tail: [0; 0x20],
    }
});

#[inline(never)]
pub fn touch_marker(path: &str, _loc: &'static u8) -> anyhow::Result<()> {
    if std::hint::black_box(false) {
        return Err(anyhow::anyhow!("err {}", path));
    }
    if std::hint::black_box(false) {
        panic!("boom");
    }
    Ok(())
}
"""

LIB_RS = r"""#![forbid(unsafe_code)]
use core::fmt;

pub struct OwnedDbDir(pub String);
impl fmt::Display for OwnedDbDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}
impl OwnedDbDir {
    #[inline(always)]
    fn checkpoint_base(&self) -> String {
        format!("{self}/checkpoint")
    }
}

#[inline(never)]
fn evm_db_hub_fast_dir() -> OwnedDbDir {
    OwnedDbDir(format!(
        "{}/evm_db_hub_fast",
        format!("{}/hyperliquid_data", base_crate::GLOBAL_HOME.home)
    ))
}

#[inline(never)]
fn evm_db_hub_slow_dir() -> OwnedDbDir {
    OwnedDbDir(format!(
        "{}/evm_db_hub_slow",
        format!("{}/hyperliquid_data", base_crate::GLOBAL_HOME.home)
    ))
}

#[inline(never)]
pub fn checkpoint_dir_for_height(dir: &OwnedDbDir, height: u64) -> String {
    format!("{}/{height}", dir.checkpoint_base())
}

#[derive(Clone, Copy)]
pub enum RocksDbShard {
    Exchange,
    Rpc,
    EvmState,
}

static SHARD_NAMES: [&str; 3] = ["Exchange", "Rpc", "EvmState"];

impl fmt::Display for RocksDbShard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(SHARD_NAMES[*self as usize])
    }
}

static LOC_TAG: u8 = 1;

#[inline(never)]
fn checkpoint_complete_marker_inner(shard: RocksDbShard, dir: &str) -> String {
    format!("{dir}/CHECKPOINT_COMPLETE_{}", shard.to_string().to_lowercase())
}

#[inline(never)]
pub fn write_checkpoint_complete_marker(shard: RocksDbShard, dir: &str) {
    let p = checkpoint_complete_marker_inner(shard, dir);
    let _ = base_crate::touch_marker(&p, &LOC_TAG);
}

pub fn run_db() {
    use std::hint::black_box;
    let _ = black_box(evm_db_hub_fast_dir());
    let _ = black_box(evm_db_hub_slow_dir());
    let d = black_box(OwnedDbDir(String::from("a")));
    let _ = black_box(checkpoint_dir_for_height(&d, black_box(42)));
    write_checkpoint_complete_marker(black_box(RocksDbShard::EvmState), black_box("d"));
}
"""

MAIN_RS = r"""#![forbid(unsafe_code)]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::hint::black_box;
use std::sync::LazyLock;

static LOC1: u8 = 1;
static LOC2: u8 = 2;

static TRACKER_LOG_DIR: LazyLock<String> = LazyLock::new(|| {
    if black_box(false) {
        panic!("dir");
    }
    String::from("x")
});

pub struct TrackerState {
    pub pad0: [u8; 0x60],
    pub map: [u8; 0x20],
    pub max_height: u64,
    pub pad1: u64,
    pub sealed: u16,
}

pub struct Ctx12 {
    pub pad0: [u8; 0x10],
    pub seal_height: u64,
    pub pad1: [u8; 0x48],
    pub extra: u64,
}

#[inline(never)]
pub fn tracker_helper_1(m: &mut [u8; 0x20], h: u64, e: &u64, s: &'static u8) -> Vec<u64> {
    black_box((m, h, e, s));
    Vec::new()
}

#[inline(never)]
pub fn tracker_helper_2(
    v: &Vec<u64>,
    t: &mut TrackerState,
    cutoff: u64,
    x: u64,
    opt: Option<u64>,
    s: &'static u8,
) {
    black_box((v, t, cutoff, x, opt, s));
}

#[inline(never)]
pub fn tracker_watermark_seal_prune(t: &mut TrackerState, h: u64, x: u64, ctx: &Ctx12) {
    t.max_height = t.max_height.max(h);
    let _ = &*TRACKER_LOG_DIR;
    let v = tracker_helper_1(&mut t.map, h, &ctx.extra, &LOC1);
    if h == ctx.seal_height {
        t.sealed = 1;
    }
    let cutoff = h.saturating_sub(50_000);
    tracker_helper_2(&v, t, cutoff, x, None, &LOC2);
}

fn main() {
    db_abci_logic::run_db();
    let mut ts = TrackerState {
        pad0: [0; 0x60],
        map: [0; 0x20],
        max_height: 0,
        pad1: 0,
        sealed: 0,
    };
    let ctx = Ctx12 {
        pad0: [0; 0x10],
        seal_height: 10,
        pad1: [0; 0x48],
        extra: 5,
    };
    tracker_watermark_seal_prune(black_box(&mut ts), black_box(10), black_box(2), black_box(&ctx));
    let v = tracker_helper_1(&mut ts.map, 9, &ctx.extra, &LOC2);
    tracker_helper_2(&v, &mut ts, 1, 2, Some(black_box(7)), &LOC1);
}
"""


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    sections: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off
        )
        end = data.index(b"\x00", shstr_off + sh_name)
        sections[data[shstr_off + sh_name : end].decode("ascii")] = (sh_addr, sh_offset, sh_size)
    return sections


def parse_obj_sections(obj: bytes) -> dict[str, tuple[bytes, list[int]]]:
    if len(obj) < 64 or obj[:4] != b"\x7fELF":
        return {}
    o_shoff = struct.unpack_from("<Q", obj, 0x28)[0]
    o_shentsize, o_shnum, o_shstrndx = struct.unpack_from("<HHH", obj, 0x3A)
    o_shstr = struct.unpack_from("<Q", obj, o_shoff + o_shstrndx * o_shentsize + 24)[0]
    o_secs = []
    for i in range(o_shnum):
        off = o_shoff + i * o_shentsize
        sh_name, sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, _sh_link, sh_info = (
            struct.unpack_from("<IIQQQQII", obj, off)
        )
        end = obj.index(b"\x00", o_shstr + sh_name)
        o_secs.append(
            (i, obj[o_shstr + sh_name : end].decode("utf-8", "replace"), sh_type, sh_offset, sh_size, sh_info)
        )

    relocs: dict[int, list[int]] = {}
    for _idx, _name, stype, soff, ssz, sinfo in o_secs:
        if stype == 4:
            offs: set[int] = set()
            for p in range(soff, soff + ssz, 24):
                r_offset, r_info, _r_addend = struct.unpack_from("<QQq", obj, p)
                width = 8 if (r_info & 0xFFFFFFFF) == 1 else 4
                for k in range(width):
                    offs.add(r_offset + k)
            relocs[sinfo] = sorted(offs)

    by_name: dict[str, tuple[bytes, list[int]]] = {}
    for idx, name, stype, soff, ssz, _sinfo in o_secs:
        if stype == 1 and name.startswith(".text."):
            by_name[name] = (obj[soff : soff + ssz], relocs.get(idx, []))
    return by_name


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                fdes[int(parts[0], 16)] = int(parts[1], 16)
    return fdes


def compile_thinlto_jemalloc(target_dir: Path | None = None) -> tuple[list[tuple[str, bytes, list[int]]], str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="node115-sa-logic-") as td:
        root = Path(td)
        (root / "base_crate" / "src").mkdir(parents=True)
        (root / "db_abci_logic" / "src").mkdir(parents=True)
        (root / "app" / "src").mkdir(parents=True)
        (root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["base_crate", "db_abci_logic", "app"]\nresolver = "2"\n\n'
            '[profile.release]\nopt-level = 3\nlto = "thin"\noverflow-checks = true\n',
            encoding="utf-8",
        )
        (root / "base_crate" / "Cargo.toml").write_text(
            '[package]\nname = "base_crate"\nversion = "0.1.0"\nedition = "2021"\n\n'
            '[dependencies]\nanyhow = "=1.0.105"\n',
            encoding="utf-8",
        )
        (root / "db_abci_logic" / "Cargo.toml").write_text(
            '[package]\nname = "db_abci_logic"\nversion = "0.1.0"\nedition = "2021"\n\n'
            '[dependencies]\nbase_crate = { path = "../base_crate" }\nanyhow = "=1.0.105"\n',
            encoding="utf-8",
        )
        (root / "app" / "Cargo.toml").write_text(
            '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n'
            '[dependencies]\ndb_abci_logic = { path = "../db_abci_logic" }\n'
            'tikv-jemallocator = "=0.6.0"\n',
            encoding="utf-8",
        )
        (root / "base_crate" / "src" / "lib.rs").write_text(BASE_RS, encoding="utf-8")
        (root / "db_abci_logic" / "src" / "lib.rs").write_text(LIB_RS, encoding="utf-8")
        (root / "app" / "src" / "main.rs").write_text(MAIN_RS, encoding="utf-8")

        tdir = target_dir if target_dir is not None else (root / "target")
        deps = tdir / "release" / "deps"
        if deps.exists():
            for old_o in list(deps.glob("app-*.o")) + list(deps.glob("db_abci_logic-*.o")):
                old_o.unlink()

        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(tdir)
        env["CARGO_BUILD_JOBS"] = env.get("CARGO_BUILD_JOBS", "4")
        env["RUSTFLAGS"] = "-C save-temps"
        subprocess.run(
            ["cargo", "+1.95.0", "build", "--offline", "--release", "--manifest-path", str(root / "Cargo.toml")],
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        compiled: list[tuple[str, bytes, list[int]]] = []
        for obj_path in sorted(deps.glob("app-*.o")) + sorted(deps.glob("db_abci_logic-*.o")):
            for sym, (cbytes, roffs) in parse_obj_sections(obj_path.read_bytes()).items():
                compiled.append((sym, cbytes, roffs))
        if not compiled:
            raise AssertionError("ThinLTO + jemalloc build produced no ELF .text.* objects")
        return compiled, ver


def extract_interval(w: dict, fdes: dict[int, int]) -> tuple[int, int] | None:
    s = None
    for k in ("start", "start_va", "va_start", "fde_start", "node115_start", "va"):
        if w.get(k) is not None:
            s = w[k]
            break
    if s is None:
        return None
    si = int(s, 16) if isinstance(s, str) else int(s)
    for k in ("end", "end_va", "va_end", "fde_end", "node115_end"):
        if w.get(k) is not None:
            return (si, int(w[k], 16) if isinstance(w[k], str) else int(w[k]))
    for k in ("size", "len", "byte_len", "bytes"):
        if w.get(k) is not None:
            return (si, si + int(w[k]))
    return (si, fdes[si]) if si in fdes else None


def check_disjointness(windows: list[dict], fdes: dict[int, int]) -> None:
    own: list[tuple[int, int, str]] = []
    for w in windows:
        s = int(w["start_va"], 16)
        e = int(w["end_va"], 16)
        for ps, pe, plabel in own:
            if s < pe and ps < e:
                raise AssertionError(f"internal overlap {w['label']} vs {plabel}")
        own.append((s, e, w["label"]))

    bw = json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8"))
    for ew in bw.get("windows", []):
        iv = extract_interval(ew, fdes)
        if not iv:
            continue
        es, ee = iv
        is_dep = "dependency" in ew
        for s, e, label in own:
            if s < ee and es < e:
                if is_dep or (s, e) != (es, ee):
                    raise AssertionError(
                        f"overlap with byte-windows.json ({'dep' if is_dep else 'fp'}): "
                        f"{label} 0x{s:x}..0x{e:x} vs 0x{es:x}..0x{ee:x}"
                    )

    patterns = [
        "*byte-matches*",
        "*gate-closure*",
        "*thinlto*",
        "*100pct*",
        "*census*",
    ]
    seen_paths: set[Path] = set()
    for pat in patterns:
        for fname in ("records.json", "census.json"):
            for p_str in sorted(glob.glob(str(REPO / "research" / "work-items" / pat / fname))):
                p = Path(p_str).resolve()
                if p == RECORDS_PATH.resolve() or p in seen_paths:
                    continue
                seen_paths.add(p)
                d = json.loads(p.read_text(encoding="utf-8"))
                for key in ("windows", "matches", "byte_matches", "compiled_matches"):
                    for ew in d.get(key, []) if isinstance(d.get(key), list) else []:
                        if not isinstance(ew, dict):
                            continue
                        iv = extract_interval(ew, fdes)
                        if not iv:
                            continue
                        es, ee = iv
                        for s, e, label in own:
                            if s < ee and es < e:
                                raise AssertionError(
                                    f"overlap with sibling packet {p.parent.name}: "
                                    f"{label} 0x{s:x}..0x{e:x} vs 0x{es:x}..0x{ee:x}"
                                )


def is_forbidden_stdlib(sym: str) -> bool:
    return any(
        bad in sym
        for bad in ("simd_contains", "StringError", "drop_in_place", "write_fmt", "call_once_force")
    )


def build_records_and_bodies(
    data115: bytes,
    sections115: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    target_dir: Path | None = None,
) -> tuple[dict, bytes]:
    text_va, text_off, _ = sections115[".text"]
    compiled, rustc_ver = compile_thinlto_jemalloc(target_dir=target_dir)

    windows = []
    bodies = bytearray()
    storage_w = storage_b = abci_w = abci_b = 0
    total_raw = 0
    raw_equal_windows = 0

    for comp, label, kind, s, e in WINDOW_SPECS:
        sz = e - s
        if fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch for {label}: 0x{s:x}..0x{e:x}")
        tbytes = data115[text_off + (s - text_va) : text_off + (e - text_va)]
        found = None
        for sym, cbytes, roffs in compiled:
            if len(cbytes) != sz or is_forbidden_stdlib(sym):
                continue
            ro_set = set(roffs)
            if any(cbytes[i] != tbytes[i] and i not in ro_set for i in range(sz)):
                continue
            raw_eq = sum(1 for i in range(sz) if cbytes[i] == tbytes[i])
            if found is None or raw_eq > found[3]:
                found = (sym, cbytes, roffs, raw_eq)
        if found is None:
            raise AssertionError(f"No 0-diff compiled match for {label} 0x{s:x}..0x{e:x} ({sz} B)")
        sym, cbytes, roffs, raw_eq = found
        body_off = len(bodies)
        bodies.extend(cbytes)
        if raw_eq == sz:
            raw_equal_windows += 1
        total_raw += raw_eq
        if comp == "storage":
            storage_w += 1
            storage_b += sz
        else:
            abci_w += 1
            abci_b += sz
        windows.append(
            {
                "component": comp,
                "label": label,
                "kind": kind,
                "compiled_section": sym,
                "start_va": f"0x{s:x}",
                "end_va": f"0x{e:x}",
                "size": sz,
                "body_offset": body_off,
                "raw_equal_bytes": raw_eq,
                "relocation_offsets": roffs,
                "target_sha256": hashlib.sha256(tbytes).hexdigest(),
                "compiled_sha256": hashlib.sha256(cbytes).hexdigest(),
            }
        )

    rec = {
        "schema_version": 1,
        "work_item": "RE-009-node115-storage-abci-logic-byte-matches",
        "target_binary": {
            "path": EXPECTED_BINARY_PATH,
            "size": EXPECTED_BINARY_SIZE,
            "sha256": EXPECTED_BINARY_SHA256,
        },
        "toolchain": {
            "rustc_version": rustc_ver,
            "edition": "2021",
            "profile": "opt-level=3, overflow-checks=true, lto=thin",
            "allocator": "tikv-jemallocator = 0.6.0",
        },
        "bodies_file": "bodies.bin",
        "bodies_sha256": hashlib.sha256(bytes(bodies)).hexdigest(),
        "rodata_anchors": [
            {"name": name, "va": f"0x{va:x}", "ascii": txt}
            for name, va, txt in RODATA_ANCHORS
        ],
        "instruction_anchors": [
            {"name": "tracker_prune_window_50000_live1", "va": "0x276053a", "hex": "4881eb50c30000"},
            {"name": "tracker_prune_window_50000_live2", "va": "0x276063a", "hex": "4881eb50c30000"},
        ],
        "summary": {
            "windows": len(windows),
            "total_bytes": len(bodies),
            "raw_equal_bytes": total_raw,
            "raw_equal_windows": raw_equal_windows,
            "storage_windows": storage_w,
            "storage_bytes": storage_b,
            "abci_windows": abci_w,
            "abci_bytes": abci_b,
        },
        "windows": windows,
    }
    return rec, bytes(bodies)


def verify_records(
    records: dict,
    bodies: bytes,
    data115: bytes,
    sections115: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
) -> None:
    tb = records["target_binary"]
    if len(data115) != tb["size"]:
        raise AssertionError("target binary size mismatch")
    if hashlib.sha256(data115).hexdigest() != tb["sha256"]:
        raise AssertionError("target binary sha256 mismatch")
    if hashlib.sha256(bodies).hexdigest() != records["bodies_sha256"]:
        raise AssertionError("bodies_sha256 mismatch")

    text_va, text_off, text_sz = sections115[".text"]
    ro_va, ro_off, ro_sz = sections115[".rodata"]

    for anc in records["rodata_anchors"]:
        va = int(anc["va"], 16)
        want = anc["ascii"].encode("ascii")
        if not (ro_va <= va and va + len(want) <= ro_va + ro_sz):
            raise AssertionError(f"rodata anchor out of bounds: {anc['name']}")
        got = data115[ro_off + (va - ro_va) : ro_off + (va - ro_va) + len(want)]
        if got != want:
            raise AssertionError(f"rodata anchor mismatch for {anc['name']}: {got!r} != {want!r}")

    for ianc in records["instruction_anchors"]:
        va = int(ianc["va"], 16)
        want = bytes.fromhex(ianc["hex"])
        got = data115[text_off + (va - text_va) : text_off + (va - text_va) + len(want)]
        if got != want:
            raise AssertionError(f"instruction anchor mismatch for {ianc['name']}")

    windows = records["windows"]
    check_disjointness(windows, fdes)

    tot_bytes = tot_raw = raw_wins = 0
    for w in windows:
        s = int(w["start_va"], 16)
        e = int(w["end_va"], 16)
        sz = int(w["size"])
        boff = int(w["body_offset"])
        if e - s != sz or fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch for {w['label']}")
        if not (text_va <= s and e <= text_va + text_sz):
            raise AssertionError(f"out of .text: {w['label']}")
        if is_forbidden_stdlib(w["compiled_section"]):
            raise AssertionError(f"stdlib compiled_section forbidden: {w['compiled_section']}")

        tbytes = data115[text_off + (s - text_va) : text_off + (e - text_va)]
        if hashlib.sha256(tbytes).hexdigest() != w["target_sha256"]:
            raise AssertionError(f"target_sha256 mismatch for {w['label']}")

        cbytes = bodies[boff : boff + sz]
        if len(cbytes) != sz or hashlib.sha256(cbytes).hexdigest() != w["compiled_sha256"]:
            raise AssertionError(f"compiled body mismatch for {w['label']}")

        ro_set = set(w["relocation_offsets"])
        non_reloc = [i for i in range(sz) if cbytes[i] != tbytes[i] and i not in ro_set]
        if non_reloc:
            raise AssertionError(f"non-reloc byte diffs for {w['label']}: {non_reloc[:6]}")
        raw_eq = sum(1 for i in range(sz) if cbytes[i] == tbytes[i])
        if raw_eq != w["raw_equal_bytes"]:
            raise AssertionError(f"raw_equal_bytes mismatch for {w['label']}: {raw_eq} != {w['raw_equal_bytes']}")
        if raw_eq == sz:
            raw_wins += 1
        tot_bytes += sz
        tot_raw += raw_eq

    sm = records["summary"]
    if (
        sm["windows"] != len(windows)
        or sm["total_bytes"] != tot_bytes
        or sm["raw_equal_bytes"] != tot_raw
        or sm["raw_equal_windows"] != raw_wins
    ):
        raise AssertionError("summary totals mismatch")


def run_negative_controls(
    records: dict,
    bodies: bytes,
    data115: bytes,
    sections115: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
) -> int:
    def mut_drop_reloc(r: dict) -> None:
        r["windows"][0]["relocation_offsets"] = r["windows"][0]["relocation_offsets"][1:]

    def mut_bad_fde(r: dict) -> None:
        r["windows"][0]["end_va"] = "0x16929af"
        r["windows"][0]["size"] = 255

    def mut_overlap(r: dict) -> None:
        r["windows"].append(copy.deepcopy(r["windows"][0]))

    def mut_bad_rodata(r: dict) -> None:
        r["rodata_anchors"][0]["ascii"] = "/hyperliquid_datX"

    rejected = 0
    for name, fn in [
        ("drop_reloc", mut_drop_reloc),
        ("bad_fde", mut_bad_fde),
        ("internal_overlap", mut_overlap),
        ("bad_rodata", mut_bad_rodata),
    ]:
        mutated = copy.deepcopy(records)
        fn(mutated)
        try:
            verify_records(mutated, bodies, data115, sections115, fdes)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError(f"negative control {name} was NOT rejected")
    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true", help="Rebuild and write records.json + bodies.bin")
    ap.add_argument("--rebuild", action="store_true", help="Live-rebuild and assert byte-for-byte equality with bodies.bin")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    data115 = (REPO / EXPECTED_BINARY_PATH).read_bytes()
    sections115 = parse_elf_sections(data115)
    fdes = load_fde_map()
    cached_tdir = REPO / "work" / "target" / "storage-abci-logic"

    if args.generate:
        rec, bodies = build_records_and_bodies(data115, sections115, fdes, target_dir=cached_tdir)
        BODIES_PATH.write_bytes(bodies)
        RECORDS_PATH.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")

    records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    bodies = BODIES_PATH.read_bytes()
    verify_records(records, bodies, data115, sections115, fdes)

    if args.rebuild:
        rebuilt_rec, rebuilt_bodies = build_records_and_bodies(data115, sections115, fdes, target_dir=cached_tdir)
        if rebuilt_bodies != bodies:
            raise AssertionError("Live ThinLTO+jemalloc rebuild bodies.bin differs from committed bodies.bin")
        if rebuilt_rec["summary"] != records["summary"]:
            raise AssertionError("Live ThinLTO+jemalloc rebuild summary differs from records.json")

    sm = records["summary"]
    msg = (
        f"PASS: {sm['windows']}/{sm['windows']} relocation-qualified, "
        f"{sm['total_bytes']} B ({sm['raw_equal_bytes']} raw-equal, {sm['raw_equal_windows']} 100%-raw; "
        f"storage {sm['storage_windows']}w/{sm['storage_bytes']}B, "
        f"abci {sm['abci_windows']}w/{sm['abci_bytes']}B; rebuild={args.rebuild})"
    )
    if args.self_test:
        neg = run_negative_controls(records, bodies, data115, sections115, fdes)
        msg += f", {neg}/{neg} negative controls rejected"
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
