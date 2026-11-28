#!/usr/bin/env python3
"""Verify 4 strictly disjoint first-party ThinLTO + tikv-jemallocator abci (l1/src/abci/state.rs) business-logic FDEs (4,362 B)."""

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
if str(REPO / "tools") not in sys.path:
    sys.path.insert(0, str(REPO / "tools"))

import byte_progress  # noqa: E402

RECORDS_PATH = HERE / "records.json"
BODIES_PATH = HERE / "bodies.bin"
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_PATH = REPO / "research" / "byte-windows.json"

EXPECTED_BINARY_PATH = "artifacts/node/115/hl-node"
EXPECTED_BINARY_SIZE = 105896032
EXPECTED_BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOW_SPECS = [
    (
        "abci",
        "abci_state_serialize_and_save_26a2810",
        "l1/src/abci/state.rs:193,195 serialize_and_save_abci_state (copy 1)",
        "abci_state_serialize_and_save",
        0x26A2810,
        0x26A2C7E,
    ),
    (
        "abci",
        "abci_state_serialize_and_save_4e4af80",
        "l1/src/abci/state.rs:193,195 serialize_and_save_abci_state (copy 2)",
        "abci_state_serialize_and_save",
        0x4E4AF80,
        0x4E4B3EE,
    ),
    (
        "abci",
        "abci_state_serialize_and_save_4e4b3f0",
        "l1/src/abci/state.rs:193,195 serialize_and_save_abci_state (copy 3)",
        "abci_state_serialize_and_save",
        0x4E4B3F0,
        0x4E4B85E,
    ),
    (
        "abci",
        "abci_state_serialize_to_vec_4e4b860",
        "l1/src/abci/state.rs:161 serialize_abci_state_to_vec",
        "abci_state_serialize_to_vec",
        0x4E4B860,
        0x4E4BC20,
    ),
]

RODATA_ANCHORS = [
    ("abci_state_src", 0x443168, "l1/src/abci/state.rs"),
    ("chrono_iso_fmt", 0x465AE2, "%Y-%m-%dT%H:%M:%S%.3fZ"),
    ("serialized_abci_state", 0x5F41EE, "serialized abci state"),
    ("warn_prefix", 0x4309A1, " WARN >>> "),
]

LOCATION_ANCHORS = [
    ("abci_state_193_56_cgu1", 0x6437490, "l1/src/abci/state.rs", 193, 56),
    ("abci_state_195_17_cgu1", 0x64374A8, "l1/src/abci/state.rs", 195, 17),
    ("abci_state_195_64_cgu1", 0x64374C0, "l1/src/abci/state.rs", 195, 64),
    ("abci_state_161_83_cgu2", 0x649D9F8, "l1/src/abci/state.rs", 161, 83),
    ("abci_state_193_56_cgu2", 0x649DA10, "l1/src/abci/state.rs", 193, 56),
    ("abci_state_195_17_cgu2", 0x649DA28, "l1/src/abci/state.rs", 195, 17),
    ("abci_state_195_64_cgu2", 0x649DA40, "l1/src/abci/state.rs", 195, 64),
]

BASE_RS = r"""#![forbid(unsafe_code)]
use std::fmt;
use std::hint::black_box;
use std::panic::Location;

#[derive(Clone, Copy)]
pub struct NaiveDateTime {
    pub a: u32,
    pub b: u32,
    pub c: u32,
}

#[inline(never)]
pub fn current_wall_time() -> NaiveDateTime {
    if black_box(false) {
        panic!("time");
    }
    black_box(NaiveDateTime { a: 0, b: 0, c: 0 })
}

#[inline(never)]
pub fn log_formatted(args: fmt::Arguments<'_>) {
    black_box(args);
    if black_box(false) {
        panic!("log");
    }
}

#[track_caller]
#[inline(never)]
pub fn write_bytes_to_file(bytes: &[u8], path: &str) -> anyhow::Result<()> {
    black_box((bytes, path, Location::caller()));
    if black_box(false) {
        panic!("wb");
    }
    if black_box(false) {
        return Err(anyhow::anyhow!("wb"));
    }
    Ok(())
}
"""

LIB_RS = r"""#![forbid(unsafe_code)]
use base_crate::{current_wall_time, log_formatted, write_bytes_to_file, NaiveDateTime};
use std::collections::BTreeMap;
use std::fmt;
use std::hint::black_box;
use std::marker::PhantomData;
use std::sync::LazyLock;
use std::time::Instant;

#[derive(Clone, Copy)]
struct NodeLabel<T = ()>(&'static str, PhantomData<T>);
impl<T> fmt::Display for NodeLabel<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        black_box(self);
        if black_box(false) {
            panic!("nl");
        }
        f.write_str(self.0)
    }
}

static LAZY_LABEL: LazyLock<NodeLabel<()>> = LazyLock::new(|| {
    if black_box(false) {
        panic!("lbl");
    }
    black_box(NodeLabel("node", PhantomData))
});

#[allow(dead_code)]
struct FormattedTime<T = ()> {
    date: u32,
    time: Option<(u32, u32)>,
    cached: Option<(String, u64)>,
    fmt: &'static str,
    a: u64,
    b: u64,
    _p: PhantomData<T>,
}

impl<T> fmt::Display for FormattedTime<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        black_box(self);
        if black_box(false) {
            panic!("ft");
        }
        f.write_str("t")
    }
}

#[inline(always)]
fn format_now() -> FormattedTime<()> {
    let now: NaiveDateTime = current_wall_time();
    FormattedTime {
        date: now.a,
        time: Some((now.b, now.c)),
        cached: None,
        fmt: "%Y-%m-%dT%H:%M:%S%.3fZ",
        a: 8,
        b: 0,
        _p: PhantomData,
    }
}

pub struct AbciState {
    pub pad: [u64; 5],
    pub height: u64,
}

pub struct StateRef<'a>(pub &'a AbciState);

#[repr(C)]
pub struct RmpSerializer<'a> {
    pub buf: &'a mut Vec<u8>,
    pub cfg: u32,
    pub extra: u8,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum SerErr {
    Syntax(String),
    InvalidValueWrite(std::io::Error),
    InvalidDataWrite(std::io::Error),
    UnknownLength,
    DepthLimitExceeded,
}

#[inline(never)]
fn serialize_rmp(state: &StateRef<'_>, ser: &mut RmpSerializer<'_>) -> Result<(), SerErr> {
    black_box((state, ser));
    if black_box(false) {
        panic!("rmp");
    }
    if black_box(false) {
        return Err(SerErr::Syntax(String::new()));
    }
    if black_box(false) {
        return Err(SerErr::UnknownLength);
    }
    Ok(())
}

#[inline(always)]
fn to_vec_named(r: &StateRef<'_>) -> Result<Vec<u8>, SerErr> {
    let mut buf: Vec<u8> = Vec::new();
    let mut ser = RmpSerializer {
        buf: &mut buf,
        cfg: 0x01000400,
        extra: 0,
    };
    serialize_rmp(r, &mut ser)?;
    Ok(buf)
}

#[inline(always)]
fn save_to_vec_and_file(r: &StateRef<'_>, path: &str) -> Vec<u8> {
    let buf = to_vec_named(r).unwrap();
    write_bytes_to_file(&buf, path).unwrap();
    buf
}

#[inline(never)]
fn abci_state_serialize_and_save(state: &AbciState, path: &str) -> Vec<u8> {
    let start = Instant::now();
    let height = state.height;
    let r = StateRef(state);
    let buf = save_to_vec_and_file(&r, path);
    let elapsed = start.elapsed().as_secs_f64();
    let elapsed = if elapsed.is_finite() { elapsed } else { 0.0 };
    {
        let ft = format_now();
        let label: NodeLabel<()> = *LAZY_LABEL;
        let msg: &str = "serialized abci state______________________";
        log_formatted(format_args!(
            "{} WARN >>> {} @@ {} @@ [height: {:?}] @ [elapsed: {:?}]\n\n",
            ft, label, msg, &height, &elapsed
        ));
    }
    buf
}

#[inline(never)]
fn abci_state_serialize_to_vec(state: &AbciState) -> Vec<u8> {
    let start = Instant::now();
    let height = state.height;
    let r = StateRef(state);
    let buf = to_vec_named(&r).unwrap();
    let elapsed = start.elapsed().as_secs_f64();
    let elapsed = if elapsed.is_finite() { elapsed } else { 0.0 };
    {
        let ft = format_now();
        let label: NodeLabel<()> = *LAZY_LABEL;
        let msg: &str = "serialized abci state______________________";
        log_formatted(format_args!(
            "{} WARN >>> {} @@ {} @@ [height: {:?}] @ [elapsed: {:?}]\n\n",
            ft, label, msg, &height, &elapsed
        ));
    }
    buf
}

#[inline(never)]
pub fn touch_generics(mut m: BTreeMap<String, Vec<u8>>, dir: &str) -> anyhow::Result<String> {
    if black_box(false) {
        std::fs::create_dir_all(dir)?;
    }
    let s = format!("{dir}/{}", black_box(1u64));
    m.insert(s.clone(), vec![1, 2, 3]);
    Ok(format!("{m:?}"))
}

#[inline(never)]
pub fn run_all(st: &AbciState, p1: &str, p2: &str) -> (Vec<u8>, Vec<u8>) {
    let a = black_box(abci_state_serialize_and_save(st, p1));
    let _ = black_box(abci_state_serialize_and_save(st, p2));
    let b = black_box(abci_state_serialize_to_vec(st));
    let _ = black_box(abci_state_serialize_to_vec(st));
    (a, b)
}
"""

MAIN_RS = r"""#![forbid(unsafe_code)]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::collections::BTreeMap;
use std::hint::black_box;
use storage_abci_w3::*;

fn main() {
    let _ = black_box(touch_generics(black_box(BTreeMap::new()), black_box("d")));
    let st = black_box(AbciState {
        pad: [0; 5],
        height: 7,
    });
    let _ = black_box(run_all(&st, black_box("p"), black_box("q")));
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


def parse_obj_sections(obj: bytes) -> dict[str, tuple[bytes, list[dict]]]:
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

    relocs: dict[int, list[dict]] = {}
    for _idx, _name, stype, soff, ssz, sinfo in o_secs:
        if stype == 4:
            entries: list[dict] = []
            for p in range(soff, soff + ssz, 24):
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", obj, p)
                kind = r_info & 0xFFFFFFFF
                width = 8 if kind == 1 else 4
                entries.append(
                    {
                        "offset": r_offset,
                        "kind": kind,
                        "width": width,
                        "addend": r_addend,
                    }
                )
            relocs[sinfo] = entries

    by_name: dict[str, tuple[bytes, list[dict]]] = {}
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


def compile_thinlto_jemalloc(
    target_dir: Path | None = None,
) -> tuple[list[tuple[str, bytes, list[dict]]], str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="node115-storage-abci-w3-") as td:
        root = Path(td)
        (root / "base_crate" / "src").mkdir(parents=True)
        (root / "storage_abci_w3" / "src").mkdir(parents=True)
        (root / "app" / "src").mkdir(parents=True)
        (root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["base_crate", "storage_abci_w3", "app"]\nresolver = "2"\n\n'
            '[profile.release]\nopt-level = 3\nlto = "thin"\noverflow-checks = true\ncodegen-units = 256\n',
            encoding="utf-8",
        )
        (root / "base_crate" / "Cargo.toml").write_text(
            '[package]\nname = "base_crate"\nversion = "0.1.0"\nedition = "2021"\n\n'
            '[dependencies]\nanyhow = "1"\n',
            encoding="utf-8",
        )
        (root / "storage_abci_w3" / "Cargo.toml").write_text(
            '[package]\nname = "storage_abci_w3"\nversion = "0.1.0"\nedition = "2021"\n\n'
            '[dependencies]\nanyhow = "1"\nbase_crate = { path = "../base_crate" }\n',
            encoding="utf-8",
        )
        (root / "app" / "Cargo.toml").write_text(
            '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n'
            '[dependencies]\nanyhow = "1"\nbase_crate = { path = "../base_crate" }\n'
            'storage_abci_w3 = { path = "../storage_abci_w3" }\n'
            'tikv-jemallocator = "=0.6.0"\n',
            encoding="utf-8",
        )
        (root / "base_crate" / "src" / "lib.rs").write_text(BASE_RS, encoding="utf-8")
        (root / "storage_abci_w3" / "src" / "lib.rs").write_text(LIB_RS, encoding="utf-8")
        (root / "app" / "src" / "main.rs").write_text(MAIN_RS, encoding="utf-8")

        tdir = target_dir if target_dir is not None else (root / "target")
        deps = tdir / "release" / "deps"
        if deps.exists():
            for old_o in list(deps.glob("app-*.o")) + list(deps.glob("storage_abci_w3-*.o")):
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

        compiled: list[tuple[str, bytes, list[dict]]] = []
        for obj_path in sorted(deps.glob("app-*.storage_abci_w3*.rcgu.o")):
            for sym, (cbytes, rels) in parse_obj_sections(obj_path.read_bytes()).items():
                compiled.append((sym, cbytes, rels))
        if not compiled:
            raise AssertionError("ThinLTO + jemalloc build produced no ELF .text.* objects")
        return compiled, ver


def _to_int(v: object) -> int | None:
    if isinstance(v, int):
        return v
    if isinstance(v, str) and (v.startswith("0x") or v.isdigit()):
        return int(v, 0)
    return None


def extract_interval(w: dict, fdes: dict[int, int]) -> tuple[int, int] | None:
    si = None
    for k in ("start", "start_va", "va_start", "fde_start", "node115_start", "va", "start_addr"):
        if w.get(k) is not None:
            si = _to_int(w[k])
            break
    if si is None:
        return None
    for k in ("end", "end_va", "va_end", "fde_end", "node115_end", "end_addr"):
        if w.get(k) is not None:
            ei = _to_int(w[k])
            if ei is not None:
                return (si, ei)
    for k in ("size", "size_bytes", "len", "byte_len", "bytes", "length"):
        if isinstance(w.get(k), int):
            return (si, si + int(w[k]))
    return (si, fdes[si]) if si in fdes else None


def check_disjointness(windows: list[dict], fdes: dict[int, int]) -> None:
    own: list[tuple[int, int, str, str]] = []
    for w in windows:
        s = int(w["start_va"], 16)
        e = int(w["end_va"], 16)
        for ps, pe, plabel, _pcomp in own:
            if s < pe and ps < e:
                raise AssertionError(f"internal overlap {w['label']} vs {plabel}")
        own.append((s, e, w["label"], w["component"]))

    bw = json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8"))
    for ew in bw.get("windows", []):
        iv = extract_interval(ew, fdes)
        if not iv:
            continue
        es, ee = iv
        is_dep = "dependency" in ew
        for s, e, label, comp in own:
            if s < ee and es < e:
                if is_dep or (s, e) != (es, ee) or ew.get("component") != comp:
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
        "*wave*",
        "*identity*",
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
                lists = [d] if isinstance(d, list) else [
                    d.get(k, []) for k in ("windows", "matches", "byte_matches", "compiled_matches")
                ]
                for items in lists:
                    if not isinstance(items, list):
                        continue
                    for ew in items:
                        if not isinstance(ew, dict):
                            continue
                        iv = extract_interval(ew, fdes)
                        if not iv:
                            continue
                        es, ee = iv
                        for s, e, label, _comp in own:
                            if s < ee and es < e:
                                raise AssertionError(
                                    f"overlap with sibling packet {p.parent.name}: "
                                    f"{label} 0x{s:x}..0x{e:x} vs 0x{es:x}..0x{ee:x}"
                                )


def is_first_party_symbol(sym: str, fn_token: str | None = None) -> bool:
    if any(
        bad in sym
        for bad in (
            "drop_in_place",
            "write_fmt",
            "call_once_force",
            "core3ptr",
            "alloc",
            "std4sync",
            "anyhow",
        )
    ):
        return False
    if "storage_abci_w3" not in sym:
        return False
    if fn_token is not None and fn_token not in sym:
        return False
    return True


def verify_location_anchors(
    data115: bytes,
    sections115: dict[str, tuple[int, int, int]],
    loc_anchors: list[dict],
) -> None:
    ro_va, ro_off, ro_sz = sections115[".rodata"]
    dr_va, dr_off, dr_sz = sections115[".data.rel.ro"]
    _rela_va, rela_off, rela_sz = sections115[".rela.dyn"]

    rel_map: dict[int, int] = {}
    for off in range(rela_off, rela_off + rela_sz, 24):
        r_off, r_info, r_add = struct.unpack_from("<QQq", data115, off)
        if (r_info & 0xFFFFFFFF) == 8:
            rel_map[r_off] = r_add

    for loc in loc_anchors:
        va = int(loc["va"], 16)
        if not (dr_va <= va and va + 24 <= dr_va + dr_sz):
            raise AssertionError(f"location anchor out of .data.rel.ro: {loc['name']}")
        ptr = rel_map.get(va)
        if ptr is None or not (ro_va <= ptr < ro_va + ro_sz):
            raise AssertionError(f"location anchor missing .rela.dyn string ptr: {loc['name']}")
        ln, line, col = struct.unpack_from("<QII", data115, dr_off + (va - dr_va) + 8)
        got_file = data115[ro_off + (ptr - ro_va) : ro_off + (ptr - ro_va) + ln].decode("ascii")
        if (got_file, line, col) != (loc["file"], int(loc["line"]), int(loc["col"])):
            raise AssertionError(
                f"location anchor mismatch for {loc['name']}: "
                f"{got_file}:{line}:{col} != {loc['file']}:{loc['line']}:{loc['col']}"
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
    total_raw = 0
    raw_equal_windows = 0

    for comp, label, kind, fn_token, s, e in WINDOW_SPECS:
        sz = e - s
        if fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch for {label}: 0x{s:x}..0x{e:x}")
        tbytes = data115[text_off + (s - text_va) : text_off + (e - text_va)]
        found = None
        for sym, cbytes, rels in compiled:
            if len(cbytes) != sz or not is_first_party_symbol(sym, fn_token):
                continue
            cmp = byte_progress.compare(cbytes, tbytes, rels)
            if not cmp["relocation_qualified"] or cmp["non_relocation_difference_offsets"]:
                continue
            raw_eq = int(cmp["raw_equal_bytes"])
            if found is None or raw_eq > found[3]:
                found = (sym, cbytes, rels, raw_eq)
        if found is None:
            raise AssertionError(
                f"No 0-diff first-party compiled match for {label} ({fn_token}) 0x{s:x}..0x{e:x} ({sz} B)"
            )
        sym, cbytes, rels, raw_eq = found
        body_off = len(bodies)
        bodies.extend(cbytes)
        if raw_eq == sz:
            raw_equal_windows += 1
        total_raw += raw_eq
        windows.append(
            {
                "component": comp,
                "label": label,
                "kind": kind,
                "fn_token": fn_token,
                "compiled_section": sym,
                "start_va": f"0x{s:x}",
                "end_va": f"0x{e:x}",
                "size": sz,
                "body_offset": body_off,
                "raw_equal_bytes": raw_eq,
                "relocations": rels,
                "target_sha256": hashlib.sha256(tbytes).hexdigest(),
                "compiled_sha256": hashlib.sha256(cbytes).hexdigest(),
            }
        )

    rec = {
        "schema_version": 1,
        "work_item": "RE-009-node115-storage-abci-logic-wave3-byte-matches",
        "target_binary": {
            "path": EXPECTED_BINARY_PATH,
            "size": EXPECTED_BINARY_SIZE,
            "sha256": EXPECTED_BINARY_SHA256,
        },
        "toolchain": {
            "rustc_version": rustc_ver,
            "edition": "2021",
            "profile": "opt-level=3, overflow-checks=true, lto=thin, codegen-units=256",
            "allocator": "tikv-jemallocator = 0.6.0",
        },
        "bodies_file": "bodies.bin",
        "bodies_sha256": hashlib.sha256(bytes(bodies)).hexdigest(),
        "rodata_anchors": [
            {"name": name, "va": f"0x{va:x}", "ascii": txt}
            for name, va, txt in RODATA_ANCHORS
        ],
        "location_anchors": [
            {"name": name, "va": f"0x{va:x}", "file": f, "line": ln, "col": col}
            for name, va, f, ln, col in LOCATION_ANCHORS
        ],
        "summary": {
            "windows": len(windows),
            "total_bytes": len(bodies),
            "raw_equal_bytes": total_raw,
            "raw_equal_windows": raw_equal_windows,
            "abci_windows": len(windows),
            "abci_bytes": len(bodies),
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

    verify_location_anchors(data115, sections115, records["location_anchors"])

    windows = records["windows"]
    check_disjointness(windows, fdes)

    tot_bytes = tot_raw = raw_wins = 0
    for w in windows:
        s = int(w["start_va"], 16)
        e = int(w["end_va"], 16)
        sz = int(w["size"])
        boff = int(w["body_offset"])
        if w["component"] != "abci":
            raise AssertionError(f"unexpected component {w['component']!r} for {w['label']}")
        if e - s != sz or fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch for {w['label']}")
        if not (text_va <= s and e <= text_va + text_sz):
            raise AssertionError(f"out of .text: {w['label']}")
        if not is_first_party_symbol(w["compiled_section"], w.get("fn_token")):
            raise AssertionError(f"non-first-party compiled_section: {w['compiled_section']}")

        tbytes = data115[text_off + (s - text_va) : text_off + (e - text_va)]
        if hashlib.sha256(tbytes).hexdigest() != w["target_sha256"]:
            raise AssertionError(f"target_sha256 mismatch for {w['label']}")

        cbytes = bodies[boff : boff + sz]
        if len(cbytes) != sz or hashlib.sha256(cbytes).hexdigest() != w["compiled_sha256"]:
            raise AssertionError(f"compiled body mismatch for {w['label']}")

        cmp = byte_progress.compare(cbytes, tbytes, w["relocations"])
        if not cmp["relocation_qualified"] or cmp["non_relocation_difference_offsets"]:
            raise AssertionError(
                f"byte_progress.compare failed for {w['label']}: "
                f"diffs={cmp['non_relocation_difference_offsets'][:6]}"
            )
        raw_eq = int(cmp["raw_equal_bytes"])
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
        or sm["abci_windows"] != len(windows)
        or sm["abci_bytes"] != tot_bytes
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
        r["windows"][0]["relocations"] = r["windows"][0]["relocations"][1:]

    def mut_bad_fde(r: dict) -> None:
        r["windows"][0]["end_va"] = "0x26a2c7f"
        r["windows"][0]["size"] = 1135

    def mut_overlap(r: dict) -> None:
        r["windows"].append(copy.deepcopy(r["windows"][0]))

    def mut_bad_location(r: dict) -> None:
        r["location_anchors"][0]["line"] = 99999

    rejected = 0
    for name, fn in [
        ("drop_reloc", mut_drop_reloc),
        ("bad_fde", mut_bad_fde),
        ("internal_overlap", mut_overlap),
        ("bad_location", mut_bad_location),
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
    ap.add_argument(
        "--rebuild",
        action="store_true",
        help="Live-rebuild and assert byte-for-byte equality with bodies.bin",
    )
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    data115 = (REPO / EXPECTED_BINARY_PATH).read_bytes()
    sections115 = parse_elf_sections(data115)
    fdes = load_fde_map()
    cached_tdir = REPO / "work" / "target" / "storage-abci-w3"

    if args.generate:
        rec, bodies = build_records_and_bodies(data115, sections115, fdes, target_dir=cached_tdir)
        BODIES_PATH.write_bytes(bodies)
        RECORDS_PATH.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")

    records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    bodies = BODIES_PATH.read_bytes()
    verify_records(records, bodies, data115, sections115, fdes)

    if args.rebuild:
        rebuilt_rec, rebuilt_bodies = build_records_and_bodies(
            data115, sections115, fdes, target_dir=cached_tdir
        )
        if rebuilt_bodies != bodies:
            raise AssertionError("Live ThinLTO+jemalloc rebuild bodies.bin differs from committed bodies.bin")
        if rebuilt_rec["summary"] != records["summary"]:
            raise AssertionError("Live ThinLTO+jemalloc rebuild summary differs from records.json")

    sm = records["summary"]
    msg = (
        f"PASS: {sm['windows']}/{sm['windows']} relocation-qualified, "
        f"{sm['total_bytes']} B ({sm['raw_equal_bytes']} raw-equal, {sm['raw_equal_windows']} 100%-raw; "
        f"abci {sm['abci_windows']}w/{sm['abci_bytes']}B; rebuild={args.rebuild})"
    )
    if args.self_test:
        neg = run_negative_controls(records, bodies, data115, sections115, fdes)
        msg += f", {neg}/{neg} negative controls rejected"
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
