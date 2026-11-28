#!/usr/bin/env python3
"""Verify 8 strictly disjoint pure first-party node-runtime gossip protocol compiled-byte
FDE matches (3,893 B: 7 zero-dep bincode-fork::Encode = 3,003 B; 1 serde::Serialize = 890 B)
against node #115."""

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
import tomllib
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_JSON = REPO_ROOT / "research" / "byte-windows.json"
WORK_ITEMS_DIR = REPO_ROOT / "research" / "work-items"
STD_BINCODE_DIR = PACKET_DIR / "std_bincode"
JEM_SERDE_DIR = PACKET_DIR / "jem_serde"
LICENSES_PATH = PACKET_DIR / "licenses.json"
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

RUST_SOURCES = [
    STD_BINCODE_DIR / "encode_req.rs",
    STD_BINCODE_DIR / "encode_status_peer.rs",
    STD_BINCODE_DIR / "encode_resp.rs",
    JEM_SERDE_DIR / "src" / "main.rs",
]

FORBIDDEN_SYMBOL_TOKENS = (
    "drop_in_place",
    "core::",
    "alloc::",
    "std::",
    "hashbrown",
    "serde_json",
    "rmp_serde",
    "simd_contains",
    "call_once_force",
    "write_fmt",
)

# 8 strictly disjoint pure first-party node-runtime FDEs (3,893 B):
# (start_va, end_va, window_id, component, pool, kind, symbol_token, description, rodata_anchors)
TARGET_WINDOWS = [
    (
        0x5A80370,
        0x5A806EA,
        "node-runtime-gossip-rpc-request-serde-json-serialize-5a80370",
        "node-runtime",
        "jem_serde",
        "serde_serialize",
        "GossipRpcRequest",
        "node/src/gossip_rpc.rs <GossipRpcRequest as serde::Serialize>::serialize (serde_json compact, 0x5a80370)",
        ["ClientBlocks", "Peers", "GossipStatus", "start_round", "end_round"],
    ),
    (
        0x5AA9710,
        0x5AA9848,
        "node-runtime-gossip-status-bincode-encode-sw-5aa9710",
        "node-runtime",
        "std_bincode:encode_status_peer",
        "bincode_encode",
        "GossipStatus",
        "node/src/gossip_rpc.rs <GossipStatus as bincode_fork::Encode>::encode (SizeWriter, 0x5aa9710)",
        [],
    ),
    (
        0x5AA9850,
        0x5AA99D7,
        "node-runtime-gossip-status-bincode-encode-vec-5aa9850",
        "node-runtime",
        "std_bincode:encode_status_peer",
        "bincode_encode",
        "GossipStatus",
        "node/src/gossip_rpc.rs <GossipStatus as bincode_fork::Encode>::encode (VecWriter, 0x5aa9850)",
        [],
    ),
    (
        0x5AAA630,
        0x5AAA735,
        "node-runtime-gossip-peer-entry-bincode-encode-vec-5aaa630",
        "node-runtime",
        "std_bincode:encode_status_peer",
        "bincode_encode",
        "PeerEntry",
        "node/src/gossip_rpc.rs <(NodeIp, PeerInfo) as bincode_fork::Encode>::encode (VecWriter, called by VecDeque::encode 0x58272e0, 0x5aaa630)",
        [],
    ),
    (
        0x5AAA740,
        0x5AAA808,
        "node-runtime-ref-gossip-rpc-request-bincode-encode-sw-5aaa740",
        "node-runtime",
        "std_bincode:encode_req",
        "bincode_encode",
        "Encode",
        "node/src/gossip_rpc.rs <&GossipRpcRequest as bincode_fork::Encode>::encode (SizeWriter, 0x5aaa740)",
        [],
    ),
    (
        0x5AAA810,
        0x5AAAB63,
        "node-runtime-ref-gossip-rpc-response-bincode-encode-vec-5aaa810",
        "node-runtime",
        "std_bincode:encode_resp",
        "bincode_encode",
        "Encode",
        "node/src/gossip_rpc.rs <&GossipRpcResponse as bincode_fork::Encode>::encode (VecWriter, 0x5aaa810)",
        [],
    ),
    (
        0x5AAAB70,
        0x5AAAC38,
        "node-runtime-ref-gossip-rpc-request-bincode-encode-vec-5aaab70",
        "node-runtime",
        "std_bincode:encode_req",
        "bincode_encode",
        "Encode",
        "node/src/gossip_rpc.rs <&GossipRpcRequest as bincode_fork::Encode>::encode (VecWriter, 0x5aaab70)",
        [],
    ),
    (
        0x5AAAC40,
        0x5AAAF54,
        "node-runtime-ref-gossip-rpc-response-bincode-encode-sw-5aaac40",
        "node-runtime",
        "std_bincode:encode_resp",
        "bincode_encode",
        "Encode",
        "node/src/gossip_rpc.rs <&GossipRpcResponse as bincode_fork::Encode>::encode (SizeWriter, 0x5aaac40)",
        [],
    ),
]


def _to_int(v) -> int:
    return int(v, 16) if isinstance(v, str) else int(v)


def check_forbid_unsafe_and_licenses() -> None:
    for rs in RUST_SOURCES:
        txt = rs.read_text(encoding="utf-8")
        if "#![forbid(unsafe_code)]" not in txt:
            raise AssertionError(f"Missing #![forbid(unsafe_code)] in {rs}")
    licenses = json.loads(LICENSES_PATH.read_text(encoding="utf-8"))
    lock = tomllib.loads((JEM_SERDE_DIR / "Cargo.lock").read_text(encoding="utf-8"))
    lock_pkgs = {
        f"{p['name']} {p['version']}"
        for p in lock["package"]
        if p["name"] != "hl_node115_gossip_serde"
    }
    missing = sorted(lock_pkgs - set(licenses.keys()))
    if missing:
        raise AssertionError(f"Missing licenses.json entries: {missing}")


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    for line in FDE_TSV.read_text(encoding="utf-8").splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 2:
            fdes[int(parts[0], 16)] = int(parts[1], 16)
    return fdes


def check_rodata_anchors(
    bin_data: bytes,
    rodata: dict,
    va: int,
    tbytes: bytes,
    relocs: list[dict],
    expected_strings: list[str],
) -> list[str]:
    if not expected_strings:
        return []
    ro_va, ro_off, ro_end = (
        rodata["address"],
        rodata["offset"],
        rodata["address"] + rodata["size"],
    )
    matched: set[str] = set()
    n = len(tbytes)
    for rel in relocs:
        o = rel["offset"]
        rt = rel["type"]
        add = rel["addend"]
        if rt != 2 or o + 4 > n:
            continue
        disp = struct.unpack_from("<i", tbytes, o)[0]
        tva = va + o - add + disp
        if ro_va <= tva < ro_end:
            foff = ro_off + (tva - ro_va)
            for s in expected_strings:
                sb = s.encode("utf-8")
                if bin_data[foff : foff + len(sb)] == sb:
                    matched.add(s)
    missing = [s for s in expected_strings if s not in matched]
    if missing:
        raise AssertionError(
            f"Missing direct PC32 .rodata anchors at {hex(va)}: {missing} (found {sorted(matched)})"
        )
    return sorted(matched)


def check_disjoint_against_repo(records: list[dict]) -> None:
    intervals = sorted((r["start"], r["end"], r["id"]) for r in records)
    for i in range(1, len(intervals)):
        if intervals[i][0] < intervals[i - 1][1]:
            raise AssertionError(f"Internal overlap: {intervals[i - 1]} vs {intervals[i]}")

    own_ids = {r["id"] for r in records}
    claimed: list[tuple[int, int, str]] = []

    if BYTE_WINDOWS_JSON.exists():
        bw = json.loads(BYTE_WINDOWS_JSON.read_text(encoding="utf-8"))
        for w in bw if isinstance(bw, list) else bw.get("windows", []):
            wid = w.get("id", "")
            if wid in own_ids:
                continue
            claimed.append((_to_int(w["start"]), _to_int(w["end"]), f"byte-windows.json:{wid}"))

    for pat in ("records.json", "census.json"):
        for p in sorted(WORK_ITEMS_DIR.glob(f"*/{pat}")):
            if p.parent.resolve() == PACKET_DIR.resolve():
                continue
            obj = json.loads(p.read_text(encoding="utf-8"))
            items = obj if isinstance(obj, list) else obj.get("windows", obj.get("records", []))
            for w in items:
                if not isinstance(w, dict):
                    continue
                if "start" in w and "end" in w:
                    s, e = _to_int(w["start"]), _to_int(w["end"])
                elif "start_va" in w and "end_va" in w:
                    s, e = _to_int(w["start_va"]), _to_int(w["end_va"])
                elif "va" in w and "size" in w:
                    s = _to_int(w["va"])
                    e = s + _to_int(w["size"])
                else:
                    continue
                claimed.append((s, e, f"{p.parent.name}/{pat}"))

    for r in records:
        s, e = r["start"], r["end"]
        for cs, ce, src in claimed:
            if cs < e and s < ce:
                raise AssertionError(
                    f"Overlap for {r['id']} ({hex(s)}..{hex(e)}) with {src} ({hex(cs)}..{hex(ce)})"
                )


def _compile_std_bincode(rs_path: Path, td: Path) -> list[tuple[list[str], bytes, list[tuple[int, int, int]]]]:
    obj_path = td / f"{rs_path.stem}.o"
    subprocess.run(
        [
            "rustc",
            "+1.95.0",
            "--edition=2021",
            "--crate-type=rlib",
            f"--crate-name={rs_path.stem}",
            "-C",
            "opt-level=3",
            "-C",
            "overflow-checks=yes",
            "-C",
            "relocation-model=pie",
            "-C",
            "lto=off",
            "-C",
            "codegen-units=1",
            "--emit=obj",
            "-o",
            str(obj_path),
            str(rs_path),
        ],
        check=True,
        env={**os.environ, "RUST_MIN_STACK": "16777216"},
    )
    return list(object_functions(obj_path.read_bytes()))


def _compile_jem_serde(td: Path) -> list[tuple[list[str], bytes, list[tuple[int, int, int]]]]:
    target_dir = os.environ.get("NODE_RUNTIME_WAVE3_JEM_TARGET_DIR")
    if target_dir:
        tdir = Path(target_dir)
        tdir.mkdir(parents=True, exist_ok=True)
    else:
        tdir = td / "jem_target"
    env = {
        **os.environ,
        "CARGO_BUILD_JOBS": os.environ.get("CARGO_BUILD_JOBS", "4"),
        "CARGO_TARGET_DIR": str(tdir),
        "RUST_MIN_STACK": "16777216",
    }
    subprocess.run(
        [
            "cargo",
            "+1.95.0",
            "rustc",
            "--release",
            "--offline",
            "--locked",
            "--",
            "-C",
            "overflow-checks=yes",
            "-C",
            "save-temps",
        ],
        cwd=str(JEM_SERDE_DIR),
        env=env,
        check=True,
    )
    objs = sorted(
        p
        for p in glob.glob(str(tdir / "release" / "deps" / "hl_node115_gossip_serde-*.rcgu.o"))
        if not p.endswith(".rcgu.o.rcgu.o")
    )
    if not objs:
        raise AssertionError(f"No .rcgu.o objects produced in {tdir}")
    out = []
    for p in objs:
        out.extend(object_functions(Path(p).read_bytes()))
    return out


def rebuild_from_source(bin_data: bytes, text_sec: dict, rodata_sec: dict) -> tuple[bytes, list[dict]]:
    pools: dict[str, list[tuple[list[str], bytes, list[tuple[int, int, int]]]]] = {}
    with tempfile.TemporaryDirectory(prefix="node115_streamc_w3_") as td_str:
        td = Path(td_str)
        pools["std_bincode:encode_req"] = _compile_std_bincode(STD_BINCODE_DIR / "encode_req.rs", td)
        pools["std_bincode:encode_status_peer"] = _compile_std_bincode(
            STD_BINCODE_DIR / "encode_status_peer.rs", td
        )
        pools["std_bincode:encode_resp"] = _compile_std_bincode(STD_BINCODE_DIR / "encode_resp.rs", td)
        pools["jem_serde"] = _compile_jem_serde(td)

    bodies = bytearray()
    records: list[dict] = []
    for s, e, wid, comp, pool_name, kind, sym_tok, desc, anchors in TARGET_WINDOWS:
        size = e - s
        off = text_sec["offset"] + (s - text_sec["address"])
        tbytes = bin_data[off : off + size]

        best = None
        for names, body, relocs in pools[pool_name]:
            if len(body) != size:
                continue
            sym = names[0]
            if sym_tok not in sym:
                continue
            if any(tok in sym for tok in FORBIDDEN_SYMBOL_TOKENS):
                continue
            rels = [{"offset": o, "width": 4, "type": t, "addend": a} for (o, t, a) in relocs]
            res = compare(body, tbytes, rels)
            if res["relocation_qualified"] and not res["non_relocation_difference_offsets"]:
                if best is None or res["raw_equal_bytes"] > best[2]["raw_equal_bytes"]:
                    best = (sym, body, res, rels)

        if best is None:
            raise AssertionError(f"No strict relocation-qualified match found for {wid} ({hex(s)}..{hex(e)})")

        sym, body, res, rels = best
        matched_anchors = check_rodata_anchors(bin_data, rodata_sec, s, tbytes, rels, anchors)
        body_offset = len(bodies)
        bodies.extend(body)
        records.append(
            {
                "id": wid,
                "component": comp,
                "pool": pool_name,
                "kind": kind,
                "start": s,
                "end": e,
                "start_va": hex(s),
                "end_va": hex(e),
                "size": size,
                "raw_equal_bytes": res["raw_equal_bytes"],
                "relocation_count": len(rels),
                "body_offset": body_offset,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "target_body_sha256": hashlib.sha256(tbytes).hexdigest(),
                "compiled_symbol": sym,
                "rodata_anchors": matched_anchors,
                "relocations": rels,
                "description": desc,
            }
        )

    return bytes(bodies), records


def write_packet_artifacts(bodies: bytes, records: list[dict]) -> None:
    BODIES_PATH.write_bytes(bodies)
    comp_summary: dict[str, dict[str, int]] = {}
    for r in records:
        c = comp_summary.setdefault(r["component"], {"windows": 0, "bytes": 0, "raw_equal_bytes": 0})
        c["windows"] += 1
        c["bytes"] += r["size"]
        c["raw_equal_bytes"] += r["raw_equal_bytes"]
    payload = {
        "schema_version": 1,
        "work_item": "RE-005-node115-transport-runtime-logic-wave3-byte-matches",
        "source_kind": "first-party clean-room rebuild",
        "binary_path": "artifacts/node/115/hl-node",
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "binary_size": EXPECTED_BINARY_SIZE,
        "compiler": "rustc 1.95.0 (59807616e 2026-04-14)",
        "summary": {
            "total_windows": len(records),
            "matched_bytes": sum(r["size"] for r in records),
            "raw_equal_bytes": sum(r["raw_equal_bytes"] for r in records),
            "bodies_sha256": hashlib.sha256(bodies).hexdigest(),
        },
        "components": comp_summary,
        "windows": records,
    }
    RECORDS_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def verify_records(bin_data: bytes, text_sec: dict, rodata_sec: dict, fdes: dict[int, int]) -> dict:
    check_forbid_unsafe_and_licenses()
    payload = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    bodies = BODIES_PATH.read_bytes()

    if payload["binary_sha256"] != EXPECTED_BINARY_SHA256 or payload["binary_size"] != EXPECTED_BINARY_SIZE:
        raise AssertionError("Pinned binary metadata mismatch")
    if hashlib.sha256(bodies).hexdigest() != payload["summary"]["bodies_sha256"]:
        raise AssertionError("bodies.bin sha256 mismatch")

    records = payload["windows"]
    if len(records) != len(TARGET_WINDOWS):
        raise AssertionError(f"Expected {len(TARGET_WINDOWS)} windows, got {len(records)}")

    expected_keys = [(s, e, wid, comp) for s, e, wid, comp, *_ in TARGET_WINDOWS]
    actual_keys = [(r["start"], r["end"], r["id"], r["component"]) for r in records]
    if actual_keys != expected_keys:
        raise AssertionError("Window list mismatch vs TARGET_WINDOWS")

    total_bytes = 0
    total_raw = 0
    for r, spec in zip(records, TARGET_WINDOWS):
        s, e = r["start"], r["end"]
        if fdes.get(s) != e:
            raise AssertionError(f"Window {r['id']} ({hex(s)}..{hex(e)}) is not an exact node #115 FDE")
        if any(tok in r["compiled_symbol"] for tok in FORBIDDEN_SYMBOL_TOKENS):
            raise AssertionError(f"Forbidden symbol token in {r['compiled_symbol']}")
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
        check_rodata_anchors(bin_data, rodata_sec, s, tbytes, r["relocations"], spec[8])
        total_bytes += r["size"]
        total_raw += res["raw_equal_bytes"]

    if total_bytes != payload["summary"]["matched_bytes"] or total_raw != payload["summary"]["raw_equal_bytes"]:
        raise AssertionError("Summary totals mismatch")

    check_disjoint_against_repo(records)
    return payload


def run_negative_controls(bin_data: bytes, text_sec: dict, rodata_sec: dict, payload: dict) -> int:
    bodies = BODIES_PATH.read_bytes()
    r0 = payload["windows"][0]
    body0 = bodies[r0["body_offset"] : r0["body_offset"] + r0["size"]]
    off0 = text_sec["offset"] + (r0["start"] - text_sec["address"])
    tbytes0 = bin_data[off0 : off0 + r0["size"]]
    rel_covered = {rel["offset"] + k for rel in r0["relocations"] for k in range(rel["width"])}
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

    # Control 5: Missing .rodata anchor string must be rejected by check_rodata_anchors()
    try:
        check_rodata_anchors(
            bin_data, rodata_sec, r0["start"], tbytes0, r0["relocations"], ["__nonexistent_anchor__"]
        )
        raise AssertionError("Expected missing .rodata anchor rejection")
    except AssertionError:
        rejected += 1

    return rejected


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rebuild", action="store_true", help="Rebuild bodies.bin & records.json from Rust sources")
    ap.add_argument("--self-test", action="store_true", help="Run 5 negative controls after verification")
    args = ap.parse_args()

    bin_data = BINARY_PATH.read_bytes()
    if len(bin_data) != EXPECTED_BINARY_SIZE:
        raise AssertionError(f"Unexpected binary size: {len(bin_data)}")
    actual_sha = hashlib.sha256(bin_data).hexdigest()
    if actual_sha != EXPECTED_BINARY_SHA256:
        raise AssertionError(f"Unexpected binary sha256: {actual_sha}")

    secs = {s["name"]: s for s in sections(bin_data)}
    text_sec = secs[".text"]
    rodata_sec = secs[".rodata"]
    fdes = load_fde_map()

    if args.rebuild:
        bodies, records = rebuild_from_source(bin_data, text_sec, rodata_sec)
        write_packet_artifacts(bodies, records)

    payload = verify_records(bin_data, text_sec, rodata_sec, fdes)
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
        n_neg = run_negative_controls(bin_data, text_sec, rodata_sec, payload)
        msg += f" | {n_neg}/5 negative controls rejected"
    print(msg)


if __name__ == "__main__":
    main()
