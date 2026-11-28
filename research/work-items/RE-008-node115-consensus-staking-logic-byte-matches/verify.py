#!/usr/bin/env python3
"""Live rustc +1.95.0 compiled-byte verifier for RE-008-node115-consensus-staking-logic-byte-matches.

Verifies 14 strictly disjoint, zero-overlap, 100.00% relocation-qualified first-party
`consensus` (11 FDEs / 1,845 B) and `staking` (3 FDEs / 213 B) `.text` FDEs (2,058 B total)
in Linux x86-64 node #115 (`artifacts/node/115/hl-node`), including core HotStuff quorum
and validator-set lookup business logic (`ValidatorStakes::has_quorum` 365 B,
`ValidatorStakes::contains_key` 226 B), nested consensus event/message/counter enums,
`<&Block as Debug>::fmt`, and custom `Validator`/`Broadcaster`/`CValidator`/`CSigner`
`format_args!` formatters.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
RECORDS_PATH = HERE / "records.json"
LOGIC_SRC = HERE / "logic.rs"
FMT_PIC_SRC = HERE / "fmt_pic.rs"
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_PATH = REPO / "research" / "byte-windows.json"
WORK_ITEMS_DIR = REPO / "research" / "work-items"

TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105_896_032

PIE_FLAGS = [
    "--edition=2021",
    "--crate-type=rlib",
    "--crate-name",
    "cs_logic_pie",
    "-C",
    "opt-level=3",
    "-C",
    "overflow-checks=yes",
    "-C",
    "relocation-model=pie",
    "-C",
    "lto=off",
    "--emit=obj",
]

PIC_FLAGS = [
    "--edition=2021",
    "--crate-type=rlib",
    "--crate-name",
    "cs_fmt_pic",
    "-C",
    "opt-level=3",
    "-C",
    "overflow-checks=yes",
    "-C",
    "relocation-model=pic",
    "-C",
    "lto=off",
    "--emit=obj",
]

# (component, label, source_unit, symbol_substr, start_va, expected_size, expected_rodata_substrings, expected_text_hex_slice)
SPECS: list[tuple[str, str, str, str, int, int, list[str], tuple[int, str] | None]] = [
    # --- Core consensus business logic (PIE, 2 FDEs / 591 B) ---
    (
        "consensus",
        "ValidatorStakes::has_quorum@0x4d3e1a0",
        "logic.rs",
        "validator_stakes_has_quorum",
        0x4D3E1A0,
        365,
        [],
        # 0x4d3e2ee..0x4d3e305: mov $3,%edx; mov %rbx,%rax; mul %rdx; add %rcx,%rcx; cmp %rax,%rcx; sbb %rdx,%rsi; setb %al
        (0x14E, "ba030000004889d848f7e24801c94839c14819d60f92c0"),
    ),
    (
        "consensus",
        "ValidatorStakes::contains_key@0x4d3e310",
        "logic.rs",
        "validator_stakes_contains_key",
        0x4D3E310,
        226,
        [],
        # 0x4d3e379..0x4d3e384: mov $0x14,%edx; mov %rbx,%rdi; call *%r12 (20-byte Validator memcmp)
        (0x69, "ba140000004889df41ffd4"),
    ),
    # --- Consensus nested event enum fmt (PIE, 1 FDE / 291 B) ---
    (
        "consensus",
        "ConsensusEvent::fmt@0x59d70b0",
        "logic.rs",
        "ConsensusEvent",
        0x59D70B0,
        291,
        [
            "InMsg(",
            "ExecutionState",
            "TriggerTimeout",
            "EmptyBlockTimer",
            "PeriodicVoteStream",
            "JailVoteTimer",
            "L1Hash",
            "AbciDigest",
            "Artifact",
        ],
        None,
    ),
    # --- Consensus jump-table & struct/template Debug fmt (PIC, 8 FDEs / 963 B) ---
    (
        "consensus",
        "MsgKind::fmt@0x581fd50",
        "fmt_pic.rs",
        "MsgKind",
        0x581FD50,
        232,
        [
            "ExternalTx",
            "Tx",
            "Block",
            "Vote",
            "Timeout",
            "Tc",
            "Heartbeat",
            "HeartbeatAck",
            "RpcResponse",
            "RpcFailed",
        ],
        None,
    ),
    (
        "consensus",
        "ConsensusCounter::fmt@0x582ad40",
        "fmt_pic.rs",
        "ConsensusCounter",
        0x582AD40,
        211,
        [
            "CommittedBlocks",
            "CommittedTxs",
            "CommittedTxBytes",
            "DroppedTxs",
            "RpcRequestsRegistered",
            "RpcRequestsSent",
            "RoundQc",
            "RoundTc",
            "RoundCatchUp",
        ],
        None,
    ),
    (
        "consensus",
        "<&Block as Debug>::fmt@0x5941bb0",
        "fmt_pic.rs",
        "fmt_ref_block",
        0x5941BB0,
        168,
        ["Block", "proposer", "tx_hashes", "time", "parent"],
        None,
    ),
    (
        "consensus",
        "Validator::fmt@0x581f7a0",
        "fmt_pic.rs",
        "Validator$u20$as$u20$core..fmt..Debug",
        0x581F7A0,
        68,
        ["Validator("],
        None,
    ),
    (
        "consensus",
        "<&Validator as Debug>::fmt@0x57d15e0",
        "fmt_pic.rs",
        "fmt_ref_validator",
        0x57D15E0,
        71,
        ["Validator("],
        None,
    ),
    (
        "consensus",
        "<&Validator as Debug>::fmt@0x292c660",
        "fmt_pic.rs",
        "fmt_ref_validator",
        0x292C660,
        71,
        ["Validator("],
        None,
    ),
    (
        "consensus",
        "<&Broadcaster as Debug>::fmt@0x57d1540",
        "fmt_pic.rs",
        "fmt_ref_broadcaster",
        0x57D1540,
        71,
        ["Broadcaster("],
        None,
    ),
    (
        "consensus",
        "<&Broadcaster as Debug>::fmt@0x241ebc0",
        "fmt_pic.rs",
        "fmt_ref_broadcaster",
        0x241EBC0,
        71,
        ["Broadcaster("],
        None,
    ),
    # --- Staking validator/signer custom format_args! Debug fmt (PIC, 3 FDEs / 213 B) ---
    (
        "staking",
        "<&CValidator as Debug>::fmt@0x53d52c0",
        "fmt_pic.rs",
        "fmt_ref_cvalidator",
        0x53D52C0,
        71,
        ["CValidator("],
        None,
    ),
    (
        "staking",
        "<&CValidator as Debug>::fmt@0x241fce0",
        "fmt_pic.rs",
        "fmt_ref_cvalidator",
        0x241FCE0,
        71,
        ["CValidator("],
        None,
    ),
    (
        "staking",
        "<&CSigner as Debug>::fmt@0x53d5310",
        "fmt_pic.rs",
        "fmt_ref_csigner",
        0x53D5310,
        71,
        ["CSigner("],
        None,
    ),
]


def sha256_bytes(buf: bytes) -> str:
    return hashlib.sha256(buf).hexdigest()


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("Expected little-endian ELF64")
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shs = [
        struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
        for i in range(e_shnum)
    ]
    str_off = shs[e_shstrndx][4]
    out: dict[str, tuple[int, int, int]] = {}
    for sh in shs:
        end = data.index(b"\x00", str_off + sh[0])
        name = data[str_off + sh[0] : end].decode("utf-8", "replace")
        out[name] = (sh[3], sh[4], sh[5])  # (sh_addr, sh_offset, sh_size)
    return out


def parse_relocations(
    data: bytes, secs: dict[str, tuple[int, int, int]], rela_name: str
) -> list[dict[str, int]]:
    if rela_name not in secs:
        return []
    _, off, sz = secs[rela_name]
    out: list[dict[str, int]] = []
    for pos in range(off, off + sz, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, pos)
        r_type = r_info & 0xFFFFFFFF
        width = 8 if r_type == 1 else 4
        out.append(
            {
                "offset": int(r_offset),
                "width": int(width),
                "type": int(r_type),
                "addend": int(r_addend),
            }
        )
    return out


def load_fde_index() -> dict[int, tuple[int, int]]:
    out: dict[int, tuple[int, int]] = {}
    for line in FDE_TSV_PATH.read_text(encoding="utf-8").splitlines()[1:]:
        parts = line.split("\t")
        s = int(parts[0], 0)
        e = int(parts[1], 0)
        sz = int(parts[2], 0)
        if e - s != sz:
            raise ValueError(f"Malformed FDE row: {line}")
        out[s] = (e, sz)
    return out


def check_rodata_anchors(
    fde_bytes: bytes,
    fde_va: int,
    ro_va: int,
    ro_bytes: bytes,
    expected_strings: list[str],
) -> None:
    if not expected_strings:
        return
    # Collect all RIP-relative LEA targets inside fde_bytes pointing into .rodata
    ro_len = len(ro_bytes)
    observed: list[bytes] = []
    n = len(fde_bytes)
    for i in range(n - 6):
        if fde_bytes[i] in (0x48, 0x4C) and fde_bytes[i + 1] == 0x8D:
            modrm = fde_bytes[i + 2]
            if (modrm & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", fde_bytes, i + 3)[0]
                target = fde_va + i + 7 + disp
                if ro_va <= target < ro_va + ro_len:
                    rel = target - ro_va
                    observed.append(ro_bytes[rel : min(ro_len, rel + 64)])
    for needle in expected_strings:
        nb = needle.encode("utf-8")
        if not any(nb in chunk for chunk in observed):
            raise ValueError(
                f"Missing .rodata anchor {needle!r} in FDE {hex(fde_va)}"
            )


def _parse_int(v: object) -> int:
    return int(v, 0) if isinstance(v, str) else int(v)


def _extract_span(row: object) -> tuple[int, int] | None:
    if not isinstance(row, dict):
        return None
    sk = next((k for k in ("start_va", "start", "va", "addr") if k in row), None)
    if sk is None:
        return None
    s = _parse_int(row[sk])
    if "end_va" in row:
        e = _parse_int(row["end_va"])
    elif "end" in row:
        e = _parse_int(row["end"])
    elif "size_bytes" in row:
        e = s + _parse_int(row["size_bytes"])
    elif "size" in row:
        e = s + _parse_int(row["size"])
    else:
        return None
    if e <= s:
        return None
    return (s, e)


def check_disjointness(
    windows: list[tuple[int, int, str]],
    byte_windows_data: dict | None = None,
) -> None:
    # 1. Internal disjointness
    ordered = sorted(windows, key=lambda x: (x[0], x[1]))
    for i in range(len(ordered) - 1):
        s1, e1, l1 = ordered[i]
        s2, e2, l2 = ordered[i + 1]
        if s2 < e1:
            raise ValueError(
                f"Internal overlap: {l1} ({hex(s1)}..{hex(e1)}) vs {l2} ({hex(s2)}..{hex(e2)})"
            )

    # 2. research/byte-windows.json check (Wave-5 consolidation-safe):
    #    - Forbid ANY overlap with dependency windows (source_kind == 'dependency' or component == 'native-libraries'/'dependencies').
    #    - Forbid ANY partial overlap with first-party windows; allow ONLY exact (s, e) == (es, ee)
    #      if Wave 5+ later consolidates this exact packet into byte-windows.json.
    bw = (
        byte_windows_data
        if byte_windows_data is not None
        else json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8"))
    )
    for row in bw.get("windows", []):
        sp = _extract_span(row)
        if sp is None:
            continue
        es, ee = sp
        src_kind = row.get("source_kind", "")
        is_dep = src_kind == "dependency" or row.get("component") in (
            "native-libraries",
            "dependencies",
        )
        for s, e, lbl in ordered:
            if s < ee and es < e:
                if is_dep:
                    raise ValueError(
                        f"Overlap with dependency window {hex(es)}..{hex(ee)} for {lbl} ({hex(s)}..{hex(e)})"
                    )
                if (s, e) != (es, ee):
                    raise ValueError(
                        f"Partial overlap with byte-windows.json {hex(es)}..{hex(ee)} for {lbl} ({hex(s)}..{hex(e)})"
                    )

    # 3. Sibling byte-match / census / thinlto / wave / gate-closure packets: forbid ANY overlap
    #    (skip our own packet and Wave consolidation packets whose records mirror byte-windows.json).
    for p in sorted(WORK_ITEMS_DIR.glob("*/*")):
        if p.name not in ("records.json", "census.json"):
            continue
        parent_name = p.parent.name
        if parent_name == HERE.name:
            continue
        if "consolidation" in parent_name:
            continue
        if not any(
            k in parent_name
            for k in ("byte-match", "gate-closure", "thinlto", "wave")
        ):
            continue
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        for key in ("windows", "records", "matched_fdes"):
            items = doc.get(key)
            if not isinstance(items, list):
                continue
            for row in items:
                sp = _extract_span(row)
                if sp is None:
                    continue
                es, ee = sp
                for s, e, lbl in ordered:
                    if s < ee and es < e:
                        raise ValueError(
                            f"Overlap with sibling packet {parent_name} ({hex(es)}..{hex(ee)}) for {lbl} ({hex(s)}..{hex(e)})"
                        )


def compile_units(tmp_dir: Path) -> tuple[str, dict[str, tuple[bytes, dict[str, tuple[int, int, int]]]]]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    if "1.95.0" not in ver:
        raise RuntimeError(f"Expected rustc 1.95.0, got: {ver}")

    objs: dict[str, tuple[bytes, dict[str, tuple[int, int, int]]]] = {}
    for src_name, src_path, flags in [
        ("logic.rs", LOGIC_SRC, PIE_FLAGS),
        ("fmt_pic.rs", FMT_PIC_SRC, PIC_FLAGS),
    ]:
        out_o = tmp_dir / (src_name + ".o")
        cmd = ["rustc", "+1.95.0"] + flags + ["-o", str(out_o), str(src_path)]
        subprocess.run(cmd, check=True)
        od = out_o.read_bytes()
        objs[src_name] = (od, parse_elf_sections(od))
    return ver, objs


def build_records() -> tuple[dict, list[tuple[bytes, bytes, list[dict[str, int]]]]]:
    sys.path.insert(0, str(REPO / "tools"))
    import byte_progress as bp

    bin_path = REPO / TARGET_REL
    bin_data = bin_path.read_bytes()
    if len(bin_data) != TARGET_SIZE:
        raise ValueError(f"Unexpected binary size: {len(bin_data)} != {TARGET_SIZE}")
    actual_sha = sha256_bytes(bin_data)
    if actual_sha != TARGET_SHA256:
        raise ValueError(f"Unexpected binary SHA-256: {actual_sha}")

    secs = parse_elf_sections(bin_data)
    t_va, t_off, _ = secs[".text"]
    r_va, r_off, r_sz = secs[".rodata"]
    ro_bytes = bin_data[r_off : r_off + r_sz]
    fdes = load_fde_index()

    with tempfile.TemporaryDirectory() as td:
        rustc_ver, objs = compile_units(Path(td))

    windows_out: list[dict] = []
    raw_pairs: list[tuple[bytes, bytes, list[dict[str, int]]]] = []
    span_list: list[tuple[int, int, str]] = []

    for comp, label, src_unit, sym_sub, start_va, exp_sz, ro_strs, txt_anchor in SPECS:
        if start_va not in fdes:
            raise ValueError(f"FDE start {hex(start_va)} not found in node-115-fde.tsv")
        end_va, fde_sz = fdes[start_va]
        if fde_sz != exp_sz:
            raise ValueError(
                f"FDE size mismatch for {label}: {fde_sz} != {exp_sz}"
            )
        tgt_bytes = bin_data[
            t_off + (start_va - t_va) : t_off + (start_va - t_va) + fde_sz
        ]
        check_rodata_anchors(tgt_bytes, start_va, r_va, ro_bytes, ro_strs)
        if txt_anchor is not None:
            off_a, hex_a = txt_anchor
            want_a = bytes.fromhex(hex_a)
            got_a = tgt_bytes[off_a : off_a + len(want_a)]
            if got_a != want_a:
                raise ValueError(
                    f"Text anchor mismatch in {label} at +{hex(off_a)}: {got_a.hex()} != {hex_a}"
                )

        od, osecs = objs[src_unit]
        matches = [n for n in osecs if n.startswith(".text.") and sym_sub in n]
        if len(matches) != 1:
            raise ValueError(
                f"Expected 1 section matching {sym_sub!r} in {src_unit}, got {matches}"
            )
        sname = matches[0]
        _, soff, ssz = osecs[sname]
        comp_bytes = od[soff : soff + ssz]
        relocs = parse_relocations(od, osecs, ".rela" + sname)
        if len(comp_bytes) != fde_sz:
            raise ValueError(
                f"Compiled size mismatch for {label}: {len(comp_bytes)} != {fde_sz}"
            )
        cmp_res = bp.compare(tgt_bytes, comp_bytes, relocs)
        if not cmp_res["relocation_qualified"] or cmp_res["non_relocation_difference_offsets"]:
            raise ValueError(f"Byte comparison failed for {label}: {cmp_res}")

        rel_offsets = sorted(
            {r["offset"] + k for r in relocs for k in range(r["width"])}
        )
        windows_out.append(
            {
                "component": comp,
                "label": label,
                "source_unit": src_unit,
                "compile_flags": PIE_FLAGS if src_unit == "logic.rs" else PIC_FLAGS,
                "start_va": hex(start_va),
                "end_va": hex(end_va),
                "size": fde_sz,
                "target_sha256": sha256_bytes(tgt_bytes),
                "compiled_section": sname,
                "compiled_sha256": sha256_bytes(comp_bytes),
                "compiled_bytes_hex": comp_bytes.hex(),
                "relocations": relocs,
                "relocation_offsets": rel_offsets,
                "raw_equal_bytes": cmp_res["raw_equal_bytes"],
                "relocation_bytes": cmp_res["relocation_bytes"],
                "non_relocation_bytes": cmp_res["non_relocation_bytes"],
                "equal_non_relocation_bytes": cmp_res["equal_non_relocation_bytes"],
                "relocation_qualified": True,
                "rodata_anchors": ro_strs,
                "text_anchor": (
                    {"offset": txt_anchor[0], "bytes_hex": txt_anchor[1]}
                    if txt_anchor is not None
                    else None
                ),
            }
        )
        raw_pairs.append((tgt_bytes, comp_bytes, relocs))
        span_list.append((start_va, end_va, label))

    check_disjointness(span_list)

    consensus_ws = [w for w in windows_out if w["component"] == "consensus"]
    staking_ws = [w for w in windows_out if w["component"] == "staking"]
    rec = {
        "schema_version": 1,
        "work_item": HERE.name,
        "target_binary": {
            "path": TARGET_REL,
            "size": TARGET_SIZE,
            "sha256": TARGET_SHA256,
        },
        "rustc_version": rustc_ver,
        "source_files": {
            "logic.rs": sha256_bytes(LOGIC_SRC.read_bytes()),
            "fmt_pic.rs": sha256_bytes(FMT_PIC_SRC.read_bytes()),
        },
        "summary": {
            "windows": len(windows_out),
            "total_bytes": sum(w["size"] for w in windows_out),
            "raw_equal_bytes": sum(w["raw_equal_bytes"] for w in windows_out),
            "consensus_windows": len(consensus_ws),
            "consensus_bytes": sum(w["size"] for w in consensus_ws),
            "staking_windows": len(staking_ws),
            "staking_bytes": sum(w["size"] for w in staking_ws),
        },
        "windows": windows_out,
    }
    return rec, raw_pairs


def run_negative_controls(
    rec: dict, raw_pairs: list[tuple[bytes, bytes, list[dict[str, int]]]]
) -> int:
    sys.path.insert(0, str(REPO / "tools"))
    import byte_progress as bp

    rejected = 0

    # Control 1: flip 1 non-relocation byte -> must fail bp.compare
    tgt0, comp0, rel0 = raw_pairs[0]
    rel_set = {r["offset"] + k for r in rel0 for k in range(r["width"])}
    flip_idx = next(i for i in range(len(comp0)) if i not in rel_set)
    mut = bytearray(comp0)
    mut[flip_idx] ^= 0xFF
    res = bp.compare(tgt0, bytes(mut), rel0)
    if res["relocation_qualified"]:
        raise AssertionError("Negative control 1 failed: flipped byte still qualified")
    rejected += 1

    # Control 2: shifted FDE start_va + 1 -> must not match node-115-fde.tsv
    fdes = load_fde_index()
    if (int(rec["windows"][0]["start_va"], 16) + 1) in fdes:
        raise AssertionError("Negative control 2 failed: start_va+1 unexpectedly in FDE index")
    rejected += 1

    # Control 3: corrupted .rodata anchor string -> must fail check_rodata_anchors
    bin_data = (REPO / TARGET_REL).read_bytes()
    secs = parse_elf_sections(bin_data)
    t_va, t_off, _ = secs[".text"]
    r_va, r_off, r_sz = secs[".rodata"]
    ro_bytes = bin_data[r_off : r_off + r_sz]
    w2 = rec["windows"][2]
    s2 = int(w2["start_va"], 16)
    b2 = bin_data[t_off + (s2 - t_va) : t_off + (s2 - t_va) + w2["size"]]
    try:
        check_rodata_anchors(b2, s2, r_va, ro_bytes, ["NONEXISTENT_CONSENSUS_ANCHOR_XYZ"])
    except ValueError:
        rejected += 1
    else:
        raise AssertionError("Negative control 3 failed: bogus rodata anchor accepted")

    # Control 4: synthetic overlap against dependency window -> must fail check_disjointness
    bw_mut = copy.deepcopy(json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8")))
    s0 = int(rec["windows"][0]["start_va"], 16)
    e0 = int(rec["windows"][0]["end_va"], 16)
    bw_mut["windows"].append(
        {
            "component": "dependencies",
            "source_kind": "dependency",
            "start": hex(s0),
            "end": hex(e0),
        }
    )
    try:
        check_disjointness([(s0, e0, "synthetic")], byte_windows_data=bw_mut)
    except ValueError:
        rejected += 1
    else:
        raise AssertionError("Negative control 4 failed: dependency overlap accepted")

    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="Write records.json")
    ap.add_argument("--self-test", action="store_true", help="Run adversarial negative controls")
    args = ap.parse_args()

    rec, raw_pairs = build_records()
    if args.write:
        RECORDS_PATH.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
    else:
        pinned = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        if pinned != rec:
            raise ValueError("Live compiled records do not match pinned records.json")

    neg_msg = ""
    if args.self_test:
        n_rej = run_negative_controls(rec, raw_pairs)
        neg_msg = f", {n_rej}/4 negative controls rejected"

    s = rec["summary"]
    pct = 100.0 * s["raw_equal_bytes"] / s["total_bytes"]
    print(
        f"PASS: {s['windows']}/{s['windows']} relocation-qualified "
        f"(consensus {s['consensus_windows']}w/{s['consensus_bytes']} B, "
        f"staking {s['staking_windows']}w/{s['staking_bytes']} B; "
        f"total {s['total_bytes']} B, {s['raw_equal_bytes']}/{s['total_bytes']} = {pct:.2f}% raw-equal, "
        f"0 overlaps{neg_msg})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
