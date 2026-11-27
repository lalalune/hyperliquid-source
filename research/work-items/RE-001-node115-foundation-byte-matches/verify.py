#!/usr/bin/env python3
"""Compile lib.rs (rlib) and thinlto.rs (ThinLTO) with rustc 1.95.0 and verify 69 first-party foundation (`base`) FDE byte matches against node #115."""

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

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_JSON = REPO_ROOT / "research" / "byte-windows.json"
RLIB_SOURCE_PATH = PACKET_DIR / "lib.rs"
THINLTO_SOURCE_PATH = PACKET_DIR / "thinlto.rs"
RECORDS_PATH = PACKET_DIR / "records.json"

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032

# (build_mode, category, symbol_key, start_va, end_va, label)
WINDOWS: list[tuple[str, str, str, int, int, str]] = [
    # 1. Pure business logic (rlib, -C opt-level=3 -C overflow-checks=yes)
    (
        "rlib",
        "business_logic",
        "short_string_pack_rec",
        0x15472B0,
        0x1547309,
        "base/src/short_string.rs:52 short_string_pack_rec (0x15472b0)",
    ),
    # 2. First-party base enum Debug formatters (ThinLTO)
    (
        "thinlto",
        "enum_debug",
        "fmt_crate_debug_ref",
        0x1534270,
        0x153429F,
        "base <&Crate as Debug>::fmt (13 workspace crates, 0x1534270)",
    ),
    (
        "thinlto",
        "enum_debug",
        "fmt_phrase_err_debug_ref",
        0x1544470,
        0x15444A3,
        "base <&PhraseCheckError as Debug>::fmt (0x1544470)",
    ),
    # 3. First-party base struct Debug formatters (ThinLTO) — 36 FDEs, 8,513 B
    (
        "thinlto",
        "struct_debug",
        "fmt_zip_inner_args",
        0x150CFE0,
        0x150D0BD,
        "base <ZipInnerArgs as Debug>::fmt (0x150cfe0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_log_settings_ref",
        0x1544270,
        0x154446C,
        "base <&LogSettings as Debug>::fmt (7 fields, 0x1544270)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_log_settings",
        0x15528B0,
        0x1552AA9,
        "base <LogSettings as Debug>::fmt (7 fields, 0x15528b0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_code_location_ref",
        0x1500880,
        0x150095D,
        "base <&CodeLocation as Debug>::fmt (0x1500880)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_code_location",
        0x1552430,
        0x155250D,
        "base <CodeLocation as Debug>::fmt (0x1552430)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_code_location_ref",
        0x27724E0,
        0x27725BD,
        "base <&CodeLocation as Debug>::fmt (0x27724e0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_code_location",
        0x2A01560,
        0x2A0163D,
        "base <CodeLocation as Debug>::fmt (0x2a01560)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_code_location_ref",
        0x47732D0,
        0x47733AD,
        "base <&CodeLocation as Debug>::fmt (0x47732d0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_code_location",
        0x47756D0,
        0x47757AD,
        "base <CodeLocation as Debug>::fmt (0x47756d0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_code_location",
        0x4FB38E0,
        0x4FB39BD,
        "base <CodeLocation as Debug>::fmt (0x4fb38e0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_code_location_ref",
        0x5615CD0,
        0x5615DAD,
        "base <&CodeLocation as Debug>::fmt (0x5615cd0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_id_refref",
        0x1544000,
        0x15440E0,
        "base <&&LockId as Debug>::fmt (0x1544000)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_id_refref",
        0x29AF7E0,
        0x29AF8C0,
        "base <&&LockId as Debug>::fmt (0x29af7e0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_id_refref",
        0x4772EB0,
        0x4772F90,
        "base <&&LockId as Debug>::fmt (0x4772eb0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_id_refref",
        0x4F0DA40,
        0x4F0DB20,
        "base <&&LockId as Debug>::fmt (0x4f0da40)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_location_ref",
        0x15440E0,
        0x15441BD,
        "base <&LockLocation as Debug>::fmt (0x15440e0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_location",
        0x1552350,
        0x155242D,
        "base <LockLocation as Debug>::fmt (0x1552350)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_location_ref",
        0x29AF520,
        0x29AF5FD,
        "base <&LockLocation as Debug>::fmt (0x29af520)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_location",
        0x2A010A0,
        0x2A0117D,
        "base <LockLocation as Debug>::fmt (0x2a010a0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_location_ref",
        0x4773140,
        0x477321D,
        "base <&LockLocation as Debug>::fmt (0x4773140)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_location",
        0x47755F0,
        0x47756CD,
        "base <LockLocation as Debug>::fmt (0x47755f0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_location_ref",
        0x4F0DE70,
        0x4F0DF4D,
        "base <&LockLocation as Debug>::fmt (0x4f0de70)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_location",
        0x4FB3800,
        0x4FB38DD,
        "base <LockLocation as Debug>::fmt (0x4fb3800)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_order_witness",
        0x15527D0,
        0x15528AD,
        "base <LockOrderWitness as Debug>::fmt (0x15527d0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_order_witness",
        0x2A01640,
        0x2A0171D,
        "base <LockOrderWitness as Debug>::fmt (0x2a01640)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_order_witness",
        0x47757B0,
        0x477588D,
        "base <LockOrderWitness as Debug>::fmt (0x47757b0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_order_witness",
        0x4FB4750,
        0x4FB482D,
        "base <LockOrderWitness as Debug>::fmt (0x4fb4750)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_ordering_violation_ref",
        0x15441C0,
        0x1544265,
        "base <&LockOrderingViolation as Debug>::fmt (0x15441c0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_ordering_violation_ref",
        0x29AF630,
        0x29AF6D5,
        "base <&LockOrderingViolation as Debug>::fmt (0x29af630)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_ordering_violation_ref",
        0x4773220,
        0x47732C5,
        "base <&LockOrderingViolation as Debug>::fmt (0x4773220)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_lock_ordering_violation_ref",
        0x4F0DC00,
        0x4F0DCA5,
        "base <&LockOrderingViolation as Debug>::fmt (0x4f0dc00)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_signature_refref",
        0x1534160,
        0x1534267,
        "base <&&Signature as Debug>::fmt (0x1534160)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_signature_ref",
        0x2D48580,
        0x2D48684,
        "base <&Signature as Debug>::fmt (0x2d48580)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_signature",
        0x4FB3660,
        0x4FB3764,
        "base <Signature as Debug>::fmt (0x4fb3660)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_signature_ref",
        0x53D4EB0,
        0x53D4FB4,
        "base <&Signature as Debug>::fmt (0x53d4eb0)",
    ),
    (
        "thinlto",
        "struct_debug",
        "fmt_signature",
        0x5AA77B0,
        0x5AA78B4,
        "base <Signature as Debug>::fmt (0x5aa77b0)",
    ),
    # 4. First-party base serde Visitor::expecting FDEs (ThinLTO) — 30 FDEs, 750 B
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_bug_alert_ack",
        0x1500A00,
        0x1500A19,
        "base BugAlertAck expecting (0x1500a00)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_ignore",
        0x1500A20,
        0x1500A39,
        "base Ignore expecting (0x1500a20)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_signature",
        0x1533D40,
        0x1533D59,
        "base Signature expecting (0x1533d40)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_tuple_time",
        0x1560990,
        0x15609A9,
        "base Time expecting (0x1560990)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_api_secrets",
        0x15609B0,
        0x15609C9,
        "base ApiSecrets expecting (0x15609b0)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_signed_indexed_upload",
        0x1585010,
        0x1585029,
        "base SignedIndexedUpload expecting (0x1585010)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_visor_metadata",
        0x15B8AB0,
        0x15B8AC9,
        "base VisorMetadata expecting (0x15b8ab0)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_hotfix_args",
        0x15B8AD0,
        0x15B8AE9,
        "base HotfixArgs expecting (0x15b8ad0)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_hotfix_metadata",
        0x15B8AF0,
        0x15B8B09,
        "base HotfixMetadata expecting (0x15b8af0)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_publisher_binary_metadata",
        0x15B8B10,
        0x15B8B29,
        "base PublisherBinaryMetadata expecting (0x15b8b10)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_signature",
        0x2420B40,
        0x2420B59,
        "base Signature expecting (0x2420b40)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_tuple_bucket_guard",
        0x292CE90,
        0x292CEA9,
        "base BucketGuard tuple expecting (0x292ce90)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_struct_bucket_guard",
        0x2C7D070,
        0x2C7D089,
        "base BucketGuard struct expecting (0x2c7d070)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_signature",
        0x2D4A340,
        0x2D4A359,
        "base Signature expecting (0x2d4a340)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_signature",
        0x36CD470,
        0x36CD489,
        "base Signature expecting (0x36cd470)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_tuple_time",
        0x3D52940,
        0x3D52959,
        "base Time expecting (0x3d52940)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_struct_bucket_guard",
        0x4228FB0,
        0x4228FC9,
        "base BucketGuard struct expecting (0x4228fb0)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_signature",
        0x46DE2D0,
        0x46DE2E9,
        "base Signature expecting (0x46de2d0)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_tuple_bucket_guard",
        0x46DE2F0,
        0x46DE309,
        "base BucketGuard tuple expecting (0x46de2f0)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_tuple_time",
        0x4E39670,
        0x4E39689,
        "base Time expecting (0x4e39670)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_tuple_time",
        0x4E397B0,
        0x4E397C9,
        "base Time expecting (0x4e397b0)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_signed_indexed_upload",
        0x50D9080,
        0x50D9099,
        "base SignedIndexedUpload expecting (0x50d9080)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_signature",
        0x53D6110,
        0x53D6129,
        "base Signature expecting (0x53d6110)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_signature",
        0x53D64B0,
        0x53D64C9,
        "base Signature expecting (0x53d64b0)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_struct_bucket_guard",
        0x5616B70,
        0x5616B89,
        "base BucketGuard struct expecting (0x5616b70)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_tuple_bucket_guard",
        0x5A2EEB0,
        0x5A2EEC9,
        "base BucketGuard tuple expecting (0x5a2eeb0)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_hotfix_metadata",
        0x5A2F290,
        0x5A2F2A9,
        "base HotfixMetadata expecting (0x5a2f290)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_visor_metadata",
        0x5A2F390,
        0x5A2F3A9,
        "base VisorMetadata expecting (0x5a2f390)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_publisher_binary_metadata",
        0x5A2F430,
        0x5A2F449,
        "base PublisherBinaryMetadata expecting (0x5a2f430)",
    ),
    (
        "thinlto",
        "visitor_expecting",
        "base_expecting_hotfix_args",
        0x5A2F4D0,
        0x5A2F4E9,
        "base HotfixArgs expecting (0x5a2f4d0)",
    ),
]


def parse_elf_sections(
    blob: bytes,
) -> list[tuple[int, str, int, int, int, int, int, int]]:
    e_shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", blob, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", blob, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", blob, 0x3E)[0]
    shstr_off = struct.unpack_from(
        "<Q", blob, e_shoff + e_shstrndx * e_shentsize + 24
    )[0]
    out = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, _sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info = (
            struct.unpack_from("<IIQQQQII", blob, off)
        )
        end = blob.find(b"\0", shstr_off + sh_name)
        name = blob[shstr_off + sh_name : end].decode("latin1")
        out.append((i, name, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_info))
    return out


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


def load_registered_windows() -> list[tuple[int, int, str, bool]]:
    if not BYTE_WINDOWS_JSON.exists():
        return []
    bw = json.loads(BYTE_WINDOWS_JSON.read_text(encoding="utf-8"))
    return [
        (int(w["start"]), int(w["end"]), str(w.get("id", "?")), "dependency" in w)
        for w in bw.get("windows", [])
    ]


def load_sibling_packet_windows() -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    work_items = REPO_ROOT / "research" / "work-items"
    for rec_path in sorted(work_items.glob("*/records.json")):
        if rec_path.parent == PACKET_DIR:
            continue
        if not (
            "byte-matches" in rec_path.parent.name
            or rec_path.parent.name == "RE-015-node115-constants-gate-closure"
        ):
            continue
        data = json.loads(rec_path.read_text(encoding="utf-8"))
        for w in data.get("windows", []):
            sv = w.get("start_va") if "start_va" in w else w.get("start")
            ev = w.get("end_va") if "end_va" in w else w.get("end")
            if sv is None or ev is None:
                continue
            s = int(sv, 16) if isinstance(sv, str) else int(sv)
            e = int(ev, 16) if isinstance(ev, str) else int(ev)
            out.append((s, e, rec_path.parent.name))
    return out


def extract_compiled_symbols(obj: bytes) -> list[tuple[str, bytes, list[int]]]:
    secs = parse_elf_sections(obj)
    symtabs = [s for s in secs if s[2] == 2]
    if not symtabs:
        return []
    symtab = symtabs[0]
    strtab = secs[symtab[6]]
    relas_by_sec: dict[int, list[int]] = {}
    for s in secs:
        if s[2] == 4:
            relas_by_sec[s[7]] = [
                struct.unpack_from("<Q", obj, o)[0]
                for o in range(s[4], s[4] + s[5], 24)
            ]
    out = []
    for o in range(symtab[4], symtab[4] + symtab[5], 24):
        st_name, _st_info, _st_other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", obj, o
        )
        if st_size == 0 or st_shndx >= len(secs):
            continue
        end = obj.find(b"\0", strtab[4] + st_name)
        name = obj[strtab[4] + st_name : end].decode("latin1")
        sec = secs[st_shndx]
        code = obj[sec[4] + st_value : sec[4] + st_value + st_size]
        rels = sorted(
            r_off - st_value
            for r_off in relas_by_sec.get(st_shndx, [])
            if st_value <= r_off < st_value + st_size
        )
        out.append((name, code, rels))
    return out


def compile_objects() -> tuple[
    list[tuple[str, bytes, list[int]]],
    list[tuple[str, bytes, list[int]]],
    str,
]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="re001-foundation-bytes-") as tmpdir:
        td = Path(tmpdir)
        rlib_obj = td / "foundation_rlib.o"
        subprocess.run(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-type=rlib",
                "--crate-name=foundation_byte_matches_rlib",
                "-C",
                "opt-level=3",
                "-C",
                "overflow-checks=yes",
                "--emit=obj",
                "-o",
                str(rlib_obj),
                str(RLIB_SOURCE_PATH),
            ],
            check=True,
        )
        rlib_syms = extract_compiled_symbols(rlib_obj.read_bytes())

        thin_dir = td / "thinlto"
        thin_dir.mkdir()
        subprocess.run(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-name=foundation_byte_matches_thinlto",
                "-C",
                "opt-level=3",
                "-C",
                "overflow-checks=yes",
                "-C",
                "lto=thin",
                "-C",
                "codegen-units=1",
                "-C",
                "save-temps",
                "-o",
                str(thin_dir / "probe"),
                str(THINLTO_SOURCE_PATH),
            ],
            check=True,
            cwd=thin_dir,
        )
        thin_syms: list[tuple[str, bytes, list[int]]] = []
        for obj_p in sorted(thin_dir.glob("*.rcgu.o")):
            thin_syms.extend(extract_compiled_symbols(obj_p.read_bytes()))
        return rlib_syms, thin_syms, ver


def match_symbol(
    syms: list[tuple[str, bytes, list[int]]], needle: str
) -> tuple[str, bytes, list[int]]:
    token = f"{len(needle)}{needle}17h"
    matches = [s for s in syms if token in s[0]]
    if len(matches) != 1:
        raise ValueError(
            f"expected 1 symbol matching {token!r}, found {len(matches)}: {[m[0] for m in matches]}"
        )
    return matches[0]


def build_records(hl_data: bytes) -> dict[str, object]:
    hl_secs = {s[1]: s for s in parse_elf_sections(hl_data)}
    t_addr, t_off = hl_secs[".text"][3], hl_secs[".text"][4]
    fde_map = load_fde_map()
    reg_windows = load_registered_windows()
    sibling_windows = load_sibling_packet_windows()
    rlib_syms, thin_syms, rustc_version = compile_objects()

    rows = []
    seen_ranges: list[tuple[int, int]] = []
    for mode, category, sym_key, start_va, end_va, label in WINDOWS:
        if fde_map and fde_map.get(start_va) != end_va:
            raise ValueError(
                f"FDE mismatch for {label}: index has {fde_map.get(start_va)}, expected 0x{end_va:x}"
            )
        for rs, re_, rid, is_dep in reg_windows:
            if start_va < re_ and rs < end_va:
                if is_dep or (start_va, end_va) != (rs, re_):
                    raise ValueError(
                        f"Window {label} overlaps research/byte-windows.json entry {rid}"
                    )
        for ss, se, sname in sibling_windows:
            if start_va < se and ss < end_va:
                raise ValueError(
                    f"Window {label} overlaps sibling packet {sname} (0x{ss:x}..0x{se:x})"
                )
        for ps, pe in seen_ranges:
            if start_va < pe and ps < end_va:
                raise ValueError(
                    f"Internal overlap for {label} (0x{start_va:x}..0x{end_va:x})"
                )
        seen_ranges.append((start_va, end_va))

        syms = rlib_syms if mode == "rlib" else thin_syms
        _sym_name, compiled, rels = match_symbol(syms, sym_key)
        target = hl_data[t_off + (start_va - t_addr) : t_off + (end_va - t_addr)]
        if len(compiled) != len(target):
            raise ValueError(
                f"length mismatch for {label}: compiled={len(compiled)} target={len(target)}"
            )
        mask = bytearray(len(compiled))
        for r_off in rels:
            for k in range(4):
                if r_off + k < len(mask):
                    mask[r_off + k] = 1
        mismatches = [
            i for i in range(len(compiled)) if not mask[i] and compiled[i] != target[i]
        ]
        if mismatches:
            raise ValueError(
                f"non-relocation mismatches for {label}: {mismatches[:8]}"
            )
        raw_equal = sum(1 for a, b in zip(compiled, target) if a == b)
        rows.append(
            {
                "component": "foundation",
                "build_mode": mode,
                "category": category,
                "label": label,
                "symbol_key": sym_key,
                "start_va": f"0x{start_va:x}",
                "end_va": f"0x{end_va:x}",
                "size": len(target),
                "raw_equal_bytes": raw_equal,
                "relocation_offsets": rels,
                "relocation_qualified": True,
                "target_sha256": hashlib.sha256(target).hexdigest(),
                "compiled_sha256": hashlib.sha256(compiled).hexdigest(),
            }
        )

    by_cat: dict[str, dict[str, int]] = {}
    for r in rows:
        cat = str(r["category"])
        entry = by_cat.setdefault(cat, {"windows": 0, "bytes": 0})
        entry["windows"] += 1
        entry["bytes"] += int(r["size"])

    return {
        "schema_version": 1,
        "work_item": "RE-001-node115-foundation-byte-matches",
        "target_binary": {
            "path": "artifacts/node/115/hl-node",
            "size": len(hl_data),
            "sha256": hashlib.sha256(hl_data).hexdigest(),
        },
        "rlib_source_sha256": hashlib.sha256(RLIB_SOURCE_PATH.read_bytes()).hexdigest(),
        "thinlto_source_sha256": hashlib.sha256(
            THINLTO_SOURCE_PATH.read_bytes()
        ).hexdigest(),
        "rustc_version": rustc_version,
        "summary": {
            "windows": len(rows),
            "total_bytes": sum(int(r["size"]) for r in rows),
            "raw_equal_bytes": sum(int(r["raw_equal_bytes"]) for r in rows),
            "by_category": by_cat,
        },
        "windows": rows,
    }


def verify_records(
    records: dict[str, object], hl_data: bytes, rebuild: bool = True
) -> None:
    tb = records["target_binary"]
    if tb["sha256"] != EXPECTED_BINARY_SHA256 or tb["size"] != EXPECTED_BINARY_SIZE:
        raise ValueError("target_binary metadata mismatch")
    if hashlib.sha256(hl_data).hexdigest() != EXPECTED_BINARY_SHA256:
        raise ValueError("on-disk binary SHA-256 mismatch")
    if (
        records["rlib_source_sha256"]
        != hashlib.sha256(RLIB_SOURCE_PATH.read_bytes()).hexdigest()
    ):
        raise ValueError("rlib_source_sha256 mismatch")
    if (
        records["thinlto_source_sha256"]
        != hashlib.sha256(THINLTO_SOURCE_PATH.read_bytes()).hexdigest()
    ):
        raise ValueError("thinlto_source_sha256 mismatch")

    rows = records["windows"]
    if len(rows) != len(WINDOWS):
        raise ValueError(f"expected {len(WINDOWS)} windows, got {len(rows)}")
    seen = set()
    for r in rows:
        key = (r["start_va"], r["end_va"])
        if key in seen:
            raise ValueError(f"duplicate window {key}")
        seen.add(key)

    if rebuild:
        rebuilt = build_records(hl_data)
        if (
            rebuilt["windows"] != records["windows"]
            or rebuilt["summary"] != records["summary"]
        ):
            raise ValueError(
                "rebuilt compiled-byte records diverge from committed records.json"
            )
    else:
        hl_secs = {s[1]: s for s in parse_elf_sections(hl_data)}
        t_addr, t_off = hl_secs[".text"][3], hl_secs[".text"][4]
        for r in rows:
            s_va = int(r["start_va"], 16)
            e_va = int(r["end_va"], 16)
            target = hl_data[t_off + (s_va - t_addr) : t_off + (e_va - t_addr)]
            if (
                len(target) != r["size"]
                or hashlib.sha256(target).hexdigest() != r["target_sha256"]
            ):
                raise ValueError(f"target bytes mismatch for {r['label']}")
            if not r["relocation_qualified"]:
                raise ValueError(f"window not relocation-qualified: {r['label']}")


def run_negative_controls(records: dict[str, object], hl_data: bytes) -> int:
    mutations = []

    m1 = copy.deepcopy(records)
    m1["rlib_source_sha256"] = "0" * 64
    mutations.append(("corrupted_rlib_source_sha256", m1))

    m2 = copy.deepcopy(records)
    m2["windows"][0]["target_sha256"] = "f" * 64
    mutations.append(("corrupted_target_sha256", m2))

    m3 = copy.deepcopy(records)
    m3["windows"][0]["relocation_qualified"] = False
    mutations.append(("relocation_qualified_false", m3))

    m4 = copy.deepcopy(records)
    m4["windows"][1] = copy.deepcopy(m4["windows"][0])
    mutations.append(("duplicate_window", m4))

    for name, mutated in mutations:
        try:
            verify_records(mutated, hl_data, rebuild=False)
        except ValueError:
            continue
        raise AssertionError(f"negative control {name} was unexpectedly accepted")
    return len(mutations)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write", action="store_true", help="Compile and write records.json"
    )
    parser.add_argument(
        "--self-test", action="store_true", help="Run negative controls"
    )
    args = parser.parse_args()

    hl_data = BINARY_PATH.read_bytes()
    if args.write:
        records = build_records(hl_data)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        verify_records(records, hl_data, rebuild=False)
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        verify_records(records, hl_data, rebuild=True)

    neg = run_negative_controls(records, hl_data) if args.self_test else 0
    s = records["summary"]
    print(
        f"RE-001-node115-foundation-byte-matches verified: "
        f"{s['windows']}/{s['windows']} relocation-qualified windows, "
        f"{s['total_bytes']} B ({s['raw_equal_bytes']} raw-equal), "
        f"categories={s['by_category']}"
        + (f", {neg}/{neg} negative controls rejected." if args.self_test else ".")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
