#!/usr/bin/env python3
"""Packet checker for RE-001-tag3-tag4-queries-1af0-1e40-115.

Checks, all against the materialized node #115 binary:
  1. binary SHA-256 matches provenance/artifacts.json
  2. MANIFEST.sha256 matches every packet file
  3. excerpts + call-site windows + frames.txt regenerate
     byte-for-byte via export_excerpts.py
  4. every excerpt line's bytes match the raw binary
     (file offset = virtual address - 0x1000 in the executable LOAD segment)
  5. every frames.txt FDE line is present in fresh readelf output,
     each site window holds its call to the query, and
     callers.tsv lists every recorded site
  6. census: executable-LOAD E8/E9 scan gives exactly the recorded
     sites for the tag-3 query, the tag-4 query, the gate, the
     limit check, the flag-bit setter, frame-and-deliver and the
     frame builder, confirmed with objdump; the ULEB128 encoder
     has exactly 165 direct calls including the eleven
     query-family sites; no RELATIVE relocation targets any
     pinned routine; no stored qwords; exactly one RELATIVE
     record at 0x64ecf80 with addend 0x5d4d490 (the expected-slot
     walker global)
  7. the gate jump table at 0x97c5f4 resolves to the targets in
     jump_table.tsv, byte-for-byte against the raw binary
  8. records.json is semantic-only (no per-instruction token list)
     and its consumer counts match the census
  9. model spot checks plus every test_* function in
     tests/test_tag3_tag4_queries_1af0_1e40_115.py

Run from the repository root: python3 <packet>/verify.py
Prints ALL CHECKS PASSED or exits non-zero naming the failed check.
"""
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path.cwd()
PACKET = ROOT / "research/work-items/RE-001-tag3-tag4-queries-1af0-1e40-115"
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
EXCERPTS = {
    "tag3.txt": (0x61B1AF0, 0x61B1E18),
    "tag4.txt": (0x61B1E40, 0x61B21CA),
    "gate.txt": (0x61B1930, 0x61B19E7),
    "limit_check.txt": (0x61B1910, 0x61B192B),
    "bitset.txt": (0x61B18B0, 0x61B18C8),
    "frame_deliver.txt": (0x61B1A10, 0x61B1AC6),
    "varint.txt": (0x61BD410, 0x61BD4E9),
    "framer.txt": (0x61B1260, 0x61B13A3),
    "cleanup_tag3.txt": (0x61B1AC6, 0x61B1AEB),
    "cleanup_tag4.txt": (0x61B1E18, 0x61B1E3D),
    "site-5e8f565.txt": (0x5E8F53E, 0x5E8F58D),
    "site-5e8f5a4.txt": (0x5E8F57E, 0x5E8F5CC),
    "site-5e90e06.txt": (0x5E90DDE, 0x5E90E2E),
    "site-5e90e42.txt": (0x5E90E1C, 0x5E90E6A),
    "site-5e922ca.txt": (0x5E922A8, 0x5E922F2),
    "site-5e92ebe.txt": (0x5E92E97, 0x5E92EE6),
    "site-5e92efa.txt": (0x5E92ED4, 0x5E92F22),
    "site-5d61261.txt": (0x5D6123B, 0x5D61289),
    "site-5e706b9.txt": (0x5E70697, 0x5E706E1),
    "site-5e7cd24.txt": (0x5E7CCFE, 0x5E7CD4C),
}
SITE_FILES = {
    0x5E8F565: ("site-5e8f565.txt", "61b1af0"),
    0x5E8F5A4: ("site-5e8f5a4.txt", "61b1af0"),
    0x5E90E06: ("site-5e90e06.txt", "61b1af0"),
    0x5E90E42: ("site-5e90e42.txt", "61b1af0"),
    0x5E922CA: ("site-5e922ca.txt", "61b1af0"),
    0x5E92EBE: ("site-5e92ebe.txt", "61b1af0"),
    0x5E92EFA: ("site-5e92efa.txt", "61b1af0"),
    0x5D61261: ("site-5d61261.txt", "61b1e40"),
    0x5E706B9: ("site-5e706b9.txt", "61b1e40"),
    0x5E7CD24: ("site-5e7cd24.txt", "61b1e40"),
}
EXPECTED_SITES = {
    0x61B1AF0: [(0x5E8F565, "call"), (0x5E8F5A4, "call"),
               (0x5E90E06, "call"), (0x5E90E42, "call"),
               (0x5E922CA, "call"), (0x5E92EBE, "call"),
               (0x5E92EFA, "call")],
    0x61B1E40: [(0x5D61261, "call"), (0x5E706B9, "call"),
               (0x5E7CD24, "call")],
    0x61B1930: [(0x61B1B28, "call"), (0x61B1E7B, "call"),
               (0x61B2247, "call"), (0x61B27B7, "call"),
               (0x61B2DC8, "call")],
    0x61B1910: [(0x61B1940, "call")],
    0x61B18B0: [(0x61B1CD4, "call"), (0x61B202C, "call"),
               (0x61B203B, "call"), (0x61B23EC, "call"),
               (0x61B23FB, "call"), (0x61B241F, "call"),
               (0x61B25BF, "call"), (0x61B295C, "call"),
               (0x61B296B, "call"), (0x61B298F, "call"),
               (0x61B2B2F, "call"), (0x61B2F46, "call"),
               (0x61B2F53, "call"), (0x61B2F60, "call"),
               (0x61B368B, "call")],
    0x61B1A10: [(0x61B1D88, "call"), (0x61B211E, "call"),
               (0x61B257B, "call"), (0x61B2AEB, "call"),
               (0x61B3318, "call"), (0x61B36B2, "call"),
               (0x61B3CC7, "call")],
    0x61B1260: [(0x61B1A57, "call"), (0x61BB28F, "call"),
               (0x61BBA0E, "call"), (0x61BC790, "call"),
               (0x61BCC0E, "call")],
}
VARINT = 0x61BD410
VARINT_FAMILY_SITES = [0x61B1D2B, 0x61B20C0, 0x61B24A3, 0x61B251A,
                       0x61B25D8, 0x61B2A13, 0x61B2A8A, 0x61B2B48,
                       0x61B306E, 0x61B31C6, 0x61B3275]
VARINT_TOTAL = 165
EXPECTED_GLOBAL = 0x64ECF80
EXPECTED_ADDEND = 0x5D4D490
JUMP_TABLE_ADDR = 0x97C5F4


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def scan_calls(data, target):
    """Executable-LOAD E8/E9 scan for one target, each candidate
    confirmed with objdump. Returns sorted (va, kind) pairs."""
    found = []
    for off, base, size in EXEC:
        seg = data[off:off + size]
        for op in (0xE8, 0xE9):
            i = seg.find(bytes([op]))
            while i != -1:
                if i + 5 <= len(seg):
                    rel = struct.unpack_from("<i", seg, i + 1)[0]
                    if base + i + 5 + rel == target:
                        va = base + i
                        out = subprocess.run(
                            ["objdump", "-d",
                             f"--start-address={va:#x}",
                             f"--stop-address={va + 6:#x}", str(BIN)],
                            capture_output=True, text=True).stdout
                        for line in out.splitlines():
                            if (f"{va:x}:" in line
                                    and f"{target:x}" in line
                                    and ("call" in line
                                         or "jmp" in line)):
                                found.append(
                                    (va, "call" if op == 0xE8
                                     else "jmp"))
                i = seg.find(bytes([op]), i + 1)
    return sorted(found)


def main():
    data = BIN.read_bytes()
    # 1. digest + provenance binding
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("binary digest mismatch")
    prov = json.loads((ROOT / "provenance/artifacts.json").read_text())
    digests = [f["sha256"] for f in prov["files"]]
    if DIGEST not in digests:
        fail("digest not present in provenance/artifacts.json")
    # 2. manifest
    manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    seen = {}
    for line in manifest:
        digest, name = line.split("  ")
        seen[name] = digest
    actual = {p.name for p in PACKET.iterdir() if p.name != "MANIFEST.sha256"}
    if set(seen) != actual:
        fail(f"manifest file set mismatch: {sorted(set(seen) ^ actual)}")
    for name, digest in seen.items():
        if hashlib.sha256((PACKET / name).read_bytes()).hexdigest() != digest:
            fail(f"manifest hash mismatch for {name}")
    # 3. excerpt + site window + frames regeneration byte-for-byte
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, str(PACKET / "export_excerpts.py"), tmp],
                       check=True, cwd=ROOT, capture_output=True)
        for name in (list(EXCERPTS) + ["frames.txt"]):
            if (Path(tmp) / name).read_bytes() != (PACKET / name).read_bytes():
                fail(f"regenerated {name} differs from packet copy")
    # 4. every excerpt line byte-for-byte vs raw binary,
    # including objdump continuation lines
    line_re = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\t")
    cont_re = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\s*$")
    total = 0
    for name, (start, end) in EXCERPTS.items():
        prev_va = prev_len = None
        for line in (PACKET / name).read_text().splitlines():
            m = line_re.match(line)
            if m:
                va = int(m.group(1), 16)
                if prev_va is not None and va != prev_va + prev_len:
                    fail(f"{name}: line at 0x{va:x} does not follow previous")
                raw = bytes.fromhex(m.group(2).replace(" ", ""))
                if not (start <= va < end):
                    fail(f"{name}: line at 0x{va:x} outside range")
                if data[va - 0x1000: va - 0x1000 + len(raw)] != raw:
                    fail(f"{name}: bytes mismatch at 0x{va:x}")
                prev_va, prev_len = va, len(raw)
                total += 1
            else:
                m = cont_re.match(line)
                if not m:
                    continue
                va = int(m.group(1), 16)
                if prev_va is None or va != prev_len + prev_va:
                    fail(f"{name}: continuation line at 0x{va:x} "
                         f"does not follow previous bytes")
                raw = bytes.fromhex(m.group(2).replace(" ", ""))
                if not (start <= va < end):
                    fail(f"{name}: line at 0x{va:x} outside range")
                if data[va - 0x1000: va - 0x1000 + len(raw)] != raw:
                    fail(f"{name}: bytes mismatch at 0x{va:x}")
                prev_va, prev_len = va, len(raw)
    print(f"excerpt lines verified byte-for-byte: {total}")
    # 5. FDE lines present in fresh readelf output; site windows hold
    # their calls to the queries; callers.tsv lists every site
    frames = subprocess.run(["readelf", "--debug-dump=frames", str(BIN)],
                            capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        if line not in frames:
            fail(f"FDE line missing from readelf output: {line}")
    for va, (name, target) in SITE_FILES.items():
        site_text = (PACKET / name).read_text()
        if f"{va:x}:" not in site_text or target not in site_text:
            fail(f"{name} missing window for 0x{va:x}")
    tsv = (PACKET / "callers.tsv").read_text()
    for sites in EXPECTED_SITES.values():
        for va, _kind in sites:
            if f"{va:#x}" not in tsv:
                fail(f"callers.tsv missing site 0x{va:x}")
    for va in VARINT_FAMILY_SITES:
        if f"{va:#x}" not in tsv:
            fail(f"callers.tsv missing varint site 0x{va:x}")
    # 6. census + relocations + stored qwords
    for target, expected in EXPECTED_SITES.items():
        confirmed = scan_calls(data, target)
        if confirmed != sorted(expected):
            fail(f"census mismatch for {target:#x}: {confirmed} != {expected}")
        print(f"census for {target:#x}: {len(confirmed)} sites, as recorded")
        if data.count(struct.pack("<Q", target)) != 0:
            fail("stored qword references found")
    varint_calls = scan_calls(data, VARINT)
    if len(varint_calls) != VARINT_TOTAL:
        fail(f"varint census mismatch: {len(varint_calls)} != {VARINT_TOTAL}")
    if not all((va, "call") in varint_calls for va in VARINT_FAMILY_SITES):
        fail("varint family sites missing from census")
    if data.count(struct.pack("<Q", VARINT)) != 0:
        fail("stored qword references found for varint")
    print(f"census for varint 0x61bd410: {len(varint_calls)} sites, as recorded")
    relocs = subprocess.run(["readelf", "-r", str(BIN)],
                            capture_output=True, text=True).stdout
    global_hits = []
    for ln in relocs.splitlines():
        f = ln.split()
        if len(f) >= 3 and f[2] == "R_X86_64_RELATIVE":
            try:
                addr = int(f[0], 16)
                addend = int(f[-1], 16)
            except ValueError:
                continue
            if addend in EXPECTED_SITES or addend == VARINT:
                fail("RELATIVE relocation targets a pinned routine")
            if addr == EXPECTED_GLOBAL:
                global_hits.append(addend)
    if global_hits != [EXPECTED_ADDEND]:
        fail(f"walker global relocation mismatch: {global_hits}")
    print("walker global relocation: 0x64ecf80 -> 0x5d4d490, as recorded")
    # 7. gate jump table resolves against the raw binary
    rows = (PACKET / "jump_table.tsv").read_text().splitlines()[1:]
    if len(rows) != 11:
        fail(f"jump table row count: {len(rows)} != 11")
    for row in rows:
        index, tag, rel32, target, _handler = row.split("\t")
        rel = struct.unpack_from(
            "<i", data, JUMP_TABLE_ADDR + int(index) * 4)[0]
        if rel != int(rel32, 16):
            fail(f"jump table entry {index}: rel32 {rel:#x} != {rel32}")
        if JUMP_TABLE_ADDR + rel != int(target, 16):
            fail(f"jump table entry {index}: target mismatch")
    print("jump table entries verified byte-for-byte: 11")
    # 8. records.json is semantic-only; consumer counts match census
    records_text = (PACKET / "records.json").read_text()
    for banned in ("mnemonic", "instructions"):
        if banned in records_text:
            fail(f"records.json contains banned token: {banned}")
    records = json.loads(records_text)
    if records["routine"]["binary_sha256"] != DIGEST:
        fail("records.json digest mismatch")
    for target, expected in EXPECTED_SITES.items():
        entry = records["consumers"][f"{target:#x}"]
        if entry["direct_calls"] != len(expected):
            fail(f"records.json consumer count mismatch for {target:#x}")
        if entry["tail_jumps"] != 0 or entry["stored_qwords"] != 0:
            fail(f"records.json consumer census mismatch for {target:#x}")
        if sorted(int(s, 16) for s in entry["sites"]) != sorted(
                va for va, _ in expected):
            fail(f"records.json site list mismatch for {target:#x}")
    varint_entry = records["consumers"][f"{VARINT:#x}"]
    if varint_entry["direct_calls"] != VARINT_TOTAL:
        fail("records.json varint count mismatch")
    if sorted(int(s, 16) for s in varint_entry["sites"]) != sorted(
            VARINT_FAMILY_SITES):
        fail("records.json varint site list mismatch")
    table = records["gate_jump_table"]["entries"]
    if len(table) != 11:
        fail("records.json jump table entry count mismatch")
    for entry in table:
        rel = struct.unpack_from(
            "<i", data, JUMP_TABLE_ADDR + entry["index"] * 4)[0]
        if JUMP_TABLE_ADDR + rel != int(entry["target"], 16):
            fail("records.json jump table target mismatch")
    # 9. model spot checks + test functions
    sys.path.insert(0, str(ROOT))
    from tools.tag3_tag4_queries_1af0_1e40_115 import (
        Obj, build_message_tag3, build_message_tag4, frame, gate,
        pick_handler, set_bit, tag3_query, tag4_query, uleb128,
        zero_out_record)
    if uleb128(0x7F) != b"\x7f" or uleb128(0x80) != b"\x80\x01":
        fail("model spot check failed: varint widths")
    if set_bit(0, 1) != (0x02, 1) or set_bit(0x02, 1) != (0x02, 0):
        fail("model spot check failed: flag-bit setter")
    obj = Obj([0x5D4D490] * 13, 10, 3, 0, "t", lambda: 5)
    if gate(obj, 3) or obj.counter30 != 1:
        fail("model spot check failed: gate throttle step 1")
    if gate(obj, 3) or obj.counter30 != 2:
        fail("model spot check failed: gate throttle step 2")
    if not gate(obj, 3) or obj.counter30 != 0:
        fail("model spot check failed: gate throttle fires on 3rd")
    if pick_handler([0x5D4D490, 0x5D4D490, 0x1234] + [0x5D4D490] * 10) != 2:
        fail("model spot check failed: chain walk first mismatch")
    if pick_handler([0x5D4D490] * 13) != 12:
        fail("model spot check failed: chain walk thirteenth link")
    if build_message_tag3((b"AB", 2))[:8] != struct.pack("<Q", 0x02):
        fail("model spot check failed: tag-3 message mask")
    if build_message_tag4(0xAABBCCDD, (b"AB", 2))[:12] != (
            struct.pack("<Q", 0x0C) + struct.pack("<I", 0xAABBCCDD)):
        fail("model spot check failed: tag-4 message mask and u32")
    if frame(0x99, 3, b"MSG") != (struct.pack("<Q", 0x99) + b"\x03"
                                  + struct.pack("<I", 3) + b"MSG"):
        fail("model spot check failed: frame layout")
    seen = []
    out, framed = tag3_query(
        Obj([0x5D4D490] * 13, 10, 1, 0, "t", lambda: 5),
        (b"A", 1), handler=lambda i: (seen.append(i), 0x42)[1],
        deliver=lambda o, t, f: o.update(
            {"u32": 1, "u16": 2, "qword": 3}))
    if seen != [12] or out != {"u32": 1, "u16": 2, "qword": 3}:
        fail("model spot check failed: tag-3 end to end")
    seen = []
    out, framed = tag4_query(
        Obj([0x5D4D490] * 13, 10, 1, 0, "t", lambda: 5),
        lambda: 0x1234, (b"A", 1),
        handler=lambda i: (seen.append(i), 0x42)[1],
        deliver=lambda o, t, f: o.update(
            {"u32": 1, "u16": 2, "qword": 3}))
    if seen != [12] or out != {"u32": 1, "u16": 2, "qword": 3}:
        fail("model spot check failed: tag-4 end to end")
    spec_t = importlib.util.spec_from_file_location(
        "test_tag3_tag4_queries_1af0_1e40_115",
        ROOT / "tests/test_tag3_tag4_queries_1af0_1e40_115.py")
    tests = importlib.util.module_from_spec(spec_t)
    spec_t.loader.exec_module(tests)
    passed = 0
    for name in dir(tests):
        if name.startswith("test_"):
            getattr(tests, name)()
            passed += 1
    print(f"model tests passed: {passed}")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
