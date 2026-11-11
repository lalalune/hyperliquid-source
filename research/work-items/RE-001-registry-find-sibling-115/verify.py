#!/usr/bin/env python3
"""Packet checker for RE-001-registry-find-sibling-115 (node #115).

Run from the repository root:

    python3 research/work-items/RE-001-registry-find-sibling-115/verify.py

11 checks: (1) artifact digest, (2) MANIFEST coverage, (3) excerpt
regeneration byte-for-byte, (4) raw-byte instruction check of every
excerpt line, (5) fixed spots + three seeded random gate spots
(random.seed(20261106)), (6) FDE presence, (7) relocation presence,
(8) literal read-back, (9) census reproduction, (10) GOT
re-derivation from relocations.txt plus model constants, (11) model
tests. Prints ALL CHECKS PASSED on success.
"""

import hashlib
import json
import random
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = {
    "entry.txt": (0x609A740, 0x609B6F3),
    "find_e70.txt": (0x6099E70, 0x609A1A9),
    "no_equals.txt": (0x609BA30, 0x609BA76),
    "resolve_no_equals.txt": (0x609B8A0, 0x609BA2A),
    "kind_dispatch.txt": (0x609B700, 0x609B869),
    "element_scan.txt": (0x6096F40, 0x609710F),
    "name_lookup.txt": (0x60BA0B0, 0x60BA441),
    "hash_name_find.txt": (0x60B84B0, 0x60B8564),
    "move_assign.txt": (0x60B79E0, 0x60B7AB8),
    "ends_with.txt": (0x61D1390, 0x61D13DB),
    "str_compare.txt": (0x61D13E0, 0x61D1437),
    "fallback_delegate.txt": (0x6097150, 0x6097192),
    "delegate_impl.txt": (0x6097110, 0x609714E),
    "zero_stub.txt": (0x60956F0, 0x609570C),
    "find_norm.txt": (0x609A410, 0x609A67C),
    "parser.txt": (0x60C1190, 0x60C1887),
    "map_clear.txt": (0x5D5B300, 0x5D5B39B),
    "status_builder.txt": (0x61CF670, 0x61CF767),
    "shared_release.txt": (0x5D35070, 0x5D350BC),
}

# Fixed gate spots: (address, substring expected in the line).
SPOTS = [
    (0x609A740, "endbr64"),
    (0x6099E70, "endbr64"),
    (0x609B700, "endbr64"),
    (0x60BA0B0, "endbr64"),
    (0x609B8A0, "endbr64"),
]

# Census routine name -> address (for check 9).
NAME_TO_ADDR = {
    "entry": 0x609A740,
    "find_e70": 0x6099E70,
    "no_equals": 0x609BA30,
    "resolve_no_equals": 0x609B8A0,
    "kind_dispatch": 0x609B700,
    "element_scan": 0x6096F40,
    "name_lookup": 0x60BA0B0,
    "hash_name_find": 0x60B84B0,
    "move_assign": 0x60B79E0,
    "ends_with": 0x61D1390,
    "str_compare": 0x61D13E0,
    "fallback_delegate": 0x6097150,
    "delegate_impl": 0x6097110,
    "zero_stub": 0x60956F0,
    "find_norm": 0x609A410,
    "parser": 0x60C1190,
    "map_clear": 0x5D5B300,
    "status_builder": 0x61CF670,
    "shared_release": 0x5D35070,
}

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t")


def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)


def load_segments(data):
    """(vaddr, file offset, file size) for PT_LOAD segments."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    out = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz,
         _memsz, _align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1:
            out.append((p_vaddr, p_offset, p_filesz))
    return out


def va_to_off(segments, va):
    for vaddr, offset, filesz in segments:
        if vaddr <= va < vaddr + filesz:
            return va - vaddr + offset
    fail("address %#x not in a file-backed segment" % va)


def main():
    data = BINARY.read_bytes()
    segments = load_segments(data)
    records = json.loads((PACKET / "records.json").read_text())

    # 1. Target digest.
    artifacts = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    digest = None
    for entry in artifacts["files"]:
        if entry["path"] == "artifacts/node/115/hl-node":
            digest = entry["sha256"]
    if digest != TARGET_SHA256:
        fail("provenance digest mismatch: %r" % digest)
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        fail("binary digest mismatch")
    print("digest OK")

    # 2. Manifest (recursive: every file under the packet).
    manifest = {}
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest_hex, name = line.split(None, 1)
        manifest[name.strip()] = digest_hex
    packet_files = sorted(
        str(p.relative_to(PACKET))
        for p in PACKET.rglob("*")
        if p.is_file() and p.name != "MANIFEST.sha256")
    if sorted(manifest) != packet_files:
        fail("manifest file list mismatch: %s vs %s"
             % (sorted(manifest), packet_files))
    for name, digest_hex in manifest.items():
        actual = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if actual != digest_hex:
            fail("manifest hash mismatch for %s" % name)
    print("manifest OK (%d files)" % len(manifest))

    # 3 + 4. Excerpt regeneration and raw bytes.
    all_lines = []  # (address, bytes, text) for the random gate spots
    for name, (start, stop) in sorted(WINDOWS.items()):
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        stored = (PACKET / "excerpts" / name).read_text()
        if text != stored:
            fail("excerpt %s differs from a fresh objdump run" % name)
        for line in stored.splitlines():
            match = LINE_RE.match(line)
            if not match:
                continue
            addr = int(match.group(1), 16)
            raw = bytes(int(b, 16) for b in match.group(2).split())
            off = va_to_off(segments, addr)
            if data[off:off + len(raw)] != raw:
                fail("excerpt %s line %#x bytes mismatch" % (name, addr))
            all_lines.append((addr, raw, line))
    print("excerpts OK (%d windows, %d instruction lines byte-checked)"
          % (len(WINDOWS), len(all_lines)))

    # 5. Fixed spots + three seeded random gate spots.
    by_addr = {addr: line for addr, _raw, line in all_lines}
    for addr, mnemonic in SPOTS:
        if addr not in by_addr or mnemonic not in by_addr[addr]:
            fail("spot %#x (%s) not found" % (addr, mnemonic))
    rng = random.Random(20261106)
    chosen = rng.sample(all_lines, 3)
    for addr, raw, line in chosen:
        off = va_to_off(segments, addr)
        if data[off:off + len(raw)] != raw:
            fail("random gate spot %#x bytes mismatch" % addr)
    print("spots OK (%d fixed + 3 random: %s)"
          % (len(SPOTS),
             ", ".join("%#x" % addr for addr, _r, _l in chosen)))

    # 6. Frames.
    frames_text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        if line.strip() and line.strip() not in frames_text:
            fail("frames.txt line missing from fresh readelf: %s" % line)
    print("frames OK")

    # 7. Relocations.
    reloc_text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        if line.strip() and line.strip() not in reloc_text:
            fail("relocations.txt line missing from fresh readelf: %s" % line)
    print("relocations OK")

    # 8. Literals (prefix match at the recorded address).
    for literal in records["literals"]:
        addr = int(literal["address"], 16)
        want = literal["value"].encode()
        off = va_to_off(segments, addr)
        if data[off:off + len(want)] != want:
            fail("literal at %s mismatch" % literal["address"])
    print("literals OK (%d)" % len(records["literals"]))

    # 9. Census reproduction.
    before = (PACKET / "callers.tsv").read_bytes()
    subprocess.run([sys.executable, str(PACKET / "census.py")],
                   capture_output=True, text=True, check=True, cwd=ROOT)
    after = (PACKET / "callers.tsv").read_bytes()
    if before != after:
        fail("census.py did not reproduce callers.tsv")
    rows = {}
    data_rows = 0
    for line in after.decode().splitlines()[1:]:
        if not line.strip():
            continue
        data_rows += 1
        site, target, _caller, kind = line.split("\t")
        rows.setdefault(target, {"call": 0, "jmp": 0, "lea": 0})
        rows[target][kind] += 1
    if data_rows != records["callers_tsv_rows"]:
        fail("callers.tsv rows: got %d, want %d"
             % (data_rows, records["callers_tsv_rows"]))
    for name, entry in records["census"]["counts"].items():
        target_hex = "%#x" % NAME_TO_ADDR[name]
        got = rows.get(target_hex, {"call": 0, "jmp": 0, "lea": 0})
        for kind in ("call", "jmp", "lea"):
            want = entry.get(kind)
            if want is None:
                continue
            if got[kind] != want:
                fail("census %s %s: got %d, want %d"
                     % (name, kind, got[kind], want))
    print("census OK (%d rows)" % data_rows)

    # 10. GOT rows re-derived from relocations.txt.
    # Each vtables.tsv row is (slot, target, kind): for a GLOB_DAT
    # row the slot must be the relocation offset and the target
    # the relocated symbol name.
    reloc_map = {}
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        match = re.match(
            r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+(R_X86_64_\w+)\s+"
            r"[0-9a-f]+\s+(\S+)", line)
        if match:
            reloc_map[int(match.group(1), 16)] = (
                match.group(2), match.group(3))
    vtable_rows = 0
    for line in (PACKET / "vtables.tsv").read_text().splitlines()[1:]:
        if not line.strip():
            continue
        vtable_rows += 1
        slot_hex, target, kind = line.split("\t")
        got = reloc_map.get(int(slot_hex, 16))
        if got is None:
            fail("vtable slot %s has no relocation row" % slot_hex)
        if got[0] != kind:
            fail("vtable slot %s kind: got %s, want %s"
                 % (slot_hex, got[0], kind))
        if got[1].split("@")[0] != target:
            fail("vtable slot %s target: got %s, want %s"
                 % (slot_hex, got[1], target))
    if vtable_rows != records["vtables"]["rows"]:
        fail("vtables.tsv rows: got %d, want %d"
             % (vtable_rows, records["vtables"]["rows"]))
    # Model constants match the packet.
    sys.path.insert(0, str(ROOT / "tools"))
    import registry_find_sibling_115 as model
    checks = [
        ("ENTRY", model.ENTRY, 0x609A740),
        ("FIND_E70", model.FIND_E70, 0x6099E70),
        ("NO_EQUALS", model.NO_EQUALS, 0x609BA30),
        ("RESOLVE_NO_EQUALS", model.RESOLVE_NO_EQUALS, 0x609B8A0),
        ("KIND_DISPATCH", model.KIND_DISPATCH, 0x609B700),
        ("ELEMENT_SCAN", model.ELEMENT_SCAN, 0x6096F40),
        ("NAME_LOOKUP", model.NAME_LOOKUP, 0x60BA0B0),
        ("HASH_NAME_FIND", model.HASH_NAME_FIND, 0x60B84B0),
        ("MOVE_ASSIGN", model.MOVE_ASSIGN, 0x60B79E0),
        ("ENDS_WITH", model.ENDS_WITH, 0x61D1390),
        ("STR_COMPARE", model.STR_COMPARE, 0x61D13E0),
        ("FALLBACK_DELEGATE", model.FALLBACK_DELEGATE, 0x6097150),
        ("DELEGATE_IMPL", model.DELEGATE_IMPL, 0x6097110),
        ("ZERO_STUB", model.ZERO_STUB, 0x60956F0),
        ("FIND_NORM", model.FIND_NORM, 0x609A410),
        ("PARSER", model.PARSER, 0x60C1190),
        ("MAP_CLEAR", model.MAP_CLEAR, 0x5D5B300),
        ("STATUS_BUILDER", model.STATUS_BUILDER, 0x61CF670),
        ("SHARED_RELEASE", model.SHARED_RELEASE, 0x5D35070),
        ("LIBC_SINGLE_THREADED", model.LIBC_SINGLE_THREADED, 0x64ED290),
        ("HASH_SEED", model.HASH_SEED, 0xC70F6907),
        ("LINEAR_WALK_LIMIT", model.LINEAR_WALK_LIMIT, 20),
        ("VALUE_SIZE", model.VALUE_SIZE, 0x50),
        ("NOT_SUPPORTED", model.NOT_SUPPORTED, 3),
        ("INVALID_ARGUMENT", model.INVALID_ARGUMENT, 4),
        ("OPTION_NOT_FOUND", model.OPTION_NOT_FOUND, 1),
    ]
    for label, got, want in checks:
        if got != want:
            fail("model %s: got %#x, want %#x" % (label, got, want))
    print("vtables OK (%d rows) + model constants OK" % vtable_rows)

    # 11. Model tests.
    result = subprocess.run(
        [sys.executable,
         str(ROOT / "tests" / "test_registry_find_sibling_115.py")],
        capture_output=True, text=True, cwd=ROOT)
    if result.returncode != 0:
        fail("model tests failed:\n" + result.stdout + result.stderr)
    print("model tests OK: " + result.stdout.strip().splitlines()[-1])

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
