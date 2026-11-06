#!/usr/bin/env python3
"""Packet checker for RE-001-registry-find-115 (node #115).

Run from the repository root:

    python3 research/work-items/RE-001-registry-find-115/verify.py

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
    "find_entry.txt": (0x609E510, 0x609F073),
    "find_norm.txt": (0x609A410, 0x609A67C),
    "parser.txt": (0x60C1190, 0x60C1887),
    "trim.txt": (0x61D11F0, 0x61D1382),
    "value_extract.txt": (0x60B97F0, 0x60B9D70),
    "map_index.txt": (0x60C0E90, 0x60C112F),
    "worker.txt": (0x6097630, 0x60984E8),
    "thunk.txt": (0x6098510, 0x60985AF),
    "matcher.txt": (0x60BB9A0, 0x60BBDEB),
    "fallback.txt": (0x609E2D0, 0x609E3E2),
    "map_find.txt": (0x609A1B0, 0x609A2E7),
    "map_erase.txt": (0x609A2F0, 0x609A3DE),
    "map_clear.txt": (0x5D5B300, 0x5D5B39B),
    "value_copy.txt": (0x60B9D70, 0x60B9DFC),
    "resolver.txt": (0x60971C0, 0x609755B),
    "serializer.txt": (0x60BA600, 0x60BB855),
    "value_assign.txt": (0x60B79E0, 0x60B7AB8),
    "status_copy.txt": (0x60B7AC0, 0x60B7B29),
    "range_assign.txt": (0x60B7CD0, 0x60B7D73),
    "fallback_delegate.txt": (0x6097150, 0x6097192),
    "delegate_impl.txt": (0x6097110, 0x609714E),
    "value_dtor.txt": (0x5E33FB0, 0x5E33FEA),
    "cstr_ctor.txt": (0x60B7D80, 0x60B7E63),
    "cstr_replace.txt": (0x60B79B0, 0x60B79DE),
    "status_builder.txt": (0x61CF670, 0x61CF767),
}

# Fixed gate spots: (address, substring expected in the line).
SPOTS = [
    (0x609E510, "endbr64"),
    (0x609A410, "endbr64"),
    (0x60C1190, "endbr64"),
    (0x6097630, "endbr64"),
    (0x60BB9A0, "endbr64"),
]

# GOT-based vtable rows: the slot column holds the absolute GOT
# address (names ending in "-GOT"); the delegate vtable base
# itself was not pinned from locally retained evidence.
GOT_VTABLES = {"delegate-GOT"}

# Census routine name -> address (for check 9).
NAME_TO_ADDR = {
    "find_entry": 0x609E510,
    "find_norm": 0x609A410,
    "parser": 0x60C1190,
    "trim": 0x61D11F0,
    "value_extract": 0x60B97F0,
    "map_find": 0x609A1B0,
    "map_erase": 0x609A2F0,
    "map_index": 0x60C0E90,
    "map_clear": 0x5D5B300,
    "status_copy": 0x60B7AC0,
    "value_assign": 0x60B79E0,
    "range_assign": 0x60B7CD0,
    "value_copy": 0x60B9D70,
    "thunk": 0x6098510,
    "worker": 0x6097630,
    "matcher": 0x60BB9A0,
    "resolver": 0x60971C0,
    "serializer": 0x60BA600,
    "fallback": 0x609E2D0,
    "fallback_delegate": 0x6097150,
    "delegate_impl": 0x6097110,
    "value_dtor": 0x5E33FB0,
    "cstr_replace": 0x60B79B0,
    "cstr_ctor": 0x60B7D80,
    "status_builder": 0x61CF670,
    "shared_release": 0x5D35070,
    "rehash": 0x5D38260,
    "host": 0x6077820,
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
    reloc_map = {}
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        match = re.match(r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", line)
        if match:
            reloc_map[int(match.group(1), 16)] = int(match.group(2), 16)
    vtable_rows = 0
    for line in (PACKET / "vtables.tsv").read_text().splitlines()[1:]:
        if not line.strip():
            continue
        vtable_rows += 1
        name, slot_hex, target_hex, _role = line.split("\t")
        if name in GOT_VTABLES:
            got = reloc_map.get(int(slot_hex, 16))
        else:
            fail("unknown vtable %s (only GOT rows are pinned here)" % name)
        if got != int(target_hex, 16):
            fail("vtable %s slot %s: got %#x, want %s"
                 % (name, slot_hex, got if got is not None else -1, target_hex))
    if vtable_rows != records["vtables"]["rows"]:
        fail("vtables.tsv rows: got %d, want %d"
             % (vtable_rows, records["vtables"]["rows"]))
    # Model constants match the packet.
    sys.path.insert(0, str(ROOT / "tools"))
    import registry_find_115 as model
    checks = [
        ("FIND_ENTRY", model.FIND_ENTRY, 0x609E510),
        ("FIND_NORM", model.FIND_NORM, 0x609A410),
        ("PARSER", model.PARSER, 0x60C1190),
        ("TRIM", model.TRIM, 0x61D11F0),
        ("VALUE_EXTRACT", model.VALUE_EXTRACT, 0x60B97F0),
        ("MAP_FIND", model.MAP_FIND, 0x609A1B0),
        ("MAP_ERASE", model.MAP_ERASE, 0x609A2F0),
        ("MAP_INDEX", model.MAP_INDEX, 0x60C0E90),
        ("MAP_CLEAR", model.MAP_CLEAR, 0x5D5B300),
        ("STATUS_COPY", model.STATUS_COPY, 0x60B7AC0),
        ("VALUE_ASSIGN", model.VALUE_ASSIGN, 0x60B79E0),
        ("RANGE_ASSIGN", model.RANGE_ASSIGN, 0x60B7CD0),
        ("VALUE_COPY", model.VALUE_COPY, 0x60B9D70),
        ("THUNK", model.THUNK, 0x6098510),
        ("WORKER", model.WORKER, 0x6097630),
        ("MATCHER", model.MATCHER, 0x60BB9A0),
        ("RESOLVER", model.RESOLVER, 0x60971C0),
        ("SERIALIZER", model.SERIALIZER, 0x60BA600),
        ("FALLBACK", model.FALLBACK, 0x609E2D0),
        ("FALLBACK_DELEGATE", model.FALLBACK_DELEGATE, 0x6097150),
        ("DELEGATE_IMPL", model.DELEGATE_IMPL, 0x6097110),
        ("VALUE_DTOR", model.VALUE_DTOR, 0x5E33FB0),
        ("CSTR_REPLACE", model.CSTR_REPLACE, 0x60B79B0),
        ("CSTR_CTOR", model.CSTR_CTOR, 0x60B7D80),
        ("STATUS_BUILDER", model.STATUS_BUILDER, 0x61CF670),
        ("CANONICAL_DELEGATE", model.CANONICAL_DELEGATE, 0x5D2E770),
        ("LIBC_SINGLE_THREADED", model.LIBC_SINGLE_THREADED, 0x64ED290),
        ("HASH_SEED", model.HASH_SEED, 0xC70F6907),
        ("LINEAR_WALK_LIMIT", model.LINEAR_WALK_LIMIT, 20),
        ("VALUE_SIZE", model.VALUE_SIZE, 0x50),
        ("MAP_NODE_SIZE", model.MAP_NODE_SIZE, 0x50),
        ("NOT_SUPPORTED", model.NOT_SUPPORTED, 3),
        ("INVALID_ARGUMENT", model.INVALID_ARGUMENT, 4),
    ]
    for label, got, want in checks:
        if got != want:
            fail("model %s: got %#x, want %#x" % (label, got, want))
    print("vtables OK (%d rows) + model constants OK" % vtable_rows)

    # 11. Model tests.
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_registry_find_115.py")],
        capture_output=True, text=True, cwd=ROOT)
    if result.returncode != 0:
        fail("model tests failed:\n" + result.stdout + result.stderr)
    print("model tests OK: " + result.stdout.strip().splitlines()[-1])

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
