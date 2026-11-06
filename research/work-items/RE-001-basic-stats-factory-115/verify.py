"""Verify the RE-001-basic-stats-factory-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-basic-stats-factory-115/verify.py

Checks, in order (fails fast with a clear message):
  1. The target digest from provenance/artifacts.json.
  2. MANIFEST.sha256 covers every packet file (including
     excerpts/) and every hash matches.
  3. Every excerpt regenerates byte-for-byte from a fresh objdump
     run on the real binary.
  4. Every instruction line in every excerpt matches the raw
     binary bytes at that address.
  5. Fixed spot instructions plus three seeded random gate spots
     (random.seed(20261106)) verify byte-for-byte.
  6. Every FDE range in frames.txt is present in a fresh readelf
     frame dump.
  7. Every relocation record in relocations.txt is present in a
     fresh readelf -r dump.
  8. Every literal in records.json (strings, typeinfo names)
     reads back from the binary at its address.
  9. The census reproduces: re-running census.py leaves
     callers.tsv byte-identical, and the per-routine counts in
     records.json match it.
 10. The vtable slot table in vtables.tsv re-derives from
     relocations.txt, and the model constants match it.
 11. The model tests pass (tests/test_basic_stats_factory_115.py).

Exit 0 with ALL CHECKS PASSED, else exit 1.
"""

import hashlib
import json
import random
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = {
    "host.txt": (0x6077820, 0x60780A0),
    "register.txt": (0x6075BC0, 0x6075FF5),
    "stats_ctor.txt": (0x6071A00, 0x6071B60),
    "creator.txt": (0x6071BA0, 0x6071CCB),
    "manager.txt": (0x606FA50, 0x606FA7D),
    "registry_default.txt": (0x61F8B60, 0x61F8D12),
    "map_op.txt": (0x5FD1DA0, 0x5FD1FFA),
    "vector_grow.txt": (0x5FD17C0, 0x5FD1962),
    "mutex_init.txt": (0x60D50C0, 0x60D5157),
    "shard_store.txt": (0x60716D0, 0x6071952),
    "options_record.txt": (0x6099CE0, 0x6099E34),
    "stats_dtor.txt": (0x6070EA0, 0x607103C),
    "stats_dtor_delete.txt": (0x6071040, 0x607105B),
    "factory_dtor.txt": (0x606FAD0, 0x606FB12),
    "factory_dtor_delete.txt": (0x606FDA0, 0x606FDEA),
    "factory_matches.txt": (0x606FB40, 0x606FB4E),
    "factory_name.txt": (0x606FB50, 0x606FB5E),
    "pattern_dtor.txt": (0x5FF2030, 0x5FF2145),
    "pattern_dtor_delete.txt": (0x5FF2150, 0x5FF225F),
    "pattern_matches.txt": (0x61F8670, 0x61F86F2),
    "pattern_name.txt": (0x61F8120, 0x61F8129),
    "match_helper.txt": (0x61F8430, 0x61F8670),
    "submatch.txt": (0x61F8280, 0x61F842B),
    "counted_impl_dtor.txt": (0x606FAC0, 0x606FAC5),
    "counted_impl_dtor_delete.txt": (0x606FB80, 0x606FB8E),
    "counted_impl_dispose.txt": (0x60710B0, 0x60710FB),
    "counted_impl_destroy.txt": (0x606FB90, 0x606FB9E),
    "counted_impl_get_deleter.txt": (0x606FB30, 0x606FB37),
    "counted_stats_dtor.txt": (0x606FAB0, 0x606FAB5),
    "counted_stats_dtor_delete.txt": (0x606FB60, 0x606FB6E),
    "counted_stats_dispose.txt": (0x6071060, 0x60710AB),
    "counted_stats_destroy.txt": (0x606FB70, 0x606FB7E),
    "counted_stats_get_deleter.txt": (0x606FB20, 0x606FB27),
    "inplace_registry_dtor.txt": (0x61F8130, 0x61F8135),
    "inplace_registry_dtor_delete.txt": (0x61F8140, 0x61F814E),
    "inplace_registry_dispose.txt": (0x61F8760, 0x61F89DB),
    "inplace_registry_destroy.txt": (0x61F8170, 0x61F817E),
    "inplace_registry_get_deleter.txt": (0x61F8180, 0x61F81C7),
    "inplace_library_dtor.txt": (0x5FEFC70, 0x5FEFC75),
    "inplace_library_dtor_delete.txt": (0x5FEFD00, 0x5FEFD0E),
    "inplace_library_dispose.txt": (0x5FF7900, 0x5FF7952),
    "inplace_library_destroy.txt": (0x5FEFD50, 0x5FEFD5E),
    "inplace_library_get_deleter.txt": (0x5FEFF70, 0x5FEFFB7),
}

# (address, mnemonic text that must appear on that line)
SPOTS = [
    (0x6077820, "endbr64"),
    (0x607788d, "lea"),
    (0x6075bc0, "endbr64"),
    (0x6075c00, "call"),
    (0x6075c11, "lea"),
    (0x6075c27, "lea"),
    (0x6075e13, "call"),
    (0x6075f30, "call"),
    (0x6075db4, "call"),
    (0x6071a00, "endbr64"),
    (0x6071a7c, "call"),
    (0x6071a85, "call"),
    (0x6071af1, "call"),
    (0x6071ba0, "endbr64"),
    (0x6071bda, "call"),
    (0x606fa50, "endbr64"),
    (0x61f8b60, "endbr64"),
    (0x5fd1da0, "endbr64"),
    (0x60716d0, "endbr64"),
    (0x607174b, "call"),
    (0x607187c, "mov"),
    (0x6099ce0, "endbr64"),
    (0x6070ea0, "endbr64"),
    (0x6070f2c, "call"),
    (0x6070f35, "call"),
    (0x61f8670, "endbr64"),
    (0x61f869a, "call"),
    (0x61f8430, "endbr64"),
    (0x61f84a2, "call"),
    (0x61f8526, "call"),
    (0x61f8280, "endbr64"),
    (0x61f838c, "call"),
    (0x61f83dc, "call"),
    (0x61f8426, "call"),
    (0x60710b0, "endbr64"),
    (0x6071060, "endbr64"),
]

VTABLE_BASES = {
    "StatisticsImpl": 0x64D2D88,
    "FactoryEntry<Statistics>": 0x64D2E98,
    "_Sp_counted_ptr<StatisticsImpl>": 0x64D2EC8,
    "_Sp_counted_ptr<Statistics>": 0x64D2F00,
    "PatternEntry": 0x64D8ED0,
    "_Sp_counted_ptr_inplace<ObjectRegistry>": 0x64D8F00,
    "_Sp_counted_ptr_inplace<ObjectLibrary>": 0x64D00F0,
}

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )*[0-9a-f]{2})(?:\s*\t| *$)")


def fail(message):
    print("FAIL: " + message)
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

    # 8. Literals (prefix match at the recorded address; the
    # "StatisticsOption" literal is a 16-byte prefix of a longer run).
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
        rows.setdefault(target, {"call": 0, "tail jump": 0, "lea": 0})
        rows[target][kind] += 1
    census = records["census"]
    if data_rows != census["callers_tsv_rows"]:
        fail("callers.tsv rows: got %d, want %d"
             % (data_rows, census["callers_tsv_rows"]))
    for target_hex, entry in census["counts"].items():
        got = rows.get(target_hex, {"call": 0, "tail jump": 0, "lea": 0})
        for kind in ("calls", "jumps", "leas"):
            want = entry.get(kind)
            if want is None:
                continue
            key = {"calls": "call", "jumps": "tail jump",
                   "leas": "lea"}[kind]
            if got[key] != want:
                fail("census %s %s: got %d, want %d"
                     % (target_hex, kind, got[key], want))
    print("census OK (%d rows)" % data_rows)

    # 10. Vtable slots re-derived from relocations.txt.
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
        base = VTABLE_BASES[name]
        got = reloc_map.get(base + int(slot_hex, 16))
        if got != int(target_hex, 16):
            fail("vtable %s slot %s: got %#x, want %s"
                 % (name, slot_hex, got if got is not None else -1, target_hex))
    if vtable_rows != records["vtables"]["rows"]:
        fail("vtables.tsv rows: got %d, want %d"
             % (vtable_rows, records["vtables"]["rows"]))
    # Model constants match the packet.
    sys.path.insert(0, str(ROOT / "tools"))
    import basic_stats_factory_115 as model
    checks = [
        ("STATISTICS_IMPL_VPTR", model.STATISTICS_IMPL_VPTR, 0x64D2D88),
        ("COUNTED_IMPL_VPTR", model.COUNTED_IMPL_VPTR, 0x64D2EC8),
        ("FACTORY_ENTRY_VPTR", model.FACTORY_ENTRY_VPTR, 0x64D2E98),
        ("PATTERN_ENTRY_VPTR", model.PATTERN_ENTRY_VPTR, 0x64D8ED0),
        ("MANAGER", model.MANAGER, 0x606FA50),
        ("CREATOR", model.CREATOR, 0x6071BA0),
        ("HOST", model.HOST, 0x6077820),
        ("REGISTER_ONCE", model.REGISTER_ONCE, 0x6075BC0),
        ("STATS_CTOR", model.STATS_CTOR, 0x6071A00),
        ("SHARD_SIZE", model.SHARD_SIZE, 0xCE40),
    ]
    for label, got, want in checks:
        if got != want:
            fail("model %s: got %#x, want %#x" % (label, got, want))
    print("vtables OK (%d rows) + model constants OK" % vtable_rows)

    # 11. Model tests.
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_basic_stats_factory_115.py")],
        capture_output=True, text=True, cwd=ROOT)
    if result.returncode != 0:
        fail("model tests failed:\n" + result.stdout + result.stderr)
    print("model tests OK: " + result.stdout.strip().splitlines()[-1])

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
