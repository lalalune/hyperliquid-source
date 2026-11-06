"""Verify the RE-001-histogram-stats-family-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-histogram-stats-family-115/verify.py

Checks, in order (fails fast with a clear message):
  1. The target digest from provenance/artifacts.json.
  2. MANIFEST.sha256 covers every packet file and every hash matches.
  3. Every excerpt regenerates byte-for-byte from a fresh objdump
     run on the real binary (this subsumes the re-ship check for
     the five excerpts copied from #3362).
  4. Every instruction line in every excerpt matches the raw
     binary bytes at that address.
  5. Fixed spot instructions plus three seeded random gate spots
     (random.seed(20261106)) verify byte-for-byte.
  6. Every FDE range in frames.txt is present in a fresh readelf
     frame dump.
  7. Every RELATIVE record in relocations.txt is present in a
     fresh readelf -r dump.
  8. Every literal in records.json (doubles, seed qwords, format
     strings, name strings) reads back from the binary.
  9. The census reproduces: re-running census.py leaves
     callers.tsv byte-identical, and the per-routine counts and
     site lists in records.json match it.
 10. The boundary list re-derives from the model and matches
     boundaries.tsv and records.json; the vtable slot table in
     records.json matches relocations.txt.
 11. The model tests pass (tests/test_histogram_stats_115.py).

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
    "boundaries_dtor.txt": (0x606AF70, 0x606AF91),
    "bucket_index.txt": (0x606AFA0, 0x606B013),
    "shared_init.txt": (0x606B020, 0x606B07C),
    "bucket_count_init.txt": (0x606B080, 0x606B0A2),
    "locked_init.txt": (0x606B0C0, 0x606B10A),
    "empty_check.txt": (0x606B110, 0x606B11F),
    "empty_thunk.txt": (0x606B120, 0x606B12D),
    "record.txt": (0x606B130, 0x606B1B3),
    "record_thunk.txt": (0x606B1C0, 0x606B1CD),
    "merge_inner.txt": (0x606B1D0, 0x606B253),
    "percentile.txt": (0x606B260, 0x606B4FE),
    "median.txt": (0x606B500, 0x606B511),
    "median_thunk.txt": (0x606B520, 0x606B52D),
    "percentile_thunk.txt": (0x606B530, 0x606B53D),
    "average.txt": (0x606B540, 0x606B5B9),
    "average_thunk.txt": (0x606B5C0, 0x606B5CD),
    "stddev.txt": (0x606B5D0, 0x606B6AE),
    "stddev_thunk.txt": (0x606B6B0, 0x606B6BD),
    "renderer_cleanup.txt": (0x606B6BE, 0x606B6E6),
    "renderer.txt": (0x606B6F0, 0x606BC8D),
    "tostring_entry.txt": (0x606BC90, 0x606BCD3),
    "percentile_struct.txt": (0x606BCE0, 0x606BDCD),
    "percentile_struct_thunk.txt": (0x606BDD0, 0x606BDDD),
    "merge_wrapper.txt": (0x606BDF0, 0x606BE3D),
    "merge_entry.txt": (0x606BE40, 0x606BED5),
    "name_accessor.txt": (0x606AF40, 0x606AF4C),
    "min_accessor.txt": (0x606AF50, 0x606AF59),
    "max_accessor.txt": (0x606AF60, 0x606AF69),
    "boundaries_init.txt": (0x606BF10, 0x606C134),
    "boundaries_static_init.txt": (0x606C140, 0x606C16B),
}

# (address, mnemonic text that must appear on that line)
SPOTS = [
    (0x606B260, "endbr64"),
    (0x606B28B, "divsd"),
    (0x606B2FD, "mov"),
    (0x606B384, "ret"),
    (0x606B504, "movsd"),
    (0x606B571, "divsd"),
    (0x606B5D0, "endbr64"),
    (0x606B640, "sqrtsd"),
    (0x606B6F0, "endbr64"),
    (0x606B761, "lea"),
    (0x606B826, "call"),
    (0x606B9D1, "lea"),
    (0x606BC90, "endbr64"),
    (0x606BE40, "endbr64"),
    (0x606BF48, "movdqa"),
    (0x606C140, "endbr64"),
    (0x606AFA0, "endbr64"),
    (0x606B130, "endbr64"),
]

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

    # 2. Manifest.
    manifest = {}
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest_hex, name = line.split(None, 1)
        manifest[name.strip()] = digest_hex
    packet_files = sorted(p.name for p in PACKET.iterdir()
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
        stored = (PACKET / name).read_text()
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

    # 8. Literals.
    literals = records["literals"]
    for addr_hex, want in literals["doubles"].items():
        addr = int(addr_hex, 16)
        off = va_to_off(segments, addr)
        got = struct.unpack_from("<d", data, off)[0]
        if got != want:
            fail("double at %s: got %r, want %r" % (addr_hex, got, want))
    seed = literals["seed_qwords"]["0x453950"]
    off = va_to_off(segments, 0x453950)
    got = list(struct.unpack_from("<QQ", data, off))
    if got != seed:
        fail("seed qwords mismatch: %r" % got)
    for addr_hex, want in literals["formats"].items():
        addr = int(addr_hex, 16)
        off = va_to_off(segments, addr)
        end = data.find(b"\x00", off)
        got = data[off:end].decode()
        if got != want:
            fail("format at %s: got %r, want %r" % (addr_hex, got, want))
    for addr_hex, want in literals["strings"].items():
        addr = int(addr_hex, 16)
        off = va_to_off(segments, addr)
        end = data.find(b"\x00", off)
        got = data[off:end].decode()
        if got != want:
            fail("string at %s: got %r, want %r" % (addr_hex, got, want))
    # Typeinfo names.
    for addr_hex, want in (("0x9753f0", "N7rocksdb13HistogramImplE"),
                           ("0x9753d0", "N7rocksdb9HistogramE")):
        addr = int(addr_hex, 16)
        off = va_to_off(segments, addr)
        end = data.find(b"\x00", off)
        if data[off:end].decode() != want:
            fail("typeinfo name at %s mismatch" % addr_hex)
    print("literals OK")

    # 9. Census reproduction.
    before = (PACKET / "callers.tsv").read_bytes()
    subprocess.run([sys.executable, str(PACKET / "census.py")],
                   capture_output=True, text=True, check=True, cwd=ROOT)
    after = (PACKET / "callers.tsv").read_bytes()
    if before != after:
        fail("census.py did not reproduce callers.tsv")
    rows = {}
    for line in after.decode().splitlines()[1:]:
        if not line.strip():
            continue
        site, target, _caller, kind = line.split("\t")
        rows.setdefault(target, {"call": [], "tail jump": [], "lea": []})
        rows[target][kind].append(site)
    census = records["census"]
    for target_hex, entry in census.items():
        got = rows.get(target_hex, {"call": [], "tail jump": [], "lea": []})
        for kind in ("calls", "jumps", "leas"):
            want = entry.get(kind)
            if want is None:
                continue
            key = {"calls": "call", "jumps": "tail jump",
                   "leas": "lea"}[kind]
            if isinstance(want, int):
                if len(got[key]) != want:
                    fail("census %s %s: got %d, want %d"
                         % (target_hex, kind, len(got[key]), want))
            else:
                if sorted(got[key]) != sorted(want):
                    fail("census %s %s sites mismatch: %r vs %r"
                         % (target_hex, kind, got[key], want))
    print("census OK")

    # 10. Boundaries and vtable slots re-derived.
    sys.path.insert(0, str(ROOT / "tools"))
    import histogram_stats_115 as model
    boundaries = model.generate_boundaries()
    if boundaries != model.BOUNDARIES:
        fail("boundary generator is not deterministic")
    tsv = []
    for line in (PACKET / "boundaries.tsv").read_text().splitlines()[1:]:
        if line.strip():
            _index, value = line.split("\t")
            tsv.append(int(value))
    if tsv != boundaries:
        fail("boundaries.tsv does not match the model")
    bounds_rec = records["boundaries"]
    if (bounds_rec["count"] != len(boundaries)
            or bounds_rec["first"] != boundaries[0]
            or bounds_rec["last"] != boundaries[-1]
            or bounds_rec["first_12"] != boundaries[:12]):
        fail("records.json boundaries do not match the model")
    reloc_map = {}
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        match = re.match(r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", line)
        if match:
            reloc_map[int(match.group(1), 16)] = int(match.group(2), 16)
    vtable_base = 0x64D2B80
    for slot_hex, target_hex in records["histogram_impl_vtable"]["slots"].items():
        slot = int(slot_hex, 16)
        want = int(target_hex.split()[0], 16)
        got = reloc_map.get(vtable_base + slot)
        if got != want:
            fail("vtable slot %s: got %#x, want %#x"
                 % (slot_hex, got if got else -1, want))
    print("records re-derived OK")

    # 11. Model tests.
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_histogram_stats_115.py")],
        capture_output=True, text=True, cwd=ROOT)
    if result.returncode != 0:
        fail("model tests failed:\n" + result.stdout + result.stderr)
    print("model tests OK: " + result.stdout.strip().splitlines()[0])

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
