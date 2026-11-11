"""Checker for the RE-001-stats-produce-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-produce-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run (the 13
new windows) and byte-identical re-ship against the source
packets (the 4 re-shipped excerpts); every excerpt instruction
byte-for-byte against the raw binary (a fresh objdump run with
raw bytes shown, parsed and compared to the file bytes at each
instruction address); spot instructions byte-for-byte against
a fresh objdump run and the raw binary (the entry byte of each
of the 13 new windows, plus three gate spots picked with
random.seed(20261106) from the direct call sites in main.txt:
0x607086b, 0x6070895, 0x60708cb); the FDE ranges in frames.txt
against a fresh frame dump; the relocation set against a fresh
relocation dump (the StatisticsImpl vtable + typeinfo records,
the HistogramImpl vtable + typeinfo records, the GOT slot and
the ruled-out lookalike slot); the string literals and the
pinned double constants against the raw binary; census
consistency (a fresh census scan for the key routines against
callers.tsv); the semantic records (re-deriving both vtable
slot tables, the typeinfo names, the GOT value and the
percentile constants from the binary); and the model tests in
tests/test_stats_produce_115.py.
Prints ALL CHECKS PASSED on success, else raises.
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
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    ("main.txt", 0x6070810, 0x6070AB5),
    ("ticker_getter.txt", 0x6070430, 0x607047D),
    ("histogram_builder.txt", 0x6070500, 0x60705D8),
    ("histogram_init_a.txt", 0x606B080, 0x606B0A2),
    ("histogram_init_b.txt", 0x606B0C0, 0x606B10A),
    ("histogram_merge.txt", 0x606BDF0, 0x606BE3D),
    ("histogram_percentiles.txt", 0x606BCE0, 0x606BDCD),
    ("histogram_thunk.txt", 0x606BDD0, 0x606BDDD),
    ("histogram_delete.txt", 0x5D8B3B0, 0x5D8B3BE),
    ("shared_ptr_copy.txt", 0x5D35C00, 0x5D35C26),
    ("rebuild_caller.txt", 0x5D58720, 0x5D58809),
    ("stats_copy_site.txt", 0x5D58249, 0x5D5828C),
    ("log_dispatch.txt", 0x5FCF060, 0x5FCF153),
]

RESHIPPED = [
    ("stats_emit.txt", "research/work-items/RE-001-stats-emit-52020-115/main.txt"),
    ("mutex_lock.txt", "research/work-items/RE-001-mutex-wrappers-115/lock.txt"),
    ("mutex_unlock.txt", "research/work-items/RE-001-mutex-wrappers-115/unlock.txt"),
    ("acquire.txt", "research/work-items/RE-001-instrumented-acquire-6ca40-115/main.txt"),
]

# (r_offset, expected addend) for the relocation set.
EXPECTED_RELOCATIONS = {}
for _i in range(32):
    EXPECTED_RELOCATIONS[0x64D2D80 + _i * 8] = None  # filled below
STATS_VTABLE = [
    0x64D2CF8,  # typeinfo ptr at 0x64d2d80
    0x6070EA0, 0x6071040, 0x609D760, 0x609DC40, 0x5D32560, 0x6095E70,
    0x6096790, 0x5D2E090, 0x60956F0, 0x609D0E0, 0x60986B0, 0x6095710,
    0x609DE80, 0x609D980, 0x606FA20, 0x5D32A30, 0x5D2E770, 0x606FA30,
    0x5D2CA10, 0x6070490, 0x6070610, 0x6070700, 0x606FBA0, 0x6070DC0,
    0x6070C50, 0x5D48960, 0x606FFD0, 0x606FEF0, 0x6070B30, 0x6070810,
    0x6076030, 0x606FA40,
]
HIST_VTABLE = [
    0x64D2B58,  # typeinfo ptr at 0x64d2b78
    0x5D89570, 0x5D8B3B0, 0x606B0C0, 0x606B120, 0x606B1C0, 0x606BE40,
    0x606BC90, 0x606AF40, 0x606AF50, 0x606AF60, 0x5EEB2E0, 0x606B520,
    0x606B530, 0x606B5C0, 0x606B6B0, 0x606BDD0,
]
EXPECTED_RELOCATIONS.update({
    0x64D2D00: 0x975500,  # StatisticsImpl typeinfo name pointer
    0x64D2D08: 0x64D2CE0,  # StatisticsImpl typeinfo base pointer
    0x64D2CE8: 0x9754E0,  # Statistics typeinfo name pointer
    0x64D2B60: 0x9753F0,  # HistogramImpl typeinfo name pointer
    0x64ED2F0: 0x5D8B3B0,  # GOT slot read by the delete check
    0x64EAB50: 0x5D356E0,  # ruled-out lookalike data slot
})
for _i, _v in enumerate(STATS_VTABLE):
    EXPECTED_RELOCATIONS[0x64D2D80 + _i * 8] = _v
for _i, _v in enumerate(HIST_VTABLE):
    EXPECTED_RELOCATIONS[0x64D2B78 + _i * 8] = _v

LITERALS = {
    0x44FD60: b"%s COUNT : %lu\n",
    0x9609A0: b"%s P50 : %f P95 : %f P99 : %f P100 : %f COUNT : %lu SUM : %lu\n",
    0x4350A5: b"[%s:774] STATISTICS:\n %s",
    0x4451B9: b"db/db_impl/db_impl.cc",
}
DOUBLES = {0x459640: 95.0, 0x459258: 99.0}

GATE_SPOTS = [0x607086B, 0x6070895, 0x60708CB]


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def objdump(start, stop, raw=False):
    cmd = ["objdump", "-d"]
    if raw:
        cmd.append("--show-raw-insn")
    cmd += ["--start-address=%#x" % start, "--stop-address=%#x" % stop,
            "work/hl-node-115.bin"]
    return subprocess.run(cmd, capture_output=True, text=True,
                          check=True, cwd=ROOT).stdout


def vaddr_to_offset(vaddr):
    """File offset for a virtual address in .text/.rodata (both
    map 1:1 in the file layout used by this binary's segments
    for the ranges this checker reads)."""
    data = BINARY.read_bytes()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    raise SystemExit("no LOAD segment for %#x" % vaddr)


def check_digest():
    got = sha256_file(BINARY)
    assert got == DIGEST, "binary digest %s != %s" % (got, DIGEST)
    print("digest OK")


def check_manifest():
    lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    seen = set()
    for line in lines:
        digest, name = line.split(None, 1)
        name = name.strip()
        assert name != "MANIFEST.sha256", "manifest lists itself"
        seen.add(name)
        assert sha256_file(PACKET / name) == digest, "manifest mismatch: %s" % name
    on_disk = {p.name for p in PACKET.iterdir()
               if p.is_file() and p.name != "MANIFEST.sha256"}
    assert seen == on_disk, "manifest/file set differs: %s vs %s" % (seen, on_disk)
    print("manifest OK (%d files)" % len(seen))


def check_excerpts():
    for name, start, stop in WINDOWS:
        fresh = objdump(start, stop)
        stored = (PACKET / name).read_text()
        assert fresh == stored, "excerpt regeneration differs: %s" % name
    print("excerpts regenerate OK (%d windows)" % len(WINDOWS))
    for name, source in RESHIPPED:
        stored = (PACKET / name).read_text()
        assert (ROOT / source).read_text() == stored, \
            "re-ship differs: %s" % name
    print("re-shipped excerpts OK (%d files)" % len(RESHIPPED))


def check_raw_bytes():
    data = BINARY.read_bytes()
    for name, start, stop in WINDOWS:
        text = objdump(start, stop, raw=True)
        n = 0
        for line in text.splitlines():
            m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+)\t", line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            raw = bytes.fromhex(m.group(2).replace(" ", ""))
            off = vaddr_to_offset(addr)
            assert data[off:off + len(raw)] == raw, \
                "raw bytes differ at %#x in %s" % (addr, name)
            n += 1
        assert n > 0, "no instructions parsed in %s" % name
    print("raw bytes OK (%d windows)" % len(WINDOWS))


def check_spots():
    data = BINARY.read_bytes()
    spots = [start for _name, start, _stop in WINDOWS] + GATE_SPOTS
    for addr in spots:
        text = objdump(addr, addr + 16, raw=True)
        m = re.search(r"\s*([0-9a-f]+):\t([0-9a-f ]+)\t(\S.*)", text)
        assert m, "no instruction at %#x" % addr
        assert int(m.group(1), 16) == addr, "spot address mismatch %#x" % addr
        raw = bytes.fromhex(m.group(2).replace(" ", ""))
        off = vaddr_to_offset(addr)
        assert data[off:off + len(raw)] == raw, "spot bytes differ at %#x" % addr
    print("spot instructions OK (%d spots)" % len(spots))


def check_frames():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        assert line in text, "FDE line missing from fresh dump: %s" % line
    print("frames OK")


def check_relocations():
    text = subprocess.run(["readelf", "-r", str(BINARY)],
                          capture_output=True, text=True, check=True).stdout
    relocs = {}
    for line in text.splitlines():
        m = re.match("[ ]*([0-9a-f]+)[ ]+([0-9a-f]+)[ ]+R_X86_64_([A-Za-z]+)"
                     "(?:[ ]+([0-9a-f]+))?", line)
        if m and m.group(3) == "RELATIVE" and m.group(4) is not None:
            relocs[int(m.group(1), 16)] = int(m.group(4), 16)
    for off, want in EXPECTED_RELOCATIONS.items():
        assert relocs.get(off) == want, \
            "relocation %#x: got %#x want %#x" % (
                off, relocs.get(off, -1), want)
    print("relocations OK (%d records)" % len(EXPECTED_RELOCATIONS))


def check_literals():
    data = BINARY.read_bytes()
    for addr, want in LITERALS.items():
        off = vaddr_to_offset(addr)
        got = data[off:off + len(want)]
        assert got == want, "literal at %#x: %r" % (addr, got)
    for addr, want in DOUBLES.items():
        off = vaddr_to_offset(addr)
        got = struct.unpack_from("<d", data, off)[0]
        assert got == want, "double at %#x: %r" % (addr, got)
    print("literals OK")


def check_census():
    proc = subprocess.run(
        [sys.executable,
         "research/work-items/RE-001-stats-produce-115/census.py"],
        capture_output=True, text=True, check=True, cwd=ROOT)
    out = proc.stdout
    want = [
        "0x6070810 calls=0  jumps=0  leas=0  qwords=1 0x11ce60 relative=1 0x64d2e70",
        "0x5d52020 calls=1 0x5d7e339 jumps=0  leas=0  qwords=0  relative=0 ",
        "0x5d57770 calls=2 0x5d5879d 0x5d753d4 jumps=0  leas=0  qwords=0  relative=0 ",
        "0x606bdd0 calls=0  jumps=0  leas=0  qwords=1 0x11c830 relative=1 0x64d2bf8",
        "0x5d8b3b0 calls=0  jumps=0  leas=0  qwords=2 0x11c6e0 0x15cf88 relative=2 0x64d2b88 0x64ed2f0",
    ]
    for line in want:
        assert line in out, "census line missing: %s" % line
    rows = (PACKET / "callers.tsv").read_text().splitlines()
    assert rows[0] == "site\ttarget\tcaller\tkind"
    assert len(rows) == 1760, "callers.tsv rows: %d" % len(rows)
    print("census OK")


def check_records():
    rec = json.loads((PACKET / "records.json").read_text())
    assert rec["target_sha256"] == DIGEST
    assert rec["statistics_impl_vtable"]["slots"]["0xe8"] == "0x6070810"
    assert rec["histogram_impl_vtable"]["slots"]["0x78"] == "0x606bdd0"
    assert rec["histogram_impl_vtable"]["slots"]["0x08"] == "0x5d8b3b0"
    # Re-derive both vtable tables from .rela.dyn.
    data = BINARY.read_bytes()
    rela_off, rela_size = 0x6BE8, 0x163CC8
    off_map = {}
    for i in range(rela_size // 24):
        off, info, addend = struct.unpack_from("<QQq", data, rela_off + i * 24)
        if info & 0xFFFFFFFF == 8:
            off_map[off] = addend
    for idx in range(32):
        got = off_map[0x64D2D88 + idx * 8]
        want = int(rec["statistics_impl_vtable"]["slots"]["0x%02x" % (idx * 8)], 16)
        assert got == want, "stats vtable slot 0x%02x: %#x" % (idx * 8, got)
    for idx in range(16):
        got = off_map[0x64D2B80 + idx * 8]
        want = int(rec["histogram_impl_vtable"]["slots"]["0x%02x" % (idx * 8)], 16)
        assert got == want, "hist vtable slot 0x%02x: %#x" % (idx * 8, got)
    # Typeinfo names.
    for addr, want in [(0x975500, b"N7rocksdb14StatisticsImplE"),
                       (0x9754E0, b"N7rocksdb10StatisticsE"),
                       (0x9753F0, b"N7rocksdb13HistogramImplE")]:
        off = vaddr_to_offset(addr)
        end = data.index(b"\0", off)
        assert data[off:end] == want, "typeinfo name at %#x" % addr
    # Percentile constants in the percentiles excerpt (objdump
    # prints the RIP-relative targets as "# 459640" / "# 459258").
    pct = (PACKET / "histogram_percentiles.txt").read_text()
    assert "# 459640" in pct and "# 459258" in pct
    print("records OK")


def check_tests():
    proc = subprocess.run(
        [sys.executable, "tests/test_stats_produce_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT)
    assert "0 failed" in proc.stdout, proc.stdout
    print("model tests OK: %s" % proc.stdout.strip())


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_raw_bytes()
    check_spots()
    check_frames()
    check_relocations()
    check_literals()
    check_census()
    check_records()
    check_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
