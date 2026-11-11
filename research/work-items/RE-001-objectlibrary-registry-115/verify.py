"""Checker for the RE-001-objectlibrary-registry-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-objectlibrary-registry-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary
(three random ones among them, seed 115: 0x5fd2035, 0x5fd1dad,
0x61f8615); the FDE ranges in frames.txt against a fresh frame
dump; the relocation set against a fresh relocation dump (31
records: the FactoryEntry node vtables, the ObjectLibrary
control-block vtable, the PatternEntry + ObjectRegistry
control-block vtables, the _Sp_make_shared_tag GOT slot); the
string literals against the raw binary; census consistency
(callers.tsv against a fresh census run: every pinned routine's
direct calls, tail jumps, lea references, stored qwords and
RELATIVE addends, and the callers.tsv caller function against
the smallest enclosing FDE range from a fresh frame dump); the
semantic records (re-deriving the census entries, the
relocation rows, the caller lists, the vtable maps, the
typeinfo names, the excerpt needles and the model behaviour);
and the model tests in tests/test_objectlibrary_registry_115.py.
Prints ALL CHECKS PASSED on success, else raises.
"""

import hashlib
import importlib.util
import json
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
    ("getter-61f8b60.objdump.txt", 0x61F8B60, 0x61F8D12),
    ("count-61f8700.objdump.txt", 0x61F8700, 0x61F8760),
    ("find-or-insert-5fd1da0.objdump.txt", 0x5FD1DA0, 0x5FD1FFA),
    ("find-or-insert-cold-5fd1ffa.objdump.txt", 0x5FD1FFA, 0x5FD20C4),
    ("rehash-5fd1c60.objdump.txt", 0x5FD1C60, 0x5FD1D9D),
    ("vector-insert-5fd17c0.objdump.txt", 0x5FD17C0, 0x5FD1962),
    ("insert-5fd24c0.objdump.txt", 0x5FD24C0, 0x5FD2748),
    ("default-init-5fd20d0.objdump.txt", 0x5FD20D0, 0x5FD241D),
    ("register-5fd27c0.objdump.txt", 0x5FD27C0, 0x5FD297F),
    ("cb-d1-5fefc70.objdump.txt", 0x5FEFC70, 0x5FEFC75),
    ("cb-d0-5fefd00.objdump.txt", 0x5FEFD00, 0x5FEFD0E),
    ("cb-dispose-5ff7900.objdump.txt", 0x5FF7900, 0x5FF7952),
    ("cb-destroy-5fefd50.objdump.txt", 0x5FEFD50, 0x5FEFD5E),
    ("cb-getdeleter-5feff70.objdump.txt", 0x5FEFF70, 0x5FEFFB7),
    ("map-destroy-5ff7820.objdump.txt", 0x5FF7820, 0x5FF78FF),
    ("pattern-d2-5ff2030.objdump.txt", 0x5FF2030, 0x5FF2145),
    ("pattern-d0-5ff2150.objdump.txt", 0x5FF2150, 0x5FF225F),
    ("pattern-match-61f8670.objdump.txt", 0x61F8670, 0x61F86F2),
    ("str-match-61f8430.objdump.txt", 0x61F8430, 0x61F8670),
    ("elem-match-61f8280.objdump.txt", 0x61F8280, 0x61F842B),
    ("pattern-accessor-61f8120.objdump.txt", 0x61F8120, 0x61F8129),
    ("node-env-d2-5fcc700.objdump.txt", 0x5FCC700, 0x5FCC742),
    ("node-env-d0-5fcd840.objdump.txt", 0x5FCD840, 0x5FCD88A),
    ("node-env-fwd2-5fcc7e0.objdump.txt", 0x5FCC7E0, 0x5FCC7EE),
    ("node-env-fwd3-5fcc7f0.objdump.txt", 0x5FCC7F0, 0x5FCC7FE),
    ("node-clock-d2-5fcc6b0.objdump.txt", 0x5FCC6B0, 0x5FCC6F2),
    ("node-clock-d0-5fcd7f0.objdump.txt", 0x5FCD7F0, 0x5FCD83A),
    ("node-clock-fwd2-5fcc7c0.objdump.txt", 0x5FCC7C0, 0x5FCC7CE),
    ("node-clock-fwd3-5fcc7d0.objdump.txt", 0x5FCC7D0, 0x5FCC7DE),
    ("node-envptr-d1-5fcc6a0.objdump.txt", 0x5FCC6A0, 0x5FCC6A5),
    ("node-envptr-d0-5fcc830.objdump.txt", 0x5FCC830, 0x5FCC83E),
]

# (target, expected direct calls, expected tail jumps, expected leas)
EXPECTED_CENSUS = {
    0x5FCC6A0: (0, 0, 0),
    0x5FCC6B0: (0, 0, 0),
    0x5FCC700: (0, 0, 0),
    0x5FCC7C0: (0, 0, 0),
    0x5FCC7D0: (0, 0, 0),
    0x5FCC7E0: (0, 0, 0),
    0x5FCC7F0: (0, 0, 0),
    0x5FCC830: (0, 0, 0),
    0x5FCD7F0: (0, 0, 0),
    0x5FCD840: (0, 0, 0),
    0x5FD17C0: (22, 0, 0),
    0x5FD1C60: (1, 0, 0),
    0x5FD1DA0: (22, 0, 0),
    0x5FD20D0: (0, 0, 1),
    0x5FD24C0: (2, 0, 0),
    0x5FD27C0: (0, 0, 2),
    0x5FEFC70: (0, 0, 0),
    0x5FEFD00: (0, 0, 0),
    0x5FEFD50: (0, 0, 0),
    0x5FEFF70: (0, 0, 0),
    0x5FF2030: (41, 0, 0),
    0x5FF2150: (0, 0, 0),
    0x5FF7820: (5, 0, 0),
    0x5FF7900: (0, 0, 0),
    0x61F8120: (0, 0, 0),
    0x61F8280: (1, 0, 0),
    0x61F8430: (2, 0, 0),
    0x61F8670: (0, 0, 0),
    0x61F8700: (8, 0, 0),
    0x61F8B60: (17, 0, 0),
}

# File offsets of 8-byte-aligned qwords equal to the target.
EXPECTED_QWORDS = {
    0x5FCC6A0: ['0x10fb28'],
    0x5FCC6B0: ['0x10fab0'],
    0x5FCC700: ['0x10fa38'],
    0x5FCC7C0: ['0x10fae0'],
    0x5FCC7D0: ['0x10faf8'],
    0x5FCC7E0: ['0x10fa68'],
    0x5FCC7F0: ['0x10fa80'],
    0x5FCC830: ['0x10fb40'],
    0x5FCD7F0: ['0x10fac8'],
    0x5FCD840: ['0x10fa50'],
    0x5FEFC70: ['0x1155d0'],
    0x5FEFD00: ['0x1155e8'],
    0x5FEFD50: ['0x115618'],
    0x5FEFF70: ['0x115630'],
    0x5FF2030: ['0x12bc08'],
    0x5FF2150: ['0x12bc20'],
    0x5FF7900: ['0x115600'],
    0x61F8120: ['0x12bc50'],
    0x61F8670: ['0x12bc38'],
}

# Number of RELATIVE records whose addend is the target.
EXPECTED_RELATIVE = {
    0x5FCC6A0: 1,
    0x5FCC6B0: 1,
    0x5FCC700: 1,
    0x5FCC7C0: 1,
    0x5FCC7D0: 1,
    0x5FCC7E0: 1,
    0x5FCC7F0: 1,
    0x5FCC830: 1,
    0x5FCD7F0: 1,
    0x5FCD840: 1,
    0x5FEFC70: 1,
    0x5FEFD00: 1,
    0x5FEFD50: 1,
    0x5FEFF70: 1,
    0x5FF2030: 1,
    0x5FF2150: 1,
    0x5FF7900: 1,
    0x61F8120: 1,
    0x61F8670: 1,
}

# The stored relocations.txt rows: (offset, addend).
EXPECTED_RELOCATIONS = [
    (0x64cde60, 0x64cd9a0), (0x64cde68, 0x5fcc700), (0x64cde70, 0x5fcd840),
    (0x64cde78, 0x5fcc7e0), (0x64cde80, 0x5fcc7f0), (0x64cde90, 0x64cd9b8),
    (0x64cde98, 0x5fcc6b0), (0x64cdea0, 0x5fcd7f0), (0x64cdea8, 0x5fcc7c0),
    (0x64cdeb0, 0x5fcc7d0), (0x64cdec0, 0x64cda10), (0x64cdec8, 0x5fcc6a0),
    (0x64cded0, 0x5fcc830), (0x64d00e8, 0x64cf808), (0x64d00f0, 0x5fefc70),
    (0x64d00f8, 0x5fefd00), (0x64d0100, 0x5ff7900), (0x64d0108, 0x5fefd50),
    (0x64d0110, 0x5feff70), (0x64d8ec8, 0x64d8e90), (0x64d8ed0, 0x5ff2030),
    (0x64d8ed8, 0x5ff2150), (0x64d8ee0, 0x61f8670), (0x64d8ee8, 0x61f8120),
    (0x64d8ef8, 0x64d8ea8), (0x64d8f00, 0x61f8130), (0x64d8f08, 0x61f8140),
    (0x64d8f10, 0x61f8760), (0x64d8f18, 0x61f8170), (0x64d8f20, 0x61f8180),
    (0x64ecdc8, 0x96cb48),
]

SPOT_BYTES = {
    0x61F8B60: bytes.fromhex("f30f1efa"),
    0x61F8700: bytes.fromhex("f30f1efa"),
    0x5FD1DA0: bytes.fromhex("f30f1efa"),
    0x5FD24C0: bytes.fromhex("4156"),
    0x5FD27C0: bytes.fromhex("f30f1efa"),
    0x5FD20D0: bytes.fromhex("f30f1efa"),
    0x5FF7900: bytes.fromhex("f30f1efa"),
    0x5FF7820: bytes.fromhex("f30f1efa"),
    0x5FF2030: bytes.fromhex("f30f1efa"),
    0x61F8430: bytes.fromhex("f30f1efa"),
    0x61F8280: bytes.fromhex("f30f1efa"),
    0x5FCC700: bytes.fromhex("f30f1efa"),
    0x5FCC6B0: bytes.fromhex("f30f1efa"),
    0x5FEFD00: bytes.fromhex("f30f1efa"),
    0x5FEFF70: bytes.fromhex("f30f1efa"),
    # Seeded-random gate spots (seed 115).
    0x5FD2035: bytes.fromhex("ffd0"),
    0x5FD1DAD: bytes.fromhex("4155"),
    0x61F8615: bytes.fromhex("8b442408"),
}
TAB = chr(9)
LINE_RE = re.compile("^ *([0-9a-f]+):" + TAB + "([0-9a-f ]+?)" + TAB + "(.*)$")
CONT_RE = re.compile("^ *([0-9a-f]+):" + TAB + "([0-9a-f ]+?) *$")


def fail(message):
    raise AssertionError(message)


def load_segments(data):
    """(offset, vaddr, filesz) for every PT_LOAD segment."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    out = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _f, p_offset, p_vaddr, _p, p_filesz,
         _m, _a) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1:
            out.append((p_offset, p_vaddr, p_filesz))
    return out


def va_to_off(segments, va):
    for off, vaddr, size in segments:
        if vaddr <= va < vaddr + size:
            return off + (va - vaddr)
    return None


def parse_excerpt(text):
    """[(address, bytes)] for one excerpt, merging objdump
    continuation lines into the previous instruction."""
    ins = []
    for line in text.splitlines():
        m = LINE_RE.match(line)
        if m:
            raw = m.group(2).replace(" ", "")
            ins.append([int(m.group(1), 16), bytes.fromhex(raw)])
            continue
        m = CONT_RE.match(line)
        if m and ins:
            raw = m.group(2).replace(" ", "")
            ins[-1][1] += bytes.fromhex(raw)
            continue
    return [(a, b) for a, b in ins]


def check_digest(data):
    got = hashlib.sha256(data).hexdigest()
    if got != DIGEST:
        fail("binary digest mismatch: %s != %s" % (got, DIGEST))
    print("digest ok")


def check_manifest():
    lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    seen = set()
    for line in lines:
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        name = name.lstrip("*").strip()
        seen.add(name)
        got = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if got != digest:
            fail("manifest mismatch for %s" % name)
    files = {p.name for p in PACKET.iterdir()
             if p.is_file() and p.name != "MANIFEST.sha256"}
    if seen != files:
        fail("manifest file set mismatch: extra=%s missing=%s"
             % (sorted(seen - files), sorted(files - seen)))
    print("manifest ok (%d files)" % len(seen))


def check_excerpts(segments, data):
    for name, start, stop in WINDOWS:
        fresh = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True,
            cwd=ROOT).stdout
        stored = (PACKET / name).read_text()
        if fresh != stored:
            fail("excerpt %s does not match a fresh objdump run" % name)
        for addr, raw in parse_excerpt(stored):
            off = va_to_off(segments, addr)
            if off is None:
                fail("excerpt %s: no file offset for %#x" % (name, addr))
            if data[off:off + len(raw)] != raw:
                fail("excerpt %s: bytes mismatch at %#x" % (name, addr))
    print("excerpts ok (%d windows)" % len(WINDOWS))


def check_spots(segments, data):
    for addr, expect in SPOT_BYTES.items():
        fresh = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % addr,
             "--stop-address=%#x" % (addr + 16),
             "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True,
            cwd=ROOT).stdout
        ins = parse_excerpt(fresh)
        if not ins or ins[0][0] != addr:
            fail("spot %#x: no instruction at that address" % addr)
        raw = ins[0][1]
        if raw != expect:
            fail("spot %#x: %s != %s" % (addr, raw.hex(), expect.hex()))
        off = va_to_off(segments, addr)
        if data[off:off + len(raw)] != raw:
            fail("spot %#x: raw binary mismatch" % addr)
    print("spots ok (%d)" % len(SPOT_BYTES))


def check_frames():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    fresh = set()
    for m in re.finditer("pc=([0-9a-f]+)[.][.]([0-9a-f]+)", text):
        fresh.add((int(m.group(1), 16), int(m.group(2), 16)))
    for line in (PACKET / "frames.txt").read_text().splitlines():
        m = re.search("pc=([0-9a-f]+)[.][.]([0-9a-f]+)", line)
        if not m:
            if not line.strip() or line.startswith("start"):
                continue
            fail("frames.txt line has no pc range: %s" % line)
        pair = (int(m.group(1), 16), int(m.group(2), 16))
        if pair not in fresh:
            fail("FDE %#x..%#x not in a fresh frame dump" % pair)
    print("frames ok")


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    relocs = {}
    for line in text.splitlines():
        m = re.match("[ ]*([0-9a-f]+)[ ]+([0-9a-f]+)[ ]+R_X86_64_([A-Za-z]+)"
                     "(?:[ ]+([0-9a-f]+))?", line)
        if not m or m.group(3) != "RELATIVE" or m.group(4) is None:
            continue
        relocs[int(m.group(1), 16)] = int(m.group(4), 16)
    stored = []
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split()
        stored.append((int(parts[0], 16), int(parts[3], 16)))
        if relocs.get(int(parts[0], 16)) != int(parts[3], 16):
            fail("relocation %s not in a fresh dump" % line)
    if len(stored) != len(EXPECTED_RELOCATIONS):
        fail("relocation count %d != %d"
             % (len(stored), len(EXPECTED_RELOCATIONS)))
    if sorted(stored) != sorted(EXPECTED_RELOCATIONS):
        fail("stored relocation set mismatch")
    for target, count in EXPECTED_RELATIVE.items():
        got = [o for o, a in relocs.items() if a == target]
        if len(got) != count:
            fail("RELATIVE count for %#x: %d != %d"
                 % (target, len(got), count))
    print("relocations ok (%d records)" % len(stored))


def check_literals(segments, data, records):
    for lit in records["literals"]:
        addr = lit["addr"]
        off = va_to_off(segments, addr)
        if off is None:
            fail("literal %#x: no file offset" % addr)
        if off != lit["offset"]:
            fail("literal %#x offset %#x != %#x" % (addr, off, lit["offset"]))
        if lit["text"].startswith("<"):
            if addr == 0x459B20:
                want = struct.pack("<Q", 0x100000001)
            else:
                fail("unknown special literal %#x" % addr)
        else:
            want = lit["text"].encode() + b"\x00"
        if data[off:off + len(want)] != want:
            fail("literal %#x mismatch" % addr)
    print("literals ok (%d)" % len(records["literals"]))


def check_census():
    spec = importlib.util.spec_from_file_location(
        "packet_census", PACKET / "census.py")
    census = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(census)
    data = BINARY.read_bytes()
    sites = census.disassembly_sites()
    relocs, _lines = census.relative_records()
    ranges = census.frame_ranges()
    ordered = sorted(ranges)
    starts = [a for a, _b in ordered]
    for target, (want_calls, want_jumps, want_leas) in EXPECTED_CENSUS.items():
        calls, jumps = census.scan(sites, target)
        leas = sites.get(target, ([], [], []))[2]
        if (len(calls), len(jumps), len(leas)) != (want_calls, want_jumps, want_leas):
            fail("census for %#x: calls=%d jumps=%d leas=%d, want %d/%d/%d"
                 % (target, len(calls), len(jumps), len(leas),
                    want_calls, want_jumps, want_leas))
        qw = census.qwords(data, target)
        want_qw = [int(x, 16)
                   for x in EXPECTED_QWORDS.get(target, [])]
        if qw != want_qw:
            fail("qwords for %#x: %s != %s" % (target, qw, want_qw))
        rel = sorted(o for o, a in relocs.items() if a == target)
        want_rel = EXPECTED_RELATIVE.get(target, 0)
        if len(rel) != want_rel:
            fail("RELATIVE count for %#x: %d != %d"
                 % (target, len(rel), want_rel))
    rows = []
    for line in (PACKET / "callers.tsv").read_text().splitlines()[1:]:
        if not line.strip():
            continue
        site, target, caller, kind = line.split("\t")
        rows.append((int(site, 16), int(target, 16), caller, kind))
        want = census.enclosing_fde(ordered, starts, int(site, 16))
        if caller != want:
            fail("callers.tsv caller for %s: %s != %s"
                 % (site, caller, want))
    expect_rows = []
    for target in sorted(EXPECTED_CENSUS):
        calls, jumps = census.scan(sites, target)
        leas = sites.get(target, ([], [], []))[2]
        for site in calls:
            expect_rows.append((site, target, "call"))
        for site in jumps:
            expect_rows.append((site, target, "tail jump"))
        for site in leas:
            expect_rows.append((site, target, "lea"))
    expect_rows.sort()
    got_rows = sorted((s, t, k) for s, t, _c, k in rows)
    if got_rows != expect_rows:
        fail("callers.tsv rows do not match a fresh census run")
    print("census ok (%d rows)" % len(rows))


def check_records(segments, data, records):
    spec = importlib.util.spec_from_file_location(
        "packet_census_rel", PACKET / "census.py")
    census_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(census_mod)
    full_relocs, _lines = census_mod.relative_records()
    sites = census_mod.disassembly_sites()

    # Census entries re-derive from a fresh run.
    for key, entry in records["census"]["targets"].items():
        target = int(key, 16)
        if target not in EXPECTED_CENSUS:
            fail("records census has an unexpected target %#x" % target)
        want = EXPECTED_CENSUS[target]
        if (entry["calls"], entry["jumps"], entry["leas"]) != want:
            fail("records census for %#x: %s != %s"
                 % (target, (entry["calls"], entry["jumps"], entry["leas"]),
                    want))
        if entry["qwords"] != len(EXPECTED_QWORDS.get(target, [])):
            fail("records qword count for %#x: %d != %d"
                 % (target, entry["qwords"],
                    len(EXPECTED_QWORDS.get(target, []))))
        if entry["relative"] != EXPECTED_RELATIVE.get(target, 0):
            fail("records RELATIVE count for %#x: %d != %d"
                 % (target, entry["relative"],
                    EXPECTED_RELATIVE.get(target, 0)))
    if len(records["census"]["targets"]) != len(EXPECTED_CENSUS):
        fail("records census target count mismatch")
    if records["census"]["relocation_records"] != 31:
        fail("records relocation total != 31")
    if records["census"]["callers_tsv_rows"] != 124:
        fail("records callers.tsv row count != 124")
    if records["test_checks"] != 23:
        fail("records test_checks != 23")
    if records["target"]["sha256"] != DIGEST:
        fail("records target digest mismatch")

    # The relocation rows re-derive from a fresh readelf dump.
    for row in records["relocations"]:
        if full_relocs.get(row["offset"]) != row["addend"]:
            fail("records relocation %#x not in a fresh dump"
                 % row["offset"])
    if sorted((r["offset"], r["addend"]) for r in records["relocations"]) \
            != sorted(EXPECTED_RELOCATIONS):
        fail("records relocation set mismatch")

    # Caller lists re-derive from a fresh census run.
    def call_sites(target):
        return ["%#x" % s for s in
                census_mod.scan(sites, target)[0]]

    def lea_sites(target):
        return ["%#x" % s for s in
                sites.get(target, ([], [], []))[2]]

    def addr_list(entries):
        # Records annotate callers ("0x5fd210c (default-init ...)").
        return [e.split()[0] for e in entries]

    if call_sites(0x61F8B60) != addr_list(records["getter"]["callers"]):
        fail("getter caller mismatch")
    if call_sites(0x61F8700) != addr_list(records["count"]["callers"]):
        fail("count caller mismatch")
    if call_sites(0x5FD1DA0) != addr_list(records["find_or_insert"]["callers"]):
        fail("find-or-insert caller mismatch")
    if call_sites(0x5FD17C0) != addr_list(records["vector_insert"]["callers"]):
        fail("vector-insert caller mismatch")
    if call_sites(0x5FD24C0) != addr_list(records["insert"]["callers"]):
        fail("insert caller mismatch")
    if call_sites(0x5FD1C60) != addr_list(records["rehash"]["callers"]):
        fail("rehash caller mismatch")
    if call_sites(0x5FF7820) != addr_list(records["map_destroy"]["callers"]):
        fail("map-destroy caller mismatch")
    if call_sites(0x61F8430) != addr_list(records["str_match"]["callers"]):
        fail("str-match caller mismatch")
    if call_sites(0x61F8280) != addr_list(records["elem_match"]["callers"]):
        fail("elem-match caller mismatch")
    if lea_sites(0x5FD20D0) != addr_list(records["default_init"]["lea_sites"]):
        fail("default-init lea sites mismatch")
    if lea_sites(0x5FD27C0) != addr_list(records["register"]["lea_sites"]):
        fail("register lea sites mismatch")

    # Vtable maps re-derive from a fresh readelf dump.
    def vtable_map(base, nslots):
        return ["0x%x" % full_relocs.get(base + i * 8, 0)
                for i in range(nslots)]

    fn = records["factory_nodes"]
    if vtable_map(0x64CDE68, 4) != [
            "0x%x" % s["addr"] for s in fn["env_vtable"]["slots"]]:
        fail("FactoryEntry<Env> vtable map mismatch")
    if vtable_map(0x64CDE98, 4) != [
            "0x%x" % s["addr"] for s in fn["clock_vtable"]["slots"]]:
        fail("FactoryEntry<SystemClock> vtable map mismatch")
    if vtable_map(0x64CDEC8, 5) != [
            "0x%x" % s["addr"] for s in fn["env_ptr_cb_vtable"]["slots"]]:
        fail("_Sp_counted_ptr<Env*> vtable map mismatch")
    cb = records["control_block"]
    if vtable_map(0x64D00F0, 5) != [
            "0x%x" % s["addr"] for s in cb["slots"]]:
        fail("ObjectLibrary control-block vtable map mismatch")
    pe = records["pattern_entry"]
    if vtable_map(0x64D8ED0, 4) != [
            "0x%x" % s["addr"] for s in pe["slots"]]:
        fail("PatternEntry vtable map mismatch")
    ob = records["object_registry_cb_vtable"]
    if vtable_map(0x64D8F00, 5) != [
            "0x%x" % s["addr"] for s in ob["slots"]]:
        fail("ObjectRegistry control-block vtable map mismatch")

    # Typeinfo names.
    if cb["typeinfo"] != ("St23_Sp_counted_ptr_inplace"
                          "IN7rocksdb13ObjectLibraryESaIvE"
                          "LN9__gnu_cxx12_Lock_policyE2EE"):
        fail("control-block typeinfo mismatch")
    if pe["typeinfo"] != "N7rocksdb13ObjectLibrary12PatternEntryE":
        fail("PatternEntry typeinfo mismatch")
    if fn["env_vtable"]["typeinfo"] != (
            "N7rocksdb13ObjectLibrary12FactoryEntryINS_3EnvEEE"):
        fail("FactoryEntry<Env> typeinfo mismatch")
    if fn["clock_vtable"]["typeinfo"] != (
            "N7rocksdb13ObjectLibrary12FactoryEntryINS_11SystemClockEEE"):
        fail("FactoryEntry<SystemClock> typeinfo mismatch")
    if fn["env_ptr_cb_vtable"]["typeinfo"] != (
            "St15_Sp_counted_ptrIPN7rocksdb3EnvE"
            "LN9__gnu_cxx12_Lock_policyE2EE"):
        fail("_Sp_counted_ptr<Env*> typeinfo mismatch")
    if ob["typeinfo"] != ("St23_Sp_counted_ptr_inplace"
                          "IN7rocksdb14ObjectRegistryESaIvE"
                          "LN9__gnu_cxx12_Lock_policyE2EE"):
        fail("ObjectRegistry control-block typeinfo mismatch")

    # Excerpt needles for the pinned semantics.
    def excerpt(name):
        return (PACKET / name).read_text()

    getter = excerpt("getter-61f8b60.objdump.txt")
    for needle in ("# 6509110", "# 459b20", "# 64d00e0"):
        if needle not in getter:
            fail("getter line missing: %s" % needle)
    count = excerpt("count-61f8700.objdump.txt")
    if "pthread_mutex_lock" not in count:
        fail("count must lock the mutex")
    foi = excerpt("find-or-insert-5fd1da0.objdump.txt")
    for needle in ("0xc70f6907", "call   5fd1c60"):
        if needle not in foi:
            fail("find-or-insert line missing: %s" % needle)
    insert = excerpt("insert-5fd24c0.objdump.txt")
    for needle in ("# 44a397", "call   5fd1da0"):
        if needle not in insert:
            fail("insert line missing: %s" % needle)
    register = excerpt("register-5fd27c0.objdump.txt")
    for needle in ("# 447686", "# 43e762"):
        if needle not in register:
            fail("register line missing: %s" % needle)
    if register.count("call   5fd24c0") != 2:
        fail("register must call insert twice")
    default_init = excerpt("default-init-5fd20d0.objdump.txt")
    for needle in ("# 438369", "# 4372ae"):
        if needle not in default_init:
            fail("default-init line missing: %s" % needle)
    dispose = excerpt("cb-dispose-5ff7900.objdump.txt")
    if "call   5ff7820" not in dispose:
        fail("cb dispose must call the map destroy")
    matcher = excerpt("pattern-match-61f8670.objdump.txt")
    if matcher.count("call   61f8430") != 2:
        fail("pattern Matches must call str-match twice")
    str_match = excerpt("str-match-61f8430.objdump.txt")
    if "call   61f8280" not in str_match:
        fail("str-match must call elem-match")
    if "mov    0x20(%r12),%edx" not in str_match:
        fail("str-match must load the lagged mode")
    for name, slot in (("node-env-fwd2-5fcc7e0.objdump.txt", 2),
                       ("node-clock-fwd2-5fcc7c0.objdump.txt", 2)):
        if "jmp    *0x10(%rax)" not in excerpt(name):
            fail("%s must forward slot 2" % name)
    for name in ("node-env-fwd3-5fcc7f0.objdump.txt",
                 "node-clock-fwd3-5fcc7d0.objdump.txt"):
        if "jmp    *0x18(%rax)" not in excerpt(name):
            fail("%s must forward slot 3" % name)
    accessor = excerpt("pattern-accessor-61f8120.objdump.txt")
    if "mov    0x8(%rdi),%rax" not in accessor:
        fail("pattern accessor must return this+0x08")

    # The model constants and behaviour.
    sys.path.insert(0, str(ROOT / "tools"))
    import objectlibrary_registry_115 as model
    if model.CONTROL_BLOCK_VTABLE != 0x64D00F0:
        fail("model control-block vtable mismatch")
    if model.PATTERN_ENTRY_VTABLE != 0x64D8ED0:
        fail("model PatternEntry vtable mismatch")
    if model.NODE_ENV_VTABLE != 0x64CDE68:
        fail("model node Env vtable mismatch")
    if model.FRESH_COUNTS != 0x100000001:
        fail("model fresh counts mismatch")
    if model.HASH_SEED != 0xC70F6907:
        fail("model hash seed mismatch")
    reg = model.ObjectLibrary.default()
    reg.register()
    reg.default_init()
    keys, total = reg.count()
    if (keys, total) != (2, 3):
        fail("model full sequence count mismatch: %r" % ((keys, total),))
    vec = reg.map.find(model.ENVIRONMENT_KEY)
    if [n.entry.pattern for n in vec] != ["MockEnv", "CompositeEnv"]:
        fail("model Environment entries mismatch")
    if not vec[0].matches("MockEnv"):
        fail("model node matcher mismatch")
    if vec[0].matches("CompositeEnv"):
        fail("model node matcher cross-match")
    if reg.get_deleter("St19_Sp_make_shared_tag") is not reg:
        fail("model get-deleter tag mismatch")
    if reg.get_deleter("other") is not None:
        fail("model get-deleter other mismatch")
    reg.dispose()
    if not reg.map.destroyed or reg.map.element_count != 0:
        fail("model dispose mismatch")
    print("records ok (census, relocations, callers, vtables, "
          "typeinfo, excerpts, model)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/test_objectlibrary_registry_115.py", "-q"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "23 passed" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (23 tests)")


def main():
    data = BINARY.read_bytes()
    segments = load_segments(data)
    records = json.loads((PACKET / "records.json").read_text())
    check_digest(data)
    check_manifest()
    check_excerpts(segments, data)
    check_spots(segments, data)
    check_frames()
    check_relocations()
    check_literals(segments, data, records)
    check_census()
    check_records(segments, data, records)
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
