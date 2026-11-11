"""Checker for the RE-001-systemclock-installers-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-systemclock-installers-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary
(three random ones among them, seed 115: 0x5fd27cf, 0x5fd23f1,
0x5fd20e3); the FDE ranges in frames.txt against a fresh frame
dump; the relocation set against a fresh relocation dump (47
records: the FactoryEntry headers, the wrapper vtable, the
registry node vtable, the emulated slots 0-1, the make_shared
control-block vtable, the holder vtable, the registry entry
vtable and the GOT canonical slot); the string literals against
the raw binary; census consistency (callers.tsv against a fresh
census run: every pinned routine's direct calls, tail jumps,
lea references, stored qwords and RELATIVE addends, and the
callers.tsv caller function against the smallest enclosing FDE
range from a fresh frame dump); the semantic records
(re-deriving the census entries, the relocation rows, the
reshipped excerpts, the installer forms and the model
behaviour); and the model tests in
tests/test_systemclock_installers_115.py.
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
RE3352 = ROOT / "research" / "work-items" / "RE-001-canonical-lea-sites-115"

WINDOWS = [
    ("append-6099ce0.objdump.txt", 0x6099CE0, 0x6099E34),
    ("grow-6099790.objdump.txt", 0x6099790, 0x6099CAD),
    ("emu-ctor-6029390.objdump.txt", 0x6029390, 0x60294F5),
    ("lastuse-5d35070.objdump.txt", 0x5D35070, 0x5D350BC),
    ("landing-602934c.objdump.txt", 0x602934C, 0x6029383),
    ("reg-sysclocks-5fd27c0.objdump.txt", 0x5FD27C0, 0x5FD297F),
    ("default-init-5fd20d0.objdump.txt", 0x5FD20D0, 0x5FD241D),
    ("insert-5fd24c0.objdump.txt", 0x5FD24C0, 0x5FD2748),
    ("invoker-mockenv-5fcd5b0.objdump.txt", 0x5FCD5B0, 0x5FCD5DB),
    ("invoker-timeemu-5fcd550.objdump.txt", 0x5FCD550, 0x5FCD5A9),
    ("invoker-composite-5fcf450.objdump.txt", 0x5FCF450, 0x5FCF4CB),
    ("factory-60297a0.objdump.txt", 0x60297A0, 0x60298F7),
    ("accessor-5fcf430.objdump.txt", 0x5FCF430, 0x5FCF439),
    ("node-dtor-5fcc700.objdump.txt", 0x5FCC700, 0x5FCC742),
    ("vtable_install_1.txt", 0x5FD0090, 0x5FD0178),
    ("vtable_install_2.txt", 0x6029110, 0x602922B),
    ("vtable_install_3.txt", 0x6029230, 0x602934B),
    ("vtable_install_4.txt", 0x6029500, 0x602961B),
    ("vtable_install_5.txt", 0x6029620, 0x602973B),
    ("entry_install_1.txt", 0x5FCC5D0, 0x5FCC5FD),
    ("entry_install_2.txt", 0x5FCC600, 0x5FCC62D),
    ("entry_install_3.txt", 0x5FCC630, 0x5FCC65D),
]

# (target, expected direct calls, expected tail jumps, expected leas)
EXPECTED_CENSUS = {
    0x5FD0090: (1, 0, 0),
    0x6029110: (0, 0, 0),
    0x6029230: (1, 0, 0),
    0x6029500: (0, 0, 0),
    0x6029620: (0, 0, 0),
    0x6099CE0: (37, 0, 0),
    0x6099790: (1, 0, 0),
    0x5D35070: (654, 36, 0),
    0x6029390: (2, 0, 0),
    0x602934C: (0, 1, 0),
    0x60297A0: (1, 0, 0),
    0x5FCF430: (19, 0, 0),
    0x5FCC5D0: (0, 0, 1),
    0x5FCC600: (0, 0, 1),
    0x5FCC630: (0, 0, 1),
    0x5FD27C0: (0, 0, 2),
    0x5FD20D0: (0, 0, 1),
    0x5FD24C0: (2, 0, 0),
    0x5FCD5B0: (0, 0, 1),
    0x5FCD550: (0, 0, 1),
    0x5FCF450: (0, 0, 1),
    0x5FCC700: (0, 0, 0),
    0x5FE2860: (17, 0, 0),
    0x5FCF390: (14, 0, 0),
    0x5FD7360: (2, 0, 0),
    0x6028D80: (1, 0, 0),
}

# File offsets of 8-byte-aligned qwords equal to the target.
EXPECTED_QWORDS = {
    0x6029110: ["0x118e28"],
    0x6029620: ["0x118e40"],
    0x5FCC700: ["0x10fa38"],
}

# Number of RELATIVE records whose addend is the target.
EXPECTED_RELATIVE = {
    0x6029110: 1,
    0x6029620: 1,
    0x5FCC700: 1,
}

# The stored relocations.txt rows: (offset, addend).
EXPECTED_RELOCATIONS = [
    (0x64CD9C0, 0x9721E0),
    (0x64CD9C8, 0x64CD990),
    (0x64CD9D8, 0x972220),
    (0x64CD9E8, 0x9722E0),
    (0x64CD9F8, 0x9723A0),
    (0x64CDD80, 0x64CD960),
    (0x64CDD98, 0x609D760),
    (0x64CDDA0, 0x609DC40),
    (0x64CDDA8, 0x5D32560),
    (0x64CDDB0, 0x5FCF590),
    (0x64CDDB8, 0x6096790),
    (0x64CDDC0, 0x5D2E090),
    (0x64CDDC8, 0x60956F0),
    (0x64CDDD0, 0x609D0E0),
    (0x64CDDD8, 0x60986B0),
    (0x64CDDE0, 0x6095710),
    (0x64CDDE8, 0x5FCDAE0),
    (0x64CDDF0, 0x609D980),
    (0x64CDE00, 0x5D32A30),
    (0x64CDE08, 0x5D2E770),
    (0x64CDE10, 0x5FCC3F0),
    (0x64CDE18, 0x5D2CA10),
    (0x64CDE20, 0x5D4D490),
    (0x64CDE28, 0x5FCC340),
    (0x64CDE30, 0x5FCC360),
    (0x64CDE38, 0x5FCC380),
    (0x64CDE40, 0x5DD41A0),
    (0x64CDE48, 0x5D4B100),
    (0x64CDE50, 0x5FCC3A0),
    (0x64CDE60, 0x64CD9A0),
    (0x64CDE68, 0x5FCC700),
    (0x64CDE70, 0x5FCD840),
    (0x64CDE78, 0x5FCC7E0),
    (0x64CE2D0, 0x64CDFA8),
    (0x64CE2E8, 0x609D760),
    (0x64D1650, 0x6029110),
    (0x64D1658, 0x6029620),
    (0x64D1C30, 0x64D1358),
    (0x64D1C38, 0x6025910),
    (0x64D1C40, 0x6025A70),
    (0x64D1C48, 0x6025950),
    (0x64D1C50, 0x6025B90),
    (0x64D1C58, 0x6026070),
    (0x64D8EC8, 0x64D8E90),
    (0x64D8ED0, 0x5FF2030),
    (0x64D8ED8, 0x5FF2150),
    (0x64ED3E8, 0x5D4B100),
]

SPOT_BYTES = {
    0x5D35070: bytes.fromhex("f30f1efa"),
    0x5FCC5D0: bytes.fromhex("f30f1efa"),
    0x5FCC700: bytes.fromhex("f30f1efa"),
    0x5FCC72B: bytes.fromhex("ffd0"),
    0x5FCD577: bytes.fromhex("e814be0500"),
    0x5FCF430: bytes.fromhex("f30f1efa"),
    0x5FD0090: bytes.fromhex("f30f1efa"),
    0x5FD20E3: bytes.fromhex("55"),
    0x5FD23F1: bytes.fromhex("4889c3"),
    0x5FD27CF: bytes.fromhex("4154"),
    0x5FD2848: bytes.fromhex("e873fcffff"),
    0x6029390: bytes.fromhex("f30f1efa"),
    0x60293B6: bytes.fromhex("e8d56cfaff"),
    0x6029494: bytes.fromhex("e847080700"),
    0x60297A0: bytes.fromhex("f30f1efa"),
    0x6029800: bytes.fromhex("e88bfbffff"),
    0x6099790: bytes.fromhex("f30f1efa"),
    0x6099CE0: bytes.fromhex("f30f1efa"),
    0x6099E0A: bytes.fromhex("e881f9ffff"),
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
    if len(records["census"]["targets"]) != len(EXPECTED_CENSUS):
        fail("records census target count mismatch")
    if records["census"]["relocation_records"] != 47:
        fail("records relocation total != 47")
    if records["census"]["callers_tsv_rows"] != 798:
        fail("records callers.tsv row count != 798")
    if records["test_checks"] != 135:
        fail("records test_checks != 135")
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

    # The re-shipped excerpts match #3352 byte-for-byte.
    for entry in records["reshipped"]:
        local = hashlib.sha256(
            (PACKET / entry["file"]).read_bytes()).hexdigest()
        prior = hashlib.sha256(
            (RE3352 / entry["file"]).read_bytes()).hexdigest()
        if local != entry["sha256"] or prior != entry["sha256"]:
            fail("reshipped excerpt %s hash mismatch" % entry["file"])

    # Installer callers re-derive from the fresh census.
    installers = {i["addr"]: i for i in records["installers"]}
    if installers[0x5FD0090]["callers"] != ["0x60293b6"]:
        fail("wrapper ctor caller mismatch")
    if installers[0x6029230]["callers"] != ["0x6029357"]:
        fail("wrapper D2 caller mismatch")
    if installers[0x6029110]["callers"] != []:
        fail("emulated D2 must have no direct callers")
    if installers[0x6029500]["callers"] != []:
        fail("wrapper D0 must have no direct callers")
    if installers[0x6029620]["callers"] != []:
        fail("emulated D0 must have no direct callers")

    # Thunk lea sites re-derive from the fresh census.
    for thunk in records["thunks"]:
        leas = sites.get(thunk["addr"], ([], [], []))[2]
        if ["%#x" % l for l in leas] != thunk["lea_sites"]:
            fail("thunk %#x lea sites mismatch" % thunk["addr"])

    # The append clock sites are the three pinned call sites.
    if sorted(records["append"]["clock_sites"]) != \
            ["0x5fd0124", "0x6029454", "0x6029494"]:
        fail("append clock sites mismatch")
    if records["append"]["calls"] != 37:
        fail("append call count mismatch")
    if records["last_use_helper"]["calls"] != 654:
        fail("last-use call count mismatch")
    if records["last_use_helper"]["jumps"] != 36:
        fail("last-use jump count mismatch")

    # The manager op sites: op 2 in insert and in the registry
    # find; op 3 in the two registrations, default-init and the
    # node D2. Op 0 and op 1 are never invoked.
    ops = records["manager_ops"]
    if ops["op_0"]["invoked"] or ops["op_1"]["invoked"]:
        fail("manager op 0/1 must never be invoked")
    if not ops["op_2"]["invoked"] or not ops["op_3"]["invoked"]:
        fail("manager op 2/3 must be invoked")
    if len(ops["op_2"]["sites"]) != 2 or len(ops["op_3"]["sites"]) != 4:
        fail("manager op site counts mismatch")

    # The vtable installers: lea of the header plus 0x10 and
    # the vptr store.
    for i in range(1, 6):
        text = (PACKET / ("vtable_install_%d.txt" % i)).read_text()
        if "64cdd78" not in text:
            fail("vtable installer %d must lea the header" % i)
        if "add    $0x10,%rax" not in text:
            fail("vtable installer %d must add 0x10" % i)
        if "mov    %rax,(%rdi)" not in text:
            fail("vtable installer %d must store the vptr" % i)
    # The entry thunks: the mode test and the vtable install.
    for i, vtable in enumerate((0x64CD9D0, 0x64CD9E0, 0x64CD9F0), 1):
        text = (PACKET / ("entry_install_%d.txt" % i)).read_text()
        if ("# %x" % vtable) not in text:
            fail("entry installer %d must lea %#x" % (i, vtable))
        if "mov    %rax,(%rdi)" not in text:
            fail("entry installer %d must store the vtable" % i)
    # The factory: new(0x60), the control-block counts and the
    # mode-1 emulated ctor call.
    factory = (PACKET / "factory-60297a0.objdump.txt").read_text()
    for needle in ("mov    $0x60,%edi",
                   "movabs $0x100000001,%rax",
                   "call   6029390"):
        if needle not in factory:
            fail("factory line missing: %s" % needle)
    # The invokers: each replaces the cell and the time-emu one
    # calls the emulated ctor in mode 0.
    invoker_timeemu = (PACKET / "invoker-timeemu-5fcd550.objdump.txt").read_text()
    if "call   6029390" not in invoker_timeemu:
        fail("time-emu invoker must call the emulated ctor")
    if "mov    $0x50,%edi" not in invoker_timeemu:
        fail("time-emu invoker must allocate 0x50 bytes")
    # The node D2: the manager op-3 call and the entry D0 jump.
    node_dtor = (PACKET / "node-dtor-5fcc700.objdump.txt").read_text()
    if "mov    $0x3,%edx" not in node_dtor:
        fail("node D2 must call the manager with op 3")
    if "jmp    *%rax" not in node_dtor:
        fail("node D2 must tail-jump to the entry D0")
    # The append: the grow call at capacity.
    append = (PACKET / "append-6099ce0.objdump.txt").read_text()
    if "call   6099790" not in append:
        fail("append must call grow at capacity")
    # The grow: the doubling constant and the max check.
    grow = (PACKET / "grow-6099790.objdump.txt").read_text()
    if "0xaaaaaaaaaaaaaaab" not in grow:
        fail("grow must divide by 48 with 0xaaaaaaaaaaaaaaab")
    if "0x2aaaaaaaaaaaaaa" not in grow:
        fail("grow must check against the max capacity")

    # The model constants and behaviour.
    sys.path.insert(0, str(ROOT / "tools"))
    import systemclock_installers_115 as model
    if model.WRAPPER_VTABLE != 0x64CDD88:
        fail("model wrapper vtable mismatch")
    if model.EMULATED_VTABLE != 0x64D1650:
        fail("model emulated vtable mismatch")
    if model.SCALE != 0x431BDE82D7B634DB:
        fail("model scale constant mismatch")
    if model.scaled_add(2 ** 40) != 1099511:
        fail("model scaled add mismatch")
    if model.FACTORY_COUNTS != 0x100000001:
        fail("model factory counts mismatch")
    ctrl = model.ControlBlock(use=1, weak=1)
    if model.last_use_helper(ctrl) != ["dispose", "weak--", "destroy"]:
        fail("model last-use helper mismatch")
    vec = model.OptionsVector()
    vec.append("x" * 16, "p", 1)
    if not vec.records[0]["heap"]:
        fail("model SSO rule mismatch")
    wrapped = model.SharedPtr(object(), model.ControlBlock(use=1, weak=1))
    wrapper = model.Wrapper.ctor_c1(wrapped)
    if len(wrapper.options.records) != 1:
        fail("model wrapper ctor record mismatch")
    if "vector-destroy:1" not in wrapper.dtor_d2():
        fail("model wrapper D2 mismatch")
    reg = model.Registry()
    reg.register_builtin_system_clocks()
    reg.default_init()
    if sorted(reg.nodes) != ["CompositeEnv", "MockEnv",
                             "TimeEmulatedSystemClock"]:
        fail("model registry mismatch")
    print("records ok (census, relocations, reshipped, installers, "
          "thunks, manager ops, excerpts, model)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_systemclock_installers_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "ALL CHECKS PASSED (135 checks)" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (135 checks)")


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
