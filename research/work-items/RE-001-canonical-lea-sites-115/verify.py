"""Checker for the RE-001-canonical-lea-sites-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-canonical-lea-sites-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary
(three random ones among them: 0x5dc9f4b, 0x5e18da7,
0x5f8674c); the FDE ranges in frames.txt against a fresh frame
dump; the relocation set against a fresh relocation dump (30
records: the SystemClockWrapper vtable header + slots, the
FactoryEntry vtable headers, the GOT canonical slot); the
typeinfo-name literals against the raw binary; census
consistency (callers.tsv against a fresh census run: every
pinned routine's direct calls, tail jumps, lea references,
stored qwords and RELATIVE addends, and the callers.tsv caller
function against the smallest enclosing FDE range from a fresh
frame dump); the semantic records (re-deriving the census
entries, the GOT canonical records, the vtable slot tables,
the site walk depths and dispatch args, the installer forms
and the model behaviour); and the model tests in
tests/test_canonical_lea_sites_115.py.
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
    ("site_a.txt", 0x5DC9D70, 0x5DCA807),
    ("site_b.txt", 0x5E18D20, 0x5E19117),
    ("site_c.txt", 0x5F7D7D0, 0x5F7DE6E),
    ("site_d.txt", 0x5F865D0, 0x5F87065),
    ("canonical.txt", 0x5D4B100, 0x5D4B20C),
    ("resolver.txt", 0x5F074E0, 0x5F07603),
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
    0x5D4B100: (0, 0, 4),
    0x5F074E0: (1, 0, 0),
    0x5DC9D70: (2, 0, 0),
    0x5E18D20: (1, 0, 0),
    0x5F7D7D0: (1, 0, 0),
    0x5F865D0: (1, 0, 0),
    0x5FD0090: (1, 0, 0),
    0x6029110: (0, 0, 0),
    0x6029230: (1, 0, 0),
    0x6029500: (0, 0, 0),
    0x6029620: (0, 0, 0),
    0x5FCC5D0: (0, 0, 1),
    0x5FCC600: (0, 0, 1),
    0x5FCC630: (0, 0, 1),
}

# File offsets of 8-byte-aligned qwords equal to the target.
EXPECTED_QWORDS = {
    0x5D4B100: ["0x10f9f0", "0x15d270"],
    0x6029110: ["0x118e28"],
    0x6029620: ["0x118e40"],
}

# Number of RELATIVE records whose addend is the target.
EXPECTED_RELATIVE = {
    0x5D4B100: 2,
    0x6029110: 1,
    0x6029620: 1,
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
    (0x64ED3E8, 0x5D4B100),
]

SPOT_BYTES = {
    0x5DC9D70: "f30f1efa",
    0x5DC9E69: "488d059012f8ff",
    0x5DC9F66: "ff90c0000000",
    0x5DC9F4B: "488b7620",
    0x5E18D20: "f30f1efa",
    0x5E18DBB: "488d053e23f3ff",
    0x5E18DA7: "488bb040020000",
    0x5E18E7C: "ff90c0000000",
    0x5F7D7D0: "f30f1efa",
    0x5F7D83E: "488d05bbd8dcff",
    0x5F7D939: "ff90c0000000",
    0x5F865D0: "55",
    0x5F8666A: "488d058f4adcff",
    0x5F8674C: "488dbd00ffffff",
    0x5D4B100: "f30f1efa",
    0x5D4B1CB: "ff90c0000000",
    0x5F074E0: "f30f1efa",
    0x5FD0090: "f30f1efa",
    0x5FD00AF: "488d05c2dc4f00",
    0x6029110: "f30f1efa",
    0x6029114: "488d055d4c4a00",
    0x6029230: "f30f1efa",
    0x6029500: "f30f1efa",
    0x6029620: "f30f1efa",
    0x5FCC5D0: "f30f1efa",
    0x5FCC5F0: "488d05d9135000",
    0x5FCC600: "f30f1efa",
    0x5FCC630: "f30f1efa",
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
        if raw.hex() != expect:
            fail("spot %#x: %s != %s" % (addr, raw.hex(), expect))
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
    for key, lit in records["literals"].items():
        addr = int(lit["address"], 16)
        off = va_to_off(segments, addr)
        if off is None:
            fail("literal %s: no file offset" % lit["address"])
        if "bytes" in lit:
            want = bytes.fromhex(lit["bytes"])
        elif "text" in lit:
            want = lit["text"].encode() + b"\x00"
        elif "value" in lit:
            want = struct.pack("<Q", int(lit["value"], 16))
        else:
            fail("literal %s has no bytes/text/value" % key)
        if data[off:off + len(want)] != want:
            fail("literal %s mismatch at %s" % (key, lit["address"]))
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

    for key, entry in records["census"].items():
        if not isinstance(entry, dict) or "calls" not in entry:
            continue
        m = re.search("0x([0-9a-f]+)$", key)
        if not m:
            fail("records census key has no address: %s" % key)
        target = int(m.group(1), 16)
        want_calls = EXPECTED_CENSUS[target][0]
        if entry["calls"] != want_calls:
            fail("records census calls for %#x: %d != %d"
                 % (target, entry["calls"], want_calls))
        if "callsites" in entry:
            if len(entry["callsites"]) != want_calls:
                fail("records callsites for %#x: %d != %d"
                     % (target, len(entry["callsites"]), want_calls))
    if records["census"]["relocation_records_total"] != 30:
        fail("records relocation total != 30")
    if records["census"]["callers_tsv_rows"] != 15:
        fail("records callers.tsv row count != 15")
    if records["census"]["test_checks"] != 172:
        fail("records test_checks != 172")

    # The canonical's GOT records: the stored slot and the
    # wrapper vtable slot re-derive from a fresh readelf dump.
    got = records["got_canonical"]
    if full_relocs.get(int(got["slot"], 16)) != 0x5D4B100:
        fail("GOT canonical slot not in a fresh dump")
    if full_relocs.get(int(got["second_slot"], 16)) != 0x5D4B100:
        fail("second canonical slot not in a fresh dump")
    canon = records["census"]["canonical_0x5d4b100"]
    if sorted(int(x, 16) for x in canon["relative_sites"]) != \
            sorted([int(got["slot"], 16), int(got["second_slot"], 16)]):
        fail("canonical relative sites mismatch")
    if [int(x, 16) for x in canon["qword_file_offsets"]] != \
            census_mod.qwords(data, 0x5D4B100):
        fail("canonical qword file offsets mismatch")
    if sorted(int(x, 16) for x in canon["lea_sites"]) != \
            [0x5DC9E69, 0x5E18DBB, 0x5F7D83E, 0x5F8666A]:
        fail("canonical lea sites mismatch")

    # The wrapper vtable slot table re-derives from the
    # fresh relocation dump.
    wrapper = records["wrapper_vtable"]
    for i, slot in enumerate(wrapper["slots"]):
        addr = int(wrapper["address"], 16) + i * 8
        want = None if slot is None else int(slot, 16)
        got_rel = full_relocs.get(addr)
        if got_rel != want:
            fail("wrapper slot %d: %#x != %s" % (i, got_rel or 0, want))
    if wrapper["slots"][24] != "0x5d4b100":
        fail("wrapper slot 24 is not the canonical")
    if full_relocs.get(int(wrapper["header_address"], 16) + 8) != \
            int(wrapper["typeinfo"], 16):
        fail("wrapper typeinfo pointer not in a fresh dump")

    # The emulated vtable slot table re-derives the same way.
    emulated = records["emulated_vtable"]
    for i, slot in enumerate(emulated["slots"]):
        addr = int(emulated["address"], 16) + i * 8
        if full_relocs.get(addr) != int(slot, 16):
            fail("emulated slot %d mismatch" % i)
    if emulated["slots"][24] != "0x6025eb0":
        fail("emulated slot 24 is not 0x6025eb0")

    site_a = (PACKET / "site_a.txt").read_text()
    site_b = (PACKET / "site_b.txt").read_text()
    site_c = (PACKET / "site_c.txt").read_text()
    site_d = (PACKET / "site_d.txt").read_text()
    canonical = (PACKET / "canonical.txt").read_text()
    resolver = (PACKET / "resolver.txt").read_text()

    # Each site: the lea, the unrolled comparisons, the
    # terminal unconditional slot-24 call and the mismatch
    # slot-24 call.
    for name, text, lea in (
            ("site_a", site_a, "5dc9e69"),
            ("site_b", site_b, "5e18dbb"),
            ("site_c", site_c, "5f7d83e"),
            ("site_d", site_d, "5f8666a")):
        if "lea" not in text or "5d4b100" not in text:
            fail("%s must lea the canonical" % name)
        if "call   *0xc0(%rax)" not in text:
            fail("%s must call slot 0xc0 on the terminal node" % name)
        if "call   *%rcx" not in text:
            fail("%s must call the mismatching slot 0xc0" % name)
        if text.count("mov    0xc0(%") < 2:
            fail("%s must compare slot 0xc0 more than once" % name)
    # Walk depths: count the slot-24 comparisons (cmp %rax,%rcx
    # after a 0xc0 load) in each site.
    for name, text, want in (
            ("site_a", site_a, 11), ("site_b", site_b, 9),
            ("site_c", site_c, 11), ("site_d", site_d, 11)):
        count = text.count("cmp    %rax,%rcx")
        if count != want:
            fail("%s compared levels %d != %d" % (name, count, want))
    # The canonical: the advance, the GOT comparison, the
    # unconditional ninth-level call.
    for needle in ("mov    0x20(%rsi),%rsi",
                   "call   *0xc0(%rax)"):
        if needle not in canonical:
            fail("canonical line missing: %s" % needle)
    if canonical.count("mov    0x20(%rsi),%rsi") != 9:
        fail("canonical must advance the chain 9 times")
    # The resolver: the sentinel test and the slot call.
    for needle in ("mov    0xcb8(%rdi),%rax",
                   "cmp    $0xffffffffffffffff,%rax",
                   "call   *0xc0(%rax)"):
        if needle not in resolver:
            fail("resolver line missing: %s" % needle)
    if resolver.count("call   *0xc0(%rax)") != 1:
        fail("resolver must call slot 0xc0 exactly once directly")

    # The re-shipped excerpts match #3322 byte-for-byte.
    if hashlib.sha256(canonical.encode()).hexdigest() != \
            records["canonical_0x5d4b100"]["excerpt_sha256"]:
        fail("canonical excerpt hash mismatch")
    if hashlib.sha256(resolver.encode()).hexdigest() != \
            records["resolver_0x5f074e0"]["excerpt_sha256"]:
        fail("resolver excerpt hash mismatch")

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

    # The site records rebuild from the model.
    sys.path.insert(0, str(ROOT / "tools"))
    import canonical_lea_sites_115 as model
    if model.CANONICAL != 0x5D4B100:
        fail("model canonical mismatch")
    if model.WRAPPER_SLOTS[24] != 0x5D4B100:
        fail("model wrapper slot 24 mismatch")
    if model.EMULATED_SLOTS[24] != 0x6025EB0:
        fail("model emulated slot 24 mismatch")
    if model.SITE_DEPTHS != {"A": (11, 12), "B": (9, 10),
                             "C": (11, 12), "D": (11, 12)}:
        fail("model site depths mismatch")
    if model.SCALE != 0x431BDE82D7B634DB:
        fail("model scale constant mismatch")
    if model.scaled_add(2 ** 40) != 1099511:
        fail("model scaled add mismatch")

    def stub(value):
        def run(chain, node_id, out, val, invoked):
            invoked.append(node_id)
            out["code"] = value
            val["value"] = value * 100
            return out
        return run

    chain = {i: {"slot24": None, "next": i + 1 if i < 11 else None,
                 "flag48": False, "v30": 0, "v40": 0}
             for i in range(12)}
    chain[11] = {"slot24": stub(7), "next": None,
                 "flag48": False, "v30": 0, "v40": 0}
    how, node, invoked, out, value = model.walk_dispatch(chain, 0, "A")
    if (how, node, invoked, value["value"]) != ("terminal", 11, [11], 700):
        fail("model site A dispatch mismatch")
    chain = {i: {"slot24": None, "next": i + 1 if i < 10 else None,
                 "flag48": False, "v30": 0, "v40": 0}
             for i in range(10)}
    chain[9] = {"slot24": model.emulated_slot24, "next": None,
                "flag48": True, "v30": 50, "v40": 2 ** 40}
    how, node, invoked, out, value = model.walk_dispatch(chain, 0, "B")
    if value["value"] != 50 + 1099511:
        fail("model site B emulated dispatch mismatch")
    if records["sites"]["A"]["compared_levels"] != 11:
        fail("records site A depth mismatch")
    if records["sites"]["B"]["compared_levels"] != 9:
        fail("records site B depth mismatch")
    if records["sites"]["C"]["compared_levels"] != 11:
        fail("records site C depth mismatch")
    if records["sites"]["D"]["compared_levels"] != 11:
        fail("records site D depth mismatch")
    if records["canonical_0x5d4b100"]["compared_levels"] != 8:
        fail("canonical compared levels record mismatch")
    if records["canonical_0x5d4b100"]["unconditional_level"] != 9:
        fail("canonical unconditional level record mismatch")
    print("records ok (census, got, vtables, sites, canonical, "
          "resolver, installers, model)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_canonical_lea_sites_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "172 checks, 0 failed" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (172 checks)")


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
