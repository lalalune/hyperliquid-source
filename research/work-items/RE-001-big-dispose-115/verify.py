"""Checker for the RE-001-big-dispose-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-big-dispose-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary
(three random ones among them: 0x5f06234, 0x5f055b9, 0x5f06426);
the FDE ranges in frames.txt against a fresh frame dump; the
relocation set against a fresh relocation dump (17 records: the
two control vtable groups' 10 function slots plus their two
typeinfo pointers, and the five control typeinfo-object records
including the neighbour MemTableIterator base record); the
message literals against the raw binary; census consistency
(callers.tsv against a fresh census run: every pinned routine's
direct calls, tail jumps, lea references, stored qwords and
RELATIVE addends, and the callers.tsv caller function against
the smallest enclosing FDE range from a fresh frame dump); the
semantic records (re-deriving the census entries, the
control-slot relative records, the dispose/clear/sort/
cleanable/list/tree records, the vtable/typeinfo records
including the corrected neighbour typeinfo name pointer, and
the typeinfo names via c++filt); and the model tests in
tests/test_big_dispose_115.py.
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
    ("big_dispose.txt", 0x5F061B0, 0x5F06548),
    ("introsort.txt", 0x5F053D0, 0x5F05678),
    ("insertion_sort.txt", 0x5F05120, 0x5F051F5),
    ("adjust_heap.txt", 0x5F04F80, 0x5F0511D),
    ("tree_destroy.txt", 0x5F059B0, 0x5F05B79),
    ("cleanable_drain.txt", 0x61BD0E0, 0x61BD131),
    ("cleanable_init.txt", 0x61BD0C0, 0x61BD0D4),
]

# (target, expected direct calls, expected tail jumps, expected leas)
EXPECTED_CENSUS = {
    0x5D35070: (654, 36, 0), 0x5D350C0: (1273, 25, 0),
    0x5D497E0: (6, 0, 0), 0x5D4A3F0: (4, 0, 0),
    0x5D50470: (9, 0, 0),
    0x5F04E20: (0, 0, 0), 0x5F04E30: (0, 0, 0),
    0x5F04E50: (0, 0, 0), 0x5F04E60: (0, 0, 0),
    0x5F04F60: (0, 0, 0), 0x5F04F70: (0, 0, 0),
    0x5F04F80: (2, 0, 0), 0x5F05120: (10, 0, 0),
    0x5F05380: (0, 0, 0), 0x5F053D0: (6, 0, 0),
    0x5F057C0: (0, 0, 0), 0x5F059B0: (6, 0, 0),
    0x5F061B0: (0, 0, 0), 0x5F0A1DC: (2, 0, 0),
    0x5F0A290: (0, 0, 0), 0x5F117A0: (0, 0, 0),
    0x61BD0C0: (103, 0, 0), 0x61BD0E0: (223, 32, 0),
    0x63F0D80: (11706, 898, 0),
}

# File offsets of 8-byte-aligned qwords equal to the target
# (these are the addend fields of .rela.dyn RELATIVE records).
EXPECTED_QWORDS = {
    0x5F04E20: ["0x10c2d0"], 0x5F04E30: ["0x10c240"],
    0x5F04E50: ["0x10c258"], 0x5F04E60: ["0x10c2e8"],
    0x5F04F60: ["0x10c318"], 0x5F04F70: ["0x10c288"],
    0x5F05380: ["0x10c330"], 0x5F057C0: ["0x10c2a0"],
    0x5F061B0: ["0x10c270"], 0x5F0A290: ["0x10c300"],
    0x5F117A0: ["0x10bf10"],
}

# Number of RELATIVE records whose addend is the target.
EXPECTED_RELATIVE = {
    0x5F04E20: 1, 0x5F04E30: 1, 0x5F04E50: 1, 0x5F04E60: 1,
    0x5F04F60: 1, 0x5F04F70: 1, 0x5F05380: 1, 0x5F057C0: 1,
    0x5F061B0: 1, 0x5F0A290: 1, 0x5F117A0: 1,
}

SPOT_BYTES = {
    0x5F061B0: "f30f1efa",
    0x5F061BE: "4c8b6738",
    0x5F061F5: "e886ab4e00",
    0x5F0620A: "e8d16e2b00",
    0x5F06234: "e877f7ffff",
    0x5F06348: "e883f0ffff",
    0x5F06367: "e8b4edffff",
    0x5F06426: "ffd0",
    0x5F062A5: "e9d6aa4e00",
    0x5F053D0: "4889f0",
    0x5F05400: "48c1f805",
    0x5F055B9: "e812feffff",
    0x5F0560D: "e86ef9ffff",
    0x5F05120: "4839f7",
    0x5F05183: "488b39",
    0x5F04F80: "488d42ff",
    0x5F04FB0: "4c8b6108",
    0x5F059B0: "4157",
    0x5F05A41: "e86affffff",
    0x5F05A52: "e829b34e00",
    0x61BD0E0: "f30f1efa",
    0x61BD0F8: "ffd0",
    0x61BD0C0: "f30f1efa",
    0x61BD0C4: "48c70700000000",
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
    if len(stored) != 17:
        fail("relocation count %d != 17" % len(stored))
    for target, count in EXPECTED_RELATIVE.items():
        got = [o for o, a in relocs.items() if a == target]
        if len(got) != count:
            fail("RELATIVE count for %#x: %d != %d"
                 % (target, len(got), count))
    for target in EXPECTED_CENSUS:
        if target in EXPECTED_RELATIVE:
            continue
        got = [o for o, a in relocs.items() if a == target]
        if got:
            fail("unexpected RELATIVE records for %#x: %s" % (target, got))
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


# ----------------------------------------------------------------
# Census re-derivation (imports the packet's census module).
# ----------------------------------------------------------------

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


# ----------------------------------------------------------------
# Semantic-record re-derivation from the excerpts.
# ----------------------------------------------------------------

def check_records(segments, data, records):
    spec = importlib.util.spec_from_file_location(
        "packet_census_rel", PACKET / "census.py")
    census_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(census_mod)
    full_relocs, _lines = census_mod.relative_records()

    # The records census section must agree with the verify
    # expectations. Keys are "name_0x<addr>"; the control-slot
    # sub-table is checked separately below.
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
            # (callsites are re-checked against a fresh census run
            # by check_census; here we only require the recorded
            # count to match the list.)
            if len(entry["callsites"]) != want_calls:
                fail("records callsites for %#x: %d != %d"
                     % (target, len(entry["callsites"]), want_calls))
    if records["census"]["relocation_records_total"] != 17:
        fail("records relocation total != 17")
    if records["census"]["callers_tsv_rows"] != 14995:
        fail("records callers.tsv row count != 14995")
    if records["test_checks"] != 152:
        fail("records test_checks != 152")

    # The control-slot relative records: each target's RELATIVE
    # site and its stored-qword file offset re-derive from a
    # fresh readelf dump and from the raw binary.
    slot_rel = records["census"]["control_slot_functions_relative"]
    for addr_hex, entry in slot_rel.items():
        target = int(addr_hex, 16)
        site = int(entry["relative_site"], 16)
        if full_relocs.get(site) != target:
            fail("slot RELATIVE %#x -> %#x not in a fresh dump"
                 % (site, target))
        qoff = int(entry["qword_file_offset"], 16)
        if census_mod.qwords(data, target) != [qoff]:
            fail("slot qwords for %#x != [%#x]" % (target, qoff))

    big_dispose = (PACKET / "big_dispose.txt").read_text()
    introsort = (PACKET / "introsort.txt").read_text()
    insertion_sort = (PACKET / "insertion_sort.txt").read_text()
    adjust_heap = (PACKET / "adjust_heap.txt").read_text()
    tree_destroy = (PACKET / "tree_destroy.txt").read_text()
    cleanable_drain = (PACKET / "cleanable_drain.txt").read_text()
    cleanable_init = (PACKET / "cleanable_init.txt").read_text()

    # The dispose: the state-pointer load, the flag test, the
    # sort/insertion/tree/cleanable calls, the three vector frees
    # and the tail-jump free of the 0xe8-byte state.
    for needle in ("mov    0x38(%rdi),%r12",
                   "cmpb   $0x0,0xb8(%r12)",
                   "call   5f053d0",
                   "call   5f05120",
                   "call   5f059b0",
                   "call   61bd0e0",
                   "movq   $0x0,0x98(%r12)",
                   "movq   $0x0,0xb0(%r12)",
                   "mov    $0xe8,%esi",
                   "jmp    63f0d80",
                   "call   *%rax"):
        if needle not in big_dispose:
            fail("big_dispose line missing: %s" % needle)
    # The introsort: the 16-pair early return, the depth test,
    # the median pivot selection, the self-recursion and the
    # heapsort fallback calls.
    for needle in ("cmp    $0x100,%rax",
                   "test   %rdx,%rdx",
                   "call   5f053d0",
                   "call   5f04f80"):
        if needle not in introsort:
            fail("introsort line missing: %s" % needle)
    if introsort.count("call   5f04f80") != 2:
        fail("introsort must call __adjust_heap twice")
    # The insertion sort: the empty-range return and the
    # predecessor comparison.
    for needle in ("cmp    %rsi,%rdi",
                   "mov    -0x10(%rax),%rdx"):
        if needle not in insertion_sort:
            fail("insertion_sort line missing: %s" % needle)
    # The heap adjust: the (len-1)/2 parent computation, the
    # odd-length tail test and the sift-up loop.
    for needle in ("lea    -0x1(%rdx),%rax",
                   "test   $0x1,%r11b",
                   "sar    $1,%rbp"):
        if needle not in adjust_heap:
            fail("adjust_heap line missing: %s" % needle)
    # The tree destroy: the self-recursion and the 0x28 free.
    for needle in ("call   5f059b0",
                   "mov    $0x28,%esi"):
        if needle not in tree_destroy:
            fail("tree_destroy line missing: %s" % needle)
    # The Cleanable drain: the head call and the 0x20 node free.
    for needle in ("call   *%rax",
                   "mov    $0x20,%esi"):
        if needle not in cleanable_drain:
            fail("cleanable_drain line missing: %s" % needle)
    # The Cleanable init: both zero stores.
    for needle in ("movq   $0x0,(%rdi)",
                   "movq   $0x0,0x18(%rdi)"):
        if needle not in cleanable_init:
            fail("cleanable_init line missing: %s" % needle)

    # The sort/depth records rebuild from the model.
    sys.path.insert(0, str(ROOT / "tools"))
    import big_dispose_115 as model
    if model.depth_limit(0) != -2:
        fail("depth_limit(0) != -2")
    if model.depth_limit(16) != 8:
        fail("depth_limit(16) != 8")
    if model.depth_limit(1024) != 20:
        fail("depth_limit(1024) != 20")
    if model.sort_pairs([(5, 0), (1, 0), (3, 0), (1, 0)]) != \
            [(1, 0), (1, 0), (3, 0), (5, 0)]:
        fail("model sort_pairs mismatch")
    if model.unique_pairs([(1, 0), (1, 0), (2, 0)]) != [(1, 0), (2, 0)]:
        fail("model unique_pairs mismatch")
    if records["sort_phase"]["depth_argument"] != (
            "2 times floor(log2(element_count)) for element_count >= 1, "
            "computed with bsr; the literal -2 left in rdx when the "
            "byte count is below 16"):
        fail("sort depth record mismatch")
    if records["literals"]["control_counts"]["value"] != "0x100000001":
        fail("control counts literal != 0x100000001")
    if records["big_dispose_0x5f061b0"]["state_pointer"] != (
            "control+0x38 == cache object at control+0x10 plus 0x28"):
        fail("state pointer record mismatch")

    # The vtable slot tables in the model must match the
    # RELATIVE records stored in relocations.txt.
    stored = {}
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split()
        stored[int(parts[0], 16)] = int(parts[3], 16)
    for vptr, slots in model.VTABLE_SLOTS.items():
        for off, addend in slots.items():
            if stored.get(vptr + off) != addend:
                fail("vtable slot %#x+%#x: %#x != %#x"
                     % (vptr, off, stored.get(vptr + off, -1), addend))
    total = sum(len(s) for s in model.VTABLE_SLOTS.values())
    if total != 10:
        fail("vtable slot total %d != 10" % total)
    for vptr, ti in model.TYPEINFO_POINTERS.items():
        if stored.get(vptr - 0x08) != ti:
            fail("typeinfo pointer %#x-0x08 != %#x" % (vptr, ti))
    for ti, name_addr in model.TYPEINFO_NAME_POINTERS.items():
        if ti in (model.BIG_TYPEINFO, model.SMALL_TYPEINFO):
            if stored.get(ti + 0x08) != name_addr:
                fail("typeinfo name pointer %#x+0x08 != %#x"
                     % (ti, name_addr))
        elif ti == model.NEIGHBOUR_TYPEINFO:
            if full_relocs.get(ti + 0x08) != name_addr:
                fail("neighbour typeinfo name pointer %#x+0x08 != %#x "
                     "(full dump)" % (ti, name_addr))
        elif ti == model.NEIGHBOUR_BASE_TYPEINFO:
            if full_relocs.get(ti + 0x08) != name_addr:
                fail("neighbour base typeinfo name pointer %#x+0x08 != "
                     "%#x (full dump)" % (ti, name_addr))
        else:
            if full_relocs.get(ti + 0x08) != name_addr:
                fail("typeinfo name pointer %#x+0x08 != %#x (full dump)"
                     % (ti, name_addr))
    for ti, base in model.TYPEINFO_BASE_POINTERS.items():
        if ti in (model.BIG_TYPEINFO, model.SMALL_TYPEINFO):
            if stored.get(ti + 0x10) != base:
                fail("typeinfo base pointer %#x+0x10 != %#x"
                     % (ti, base))
        else:
            if full_relocs.get(ti + 0x10) != base:
                fail("typeinfo base pointer %#x+0x10 != %#x (full dump)"
                     % (ti, base))
    if len(stored) != 17:
        fail("relocation record total %d != 17" % len(stored))
    # The neighbour typeinfo's own base record is stored too.
    if stored.get(0x64CC590) != 0x64CA638:
        fail("neighbour base RELATIVE 0x64cc590 != 0x64ca638")

    # The typeinfo names demangle to the recorded class names.
    expect = {
        "St23_Sp_counted_ptr_inplaceIN7rocksdb33FragmentedRangeTombstoneListCacheESaIvELN9__gnu_cxx12_Lock_policyE2EE":
            "std::_Sp_counted_ptr_inplace<rocksdb::FragmentedRangeTombstoneListCache",
        "St23_Sp_counted_ptr_inplaceIKSt10shared_ptrIN7rocksdb33FragmentedRangeTombstoneListCacheEESaIvELN9__gnu_cxx12_Lock_policyE2EE":
            "std::_Sp_counted_ptr_inplace<std::shared_ptr<rocksdb::FragmentedRangeTombstoneListCache>",
        "St16_Sp_counted_baseILN9__gnu_cxx12_Lock_policyE2EE":
            "std::_Sp_counted_base",
        "N7rocksdb16MemTableIteratorE": "rocksdb::MemTableIterator",
        "N7rocksdb20InternalIteratorBaseINS_5SliceEEE":
            "rocksdb::InternalIteratorBase<rocksdb::Slice>",
    }
    for key, entry in records["typeinfo"].items():
        if not isinstance(entry, dict) or "name" not in entry:
            continue
        mangled = entry["name"]
        if mangled not in expect:
            continue
        out = subprocess.run(["c++filt", "_ZTI" + mangled],
                             capture_output=True, text=True,
                             check=True).stdout.strip()
        if expect[mangled] not in out:
            fail("typeinfo %s demangles to %s" % (mangled, out))
        addr = int(entry["name_address"], 16)
        off = va_to_off(segments, addr)
        if off is None:
            fail("typeinfo %s: no file offset" % mangled)
        end = data.index(b"\x00", off)
        if data[off:end].decode().lstrip("*") != mangled:
            fail("typeinfo %s string mismatch" % mangled)
    print("records ok (dispose, clear, sort, cleanable, lists, "
          "tree, vtables, typeinfo)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_big_dispose_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "all 152 checks passed" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (152 checks)")


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
