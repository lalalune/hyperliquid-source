"""Checker for the RE-001-skiplist-rep-factory-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-skiplist-rep-factory-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; the re-shipped
holder ctor excerpt against its pinned SHA-256 value; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary
(three random ones among them: 0x60636d1, 0x605e0f4, 0x5f104e9);
the FDE ranges in frames.txt against a fresh frame dump; the
relocation set against a fresh relocation dump (89 records: the
five vtable groups' 70 function slots plus the five typeinfo
pointers, the five typeinfo name pointers and the four base
pointers, the canonical GOT entry, and the eight qword-file
offsets of the RELATIVE addends); the message literals against
the raw binary; census consistency (callers.tsv against a fresh
census run: every pinned routine's direct calls, tail jumps,
lea references, stored qwords and RELATIVE addends, and the
callers.tsv caller function against the smallest enclosing
FDE range from a fresh frame dump); the semantic records
(re-deriving the factory product fields, the arena init and
sub-init fields, the owner dispatch gate, the holder teardown,
the vtable slot tables against relocations.txt, and the
typeinfo names via c++filt); and the model tests in
tests/test_skiplist_rep_factory_115.py.
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
    ("factory.txt", 0x6063640, 0x6063752),
    ("holder_ctor.txt", 0x6064440, 0x6064551),
    ("arena_init.txt", 0x605E010, 0x605E163),
    ("arena_subinit.txt", 0x605DD90, 0x605DFCD),
    ("small_init.txt", 0x605E810, 0x605E826),
    ("huge_align.txt", 0x605CFA0, 0x605CFD6),
    ("arena_stat.txt", 0x5F04DA0, 0x5F04DAC),
    ("fwd_slot20.txt", 0x5F04D90, 0x5F04D9D),
    ("fwd_rep_slot19.txt", 0x5F04D80, 0x5F04D8D),
    ("noop_rep_slot10.txt", 0x5F04D50, 0x5F04D55),
    ("noop_rep_slot11.txt", 0x5F04D60, 0x5F04D65),
    ("owner_window.txt", 0x5F104CD, 0x5F105A0),
    ("owner_noncanon.txt", 0x5F10C40, 0x5F10C53),
]

# Re-shipped byte-identical from the holder packet (#3272).
RESHIPPED_SHA = {
    "holder_ctor.txt": "e0440004638724fd7926244cf19f96f7b14ce424464fdd1ce7afb7a02ebdbd8f",
}

# (target, expected direct calls, expected tail jumps, expected leas)
EXPECTED_CENSUS = {
    0x5F04D50: (0, 0, 0), 0x5F04D60: (0, 0, 0),
    0x5F04D80: (0, 0, 0), 0x5F04D90: (0, 0, 0),
    0x5F04DA0: (0, 0, 0), 0x5F10180: (1, 0, 0),
    0x5F103F0: (2, 0, 0), 0x5F10D00: (0, 0, 0),
    0x5F117A0: (0, 0, 0), 0x5F11C40: (0, 0, 0),
    0x605CC30: (37, 2, 0), 0x605CFA0: (2, 0, 0),
    0x605D7B0: (8, 0, 0), 0x605DD90: (19, 0, 0),
    0x605E010: (1, 0, 0), 0x605E170: (2, 0, 0),
    0x605E810: (1, 0, 0), 0x6063640: (1, 0, 0),
    0x6064440: (5, 0, 0),
    0x63F0A50: (61130, 0, 0), 0x63F0A60: (1530, 1, 0),
    0x63F0A80: (287, 0, 0), 0x63F0AA0: (652, 0, 0),
    0x63F0B20: (11, 0, 0), 0x63F0D70: (6391, 0, 0),
    0x63F0D80: (11706, 898, 0), 0x63F0DB0: (5778, 2, 0),
    0x63F0DC0: (6140, 65, 0), 0x63F0DD0: (1935, 0, 0),
    0x63F0DE0: (1380, 0, 0), 0x63F0E10: (1069, 0, 0),
    0x63F0E30: (201, 0, 0), 0x63F0F00: (442, 2, 0),
    0x63F0F90: (277, 0, 0), 0x63F0FA0: (38, 0, 0),
    0x63F1040: (100, 0, 0), 0x63F13A0: (4, 0, 0),
    0x63F13B0: (2, 0, 0),
}

# File offsets of .rela.dyn RELATIVE addends naming the target
# (these are file offsets, not stored data qwords).
EXPECTED_QWORDS = {
    0x5F04D50: ["0x11ac40", "0x11b3c0", "0x11bb40", "0x15dbd0"],
    0x5F04D60: ["0x11ac58", "0x11b3d8", "0x11bb58", "0x11c098",
                "0x15dbe8"],
    0x5F04D80: ["0x11bc18", "0x11c158", "0x15dc00"],
    0x5F04D90: ["0x11af70", "0x11b6f0", "0x11be70", "0x11c4d0",
                "0x15dc18"],
    0x5F04DA0: ["0x10bf28"],
    0x5F10180: ["0x10bec8"],
    0x5F10D00: ["0x10bee0"],
    0x5F117A0: ["0x10bf10"],
    0x5F11C40: ["0x10bef8"],
    0x605CC30: ["0x11a730"],
    0x605D7B0: ["0x11a778"],
    0x6063640: ["0x11be58"],
}

# Number of RELATIVE records whose addend is the target.
EXPECTED_RELATIVE = {
    0x5F04D50: 4, 0x5F04D60: 5, 0x5F04D80: 3, 0x5F04D90: 5,
    0x5F04DA0: 1, 0x5F10180: 1, 0x5F10D00: 1, 0x5F117A0: 1,
    0x5F11C40: 1, 0x605CC30: 1, 0x605D7B0: 1, 0x6063640: 1,
}

SPOT_BYTES = {
    0x6063640: "f30f1efa",
    0x6063687: "48b80c00040000000020",
    0x60636D1: "ff5018",
    0x605E010: "f30f1efa",
    0x605E0F4: "e897fcffff",
    0x605DD90: "f30f1efa",
    0x605DDB8: "e8e3f1ffff",
    0x605DF33: "4c89a3d8080000",
    0x5F104CD: "498bbda8020000",
    0x5F104E9: "4c3b1590d25d00",
    0x5F10517: "e8243f1500",
    0x5F10530: "e80b311500",
    0x605CFA0: "f30f1efa",
    0x5F04D90: "f30f1efa",
    0x5F04DA0: "f30f1efa",
    0x605E810: "f30f1efa",
    0x5F04D80: "f30f1efa",
    0x5F04D50: "f30f1efa",
    0x5F10C40: "488b542420",
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


def check_reshipped():
    for name, want in RESHIPPED_SHA.items():
        got = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if got != want:
            fail("re-shipped %s changed: %s != %s" % (name, got, want))
    print("re-shipped excerpts ok (%d)" % len(RESHIPPED_SHA))


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
    if len(stored) != 89:
        fail("relocation count %d != 89" % len(stored))
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
    for lit in records["literals"]:
        addr = int(lit["address"], 16)
        off = va_to_off(segments, addr)
        if off is None:
            fail("literal %s: no file offset" % lit["address"])
        if "bytes" in lit:
            want = bytes.fromhex(lit["bytes"])
            if data[off:off + len(want)] != want:
                fail("literal bytes mismatch at %s" % lit["address"])
        else:
            want = lit["text"].encode() + b"\x00"
            if data[off:off + len(want)] != want:
                fail("literal text mismatch at %s" % lit["address"])
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
    # The records census section must agree with the verify
    # expectations, including the stored-qword file offsets and
    # the RELATIVE record offsets.
    # The "relative" field lists every RELATIVE record in the
    # whole binary whose addend is the target (re-derived from a
    # fresh readelf dump, not from the filtered 89-record
    # relocations.txt, which only covers the vtable groups).
    spec = importlib.util.spec_from_file_location(
        "packet_census_rel", PACKET / "census.py")
    census_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(census_mod)
    full_relocs, _lines = census_mod.relative_records()
    for addr_hex, entry in records["census"].items():
        target = int(addr_hex, 16)
        want_calls, want_jumps, want_leas = EXPECTED_CENSUS[target]
        if (entry["calls"], entry["jumps"], entry["leas"]) != (
                want_calls, want_jumps, want_leas):
            fail("records census for %#x disagrees with verify" % target)
        want_qw = EXPECTED_QWORDS.get(target, [])
        if entry["qwords"] != want_qw:
            fail("records qwords for %#x: %s != %s"
                 % (target, entry["qwords"], want_qw))
        want_rel = ["%#x" % o for o in sorted(
            o for o, a in full_relocs.items() if a == target)]
        if entry["relative"] != want_rel:
            fail("records RELATIVE for %#x: %s != %s"
                 % (target, entry["relative"], want_rel))

    factory = (PACKET / "factory.txt").read_text()
    arena_init = (PACKET / "arena_init.txt").read_text()
    arena_sub = (PACKET / "arena_subinit.txt").read_text()
    owner = (PACKET / "owner_window.txt").read_text()
    noncanon = (PACKET / "owner_noncanon.txt").read_text()
    huge = (PACKET / "huge_align.txt").read_text()
    small = (PACKET / "small_init.txt").read_text()
    fwd20 = (PACKET / "fwd_slot20.txt").read_text()
    fwdrep = (PACKET / "fwd_rep_slot19.txt").read_text()
    stat = (PACKET / "arena_stat.txt").read_text()

    # The factory: 0x58-byte product, the 0x200000000004000c
    # qword, the two slot-3 calls, the 12-write-then-zero loop,
    # the 0xe8 second size, the alloc2 self-links.
    for needle in ("mov    $0x58,%edi",
                   "movabs $0x200000000004000c,%rax",
                   "movl   $0xc,0x58(%rax)",
                   "call   *0x18(%rax)",
                   "movl   $0x1,0x30(%rbx)",
                   "movups %xmm0,0x8(%rax)",
                   "movq   $0x0,(%rdx,%rcx,8)",
                   "call   63f0dd0"):
        if needle not in factory:
            fail("factory line missing: %s" % needle)
    # The arena init: the 0x100000 cap, the 0x20000 cap value,
    # the hardware_concurrency call, the shard zeroing, the
    # sub-init call, the stat shadow copies and the lock byte.
    for needle in ("cmp    $0x100000,%rsi",
                   "mov    $0x20000,%edx",
                   "call   63f13a0",
                   "movb   $0x0,0x28(%rdx)",
                   "call   605dd90",
                   "mov    0x930(%rbx),%rax",
                   "mov    0x940(%rbx),%rax",
                   "mov    0x918(%rbx),%rax",
                   "movb   $0x0,0x950(%rbx)",
                   "call   63f0dc0"):
        if needle not in arena_init:
            fail("arena_init line missing: %s" % needle)
    # The sub-init: the huge-align call, the two block pairs,
    # the 0x800 stat values, the rounding store, the register call.
    for needle in ("call   605cfa0",
                   "movq   $0x8,0x820(%rbx)",
                   "movq   $0x8,0x870(%rbx)",
                   "movq   $0x800,0x8d0(%rbx)",
                   "movq   $0x800,0x8e0(%rbx)",
                   "mov    %r12,0x8d8(%rbx)",
                   "call   605e830",
                   "movups %xmm1,0x828(%rbx)"):
        if needle not in arena_sub:
            fail("arena_subinit line missing: %s" % needle)
    # The owner window: the factory pointer, the GOT gate, the
    # virtual slot-19 call, the +0xa50 store, the holder ctor,
    # the direct factory call, the +0xa58 store, the teardown
    # frees.
    for needle in ("mov    0x2a8(%r13),%rdi",
                   "# 64ed780",
                   "call   *0x98(%rax)",
                   "mov    %rax,0xa50(%rbx)",
                   "call   6064440",
                   "call   6063640",
                   "mov    %rax,0xa58(%rbx)",
                   "call   63f0d80"):
        if needle not in owner:
            fail("owner_window line missing: %s" % needle)
    # The non-canonical branch: the extra r9 argument, the
    # slot-20 call itself, the jump back to the +0xa50 store.
    for needle in ("mov    %r15d,%r9d",
                   "call   *%r10",
                   "jmp    5f10502"):
        if needle not in noncanon:
            fail("owner_noncanon line missing: %s" % needle)
    # The huge-align helper: the 0x1000 bounds and the 16-byte
    # rounding.
    for needle in ("mov    $0x1000,%eax",
                   "cmp    $0x1000,%rdi",
                   "add    $0x7ffff000,%rax",
                   "test   $0xf,%dil",
                   "lea    0x10(%rdi),%rax"):
        if needle not in huge:
            fail("huge_align line missing: %s" % needle)
    # The small init: {ptr, 0, u16 0}.
    for needle in ("mov    %rsi,(%rdi)",
                   "movq   $0x0,0x8(%rdi)",
                   "mov    %ax,0x10(%rdi)"):
        if needle not in small:
            fail("small_init line missing: %s" % needle)
    # The forwarders and the stat getter.
    if "jmp    *0x98(%rax)" not in fwd20:
        fail("fwd_slot20 line missing: jmp *0x98(%rax)")
    if "jmp    *0x90(%rax)" not in fwdrep:
        fail("fwd_rep_slot19 line missing: jmp *0x90(%rax)")
    if "mov    0x870(%rdi),%rax" not in stat:
        fail("arena_stat line missing: mov 0x870(%rdi),%rax")

    # The record key rebuilds from its constant chunk.
    if records["holder"]["record"]["key"] != "SkipListFactoryOptions":
        fail("holder record key mismatch")
    # The product qword rebuilds from the model's constant.
    if records["factory"]["fields"]["+0x10"] != (
            "qword 0x200000000004000c: u16 count 12, u16 4, "
            "u32 0x20000000"):
        fail("factory +0x10 field record mismatch")
    if records["factory"]["alloc2"]["formula"] != (
            "0x18 + 2 * (8 + 8 * count), count = 12"):
        fail("alloc2 size formula mismatch")
    if records["factory"]["alloc2"]["size"] != "0xe8":
        fail("alloc2 size mismatch")

    # The vtable slot tables in the model must match the
    # RELATIVE records stored in relocations.txt.
    sys.path.insert(0, str(ROOT / "tools"))
    import skiplist_rep_factory_115 as model
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
    if total != 70:
        fail("vtable slot total %d != 70" % total)
    for vptr, ti in model.TYPEINFO_POINTERS.items():
        if stored.get(vptr - 0x08) != ti:
            fail("typeinfo pointer %#x-0x08 != %#x" % (vptr, ti))
    for ti, name_addr in model.TYPEINFO_NAME_POINTERS.items():
        if stored.get(ti + 0x08) != name_addr:
            fail("typeinfo name pointer %#x+0x08 != %#x" % (ti, name_addr))
    if len(stored) != 89:
        fail("relocation record total %d != 89" % len(stored))

    # The typeinfo names demangle to the recorded class names.
    expect = {
        "N7rocksdb12_GLOBAL__N_111SkipListRepE":
            "rocksdb::(anonymous namespace)::SkipListRep",
        "N7rocksdb15SkipListFactoryE": "rocksdb::SkipListFactory",
        "N7rocksdb15ConcurrentArenaE": "rocksdb::ConcurrentArena",
        "N7rocksdb5ArenaE": "rocksdb::Arena",
        "N7rocksdb12ConfigurableE": "rocksdb::Configurable",
        "N7rocksdb9AllocatorE": "rocksdb::Allocator",
        "N7rocksdb11MemTableRepE": "rocksdb::MemTableRep",
        "N7rocksdb18MemTableRepFactoryE": "rocksdb::MemTableRepFactory",
        "N7rocksdb11MemTableRep8IteratorE":
            "rocksdb::MemTableRep::Iterator",
    }
    for lit in records["literals"]:
        name = lit.get("text")
        if name is None or name.lstrip("*") not in expect:
            continue
        mangled = name.lstrip("*")
        out = subprocess.run(["c++filt", "_ZTI" + mangled],
                             capture_output=True, text=True,
                             check=True).stdout.strip()
        if expect[mangled] not in out:
            fail("typeinfo %s demangles to %s" % (name, out))
    print("records ok (factory, arena, owner, vtables, typeinfo)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_skiplist_rep_factory_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "all 160 checks passed" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (160 checks)")


def main():
    data = BINARY.read_bytes()
    segments = load_segments(data)
    records = json.loads((PACKET / "records.json").read_text())
    check_digest(data)
    check_manifest()
    check_reshipped()
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
