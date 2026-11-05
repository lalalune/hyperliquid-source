"""Checker for the RE-001-owner-tail-phases-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-owner-tail-phases-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary
(three random ones among them: 0x5f10925, 0x5f07400, 0x5f10b55);
the FDE ranges in frames.txt against a fresh frame dump; the
relocation set against a fresh relocation dump (43 records: the
two control vtable groups' 10 function slots plus their two
typeinfo pointers, the five control typeinfo-object records,
the SkipListRep vtable group's 24 records, and the two GOT
entries); the message literals against the raw binary; census
consistency (callers.tsv against a fresh census run: every
pinned routine's direct calls, tail jumps, lea references,
stored qwords and RELATIVE addends, and the callers.tsv caller
function against the smallest enclosing FDE range from a fresh
frame dump); the semantic records (re-deriving the census
entries, the control-slot relative records, the gate/array/
tail/predicate/vtable/typeinfo records, and the typeinfo names
via c++filt); and the model tests in
tests/test_owner_tail_phases_115.py.
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
    ("owner.txt", 0x5F103F0, 0x5F10CF8),
    ("prologue_helper.txt", 0x5F07230, 0x5F072F6),
    ("elem_ctor.txt", 0x60D5880, 0x60D5917),
    ("once_helper.txt", 0x5F07490, 0x5F074D3),
    ("once_pred.txt", 0x5F07300, 0x5F07481),
    ("small_install.txt", 0x61C26F0, 0x61C27A8),
    ("small_dispose.txt", 0x5F0A290, 0x5F0A319),
    ("caller_small.txt", 0x5D8CA00, 0x5D8CA6A),
    ("caller_big_window.txt", 0x5ED086C, 0x5ED08C6),
    ("slot15.txt", 0x6062FB0, 0x6062FB7),
]

# (target, expected direct calls, expected tail jumps, expected leas)
EXPECTED_CENSUS = {
    0x5D35070: (654, 36, 0), 0x5D350C0: (1273, 25, 0),
    0x5D8CA00: (3, 0, 0), 0x5ED01F0: (1, 0, 0),
    0x5F04E20: (0, 0, 0), 0x5F04E30: (0, 0, 0),
    0x5F04E50: (0, 0, 0), 0x5F04E60: (0, 0, 0),
    0x5F04F60: (0, 0, 0), 0x5F04F70: (0, 0, 0),
    0x5F05380: (0, 0, 0), 0x5F057C0: (0, 0, 0),
    0x5F061B0: (0, 0, 0), 0x5F07230: (1, 0, 0),
    0x5F07300: (2, 0, 0), 0x5F07490: (7, 0, 0),
    0x5F0A1DC: (2, 0, 0), 0x5F0A290: (0, 0, 0),
    0x5F0B420: (1, 0, 0), 0x5F103F0: (2, 0, 0),
    0x5F117A0: (0, 0, 0), 0x605CFA0: (2, 0, 0),
    0x605E010: (1, 0, 0), 0x605E810: (1, 0, 0),
    0x6062FB0: (0, 0, 0), 0x6063640: (1, 0, 0),
    0x6064440: (5, 0, 0), 0x60D5880: (3, 0, 0),
    0x61C26F0: (1, 0, 0), 0x61D1F30: (24, 0, 0),
    0x63F0A50: (61130, 0, 0), 0x63F0A90: (548, 7, 0),
    0x63F0BF0: (75, 0, 0), 0x63F0D70: (6391, 0, 0),
    0x63F0D80: (11706, 898, 0), 0x63F0DB0: (5778, 2, 0),
    0x63F0DD0: (1935, 0, 0), 0x63F0DE0: (1380, 0, 0),
    0x63F1380: (3, 0, 0), 0x63F1390: (3, 0, 0),
    0x63F1400: (36, 0, 0), 0x63F1820: (1, 0, 0),
}

# File offsets of 8-byte-aligned qwords equal to the target
# (these are the addend fields of .rela.dyn RELATIVE records).
EXPECTED_QWORDS = {
    0x5F04E20: ["0x10c2d0"], 0x5F04E30: ["0x10c240"],
    0x5F04E50: ["0x10c258"], 0x5F04E60: ["0x10c2e8"],
    0x5F04F60: ["0x10c318"], 0x5F04F70: ["0x10c288"],
    0x5F05380: ["0x10c330"], 0x5F057C0: ["0x10c2a0"],
    0x5F061B0: ["0x10c270"], 0x5F0A290: ["0x10c300"],
    0x5F117A0: ["0x10bf10"], 0x6062FB0: ["0x11bbb8"],
    0x6063640: ["0x11be58"],
}

# Number of RELATIVE records whose addend is the target.
EXPECTED_RELATIVE = {
    0x5F04E20: 1, 0x5F04E30: 1, 0x5F04E50: 1, 0x5F04E60: 1,
    0x5F04F60: 1, 0x5F04F70: 1, 0x5F05380: 1, 0x5F057C0: 1,
    0x5F061B0: 1, 0x5F0A290: 1, 0x5F117A0: 1, 0x6062FB0: 1,
    0x6063640: 1,
}

SPOT_BYTES = {
    0x5F103F0: "f30f1efa",
    0x5F10461: "e8ca6dffff",
    0x5F104C8: "e843db1400",
    0x5F10517: "e8243f1500",
    0x5F10530: "e80b311500",
    0x5F107DB: "e8a0501c00",
    0x5F10918: "e803abffff",
    0x5F10920: "e86b6bffff",
    0x5F10925: "4883bb580c000000",
    0x5F10B55: "e96645e2ff",
    0x5F10C10: "e8db1a2b00",
    0x5F07230: "f30f1efa",
    0x60D5880: "f30f1efa",
    0x5F07490: "f30f1efa",
    0x5F07300: "f30f1efa",
    0x5F07400: "4889c2",
    0x61C26F0: "f30f1efa",
    0x5F0A290: "f30f1efa",
    0x5D8CA00: "f30f1efa",
    0x5ED086C: "48c78520efffff00000000",
    0x6062FB0: "f30f1efa",
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
    if len(stored) != 43:
        fail("relocation count %d != 43" % len(stored))
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
    if records["census"]["relocation_records_total"] != 43:
        fail("records relocation total != 43")
    if records["test_checks"] != 513:
        fail("records test_checks != 513")

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

    owner = (PACKET / "owner.txt").read_text()
    prologue = (PACKET / "prologue_helper.txt").read_text()
    elem_ctor = (PACKET / "elem_ctor.txt").read_text()
    once_pred = (PACKET / "once_pred.txt").read_text()
    small_install = (PACKET / "small_install.txt").read_text()
    small_dispose = (PACKET / "small_dispose.txt").read_text()
    caller_small = (PACKET / "caller_small.txt").read_text()
    caller_big = (PACKET / "caller_big_window.txt").read_text()
    slot15 = (PACKET / "slot15.txt").read_text()

    # The owner: the factory and holder calls from #3286, the
    # +0xa50/+0xa58 stores, the element-ctor call, the table-init
    # and once-helper calls, the small-install call, the guard
    # constant, the destroy-dispatch calls and the epilogue
    # tail-jump to the release helper. The whole-function excerpt
    # subsumes the two #3286 owner windows byte-for-byte.
    for needle in ("call   6063640",
                   "call   6064440",
                   "mov    %rax,0xa50(%rbx)",
                   "mov    %rax,0xa58(%rbx)",
                   "call   60d5880",
                   "call   5f0b420",
                   "call   5f07490",
                   "call   61c26f0",
                   "249249249249249",
                   "call   5d35070",
                   "jmp    5d350c0",
                   "movl   $0x3f800000,0xca0(%rbx)"):
        if needle not in owner:
            fail("owner line missing: %s" % needle)
    # The prologue helper: the double multiply, the movlpd/movups
    # pair that builds owner+0x50..0x57.
    for needle in ("mulsd  0x18(%r8),%xmm0",
                   "movlpd 0x218(%rcx),%xmm1",
                   "movups %xmm1,0x38(%rax)"):
        if needle not in prologue:
            fail("prologue_helper line missing: %s" % needle)
    # The element ctor: rwlock init, the strerror builder, the
    # fprintf error path.
    for needle in ("call   63f1820",
                   "call   61d1f30",
                   "call   63f1400"):
        if needle not in elem_ctor:
            fail("elem_ctor line missing: %s" % needle)
    # The once predicate: the two virtual slot-15 calls, the
    # 0.6 scale load at 0x4591d0, the +0x78 read.
    if once_pred.count("call   *0x78(%rax)") != 2:
        fail("once_pred must call slot 15 twice")
    for needle in ("# 4591d0",
                   "mov    0x78(%rbp),%rsi"):
        if needle not in once_pred:
            fail("once_pred line missing: %s" % needle)
    # The small install: the arena slot-3 virtual call.
    if "call   *0x18(%rax)" not in small_install:
        fail("small_install line missing: call *0x18(%rax)")
    # The small dispose: the big control's _M_dispose slot call
    # and the destroy-dispatch tail jump.
    for needle in ("call   *0x10(%rax)",
                   "jmp    5d35070"):
        if needle not in small_dispose:
            fail("small_dispose line missing: %s" % needle)
    # Both callers call the owner.
    if "call   5f103f0" not in caller_small:
        fail("caller_small line missing: call 5f103f0")
    if "call   5f103f0" not in caller_big:
        fail("caller_big_window line missing: call 5f103f0")
    # The slot-15 stub returns zero.
    if "xor    %eax,%eax" not in slot15:
        fail("slot15 line missing: xor %eax,%eax")

    # The gate, array and tail records rebuild from the model.
    sys.path.insert(0, str(ROOT / "tools"))
    import owner_tail_phases_115 as model
    if records["element_array_phase_b"]["max_count"] != "0x249249249249249":
        fail("element array max_count mismatch")
    if records["element_array_phase_b"]["element_size"] != 56:
        fail("element array element_size != 56")
    if model.ELEM_MAX_COUNT * 56 != model.ELEM_MAX_BYTES:
        fail("model guard constant mismatch")
    if records["small_install_gate"]["rebuild_condition"] != (
            "(+0x20 != 0) AND (+0xc58 != 0 OR +0x30 != 0)"):
        fail("small-install gate record mismatch")
    if model.descriptor_size(1600) != (28, 255):
        fail("descriptor_size(1600) != (28, 255)")
    if records["once_predicate_0x5f07300"]["store"] != (
            "+0xcd0 = slot15(+0xa50) + slot15(+0xa58) + *(owner+0xa00); "
            "both calls return 0, so +0xcd0 = *(owner+0xa00)"):
        fail("once predicate store record mismatch")
    if records["literals"]["predicate_scale"]["value"] != 0.6:
        fail("predicate scale literal != 0.6")

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
    if total != 33:
        fail("vtable slot total %d != 33" % total)
    for vptr, ti in model.TYPEINFO_POINTERS.items():
        if stored.get(vptr - 0x08) != ti:
            fail("typeinfo pointer %#x-0x08 != %#x" % (vptr, ti))
    # Control typeinfo name/base pointers are in relocations.txt;
    # the SkipListRep/MemTableRep ones are verified against the
    # full fresh relocation dump (outside the stored ranges).
    for ti, name_addr in model.TYPEINFO_NAME_POINTERS.items():
        if ti in (model.BIG_TYPEINFO, model.SMALL_TYPEINFO):
            if stored.get(ti + 0x08) != name_addr:
                fail("typeinfo name pointer %#x+0x08 != %#x"
                     % (ti, name_addr))
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
    if len(stored) != 43:
        fail("relocation record total %d != 43" % len(stored))

    # The typeinfo names demangle to the recorded class names.
    expect = {
        "N7rocksdb12_GLOBAL__N_111SkipListRepE":
            "rocksdb::(anonymous namespace)::SkipListRep",
        "N7rocksdb11MemTableRepE": "rocksdb::MemTableRep",
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
        # The stored name string at the recorded address matches
        # the record (SkipListRep's stored string carries a
        # leading "*").
        addr = int(entry["name_address"], 16)
        off = va_to_off(segments, addr)
        if off is None:
            fail("typeinfo %s: no file offset" % mangled)
        end = data.index(b"\x00", off)
        if data[off:end].decode().lstrip("*") != mangled:
            fail("typeinfo %s string mismatch" % mangled)
    print("records ok (owner, gate, array, tail, predicate, "
          "vtables, typeinfo)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_owner_tail_phases_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "all 513 checks passed" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (513 checks)")


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
