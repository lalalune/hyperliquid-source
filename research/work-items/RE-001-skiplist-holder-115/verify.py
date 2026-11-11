"""Checker for the RE-001-skiplist-holder-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-skiplist-holder-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; the re-shipped
excerpts against their pinned SHA-256 values; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary
(three random ones among them: 0x60b3de9, 0x5d94cfb, 0x6195a04);
the FDE ranges in frames.txt against a fresh frame dump; the
relocation set against a fresh relocation dump (64 records: the
four vtable groups' 56 function slots plus the four typeinfo
pointers and the four typeinfo name pointers; no pinned routine
is installed by a RELATIVE record); the message literals
against the raw binary; census consistency (callers.tsv against
a fresh census run: every pinned routine's direct calls, tail
jumps, lea references, stored qwords and RELATIVE addends, and
the callers.tsv caller function against the smallest enclosing
FDE range from a fresh frame dump); the semantic records
(re-deriving the record keys from their constant chunks, the
gate literals, the seven-ones block, the shared_ptr installs,
the ":" setter call chains, the registry lea references, the
vtable slot tables against relocations.txt, and the typeinfo
names via c++filt); and the model tests in
tests/test_skiplist_holder_115.py.
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
    ("holder_ctor.txt", 0x6064440, 0x6064551),
    ("pushback.txt", 0x6099CE0, 0x6099E34),
    ("base_init.txt", 0x60B3C30, 0x60B3EEB),
    ("replace.txt", 0x5D946B0, 0x5D9518D),
    ("setter_skip.txt", 0x61935B0, 0x6193791),
    ("setter_hash.txt", 0x6193390, 0x6193559),
    ("hash_factory_ctor.txt", 0x605F150, 0x605F28E),
    ("release.txt", 0x5D350C0, 0x5D35145),
    ("dispatcher.txt", 0x6195290, 0x619686D),
    ("accessor_skip.txt", 0x6192860, 0x619288D),
    ("accessor_hash.txt", 0x6192890, 0x61928BD),
    ("parse_stub.txt", 0x61D1EF0, 0x61D1EF9),
]

# Re-shipped byte-identical from earlier packets.
RESHIPPED_SHA = {
    "holder_ctor.txt": "e0440004638724fd7926244cf19f96f7b14ce424464fdd1ce7afb7a02ebdbd8f",
    "pushback.txt": "f813fd6acf4f8a0b6bc65e7547cc59cbce95e8ae2277d79f688efb4257453817",
    "base_init.txt": "47a46ae45acb42a1b0fe06728814e887de7ddb6cf439ddab64c56382c31e08d5",
    "release.txt": "ce4ab17b4cd37b91afc62e8719d70812b2d36027a1c92eb39ea4916f707792a1",
}

# (target, expected direct calls, expected tail jumps, expected leas)
EXPECTED_CENSUS = {
    0x6064440: (5, 0, 0), 0x605F150: (1, 0, 0),
    0x61935B0: (0, 0, 1), 0x6193390: (0, 0, 1),
    0x6192860: (0, 0, 1), 0x6192890: (0, 0, 1),
    0x61D1540: (12, 1, 0), 0x61D1EF0: (13, 0, 0),
    0x60B3C30: (1, 0, 0), 0x5D946B0: (1, 0, 0),
    0x6099CE0: (37, 0, 0), 0x5D350C0: (1273, 25, 0),
    0x6195290: (1, 0, 0),
    0x63F0DD0: (1935, 0, 0), 0x63F0D80: (11706, 898, 0),
    0x63F0E10: (1069, 0, 0), 0x63F0A80: (287, 0, 0),
    0x63F0AA0: (652, 0, 0), 0x63F0D70: (6391, 0, 0),
    0x63F0FA0: (38, 0, 0), 0x63F0A60: (1530, 1, 0),
    0x63F0DB0: (5778, 2, 0), 0x63F1040: (100, 0, 0),
    0x63F0A50: (61130, 0, 0), 0x63F0F00: (442, 2, 0),
}

EXPECTED_QWORDS = {}

EXPECTED_RELATIVE = {}

SPOT_BYTES = {
    0x6064440: "f30f1efa",
    0x6064444: "4155",
    0x60644FC: "e8df570300",
    0x6099CE0: "f30f1efa",
    0x60B3C30: "f30f1efa",
    0x60B3D07: "0f1183b0000000",
    0x60B3D0E: "e8bdd03300",
    0x60B3DD2: "e86906fbff",
    0x60B3DE9: "488d1580f94100",
    0x60B3E0B: "4883c210",
    0x60B3E23: "48898330010000",
    0x60B3E2C: "4889ab28010000",
    0x5D946B0: "f30f1efa",
    0x5D94C43: "488bbb28010000",
    0x5D94CE8: "e853f72c00",
    0x5D94CED: "488bbb30010000",
    0x5D94CF4: "4c89a328010000",
    0x5D94CFB: "4c89b330010000",
    0x61935B0: "f30f1efa",
    0x61935E7: "e8b4d92500",
    0x6193652: "e899e80300",
    0x6193685: "e8b60dedff",
    0x619371A: "e8210dedff",
    0x6193760: "e8dbd82500",
    0x6193390: "f30f1efa",
    0x6193433: "e8b8ea0300",
    0x6193468: "e8e3bcecff",
    0x6193540: "e8fbda2500",
    0x605F150: "f30f1efa",
    0x605F232: "e8a9aa0300",
    0x605F270: "c3",
    0x5D350C0: "f30f1efa",
    0x6195290: "4157",
    0x61956AC: "488d05fddeffff",
    0x61956C4: "488d0d95d1ffff",
    0x6195A04: "488d0585d9ffff",
    0x6195A0B: "488d0d7eceffff",
    0x6192860: "f30f1efa",
    0x6192890: "f30f1efa",
    0x61D1EF0: "f30f1efa",
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


def parse_text_excerpt(text):
    """[(address, mnemonic text)] for one excerpt."""
    out = []
    for line in text.splitlines():
        m = LINE_RE.match(line)
        if m:
            out.append((int(m.group(1), 16), m.group(3).strip()))
    return out


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
    if len(stored) != 64:
        fail("relocation count %d != 64" % len(stored))
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
    # expectations, and every pinned routine has no stored
    # qwords and no RELATIVE records naming it.
    for addr_hex, entry in records["census"].items():
        target = int(addr_hex, 16)
        want_calls, want_jumps, want_leas = EXPECTED_CENSUS[target]
        if (entry["calls"], entry["jumps"], entry["leas"]) != (
                want_calls, want_jumps, want_leas):
            fail("records census for %#x disagrees with verify" % target)
        if entry["qwords"] or entry["relative"]:
            fail("records census for %#x has qwords/relocations" % target)

    ctor = (PACKET / "holder_ctor.txt").read_text()
    push = (PACKET / "pushback.txt").read_text()
    base = (PACKET / "base_init.txt").read_text()
    repl = (PACKET / "replace.txt").read_text()
    sset = (PACKET / "setter_skip.txt").read_text()
    hset = (PACKET / "setter_hash.txt").read_text()
    hctor = (PACKET / "hash_factory_ctor.txt").read_text()
    disp = (PACKET / "dispatcher.txt").read_text()

    # The holder ctor: vtable install (lea 0x64d27a0 + 0x10), the
    # record-vector zeroing, the key chunk and the push-back call.
    for needle in ("# 64d27a0", "add    $0x10,%rax",
                   "mov    %rax,(%rdi)", "call   6099ce0", "# 452f70"):
        if needle not in ctor:
            fail("holder_ctor line missing: %s" % needle)
    # The push-back helper: vector cap check, 0x30-byte record
    # write (key string, then a/b at +0x20), end += 0x30; the
    # 22-char key takes the _M_create + memcpy heap path.
    for needle in ("cmp    0x18(%rbx),%rbp", "addq   $0x30,0x10(%rbx)",
                   "movups %xmm0,0x20(%rbp)", "call   63f0e10",
                   "call   63f0a60", "call   63f0d80"):
        if needle not in push:
            fail("pushback line missing: %s" % needle)
    # The seven-ones heap block: four 1-dwords, two more, one more.
    for needle in ("mov    $0x1c,%edi", "movups %xmm0,(%rax)",
                   "mov    %r12,0x10(%rax)", "movl   $0x1,0x18(%rax)",
                   "# 452930"):
        if needle not in base:
            fail("base_init seven-ones line missing: %s" % needle)
    # The separate control: lea 0x64d3770, add $0x10, counts, holder.
    for needle in ("# 64d3770", "add    $0x10,%rdx",
                   "mov    %r12,0x8(%rax)", "mov    %rbp,0x10(%rax)",
                   "mov    %rdx,(%rax)",
                   "mov    %rax,0x130(%rbx)", "mov    %rbp,0x128(%rbx)",
                   "call   6064440"):
        if needle not in base:
            fail("base_init control line missing: %s" % needle)
    # The replacement: gate reads, both literals, rebuild and install.
    for needle in ("# 432031", "# 43a3e1", "call   6064440",
                   "mov    0x128(%rbx),%rdi", "mov    0x130(%rbx),%rdi",
                   "mov    %r12,0x128(%rbx)", "mov    %r14,0x130(%rbx)",
                   "call   5d350c0"):
        if needle not in repl:
            fail("replace line missing: %s" % needle)
    # The ":" setters: find, stub, ctor, out_of_range throw.
    for needle in ("call   63f0fa0", "call   61d1ef0", "# 441b18"):
        if needle not in sset or needle not in hset:
            fail("setter line missing: %s" % needle)
    for needle in ("call   6064440", "call   63f1040"):
        if needle not in sset:
            fail("setter_skip line missing: %s" % needle)
    for needle in ("call   605f150", "call   63f1040"):
        if needle not in hset:
            fail("setter_hash line missing: %s" % needle)
    # The hash ctor: vtable install, record key chunks, push-back.
    for needle in ("# 64d2230", "call   6099ce0", "# 451100", "# 4532c0"):
        if needle not in hctor:
            fail("hash_factory_ctor line missing: %s" % needle)
    # The registry: lea references to both setters and both accessors.
    for needle in ("# 61935b0", "# 6193390", "# 6192860", "# 6192890"):
        if needle not in disp:
            fail("dispatcher lea missing: %s" % needle)

    # The record keys rebuild from their constant chunks, with the
    # documented overlaps: the skiplist immediate lands at key+0x0e
    # (overwriting chunk1 bytes 14..15), the hash second chunk at
    # key+0x0d (overwriting chunk1 bytes 13..15 with identical bytes).
    if records["holders"]["skiplist"]["records"][0]["key"] != (
            "SkipListFactoryO"[:14] + "yOptions"):
        fail("skiplist record key does not rebuild from its chunks")
    if records["holders"]["hashlink"]["records"][0]["key"] != (
            "HashLinkListRepF"[:13] + "epFactoryOptions"):
        fail("hash record key does not rebuild from its chunks")

    # The vtable slot tables in the model must match the
    # RELATIVE records stored in relocations.txt.
    sys.path.insert(0, str(ROOT / "tools"))
    import skiplist_holder_115 as model
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
    if total != 56:
        fail("vtable slot total %d != 56" % total)
    for vptr, ti in model.TYPEINFO_POINTERS.items():
        if stored.get(vptr - 0x08) != ti:
            fail("typeinfo pointer %#x-0x08 != %#x" % (vptr, ti))
    for ti, name_addr in model.TYPEINFO_NAME_POINTERS.items():
        if stored.get(ti + 0x08) != name_addr:
            fail("typeinfo name pointer %#x+0x08 != %#x" % (ti, name_addr))
    if len(stored) != 64:
        fail("relocation record total %d != 64" % len(stored))
    if not model.INPLACE_CONTROL_SLOT5_RAW_ZERO:
        fail("inplace control slot 5 is not recorded as raw zero")

    # The typeinfo names demangle to the recorded class names.
    expect = {
        "N7rocksdb15SkipListFactoryE": "rocksdb::SkipListFactory",
        "N7rocksdb12_GLOBAL__N_122HashLinkListRepFactoryE":
            "rocksdb::(anonymous namespace)::HashLinkListRepFactory",
        "St15_Sp_counted_ptrIPN7rocksdb15SkipListFactoryELN9__gnu_cxx12_Lock_policyE2EE":
            "_Sp_counted_ptr<rocksdb::SkipListFactory*",
        "St23_Sp_counted_ptr_inplaceIN7rocksdb15SkipListFactoryESaIvELN9__gnu_cxx12_Lock_policyE2EE":
            "_Sp_counted_ptr_inplace<rocksdb::SkipListFactory",
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
    print("records ok (holders, gate, setters, registry, vtables, typeinfo)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_skiplist_holder_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "all 136 checks passed" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (136 checks)")


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
