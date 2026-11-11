"""Checker for the RE-001-lazy-resolver-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-lazy-resolver-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary
(three random ones among them: 0x5f07541, 0x5d4b1cb, 0x5f0ef5b);
the FDE ranges in frames.txt against a fresh frame dump; the
relocation set against a fresh relocation dump (1 record: the
GOT slot 0x64ed3e8 holding the canonical 0x5d4b100); the
message literals against the raw binary; census consistency
(callers.tsv against a fresh census run: every pinned routine's
direct calls, tail jumps, lea references, stored qwords and
RELATIVE addends, and the callers.tsv caller function against
the smallest enclosing FDE range from a fresh frame dump); the
semantic records (re-deriving the census entries, the GOT
canonical records, the resolver/canonical/callsite/once
records, the sentinel constant and the model behaviour); and
the model tests in tests/test_lazy_resolver_115.py.
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
    ("resolver.txt", 0x5F074E0, 0x5F07603),
    ("canonical.txt", 0x5D4B100, 0x5D4B20C),
    ("callsite.txt", 0x5F0EF1C, 0x5F0EF60),
    ("once_helper.txt", 0x5F07490, 0x5F074D3),
    ("once_pred.txt", 0x5F07300, 0x5F07481),
]

# (target, expected direct calls, expected tail jumps, expected leas)
EXPECTED_CENSUS = {
    0x5D350C0: (1273, 25, 0),
    0x5D4B100: (0, 0, 4),
    0x5F07300: (2, 0, 0),
    0x5F07490: (7, 0, 0),
    0x5F074E0: (1, 0, 0),
    0x5F0B420: (1, 0, 0),
    0x5F0E890: (10, 0, 0),
    0x5F0F930: (1, 0, 0),
    0x5FBCD50: (4, 0, 0),
    0x5FBCFA0: (3, 0, 0),
}

# File offsets of 8-byte-aligned qwords equal to the target
# (these are the addend fields of .rela.dyn RELATIVE records).
EXPECTED_QWORDS = {
    0x5D4B100: ["0x10f9f0", "0x15d270"],
}

# Number of RELATIVE records whose addend is the target.
EXPECTED_RELATIVE = {
    0x5D4B100: 2,
}

SPOT_BYTES = {
    0x5F074E0: "f30f1efa",
    0x5F074F7: "488b87b80c0000",
    0x5F07520: "488bb7700c0000",
    0x5F07541: "483b05a05e5e00",
    0x5F0759C: "ff90c0000000",
    0x5F075B5: "f0480fb113",
    0x5F075C8: "e8f3974e00",
    0x5D4B100: "f30f1efa",
    0x5D4B10C: "488b7620",
    0x5D4B1CB: "ff90c0000000",
    0x5F0EF33: "498b85180c0000",
    0x5F0EF46: "e84585ffff",
    0x5F0EF5B: "e88085ffff",
    0x5F07490: "f30f1efa",
    0x5F07300: "f30f1efa",
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
    if len(stored) != 1:
        fail("relocation count %d != 1" % len(stored))
    if stored != [(0x64ED3E8, 0x5D4B100)]:
        fail("stored relocation is not the canonical GOT slot")
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

    # The records census section must agree with the verify
    # expectations. Keys are "name_0x<addr>".
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
    if records["census"]["relocation_records_total"] != 1:
        fail("records relocation total != 1")
    if records["census"]["callers_tsv_rows"] != 1331:
        fail("records callers.tsv row count != 1331")
    if records["census"]["test_checks"] != 78:
        fail("records test_checks != 78")

    # The canonical's GOT records: the stored slot and the
    # second slot re-derive from a fresh readelf dump.
    got = records["got_canonical"]
    if full_relocs.get(int(got["slot"], 16)) != 0x5D4B100:
        fail("GOT canonical slot not in a fresh dump")
    if full_relocs.get(int(got["second_slot"], 16)) != 0x5D4B100:
        fail("second canonical GOT slot not in a fresh dump")
    canon = records["census"]["canonical_0x5d4b100"]
    if sorted(int(x, 16) for x in canon["relative_sites"]) != \
            sorted([int(got["slot"], 16), int(got["second_slot"], 16)]):
        fail("canonical relative sites mismatch")
    if [int(x, 16) for x in canon["qword_file_offsets"]] != \
            census_mod.qwords(data, 0x5D4B100):
        fail("canonical qword file offsets mismatch")

    resolver = (PACKET / "resolver.txt").read_text()
    canonical = (PACKET / "canonical.txt").read_text()
    callsite = (PACKET / "callsite.txt").read_text()
    once_helper = (PACKET / "once_helper.txt").read_text()
    once_pred = (PACKET / "once_pred.txt").read_text()

    # The resolver: the sentinel test, the chain-head load,
    # the canonical comparison, the slot call, the gated
    # cmpxchg and the owned-pointer free.
    for needle in ("mov    0xcb8(%rdi),%rax",
                   "cmp    $0xffffffffffffffff,%rax",
                   "mov    0xc70(%rdi),%rsi",
                   "lea    0xcb8(%rdi),%rbx",
                   "movq   $0x0,0x8(%rsp)",
                   "cmp    0x5e5ea0(%rip),%rax",
                   "call   *0xc0(%rax)",
                   "cmpb   $0x0,0x10(%rsp)",
                   "lock cmpxchg %rdx,(%rbx)",
                   "call   63f0dc0"):
        if needle not in resolver:
            fail("resolver line missing: %s" % needle)
    if resolver.count("call   *0xc0(%rax)") != 1:
        fail("resolver must call slot 0xc0 exactly once directly")
    # The canonical: the advance, the GOT comparison, the
    # unconditional ninth-level call and the return of the
    # bool-out pointer.
    for needle in ("mov    0x20(%rsi),%rsi",
                   "cmp    0x7a22b7(%rip),%rax",
                   "call   *0xc0(%rax)",
                   "mov    %rbx,%rax"):
        if needle not in canonical:
            fail("canonical line missing: %s" % needle)
    if canonical.count("mov    0x20(%rsi),%rsi") != 9:
        fail("canonical must advance the chain 9 times")
    # The call site: the +0xc18 gate, the +0xc60/+0x30
    # branch, the helper call and the resolver call.
    for needle in ("mov    0xc60(%r13),%rbp",
                   "cmpb   $0x0,0x30(%r13)",
                   "mov    0xc18(%r13),%rax",
                   "call   5f07490",
                   "call   5f074e0"):
        if needle not in callsite:
            fail("callsite line missing: %s" % needle)
    # The re-shipped once excerpts: the helper calls the
    # predicate, the predicate calls SkipListRep slot 15.
    if "call   5f07300" not in once_helper:
        fail("once helper must call the predicate")
    if "call   *0x78(%rax)" not in once_pred:
        fail("once predicate must call slot 0x78")
    if "endbr64" not in once_helper or "endbr64" not in once_pred:
        fail("re-shipped excerpts must start with endbr64")

    # The sentinel constant bytes re-derive from the raw binary.
    off = va_to_off(segments, 0x456590)
    if data[off:off + 16] != bytes.fromhex(
            "ffffffffffffffff0000000000000000"):
        fail("sentinel constant bytes mismatch")

    # The resolver/canonical/gate records rebuild from the model.
    sys.path.insert(0, str(ROOT / "tools"))
    import lazy_resolver_115 as model
    if model.SENTINEL != 0xFFFFFFFFFFFFFFFF:
        fail("model sentinel != -1")
    if model.SENTINEL_CONSTANT_BYTES != bytes.fromhex(
            "ffffffffffffffff0000000000000000"):
        fail("model sentinel constant bytes mismatch")
    if model.INLINE_LEVELS != 4 or model.CANONICAL_LEVELS != 8:
        fail("model level counts mismatch")

    def slot(value, skip=False, owned=None):
        def call(_node, out):
            out["value"] = value
            out["skip_cache"] = skip
            out["owned"] = owned
        return call

    chain = {1: {"slot24": None, "next": 2},
             2: {"slot24": None, "next": 3},
             3: {"slot24": slot(0x42), "next": None}}
    owner = model.fresh_owner(chain_head=1)
    invoked = []
    installed, freed = model.resolve(owner, chain, invoked)
    if not installed or owner["cb8"] != 0x42 or invoked != [3]:
        fail("model resolve mismatch")
    if model.chain_depth_to_winner(chain, 1) != 2:
        fail("model chain depth mismatch")
    if not model.callsite_gate({"c18": 1, "c60": 1, "c30": 0}):
        fail("model callsite gate mismatch")
    if model.callsite_gate({"c18": 1, "c60": 1, "c30": 1}):
        fail("model callsite gate must skip the small-table path")
    if records["resolver_0x5f074e0"]["sentinel"] != (
            "owner+0xcb8 starts at -1, the low qword of the 16-byte "
            "constant at 0x456590 installed by the owner-tail init "
            "in #3304"):
        fail("resolver sentinel record mismatch")
    if records["resolver_0x5f074e0"]["inline_levels"] != 4:
        fail("resolver inline levels record mismatch")
    if records["canonical_0x5d4b100"]["compared_levels"] != 8:
        fail("canonical compared levels record mismatch")
    if records["canonical_0x5d4b100"]["unconditional_level"] != 9:
        fail("canonical unconditional level record mismatch")
    print("records ok (resolver, canonical, callsite, once, got, census)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_lazy_resolver_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "all 78 checks passed" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (78 checks)")


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
