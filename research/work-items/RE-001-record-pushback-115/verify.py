"""Checker for the RE-001-record-pushback-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-record-pushback-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary;
the FDE ranges in frames.txt against a fresh frame dump; the
relocation set against a fresh relocation dump (no pinned
routine is installed by a RELATIVE record); the message
literals against the raw binary; census consistency
(callers.tsv against a fresh census run: every pinned
routine's direct calls, tail jumps, stored qwords and
RELATIVE addends, and the callers.tsv caller function against
the smallest enclosing FDE range from a fresh frame dump);
the semantic records (re-deriving the SkipListFactoryOptions
key construction, the growth capacity rule, the push-back
fast-path stores and the three call-site arguments from the
excerpts); and the model tests in
tests/test_record_pushback_115.py.
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
    ("pushback.txt", 0x6099CE0, 0x6099E34),
    ("growth.txt", 0x6099790, 0x6099CAD),
    ("caller_64440.txt", 0x6064440, 0x6064551),
    ("caller_5fd0090.txt", 0x5FD0090, 0x5FD0178),
    ("table_init.txt", 0x60DB710, 0x60DBD69),
]

# (target, expected direct calls, expected tail jumps)
EXPECTED_CENSUS = {
    0x6099CE0: (37, 0), 0x6099790: (1, 0), 0x6064440: (5, 0),
    0x5FD0090: (1, 0), 0x60DB710: (3, 0), 0x63F0F00: (442, 2),
    0x63F0E10: (1069, 0), 0x63F0A60: (1530, 1), 0x63F0D80: (11706, 898),
    0x63F0DD0: (1935, 0), 0x63F0DB0: (5778, 2),
}

EXPECTED_QWORDS = {}

EXPECTED_RELATIVE = {}

SPOT_BYTES = {
    0x6099CE0: "f30f1efa",
    0x6099790: "f30f1efa",
    0x6064440: "f30f1efa",
    0x5FD0090: "f30f1efa",
    0x60DB710: "f30f1efa",
    0x6099D89: "4883431030",
    0x60997FE: "488d0c00",
    0x60644CE: "48b9794f7074696f6e73",
    0x6099E0A: "e881f9ffff",
    0x60DB9DB: "e800e3fbff",
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
    for target, (want_calls, want_jumps) in EXPECTED_CENSUS.items():
        calls, jumps = census.scan(sites, target)
        if len(calls) != want_calls or len(jumps) != want_jumps:
            fail("census for %#x: calls=%d jumps=%d, want %d/%d"
                 % (target, len(calls), len(jumps),
                    want_calls, want_jumps))
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
        want = census.enclosing_fde(ranges, int(site, 16))
        if caller != want:
            fail("callers.tsv caller for %s: %s != %s"
                 % (site, caller, want))
    expect_rows = []
    for target in sorted(EXPECTED_CENSUS):
        calls, jumps = census.scan(sites, target)
        for site in calls:
            expect_rows.append((site, target, "call"))
        for site in jumps:
            expect_rows.append((site, target, "tail jump"))
    expect_rows.sort()
    got_rows = sorted((s, t, k) for s, t, _c, k in rows)
    if got_rows != expect_rows:
        fail("callers.tsv rows do not match a fresh census run")
    print("census ok (%d rows)" % len(rows))


# ----------------------------------------------------------------
# Semantic-record re-derivation from the excerpts.
# ----------------------------------------------------------------

def _ins_by_addr(name):
    text = (PACKET / name).read_text()
    return dict(parse_text_excerpt(text))


def check_records(segments, data, records):
    # The records census section must agree with the verify
    # expectations.
    for addr_hex, entry in records["census"].items():
        target = int(addr_hex, 16)
        want_calls, want_jumps = EXPECTED_CENSUS[target]
        if (entry["calls"], entry["jumps"]) != (want_calls, want_jumps):
            fail("records census for %#x disagrees with verify" % target)
        if entry["qwords"] or entry["relative"]:
            fail("records census for %#x has qwords/relocations" % target)

    # The SkipListFactoryOptions key, rebuilt from the two
    # overlapping constant stores in caller_64440.txt.
    ins = _ins_by_addr("caller_64440.txt")
    chunk_addr = None
    chunk8 = None
    store_off = None
    size = None
    for addr, txt in sorted(ins.items()):
        if "movdqa" in txt and "(%rip)" in txt and "#" in txt:
            chunk_addr = int(txt.split("#")[1].strip().split()[0], 16)
        m = re.search(r"movabs \$0x([0-9a-f]+),%rcx", txt)
        if m:
            chunk8 = bytes.fromhex(m.group(1))
            chunk8 = chunk8[::-1]  # little-endian immediate
        m = re.search(r"mov\s+%rcx,0x([0-9a-f]+)\(%rax\)", txt)
        if m:
            store_off = int(m.group(1), 16)
        m = re.search(r"movq\s+\$0x([0-9a-f]+),0x8\(%rsp\)", txt)
        if m:
            size = int(m.group(1), 16)
    if chunk_addr is None or chunk8 is None or store_off is None:
        fail("key construction not found in caller_64440.txt")
    off = va_to_off(segments, chunk_addr)
    chunk16 = data[off:off + 16]
    sys.path.insert(0, str(ROOT / "tools"))
    from record_pushback_115 import key_from_chunks
    rebuilt = key_from_chunks(chunk16, chunk8, store_off, size)
    want_key = records["call_sites"][1]["key"]
    if rebuilt != want_key:
        fail("rebuilt key %r != %r" % (rebuilt, want_key))
    if size != records["call_sites"][1]["key_length"]:
        fail("key size %d != %d" % (size, records["call_sites"][1]["key_length"]))

    # The growth capacity rule, from growth.txt.
    growth_lines = (PACKET / "growth.txt").read_text()
    if "0x2aaaaaaaaaaaaaa" not in growth_lines:
        fail("MAX_SIZE immediate missing from growth.txt")
    if "lea    (%rax,%rax,1),%rcx" not in growth_lines:
        fail("doubling lea missing from growth.txt")
    if "lea    (%rax,%rax,2),%rax" not in growth_lines:
        fail("times-48 lea missing from growth.txt")
    if "shl    $0x4,%rax" not in growth_lines:
        fail("times-16 shift missing from growth.txt")
    if "# 43d55a" not in growth_lines:
        fail("length_error literal address missing from growth.txt")
    if records["growth"]["max_size"] != 0x2AAAAAAAAAAAAAA:
        fail("records MAX_SIZE mismatch")
    if records["growth"]["max_size"] != (2 ** 63 - 1) // 48:
        fail("records MAX_SIZE is not (2^63-1)//48")

    # The push-back fast path, from pushback.txt.
    push = _ins_by_addr("pushback.txt")
    if 0x6099E0A not in push or "6099790" not in push[0x6099E0A]:
        fail("growth call at 0x6099e0a missing from pushback.txt")
    if 0x6099D89 not in push or "addq" not in push[0x6099D89]:
        fail("end advance at 0x6099d89 missing from pushback.txt")
    if 0x6099D2B not in push or "63f0f00" not in push[0x6099D2B]:
        fail("_M_assign call at 0x6099d2b missing from pushback.txt")
    push_lines = (PACKET / "pushback.txt").read_text()
    for needle in ("mov    0x10(%rbx),%rbp", "cmp    0x18(%rbx),%rbp",
                   "movdqa 0x30(%rsp),%xmm0", "movups %xmm0,0x20(%rbp)"):
        if needle not in push_lines:
            fail("push-back line missing: %s" % needle)

    # The three call-site arguments, from their excerpts.
    c64440 = (PACKET / "caller_64440.txt").read_text()
    for needle in ("lea    0x4a1750(%rip),%rcx        # 6505c40",
                   "lea    0x20(%rbx),%r13",
                   "call   6099ce0"):
        if needle not in c64440:
            fail("caller_64440 line missing: %s" % needle)
    c5fd = (PACKET / "caller_5fd0090.txt").read_text()
    for needle in ("lea    0x534a71(%rip),%rcx        # 6504b80",
                   "lea    0x20(%rbx),%rdx",
                   "movq   $0x0,0x8(%rsp)",
                   "call   6099ce0"):
        if needle not in c5fd:
            fail("caller_5fd0090 line missing: %s" % needle)
    table = (PACKET / "table_init.txt").read_text()
    for needle in ("lea    0x42bb6e(%rip),%rcx        # 6507540",
                   "lea    -0x5c9743c(%rip),%rsi        # 444587",
                   "mov    %r13,%rdx",
                   "call   6099ce0"):
        if needle not in table:
            fail("table_init line missing: %s" % needle)
    print("records ok (3 call sites, growth rule, key build)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_record_pushback_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "all 47 checks passed" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (47 checks)")


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
