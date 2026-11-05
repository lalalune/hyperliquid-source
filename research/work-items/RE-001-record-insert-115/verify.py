"""Checker for the RE-001-record-insert-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-record-insert-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary
(three random ones among them: 0x5f0ea4f, 0x5f0eb87,
0x5f0ec39); the FDE ranges in frames.txt against a fresh
frame dump; the relocation set against a fresh relocation
dump (8 records: the canonical 0x5d4b100 in two GOT slots
and the six product forwarders in their GOT slots); the
message literals against the raw binary; census consistency
(callers.tsv against a fresh census run: every pinned
routine's direct calls, tail jumps, lea references, stored
qwords and RELATIVE addends, and the callers.tsv caller
function against the smallest enclosing FDE range from a
fresh frame dump); the semantic records (re-deriving the
census entries, the GOT canonical records, the min-install
records, the validate messages, the refcount constant and
the model behaviour); and the model tests in
tests/test_record_insert_115.py.
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
    ("main.txt", 0x5F0E890, 0x5F0F37E),
    ("hash_resolve.txt", 0x5F09E90, 0x5F09FAF),
    ("key_validate.txt", 0x5F09B10, 0x5F09E84),
    ("map_find_or_insert.txt", 0x5F0E660, 0x5F0E85F),
    ("hash32.txt", 0x61C34A0, 0x61C3525),
    ("varint_encode.txt", 0x61BD410, 0x61BD4E9),
    ("record_move.txt", 0x5F05310, 0x5F05379),
    ("once_helper.txt", 0x5F07490, 0x5F074D3),
    ("once_pred.txt", 0x5F07300, 0x5F07481),
    ("resolver.txt", 0x5F074E0, 0x5F07603),
    ("canonical.txt", 0x5D4B100, 0x5D4B20C),
    ("release.txt", 0x5D350C0, 0x5D35145),
    ("status_builder.txt", 0x61CF670, 0x61CF767),
]

# (target, expected direct calls, expected tail jumps, expected leas)
EXPECTED_CENSUS = {
    0x5D350C0: (1273, 25, 0),
    0x5D4B100: (0, 0, 4),
    0x5F05310: (19, 0, 0),
    0x5F07300: (2, 0, 0),
    0x5F07490: (7, 0, 0),
    0x5F074E0: (1, 0, 0),
    0x5F09B10: (3, 0, 0),
    0x5F09E90: (5, 0, 0),
    0x5F0E660: (1, 0, 0),
    0x5F0E890: (10, 0, 0),
    0x5F0F3D0: (1, 0, 0),
    0x5F0F930: (1, 0, 0),
    0x61BD410: (165, 0, 0),
    0x61C34A0: (26, 0, 0),
    0x61CF670: (847, 0, 0),
}

# File offsets of 8-byte-aligned qwords equal to the target
# (these are the addend fields of .rela.dyn RELATIVE records).
EXPECTED_QWORDS = {
    0x5D4B100: ["0x10f9f0", "0x15d270"],
}

# Number of RELATIVE records whose addend is the target.
# Each forwarder is held in four GOT slots; the canonical
# in two.
EXPECTED_RELATIVE = {
    0x5D4B100: 2,
    0x5F04CF0: 4,
    0x5F04D10: 4,
    0x5F04D20: 4,
    0x5F04D30: 4,
    0x5F05740: 4,
    0x5F05780: 4,
}

SPOT_BYTES = {
    0x5F0E890: "f30f1efa",
    0x5F0EA4F: "e83cb4ffff",
    0x5F0EA79: "e892b0ffff",
    0x5F0EB87: "e814492b00",
    0x5F0EC39: "f0480fb11a",
    0x5F0EF46: "e84585ffff",
    0x5F0EF5B: "e88085ffff",
    0x5F0F30D: "e85e032c00",
    0x5F0F188: "49899d180c0000",
    0x5F0E9FD: "450fb6f7",
    0x61C34A0: "f30f1efa",
    0x61BD410: "f30f1efa",
    0x5F0E660: "f30f1efa",
    0x5F05310: "4839f7",
    0x61CF670: "f30f1efa",
    0x5D350C0: "f30f1efa",
    0x5D4B100: "f30f1efa",
    0x5F09B10: "f30f1efa",
    0x5F09E90: "f30f1efa",
    0x5F07490: "f30f1efa",
    0x5F07300: "f30f1efa",
    0x5F074E0: "f30f1efa",
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
    if len(stored) != 8:
        fail("relocation count %d != 8" % len(stored))
    if stored != [(0x64CDE48, 0x5D4B100), (0x64ED3E8, 0x5D4B100),
                  (0x64ED748, 0x5F04CF0), (0x64ED750, 0x5F04D10),
                  (0x64ED758, 0x5F04D20), (0x64ED760, 0x5F04D30),
                  (0x64ED798, 0x5F05740), (0x64ED7A0, 0x5F05780)]:
        fail("stored relocations are not the expected GOT slots")
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
                     % (target, len(entry["callsites"])))
    if records["census"]["relocation_records_total"] != 8:
        fail("records relocation total != 8")
    if records["census"]["callers_tsv_rows"] != 2391:
        fail("records callers.tsv row count != 2391")
    if records["census"]["test_checks"] != 150:
        fail("records test_checks != 150")

    # The GOT canonical records re-derive from a fresh dump.
    for got_slot, entry in records["got_canonicals"].items():
        if full_relocs.get(int(got_slot, 16)) != int(entry["target"], 16):
            fail("GOT canonical %s not in a fresh dump" % got_slot)
    canon = records["census"]["canonical_0x5d4b100"]
    if [int(x, 16) for x in canon["qword_file_offsets"]] != \
            census_mod.qwords(data, 0x5D4B100):
        fail("canonical qword file offsets mismatch")
    if sorted(int(x, 16) for x in canon["relative_sites"]) != \
            [0x64CDE48, 0x64ED3E8]:
        fail("canonical relative sites mismatch")

    main = (PACKET / "main.txt").read_text()
    hash_resolve = (PACKET / "hash_resolve.txt").read_text()
    key_validate = (PACKET / "key_validate.txt").read_text()
    map_ex = (PACKET / "map_find_or_insert.txt").read_text()
    hash32 = (PACKET / "hash32.txt").read_text()
    varint = (PACKET / "varint_encode.txt").read_text()
    record_move = (PACKET / "record_move.txt").read_text()
    status_builder = (PACKET / "status_builder.txt").read_text()

    # The main window: the resolve and validate calls, the
    # validate skip, the two CAS loops, the first-install
    # store, the bloom hash calls, the slot dispatch, the
    # TryAgain build, the map call, the type-class constant
    # and the once/resolver tail.
    for needle, want in (
            ("call   5f09e90", 1),
            ("call   5f09b10", 1),
            ("test   %r12,%r12", 1),
            ("je     5f0ea9e", 2),  # the validate skip (0x5f0ea69)
            # and the validate-success branch (0x5f0ea97)
            ("lock cmpxchg %rbx,(%rdx)", 2),
            ("mov    %rbx,0xc18(%r13)", 1),
            ("call   61c34a0", 4),
            ("call   61bd410", 2),
            ("call   61cf670", 1),
            ("call   5f0e660", 1),
            ("movabs $0xffffffffffffff", 2),
            ("mov    $0x100081,%eax", 1),
            ("call   5f07490", 1),
            ("call   5f074e0", 1),
            ("call   *0xa0(%rax)", 3),
            ("call   *0x98(%rax)", 3),
            ("addq   $0x1,0x8(%rax)", 1),
            ("mov    0xa70(%r13),%rax", 1),
            ("pthread_mutex_lock", 1),
            ("pthread_mutex_unlock", 1)):
        if main.count(needle) != want:
            fail("main needle %r: %d != %d"
                 % (needle, main.count(needle), want))
    if "endbr64" not in main:
        fail("main excerpt must start with endbr64")
    # The map: one hash call with seed 0x18d and a division
    # for the bucket.
    if map_ex.count("call   61c34a0") != 1:
        fail("map must call hash32 exactly once")
    if "mov    $0x18d,%edx" not in map_ex:
        fail("map must seed the hash with 0x18d")
    if "div" not in map_ex:
        fail("map must divide for the bucket index")
    # The hash32: three multiplies by 0xc6a4a793.
    if hash32.count("0xc6a4a793") != 3:
        fail("hash32 must multiply by 0xc6a4a793 three times")
    # The varint encoder: the 0x7f fast path and the 0x80
    # continuation bit.
    if "cmp    $0x7f,%esi" not in varint:
        fail("varint must test the 0x7f fast path")
    if "or     $0xffffff80,%r8d" not in varint:
        fail("varint must set the 0x80 continuation bit")
    # The record move: six byte copies and a tail jump to
    # delete[].
    if record_move.count("movzbl") != 6:
        fail("record move must copy six bytes")
    if "jmp    63f0dc0" not in record_move:
        fail("record move must tail-jump to delete[]")
    # The status builder: a heap allocation and two copies.
    if "call   63f0e30" not in status_builder:
        fail("status builder must allocate the message")
    if status_builder.count("call   63f0e00") != 2:
        fail("status builder must copy twice")
    # The re-shipped excerpts must be the same windows the
    # merged packets pinned.
    if hash_resolve.count("endbr64") != 1:
        fail("hash resolve excerpt must start with endbr64")
    if key_validate.count("endbr64") != 1:
        fail("key validate excerpt must start with endbr64")

    # The refcount constant re-derives from the raw binary.
    off = va_to_off(segments, 0x459B20)
    if struct.unpack_from("<Q", data, off)[0] != 0x100000001:
        fail("refcount constant mismatch")

    # The model behaviour re-derives the records.
    sys.path.insert(0, str(ROOT / "tools"))
    import record_insert_115 as model
    if model.C20_SENTINEL != 0x00FFFFFFFFFFFFFF:
        fail("model sentinel mismatch")
    if model.HASH32_SEED != 0xBC9F1D34:
        fail("model bloom seed mismatch")
    if model.GOLDEN64 != 0x9E3779B97F4A7C13:
        fail("model golden ratio mismatch")
    if model.encode_varint32(0x80) != b"\x80\x01":
        fail("model varint encode mismatch")
    if model.hash32(b"a", 0) != 0xCA6C9DD6:
        fail("model hash32 mismatch")
    if model.min_install(0, model.C20_SENTINEL, 5) != \
            (5, model.C20_SENTINEL):
        fail("model min-install mismatch")
    if model.min_install(1, model.C20_SENTINEL, 0) != (0, 0):
        fail("model min-install zero mismatch")
    if records["min_install"]["closes_unknown"] != (
            "the writer of owner+0xc18, recorded as an open "
            "unknown in #3322 (RE-001-lazy-resolver-115)"):
        fail("min-install closes-unknown record mismatch")
    if records["counters"]["owner_a78"] != (
            "owner+0xa78 += 1 when type <= 0x14 and bit type of "
            "0x100081 is set, i.e. types 0, 7, 20 "
            "(0x5f0ee31..0x5f0ee46, bump at 0x5f0f090), updated "
            "only on the flag==0 path"):
        fail("counters a78 record mismatch")
    if records["validate_0x5f09b10"]["error_messages"][
            "protection_mismatch"]["text"] != "ProtectionInfo mismatch":
        fail("validate message record mismatch")
    print("records ok (census, got, main, map, hash32, varint, "
          "record move, status builder, literals, model)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_record_insert_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "ALL 150 CHECKS PASSED" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (150 checks)")


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
