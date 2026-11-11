"""Checker for the RE-001-record-write-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-record-write-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary
(the entry byte of each of the 14 windows, plus three gate
spots picked with random.seed(3331) from the direct call
sites in main.txt: 0x5f0fc2f, 0x5f0fb60, 0x5f0fc80); the FDE
ranges in frames.txt against a fresh frame dump; the relocation
set against a fresh relocation dump (exactly 2 records: the
GOT slots 0x64ed010 and 0x64ed778 holding the canonical
forwarders); the rwlock string literals and the seven validate
messages against the raw binary; census consistency
(callers.tsv against a fresh census run: every pinned
routine's direct calls, tail jumps, lea references, stored
qwords and RELATIVE addends, and the callers.tsv caller
function against the smallest enclosing FDE range from a
fresh frame dump); the semantic records (re-deriving the
census entries, the GOT canonical records, the main/key-build/
key-len/varint/rwlock needles, the validate messages, the
once-helper sites, the single caller and the model behaviour);
and the model tests in tests/test_record_write_115.py.
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
    ("main.txt", 0x5F0F930, 0x5F10134),
    ("key_build.txt", 0x5EAB0C0, 0x5EAB192),
    ("key_len.txt", 0x5F06F40, 0x5F06F99),
    ("varint_decode.txt", 0x61BD4F0, 0x61BD53B),
    ("rwlock_wrlock.txt", 0x60D5AB0, 0x60D5B45),
    ("rwlock_unlock.txt", 0x60D5C30, 0x60D5CC5),
    ("record_insert.txt", 0x5F0E890, 0x5F0F37E),
    ("record_move.txt", 0x5F05310, 0x5F05379),
    ("varint_encode.txt", 0x61BD410, 0x61BD4E9),
    ("once_helper.txt", 0x5F07490, 0x5F074D3),
    ("once_predicate.txt", 0x5F07300, 0x5F07481),
    ("value_resolve.txt", 0x5F09E90, 0x5F09FAF),
    ("protection_validate.txt", 0x5F09B10, 0x5F09E84),
    ("hash_bucket.txt", 0x5F099B0, 0x5F09A42),
]

# (target, expected direct calls, expected tail jumps, expected leas)
EXPECTED_CENSUS = {
    0x5EAB0C0: (13, 0, 0),
    0x5F05310: (19, 0, 0),
    0x5F06F40: (6, 0, 0),
    0x5F07300: (2, 0, 0),
    0x5F07490: (7, 0, 0),
    0x5F099B0: (7, 0, 0),
    0x5F09B10: (3, 0, 0),
    0x5F09E90: (5, 0, 0),
    0x5F0E890: (10, 0, 0),
    0x5F0F3D0: (1, 0, 0),
    0x5F0F930: (1, 0, 0),
    0x60D5AB0: (11, 0, 0),
    0x60D5C30: (23, 0, 0),
    0x61BD410: (165, 0, 0),
    0x61BD4F0: (149, 0, 0),
    0x61C3530: (108, 0, 0),
}

# No pinned routine is installed by a RELATIVE record, and no
# 8-byte-aligned qword in the file equals a pinned routine
# address (the two GOT canonicals 0x5f04d80 / 0x5d2ca80 are
# forwarders, not pinned routines).
EXPECTED_QWORDS = {}
EXPECTED_RELATIVE = {}

# Entry byte of each window, plus the three seeded gate spots.
SPOT_BYTES = {
    0x5F0F930: "f30f1efa",
    0x5EAB0C0: "f30f1efa",
    0x5F06F40: "f30f1efa",
    0x61BD4F0: "f30f1efa",
    0x60D5AB0: "f30f1efa",
    0x60D5C30: "f30f1efa",
    0x5F0E890: "f30f1efa",
    0x5F05310: "4839f7",
    0x61BD410: "f30f1efa",
    0x5F07490: "f30f1efa",
    0x5F07300: "f30f1efa",
    0x5F09E90: "f30f1efa",
    0x5F09B10: "f30f1efa",
    0x5F099B0: "f30f1efa",
    0x5F0FC2F: "41ff542440",
    0x5F0FB60: "ffd2",
    0x5F0FC80: "e82b114e00",
}

TAB = chr(9)
LINE_RE = re.compile("^ *([0-9a-f]+):" + TAB + "([0-9a-f ]+?)" + TAB + "(.*)$")
CONT_RE = re.compile("^ *([0-9a-f]+):" + TAB + "([0-9a-f ]+?) *$")
RELOC_RE = re.compile("^[ ]*([0-9a-f]+)[ ]+([0-9a-f]+)[ ]+R_X86_64_RELATIVE"
                      "[ ]+([0-9a-f]+)")


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
        m = RELOC_RE.match(line)
        if not m:
            continue
        stored.append((int(m.group(1), 16), int(m.group(3), 16)))
        if relocs.get(int(m.group(1), 16)) != int(m.group(3), 16):
            fail("relocation %s not in a fresh dump" % line)
    if len(stored) != 2:
        fail("relocation count %d != 2" % len(stored))
    if stored != [(0x64ED010, 0x5D2CA80), (0x64ED778, 0x5F04D80)]:
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
    for name, addr_s in records["rwlock"]["literals"].items():
        addr = int(addr_s, 16)
        off = va_to_off(segments, addr)
        if off is None:
            fail("literal %s: no file offset" % addr_s)
        want = name.encode() + b"\x00"
        if data[off:off + len(want)] != want:
            fail("literal %s mismatch at %s" % (name, addr_s))
    for message in records["validate_0x5f09b10"]["messages"]:
        want = message.encode() + b"\x00"
        if want not in data:
            fail("validate message not in binary: %r" % message)
    print("literals ok (%d rwlock + %d validate messages)"
          % (len(records["rwlock"]["literals"]),
             len(records["validate_0x5f09b10"]["messages"])))


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
    if records["census"]["relocation_records_total"] != 2:
        fail("records relocation total != 2")
    if records["census"]["callers_tsv_rows"] != 530:
        fail("records callers.tsv row count != 530")
    if records["census"]["test_checks"] != 118:
        fail("records test_checks != 118")

    # The GOT canonical records re-derive from a fresh dump.
    for entry in records["got_canonicals"]:
        slot = int(entry["slot"], 16)
        if full_relocs.get(slot) != int(entry["holds"], 16):
            fail("GOT canonical %s not in a fresh dump" % entry["slot"])
    if records["census"]["main_0x5f0f930"]["callsites"] != ["0x5fc6433"]:
        fail("records main single caller mismatch")
    if records["once_helper_0x5f07490"]["sites_in_main"] != [
            "0x5f0fc4d", "0x5f0fce4", "0x5f0ff5e"]:
        fail("records once-helper sites mismatch")

    main = (PACKET / "main.txt").read_text()
    key_build = (PACKET / "key_build.txt").read_text()
    key_len = (PACKET / "key_len.txt").read_text()
    varint_decode = (PACKET / "varint_decode.txt").read_text()
    wrlock = (PACKET / "rwlock_wrlock.txt").read_text()
    unlock = (PACKET / "rwlock_unlock.txt").read_text()

    # The main window: the key build, the two lookups, the
    # bucket + lock, the dispatch, the three once sites, the
    # six hash calls, the resolve/validate/insert/move calls,
    # the stats codes and the hash seeds.
    for needle, want in (
            ("call   5eab0c0", 1),
            ("call   61bd4f0", 1),
            ("call   5f06f40", 1),
            ("call   5f099b0", 1),
            ("call   60d5ab0", 1),
            ("call   5f07490", 3),
            ("call   60d5c30", 2),
            ("call   61c3530", 6),
            ("call   5f09e90", 2),
            ("call   5f09b10", 1),
            ("call   5f0e890", 1),
            ("call   5f05310", 2),
            ("call   61bd410", 1),
            ("call   *0x40(%r12)", 1),
            ("call   *0x90(%rax)", 1),
            ("call   *%rcx", 2),
            ("call   *0x10(%rax)", 2),
            ("call   *0x18(%rdx)", 1),
            ("call   *0xb0(%rax)", 2),
            ("call   *0x8", 1),
            ("call   *%rdx", 1),
            ("0x77a00858ddd37f21", 2),
            ("0xd28aad72f49bd50b", 4),
            ("cmp    $0x1,%al", 1),
            ("mov    $0x27,%esi", 1),
            ("mov    $0x25,%esi", 1)):
        if main.count(needle) != want:
            fail("main needle %r: %d != %d"
                 % (needle, main.count(needle), want))
    if "endbr64" not in main:
        fail("main excerpt must start with endbr64")
    # The key build: one varint encode, the 0x16 trailer
    # or, the 0xc8 inline bound, the 0x8 trailer shift and
    # one operator-new call.
    for needle, want in (
            ("call   61bd410", 1),
            ("or     $0x16,%rbx", 1),
            ("cmp    $0xc8,%rdi", 1),
            ("shl    $0x8,%rbx", 1),
            ("call   63f0e30", 1)):
        if key_build.count(needle) != want:
            fail("key build needle %r: %d != %d"
                 % (needle, key_build.count(needle), want))
    # The key-length reader: one varint decode, the
    # single-byte fast path and its not-taken jump.
    for needle, want in (
            ("call   61bd4f0", 1),
            ("test   %dl,%dl", 1),
            ("jns", 1)):
        if key_len.count(needle) != want:
            fail("key len needle %r: %d != %d"
                 % (needle, key_len.count(needle), want))
    # The varint decoder: the 0x1c shift bound and the
    # 0x7f low-bits mask.
    for needle, want in (
            ("cmp    $0x1c,%ecx", 1),
            ("and    $0x7f,%edi", 1)):
        if varint_decode.count(needle) != want:
            fail("varint decode needle %r: %d != %d"
                 % (needle, varint_decode.count(needle), want))
    # The rwlock pair: the 0x6e accepted rc and the
    # 0xffffffef accepted-rc mask in each.
    for text, name in ((wrlock, "wrlock"), (unlock, "unlock")):
        for needle, want in (
                ("cmp    $0x6e,%eax", 1),
                ("test   $0xffffffef,%eax", 1)):
            if text.count(needle) != want:
                fail("%s needle %r: %d != %d"
                     % (name, needle, text.count(needle), want))

    # The validate messages re-derive from the records list.
    if records["validate_0x5f09b10"]["messages"] != [
            "Unable to parse internal key length",
            "Internal key length too short",
            "Internal key length too long",
            "Unable to parse value length",
            "Value length too short",
            "Value length too long",
            "ProtectionInfo mismatch"]:
        fail("validate messages record mismatch")

    # The model behaviour re-derives the records.
    sys.path.insert(0, str(ROOT / "tools"))
    import record_write_115 as model
    if model.TYPE_VALUE != 1:
        fail("model type value mismatch")
    if model.TRAILER_TYPE != 0x16:
        fail("model trailer type mismatch")
    if model.INLINE_LIMIT != 0xC8:
        fail("model inline limit mismatch")
    if model.SEED_SHIFTED_TRAILER != 0x77A00858DDD37F21:
        fail("model shifted-trailer seed mismatch")
    if model.SEED_VALUE != 0xD28AAD72F49BD50B:
        fail("model value seed mismatch")
    if model.SEED_TAG_BYTE != 0xA5155AE5E937AA16:
        fail("model tag-byte seed mismatch")
    if model.STATS_ARM1 != 0x27 or model.STATS_ARM2 != 0x25:
        fail("model stats codes mismatch")
    if model.RWLOCK_OK != (0, 0x10, 0x6E):
        fail("model rwlock rc set mismatch")
    if model.encode_varint32(0x80) != b"\x80\x01":
        fail("model varint encode mismatch")
    built = model.build_internal_key(b"hello", 0x1234)
    if built["bytes"][:1] != b"\x0d" or built["bytes"][1:6] != b"hello":
        fail("model key build mismatch")
    if int.from_bytes(built["bytes"][6:14], "little") != ((0x1234 << 8) | 0x16):
        fail("model key trailer mismatch")
    if model.build_internal_key(bytes(187), 1)["inline"] is not True:
        fail("model inline boundary mismatch")
    if model.build_internal_key(bytes(188), 1)["inline"] is not False:
        fail("model heap boundary mismatch")
    print("records ok (census, got, main, key build, key len, "
          "varint, rwlock, literals, model)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_record_write_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "ALL 118 CHECKS PASSED" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (118 checks)")


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
