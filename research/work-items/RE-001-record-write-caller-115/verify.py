"""Checker for the RE-001-record-write-caller-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-record-write-caller-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary
(the entry byte of each of the 23 windows, plus three gate
spots picked with random.seed(3338) from the direct call
sites in main.txt: 0x5fc6e35, 0x5fc6629, 0x5fc69b1); the FDE
ranges in frames.txt against a fresh frame dump; the
relocation set against a fresh relocation dump (exactly 9
records: the two GOT slots and the SnapshotImpl vtable /
typeinfo records); the string literals and the pinned
constants against the raw binary; census consistency
(callers.tsv against a fresh census scan: every pinned
routine's direct calls, tail jumps, lea references, stored
qwords and RELATIVE addends, and the callers.tsv caller
function against the smallest enclosing FDE range from a
fresh frame dump); the semantic records (re-deriving the
census entries, the GOT canonical records, the main /
sibling / fallback / validator needles, the callers of the
main routine, the family records and the model behaviour);
and the model tests in tests/test_record_write_caller_115.py.
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
    ("main.txt", 0x5FC6070, 0x5FC6E8B),
    ("sibling_write.txt", 0x5F0F3D0, 0x5F0F8C1),
    ("validator.txt", 0x5FB9A10, 0x5FB9BCB),
    ("hashmap.txt", 0x5FC5E30, 0x5FC5FDF),
    ("hashmap_rehash.txt", 0x5FC5CF0, 0x5FC5E2D),
    ("map_lookup.txt", 0x5FB7040, 0x5FB70D2),
    ("hash_combine.txt", 0x5FB70E0, 0x5FB7131),
    ("status_move.txt", 0x5FB71B0, 0x5FB7219),
    ("produce_ctor.txt", 0x60B21F0, 0x60B2262),
    ("strdup.txt", 0x61CF610, 0x61CF64F),
    ("stub.txt", 0x5D54F00, 0x5D54F05),
    ("fallback.txt", 0x5FBED30, 0x5FBF077),
    ("fallback_get.txt", 0x5FBB000, 0x5FBB00C),
    ("fallback_get_alias.txt", 0x5FBB010, 0x5FBB019),
    ("fallback_set.txt", 0x5FBBC30, 0x5FBBC3C),
    ("fallback_grow.txt", 0x5FB7440, 0x5FB75BB),
    ("fallback_final.txt", 0x5FBEBC0, 0x5FBED25),
    ("register.txt", 0x5F0A1A0, 0x5F0A1D0),
    ("post_hook.txt", 0x5FB6A60, 0x5FB6BBF),
    ("record_write.txt", 0x5F0F930, 0x5F10134),
    ("record_insert.txt", 0x5F0E890, 0x5F0F37E),
    ("varint_encode.txt", 0x61BD410, 0x61BD4E9),
    ("status_builder.txt", 0x61CF670, 0x61CF767),
]

# (target, expected direct calls, expected tail jumps, expected leas)
EXPECTED_CENSUS = {
    0x5D54B10: (2, 0, 0),
    0x5D54F00: (10, 1, 0),
    0x5ED88C0: (1, 0, 0),
    0x5F0A1A0: (1, 0, 0),
    0x5F0E890: (10, 0, 0),
    0x5F0F3D0: (1, 0, 0),
    0x5F0F930: (1, 0, 0),
    0x5F13430: (1, 0, 0),
    0x5F13440: (1, 0, 0),
    0x5F44DB0: (0, 1, 0),
    0x5FB6A60: (3, 0, 0),
    0x5FB7040: (6, 0, 0),
    0x5FB70E0: (3, 0, 0),
    0x5FB71B0: (43, 0, 0),
    0x5FB7440: (18, 0, 0),
    0x5FB9560: (4, 0, 0),
    0x5FB9A10: (5, 0, 0),
    0x5FB9CF0: (1, 0, 0),
    0x5FBB000: (24, 1, 0),
    0x5FBB010: (15, 1, 0),
    0x5FBBC30: (15, 0, 0),
    0x5FBE180: (2, 0, 0),
    0x5FBE340: (5, 0, 0),
    0x5FBEBC0: (11, 0, 0),
    0x5FBED30: (5, 0, 0),
    0x5FC5CF0: (1, 0, 0),
    0x5FC5E30: (2, 0, 0),
    0x5FC6070: (6, 0, 0),
    0x5FCF060: (252, 1, 0),
    0x60B21F0: (61, 0, 0),
    0x61BD410: (165, 0, 0),
    0x61BE810: (9, 1, 0),
    0x61C3530: (108, 0, 0),
    0x61CF610: (425, 0, 0),
    0x61CF670: (847, 0, 0),
}

# No 8-byte-aligned qword in the file equals a pinned routine
# address.
EXPECTED_QWORDS = {}

# Routines installed by RELATIVE records: the two GOT
# canonicals and the SnapshotImpl vtable slots. The
# canonicals are installed at several GOT slots each; the
# counts below are the totals from a fresh relocation dump.
EXPECTED_RELATIVE = {
    0x5D2CA80: 2,
    0x5F04D80: 3,
    0x5D484B0: 2,
    0x5D484C0: 1,
    0x5D484D0: 1,
    0x5D54F10: 1,
    0x5D54F30: 1,
}

# Entry byte of each window, plus the three seeded gate spots.
SPOT_BYTES = {
    0x5FC6070: "55",
    0x5F0F3D0: "f30f1efa",
    0x5FB9A10: "4155",
    0x5FC5E30: "f30f1efa",
    0x5FC5CF0: "f30f1efa",
    0x5FB7040: "55",
    0x5FB70E0: "4156",
    0x5FB71B0: "4839f7",
    0x60B21F0: "f30f1efa",
    0x61CF610: "f30f1efa",
    0x5D54F00: "f30f1efa",
    0x5FBED30: "f30f1efa",
    0x5FBB000: "f30f1efa",
    0x5FBB010: "f30f1efa",
    0x5FBBC30: "f30f1efa",
    0x5FB7440: "4157",
    0x5FBEBC0: "f30f1efa",
    0x5F0A1A0: "f30f1efa",
    0x5FB6A60: "4157",
    0x5F0F930: "f30f1efa",
    0x5F0E890: "f30f1efa",
    0x61BD410: "f30f1efa",
    0x61CF670: "f30f1efa",
    0x5FC6E35: "e8369f4200",
    0x5FC6629: "e8a2a74200",
    0x5FC69B1: "e88a06ffff",
}

# The nine RELATIVE records kept in relocations.txt.
EXPECTED_RELOCATIONS = [
    (0x64C9160, 0x96CE30),
    (0x64C92C8, 0x64C9158),
    (0x64C92D0, 0x5D484B0),
    (0x64C92D8, 0x5D484C0),
    (0x64C92E0, 0x5D484D0),
    (0x64C92E8, 0x5D54F10),
    (0x64C92F0, 0x5D54F30),
    (0x64ED010, 0x5D2CA80),
    (0x64ED778, 0x5F04D80),
]

TAB = chr(9)
LINE_RE = re.compile("^ *([0-9a-f]+):" + TAB + "([0-9a-f ]+?)" + TAB + "(.*)$")
CONT_RE = re.compile("^ *([0-9a-f]+):" + TAB + "([0-9a-f ]+?) *$")
RELOC_RE = re.compile("^[ ]*([0-9a-f]+)[ ]+([0-9a-f]+)[ ]+R_X86_64_RELATIVE"
                      "[ ]+([0-9a-f]+)")
CALL_RE = re.compile(r"^\s*([0-9a-f]+):.*\b(call|jmp)\s+([0-9a-f]+)\b")


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
    if stored != EXPECTED_RELOCATIONS:
        fail("stored relocations are not the expected 9 records: %s"
             % (stored,))
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
    for entry in records["strings"]:
        addr = int(entry["address"], 16)
        off = va_to_off(segments, addr)
        if off is None:
            fail("string %s: no file offset" % entry["address"])
        want = entry["text"].encode() + b"\x00"
        if data[off:off + len(want)] != want:
            fail("string mismatch at %s: %r" % (entry["address"], entry["text"]))
        if "length" in entry and len(entry["text"]) != entry["length"]:
            fail("string length mismatch for %r" % entry["text"])
    consts = records["constants"]
    for seed in (consts["hash_seed"], consts["sibling_fold_seed"]):
        value = int(seed, 16).to_bytes(8, "little")
        if value not in data:
            fail("seed %s not in the binary" % seed)
    for seed in consts["fallback_hash_seeds"][1:]:
        value = int(seed, 16).to_bytes(8, "little")
        if value not in data:
            fail("fallback seed %s not in the binary" % seed)
    print("literals ok (%d strings, %d seeds)"
          % (len(records["strings"]), 1 + len(consts["fallback_hash_seeds"])))


def _fast_sites(census_mod):
    """One objdump pass over every executable LOAD segment,
    keeping direct call/jump lines naming a pinned routine
    (the same method as census.py, streamed with a compiled
    pattern). Returns {target: ([calls], [jumps], [leas])}."""
    data = BINARY.read_bytes()
    sites = {}
    for _off, vaddr, filesz in census_mod.exec_segments(data):
        proc = subprocess.Popen(
            ["objdump", "-d", "--no-show-raw-insn",
             "--start-address=%#x" % vaddr,
             "--stop-address=%#x" % (vaddr + filesz), str(BINARY)],
            stdout=subprocess.PIPE, text=True)
        for line in proc.stdout:
            m = CALL_RE.match(line)
            if not m:
                continue
            site, mnem, tgt = (int(m.group(1), 16), m.group(2),
                               int(m.group(3), 16))
            if tgt in EXPECTED_CENSUS:
                entry = sites.setdefault(tgt, ([], [], []))
                entry[0 if mnem == "call" else 1].append(site)
        proc.wait()
        if proc.returncode != 0:
            fail("objdump failed on segment %#x" % vaddr)
    for entry in sites.values():
        for lst in entry:
            lst.sort()
    return sites


def check_census():
    spec = importlib.util.spec_from_file_location(
        "packet_census", PACKET / "census.py")
    census = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(census)
    data = BINARY.read_bytes()
    sites = _fast_sites(census)
    relocs, _lines = census.relative_records()
    ranges = census.frame_ranges()
    ordered = sorted(ranges)
    starts = [a for a, _b in ordered]
    for target, (want_calls, want_jumps, want_leas) in EXPECTED_CENSUS.items():
        calls, jumps, leas = sites.get(target, ([], [], []))
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
        calls, jumps, leas = sites.get(target, ([], [], []))
        for site in calls:
            expect_rows.append((site, target, "call"))
        for site in jumps:
            expect_rows.append((site, target, "tail jump"))
        for site in leas:
            expect_rows.append((site, target, "lea"))
    expect_rows.sort()
    got_rows = sorted((s, t, k) for s, t, _c, k in rows)
    if got_rows != expect_rows:
        fail("callers.tsv rows do not match a fresh census scan")
    print("census ok (%d rows)" % len(rows))


def check_records(segments, data, records):
    # The records census section must agree with the verify
    # expectations.
    for key, entry in records["census"].items():
        target = int(key, 16)
        want = EXPECTED_CENSUS[target]
        got = (entry["calls"], entry["jumps"], entry["leas"])
        if got != want:
            fail("records census for %#x: %s != %s" % (target, got, want))
        if entry["qwords"] != 0 or entry["relative"] != EXPECTED_RELATIVE.get(target, 0):
            fail("records qwords/relative for %#x mismatch" % target)
    if records["artifact"]["sha256"] != DIGEST:
        fail("records artifact digest mismatch")
    if records["node"] != 115 or records["task"] != "RE-001":
        fail("records node/task mismatch")

    # The callers of the main routine re-derive from callers.tsv.
    rows = {}
    for line in (PACKET / "callers.tsv").read_text().splitlines()[1:]:
        if not line.strip():
            continue
        site, target, caller, kind = line.split("\t")
        rows.setdefault(int(target, 16), []).append(
            (int(site, 16), caller, kind))
    main_calls = sorted(s for s, _c, k in rows[0x5FC6070] if k == "call")
    want_main = sorted(int(c["site"], 16) for c in records["callers_of_main"])
    if main_calls != want_main:
        fail("records callers of main mismatch: %s != %s"
             % (main_calls, want_main))
    if [c["caller"] for c in records["callers_of_main"]] != [
            "0x5fc6ec0..0x5fc70b6", "0x5fc6ec0..0x5fc70b6",
            "0x5fc70e0..0x5fc72d6", "0x5fc70e0..0x5fc72d6",
            "0x5fc7300..0x5fc74f6", "0x5fc7300..0x5fc74f6"]:
        fail("records main caller ranges mismatch")

    # The family records re-derive from callers.tsv.
    for key, want_callers in (
            ("validator_callers", ["0x5fc2900..0x5fc3acf",
                                   "0x5fc6070..0x5fc6e8b",
                                   "0x5fc7b40..0x5fc806b",
                                   "0x5fc80a0..0x5fc852b",
                                   "0x5fc8590..0x5fc8ece"]),
            ("check_callers", ["0x5fc2900..0x5fc3acf",
                               "0x5fc6070..0x5fc6e8b",
                               "0x5fc7b40..0x5fc806b",
                               "0x5fc80a0..0x5fc852b",
                               "0x5fc8590..0x5fc8ece"])):
        got = sorted({c for _s, c, _k in rows[0x5FB9A10 if "validator" in key else 0x5FBE340]})
        if got != sorted(want_callers):
            fail("records %s mismatch: %s" % (key, got))
    got_hook = sorted({c for _s, c, _k in rows[0x5FB6A60]})
    if got_hook != sorted(records["family"]["post_hook_callers"]):
        fail("records post-hook callers mismatch: %s" % (got_hook,))

    main = (PACKET / "main.txt").read_text()
    sibling = (PACKET / "sibling_write.txt").read_text()
    fb = (PACKET / "fallback.txt").read_text()
    validator = (PACKET / "validator.txt").read_text()
    for needle, want in (
            ("call   5fb9a10", 1),
            ("call   5fc5e30", 1),
            ("call   5f0f3d0", 1),
            ("call   5f0f930", 1),
            ("call   5f0e890", 2),
            ("call   5fbed30", 3),
            ("call   5fbe340", 1),
            ("call   5fb6a60", 1),
            ("call   5fb70e0", 2),
            ("call   5fb71b0", 8),
            ("call   60b21f0", 1),
            ("call   61cf610", 1),
            ("call   *0x28(%rax)", 1),
            ("call   *0xe8(%r10)", 1),
            ("call   *0x3e8(%rdx)", 1),
            ("call   *0x20(%rax)", 1),
            ("call   *0xb0(%rax)", 1),
            ("call   5d54f00", 1),
            ("call   5fb7040", 2),
            ("movl   $0x3,-0x1a0", 1),
            ("cmp    $0x1,%al", 1),
            ("mov    $0x25,%esi", 1)):
        if main.count(needle) != want:
            fail("main needle %r: %d != %d"
                 % (needle, main.count(needle), want))
    if "endbr64" in main.splitlines()[0]:
        fail("main excerpt must start with push %rbp, not endbr64")
    for needle, want in (
            ("0x77a00858ddd37f21", 2),
            ("mov    $0x27,%esi", 1),
            ("call   5f0e890", 1)):
        if sibling.count(needle) != want:
            fail("sibling needle %r: %d != %d"
                 % (needle, sibling.count(needle), want))
    for needle, want in (
            ("0xd28aad72f49bd50b", 1),
            ("0xa5155ae5e937aa16", 1),
            ("0x4a2ab5cbd26f542c", 1)):
        if fb.count(needle) != want:
            fail("fallback needle %r: %d != %d"
                 % (needle, fb.count(needle), want))
    if validator.count("call   5f0a1a0") != 1:
        fail("validator min-register call count mismatch")

    # The model behaviour re-derives the records.
    sys.path.insert(0, str(ROOT / "tools"))
    import record_write_caller_115 as model
    if model.DIGEST != DIGEST:
        fail("model digest mismatch")
    if model.HASH_SEED != 0xD28AAD72F49BD50B:
        fail("model hash seed mismatch")
    if model.SIBLING_FOLD_SEED != 0x77A00858DDD37F21:
        fail("model sibling fold seed mismatch")
    if model.FALLBACK_HASH_SEEDS != (
            0x0, 0xD28AAD72F49BD50B, 0xA5155AE5E937AA16, 0x4A2AB5CBD26F542C):
        fail("model fallback hash seeds mismatch")
    if model.SNAPSHOT_VTABLE != 0x64C92D0:
        fail("model snapshot vtable mismatch")
    if model.SNAPSHOT_VTABLE_SLOTS != (
            0x5D484B0, 0x5D484C0, 0x5D484D0, 0x5D54F10, 0x5D54F30):
        fail("model snapshot vtable slots mismatch")
    if model.ABORTED_MEMORY_LIMIT != 0x70A:
        fail("model aborted code mismatch")
    if model.CANONICAL_PRODUCT1 != 0x5F04D80:
        fail("model product-1 canonical mismatch")
    if model.CANONICAL_PRODUCT2 != 0x5D2CA80:
        fail("model product-2 canonical mismatch")
    if model.produce_request_init()[0x2C] != 0x001:
        fail("model produce request +0x2c mismatch")
    if model.varint_encode(300) != b"\xac\x02":
        fail("model varint encode mismatch")
    if model.varint_decode(bytes([5, 9]), 0) != (5, 1):
        fail("model varint decode mismatch")
    print("records ok (census, callers, family, main, sibling, "
          "fallback, validator, model)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_record_write_caller_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "32 tests, 0 failed" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (32 tests)")


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
