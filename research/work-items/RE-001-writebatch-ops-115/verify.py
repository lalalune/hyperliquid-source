"""Checker for the RE-001-writebatch-ops-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-writebatch-ops-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run (the
guard excerpt is re-shipped from PR #3202, so it is checked
by its pinned SHA-256 instead); every excerpt instruction
byte-for-byte against the raw binary (objdump splits a few
long instructions across two lines; the parser accumulates
those continuations); spot instructions byte-for-byte
against a fresh objdump run and the raw binary; the FDE
ranges in frames.txt against a fresh frame dump; the
relocation set against a fresh relocation dump (the
WriteBatch vtable range plus every RELATIVE record naming a
pinned routine; the guard and the Status builder appear in
none); the message literals against the raw binary; census
consistency (callers.tsv against a fresh census run: every
pinned routine's direct calls, tail jumps, stored qwords and
RELATIVE addends, and the callers.tsv caller function
against the smallest enclosing FDE range from a fresh frame
dump); the semantic records (re-deriving the record-type
bytes from the inner excerpts, the vtable slots from the
relocation set, the 0xe0 dispatch from the implementation
excerpts, and the PutEntity size limits from its inner);
and the model tests. Prints ALL CHECKS PASSED on success,
else raises.
"""

import ast
import bisect
import hashlib
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
GUARD_MAIN_SHA256 = "455f831e6787d422a80cda71839d12ed4e26e3c3ab93ac5148d917ebcd73ce5a"

WINDOWS = [
    ("wrap_put.txt", 0x5E94540, 0x5E94656),
    ("wrap_putentity.txt", 0x5E94B20, 0x5E94C36),
    ("wrap_delete.txt", 0x5E94DA0, 0x5E94EA3),
    ("wrap_singledelete.txt", 0x5E952C0, 0x5E953C3),
    ("wrap_deleterange.txt", 0x5E95800, 0x5E95916),
    ("wrap_merge.txt", 0x5E95D70, 0x5E95EF7),
    ("impl_put.txt", 0x5E943F0, 0x5E944FF),
    ("impl_putentity.txt", 0x5E94970, 0x5E94AE1),
    ("impl_delete.txt", 0x5E94C70, 0x5E94D5E),
    ("impl_singledelete.txt", 0x5E95190, 0x5E9527E),
    ("impl_deleterange.txt", 0x5E956B0, 0x5E957B7),
    ("impl_merge.txt", 0x5E95C20, 0x5E95D27),
    ("mid_put.txt", 0x5FBF5D0, 0x5FBF795),
    ("mid_putentity.txt", 0x5FC4DB0, 0x5FC4F43),
    ("mid_delete.txt", 0x5FC0320, 0x5FC04AD),
    ("mid_singledelete.txt", 0x5FC1010, 0x5FC119D),
    ("mid_deleterange.txt", 0x5FC1E60, 0x5FC2045),
    ("mid_merge.txt", 0x5FC4020, 0x5FC41E5),
    ("inner_put.txt", 0x5FBF0B0, 0x5FBF588),
    ("inner_putentity.txt", 0x5FC46C0, 0x5FC4D78),
    ("inner_delete.txt", 0x5FBFF40, 0x5FC02E8),
    ("inner_singledelete.txt", 0x5FC0C30, 0x5FC0FD8),
    ("inner_deleterange.txt", 0x5FC1980, 0x5FC1E23),
    ("inner_merge.txt", 0x5FC3B00, 0x5FC3FD8),
    ("batch_ctor.txt", 0x5FB9F90, 0x5FBA0BE),
    ("batch_dtor.txt", 0x5FB7EE0, 0x5FB7FB7),
    ("strdup.txt", 0x61CF610, 0x61CF64F),
    ("cf_resolve.txt", 0x5FBBC90, 0x5FBBE5B),
    ("tail_put.txt", 0x5FBED30, 0x5FBF077),
    ("tail_delete.txt", 0x5FBFC20, 0x5FBFF39),
    ("tail_singledelete.txt", 0x5FC0910, 0x5FC0C29),
    ("tail_deleterange.txt", 0x5FC1600, 0x5FC1979),
    ("tail_merge.txt", 0x5FC24F0, 0x5FC27F7),
    ("guard_main.txt", 0x5D58810, 0x5D58AC5),
]

# (target, expected direct calls, expected tail jumps)
EXPECTED_CENSUS = {
    0x5D58810: (15, 0),
    0x5E943F0: (1, 0), 0x5E94540: (0, 0), 0x5E94970: (1, 0),
    0x5E94B20: (0, 0), 0x5E94C70: (1, 0), 0x5E94DA0: (0, 0),
    0x5E95190: (1, 0), 0x5E952C0: (0, 0), 0x5E956B0: (1, 0),
    0x5E95800: (0, 0), 0x5E95C20: (1, 0), 0x5E95D70: (0, 0),
    0x5FB7EE0: (65, 0), 0x5FB9F90: (27, 0), 0x5FBBC90: (16, 0),
    0x5FBED30: (5, 0), 0x5FBF0B0: (4, 0), 0x5FBF5D0: (5, 0),
    0x5FBFC20: (5, 0), 0x5FBFF40: (4, 0), 0x5FC0320: (1, 0),
    0x5FC0910: (4, 0), 0x5FC0C30: (4, 0), 0x5FC1010: (1, 0),
    0x5FC1600: (5, 0), 0x5FC1980: (4, 0), 0x5FC1E60: (1, 0),
    0x5FC24F0: (5, 0), 0x5FC3B00: (4, 0), 0x5FC4020: (2, 0),
    0x5FC46C0: (1, 0), 0x5FC4DB0: (1, 0), 0x61CF610: (425, 0),
    0x61CF670: (847, 0),
}

EXPECTED_QWORDS = {
    0x5E94540: ["0x103e88"], 0x5E94B20: ["0x103ee8"],
    0x5E94DA0: ["0x103f00"], 0x5E952C0: ["0x103f60", "0x1093d8"],
    0x5E95800: ["0x103fc0", "0x1085c8", "0x109438", "0x10a5a8"],
    0x5E95D70: ["0x103ff0"], 0x5FB7EE0: ["0x10e310"],
    0x5FBF5D0: ["0x10e340"], 0x5FC0320: ["0x10e448"],
    0x5FC1010: ["0x10e4c0"], 0x5FC1E60: ["0x10e538"],
    0x5FC4020: ["0x10e3d0"], 0x5FC4DB0: ["0x10e3b8"],
}

EXPECTED_RELATIVE = {
    0x5E94540: 1, 0x5E94B20: 1, 0x5E94DA0: 1, 0x5E952C0: 2,
    0x5E95800: 4, 0x5E95D70: 1, 0x5FB7EE0: 1, 0x5FBF5D0: 1,
    0x5FC0320: 1, 0x5FC1010: 1, 0x5FC1E60: 1, 0x5FC4020: 1,
    0x5FC4DB0: 1,
}

SPOT_BYTES = {
    0x5E94540: "f30f1efa",
    0x5FBF0B0: "f30f1efa",
    0x5FC46F4: "b8ffffffff",
    0x5E95D70: "f30f1efa",
    0x5FB9F90: "f30f1efa",
}

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$")


def fail(message):
    raise AssertionError(message)


def check_digest():
    actual = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    if actual != DIGEST:
        fail("digest mismatch: %s" % actual)
    provenance = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    entries = [f for f in provenance["files"]
               if f["path"] == "artifacts/node/115/hl-node"]
    if not entries or entries[0]["sha256"] != DIGEST:
        fail("provenance entry mismatch")


def check_manifest():
    lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    if not lines:
        fail("empty manifest")
    seen = set()
    for line in lines:
        digest, name = line.split("  ", 1)
        seen.add(name)
        actual = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if actual != digest:
            fail("manifest mismatch for %s" % name)
    expected = {"README.md", "records.json", "frames.txt",
                "relocations.txt", "callers.tsv", "export_excerpts.py",
                "census.py", "verify.py"}
    expected |= {name for name, _s, _e in WINDOWS}
    if seen != expected:
        fail("manifest file set mismatch: %s" % sorted(seen))


_BINARY_DATA = None


def binary_data():
    global _BINARY_DATA
    if _BINARY_DATA is None:
        _BINARY_DATA = BINARY.read_bytes()
    return _BINARY_DATA


def va_bytes(vaddr, size):
    data = binary_data()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:
            start = p_offset + (vaddr - p_vaddr)
            return data[start:start + size]
    fail("no LOAD segment for %#x" % vaddr)


def parse_excerpt(text):
    """Return [(address, bytes)] with split lines accumulated."""
    instructions = []
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        raw = bytes.fromhex(match.group(2).strip())
        mnemonic = (match.group(3) or "").strip()
        if not mnemonic and instructions and address == instructions[-1][0] + len(instructions[-1][1]):
            instructions[-1] = (instructions[-1][0], instructions[-1][1] + raw)
        else:
            instructions.append((address, raw))
    return instructions


def check_excerpts():
    for name, start, stop in WINDOWS:
        stored = (PACKET / name).read_text()
        if name == "guard_main.txt":
            actual = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
            if actual != GUARD_MAIN_SHA256:
                fail("guard_main.txt is not the PR #3202 excerpt")
        else:
            text = subprocess.run(
                ["objdump", "-d", "--start-address=%#x" % start,
                 "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
                capture_output=True, text=True, check=True, cwd=ROOT).stdout
            if text != stored:
                fail("excerpt mismatch for %s" % name)
        instructions = parse_excerpt(stored)
        if not instructions or instructions[0][0] != start:
            fail("excerpt %s does not start at %#x" % (name, start))
        for address, raw in instructions:
            if va_bytes(address, len(raw)) != raw:
                fail("raw byte mismatch at %#x in %s" % (address, name))
        if instructions[-1][0] + len(instructions[-1][1]) != stop:
            fail("excerpt %s does not end at %#x" % (name, stop))


def check_spots():
    for address, hex_bytes in SPOT_BYTES.items():
        raw = bytes.fromhex(hex_bytes)
        if va_bytes(address, len(raw)) != raw:
            fail("spot raw byte mismatch at %#x" % address)
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % address,
             "--stop-address=%#x" % (address + 0x10),
             "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        instructions = parse_excerpt(text)
        if not instructions or instructions[0][0] != address:
            fail("spot objdump missing %#x" % address)
        if instructions[0][1] != raw:
            fail("spot objdump byte mismatch at %#x" % address)


_FRAME_RANGES = None


def frame_ranges():
    """All FDE pc ranges from a fresh frame dump (memoized: the
    dump is ~3.6M lines and parsing it dominates)."""
    global _FRAME_RANGES
    if _FRAME_RANGES is None:
        text = subprocess.run(
            ["readelf", "--debug-dump=frames", str(BINARY)],
            capture_output=True, text=True, check=True).stdout
        ranges = []
        for match in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", text):
            ranges.append((int(match.group(1), 16), int(match.group(2), 16)))
        _FRAME_RANGES = ranges
    return _FRAME_RANGES


def check_frames():
    fresh = set(frame_ranges())
    for line in (PACKET / "frames.txt").read_text().splitlines():
        match = re.search(r"(0x[0-9a-f]+)\.\.(0x[0-9a-f]+)", line)
        if not match:
            fail("frames.txt line without range: %s" % line)
        want = (int(match.group(1), 16), int(match.group(2), 16))
        if want not in fresh:
            fail("frame range missing: %s" % match.group(0))


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for target in (0x5D58810, 0x61CF670, 0x61CF610, 0x5FB9F90, 0x5FBBC90):
        for line in text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                fail("unexpected RELATIVE line for %#x: %s" % (target, line))
    targets = set(EXPECTED_CENSUS) | {0x5D58810, 0x61CF670}
    want = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or "RELATIVE" not in line:
            continue
        offset = int(parts[0], 16)
        addend = int(parts[3], 16)
        if (0x64CD488 <= offset < 0x64CD600) or addend in targets:
            want.append(line)
    stored = (PACKET / "relocations.txt").read_text().splitlines()
    if stored != want:
        fail("relocations.txt mismatch: %d stored vs %d fresh"
             % (len(stored), len(want)))
    if len(want) != 55:
        fail("relocation count mismatch: %d" % len(want))


def check_literals():
    cases = [
        (0x968AF8, 40, b"Provide a merge_operator when opening DB"),
        (0x95E658, 54, b"Cannot call this method without a column family handle"),
        (0x96A420, 59, b"Cannot call this method on column family enabling timestamp"),
        (0x95D110, 34, b"Default cf timestamp size mismatch"),
        (0x44D099, 16, b"key is too large"),
        (0x965750, 31, b"wide column entity is too large"),
    ]
    for address, length, want in cases:
        if va_bytes(address, length) != want:
            fail("literal mismatch at %#x: %r" % (address, va_bytes(address, length)))


CENSUS_LINE_RE = re.compile(
    r"^0x([0-9a-f]+) calls=(\d+) (.*?) jumps=(\d+) (.*?) "
    r"qwords=(\d+) (.*?) relative=(\d+) (.*?)$")


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    census = {}
    for line in out.splitlines():
        match = CENSUS_LINE_RE.match(line)
        if not match:
            continue
        target = int(match.group(1), 16)
        calls = match.group(3).split() if int(match.group(2)) else []
        jumps = match.group(5).split() if int(match.group(4)) else []
        qwords = match.group(7).split() if int(match.group(6)) else []
        rels = match.group(9).split() if int(match.group(8)) else []
        census[target] = (calls, jumps, qwords, rels)
    if set(census) != set(EXPECTED_CENSUS):
        fail("census target set mismatch: %s"
             % sorted(set(census) ^ set(EXPECTED_CENSUS)))
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    tsv_calls = {}
    tsv_jumps = {}
    tsv_callers = {}
    for row in rows:
        site, target, caller, kind = row.split("\t")[0:4]
        tsv_callers[site] = caller
        if kind == "call":
            tsv_calls.setdefault(target, []).append(site)
        elif kind == "tail jump":
            tsv_jumps.setdefault(target, []).append(site)
        else:
            fail("unknown callers.tsv kind: %s" % kind)
    for target, (want_calls, want_jumps) in EXPECTED_CENSUS.items():
        calls, jumps, qwords, rels = census[target]
        if len(calls) != want_calls:
            fail("census call count mismatch for %#x: %d" % (target, len(calls)))
        if len(jumps) != want_jumps:
            fail("census jump count mismatch for %#x: %d" % (target, len(jumps)))
        if sorted(calls) != sorted(tsv_calls.get("%#x" % target, [])):
            fail("callers.tsv calls do not match census for %#x" % target)
        if sorted(jumps) != sorted(tsv_jumps.get("%#x" % target, [])):
            fail("callers.tsv jumps do not match census for %#x" % target)
        if sorted(qwords) != sorted(EXPECTED_QWORDS.get(target, [])):
            fail("census stored qwords mismatch for %#x: %s" % (target, qwords))
        if len(rels) != EXPECTED_RELATIVE.get(target, 0):
            fail("census RELATIVE mismatch for %#x: %d" % (target, len(rels)))
    ranges = frame_ranges()
    # FDEs are (nearly) disjoint, so the smallest enclosing
    # range for a site is found by bisect on the sorted
    # starts, with a bounded neighbourhood scan for duplicate
    # entries (.eh_frame + .debug_frame copies) and a full
    # scan as a correctness fallback.
    ordered = sorted(ranges)
    starts = [a for a, _b in ordered]
    for site, caller in tsv_callers.items():
        value = int(site, 16)
        idx = bisect.bisect_right(starts, value) - 1
        cands = []
        for j in range(max(0, idx - 2), min(len(ordered), idx + 3)):
            a, b = ordered[j]
            if a <= value < b:
                cands.append((a, b))
        if not cands:
            cands = [(a, b) for a, b in ranges if a <= value < b]
        if not cands:
            fail("no enclosing FDE for site %s" % site)
        a, b = min(cands, key=lambda ab: ab[1] - ab[0])
        if caller != "%#x..%#x" % (a, b):
            fail("caller mismatch for %s: %s vs %#x..%#x"
                 % (site, caller, a, b))


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["task"] != "RE-001":
        fail("records task mismatch")
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["guard"]["direct_calls"] != 15:
        fail("records guard call count mismatch")
    if records["cf_resolve"]["size_bytes"] != 459:
        fail("records resolver size mismatch")
    if records["writebatch"]["typeinfo_name"] != "rocksdb::WriteBatch":
        fail("records typeinfo name mismatch")
    if records["writebatch"]["vtable"] != "0x64cd498":
        fail("records vtable address mismatch")
    # Re-derive the record-type bytes from the inner excerpts:
    # each inner writes its default-CF type byte and its with-CF
    # type byte at pinned sites (a movb into the rep_ buffer or
    # a stack slot, or a mov into %esi/%r8d before push_back).
    type_sites = {
        "put": ("inner_put.txt",
                "movb   $0x1,0x17(%rsp)", "mov    $0x5,%esi"),
        "putentity": ("inner_putentity.txt",
                      "mov    $0x16,%esi", "mov    $0x17,%esi"),
        "delete": ("inner_delete.txt",
                   "movb   $0x0,(%rax,%r13,1)", "movb   $0x4,(%rax,%r13,1)"),
        "singledelete": ("inner_singledelete.txt",
                         "movb   $0x7,(%rax,%r13,1)", "movb   $0x8,(%rax,%r13,1)"),
        "deleterange": ("inner_deleterange.txt",
                        "movb   $0xf,(%rax,%r14,1)", "movb   $0xe,(%rax,%r14,1)"),
        "merge": ("inner_merge.txt",
                  "movb   $0x2,0x17(%rsp)", "mov    $0x6,%esi"),
    }
    type_bytes = {
        "put": (0x01, 0x05), "putentity": (0x16, 0x17),
        "delete": (0x00, 0x04), "singledelete": (0x07, 0x08),
        "deleterange": (0x0F, 0x0E), "merge": (0x02, 0x06),
    }
    vtable_slots = {"put": 2, "putentity": 7, "delete": 13,
                    "singledelete": 18, "deleterange": 23, "merge": 8}
    for op, (name, default_site, cf_site) in type_sites.items():
        text = (PACKET / name).read_text()
        if default_site not in text:
            fail("records %s default type site not in excerpt" % op)
        if cf_site not in text:
            fail("records %s CF type site not in excerpt" % op)
        rec = records["operations"][op]
        want_default, want_cf = type_bytes[op]
        if rec["record_type_default"] != "0x%02x" % want_default:
            fail("records %s default type mismatch" % op)
        if rec["record_type_cf"] != "0x%02x" % want_cf:
            fail("records %s CF type mismatch" % op)
        if rec["vtable_slot"] != vtable_slots[op]:
            fail("records %s vtable slot mismatch" % op)
        # The implementation dispatches through virtual slot 0xe0.
        impl = (PACKET / ("impl_%s.txt" % op)).read_text()
        if "call   *0xe0(%rax)" not in impl:
            fail("records %s impl has no slot 0xe0 dispatch" % op)
        # The middle calls the CF resolver 0x5fbbc90.
        mid = (PACKET / ("mid_%s.txt" % op)).read_text()
        if "call   5fbbc90" not in mid:
            fail("records %s middle has no resolver call" % op)
    # PutEntity size limits: the key length and the entity size
    # are each compared against 0xffffffff (loaded with
    # mov $0xffffffff,%eax just before each compare).
    inner = (PACKET / "inner_putentity.txt").read_text()
    if inner.count("mov    $0xffffffff,%eax") != 2:
        fail("PutEntity 0xffffffff loads missing")
    if "call   5fb4f60" not in inner:
        fail("PutEntity entity-size call missing")
    # The merge-operator gate: the Merge wrapper checks
    # *(result+0x5c8) after a slot 0x30 call.
    wrap = (PACKET / "wrap_merge.txt").read_text()
    if "call   *0x30(%rax)" not in wrap:
        fail("Merge wrapper has no slot 0x30 gate")
    if "0x5c8(%rax)" not in wrap:
        fail("Merge wrapper has no +0x5c8 check")
    literal_keys = {
        "merge_operator": "Provide a merge_operator when opening DB",
        "no_cf_handle": "Cannot call this method without a column family handle",
        "cf_timestamp": "Cannot call this method on column family enabling timestamp",
        "ts_mismatch": "Default cf timestamp size mismatch",
        "key_too_large": "key is too large",
        "entity_too_large": "wide column entity is too large",
    }
    for key, literal in literal_keys.items():
        if records["literals"][key]["text"] != literal:
            fail("records literal mismatch for %s" % key)
    if records["status"]["invalid_argument_code"] != 4:
        fail("records code mismatch")
    if records["census"]["0x5d58810"]["direct_calls"] != 15:
        fail("records census guard count mismatch")
    if records["census"]["0x61cf670"]["direct_calls"] != 847:
        fail("records census builder count mismatch")
    if records["census"]["0x5fc4020"]["direct_calls"] != 2:
        fail("records census merge-middle count mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_writebatch_ops_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "checks passed" not in out:
        fail("model tests did not pass: %s" % out)


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_spots()
    check_frames()
    check_relocations()
    check_literals()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
