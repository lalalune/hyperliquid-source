"""Checker for the RE-001-pow10-scale-01110-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-pow10-scale-01110-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the panic strings and the two static location
records against the raw binary and the relocation records;
the FDE ranges in frames.txt against a fresh frame dump; the
relocation records in relocations.txt against a fresh
relocation dump; census consistency (callers.tsv against a
fresh scan: 24 direct calls, 0 tail jumps, no stored qwords,
no RELATIVE addends for the routine address, 0 internal calls,
0 internal direct tail jumps, 2 internal indirect calls,
0 internal indirect tail jumps) and the callers.tsv caller
function against the smallest enclosing FDE range from a fresh
frame dump; the semantic records; and the model tests. Prints
ALL CHECKS PASSED on success, else raises.
"""

import ast
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

WINDOWS = [
    ("main.txt", 0x5A01110, 0x5A0130B),
    ("panic_unwrap.txt", 0x1680C10, 0x1680C29),
    ("panic_encode.txt", 0x1680E60, 0x1680E72),
    ("panic_unwind.txt", 0x1680E80, 0x1680EAC),
    ("panic_sub_overflow.txt", 0x1681E40, 0x1681E59),
]

EXPECTED_CALLS = {
    0x5A01110: ["0x517ab94", "0x517ad51", "0x517bc84", "0x517be41",
                "0x543ebf0", "0x58f044b", "0x58f291b", "0x58f4e1a",
                "0x58f520a", "0x58f55fa", "0x58f59ea", "0x58fca65",
                "0x5900365", "0x5902669", "0x5902713", "0x590a3c9",
                "0x590a473", "0x591bb71", "0x591cb11", "0x5a00f53",
                "0x5a2196a", "0x5a2232a", "0x5a30b92", "0x5a33d12"],
}

EXPECTED_JUMPS = {0x5A01110: []}

EXPECTED_INTERNAL_CALLS = []
EXPECTED_INTERNAL_JUMPS = []
EXPECTED_INTERNAL_INDIRECT_CALLS = ["0x5a012f8", "0x5a01305"]
EXPECTED_INTERNAL_INDIRECT_JUMPS = []

SPOT_BYTES = {
    0x5A01110: "50",
    0x5A01116: "4881faa0860100",
    0x5A01263: "48ba4b598638d6c56d34",
    0x5A01270: "48f7e2",
    0x5A01285: "0f92c0",
    0x5A0129A: "0fb644301d",
    0x5A012E2: "480f42ca",
    0x5A012F8: "ff1532e5ad00",
    0x5A01305: "ff153de5ad00",
    0x1680C10: "55",
    0x1681E40: "55",
}

EXPECTED_RELOCATIONS = {
    0x64DF830: 0x1680C10,
    0x64DF848: 0x1681E40,
    0x64DF730: 0x1680E60,
    0x64DF6B8: 0x1680E80,
    0x64768A8: 0x437DF7,
    0x6478258: 0x437DF7,
}

FILE_STRING = (0x437DF7, b"l1/src/perp_meta.rs")
UNWRAP_MESSAGE = (0x46E992, b"called `Option::unwrap()` on a `None` value")
SUB_MESSAGE = (0x46EB80, b"attempt to subtract with overflow")
LOCATION_RECORDS = [
    (0x64768A8, 163, 38),
    (0x6478258, 287, 28),
]

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$")


def fail(message):
    raise AssertionError(message)


def load_segments(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1:
            segments.append((p_vaddr, p_offset, p_filesz))
    return segments


def read_at(data, segments, vaddr, size):
    for p_vaddr, p_offset, p_filesz in segments:
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            start = p_offset + (vaddr - p_vaddr)
            return data[start:start + size]
    fail("address %#x is not file-backed" % vaddr)


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
    expected = {"README.md", "records.json", "main.txt",
                "panic_unwrap.txt", "panic_encode.txt",
                "panic_unwind.txt", "panic_sub_overflow.txt",
                "frames.txt", "relocations.txt", "callers.tsv",
                "export_excerpts.py", "census.py", "verify.py"}
    if seen != expected:
        fail("manifest file set mismatch: %s" % sorted(seen))


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
    data = BINARY.read_bytes()
    segments = load_segments(data)
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        stored = (PACKET / name).read_text()
        if text != stored:
            fail("excerpt mismatch for %s" % name)
        instructions = parse_excerpt(stored)
        if not instructions or instructions[0][0] != start:
            fail("excerpt %s does not start at %#x" % (name, start))
        for address, raw in instructions:
            if read_at(data, segments, address, len(raw)) != raw:
                fail("raw byte mismatch at %#x in %s" % (address, name))
        if instructions[-1][0] + len(instructions[-1][1]) != stop:
            fail("excerpt %s does not end at %#x" % (name, stop))


def check_spots():
    data = BINARY.read_bytes()
    segments = load_segments(data)
    for address, hex_bytes in SPOT_BYTES.items():
        raw = bytes.fromhex(hex_bytes)
        if read_at(data, segments, address, len(raw)) != raw:
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


def relocation_map():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    result = {}
    for line in text.splitlines():
        match = re.match(
            r"([0-9a-f]{12})\s+\S+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", line)
        if match:
            result[int(match.group(1), 16)] = int(match.group(2), 16)
    return result, text


def check_strings_and_locations():
    data = BINARY.read_bytes()
    segments = load_segments(data)
    for address, want in (FILE_STRING, UNWRAP_MESSAGE, SUB_MESSAGE):
        if read_at(data, segments, address, len(want)) != want:
            fail("string mismatch at %#x" % address)
    relocations, _text = relocation_map()
    for slot, target in EXPECTED_RELOCATIONS.items():
        if relocations.get(slot) != target:
            fail("relocation mismatch at %#x: %s" % (slot, relocations.get(slot)))
    for record, line, col in LOCATION_RECORDS:
        first = struct.unpack(
            "<Q", read_at(data, segments, record, 8))[0]
        if first != 0:
            fail("location record %#x file pointer is not the "
                 "pre-relocation 0" % record)
        length = struct.unpack(
            "<Q", read_at(data, segments, record + 8, 8))[0]
        if length != len(FILE_STRING[1]):
            fail("location record %#x file length mismatch" % record)
        packed = struct.unpack(
            "<Q", read_at(data, segments, record + 16, 8))[0]
        if packed != (line | (col << 32)):
            fail("location record %#x line/col mismatch: %#x"
                 % (record, packed))


def check_frames():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        match = re.search(r"pc=([0-9a-f]+\.\.[0-9a-f]+)", line)
        if not match:
            fail("frames.txt line without pc range: %s" % line)
        if ("pc=" + match.group(1)) not in text:
            fail("frame range missing: %s" % match.group(1))


def check_relocations():
    _relocations, text = relocation_map()
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        if line not in text:
            fail("relocation record missing from fresh dump: %s" % line)


def frame_ranges():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    ranges = []
    for match in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", text):
        ranges.append((int(match.group(1), 16), int(match.group(2), 16)))
    return ranges


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
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
    for target, want_calls in EXPECTED_CALLS.items():
        match = re.search(
            r"routine %#x: direct calls: (\[.*\])" % target, out)
        if not match:
            fail("census output has no direct-calls list for %#x" % target)
        calls = ast.literal_eval(match.group(1))
        if sorted(calls) != sorted(want_calls):
            fail("census calls mismatch for %#x: %s vs %s"
                 % (target, calls, want_calls))
        if sorted(calls) != sorted(tsv_calls.get("%#x" % target, [])):
            fail("callers.tsv calls do not match census for %#x" % target)
        want_jumps = EXPECTED_JUMPS[target]
        match = re.search(
            r"routine %#x: tail jumps: (\[.*\])" % target, out)
        if not match:
            fail("census jumps mismatch for %#x" % target)
        jumps = ast.literal_eval(match.group(1))
        if sorted(jumps) != sorted(want_jumps):
            fail("census jumps mismatch for %#x: %s vs %s"
                 % (target, jumps, want_jumps))
        if sorted(jumps) != sorted(tsv_jumps.get("%#x" % target, [])):
            fail("callers.tsv jumps do not match census for %#x" % target)
        for label, want in (
                ("internal calls", EXPECTED_INTERNAL_CALLS),
                ("internal tail jumps", EXPECTED_INTERNAL_JUMPS),
                ("internal indirect calls", EXPECTED_INTERNAL_INDIRECT_CALLS),
                ("internal indirect tail jumps", EXPECTED_INTERNAL_INDIRECT_JUMPS)):
            match = re.search(
                r"routine %#x: %s: (\[.*\])" % (target, label), out)
            if not match or sorted(ast.literal_eval(match.group(1))) != sorted(want):
                fail("census %s mismatch" % label)
    for target in EXPECTED_CALLS:
        for want in ("routine %#x: stored qwords: []" % target,
                     "routine %#x: RELATIVE addends: 0" % target):
            if want not in out:
                fail("census mismatch, missing %r" % want)
    ranges = frame_ranges()
    for site, caller in tsv_callers.items():
        value = int(site, 16)
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
    if records["routine"]["address"] != "0x5a01110":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x5a01110..0x5a0130b":
        fail("records routine FDE mismatch")
    if records["routine"]["size_bytes"] != 507:
        fail("records routine size mismatch")
    if records["routine"]["internal_calls"] != 0:
        fail("records internal call count mismatch")
    if records["routine"]["internal_indirect_calls"] != 2:
        fail("records internal indirect call count mismatch")
    if records["division"]["magic"] != "0x346dc5d63886594b":
        fail("records division magic mismatch")
    if records["division"]["divisor"] != 10000:
        fail("records division divisor mismatch")
    if records["fields"]["expected_quotient"] != "object +0x50":
        fail("records quotient field mismatch")
    if records["fields"]["bound"] != "object +0x10":
        fail("records bound field mismatch")
    if records["unwrap_exit"]["message"] != \
            "called `Option::unwrap()` on a `None` value":
        fail("records unwrap message mismatch")
    if records["unwrap_exit"]["line"] != 163:
        fail("records unwrap line mismatch")
    if records["sub_overflow_exit"]["message"] != \
            "attempt to subtract with overflow":
        fail("records sub message mismatch")
    if records["sub_overflow_exit"]["passed_length"] != 67:
        fail("records sub passed length mismatch")
    if records["sub_overflow_exit"]["line"] != 287:
        fail("records sub line mismatch")
    if records["result"]["rule"] != "min(cascade, 10 ** (6 - byte))":
        fail("records result rule mismatch")
    if records["census"]["direct_call_count"] != 24:
        fail("records call count mismatch")
    if records["census"]["tail_jump_count"] != 0:
        fail("records census jump count mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_pow10_scale_01110_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "checks pass" not in out:
        fail("model tests did not pass: %s" % out)


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_spots()
    check_strings_and_locations()
    check_frames()
    check_relocations()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
