"""Checker for the RE-001-uint-decimal-string-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-uint-decimal-string-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges against a fresh frame dump;
the empty relocation set against a fresh relocation dump;
census consistency (callers.tsv against a fresh scan: 17
direct calls, 0 tail jumps, no stored qwords, no RELATIVE
addends) and each callers.tsv caller function against the
smallest enclosing FDE range from a fresh frame dump; the
semantic records; the digit-pair table recomputed from the
binary's constant chunks; and the model tests.
Prints ALL CHECKS PASSED on success, else raises.
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
    ("main.txt", 0x5D4F970, 0x5D4FCDD),
]

EXPECTED_CALLS = {
    0x5D4F970: ["0x5d63d8d", "0x5d7c152", "0x5d7c16b", "0x5d88d79",
                "0x5eee3d0", "0x5ef604d", "0x5ef6083", "0x5ef60c8",
                "0x5ef6109", "0x5ef83f4", "0x5ef84ba", "0x5f0c67a",
                "0x61190d2", "0x61190f0", "0x611910d", "0x6120d0d",
                "0x6120f1f"],
}

EXPECTED_JUMPS = {0x5D4F970: []}

SPOT_BYTES = {
    0x5D4F970: "f30f1efa",
    0x5D4FA2F: "e8cc156a00",
    0x5D4FB64: "83c330",
}

TABLE_CHUNKS = [0x451750, 0x453230, 0x456910, 0x453E00, 0x451DB0,
                0x452BA0, 0x455590, 0x456240, 0x456920, 0x4528D0,
                0x456250, 0x453240]
TABLE_OVERLAP_CHUNK = 0x454870
TABLE_OVERLAP_OFFSET = 0xB9

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
    expected = {"README.md", "records.json", "main.txt",
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
            # Executable LOAD segment: file offset = vaddr - 0x1000.
            if data[address - 0x1000:address - 0x1000 + len(raw)] != raw:
                fail("raw byte mismatch at %#x in %s" % (address, name))
        if instructions[-1][0] + len(instructions[-1][1]) != stop:
            fail("excerpt %s does not end at %#x" % (name, stop))


def check_spots():
    data = BINARY.read_bytes()
    for address, hex_bytes in SPOT_BYTES.items():
        raw = bytes.fromhex(hex_bytes)
        if data[address - 0x1000:address - 0x1000 + len(raw)] != raw:
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


def check_frames():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for want in ("pc=0000000005d4f970..0000000005d4fcdd",
                 "pc=0000000005d63c00..0000000005d63e17",
                 "pc=0000000005d7b620..0000000005d7d442",
                 "pc=0000000005d88840..0000000005d89173",
                 "pc=0000000005eee310..0000000005eee421",
                 "pc=0000000005ef5d40..0000000005ef621d",
                 "pc=0000000005ef8360..0000000005ef94ee",
                 "pc=0000000005f0b760..0000000005f0ce01",
                 "pc=0000000006117ed0..0000000006119dad",
                 "pc=000000000611fb10..00000000061213db"):
        if want not in text:
            fail("frame range missing: %s" % want)
        if want not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % want)


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for target in (0x5D4F970,):
        for line in text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                fail("unexpected RELATIVE line for %#x: %s" % (target, line))
    if (PACKET / "relocations.txt").read_text() != "":
        fail("relocations.txt is not empty")


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
    if records["routine"]["address"] != "0x5d4f970":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x5d4f970..0x5d4fcdd":
        fail("records routine FDE mismatch")
    if records["census"]["direct_call_count"] != 17:
        fail("records call count mismatch")
    if records["census"]["tail_jump_count"] != 0:
        fail("records census jump count mismatch")
    if records["routine"]["size_bytes"] != 877:
        fail("records node size mismatch")
    if records["digit_count"]["group_divisor"] != 10000:
        fail("records digit-count divisor mismatch")
    if records["fill"]["divisor"] != 100:
        fail("records fill divisor mismatch")
    if not records["pair_table"]["entries"].startswith("100 two-character"):
        fail("records pair table mismatch")


def check_pair_table():
    data = BINARY.read_bytes()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1:
            segs.append((p_vaddr, p_offset, p_filesz))

    def v2o(vaddr):
        for va, off, fsz in segs:
            if va <= vaddr < va + fsz:
                return off + (vaddr - va)
        fail("no segment for %#x" % vaddr)

    table = bytearray(b"".join(
        data[v2o(c):v2o(c) + 16] for c in TABLE_CHUNKS))
    overlap = data[v2o(TABLE_OVERLAP_CHUNK):v2o(TABLE_OVERLAP_CHUNK) + 16]
    table[TABLE_OVERLAP_OFFSET:TABLE_OVERLAP_OFFSET + 16] = overlap
    for i in range(100):
        if bytes(table[2 * i:2 * i + 2]) != ("%02d" % i).encode():
            fail("pair table mismatch at pair %d" % i)


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_uint_decimal_string_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "checks pass" not in out:
        fail("model tests did not pass: %s" % out)


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_spots()
    check_frames()
    check_relocations()
    check_census()
    check_records()
    check_pair_table()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
