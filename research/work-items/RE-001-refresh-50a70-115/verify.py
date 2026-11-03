"""Checker for the RE-001-refresh-50a70-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-refresh-50a70-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges in frames.txt against a fresh
frame dump; the relocation records in relocations.txt against
a fresh relocation dump; census consistency (no direct calls,
no tail jumps, the four RELATIVE records and their .rela.dyn
addend positions, 13 internal calls, 3 internal direct tail
jumps all landing in the cleanup fragment, 4 internal
indirect calls, 0 internal indirect tail jumps); the
semantic records; and the model tests. Prints ALL CHECKS
PASSED on success, else raises.
"""

import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    ("main.txt", 0x5D50A70, 0x5D50DC5),
    ("cleanup.txt", 0x5D50A06, 0x5D50A6C),
    ("teardown.txt", 0x5D509C0, 0x5D50A06),
    ("global_target.txt", 0x5D486C0, 0x5D486CE),
]

EXPECTED_CALLS = {0x5D50A70: []}

EXPECTED_JUMPS = {0x5D50A70: []}

EXPECTED_INTERNAL_CALLS = [
    "0x5d50aa8", "0x5d50ac3", "0x5d50af8", "0x5d50bd8",
    "0x5d50cbe", "0x5d50cc6", "0x5d50cce", "0x5d50cea",
    "0x5d50d02", "0x5d50d3b", "0x5d50d5e", "0x5d50d7d",
    "0x5d50d9c"]
EXPECTED_INTERNAL_JUMPS = ["0x5d50da8", "0x5d50db4", "0x5d50dc0"]
EXPECTED_INTERNAL_INDIRECT_CALLS = [
    "0x5d50ad3", "0x5d50ae8", "0x5d50d90", "0x5d50d98"]
EXPECTED_INTERNAL_INDIRECT_JUMPS = []

EXPECTED_STORED_QWORDS = ["0x1056c8", "0x109cd0", "0x10ab40",
                          "0x10bcb0"]

SPOT_BYTES = {
    0x5D50A70: "f30f1efa",
    0x5D50AA8: "e893bf3100",
    0x5D50AD3: "ff9000030000",
    0x5D50CBE: "e8ddb02700",
    0x5D50D3B: "e840006a00",
    0x5D50A06: "488b7d08",
    0x5D509C0: "f30f1efa",
    0x5D486C0: "f30f1efa",
    0x5D50DC0: "e96afcffff",
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
    expected = {"README.md", "records.json", "main.txt",
                "cleanup.txt", "teardown.txt", "global_target.txt",
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
    for line in (PACKET / "frames.txt").read_text().splitlines():
        match = re.search(r"pc=([0-9a-f]+\.\.[0-9a-f]+)", line)
        if not match:
            fail("frames.txt line without pc range: %s" % line)
        if ("pc=" + match.group(1)) not in text:
            fail("frame range missing: %s" % match.group(1))


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    stored = (PACKET / "relocations.txt").read_text().splitlines()
    if len(stored) != 5:
        fail("relocations.txt must hold 5 records, got %d" % len(stored))
    for line in stored:
        if line.strip() not in text:
            fail("relocation record missing from fresh dump: %s" % line)


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    if rows:
        fail("callers.tsv must be header-only for this routine")
    for target, want_calls in EXPECTED_CALLS.items():
        match = re.search(
            r"routine %#x: direct calls: (\[.*\])" % target, out)
        if not match:
            fail("census output has no direct-calls list for %#x" % target)
        calls = ast.literal_eval(match.group(1))
        if sorted(calls) != sorted(want_calls):
            fail("census calls mismatch for %#x: %s vs %s"
                 % (target, calls, want_calls))
        want_jumps = EXPECTED_JUMPS[target]
        match = re.search(
            r"routine %#x: tail jumps: (\[.*\])" % target, out)
        if not match:
            fail("census jumps mismatch for %#x" % target)
        jumps = ast.literal_eval(match.group(1))
        if sorted(jumps) != sorted(want_jumps):
            fail("census jumps mismatch for %#x: %s vs %s"
                 % (target, jumps, want_jumps))
        for label, want in (
                ("internal calls", EXPECTED_INTERNAL_CALLS),
                ("internal tail jumps", EXPECTED_INTERNAL_JUMPS),
                ("internal indirect calls",
                 EXPECTED_INTERNAL_INDIRECT_CALLS),
                ("internal indirect tail jumps",
                 EXPECTED_INTERNAL_INDIRECT_JUMPS)):
            match = re.search(
                r"routine %#x: %s: (\[.*\])" % (target, label), out)
            if not match or sorted(ast.literal_eval(match.group(1))) != sorted(want):
                fail("census %s mismatch" % label)
    for target in EXPECTED_CALLS:
        want_qwords = ("routine %#x: stored qwords: %s"
                       % (target, EXPECTED_STORED_QWORDS))
        if want_qwords not in out:
            fail("census stored qwords mismatch, missing %r" % want_qwords)
        if ("routine %#x: RELATIVE addends: 4" % target) not in out:
            fail("census RELATIVE addends mismatch")


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["task"] != "RE-001":
        fail("records task mismatch")
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["routine"]["address"] != "0x5d50a70":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x5d50a70..0x5d50dc5":
        fail("records routine FDE mismatch")
    if records["routine"]["size_bytes"] != 853:
        fail("records routine size mismatch")
    if records["routine"]["internal_calls"] != 13:
        fail("records internal call count mismatch")
    if records["routine"]["internal_tail_jumps"] != 3:
        fail("records internal tail jump count mismatch")
    if records["routine"]["internal_indirect_calls"] != 4:
        fail("records internal indirect call count mismatch")
    if records["routine"]["internal_indirect_tail_jumps"] != 0:
        fail("records internal indirect tail jump count mismatch")
    if records["census"]["direct_call_count"] != 0:
        fail("records call count mismatch")
    if records["census"]["tail_jump_count"] != 0:
        fail("records census jump count mismatch")
    if records["census"]["relative_addends"] != 4:
        fail("records RELATIVE count mismatch")
    if records["dispose"]["global"]["relocated_value"] != "0x5d486c0":
        fail("records global value mismatch")
    if records["temp_init"]["slots"]["+0x08"] != "0x400000000":
        fail("records temp +0x08 mismatch")
    if records["temp_init"]["slots"]["+0x50"] != "0x100":
        fail("records temp +0x50 mismatch")
    if records["temp_init"]["slots"]["+0x60"] != "0x00ffffffffffffff":
        fail("records temp +0x60 mismatch")
    if records["temp_init"]["not_written"] != "+0x88..+0xef":
        fail("records temp gap mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_refresh_50a70_115.py"],
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
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
