"""Checker for the RE-001-chain-reset-dispatch-4dc00-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-chain-reset-dispatch-4dc00-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE range in frames.txt against a fresh
frame dump; the relocation record against a fresh readelf -r
run; census consistency (0 direct calls, 0 tail jumps, the
four .rela.dyn addend file offsets, 4 internal calls of the
first group plus the remaining internal calls, 1 landing-pad
stub, 1 internal indirect call, 1 internal direct tail jump,
the four RELATIVE slots, callers.tsv with no rows,
pointer_slots.tsv matching the records); the semantic
records; and the model tests. Prints ALL CHECKS PASSED on
success, else raises.
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
    ("main.txt", 0x5D4DC00, 0x5D4DD50),
]

EXPECTED_CALLS = []
EXPECTED_TAIL_JUMPS = []
EXPECTED_QWORDS = ["0x104308", "0x108910", "0x109780", "0x10a8f0"]
EXPECTED_SLOTS = ["0x64c9538", "0x64cb2b0", "0x64cb790", "0x64cbd90"]
EXPECTED_INTERNAL_CALLS = ["0x5d4dc23", "0x5d4dc38", "0x5d4dc56",
                           "0x5d4dc70", "0x5d4dc7d", "0x5d4dce0",
                           "0x5d4dcf5", "0x5d4dcff"]
EXPECTED_INTERNAL_TAIL_JUMPS = ["0x5d4dd36"]
EXPECTED_INTERNAL_INDIRECT_CALLS = ["0x5d4dcb3"]
EXPECTED_LANDING_PAD_STUBS = ["0x5d4dd4b"]
EXPECTED_POINTER_SLOTS = {
    "0x64c9538": ("0x5d63c00", "0x5d2fb80", "0x5d4dc00", "0x5d2ed80", "0x5d63e20"),
    "0x64cb2b0": ("0x5d63c00", "0x5d2fb80", "0x5d4dc00", "0x5d2ed80", "0x5d63e20"),
    "0x64cb790": ("0x5d63c00", "0x5d2fb80", "0x5d4dc00", "0x5d2ed80", "0x5d63e20"),
    "0x64cbd90": ("0x5d63c00", "0x5d2fb80", "0x5d4dc00", "0x5d2ed80", "0x5d63e20"),
}
EXPECTED_RELA_OFFSETS = {
    "0x64c9538": "0x1042f8",
    "0x64cb2b0": "0x108900",
    "0x64cb790": "0x109770",
    "0x64cbd90": "0x10a8e0",
}

SPOT_BYTES = {
    0x5D4DC23: "e8680b1a00",
    0x5D4DCB3: "ff5030",
    0x5D4DCE0: "e85bed3100",
    0x5D4DD36: "e9250d1a00",
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
                "frames.txt", "relocations.txt", "callers.tsv",
                "pointer_slots.tsv",
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
        if not instructions or instructions[0][1] != raw:
            fail("spot objdump byte mismatch at %#x" % address)


def check_frames():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        match = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if not match:
            fail("frames.txt line without pc range: %s" % line)
        if ("pc=" + match.group(1) + ".." + match.group(2)) not in text:
            fail("frame range missing: %s" % match.group(0))


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    fresh = [line for line in text.splitlines()
             if "5d4dc00" in line and "RELATIVE" in line]
    stored = (PACKET / "relocations.txt").read_text().splitlines()
    if fresh != stored:
        fail("relocations.txt mismatch: %s vs %s" % (stored, fresh))
    if len(stored) != 4:
        fail("relocations.txt must hold 4 lines, got %d" % len(stored))


def census_value(out, label):
    match = re.search(label + r": (\[.*\])", out)
    if not match:
        fail("census label missing: %s" % label)
    return ast.literal_eval(match.group(1))


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if census_value(out, r"routine 0x5d4dc00: direct calls") != EXPECTED_CALLS:
        fail("census calls mismatch: %s" % out)
    if census_value(out, r"routine 0x5d4dc00: tail jumps") != EXPECTED_TAIL_JUMPS:
        fail("census jumps mismatch: %s" % out)
    if sorted(census_value(out, r"routine 0x5d4dc00: stored qwords \(file offsets\)")) != sorted(EXPECTED_QWORDS):
        fail("census stored qwords mismatch: %s" % out)
    if sorted(census_value(out, r"routine 0x5d4dc00: RELATIVE slots")) != sorted(EXPECTED_SLOTS):
        fail("census RELATIVE slots mismatch: %s" % out)
    if sorted(census_value(out, r"routine 0x5d4dc00: internal direct calls")) != sorted(EXPECTED_INTERNAL_CALLS):
        fail("census internal calls mismatch: %s" % out)
    if census_value(out, r"routine 0x5d4dc00: internal indirect calls") != EXPECTED_INTERNAL_INDIRECT_CALLS:
        fail("census internal indirect calls mismatch: %s" % out)
    if census_value(out, r"routine 0x5d4dc00: internal direct tail jumps") != EXPECTED_INTERNAL_TAIL_JUMPS:
        fail("census internal tail jumps mismatch: %s" % out)
    if census_value(out, r"routine 0x5d4dc00: landing-pad-stub tail jumps") != EXPECTED_LANDING_PAD_STUBS:
        fail("census landing-pad stubs mismatch: %s" % out)
    callers = (PACKET / "callers.tsv").read_text().splitlines()
    if len(callers) != 1:
        fail("callers.tsv must hold only its header, got %d lines" % len(callers))
    rows = (PACKET / "pointer_slots.tsv").read_text().splitlines()[1:]
    if len(rows) != 4:
        fail("pointer_slots.tsv must hold 4 rows, got %d" % len(rows))
    for row in rows:
        fields = row.split("\t")
        slot = fields[0]
        if tuple(fields[1:6]) != EXPECTED_POINTER_SLOTS[slot]:
            fail("pointer slot neighbours mismatch for %s" % slot)
        if fields[6] != EXPECTED_RELA_OFFSETS[slot]:
            fail("rela entry offset mismatch for %s" % slot)
        if fields[7] not in EXPECTED_QWORDS:
            fail("stored qword offset mismatch for %s" % slot)


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["routine"]["address"] != "0x5d4dc00":
        fail("records routine address mismatch")
    if records["census"]["relative_slots"] != EXPECTED_SLOTS:
        fail("records census slots mismatch")
    if records["task_id"] != "RE-001":
        fail("records task id mismatch")
    text = json.dumps(records)
    if "endbr64" in text or "mov " in text:
        fail("records.json must not carry per-instruction detail")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_chain_reset_dispatch_4dc00_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "ALL MODEL TESTS PASSED" not in out:
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
