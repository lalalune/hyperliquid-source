"""Checker for the RE-001-keyed-lookup-finalize-52660-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-keyed-lookup-finalize-52660-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges in frames.txt against a fresh
frame dump; the relocation record against a fresh readelf -r
run; census consistency (wrapper: 1 direct call, 1 tail
jump, 1 internal call; lookup: 1 direct call, 0 tail jumps,
4 internal calls, 1 landing-pad-stub tail jump; neither
routine has stored qwords or RELATIVE addends; callers.tsv
with its 3 rows); the semantic records; and the model tests.
Prints ALL CHECKS PASSED on success, else raises.
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
    ("wrapper.txt", 0x606C680, 0x606C6A5),
    ("lookup.txt", 0x5D52660, 0x5D52765),
]

EXPECTED_WRAPPER_CALLS = ["0x5d4cd33"]
EXPECTED_WRAPPER_TAIL_JUMPS = ["0x606c6d6"]
EXPECTED_WRAPPER_INTERNAL_CALLS = ["0x606c69b"]
EXPECTED_WRAPPER_INTERNAL_TAIL_JUMPS = []
EXPECTED_LOOKUP_CALLS = ["0x606c69b"]
EXPECTED_LOOKUP_TAIL_JUMPS = []
EXPECTED_LOOKUP_INTERNAL_CALLS = ["0x5d526b8", "0x5d52729",
                                  "0x5d52742", "0x5d5274f"]
EXPECTED_LOOKUP_INTERNAL_TAIL_JUMPS = ["0x5d52760"]
EXPECTED_CALLERS = [
    ("0x5d4cd33", "0x606c680", "0x5d4cc80..0x5d4ce6a", "call"),
    ("0x606c6d6", "0x606c680", "0x606c6b0..0x606c6db", "jmp"),
    ("0x606c69b", "0x5d52660", "0x606c680..0x606c6a5", "call"),
]

SPOT_BYTES = {
    0x606C69B: "e8c05fceff",
    0x5D526B8: "e883a33100",
    0x606C6D6: "e9a5ffffff",
    0x5D52760: "e9e7feffff",
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
    expected = {"README.md", "records.json", "wrapper.txt", "lookup.txt",
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
        if not instructions or instructions[0][1] != raw:
            fail("spot objdump byte mismatch at %#x" % address)


def check_frames():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    lines = (PACKET / "frames.txt").read_text().splitlines()
    if len(lines) != 4:
        fail("frames.txt must hold 4 lines, got %d" % len(lines))
    for line in lines:
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
             if ("606c680" in line or "5d52660" in line)
             and "RELATIVE" in line]
    stored = (PACKET / "relocations.txt").read_text().splitlines()
    if fresh != stored:
        fail("relocations.txt mismatch: %s vs %s" % (stored, fresh))
    if stored:
        fail("relocations.txt must be empty, got %d lines" % len(stored))


def census_value(out, routine, label):
    match = re.search(
        r"routine %s: %s: (\[.*\])" % (routine, label), out)
    if not match:
        fail("census %s missing for %s" % (label, routine))
    return ast.literal_eval(match.group(1))


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    checks = [
        ("0x606c680", "direct calls", EXPECTED_WRAPPER_CALLS),
        ("0x606c680", "tail jumps", EXPECTED_WRAPPER_TAIL_JUMPS),
        ("0x606c680", "internal calls", EXPECTED_WRAPPER_INTERNAL_CALLS),
        ("0x606c680", "internal tail jumps",
         EXPECTED_WRAPPER_INTERNAL_TAIL_JUMPS),
        ("0x606c680", "internal indirect calls", []),
        ("0x606c680", "internal indirect tail jumps", []),
        ("0x606c680", "stored qwords \\(file offsets\\)", []),
        ("0x606c680", "RELATIVE slots", []),
        ("0x5d52660", "direct calls", EXPECTED_LOOKUP_CALLS),
        ("0x5d52660", "tail jumps", EXPECTED_LOOKUP_TAIL_JUMPS),
        ("0x5d52660", "internal calls", EXPECTED_LOOKUP_INTERNAL_CALLS),
        ("0x5d52660", "internal tail jumps",
         EXPECTED_LOOKUP_INTERNAL_TAIL_JUMPS),
        ("0x5d52660", "internal indirect calls", []),
        ("0x5d52660", "internal indirect tail jumps", []),
        ("0x5d52660", "stored qwords \\(file offsets\\)", []),
        ("0x5d52660", "RELATIVE slots", []),
    ]
    for routine, label, want in checks:
        got = census_value(out, routine, label)
        if sorted(got) != sorted(want):
            fail("census %s mismatch for %s: %s" % (label, routine, got))
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    if len(rows) != 3:
        fail("callers.tsv must hold 3 rows, got %d" % len(rows))
    for row in rows:
        parts = tuple(row.split("\t"))
        if parts not in EXPECTED_CALLERS:
            fail("callers.tsv row mismatch: %s" % row)


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["task"] != "RE-001":
        fail("records task mismatch")
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["wrapper"]["address"] != "0x606c680":
        fail("records wrapper address mismatch")
    if records["wrapper"]["fde"] != "0x606c680..0x606c6a5":
        fail("records wrapper FDE mismatch")
    if records["wrapper"]["size_bytes"] != 37:
        fail("records wrapper size mismatch")
    if records["lookup"]["address"] != "0x5d52660":
        fail("records lookup address mismatch")
    if records["lookup"]["fde"] != "0x5d52660..0x5d52765":
        fail("records lookup FDE mismatch")
    if records["lookup"]["size_bytes"] != 261:
        fail("records lookup size mismatch")
    if records["census"]["direct_calls"] != {
            "0x5d52660": ["0x606c69b"],
            "0x606c680": ["0x5d4cd33"]}:
        fail("records census calls mismatch")
    if records["census"]["tail_jumps"] != {
            "0x5d52660": [],
            "0x606c680": ["0x606c6d6"]}:
        fail("records census jumps mismatch")
    if records["census"]["relative_addends"] != 0:
        fail("records RELATIVE count mismatch")
    if len(records["phases"]) != 5:
        fail("records phase count mismatch")
    if records["phases"][0]["name"] != "null-out early return":
        fail("records first phase mismatch")
    if len(records["consumers"]) != 2:
        fail("records consumer count mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_keyed_lookup_finalize_52660_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "checks pass" not in out:
        fail("model tests did not pass: %s" % out)


def main():
    check_digest()
    check_manifest()
    check_frames()
    check_relocations()
    check_excerpts()
    check_spots()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
