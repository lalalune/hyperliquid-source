"""Checker for the RE-001-delimited-key-parse-eb60-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-delimited-key-parse-eb60-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges in frames.txt against a fresh
frame dump; the relocation record against a fresh readelf -r
run; census consistency (routine: 2 direct calls, 0 tail
jumps, 14 internal calls, 4 landing-pad-stub tail jumps, no
stored qwords, no RELATIVE addends; callers.tsv with its 2
rows); the semantic records; and the model tests.
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
    ("main.txt", 0x606EB60, 0x606EEAC),
    ("cleanup.txt", 0x606EB0C, 0x606EB5A),
]

EXPECTED_CALLS = ["0x606f07c", "0x606f1bd"]
EXPECTED_TAIL_JUMPS = []
EXPECTED_INTERNAL_CALLS = [
    "0x606ebb0", "0x606ebc6", "0x606ec02", "0x606ec8c", "0x606eca7",
    "0x606ecd4", "0x606ed41", "0x606ed5d", "0x606ed85", "0x606eda2",
    "0x606eded", "0x606ee0c", "0x606ee2d", "0x606ee61",
]
EXPECTED_INTERNAL_TAIL_JUMPS = [
    "0x606ee7a", "0x606ee8f", "0x606ee9b", "0x606eea7",
]
EXPECTED_CALLERS = [
    ("0x606f07c", "0x606ef50..0x606f91f", "direct call"),
    ("0x606f1bd", "0x606ef50..0x606f91f", "direct call"),
]

SPOT_BYTES = {
    0x606EBC6: "e8d5233800",
    0x606EC8C: "e8af281600",
    0x606EE61: "e8da213800",
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
    expected = {"README.md", "records.json", "main.txt", "cleanup.txt",
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
    if len(lines) != 3:
        fail("frames.txt must hold 3 lines, got %d" % len(lines))
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
             if "606eb60" in line and "RELATIVE" in line]
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
        ("0x606eb60", "direct calls", EXPECTED_CALLS),
        ("0x606eb60", "tail jumps", EXPECTED_TAIL_JUMPS),
        ("0x606eb60", "internal calls", EXPECTED_INTERNAL_CALLS),
        ("0x606eb60", "internal tail jumps",
         EXPECTED_INTERNAL_TAIL_JUMPS),
        ("0x606eb60", "internal indirect calls", []),
        ("0x606eb60", "internal indirect tail jumps", []),
        ("0x606eb60", "stored qwords \\(file offsets\\)", []),
        ("0x606eb60", "RELATIVE slots", []),
    ]
    for routine, label, want in checks:
        got = census_value(out, routine, label)
        if sorted(got) != sorted(want):
            fail("census %s mismatch for %s: %s" % (label, routine, got))
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    if len(rows) != 2:
        fail("callers.tsv must hold 2 rows, got %d" % len(rows))
    for row in rows:
        parts = tuple(row.split("\t"))
        if parts not in EXPECTED_CALLERS:
            fail("callers.tsv row mismatch: %s" % row)


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["task_id"] != "RE-001":
        fail("records task mismatch")
    if records["routine"]["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["routine"]["address"] != "0x606eb60":
        fail("records routine address mismatch")
    if records["routine"]["fde_range"] != ["0x606eb60", "0x606eeac"]:
        fail("records routine FDE mismatch")
    if records["routine"]["cleanup_fragment_fde_range"] != [
            "0x606eb0c", "0x606eb5a"]:
        fail("records cleanup FDE mismatch")
    if records["census"]["direct_calls"] != EXPECTED_CALLS:
        fail("records census calls mismatch")
    if records["census"]["tail_jumps"] != []:
        fail("records census jumps mismatch")
    if records["census"]["relative_slots"] != []:
        fail("records RELATIVE count mismatch")
    if records["prefix_number_parser"]["suffix_multipliers"] != {
            "G_or_g": "value << 30", "K_or_k": "value << 10",
            "M_or_m": "value << 20", "T_or_t": "value << 40"}:
        fail("records suffix table mismatch")
    if len(records["callers"]) != 2:
        fail("records caller count mismatch")
    if records["string_constants"]["separator"]["bytes"] != "#":
        fail("records separator mismatch")


def check_model_tests():
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests",
         "-p", "test_delimited_key_parse_eb60_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if result.returncode != 0 or "OK" not in result.stderr + result.stdout:
        fail("model tests did not pass: %s%s"
             % (result.stdout, result.stderr))


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
