"""Checker for the RE-001-control-block-9520-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-control-block-9520-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges in frames.txt against a fresh
frame dump; the relocation records in relocations.txt against
a fresh relocation dump; census consistency (4 direct calls
with their enclosing caller FDEs, 0 tail jumps, no stored
qwords, no RELATIVE addends for the routine address, 1
internal call, 0 internal tail jumps, 0 internal indirect
transfers, and callers.tsv matching the census); the
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
    ("main.txt", 0x5FC9520, 0x5FC955E),
    ("reset.txt", 0x5FC9460, 0x5FC947B),
    ("deleting.txt", 0x5FC9480, 0x5FC949B),
]

EXPECTED_CALLS = ["0x5d50d02", "0x5d8bf6f", "0x5d8c1e0", "0x5d8c2c8"]
EXPECTED_CALLERS = {
    0x5D50D02: (0x5D50A70, 0x5D50DC5),
    0x5D8BF6F: (0x5D8BEA0, 0x5D8C97A),
    0x5D8C1E0: (0x5D8BEA0, 0x5D8C97A),
    0x5D8C2C8: (0x5D8BEA0, 0x5D8C97A),
}
EXPECTED_INTERNAL_CALLS = ["0x5fc9539"]

SPOT_BYTES = {
    0x5FC9530: "f0830601",
    0x5FC9539: "e892784200",
    0x5FC9551: "488910",
    0x5FC9460: "f30f1efa",
    0x5FC9480: "f30f1efa",
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
                "reset.txt", "deleting.txt", "frames.txt",
                "relocations.txt", "callers.tsv",
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
        match = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if not match:
            fail("frames.txt line without pc range: %s" % line)
        if ("pc=" + match.group(1) + ".." + match.group(2)) not in text:
            fail("frame range missing: %s" % match.group(0))


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    stored = (PACKET / "relocations.txt").read_text().splitlines()
    if len(stored) != 4:
        fail("relocations.txt must hold 4 records, got %d" % len(stored))
    for line in stored[:3]:
        if line.strip() not in text:
            fail("relocation record missing from fresh dump: %s" % line)
    if not re.search(r"^0000064cd828\s+.*R_X86_64_64", text, re.M):
        fail("typeinfo relocation at 0x64cd828 missing")


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    match = re.search(
        r"routine 0x5fc9520: direct calls: (\[.*\])", out)
    if not match or sorted(ast.literal_eval(match.group(1))) != sorted(EXPECTED_CALLS):
        fail("census calls mismatch: %s" % out)
    match = re.search(
        r"routine 0x5fc9520: tail jumps: (\[.*\])", out)
    if not match or ast.literal_eval(match.group(1)):
        fail("census jumps mismatch")
    if "routine 0x5fc9520: stored qwords: []" not in out:
        fail("census stored qwords mismatch")
    if "routine 0x5fc9520: RELATIVE addends: 0" not in out:
        fail("census RELATIVE mismatch")
    for label, want in (
            ("internal calls", EXPECTED_INTERNAL_CALLS),
            ("internal tail jumps", []),
            ("internal indirect calls", []),
            ("internal indirect tail jumps", [])):
        match = re.search(
            r"routine 0x5fc9520: %s: (\[.*\])" % label, out)
        if not match or sorted(ast.literal_eval(match.group(1))) != sorted(want):
            fail("census %s mismatch" % label)
    for site, (start, stop) in EXPECTED_CALLERS.items():
        want = "site %#x caller %#x..%#x" % (site, start, stop)
        if want not in out:
            fail("census caller mismatch, missing %r" % want)
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    if len(rows) != 4:
        fail("callers.tsv must hold 4 sites")
    for row in rows:
        site, _target, caller, kind = row.split("\t")
        start, stop = EXPECTED_CALLERS[int(site, 16)]
        if caller != "%#x..%#x" % (start, stop) or kind != "call":
            fail("callers.tsv row mismatch: %s" % row)


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["task"] != "RE-001":
        fail("records task mismatch")
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["routine"]["address"] != "0x5fc9520":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x5fc9520..0x5fc955e":
        fail("records routine FDE mismatch")
    if records["routine"]["size_bytes"] != 62:
        fail("records routine size mismatch")
    if records["routine"]["internal_calls"] != 1:
        fail("records internal call count mismatch")
    if records["census"]["direct_call_count"] != 4:
        fail("records call count mismatch")
    if records["census"]["tail_jump_count"] != 0:
        fail("records census jump count mismatch")
    if records["census"]["relative_addends"] != 0:
        fail("records RELATIVE count mismatch")
    if records["vtable"]["address"] != "0x64cd880":
        fail("records vtable address mismatch")
    if records["vtable"]["slots"][0]["relocated_value"] != "0x5fc9460":
        fail("records reset slot mismatch")
    if records["vtable"]["slots"][1]["relocated_value"] != "0x5fc9480":
        fail("records deleting slot mismatch")
    if records["reset"]["address"] != "0x5fc9460":
        fail("records reset address mismatch")
    if records["deleting"]["address"] != "0x5fc9480":
        fail("records deleting address mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_control_block_9520_115.py"],
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
