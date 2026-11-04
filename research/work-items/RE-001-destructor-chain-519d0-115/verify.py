"""Checker for the RE-001-destructor-chain-519d0-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-destructor-chain-519d0-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges in frames.txt against a fresh
frame dump; the empty relocation record (no relocation line
mentions the routine address); census consistency (12 direct
calls with their enclosing caller FDEs, 0 tail jumps, no
stored qwords, no RELATIVE addends for the routine address,
4 internal calls, 1 internal tail jump, 0 internal indirect
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
    ("main.txt", 0x5D519D0, 0x5D51AAF),
]

EXPECTED_CALLS = ["0x5d71ef9", "0x5ddf28c", "0x5ddf92d",
                   "0x5de0f21", "0x5de1a2a", "0x5e8eeb6",
                   "0x5e8fadd", "0x5e908d2", "0x5e9146a",
                   "0x5e91982", "0x5e91d1d", "0x5e930a4"]
EXPECTED_TAIL_JUMPS = []
EXPECTED_CALLERS = {
    0x5D71EF9: (0x5D71EEA, 0x5D71FE0),
    0x5DDF28C: (0x5DDF236, 0x5DDF42C),
    0x5DDF92D: (0x5DDF430, 0x5DE0AFE),
    0x5DE0F21: (0x5DE0EC0, 0x5DE0FFC),
    0x5DE1A2A: (0x5DE1000, 0x5DE251D),
    0x5E8EEB6: (0x5E8EE70, 0x5E8EF82),
    0x5E8FADD: (0x5E8EF90, 0x5E904BD),
    0x5E908D2: (0x5E908BE, 0x5E909CC),
    0x5E9146A: (0x5E909D0, 0x5E91CD2),
    0x5E91982: (0x5E909D0, 0x5E91CD2),
    0x5E91D1D: (0x5E91CD2, 0x5E91EC7),
    0x5E930A4: (0x5E91ED0, 0x5E9406A),
}
EXPECTED_INTERNAL_CALLS = ["0x5d519e1", "0x5d51a27",
                           "0x5d51a34", "0x5d51a98"]
EXPECTED_INTERNAL_TAIL_JUMPS = ["0x5d51aaa"]

SPOT_BYTES = {
    0x5D519E1: "e8faf3ffff",
    0x5D51A27: "e814f31b00",
    0x5D51AAA: "e961f5ffff",
    0x5D51A98: "e8e3f26900",
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
    stored = (PACKET / "relocations.txt").read_text()
    if stored != "":
        fail("relocations.txt must be empty for this packet")
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for line in text.splitlines():
        if "5d519d0" in line:
            fail("unexpected relocation mentioning the routine: %s" % line)


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    match = re.search(
        r"routine 0x5d519d0: direct calls: (\[.*\])", out)
    if not match or sorted(ast.literal_eval(match.group(1))) != sorted(EXPECTED_CALLS):
        fail("census calls mismatch: %s" % out)
    match = re.search(
        r"routine 0x5d519d0: tail jumps: (\[.*\])", out)
    if not match or ast.literal_eval(match.group(1)) != EXPECTED_TAIL_JUMPS:
        fail("census jumps mismatch: %s" % out)
    if "routine 0x5d519d0: stored qwords: []" not in out:
        fail("census stored qwords mismatch")
    if "routine 0x5d519d0: RELATIVE addends: 0" not in out:
        fail("census RELATIVE mismatch")
    for label, want in (
            ("internal calls", EXPECTED_INTERNAL_CALLS),
            ("internal tail jumps", EXPECTED_INTERNAL_TAIL_JUMPS),
            ("internal indirect calls", []),
            ("internal indirect tail jumps", [])):
        match = re.search(
            r"routine 0x5d519d0: %s: (\[.*\])" % label, out)
        if not match or sorted(ast.literal_eval(match.group(1))) != sorted(want):
            fail("census %s mismatch" % label)
    for site, (start, stop) in EXPECTED_CALLERS.items():
        want = "site %#x caller %#x..%#x" % (site, start, stop)
        if want not in out:
            fail("census caller mismatch, missing %r" % want)
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    if len(rows) != 12:
        fail("callers.tsv must hold 12 sites, got %d" % len(rows))
    for row in rows:
        site, _target, caller, kind = row.split("\t")
        if kind != "call":
            fail("callers.tsv unknown kind: %s" % row)
        start, stop = EXPECTED_CALLERS[int(site, 16)]
        if caller != "%#x..%#x" % (start, stop):
            fail("callers.tsv row mismatch: %s" % row)


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["task"] != "RE-001":
        fail("records task mismatch")
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["routine"]["address"] != "0x5d519d0":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x5d519d0..0x5d51aaf":
        fail("records routine FDE mismatch")
    if records["routine"]["size_bytes"] != 223:
        fail("records routine size mismatch")
    if records["routine"]["internal_calls"] != 4:
        fail("records internal call count mismatch")
    if records["routine"]["internal_tail_jumps"] != 1:
        fail("records internal tail jump count mismatch")
    if records["census"]["direct_call_count"] != 12:
        fail("records call count mismatch")
    if records["census"]["tail_jump_count"] != 0:
        fail("records census jump count mismatch")
    if records["census"]["relative_addends"] != 0:
        fail("records RELATIVE count mismatch")
    if len(records["phases"]) != 4:
        fail("records phase count mismatch")
    if records["phases"][0]["name"] != "composite destructor call":
        fail("records first phase mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_destructor_chain_519d0_115.py"],
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
