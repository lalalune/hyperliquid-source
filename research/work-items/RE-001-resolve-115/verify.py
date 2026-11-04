"""Checker for the RE-001-resolve-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-resolve-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); three
spot instructions byte-for-byte against a fresh objdump run
and the raw binary; the FDE ranges against a fresh frame dump;
the RELATIVE slot line against a fresh relocation dump;
census consistency (callers.tsv against a fresh whole-file
scan, the wrapper's zero calls and one RELATIVE addend, the
leaf's ten calls, no tail jumps, no leaf stored qwords, no
leaf RELATIVE addends); the semantic records; and the model
tests.
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
    ("main.txt", 0x5D8CF30, 0x5D8CF6D),
    ("leaf.txt", 0x5D8CE80, 0x5D8CE8C),
]

EXPECTED_CALLS = {
    0x5D8CF30: [],
    0x5D8CE80: ["0x5d69889", "0x5d8cf40", "0x5e51f85", "0x5e5352d",
                "0x5e6b642", "0x5e6bf1d", "0x5e6d9cc", "0x5e8486d",
                "0x5e8bc17", "0x5fa46c8"],
}

EXPECTED_JUMPS = {
    0x5D8CF30: [],
    0x5D8CE80: [],
}

# Three spot instructions, verified byte-for-byte against a fresh
# objdump run and the raw binary (anti-low-quality self-check).
SPOT_BYTES = {
    0x5D8CF38: "488b7f08",
    0x5D8CF58: "e833ffffff",
    0x5D8CE84: "488b8718010000",
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
    expected = {"README.md", "records.json", "main.txt", "leaf.txt",
                "frames.txt", "relocations.txt",
                "callers.tsv", "export_excerpts.py",
                "census.py", "verify.py"}
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
    for want in ("pc=0000000005d8cf30..0000000005d8cf6d",
                 "pc=0000000005d8ce80..0000000005d8ce8c"):
        if want not in text:
            fail("frame range missing: %s" % want)
        if want not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % want)


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    want = "0000064c9bc8  000000000008 R_X86_64_RELATIVE                    5d8cf30"
    if want not in text:
        fail("relocation slot line missing from fresh dump")
    if want not in (PACKET / "relocations.txt").read_text():
        fail("relocations.txt missing the slot line")
    if "5d8ce80" in text and "RELATIVE" in text:
        for line in text.splitlines():
            if "5d8ce80" in line and "RELATIVE" in line:
                fail("unexpected leaf RELATIVE line: %s" % line)


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    tsv_calls = {}
    tsv_jumps = {}
    tsv_pointers = []
    for row in rows:
        site, target, _caller, kind = row.split("\t")[0:4]
        if kind == "call":
            tsv_calls.setdefault(target, []).append(site)
        elif kind == "tail jump":
            tsv_jumps.setdefault(target, []).append(site)
        elif kind == "pointer":
            tsv_pointers.append((site, target))
        else:
            fail("unknown callers.tsv kind: %s" % kind)
    if tsv_pointers != [("0x64c9bc8", "0x5d8cf30")]:
        fail("pointer row mismatch: %s" % tsv_pointers)
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
    for want in ("routine 0x5d8cf30: stored qwords: [1069888]",
                 "routine 0x5d8cf30: RELATIVE addends: 1",
                 "routine 0x5d8ce80: stored qwords: []",
                 "routine 0x5d8ce80: RELATIVE addends: 0"):
        if want not in out:
            fail("census mismatch, missing %r" % want)


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["task"] != "RE-001":
        fail("records task mismatch")
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    total = sum(len(sites) for sites in EXPECTED_CALLS.values())
    if records["census"]["direct_call_count"] != total:
        fail("records census count mismatch")
    if records["wrapper"]["address"] != "0x5d8cf30":
        fail("records wrapper address mismatch")
    if records["leaf"]["address"] != "0x5d8ce80":
        fail("records leaf address mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_resolve_115.py"],
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
