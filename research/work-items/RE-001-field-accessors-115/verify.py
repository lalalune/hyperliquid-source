"""Checker for the RE-001-field-accessors-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-field-accessors-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); three extra
spot instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges against a fresh frame dump;
census consistency (callers.tsv against a fresh whole-file
scan, all sites present, no tail jumps, no stored qwords, no
RELATIVE addends); the semantic records; and the model tests.
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
    ("main.txt", 0x5D8D0C0, 0x5D8D0E9),
    ("site-recordfill.txt", 0x5F6EB80, 0x5F6EB96),
    ("site-shared.txt", 0x5F9DF8F, 0x5F9DFD6),
    ("site-getter-96156.txt", 0x5F96152, 0x5F96167),
    ("site-getter-97841.txt", 0x5F9782C, 0x5F97858),
    ("site-getter-9ab06.txt", 0x5F9AB02, 0x5F9AB33),
    ("site-get18-95e21.txt", 0x5D95E1A, 0x5D95E37),
    ("site-get18-3c20.txt", 0x5DE3C18, 0x5DE3C2F),
    ("site-get18-ecdd.txt", 0x5E8ECD5, 0x5E8ECE8),
]

EXPECTED_CALLS = {
    0x5D8D0C0: ["0x5f6eb88", "0x5f96156", "0x5f97841", "0x5f9ab06"],
    0x5D8D0D0: ["0x5f9dfa1"],
    0x5D8D0E0: ["0x5d95e21", "0x5de3c20", "0x5e8ecdd"],
}

# Three spot instructions, verified byte-for-byte against a fresh
# objdump run and the raw binary (anti-low-quality self-check).
SPOT_BYTES = {
    0x5D8D0C4: "8b4770",
    0x5D8D0D9: "0f42c6",
    0x5F9DFA1: "e82af1deff",
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
                "site-recordfill.txt", "site-shared.txt",
                "site-getter-96156.txt", "site-getter-97841.txt",
                "site-getter-9ab06.txt", "site-get18-95e21.txt",
                "site-get18-3c20.txt", "site-get18-ecdd.txt",
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
    for want in ("pc=0000000005d8d0c0..0000000005d8d0c8",
                 "pc=0000000005d8d0d0..0000000005d8d0e0",
                 "pc=0000000005d8d0e0..0000000005d8d0e9",
                 "pc=0000000005f6eb50..0000000005f6eb96",
                 "pc=0000000005d954b0..0000000005d96890",
                 "pc=0000000005de3340..0000000005de404e",
                 "pc=0000000005e8e4a0..0000000005e8ee70",
                 "pc=0000000005f95b80..0000000005f98c8d",
                 "pc=0000000005f9a580..0000000005f9aca9",
                 "pc=0000000005f9daf0..0000000005f9eccd"):
        if want not in text:
            fail("frame range missing: %s" % want)
        if want not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % want)


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    tsv = {}
    for row in rows:
        site, leaf = row.split("\t")[0], row.split("\t")[1]
        tsv.setdefault(leaf, []).append(site)
    for target, want_calls in EXPECTED_CALLS.items():
        match = re.search(
            r"leaf %#x: direct calls: (\[.*\])" % target, out)
        if not match:
            fail("census output has no direct-calls list for %#x" % target)
        calls = ast.literal_eval(match.group(1))
        if sorted(calls) != sorted(want_calls):
            fail("census calls mismatch for %#x: %s vs %s"
                 % (target, calls, want_calls))
        if sorted(calls) != sorted(tsv.get("%#x" % target, [])):
            fail("callers.tsv does not match census for %#x" % target)
        for want in ("leaf %#x: tail jumps: []" % target,
                     "leaf %#x: stored qwords: []" % target,
                     "leaf %#x: RELATIVE addends: 0" % target):
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


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_field_accessors_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "checks pass" not in out:
        fail("model tests did not pass:\n%s" % out)
    print(out.strip())


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_spots()
    check_frames()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
