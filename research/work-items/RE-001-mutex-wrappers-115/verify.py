"""Checker for the RE-001-mutex-wrappers-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-mutex-wrappers-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges in frames.txt against a fresh
frame dump; the relocation record against a fresh readelf -r
run (expected empty: code addresses draw no relocations);
the format and operation strings byte-for-byte against the
binary; census consistency (157 lock calls, 1 lock tail jump,
669 unlock calls, 5 unlock tail jumps, 2 stub calls, no
stored qwords, no RELATIVE slots, the internal transfers of
all five windows); callers.tsv matching the census wrapper
sites exactly; the semantic records; and the model tests.
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
    ("lock.txt", 0x60D5230, 0x60D52C5),
    ("lock_cleanup.txt", 0x60D5200, 0x60D5225),
    ("unlock.txt", 0x60D52F0, 0x60D5385),
    ("unlock_cleanup.txt", 0x60D52C6, 0x60D52EB),
    ("stub.txt", 0x606CA00, 0x606CA09),
]

EXPECTED_LOCK_CALLS = 157
EXPECTED_LOCK_JUMPS = ["0x606ca04"]
EXPECTED_UNLOCK_CALLS = 669
EXPECTED_UNLOCK_JUMPS = ["0x5d53182", "0x5dfd030", "0x5e8633c",
                         "0x5e86bde", "0x5e86c44"]
EXPECTED_STUB_CALLS = ["0x606cb0f", "0x606cbea"]
EXPECTED_LOCK_INTERNAL_CALLS = ["0x60d524a", "0x60d527a", "0x60d52a2",
                                "0x60d52aa", "0x60d52af", "0x60d52b4"]
EXPECTED_LOCK_STUBS = ["0x60d52c0"]
EXPECTED_LOCK_CLEANUP_CALLS = ["0x60d5203", "0x60d521b", "0x60d5220"]
EXPECTED_UNLOCK_INTERNAL_CALLS = ["0x60d530a", "0x60d533a", "0x60d5362",
                                  "0x60d536a", "0x60d536f", "0x60d5374"]
EXPECTED_UNLOCK_STUBS = ["0x60d5380"]
EXPECTED_UNLOCK_CLEANUP_CALLS = ["0x60d52c9", "0x60d52e1", "0x60d52e6"]
EXPECTED_STUB_JUMPS = ["0x606ca04"]

SPOT_BYTES = {
    0x60D524A: "e811b93100",
    0x60D530A: "e861b83100",
    0x606CA04: "e927880600",
    0x60D52C0: "e93bffffff",
    0x60D5380: "e941ffffff",
}

STRINGS = {
    0x43742F: b"pthread %s: %s\n",
    0x43FA29: b"lock",
    0x43948F: b"unlock",
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
    expected = {"README.md", "records.json", "lock.txt", "lock_cleanup.txt",
                "unlock.txt", "unlock_cleanup.txt", "stub.txt",
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
    if len(lines) != 5:
        fail("frames.txt must hold 5 lines, got %d" % len(lines))
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
             if any(a in line for a in ("60d5230", "60d52f0", "606ca00"))]
    stored = (PACKET / "relocations.txt").read_text().splitlines()
    if fresh != stored:
        fail("relocations.txt mismatch: %s vs %s" % (stored, fresh))
    if stored:
        fail("relocations.txt must be empty, got %d lines" % len(stored))


def check_strings():
    data = BINARY.read_bytes()
    for address, expected in STRINGS.items():
        # First LOAD segment is mapped at its file offset.
        if data[address:address + len(expected)] != expected:
            fail("string mismatch at %#x" % address)
        if data[address + len(expected)] != 0:
            fail("string at %#x is not NUL-terminated" % address)


def census_value(out, label):
    match = re.search(re.escape(label) + r": (\[.*\])", out)
    if not match:
        fail("census label missing: %s" % label)
    return ast.literal_eval(match.group(1))


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if len(census_value(out, "lock 0x60d5230: direct calls")) != EXPECTED_LOCK_CALLS:
        fail("census lock calls mismatch: %s" % out)
    if census_value(out, "lock 0x60d5230: tail jumps") != EXPECTED_LOCK_JUMPS:
        fail("census lock jumps mismatch: %s" % out)
    if len(census_value(out, "unlock 0x60d52f0: direct calls")) != EXPECTED_UNLOCK_CALLS:
        fail("census unlock calls mismatch: %s" % out)
    if census_value(out, "unlock 0x60d52f0: tail jumps") != EXPECTED_UNLOCK_JUMPS:
        fail("census unlock jumps mismatch: %s" % out)
    if census_value(out, "stub 0x606ca00: direct calls") != EXPECTED_STUB_CALLS:
        fail("census stub calls mismatch: %s" % out)
    for label in ("lock 0x60d5230: stored qwords (file offsets)",
                  "unlock 0x60d52f0: stored qwords (file offsets)",
                  "stub 0x606ca00: stored qwords (file offsets)",
                  "lock 0x60d5230: RELATIVE slots",
                  "unlock 0x60d52f0: RELATIVE slots",
                  "stub 0x606ca00: RELATIVE slots"):
        if census_value(out, label) != []:
            fail("census %s must be empty: %s" % (label, out))
    if census_value(out, "lock window 0x60d5230: internal direct calls") != EXPECTED_LOCK_INTERNAL_CALLS:
        fail("census lock internal calls mismatch: %s" % out)
    if census_value(out, "lock window 0x60d5230: landing-pad-stub tail jumps") != EXPECTED_LOCK_STUBS:
        fail("census lock stubs mismatch: %s" % out)
    if census_value(out, "lock_cleanup window 0x60d5200: internal direct calls") != EXPECTED_LOCK_CLEANUP_CALLS:
        fail("census lock cleanup calls mismatch: %s" % out)
    if census_value(out, "unlock window 0x60d52f0: internal direct calls") != EXPECTED_UNLOCK_INTERNAL_CALLS:
        fail("census unlock internal calls mismatch: %s" % out)
    if census_value(out, "unlock window 0x60d52f0: landing-pad-stub tail jumps") != EXPECTED_UNLOCK_STUBS:
        fail("census unlock stubs mismatch: %s" % out)
    if census_value(out, "unlock_cleanup window 0x60d52c6: internal direct calls") != EXPECTED_UNLOCK_CLEANUP_CALLS:
        fail("census unlock cleanup calls mismatch: %s" % out)
    if census_value(out, "stub window 0x606ca00: internal direct tail jumps") != EXPECTED_STUB_JUMPS:
        fail("census stub jumps mismatch: %s" % out)
    expected_rows = set()
    for site in census_value(out, "lock 0x60d5230: direct calls"):
        expected_rows.add((site, "0x60d5230", "call"))
    for site in census_value(out, "lock 0x60d5230: tail jumps"):
        expected_rows.add((site, "0x60d5230", "jump"))
    for site in census_value(out, "unlock 0x60d52f0: direct calls"):
        expected_rows.add((site, "0x60d52f0", "call"))
    for site in census_value(out, "unlock 0x60d52f0: tail jumps"):
        expected_rows.add((site, "0x60d52f0", "jump"))
    lines = (PACKET / "callers.tsv").read_text().splitlines()
    if lines[0] != "site\ttarget\tkind":
        fail("callers.tsv header mismatch")
    rows = set(tuple(line.split("\t")) for line in lines[1:])
    if rows != expected_rows:
        fail("callers.tsv rows mismatch census: %d vs %d"
             % (len(rows), len(expected_rows)))


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["task_id"] != "RE-001":
        fail("records task id mismatch")
    if records["census"]["lock_direct_calls"] != EXPECTED_LOCK_CALLS:
        fail("records lock calls mismatch")
    if records["census"]["unlock_direct_calls"] != EXPECTED_UNLOCK_CALLS:
        fail("records unlock calls mismatch")
    if records["census"]["callers_rows"] != 832:
        fail("records callers rows mismatch")
    text = json.dumps(records)
    if "endbr64" in text or "mov " in text:
        fail("records.json must not carry per-instruction detail")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_mutex_wrappers_115.py"],
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
    check_strings()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
