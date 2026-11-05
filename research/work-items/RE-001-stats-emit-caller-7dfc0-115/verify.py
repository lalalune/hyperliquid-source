"""Checker for the RE-001-stats-emit-caller-7dfc0-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-emit-caller-7dfc0-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges in frames.txt against a fresh
frame dump; the RELATIVE records in relocations.txt against a
fresh relocation dump; census consistency (callers.tsv against
a fresh scan: every pinned routine's direct-call and tail-jump
lists, stored qwords, RELATIVE counts, the main routine's and
the cleanup fragment's internal transfer lists) and the
callers.tsv caller function against the smallest enclosing
FDE range from a fresh frame dump; the semantic records; and
the model tests. Prints ALL CHECKS PASSED on success, else raises.
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
    ("main.txt", 0x5D7DFC0, 0x5D7E627),
    ("cleanup.txt", 0x5D7DEDE, 0x5D7DFBA),
    ("string_assign.txt", 0x5D4AB80, 0x5D4AC63),
    ("version_release.txt", 0x5D911E0, 0x5D912A3),
    ("mutex_unlock.txt", 0x60D52F0, 0x60D5385),
    ("noop_hook.txt", 0x5F04CE0, 0x5F04CE5),
    ("identity.txt", 0x5D3A940, 0x5D3A945),
    ("log_dispatch.txt", 0x5FCF060, 0x5FCF153),
    ("registry_lookup.txt", 0x5EEE790, 0x5EEE9E7),
    ("trim_invoke.txt", 0x5EEE9F0, 0x5EEEA59),
    ("acquire.txt", 0x606CA40, 0x606CC6A),
    ("stats_emit.txt", 0x5D52020, 0x5D520C1),
    ("site-5d7e63a.txt", 0x5D7E630, 0x5D7E63F),
]

EXPECTED_CALLS = {
    0x5D7DFC0: [],
    0x5D4AB80: None,  # 35 sites; count-checked, list-checked via TSV
    0x5D911E0: None,
    0x60D52F0: None,
    0x5F04CE0: ["0x5d7e456"],
    0x5D3A940: [],
    0x5FCF060: None,
    0x5EEE790: ["0x5d4dc23", "0x5d63c2f", "0x5d63e3a", "0x5d63f02",
                "0x5d7e221", "0x5d7e26b"],
    0x5EEE9F0: ["0x5d63d20", "0x5d7e249", "0x5d7e2c9"],
    0x5EEF8A0: ["0x5d7e0d7", "0x5ef03d5", "0x5ef9565"],
    0x606CA40: None,
    0x5D52020: ["0x5d7e339"],
    0x5D7DDA0: ["0x5d7e582"],
}

EXPECTED_JUMPS = {
    0x5D7DFC0: ["0x5d7e63a"],
    0x5D4AB80: [],
    0x5D911E0: None,
    0x60D52F0: None,
    0x5F04CE0: [],
    0x5D3A940: [],
    0x5FCF060: None,
    0x5EEE790: [],
    0x5EEE9F0: None,
    0x5EEF8A0: [],
    0x606CA40: None,
    0x5D52020: [],
    0x5D7DDA0: [],
}

EXPECTED_CALL_COUNTS = {
    0x5D4AB80: 35, 0x5D911E0: 53, 0x60D52F0: 669, 0x5FCF060: 252,
    0x606CA40: 244,
}

EXPECTED_JUMP_COUNTS = {
    0x5D911E0: 1, 0x60D52F0: 5, 0x5FCF060: 1, 0x5EEE9F0: 1,
    0x606CA40: 8,
}

EXPECTED_QWORDS = {
    0x5D3A940: ["0x102820", "0x102b20", "0x102dc0", "0x102eb0",
                "0x1031c8", "0x1034b0", "0x105a90", "0x15be18"],
}

EXPECTED_RELATIVE = {0x5D3A940: 8}

EXPECTED_INTERNAL_CALLS = [
    "0x5d7e074", "0x5d7e0c9", "0x5d7e0d7", "0x5d7e103", "0x5d7e138",
    "0x5d7e1c4", "0x5d7e1d8", "0x5d7e221", "0x5d7e249", "0x5d7e26b",
    "0x5d7e2c9", "0x5d7e2ec", "0x5d7e305", "0x5d7e323", "0x5d7e339",
    "0x5d7e35b", "0x5d7e379", "0x5d7e3a8", "0x5d7e3b2", "0x5d7e456",
    "0x5d7e47b", "0x5d7e499", "0x5d7e4ab", "0x5d7e4bc", "0x5d7e4e4",
    "0x5d7e515", "0x5d7e582", "0x5d7e5ce",
]
EXPECTED_INTERNAL_JUMPS = [
    "0x5d7e5da", "0x5d7e5e6", "0x5d7e5f2", "0x5d7e5fe", "0x5d7e60a",
    "0x5d7e616", "0x5d7e622",
]
EXPECTED_INTERNAL_INDIRECT_CALLS = ["0x5d7e111", "0x5d7e56b"]
EXPECTED_INTERNAL_INDIRECT_JUMPS = []
EXPECTED_CLEANUP_CALLS = [
    "0x5d7dee9", "0x5d7def6", "0x5d7df02", "0x5d7df19", "0x5d7df37",
    "0x5d7df60", "0x5d7df6a", "0x5d7df85", "0x5d7df92", "0x5d7df9e",
    "0x5d7dfae", "0x5d7dfb5",
]

SPOT_BYTES = {
    0x5D7DFC0: "f30f1efa",
    0x5D7E074: "e8c7e92e00",
    0x5D7E111: "ff5038",
    0x5D7E339: "e8e23cfdff",
    0x5D7E63A: "e981f9ffff",
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
                "string_assign.txt", "version_release.txt",
                "mutex_unlock.txt", "noop_hook.txt", "identity.txt",
                "log_dispatch.txt", "registry_lookup.txt",
                "trim_invoke.txt", "acquire.txt", "stats_emit.txt",
                "site-5d7e63a.txt", "frames.txt", "relocations.txt",
                "callers.tsv", "export_excerpts.py", "census.py",
                "verify.py"}
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
    fresh = [l for l in text.splitlines()
             if "5d3a940" in l and "RELATIVE" in l]
    if [l.strip() for l in stored] != [l.strip() for l in fresh]:
        fail("relocations.txt mismatch: %r vs %r" % (stored, fresh))
    for target in (0x5D7DFC0, 0x5D4AB80, 0x5D911E0, 0x60D52F0, 0x5F04CE0,
                   0x5FCF060, 0x5EEE790, 0x5EEE9F0, 0x5EEF8A0, 0x606CA40,
                   0x5D52020, 0x5D7DDA0):
        for line in text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                fail("unexpected RELATIVE line for %#x: %s" % (target, line))


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
        if want_calls is not None:
            if sorted(calls) != sorted(want_calls):
                fail("census calls mismatch for %#x: %s vs %s"
                     % (target, calls, want_calls))
        elif len(calls) != EXPECTED_CALL_COUNTS[target]:
            fail("census call count mismatch for %#x: %d"
                 % (target, len(calls)))
        if sorted(calls) != sorted(tsv_calls.get("%#x" % target, [])):
            fail("callers.tsv calls do not match census for %#x" % target)
        want_jumps = EXPECTED_JUMPS[target]
        match = re.search(
            r"routine %#x: tail jumps: (\[.*\])" % target, out)
        if not match:
            fail("census jumps mismatch for %#x" % target)
        jumps = ast.literal_eval(match.group(1))
        if want_jumps is not None:
            if sorted(jumps) != sorted(want_jumps):
                fail("census jumps mismatch for %#x: %s vs %s"
                     % (target, jumps, want_jumps))
        elif len(jumps) != EXPECTED_JUMP_COUNTS[target]:
            fail("census jump count mismatch for %#x: %d"
                 % (target, len(jumps)))
        if sorted(jumps) != sorted(tsv_jumps.get("%#x" % target, [])):
            fail("callers.tsv jumps do not match census for %#x" % target)
        match = re.search(
            r"routine %#x: stored qwords: (\[.*\])" % target, out)
        if not match:
            fail("census output has no stored-qwords list for %#x" % target)
        qwords = ast.literal_eval(match.group(1))
        want_qwords = EXPECTED_QWORDS.get(target, [])
        if sorted(qwords) != sorted(want_qwords):
            fail("census qwords mismatch for %#x: %s vs %s"
                 % (target, qwords, want_qwords))
        match = re.search(
            r"routine %#x: RELATIVE addends: (\d+)" % target, out)
        if not match:
            fail("census output has no RELATIVE count for %#x" % target)
        if int(match.group(1)) != EXPECTED_RELATIVE.get(target, 0):
            fail("census RELATIVE mismatch for %#x" % target)
    for label, want in (
            ("routine 0x5d7dfc0: internal calls", EXPECTED_INTERNAL_CALLS),
            ("routine 0x5d7dfc0: internal tail jumps", EXPECTED_INTERNAL_JUMPS),
            ("routine 0x5d7dfc0: internal indirect calls",
             EXPECTED_INTERNAL_INDIRECT_CALLS),
            ("routine 0x5d7dfc0: internal indirect tail jumps",
             EXPECTED_INTERNAL_INDIRECT_JUMPS),
            ("cleanup 0x5d7dede: internal calls", EXPECTED_CLEANUP_CALLS),
            ("cleanup 0x5d7dede: internal tail jumps", []),
            ("cleanup 0x5d7dede: internal indirect calls", []),
            ("cleanup 0x5d7dede: internal indirect tail jumps", [])):
        match = re.search(r"%s: (\[.*\])" % re.escape(label), out)
        if not match or sorted(ast.literal_eval(match.group(1))) != sorted(want):
            fail("census %s mismatch" % label)
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
    if records["routine"]["address"] != "0x5d7dfc0":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x5d7dfc0..0x5d7e627":
        fail("records routine FDE mismatch")
    if records["routine"]["size_bytes"] != 2151:
        fail("records routine size mismatch")
    if records["routine"]["internal_calls"] != 28:
        fail("records internal call count mismatch")
    if records["routine"]["internal_tail_jumps"] != 7:
        fail("records internal tail jump count mismatch")
    if records["routine"]["internal_indirect_calls"] != 2:
        fail("records internal indirect call count mismatch")
    if records["routine"]["internal_indirect_tail_jumps"] != 0:
        fail("records internal indirect tail jump count mismatch")
    if records["sentinel"]["value"] != "0xffffffff":
        fail("records sentinel mismatch")
    if records["skip_flag"]["field"] != "object +0x17b4":
        fail("records skip flag mismatch")
    if records["emit_phase"]["calls"][0]["format"] != \
            "[%s:1084] ------- DUMPING STATS -------":
        fail("records dump format mismatch")
    if records["emit_phase"]["calls"][1]["format"] != "[%s:1086] %s":
        fail("records dump-string format mismatch")
    if records["malloc_branch"]["calls"][0]["format"] != \
            "[%s:1091] ------- Malloc STATS -------":
        fail("records malloc format mismatch")
    if records["stats_emit_call"]["callee"] != "0x5d52020":
        fail("records stats-emit callee mismatch")
    if records["thunk"]["site"] != "0x5d7e63a":
        fail("records thunk site mismatch")
    if records["census"]["direct_call_count"] != 0:
        fail("records census call count mismatch")
    if records["census"]["tail_jump_count"] != 1:
        fail("records census jump count mismatch")


def check_tests():
    result = subprocess.run(
        [sys.executable, "tests/test_stats_emit_caller_7dfc0_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if result.returncode != 0:
        fail("model tests failed:\n%s" % result.stdout)


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_spots()
    check_frames()
    check_relocations()
    check_census()
    check_records()
    check_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
