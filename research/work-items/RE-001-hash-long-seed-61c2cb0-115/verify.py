"""Checker for the RE-001-hash-long-seed-61c2cb0-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-hash-long-seed-61c2cb0-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges in frames.txt against a fresh
frame dump; the relocation records in relocations.txt against
a fresh relocation dump (no RELATIVE record carries the
routine, and the __stack_chk_fail JUMP_SLOT behind the
canary-failure call is present); census consistency
(callers.tsv against a fresh scan: 0 direct calls, 1 tail
jump, no stored qwords, no RELATIVE addends, 2 internal
calls, 1 internal direct tail jump, 0 internal indirect
calls, 0 internal indirect tail jumps) and the callers.tsv
caller function against the smallest enclosing FDE range
from a fresh frame dump; the semantic records; and the
model tests. The Unicorn differential (differential.py) is
a separate check that needs the unicorn package. Prints
ALL CHECKS PASSED on success, else raises.
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
    ("main.txt", 0x61C2CB0, 0x61C3221),
]

EXPECTED_CALLS = {
    0x61C2CB0: [],
}

EXPECTED_JUMPS = {0x61C2CB0: ["0x61c3808"]}

EXPECTED_INTERNAL_CALLS = ["0x61c31fc", "0x61c321c"]
EXPECTED_INTERNAL_JUMPS = ["0x61c2cf3"]
EXPECTED_INTERNAL_INDIRECT_CALLS = []
EXPECTED_INTERNAL_INDIRECT_JUMPS = []

SPOT_BYTES = {
    0x61C2CB0: "4881ec18010000",
    0x61C2CD0: "4885d2",
    0x61C2CF3: "e998fbffff",
    0x61C2E6C: "0f84b6010000",
    0x61C31E6: "48ba87caeb85b179379e",
    0x61C31F0: "488d74244b",
    0x61C31FC: "e8eff5ffff",
    0x61C3214: "4881c418010000",
    0x61C321B: "c3",
    0x61C321C: "e84fdb2200",
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
                "export_excerpts.py", "census.py", "verify.py",
                "differential.py"}
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
    for target in (0x61C2CB0,):
        for line in text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                fail("unexpected RELATIVE line for %#x: %s" % (target, line))
    stored = (PACKET / "relocations.txt").read_text()
    if not any("64ee308" in line and "__stack_chk_fail" in line
               for line in text.splitlines()):
        fail("__stack_chk_fail JUMP_SLOT for 0x64ee308 missing")
    if "64ee308" not in stored or "__stack_chk_fail" not in stored:
        fail("relocations.txt does not record the stack-check slot")


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
        for label, want in (
                ("internal calls", EXPECTED_INTERNAL_CALLS),
                ("internal tail jumps", EXPECTED_INTERNAL_JUMPS),
                ("internal indirect calls", EXPECTED_INTERNAL_INDIRECT_CALLS),
                ("internal indirect tail jumps", EXPECTED_INTERNAL_INDIRECT_JUMPS)):
            match = re.search(
                r"routine %#x: %s: (\[.*\])" % (target, label), out)
            if not match or sorted(ast.literal_eval(match.group(1))) != sorted(want):
                fail("census %s mismatch" % label)
    for target in EXPECTED_CALLS:
        for want in ("routine %#x: stored qwords: []" % target,
                     "routine %#x: RELATIVE addends: 0" % target):
            if want not in out:
                fail("census mismatch, missing %r" % want)
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
    routine = records["routine"]
    if routine["address"] != "0x61c2cb0":
        fail("records routine address mismatch")
    if routine["fde"] != "0x61c2cb0..0x61c3221":
        fail("records routine FDE mismatch")
    if routine["size_bytes"] != 1393:
        fail("records routine size mismatch")
    if routine["internal_calls"] != len(EXPECTED_INTERNAL_CALLS):
        fail("records internal call count mismatch")
    if routine["internal_tail_jumps"] != len(EXPECTED_INTERNAL_JUMPS):
        fail("records internal tail jump count mismatch")
    if routine["internal_indirect_calls"] \
            != len(EXPECTED_INTERNAL_INDIRECT_CALLS):
        fail("records internal indirect call count mismatch")
    if routine["internal_indirect_tail_jumps"] \
            != len(EXPECTED_INTERNAL_INDIRECT_JUMPS):
        fail("records internal indirect tail jump count mismatch")
    census = records["census"]
    if census["direct_call_count"] != 0:
        fail("records direct call count mismatch")
    if census["tail_jump_count"] != 1:
        fail("records census jump count mismatch")
    if census["internal_calls"] != len(EXPECTED_INTERNAL_CALLS):
        fail("records census internal calls mismatch")
    if census["internal_tail_jumps"] != len(EXPECTED_INTERNAL_JUMPS):
        fail("records census internal jumps mismatch")
    if len(records["consumers"]) != 1:
        fail("records consumers mismatch")
    if records["consumers"][0]["site"] != "0x61c3808":
        fail("records consumer site mismatch")
    if records["delegation"]["target"].split(" ")[0] != "0x61c2890":
        fail("records delegation target mismatch")
    sources = records["custom_secret"]["sources"]
    if len(sources) != 24:
        fail("records custom secret source count mismatch")
    for i, source in enumerate(sources):
        want_delta = "+seed" if i % 2 == 0 else "-seed"
        if source["delta"] != want_delta:
            fail("records custom secret delta mismatch at %d" % i)
        if source["secret_byte_offset"] != 8 * i:
            fail("records custom secret offset mismatch at %d" % i)
    if len(records["acc_init"]["values"]) != 8:
        fail("records acc init count mismatch")
    if records["merge_handoff"]["site"] != "0x61c31fc":
        fail("records merge hand-off site mismatch")
    if records["accumulate"]["last_stripe"] is None:
        fail("records last stripe missing")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_hash_long_seed_61c2cb0_115.py"],
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
