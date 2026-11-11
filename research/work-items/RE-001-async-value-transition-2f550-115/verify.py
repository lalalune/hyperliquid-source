"""Checker for the RE-001-async-value-transition-2f550-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-async-value-transition-2f550-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary (objdump
splits a few long instructions across two lines; the parser
accumulates those continuations); spot instructions byte-for-byte
against a fresh objdump run and the raw binary; the jump table
entries and the two guard message strings against the raw binary;
the FDE ranges in frames.txt against a fresh frame dump; the
relocation records in relocations.txt against a fresh relocation
dump; census consistency (callers.tsv against a fresh scan: 10
direct calls, 0 tail jumps, no stored qwords, no RELATIVE
addends for the routine address, 6 internal calls, 0 internal
direct tail jumps, 6 internal indirect calls, 1 internal
indirect tail jump) and the callers.tsv caller function against
the smallest enclosing FDE range from a fresh frame dump; the
semantic records; and the model tests. Prints ALL CHECKS PASSED
on success, else raises.
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
    ("main.txt", 0x5A2F550, 0x5A2F661),
    ("helper.txt", 0x5A2F760, 0x5A2FA70),
    ("release.txt", 0x5A52490, 0x5A52518),
    ("guard_completion.txt", 0x1681E60, 0x1681E7A),
    ("guard_panicking.txt", 0x1681E80, 0x1681E9A),
    ("caller.txt", 0x5A794E8, 0x5A794F7),
]

EXPECTED_CALLS = {
    0x5A2F550: ["0x5a5edb5", "0x5a61eab", "0x5a66fe6", "0x5a6b0fd",
                "0x5a6d24d", "0x5a7115a", "0x5a794f2", "0x5a7e632",
                "0x5a8507d", "0x5a89d98"],
}

EXPECTED_JUMPS = {0x5A2F550: []}

EXPECTED_INTERNAL_CALLS = ["0x5a2f59e", "0x5a2f5e8", "0x5a2f622",
                           "0x5a2f63c", "0x5a2f647", "0x5a2f656"]
EXPECTED_INTERNAL_JUMPS = []
EXPECTED_INTERNAL_INDIRECT_CALLS = ["0x5a2f5cd", "0x5a2f5de",
                                    "0x5a2f608", "0x5a2f615",
                                    "0x5a2f629", "0x5a2f65b"]
EXPECTED_INTERNAL_INDIRECT_JUMPS = ["0x5a2f56f"]

SPOT_BYTES = {
    0x5A2F550: "55",
    0x5A2F561: "488d0dec99f0fa",
    0x5A2F56F: "ffe0",
    0x5A2F57E: "660f2ec1",
    0x5A2F590: "c6838800000000",
    0x5A2F59E: "e8bd010000",
    0x5A2F5C7: "f048ff08",
    0x5A2F5E8: "e8a32e0200",
    0x5A2F5EF: "4088ab90000000",
    0x5A2F608: "ff15521dab00",
    0x5A2F615: "ff154d1dab00",
    0x5A2F656: "e8f5139c00",
    0x5A2F760: "55",
    0x5A2F773: "0fb64778",
    0x5A2FA47: "c6437802",
    0x5A52490: "4156",
    0x1681E60: "55",
    0x1681E80: "55",
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
                "helper.txt", "release.txt", "guard_completion.txt",
                "guard_panicking.txt", "caller.txt", "frames.txt",
                "relocations.txt", "callers.tsv", "export_excerpts.py",
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


def check_table_and_messages():
    # The table and the message strings live in the first LOAD
    # segment, where the virtual address equals the file offset.
    data = BINARY.read_bytes()
    want = [0x5A2F571, 0x5A2F60E, 0x5A2F601, 0x5A2F597]
    for i, target in enumerate(want):
        off = struct.unpack_from("<i", data, 0x938F54 + 4 * i)[0]
        if 0x938F54 + off != target:
            fail("jump table entry %d mismatch: %#x" % (i, 0x938F54 + off))
    if data[0x46F2ED:0x46F2ED + 35] != b"`async fn` resumed after completion":
        fail("completion guard message mismatch")
    if data[0x46F310:0x46F310 + 34] != b"`async fn` resumed after panicking":
        fail("panicking guard message mismatch")
    if data[0x46E9BD:0x46E9BD + 36] != b"panic in a destructor during cleanup":
        fail("cleanup panic message mismatch")


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
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        if line.strip() and line not in text:
            fail("relocation record missing from fresh dump: %s" % line)


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
    if routine["address"] != "0x5a2f550":
        fail("records routine address mismatch")
    if routine["fde"] != "0x5a2f550..0x5a2f661":
        fail("records routine FDE mismatch")
    if routine["size_bytes"] != 273:
        fail("records routine size mismatch")
    if routine["internal_calls"] != 6:
        fail("records internal call count mismatch")
    if routine["internal_indirect_calls"] != 6:
        fail("records internal indirect call count mismatch")
    if routine["internal_tail_jumps"] != 0:
        fail("records internal tail jump count mismatch")
    if routine["internal_indirect_tail_jumps"] != 1:
        fail("records internal indirect tail jump count mismatch")
    table = records["jump_table"]
    if table["address"] != "0x938f54":
        fail("records jump table address mismatch")
    if table["targets"] != {"0": "0x5a2f571", "1": "0x5a2f60e",
                            "2": "0x5a2f601", "3": "0x5a2f597"}:
        fail("records jump table targets mismatch")
    if records["helper"]["callee"] != "0x5a2f760":
        fail("records helper callee mismatch")
    if records["release"]["callee"] != "0x5a52490":
        fail("records release callee mismatch")
    if records["cleanup_callee"]["callee"] != "0x5a55e70":
        fail("records cleanup callee mismatch")
    guards = records["guards"]
    if guards["completion"]["shim"] != "0x1681e60":
        fail("records completion guard mismatch")
    if guards["panicking"]["shim"] != "0x1681e80":
        fail("records panicking guard mismatch")
    if guards["global_cell"]["relocated_value"] != "0x4326c1":
        fail("records global cell value mismatch")
    if records["census"]["direct_call_count"] != 10:
        fail("records call count mismatch")
    if records["census"]["tail_jump_count"] != 0:
        fail("records census jump count mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_async_value_transition_2f550_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "checks pass" not in out:
        fail("model tests did not pass: %s" % out)


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_spots()
    check_table_and_messages()
    check_frames()
    check_relocations()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
