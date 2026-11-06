"""Checker for the RE-001-refresh-callee-8a0-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-refresh-callee-8a0-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges in frames.txt against a fresh
frame dump; the relocation records in relocations.txt against a
fresh relocation dump; census consistency (callers.tsv against
a fresh scan for every pinned routine, the stored-qword lists,
the RELATIVE addend counts, and the refresh routine's internal
transfers) and the callers.tsv caller function against the
smallest enclosing FDE range from a fresh frame dump; the
semantic records; and the model tests. Prints
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

WINDOWS = [('main.txt', 99547296, 99548489), ('cleanup.txt', 99547220, 99547293), ('filler.txt', 99545984, 99547219), ('string_move.txt', 99531552, 99531768), ('produce_identity.txt', 97789920, 97790114), ('walker70.txt', 97710016, 97710186), ('walker78.txt', 97709840, 97710010), ('const_minus1.txt', 97775472, 97775484), ('const_zero.txt', 97775488, 97775495), ('pid_wrapper.txt', 101539456, 101539476), ('range_begin.txt', 99529360, 99529404), ('range_end.txt', 99530576, 99530629), ('init_record.txt', 99542304, 99542354), ('store_value.txt', 99542368, 99542380), ('bump_counter.txt', 99542384, 99542396), ('walker.txt', 97834128, 97834322), ('caller_5ef0390.txt', 99550096, 99550728), ('caller_5ef9520.txt', 99587360, 99587936), ('site-5d7e0d7.txt', 98033840, 98033906), ('site-5ef03d5.txt', 99550134, 99550170), ('site-5ef9565.txt', 99587398, 99587434)]

EXPECTED_CALLS = {99547296: ['0x5d7e0d7', '0x5ef03d5', '0x5ef9565'], 99545984: ['0x5eef9b1'], 99542304: ['0x5eef9db'], 99542384: ['0x5eefb04'], 99542368: ['0x5eefb5c'], 99531552: ['0x5eec463', '0x5eed2da', '0x5eee3db', '0x5eef126', '0x5eef2f4', '0x5eef3f1', '0x5eef5d9', '0x5ef0563', '0x5ef4d06', '0x5ef4fe2', '0x5ef5fd6', '0x5ef606c', '0x5ef60a3', '0x5ef60e4', '0x5ef6125', '0x5ef6460', '0x5ef840f', '0x5ef847e', '0x5ef84da', '0x5ef9c6d'], 101539456: ['0x5eef56e', '0x602e7f2', '0x602ea58', '0x602ea91'], 99548576: ['0x5ef0558', '0x5ef7aad'], 99582816: ['0x5ef96db']}

EXPECTED_JUMPS = {t: [] for t in EXPECTED_CALLS}

EXPECTED_QWORDS = {99531552: [], 99542304: [], 99542368: [], 99542384: [], 99545984: [], 99547296: [], 99548576: [], 99582816: [], 101539456: []}

EXPECTED_RELATIVE = {99531552: 0, 99542304: 0, 99542368: 0, 99542384: 0, 99545984: 0, 99547296: 0, 99548576: 0, 99582816: 0, 101539456: 0}

EXPECTED_INTERNAL_CALLS = ["0x5eef902", "0x5eef9b1", "0x5eef9db",
                           "0x5eefb04", "0x5eefb5c", "0x5eefb64",
                           "0x5eefb94", "0x5eefc85", "0x5eefcf2",
                           "0x5eefd09", "0x5eefd20"]
EXPECTED_INTERNAL_JUMPS = ["0x5eefcab", "0x5eefd2c", "0x5eefd38",
                           "0x5eefd44"]
EXPECTED_INTERNAL_INDIRECT_CALLS = ["0x5eef979", "0x5eefac3",
                                    "0x5eefae8", "0x5eefb18",
                                    "0x5eefb2f", "0x5eefb3b",
                                    "0x5eefcd0", "0x5eefceb"]
EXPECTED_INTERNAL_INDIRECT_JUMPS = []

SPOT_BYTES = {
    0x5EEF8A0: "f30f1efa",
    0x5EEF902: "e859125000",
    0x5EEF979: "ff9098000000",
    0x5EEF9B1: "e8caf9ffff",
    0x5EEFB94: "e867135000",
    0x5EEFCAB: "e9c00e5000",
    0x5EEF380: "f30f1efa",
    0x5EEBB20: "55",
    0x5D427E0: "f30f1efa",
    0x5EF03D5: "e8c6f4ffff",
    0x5EF9565: "e83663ffff",
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
    expected = {"README.md", "records.json", "frames.txt",
                "relocations.txt", "callers.tsv", "export_excerpts.py",
                "census.py", "verify.py"}
    expected |= {name for name, _s, _e in WINDOWS}
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
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        if line.strip() not in text:
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
        match = re.search(
            r"routine %#x: stored qwords: (\[.*\])" % target, out)
        if not match:
            fail("census output has no stored-qwords list for %#x" % target)
        qwords = ast.literal_eval(match.group(1))
        if sorted(qwords) != sorted(EXPECTED_QWORDS.get(target, [])):
            fail("census qwords mismatch for %#x: %s vs %s"
                 % (target, qwords, EXPECTED_QWORDS.get(target, [])))
        match = re.search(
            r"routine %#x: RELATIVE addends: (\d+)" % target, out)
        if not match:
            fail("census output has no RELATIVE count for %#x" % target)
        if int(match.group(1)) != EXPECTED_RELATIVE.get(target, 0):
            fail("census RELATIVE mismatch for %#x" % target)
    for label, want in (
            ("internal calls", EXPECTED_INTERNAL_CALLS),
            ("internal tail jumps", EXPECTED_INTERNAL_JUMPS),
            ("internal indirect calls", EXPECTED_INTERNAL_INDIRECT_CALLS),
            ("internal indirect tail jumps", EXPECTED_INTERNAL_INDIRECT_JUMPS)):
        match = re.search(
            r"routine %#x: %s: (\[.*\])" % (0x5EEF8A0, label), out)
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
    if records["routine"]["address"] != "0x5eef8a0":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x5eef8a0..0x5eefd49":
        fail("records routine FDE mismatch")
    if records["routine"]["size_bytes"] != 1193:
        fail("records routine size mismatch")
    if records["routine"]["internal_calls"] != 11:
        fail("records internal call count mismatch")
    if records["routine"]["internal_tail_jumps"] != 4:
        fail("records internal tail jump count mismatch")
    if records["routine"]["internal_indirect_calls"] != 8:
        fail("records internal indirect tail jump count mismatch")
    if records["routine"]["internal_indirect_tail_jumps"] != 0:
        fail("records internal indirect tail jump count mismatch")
    if records["budget"]["slow"]["per_unit_ns"] != 500:
        fail("records slow per-unit mismatch")
    if records["budget"]["slow"]["cap_ns"] != 180000000:
        fail("records slow cap mismatch")
    if records["budget"]["fast"]["per_unit_ns"] != 10:
        fail("records fast per-unit mismatch")
    if records["budget"]["fast"]["cap_ns"] != 10000000:
        fail("records fast cap mismatch")
    if records["chain_walk"]["identity"] != "0x5d4d490":
        fail("records walker mismatch")
    if records["produce_chain"]["identity"] != "0x5d427e0":
        fail("records produce identity mismatch")
    if records["snapshot"]["size_bytes"] != 312:
        fail("records snapshot size mismatch")
    if records["publish_copy"]["size_bytes"] != 312:
        fail("records publish size mismatch")
    if records["name_string"]["format"] != "name@0x<ptr>#<pid>":
        fail("records name format mismatch")
    if len(records["callers"]) != 3:
        fail("records caller count mismatch")
    if records["census"]["direct_calls"]["0x5eef8a0"] != [
            "0x5d7e0d7", "0x5ef03d5", "0x5ef9565"]:
        fail("records refresh call list mismatch")
    if len(records["census"]["direct_calls"]["0x5eebb20"]) != 20:
        fail("records string-move call count mismatch")
    if records["census"]["relative_addends"]["0x5d427e0"] != 4:
        fail("records RELATIVE count mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_refresh_callee_8a0_115.py"],
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
