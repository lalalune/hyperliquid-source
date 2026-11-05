"""Checker for the RE-001-timestamp-guard-8810-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-timestamp-guard-8810-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges in frames.txt against a fresh
frame dump; the relocation set against a fresh relocation
dump (the getter address is a RELATIVE addend in exactly 4
records; the guard and builder addresses in none); the
message literals against the raw binary; census consistency
(callers.tsv against a fresh scan: guard 15 direct calls,
builder 847 direct calls, getter 0; internal transfers per
routine; stored qwords; RELATIVE addends) and the
callers.tsv caller function against the smallest enclosing
FDE range from a fresh frame dump; the semantic records; and
the model tests. Prints ALL CHECKS PASSED on success, else
raises.
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
    ("main.txt", 0x5D58810, 0x5D58AC5),
    ("status_builder.txt", 0x61CF670, 0x61CF767),
    ("default_getter.txt", 0x5D48510, 0x5D4851C),
]

EXPECTED_CALLS = {
    0x5D58810: ["0x5d60c49", "0x5d618f9", "0x5d6db9a", "0x5d6ff89",
                "0x5d78f08", "0x5e71749", "0x5e7d35d", "0x5e7dc39",
                "0x5e80ad3", "0x5e9457c", "0x5e94b5c", "0x5e94dd7",
                "0x5e952f7", "0x5e9583c", "0x5e95daa"],
    0x5D48510: [],
}
EXPECTED_BUILDER_CALL_COUNT = 847

EXPECTED_JUMPS = {0x5D58810: [], 0x61CF670: [], 0x5D48510: []}

EXPECTED_INTERNAL = {
    0x5D58810: {
        "internal calls": ["0x5d58898", "0x5d588ac", "0x5d588c4",
                           "0x5d58900", "0x5d5896d", "0x5d5899d",
                           "0x5d589a5", "0x5d589c8", "0x5d589e5",
                           "0x5d58a22", "0x5d58a63", "0x5d58a80",
                           "0x5d58a88", "0x5d58aa0", "0x5d58ac0"],
        "internal tail jumps": [],
        "internal indirect calls": ["0x5d58849", "0x5d588b7", "0x5d58a73"],
        "internal indirect tail jumps": [],
    },
    0x61CF670: {
        "internal calls": ["0x61cf6c5", "0x61cf6d7", "0x61cf74f"],
        "internal tail jumps": ["0x61cf704", "0x61cf762"],
        "internal indirect calls": [],
        "internal indirect tail jumps": [],
    },
    0x5D48510: {
        "internal calls": [],
        "internal tail jumps": [],
        "internal indirect calls": [],
        "internal indirect tail jumps": [],
    },
}

EXPECTED_QWORDS = {
    0x5D58810: [],
    0x61CF670: [],
    0x5D48510: ["0x105950", "0x109f58", "0x10adc8", "0x10bf38"],
}

EXPECTED_RELATIVE = {0x5D58810: 0, 0x61CF670: 0, 0x5D48510: 4}

SPOT_BYTES = {
    0x5D58810: "f30f1efa",
    0x5D58849: "ff5028",
    0x5D5899D: "e8ce6c4700",
    0x61CF6C5: "e866172200",
    0x5D48514: "488b8740070000",
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
                "status_builder.txt", "default_getter.txt",
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
    for target in (0x5D58810, 0x61CF670):
        for line in text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                fail("unexpected RELATIVE line for %#x: %s" % (target, line))
    want = [l for l in text.splitlines()
            if "5d48510" in l and "RELATIVE" in l]
    stored = (PACKET / "relocations.txt").read_text().splitlines()
    if stored != want:
        fail("relocations.txt mismatch: %s vs %s" % (stored, want))
    if len(want) != 4:
        fail("getter RELATIVE count mismatch: %d" % len(want))


def va_bytes(vaddr, size):
    data = BINARY.read_bytes()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:
            start = p_offset + (vaddr - p_vaddr)
            return data[start:start + size]
    fail("no LOAD segment for %#x" % vaddr)


def check_literals():
    prefix = va_bytes(0x9600B8, 41)
    if prefix != b"cannot call this method on column family ":
        fail("prefix literal mismatch: %r" % prefix)
    suffix = va_bytes(0x437085, 23)
    if suffix != b" that enables timestamp":
        fail("suffix literal mismatch: %r" % suffix)
    if va_bytes(0x4376FD, 1) != b"\x00":
        fail("second-view first byte is not NUL")
    path = va_bytes(0x4376FE, 68)
    if path != b"/home/ubuntu/hl/code_Mainnet/z_vendor/futures-channel/src/oneshot.rs":
        fail("oneshot path mismatch: %r" % path)


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
    for target in (0x5D58810, 0x61CF670, 0x5D48510):
        match = re.search(
            r"routine %#x: direct calls: (\[.*\])" % target, out)
        if not match:
            fail("census output has no direct-calls list for %#x" % target)
        calls = ast.literal_eval(match.group(1))
        if target in EXPECTED_CALLS:
            if sorted(calls) != sorted(EXPECTED_CALLS[target]):
                fail("census calls mismatch for %#x: %s vs %s"
                     % (target, calls, EXPECTED_CALLS[target]))
        else:
            if len(calls) != EXPECTED_BUILDER_CALL_COUNT:
                fail("builder call count mismatch: %d" % len(calls))
        if sorted(calls) != sorted(tsv_calls.get("%#x" % target, [])):
            fail("callers.tsv calls do not match census for %#x" % target)
        want_jumps = EXPECTED_JUMPS[target]
        match = re.search(
            r"routine %#x: tail jumps: (\[.*\])" % target, out)
        if not match:
            fail("census jumps missing for %#x" % target)
        jumps = ast.literal_eval(match.group(1))
        if sorted(jumps) != sorted(want_jumps):
            fail("census jumps mismatch for %#x: %s vs %s"
                 % (target, jumps, want_jumps))
        if sorted(jumps) != sorted(tsv_jumps.get("%#x" % target, [])):
            fail("callers.tsv jumps do not match census for %#x" % target)
        for label, want in EXPECTED_INTERNAL[target].items():
            match = re.search(
                r"routine %#x: %s: (\[.*\])" % (target, label), out)
            if not match or sorted(ast.literal_eval(match.group(1))) != sorted(want):
                fail("census %s mismatch for %#x" % (label, target))
        match = re.search(
            r"routine %#x: stored qwords: (\[.*\])" % target, out)
        if not match or sorted(ast.literal_eval(match.group(1))) != sorted(EXPECTED_QWORDS[target]):
            fail("census stored qwords mismatch for %#x" % target)
        match = re.search(
            r"routine %#x: RELATIVE addends: (\d+)" % target, out)
        if not match or int(match.group(1)) != EXPECTED_RELATIVE[target]:
            fail("census RELATIVE mismatch for %#x" % target)
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
    if records["routine"]["address"] != "0x5d58810":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x5d58810..0x5d58ac5":
        fail("records routine FDE mismatch")
    if records["routine"]["size_bytes"] != 693:
        fail("records routine size mismatch")
    if records["routine"]["internal_calls"] != 15:
        fail("records internal call count mismatch")
    if records["routine"]["internal_indirect_calls"] != 3:
        fail("records internal indirect call count mismatch")
    if records["builder"]["address"] != "0x61cf670":
        fail("records builder address mismatch")
    if records["builder"]["size_bytes"] != 247:
        fail("records builder size mismatch")
    if records["builder"]["internal_calls"] != 3:
        fail("records builder internal call count mismatch")
    if records["builder"]["internal_tail_jumps"] != 2:
        fail("records builder internal tail jump count mismatch")
    if records["getter"]["address"] != "0x5d48510":
        fail("records getter address mismatch")
    if records["getter"]["size_bytes"] != 12:
        fail("records getter size mismatch")
    if records["literals"]["prefix"]["text"] != "cannot call this method on column family ":
        fail("records prefix mismatch")
    if records["literals"]["suffix"]["text"] != " that enables timestamp":
        fail("records suffix mismatch")
    if records["literals"]["second_view"]["length"] != 0:
        fail("records second view length mismatch")
    if records["status"]["invalid_argument_code"] != 4:
        fail("records code mismatch")
    if records["resolve"]["default_getter"] != "0x5d48510":
        fail("records default getter mismatch")
    if records["census"]["guard"]["direct_calls"] != 15:
        fail("records guard call count mismatch")
    if records["census"]["builder"]["direct_calls"] != 847:
        fail("records builder call count mismatch")
    if records["census"]["getter"]["relative_addends"] != 4:
        fail("records getter RELATIVE count mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_timestamp_guard_8810_115.py"],
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
    check_literals()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
