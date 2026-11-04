"""Checker for the RE-001-slot-replace-4cc80-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-slot-replace-4cc80-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE range in frames.txt against a fresh
frame dump; the relocation record against a fresh readelf -r
run; census consistency (0 direct calls, 0 tail jumps, the
four .rela.dyn addend file offsets, 6 internal calls, 2
landing-pad-stub tail jumps, 2 internal indirect calls, 0
internal indirect tail jumps, the four RELATIVE slots,
callers.tsv with no rows, pointer_slots.tsv matching the
records); the report strings in the binary; the semantic
records; and the model tests. Prints ALL CHECKS PASSED on
success, else raises.
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
    ("main.txt", 0x5D4CC80, 0x5D4CE6A),
]

EXPECTED_CALLS = []
EXPECTED_TAIL_JUMPS = []
EXPECTED_QWORDS = ["0x104ab8", "0x1090c0", "0x109f30", "0x10b0a0"]
EXPECTED_SLOTS = ["0x64c97c8", "0x64cb540", "0x64cba20", "0x64cc020"]
EXPECTED_INTERNAL_CALLS = ["0x5d4cccc", "0x5d4cd33", "0x5d4cd88",
                           "0x5d4cdf7", "0x5d4ce43", "0x5d4ce4d"]
EXPECTED_INTERNAL_TAIL_JUMPS = ["0x5d4ce59", "0x5d4ce65"]
EXPECTED_INTERNAL_INDIRECT_CALLS = ["0x5d4cd48", "0x5d4cd58"]
EXPECTED_POINTER_SLOTS = {
    "0x64c97c8": ("0x5d49030", "0x5d44c50", "0x5d48980", "0x5d5b520"),
    "0x64cb540": ("0x5d49030", "0x5d44c50", "0x5d48980", "0x5d5b520"),
    "0x64cba20": ("0x5d49030", "0x5d44c50", "0x5d48980", "0x5d5b520"),
    "0x64cc020": ("0x5d49030", "0x5d44c50", "0x5e84a80", "0x5d5b520"),
}

SPOT_BYTES = {
    0x5D4CCAE: "80bec904000000",
    0x5D4CD33: "e848f93100",
    0x5D4CD48: "ff5008",
    0x5D4CE43: "e828284800",
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
                "pointer_slots.tsv",
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
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    fresh = [line for line in text.splitlines()
             if "5d4cc80" in line and "RELATIVE" in line]
    stored = (PACKET / "relocations.txt").read_text().splitlines()
    if fresh != stored:
        fail("relocations.txt mismatch: %s vs %s" % (stored, fresh))
    if len(stored) != 4:
        fail("relocations.txt must hold 4 lines, got %d" % len(stored))


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    match = re.search(
        r"routine 0x5d4cc80: direct calls: (\[.*\])", out)
    if not match or ast.literal_eval(match.group(1)) != EXPECTED_CALLS:
        fail("census calls mismatch: %s" % out)
    match = re.search(
        r"routine 0x5d4cc80: tail jumps: (\[.*\])", out)
    if not match or ast.literal_eval(match.group(1)) != EXPECTED_TAIL_JUMPS:
        fail("census jumps mismatch: %s" % out)
    match = re.search(
        r"routine 0x5d4cc80: stored qwords \(file offsets\): (\[.*\])", out)
    if not match or sorted(ast.literal_eval(match.group(1))) != sorted(EXPECTED_QWORDS):
        fail("census stored qwords mismatch: %s" % out)
    match = re.search(
        r"routine 0x5d4cc80: RELATIVE slots: (\[.*\])", out)
    if not match or sorted(ast.literal_eval(match.group(1))) != sorted(EXPECTED_SLOTS):
        fail("census RELATIVE slots mismatch: %s" % out)
    for label, want in (
            ("internal calls", EXPECTED_INTERNAL_CALLS),
            ("internal tail jumps", EXPECTED_INTERNAL_TAIL_JUMPS),
            ("internal indirect calls", EXPECTED_INTERNAL_INDIRECT_CALLS),
            ("internal indirect tail jumps", [])):
        match = re.search(
            r"routine 0x5d4cc80: %s: (\[.*\])" % label, out)
        if not match or sorted(ast.literal_eval(match.group(1))) != sorted(want):
            fail("census %s mismatch" % label)
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    if rows:
        fail("callers.tsv must hold no rows, got %d" % len(rows))
    rows = (PACKET / "pointer_slots.tsv").read_text().splitlines()[1:]
    if len(rows) != 4:
        fail("pointer_slots.tsv must hold 4 rows, got %d" % len(rows))
    for row in rows:
        slot, prev2, prev1, next1, next2 = row.split("\t")
        if EXPECTED_POINTER_SLOTS.get(slot) != (prev2, prev1, next1, next2):
            fail("pointer_slots.tsv row mismatch: %s" % row)


def read_vaddr(data, vaddr, length):
    """Read length bytes at a virtual address via program headers."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:
            start = p_offset + (vaddr - p_vaddr)
            return data[start:start + length]
    fail("vaddr %#x not in any LOAD segment" % vaddr)


def check_strings():
    data = BINARY.read_bytes()
    if read_vaddr(data, 0x960EE0, 32) != b"stats_iterator not preallocated.":
        fail("report message mismatch")
    if read_vaddr(data, 0x4376FD, 1) != b"\x00":
        fail("path pointer byte mismatch")
    path = read_vaddr(data, 0x4376FE, 100).split(b"\x00")[0]
    if path != b"/home/ubuntu/hl/code_Mainnet/z_vendor/futures-channel/src/oneshot.rs":
        fail("report path mismatch: %r" % path)


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["task"] != "RE-001":
        fail("records task mismatch")
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["routine"]["address"] != "0x5d4cc80":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x5d4cc80..0x5d4ce6a":
        fail("records routine FDE mismatch")
    if records["routine"]["size_bytes"] != 490:
        fail("records routine size mismatch")
    if records["routine"]["internal_calls"] != 6:
        fail("records internal call count mismatch")
    if records["routine"]["internal_tail_jumps"] != 2:
        fail("records internal tail jump count mismatch")
    if records["routine"]["internal_indirect_calls"] != 2:
        fail("records internal indirect call count mismatch")
    if records["census"]["direct_call_count"] != 0:
        fail("records call count mismatch")
    if records["census"]["tail_jump_count"] != 0:
        fail("records census jump count mismatch")
    if records["census"]["relative_addends"] != 4:
        fail("records RELATIVE count mismatch")
    if len(records["phases"]) != 3:
        fail("records phase count mismatch")
    if records["phases"][0]["name"] != "null slot report":
        fail("records first phase mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_slot_replace_4cc80_115.py"],
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
    check_strings()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
