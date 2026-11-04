"""Checker for the RE-001-string-dispose-4-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-string-dispose-4-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges against a fresh frame dump;
the empty relocation set against a fresh relocation dump;
census consistency (callers.tsv against a fresh scan: 36
direct calls, 0 tail jumps, no stored qwords, no RELATIVE
addends, 3 internal delete calls, 1 internal delete tail
jump) and each callers.tsv caller function against the
smallest enclosing FDE range from a fresh frame dump; the
semantic records; and the model tests.
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
    ("main.txt", 0x5D506B0, 0x5D5073A),
]

EXPECTED_CALLS = {
    0x5D506B0: ["0x5d78601", "0x5de3307", "0x5de4404", "0x5dec2c1", "0x5deca32", "0x5deca42", "0x5decc25", "0x5ded8da", "0x5df3c7c", "0x5e09df5", "0x5e09e4d", "0x5e0c959", "0x5e0d0f4", "0x5e0d948", "0x5e0dbe1", "0x5e41e9d", "0x5e4452e", "0x5e45bdc", "0x5e663e8", "0x5e6645b", "0x5e6846d", "0x5ec960d", "0x5ecdb74", "0x5ed2353", "0x5ee94ad", "0x5f5abca", "0x5f5abda", "0x5f5b168", "0x5f5b175", "0x5f5c026", "0x5f5c123", "0x5f717a5", "0x5f71c80", "0x5f7a91f", "0x5f7aae9", "0x5f89ecf"],
}

EXPECTED_JUMPS = {0x5D506B0: []}

EXPECTED_INTERNAL_CALLS = ["0x5d506d6", "0x5d506f9",
                           "0x5d50713"]
EXPECTED_INTERNAL_JUMPS = ["0x5d5072e"]

SPOT_BYTES = {
    0x5D506B0: "f30f1efa",
    0x5D506D6: "e8a5066a00",
    0x5D5072E: "e94d066a00",
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
    for want in ("pc=0000000005d506b0..0000000005d5073a", "pc=0000000005d78340..0000000005d78648", "pc=0000000005de3252..0000000005de3339", "pc=0000000005de404e..0000000005de44b7", "pc=0000000005debe90..0000000005dec308", "pc=0000000005dec310..0000000005deca70", "pc=0000000005deca70..0000000005decc65", "pc=0000000005decc70..0000000005dedffa", "pc=0000000005df3b74..0000000005df3dc4", "pc=0000000005e09a60..0000000005e09e6f", "pc=0000000005e0c690..0000000005e0c979", "pc=0000000005e0ce40..0000000005e0d142", "pc=0000000005e0d150..0000000005e0eb39", "pc=0000000005e41dbe..0000000005e41f96", "pc=0000000005e41fa0..0000000005e44899", "pc=0000000005e45b64..0000000005e46100", "pc=0000000005e6634e..0000000005e6669c", "pc=0000000005e666a0..0000000005e68ceb", "pc=0000000005ec95d4..0000000005ec9669", "pc=0000000005ecd9d2..0000000005ecdbe0", "pc=0000000005ed2238..0000000005ed243b", "pc=0000000005ee93ba..0000000005ee94b9", "pc=0000000005f5a4c0..0000000005f5ac08", "pc=0000000005f5b160..0000000005f5b1cf", "pc=0000000005f5bfea..0000000005f5c1bf", "pc=0000000005f71730..0000000005f717d0", "pc=0000000005f717d0..0000000005f71d22", "pc=0000000005f7a8c2..0000000005f7ac10", "pc=0000000005f89d5e..0000000005f89ef0"):
        if want not in text:
            fail("frame range missing: %s" % want)
        if want not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % want)


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for target in (0x5D506B0,):
        for line in text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                fail("unexpected RELATIVE line for %#x: %s" % (target, line))
    if (PACKET / "relocations.txt").read_text() != "":
        fail("relocations.txt is not empty")


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
            r"routine %#x: internal delete calls: (\[.*\])" % target, out)
        if not match or ast.literal_eval(match.group(1)) != EXPECTED_INTERNAL_CALLS:
            fail("internal delete calls mismatch")
        match = re.search(
            r"routine %#x: internal delete tail jumps: (\[.*\])" % target, out)
        if not match or ast.literal_eval(match.group(1)) != EXPECTED_INTERNAL_JUMPS:
            fail("internal delete tail jumps mismatch")
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
    if records["routine"]["address"] != "0x5d506b0":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x5d506b0..0x5d5073a":
        fail("records routine FDE mismatch")
    if records["routine"]["size_bytes"] != 138:
        fail("records routine size mismatch")
    if records["fields"]["count"] != 4:
        fail("records field count mismatch")
    if records["fields"]["order"] != ["0xf8", "0xd8",
                                     "0x48", "0x28"]:
        fail("records field order mismatch")
    if records["dispose_rule"]["delete_size"] != "capacity + 1":
        fail("records delete size mismatch")
    if records["census"]["direct_call_count"] != 36:
        fail("records call count mismatch")
    if records["census"]["internal_delete_calls"] != 3:
        fail("records internal delete call count mismatch")
    if records["census"]["internal_delete_tail_jump"] != 1:
        fail("records internal delete tail jump mismatch")
    if records["census"]["tail_jump_count"] != 0:
        fail("records census jump count mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_string_dispose_4_115.py"],
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
