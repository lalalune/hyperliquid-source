"""Checker for the RE-001-node-tree-60-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-node-tree-60-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges against a fresh frame dump;
the empty relocation set against a fresh relocation dump;
census consistency (callers.tsv against a fresh whole-file
scan: teardown 23 calls, copy 4 calls, builder 79 calls, no
tail jumps, no stored qwords, no RELATIVE addends); the
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
    ("teardown.txt", 0x5D4CFD0, 0x5D4D041),
    ("copy.txt", 0x5D4D050, 0x5D4D241),
    ("helper.txt", 0x5D4A6A0, 0x5D4A743),
    ("sites_copy1.txt", 0x5D8006E, 0x5D800C8),
    ("sites_copy2.txt", 0x5D80104, 0x5D80158),
    ("sites_teardown_cleanup.txt", 0x5D80378, 0x5D8039C),
    ("sites_teardown_loops.txt", 0x5D80609, 0x5D806CD),
]

EXPECTED_CALLS = {
    0x5D4CFD0: ["0x5d4cfe7", "0x5d4d20d", "0x5d4dc38", "0x5d4e641",
                "0x5d4ea66", "0x5d4eb7c", "0x5d5018b", "0x5d501f0",
                "0x5d55122", "0x5d55137", "0x5d56b6d", "0x5d56c41",
                "0x5d5e2b9", "0x5d5e320", "0x5d5e648", "0x5d5e654",
                "0x5d5e91f", "0x5d5e988", "0x5d5ec79", "0x5d5ece0",
                "0x5d8037f", "0x5d8061c", "0x5d8067e"],
    0x5D4D050: ["0x5d4d0d3", "0x5d4d161", "0x5d80073", "0x5d80109"],
    0x5D4A6A0: ["0x5d4acd5", "0x5d4acf1", "0x5d4d086", "0x5d4d0a5",
                "0x5d4d117", "0x5d4d133", "0x5d4de8d", "0x5d4df3e",
                "0x5d4dfbd", "0x5d4e075", "0x5d4e71a", "0x5d4e737",
                "0x5d4e808", "0x5d4e820", "0x5d4e89a", "0x5d4e8b6",
                "0x5d4e968", "0x5d4e987", "0x5d52fe9", "0x5d53008",
                "0x5d57895", "0x5d578dc", "0x5d5790a", "0x5d57c57",
                "0x5d58326", "0x5d59944", "0x5d65631", "0x5d65a89",
                "0x5d66b7c", "0x5d6c8a6", "0x5d6cb04", "0x5d6cb1f",
                "0x5d6cbc0", "0x5d6cbd8", "0x5d7158a", "0x5d772a5",
                "0x5d772c4", "0x5d77300", "0x5d7732b", "0x5d7736a",
                "0x5d77398", "0x5d7740e", "0x5d7743c", "0x5d7746a",
                "0x5d77495", "0x5d774c0", "0x5d783c4", "0x5d7848f",
                "0x5d784ba", "0x5d7b763", "0x5d7b85f", "0x5d7bb4b",
                "0x5d7cb90", "0x5d7dcce", "0x5d7fcc5", "0x5d7fce6",
                "0x5d7fd07", "0x5d7fe25", "0x5d7fe55", "0x5d7fe85",
                "0x5d7feb5", "0x5d7fee5", "0x5d7ff15", "0x5d7ff45",
                "0x5d7ff75", "0x5d7ffa3", "0x5d7ffd1", "0x5d7ffff",
                "0x5d8002d", "0x5d801b9", "0x5d8020e", "0x5d80239",
                "0x5d80d70", "0x5d80da0", "0x5d80e89", "0x5d811dd",
                "0x5d81221", "0x5d854ea", "0x5d86b53"],
}

EXPECTED_JUMPS = {target: [] for target in EXPECTED_CALLS}

SPOT_BYTES = {
    0x5D4CFE7: "e8e4ffffff",
    0x5D4D0D3: "e878ffffff",
    0x5D4A72F: "e82c636a00",
    0x5D8067E: "e84dc9fcff",
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
    expected = {"README.md", "records.json", "teardown.txt", "copy.txt",
                "helper.txt", "sites_copy1.txt", "sites_copy2.txt",
                "sites_teardown_cleanup.txt", "sites_teardown_loops.txt",
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
    for want in ("pc=0000000005d4cfd0..0000000005d4d041",
                 "pc=0000000005d4d050..0000000005d4d241",
                 "pc=0000000005d4a6a0..0000000005d4a743",
                 "pc=0000000005d7fc80..0000000005d8043e",
                 "pc=0000000005d80440..0000000005d81813"):
        if want not in text:
            fail("frame range missing: %s" % want)
        if want not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % want)


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for target in (0x5D4CFD0, 0x5D4D050, 0x5D4A6A0):
        for line in text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                fail("unexpected RELATIVE line for %#x: %s" % (target, line))
    if (PACKET / "relocations.txt").read_text() != "":
        fail("relocations.txt is not empty")


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    tsv_calls = {}
    tsv_jumps = {}
    for row in rows:
        site, target, _caller, kind = row.split("\t")[0:4]
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
    for want in ("routine 0x5d4cfd0: stored qwords: []",
                 "routine 0x5d4cfd0: RELATIVE addends: 0",
                 "routine 0x5d4d050: stored qwords: []",
                 "routine 0x5d4d050: RELATIVE addends: 0",
                 "routine 0x5d4a6a0: stored qwords: []",
                 "routine 0x5d4a6a0: RELATIVE addends: 0"):
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
    if records["routines"]["teardown"]["address"] != "0x5d4cfd0":
        fail("records teardown address mismatch")
    if records["routines"]["copy"]["address"] != "0x5d4d050":
        fail("records copy address mismatch")
    if records["routines"]["string_builder"]["address"] != "0x5d4a6a0":
        fail("records builder address mismatch")
    if records["node_layout"]["size_bytes"] != 96:
        fail("records node size mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_node_tree_60_115.py"],
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
