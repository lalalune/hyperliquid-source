"""Checker for the RE-001-error-wrap-dispatch-50df400-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-error-wrap-dispatch-50df400-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges in frames.txt against a fresh
frame dump; the relocation records in relocations.txt against
a fresh relocation dump (the four R_X86_64_RELATIVE records
the body's own transfers resolve through, plus the
_Unwind_Resume JUMP_SLOT behind the landing pad's PLT call);
census consistency (callers.tsv against a fresh scan: 9
direct calls, 0 tail jumps, no stored qwords, no RELATIVE
addends, 4 internal calls, 0 internal direct tail jumps,
2 internal indirect calls, 0 internal indirect tail jumps)
and the callers.tsv caller functions against the smallest
enclosing FDE ranges from a fresh frame dump; the semantic
records; and the model tests. The Unicorn differential
(differential.py) is a separate check that needs the unicorn
package. Prints ALL CHECKS PASSED on success, else raises.
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
    ("main.txt", 0x50DF400, 0x50DF4B6),
]

EXPECTED_CALLS = {
    0x50DF400: ["0x50dd97a", "0x50ddc6a", "0x50ddfa9", "0x50de2aa",
                "0x50de4e2", "0x50de9fa", "0x50dedca", "0x50df0ba",
                "0x50df3aa"],
}

EXPECTED_JUMPS = {0x50DF400: []}

EXPECTED_INTERNAL_CALLS = ["0x50df438", "0x50df477",
                           "0x50df4a3", "0x50df4ab"]
EXPECTED_INTERNAL_JUMPS = []
EXPECTED_INTERNAL_INDIRECT_CALLS = ["0x50df48c", "0x50df4b0"]
EXPECTED_INTERNAL_INDIRECT_JUMPS = []

# GOT slot (file offset in the relocation record) -> resolved
# target the body's transfers rely on. Checked against a
# fresh `readelf -r` dump and against relocations.txt.
EXPECTED_RELATIVE = {
    "64df4a0": "635de30",
    "64df4c0": "1680cab",
    "64df520": "1681da0",
    "64e0a48": "5c3f000",
}

SPOT_BYTES = {
    0x50DF400: "4156",
    0x50DF40F: "488d050a6f5300",
    0x50DF420: "488b0521164001",
    0x50DF438: "e8331c0200",
    0x50DF440: "48ba0000000000000080",
    0x50DF455: "480f48ca",
    0x50DF477: "e804110100",
    0x50DF48C: "ff150e004001",
    0x50DF49D: "4989c6",
    0x50DF4B0: "ff150a004001",
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
    for target in (0x50DF400,):
        for line in text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                fail("unexpected RELATIVE line for %#x: %s" % (target, line))
    stored = (PACKET / "relocations.txt").read_text()
    for slot, resolved in EXPECTED_RELATIVE.items():
        found = False
        for line in text.splitlines():
            if slot in line and "RELATIVE" in line \
                    and line.rstrip().endswith(resolved):
                found = True
        if not found:
            fail("RELATIVE record missing: slot %s -> %s"
                 % (slot, resolved))
        if slot not in stored or resolved not in stored:
            fail("relocations.txt does not record slot %s" % slot)
    if not any("64ee178" in line and "_Unwind_Resume" in line
               for line in text.splitlines()):
        fail("_Unwind_Resume JUMP_SLOT for 0x64ee178 missing")
    if "64ee178" not in stored or "_Unwind_Resume" not in stored:
        fail("relocations.txt does not record the resume slot")


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
    if routine["address"] != "0x50df400":
        fail("records routine address mismatch")
    if routine["fde"] != "0x50df400..0x50df4b6":
        fail("records routine FDE mismatch")
    if routine["size_bytes"] != 182:
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
    if census["direct_call_count"] != 9:
        fail("records call count mismatch")
    if census["tail_jump_count"] != 0:
        fail("records census jump count mismatch")
    if census["internal_calls"] != len(EXPECTED_INTERNAL_CALLS):
        fail("records census internal calls mismatch")
    if census["internal_indirect_calls"] \
            != len(EXPECTED_INTERNAL_INDIRECT_CALLS):
        fail("records census internal indirect calls mismatch")
    if len(records["consumers"]) != 9:
        fail("records consumers mismatch")
    words = records["descriptor"]["words"]
    if [w["offset"] for w in words] != ["0x00", "0x08", "0x10", "0x18"]:
        fail("records descriptor offsets mismatch")
    if records["discriminant"]["default"] != 4:
        fail("records discriminant default mismatch")
    if records["landing_pad"]["address"] != "0x50df49d":
        fail("records landing pad mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_error_wrap_dispatch_50df400_115.py"],
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
