"""Checker for the RE-001-span-count-predicate-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-span-count-predicate-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
predicate, site, exit and cleanup instructions byte-for-byte
against the raw binary; the FDE ranges against a fresh frame
dump; census consistency (callers.tsv counts, the single direct
call site, byte-level spot checks of the call); the semantic
records; and the model tests.
Prints ALL CHECKS PASSED on success, else raises.
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    ("main.txt", 0x5F6EA90, 0x5F6EAB5),
    ("site.txt", 0x5FA1598, 0x5FA15F6),
    ("exit.txt", 0x5FA1786, 0x5FA17A0),
    ("cleanup.txt", 0x5FA129C, 0x5FA12BF),
]

# (address, raw bytes) spot checks, taken from the excerpt byte
# columns and confirmed against the raw binary by this checker
# itself. The whole predicate, the site argument setup, the call,
# the result test, the true-arm loop head, the empty-range arm
# and the loop-exit follow-up call.
SPOT_BYTES = {
    0x5F6EA90: "f30f1efa",
    0x5F6EA94: "48baabaaaaaaaaaaaaaa",
    0x5F6EA9E: "488b4710",
    0x5F6EAA2: "482b4708",
    0x5F6EAA6: "48c1f807",
    0x5F6EAAA: "480fafc2",
    0x5F6EAAE: "483b07",
    0x5F6EAB1: "0f94c0",
    0x5F6EAB4: "c3",
    0x5FA1598: "488b7c2430",
    0x5FA159D: "e8eed4fcff",
    0x5FA15A2: "84c0",
    0x5FA15A4: "0f84f2fcffff",
    0x5FA15AA: "488b4328",
    0x5FA15AE: "4c8b6320",
    0x5FA15B2: "4889442448",
    0x5FA15B7: "4939c4",
    0x5FA15BA: "0f84c6010000",
    0x5FA15C0: "488d842490000000",
    0x5FA15C8: "4889442440",
    0x5FA15CD: "eb13",
    0x5FA15D0: "4981c480010000",
    0x5FA15D7: "4c39642448",
    0x5FA15DC: "0f84af010000",
    0x5FA15E2: "488b03",
    0x5FA15E5: "488b4c2440",
    0x5FA15EA: "4c89e2",
    0x5FA15ED: "4889de",
    0x5FA15F0: "4889ef",
    0x5FA15F3: "ff5018",
    0x5FA1786: "807c247000",
    0x5FA178B: "0f85e3feffff",
    0x5FA1791: "488b7c2430",
    0x5FA1796: "e825d3fcff",
    0x5FA179B: "e9fcfaffff",
    0x5FA129C: "488bbc2450020000",
}

SPOT_CALLS = {
    0x5FA159D: 0x5F6EA90,
    0x5FA1796: 0x5F6EAC0,
}


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
                "site.txt", "exit.txt", "cleanup.txt", "frames.txt",
                "relocations.txt", "callers.tsv", "export_excerpts.py",
                "census.py", "verify.py"}
    if seen != expected:
        fail("manifest file set mismatch: %s" % sorted(seen))


def check_excerpts():
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        if text != (PACKET / name).read_text():
            fail("excerpt mismatch for %s" % name)


def check_spot_bytes():
    data = BINARY.read_bytes()
    for address, hex_bytes in SPOT_BYTES.items():
        raw = bytes.fromhex(hex_bytes)
        # Executable LOAD segment: file offset = vaddr - 0x1000.
        if data[address - 0x1000:address - 0x1000 + len(raw)] != raw:
            fail("raw byte mismatch at %#x" % address)
    for site, target in SPOT_CALLS.items():
        raw = bytes.fromhex(SPOT_BYTES[site])
        if raw[0] != 0xE8:
            fail("not a direct call at %#x" % site)
        disp = int.from_bytes(raw[1:5], "little", signed=True)
        if site + 5 + disp != target:
            fail("call at %#x targets %#x, want %#x"
                 % (site, site + 5 + disp, target))


def check_frames():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for want in ("pc=0000000005f6ea90..0000000005f6eab5",
                 "pc=0000000005fa0e40..0000000005fa1d4a"):
        if want not in text:
            fail("frame range missing: %s" % want)
        if want not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % want)


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    for want in ("direct calls: ['0x5fa159d']",
                 "tail jumps: []",
                 "stored qwords: []",
                 "RELATIVE addends: 0"):
        if want not in out:
            fail("census mismatch, missing %r in:\n%s" % (want, out))
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    if len(rows) != 2:
        fail("callers.tsv row count: %d" % len(rows))


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["task"] != "RE-001":
        fail("records task mismatch")
    if records["predicate"]["address"] != "0x5f6ea90":
        fail("records predicate address mismatch")
    if records["call_sites"][0]["site"] != "0x5fa159d":
        fail("records sole site mismatch")
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_span_count_predicate_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "checks passed" not in out:
        fail("model tests did not pass:\n%s" % out)
    print(out.strip())


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_spot_bytes()
    check_frames()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
