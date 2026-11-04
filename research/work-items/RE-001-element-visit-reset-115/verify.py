"""Checker for the RE-001-element-visit-reset-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-element-visit-reset-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
routine and site instructions byte-for-byte against the raw
binary; the FDE ranges against a fresh frame dump; census
consistency (callers.tsv counts, the two direct call sites,
byte-level spot checks of the calls); the semantic records;
and the model tests.
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
    ("main.txt", 0x5F6EAC0, 0x5F6EB13),
    ("site1.txt", 0x5F7636D, 0x5F76392),
    ("site2.txt", 0x5FA1786, 0x5FA17A0),
]

SPOT_BYTES = {
    0x5F6EAC0: "f30f1efa",
    0x5F6EAC4: "4155",
    0x5F6EAC6: "4154",
    0x5F6EAC8: "55",
    0x5F6EAC9: "53",
    0x5F6EACA: "4883ec08",
    0x5F6EACE: "4c8b6f08",
    0x5F6EAD2: "4c8b6710",
    0x5F6EAD6: "48c70700000000",
    0x5F6EADD: "4d39e5",
    0x5F6EAE0: "7426",
    0x5F6EAE2: "4889fd",
    0x5F6EAE5: "4c89eb",
    0x5F6EAE8: "0f1f840000000000",
    0x5F6EAF0: "4889df",
    0x5F6EAF3: "4881c380010000",
    0x5F6EAFA: "e8f12bdeff",
    0x5F6EAFF: "4939dc",
    0x5F6EB02: "75ec",
    0x5F6EB04: "4c896d10",
    0x5F6EB08: "4883c408",
    0x5F6EB0C: "5b",
    0x5F6EB0D: "5d",
    0x5F6EB0E: "415c",
    0x5F6EB10: "415d",
    0x5F6EB12: "c3",
    0x5F7636D: "498bbfc0020000",
    0x5F76374: "4885ff",
    0x5F76377: "0f844afcffff",
    0x5F7637D: "c6872103000000",
    0x5F76384: "4883c718",
    0x5F76388: "e83387ffff",
    0x5F7638D: "e935fcffff",
    0x5FA1786: "807c247000",
    0x5FA178B: "0f85e3feffff",
    0x5FA1791: "488b7c2430",
    0x5FA1796: "e825d3fcff",
    0x5FA179B: "e9fcfaffff"
}

SPOT_CALLS = {
    0x5F76388: 0x5F6EAC0,
    0x5FA1796: 0x5F6EAC0,
    0x5F6EAFA: 0x5D516F0,
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
                "site1.txt", "site2.txt", "frames.txt",
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
    for want in ("pc=0000000005f6eac0..0000000005f6eb13",
                 "pc=0000000005d516f0..0000000005d519c5",
                 "pc=0000000005f75b10..0000000005f763fe",
                 "pc=0000000005fa0e40..0000000005fa1d4a"):
        if want not in text:
            fail("frame range missing: %s" % want)
        if want not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % want)


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    for want in ("direct calls: ['0x5f76388', '0x5fa1796']",
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
    if records["routine"]["address"] != "0x5f6eac0":
        fail("records routine address mismatch")
    if [s["site"] for s in records["call_sites"]] != ["0x5f76388", "0x5fa1796"]:
        fail("records call sites mismatch")
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_element_visit_reset_115.py"],
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
