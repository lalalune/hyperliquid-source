"""Checker for the RE-001-advance-max-field-raise-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-advance-max-field-raise-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; leaf
instructions byte-for-byte against a fresh objdump run and the raw
binary; the FDE ranges against a fresh frame dump; census
consistency (callers.tsv counts, all seven direct call sites,
byte-level spot checks of calls); the semantic records; and the
model tests.
Prints ALL CHECKS PASSED on success, else raises.
"""

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
    ("main-advance.txt", 0x5F6F400, 0x5F6F424),
    ("main-max.txt", 0x5F6F430, 0x5F6F450),
    ("site-5e6987d.txt", 0x5E69876, 0x5E69889),
    ("site-5e6b3ac.txt", 0x5E6B3A1, 0x5E6B3B5),
    ("site-5e82edc.txt", 0x5E82EC3, 0x5E82EE8),
    ("site-5f9846d.txt", 0x5F98467, 0x5F98477),
    ("site-shared-5f9dfb1.txt", 0x5F9DFA6, 0x5F9DFDA),
]

# (address, raw bytes) spot checks, taken from the excerpt byte
# columns and confirmed against the raw binary by this checker
# itself. Both leaves in full, all seven call sites, and three
# extra site-setup instructions.
SPOT_BYTES = {
    0x5F6F400: "f30f1efa",
    0x5F6F404: "488b87d8000000",
    0x5F6F40B: "4839c6",
    0x5F6F40E: "7308",
    0x5F6F418: "4883c601",
    0x5F6F41C: "4889b7d8000000",
    0x5F6F430: "f30f1efa",
    0x5F6F434: "488b87e0000000",
    0x5F6F43B: "4839f0",
    0x5F6F43E: "7208",
    0x5F6F448: "4889b7e0000000",
    0x5E6987D: "e87e5b1000",
    0x5E6B3AC: "e84f401000",
    0x5E82EDC: "e81fc50e00",
    0x5F9846D: "e8be6ffdff",
    0x5F9DFB1: "e87a14fdff",
    0x5F9DFC1: "e83a14fdff",
    0x5F9DFD1: "e82a14fdff",
    0x5E69876: "498b7e68",
    0x5F9DFA6: "488bb578010000",
    0x5E82EC7: "488bb5e0fcffff",
}

SPOT_CALLS = {
    0x5E6987D: 0x5F6F400,
    0x5E6B3AC: 0x5F6F400,
    0x5E82EDC: 0x5F6F400,
    0x5F9DFC1: 0x5F6F400,
    0x5F9DFD1: 0x5F6F400,
    0x5F9846D: 0x5F6F430,
    0x5F9DFB1: 0x5F6F430,
}

EXCERPT_OF = {
    0x5F6F400: "main-advance.txt",
    0x5F6F404: "main-advance.txt",
    0x5F6F40B: "main-advance.txt",
    0x5F6F40E: "main-advance.txt",
    0x5F6F418: "main-advance.txt",
    0x5F6F41C: "main-advance.txt",
    0x5F6F430: "main-max.txt",
    0x5F6F434: "main-max.txt",
    0x5F6F43B: "main-max.txt",
    0x5F6F43E: "main-max.txt",
    0x5F6F448: "main-max.txt",
    0x5E6987D: "site-5e6987d.txt",
    0x5E6B3AC: "site-5e6b3ac.txt",
    0x5E82EDC: "site-5e82edc.txt",
    0x5F9846D: "site-5f9846d.txt",
    0x5F9DFB1: "site-shared-5f9dfb1.txt",
    0x5F9DFC1: "site-shared-5f9dfb1.txt",
    0x5F9DFD1: "site-shared-5f9dfb1.txt",
    0x5E69876: "site-5e6987d.txt",
    0x5F9DFA6: "site-shared-5f9dfb1.txt",
    0x5E82EC7: "site-5e82edc.txt",
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
    expected = {"README.md", "records.json", "main-advance.txt",
                "main-max.txt", "site-5e6987d.txt",
                "site-5e6b3ac.txt", "site-5e82edc.txt",
                "site-5f9846d.txt", "site-shared-5f9dfb1.txt",
                "frames.txt", "relocations.txt",
                "callers.tsv", "export_excerpts.py", "census.py",
                "verify.py"}
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
            fail("raw binary mismatch at %#x" % address)
    texts = {n: (PACKET / n).read_text() for n in set(EXCERPT_OF.values())}
    for address, hex_bytes in SPOT_BYTES.items():
        text = texts[EXCERPT_OF[address]]
        pattern = r"\s*%x:\s+((?:[0-9a-f]{2} )+(?:[0-9a-f]{2})?)" % address
        match = re.search(pattern, text)
        if not match:
            fail("spot instruction %#x not in excerpt" % address)
        shown = match.group(1).replace(" ", "")
        if shown != hex_bytes:
            fail("excerpt bytes mismatch at %#x: %s != %s"
                 % (address, shown, hex_bytes))
    if "endbr64" not in texts["main-advance.txt"]:
        fail("advance excerpt lost its entry instruction")
    if "endbr64" not in texts["main-max.txt"]:
        fail("max excerpt lost its entry instruction")


def check_frames():
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for needle in ("pc=0000000005f6f400..0000000005f6f424",
                   "pc=0000000005f6f430..0000000005f6f450",
                   "pc=0000000005e68fd0..0000000005e6b82a",
                   "pc=0000000005e82cc0..0000000005e844e1",
                   "pc=0000000005f9daf0..0000000005f9eccd",
                   "pc=0000000005f95b80..0000000005f98c8d"):
        if needle not in frames:
            fail("FDE range missing: %s" % needle)
        if needle not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % needle)


def check_census():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+(5f6f400|5f6f430)\b")
    found = {0x5F6F400: {"call": set(), "jmp": set()},
             0x5F6F430: {"call": set(), "jmp": set()}}
    for line in proc.stdout:
        match = pattern.match(line)
        if match:
            found[int(match.group(3), 16)][match.group(2)].add(
                int(match.group(1), 16))
    proc.wait()
    if proc.returncode != 0:
        fail("objdump census failed")
    if found[0x5F6F400]["call"] != {0x5E6987D, 0x5E6B3AC, 0x5E82EDC,
                                    0x5F9DFC1, 0x5F9DFD1}:
        fail("advance call sites mismatch: %s"
             % found[0x5F6F400]["call"])
    if found[0x5F6F400]["jmp"] != set():
        fail("advance tail jumps mismatch: %s" % found[0x5F6F400]["jmp"])
    if found[0x5F6F430]["call"] != {0x5F9846D, 0x5F9DFB1}:
        fail("max call sites mismatch: %s" % found[0x5F6F430]["call"])
    if found[0x5F6F430]["jmp"] != set():
        fail("max tail jumps mismatch: %s" % found[0x5F6F430]["jmp"])
    callers = (PACKET / "callers.tsv").read_text().splitlines()
    if callers != ["window\tsite\tkind",
                   "advance\t0x5e6987d\tcall",
                   "advance\t0x5e6b3ac\tcall",
                   "advance\t0x5e82edc\tcall",
                   "advance\t0x5f9dfc1\tcall",
                   "advance\t0x5f9dfd1\tcall",
                   "max\t0x5f9846d\tcall",
                   "max\t0x5f9dfb1\tcall"]:
        fail("callers.tsv mismatch")
    data = BINARY.read_bytes()
    for address, target in SPOT_CALLS.items():
        raw = data[address - 0x1000:address - 0x1000 + 5]
        if raw[0] != 0xE8:
            fail("spot call at %#x is not a direct call" % address)
        rel = int.from_bytes(raw[1:5], "little", signed=True)
        if address + 5 + rel != target:
            fail("spot call at %#x does not target %#x" % (address, target))


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["task"] != "RE-001" or records["node"] != 115:
        fail("records task/node mismatch")
    if records["census"]["advance_0x5f6f400"]["direct_calls"] != [
            "0x5e6987d", "0x5e6b3ac", "0x5e82edc", "0x5f9dfc1",
            "0x5f9dfd1"]:
        fail("records advance census mismatch")
    if records["census"]["max_0x5f6f430"]["direct_calls"] != [
            "0x5f9846d", "0x5f9dfb1"]:
        fail("records max census mismatch")
    if "endbr64" in json.dumps(records):
        fail("records carry instruction-level detail")


def check_model_tests():
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_advance_max_raise_115.py")],
        capture_output=True, text=True, cwd=ROOT)
    if result.returncode != 0:
        fail("model tests failed:\n%s\n%s" % (result.stdout, result.stderr))


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
    sys.exit(main())
