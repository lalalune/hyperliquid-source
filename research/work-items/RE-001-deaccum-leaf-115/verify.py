"""Checker for the RE-001-deaccum-leaf-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-deaccum-leaf-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; leaf
instructions byte-for-byte against a fresh objdump run and the raw
binary; the FDE ranges against a fresh frame dump; census
consistency (callers.tsv counts, all three direct call sites and
both tail jumps, byte-level spot checks of calls and jumps); the
semantic records; and the model tests.
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
    ("main.txt", 0x5F6B620, 0x5F6B660),
    ("site-5f53747.txt", 0x5F536FF, 0x5F53750),
    ("site-5f537af.txt", 0x5F5376B, 0x5F537BA),
    ("site-5f5390a.txt", 0x5F538FC, 0x5F53918),
    ("tail-5f45d50.txt", 0x5F45CF0, 0x5F45D55),
    ("tail-5f45df6.txt", 0x5F45DB0, 0x5F45DFB),
]

# (address, raw bytes) spot checks, taken from the excerpt byte
# columns and confirmed against the raw binary by this checker
# itself. Leaf entry, flag-byte compare, gate branch, the three
# counter updates, the return, and all five consumers.
SPOT_BYTES = {
    0x5F6B620: "f30f1efa",
    0x5F6B624: "80beb500000000",
    0x5F6B62B: "7432",
    0x5F6B62D: "488b8688000000",
    0x5F6B634: "480387b00f0000",
    0x5F6B63B: "482b8680000000",
    0x5F6B642: "488987b00f0000",
    0x5F6B649: "488b8688000000",
    0x5F6B658: "482987b80f0000",
    0x5F6B65F: "c3",
    0x5F53747: "e8d47e0100",
    0x5F537AF: "e86c7e0100",
    0x5F5390A: "e8117d0100",
    0x5F45D50: "e9cb580200",
    0x5F45DF6: "e925580200",
}

# (call site, expected target) byte-level spot checks: all three
# direct call sites of the leaf.
SPOT_CALLS = {
    0x5F53747: 0x5F6B620,
    0x5F537AF: 0x5F6B620,
    0x5F5390A: 0x5F6B620,
}

# (tail-jump site, expected target) byte-level spot checks: both
# tail jumps to the leaf.
SPOT_JUMPS = {
    0x5F45D50: 0x5F6B620,
    0x5F45DF6: 0x5F6B620,
}

EXCERPT_OF = {
    0x5F6B620: "main.txt",
    0x5F6B624: "main.txt",
    0x5F6B62B: "main.txt",
    0x5F6B62D: "main.txt",
    0x5F6B634: "main.txt",
    0x5F6B63B: "main.txt",
    0x5F6B642: "main.txt",
    0x5F6B649: "main.txt",
    0x5F6B658: "main.txt",
    0x5F6B65F: "main.txt",
    0x5F53747: "site-5f53747.txt",
    0x5F537AF: "site-5f537af.txt",
    0x5F5390A: "site-5f5390a.txt",
    0x5F45D50: "tail-5f45d50.txt",
    0x5F45DF6: "tail-5f45df6.txt",
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
                "site-5f53747.txt", "site-5f537af.txt",
                "site-5f5390a.txt", "tail-5f45d50.txt",
                "tail-5f45df6.txt", "frames.txt", "relocations.txt",
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
        pattern = r"\s*%x:\s+((?:[0-9a-f]{2} )+)" % address
        match = re.search(pattern, text)
        if not match:
            fail("spot instruction %#x not in excerpt" % address)
        shown = match.group(1).replace(" ", "")
        if shown != hex_bytes:
            fail("excerpt bytes mismatch at %#x: %s != %s"
                 % (address, shown, hex_bytes))
    if "endbr64" not in texts["main.txt"]:
        fail("main excerpt lost its entry instruction")


def check_frames():
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for needle in ("pc=0000000005f6b620..0000000005f6b660",
                   "pc=0000000005f52c50..0000000005f53f02",
                   "pc=0000000005f45cf0..0000000005f45e5d",
                   "pc=0000000005f6b590..0000000005f6b618"):
        if needle not in frames:
            fail("FDE range missing: %s" % needle)
        if needle not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % needle)


def check_census():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+(5f6b620)\b")
    found = {0x5F6B620: {"call": set(), "jmp": set()}}
    for line in proc.stdout:
        match = pattern.match(line)
        if match:
            found[int(match.group(3), 16)][match.group(2)].add(
                int(match.group(1), 16))
    proc.wait()
    if proc.returncode != 0:
        fail("objdump census failed")
    if found[0x5F6B620]["call"] != {0x5F53747, 0x5F537AF, 0x5F5390A}:
        fail("leaf call sites mismatch: %s"
             % found[0x5F6B620]["call"])
    if found[0x5F6B620]["jmp"] != {0x5F45D50, 0x5F45DF6}:
        fail("leaf tail jumps mismatch: %s"
             % found[0x5F6B620]["jmp"])
    callers = (PACKET / "callers.tsv").read_text().splitlines()
    if callers != ["window\tsite\tkind",
                   "leaf\t0x5f53747\tcall",
                   "leaf\t0x5f537af\tcall",
                   "leaf\t0x5f5390a\tcall",
                   "leaf\t0x5f45d50\tjmp",
                   "leaf\t0x5f45df6\tjmp"]:
        fail("callers.tsv mismatch")
    data = BINARY.read_bytes()
    for address, target in SPOT_CALLS.items():
        raw = data[address - 0x1000:address - 0x1000 + 5]
        if raw[0] != 0xE8:
            fail("spot call at %#x is not a direct call" % address)
        rel = int.from_bytes(raw[1:5], "little", signed=True)
        if address + 5 + rel != target:
            fail("spot call at %#x does not target %#x" % (address, target))
    for address, target in SPOT_JUMPS.items():
        raw = data[address - 0x1000:address - 0x1000 + 5]
        if raw[0] != 0xE9:
            fail("spot jump at %#x is not a direct jump" % address)
        rel = int.from_bytes(raw[1:5], "little", signed=True)
        if address + 5 + rel != target:
            fail("spot jump at %#x does not target %#x" % (address, target))


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["task"] != "RE-001" or records["node"] != 115:
        fail("records task/node mismatch")
    if records["census"]["leaf_0x5f6b620"]["direct_calls"] != [
            "0x5f53747", "0x5f537af", "0x5f5390a"]:
        fail("records leaf census mismatch")
    if records["census"]["leaf_0x5f6b620"]["tail_jumps"] != [
            "0x5f45d50", "0x5f45df6"]:
        fail("records leaf tail jumps mismatch")
    if "endbr64" in json.dumps(records):
        fail("records carry instruction-level detail")


def check_model_tests():
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_deaccum_leaf_115.py")],
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
    main()
