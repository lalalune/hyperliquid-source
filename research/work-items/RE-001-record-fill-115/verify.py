"""Checker for the RE-001-record-fill-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-record-fill-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; routine
instructions byte-for-byte against a fresh objdump run and the raw
binary; the FDE ranges against a fresh frame dump; census
consistency (callers.tsv counts, the single direct call site,
byte-level spot checks of the call); the semantic records; and the
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
    ("main.txt", 0x5F6EB50, 0x5F6EB96),
    ("site.txt", 0x5F95C40, 0x5F95D21),
]

# (address, raw bytes) spot checks, taken from the excerpt byte
# columns and confirmed against the raw binary by this checker
# itself. The whole routine, the site gate/setup/call/post-call
# instructions, and three extra post-call instructions.
SPOT_BYTES = {
    0x5F6EB50: "f30f1efa",
    0x5F6EB54: "488b87d8000000",
    0x5F6EB5B: "48894658",
    0x5F6EB5F: "c6467c01",
    0x5F6EB63: "488b02",
    0x5F6EB66: "80be3401000000",
    0x5F6EB6D: "c6467f01",
    0x5F6EB71: "48894670",
    0x5F6EB75: "7509",
    0x5F6EB77: "c3",
    0x5F6EB80: "53",
    0x5F6EB81: "488b7f40",
    0x5F6EB85: "4889f3",
    0x5F6EB88: "e833e5e1ff",
    0x5F6EB8D: "c6437d01",
    0x5F6EB91: "894360",
    0x5F6EB94: "5b",
    0x5F6EB95: "c3",
    0x5F95C4F: "4889b570f9ffff",
    0x5F95C61: "488b30",
    0x5F95C7A: "80be3501000000",
    0x5F95CCE: "0f298510faffff",
    0x5F95CD5: "750d",
    0x5F95CD7: "80be3401000000",
    0x5F95CDE: "0f84d8070000",
    0x5F95CE4: "488d8520feffff",
    0x5F95CEB: "488d95a8f9ffff",
    0x5F95CF2: "4889df",
    0x5F95CF5: "48898590f9ffff",
    0x5F95CFC: "4c8dad40fdffff",
    0x5F95D03: "e8488efdff",
    0x5F95D08: "488b8570f9ffff",
    0x5F95D0F: "488b8068020000",
    0x5F95D16: "488b5048",
    0x5F95D1A: "488b85f0fcffff",
}

SPOT_CALLS = {
    0x5F95D03: 0x5F6EB50,
}

EXCERPT_OF = {}
for _address in SPOT_BYTES:
    EXCERPT_OF[_address] = ("main.txt" if _address < 0x5F70000
                            else "site.txt")


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
                "site.txt", "frames.txt", "relocations.txt",
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
    if "endbr64" not in texts["main.txt"]:
        fail("main excerpt lost its entry instruction")


def check_frames():
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for needle in ("pc=0000000005f6eb50..0000000005f6eb96",
                   "pc=0000000005d8d0c0..0000000005d8d0c8",
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
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+(5f6eb50)\b")
    found = {"call": set(), "jmp": set()}
    for line in proc.stdout:
        match = pattern.match(line)
        if match:
            found[match.group(2)].add(int(match.group(1), 16))
    proc.wait()
    if proc.returncode != 0:
        fail("objdump census failed")
    if found["call"] != {0x5F95D03}:
        fail("routine call sites mismatch: %s" % found["call"])
    if found["jmp"] != set():
        fail("routine tail jumps mismatch: %s" % found["jmp"])
    callers = (PACKET / "callers.tsv").read_text().splitlines()
    if callers != ["window\tsite\tkind",
                   "routine\t0x5f95d03\tcall"]:
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
    if records["census"]["routine_0x5f6eb50"]["direct_calls"] != [
            "0x5f95d03"]:
        fail("records routine census mismatch")
    if "endbr64" in json.dumps(records):
        fail("records carry instruction-level detail")


def check_model_tests():
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_record_fill_115.py")],
        capture_output=True, text=True, cwd=ROOT)
    if result.returncode != 0:
        fail("model tests failed:\n%s%s" % (result.stdout, result.stderr))
    print(result.stdout.strip())


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
