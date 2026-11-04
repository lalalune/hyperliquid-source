"""Checker for the RE-001-pipeline-dispatch-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-pipeline-dispatch-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; dispatcher
instructions byte-for-byte against a fresh objdump run and the raw
binary; the FDE ranges against a fresh frame dump; census
consistency (callers.tsv counts, all four direct call sites,
byte-level spot checks of calls and of the internal scan call and
prologue tail jump); the semantic records; and the model tests.
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
    ("main.txt", 0x5F88550, 0x5F8858F),
    ("site-5f956ab.txt", 0x5F956A3, 0x5F956BA),
    ("site-5f973b5.txt", 0x5F97398, 0x5F973C1),
    ("site-5fa01f1.txt", 0x5FA01CE, 0x5FA01FB),
    ("site-5fa600e.txt", 0x5FA5FE9, 0x5FA601A),
]

# (address, raw bytes) spot checks, taken from the excerpt byte
# columns and confirmed against the raw binary by this checker
# itself. Dispatcher entry, flag branch, prologue argument
# derivation, prologue tail jump, scan call, and all four call sites.
SPOT_BYTES = {
    0x5F88550: "f30f1efa",
    0x5F8855C: "4883ec08",
    0x5F88560: "84d2",
    0x5F88562: "7524",
    0x5F88564: "488b4310",
    0x5F8856C: "488d7b40",
    0x5F88570: "4889ea",
    0x5F88575: "488db068030000",
    0x5F8857C: "e92fffffff",
    0x5F88588: "e8a3edfeff",
    0x5F8858D: "ebd5",
    0x5F956AB: "e8a02effff",
    0x5F973B5: "e89611ffff",
    0x5FA01F1: "e85a83feff",
    0x5FA600E: "e83d25feff",
}

# (call site, expected target) byte-level spot checks: all four
# direct call sites of the dispatcher, plus its internal scan call
# and its prologue tail jump.
SPOT_CALLS = {
    0x5F956AB: 0x5F88550,
    0x5F973B5: 0x5F88550,
    0x5FA01F1: 0x5F88550,
    0x5FA600E: 0x5F88550,
    0x5F88588: 0x5F77330,
}

SPOT_JUMPS = {
    0x5F8857C: 0x5F884B0,
}

EXCERPT_OF = {
    0x5F88550: "main.txt",
    0x5F8855C: "main.txt",
    0x5F88560: "main.txt",
    0x5F88562: "main.txt",
    0x5F88564: "main.txt",
    0x5F8856C: "main.txt",
    0x5F88570: "main.txt",
    0x5F88575: "main.txt",
    0x5F8857C: "main.txt",
    0x5F88588: "main.txt",
    0x5F8858D: "main.txt",
    0x5F956AB: "site-5f956ab.txt",
    0x5F973B5: "site-5f973b5.txt",
    0x5FA01F1: "site-5fa01f1.txt",
    0x5FA600E: "site-5fa600e.txt",
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
                "site-5f956ab.txt", "site-5f973b5.txt",
                "site-5fa01f1.txt", "site-5fa600e.txt",
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
    if "endbr64" not in texts["main.txt"]:
        fail("main excerpt lost its entry instruction")


def check_frames():
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for needle in ("pc=0000000005f88550..0000000005f8858f",
                   "pc=0000000005f77330..0000000005f77581",
                   "pc=0000000005f884b0..0000000005f88544",
                   "pc=0000000005f95280..0000000005f957aa",
                   "pc=0000000005f95b80..0000000005f98c8d",
                   "pc=0000000005f9fbb0..0000000005fa033d",
                   "pc=0000000005fa4f80..0000000005fa63a7"):
        if needle not in frames:
            fail("FDE range missing: %s" % needle)
        if needle not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % needle)


def check_census():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+(5f88550)\b")
    found = {0x5F88550: {"call": set(), "jmp": set()}}
    for line in proc.stdout:
        match = pattern.match(line)
        if match:
            found[int(match.group(3), 16)][match.group(2)].add(
                int(match.group(1), 16))
    proc.wait()
    if proc.returncode != 0:
        fail("objdump census failed")
    if found[0x5F88550]["call"] != {0x5F956AB, 0x5F973B5,
                                    0x5FA01F1, 0x5FA600E}:
        fail("dispatcher call sites mismatch: %s"
             % found[0x5F88550]["call"])
    if found[0x5F88550]["jmp"] != set():
        fail("dispatcher tail jumps mismatch: %s"
             % found[0x5F88550]["jmp"])
    callers = (PACKET / "callers.tsv").read_text().splitlines()
    if callers != ["window\tsite\tkind",
                   "dispatcher\t0x5f956ab\tcall",
                   "dispatcher\t0x5f973b5\tcall",
                   "dispatcher\t0x5fa01f1\tcall",
                   "dispatcher\t0x5fa600e\tcall"]:
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
    if records["census"]["dispatcher_0x5f88550"]["direct_calls"] != [
            "0x5f956ab", "0x5f973b5", "0x5fa01f1", "0x5fa600e"]:
        fail("records dispatcher census mismatch")
    if records["census"]["dispatcher_0x5f88550"]["tail_jumps"] != []:
        fail("records dispatcher tail jumps mismatch")
    if "endbr64" in json.dumps(records):
        fail("records carry instruction-level detail")


def check_model_tests():
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_pipeline_dispatch_115.py")],
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
