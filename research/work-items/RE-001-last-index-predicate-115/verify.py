"""Checker for the RE-001-last-index-predicate-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-last-index-predicate-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; predicate
instructions byte-for-byte against a fresh objdump run and the raw
binary; the FDE ranges against a fresh frame dump; census
consistency (callers.tsv counts, all four direct call sites,
byte-level spot checks of call sites); the semantic records; and the
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
    ("main.txt", 0x5F6AFA0, 0x5F6AFC8),
    ("site-5f6b0e9.txt", 0x5F6B0DE, 0x5F6B0F7),
    ("record-store.txt", 0x5F6B24A, 0x5F6B258),
    ("site-5f73880.txt", 0x5F73853, 0x5F738A8),
    ("site-5f92bce.txt", 0x5F92BBE, 0x5F92BDE),
    ("site-5f9a0e4.txt", 0x5F9A0D9, 0x5F9A0EF),
]

# (address, raw bytes) spot checks, taken from the excerpt byte
# columns and confirmed against the raw binary by this checker
# itself. Predicate entry, link load, flag-byte load, flag test,
# index test, flag-or, count load, count minus one, last-index
# compare, last-index set, and the four call sites.
SPOT_BYTES = {
    0x5F6AFA0: "f30f1efa",
    0x5F6AFA4: "488b4710",
    0x5F6AFA8: "0fb68054060000",
    0x5F6AFB3: "85f6",
    0x5F6AFB5: "0f9fc0",
    0x5F6AFB8: "08d0",
    0x5F6AFBC: "8b4754",
    0x5F6AFBF: "83e801",
    0x5F6AFC2: "39f0",
    0x5F6AFC4: "0f94c0",
    0x5F6B0E9: "e8b2feffff",
    0x5F73880: "e81b77ffff",
    0x5F92BCE: "e8cd83fdff",
    0x5F9A0E4: "e8b70efdff",
}

# (call site, expected target) byte-level spot checks: all four
# direct call sites of the predicate.
SPOT_CALLS = {
    0x5F6B0E9: 0x5F6AFA0,
    0x5F73880: 0x5F6AFA0,
    0x5F92BCE: 0x5F6AFA0,
    0x5F9A0E4: 0x5F6AFA0,
}

EXCERPT_OF = {
    0x5F6AFA0: "main.txt",
    0x5F6AFA4: "main.txt",
    0x5F6AFA8: "main.txt",
    0x5F6AFB3: "main.txt",
    0x5F6AFB5: "main.txt",
    0x5F6AFB8: "main.txt",
    0x5F6AFBC: "main.txt",
    0x5F6AFBF: "main.txt",
    0x5F6AFC2: "main.txt",
    0x5F6AFC4: "main.txt",
    0x5F6B0E9: "site-5f6b0e9.txt",
    0x5F73880: "site-5f73880.txt",
    0x5F92BCE: "site-5f92bce.txt",
    0x5F9A0E4: "site-5f9a0e4.txt",
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
                "site-5f6b0e9.txt", "record-store.txt",
                "site-5f73880.txt", "site-5f92bce.txt",
                "site-5f9a0e4.txt", "frames.txt", "relocations.txt",
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
    for needle in ("pc=0000000005f6afa0..0000000005f6afc8",
                   "pc=0000000005f6b000..0000000005f6b516",
                   "pc=0000000005f733c0..0000000005f743d9",
                   "pc=0000000005f916f0..0000000005f9360c",
                   "pc=0000000005f999d0..0000000005f9a478"):
        if needle not in frames:
            fail("FDE range missing: %s" % needle)
        if needle not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % needle)


def check_census():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+(5f6afa0)\b")
    found = {0x5F6AFA0: {"call": set(), "jmp": set()}}
    for line in proc.stdout:
        match = pattern.match(line)
        if match:
            found[int(match.group(3), 16)][match.group(2)].add(
                int(match.group(1), 16))
    proc.wait()
    if proc.returncode != 0:
        fail("objdump census failed")
    if found[0x5F6AFA0]["call"] != {0x5F6B0E9, 0x5F73880, 0x5F92BCE,
                                    0x5F9A0E4}:
        fail("predicate call sites mismatch: %s"
             % found[0x5F6AFA0]["call"])
    if found[0x5F6AFA0]["jmp"]:
        fail("unexpected tail jumps")
    callers = (PACKET / "callers.tsv").read_text().splitlines()
    if callers != ["window\tsite\tkind",
                   "predicate\t0x5f6b0e9\tcall",
                   "predicate\t0x5f73880\tcall",
                   "predicate\t0x5f92bce\tcall",
                   "predicate\t0x5f9a0e4\tcall"]:
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
    if records["census"]["predicate_0x5f6afa0"]["direct_calls"] != [
            "0x5f6b0e9", "0x5f73880", "0x5f92bce", "0x5f9a0e4"]:
        fail("records predicate census mismatch")
    if "endbr64" in json.dumps(records):
        fail("records carry instruction-level detail")


def check_model_tests():
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_last_index_predicate_115.py")],
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
