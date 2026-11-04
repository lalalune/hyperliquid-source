"""Checker for the RE-001-teardown-pair-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-teardown-pair-115/verify.py

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
    ("main-release.txt", 0x5F78000, 0x5F78021),
    ("main-clear.txt", 0x5F78030, 0x5F78059),
    ("site-landing.txt", 0x5F7F223, 0x5F7F25B),
    ("site-cleanup.txt", 0x5F7F280, 0x5F7F2AD),
    ("site-loop.txt", 0x5F7F2EF, 0x5F7F301),
]

# (address, raw bytes) spot checks, taken from the excerpt byte
# columns and confirmed against the raw binary by this checker
# itself. Both leaves in full, all seven call sites, and three
# extra site-setup instructions.
SPOT_BYTES = {
    0x5F78000: "f30f1efa",
    0x5F78004: "488b07",
    0x5F78007: "4885c0",
    0x5F7800A: "7414",
    0x5F7800C: "488b7710",
    0x5F78010: "4889c7",
    0x5F78013: "4829c6",
    0x5F78016: "e9658d4700",
    0x5F78030: "f30f1efa",
    0x5F78034: "48833f00",
    0x5F78038: "7407",
    0x5F7803A: "48c70700000000",
    0x5F78041: "488b8790010000",
    0x5F78048: "483b8798010000",
    0x5F7804F: "7407",
    0x5F78051: "48898798010000",
    0x5F7F22F: "e8cc8dffff",
    0x5F7F247: "e8e48dffff",
    0x5F7F251: "e8aa8dffff",
    0x5F7F28B: "e8708dffff",
    0x5F7F293: "e8988dffff",
    0x5F7F2A0: "e85b8dffff",
    0x5F7F2FA: "e8018dffff",
    0x5F7F22A: "488b7c2428",
    0x5F7F244: "4c89e7",
    0x5F7F280: "4c89ef",
}

SPOT_CALLS = {
    0x5F7F22F: 0x5F78000,
    0x5F7F247: 0x5F78030,
    0x5F7F251: 0x5F78000,
    0x5F7F28B: 0x5F78000,
    0x5F7F293: 0x5F78030,
    0x5F7F2A0: 0x5F78000,
    0x5F7F2FA: 0x5F78000,
}

EXCERPT_OF = {
    0x5F78000: "main-release.txt",
    0x5F78004: "main-release.txt",
    0x5F78007: "main-release.txt",
    0x5F7800A: "main-release.txt",
    0x5F7800C: "main-release.txt",
    0x5F78010: "main-release.txt",
    0x5F78013: "main-release.txt",
    0x5F78016: "main-release.txt",
    0x5F78030: "main-clear.txt",
    0x5F78034: "main-clear.txt",
    0x5F78038: "main-clear.txt",
    0x5F7803A: "main-clear.txt",
    0x5F78041: "main-clear.txt",
    0x5F78048: "main-clear.txt",
    0x5F7804F: "main-clear.txt",
    0x5F78051: "main-clear.txt",
    0x5F7F22F: "site-landing.txt",
    0x5F7F247: "site-landing.txt",
    0x5F7F251: "site-landing.txt",
    0x5F7F28B: "site-cleanup.txt",
    0x5F7F293: "site-cleanup.txt",
    0x5F7F2A0: "site-cleanup.txt",
    0x5F7F2FA: "site-loop.txt",
    0x5F7F22A: "site-landing.txt",
    0x5F7F244: "site-landing.txt",
    0x5F7F280: "site-cleanup.txt",
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
    expected = {"README.md", "records.json", "main-release.txt",
                "main-clear.txt", "site-landing.txt",
                "site-cleanup.txt", "site-loop.txt",
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
    if "endbr64" not in texts["main-release.txt"]:
        fail("release excerpt lost its entry instruction")
    if "endbr64" not in texts["main-clear.txt"]:
        fail("clear excerpt lost its entry instruction")


def check_frames():
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for needle in ("pc=0000000005f78000..0000000005f78021",
                   "pc=0000000005f78030..0000000005f78059",
                   "pc=0000000005f7ede0..0000000005f7f280",
                   "pc=0000000005f7f280..0000000005f7f375"):
        if needle not in frames:
            fail("FDE range missing: %s" % needle)
        if needle not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % needle)


def check_census():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+(5f78000|5f78030)\b")
    found = {0x5F78000: {"call": set(), "jmp": set()},
             0x5F78030: {"call": set(), "jmp": set()}}
    for line in proc.stdout:
        match = pattern.match(line)
        if match:
            found[int(match.group(3), 16)][match.group(2)].add(
                int(match.group(1), 16))
    proc.wait()
    if proc.returncode != 0:
        fail("objdump census failed")
    if found[0x5F78000]["call"] != {0x5F7F22F, 0x5F7F251, 0x5F7F28B,
                                    0x5F7F2A0, 0x5F7F2FA}:
        fail("release call sites mismatch: %s"
             % found[0x5F78000]["call"])
    if found[0x5F78000]["jmp"] != set():
        fail("release tail jumps mismatch: %s" % found[0x5F78000]["jmp"])
    if found[0x5F78030]["call"] != {0x5F7F247, 0x5F7F293}:
        fail("clear call sites mismatch: %s" % found[0x5F78030]["call"])
    if found[0x5F78030]["jmp"] != set():
        fail("clear tail jumps mismatch: %s" % found[0x5F78030]["jmp"])
    callers = (PACKET / "callers.tsv").read_text().splitlines()
    if callers != ["window\tsite\tkind",
                   "release\t0x5f7f22f\tcall",
                   "release\t0x5f7f251\tcall",
                   "release\t0x5f7f28b\tcall",
                   "release\t0x5f7f2a0\tcall",
                   "release\t0x5f7f2fa\tcall",
                   "clear\t0x5f7f247\tcall",
                   "clear\t0x5f7f293\tcall"]:
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
    if records["census"]["release_0x5f78000"]["direct_calls"] != [
            "0x5f7f22f", "0x5f7f251", "0x5f7f28b", "0x5f7f2a0",
            "0x5f7f2fa"]:
        fail("records release census mismatch")
    if records["census"]["clear_0x5f78030"]["direct_calls"] != [
            "0x5f7f247", "0x5f7f293"]:
        fail("records clear census mismatch")
    if "endbr64" in json.dumps(records):
        fail("records carry instruction-level detail")


def check_model_tests():
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_teardown_pair_115.py")],
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
