"""Checker for the RE-001-flag-variant-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-flag-variant-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; leaf
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
    ("main.txt", 0x5F6B740, 0x5F6B753),
    ("site.txt", 0x5DF5BE8, 0x5DF5C26),
]

# (address, raw bytes) spot checks, taken from the excerpt byte
# columns and confirmed against the raw binary by this checker
# itself. The whole leaf, the site argument setup, the call, the
# result comparison, and the virtual-call disposition.
SPOT_BYTES = {
    0x5F6B740: "f30f1efa",
    0x5F6B744: "31c0",
    0x5F6B746: "4084f6",
    0x5F6B749: "0f94c0",
    0x5F6B74C: "034710",
    0x5F6B74F: "83e802",
    0x5F6B752: "c3",
    0x5DF5BE8: "488b8010070000",
    0x5DF5BEF: "410fb6b7c3040000",
    0x5DF5BF7: "488b7830",
    0x5DF5BFB: "4883c740",
    0x5DF5BFF: "e83c5b1700",
    0x5DF5C04: "39d8",
    0x5DF5C06: "0f85c4eeffff",
    0x5DF5C0C: "498bbf18030000",
    0x5DF5C13: "31f6",
    0x5DF5C15: "488b07",
    0x5DF5C18: "ff9000020000",
    0x5DF5C1E: "85c0",
    0x5DF5C20: "0f8eaaeeffff",
}

SPOT_CALLS = {
    0x5DF5BFF: 0x5F6B740,
}

EXCERPT_OF = {}
for _address in SPOT_BYTES:
    EXCERPT_OF[_address] = ("main.txt" if _address > 0x5F00000
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
    # objdump splits one long instruction's byte column across two
    # lines (e.g. the movzbl at 0x5df5bef carries its final byte on
    # the 0x5df5bf6 line), so accumulate consecutive entries until
    # the expected length is reached instead of reading one line.
    entries = {}
    for text in texts.values():
        ordered = []
        for line in text.splitlines():
            match = re.match(
                r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} ?)+)", line)
            if match:
                ordered.append((int(match.group(1), 16),
                                match.group(2).replace(" ", "")))
        for i, (addr, shown) in enumerate(ordered):
            entries[addr] = "".join(b for _, b in ordered[i:])
    for address, hex_bytes in SPOT_BYTES.items():
        text = texts[EXCERPT_OF[address]]
        if address not in entries:
            fail("spot instruction %#x not in excerpt" % address)
        shown = entries[address][:len(hex_bytes)]
        if shown != hex_bytes:
            fail("excerpt bytes mismatch at %#x: %s != %s"
                 % (address, shown, hex_bytes))
    if "endbr64" not in texts["main.txt"]:
        fail("main excerpt lost its entry instruction")


def check_frames():
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for needle in ("pc=0000000005f6b740..0000000005f6b753",
                   "pc=0000000005df0f40..0000000005df1e22"):
        if needle not in frames:
            fail("FDE range missing: %s" % needle)
        if needle not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % needle)


def check_census():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+(5f6b740)\b")
    found = {"call": set(), "jmp": set()}
    for line in proc.stdout:
        match = pattern.match(line)
        if match:
            found[match.group(2)].add(int(match.group(1), 16))
    proc.wait()
    if proc.returncode != 0:
        fail("objdump census failed")
    if found["call"] != {0x5DF5BFF}:
        fail("leaf call sites mismatch: %s" % found["call"])
    if found["jmp"] != set():
        fail("leaf tail jumps mismatch: %s" % found["jmp"])
    callers = (PACKET / "callers.tsv").read_text().splitlines()
    if callers != ["window\tsite\tkind",
                   "leaf\t0x5df5bff\tcall"]:
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
    if records["census"]["leaf_0x5f6b740"]["direct_calls"] != [
            "0x5df5bff"]:
        fail("records leaf census mismatch")
    if "endbr64" in json.dumps(records):
        fail("records carry instruction-level detail")


def check_model_tests():
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_flag_variant_115.py")],
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
