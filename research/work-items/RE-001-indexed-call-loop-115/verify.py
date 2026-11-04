"""Checker for the RE-001-indexed-call-loop-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-indexed-call-loop-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; driver
instructions byte-for-byte against a fresh objdump run and the raw
binary; the FDE ranges against a fresh frame dump; census
consistency (callers.tsv counts, both direct call sites, byte-level
spot checks of call sites); the semantic records; and the model
tests.
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
    ("main.txt", 0x5F6B520, 0x5F6B581),
    ("caller-site.txt", 0x5D60780, 0x5D607AE),
]

# (address, raw bytes) spot checks, taken from the excerpt byte
# columns and confirmed against the raw binary by this checker
# itself. Driver entry, count load, empty-arm jump, flag
# zero-extension, index copy, index increment, loop call, loop
# compare, loop jump, and the caller's call site.
SPOT_BYTES = {
    0x5F6B520: "f30f1efa",
    0x5F6B524: "8b4754",
    0x5F6B529: "7e55",
    0x5F6B53C: "450fb6e0",
    0x5F6B550: "4189d8",
    0x5F6B562: "83c301",
    0x5F6B565: "e896faffff",
    0x5F6B56A: "395d54",
    0x5F6B56D: "7fe1",
    0x5D607A9: "e872ad2000",
}

# (call site, expected target) byte-level spot checks: the driver's
# sole call site and the callee's sole call site.
SPOT_CALLS = {
    0x5D607A9: 0x5F6B520,
    0x5F6B565: 0x5F6B000,
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
    expected = {"README.md", "records.json", "main.txt", "caller-site.txt",
                "frames.txt", "relocations.txt", "callers.tsv",
                "export_excerpts.py", "census.py", "verify.py"}
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
    excerpt = (PACKET / "main.txt").read_text()
    site = (PACKET / "caller-site.txt").read_text()
    for address, hex_bytes in SPOT_BYTES.items():
        text = site if address == 0x5D607A9 else excerpt
        pattern = r"\s*%x:\s+((?:[0-9a-f]{2} )+)" % address
        match = re.search(pattern, text)
        if not match:
            fail("spot instruction %#x not in excerpt" % address)
        shown = match.group(1).replace(" ", "")
        if shown != hex_bytes:
            fail("excerpt bytes mismatch at %#x: %s != %s"
                 % (address, shown, hex_bytes))
    if "endbr64" not in excerpt:
        fail("main excerpt lost its entry instruction")


def check_frames():
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for needle in ("pc=0000000005f6b520..0000000005f6b581",
                   "pc=0000000005f6b000..0000000005f6b516",
                   "pc=0000000005d60580..0000000005d60837"):
        if needle not in frames:
            fail("FDE range missing: %s" % needle)
        if needle not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % needle)


def check_census():
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+(5f6b520|5f6b000)\b")
    found = {0x5F6B520: {"call": set(), "jmp": set()},
             0x5F6B000: {"call": set(), "jmp": set()}}
    for line in proc.stdout:
        match = pattern.match(line)
        if match:
            found[int(match.group(3), 16)][match.group(2)].add(
                int(match.group(1), 16))
    proc.wait()
    if proc.returncode != 0:
        fail("objdump census failed")
    if found[0x5F6B520]["call"] != {0x5D607A9}:
        fail("driver call sites mismatch: %s" % found[0x5F6B520]["call"])
    if found[0x5F6B000]["call"] != {0x5F6B565}:
        fail("callee call sites mismatch: %s" % found[0x5F6B000]["call"])
    if found[0x5F6B520]["jmp"] or found[0x5F6B000]["jmp"]:
        fail("unexpected tail jumps")
    callers = (PACKET / "callers.tsv").read_text().splitlines()
    if callers != ["window\tsite\tkind",
                   "indexed_call_loop\t0x5d607a9\tcall",
                   "callee\t0x5f6b565\tcall"]:
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
    if records["census"]["driver_0x5f6b520"]["direct_calls"] != ["0x5d607a9"]:
        fail("records driver census mismatch")
    if records["census"]["callee_0x5f6b000"]["direct_calls"] != ["0x5f6b565"]:
        fail("records callee census mismatch")
    if "endbr64" in json.dumps(records):
        fail("records carry instruction-level detail")


def check_model_tests():
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_indexed_call_loop_115.py")],
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
