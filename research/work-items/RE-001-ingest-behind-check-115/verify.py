"""Checker for the RE-001-ingest-behind-check-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-ingest-behind-check-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; gate and
extra instructions byte-for-byte against a fresh objdump run and the
raw binary; the FDE ranges against a fresh frame dump; census
consistency (callers.tsv counts, the gate's site, byte-level spot
checks of call sites); the semantic records; and the model tests.
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
    ("gate.txt", 0x5EBD1C0, 0x5EBD323),
    ("wrapper.txt", 0x5EBD130, 0x5EBD1B8),
    ("reporter.txt", 0x61CF670, 0x61CF767),
]

# (address, raw bytes) spot checks: gate, wrapper and reporter sites.
SPOT_BYTES = {
    0x5EBD203: "e828ffffff",
    0x5EBD254: "48837a1800",
    0x5EBD2CF: "4489a590030000",
    0x5EBD158: "488b5620",
    0x5EBD196: "e805f10a00",
    0x61CF698: "4d8d642f02",
    0x61CF72B: "6641890428",
}

# (call site, expected target) byte-level spot checks.
SPOT_CALLS = {
    0x5EC97AB: 0x5EBD1C0,
    0x5EC9076: 0x5EBD130,
    0x5EC9394: 0x5EBD130,
    0x5EBD299: 0x61CF670,
    0x5D2DBE5: 0x61CF670,
    0x620A349: 0x61CF670,
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
    for line in lines:
        digest, name = line.split("  ", 1)
        actual = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if actual != digest:
            fail("manifest mismatch for %s" % name)


def objdump_window(start, stop):
    # Run from the repository root with the relative binary path so
    # the objdump header line matches the stored excerpts exactly.
    return subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout


def check_excerpts():
    for name, start, stop in WINDOWS:
        fresh = objdump_window(start, stop)
        stored = (PACKET / name).read_text()
        if fresh != stored:
            fail("excerpt regeneration mismatch for %s" % name)


def check_spot_bytes():
    data = BINARY.read_bytes()
    dumps = {}
    for name, start, stop in WINDOWS:
        dumps[name] = objdump_window(start, stop)
    for address, hexbytes in SPOT_BYTES.items():
        raw = bytes.fromhex(hexbytes)
        actual = data[address - 0x1000: address - 0x1000 + len(raw)]
        if actual != raw:
            fail("raw byte mismatch at %#x" % address)
        found = False
        for text in dumps.values():
            for line in text.splitlines():
                if line.strip().startswith("%x:" % address):
                    compact = re.sub(r"\s+", "", line)
                    if raw.hex() not in compact:
                        fail("objdump byte mismatch at %#x" % address)
                    found = True
        if not found:
            fail("no objdump line at %#x" % address)
    for site, target in SPOT_CALLS.items():
        raw = data[site - 0x1000: site - 0x1000 + 5]
        if raw[0] != 0xE8:
            fail("spot call at %#x is not a direct call" % site)
        rel = int.from_bytes(raw[1:5], "little", signed=True)
        if site + 5 + rel != target:
            fail("spot call at %#x targets %#x, want %#x"
                 % (site, site + 5 + rel, target))


def check_frames():
    frames = subprocess.run(["objdump", "--dwarf=frames", str(BINARY)],
                            capture_output=True, text=True,
                            check=True).stdout
    stored = (PACKET / "frames.txt").read_text()
    for _, start, stop in WINDOWS:
        token = "pc=%#x..%#x" % (start, stop)
        # objdump prints pc ranges zero-padded to 16 hex digits.
        pattern = "pc=%016x..%016x" % (start, stop)
        if pattern not in frames:
            fail("FDE range missing: %s" % token)
        if pattern not in stored:
            fail("frames.txt missing range: %s" % token)


def check_census():
    rows = (PACKET / "callers.tsv").read_text().splitlines()
    if rows[0] != "window\tsite\tkind":
        fail("callers.tsv header mismatch")
    body = rows[1:]
    counts = {}
    sites = set()
    for row in body:
        window, site, kind = row.split("\t")
        counts[window] = counts.get(window, 0) + 1
        sites.add((window, site))
        if kind != "call":
            fail("unexpected kind in callers.tsv: %s" % kind)
    if counts != {"gate": 1, "wrapper": 3, "reporter": 847}:
        fail("callers.tsv counts mismatch: %r" % counts)
    if ("gate", "0x5ec97ab") not in sites:
        fail("gate call site missing from callers.tsv")
    if ("reporter", "0x5ebd299") not in sites:
        fail("gate reporter site missing from callers.tsv")
    record = json.loads((PACKET / "records.json").read_text())
    if record["census"]["reporter"]["direct_calls_count"] != 847:
        fail("records census count mismatch")


def check_records():
    record = json.loads((PACKET / "records.json").read_text())
    if record["task"] != "RE-001":
        fail("records task mismatch")
    starts = [w["start"] for w in record["windows"]]
    if starts != [0x5EBD1C0, 0x5EBD130, 0x61CF670]:
        fail("records window starts mismatch")
    for window in record["windows"]:
        if window["end"] - window["start"] != window["size"]:
            fail("records window size mismatch for %s" % window["name"])
    messages = {m["address"]: m for m in record["messages"]}
    if len(messages["0x958548"]["text"]) != 118:
        fail("upper message length mismatch")
    if len(messages["0x966bf0"]["text"]) != 67:
        fail("bottom message length mismatch")
    blob = json.dumps(record)
    if "endbr64" in blob or "movq" in blob:
        fail("records.json carries instruction-level detail")


def check_model_tests():
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_ingest_behind_check_115.py")],
        capture_output=True, text=True)
    if result.returncode != 0:
        fail("model tests failed:\n%s" % result.stdout[-2000:])


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
