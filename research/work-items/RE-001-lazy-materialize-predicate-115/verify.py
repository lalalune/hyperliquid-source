"""Checker for the RE-001-lazy-materialize-predicate-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-lazy-materialize-predicate-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; predicate
instructions byte-for-byte against a fresh objdump run and the raw
binary; the FDE range against a fresh frame dump; census
consistency (callers.tsv counts, both predicate call sites,
byte-level spot checks of call sites); the semantic records; and
the model tests.
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
    ("main.txt", 0x5F77190, 0x5F77326),
]

# (address, raw bytes) spot checks: predicate entry, flag load,
# flag test, p78 compare, oracle call, status compare, flag set,
# return-1 set, error-report call. Byte strings are taken from the
# excerpt byte columns and confirmed against the raw binary by
# this checker itself.
SPOT_BYTES = {
    0x5F77190: "f30f1efa",
    0x5F771A0: "0fb6aeb5000000",
    0x5F771B7: "4084ed",
    0x5F771C0: "48837e7800",
    0x5F7720F: "e8ecf7ffff",
    0x5F77214: "807c241000",
    0x5F77219: "c683b500000001",
    0x5F7722F: "bd01000000",
    0x5F772EB: "e8707d0500",
}

# (call site, expected target) byte-level spot checks: both direct
# calls of the predicate, inside the two-phase scan 0x5f77330.
SPOT_CALLS = {
    0x5F773AE: 0x5F77190,
    0x5F774ED: 0x5F77190,
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
        token = "pc=%016x..%016x" % (start, stop)
        if token not in frames:
            fail("FDE range missing: %s" % token)
        if token not in stored:
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
    if counts != {"predicate": 2}:
        fail("callers.tsv counts mismatch: %r" % counts)
    for site in ("0x5f773ae", "0x5f774ed"):
        if ("predicate", site) not in sites:
            fail("predicate call site missing from callers.tsv: %s" % site)
    record = json.loads((PACKET / "records.json").read_text())
    census = record["census"]
    if census["predicate"]["direct_calls"] != ["0x5f773ae", "0x5f774ed"]:
        fail("records predicate census mismatch")
    if census["predicate"]["tail_jumps"] != []:
        fail("records predicate tail jumps mismatch")
    if census["predicate"]["stored_qwords"] != 0:
        fail("records predicate stored qwords mismatch")
    if census["predicate"]["relative_addends"] != 0:
        fail("records predicate relative addends mismatch")


def check_records():
    record = json.loads((PACKET / "records.json").read_text())
    if record["task"] != "RE-001":
        fail("records task mismatch")
    window = record["windows"]["predicate"]
    if window["start"] != "0x5f77190" or window["stop"] != "0x5f77326":
        fail("records window range mismatch")
    if window["size_bytes"] != 406:
        fail("records window size mismatch")
    if int(window["stop"], 16) - int(window["start"], 16) != 406:
        fail("records window arithmetic mismatch")
    if record["error_report"]["code"] != 3:
        fail("records error code mismatch")
    blob = json.dumps(record)
    if "endbr64" in blob or "movq" in blob:
        fail("records.json carries instruction-level detail")


def check_model_tests():
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_lazy_materialize_predicate_115.py")],
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
