"""Verification for the RE-001-decimal-index-group-ratio-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, the
branch sites, and the model tests. Exits nonzero on the first
failure and prints ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-decimal-index-group-ratio-115/verify.py
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY = REPO_ROOT / "work" / "hl-node-115.bin"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WINDOWS = [
    ("0x5eed240", "0x5eed329", "function_0x5eed240.txt"),
    ("0x5f6aed0", "0x5f6af99", "function_0x5f6aed0.txt"),
    ("0x61d0df0", "0x61d0e87", "function_0x61d0df0.txt"),
]

# (address, expected raw bytes) sampled from the verbatim excerpts.
# File offset = virtual address - 0x1000 for the .text section.
SAMPLES = {
    0x5EED240: "f30f1efa",        # endbr64 (caller entry)
    0x5EED27E: "e86d3b2e00",      # call 0x61d0df0 (parser)
    0x5EED29A: "48638578070000",  # movslq 0x778(%rbp),%rax (bound)
    0x5EED2A6: "498d7d40",        # lea 0x40(%r13),%rdi (ratio object)
    0x5EED2AF: "e81cdc0700",      # call 0x5f6aed0 (ratio)
    0x5EED2CF: "e8acf3ffff",      # call 0x5eec680 (formatter)
    0x5EED2DA: "e841e8ffff",      # call 0x5eebb20 (string assign)
    0x5F6AED0: "f30f1efa",        # endbr64 (ratio entry)
    0x5F6AED4: "488b87980a0000",  # mov 0xa98(%rdi),%rax (array base)
    0x5F6AEDB: "4863f6",          # movslq %esi,%rsi (index32)
    0x5F6AF90: "f20f100530de4efa",  # movsd -1.0 sentinel
    0x5F6AF48: "f20f5ec1",        # divsd (ratio divide)
    0x61D0DF0: "f30f1efa",        # endbr64 (parser entry)
    0x61D0E0C: "49b99999999999999919",  # movabs threshold
    0x61D0E24: "83e830",          # sub $0x30,%eax (digit value)
    0x61D0E31: "83f805",          # cmp $0x5,%eax (last-digit guard)
}
# Three extra gate instructions picked at random from the excerpts.
GATE_SAMPLES = {
    0x5EED320: "31db",            # xor %ebx,%ebx (failure path)
    0x5F6AEF6: "31f6",            # xor %esi,%esi (numerator zero)
    0x5F6AF00: "488b08",          # mov (%rax),%rcx (element pointer)
}
EXPECTED_FRAMES = {
    "0x5eed240": ("003576f8", "0000000000000038"),
    "0x5f6aed0": ("0035dd00", "0000000000000010"),
    "0x61d0df0": ("00377a78", "0000000000000010"),
}


def fail(message):
    print("FAIL: %s" % message, file=sys.stderr)
    return 1


def main():
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        return fail("work binary digest mismatch")
    print("digest ok")
    manifest = (PACKET_DIR / "MANIFEST.sha256").read_text().splitlines()
    for line in manifest:
        digest, name = line.split("  ", 1)
        blob = (PACKET_DIR / name).read_bytes()
        if hashlib.sha256(blob).hexdigest() != digest:
            return fail("manifest mismatch for %s" % name)
    print("manifest ok")
    for start, stop, name in WINDOWS:
        proc = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % start,
             "--stop-address=%s" % stop, "work/hl-node-115.bin"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        if proc.returncode != 0:
            return fail("objdump failed for %s" % start)
        if proc.stdout != (PACKET_DIR / name).read_text():
            return fail("excerpt mismatch for %s" % name)
    print("excerpts ok")
    for addr, expected in list(SAMPLES.items()) + list(GATE_SAMPLES.items()):
        actual = data[addr - 0x1000:addr - 0x1000 + len(expected) // 2].hex()
        if actual != expected:
            return fail("raw byte mismatch at %#x" % addr)
    print("sampled bytes ok")
    frames = (PACKET_DIR / "frames.txt").read_text()
    for start, (offset, length) in EXPECTED_FRAMES.items():
        bare = start[2:]
        if offset not in frames or length not in frames or bare not in frames:
            return fail("frame record missing for %s" % start)
    print("frames ok")
    records = json.loads((PACKET_DIR / "records.json").read_text())
    if records["artifact_sha256"] != SHA256:
        return fail("records digest mismatch")
    census_proc = subprocess.run(
        [sys.executable, str(PACKET_DIR / "census.py")],
        capture_output=True, text=True,
    )
    census = json.loads(census_proc.stdout)
    if census["0x5eed240"]["direct_calls"] != []:
        return fail("caller census changed")
    if census["0x5f6aed0"]["direct_calls"] != ["0x5eed2af"]:
        return fail("ratio census changed")
    if "0x5eed27e" not in census["0x61d0df0"]["direct_calls"]:
        return fail("parser caller site missing")
    if len(census["0x61d0df0"]["direct_calls"]) != 10:
        return fail("parser call count changed")
    print("census ok")
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    test_proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tests" / "test_decimal_index_group_ratio_115.py")],
        capture_output=True, text=True,
    )
    if test_proc.returncode != 0:
        print(test_proc.stdout, file=sys.stderr)
        print(test_proc.stderr, file=sys.stderr)
        return fail("model tests failed")
    print(test_proc.stdout.strip())
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
