"""Verification for the RE-001-plain-field-getters-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, and
the model tests. Exits nonzero on the first failure and prints
ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-plain-field-getters-115/verify.py
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
    ("0x5eeb250", "0x5eeb26f", "function_0x5eeb250.txt"),
    ("0x5eeb270", "0x5eeb28f", "function_0x5eeb270.txt"),
    ("0x5eeb2f0", "0x5eeb312", "function_0x5eeb2f0.txt"),
    ("0x5eeb320", "0x5eeb342", "function_0x5eeb320.txt"),
    ("0x5eeb350", "0x5eeb372", "function_0x5eeb350.txt"),
    ("0x5eeb380", "0x5eeb39b", "function_0x5eeb380.txt"),
]

# (address, expected raw bytes) sampled from the verbatim excerpts.
# File offset = virtual address - 0x1000 for the .text section.
SAMPLES = {
    0x5EEB250: "f30f1efa",        # endbr64 (getter A entry)
    0x5EEB254: "488b8788070000",  # mov 0x788(%rdi),%rax (member load)
    0x5EEB25B: "488b4030",        # mov 0x30(%rax),%rax (sub-object)
    0x5EEB25F: "486380300b0000",  # movslq 0xb30(%rax),%rax (signed field)
    0x5EEB266: "488906",          # mov %rax,(%rsi) (store)
    0x5EEB269: "b801000000",      # mov $0x1,%eax (return 1)
    0x5EEB26E: "c3",              # ret (getter A)
    0x5EEB270: "f30f1efa",        # endbr64 (getter B entry)
    0x5EEB274: "488b8788070000",  # mov 0x788(%rdi),%rax (member load)
    0x5EEB27B: "488b4030",        # mov 0x30(%rax),%rax (sub-object)
    0x5EEB27F: "488b8008100000",  # mov 0x1008(%rax),%rax (field)
    0x5EEB286: "488906",          # mov %rax,(%rsi) (store)
    0x5EEB289: "b801000000",      # mov $0x1,%eax (return 1)
    0x5EEB28E: "c3",              # ret (getter B)
    0x5EEB2F0: "f30f1efa",        # endbr64 (getter C entry)
    0x5EEB2F4: "488b8788070000",  # mov 0x788(%rdi),%rax (member load)
    0x5EEB2FB: "488b80e8080000",  # mov 0x8e8(%rax),%rax (sub-object)
    0x5EEB302: "488b80d00c0000",  # mov 0xcd0(%rax),%rax (field)
    0x5EEB309: "488906",          # mov %rax,(%rsi) (store)
    0x5EEB30C: "b801000000",      # mov $0x1,%eax (return 1)
    0x5EEB311: "c3",              # ret (getter C)
    0x5EEB320: "f30f1efa",        # endbr64 (getter D entry)
    0x5EEB324: "488b8788070000",  # mov 0x788(%rdi),%rax (member load)
    0x5EEB32B: "488b80e8080000",  # mov 0x8e8(%rax),%rax (sub-object)
    0x5EEB332: "488b80700a0000",  # mov 0xa70(%rax),%rax (field)
    0x5EEB339: "488906",          # mov %rax,(%rsi) (store)
    0x5EEB33C: "b801000000",      # mov $0x1,%eax (return 1)
    0x5EEB341: "c3",              # ret (getter D)
    0x5EEB350: "f30f1efa",        # endbr64 (getter E entry)
    0x5EEB354: "488b8788070000",  # mov 0x788(%rdi),%rax (member load)
    0x5EEB35B: "488b80e8080000",  # mov 0x8e8(%rax),%rax (sub-object)
    0x5EEB362: "488b80780a0000",  # mov 0xa78(%rax),%rax (field)
    0x5EEB369: "488906",          # mov %rax,(%rsi) (store)
    0x5EEB36C: "b801000000",      # mov $0x1,%eax (return 1)
    0x5EEB371: "c3",              # ret (getter E)
    0x5EEB380: "f30f1efa",        # endbr64 (getter F entry)
    0x5EEB384: "488b8788070000",  # mov 0x788(%rdi),%rax (member load)
    0x5EEB38B: "488b8028090000",  # mov 0x928(%rax),%rax (direct field)
    0x5EEB392: "488906",          # mov %rax,(%rsi) (store)
    0x5EEB395: "b801000000",      # mov $0x1,%eax (return 1)
    0x5EEB39A: "c3",              # ret (getter F)
}
# Three extra gate instructions picked at random.
GATE_SAMPLES = {
    0x5EEB25F: "486380300b0000",  # movslq 0xb30(%rax),%rax (getter A field)
    0x5EEB332: "488b80700a0000",  # mov 0xa70(%rax),%rax (getter D field)
    0x5EEB38B: "488b8028090000",  # mov 0x928(%rax),%rax (getter F field)
}
EXPECTED_FRAMES = [
    "pc=0000000005eeb250..0000000005eeb26f",
    "pc=0000000005eeb270..0000000005eeb28f",
    "pc=0000000005eeb2f0..0000000005eeb312",
    "pc=0000000005eeb320..0000000005eeb342",
    "pc=0000000005eeb350..0000000005eeb372",
    "pc=0000000005eeb380..0000000005eeb39b",
]
EMPTY = {"direct_calls": [], "tail_jumps": [], "qword_hits": [],
         "qword_hits_whole_file": [], "relative_addend_hits": []}
EXPECTED_CENSUS = {
    "0x5eeb250": dict(EMPTY),
    "0x5eeb270": dict(EMPTY),
    "0x5eeb2f0": dict(EMPTY),
    "0x5eeb320": dict(EMPTY),
    "0x5eeb350": dict(EMPTY),
    "0x5eeb380": dict(EMPTY),
}


def fail(msg):
    print("FAIL: %s" % msg, file=sys.stderr)
    return 1


def main():
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        return fail("binary digest mismatch")
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
            cwd=REPO_ROOT, capture_output=True, text=True)
        if proc.returncode != 0:
            return fail("objdump failed for %s" % name)
        if proc.stdout != (PACKET_DIR / name).read_text():
            return fail("excerpt regeneration mismatch for %s" % name)
    print("excerpts ok")
    for addr, hexbytes in {**SAMPLES, **GATE_SAMPLES}.items():
        raw = bytes.fromhex(hexbytes)
        off = addr - 0x1000
        if data[off:off + len(raw)] != raw:
            return fail("raw byte mismatch at %#x" % addr)
    print("sampled bytes ok")
    frames = (PACKET_DIR / "frames.txt").read_text()
    for expected in EXPECTED_FRAMES:
        if expected not in frames:
            return fail("missing frame %s" % expected)
    print("frames ok")
    proc = subprocess.run(
        [sys.executable, str(PACKET_DIR / "census.py")],
        capture_output=True, text=True)
    if proc.returncode != 0:
        return fail("census.py failed: %s" % proc.stderr)
    census = json.loads(proc.stdout)
    for target, expected in EXPECTED_CENSUS.items():
        if census.get(target) != expected:
            return fail("census mismatch for %s: %r" % (target, census.get(target)))
    print("census ok")
    proc = subprocess.run(
        [sys.executable,
         str(REPO_ROOT / "tests" / "test_plain_field_getters_115.py")],
        capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        return fail("model tests failed")
    print("model tests ok")
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
