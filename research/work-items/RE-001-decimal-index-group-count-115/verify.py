"""Verification for the RE-001-decimal-index-group-count-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, the
rodata format record, and the model tests. Exits nonzero on the first
failure and prints ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-decimal-index-group-count-115/verify.py
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
    ("0x5eeb9c0", "0x5eebab6", "function_0x5eeb9c0.txt"),
    ("0x61d0df0", "0x61d0e87", "function_0x61d0df0.txt"),
]

# (address, expected raw bytes) sampled from the verbatim excerpts.
# File offset = virtual address - 0x1000 for the .text section.
SAMPLES = {
    0x5EEB9C0: "f30f1efa",        # endbr64 (caller entry)
    0x5EEB9F6: "488b8788070000",  # mov 0x788(%rdi),%rax (member)
    0x5EEBA04: "e8e7532e00",      # call 0x61d0df0 (parser)
    0x5EEBA0F: "48837c240800",    # cmpq $0x0,0x8(%rsp) (remaining)
    0x5EEBA1C: "3b8578070000",    # cmp 0x778(%rbp),%eax (bound)
    0x5EEBA61: "488d1440",        # lea (%rax,%rax,2),%rdx (index*3)
    0x5EEBA86: "49c1f903",        # sar $0x3,%r9 (span >> 3)
    0x5EEBA9F: "31f6",            # xor %esi,%esi (replace pos 0)
    0x61D0DF0: "f30f1efa",        # endbr64 (parser entry)
    0x61D0E0C: "49b99999999999999919",  # movabs threshold
    0x61D0E24: "83e830",          # sub $0x30,%eax (digit value)
    0x61D0E31: "83f805",          # cmp $0x5,%eax (last-digit guard)
    0x61D0E56: "0fbe02",          # movsbl (%rdx),%eax (next char)
    0x61D0E7B: "b801000000",      # mov $0x1,%eax (consumed return)
}
# Three extra gate instructions picked at random from the excerpts.
GATE_SAMPLES = {
    0x5EEBA65: "498b85d80a0000",  # mov 0xad8(%r13),%rax (group base)
    0x5EEBA7B: "4c2b0cd0",        # sub (%rax,%rdx,8),%r9 (span)
    0x61D0E40: "488d0c48",        # lea (%rax,%rcx,2),%rcx (value*10+d)
}
EXPECTED_FRAMES = {
    "0x5eeb9c0": ("003571ec", "0000000000000038"),
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
    if census["0x5eeb9c0"]["direct_calls"] != []:
        return fail("caller census changed")
    if "0x5eeba04" not in census["0x61d0df0"]["direct_calls"]:
        return fail("parser caller site missing")
    if len(census["0x61d0df0"]["direct_calls"]) != 10:
        return fail("parser call count changed")
    print("census ok")
    fmt = data[0x4464AD:0x4464B0].split(b"\x00")[0].decode()
    if fmt != records["rodata_format"]["bytes"]:
        return fail("rodata format mismatch")
    print("rodata ok")
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    test_proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tests" / "test_decimal_index_group_count_115.py")],
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
