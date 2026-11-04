"""Verification for the RE-001-flanking-getters-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, and
the model tests. Exits nonzero on the first failure and prints
ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-flanking-getters-115/verify.py
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
    ("0x5eeb220", "0x5eeb241", "function_0x5eeb220.txt"),
    ("0x5eeb3a0", "0x5eeb3be", "function_0x5eeb3a0.txt"),
    ("0x5eeb3c0", "0x5eeb3f3", "function_0x5eeb3c0.txt"),
    ("0x5d8c9c0", "0x5d8c9cd", "function_0x5d8c9c0.txt"),
]

# (address, expected raw bytes) sampled from the verbatim excerpts.
# File offset = virtual address - 0x1000 for the .text section.
SAMPLES = {
    0x5EEB220: "f30f1efa",        # endbr64 (getter V entry)
    0x5EEB224: "488b02",          # mov (%rdx),%rax (vptr load)
    0x5EEB22E: "ff9078040000",    # call *0x478(%rax) (virtual slot)
    0x5EEB234: "0fb6c0",          # movzbl %al,%eax (low-byte mask)
    0x5EEB237: "488903",          # mov %rax,(%rbx) (store)
    0x5EEB23A: "b801000000",      # mov $0x1,%eax (return 1)
    0x5EEB240: "c3",              # ret (getter V)
    0x5EEB3A0: "f30f1efa",        # endbr64 (getter S entry)
    0x5EEB3A5: "488bbf88070000",  # mov 0x788(%rdi),%rdi (member load)
    0x5EEB3AF: "e80c16eaff",      # call 0x5d8c9c0 (stub)
    0x5EEB3B4: "488903",          # mov %rax,(%rbx) (store)
    0x5EEB3B7: "b801000000",      # mov $0x1,%eax (return 1)
    0x5EEB3BD: "c3",              # ret (getter S)
    0x5EEB3C0: "f30f1efa",        # endbr64 (getter R entry)
    0x5EEB3C5: "488dba00070000",  # lea 0x700(%rdx),%rdi (refresh arg)
    0x5EEB3D7: "e8b49f1e00",      # call 0x60d5390 (refresh)
    0x5EEB3DC: "48638340140000",  # movslq 0x1440(%rbx),%rax (signed field)
    0x5EEB3E3: "48894500",        # mov %rax,0x0(%rbp) (store)
    0x5EEB3EB: "b801000000",      # mov $0x1,%eax (return 1)
    0x5EEB3F2: "c3",              # ret (getter R)
    0x5D8C9C0: "f30f1efa",        # endbr64 (stub entry)
    0x5D8C9C4: "488b7f28",        # mov 0x28(%rdi),%rdi (sub-object)
    0x5D8C9C8: "e9d3432000",      # jmp 0x5f90da0 (tail jump)
}
# Three extra gate instructions picked at random from the excerpts.
GATE_SAMPLES = {
    0x5EEB228: "4889d7",          # mov %rdx,%rdi (obj to virtual slot)
    0x5EEB3AC: "4889f3",          # mov %rsi,%rbx (out saved)
    0x5EEB3D3: "4883ec08",        # sub $0x8,%rsp (getter R frame)
}
EXPECTED_FRAMES = {
    "0x5eeb220": ("00356dcc", "0000000000000018"),
    "0x5eeb3a0": ("00356eb0", "0000000000000018"),
    "0x5eeb3c0": ("00356ecc", "0000000000000024"),
    "0x5d8c9c0": ("0034bbe4", "0000000000000010"),
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
            cwd=REPO_ROOT, capture_output=True, text=True)
        if proc.returncode != 0:
            return fail("objdump failed for %s" % name)
        if proc.stdout != (PACKET_DIR / name).read_text():
            return fail("excerpt %s differs from a fresh objdump run" % name)
    print("excerpts regenerate byte-for-byte ok")
    for addr, expected in {**SAMPLES, **GATE_SAMPLES}.items():
        raw = data[addr - 0x1000:addr - 0x1000 + len(bytes.fromhex(expected))]
        if raw.hex() != expected:
            return fail("raw bytes mismatch at %#x" % addr)
    print("sampled + gate instruction bytes ok")
    frames = (PACKET_DIR / "frames.txt").read_text()
    for addr, (offset, length) in EXPECTED_FRAMES.items():
        needle = "%s %s" % (offset, length)
        if needle not in frames or ("00000000" + addr[2:]) not in frames:
            return fail("FDE record missing for %s" % addr)
    print("frames ok")
    proc = subprocess.run(
        [sys.executable, str(PACKET_DIR / "census.py")],
        capture_output=True, text=True)
    if proc.returncode != 0:
        return fail("census.py failed: %s" % proc.stderr)
    census = json.loads(proc.stdout)
    expected = {
        "0x5eeb220": ([], []),
        "0x5eeb3a0": ([], []),
        "0x5eeb3c0": ([], []),
        "0x5d8c9c0": (["0x5eeb3af"], []),
        "0x5f90da0": ([], ["0x5d8c9c8"]),
    }
    for addr, (calls, jumps) in expected.items():
        got = census[addr]
        if got["direct_calls"] != calls or got["tail_jumps"] != jumps:
            return fail("census mismatch for %s" % addr)
        if got["qword_hits"] or got["qword_hits_whole_file"] or got["relative_addend_hits"]:
            return fail("unexpected qword/rela hits for %s" % addr)
    print("census ok")
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tests" / "test_flanking_getters_115.py")],
        capture_output=True, text=True)
    if proc.returncode != 0 or "tests passed" not in proc.stdout:
        return fail("model tests failed: %s%s" % (proc.stdout, proc.stderr))
    print("model tests ok: %s" % proc.stdout.strip())
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
