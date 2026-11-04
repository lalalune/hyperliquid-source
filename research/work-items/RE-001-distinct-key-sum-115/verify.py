"""Verification for the RE-001-distinct-key-sum-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, and
the model tests. Exits nonzero on the first failure and prints
ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-distinct-key-sum-115/verify.py
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
    ("0x5f90da0", "0x5f90fe2", "function_0x5f90da0.txt"),
    ("0x5dd3570", "0x5dd357d", "function_0x5dd3570.txt"),
]

# (address, expected raw bytes) sampled from the verbatim excerpts.
# File offset = virtual address - 0x1000 for the .text section.
SAMPLES = {
    0x5F90DA0: "f30f1efa",        # endbr64 (walk entry)
    0x5F90DB2: "4c8ba728100000",  # mov 0x1028(%rdi),%r12 (first node)
    0x5F90E0D: "4c39e7",          # cmp %r12,%rdi (self-loop check)
    0x5F90E28: "498b9c24180b0000",  # mov 0xb18(%r12),%rbx (range begin)
    0x5F90E30: "498bac24200b0000",  # mov 0xb20(%r12),%rbp (range end)
    0x5F90E40: "488b03",          # mov (%rbx),%rax (entry object E)
    0x5F90E49: "488b00",          # mov (%rax),%rax (object F)
    0x5F90E4C: "488b08",          # mov (%rax),%rcx (key)
    0x5F90E82: "4883c310",        # add $0x10,%rbx (next entry)
    0x5F90E8B: "4d8ba42428100000",  # mov 0x1028(%r12),%r12 (next node)
    0x5F90F9C: "e80ffcffff",      # call 0x5f90bb0 (insert helper)
    0x5F90FA1: "488b03",          # mov (%rbx),%rax (entry object E)
    0x5F90FA4: "488b38",          # mov (%rax),%rdi (object F)
    0x5F90FA7: "e8c425e4ff",      # call 0x5dd3570 (value leaf)
    0x5F90FB0: "4901c5",          # add %rax,%r13 (accumulate)
    0x5F90F1D: "4c89e8",          # mov %r13,%rax (return total)
    0x5F90F2A: "c3",              # ret (walk)
    0x5DD3570: "f30f1efa",        # endbr64 (leaf entry)
    0x5DD3574: "488b4710",        # mov 0x10(%rdi),%rax (value field)
    0x5DD3578: "4883c03e",        # add $0x3e,%rax (+62)
    0x5DD357C: "c3",              # ret (leaf)
}
# Three extra gate instructions picked at random from the excerpts.
GATE_SAMPLES = {
    0x5F90E7C: "483b4808",        # cmp 0x8(%rax),%rcx (linear-scan key)
    0x5F90F35: "4889c8",          # mov %rcx,%rax (bucketed lookup setup)
    0x5F90FC9: "4531ed",          # xor %r13d,%r13d (self-loop total 0)
}
EXPECTED_FRAMES = {
    "0x5f90da0": ("0074a4a8", "0000000000000050"),
    "0x5dd3570": ("0034e3e0", "0000000000000010"),
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
        "0x5f90da0": ([], ["0x5d8c9c8"]),
        "0x5f90bb0": (["0x5f90f9c", "0x5f91217"], []),
        "0x5dd3570": (["0x5dd1694", "0x5eec2d2", "0x5eec342", "0x5ef06ca",
                        "0x5ef7376", "0x5f70b12", "0x5f7f67b", "0x5f8ee20",
                        "0x5f8ee8b", "0x5f90fa7"], []),
    }
    for addr, (calls, jumps) in expected.items():
        got = census[addr]
        if got["direct_calls"] != calls or got["tail_jumps"] != jumps:
            return fail("census mismatch for %s" % addr)
        if got["qword_hits"] or got["qword_hits_whole_file"] or got["relative_addend_hits"]:
            return fail("unexpected qword/rela hits for %s" % addr)
    print("census ok")
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tests" / "test_distinct_key_sum_115.py")],
        capture_output=True, text=True)
    if proc.returncode != 0 or "tests passed" not in proc.stdout:
        return fail("model tests failed: %s%s" % (proc.stdout, proc.stderr))
    print("model tests ok: %s" % proc.stdout.strip())
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
