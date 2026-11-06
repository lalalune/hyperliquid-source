"""Verification for the RE-001-insert-helper-5f90bb0-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, and
the model tests. Exits nonzero on the first failure and prints
ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-insert-helper-5f90bb0-115/verify.py
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
    ("0x5f90bb0", "0x5f90d72", "function_0x5f90bb0.txt"),
    ("0x5f90b86", "0x5f90bb0", "function_0x5f90b86.txt"),
    ("0x5da04d0", "0x5da060d", "function_0x5da04d0.txt"),
]

# (address, expected raw bytes) sampled from the verbatim excerpts.
# File offset = virtual address - 0x1000 for the .text section.
SAMPLES = {
    0x5F90BB0: "4156",              # push %r14 (helper entry)
    0x5F90BC2: "4c8b26",            # mov (%rsi),%r12 (key from holder)
    0x5F90BD5: "48837f1800",        # cmpq $0,0x18(%rdi) (element count)
    0x5F90BE9: "48f7f7",            # div %rdi (bucket index)
    0x5F90BF0: "4c8b04d0",          # mov (%rax,%rdx,8),%r8 (bucket slot)
    0x5F90C81: "e84a014600",        # call operator new (PLT)
    0x5F90C92: "48c70000000000",    # movq $0,(%rax) (node next = 0)
    0x5F90CB1: "e83a024600",        # call _M_need_rehash (PLT)
    0x5F90CD9: "4883451801",        # addq $1,0x18(%rbp) (count += 1)
    0x5F90D16: "e8b5f7e0ff",        # call rehash body 0x5da04d0
    0x5F90D51: "48891cd6",          # mov %rbx,(%rsi,%rdx,8) (slot fixup)
    0x5F90D66: "f30f1efa",          # endbr64 (landing pad)
    0x5F90D6D: "e914feffff",        # jmp shared cleanup 0x5f90b86
    0x5F90B86: "be10000000",        # mov $0x10,%esi (cleanup entry)
    0x5F90B8E: "e8ed014600",        # call sized operator delete (PLT)
    0x5F90BA6: "e8a5fe4500",        # call _Unwind_Resume (PLT)
    0x5DA04D0: "f30f1efa",          # endbr64 (rehash entry)
    0x5DA0509: "e8c2086500",        # call operator new (array)
    0x5DA0519: "e872056500",        # call memset (zero the array)
    0x5DA059D: "e8de076500",        # call sized operator delete (old array)
}
# Three extra gate instructions picked at random from the excerpts.
GATE_SAMPLES = {
    0x5F90CFC: "4c396308",          # cmp %r12,0x8(%rbx) (scan key compare)
    0x5F90CA9: "488b4528",          # mov 0x28(%rbp),%rax (save next_resize)
    0x5DA05F0: "48894528",          # mov %rax,0x28(%rbp) (catch restore)
}
EXPECTED_FRAMES = {
    "0x5f90bb0": ("0074a43c", "0000000000000044"),
    "0x5f90b86": ("0074a484", "0000000000000020"),
    "0x5da04d0": ("007364a0", "000000000000003c"),
    "0x5da0640": ("007364e0", "0000000000000044"),
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
        "0x5f90bb0": (["0x5f90f9c", "0x5f91217"], []),
        "0x5da0640": (["0x5da0e6e", "0x5da17cb"], []),
        "0x5da04d0": (["0x5da07a6", "0x5dee099", "0x5e2d3dc", "0x5ec7964",
                       "0x5f4dab6", "0x5f90d16", "0x5fa5732"], []),
    }
    for addr, (calls, jumps) in expected.items():
        got = census[addr]
        if got["direct_calls"] != calls or got["tail_jumps"] != jumps:
            return fail("census mismatch for %s" % addr)
        if got["qword_hits"] or got["qword_hits_whole_file"] or got["relative_addend_hits"]:
            return fail("unexpected qword/rela hits for %s" % addr)
    twin = census["twin_comparison"]
    if twin["window_bytes"] != 450 or len(twin["differing_offsets"]) != 13:
        return fail("twin comparison mismatch")
    if twin["sha256_0x5f90bb0"] != "ecb744175923bc17ec29ffae92e98c5c585d4cbc47afa87163f9c67b5134a394":
        return fail("twin comparison digest mismatch for 0x5f90bb0")
    if twin["sha256_0x5da0640"] != "02a9a02b3ab1c5d4ea37c26aae1726f92031aadc38aff16bf6995926954be0e6":
        return fail("twin comparison digest mismatch for 0x5da0640")
    print("census ok")
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tests" / "test_insert_helper_5f90bb0_115.py")],
        capture_output=True, text=True)
    if proc.returncode != 0 or "tests passed" not in proc.stdout:
        return fail("model tests failed: %s%s" % (proc.stdout, proc.stderr))
    print("model tests ok: %s" % proc.stdout.strip())
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
