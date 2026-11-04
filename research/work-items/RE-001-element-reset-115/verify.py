"""Verification for the RE-001-element-reset-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE record, the census, the
call-site raw bytes, and the model tests. Exits nonzero on the first
failure and prints ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-element-reset-115/verify.py
"""

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY = REPO_ROOT / "work" / "hl-node-115.bin"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# (address, expected raw bytes) sampled from the verbatim excerpt.
SAMPLES = {
    0x5F54EE0: "f30f1efa",            # endbr64 (element reset)
    0x5F54EF9: "c70700000000",        # movl $0,(%rdi) (head dword)
    0x5F54F3E: "0f114748",            # movups %xmm0,0x48(%rdi) (block)
    0x5F54F6D: "e80ebe4900",          # call _ZdlPvm@plt (first array)
    0x5F54F8E: "e8bdefffff",          # call 0x5f53f50 (list node)
    0x5F54FA9: "4c8badc8000000",      # mov 0xc8(%rbp),%r13 (2nd array)
    0x5F54FF0: "488bbb00010000",      # mov 0x100(%rbx),%rdi (dispose)
    0x5F550A0: "488b7b38",            # mov 0x38(%rbx),%rdi (3rd array)
    0x5F550E8: "488b85f8000000",      # mov 0xf8(%rbp),%rax (tail)
    0x5F55116: "48c7852801000000000000",  # movq $0,0x128(%rbp) (tail)
    0x5F55179: "c3",                  # ret
    0x5F551B0: "4883c328",            # add $0x28,%rbx (cold block)
}
GATE_SAMPLES = {
    0x5F54F77: "4c89ad88000000",      # mov %r13,0x88(%rbp) (end=begin)
    0x5F55036: "488b7b50",            # mov 0x50(%rbx),%rdi (dispose)
    0x5F5512A: "488b8538010000",      # mov 0x138(%rbp),%rax (tail buf)
}
# Call sites: (address, call bytes, bytes of the immediately following
# instruction).
CALL_SITES = {
    0x5F54F6D: ("e80ebe4900", "4939dc"),
    0x5F54F8E: ("e8bdefffff", "4889df"),
    0x5F550D7: ("e8a4bc4900", "4939dc"),
}
CALL_TARGETS = (0x63F0D80, 0x5F53F50)
WINDOWS = [
    ("0x5f54ee0", "0x5f551c2", "function_0x5f54ee0.txt"),
]
EXPECTED_CENSUS = {
    "0x5f54ee0": {"direct_calls": ["0x5f1337c", "0x5f1442c", "0x5f160d5",
                                   "0x5f161fd", "0x5f5c1f6"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": []},
    "0x5f53f50": {"direct_calls": ["0x5f53fe1", "0x5f54f8e"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": []},
}
EXPECTED_FRAMES = [
    "0035c7e8 0000000000000038 0035c7ec FDE cie=00000000 pc=0000000005f54ee0..0000000005f551c2",
]


def fail(message):
    print("FAIL:", message)
    return 1


def raw_at(data, address, length):
    # .text vaddr base 0x1419300 maps to file offset 0x1418300.
    return data[address - 0x1000:address - 0x1000 + length]


def main():
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        return fail("binary digest mismatch")
    with open(REPO_ROOT / "provenance" / "artifacts.json") as fh:
        provenance = json.load(fh)
    if SHA256 not in json.dumps(provenance):
        return fail("provenance entry missing")

    manifest = PACKET_DIR / "MANIFEST.sha256"
    for line in manifest.read_text().splitlines():
        digest, name = line.split("  ", 1)
        blob = (PACKET_DIR / name).read_bytes()
        if hashlib.sha256(blob).hexdigest() != digest:
            return fail("manifest mismatch for %s" % name)

    for start, stop, name in WINDOWS:
        proc = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % start,
             "--stop-address=%s" % stop, "work/hl-node-115.bin"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        if proc.returncode != 0:
            return fail("objdump failed for %s" % name)
        if proc.stdout != (PACKET_DIR / name).read_text():
            return fail("excerpt regeneration mismatch for %s" % name)

    for samples in (SAMPLES, GATE_SAMPLES):
        for address, expected in samples.items():
            raw = raw_at(data, address, len(expected) // 2).hex()
            if raw != expected:
                return fail("raw byte mismatch at %s: %s != %s"
                            % (hex(address), raw, expected))

    for address, (call_bytes, after_bytes) in CALL_SITES.items():
        raw = raw_at(data, address, 5).hex()
        if raw != call_bytes:
            return fail("call byte mismatch at %s" % hex(address))
        after = raw_at(data, address + 5, len(after_bytes) // 2).hex()
        if after != after_bytes:
            return fail("post-call mismatch at %s" % hex(address))
        rel = struct.unpack_from("<i", bytes.fromhex(call_bytes), 1)[0]
        if address + 5 + rel not in CALL_TARGETS:
            return fail("call target mismatch at %s" % hex(address))

    frames = (PACKET_DIR / "frames.txt").read_text().splitlines()
    if frames != EXPECTED_FRAMES:
        return fail("frames.txt mismatch")

    proc = subprocess.run(
        [sys.executable, str(PACKET_DIR / "census.py")],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return fail("census.py failed")
    census = json.loads(proc.stdout)
    for target, expected in EXPECTED_CENSUS.items():
        got = census[target]
        for key, want in expected.items():
            if sorted(got[key]) != sorted(want):
                return fail("census mismatch for %s %s: %s != %s"
                            % (target, key, got[key], want))

    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tests" / "test_element_reset_115.py")],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        return fail("model tests failed")
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
