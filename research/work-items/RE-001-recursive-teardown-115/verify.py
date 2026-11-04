"""Verification for the RE-001-recursive-teardown-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE record, the census, the
call-site raw bytes, and the model tests. Exits nonzero on the first
failure and prints ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-recursive-teardown-115/verify.py
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
    0x5F53F50: "4157",            # push %r15 (teardown entry)
    0x5F53F5A: "4883ec28",        # sub $0x28,%rsp
    0x5F53F63: "4885ff",          # test %rdi,%rdi (null-head check)
    0x5F53F71: "488b4018",        # mov 0x18(%rax),%rax (first child)
    0x5F53F83: "488b442408",      # mov 0x8(%rsp),%rax (chain node)
    0x5F53F95: "4d8b7e18",        # mov 0x18(%r14),%r15 (descend)
    0x5F53FAF: "4c8b6318",        # mov 0x18(%rbx),%r12 (descend)
    0x5F53FC2: "488b5518",        # mov 0x18(%rbp),%rdx (descend)
    0x5F53FE1: "e86affffff",      # call self (recursive teardown)
    0x5F53FF2: "e889cd4900",      # call _ZdlPvm@plt (delete)
    0x5F54080: "488b5510",        # mov 0x10(%rbp),%rdx (next sibling)
    0x5F54118: "c3",              # ret
}
GATE_SAMPLES = {
    0x5F53F8C: "4d85f6",          # test %r14,%r14
    0x5F53FD8: "498b7d18",        # mov 0x18(%r13),%rdi (recurse arg)
    0x5F54105: "e962feffff",      # jmp back to chain head
}
# Call sites: (address, call bytes, bytes of the immediately following
# instruction).
CALL_SITES = {
    0x5F53FE1: ("e86affffff", "4c89ef"),
    0x5F54F8E: ("e8bdefffff", "4889df"),
}
CALL_TARGETS = (0x5F53F50,)
WINDOWS = [
    ("0x5f53f50", "0x5f54119", "function_0x5f53f50.txt"),
]
EXPECTED_CENSUS = {
    "0x5f53f50": {"direct_calls": ["0x5f53fe1", "0x5f54f8e"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
}
EXPECTED_FRAMES = [
    "0035c744 0000000000000048 0035c748 FDE cie=00000000 pc=0000000005f53f50..0000000005f54119",
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
        [sys.executable, str(REPO_ROOT / "tests" / "test_recursive_teardown_115.py")],
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
