"""Verification for the RE-001-sibling-getters-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE record, the census, the
call-site raw bytes, and the model tests. Exits nonzero on the first
failure and prints ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-sibling-getters-115/verify.py
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

# (address, expected raw bytes) sampled from the verbatim excerpts.
SAMPLES = {
    0x5EEB490: "f30f1efa",            # endbr64 (list-sum getter)
    0x5EEB49D: "488bbf88070000",      # mov 0x788(%rdi),%rdi
    0x5EEB4B9: "e8227f0200",          # call 0x5f133e0 (list-sum getter)
    0x5EEB4BE: "4801e8",              # add %rbp,%rax (base addend)
    0x5EEB4D0: "f30f1efa",            # endbr64 (field-load getter)
    0x5EEB4F9: "e8227f0200",          # call 0x5f13420 (field-load getter)
    0x5F133E0: "f30f1efa",            # endbr64 (list walk)
    0x5F133EA: "4c8b6708",            # mov 0x8(%rdi),%r12 (header)
    0x5F13404: "e8c7aeffff",          # call 0x5f0e2d0 (per-element)
    0x5F13420: "f30f1efa",            # endbr64 (field load)
    0x5F13424: "488b4718",            # mov 0x18(%rdi),%rax
}
GATE_SAMPLES = {
    0x5EEB4A4: "488b87e8080000",      # mov 0x8e8(%rdi),%rax
    0x5F133F2: "4939dc",              # cmp %rbx,%r12 (header test)
    0x5F1340C: "4801c5",              # add %rax,%rbp (running sum)
}
# Call sites: (address, call bytes, bytes of the immediately following
# instruction). The branch after each test is recorded in records.json
# and checked by the model tests' packet checks.
CALL_SITES = {
    0x5EEB4B9: ("e8227f0200", "4801e8"),
    0x5EEB4F9: ("e8227f0200", "4801e8"),
    0x5F13404: ("e8c7aeffff", "488b1b"),
}
CALL_TARGETS = (0x5F133E0, 0x5F13420, 0x5F0E2D0)
WINDOWS = [
    ("0x5eeb490", "0x5eeb4d0", "function_0x5eeb490.txt"),
    ("0x5eeb4d0", "0x5eeb510", "function_0x5eeb4d0.txt"),
    ("0x5f133e0", "0x5f1341c", "function_0x5f133e0.txt"),
    ("0x5f13420", "0x5f13429", "function_0x5f13420.txt"),
]
EXPECTED_CENSUS = {
    "0x5eeb490": {"direct_calls": [], "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": []},
    "0x5eeb4d0": {"direct_calls": [], "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": []},
    "0x5f133e0": {"direct_calls": ["0x5eeb4b9"], "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": []},
    "0x5f13420": {"direct_calls": ["0x5eeb4f9"], "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": []},
    "0x5f0e2d0": {"direct_calls": ["0x5d9115f", "0x5ecc153", "0x5ecc18c",
                                   "0x5eccb2a", "0x5ed0c0d", "0x5ed0de1",
                                   "0x5ed19d5", "0x5ed29d0", "0x5f127e2",
                                   "0x5f13404", "0x5f13e49"],
                  "tail_jumps": [], "qword_hits": [],
                  "relative_addend_hits": []},
}
EXPECTED_FRAMES = [
    "00356f48 0000000000000024 00356f4c FDE cie=00000000 pc=0000000005eeb490..0000000005eeb4d0",
    "00356f70 0000000000000024 00356f74 FDE cie=00000000 pc=0000000005eeb4d0..0000000005eeb510",
    "00359140 0000000000000028 00359144 FDE cie=00000000 pc=0000000005f133e0..0000000005f1341c",
    "0035916c 0000000000000010 00359170 FDE cie=00000000 pc=0000000005f13420..0000000005f13429",
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
        [sys.executable, str(REPO_ROOT / "tests" / "test_sibling_getters_115.py")],
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
