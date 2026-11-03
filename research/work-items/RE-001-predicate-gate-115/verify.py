"""Verification for the RE-001-predicate-gate-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE record, the census, the
call-site raw bytes, and the model tests. Exits nonzero on the first
failure and prints ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-predicate-gate-115/verify.py
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
    0x5F132A0: "f30f1efa",            # endbr64
    0x5F132A4: "0fb64715",            # movzbl 0x15(%rdi),%eax
    0x5F132B3: "395704",              # cmp %edx,0x4(%rdi)
    0x5F132B6: "0f9ec0",              # setle %al
    0x5F132C0: "f30f1efa",            # endbr64
    0x5F132C4: "488b4708",            # mov 0x8(%rdi),%rax
    0x5F132C8: "48635710",            # movslq 0x10(%rdi),%rdx
    0x5F132E0: "e9bbffffff",          # jmp 0x5f132a0 (tail delegation)
    0x5F132D2: "b801000000",          # mov $0x1,%eax (mismatch arm)
    0x5EEB460: "f30f1efa",            # endbr64 (getter)
    0x5EEB476: "e8257e0200",          # call 0x5f132a0 (getter)
    0x5EEB47B: "0fb6c0",              # movzbl %al,%eax (getter store)
}
GATE_SAMPLES = {
    0x5F132AF: "85d2",                # test %edx,%edx
    0x5F132CC: "483b5010",            # cmp 0x10(%rax),%rdx
    0x5EEB46F: "4881c7f0080000",      # add $0x8f0,%rdi (getter arg)
}
# Call sites: (address, call bytes, bytes of the immediately following
# test instruction). The branch after each test is recorded in
# records.json and checked by the model tests' branch table.
CALL_SITES = {
    0x5DDAFE7: ("e8b4821300", "84c0"),
    0x5DE860E: ("e88dac1200", "84c0"),
    0x5E8D1E6: ("e8d5600800", "84c0"),
    0x5EEB476: ("e8257e0200", "0fb6c0"),
}
WINDOWS = [
    ("0x5f132a0", "0x5f132ba", "function_0x5f132a0.txt"),
    ("0x5f132c0", "0x5f132e5", "function_0x5f132c0.txt"),
    ("0x5eeb460", "0x5eeb488", "function_0x5eeb460.txt"),
]
EXPECTED_CENSUS = {
    "0x5f132a0": {"direct_calls": ["0x5ddafe7", "0x5de860e", "0x5eeb476"],
                  "tail_jumps": ["0x5f132e0"],
                  "qword_hits": [], "relative_addend_hits": []},
    "0x5f132c0": {"direct_calls": ["0x5e8d1e6"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": []},
}
EXPECTED_FRAMES = [
    "00359118 0000000000000010 0035911c FDE cie=00000000 pc=0000000005f132a0..0000000005f132ba",
    "0035912c 0000000000000010 00359130 FDE cie=00000000 pc=0000000005f132c0..0000000005f132e5",
    "00356f2c 0000000000000018 00356f30 FDE cie=00000000 pc=0000000005eeb460..0000000005eeb488",
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

    for address, (call_bytes, test_bytes) in CALL_SITES.items():
        raw = raw_at(data, address, 5).hex()
        if raw != call_bytes:
            return fail("call byte mismatch at %s" % hex(address))
        after = raw_at(data, address + 5, len(test_bytes) // 2).hex()
        if after != test_bytes:
            return fail("post-call test mismatch at %s" % hex(address))
        if address != 0x5EEB476:
            rel = struct.unpack_from("<i", bytes.fromhex(call_bytes), 1)[0]
            if address + 5 + rel not in (0x5F132A0, 0x5F132C0):
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
        [sys.executable, str(REPO_ROOT / "tests" / "test_predicate_gate_115.py")],
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
