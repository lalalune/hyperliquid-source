"""Verification for the RE-001-element-prepare-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE record, the census, the
call-site raw bytes, and the model tests. Exits nonzero on the first
failure and prints ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-element-prepare-115/verify.py
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
    0x5F13310: "f30f1efa",            # endbr64 (element prepare)
    0x5F13343: "e8b8931600",          # call 0x607c700 (guard acquire)
    0x5F13348: "4d8b6558",            # mov 0x58(%r13),%r12 (second end)
    0x5F13350: "49c1fc03",            # sar $0x3,%r12
    0x5F13354: "4d036500",            # add 0x0(%r13),%r12 (count)
    0x5F1336E: "668987880a0000",      # mov %ax,0xa88(%rdi) (zero store)
    0x5F1337C: "e85f1b0400",          # call 0x5f54ee0 (per element)
    0x5F13385: "83451001",            # addl $0x1,0x10(%rbp) (counter)
    0x5F133A3: "c6450001",            # movb $0x1,0x0(%rbp) (ready)
    0x5F133A7: "e874931600",          # call 0x607c720 (guard release)
    0x5F132E6: "4c89f7",              # mov %r14,%rdi (cleanup)
    0x5F132E9: "e832941600",          # call 0x607c720 (cleanup release)
}
GATE_SAMPLES = {
    0x5F1338E: "4883fb07",            # cmp $0x7,%rbx (array switch)
    0x5F13360: "498b4550",            # mov 0x50(%r13),%rax (second begin)
    0x5F133CE: "f30f1efa",            # endbr64 (landing pad)
}
# Call sites: (address, call bytes, bytes of the immediately following
# instruction). The branch after each test is recorded in records.json
# and checked by the model tests' packet checks.
CALL_SITES = {
    0x5F13343: ("e8b8931600", "4d8b6558"),
    0x5F1337C: ("e85f1b0400", "4883c301"),
    0x5F133A7: ("e874931600", "488b442408"),
    0x5F132E9: ("e832941600", "488b442408"),
}
CALL_TARGETS = (0x607C700, 0x5F54EE0, 0x607C720)
WINDOWS = [
    ("0x5f13310", "0x5f133da", "function_0x5f13310.txt"),
    ("0x5f132e6", "0x5f1330b", "function_0x5f132e6.txt"),
]
EXPECTED_CENSUS = {
    "0x5f13310": {"direct_calls": ["0x5de6e58", "0x5ed6895"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": []},
    "0x5f54ee0": {"direct_calls": ["0x5f1337c", "0x5f1442c", "0x5f160d5",
                                   "0x5f161fd", "0x5f5c1f6"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": []},
    "0x607c700": {"direct_calls": ["0x5e00207", "0x5e03e20", "0x5e08132",
                                   "0x5e0b26d", "0x5e10a20", "0x5ed2487",
                                   "0x5ed5e5d", "0x5f13343", "0x5f148e1",
                                   "0x5f14f28", "0x5f16a28"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": []},
    "0x607c720": {"direct_calls": ["0x5dfef6f", "0x5dffd38", "0x5e03d3c",
                                   "0x5e04ce2", "0x5e07fe7", "0x5e08aed",
                                   "0x5e0b1dc", "0x5e0c1a6", "0x5e1095d",
                                   "0x5e10c6b", "0x5ed22a6", "0x5ed3ee2",
                                   "0x5ed5d81", "0x5ed68e8", "0x5f132e9",
                                   "0x5f133a7", "0x5f14877", "0x5f149c2",
                                   "0x5f14df5", "0x5f14f72", "0x5f168ce",
                                   "0x5f1744f"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": []},
}
EXPECTED_FRAMES = [
    "00745ed4 0000000000000044 00015ca8 FDE cie=00730230 pc=0000000005f13310..0000000005f133da",
    "00745f1c 0000000000000020 00015cf0 FDE cie=00730230 pc=0000000005f132e6..0000000005f1330b",
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
        [sys.executable, str(REPO_ROOT / "tests" / "test_element_prepare_115.py")],
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
