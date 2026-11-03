"""Verification for the RE-001-decimal-keyed-group-sum-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, the
branch sites, and the model tests. Exits nonzero on the first
failure and prints ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-decimal-keyed-group-sum-115/verify.py
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
    ("0x5eee310", "0x5eee421", "function_0x5eee310.txt"),
    ("0x61d0df0", "0x61d0e87", "function_0x61d0df0.txt"),
]

# (address, expected raw bytes) sampled from the verbatim excerpts.
# File offset = virtual address - 0x1000 for the .text section.
SAMPLES = {
    0x5EEE310: "f30f1efa",        # endbr64 (caller entry)
    0x5EEE343: "e8a82a2e00",      # call 0x61d0df0 (parser)
    0x5EEE360: "498b842488070000",  # mov 0x788(%r12),%rax (member)
    0x5EEE36C: "48634250",        # movslq 0x50(%rdx),%rax (count)
    0x5EEE37B: "488d0440",        # lea (%rax,%rax,2),%rax (count*3)
    0x5EEE384: "4d8d14c1",        # lea (%r9,%rax,8),%r10 (group end)
    0x5EEE3A3: "0fb68ab7000000",  # movzbl 0xb7(%rdx),%ecx (key byte)
    0x5EEE3AF: "4c034210",        # add 0x10(%rdx),%r8 (sum field)
    0x5EEE3D0: "e89b15e6ff",      # call 0x5d4f970 (formatter)
    0x5EEE3DB: "e840d7ffff",      # call 0x5eebb20 (string assign)
    0x61D0DF0: "f30f1efa",        # endbr64 (parser entry)
    0x61D0E0C: "49b99999999999999919",  # movabs threshold
    0x61D0E24: "83e830",          # sub $0x30,%eax (digit value)
    0x61D0E31: "83f805",          # cmp $0x5,%eax (last-digit guard)
}
# Three extra gate instructions picked at random from the excerpts.
GATE_SAMPLES = {
    0x5EEE352: "4c8b442408",      # mov 0x8(%rsp),%r8 (remaining)
    0x5EEE390: "498b01",          # mov (%r9),%rax (group begin)
    0x5EEE3C5: "4c8d642420",      # lea 0x20(%rsp),%r12 (temp string)
}
EXPECTED_FRAMES = {
    "0x5eee310": ("00357850", "0000000000000030"),
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
    if census["0x5eee310"]["direct_calls"] != []:
        return fail("caller census changed")
    if "0x5eee343" not in census["0x61d0df0"]["direct_calls"]:
        return fail("parser caller site missing")
    if len(census["0x61d0df0"]["direct_calls"]) != 10:
        return fail("parser call count changed")
    print("census ok")
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    test_proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tests" / "test_decimal_keyed_group_sum_115.py")],
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
