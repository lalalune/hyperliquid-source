"""Verification for the RE-001-proportional-share-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE record, the census, and
the model tests. Exits nonzero on the first failure and prints
ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-proportional-share-115/verify.py
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

# (address, expected raw bytes) sampled from the verbatim excerpt.
SAMPLES = {
    0x5F6AD70: "f30f1efa",            # endbr64
    0x5F6AD84: "488b87b00f0000",      # mov 0xfb0(%rdi),%rax
    0x5F6ADC0: "488b4208",            # loop head: mov 0x8(%rdx),%rax
    0x5F6AE16: "f20f100d42e54efa",    # movsd constant (objdump wraps it)
    0x5F6AE78: "f20f5cc1",            # subsd (2**63 arm)
    0x5F6AE81: "480fbafe3f",          # btc $0x3f,%rsi
}
GATE_SAMPLES = {
    0x5F6AD9B: "4829d0",              # sub %rdx,%rax (span)
    0x5F6AE24: "f2480f2cf0",          # cvttsd2si %xmm0,%rsi
    0x5F6ADB4: "488d0440",            # lea (%rax,%rax,2),%rax
}


def fail(message):
    print("FAIL:", message)
    return 1


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

    proc = subprocess.run(
        ["objdump", "-d", "--start-address=0x5f6ad70",
         "--stop-address=0x5f6aece", "work/hl-node-115.bin"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return fail("objdump failed: %s" % proc.stderr)
    excerpt = (PACKET_DIR / "function_0x5f6ad70.txt").read_text()
    if proc.stdout != excerpt:
        return fail("excerpt regeneration mismatch")

    for address, expected in {**SAMPLES, **GATE_SAMPLES}.items():
        raw = data[address - 0x1000: address - 0x1000 + len(expected) // 2]
        if raw.hex() != expected:
            return fail("byte mismatch at %#x: %s != %s"
                        % (address, raw.hex(), expected))

    frames = (PACKET_DIR / "frames.txt").read_text()
    if "pc=0000000005f6ad70..0000000005f6aece" not in frames:
        return fail("FDE record missing from frames.txt")
    with open(PACKET_DIR / "records.json") as fh:
        records = json.load(fh)
    if records["windows"][0]["fde_offset"] != "0x35dcec":
        return fail("FDE offset mismatch")

    proc = subprocess.run(
        [sys.executable, str(PACKET_DIR / "census.py")],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return fail("census.py failed: %s" % proc.stderr)
    census = json.loads(proc.stdout)
    if census["direct_calls"] != ["0x5eeb5b3"]:
        return fail("census direct calls mismatch: %r" % census["direct_calls"])
    if census["tail_jumps"] or census["qword_hits"] \
            or census["relative_addend_hits"]:
        return fail("census unexpected hits: %r" % census)

    proc = subprocess.run(
        [sys.executable, "tests/test_proportional_share_115.py"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0 or "ALL" not in proc.stdout:
        return fail("model tests failed: %s%s" % (proc.stdout, proc.stderr))

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
