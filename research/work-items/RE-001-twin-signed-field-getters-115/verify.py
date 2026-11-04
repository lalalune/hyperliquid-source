"""Verification for the RE-001-twin-signed-field-getters-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, the
call-site raw bytes, and the model tests. Exits nonzero on the first
failure and prints ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-twin-signed-field-getters-115/verify.py
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
    ("0x5eeb400", "0x5eeb427", "function_0x5eeb400.txt"),
    ("0x5eeb430", "0x5eeb457", "function_0x5eeb430.txt"),
    ("0x5f12a10", "0x5f12a1c", "function_0x5f12a10.txt"),
    ("0x5f12a20", "0x5f12a2c", "function_0x5f12a20.txt"),
]

# (address, expected raw bytes) sampled from the verbatim excerpts.
# File offset = virtual address - 0x1000 for the .text section.
SAMPLES = {
    0x5EEB400: "f30f1efa",        # endbr64 (getter A entry)
    0x5EEB404: "53",              # push %rbx
    0x5EEB405: "488bbf88070000",  # mov 0x788(%rdi),%rdi (member load)
    0x5EEB40C: "4889f3",          # mov %rsi,%rbx (out save)
    0x5EEB40F: "4881c7f0080000",  # add $0x8f0,%rdi (sub-object form)
    0x5EEB416: "e8f5750200",      # call leaf A
    0x5EEB41B: "4898",            # cltq (sign extension)
    0x5EEB41D: "488903",          # mov %rax,(%rbx) (store)
    0x5EEB420: "b801000000",      # mov $0x1,%eax (return 1)
    0x5EEB425: "5b",              # pop %rbx
    0x5EEB426: "c3",              # ret (getter A)
    0x5EEB430: "f30f1efa",        # endbr64 (getter B entry)
    0x5EEB434: "53",              # push %rbx
    0x5EEB435: "488bbf88070000",  # mov 0x788(%rdi),%rdi (member load)
    0x5EEB43C: "4889f3",          # mov %rsi,%rbx (out save)
    0x5EEB43F: "4881c7f0080000",  # add $0x8f0,%rdi (sub-object form)
    0x5EEB446: "e8d5750200",      # call leaf B
    0x5EEB44B: "4898",            # cltq (sign extension)
    0x5EEB44D: "488903",          # mov %rax,(%rbx) (store)
    0x5EEB450: "b801000000",      # mov $0x1,%eax (return 1)
    0x5EEB455: "5b",              # pop %rbx
    0x5EEB456: "c3",              # ret (getter B)
    0x5F12A10: "f30f1efa",        # endbr64 (leaf A entry)
    0x5F12A14: "488b4708",        # mov 0x8(%rdi),%rax (inner load)
    0x5F12A18: "8b4010",          # mov 0x10(%rax),%eax (field 0x10)
    0x5F12A1B: "c3",              # ret (leaf A)
    0x5F12A20: "f30f1efa",        # endbr64 (leaf B entry)
    0x5F12A24: "488b4708",        # mov 0x8(%rdi),%rax (inner load)
    0x5F12A28: "8b4028",          # mov 0x28(%rax),%eax (field 0x28)
    0x5F12A2B: "c3",              # ret (leaf B)
}
# Three extra gate instructions picked at random.
GATE_SAMPLES = {
    0x5EEB425: "5b",              # pop %rbx (getter A epilogue)
    0x5F12A18: "8b4010",          # mov 0x10(%rax),%eax (leaf A field)
    0x5EEB43F: "4881c7f0080000",  # add $0x8f0,%rdi (getter B base)
}
EXPECTED_FRAMES = [
    "pc=0000000005eeb400..0000000005eeb427",
    "pc=0000000005eeb430..0000000005eeb457",
    "pc=0000000005f12a10..0000000005f12a1c",
    "pc=0000000005f12a20..0000000005f12a2c",
]
EXPECTED_CENSUS = {
    "0x5eeb400": {"direct_calls": [], "tail_jumps": [],
                  "qword_hits": [], "qword_hits_whole_file": [],
                  "relative_addend_hits": []},
    "0x5eeb430": {"direct_calls": [], "tail_jumps": [],
                  "qword_hits": [], "qword_hits_whole_file": [],
                  "relative_addend_hits": []},
    "0x5f12a10": {"direct_calls": ["0x5d8bf06", "0x5d8c007", "0x5d8c43c",
                                   "0x5dd58a1", "0x5dd58d7", "0x5dd5bd8",
                                   "0x5dd5c56", "0x5ddfba5", "0x5e896b9",
                                   "0x5e8b1e2", "0x5e8b337", "0x5e8b5cc",
                                   "0x5e8b9e4", "0x5e8bfad", "0x5ed6f05",
                                   "0x5eeb416"],
                  "tail_jumps": [], "qword_hits": [],
                  "qword_hits_whole_file": [],
                  "relative_addend_hits": []},
    "0x5f12a20": {"direct_calls": ["0x5eeb446"], "tail_jumps": [],
                  "qword_hits": [], "qword_hits_whole_file": [],
                  "relative_addend_hits": []},
}
CALL_SITES = {
    0x5EEB416: "e8f5750200",
    0x5EEB446: "e8d5750200",
}


def fail(msg):
    print("FAIL: %s" % msg, file=sys.stderr)
    return 1


def main():
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        return fail("binary digest mismatch")
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
            return fail("excerpt regeneration mismatch for %s" % name)
    print("excerpts ok")
    for addr, hexbytes in {**SAMPLES, **GATE_SAMPLES}.items():
        raw = bytes.fromhex(hexbytes)
        off = addr - 0x1000
        if data[off:off + len(raw)] != raw:
            return fail("raw byte mismatch at %#x" % addr)
    print("sampled bytes ok")
    frames = (PACKET_DIR / "frames.txt").read_text()
    for expected in EXPECTED_FRAMES:
        if expected not in frames:
            return fail("missing frame %s" % expected)
    print("frames ok")
    proc = subprocess.run(
        [sys.executable, str(PACKET_DIR / "census.py")],
        capture_output=True, text=True)
    if proc.returncode != 0:
        return fail("census.py failed: %s" % proc.stderr)
    census = json.loads(proc.stdout)
    for target, expected in EXPECTED_CENSUS.items():
        if census.get(target) != expected:
            return fail("census mismatch for %s: %r" % (target, census.get(target)))
    print("census ok")
    for addr, hexbytes in CALL_SITES.items():
        raw = bytes.fromhex(hexbytes)
        off = addr - 0x1000
        if data[off:off + len(raw)] != raw:
            return fail("call-site byte mismatch at %#x" % addr)
    print("call sites ok")
    proc = subprocess.run(
        [sys.executable,
         str(REPO_ROOT / "tests" / "test_twin_signed_field_getters_115.py")],
        capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        return fail("model tests failed")
    print("model tests ok")
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
