"""Verification for the RE-001-default-gated-predicate-getter-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, the
call-site raw bytes, the sole-gate-site claim via a full objdump grep,
and the model tests. Exits nonzero on the first failure and prints
ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-default-gated-predicate-getter-115/verify.py
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
    ("0x5eeb7a0", "0x5eeb7ef", "function_0x5eeb7a0.txt"),
    ("0x5d89610", "0x5d89617", "function_0x5d89610.txt"),
]

# (address, expected raw bytes) sampled from the verbatim excerpts.
# File offset = virtual address - 0x1000 for the .text section.
SAMPLES = {
    0x5EEB7A0: "f30f1efa",        # endbr64 (getter entry)
    0x5EEB7A5: "488b8f88070000",  # mov 0x788(%rdi),%rcx (member load)
    0x5EEB7AF: "488bb950090000",  # mov 0x950(%rcx),%rdi (object load)
    0x5EEB7B6: "488b07",          # mov (%rdi),%rax (vtable load)
    0x5EEB7B9: "488b5028",        # mov 0x28(%rax),%rdx (slot load)
    0x5EEB7BF: "483b150a1b6000",  # cmp 0x64ed2d0(%rip),%rdx (gate)
    0x5EEB7C8: "488903",          # mov %rax,(%rbx) (default store)
    0x5EEB7CB: "b801000000",      # mov $0x1,%eax (return 1)
    0x5EEB7D1: "c3",              # ret (default arm)
    0x5EEB7D8: "488b7130",        # mov 0x30(%rcx),%rsi (base load)
    0x5EEB7DC: "4883c640",        # add $0x40,%rsi (arg form)
    0x5EEB7E0: "ffd2",            # call *%rdx (virtual call)
    0x5EEB7E2: "0fb6c0",          # movzbl %al,%eax (mask)
    0x5EEB7EE: "c3",              # ret (override arm)
    0x5D89610: "f30f1efa",        # endbr64 (default entry)
    0x5D89614: "31c0",            # xor %eax,%eax (return 0)
    0x5D89616: "c3",              # ret (default)
}
# Three extra gate instructions picked at random.
GATE_SAMPLES = {
    0x5EEB7AC: "4889f3",          # mov %rsi,%rbx (out save)
    0x5EEB7BD: "31c0",            # xor %eax,%eax (zero before compare)
    0x5EEB7E5: "488903",          # mov %rax,(%rbx) (override store)
}
EXPECTED_FRAMES = [
    "pc=0000000005eeb7a0..0000000005eeb7ef",
    "pc=0000000005d89610..0000000005d89617",
]
EXPECTED_CENSUS = {
    "0x5eeb7a0": {"direct_calls": [], "tail_jumps": [],
                  "qword_hits": [], "qword_hits_whole_file": [],
                  "relative_addend_hits": []},
    "0x5d89610": {"direct_calls": [], "tail_jumps": [],
                  "qword_hits": [],
                  "qword_hits_whole_file": ["0x105208", "0x15cf28"],
                  "relative_addend_hits": ["0x1051f8", "0x15cf18"]},
}
CALL_SITES = {
    0x5EEB7E0: ("ffd2", "0fb6c0"),
}


def fail(msg):
    print("FAIL: %s" % msg, file=sys.stderr)
    return 1


def main():
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        return fail("work binary digest mismatch")
    # Manifest: every listed file hashes to its recorded value.
    manifest = (PACKET_DIR / "MANIFEST.sha256").read_text().splitlines()
    for line in manifest:
        digest, name = line.split(None, 1)
        path = PACKET_DIR / name.strip()
        if not path.exists():
            return fail("manifest file missing: %s" % name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            return fail("manifest hash mismatch: %s" % name)
    # Excerpt regeneration byte-for-byte from a fresh objdump run.
    proc = subprocess.run(
        [sys.executable, str(PACKET_DIR / "export_excerpts.py")],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        return fail("export_excerpts.py failed: %s" % proc.stderr)
    for start, stop, name in WINDOWS:
        proc = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % start,
             "--stop-address=%s" % stop, "work/hl-node-115.bin"],
            cwd=REPO_ROOT, capture_output=True, text=True)
        if proc.stdout != (PACKET_DIR / name).read_text():
            return fail("excerpt mismatch after regeneration: %s" % name)
    # Sampled + gate instruction bytes vs the raw binary.
    for addr, hexbytes in list(SAMPLES.items()) + list(GATE_SAMPLES.items()):
        off = addr - 0x1000
        raw = data[off:off + len(bytes.fromhex(hexbytes))].hex()
        if raw != hexbytes:
            return fail("raw bytes mismatch at %#x: %s != %s"
                        % (addr, raw, hexbytes))
    # FDE records.
    frames = (PACKET_DIR / "frames.txt").read_text()
    for expected in EXPECTED_FRAMES:
        if expected not in frames:
            return fail("missing FDE record: %s" % expected)
    # Census.
    proc = subprocess.run(
        [sys.executable, str(PACKET_DIR / "census.py")],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        return fail("census.py failed: %s" % proc.stderr)
    census = json.loads(proc.stdout)
    for target, expected in EXPECTED_CENSUS.items():
        got = census[target]
        for key, value in expected.items():
            if got[key] != value:
                return fail("census mismatch %s %s: %r != %r"
                            % (target, key, got[key], value))
    # Call-site raw bytes.
    for addr, (call_bytes, next_bytes) in CALL_SITES.items():
        off = addr - 0x1000
        raw = data[off:off + len(bytes.fromhex(call_bytes))].hex()
        if raw != call_bytes:
            return fail("call bytes mismatch at %#x" % addr)
        if next_bytes is not None:
            nxt = data[off + len(bytes.fromhex(call_bytes)):
                       off + len(bytes.fromhex(call_bytes))
                       + len(bytes.fromhex(next_bytes))].hex()
            if nxt != next_bytes:
                return fail("following bytes mismatch at %#x" % addr)
    # Sole-gate-site claim: exactly one .text site references 0x64ed2d0.
    dump = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", "work/hl-node-115.bin"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    hits = [ln for ln in dump.stdout.splitlines() if "# 64ed2d0" in ln]
    if len(hits) != 1 or "5eeb7bf" not in hits[0]:
        return fail("gate-site claim failed: %r" % (hits,))
    # Model tests.
    proc = subprocess.run(
        [sys.executable,
         "tests/test_default_gated_predicate_getter_115.py"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        return fail("model tests failed: %s%s" % (proc.stdout, proc.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
