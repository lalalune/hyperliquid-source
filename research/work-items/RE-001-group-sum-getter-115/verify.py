"""Verification for the RE-001-group-sum-getter-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, the
call-site raw bytes, and the model tests. Exits nonzero on the first
failure and prints ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-group-sum-getter-115/verify.py
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

# (address, expected raw bytes) sampled from the verbatim excerpts.
# File offset = virtual address - 0x1000 for the .text section.
SAMPLES = {
    0x5EEB670: "f30f1efa",        # endbr64 (getter entry)
    0x5EEB674: "53",              # push %rbx
    0x5EEB677: "4889f3",          # mov %rsi,%rbx (out saved)
    0x5EEB67A: "4885c9",          # test %rcx,%rcx (null check)
    0x5EEB67D: "7408",            # je (null arm)
    0x5EEB682: "e829f50700",      # call group sum 0x5f6abb0
    0x5EEB687: "488903",          # mov %rax,(%rbx) (store to *out)
    0x5EEB690: "c3",              # ret (getter)
    0x5F6ABB0: "f30f1efa",        # endbr64 (sum entry)
    0x5F6ABC2: "488b8708010000",  # mov 0x108(%rdi),%rax
    0x5F6ABC9: "482b8700010000",  # sub 0x100(%rdi),%rax
    0x5F6ABD0: "48c1f804",        # sar $0x4,%rax
    0x5F6ABD4: "48034770",        # add 0x70(%rdi),%rax (total)
    0x5F6ABDD: "0f84c4000000",    # je (total == 0 arm)
    0x5F6AC00: "48833c2407",      # cmpq $0x7,(%rsp) (index threshold)
    0x5F6AC05: "0f8685000000",    # jbe (inline-descriptor arm)
    0x5F6AC1F: "49837d0000",      # cmpq $0x0,0x0(%r13) (count == 0)
    0x5F6AC30: "498b5610",        # mov 0x10(%r14),%rdx (re-read per item)
    0x5F6AC5C: "e85f69fdff",      # call callee 0x5f415c0 by contract
    0x5F6AC61: "4801c3",          # add %rax,%rbx (sum += return)
    0x5F6ACA7: "31db",            # xor %ebx,%ebx (zero-total path)
    0x5F6AC8B: "c3",              # ret (sum)
}
GATE_SAMPLES = {
    0x5EEB67F: "4889cf",          # mov %rcx,%rdi (object forwarded)
    0x5F6AC4E: "488bbaC0080000".lower(),  # mov 0x8c0(%rdx),%rdi
    0x5F6AC90: "4c8b0c24",        # mov (%rsp),%r9 (inline arm index)
}
# Call sites: (address, call bytes, bytes of the immediately following
# instruction).
CALL_SITES = {
    0x5EEB682: ("e829f50700", "488903"),
    0x5F6AC5C: ("e85f69fdff", "4801c3"),
}
WINDOWS = [
    ("0x5eeb670", "0x5eeb691", "function_0x5eeb670.txt"),
    ("0x5f6abb0", "0x5f6acab", "function_0x5f6abb0.txt"),
]
EXPECTED_CENSUS = {
    "0x5eeb670": {"direct_calls": [],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5f6abb0": {"direct_calls": ["0x5eeb682"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5f415c0": {"direct_calls": ["0x5f6ac5c"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
}
EXPECTED_FRAMES = [
    "pc=0000000005eeb670..0000000005eeb691",
    "pc=0000000005f6abb0..0000000005f6acab",
]


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
    for addr, expected in EXPECTED_CENSUS.items():
        if census.get(addr) != expected:
            return fail("census mismatch for %s: %s" % (addr, census.get(addr)))
    # Call-site raw bytes.
    for addr, (call_bytes, next_bytes) in CALL_SITES.items():
        off = addr - 0x1000
        raw_call = data[off:off + len(bytes.fromhex(call_bytes))].hex()
        raw_next = data[off + len(bytes.fromhex(call_bytes)):
                        off + len(bytes.fromhex(call_bytes))
                        + len(bytes.fromhex(next_bytes))].hex()
        if raw_call != call_bytes or raw_next != next_bytes:
            return fail("call-site bytes mismatch at %#x" % addr)
    # Model tests.
    proc = subprocess.run(
        [sys.executable, "tests/test_group_sum_getter_115.py"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0 or "ALL TESTS PASSED" not in proc.stdout:
        return fail("model tests failed: %s%s" % (proc.stdout, proc.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
