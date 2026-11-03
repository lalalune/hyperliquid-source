"""Verification for the RE-001-chain-length-getter-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, the
call-site and tail-jump raw bytes, and the model tests. Exits nonzero
on the first failure and prints ALL CHECKS PASSED only when every
check passes.

Run from the repository root:
  python3 research/work-items/RE-001-chain-length-getter-115/verify.py
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
    0x5EEB610: "f30f1efa",        # endbr64 (getter entry)
    0x5EEB614: "53",              # push %rbx
    0x5EEB615: "488bbf88070000",  # mov 0x788(%rdi),%rdi (member load)
    0x5EEB61F: "e87c13eaff",      # call stub 0x5d8c9a0
    0x5EEB624: "488903",          # mov %rax,(%rbx) (store to *out)
    0x5EEB627: "b801000000",      # mov $0x1,%eax (return 1)
    0x5EEB62D: "c3",              # ret (getter)
    0x5D8C9A0: "f30f1efa",        # endbr64 (stub entry)
    0x5D8C9A8: "e9d3371e00",      # jmp counter 0x5f70180 (tail jump)
    0x5F70180: "f30f1efa",        # endbr64 (counter entry)
    0x5F70184: "488b8728100000",  # mov 0x1028(%rdi),%rax (first link)
    0x5F7018D: "4839c7",          # cmp %rax,%rdi (head check)
    0x5F70190: "7416",            # je (empty-chain arm)
    0x5F70198: "488b8028100000",  # mov 0x1028(%rax),%rax (walk step)
    0x5F7019F: "4883c201",        # add $0x1,%rdx (count++)
    0x5F701A6: "75f0",            # jne (loop back)
    0x5F701AB: "c3",              # ret (counter)
}
GATE_SAMPLES = {
    0x5EEB61C: "4889f3",          # mov %rsi,%rbx (out saved)
    0x5F7018B: "31d2",            # xor %edx,%edx (count = 0)
    0x5F701A8: "4889d0",          # mov %rdx,%rax (return count)
}
# Call sites: (address, call/jump bytes, bytes of the immediately
# following instruction, or None when the next bytes are padding).
CALL_SITES = {
    0x5EEB61F: ("e87c13eaff", "488903"),
    0x5D8C9A8: ("e9d3371e00", None),
}
WINDOWS = [
    ("0x5eeb610", "0x5eeb62e", "function_0x5eeb610.txt"),
    ("0x5d8c9a0", "0x5d8c9ad", "function_0x5d8c9a0.txt"),
    ("0x5f70180", "0x5f701ac", "function_0x5f70180.txt"),
]
EXPECTED_CENSUS = {
    "0x5eeb610": {"direct_calls": [],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5d8c9a0": {"direct_calls": ["0x5eeb61f"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5f70180": {"direct_calls": [],
                  "tail_jumps": ["0x5d8c9a8"],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
}
EXPECTED_FRAMES = [
    "pc=0000000005eeb610..0000000005eeb62e",
    "pc=0000000005d8c9a0..0000000005d8c9ad",
    "pc=0000000005f70180..0000000005f701ac",
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
    for target, expected in EXPECTED_CENSUS.items():
        got = census[target]
        for key, value in expected.items():
            if got[key] != value:
                return fail("census mismatch %s %s: %r != %r"
                            % (target, key, got[key], value))
    # Call-site and tail-jump raw bytes.
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
    # Model tests.
    proc = subprocess.run(
        [sys.executable, "tests/test_chain_length_getter_115.py"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        return fail("model tests failed: %s%s" % (proc.stdout, proc.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
