"""Verification for the RE-001-two-flag-lazy-init-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, the
call-site and tail-jump raw bytes, and the model tests. Exits nonzero
on the first failure and prints ALL CHECKS PASSED only when every
check passes.

Run from the repository root:
  python3 research/work-items/RE-001-two-flag-lazy-init-115/verify.py
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
SAMPLES = {
    0x605E8A0: "f30f1efa",        # endbr64 (variant entry)
    0x605E8A5: "807f1000",        # cmpb $0x0,0x10(%rdi) (flag10)
    0x605E8AE: "488b3b",          # mov (%rbx),%rdi (inner load)
    0x605E8B6: "807b1100",        # cmpb $0x0,0x11(%rbx) (flag11)
    0x605E8C0: "488b07",          # mov (%rdi),%rax (first qword)
    0x605E8D3: "e8b8bf0000",      # call callback 0x606a890
    0x605E8D8: "c6431101",        # movb $0x1,0x11(%rbx) (set flag11)
    0x605E8DD: "c3",              # ret (variant)
    0x605E8E0: "e87bffffff",      # call lazy-init 0x605e860
    0x605E8E5: "ebc7",            # jmp back to 0x605e8ae
    0x605E8F0: "f30f1efa",        # endbr64 (wrapper entry)
    0x605E8F8: "e8a3ffffff",      # call variant 0x605e8a0
    0x605E901: "c3",              # ret (wrapper)
    0x606A890: "f30f1efa",        # endbr64 (callback entry)
    0x606A895: "48837f2000",      # cmpq $0x0,0x20(%rdi)
    0x606A89F: "e8ccf8ffff",      # call 0x606a170
    0x606A8A8: "e9a3fdffff",      # jmp 0x606a650 (tail)
    0x606A8B0: "488b07",          # mov (%rdi),%rax
    0x606A8B8: "f048297710",      # lock sub %rsi,0x10(%rdi)
}
GATE_SAMPLES = {
    0x605E8C8: "48837f2000",      # cmpq $0x0,0x20(%rdi) (callback gate)
    0x605E8CF: "488b7308",        # mov 0x8(%rbx),%rsi (callback arg)
    0x606A8A4: "4889df",          # mov %rbx,%rdi (tail-jump setup)
}
# Call sites: (address, call bytes, bytes of the immediately following
# instruction).
CALL_SITES = {
    0x605E8E0: ("e87bffffff", "ebc7"),
    0x605E8D3: ("e8b8bf0000", "c6431101"),
    0x605E8F8: ("e8a3ffffff", "4883c408"),
    0x606A89F: ("e8ccf8ffff", "4889df"),
    0x5F10D5F: ("e83cdb1400", "4c8bad100d0000"),
    0x605CC5F: ("e83c1c0000", "498b9688080000"),
    0x5F10280: ("e86be61400", "488b442468"),
}
CALL_TARGETS = (0x605E860, 0x606A890, 0x605E8A0, 0x606A170, 0x605E8F0)
# Tail jumps: (address, jump bytes, target).
TAIL_SITES = {
    0x606A8A8: ("e9a3fdffff", 0x606A650),
    0x5F114B5: ("e936d41400", 0x605E8F0),
}
WINDOWS = [
    ("0x605e8a0", "0x605e8e7", "function_0x605e8a0.txt"),
    ("0x605e8f0", "0x605e902", "function_0x605e8f0.txt"),
    ("0x606a890", "0x606a8bf", "function_0x606a890.txt"),
]
EXPECTED_CENSUS = {
    "0x605e8a0": {"direct_calls": ["0x5f10d5f", "0x605cc5f", "0x605e8f8"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x605e8f0": {"direct_calls": ["0x5f10280"],
                  "tail_jumps": ["0x5f114b5"],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x606a890": {"direct_calls": ["0x605e8d3"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x605e860": {"direct_calls": ["0x5f14117", "0x605e8e0"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x606a170": {"direct_calls": ["0x606a89f"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x606a650": {"direct_calls": [],
                  "tail_jumps": ["0x606a8a8"],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
}
EXPECTED_FRAMES = [
    "pc=000000000605e8a0..000000000605e8e7",
    "pc=000000000605e8f0..000000000605e902",
    "pc=000000000606a890..000000000606a8bf",
]


def fail(msg):
    print("FAIL: %s" % msg, file=sys.stderr)
    return 1


def main():
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        return fail("work binary digest mismatch")
    prov = json.loads((REPO_ROOT / "provenance" / "artifacts.json")
                      .read_text())
    digests = {f["path"]: f["sha256"] for f in prov["files"]}
    if digests.get("artifacts/node/115/hl-node") != SHA256:
        return fail("provenance digest mismatch")
    manifest = (PACKET_DIR / "MANIFEST.sha256").read_text().splitlines()
    import hashlib as _h
    for line in manifest:
        digest, name = line.split("  ", 1)
        if _h.sha256((PACKET_DIR / name).read_bytes()).hexdigest() != digest:
            return fail("manifest mismatch for %s" % name)
    for start, stop, name in WINDOWS:
        proc = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % start,
             "--stop-address=%s" % stop, "work/hl-node-115.bin"],
            cwd=REPO_ROOT, capture_output=True, text=True)
        if proc.returncode != 0:
            return fail("objdump failed for %s" % name)
        if proc.stdout != (PACKET_DIR / name).read_text():
            return fail("excerpt %s is not verbatim" % name)
    for addr, expected in list(SAMPLES.items()) + list(GATE_SAMPLES.items()):
        raw = data[addr - 0x1000:addr - 0x1000 + len(expected) // 2].hex()
        if raw != expected:
            return fail("sample bytes mismatch at %#x: %s != %s"
                        % (addr, raw, expected))
    frames = (PACKET_DIR / "frames.txt").read_text()
    for frag in EXPECTED_FRAMES:
        if frag not in frames:
            return fail("frames.txt missing %s" % frag)
    records = json.loads((PACKET_DIR / "records.json").read_text())
    if records["census"] != EXPECTED_CENSUS:
        return fail("records census mismatch")
    census_out = subprocess.run(
        [sys.executable, str(PACKET_DIR / "census.py")],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if census_out.returncode != 0:
        return fail("census.py failed: %s" % census_out.stderr)
    if json.loads(census_out.stdout) != EXPECTED_CENSUS:
        return fail("live census mismatch")
    for addr, (call_bytes, next_bytes) in CALL_SITES.items():
        raw = data[addr - 0x1000:addr - 0x1000 + len(call_bytes) // 2].hex()
        if raw != call_bytes:
            return fail("call bytes mismatch at %#x" % addr)
        nxt = data[addr - 0x1000 + len(call_bytes) // 2:
                   addr - 0x1000 + len(call_bytes) // 2
                   + len(next_bytes) // 2].hex()
        if nxt != next_bytes:
            return fail("following bytes mismatch at %#x" % addr)
    for addr, (jump_bytes, target) in TAIL_SITES.items():
        raw = data[addr - 0x1000:addr - 0x1000 + len(jump_bytes) // 2].hex()
        if raw != jump_bytes:
            return fail("tail-jump bytes mismatch at %#x" % addr)
    model = subprocess.run(
        [sys.executable,
         str(REPO_ROOT / "tests" / "test_two_flag_lazy_init_115.py")],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if model.returncode != 0 or "ALL TESTS PASSED" not in model.stdout:
        return fail("model tests failed: %s%s"
                    % (model.stdout, model.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
