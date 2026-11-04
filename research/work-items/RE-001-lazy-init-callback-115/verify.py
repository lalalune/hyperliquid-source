"""Verification for the RE-001-lazy-init-callback-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, the
call-site raw bytes, and the model tests. Exits nonzero on the first
failure and prints ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-lazy-init-callback-115/verify.py
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
    0x605E860: "f30f1efa",        # endbr64 (lazy-init entry)
    0x605E868: "488b3f",          # mov (%rdi),%rdi (inner load)
    0x605E86E: "7406",            # je (inner null)
    0x605E870: "807b1000",        # cmpb $0x0,0x10(%rbx) (flag)
    0x605E880: "488b07",          # mov (%rdi),%rax (first qword)
    0x605E888: "48837f2000",      # cmpq $0x0,0x20(%rdi) (gate)
    0x605E893: "e878b80000",      # call callback 0x606a110
    0x605E898: "c6431001",        # movb $0x1,0x10(%rbx) (set flag)
    0x605E89D: "c3",              # ret (lazy-init)
    0x606A110: "f30f1efa",        # endbr64 (callback entry)
    0x606A114: "488b07",          # mov (%rdi),%rax
    0x606A117: "4885c0",          # test %rax,%rax
    0x606A11A: "7504",            # jne (null check)
    0x606A11C: "c3",              # ret (null arm)
    0x606A120: "f048297718",      # lock sub %rsi,0x18(%rdi)
    0x606A125: "c3",              # ret (callback)
}
GATE_SAMPLES = {
    0x605E874: "740a",            # je (flag nonzero return)
    0x605E88D: "7409",            # je (gate skip)
    0x606A11D: "0f1f00",          # nopl (padding before subtract)
}
# Call sites: (address, call bytes, bytes of the immediately following
# instruction).
CALL_SITES = {
    0x605E893: ("e878b80000", "c6431001"),
    0x5F14117: ("e844a71400", "8b4310"),
    0x605E8E0: ("e87bffffff", "ebc7"),
}
WINDOWS = [
    ("0x605e860", "0x605e89e", "function_0x605e860.txt"),
    ("0x606a110", "0x606a126", "function_0x606a110.txt"),
]
EXPECTED_CENSUS = {
    "0x605e860": {"direct_calls": ["0x5f14117", "0x605e8e0"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x606a110": {"direct_calls": ["0x605e893"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
}
EXPECTED_FRAMES = [
    "pc=000000000605e860..000000000605e89e",
    "pc=000000000606a110..000000000606a126",
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
    model = subprocess.run(
        [sys.executable,
         str(REPO_ROOT / "tests" / "test_lazy_init_callback_115.py")],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if model.returncode != 0 or "ALL TESTS PASSED" not in model.stdout:
        return fail("model tests failed: %s%s"
                    % (model.stdout, model.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
