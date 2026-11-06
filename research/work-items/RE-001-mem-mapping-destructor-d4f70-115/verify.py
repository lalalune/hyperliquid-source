"""Verification for the RE-001-mem-mapping-destructor-d4f70-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including the padding
gate bytes), the FDE records, the census, the call-site raw bytes, and
the model tests. Exits nonzero on the first failure and prints ALL
CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-mem-mapping-destructor-d4f70-115/verify.py
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
    0x60D4F70: "f30f1efa",        # endbr64 (entry)
    0x60D4F74: "488b07",          # mov (%rdi),%rax (pointer word)
    0x60D4F77: "4885c0",          # test %rax,%rax
    0x60D4F7A: "7414",            # je (null path to the ret)
    0x60D4F7C: "488b7708",        # mov 0x8(%rdi),%rsi (length word)
    0x60D4F80: "4889c7",          # mov %rax,%rdi
    0x60D4F83: "e978bc3100",      # jmp munmap@plt 0x63f0c00 (tail)
    0x60D4F90: "c3",              # ret (null path)
}
GATE_SAMPLES = {
    0x60D4F88: "0f1f840000000000",  # nopl padding inside the FDE
}
# Call sites: (address, call bytes, bytes of the immediately following
# instruction).
CALL_SITES = {
    0x605CCC7: ("e8a4820700", "4939df"),
    0x605CD07: ("e864820700", "48396c2410"),
    0x605CD27: ("e844820700", "4c392c24"),
    0x605CEE7: ("e884800700", "48392c24"),
    0x605CFD9: ("e8927f0700", "488b442428"),
    0x605D08E: ("e8dd7e0700", "488b442428"),
    0x605DBA7: ("e8c4730700", "4c39f3"),
    0x605DBD7: ("e894730700", "48396c2408"),
    0x605DBF7: ("e874730700", "4c392c24"),
    0x605DC87: ("e8e4720700", "48392c24"),
    0x60D4FB5: ("e8b6ffffff", "f30f6f4500"),
}
WINDOWS = [
    ("0x60d4f70", "0x60d4f91", "main.txt"),
]
EXPECTED_CENSUS = {
    "0x60d4f70": {"direct_calls": ["0x605ccc7", "0x605cd07",
                                   "0x605cd27", "0x605cee7",
                                   "0x605cfd9", "0x605d08e",
                                   "0x605dba7", "0x605dbd7",
                                   "0x605dbf7", "0x605dc87",
                                   "0x60d4fb5"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
}
EXPECTED_FRAMES = [
    "pc=00000000060d4f70..00000000060d4f91",
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
         str(REPO_ROOT / "tests" / "test_mem_mapping_destructor_d4f70_115.py")],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if model.returncode != 0 or "ALL TESTS PASSED" not in model.stdout:
        return fail("model tests failed: %s%s"
                    % (model.stdout, model.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
