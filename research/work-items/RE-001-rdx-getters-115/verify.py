"""Verification for the RE-001-rdx-getters-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, the
call-site raw bytes, and the model tests. Exits nonzero on the first
failure and prints ALL CHECKS PASSED only when every check passes.

Run from the repository root:
  python3 research/work-items/RE-001-rdx-getters-115/verify.py
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
    0x5EEB6C0: "f30f1efa",        # endbr64 (getter C entry)
    0x5EEB6C5: "4889d7",          # mov %rdx,%rdi (obj forwarded)
    0x5EEB6CB: "e880fef5ff",      # call leaf 0x5e4b550
    0x5EEB6D0: "488903",          # mov %rax,(%rbx) (store to *out)
    0x5EEB6D9: "c3",              # ret (getter C)
    0x5EEB6E0: "f30f1efa",        # endbr64 (getter D entry)
    0x5EEB6EB: "e870fef5ff",      # call leaf 0x5e4b560
    0x5EEB6F9: "c3",              # ret (getter D)
    0x5EEB700: "f30f1efa",        # endbr64 (getter E entry)
    0x5EEB706: "8b8a04110000",    # mov 0x1104(%rdx),%ecx (count)
    0x5EEB710: "488b8228110000",  # mov 0x1128(%rdx),%rax (pointer)
    0x5EEB71F: "c3",              # ret (getter E)
    0x5EEB720: "f30f1efa",        # endbr64 (getter F entry)
    0x5EEB725: "488dba00110000",  # lea 0x1100(%rdx),%rdi
    0x5EEB72F: "e8dcde0d00",      # call leaf 0x5fc9610
    0x5EEB734: "0fb6c0",          # movzbl %al,%eax (mask the raw leaf return)
    0x5EEB740: "c3",              # ret (getter F)
    0x5E4B550: "f30f1efa",        # endbr64 (leaf550 entry)
    0x5E4B554: "488b4768",        # mov 0x68(%rdi),%rax
    0x5E4B558: "488b80e0000000",  # mov 0xe0(%rax),%rax
    0x5E4B55F: "c3",              # ret (leaf550)
    0x5E4B560: "f30f1efa",        # endbr64 (leaf560 entry)
    0x5E4B576: "e8159e2800",      # call refresh 0x60d5390
    0x5E4B57B: "488b03",          # mov (%rbx),%rax (first node)
    0x5E4B583: "488b4010",        # mov 0x10(%rax),%rax (payload)
    0x5E4B590: "48c7c0ffffffff",  # mov $-1,%rax (empty list)
    0x5E4B598: "c3",              # ret (leaf560)
    0x5FC9610: "f30f1efa",        # endbr64 (leaf610 entry)
    0x5FC9614: "8b07",            # mov (%rdi),%eax
    0x5FC9616: "85c0",            # test %eax,%eax
    0x5FC961B: "c3",              # ret (leaf610)
}
GATE_SAMPLES = {
    0x5EEB70E: "7e07",            # jle (count <= 0 arm)
    0x5E4B581: "740d",            # je (empty-list arm)
    0x5FC9618: "0f9fc0",          # setg %al (low byte only)
}
# Call sites: (address, call bytes, bytes of the immediately following
# instruction).
CALL_SITES = {
    0x5EEB6CB: ("e880fef5ff", "488903"),
    0x5EEB6EB: ("e870fef5ff", "488903"),
    0x5EEB72F: ("e8dcde0d00", "0fb6c0"),
}
WINDOWS = [
    ("0x5eeb6c0", "0x5eeb6da", "function_0x5eeb6c0.txt"),
    ("0x5eeb6e0", "0x5eeb6fa", "function_0x5eeb6e0.txt"),
    ("0x5eeb700", "0x5eeb720", "function_0x5eeb700.txt"),
    ("0x5eeb720", "0x5eeb741", "function_0x5eeb720.txt"),
    ("0x5e4b550", "0x5e4b560", "function_0x5e4b550.txt"),
    ("0x5e4b560", "0x5e4b599", "function_0x5e4b560.txt"),
    ("0x5fc9610", "0x5fc961c", "function_0x5fc9610.txt"),
]
EXPECTED_CENSUS = {
    "0x5eeb6c0": {"direct_calls": [],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5eeb6e0": {"direct_calls": [],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5eeb700": {"direct_calls": [],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5eeb720": {"direct_calls": [],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5e4b550": {"direct_calls": ["0x5dd1aff", "0x5e4ef75",
                                   "0x5e697f0", "0x5eeb6cb"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5e4b560": {"direct_calls": ["0x5e4eec1", "0x5eeb6eb"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5fc9610": {"direct_calls": ["0x5d8bf39", "0x5dd5f7b",
                                   "0x5de0057", "0x5de1baf",
                                   "0x5dfcec9", "0x5dfdef0",
                                   "0x5e872f5", "0x5e8732b",
                                   "0x5e87aa1", "0x5e8e84d",
                                   "0x5ecc429", "0x5eeb72f"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
}
EXPECTED_FRAMES = [
    "pc=0000000005eeb6c0..0000000005eeb6da",
    "pc=0000000005eeb6e0..0000000005eeb6fa",
    "pc=0000000005eeb700..0000000005eeb720",
    "pc=0000000005eeb720..0000000005eeb741",
    "pc=0000000005e4b550..0000000005e4b560",
    "pc=0000000005e4b560..0000000005e4b599",
    "pc=0000000005fc9610..0000000005fc961c",
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
         str(REPO_ROOT / "tests" / "test_rdx_getters_115.py")],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if model.returncode != 0 or "ALL TESTS PASSED" not in model.stdout:
        return fail("model tests failed: %s%s"
                    % (model.stdout, model.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
