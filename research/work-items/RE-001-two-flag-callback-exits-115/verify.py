"""Verify the RE-001-two-flag-callback-exits-115 packet.

Checks, in order: the binary digest against provenance, the packet
manifest, the verbatim objdump excerpts (regenerated), sample
bytes at the pinned sites, the frames.txt fragments, the recorded
census against both the embedded expectation and a live census.py
run, the callback's call-site bytes for both exits, and the model
tests. Run from anywhere; paths resolve from this file.
"""

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY = REPO_ROOT / "work" / "hl-node-115.bin"
EXPECTED_SHA256 = \
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

EXPECTED_CENSUS = {
    "0x606a170": {"direct_calls": ["0x606a89f"], "tail_jumps": [],
                  "qword_hits": [], "qword_hits_whole_file": [],
                  "relative_addend_hits": []},
    "0x606a650": {"direct_calls": [], "tail_jumps": ["0x606a8a8"],
                  "qword_hits": [], "qword_hits_whole_file": [],
                  "relative_addend_hits": []},
    "0x606a890": {"direct_calls": ["0x605e8d3"], "tail_jumps": [],
                  "qword_hits": [], "qword_hits_whole_file": [],
                  "relative_addend_hits": []},
}

SAMPLE_BYTES = [
    (0x606A170, bytes.fromhex("f30f1efa")),          # endbr64
    (0x606A1B3, bytes.fromhex("48896b10")),          # total stored
    (0x606A27E, bytes.fromhex("ff5010")),            # fifth-level call
    (0x606A2D1, bytes.fromhex("e99a683800")),        # tail jump unlock
    (0x606A672, bytes.fromhex("80bf9800000000")),    # gate flag cmpb
    (0x606A730, bytes.fromhex("c6839900000000")),    # flag clear
    (0x606A823, bytes.fromhex("0f114358")),          # splice self-link
]

# (site, bytes, meaning): the callback's two exits and the byte
# immediately after the direct call.
CALL_SITES = [
    (0x606A89F, bytes.fromhex("e8ccf8ffff"), "call 0x606a170"),
    (0x606A8A4, bytes.fromhex("4889df"), "mov rbx,rdi reload"),
    (0x606A8A8, bytes.fromhex("e9a3fdffff"), "jmp 0x606a650"),
]


def fail(msg):
    print("FAIL: %s" % msg, file=sys.stderr)
    return 1


def main():
    records = json.loads((PACKET_DIR / "records.json").read_text())
    if records["artifact_sha256"] != EXPECTED_SHA256:
        return fail("records.json digest mismatch")
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA256:
        return fail("binary digest mismatch")

    manifest = {}
    for line in (PACKET_DIR / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        manifest[name.strip()] = digest
    expected_files = {"README.md", "census.py", "export_excerpts.py",
                      "frames.txt", "function_0x606a170.txt",
                      "function_0x606a650.txt", "records.json",
                      "relocations.txt", "verify.py"}
    if set(manifest) != expected_files:
        return fail("manifest file set mismatch: %s" % sorted(manifest))
    for name, digest in manifest.items():
        actual = hashlib.sha256(
            (PACKET_DIR / name).read_bytes()).hexdigest()
        if actual != digest:
            return fail("manifest hash mismatch for %s" % name)

    for start, stop, name in [("0x606a170", "0x606a3d6",
                               "function_0x606a170.txt"),
                              ("0x606a650", "0x606a88e",
                               "function_0x606a650.txt")]:
        proc = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % start,
             "--stop-address=%s" % stop, "work/hl-node-115.bin"],
            cwd=REPO_ROOT, capture_output=True, text=True)
        if proc.returncode != 0:
            return fail("objdump failed for %s" % name)
        if proc.stdout != (PACKET_DIR / name).read_text():
            return fail("excerpt mismatch for %s" % name)

    def at(addr, n):
        return data[addr - 0x1000:addr - 0x1000 + n]

    for addr, want in SAMPLE_BYTES:
        if at(addr, len(want)) != want:
            return fail("sample bytes mismatch at %#x" % addr)
    for addr, want, _meaning in CALL_SITES:
        if at(addr, len(want)) != want:
            return fail("call-site bytes mismatch at %#x" % addr)

    frames = (PACKET_DIR / "frames.txt").read_text()
    for frag in ["pc=000000000606a170..000000000606a3d6",
                 "pc=000000000606a650..000000000606a88e"]:
        if frag not in frames:
            return fail("frames.txt missing %s" % frag)

    if records["census"] != EXPECTED_CENSUS:
        return fail("records.json census mismatch")
    proc = subprocess.run([sys.executable,
                           str(PACKET_DIR / "census.py")],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return fail("census.py failed: %s" % proc.stderr)
    if json.loads(proc.stdout) != EXPECTED_CENSUS:
        return fail("live census mismatch")

    proc = subprocess.run(
        [sys.executable,
         str(REPO_ROOT / "tests" /
             "test_two_flag_callback_exits_115.py")],
        capture_output=True, text=True)
    if proc.returncode != 0 or "ALL TESTS PASSED" not in proc.stdout:
        return fail("model tests failed: %s%s" %
                    (proc.stdout, proc.stderr))

    print("RE-001-two-flag-callback-exits-115: all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
