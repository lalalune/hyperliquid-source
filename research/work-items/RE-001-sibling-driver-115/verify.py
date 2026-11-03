"""Verification for the RE-001-sibling-driver-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, the
call-site and tail-jump raw bytes, and the model tests. Exits nonzero
on the first failure and prints ALL CHECKS PASSED only when every
check passes.

Run from the repository root:
  python3 research/work-items/RE-001-sibling-driver-115/verify.py
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
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# (address, expected raw bytes) sampled from the verbatim excerpts.
SAMPLES = {
    0x5F140C0: "f30f1efa",        # endbr64 (driver entry)
    0x5F140E5: "e8a6feffff",      # call prepare 0x5f13f90
    0x5F140F4: "e897ffffff",      # call wrapper 0x5f14090
    0x5F14107: "483b055a965d00",  # cmp slot against .got sentinel
    0x5F14117: "e844a71400",      # call lazy-init 0x605e860
    0x5F14125: "83f801",          # cmp $0x1,%eax (counter)
    0x5F1412D: "e81ef3ffff",      # call refresh 0x5f13450
    0x5F14132: "b801000000",      # mov $0x1,%eax (return value)
    0x5F1413E: "f00fb05301",      # lock cmpxchg %dl,0x1(%rbx)
    0x5F14161: "c3",              # ret (driver)
    0x5F14168: "c60301",          # movb $0x1,(%rbx) (first-run byte)
    0x5F14170: "ffd0",            # call *%rax (dispatch)
    0x5F14090: "f30f1efa",        # endbr64 (wrapper entry)
    0x5F140A0: "e80be7ffff",      # call pre-call 0x5f127b0
    0x5F140B3: "e948ffffff",      # jmp drain 0x5f14000
    0x5F127B0: "f30f1efa",        # endbr64 (pre-call entry)
    0x5F127C6: "e805e64d00",      # call operator new
    0x5F127D5: "e8b6e84d00",      # call _M_hook
    0x5F127DA: "4883431001",      # addq $0x1,0x10(%rbx) (counter)
    0x5F127E2: "e8e9baffff",      # call aggregate 0x5f0e2d0
    0x5F127F5: "c3",              # ret (pre-call)
    0x5F127F6: "488b7b18",        # mov 0x18(%rbx),%rdi (cold block)
    0x5F1282E: "e81de24d00",      # call _Unwind_Resume
    0x605E860: "f30f1efa",        # endbr64 (lazy-init entry)
    0x605E86B: "4885ff",          # test %rdi,%rdi (inner null check)
    0x605E870: "807b1000",        # cmpb $0x0,0x10(%rbx) (flag check)
    0x605E880: "488b07",          # mov (%rdi),%rax (first qword)
    0x605E893: "e878b80000",      # call callback 0x606a110
    0x605E898: "c6431001",        # movb $0x1,0x10(%rbx) (set flag)
    0x605E89D: "c3",              # ret (lazy-init)
}
GATE_SAMPLES = {
    0x5F140EA: "488b7b08",        # mov 0x8(%rbx),%rdi (reload inner)
    0x5F1411C: "8b4310",          # mov 0x10(%rbx),%eax (counter load)
    0x5F127CE: "48896810",        # mov %rbp,0x10(%rax) (node payload)
}
# Call sites: (address, call bytes, bytes of the immediately following
# instruction).
CALL_SITES = {
    0x5F140E5: ("e8a6feffff", "488b7b08"),
    0x5F140F4: ("e897ffffff", "488bbd500a0000"),
    0x5F14117: ("e844a71400", "8b4310"),
    0x5F1412D: ("e81ef3ffff", "b801000000"),
    0x5F140A0: ("e80be7ffff", "4883c408"),
    0x5F127E2: ("e8e9baffff", "4889c2"),
    0x605E893: ("e878b80000", "c6431001"),
    0x5E83A33: ("e888060900", "4183467001"),
    0x5E8ABA9: ("e812950800", "488b8d28fbffff"),
    0x5ED1C20: ("e89b240400", "83437001"),
}
CALL_TARGETS = (0x5F13F90, 0x5F14090, 0x605E860, 0x5F13450, 0x5F127B0,
                0x5F0E2D0, 0x606A110, 0x5F140C0)
# Tail jumps: (address, jump bytes, target).
TAIL_SITES = {
    0x5F140B3: ("e948ffffff", 0x5F14000),
}
WINDOWS = [
    ("0x5f140c0", "0x5f14179", "function_0x5f140c0.txt"),
    ("0x5f14090", "0x5f140b8", "function_0x5f14090.txt"),
    ("0x5f127b0", "0x5f127f6", "function_0x5f127b0.txt"),
    ("0x5f127f6", "0x5f12833", "function_0x5f127f6.txt"),
    ("0x605e860", "0x605e89e", "function_0x605e860.txt"),
]
EXPECTED_CENSUS = {
    "0x5f140c0": {"direct_calls": ["0x5e83a33", "0x5e8aba9", "0x5ed1c20"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5f14090": {"direct_calls": ["0x5f140f4"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5f127b0": {"direct_calls": ["0x5f140a0"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x605e860": {"direct_calls": ["0x5f14117", "0x605e8e0"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5f13f90": {"direct_calls": ["0x5f140e5", "0x5f141a5",
                                   "0x5f143b5", "0x5f1468e",
                                   "0x5f15a43", "0x5f15a9a"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5f13450": {"direct_calls": ["0x5f1412d", "0x5f141be",
                                   "0x5f14545", "0x5f145cf",
                                   "0x5f147c0", "0x5f16472",
                                   "0x5f165bf"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5f14000": {"direct_calls": ["0x5f141b4"],
                  "tail_jumps": ["0x5f140b3", "0x5f14327"],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5f0e2d0": {"direct_calls": ["0x5d9115f", "0x5ecc153",
                                   "0x5ecc18c", "0x5eccb2a",
                                   "0x5ed0c0d", "0x5ed0de1",
                                   "0x5ed19d5", "0x5ed29d0",
                                   "0x5f127e2", "0x5f13404",
                                   "0x5f13e49"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x606a110": {"direct_calls": ["0x605e893"],
                  "tail_jumps": [],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
}
EXPECTED_FRAMES = [
    "00359330 0000000000000030 00359334 FDE cie=00000000 pc=0000000005f140c0..0000000005f14179",
    "00359308 0000000000000024 0035930c FDE cie=00000000 pc=0000000005f14090..0000000005f140b8",
    "00358e5c 0000000000000028 00358e60 FDE cie=00000000 pc=0000000005f127b0..0000000005f127f6",
    "00367840 000000000000001c 00367844 FDE cie=00000000 pc=000000000605e860..000000000605e89e",
    "No FDE covers 0x5f127f6..0x5f12833; it is the cold block immediately following the pre-call's ret, using the pre-call's own registers (rbx, r12, rbp); this packet does not pin the edge that enters it.",
]


def fail(message):
    print("FAIL:", message)
    return 1


def raw_at(data, address, length):
    # .text vaddr base 0x1419300 maps to file offset 0x1418300.
    return data[address - 0x1000:address - 0x1000 + length]


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

    for start, stop, name in WINDOWS:
        proc = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % start,
             "--stop-address=%s" % stop, "work/hl-node-115.bin"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        if proc.returncode != 0:
            return fail("objdump failed for %s" % name)
        if proc.stdout != (PACKET_DIR / name).read_text():
            return fail("excerpt regeneration mismatch for %s" % name)

    for samples in (SAMPLES, GATE_SAMPLES):
        for address, expected in samples.items():
            raw = raw_at(data, address, len(expected) // 2).hex()
            if raw != expected:
                return fail("raw byte mismatch at %s: %s != %s"
                            % (hex(address), raw, expected))

    for address, (call_bytes, after_bytes) in CALL_SITES.items():
        raw = raw_at(data, address, 5).hex()
        if raw != call_bytes:
            return fail("call byte mismatch at %s" % hex(address))
        after = raw_at(data, address + 5, len(after_bytes) // 2).hex()
        if after != after_bytes:
            return fail("post-call mismatch at %s" % hex(address))
        rel = struct.unpack_from("<i", bytes.fromhex(call_bytes), 1)[0]
        if address + 5 + rel not in CALL_TARGETS:
            return fail("call target mismatch at %s" % hex(address))

    for address, (jump_bytes, target) in TAIL_SITES.items():
        raw = raw_at(data, address, 5).hex()
        if raw != jump_bytes:
            return fail("tail byte mismatch at %s" % hex(address))
        rel = struct.unpack_from("<i", bytes.fromhex(jump_bytes), 1)[0]
        if address + 5 + rel != target:
            return fail("tail target mismatch at %s" % hex(address))

    frames = (PACKET_DIR / "frames.txt").read_text().splitlines()
    if frames != EXPECTED_FRAMES:
        return fail("frames.txt mismatch")

    proc = subprocess.run(
        [sys.executable, str(PACKET_DIR / "census.py")],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return fail("census.py failed: %s" % proc.stderr)
    if json.loads(proc.stdout) != EXPECTED_CENSUS:
        return fail("census mismatch: %s" % proc.stdout)

    proc = subprocess.run(
        [sys.executable, "tests/test_sibling_driver_115.py"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0 or "ALL TESTS PASSED" not in proc.stdout:
        return fail("model tests failed: %s%s"
                    % (proc.stdout, proc.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
