"""Verification for the RE-001-drain-driver-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, the
call-site and tail-jump raw bytes, and the model tests. Exits nonzero
on the first failure and prints ALL CHECKS PASSED only when every
check passes.

Run from the repository root:
  python3 research/work-items/RE-001-drain-driver-115/verify.py
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
    0x5F14180: "f30f1efa",        # endbr64 (driver entry)
    0x5F14186: "4989d4",          # mov %rdx,%r12 (predicate arg)
    0x5F14191: "4883ec10",        # sub $0x10,%rsp
    0x5F141A5: "e8e6fdffff",      # call prepare 0x5f13f90
    0x5F141AA: "488b7b08",        # mov 0x8(%rbx),%rdi (reload inner)
    0x5F141B4: "e847feffff",      # call drain 0x5f14000
    0x5F141BE: "e88df2ffff",      # call refresh 0x5f13450
    0x5F141CF: "f00fb05301",      # lock cmpxchg %dl,0x1(%rbx)
    0x5F141F4: "c3",              # ret (driver)
    0x5F141F5: "e876cb4d00",      # call __stack_chk_fail@plt
    0x5F13F90: "f30f1efa",        # endbr64 (prepare entry)
    0x5F13F98: "488b6f08",        # mov 0x8(%rdi),%rbp (inner)
    0x5F13F9C: "837d4001",        # cmpl $0x1,0x40(%rbp) (refcount)
    0x5F13FB8: "e813ce4d00",      # call operator new
    0x5F13FCA: "e871e8ffff",      # call move 0x5f12840
    0x5F13FCF: "4c896308",        # mov %r12,0x8(%rbx) (install new)
    0x5F13FD6: "e825eaffff",      # call init 0x5f12a00
    0x5F13FE4: "e9b7feffff",      # jmp release 0x5f13ea0
    0x5F13FE9: "f30f1efa",        # endbr64 (landing pad)
    0x5F13FF0: "e97dffffff",      # jmp cleanup 0x5f13f72
    0x5F13450: "f30f1efa",        # endbr64 (refresh entry)
    0x5F13458: "488b7f08",        # mov 0x8(%rdi),%rdi (inner)
    0x5F1345C: "e8cffcffff",      # call aggregate 0x5f13130
    0x5F13461: "48894320",        # mov %rax,0x20(%rbx)
    0x5F13471: "0f95c0",          # setne %al (nonempty byte)
    0x5F13478: "c3",              # ret (refresh)
    0x5F13F72: "4c89e7",          # mov %r12,%rdi (cleanup)
    0x5F13F7A: "e801ce4d00",      # call operator delete
    0x5F13F82: "e8c9ca4d00",      # call _Unwind_Resume@plt
}
GATE_SAMPLES = {
    0x5F141C3: "b801000000",      # mov $0x1,%eax (cmpxchg comparand)
    0x5F13FB3: "bf50000000",      # mov $0x50,%edi (allocation size)
    0x5F13469: "488d5018",        # lea 0x18(%rax),%rdx (header address)
}
# Call sites: (address, call bytes, bytes of the immediately following
# instruction).
CALL_SITES = {
    0x5F141A5: ("e8e6fdffff", "488b7b08"),
    0x5F141B4: ("e847feffff", "4889df"),
    0x5F141BE: ("e88df2ffff", "b801000000"),
    0x5E892A8: ("e8d3ae0800", "84c0"),
}
CALL_TARGETS = (0x5F13F90, 0x5F14000, 0x5F13450, 0x5F14180)
# Tail jumps: (address, jump bytes, target).
TAIL_SITES = {
    0x5F13FE4: ("e9b7feffff", 0x5F13EA0),
    0x5F13FF0: ("e97dffffff", 0x5F13F72),
}
WINDOWS = [
    ("0x5f14180", "0x5f141fa", "function_0x5f14180.txt"),
    ("0x5f13f90", "0x5f13ff5", "function_0x5f13f90.txt"),
    ("0x5f13450", "0x5f13479", "function_0x5f13450.txt"),
    ("0x5f13f72", "0x5f13f87", "function_0x5f13f72.txt"),
]
EXPECTED_CENSUS = {
    "0x5f14180": {"direct_calls": ["0x5e892a8"],
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
}
EXPECTED_FRAMES = [
    "00359364 0000000000000030 00359368 FDE cie=00000000 pc=0000000005f14180..0000000005f141fa",
    "00745f7c 0000000000000038 00745f80 FDE cie=0000730230 pc=0000000005f13f90..0000000005f13ff5",
    "003591a8 0000000000000018 003591ac FDE cie=00000000 pc=0000000005f13450..0000000005f13479",
    "No FDE covers 0x5f13f72..0x5f13f87; it is the landing-pad target of 0x5f13f90 (LSDA), reached by the jmp at 0x5f13ff0.",
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
        [sys.executable, "tests/test_drain_driver_115.py"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0 or "ALL TESTS PASSED" not in proc.stdout:
        return fail("model tests failed: %s%s"
                    % (proc.stdout, proc.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
