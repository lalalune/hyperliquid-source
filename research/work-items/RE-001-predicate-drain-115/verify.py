"""Verification for the RE-001-predicate-drain-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including three extra
gate instructions picked at random), the FDE records, the census, the
call-site and tail-jump raw bytes, and the model tests. Exits nonzero
on the first failure and prints ALL CHECKS PASSED only when every
check passes.

Run from the repository root:
  python3 research/work-items/RE-001-predicate-drain-115/verify.py
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
    0x5F14000: "f30f1efa",        # endbr64 (drain entry)
    0x5F14018: "4889fb",          # mov %rdi,%rbx (object)
    0x5F1401B: "4883ec18",        # sub $0x18,%rsp
    0x5F14030: "4c397b18",        # cmp %r15,0x18(%rbx) (empty test)
    0x5F14036: "4c8b7320",        # mov 0x20(%rbx),%r14 (last node)
    0x5F1403E: "48836b2801",      # subq $0x1,0x28(%rbx) (size)
    0x5F14046: "e855d04d00",      # call _M_unhook@plt
    0x5F14056: "e825cd4d00",      # call _ZdlPvm@plt (delete, 0x18)
    0x5F14066: "e895fdffff",      # call transfer 0x5f13e00
    0x5F14071: "e8caf1ffff",      # call predicate 0x5f13240
    0x5F1407C: "4883c418",        # add $0x18,%rsp (exit)
    0x5F1408D: "c3",              # ret (drain)
    0x5F13E00: "f30f1efa",        # endbr64 (transfer entry)
    0x5F13E0A: "8b4270",          # mov 0x70(%rdx),%eax (refcount)
    0x5F13E15: "894270",          # mov %eax,0x70(%rdx) (store)
    0x5F13E28: "488b06",          # mov (%rsi),%rax (count)
    0x5F13E37: "488b5648",        # mov 0x48(%rsi),%rdx (inline buf)
    0x5F13E3F: "48890e",          # mov %rcx,(%rsi) (count+1)
    0x5F13E49: "e882a4ffff",      # call aggregate 0x5f0e2d0
    0x5F13E55: "482910",          # sub %rdx,(%rax) (subtract)
    0x5F13E60: "488b4658",        # mov 0x58(%rsi),%rax (vector end)
    0x5F13E8C: "e8bfd0e7ff",      # call grow helper 0x5d90f50
    0x5F13E5E: "c3",              # ret (transfer)
}
GATE_SAMPLES = {
    0x5F1403A: "4d8b6e10",        # mov 0x10(%r14),%r13 (payload)
    0x5F13E42: "48891cc2",        # mov %rbx,(%rdx,%rax,8) (inline store)
    0x5F1405B: "488b742408",      # mov 0x8(%rsp),%rsi (collection)
}
# Call sites: (address, call bytes, bytes of the immediately following
# instruction).
CALL_SITES = {
    0x5F141B4: ("e847feffff", "4889df"),
    0x5F13EDA: ("e821ffffff", "488b6d00"),
    0x5F13F02: ("e8f9feffff", "488b6d00"),
    0x5F14066: ("e895fdffff", "4c89e6"),
}
CALL_TARGETS = (0x5F14000, 0x5F13E00)
# Tail jumps: (address, jump bytes, target).
TAIL_SITES = {
    0x5F140B3: ("e948ffffff", 0x5F14000),
    0x5F14327: ("e9d4fcffff", 0x5F14000),
    0x5F1435F: ("e99cfaffff", 0x5F13E00),
}
WINDOWS = [
    ("0x5f14000", "0x5f1408e", "function_0x5f14000.txt"),
    ("0x5f13e00", "0x5f13e93", "function_0x5f13e00.txt"),
]
EXPECTED_CENSUS = {
    "0x5f14000": {"direct_calls": ["0x5f141b4"],
                  "tail_jumps": ["0x5f140b3", "0x5f14327"],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
    "0x5f13e00": {"direct_calls": ["0x5f13eda", "0x5f13f02",
                                   "0x5f14066"],
                  "tail_jumps": ["0x5f1435f"],
                  "qword_hits": [], "relative_addend_hits": [],
                  "qword_hits_whole_file": []},
}
EXPECTED_FRAMES = [
    "003592c0 0000000000000044 003592c4 FDE cie=00000000 pc=0000000005f14000..0000000005f1408e",
    "0035924c 0000000000000034 00359250 FDE cie=00000000 pc=0000000005f13e00..0000000005f13e93",
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
        [sys.executable, "tests/test_predicate_drain_115.py"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0 or "ALL TESTS PASSED" not in proc.stdout:
        return fail("model tests failed: %s%s"
                    % (proc.stdout, proc.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
