"""Verification for the RE-001-guard-exchange-c700-115 packet.

Checks, in order: the work binary digest against provenance, the packet
manifest, verbatim excerpt regeneration, sampled instruction bytes
against a fresh objdump run and the raw binary (including four extra
gate instructions picked at random), the FDE records, the census, the
call-site and tail-jump raw bytes, and the model tests. Exits nonzero
on the first failure and prints ALL CHECKS PASSED only when every
check passes.

Run from the repository root:
  python3 research/work-items/RE-001-guard-exchange-c700-115/verify.py
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
    0x607C700: "f30f1efa",        # endbr64 (acquire entry)
    0x607C70A: "e8a1fcffff",      # call core 0x607c3b0
    0x607C70F: "8903",            # mov %eax,(%rbx) (store to slot)
    0x607C712: "c3",              # ret (acquire)
    0x607C720: "f30f1efa",        # endbr64 (release entry)
    0x607C728: "8b3f",            # mov (%rdi),%edi (load slot)
    0x607C72A: "e881fcffff",      # call core 0x607c3b0
    0x607C733: "c3",              # ret (release)
    0x607C3B0: "f30f1efa",        # endbr64 (core entry)
    0x607C3B7: "64488b042500000000",  # mov %fs:0x0,%rax (thread pointer)
    0x607C3C0: "488d80d0ffffff",  # lea -0x30(%rax),%rax (gate slot)
    0x607C3CD: "7411",            # je gate-closed return
    0x607C3E0: "31c0",            # xor %eax,%eax (closed return 0)
    0x6078810: "f30f1efa",        # endbr64 (exchange entry)
    0x6078817: "e834feffff",      # call getter 0x6078650
    0x6078821: "7405",            # je no-object return
    0x6078823: "875830",          # xchg %ebx,0x30(%rax)
    0x6078650: "f30f1efa",        # endbr64 (getter entry)
    0x6078658: "64488b042500000000",  # mov %fs:0x0,%rax (thread pointer)
    0x6078661: "488d80c8ffffff",  # lea -0x38(%rax),%rax (object slot)
    0x6078675: "480f44c2",        # cmove %rdx,%rax (flag gate)
}
GATE_SAMPLES = {
    0x607C3C7: "488b38",          # mov (%rax),%rdi (load gate qword)
    0x607C3CA: "4885ff",          # test %rdi,%rdi (gate zero test)
    0x6078668: "488b00",          # mov (%rax),%rax (load object qword)
    0x6078672: "803800",          # cmpb $0x0,(%rax) (flag byte test)
}
# Call sites: (address, call bytes, bytes of the immediately following
# instruction).
CALL_SITES = {
    0x607C70A: ("e8a1fcffff", "8903"),
    0x607C72A: ("e881fcffff", "4883c408"),
    0x6078817: ("e834feffff", "31f6"),
    0x5F13343: ("e8b8931600", "4d8b6558"),
    0x5F133A7: ("e874931600", "488b442408"),
    0x5F132E9: ("e832941600", "488b442408"),
    0x5E00207: ("e8f4c42700", "488b85e0fbffff"),
}
CALL_TARGETS = (0x607C3B0, 0x6078650, 0x607C700, 0x607C720)
# Tail jumps: (address, jump bytes, target).
TAIL_SITES = {
    0x607C3D2: ("e939c4ffff", 0x6078810),
}
WINDOWS = [
    ("0x607c700", "0x607c713", "function_0x607c700.txt"),
    ("0x607c720", "0x607c734", "function_0x607c720.txt"),
    ("0x607c3b0", "0x607c3e4", "function_0x607c3b0.txt"),
    ("0x6078810", "0x607882c", "function_0x6078810.txt"),
    ("0x6078650", "0x607867e", "function_0x6078650.txt"),
]
EXPECTED_CENSUS = {
    "0x6078650": {
        "direct_calls": [
            "0x607868f",
            "0x60786b8",
            "0x60786d8",
            "0x607871f",
            "0x6078748",
            "0x607876f",
            "0x60787b8",
            "0x6078817"
        ],
        "qword_hits": [],
        "qword_hits_whole_file": [],
        "relative_addend_hits": [],
        "tail_jumps": []
    },
    "0x6078810": {
        "direct_calls": [],
        "qword_hits": [],
        "qword_hits_whole_file": [],
        "relative_addend_hits": [],
        "tail_jumps": [
            "0x607c3d2"
        ]
    },
    "0x607c3b0": {
        "direct_calls": [
            "0x607c70a",
            "0x607c72a"
        ],
        "qword_hits": [],
        "qword_hits_whole_file": [],
        "relative_addend_hits": [],
        "tail_jumps": []
    },
    "0x607c700": {
        "direct_calls": [
            "0x5e00207",
            "0x5e03e20",
            "0x5e08132",
            "0x5e0b26d",
            "0x5e10a20",
            "0x5ed2487",
            "0x5ed5e5d",
            "0x5f13343",
            "0x5f148e1",
            "0x5f14f28",
            "0x5f16a28"
        ],
        "qword_hits": [],
        "qword_hits_whole_file": [],
        "relative_addend_hits": [],
        "tail_jumps": []
    },
    "0x607c720": {
        "direct_calls": [
            "0x5dfef6f",
            "0x5dffd38",
            "0x5e03d3c",
            "0x5e04ce2",
            "0x5e07fe7",
            "0x5e08aed",
            "0x5e0b1dc",
            "0x5e0c1a6",
            "0x5e1095d",
            "0x5e10c6b",
            "0x5ed22a6",
            "0x5ed3ee2",
            "0x5ed5d81",
            "0x5ed68e8",
            "0x5f132e9",
            "0x5f133a7",
            "0x5f14877",
            "0x5f149c2",
            "0x5f14df5",
            "0x5f14f72",
            "0x5f168ce",
            "0x5f1744f"
        ],
        "qword_hits": [],
        "qword_hits_whole_file": [],
        "relative_addend_hits": [],
        "tail_jumps": []
    }
}
EXPECTED_FRAMES = [
    "pc=000000000607c700..000000000607c713",
    "pc=000000000607c720..000000000607c734",
    "pc=000000000607c3b0..000000000607c3e4",
    "pc=0000000006078810..000000000607882c",
    "pc=0000000006078650..000000000607867e",
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
         str(REPO_ROOT / "tests" / "test_guard_exchange_c700_115.py")],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if model.returncode != 0 or "ALL TESTS PASSED" not in model.stdout:
        return fail("model tests failed: %s%s"
                    % (model.stdout, model.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
