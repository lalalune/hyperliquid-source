#!/usr/bin/env python3
"""Independent checker for this work item. Run from the repository root:

    python3 research/work-items/RE-001-group-stamp-115/verify.py

Checks: artifact digest, packet manifest, verbatim excerpt regeneration from
a fresh objdump run, three gate instructions byte-for-byte against both a
fresh objdump run and the raw binary, frame extents, census reproduction,
and the model tests. Prints ALL CHECKS PASSED or fails loudly.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
BIN = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WINDOWS = {
    "predicate_0x5f6c4e0.objdump": (0x5F6C4E0, 0x5F6C53C),
    "maximum_0x5f6c540.objdump": (0x5F6C540, 0x5F6C59D),
    "caller_0x5f6c5a0.objdump": (0x5F6C5A0, 0x5F6C734),
}
# Gate instructions: (address, expected raw bytes) checked against fresh objdump AND raw binary.
GATE = {
    0x5F6C519: bytes.fromhex("488b10"),  # mov (%rax),%rdx, predicate element load
    0x5F6C573: bytes.fromhex("488b89d0000000"),  # mov 0xd0(%rcx),%rcx, maximum field load
    0x5F6C62B: bytes.fromhex("f0480fc13b"),  # lock xadd %rdi,(%rbx), stamp value claim
}


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        raise SystemExit(1)


def main():
    data = BIN.read_bytes()
    check("artifact digest", hashlib.sha256(data).hexdigest() == DIGEST)
    manifest = {}
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        if line.strip():
            digest, path = line.split(None, 1)
            manifest[path.strip()] = digest
    for path, digest in manifest.items():
        target = PACKET / path if not path.startswith("tools/") and not path.startswith("tests/") else ROOT / path
        check(f"manifest {path}", hashlib.sha256(target.read_bytes()).hexdigest() == digest)
    for name, (start, stop) in WINDOWS.items():
        fresh = subprocess.check_output(
            ["objdump", "-d", f"--start-address={hex(start)}",
             f"--stop-address={hex(stop)}", str(BIN)], text=True)
        check(f"excerpt verbatim {name}", fresh == (PACKET / name).read_text())
    for addr, raw in GATE.items():
        # Raw binary: .text file offset = vaddr - 0x1000.
        check(f"gate raw bytes {hex(addr)}", data[addr - 0x1000:addr - 0x1000 + len(raw)] == raw)
        fresh = subprocess.check_output(
            ["objdump", "-d", f"--start-address={hex(addr)}",
             f"--stop-address={hex(addr + 16)}", str(BIN)], text=True)
        line = [ln for ln in fresh.splitlines() if ln.strip().startswith(f"{addr:x}:")]
        check(f"gate objdump {hex(addr)}",
              bool(line) and line[0].split("\t")[1].strip().replace(" ", "") == raw.hex())
    records = json.loads((PACKET / "records.json").read_text())
    check("records windows", set(records["windows"]) == {"predicate", "maximum", "caller"})
    census_out = subprocess.check_output(
        [sys.executable, str(PACKET / "census.py")], text=True, cwd=ROOT)
    census = json.loads(census_out)
    check("census predicate", census["predicate"]["direct_calls"] == ["0x5f52d1a", "0x5f6c5cd", "0x5f6c704"])
    check("census maximum", census["maximum"]["direct_calls"] == ["0x5f6c71c"])
    check("census caller", census["caller"]["direct_calls"] == ["0x5eeaa6f"]
          and census["caller"]["tail_jumps"] == ["0x5d8ce6f"])
    tests = subprocess.check_output(
        [sys.executable, str(ROOT / "tests" / "test_group_stamp_115.py")], text=True)
    check("model tests", "tests passed" in tests)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
