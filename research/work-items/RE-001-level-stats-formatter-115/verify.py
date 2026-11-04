#!/usr/bin/env python3
"""Independent checker for this work item. Run from the repository root:

    python3 research/work-items/RE-001-level-stats-formatter-115/verify.py

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
    "getter_0x5eecbb0.objdump": (0x5EECBB0, 0x5EECD7E),
    "group_sum_0x5f6c300.objdump": (0x5F6C300, 0x5F6C31B),
    "leaf_0x5da4de0.objdump": (0x5DA4DE0, 0x5DA4E1E),
}
# Gate instructions: (address, expected raw bytes) checked against fresh objdump AND raw binary.
GATE = {
    0x5EECBEE: bytes.fromhex("488b8788070000"),  # mov 0x788(%rdi),%rax, member load in the getter
    0x5F6C304: bytes.fromhex("488b87980a0000"),  # mov 0xa98(%rdi),%rax, group base load in the group sum
    0x5DA4E04: bytes.fromhex("48034a10"),  # add 0x10(%rdx),%rcx, element field accumulation in the leaf
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
             f"--stop-address={hex(addr + len(raw))}", str(BIN)], text=True)
        check(f"gate in fresh objdump {hex(addr)}", " ".join(f"{b:02x}" for b in raw) in fresh.replace("\t", " "))
    records = json.loads((PACKET / "records.json").read_text())
    census = json.loads(subprocess.check_output(
        [sys.executable, str(PACKET / "census.py")], text=True))
    for label in ("getter", "group_sum", "leaf"):
        check(f"census {label} calls", census[label]["direct_calls"] == records["census"][label]["direct_calls"])
        check(f"census {label} jumps", census[label]["tail_jumps"] == records["census"][label]["tail_jumps"])
    out = subprocess.run([sys.executable, str(ROOT / "tests" / "test_level_stats_formatter_115.py")],
                         capture_output=True, text=True)
    check("model tests", out.returncode == 0 and "tests passed" in out.stdout)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
