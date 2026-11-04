#!/usr/bin/env python3
"""Independent checker for this work item. Run from the repository root:

    python3 research/work-items/RE-001-chain-walk-getters-115/verify.py

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
    "head_0x5eee5b0.objdump": (0x5EEE5B0, 0x5EEE5C3),
    "getter70_0x5eee5d0.objdump": (0x5EEE5D0, 0x5EEE654),
    "getter78_0x5eee660.objdump": (0x5EEE660, 0x5EEE6E4),
    "getter98_0x5eee6f0.objdump": (0x5EEE6F0, 0x5EEE784),
}
# Gate instructions: (address, expected raw bytes) checked against fresh objdump AND raw binary.
GATE = {
    0x5EEE5B4: bytes.fromhex("488b8788070000"),  # mov 0x788(%rdi),%rax in the head
    0x5EEE5D8: bytes.fromhex("e8d3ffffff"),  # call head in getter slot 0x70
    0x5EEE6BB: bytes.fromhex("ff5078"),  # call *0x78(%rax) in getter slot 0x78
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
    for label in ("head", "getter70", "getter78", "getter98"):
        check(f"census {label} calls", census[label]["direct_calls"] == records["census"][label]["direct_calls"])
        check(f"census {label} jumps", census[label]["tail_jumps"] == records["census"][label]["tail_jumps"])
    out = subprocess.run([sys.executable, str(ROOT / "tests" / "test_chain_walk_getters_115.py")],
                         capture_output=True, text=True)
    check("model tests", out.returncode == 0 and "tests passed" in out.stdout)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
