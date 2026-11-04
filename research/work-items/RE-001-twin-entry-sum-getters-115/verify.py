#!/usr/bin/env python3
"""Independent checker for this work item. Run from the repository root:

    python3 research/work-items/RE-001-twin-entry-sum-getters-115/verify.py

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
    "getter_a_0x5eec290.objdump": (0x5EEC290, 0x5EEC2F3),
    "getter_b_0x5eec300.objdump": (0x5EEC300, 0x5EEC368),
    "leaf_0x5dd3570.objdump": (0x5DD3570, 0x5DD357D),
}
# Gate instructions: (address, expected raw bytes) checked against fresh objdump AND raw binary.
GATE = {
    0x5EEC2D2: bytes.fromhex("e89972eeff"),      # call leaf in getter A
    0x5EEC347: bytes.fromhex("488b43f0"),        # mov -0x10(%rbx),%rax in getter B (the discard)
    0x5DD3578: bytes.fromhex("4883c03e"),        # add $0x3e,%rax in the leaf
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
    for label, key in (("getter_a", "getter_a"), ("getter_b", "getter_b"), ("leaf", "leaf")):
        check(f"census {label} calls", census[key]["direct_calls"] == records["census"][label]["direct_calls"])
        check(f"census {label} jumps", census[key]["tail_jumps"] == records["census"][label]["tail_jumps"])
    out = subprocess.run([sys.executable, str(ROOT / "tests" / "test_twin_entry_sum_getters_115.py")],
                         capture_output=True, text=True)
    check("model tests", out.returncode == 0 and "tests passed" in out.stdout)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
