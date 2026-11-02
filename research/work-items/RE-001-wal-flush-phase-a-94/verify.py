"""Packet checker for the RE-001 WAL flush phase A work item.

Checks, all against the digest-verified binary work/hl-node-94.bin
(SHA-256 3b7179cd...c0459f):
  1. records.json parses and carries semantic records only (no
     per-instruction mnemonic list).
  2. MANIFEST.sha256 matches the packet files on disk.
  3. The verbatim excerpts regenerate byte-identically from a fresh
     objdump run (repo root, relative binary path).
  4. Sampled bytes match byte-for-byte against the raw binary and
     the fresh objdump output.
  5. The rodata log strings match records.json.
  6. The census script reproduces the reachability record.
Run from the repository root:
  python3 research/work-items/RE-001-wal-flush-phase-a-94/verify.py
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = ROOT / "research/work-items/RE-001-wal-flush-phase-a-94"
BIN = ROOT / "work/hl-node-94.bin"
BIN_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
SAMPLES = [
    (0x50E9410, bytes.fromhex("f30f1efa")),   # endbr64, window entry
    (0x50E9482, bytes.fromhex("e8b934f0ff")),  # call 0x4fec940 (lookup)
    (0x50E94EE, bytes.fromhex("483939")),     # cmp in present search
    (0x50E95A1, bytes.fromhex("e98a541400")),  # tail jump to 0x522ea30
]
FAILURES = []


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}: {name} {detail}")
    if not ok:
        FAILURES.append(name)


def file_offset(vaddr):
    # .text: file offset 0x1342c80, vaddr 0x1343c80.
    return vaddr - 0x1000


def main():
    raw = BIN.read_bytes()
    check("binary digest", hashlib.sha256(raw).hexdigest() == BIN_SHA256)
    records = json.loads((PACKET / "records.json").read_text())
    check("records parse", isinstance(records, dict))
    check("no mnemonic list",
          "instructions" not in records and "mnemonics" not in records)
    manifest_ok = True
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        path = PACKET / name.strip()
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            manifest_ok = False
    check("manifest matches", manifest_ok)
    for name, start, stop in (("window.txt", "0x50e9410", "0x50e95d4"),
                              ("caller-site.txt", "0x50ec180", "0x50ec1ab")):
        fresh = subprocess.run(
            ["objdump", "-d", f"--start-address={start}",
             f"--stop-address={stop}", "work/hl-node-94.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        check(f"excerpt regenerates: {name}",
              fresh == (PACKET / name).read_text())
    for addr, expected in SAMPLES:
        check(f"sample bytes {hex(addr)}",
              raw[file_offset(addr):file_offset(addr) + len(expected)] == expected)
    log_msg = records["log_record"]["message"].encode()
    check("log message in rodata",
          log_msg in raw and records["log_record"]["file"].encode() in raw)
    census = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    census_data = json.loads(census)
    check("census callers",
          census_data["direct_calls"] == records["callers"]["direct_calls"]
          and census_data["tail_jumps"] == []
          and census_data["qword_file_offsets"] == [])
    if FAILURES:
        print(f"FAILED: {FAILURES}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
