"""Packet checker for the RE-001 WAL replay gate work item.

Checks, all against the digest-verified binary work/hl-node-94.bin
(SHA-256 3b7179cd...c0459f):
  1. records.json parses and carries semantic records only (no
     per-instruction mnemonic list).
  2. MANIFEST.sha256 matches the packet files on disk.
  3. The verbatim excerpts regenerate byte-identically from a fresh
     objdump run (repo root, relative binary path).
  4. Sampled bytes match byte-for-byte against the raw binary and
     the fresh objdump output.
  5. The rodata report strings and the vtable relocation slots match
     records.json.
  6. The census script reproduces the reachability record.
Run from the repository root:
  python3 research/work-items/RE-001-wal-replay-gate-94/verify.py
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = ROOT / "research/work-items/RE-001-wal-replay-gate-94"
BIN = ROOT / "work/hl-node-94.bin"
BIN_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
# (address, expected bytes) sampled from the raw disassembly excerpts.
SAMPLES = [
    (0x4FA87A0, bytes.fromhex("f30f1efa")),   # endbr64, window entry
    (0x4FA8835, bytes.fromhex("e806684800")),  # call 0x542f040 (decision 3)
    (0x4FA886B, bytes.fromhex("4c39e0")),     # cmp %r12,%rax (gate)
    (0x4FA88CF, bytes.fromhex("e85c5f2600")),  # call 0x520e830 (replay)
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
        digest, name = line.split("  ", 1)
        actual = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if actual != digest:
            manifest_ok = False
            print(f"  manifest mismatch: {name}")
    check("manifest", manifest_ok)
    for name, start, stop in [("window.txt", "0x4fa87a0", "0x4fa88de"),
                              ("builder.txt", "0x542f040", "0x542f137")]:
        fresh = subprocess.run(
            ["objdump", "-d", f"--start-address={start}",
             f"--stop-address={stop}", "work/hl-node-94.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        check(f"excerpt regenerates: {name}",
              fresh == (PACKET / name).read_text())
    for addr, expected in SAMPLES:
        actual = raw[file_offset(addr):file_offset(addr) + len(expected)]
        check(f"sample {hex(addr)}", actual == expected,
              f"got {actual.hex()}")
        # the call targets decode from the rel32 as a cross-check
        if expected[0] == 0xE8:
            rel = struct.unpack_from("<i", expected, 1)[0]
            check(f"call target {hex(addr)}", addr + 5 + rel in
                  (0x542F040, 0x520E830), f"-> {hex(addr + 5 + rel)}")
    flag_msg = records["phases_in_order"][1]["message"]
    seq_msg = records["phases_in_order"][2]["report"]["message"]
    check("flag message bytes",
          raw[0x7E56D0:0x7E56D0 + 0x50].decode() == flag_msg["text"]
          and len(flag_msg["text"]) == flag_msg["length"] == 0x50)
    check("sequence message bytes",
          raw[0x7D86C8:0x7D86C8 + 0x2C].decode() == seq_msg["text"]
          and len(seq_msg["text"]) == seq_msg["length"] == 0x2C)
    slots = []
    for i in range(0x1D4E10 // 24):
        off, info, add = struct.unpack_from("<QQq", raw, 0x6BC0 + i * 24)
        if (info & 0xFFFFFFFF) == 8 and add == 0x4FA87A0:
            slots.append(off)
    expected_slots = sorted(int(s["slot_address"], 16)
                            for s in records["reachability"]["vtable_slots"])
    check("vtable slots", sorted(slots) == expected_slots,
          f"got {[hex(s) for s in sorted(slots)]}")
    census = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        cwd=ROOT, capture_output=True, text=True)
    check("census reproduces", census.returncode == 0
          and "CENSUS OK" in census.stdout, census.stderr.strip()[-200:])
    if FAILURES:
        print(f"FAILURES: {FAILURES}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
