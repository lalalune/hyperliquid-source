"""Packet checker for the RE-001 WAL replay orchestrator work item.

Checks, all against the digest-verified binary work/hl-node-94.bin
(SHA-256 3b7179cd...c0459f):
  1. records.json parses and carries semantic records only.
  2. MANIFEST.sha256 matches the packet files on disk.
  3. The verbatim excerpts regenerate byte-identically from a fresh
     objdump run (repo root, relative binary path).
  4. Three sampled instructions match byte-for-byte against the raw
     binary and the fresh objdump output.
  5. The census script reproduces the caller census.
Run from the repository root: python3 research/work-items/\\
RE-001-wal-replay-orchestrator-94/verify.py
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = ROOT / "research/work-items/RE-001-wal-replay-orchestrator-94"
BIN = ROOT / "work/hl-node-94.bin"
BIN_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
# (address, expected bytes) sampled from the raw disassembly excerpts.
SAMPLES = [
    (0x520E1B0, bytes.fromhex("f30f1efa")),       # endbr64, window entry
    (0x520E22C, bytes.fromhex("e86ff1ffff")),     # call 0x520d3a0, first replay
    (0x520E5A7, bytes.fromhex("e884040200")),     # call 0x522ea30, latest log
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
    check("binary digest",
          hashlib.sha256(raw).hexdigest() == BIN_SHA256)
    text = (PACKET / "records.json").read_text()
    records = json.loads(text)
    check("records.json parses", True)
    check("no per-instruction list in records.json",
          "mnemonic" not in text.lower()
          and "instruction" not in text.lower())
    check("task id", records.get("task") == "RE-001")
    check("window start", records["window"]["start"] == "0x520e1b0")
    check("window end", records["window"]["end"] == "0x520e7e3")
    check("artifact digest bound",
          records["window"]["artifact_sha256"] == BIN_SHA256)
    manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    ok = True
    for line in manifest:
        digest, name = line.split("  ", 1)
        actual = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if actual != digest:
            ok = False
            print(f"  manifest mismatch: {name}")
    check("MANIFEST.sha256 matches packet files", ok,
          f"({len(manifest)} files)")
    # Excerpt regeneration.
    excerpt_names = ["window.txt", "cleanup.txt", "known-18.txt",
                     "caller-sites.txt"]
    before = {n: hashlib.sha256((PACKET / n).read_bytes()).hexdigest()
              for n in excerpt_names}
    regen = subprocess.run(
        [sys.executable, str(PACKET / "export_excerpts.py")],
        cwd=ROOT, capture_output=True, text=True)
    check("export_excerpts.py runs", regen.returncode == 0, regen.stderr[-200:])
    after = {n: hashlib.sha256((PACKET / n).read_bytes()).hexdigest()
             for n in excerpt_names}
    check("excerpts regenerate identically", before == after)
    # Sampled instruction bytes.
    for addr, expected in SAMPLES:
        off = file_offset(addr)
        check(f"sample {hex(addr)} bytes",
              raw[off:off + len(expected)] == expected)
    obj = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(0x520E1B0)}",
         f"--stop-address={hex(0x520E7E3)}", "work/hl-node-94.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    check("window excerpt matches fresh objdump",
          obj == (PACKET / "window.txt").read_text())
    census = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        cwd=ROOT, capture_output=True, text=True)
    check("census reproduces callers",
          "0x502dfc9" in census.stdout
          and "0x520e8dc" in census.stdout
          and "qword refs: []" in census.stdout, census.stderr[-200:])
    print("ALL CHECKS PASSED" if not FAILURES
          else f"FAILURES: {FAILURES}")
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
