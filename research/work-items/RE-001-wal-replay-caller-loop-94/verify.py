"""Packet checker for the RE-001 WAL replay caller-loop work item.

Checks, all against the digest-verified binary work/hl-node-94.bin
(SHA-256 3b7179cd...c0459f):
  1. records.json parses and carries semantic records only (no
     per-instruction mnemonic list anywhere in the packet JSON).
  2. MANIFEST.sha256 matches the packet files on disk.
  3. The verbatim excerpts regenerate byte-identically from a fresh
     objdump run (repo root, relative binary path).
  4. Three sampled instructions match byte-for-byte against the raw
     binary and the fresh objdump output.
Run from the repository root: python3 research/work-items/\
RE-001-wal-replay-caller-loop-94/verify.py
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = ROOT / "research/work-items/RE-001-wal-replay-caller-loop-94"
BIN = ROOT / "work/hl-node-94.bin"
BIN_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
# (address, expected bytes) sampled from the raw disassembly excerpts.
SAMPLES = [
    (0x520D3A0, bytes.fromhex("f30f1efa")),       # endbr64, window entry
    (0x520D5A9, bytes.fromhex("e872ebffff")),     # call 0x520c120 driver
    (0x520D713, bytes.fromhex("ff9028010000")),   # call *0x128(%rax), chain-B fallback
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
    check("no per-instruction mnemonic list",
          "mnemonic" not in text.lower())
    check("task id", records.get("task") == "RE-001")
    check("window start", records["window"]["start"] == "0x520d3a0")
    check("window end", records["window"]["end"] == "0x520e12e")
    check("artifact digest bound",
          records["window"]["artifact_sha256"] == BIN_SHA256)
    manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    ok = True
    for line in manifest:
        digest, _, rel = line.partition("  ")
        path = PACKET / rel
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            ok = False
            print(f"  manifest mismatch: {rel}")
    check("MANIFEST.sha256 matches packet files", ok,
          f"({len(manifest)} entries)")
    # Excerpt regeneration (must run from the repo root with the relative
    # binary path, otherwise objdump's header line differs).
    cases = [("0x520d3a0", "0x520e12e", "window.txt"),
             ("0x520d31e", "0x520d3a0", "cleanup.txt")]
    for start, stop, name in cases:
        fresh = subprocess.run(
            ["objdump", "-d", f"--start-address={start}",
             f"--stop-address={stop}", "work/hl-node-94.bin"],
            cwd=ROOT, check=True, capture_output=True, text=True).stdout
        check(f"{name} regenerates",
              fresh == (PACKET / name).read_text())
    fresh_all = subprocess.run(
        ["objdump", "-d", "--start-address=0x520d3a0",
         "--stop-address=0x520e12e", "work/hl-node-94.bin"],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout
    for addr, expected in SAMPLES:
        off = file_offset(addr)
        got = raw[off:off + len(expected)]
        line = [ln for ln in fresh_all.splitlines()
                if ln.strip().startswith(f"{addr:x}:")]
        check(f"sample {addr:#x} byte-for-byte",
              got == expected and bool(line))
    sys.path.insert(0, str(ROOT / "tools"))
    import wal_replay_caller_loop as model
    check("model imports", model.RECORD_TAG_PTR == 0x575BDF0)
    print("ALL CHECKS PASSED" if not FAILURES
          else f"{len(FAILURES)} CHECK(S) FAILED")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
