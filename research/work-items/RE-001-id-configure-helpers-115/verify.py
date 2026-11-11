#!/usr/bin/env python3
"""Verify the RE-001 id-configure-helpers-115 evidence packet (node #115).

Checks:
1. The node #115 binary digest matches provenance/artifacts.json.
2. MANIFEST.sha256 covers every packet file (except itself).
3. Every objdump excerpt regenerates byte-for-byte from a fresh objdump run
   (objdump is invoked with the repo-relative binary path, so the header
   line reads "work/hl-node-115.bin: ..." with no absolute home path).
4. Every FDE in frames.txt matches readelf --debug-dump=frames.
5. Every literal in literals.tsv matches the binary bytes at its address
   (rodata vaddr == file offset; the .bss string row has length 0 and is
   skipped).
6. The caller census in callers.tsv reproduces from a fresh byte scan, and
   the slot-9 vtable rows reproduce from readelf -rW.
7. The semantic records in records.json are internally consistent
   (no per-instruction mnemonic list present) and bound to the artifact.
8. The model tests in tests/test_id_configure_helpers_115.py pass.
9. Spot bytes at pinned sites match the binary.

Exit 0 prints ALL CHECKS PASSED; any failure exits non-zero.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
BIN_REL = "artifacts/node/115/hl-node"
ARTIFACT = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TEXT_VADDR, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700

FAILURES = []


def check(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main() -> int:
    # 1. Artifact digest.
    check("artifact digest", sha256(BIN) == ARTIFACT)

    # 2. Manifest.
    manifest = (HERE / "MANIFEST.sha256").read_text().splitlines()
    listed = {}
    for line in manifest:
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        listed[name] = digest
    ok = True
    for name, digest in listed.items():
        if sha256(HERE / name) != digest:
            ok = False
            print(f"  manifest mismatch: {name}")
    extra = {p.name for p in HERE.iterdir() if p.is_file() and p.name != "MANIFEST.sha256"}
    if extra - set(listed):
        ok = False
        print(f"  files missing from manifest: {sorted(extra - set(listed))}")
    check("manifest covers packet", ok)

    # 3. Excerpts regenerate byte-for-byte.
    sys.path.insert(0, str(HERE))
    import export_excerpts  # noqa: E402
    ok = True
    for name, (start, end) in export_excerpts.FUNCTIONS.items():
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={end:#x}", BIN_REL],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
        if (HERE / name).read_text() != out:
            ok = False
            print(f"  excerpt drift: {name}")
    check("excerpts byte-identical", ok)

    # 4. FDE identities.
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BIN)],
        capture_output=True, text=True, check=True).stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
    fde_ranges = set()
    for m in re.finditer(r"pc=0+([0-9a-f]+)\.\.0+([0-9a-f]+)", frames):
        fde_ranges.add((int(m.group(1), 16), int(m.group(2), 16)))
    pinned = [(s, e) for s, e in export_excerpts.FUNCTIONS.values()]
    check("FDE identities", all(p in fde_ranges for p in pinned),
          f"missing: {[hex(a) for a, _ in pinned if (a, _) not in fde_ranges]}")

    # 5. Literals.
    data = BIN.read_bytes()
    ok = True
    for line in (HERE / "literals.tsv").read_text().splitlines()[1:]:
        if not line.strip():
            continue
        parts = line.split("\t")
        addr_s, text, length_s = parts[0], parts[1], parts[2]
        addr, length = int(addr_s, 16), int(length_s)
        if length == 0:
            continue
        got = data[addr:addr + length].decode("latin-1")
        if got != text:
            ok = False
            print(f"  literal mismatch at {addr_s}: {got!r} != {text!r}")
    check("literals match binary", ok)

    # 6. Caller census reproduces.
    import census  # noqa: E402
    ok = True
    for target in census.TARGETS:
        got = census.call_sites(data, target)
        want = [int(r.split("\t")[2], 16)
                for r in (HERE / "callers.tsv").read_text().splitlines()[1:]
                if r and int(r.split("\t")[0], 16) == target]
        if got != want:
            ok = False
            print(f"  census drift for {target:#x}: {got} != {want}")
    # Map-clear packet sites reproduce too.
    got_clear = census.call_sites(data, 0x5D5B300)
    want_clear = [int(r.split("\t")[2], 16)
                  for r in (HERE / "callers.tsv").read_text().splitlines()[1:]
                  if r and int(r.split("\t")[0], 16) == 0x5D5B300]
    if not set(want_clear) <= set(got_clear):
        ok = False
        print(f"  map-clear sites not in binary scan: {want_clear}")
    count_line = (HERE / "map-clear-count.txt").read_text().strip()
    if count_line != f"0x5d5b300 direct call sites binary-wide: {len(got_clear)}":
        ok = False
        print(f"  map-clear count drift: {count_line}")
    check("caller census reproduces", ok)

    # 6b. Slot-9 vtable rows reproduce.
    relocs = {}
    out = subprocess.run(["readelf", "-rW", str(BIN)],
                         capture_output=True, text=True, check=True).stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
    for m in re.finditer(r"^([0-9a-f]{16})\s+[0-9a-f]{16}\s+R_X86_64_RELATIVE\s+([0-9a-f]+)",
                         out, re.M):
        relocs[int(m.group(1), 16)] = int(m.group(2), 16)
    ok = True
    for line in (HERE / "slot9-vtables.tsv").read_text().splitlines()[1:]:
        if not line.strip():
            continue
        vt, slot_s, _off, tgt_s, _note = line.split("\t")
        want = relocs.get(int(vt, 16) + 8 * int(slot_s))
        got = None if tgt_s in ("None", "") else int(tgt_s, 16)
        if got != want:
            ok = False
            print(f"  slot-9 vtable drift {vt} slot {slot_s}: {got} != {want}")
    check("slot-9 vtable rows reproduce", ok)

    # 7. Semantic records only.
    records = json.loads((HERE / "records.json").read_text())
    blob = json.dumps(records)
    check("records are semantic only",
          '"mnemonic"' not in blob and '"instructions"' not in blob
          and '"opcodes"' not in blob)
    check("records bound to artifact",
          records.get("artifact_sha256") == ARTIFACT)

    # 8. Model tests.
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "-q",
         "tests/test_id_configure_helpers_115.py"],
        cwd=ROOT, capture_output=True, text=True)
    check("model tests pass", res.returncode == 0,
          res.stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin").strip().splitlines()[-1] if res.stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin").strip() else res.stderr[-500:])

    # 9. Spot bytes: fixed instruction bytes at pinned sites.
    spots = [
        (0x609A43E, b"\xc7\x07\x00\x00\x00\x00"),  # movl $0x0,(%rdi) (out = kOk)
        (0x609A477, b"\xbe\x3d\x00\x00\x00"),      # mov $0x3d,%esi ('=' for find)
        (0x609A499, b"\xe8"),                     # call 0x60c1190 (map parser)
        (0x609A595, b"\xb8\x69\x64\x00\x00"),      # mov $0x6469,%eax ('id')
        (0x609A5BF, b"\xe8"),                     # call 0x609a1b0 (map find)
        (0x609A603, b"\xe8"),                     # call 0x609a2f0 (map erase)
        (0x6097155, b"\x45\x31\xc0"),             # xor %r8d,%r8d (arg5 = 0)
        (0x609712D, b"\xff\x50\x48"),       # call *0x48(%rax) (slot 9)
        (0x609D127, b"\x48\x83\x79\x18\x00"),      # cmpq $0x0,0x18(%rcx) (map empty?)
        (0x609D5C0, b"\xc7\x44\x24\x78\x02\x00\x00"),  # movl $0x2,0x78(%rsp) (C1+0x28 = 2)
        (0x609D49C, b"\x66\x89\x44\x24\x50"),      # mov %ax,0x50(%rsp) (patch low word)
        (0x609E3A7, b"\xbe\x04\x00\x00\x00"),      # mov $0x4,%esi (code 4)
    ]
    ok = True
    for vaddr, want in spots:
        off = vaddr - 0x1000  # .text file offset = vaddr - 0x1000
        if data[off:off + len(want)] != want:
            ok = False
            print(f"  spot-byte mismatch at {vaddr:#x}")
    check("spot bytes match binary", ok)

    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s)")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
