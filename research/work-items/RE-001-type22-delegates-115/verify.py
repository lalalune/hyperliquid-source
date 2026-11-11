#!/usr/bin/env python3
"""Verify the RE-001 type22-delegates-115 evidence packet (node #115).

Checks:
1. The node #115 binary digest matches provenance/artifacts.json.
2. MANIFEST.sha256 covers every packet file (except itself).
3. Every objdump excerpt regenerates byte-for-byte from a fresh objdump run.
4. Every FDE in frames.txt matches readelf --debug-dump=frames.
5. Every literal in literals.tsv matches the binary bytes at its address
   (rodata vaddr == file offset; .bss string is enumerated, not read).
6. The caller census in callers.tsv reproduces from a fresh byte scan.
7. The vtable slots in vtables.tsv reproduce from readelf -rW.
8. The semantic records in records.json are internally consistent
   (no per-instruction mnemonic list present).
9. The model tests in tests/test_type22_delegates_115.py pass.

Exit 0 prints ALL CHECKS PASSED; any failure exits non-zero.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
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
        out = export_excerpts.excerpt(name, start, end)
        if (HERE / name).read_text() != out:
            ok = False
            print(f"  excerpt drift: {name}")
    check("excerpts byte-identical", ok)

    # 4. FDE identities.
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    fde_ranges = set()
    for m in re.finditer(r"pc=0+([0-9a-f]+)\.\.0+([0-9a-f]+)", frames):
        fde_ranges.add((int(m.group(1), 16), int(m.group(2), 16)))
    pinned = [(0x609A740, 0x609B6F3), (0x60971C0, 0x609755B),
              (0x609DE80, 0x609E29E), (0x5D32A30, 0x5D32A51),
              (0x61D1390, 0x61D13DB), (0x61D13E0, 0x61D1437),
              (0x60986B0, 0x6098A9C)]
    check("FDE identities", all(p in fde_ranges for p in pinned),
          f"missing: {[hex(a) for a, _ in pinned if (a, _) not in fde_ranges]}")

    # 5. Literals.
    data = BIN.read_bytes()
    ok = True
    for line in (HERE / "literals.tsv").read_text().splitlines()[1:]:
        if not line.strip():
            continue
        addr_s, text, length_s, _ = line.split("\t", 3)
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
    check("caller census reproduces", ok)

    recorded_leas = [int(line.split("\t")[1], 16)
                     for line in (HERE / "bss-string-lea.tsv").read_text().splitlines()[1:]
                     if line]
    check("BSS lea census reproduces", census.lea_sites(data, census.BSS_STRING) == recorded_leas)

    # 7. Vtable slots reproduce.
    relocs = {}
    out = subprocess.run(["readelf", "-rW", str(BIN)],
                         capture_output=True, text=True, check=True).stdout
    for m in re.finditer(r"^([0-9a-f]{16})\s+[0-9a-f]{16}\s+R_X86_64_RELATIVE\s+([0-9a-f]+)",
                         out, re.M):
        relocs[int(m.group(1), 16)] = int(m.group(2), 16)
    ok = True
    for line in (HERE / "vtables.tsv").read_text().splitlines()[1:]:
        if not line.strip():
            continue
        vt, slot_s, _off, tgt_s, _note = line.split("\t")
        slot = int(slot_s)
        want = relocs.get(int(vt, 16) + 8 * slot)
        got = None if tgt_s in ("None", "") else int(tgt_s, 16)
        if got != want:
            ok = False
            print(f"  vtable drift {vt} slot {slot}: {got} != {want}")
    check("vtable slots reproduce", ok)

    # 8. Semantic records only.
    records = json.loads((HERE / "records.json").read_text())
    import gen_records
    check("semantic generator reproduces records", records == gen_records.RECORDS)
    blob = json.dumps(records)
    check("records are semantic only",
          "mnemonic" not in blob and "instruction" not in blob.lower()
          or "instruction-level" in blob)
    check("records bound to artifact",
          records.get("artifact_sha256") == ARTIFACT)

    # 9. Model tests.
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "-q",
         "tests/test_type22_delegates_115.py"],
        cwd=ROOT, capture_output=True, text=True)
    check("model tests pass", res.returncode == 0,
          res.stdout.strip().splitlines()[-1] if res.stdout.strip() else res.stderr[-500:])

    # Spot bytes: fixed instruction bytes at pinned sites.
    spots = [
        (0x609a907, bytes.fromhex("0f857c020000")),
        (0x609aa1b, bytes.fromhex("84db0f8466010000")),
        (0x609aab4, bytes.fromhex("4d85ed")),
        (0x609b09f, bytes.fromhex("0f840bfdffff")),
        (0x61d1410, bytes.fromhex("85d2751c")),
        (0x61d142b, bytes.fromhex("85db0f94c0")),
        (0x609A7AA, b"\xf6\xc4\x08"),            # test $0x8,%ah (flags 0x800 gate)
        (0x609A940, b"\xff\x50\x78"),            # call *0x78(%rax) (GetId)
        (0x609A8E2, b"\xe8"),                    # call 0x61d1390 (ends_with)
        (0x60971EE, b"\xff\x50\x60"),            # call *0x60(%rax) (slot 12)
        (0x609DEEA, b"\xff\x50\x78"),            # call *0x78(%rax) (GetId in slot 12)
        (0x609DFBC, b"\x48\x8d\x35"),            # lea 0x441b15 ("id")
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
