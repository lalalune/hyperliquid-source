#!/usr/bin/env python3
"""Self-checks for RE-001 parse-then-apply-wrapper-115.

Checks: artifact digest vs provenance/artifacts.json, MANIFEST.sha256,
excerpt regeneration byte-for-byte vs fresh objdump, FDE ranges,
raw-binary spot bytes for cited instructions, caller-census
reproduction, semantic-only records, and the model tests.

Run from the repo root:
    python3 research/work-items/RE-001-parse-then-apply-wrapper-115/verify.py
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
BIN = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8e"
TEXT_VA, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700
VA_TO_OFF = 0x1000  # .text vaddr - file offset

FUNCS = {
    "fn-60c1bb0-wrapper.objdump.txt": (0x60C1BB0, 0x60C1CC5),
    "fn-60c1190-map-parse.objdump.txt": (0x60C1190, 0x60C1887),
    "fn-60c18b0-apply-loop.objdump.txt": (0x60C18B0, 0x60C1B7C),
    "fn-60c0e90-overflow-insert.objdump.txt": (0x60C0E90, 0x60C112F),
    "fn-5e317a0-caller-a.objdump.txt": (0x5E317A0, 0x5E3190A),
    "fn-5e34160-caller-b.objdump.txt": (0x5E34160, 0x5E347C1),
    "fn-60c1d50-caller-c.objdump.txt": (0x60C1D50, 0x60C26D5),
}

SPOTS = {
    0x60C1BB0: bytes.fromhex("f30f1efa"),        # wrapper endbr64
    0x60C1C2E: bytes.fromhex("e85df5ffff"),      # parse call 0x60c1190
    0x60C1C33: bytes.fromhex("803c2400"),        # cmpb $0x0,(%rsp) parse-Status test
    0x60C1C53: bytes.fromhex("e8b844c7ff"),      # map-dtor call 0x5d36110
    0x60C1C92: bytes.fromhex("e819fcffff"),      # apply call 0x60c18b0
    0x60C1C97: bytes.fromhex("488b7c2408"),      # parse-Status message free
    0x60C19F0: bytes.fromhex("488b7c2418"),      # overflow-map load (arg6)
    0x60C1AC8: bytes.fromhex("41803f00"),        # cmpb $0x0,(%r15) options_base+0x00
    0x60C1B02: bytes.fromhex("488d05977c38fa"),  # lea "Unrecognized option" 0x4497a0
    0x60C0E96: bytes.fromhex("ba07690fc7"),      # _Hash_bytes seed 0xc70f6907
    0x5E317F1: bytes.fromhex("e8ba032900"),      # caller A wrapper call
    0x5E344D6: bytes.fromhex("e8d5d62800"),      # caller B wrapper call
    0x60C20D2: bytes.fromhex("e8d9faffff"),      # caller C wrapper call
    0x60C1190: bytes.fromhex("f30f1efa"),        # parser endbr64
}

FDEs = {
    0x60C1BB0: 0x60C1CC5,
    0x60C1190: 0x60C1887,
    0x60C18B0: 0x60C1B7C,
    0x60C0E90: 0x60C112F,
    0x5E317A0: 0x5E3190A,
    0x5E34160: 0x5E347C1,
    0x60C1D50: 0x60C26D5,
    0x60BEDC0: 0x60BF5BC,
    0x5D36110: 0x5D361D5,
}

CALLERS = {
    0x60C1BB0: {0x5E317F1, 0x5E344D6, 0x60C20D2},
    0x60C1190: {0x6099FC5, 0x609A499, 0x609E896, 0x60C1C2E, 0x60C3D69, 0x60C4769},
    0x60C18B0: {0x60A1DEA, 0x60C1C92},
    0x60C0E90: {0x60C1460, 0x60C1A01},
    0x60C1D50: {0x5D3FD98, 0x5E30B66, 0x607E611, 0x608340C, 0x60834EC},
}

LITERALS = {
    0x969140: b"Mismatched key value pair, '=' expected",
    0x44FF0E: b"Unexpected char in key",
    0x4362E1: b"Empty key found",
    0x4497A0: b"Unrecognized option",
    0x44E056: b"Could not find option",
    0x4376FD: b"",
}

failures = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))
    if not ok:
        failures.append(name)


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def call_sites(data, target):
    seg = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    sites = set()
    i = 0
    while True:
        i = seg.find(b"\xe8", i)
        if i == -1 or i + 5 > len(seg):
            break
        rel = struct.unpack_from("<i", seg, i + 1)[0]
        site = TEXT_VA + i
        if site + 5 + rel == target:
            sites.add(site)
        i += 1
    return sites


def main() -> int:
    data = BIN.read_bytes()

    # 1. artifact digest
    prov = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    want = next(f["sha256"] for f in prov["files"]
                if f["path"] == "artifacts/node/115/hl-node")
    check("artifact digest", sha256_file(BIN) == want, want[:16])

    # 2. manifest
    manifest = (HERE / "MANIFEST.sha256").read_text().splitlines()
    ok = True
    for line in manifest:
        digest, name = line.split(None, 1)
        if sha256_file(HERE / name) != digest:
            ok = False
    check("MANIFEST.sha256", ok, f"{len(manifest)} files")

    # 3. excerpt regeneration
    ok = True
    for name, (start, stop) in FUNCS.items():
        out = subprocess.check_output(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={stop:#x}", "work/hl-node-115.bin"],
            cwd=ROOT, text=True)
        if (HERE / name).read_text() != out:
            ok = False
            print(f"  excerpt mismatch: {name}")
    check("excerpts regenerate byte-for-byte", ok, f"{len(FUNCS)} files")

    # 4. FDE ranges
    sys.path.insert(0, str(ROOT / "tools"))
    from fde_extents import eh_frame_records
    _, frames = eh_frame_records(data)
    fde = {f["start"]: f["end"] for f in frames}
    ok = all(fde.get(s) == e for s, e in FDEs.items())
    check("FDE ranges", ok, f"{len(FDEs)} functions")

    # 5. raw-binary spot bytes
    ok = True
    for va, want in SPOTS.items():
        if data[va - VA_TO_OFF:va - VA_TO_OFF + len(want)] != want:
            ok = False
            print(f"  spot mismatch: {va:#x}")
    check("raw-binary spot bytes", ok, f"{len(SPOTS)} sites")

    # 6. caller census
    ok = True
    for target, want in CALLERS.items():
        if call_sites(data, target) != want:
            ok = False
            print(f"  census mismatch: {target:#x}")
    check("caller census", ok, f"{len(CALLERS)} targets")

    # 7. literals in .rodata
    ok = True
    for va, want in LITERALS.items():
        end = data.index(b"\0", va)
        if data[va:end] != want:
            ok = False
            print(f"  literal mismatch: {va:#x}")
    check("literals", ok, f"{len(LITERALS)} strings")

    # 8. semantic-only records
    raw = (HERE / "records.json").read_text()
    rec = json.loads(raw)
    bad = [k for k in ('"mnemonic"', '"instructions"', '"opcodes"') if k in raw]
    check("records are semantic-only", not bad, f"bad keys: {bad}")
    check("records bound to node #115 digest",
          rec.get("artifact_sha256", "").startswith(DIGEST))

    # 9. model tests
    r = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/test_parse_then_apply_wrapper_115.py", "-q"],
        cwd=ROOT, capture_output=True, text=True)
    check("model tests", r.returncode == 0, r.stdout.strip().splitlines()[-1])

    print(f"\n{len(failures)} failures" if failures else "\nALL CHECKS PASSED")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
