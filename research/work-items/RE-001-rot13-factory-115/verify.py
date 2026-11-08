#!/usr/bin/env python3
"""Self-checks for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-rot13-factory-115/verify.py

Checks: artifact digest, manifest, excerpt regeneration (byte-identical to
fresh objdump), FDE identities, raw-binary spot bytes, literals, lea
census, semantic-only records, and the model tests. Exits non-zero on any
failure.
"""
import hashlib
import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")
    return bool(ok)


def sections(data: bytes):
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, _ = struct.unpack_from("<HHH", data, 0x3A)
    out = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        _, _, _, addr, offset, size, _, _, _, _ = struct.unpack_from(
            "<IIQQQQIIQQ", data, off)
        out.append((addr, offset, size))
    return out


def read_va(data: bytes, secs, va: int, n: int) -> bytes:
    for addr, offset, size in secs:
        if addr <= va < addr + size:
            return data[offset + va - addr: offset + va - addr + n]
    raise ValueError(f"no section contains {va:#x}")


def main() -> int:
    sys.path.insert(0, str(ROOT / "tools"))
    from fde_extents import eh_frame_records
    from rot13_factory_115 import parse_block_size  # noqa: F401  (model import)

    data = BIN.read_bytes()
    secs = sections(data)
    ok = True

    ok &= check("artifact digest",
                hashlib.sha256(data).hexdigest() == DIGEST, DIGEST[:16])

    manifest = (HERE / "MANIFEST.sha256").read_text().splitlines()
    seen = set()
    for line in manifest:
        digest, _, name = line.partition("  ")
        path = HERE / name
        seen.add(name)
        ok &= check(f"manifest {name}",
                    path.is_file()
                    and hashlib.sha256(path.read_bytes()).hexdigest() == digest,
                    digest[:12])
    packet_files = sorted(
        p.name for p in HERE.iterdir()
        if p.is_file() and p.name != "MANIFEST.sha256")
    ok &= check("manifest covers all packet files",
                seen == set(packet_files),
                f"{len(seen)} listed, {len(packet_files)} present")

    # Excerpts byte-identical to fresh objdump (repo-relative path).
    import export_excerpts
    for name, (start, end) in export_excerpts.FUNCTIONS.items():
        fresh = subprocess.run(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={end:#x}", "work/hl-node-115.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        stored = (HERE / f"fn-{name}.objdump.txt").read_text()
        ok &= check(f"excerpt fn-{name}", fresh == stored)

    # FDEs.
    _, frames = eh_frame_records(data)
    fdes = {(f["start"], f["end"]) for f in frames}
    for line in (HERE / "frames.txt").read_text().splitlines()[1:]:
        _, s, e = line.split("\t")
        ok &= check(f"FDE {s}..{e}",
                    (int(s, 16), int(e, 16)) in fdes)

    # Raw-binary spot bytes.
    spots = {
        0x5FF7120: bytes.fromhex("f30f1efa"),
        0x5FF7129: bytes.fromhex("be3a000000"),
        0x5FF71BA: bytes.fromhex("e831ad1d00"),
        0x5FF7209: bytes.fromhex("488d05908c4d00"),
        0x5FF7246: bytes.fromhex("48b9724f7074696f6e73"),
        0x5FF7261: bytes.fromhex("488d0d58e05000"),
        0x5FF7279: bytes.fromhex("e8622a0a00"),
        0x5FF735A: bytes.fromhex("48c7432020000000"),
        0x5FF7377: bytes.fromhex("e864290a00"),
        0x5FEF994: bytes.fromhex("488d053b8e45fa"),
        0x5FEF9C0: bytes.fromhex("80040a0d"),
        0x5FF7D53: bytes.fromhex("48894598"),
        0x5FF7D61: bytes.fromhex("c745a000040000"),
        0x5FF7FC4: bytes.fromhex("e8e785d4ff"),
        0x61D15E7: bytes.fromhex("e884032200"),
        0x458F68: bytes.fromhex("1600000001000000"),
    }
    for va, want in spots.items():
        got = read_va(data, secs, va, len(want))
        ok &= check(f"spot bytes {va:#x}", got == want, got.hex())

    # Literals.
    for va, want in (
            (0x453E50, b"ROT13BlockCipher"),
            (0x443890, b"ROT13BlockCipherOptions"),
            (0x4487D6, b"ROT13"),
            (0x43A5F7, b"block_size"),
            (0x4453A1, b"provider"),
            (0x439496, b"cipher")):
        got = read_va(data, secs, va, len(want))
        ok &= check(f"literal {va:#x} {want!r}", got == want)

    # Lea census (same scan as census.py).
    import census as census_mod
    refs = census_mod.scan_lea_refs(
        data, [0x65052C0, 0x64CFEA0, 0x5FF7120, 0x6505300, 0x6505280])
    ok &= check("lea map 0x65052c0",
                sorted(refs[0x65052C0]) == sorted(census_mod.EXPECTED_LEA_MAP))
    ok &= check("lea vtable 0x64cfea0",
                sorted(refs[0x64CFEA0]) == sorted(census_mod.EXPECTED_LEA_VTABLE))
    ok &= check("lea factory 0x5ff7120",
                sorted(refs[0x5FF7120]) == sorted(census_mod.EXPECTED_LEA_FACTORY))

    # Semantic-only records: no per-instruction mnemonic list.
    records = json.loads((HERE / "records.json").read_text())
    blob = json.dumps(records)
    ok &= check("records semantic-only",
                '"mnemonic"' not in blob and '"instructions"' not in blob
                and '"opcodes"' not in blob)
    ok &= check("records full digest",
                records["artifact_sha256"] == DIGEST
                and len(records["artifact_sha256"]) == 64)

    # Model tests.
    suite = unittest.defaultTestLoader.discover(
        str(ROOT / "tests"), pattern="test_rot13_factory_115.py")
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=0).run(suite)
    ok &= check("model tests", result.wasSuccessful(),
                f"{result.testsRun} run, {len(result.failures)} failures, "
                f"{len(result.errors)} errors")

    print(f"\n{sum(1 for _, p, _ in CHECKS if p)}/{len(CHECKS)} checks passed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
