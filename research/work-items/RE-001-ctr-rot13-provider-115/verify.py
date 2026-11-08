#!/usr/bin/env python3
"""Self-checks for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-ctr-rot13-provider-115/verify.py

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
    from ctr_rot13_provider_115 import create_provider_ctr  # noqa: F401

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
        0x5FF6A00: bytes.fromhex("f30f1efa"),
        0x5FF6A06: bytes.fromhex("bf38000000"),
        0x5FF6A61: bytes.fromhex("488d05f8964d00"),
        0x5FF6A6B: bytes.fromhex("488d052e944d00"),
        0x5FF6A8A: bytes.fromhex("48c7433020000000"),
        0x5FF6AF6: bytes.fromhex("e8e5310a00"),
        0x5FF6B30: bytes.fromhex("e84bfdffff"),
        0x5FF6B4E: bytes.fromhex("483b05436e4f00"),
        0x5FF6880: bytes.fromhex("f30f1efa"),
        0x5FF689F: bytes.fromhex("488d05fa964d00"),
        0x5FF690B: bytes.fromhex("c744241043697068"),
        0x5FF6926: bytes.fromhex("e8b5330a00"),
        0x5FF30B0: bytes.fromhex("f30f1efa"),
        0x5FF30B4: bytes.fromhex("488d05e5ce4d00"),
        0x5FF313E: bytes.fromhex("e93ddc3f00"),
        0x5FF6D60: bytes.fromhex("f30f1efa"),
        0x5FF6D90: bytes.fromhex("c74424203a2f2f74"),
        0x5FF6DB6: bytes.fromhex("e8d5a51d00"),
        0x5FF6E51: bytes.fromhex("e88a2e0a00"),
        0x5D350C0: bytes.fromhex("f30f1efa"),
        0x5D350C4: bytes.fromhex("48b80100000001000000"),
        0x459B20: bytes.fromhex("0100000001000000"),
        0x458F68: bytes.fromhex("1600000001000000"),
    }
    for va, want in spots.items():
        got = read_va(data, secs, va, len(want))
        ok &= check(f"spot bytes {va:#x}", got == want, got.hex())

    # Literals.
    for va, want in (
            (0x453E50, b"ROT13BlockCipher"),
            (0x443890, b"ROT13BlockCipherOptions"),
            (0x4429AE, b"1://test"),
            (0x447699, b"CTR"),
            (0x4487D6, b"ROT13"),
            (0x439496, b"cipher"),
            (0x43A5F7, b"block_size"),
            (0x4453A1, b"provider")):
        got = read_va(data, secs, va, len(want))
        ok &= check(f"literal {va:#x} {want!r}", got == want)

    # Lea census (same scan as census.py).
    import census as census_mod
    targets = [0x65052C0, 0x6505280, 0x6505300, 0x64D0160, 0x64CFFA0,
               0x64CFEA0, 0x5FF6A00, 0x5FF6D60]
    refs = census_mod.scan_lea_refs(data, targets)
    for addr, want in census_mod.EXPECTED_LEA.items():
        ok &= check(f"lea {addr:#x}",
                    sorted(refs[addr]) == sorted(want))
    for site in census_mod.EXPECTED_LEA_CONFIG_SUBSET:
        ok &= check(f"lea Configurable subset {site:#x}",
                    site in census_mod.scan_lea_refs(data, [0x64D3420])[0x64D3420])
    e8 = census_mod.scan_e8_callers(data, 0x5FF6880)
    ok &= check("E8 callers of holder 0x5ff6880",
                sorted(e8) == sorted(census_mod.EXPECTED_E8_HOLDER))

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
        str(ROOT / "tests"), pattern="test_ctr_rot13_provider_115.py")
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=0).run(suite)
    ok &= check("model tests", result.wasSuccessful(),
                f"{result.testsRun} run, {len(result.failures)} failures, "
                f"{len(result.errors)} errors")

    print(f"\n{sum(1 for _, p, _ in CHECKS if p)}/{len(CHECKS)} checks passed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
