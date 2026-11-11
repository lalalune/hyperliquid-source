#!/usr/bin/env python3
"""Self-checks for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-encrypted-fs-factory-115/verify.py

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
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
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
    from encrypted_fs_factory_115 import create_encrypted_fs  # noqa: F401

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
             f"--stop-address={end:#x}", "artifacts/node/115/hl-node"],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
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
        0x5FF6690: bytes.fromhex("f30f1efa"),
        0x5FF66A9: bytes.fromhex("bf40000000"),
        0x5FF66C3: bytes.fromhex("e808a73f00"),
        0x5FF66D1: bytes.fromhex("e83a0bffff"),
        0x5FF66D6: bytes.fromhex("488d05c3954d00"),
        0x5FF66DD: bytes.fromhex("48c7433800000000"),
        0x5FF6763: bytes.fromhex("488d0d96eb5000"),
        0x5FF677E: bytes.fromhex("e85d350a00"),
        0x5FF679B: bytes.fromhex("498b3c24"),
        0x5FF67AB: bytes.fromhex("ff5008"),
        0x5FF67B0: bytes.fromhex("c7450000000000"),
        0x5FE7210: bytes.fromhex("f30f1efa"),
        0x5FE7232: bytes.fromhex("e849feffff"),
        0x5FE7237: bytes.fromhex("488d05b27f4e00"),
        0x5FE7292: bytes.fromhex("e8492a0b00"),
        0x5FE7080: bytes.fromhex("f30f1efa"),
        0x5FE7084: bytes.fromhex("488d056d7f4e00"),
        0x5FE70B0: bytes.fromhex("f30f1efa"),
        0x5FE70B4: bytes.fromhex("488d0565c34e00"),
        0x5FF3000: bytes.fromhex("f30f1efa"),
        0x5FF3004: bytes.fromhex("488d0595cc4d00"),
        0x5FF301B: bytes.fromhex("e8a020d4ff"),
        0x5FF3040: bytes.fromhex("e96b40ffff"),
        0x5FF3050: bytes.fromhex("f30f1efa"),
        0x5FF3097: bytes.fromhex("be40000000"),
        0x5FF309D: bytes.fromhex("e9dedc3f00"),
        0x5FE7A20: bytes.fromhex("f30f1efa"),
        0x5FE7A67: bytes.fromhex("e824ec0000"),
        0x5FEF930: bytes.fromhex("f30f1efa"),
        0x5FEF934: bytes.fromhex("488d05d34d45fa"),
        0x5FE7EE0: bytes.fromhex("f30f1efa"),
        0x5FE7EE6: bytes.fromhex("80cd04"),
        0x5FE8035: bytes.fromhex("c783a800000016000000"),
        0x5FEB760: bytes.fromhex("55"),
        0x5FEB7CA: bytes.fromhex("e811c7ffff"),
        0x5FEB7EC: bytes.fromhex("c78510ffffff74617267"),
        0x5FEB9CD: bytes.fromhex("e8de4bd5ff"),
        0x5FEBA18: bytes.fromhex("e963554000"),
        0x5FEBF50: bytes.fromhex("4156"),
        0x5FEC0C6: bytes.fromhex("488d0553b9ffff"),
        0x5FE5700: bytes.fromhex("f30f1efa"),
        0x5FE5704: bytes.fromhex("85d2"),
        0x5FE5720: bytes.fromhex("488d0581964e00"),
        0x458F68: bytes.fromhex("1600000001000000"),
    }
    for va, want in spots.items():
        got = read_va(data, secs, va, len(want))
        ok &= check(f"spot bytes {va:#x}", got == want, got.hex())

    # Literals.
    for va, want in (
            (0x4539B0, b"EncryptionProvid"),
            (0x4453A1, b"provider"),
            (0x44470E, b"EncryptedFileSystem"),
            (0x4552D0, b"EncryptedFileSys"),
            (0x4552C0, b"ReadOnlyFileSyst"),
            (0x4510E0, b"CountedFileSyste"),
            (0x4565B0, b"MemoryFileSystem"),
            (0x439496, b"cipher"),
            (0x43A5F7, b"block_size")):
        got = read_va(data, secs, va, len(want))
        ok &= check(f"literal {va:#x} {want!r}", got == want)

    # Lea census (same scan as census.py).
    import census as census_mod
    targets = list(census_mod.EXPECTED_LEA) + [
        census_mod.VT_WRAPPER_BASE, census_mod.VT_CONFIG_BASE]
    refs = census_mod.scan_lea_refs(data, targets)
    for addr, want in census_mod.EXPECTED_LEA.items():
        ok &= check(f"lea {addr:#x}",
                    sorted(refs[addr]) == sorted(want))
    ok &= check("lea wrapper vtable base",
                sorted(refs[census_mod.VT_WRAPPER_BASE])
                == sorted(census_mod.EXPECTED_LEA_WRAPPER_BASE))
    for site in census_mod.EXPECTED_LEA_CONFIG_SUBSET:
        ok &= check(f"lea Configurable subset {site:#x}",
                    site in refs[census_mod.VT_CONFIG_BASE])
    for target, want in census_mod.EXPECTED_E8.items():
        got = census_mod.scan_e8_callers(data, target)
        ok &= check(f"E8 callers of {target:#x}",
                    sorted(got) == sorted(want))

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
        str(ROOT / "tests"), pattern="test_encrypted_fs_factory_115.py")
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=0).run(suite)
    ok &= check("model tests", result.wasSuccessful(),
                f"{result.testsRun} run, {len(result.failures)} failures, "
                f"{len(result.errors)} errors")

    print(f"\n{sum(1 for _, p, _ in CHECKS if p)}/{len(CHECKS)} checks passed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
