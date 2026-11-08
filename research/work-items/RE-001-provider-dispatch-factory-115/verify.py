#!/usr/bin/env python3
"""Self-checks for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-provider-dispatch-factory-115/verify.py

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
    from provider_dispatch_factory_115 import dispatch  # noqa: F401

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
        0x5FFABD0: bytes.fromhex("f30f1efa"),
        0x5FFABF9: bytes.fromhex("48837e2000"),
        0x5FFAC3B: bytes.fromhex("e8304a1d00"),
        0x5FFAC73: bytes.fromhex("488d3d5cdb44fa"),
        0x5FFAC83: bytes.fromhex("e898623f00"),
        0x5FFAC90: bytes.fromhex("bf28000000"),
        0x5FFACC1: bytes.fromhex("488d05d8514d00"),
        0x5FFACEE: bytes.fromhex("e8edef0900"),
        0x5FFAD15: bytes.fromhex("e8b6603f00"),
        0x5FFAD1A: bytes.fromhex("488b15ffed45fa"),
        0x5FFAD31: bytes.fromhex("488d15f0534d00"),
        0x5FFAD44: bytes.fromhex("e877a3d3ff"),
        0x5FFAD4B: bytes.fromhex("c70300000000"),
        0x5FFAD7C: bytes.fromhex("e87f55ffff"),
        0x5FFAD84: bytes.fromhex("e8070b0c00"),
        0x5FFAD95: bytes.fromhex("e876f9ffff"),
        0x5FFA710: bytes.fromhex("f30f1efa"),
        0x5FFA786: bytes.fromhex("488d3debaa5000"),
        0x5FFA790: bytes.fromhex("e83b6c3f00"),
        0x5FFA85A: bytes.fromhex("e8b13c0a00"),
        0x5FFA886: bytes.fromhex("e80556ffff"),
        0x5FFA918: bytes.fromhex("e8a3a7d3ff"),
        0x5FFA962: bytes.fromhex("e879f6ffff"),
        0x5FFAA27: bytes.fromhex("e8444c1d00"),
        0x5FFAA45: bytes.fromhex("e886380a00"),
        0x5FFAE10: bytes.fromhex("f30f1efa"),
        0x5FFAE30: bytes.fromhex("4883790802"),
        0x5FFAE63: bytes.fromhex("6681396964"),
        0x5FFAE40: bytes.fromhex("e8cbf8ffff"),
        0x5FFBA10: bytes.fromhex("f30f1efa"),
        0x5FFBDE0: bytes.fromhex("f30f1efa"),
        0x5FFBE10: bytes.fromhex("e8fbfbffff"),
        0x5FF9FE0: bytes.fromhex("f30f1efa"),
        0x60BB890: bytes.fromhex("f30f1efa"),
        0x60BB8B1: bytes.fromhex("c70700010101"),
        0x60BB8CC: bytes.fromhex("66894718"),
        0x5FF0300: bytes.fromhex("41554c8d6f10"),
        0x459B20: bytes.fromhex("0100000001000000"),
    }
    for va, want in spots.items():
        got = read_va(data, secs, va, len(want))
        ok &= check(f"spot bytes {va:#x}", got == want, got.hex())

    # Literals.
    for va, want in (
            (0x4487D6, b"ROT13"),
            (0x968090, b"Cannot add keys to CTREncryptionProvider"),
            (0x443890, b"ROT13BlockCipherOptions"),
            (0x433F9F, b"Cannot reset object "),
            (0x4487C0, b"Cannot make a shared "),
            (0x43FA43, b"BlockCipher"),
            (0x432138, b" from unguarded one "),
            (0x439466, b"Could not load "),
            (0x43A5F7, b"block_size")):
        got = read_va(data, secs, va, len(want))
        ok &= check(f"literal {va:#x} {want!r}", got == want)

    # Lea census (same scan as census.py).
    import census as census_mod
    refs = census_mod.scan_lea_refs(data, list(census_mod.EXPECTED_LEA))
    for addr, want in census_mod.EXPECTED_LEA.items():
        ok &= check(f"lea {addr:#x}",
                    sorted(refs[addr]) == sorted(want))
    for target, want in census_mod.EXPECTED_E8.items():
        got = census_mod.scan_e8_callers(data, target)
        ok &= check(f"E8 callers of {target:#x}",
                    sorted(got) == sorted(want))
    for target, sites in (
            (census_mod.RELEASE, census_mod.EXPECTED_E8_RELEASE_IN_PACKET),
            (census_mod.REGISTER_OPTIONS,
             census_mod.EXPECTED_E8_REGISTER_OPTIONS_IN_PACKET),
            (census_mod.CONFIGURE_HOST,
             census_mod.EXPECTED_E8_CONFIGURE_HOST_IN_PACKET),
            (census_mod.NULL_CONFIGURE,
             census_mod.EXPECTED_E8_NULL_CONFIGURE_IN_PACKET),
            (census_mod.STATUS_CTOR,
             census_mod.EXPECTED_E8_STATUS_CTOR_IN_PACKET)):
        got = census_mod.scan_e8_callers(data, target)
        for site in sites:
            ok &= check(f"E8 in-packet {target:#x} site {site:#x}",
                        site in got)

    # Vtable slots + typeinfos.
    relocs = census_mod.rela_dyn(data)
    for vtable, slots in census_mod.VTABLE_SLOTS.items():
        for slot, want in slots:
            got = census_mod.vtable_slot(data, secs, relocs, vtable, slot)
            ok &= check(f"vtable {vtable:#x} slot {slot}",
                        got == want, f"{got:#x}")
    for vtable, (typeinfo, name) in census_mod.TYPEINFOS.items():
        ti = relocs.get(vtable - 0x8)
        ok &= check(f"vtable {vtable:#x} typeinfo",
                    ti is not None and ti[2] == typeinfo)
        got_name = relocs.get(typeinfo + 0x8)
        ok &= check(f"typeinfo name {vtable:#x}",
                    got_name is not None
                    and census_mod.cstr(data, got_name[2]) == name)
    ok &= check("CTR vtable length 27",
                census_mod.vtable_len(data, secs, relocs,
                                      census_mod.VT_CTR) == 27)
    ok &= check("control-block vtable length 6",
                census_mod.vtable_len(data, secs, relocs,
                                      census_mod.VT_CTRL) == 6)
    for slot, want in ((census_mod.GOT_WRAPPER, census_mod.WRAPPER),
                       (census_mod.GOT_TWIN_WRAPPER,
                        census_mod.TWIN_WRAPPER)):
        got = relocs.get(slot)
        ok &= check(f"GOT slot {slot:#x}",
                    got is not None and got[0] == 8 and got[2] == want)

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
        str(ROOT / "tests"), pattern="test_provider_dispatch_factory_115.py")
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=0).run(suite)
    ok &= check("model tests", result.wasSuccessful(),
                f"{result.testsRun} run, {len(result.failures)} failures, "
                f"{len(result.errors)} errors")

    print(f"\n{sum(1 for _, p, _ in CHECKS if p)}/{len(CHECKS)} checks passed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
