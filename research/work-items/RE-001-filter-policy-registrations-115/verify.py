#!/usr/bin/env python3
"""Self-checks for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-filter-policy-registrations-115/verify.py

Checks: artifact digest, manifest, excerpt regeneration (byte-identical to
fresh objdump), FDE identities, raw-binary spot bytes, literals, lea
census, E8 census, vtable slots + typeinfo, manager template identity,
semantic-only records, and the model tests. Exits non-zero on any failure.
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
    from filter_policy_registrations_115 import REGISTRATIONS  # noqa: F401

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
        0x6137810: bytes.fromhex("4157"),
        0x6137829: bytes.fromhex("bf30000000"),
        0x6137888: bytes.fromhex("bf70000000"),
        0x6137B6C: bytes.fromhex("488d359b5631fa"),
        0x6137B87: bytes.fromhex("e814a2e9ff"),
        0x6137FE0: bytes.fromhex("4157"),
        0x6138179: bytes.fromhex("488d358e5031fa"),
        0x613818F: bytes.fromhex("e80c9ce9ff"),
        0x613825F: bytes.fromhex("e8acf5ffff"),
        0x6138A48: bytes.fromhex("e893f5ffff"),
        0x612DE10: bytes.fromhex("f30f1efa"),
        0x612DE15: bytes.fromhex("bf20000000"),
        0x612DE22: bytes.fromhex("488d15b76c3a00"),
        0x612DE33: bytes.fromhex("4883c210"),
        0x6134130: bytes.fromhex("f30f1efa"),
        0x6134141: bytes.fromhex("ba3a000000"),
        0x613416E: bytes.fromhex("bf40000000"),
        0x6134188: bytes.fromhex("e8d3bfffff"),
        0x61338A0: bytes.fromhex("f30f1efa"),
        0x6134010: bytes.fromhex("f30f1efa"),
        0x613404C: bytes.fromhex("bf01000000"),
        0x6134051: bytes.fromhex("e89addffff"),
        0x6133EF0: bytes.fromhex("f30f1efa"),
        0x6133F2C: bytes.fromhex("31ff"),
        0x6133F2E: bytes.fromhex("e88ddfffff"),
        0x6133DC0: bytes.fromhex("f30f1efa"),
        0x6133E09: bytes.fromhex("e882dd0900"),
        0x6133E0E: bytes.fromhex("89c7"),
        0x6133E15: bytes.fromhex("e8a6e0ffff"),
        0x61339E0: bytes.fromhex("f30f1efa"),
        0x6133A1E: bytes.fromhex("bf40000000"),
        0x6133A3D: bytes.fromhex("488d058c153a00"),
        0x6133A4D: bytes.fromhex("4883c010"),
        0x6133B30: bytes.fromhex("f30f1efa"),
        0x6133B8D: bytes.fromhex("488d05fc143a00"),
        0x6133C80: bytes.fromhex("f30f1efa"),
        0x6133CDD: bytes.fromhex("488d056c143a00"),
        0x612D2A0: bytes.fromhex("f30f1efa"),
        0x612D2A4: bytes.fromhex("85d2"),
        0x612D2C0: bytes.fromhex("488d0559773a00"),
    }
    for va, want in spots.items():
        got = read_va(data, secs, va, len(want))
        ok &= check(f"spot bytes {va:#x}", got == want, got.hex())

    # Literals.
    for va, want in (
            (0x44481B, b"rocksdb.BuiltinBloomFilter"),
            (0x43C831, b"bloomfilter"),
            (0x44FF67, b"rocksdb.BloomFilter"),
            (0x43E8EB, b"ribbonfilter"),
            (0x4466F4, b"rocksdb.RibbonFilter"),
            (0x442AC3, b":false"),
            (0x4384F5, b":true"),
            (0x95DEA0, b"rocksdb.internal.LegacyBloomFilter"),
            (0x965BC0, b"rocksdb.internal.FastLocalBloomFilter"),
            (0x96A630, b"rocksdb.internal.Standard128RibbonFilter"),
            (0x44D20E, b"FilterPolicy")):
        got = read_va(data, secs, va, len(want))
        ok &= check(f"literal {va:#x} {want!r}", got == want)

    # Lea census (same scans as census.py).
    import census as census_mod
    refs = census_mod.scan_lea_refs(data, list(census_mod.EXPECTED_LEA_FULL))
    for addr, want in census_mod.EXPECTED_LEA_FULL.items():
        ok &= check(f"lea {addr:#x}",
                    sorted(refs[addr]) == sorted(want))
    for target, want in census_mod.EXPECTED_E8.items():
        got = census_mod.scan_e8_callers(data, target)
        ok &= check(f"E8 callers of {target:#x}",
                    sorted(got) == sorted(want))
    for target, want in census_mod.EXPECTED_E8_IN_PACKET.items():
        got = census_mod.scan_e8_callers(data, target)
        got_in = sorted(s for s in got
                        if census_mod.in_pinned_fdes(s))
        ok &= check(f"E8 in-packet {target:#x}",
                    got_in == sorted(want))
    for target in census_mod.EXPECTED_E8_NONE:
        got = census_mod.scan_e8_callers(data, target)
        ok &= check(f"no E8 caller of {target:#x}", got == [],
                    f"{[hex(x) for x in got]}")

    # Vtable slots + typeinfo.
    relocs = census_mod.rela_dyn(data)
    for vtable, slots in census_mod.VTABLE_SLOTS.items():
        for slot, want in slots:
            got = census_mod.vtable_slot(data, secs, relocs, vtable, slot)
            ok &= check(f"vtable {vtable:#x} slot {slot}",
                        got == want, f"{got:#x}")
    for vtable in (0x64D4AF0, 0x64D4F20, 0x64D4FE0, 0x64D50A0, 0x64D5160,
                   0x64D52E0):
        for slot, want in census_mod.SHARED_POLICY_SLOTS:
            got = census_mod.vtable_slot(data, secs, relocs, vtable, slot)
            ok &= check(f"policy vtable {vtable:#x} shared slot {slot}",
                        got == want, f"{got:#x}")
        ok &= check(f"policy vtable {vtable:#x} length 23",
                    census_mod.vtable_len(data, secs, relocs, vtable) == 23)
        ok &= check(f"policy vtable {vtable:#x} trailing slot zero",
                    census_mod.vtable_slot(data, secs, relocs, vtable, 22) == 0)
    for vtable in (0x64D8ED0, 0x64D53A0):
        ok &= check(f"vtable {vtable:#x} length 5",
                    census_mod.vtable_len(data, secs, relocs, vtable) == 5)
        ok &= check(f"vtable {vtable:#x} trailing slot zero",
                    census_mod.vtable_slot(data, secs, relocs, vtable, 4) == 0)
    for vtable, (typeinfo, name) in census_mod.TYPEINFOS.items():
        ti = relocs.get(vtable - 0x8)
        ok &= check(f"vtable {vtable:#x} typeinfo",
                    ti is not None and ti[2] == typeinfo)
        got_name = relocs.get(typeinfo + 0x8)
        ok &= check(f"typeinfo name {vtable:#x}",
                    got_name is not None
                    and census_mod.cstr(data, got_name[2]) == name)

    # Manager template: byte-identical except the op-0 lea rel32.
    for mgr, want_ti in census_mod.MANAGER_TYPEINFOS:
        b = read_va(data, secs, mgr, 0x2D)
        template = read_va(data, secs, census_mod.MANAGERS[0], 0x2D)
        ok &= check(f"manager {mgr:#x} template head",
                    b[:0x20] == template[:0x20])
        ok &= check(f"manager {mgr:#x} template tail",
                    b[0x27:] == template[0x27:])
        rel = struct.unpack_from("<i", b, 0x23)[0]
        ok &= check(f"manager {mgr:#x} op-0 typeinfo",
                    mgr + 0x20 + 7 + rel == want_ti, f"{want_ti:#x}")

    # Semantic-only records: no per-instruction mnemonic list.
    records = json.loads((HERE / "records.json").read_text())
    blob = json.dumps(records)
    ok &= check("records semantic-only",
                '"mnemonic"' not in blob and '"instructions"' not in blob
                and '"opcodes"' not in blob)
    ok &= check("records full digest",
                records["artifact_sha256"] == DIGEST
                and len(records["artifact_sha256"]) == 64)
    ok &= check("records nine registrations",
                len(records["registrar_0x6137fe0"]["registrations"]) == 9)
    ok &= check("model table nine factories", len(REGISTRATIONS) == 9)

    # Model tests.
    suite = unittest.defaultTestLoader.discover(
        str(ROOT / "tests"), pattern="test_filter_policy_registrations_115.py")
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=0).run(suite)
    ok &= check("model tests", result.wasSuccessful(),
                f"{result.testsRun} run, {len(result.failures)} failures, "
                f"{len(result.errors)} errors")

    print(f"\n{sum(1 for _, p, _ in CHECKS if p)}/{len(CHECKS)} checks passed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
