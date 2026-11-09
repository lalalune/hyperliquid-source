#!/usr/bin/env python3
"""Self-checks for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-filter-policy-dispatch-115/verify.py

Checks: artifact digest, manifest, excerpt regeneration (byte-identical to
fresh objdump), FDE identities, raw-binary spot bytes, literals, lea
census, E8 census, vtable slots + typeinfo, semantic-only records, and the
model tests. Exits non-zero on any failure.
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
    from filter_policy_dispatch_115 import dispatch  # noqa: F401

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
        0x6136B40: bytes.fromhex("f30f1efa"),
        0x6136650: bytes.fromhex("f30f1efa"),
        0x61366CD: bytes.fromhex("48b846696c746572506f"),
        0x61366E0: bytes.fromhex("c745086c696379"),
        0x61366E7: bytes.fromhex("48c74424480c000000"),
        0x6136802: bytes.fromhex("e849feffff"),
        0x61368B5: bytes.fromhex("e826a62b00"),
        0x613695A: bytes.fromhex("e841a12b00"),
        0x6136766: bytes.fromhex("ff5010"),
        0x61367A5: bytes.fromhex("ffd0"),
        0x6136B83: bytes.fromhex("e8c8faffff"),
        0x6136BEA: bytes.fromhex("ff542478"),
        0x6136BF7: bytes.fromhex("31d2"),
        0x6136C42: bytes.fromhex("ffd0"),
        0x6136C66: bytes.fromhex("bf18000000"),
        0x6136C70: bytes.fromhex("488b15a92e32fa"),
        0x6136C91: bytes.fromhex("488d1548cb3900"),
        0x6136CAB: bytes.fromhex("e810e4bfff"),
        0x6136D24: bytes.fromhex("488d35951a31fa"),
        0x6136E05: bytes.fromhex("e866880900"),
        0x6136E30: bytes.fromhex("0fb7442430"),
        0x6136E7B: bytes.fromhex("488d35e42530fa"),
        0x6136F0A: bytes.fromhex("e861870900"),
        0x6136F59: bytes.fromhex("e812870900"),
        0x6137021: bytes.fromhex("e84a860900"),
        0x61374A0: bytes.fromhex("e89bf6ffff"),
        0x459B20: bytes.fromhex("0100000001000000"),
        0x6137B6C: bytes.fromhex("488d359b5631fa"),
        0x6138179: bytes.fromhex("488d358e5031fa"),
        0x60DAFE0: bytes.fromhex("e8abc20500"),
    }
    for va, want in spots.items():
        got = read_va(data, secs, va, len(want))
        ok &= check(f"spot bytes {va:#x}", got == want, got.hex())

    # Literals.
    for va, want in (
            (0x4487C0, b"Cannot make a shared "),
            (0x44D20E, b"FilterPolicy"),
            (0x432138, b" from unguarded one "),
            (0x439466, b"Could not load "),
            (0x442AC3, b":false"),
            (0x4384F5, b":true")):
        got = read_va(data, secs, va, len(want))
        ok &= check(f"literal {va:#x} {want!r}", got == want)

    # Lea census (same scans as census.py).
    import census as census_mod
    refs = census_mod.scan_lea_refs(
        data, list(census_mod.EXPECTED_LEA_FULL)
        + list(census_mod.EXPECTED_LEA_IN_PACKET))
    for addr, want in census_mod.EXPECTED_LEA_FULL.items():
        ok &= check(f"lea {addr:#x}",
                    sorted(refs[addr]) == sorted(want))
    for addr, want in census_mod.EXPECTED_LEA_IN_PACKET.items():
        got = sorted(s for s in refs[addr]
                     if census_mod.in_pinned_fdes(s))
        ok &= check(f"lea in-packet {addr:#x}", got == sorted(want))
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
    # Template differences: no map-find helper call and no move-assign
    # call anywhere in the pinned FDEs.
    for target in census_mod.EXPECTED_E8_NOT_IN_PACKET:
        got = census_mod.scan_e8_callers(data, target)
        got_in = sorted(s for s in got
                        if census_mod.in_pinned_fdes(s))
        ok &= check(f"no in-packet E8 caller of {target:#x}",
                    got_in == [], f"{[hex(x) for x in got_in]}")

    # Vtable slots + typeinfo.
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
    ok &= check("control-block vtable length 6 (5 slots + trailing zero)",
                census_mod.vtable_len(data, secs, relocs,
                                      census_mod.CTRL_VTABLE) == 6)
    ok &= check("trailing vtable slot is zero",
                census_mod.vtable_slot(data, secs, relocs,
                                       census_mod.CTRL_VTABLE, 5) == 0)
    ok &= check("string ctor copies share first 16 bytes",
                read_va(data, secs, census_mod.STR_CTOR, 16)
                == read_va(data, secs, census_mod.STR_CTOR_OTHER, 16))

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
        str(ROOT / "tests"), pattern="test_filter_policy_dispatch_115.py")
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=0).run(suite)
    ok &= check("model tests", result.wasSuccessful(),
                f"{result.testsRun} run, {len(result.failures)} failures, "
                f"{len(result.errors)} errors")

    print(f"\n{sum(1 for _, p, _ in CHECKS if p)}/{len(CHECKS)} checks passed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
