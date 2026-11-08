#!/usr/bin/env python3
"""Verification for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-emulated-clock-options-115/verify.py

Checks: artifact digest vs provenance/artifacts.json, MANIFEST.sha256,
excerpt regeneration, FDEs, raw-binary spot bytes, lea/E8 censuses,
Emulated vtable slots, manager typeinfos, semantic-only records,
model tests. Exits non-zero on any failure.
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools"))
import census as C
import export_excerpts as E

DIGEST = C.DIGEST

CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append((name, ok, detail))
    if not ok:
        print(f"FAIL: {name} {detail}")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    data = BIN.read_bytes()
    secs = C.sections(data)
    relocs = C.rela_dyn(data)

    # 1. artifact digest
    check("artifact digest", sha256_file(BIN) == DIGEST, DIGEST[:16])

    # 2. MANIFEST.sha256
    manifest = (HERE / "MANIFEST.sha256").read_text().splitlines()
    ok = True
    for line in manifest:
        digest, name = line.split(None, 1)
        if sha256_file(HERE / name) != digest:
            ok = False
            print(f"FAIL: manifest mismatch {name}")
    check("manifest", ok, f"{len(manifest)} files")

    # 3. excerpt regeneration
    ok = True
    for start, end in E.EXCERPTS:
        want = E.disassemble(start, end)
        got = (HERE / f"fn-{start:x}.txt").read_text()
        if want != got:
            ok = False
            print(f"FAIL: excerpt fn-{start:x}.txt differs")
    check("excerpts regenerate", ok, f"{len(E.EXCERPTS)} files")

    # 4. FDEs
    from fde_extents import eh_frame_records
    _, frames = eh_frame_records(data)
    fdes = {(f["start"], f["end"]) for f in frames}
    ok = all((s, e) in fdes for s, e in C.PINNED_FDES)
    check("FDEs", ok, f"{len(C.PINNED_FDES)} pinned")

    # 5. raw-binary spot bytes
    def va_bytes(va, n):
        return C.read_va(data, secs, va, n)

    def e8_target(site):
        rel = struct.unpack_from("<i", va_bytes(site, 5), 1)[0]
        return site + 5 + rel

    def lea_target(site):
        rel = struct.unpack_from("<i", va_bytes(site, 7), 3)[0]
        return site + 7 + rel

    spot = [
        ("insert E8 0x6029e6b -> 0x5d405b0",
         e8_target(0x6029E6B) == 0x5D405B0),
        ("insert E8 0x6029fff -> 0x5d405b0",
         e8_target(0x6029FFF) == 0x5D405B0),
        ("insert E8 0x602a19a -> 0x5d405b0",
         e8_target(0x602A19A) == 0x5D405B0),
        ("key literal time_elapse_only_sleep",
         va_bytes(0x4476C8, 22) == b"time_elapse_only_sleep"),
        ("key literal mock_sleep",
         va_bytes(0x4331D7, 10) == b"mock_sleep"),
        ("key literal supports_direct_io",
         va_bytes(0x44657E, 18) == b"supports_direct_io"),
        ("init stub bytes + E9 -> initializer",
         va_bytes(0x602E4C0, 4) == bytes.fromhex("f30f1efa")
         and struct.unpack_from("<i", va_bytes(0x602E4C4, 5), 1)[0]
         + 0x602E4C9 == 0x6029D10),
        ("manager 0x6025820 op-0 lea -> typeinfo 0x64d1300",
         lea_target(0x6025840) == 0x64D1300),
        ("manager 0x6025850 op-0 lea -> typeinfo 0x64d1310",
         lea_target(0x6025870) == 0x64D1310),
        ("manager 0x6025880 op-0 lea -> typeinfo 0x64d1320",
         lea_target(0x60258A0) == 0x64D1320),
        ("manager 0x60258b0 op-0 lea -> typeinfo 0x64d1330",
         lea_target(0x60258D0) == 0x64D1330),
        ("bool parser 'true' immediate",
         va_bytes(0x61D14E5, 4) == b"true"),
        ("bool parser 'fals' immediate",
         va_bytes(0x61D14C7, 4) == b"fals"),
        ("bool parser 'e' immediate",
         va_bytes(0x61D14D1, 4) == bytes.fromhex("80780465")),
        ("bool parser '1' immediate",
         va_bytes(0x61D14A3, 2) == bytes.fromhex("3c31")),
        ("bool parser '0' immediate",
         va_bytes(0x61D14F8, 2) == bytes.fromhex("3c30")),
        ("getter 0x6025e50 reads +0x48",
         va_bytes(0x6025E65, 4) == bytes.fromhex("0fb64048")),
        ("getter 0x6026100 reads +0x49",
         va_bytes(0x6026115, 4) == bytes.fromhex("0fb65049")),
        ("setter 0x6026ba0 xchg into +0x48",
         va_bytes(0x6026BEB, 3) == bytes.fromhex("865548")),
        ("setter 0x6026ba0 mov into +0x49",
         va_bytes(0x6026BF2, 3) == bytes.fromhex("884549")),
        ("setter 0x6026ad0 mov into +0x49",
         va_bytes(0x6026B1D, 4) == bytes.fromhex("41884549")),
        ("sleep counter lock-add +0x38",
         va_bytes(0x6025B44, 5) == bytes.fromhex("f083473801")),
        ("sleep offset lock-add +0x40",
         va_bytes(0x6025B73, 5) == bytes.fromhex("f048014740")),
        ("sleep tests +0x49",
         va_bytes(0x6025B49, 4) == bytes.fromhex("807f4900")),
        ("get-current-time tests +0x48",
         va_bytes(0x6025EE9, 4) == bytes.fromhex("0fb64648")),
        ("get-current-time reads +0x30",
         va_bytes(0x6025EF1, 4) == bytes.fromhex("488b4630")),
    ]
    for name, ok in spot:
        check(name, ok)

    # 6. lea censuses
    leas = C.scan_lea_refs(data, list(C.EXPECTED_LEA_FULL)
                           + list(C.EXPECTED_LEA_IN_PACKET))
    for tgt, want in C.EXPECTED_LEA_FULL.items():
        check(f"lea census {tgt:#x}", leas[tgt] == want, str(leas[tgt]))
    for tgt, want in C.EXPECTED_LEA_IN_PACKET.items():
        check(f"lea in-packet {tgt:#x}",
              all(s in leas[tgt] for s in want), str(leas[tgt]))

    # 7. E8 censuses
    for tgt in C.EXPECTED_E8_NONE:
        got = C.scan_e8_callers(data, tgt)
        check(f"E8 none {tgt:#x}", got == [], str(got))
    for tgt, want in C.EXPECTED_E8_CALLERS.items():
        got = C.scan_e8_callers(data, tgt)
        check(f"E8 callers {tgt:#x}", got == want, str(got))
    for tgt, want in C.EXPECTED_E8_IN_PACKET.items():
        got = C.scan_e8_callers(data, tgt)
        check(f"E8 in-packet {tgt:#x}",
              all(s in got for s in want), str(got))

    # 8. E9 stub + .init_array rela
    jumps = C.scan_e9_jumps(data, C.INITIALIZER)
    check("E9 stub -> initializer", jumps == [C.INIT_STUB_JMP], str(jumps))
    init_rela = [a for (o, (_, _, a)) in
                 ((k, v) for k, v in relocs.items())
                 if 0x63F36C8 <= o < 0x63F36C8 + 0x540]
    check(".init_array installs stub", C.INIT_STUB in init_rela)

    # 9. vtable slots + manager typeinfos
    for slot, want in C.EXPECTED_VTABLE_SLOTS.items():
        got = C.vtable_slot(data, secs, relocs, C.EMULATED_VTABLE, slot)
        check(f"vtable slot {slot}", got == want, f"{got:#x}")
    for mgr, (ti, want_name) in C.MANAGER_TYPEINFOS.items():
        got = C.typeinfo_name(data, secs, relocs, ti)
        check(f"manager {mgr:#x} typeinfo", got == want_name)

    # 10. semantic-only records, full digest
    rec = json.loads((HERE / "records.json").read_text())
    blob = json.dumps(rec)
    check("records bound to full node #115 digest",
          rec.get("target", {}).get("sha256", "") == DIGEST)
    check("records have no mnemonic list",
          "mnemonic" not in blob and "opcode" not in blob)

    # 11. model tests
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q",
         str(ROOT / "tests" / "test_emulated_clock_options_115.py")],
        capture_output=True, text=True)
    check("model tests", r.returncode == 0,
          (r.stdout.strip().splitlines() or [""])[-1])

    failed = [c for c in CHECKS if not c[1]]
    print(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
