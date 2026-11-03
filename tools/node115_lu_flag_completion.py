#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-flag-completion.

Checks, all read-only (the node binary is never executed):
  - binary size and SHA-256
  - both claimed FDE byte sets (full + body-proper SHAs) vs packet hex
  - ret bytes at both body ends
  - 12 opcode spot checks inside the claimed FDEs
  - GOT relocation addends (free target, memmove import, panic Locations)
  - panic message strings in .rodata
  - packet records.json agreement (SHAs, counts, census)
  - whole-.text caller census re-derived by byte scan

Usage: python3 tools/node115_lu_flag_completion.py
Exit 0 on success, 1 on any failure. Prints a JSON summary.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-flag-completion"

TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
TEXT_SIZE = 0x4FD7700


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def text_bytes(data, va_start, va_end):
    return data[TEXT_OFF + (va_start - TEXT_VA):TEXT_OFF + (va_end - TEXT_VA)]


def expect(cond, msg, failures):
    if not cond:
        failures.append(msg)


def parse_relocations(binary):
    """Return {offset: (type, addend_or_symbol)} from `readelf -r`."""
    out = subprocess.run(["readelf", "-r", str(binary)],
                         capture_output=True, text=True, check=True).stdout
    relocs = {}
    for line in out.splitlines():
        m = re.match(
            r"([0-9a-f]+)\s+[0-9a-f]+\s+(R_X86_64_\w+|R_X86_64_GLOB_DAT)"
            r"\s+([0-9a-f]+)?(?:\s+(\S+))?", line)
        if not m:
            continue
        off = int(m.group(1), 16)
        typ = m.group(2)
        val = m.group(3)
        sym = m.group(4) or ""
        relocs[off] = (typ, val, sym)
    return relocs


def scan_e8(data, target):
    hits = []
    for i in range(TEXT_SIZE - 5):
        if data[TEXT_OFF + i] == 0xE8:
            rel = struct.unpack_from("<i", data, TEXT_OFF + i + 1)[0]
            if TEXT_VA + i + 5 + rel == target:
                hits.append(TEXT_VA + i)
    return hits


def verify(binary_path=BINARY, packet_dir=PACKET):
    failures = []
    checks = {}
    data = binary_path.read_bytes()
    records = json.loads((packet_dir / "records.json").read_text())
    flag = records["flag_helper"]
    comp = records["completion_helper"]

    # Binary identity.
    checks["binary_size"] = len(data)
    expect(len(data) == records["binary"]["size"],
           f"binary size {len(data)} != {records['binary']['size']}", failures)
    digest = sha256(data)
    checks["binary_sha256"] = digest
    expect(digest == records["binary"]["sha256"],
           "binary SHA-256 mismatch", failures)

    # FDE byte sets and SHAs.
    for name, rec, hexfile, start, end, body_end in (
        ("flag", flag, "fdeccf20.hex", 0x4DCCF20, 0x4DCD300, 0x4DCD2C0),
        ("completion", comp, "fde86a0.hex", 0x4DA86A0, 0x4DA885B, 0x4DA881B),
    ):
        packet_hex = (packet_dir / hexfile).read_text().strip()
        body = text_bytes(data, start, body_end)
        full = text_bytes(data, start, end)
        expect(len(full) == rec["bytes"],
               f"{name} FDE length {len(full)} != {rec['bytes']}", failures)
        expect(len(body) == rec["body_bytes"],
               f"{name} body length {len(body)} != {rec['body_bytes']}",
               failures)
        expect(sha256(full) == rec["full_sha256"],
               f"{name} full-FDE SHA mismatch", failures)
        expect(sha256(body) == rec["body_sha256"],
               f"{name} body SHA mismatch", failures)
        expect(packet_hex == full.hex(),
               f"{name} packet hex != binary bytes", failures)
        expect(full[body_end - start] == 0xC3,
               f"{name} ret byte != 0xc3", failures)
        checks[f"{name}_bytes"] = len(full)
        checks[f"{name}_instructions_body_plus_tail"] = (
            rec["body_instructions"] + rec["tail_instructions"])

    # Opcode spot checks: (VA, expected bytes).
    spots = [
        (0x4DCD06C, bytes.fromhex("e85fdfa200")),   # call lookup 0x57fafd0
        (0x4DCD07A, bytes.fromhex("49837e183f")),   # cmp [r14+0x18],0x3f
        (0x4DCD04E, bytes.fromhex("48b80000000000000080")),  # movabs sentinel
        (0x4DCD1C4, bytes.fromhex("0fb7b8e6000000")),  # movzx edi,[rax+0xe6]
        (0x4DCD2A9, bytes.fromhex("48893b")),       # mov [rbx],rdi (flag)
        (0x4DCD2C0, bytes.fromhex("c3")),           # flag ret
        (0x4DA86E6, bytes.fromhex("48ff4810")),     # dec [rax+0x10]
        (0x4DA86EA, bytes.fromhex("807c240701")),   # cmp [rsp+0x7],1
        (0x4DA8726, bytes.fromhex("be48010000")),   # mov esi,0x148
        (0x4DA872D, bytes.fromhex("ff156d6d7301")),  # call [GOT 0x64df4a0]
        (0x4DA87EA, bytes.fromhex("4d897e18")),     # mov [r14+0x18],r15
        (0x4DA881B, bytes.fromhex("c3")),           # completion ret
    ]
    for va, want in spots:
        got = text_bytes(data, va, va + len(want))
        expect(got == want, f"spot check at 0x{va:x} mismatch", failures)
    checks["spot_checks"] = len(spots)

    # GOT relocations.
    relocs = parse_relocations(binary_path)
    expect(relocs.get(0x64DF4A0, (None, None, None))[1] == "635de30",
           "free GOT slot 0x64df4a0 addend != 0x635de30", failures)
    typ, _, sym = relocs.get(0x64DF568, (None, None, ""))
    expect(typ == "R_X86_64_GLOB_DAT" and "memmove" in sym,
           "memmove GOT slot 0x64df568 mismatch", failures)
    for slot, want in ((0x649CC20, "4402cd"), (0x649A528, "4344f8"),
                       (0x64A36D0, "430444")):
        expect(relocs.get(slot, (None, None, None))[1] == want,
               f"Location slot 0x{slot:x} addend != 0x{want}", failures)
    checks["relocations_checked"] = 5

    # Panic strings (.rodata file offset == VA).
    expect(data[0x9171B6:0x9171B6 + 20] == b"occupied entry index",
           "occupied-entry message mismatch", failures)
    expect(data[0x913418:0x913418 + 33] == b"assertion failed: self.height > 0",
           "height assertion message mismatch", failures)

    # Caller census re-derived by byte scan.
    text = data
    flag_callers = scan_e8(text, 0x4DCCF20)
    comp_callers = scan_e8(text, 0x4DA86A0)
    expect(sorted(hex(x) for x in flag_callers) ==
           sorted(flag["direct_e8_callers"]),
           f"flag E8 census {flag_callers} != records", failures)
    expect(sorted(hex(x) for x in comp_callers) ==
           sorted(comp["direct_e8_callers"]),
           f"completion E8 census {comp_callers} != records", failures)
    expect(not any(v[1] in ("4dccf20", "4da86a0") for v in relocs.values()),
           "unexpected GOT addend for a claimed FDE", failures)
    checks["flag_e8_callers"] = len(flag_callers)
    checks["completion_e8_callers"] = len(comp_callers)

    # Records agreement for counts.
    expect(flag["total_instructions"] ==
           flag["body_instructions"] + flag["tail_instructions"],
           "flag instruction split mismatch", failures)
    expect(comp["total_instructions"] ==
           comp["body_instructions"] + comp["tail_instructions"],
           "completion instruction split mismatch", failures)

    return {"ok": not failures, "failures": failures, "checks": checks}


def main():
    result = verify()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
