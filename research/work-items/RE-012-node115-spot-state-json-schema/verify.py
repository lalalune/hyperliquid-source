#!/usr/bin/env python3
"""Reconstruct the spot response field names and JSON writers by reading node #115."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

import capstone
from capstone.x86 import X86_REG_RIP

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
STRUCTS = {"account": 0x2F0EB30, "balance": 0x2F0E8C0, "escrow": 0x2F0E770}
GUARDS = {
    0x2f0eb90: 0x2f0ebb5, 0x2f0ebe4: 0x2f0ec0d, 0x2f0ec10: 0x2f0ec38,
    0x2f0ec45: 0x2f0ec72, 0x2f0ec75: 0x2f0eca2, 0x2f0eca7: 0x2f0ecd3,
    0x2f0e942: 0x2f0e96a, 0x2f0e9ea: 0x2f0ea17, 0x2f0ea1a: 0x2f0ea47,
    0x2f0ea4a: 0x2f0ea77, 0x2f0ea7d: 0x2f0eaa9,
}
CALLS = {0x2efe5a1: 0x2f0eb30, 0x2ebe81c: 0x2f0e8c0, 0x2ebe866: 0x2f0e8c0,
         0x2ec23ec: 0x2f0e770, 0x2ec2436: 0x2f0e770, 0x2ec7471: 0x2eac9e0,
         0x2eacf07: 0x2ee1ee0, 0x2eacf46: 0x2edf980, 0x2ec4225: 0x2edf980}
ADDITIONAL = {
    0x2f0eb8d: ("cmp", "byte ptr [rcx], 0"),
    0x2f0ec38: ("movabs", "r14, 0x8000000000000001"),
    0x2ec736a: ("movabs", "rcx, 0x8000000000000000"),
    0x2ec7386: ("lea", "rdx, [rcx + 1]"),
    0x2ec738a: ("cmp", "rax, rdx"),
    0x2eaca3e: ("mov", "byte ptr [rax + rsi], 0x5b"),
    0x2edf98c: ("movsd", "xmm0, qword ptr [rdi]"),
    0x2edf9b5: ("mov", "byte ptr [rax + rsi], 0x22"),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def measure(data):
    require(hashlib.sha256(data).hexdigest() == TARGET_SHA, "target SHA-256")
    sec = sections(data)
    _, fdes = eh_frame_records(data, sec)
    ends = {f["start"]: f["end"] for f in fdes}
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True

    def span(address, length):
        match, = [s for s in sec if s["type"] != 8 and
                  s["address"] <= address and address + length <= s["address"] + s["size"]]
        offset = address - match["address"] + match["offset"]
        return data[offset:offset + length]

    checks = {pc: ("je", hex(dst)) for pc, dst in GUARDS.items()}
    checks.update({pc: ("call", hex(dst)) for pc, dst in CALLS.items()})
    checks.update(ADDITIONAL)
    bodies, fields = {}, {}
    for start, end in sorted(ends.items()):
        if start not in STRUCTS.values() and not any(start <= pc < end for pc in checks):
            continue
        code = span(start, end - start)
        rows = list(decoder.disasm(code, start))
        require(rows and rows[-1].address + rows[-1].size == end, "complete FDE disassembly")
        bodies[hex(start)] = {"end": hex(end), "sha256": hashlib.sha256(code).hexdigest()}
        for row in rows:
            if row.address in checks:
                require((row.mnemonic, row.op_str) == checks.pop(row.address), hex(row.address))
        name = next((key for key, pc in STRUCTS.items() if pc == start), None)
        if not name:
            continue
        fields[name] = []
        for i, row in enumerate(rows):
            if row.mnemonic != "lea" or not row.op_str.startswith("rsi, [rip"):
                continue
            require(row.operands[1].mem.base == X86_REG_RIP, "RIP-relative literal")
            address = row.address + row.size + row.operands[1].mem.disp
            following = rows[i + 1:i + 7]
            width = next(r.operands[1].imm for r in following if r.mnemonic == "mov" and r.op_str.startswith("edx, "))
            key = span(address, width).decode("ascii")
            if key == "}":
                continue
            writer = next(r for r in following if r.mnemonic == "call")
            fields[name].append({"name": key, "site": hex(row.address), "literal": hex(address),
                                 "writer": hex(writer.operands[0].imm)})
    require(not checks, "unverified selected instructions")
    return {"target_sha256": TARGET_SHA, "fields_in_emission_order": fields, "fdes": bodies}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    args = p.parse_args()
    print(json.dumps(measure(args.target.read_bytes()), indent=2))
