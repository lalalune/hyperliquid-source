#!/usr/bin/env python3
"""Statically verify the node #115 TWAP heap selector and its downstream calls."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

import capstone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records

PIN = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
# (selector start, batch consumer start, slice target)
FAMILY = [
    (0x2D31530, 0x231C6B0, 0x2DD4530),
    (0x2D319C0, 0x231CC30, 0x2DD34F0),
    (0x5A15290, 0x5B315B0, 0x5A33760),
    (0x5A15720, 0x5B2FD20, 0x5A31640),
    (0x5A15BB0, 0x5B2EE50, 0x5A32BE0),
    (0x5A16040, 0x5B2F650, 0x5A305E0),
]


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def inspect(data):
    require(hashlib.sha256(data).hexdigest() == PIN, "target digest")
    sects = sections(data)
    text, = [s for s in sects if s["name"] == ".text"]
    _, fdes = eh_frame_records(data, sects)
    ends = {f["start"]: f["end"] for f in fdes}
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def body(start):
        end = ends[start]
        require(text["address"] <= start < end <= text["address"] + text["size"], "text bounds")
        offset = text["offset"] + start - text["address"]
        code = data[offset:offset + end - start]
        rows = {r.address - start: (r.mnemonic, r.op_str) for r in decoder.disasm(code, start)}
        return rows, hashlib.sha256(code).hexdigest()

    result = []
    for start, consumer, slice_target in FAMILY:
        rows, digest = body(start)
        require(ends[start] == start + 0x48D, "selector extent")

        def expect(offset, mnemonic, operands):
            require(rows[offset] == (mnemonic, operands), f"{start + offset:#x}: {mnemonic} {operands}")

        def branch(offset, mnemonic, destination):
            expect(offset, mnemonic, hex(start + destination))

        for off, op in [(0x259, "setle"), (0x26a, "setbe")]:
            expect(off, op, "al")
        branch(0x25c, "jne", 0x355)
        branch(0x26d, "jne", 0x355)
        branch(0x27b, "jbe", 0x359)
        branch(0x281, "jmp", 0x3b5)
        branch(0x357, "je", 0x3b5)
        branch(0x24b, "jne", 0x340)
        pop = 0x24B90A0 if start < 0x5000000 else 0x4ECAE60
        for off in (0x90, 0x34b, 0x364):
            expect(off, "call", hex(pop))
        branch(0x350, "jmp", 0x95)
        expect(0x388, "shl", "rcx, 5")
        expect(0x390, "mov", "dword ptr [rax + rcx + 0x10], edx")
        expect(0x399, "movups", "xmmword ptr [rax + rcx], xmm0")
        expect(0x39d, "mov", "qword ptr [rax + rcx + 0x18], r12")
        branch(0x3af, "jne", 0xa0)
        expect(0x44d, "call", hex(consumer))
        consumer_rows, consumer_digest = body(consumer)
        calls = [hex(consumer + off) for off, row in consumer_rows.items()
                 if row == ("call", hex(slice_target))]
        require(len(calls) == 2 and slice_target in ends, "two direct calls to slice FDE")
        result.append({"selector": hex(start), "end": hex(ends[start]), "sha256": digest,
                       "pop": hex(pop), "consumer": hex(consumer), "consumer_end": hex(ends[consumer]),
                       "consumer_sha256": consumer_digest, "slice": hex(slice_target), "call_sites": calls})
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    args = parser.parse_args()
    print(json.dumps(inspect(args.target.read_bytes()), indent=2))
