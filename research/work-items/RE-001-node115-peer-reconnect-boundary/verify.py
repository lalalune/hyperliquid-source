#!/usr/bin/env python3
"""Static node115 diagnostic-associated route: no captured code execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET = Path("artifacts/node/115/hl-node")
START, END = 0x5a87930, 0x5a87a52
FDE = (0x5a82670, 0x5a89535)
DIAGNOSTIC = b"forward_client_blocks process_client_block_wire error, reconnecting to a new peer: "


def require(ok, label):
    if not ok:
        raise ValueError(label)


class Elf:
    def __init__(self, data):
        self.data = data
        require(data[:6] == b"\x7fELF\x02\x01", "ELF64 little-endian")
        phoff = struct.unpack_from("<Q", data, 32)[0]
        ents, count = struct.unpack_from("<HH", data, 54)
        self.loads = []
        for i in range(count):
            row = struct.unpack_from("<IIQQQQQQ", data, phoff + i * ents)
            if row[0] == 1:
                self.loads.append(row)
        shoff = struct.unpack_from("<Q", data, 40)[0]
        ents, count = struct.unpack_from("<HH", data, 58)
        self.relocations = {}
        self.relocation_offsets = {}
        for i in range(count):
            row = struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * ents)
            if row[1] != 4:  # SHT_RELA
                continue
            require(row[9] == 24, "RELA entry size")
            for off in range(row[4], row[4] + row[5], 24):
                slot, info, addend = struct.unpack_from("<QQq", data, off)
                self.relocations[slot] = (info, addend)
                self.relocation_offsets[slot] = off

    def offset(self, va, size):
        hits = [row[2] + va - row[3] for row in self.loads
                if row[3] <= va and va + size <= row[3] + row[5]]
        require(len(hits) == 1, "unique file-backed VA")
        return hits[0]

    def at(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]


def authenticate(data):
    require(len(data) == 105896032, "target size")
    require(hashlib.sha256(data).hexdigest() == SHA256, "target digest")


def rip(elf, va, opcode):
    require(elf.at(va, len(opcode)) == opcode, "opcode " + hex(va))
    n = len(opcode) + 4
    return va + n + struct.unpack("<i", elf.at(va + len(opcode), 4))[0]


def verify_sites(elf):
    require(rip(elf, START, b"\x48\x8d\x05") == 0x445ff6, "diagnostic xref")
    require(elf.at(0x445ff6, 1) == bytes([83]), "diagnostic preceding byte")
    require(elf.at(0x445ff7, len(DIAGNOSTIC)) == DIAGNOSTIC, "diagnostic bytes")
    require(rip(elf, 0x5a879cb, b"\x48\x8d\x0d") == 0x64b9228, "Location xref")
    info, path_va = elf.relocations[0x64b9228]
    require(info == 8, "Location relative relocation")
    length, line, column = struct.unpack("<QII", elf.at(0x64b9230, 16))
    require((length, line, column) == (21, 254, 37), "Location fields")
    require(elf.at(path_va, length) == b"node/src/nv_stream.rs", "Location source path")
    require(rip(elf, 0x5a879e2, b"\xff\x15") == 0x64e0b18, "indirect call slot")
    require(elf.relocations[0x64e0b18] == (8, 22065936), "call relative relocation")
    require(rip(elf, 0x5a879f0, b"\xe8") == 0x5a4b050, "direct call")
    # Exact native opcode/immediate/displacement obligations, not an emulator.
    sites = {
        0x5a879f5: "66c783a60100000000",  # word owner+0x1a6 = 0
        0x5a879fe: "c683a801000000",      # byte owner+0x1a8 = 0
        0x5a87a05: "4c8bbb20010000",      # r15 = [owner+0x120]
        0x5a87a10: "b10131c0f0410fb04f10",  # first byte cmpxchg input
        0x5a87a20: "41c647680231c9b001f0410fb04f10",  # +0x68=2, release attempt
        0x5a87a35: "48b89a9999999999b93f",  # raw binary64 bits only
        0x5a87a3f: "488983b0010000",      # owner+0x1b0
        0x5a87a46: "c6834002000000",      # owner+0x240 = 0
    }
    for va, encoded in sites.items():
        expected = bytes.fromhex(encoded)
        require(elf.at(va, len(expected)) == expected, "native site " + hex(va))
    require(rip(elf, 0x5a87a1a, b"\x0f\x85") == 0x5a88a6d, "claim contention edge")
    require(rip(elf, 0x5a87a2f, b"\x0f\x85") == 0x5a88a80, "release contention edge")
    require(rip(elf, 0x5a87a4d, b"\xe9") == 0x5a8506f, "continuation edge")
    return {"source_association": "node/src/nv_stream.rs:254:37",
            "source_location_va": hex(0x64b9228),
            "indirect_call_slot": hex(0x64e0b18),
            "indirect_call_addend": hex(22065936),
            "native_obligation_groups": len(sites),
            "diagnostic_bytes": len(DIAGNOSTIC),
            "scope": "diagnostic-associated local stores and edges only"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=TARGET)
    args = parser.parse_args()
    data = args.target.read_bytes()
    authenticate(data)
    elf = Elf(data)
    result = verify_sites(elf)
    frames = subprocess.run(["readelf", "-wf", str(args.target)],
                            check=True, text=True, capture_output=True, timeout=30).stdout
    ranges = [(int(a, 16), int(b, 16)) for a, b in
              re.findall(r"FDE .*?pc=([0-9a-f]+)\.\.([0-9a-f]+)", frames)]
    owners = [row for row in ranges if row[0] <= START and END <= row[1]]
    require(owners == [FDE], "unique native FDE")
    result.update({"target_sha256": SHA256, "target_bytes": len(data),
                   "fde": [hex(x) for x in FDE],
                   "excerpt_va": [hex(START), hex(END)],
                   "excerpt_file_offset": hex(elf.offset(START, END - START)),
                   "excerpt_bytes": END - START,
                   "excerpt_sha256": hashlib.sha256(elf.at(START, END - START)).hexdigest(),
                   "readelf_version": subprocess.check_output(["readelf", "--version"], text=True).splitlines()[0],
                   "captured_code_executed": False})
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
