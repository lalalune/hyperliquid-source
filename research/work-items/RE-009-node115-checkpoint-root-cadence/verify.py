"""Verify the selected #115 checkpoint root cadence against the pinned ELF."""
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKET.parents[2] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__, "run without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {item["name"]: item for item in parse_sections(data)}

    def at(name, address, length):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + length <= section["size"]
        offset = section["offset"] + delta
        return data[offset:offset + length]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(at(".eh_frame", frame["va"], frame["size"]), frame["va"])
    indexed = {row["entry"]: row["end"] for row in fdes}
    entries = (0x31050E0, 0x2FD7260, 0x32CAF70, 0x3C2E860, 0x5A07EC0)
    bounds = [(entry, indexed[entry]) for entry in entries]
    windows = {}
    for line in (PACKET / "windows.txt").read_text().splitlines():
        address, encoding, _ = line.split("\t", maxsplit=2)
        address = int(address, 16)
        raw = bytes.fromhex(encoding)
        assert any(start <= address < address + len(raw) <= end for start, end in bounds)
        assert address not in windows and at(".text", address, len(raw)) == raw
        windows[address] = raw

    def edge(address, opcode):
        raw = windows[address]
        assert raw[:-4] == bytes.fromhex(opcode)
        return address + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    def operand(address, opcode):
        prefix = bytes.fromhex(opcode)
        raw = windows[address]
        assert raw[:-4] == prefix
        return int.from_bytes(raw[-4:], "little")

    table = edge(0x2FD7444, "4c8d3d")
    index = int.from_bytes(at(".rodata", table + 4 * 58, 4), "little", signed=True)
    assert table + index == 0x2FD8149
    assert at(".rodata", edge(0x2FDFE88, "488d05"), 3) == b"msc"
    assert edge(0x2FD8164, "e8") == 0x31050E0
    assert at(".rodata", edge(0x31078CD, "488d05"), 3) == b"aci"
    assert edge(0x3105B2E, "0f85") == 0x31078CD
    assert edge(0x3105B37, "e8") == 0x45A9070
    assert operand(0x3105B56, "48898424") == operand(0x3106952, "4c8b8c24") == 0x270
    assert operand(0x310695D, "41b8") == 1000
    assert windows[0x3106963] == bytes.fromhex("4d0f45c1")
    size = operand(0x3106B15, "ba")
    assert size == 0xF8
    offset = operand(0x3106A8A, "4c898424") - operand(0x3106B0D, "488db424")
    assert offset == 0xC0 and offset + 8 <= size

    def copy(position, source, destination, size):
        assert source <= position and position + 8 <= source + size
        return destination + position - source

    position = operand(0x2FD8157, "488dbc24") + offset
    position = copy(position, operand(0x2FD81A7, "488db424"),
                    operand(0x2FD819A, "488dbc24"), operand(0x2FD81A2, "ba"))
    assert edge(0x2FD81AF, "ff15") == 0x64DF508
    position = copy(position, operand(0x2FD81F3, "488db424"),
                    operand(0x2FD8200, "488dbc24"), operand(0x2FD81FB, "ba"))
    assert edge(0x2FD8208, "e9") == 0x2FD77CF
    assert edge(0x2FD77CF, "ff15") == 0x64DF508
    position = copy(position, operand(0x2FE4645, "488db424"),
                    operand(0x2FE4632, "488dbb"), operand(0x2FE4640, "ba"))
    assert position == 0x1EA8

    assert edge(0x32CB0DC, "e8") == 0x2FD7260
    position += operand(0x32CB0CC, "488dbc24")
    position = copy(position, operand(0x32CB221, "488db424"),
                    operand(0x32CB229, "488dbc24"), operand(0x32CB231, "ba"))
    position = copy(position, operand(0x32CB79F, "488db424"), 0, operand(0x32CB7A7, "ba"))
    assert position == 0x1EA8
    assert edge(0x32CB236, "ff15") == edge(0x32CB7AC, "ff15") == 0x64DF508
    position = copy(position, operand(0x3C2EFF5, "498db6"),
                    operand(0x3C2EFE9, "488dbb"), operand(0x3C2EFF0, "ba"))
    assert position == operand(0x5A07F85, "488b8e") == 0x39C8
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: msc.aci uses default 1000 and reaches decoded +0x1ea8, materialized +0x39c8")



if __name__ == "__main__":
    main()
