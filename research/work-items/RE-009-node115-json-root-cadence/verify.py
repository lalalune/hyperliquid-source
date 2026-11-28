"""Verify the selected #115 JSON checkpoint root cadence against the pinned ELF."""
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKET.parents[2] / "tools"))

from abci_state_read115 import HEIGHT_OPERANDS
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
    entries = (0x400CEC0, 0x3EFB050, 0x3C2E860, 0x5A07EC0)
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

    def entry(table, index):
        relative = int.from_bytes(at(".rodata", table + 4 * index, 4), "little", signed=True)
        return table + relative

    assert entry(edge(0x3EFB236, "488d1d"), 58) == 0x3EFBA62
    assert at(".rodata", edge(0x3F06EB3, "488d05"), 3) == b"msc"
    assert edge(0x3EFBAA8, "0f83") == 0x3EFD264
    assert edge(0x3EFD286, "e8") == 0x400CEC0
    assert entry(edge(0x400D0E7, "488d0d"), 11) == 0x400D161
    assert at(".rodata", edge(0x400F0AE, "488d05"), 3) == b"aci"
    assert edge(0x400D16A, "0f85") == 0x400F080
    assert edge(0x400D19B, "0f83") == 0x400DA4E
    assert edge(0x400DA69, "e8") == 0x3FD23D0
    assert operand(0x400DA6E, "48899424") == operand(0x400E627, "4c8b9424") == 0x90
    assert operand(0x400E58E, "be") == 1000
    assert windows[0x400E632] == bytes.fromhex("490f45f2")

    def copy(position, source, destination, size):
        assert source <= position and position + 8 <= source + size
        return destination + position - source

    position = operand(0x400E701, "4889b424")
    position = copy(position, operand(0x400EC85, "488db424"),
                    operand(0x400EC7D, "488dbc24"), operand(0x400EC8D, "ba"))
    position = copy(position, operand(0x400ECAB, "488db424"),
                    operand(0x400ECA3, "488dbc24"), operand(0x400ECB3, "ba"))
    position = copy(position, operand(0x400ED38, "488db424"),
                    operand(0x400ED40, "488dbc24"), operand(0x400ED48, "ba"))
    assert windows[0x400ED79] == bytes.fromhex("488d7b10")
    position = copy(position, operand(0x400ED7D, "488db424"), 0x10, operand(0x400ED85, "ba"))
    assert position == 0xC0
    for call in (0x400EC92, 0x400ECB8, 0x400ED4D, 0x400ED8A, 0x3EFD2BA, 0x3EFE1FF):
        assert edge(call, "ff15") == 0x64DF508

    position += operand(0x3EFD27B, "488dbc24")
    position = copy(position, operand(0x3EFD2B2, "488db424"),
                    operand(0x3EFD2A5, "488dbc24"), operand(0x3EFD2AD, "ba"))
    position = copy(position, operand(0x3EFD2E7, "488db424"),
                    operand(0x3EFD2F4, "488dbc24"), operand(0x3EFD2EF, "ba"))
    assert edge(0x3EFD2FC, "e9") == 0x3EFE1FF
    assert edge(0x3F0BF32, "488b1d") == 0x64DF508
    position = copy(position, operand(0x3F0BF3E, "488db424"),
                    operand(0x3F0BF2B, "498dbd"), operand(0x3F0BF39, "ba"))
    assert position == 0x1EA8

    bulk = {}
    for name, address, opcode, width, _ in HEIGHT_OPERANDS:
        if not name.startswith(("nested_", "outer_")):
            continue
        prefix = bytes.fromhex(opcode)
        raw = at(".text", address, len(prefix) + width)
        assert raw.startswith(prefix)
        bulk[name] = int.from_bytes(raw[len(prefix):], "little")
    position += bulk["nested_child_buffer"]
    for number in range(1, 3):
        prefix = f"nested_copy{number}_"
        position = copy(position, bulk[prefix + "source"], bulk[prefix + "dest"], bulk[prefix + "size"])
    assert position == 0x1EA8 and position + 8 <= bulk["outer_copy_size"]
    position = copy(position, operand(0x3C2EFF5, "498db6"),
                    operand(0x3C2EFE9, "488dbb"), operand(0x3C2EFF0, "ba"))
    assert position == operand(0x5A07F85, "488b8e") == 0x39C8
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: selected JSON msc.aci default and projection +0xc0 -> +0x1ea8 -> +0x39c8")



if __name__ == "__main__":
    main()
