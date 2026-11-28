"""Verify the selected #115 JSON time format items against the pinned ELF."""
import hashlib
from pathlib import Path
import struct
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
    entries = (0x3FD2100, 0x472E8C0)
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

    assert edge(0x3FD21D3, "e8") == 0x472E8C0
    assert edge(0x472E99B, "e8") == 0x1620BE0
    start = edge(0x472E985, "4c8d05")
    end = edge(0x472E98C, "4c8d0d")
    assert (end - start) % 24 == 0
    rela = sections[".rela.dyn"]
    relative = {offset: target for offset, info, target in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if info == 8}
    items = []
    for address in range(start, end, 24):
        item = at(".data.rel.ro", address, 24)
        if item[0] == 0:
            length = int.from_bytes(item[16:], "little")
            items.append(at(".rodata", relative[address + 8], length).decode("ascii"))
        elif item[0] == 2:
            assert item[16:] == bytes(8)
            items.append("space")
        else:
            assert item[0] in (4, 5)
            items.append((item[0], item[1]))
    assert items == [
        (4, 0), "space", "-", (4, 6), "space", "-", (4, 7), "space", "T",
        (4, 14), "space", ":", (4, 16), "space", ":", (4, 17), (5, 10), "space",
    ]
    assert windows[0x472E9AE] == bytes.fromhex("4885c9")
    assert windows[0x472E9B3] == bytes.fromhex("4885d2")
    assert windows[0x472E9B1] == bytes.fromhex("743b")
    assert windows[0x472E9B6] == bytes.fromhex("7536")
    assert windows[0x472E9C2] == bytes.fromhex("31d2")
    assert relative[edge(0x472E9C4, "ff15")] == 0x1627E60
    assert windows[0x472E9D4] == bytes.fromhex("89430c")
    assert windows[0x472E9DB] == bytes.fromhex("48894304")
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in two FDEs")
    print(f"PASS: time-format item range {start:#x}..{end:#x} contains {len(items)} items")
    print("Decoded item sequence:", items)
    print("PASS: success requires complete consumption and passes a 12-byte constructed value")



if __name__ == "__main__":
    main()
