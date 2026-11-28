"""Verify the selected #115 MessagePack checkpoint clock framing against the pinned ELF."""
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
    entries = (0x2F6FA30, 0x472E750, 0x472E8C0)
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

    def entry(table, index):
        return table + struct.unpack("<i", at(".rodata", table + index * 4, 4))[0]

    table = edge(0x2F6FB61, "488d05")
    assert [entry(table, marker) for marker in (0xD9, 0xDA, 0xDB)] == [
        0x2F6FE51, 0x2F6FE36, 0x2F6FE6C,
    ]
    assert windows[0x2F6FB52] == bytes.fromhex("80e21f")
    assert edge(0x2F6FB58, "0f82") == 0x2F6FD95
    assert edge(0x2F6FD98, "e9") == 0x2F6FF71
    assert windows[0x2F6FE61] == bytes.fromhex("0fb60a")
    assert edge(0x2F6FE67, "e9") == 0x2F6FF69
    assert edge(0x2F6FE42, "0f83") == 0x2F6FF41
    assert windows[0x2F6FF48] == bytes.fromhex("66c1c208")
    assert edge(0x2F6FE78, "0f83") == 0x2F6FF5D
    assert windows[0x2F6FF67] == bytes.fromhex("0fc9")
    assert windows[0x2F6FF74] == bytes.fromhex("4c29f0")
    assert edge(0x2F6FFC8, "e8") == 0x472E750
    assert edge(0x2F6FFCD, "e9") == 0x2F6FB86

    rela = sections[".rela.dyn"]
    relative = {offset: target for offset, info, target in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if info == 8}
    assert relative[edge(0x2F6FFAA, "ff15")] == 0x16815E0
    assert edge(0x472E817, "4c8d05") == edge(0x472E985, "4c8d05") == 0x6405668
    assert edge(0x472E81E, "4c8d0d") == edge(0x472E98C, "4c8d0d") == 0x6405818
    assert edge(0x472E82F, "e8") == edge(0x472E99B, "e8") == 0x1620BE0
    assert relative[edge(0x472E859, "ff15")] == relative[edge(0x472E9C4, "ff15")] == 0x1627E60
    assert windows[0x472E86A] == bytes.fromhex("89430c")
    assert windows[0x472E872] == bytes.fromhex("48894304")
    assert windows[0x472E876] == bytes.fromhex("c60309")
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in three FDEs")
    print("PASS: fixstr and three explicit length markers converge on the MessagePack Time conversion")
    print("PASS: MessagePack and JSON use the same format table, interpreter, and time constructor")



if __name__ == "__main__":
    main()
