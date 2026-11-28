"""Verify the selected #115 two completed-buffer arms composing into the replay codec against the pinned ELF."""
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
    entries = (0x5AB4390, 0x5A806F0)
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

    relative = {
        offset: target
        for offset, info, target in struct.iter_unpack(
            "<QQq", at(".rela.dyn", sections[".rela.dyn"]["va"], sections[".rela.dyn"]["size"])
        )
        if info == 8
    }
    assert windows[0x5AB57A7] == bytes.fromhex("807b5000")
    assert edge(0x5AB57AB, "0f84") == 0x5AB586C
    assert windows[0x5AB57C1] == bytes.fromhex("488b4b28")
    assert relative[edge(0x5AB57D5, "ff15")] == 0x477F8C0
    for address, encoding in (
        (0x5AB5874, "488b6b68"),  # plain base
        (0x5AB5878, "4c8b7370"),  # plain length
        (0x5AB588A, "4c8bb424d0000000"),  # transformed length
        (0x5AB5827, "48896808"),
        (0x5AB582B, "4c897010"),
        (0x5A80C48, "48899388060000"),
        (0x5A80DB8, "488b8b88060000"),
        (0x5A80DE1, "4889ee"),
        (0x5A80DE4, "4c89fa"),
    ):
        assert windows[address] == bytes.fromhex(encoding), hex(address)
    assert windows[0x5A80918][:7] == bytes.fromhex("48c783e8000000")
    assert int.from_bytes(windows[0x5A80918][7:], "little") == 10_000_000
    assert edge(0x5A80DE7, "e8") == 0x5860BB0
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} handoff witnesses in {len(bounds)} FDEs")
    print("PASS: direct and transformed span witnesses, shared producer limit and replay decoder call")


if __name__ == "__main__":
    main()
