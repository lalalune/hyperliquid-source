"""Verify the selected #115 checkpoint cadence export against the pinned ELF."""
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
    entries = (0x3C13960, 0x3D2F090, 0x3D33060, 0x3D517E0,
               0x3C2F460, 0x3D2C480, 0x3C2DF50, 0x4647FF0)
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

    for call, helper, name in (
        (0x3C15459, 0x3D2F090, 0x3D2F0B7),
        (0x3C2FD8C, 0x3D2C480, 0x3D2C494),
    ):
        assert edge(call, "e8") == helper
        assert at(".rodata", edge(name, "488d35"), 3) == b"msc"
    assert at(".rodata", edge(0x3D3307E, "488d05"), 3) == b"aci"
    assert at(".rodata", edge(0x3C2E1D2, "488d35"), 3) == b"aci"
    assert edge(0x3D2F48B, "e8") == 0x3D33060
    assert edge(0x3D2C4DA, "e8") == 0x3C2DF50

    assert windows[0x3C15447] == bytes.fromhex("4981c7e81d0000")
    assert windows[0x3C2FD7F] == bytes.fromhex("4881c3e81d0000")
    assert windows[0x3D2F47C] == bytes.fromhex("498b97c0000000")
    assert windows[0x3D330A1] == bytes.fromhex("4c89fa")
    assert edge(0x3D330AF, "e8") == 0x3D517E0
    assert windows[0x3C2E1CB] == bytes.fromhex("4881c3c0000000")
    assert windows[0x3C2E1E1] == bytes.fromhex("4889d9")
    assert edge(0x3C2E1E4, "e8") == 0x4647FF0
    assert windows[0x464800C] == bytes.fromhex("488b3b")
    assert edge(0x4648040, "e8") == 0x46EF580
    assert edge(0x4648069, "ff15") == 0x64DF508

    assert edge(0x3D5184A, "e8") == 0x3D51D10
    assert windows[0x3D517F0] == bytes.fromhex("4881fa00010000")
    assert windows[0x3D5183C] == bytes.fromhex("4881fa00000100")
    marker = windows[0x3D51855][-1]
    assert marker == 0xCD
    default_value = 1000
    assert 256 <= default_value < 65536
    encoded_example = bytes([marker]) + default_value.to_bytes(2, "big")
    assert encoded_example == bytes.fromhex("cd03e8")
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: historical +0x1ea8 -> msc.aci through the MessagePack and JSON exporters")
    print(f"PASS: synthetic cadence 1000 payload -> MessagePack {encoded_example.hex()} / JSON {default_value}")



if __name__ == "__main__":
    main()
