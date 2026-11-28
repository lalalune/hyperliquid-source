"""Verify the selected #115 context clock writer against the pinned ELF."""
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
    entries = (0x4D93030, 0x4E0DA40, 0x5307510, 0x526E1A0, 0x57CF860, 0x57D0B20)
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

    for pointer, literal, length, call, offset, key in (
        (0x4D93238, 0x4D9323C, 0x4D93248, 0x4D93250, 0x60, b"time"),
        (0x4D93260, 0x4D93264, 0x4D93270, 0x4D93278, 0x6C, b"prev_time"),
    ):
        assert windows[pointer] == b"\x4d\x8d\x47" + bytes([offset])
        assert windows[length] == b"\xb9" + len(key).to_bytes(4, "little")
        assert at(".rodata", edge(literal, "488d15"), len(key)) == key
        assert edge(call, "e8") == 0x4E0DA40

    assert windows[0x4E0DA4C] == bytes.fromhex("807e0b00")
    assert edge(0x4E0DA61, "e8") == edge(0x53075B8, "e8") == 0x57CF860
    assert edge(0x4E0DA83, "e8") == 0x5307510
    vtable = edge(0x530754F, "488d05")
    assert windows[0x5307581] == bytes.fromhex("be54000000")
    assert windows[0x5307586] == bytes.fromhex("ff5020")
    assert windows[0x530758D] == bytes.fromhex("4983c704")
    assert windows[0x526E1F1] == bytes.fromhex("40883401")
    rela = sections[".rela.dyn"]
    relative = {offset: target for offset, info, target in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if info == 8}
    assert relative[edge(0x5307569, "ff15")] == 0x1628BC0
    assert relative[vtable + 0x20] == 0x526E1A0
    assert relative[edge(0x5307599, "ff15")] == 0x162A760

    assert windows[0x57CF876] == bytes.fromhex("83fa20")
    assert windows[0x57CF87F] == bytes.fromhex("b3a0")
    assert edge(0x57CF8BC, "e8") == 0x57D0B20
    assert windows[0x57D0B49] + windows[0x57D0B4D] == bytes.fromhex("4080e61f4080cea0")
    assert edge(0x57CFBE4, "ff15") == 0x64DF508
    date_time = b"2026-01-02T03:04:05"
    fixstr = bytes([0xA0 | (len(date_time) & 0x1F)]) + date_time
    assert len(date_time) < 32 and fixstr[0] == 0xB3
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: both keys reach the same date / literal T / time formatter and MessagePack string writer")
    print(f"PASS: synthetic fixstr framing only: {fixstr.hex()}")


if __name__ == "__main__":
    main()
