"""Verify the selected #115 context identifier codec against the pinned ELF."""
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
    entries = (0x30D1C60, 0x4D93030, 0x4E0DD00)
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

    for name, offset, call, staged, reload, store, load, key, size, writer in (
        (b"next_oid", 0x38, 0x30D2C3D, 0x30D2C55, 0x30D31C2, 0x30D31CA,
         0x4D93288, 0x4D9328C, 0x4D93298, 0x4D932A0),
        (b"next_lid", 0x40, 0x30D2CE5, 0x30D2CFD, 0x30D31CE, 0x30D31D6,
         0x4D932B0, 0x4D932B4, 0x4D932C0, 0x4D932C8),
        (b"next_twap_id", 0x48, 0x30D2B95, 0x30D2BAD, 0x30D31DA, 0x30D31E2,
         0x4D932D8, 0x4D932DC, 0x4D932E8, 0x4D932F0),
    ):
        assert edge(call, "ff15") == 0x64E2580
        assert windows[staged][:4] == bytes.fromhex("48898c24")
        assert windows[reload][:4] == bytes.fromhex("488b8424")
        assert windows[staged][4:] == windows[reload][4:]
        assert windows[store] == bytes.fromhex("488943") + bytes([offset])
        assert windows[load] == bytes.fromhex("4d8b47") + bytes([offset])
        assert windows[size] == b"\xb9" + len(name).to_bytes(4, "little")
        assert at(".rodata", edge(key, "488d15"), len(name)) == name
        assert edge(writer, "e8") == 0x4E0DD00

    assert windows[0x30D2EEE] == bytes.fromhex("31c0")
    assert windows[0x30D2F04] == bytes.fromhex("f684240801000001")
    assert windows[0x30D2F14] == bytes.fromhex("480f44c8")
    assert windows[0x30D2F18] == bytes.fromhex("48898c2448010000")
    assert edge(0x30D316F, "0f84") == 0x30D3637
    assert edge(0x30D317D, "0f84") == 0x30D36E0

    rela = sections[".rela.dyn"]
    relative = {offset: target for offset, info, target in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if info == 8}
    assert relative[0x64E2580] == 0x348E980
    assert edge(0x4E0DD2D, "e8") == 0x57CF860
    assert windows[0x4E0DD40] == bytes.fromhex("4c89f2")
    assert edge(0x4E0DD43, "e8") == 0x57D00B0
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: keyed counters project to +0x38/+0x40/+0x48 and use the unsigned writer")
    print("PASS: absent TWAP stages zero; order and LID use separate missing-field arms")



if __name__ == "__main__":
    main()
