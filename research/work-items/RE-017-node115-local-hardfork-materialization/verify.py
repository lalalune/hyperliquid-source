"""Verify the local MessagePack hardfork pair through startup materialization."""
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
    entries = (0x1AC8460, 0x1850600, 0x199CE60, 0x1B44F30, 0x26A3610, 0x2CC1120, 0x3C13610, 0x3C2E860)
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

    def encode(address, prefix, displacement=None):
        expected = bytes.fromhex(prefix)
        if displacement is not None:
            expected += displacement.to_bytes(4, "little")
        assert windows[address] == expected, hex(address)

    def stack_move(load, load_opcode, source, store, store_opcode, dest):
        encode(load, load_opcode, source)
        encode(store, store_opcode, dest)

    # The initial stage at +0x1810 is the pair from the local Context packet.
    stack_move(0x1AC9EE4, "0f288424", 0x1810, 0x1AC9EEC, "0f298424", 0x1830)
    encode(0x1ACCA31, "0f288424", 0x1830)
    encode(0x1ACCA39, "0f29442470")
    encode(0x1ACCAFC, "0f28442470")
    encode(0x1ACCB01, "0f298424", 0x580)
    stack_move(0x1ACCB27, "0f288424", 0x580, 0x1ACCB2F, "0f118424", 0x1C88)
    encode(0x1ACCB72, "488dbc24", 0x1C98)
    assert edge(0x1ACCCA4, "0f85") == 0x1ACA05C
    encode(0x1AC84B0, "4889fb")
    encode(0x1ACA063, "488db424", 0x1C70)
    encode(0x1ACA06B, "ba", 0xBA0)
    encode(0x1ACA070, "4889df")
    assert edge(0x1ACA073, "ff15") == 0x64DF508
    locus_pair = 0x1C88 - 0x1C70
    assert locus_pair + 16 <= 0x1C98 - 0x1C70

    # The inner Exchange retains the prefix separately from its +0x28 tail.
    encode(0x1850C5F, "488dbc24", 0xBF8)
    assert edge(0x1850C6C, "e8") == 0x1AC8460
    encode(0x1850C79, "488d8424", 0xC00)
    encode(0x1850C84, "0f104810")
    assert 0xBF8 + locus_pair == 0xC00 + 0x10
    encode(0x1850C90, "0f298c24", 0x6B0)
    encode(0x1850CE4, "0f288c24", 0x6B0)
    encode(0x1850CEC, "488d8424", 0x4A80)
    encode(0x1850CF4, "0f114810")
    encode(0x1850D08, "488dbc24", 0x4AA0)
    assert 0x4A80 + 0x10 + 16 == 0x4AA0
    encode(0x1853C4A, "488dbc24", 0x2CC0)
    encode(0x1853C52, "488db424", 0x4A78)
    encode(0x1853C5A, "ba", 0xBA0)
    assert edge(0x1853C5F, "ff15") == 0x64DF508
    encode(0x185D566, "488dbc24", 0xBF8)
    encode(0x185D56E, "488db424", 0x2CC0)
    encode(0x185D576, "ba", 0xBA0)
    encode(0x185D57B, "ffd5")
    encode(0x185DB74, "488db424", 0xBF8)
    encode(0x185DB71, "4889df")
    encode(0x185DB6C, "ba", 0x10E8)
    encode(0x185DB7C, "ffd5")
    assert edge(0x185D550, "488b2d") == 0x64DF508
    encode(0x185066B, "4889fb")
    inner_pair = 0x4A80 + 0x10 - 0x4A78
    assert inner_pair == locus_pair and inner_pair + 16 <= min(0xBA0, 0x10E8)

    # The outer Exchange preserves the second prefix lane and then boxes it.
    encode(0x199CFBC, "488dbc24", 0x4060)
    assert edge(0x199CFCC, "e8") == 0x1850600
    stack_move(0x199CFE9, "0f108424", 0x4078, 0x199CFF1, "0f298424", 0x80B0)
    stack_move(0x199D135, "660f6f8c24", 0x80B0, 0x199D147, "f30f7f8c24", 0x9810)
    encode(0x199D150, "4c89bc24", 0x97F8)
    assert 0x4078 - 0x4060 == 0x9810 - 0x97F8 == inner_pair
    assert edge(0x199D161, "0f84") == 0x199D687
    encode(0x199D687, "488dbc24", 0x1098)
    encode(0x199D68F, "488db424", 0x97F8)
    encode(0x199D697, "ba", 0x27A8)
    assert edge(0x199D69C, "ff15") == 0x64DF508
    encode(0x199D6B6, "488db424", 0x1098)
    assert edge(0x199D6BE, "e9") == 0x199D758
    encode(0x199D758, "ba", 0x27A8)
    assert edge(0x199D760, "ff15") == 0x64DF508
    assert edge(0x1B45512, "e8") == 0x199CE60
    assert edge(0x1B4551F, "0f85") == 0x1B450CF
    encode(0x1B450DC, "4c8da424", 0xA8)
    assert edge(0x1B450E7, "4c8b2d") == 0x64DF508
    encode(0x1B4510A, "ba", 0x27A8)
    encode(0x1B4510F, "4889442438")
    encode(0x1B45114, "4889c7")
    encode(0x1B45117, "4c89e6")
    encode(0x1B4511A, "41ffd5")

    # Follow the same allocated pointer into the local materializer.
    encode(0x1B45CE5, "488b442438")
    assert edge(0x1B45CED, "0f85") == 0x1B4603A
    encode(0x1B4603A, "48898424", 0x90)
    encode(0x1B46042, "c684248800000009")
    encode(0x1B46060, "0f108424", 0x88)
    encode(0x1B46074, "0f1103")
    assert edge(0x26A38AA, "e8") == 0x1B44F30
    encode(0x26A389E, "488d7c2468")
    encode(0x26A38AF, "807c246809")
    encode(0x26A38B6, "488b5c2470")
    encode(0x26A37F6, "4889da")
    assert edge(0x2CC1249, "e8") == 0x26A3610
    encode(0x2CC124E, "4989d7")
    assert edge(0x2CC1253, "0f84") == 0x2CC15BA
    encode(0x2CC19E4, "4c89ff")

    slots = sections[".rela.dyn"]
    resolved = {location: value for location, kind, value in struct.iter_unpack(
        "<QQq", at(".rela.dyn", slots["va"], slots["size"])
    ) if kind == 8}
    assert resolved[edge(0x2CC19EA, "ff15")] == 0x3C13610
    encode(0x3C1365C, "4889fb")
    encode(0x3C1365F, "4889e7")
    encode(0x3C13662, "4889de")
    assert resolved[edge(0x3C13665, "ff15")] == 0x3C2E860
    encode(0x3C2E8A7, "4989f6")
    encode(0x3C2E8AA, "4889fb")
    assert edge(0x3C2EC6A, "4c8b2d") == 0x64DF508
    encode(0x3C2EFFF, "ba", 0xBA0)
    encode(0x3C2F004, "4889df")
    encode(0x3C2F007, "4c89f6")
    encode(0x3C2F00A, "41ffd5")
    encode(0x3C1367B, "4889e6")
    encode(0x3C1367E, "ba", 0x42C8)
    encode(0x3C13683, "4889c7")
    encode(0x3C13686, "4989c6")
    assert edge(0x3C13689, "ff15") == 0x64DF508
    encode(0x3C1369F, "4c89f0")
    encode(0x2CC19F4, "498986", 0xE0)
    assert inner_pair + 16 <= min(0x27A8, 0xBA0, 0x42C8)

    print(f"PASS: pinned #115 {TARGET_SHA256}, {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: local Context staging pair follows the selected Locus and Exchange returns")
    print("PASS: allocated decoder result retains the pair at +0x18/+0x20")
    print("PASS: local startup materializer copies the same offsets before the optional rewrite")


if __name__ == "__main__":
    main()
