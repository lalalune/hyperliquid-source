import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

BOUNDS = {
    (0x40908E0, 0x4093E93),
    (0x3EFB050, 0x3F0DFAF),
    (0x4000C30, 0x40030F2),
    (0x3C31160, 0x3C3122C),
}


def main():
    assert __debug__, "run Python without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def read(name, address, width):
        section = sections[name]
        displacement = address - section["va"]
        assert 0 <= displacement <= displacement + width <= section["size"]
        offset = section["offset"] + displacement
        return data[offset:offset + width]

    def anchor(address, encoded):
        expected = bytes.fromhex(encoded)
        assert read(".text", address, len(expected)) == expected

    def operand(address, encoded):
        prefix = bytes.fromhex(encoded)
        raw = read(".text", address, len(prefix) + 4)
        assert raw.startswith(prefix)
        return struct.unpack("<i", raw[-4:])[0]

    def rip(address, encoded):
        return address + len(bytes.fromhex(encoded)) + 4 + operand(address, encoded)

    def target(table, index):
        return table + struct.unpack("<i", read(".rodata", table + index * 4, 4))[0]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", frame["va"], frame["size"]), frame["va"])
    assert BOUNDS <= {(row["entry"], row["end"]) for row in fdes}
    rela = sections[".rela.dyn"]
    relative = {s: a for s, i, a in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    ) if i == 8}

    assert rip(0x40909DB, "e8") == 0x3EFB050
    assert target(rip(0x3EFB236, "488d1d"), 57) == 0x3EFC710
    assert rip(0x3EFC718, "0f85") == 0x3F068BF
    assert read(".rodata", rip(0x3F068BF, "488d05"), 4) == b"advt"
    assert rip(0x3EFE187, "e8") == 0x4000C30
    assert target(rip(0x4000E5C, "488d0d"), 4) == 0x40011A4
    assert rip(0x40011AD, "0f85") == 0x4002ACE
    assert read(".rodata", rip(0x4002AFB, "488d05"), 3) == b"adu"
    assert read(".rodata", rip(0x4001F38, "488d05"), 3) == b"adu"
    assert rip(0x4001343, "e8") == 0x3FBC520
    anchor(0x4001348, "83bc24d000000001")
    anchor(0x400135B, "f30f7e8424d8000000")
    scalar = operand(0x4001364, "660fd68424")
    assert operand(0x4002298, "f20f108424") == scalar
    scratch_word = operand(0x40022A1, "f20f118424")
    assert scratch_word - operand(0x4001A29, "488db424") == 0x88
    assert operand(0x4001A31, "ba") == 0xB8
    assert rip(0x4001A36, "ff15") == 0x64DF508
    assert operand(0x4001BAB, "488db424") == 0x230
    assert operand(0x4001BB3, "488dbc24") == operand(0x4001C03, "488db424") == 0x3B0
    assert operand(0x4001BBB, "ba") == operand(0x4001C0B, "ba") == 0xA8
    assert rip(0x4001BC0, "ff15") == rip(0x4001C10, "ff15") == 0x64DF508
    anchor(0x4001BFF, "488d7d10")
    child_word = scratch_word - 0x230 + 0x10
    assert child_word == 0x88
    assert operand(0x3EFE1B5, "488db424") - operand(0x3EFE17C, "488dbc24") == 0x10
    assert operand(0x3EFE1F7, "488dbc24") == 0x2978 + 0x10
    assert rip(0x3EFE1BD, "ff15") == rip(0x3EFE1FF, "ff15") == 0x64DF508

    data_slot = operand(0x3F0BC7C, "488dbc24")
    assert data_slot == operand(0x3F0BC8C, "488dbc24") == operand(0x3F0C3DA, "488db424")
    assert operand(0x3F0BC94, "488db424") == 0x2978
    assert relative[rip(0x3F0BC84, "ff15")] == 0x3C31160
    anchor(0x3C311D5, "0f57c00f118380000000")
    assert operand(0x3F0C3E2, "ba") == 0xB8
    assert rip(0x3F0BF32, "488b1d") == 0x64DF508
    anchor(0x3F0C3E7, "ffd3")
    assert operand(0x3F0C3D3, "498dbd") + child_word == 0x23B8
    print("PASS: four FDEs; JSON Exchange index 57 and tracker index 4")
    print("PASS: parsed delay +0x88 and constructor zero join at historical output +0x23b8")


if __name__ == "__main__":
    main()
