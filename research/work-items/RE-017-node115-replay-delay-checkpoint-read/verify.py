import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

FDE_BOUNDS = {
    (0x32CAF70, 0x32D0916),
    (0x2FD7260, 0x2FE66A2),
    (0x33B2A30, 0x33B4FD1),
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
        actual = read(".text", address, len(prefix) + 4)
        assert actual.startswith(prefix)
        return struct.unpack("<i", actual[-4:])[0]

    def rip(address, encoded):
        return address + len(bytes.fromhex(encoded)) + 4 + operand(address, encoded)

    def indexed(base, index):
        return base + struct.unpack("<i", read(".rodata", base + 4 * index, 4))[0]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", frame["va"], frame["size"]), frame["va"])
    assert FDE_BOUNDS <= {(row["entry"], row["end"]) for row in fdes}
    rela = sections[".rela.dyn"]
    relocations = {
        address: (info, target)
        for address, info, target in struct.iter_unpack(
            "<QQq", read(".rela.dyn", rela["va"], rela["size"])
        )
    }
    assert rip(0x32CB0DC, "e8") == 0x2FD7260
    table = rip(0x2FD7444, "4c8d3d")
    anchor(0x2FD78B8, "496304874c01f8ffe0")
    assert indexed(table, 57) == 0x2FD925A
    assert read(".rodata", rip(0x2FDF688, "488d05"), 4) == b"advt"
    assert operand(0x2FD9272, "488dbc24") == 0xB38
    assert rip(0x2FD927F, "e8") == 0x33B2A30

    table = rip(0x33B2C3A, "4c8d2d")
    anchor(0x33B2C66, "49634485004c01e8ffe0")
    assert indexed(table, 4) == 0x33B2D6C
    assert read(".rodata", rip(0x33B4A8F, "488d05"), 3) == b"adu"
    assert rip(0x33B2D86, "e8") == 0x46F3CB0
    anchor(0x33B2D93, "4080fd090f8517040000")
    slot = operand(0x33B2DA6, "f20f118424")
    assert operand(0x33B3F9B, "f20f108424") == slot
    word = operand(0x33B3FA4, "f20f118424")
    record = operand(0x33B4088, "488db424")
    assert word - record == 0x88
    assert operand(0x33B4080, "488dbc24") == operand(0x33B40B1, "488db424") == 0x4D0
    assert operand(0x33B4090, "ba") == operand(0x33B40B9, "ba") == 0xB8
    anchor(0x33B2A44, "4889fb")
    anchor(0x33B40BE, "4889df")
    assert rip(0x33B4095, "ff15") == rip(0x33B40C1, "ff15") == 0x64DF508
    assert rip(0x33B3CD3, "e8") == 0x46F3BB0
    assert read(".rodata", rip(0x33B3CBF, "488d35"), 3) == b"adu"

    assert operand(0x2FD92CB, "488db424") == 0xB38 + 0x28
    assert operand(0x2FD92BE, "488dbc24") == operand(0x2FD9317, "488db424") == 0x1F40
    assert operand(0x2FD9324, "488dbc24") == 0x2E38 + 0x28
    assert operand(0x2FD931F, "ba") == 0x90
    assert rip(0x2FD932C, "e9") == 0x2FD77CF
    assert rip(0x2FD77CF, "ff15") == rip(0x2FD92D3, "ff15") == 0x64DF508

    anchor(0x2FE4335, "48398424382e00007516")
    assert operand(0x2FE433F, "488dbc24") == operand(0x2FE4355, "488dbc24") == 0x308
    assert operand(0x2FE435D, "488db424") == 0x2E38
    assert rip(0x2FE436A, "ff15") == 0x64DF508
    default_slot = rip(0x2FE434D, "ff15")
    assert relocations[default_slot] == (8, 0x3C31160)
    anchor(0x3C31165, "4889fb")
    anchor(0x3C311D5, "0f57c0")
    default_store = operand(0x3C311D8, "0f1183")
    assert default_store <= word - record < default_store + 16
    assert rip(0x2FE4639, "488b2d") == 0x64DF508
    assert operand(0x2FE4AAB, "488db424") == 0x308
    assert operand(0x2FE4AB3, "ba") == 0xB8
    anchor(0x2FE4AB8, "ffd5")
    historical = operand(0x2FE4AA4, "488dbb") + word - record
    assert historical == 0x23B8
    print("PASS: 4 FDEs; Exchange index 57, tracker index 4, shared output +0x23b8")
    print("PASS: absent tracker constructor writes binary64 +0.0; omitted adu takes its own field path")


if __name__ == "__main__":
    main()
