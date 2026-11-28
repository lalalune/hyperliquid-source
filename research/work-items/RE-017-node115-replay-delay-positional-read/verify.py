import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

BOUNDS = {
    (0x32CAF70, 0x32D0916),
    (0x30432A0, 0x304333F),
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
        delta = address - section["va"]
        assert 0 <= delta <= delta + width <= section["size"]
        offset = section["offset"] + delta
        return data[offset:offset + width]

    def check(address, encoded):
        expected = bytes.fromhex(encoded)
        assert read(".text", address, len(expected)) == expected

    def operand(address, encoded):
        prefix = bytes.fromhex(encoded)
        raw = read(".text", address, len(prefix) + 4)
        assert raw.startswith(prefix)
        return struct.unpack("<i", raw[-4:])[0]

    def edge(address, encoded):
        return address + len(bytes.fromhex(encoded)) + 4 + operand(address, encoded)

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", frame["va"], frame["size"]), frame["va"])
    assert BOUNDS <= {(row["entry"], row["end"]) for row in fdes}
    rela = sections[".rela.dyn"]
    relocations = {(s, i, a) for s, i, a in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    assert edge(0x32CFCE9, "e8") == 0x30432A0
    check(0x30432B9, "8b460885c07445ffc8894608488b36")
    check(0x30432AF, "49be0000000000000080")
    check(0x3043305, "4c8933")
    assert edge(0x30432CF, "e8") == 0x33B2A30
    check(0x32CFD61, "4c3b7424187575")
    default = edge(0x32CFD70, "ff15")
    assert (default, 8, 0x3C31160) in relocations
    check(0x3C311D5, "0f57c00f118380000000")
    tracker = operand(0x32CFD68, "488dbc24")
    assert tracker + 0x28 == operand(0x32CFE1A, "488dbc24")

    check(0x33B448A, "837c243800")
    assert edge(0x33B448F, "0f84") == 0x33B481C
    check(0x33B482F, "be04000000")
    assert edge(0x33B4834, "e8") == 0x2F7FE90
    assert edge(0x33B449D, "e8") == 0x46F3CB0
    check(0x33B44A2, "0fb64424503c09")
    check(0x33B44AF, "f20f10442458f20f11442410")
    check(0x33B44BB, "837c243801")
    assert edge(0x33B44C0, "0f85") == 0x33B48EB
    assert edge(0x33B48F5, "e8") == 0x322E740
    check(0x33B45E8, "f20f10442410")
    field = operand(0x33B45EE, "f20f118424") - (operand(0x33B4656, "488db424") - 0x28)
    assert field == 0x88
    assert operand(0x33B4666, "ba") == 0x90
    assert edge(0x33B466B, "ff15") == 0x64DF508
    assert operand(0x33B4994, "ba") == operand(0x33B40B9, "ba") == 0xB8
    assert edge(0x33B49BD, "e9") == 0x33B40B9

    assert operand(0x32D03B8, "488db424") == tracker
    first_copy = operand(0x32D03B0, "488dbc24")
    assert operand(0x32CC0CE, "488db424") == first_copy
    assert operand(0x32CC0C6, "4c8da424") == 0x80A0
    check(0x32CC765, "4c89e641ffd6")
    assert operand(0x32D03C0, "ba") == operand(0x32CC0D6, "ba") == operand(0x32CC760, "ba") == 0xB8
    assembled = operand(0x32CCB66, "488db424")
    placed = operand(0x32CC758, "488dbc24")
    assert placed - assembled + field == 0x23B8
    assert operand(0x32CCB6E, "ba") == 0x27A8
    assert edge(0x32CCB73, "ff15") == 0x64DF508
    print("PASS: four FDEs, outer absent-tracker default, fifth-element count guard, optional sixth-element call")
    print(f"PASS: historical layout {placed:#x} - {assembled:#x} + {field:#x} = 0x23b8")


if __name__ == "__main__":
    main()
