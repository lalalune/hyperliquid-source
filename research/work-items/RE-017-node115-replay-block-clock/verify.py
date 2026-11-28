import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

BOUNDS = {
    (0x5A04E40, 0x5A065F8), (0x5A06600, 0x5A07EB6),
    (0x5483850, 0x5483F43), (0x5483F50, 0x5484663),
    (0x54897E0, 0x548C8E0), (0x5486720, 0x54897E0),
    (0x5AFA030, 0x5AFA1EE),
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

    def check(address, encoded):
        expected = bytes.fromhex(encoded)
        assert read(".text", address, len(expected)) == expected

    def operand(address, prefix):
        opcode = bytes.fromhex(prefix)
        raw = read(".text", address, len(opcode) + 4)
        assert raw.startswith(opcode)
        return struct.unpack("<i", raw[-4:])[0]

    def call(address, target):
        assert address + 5 + operand(address, "e8") == target

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", frame["va"], frame["size"]), frame["va"])
    assert BOUNDS <= {(row["entry"], row["end"]) for row in fdes}
    for header, copy, argument, begin_call, begin in [
        (0x5A04E71, 0x5A04E7D, 0x5A04FD6, 0x5A04FE9, 0x5483850),
        (0x5A0663D, 0x5A06649, 0x5A06798, 0x5A067AD, 0x5483F50),
    ]:
        check(header, "488b4318")
        check(copy, "488b4838")
        check(copy + 12, "8b4840")
        first_slot = operand(copy + 4, "48898c24")
        assert operand(copy + 15, "898c24") == first_slot + 8
        assert operand(argument, "488d9424") == first_slot
        call(begin_call, begin)

    clock_a = read(".text", 0x5483850, 0x83)
    clock_b = read(".text", 0x5483F50, 0x83)
    assert clock_a == clock_b
    check(0x548388A, "8b02413b45600f9ec27519418b5104413b55640f96c2750c"
                      "418b5108413b55687706eb2584d27521")
    check(0x54838B2, "418b54240841895574498b14244989556c498b1149891424418b51084189542408")

    check(0x5A04F5F, "498d84245004000048898424e8000000")
    check(0x5A055A8, "488bb424e8000000")
    call(0x5A055B0, 0x54897E0)
    check(0x54897FB, "4c8b26")
    check(0x548BECD, "498d5c2460")
    check(0x548BF18, "8b430889842428020000488b034889842420020000")
    assert operand(0x548BF2D, "498db424") == 0x3E50
    assert operand(0x548BF3D, "488d9424") == 0x220
    call(0x548BF4B, 0x5AFA030)

    check(0x5A06727, "498d87500400004889442418")
    check(0x5A06DB1, "488b742418")
    call(0x5A06DB6, 0x5486720)
    check(0x548673B, "4c8b26")
    check(0x5486900, "4c89642408")
    check(0x5488D7F, "488b6c2408")
    check(0x5488D8D, "4c8d6560")
    check(0x5488DD7, "418b44240889842428020000498b04244889842420020000")
    assert operand(0x5488DEF, "488db5") == 0x49C0
    assert operand(0x5488DFE, "488d9424") == 0x220
    call(0x5488E0C, 0x5AFA030)
    check(0x5AFA071, "48891424")
    print("PASS: seven FDEs and two 12-byte nested-block-to-begin handoffs")
    print("PASS: 0x83 matching begin bytes; both state clock copies reach shared drain")


if __name__ == "__main__":
    main()
