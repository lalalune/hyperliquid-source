import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections


def main():
    assert __debug__, "run Python without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def read(section, address, size):
        entry = sections[section]
        displacement = address - entry["va"]
        assert 0 <= displacement <= displacement + size <= entry["size"]
        offset = entry["offset"] + displacement
        return data[offset:offset + size]

    def text(address, size):
        return read(".text", address, size)

    def rip(address, opcode):
        instruction = text(address, len(opcode) + 4)
        assert instruction.startswith(opcode)
        return address + len(instruction) + struct.unpack("<i", instruction[-4:])[0]

    rela = sections[".rela.dyn"]
    raw = read(".rela.dyn", rela["va"], rela["size"])
    relocs = {address: addend for address, info, addend in struct.iter_unpack("<QQq", raw)
              if info == 8}
    assert text(0x1696BE0, 7) == bytes.fromhex("400fb6c6c1e003")
    pointers = rip(0x1696BE7, b"\x48\x8d\x0d")
    lengths = rip(0x1696BF2, b"\x48\x8d\x0d")
    assert (pointers, lengths) == (0x6408C50, 0x47B450)
    assert text(0x1696C10, 36) == bytes.fromhex(
        "488b5c24084c8b742410488b5424184c896c24404c896424484c8d6424084c89e74c89f6"
    )
    assert relocs[rip(0x1696C34, b"\xff\x15")] == 0x141D8F0
    assert text(0x1696C50, 5) == bytes.fromhex("4c89642430")
    assert rip(0x1696C55, b"\x48\x8d\x05") == 0x155C6E0
    assert text(0x1696C5C, 5) == bytes.fromhex("4889442438")
    assert text(0x155C6E0, 14) == bytes.fromhex("4889f0488b7708488b57104889c7")
    assert relocs[rip(0x155C6EE, b"\xff\x25")] == 0x167FA70
    format_address = rip(0x1696C61, b"\x48\x8d\x35")
    assert relocs[rip(0x1696C70, b"\xff\x15")] == 0x141E3A0
    format_record = b"\xc0\x15/CHECKPOINT_COMPLETE_\xc0\x00"
    assert read(".rodata", format_address, len(format_record)) == format_record
    prefix_length = read(".rodata", format_address + 1, 1)[0]
    prefix = read(".rodata", format_address + 2, prefix_length)
    assert text(0x141D92F, 10) == bytes.fromhex("4883fb100f828b000000")
    assert text(0x141D9C4, 15) == bytes.fromhex("4989c14889d94989c84a8d143931c9")
    assert text(0x141D9E0, 10) == bytes.fromhex("410fb6340c4084f67857")
    ascii_loop = text(0x141D9EA, 22)
    assert ascii_loop == bytes.fromhex("8d7e9f4080ff1a400f92c740c0e7054030f741883c09")
    assert text(0x141DA17, 27) == bytes.fromhex(
        "488b4dd0488b45a048894810488b4dc0488908488b4dc848894808"
    )

    def transform(byte):
        assert byte < 128
        return byte ^ ((int((byte + ascii_loop[2]) % 256 < ascii_loop[6])) << ascii_loop[14])

    assert bytes(map(transform, b"@AZ[\x60az{09")) == b"@AZ[\x60AZ{09"
    expected = [(b"Exchange", b"EXCHANGE"), (b"Rpc", b"RPC"), (b"EvmState", b"EVMSTATE")]
    for selector, (original, uppercase) in enumerate(expected):
        length, = struct.unpack("<Q", read(".rodata", lengths + 8 * selector, 8))
        assert 0 < length < 16
        name = read(".rodata", relocs[pointers + 8 * selector], length)
        assert name == original
        suffix = bytes(map(transform, name))
        assert suffix == uppercase and suffix != name.lower()
        print(f"selector {selector}: {name.decode()} -> {(prefix + suffix).decode()}")
    print("PASS: pinned binary, selector tables, casing instructions, transformed formatter argument")


if __name__ == "__main__":
    main()
