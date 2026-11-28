import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__, "run Python without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def section(name):
        entry = sections[name]
        offset = entry["offset"]
        return data[offset:offset + entry["size"]], entry["va"]

    text, text_base = section(".text")

    def raw(address, size):
        offset = address - text_base
        assert 0 <= offset <= offset + size <= len(text)
        return text[offset:offset + size]

    def check(address, encoded):
        expected = bytes.fromhex(encoded)
        assert raw(address, len(expected)) == expected

    eh, eh_address = section(".eh_frame")
    _, rows = walk_eh_frame(eh, eh_address)
    bounds = {(row["entry"], row["end"]) for row in rows}
    assert {(0x51520F0, 0x51528FB), (0x15ED960, 0x15EDB81)} <= bounds
    check(0x515218D, "f20f1000")
    call = raw(0x51521AA, 6)
    assert call[:2] == b"\xff\x15"
    slot = 0x51521B0 + struct.unpack("<i", call[2:])[0]
    rela, _ = section(".rela.dyn")
    assert (slot, 8, 0x15ED960) in struct.iter_unpack("<QQq", rela)

    # Subsecond path. Bit 31 of the middle word is the rounding bit.
    # The lower discarded bits and quotient parity distinguish an exact half.
    check(0x15EDA92, "b900ca9a3b48f7e14889d14869d700ca9a3b4801d1")
    check(0x15EDAB3, "85c9791f482500feffff89c9ba000000804831ca4809c2"
                      "0f95c04008f80fb6d083e20101fa")
    check(0x15EDAD8, "31c081fa00ca9a3b0f94c00f44d6c3")
    # Fractional part of a value >= 1 second. Bit 51 is the rounding bit.
    check(0x15EDB0B, "b900ca9a3b4889f048f7e1c1e20c4889c648c1ee3409d6")
    check(0x15EDB24, "480fbae033ba00000000732648ba00feffffffff0f004821d0"
                      "48ba00000000000008004839d00f95c04008f00fb6d083e20101f2")
    check(0x15EDB5A, "81fa00ca9a3b400f94c60f44d14889f84801f0c3")
    check(0x51521B0, "89d6b900ca9a3b48f7e14889c189f04801c14883d200")
    check(0x51521C6, "48b8ffffffffffffff7f4839c1480f43c84885d2480f45c8")
    scale, = struct.unpack("<I", raw(0x15EDA93, 4))
    cap, = struct.unpack("<Q", raw(0x51521C8, 8))
    vectors = [
        (0.25e-9, 0), (0.75e-9, 1),
        (1 / 1024, 976_562), (3 / 1024, 2_929_688),
        (1 + 1 / 1024, 1_000_976_562), (1 + 3 / 1024, 1_002_929_688),
        (0.999_999_999_75, 1_000_000_000),
        (10_000_000_000.0, cap),
    ]
    for value, expected in vectors:
        numerator, denominator = value.as_integer_ratio()
        integer, discarded = divmod(numerator * scale, denominator)
        round_bit = (
            2 * discarded > denominator
            or (2 * discarded == denominator and integer % 2 == 1)
        )
        result = min(integer + round_bit, cap)
        assert result == expected
        print(f"{value.hex()} -> {result} ns")
    print("PASS: two FDEs, duration relocation, both rounding paths, carry and cap")


if __name__ == "__main__":
    main()
