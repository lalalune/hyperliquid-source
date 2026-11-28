"""Verify selected #115 replica export coordinates and the offline reader."""
import hashlib
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame
from replica_record import Coordinates, parse_coordinates, select_height


def main():
    assert __debug__, "run without -O"
    data = (ROOT / TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {row["name"]: row for row in parse_sections(data)}

    def at(name, address, width):
        section = sections[name]
        displacement = address - section["va"]
        assert 0 <= displacement <= displacement + width <= section["size"]
        offset = section["offset"] + displacement
        return data[offset:offset+width]

    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(at(".eh_frame", eh["va"], eh["size"]), eh["va"])
    bounds = {(row["entry"], row["end"]) for row in fdes}
    assert {(0x4d6d740, 0x4d6d886), (0x4d6d5c0, 0x4d6d73d)} <= bounds
    for address, field in (
        (0x4d6d777, b"abci_block"),
        (0x4d6d7a4, b"resps"),
        (0x4d6d7ca, b"height"),
        (0x4d6d625, b"signed_action_bundles"),
        (0x4d6d656, b"round"),
        (0x4d6d680, b"parent_round"),
    ):
        code = at(".text", address, 7)
        assert code[:3] == bytes.fromhex("488d35")
        literal = address + 7 + struct.unpack("<i", code[3:])[0]
        assert at(".rodata", literal, len(field)) == field
    assert at(".text", 0x50e307b, 4) == bytes.fromhex("c604030a")
    assert at(".text", 0x506e2f6, 7).endswith(b"null")
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}, six writer labels, explicit null and newline")

    lines = (HERE / "synthetic.jsonl").read_text().splitlines()
    assert select_height(lines, 42) == Coordinates(42, 1300, 998, 0, False)
    assert select_height(lines, 43) == Coordinates(43, 1400, 1300, 0, True)
    assert select_height(lines, 998) is None
    try:
        select_height(lines + [lines[1]], 42)
    except ValueError as error:
        assert str(error) == "ambiguous replica height 42"
    else:
        raise AssertionError("duplicate height was accepted")
    for changed, expected in (
        (lines[1].replace('"height":42', '"height":true'), "height must be"),
        (lines[1].replace('"height":42', '"height":42,"height":43'), "duplicate field"),
        (lines[1].replace('"resps":null,', ""), "missing resps"),
    ):
        try:
            parse_coordinates(changed)
        except ValueError as error:
            assert expected in str(error)
        else:
            raise AssertionError(f"accepted changed record: {changed}")
    print("PASS: three distinct coordinates, missing/duplicate height and response-presence controls")


if __name__ == "__main__":
    main()
