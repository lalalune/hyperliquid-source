"""Tie the Rust rebuild fold to all selected #115 accumulator arms."""

import csv
from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

LANE_LOOPS = {
    "accounts_full": (0x3D4B190, 0x3D4B1EF),
    "contracts_full": (0x3D4B7B0, 0x3D4B80F),
    "storage_full": (0x3D4AA70, 0x3D4AACF),
    "accounts_tail": (0x3D4B2D0, 0x3D4B32F),
    "contracts_tail": (0x3D4B970, 0x3D4B9CF),
    "storage_tail": (0x3D4ABB0, 0x3D4AC0F),
}
EMPTY_TARGETS = (
    ("accounts", 0x3D4B227, 0x3D4B34C),
    ("contracts", 0x3D4B8CF, 0x3D4B9EC),
    ("storage", 0x3D4AB07, 0x3D4AC2C),
)
INIT_CALLS = (
    ("accounts", 0x3C27FC6, 0x3C27FDF, 0x3D4ACF0),
    ("contracts", 0x3C28586, 0x3C2859F, 0x3D4B410),
    ("storage", 0x3C282A6, 0x3C282BF, 0x3D4A640),
)
RETURN_CALLS = (0x3D4B35C, 0x3D4B9FC, 0x3D4AC3C)


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def section_data(name):
        section = sections[name]
        return image[section["offset"]:section["offset"] + section["size"]]

    _, fdes = walk_eh_frame(section_data(".eh_frame"), sections[".eh_frame"]["va"])
    bounds = {fde["entry"]: fde["end"] for fde in fdes}
    text = section_data(".text")
    text_va = sections[".text"]["va"]

    def text_range(start, length):
        off = start - text_va
        assert 0 <= off < off + length <= len(text)
        return text[off:off + length]

    ranges = {}
    with Path(__file__).with_name("windows.tsv").open() as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            fde, start, end = (int(row[key], 16) for key in ("fde", "start", "end"))
            pinned = bytes.fromhex(row["bytes"])
            assert fde <= start < end <= bounds[fde]
            assert row["name"] not in ranges and text_range(start, end - start) == pinned
            ranges[row["name"]] = pinned

    def target(address, size, width=4):
        raw = text_range(address, size)
        return address + size + int.from_bytes(raw[-width:], "little", signed=True)

    for name, (loop_start, loop_back) in LANE_LOOPS.items():
        assert target(loop_back, 2, 1) == loop_start
        loop = text_range(loop_start, loop_back - loop_start)
        assert loop.count(bytes.fromhex("660ffdc8")) == 1
        assert loop.endswith(bytes.fromhex("4883c008483d00040000"))
        assert bytes.fromhex("ffffffff") in ranges[name]
        assert ranges[name].count(bytes.fromhex("480f43")) >= 2
    for name, branch, output in EMPTY_TARGETS:
        assert target(branch, 6) == output
        assert ranges[name + "_empty_tail"].startswith(bytes.fromhex("488b4c24204885c9"))
        assert bytes.fromhex("ba10080000") in ranges[name + "_return"]
    for name, zero_call, scan_call, scan in INIT_CALLS:
        assert target(zero_call, 6) == 0x64DF750
        assert target(scan_call, 5) == scan
        assert bytes.fromhex("ba100800004c89ef31f6") in ranges[name + "_init"]

    relocations = {slot: (info, addend) for slot, info, addend in
                   struct.iter_unpack("<QQq", section_data(".rela.dyn"))}
    assert all(target(address, 6) == 0x64DF508 for address in RETURN_CALLS)
    for slot, name in ((0x64DF508, b"memcpy\x00"), (0x64DF750, b"memset\x00")):
        info, addend = relocations[slot]
        assert info & 0xFFFFFFFF == 6 and addend == 0
        offset = struct.unpack_from("<I", section_data(".dynsym"), (info >> 32) * 24)[0]
        assert section_data(".dynstr")[offset:offset + len(name)] == name

    print(f"PASS: #115 {TARGET_SHA256}, {len(ranges)} exact windows")
    print("PASS: three zero initializers, six 1,024-lane loops, saturated counter arms and empty tails")


if __name__ == "__main__":
    main()
