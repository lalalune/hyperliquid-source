"""Check the selected hardfork reset and root visitor paths without executing the ELF."""

import hashlib
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(Path.cwd() / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__, "run without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def at(name, address, length):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + length <= section["size"]
        offset = section["offset"] + delta
        return data[offset:offset + length]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(at(".eh_frame", frame["va"], frame["size"]), frame["va"])
    indexed = {row["entry"]: row["end"] for row in fdes}
    entries = (0x3C2E860, 0x3C12800, 0x2CC1120, 0x55EA030, 0x4E34CE0, 0x54423C0,
               0x5AD07C0, 0x4E1AB10, 0x5AD0940, 0x4D3EAC0)
    bounds = [(entry, indexed[entry]) for entry in entries]
    def matches_window(address, raw):
        return (any(start <= address < address + len(raw) <= end for start, end in bounds)
                and at(".text", address, len(raw)) == raw)

    windows = {}
    for line in (PACKET / "windows.txt").read_text().splitlines():
        address, encoding, _ = line.split("\t", maxsplit=2)
        address = int(address, 16)
        raw = bytes.fromhex(encoding)
        assert address not in windows
        assert matches_window(address, raw)
        windows[address] = raw

    def operand(address, opcode):
        prefix = bytes.fromhex(opcode)
        raw = windows[address]
        assert raw.startswith(prefix) and len(raw) > len(prefix)
        return int.from_bytes(raw[len(prefix):], "little")

    def edge(address, opcode):
        prefix = bytes.fromhex(opcode)
        raw = windows[address]
        assert raw.startswith(prefix) and len(raw) > len(prefix)
        return address + len(raw) + int.from_bytes(raw[len(prefix):], "little", signed=True)

    def raw(address, expected):
        assert windows[address] == bytes.fromhex(expected)

    record_count = operand(0x3C2EFC4, "ba")
    assert record_count == operand(0x3C2EFDA, "ba") == 0xB8
    historical = (operand(0x3C2EFC9, "498db6"), operand(0x3C2EFDF, "498db6"))
    materialized = (operand(0x3C2EFBD, "488dbb"), operand(0x3C2EFD3, "488dbb"))
    assert historical == (0x2278, 0x2330)
    assert materialized == (0x3D98, 0x3E50)
    assert historical[1] - historical[0] == materialized[1] - materialized[0] == record_count
    assert windows[0x3C2EFD0] == windows[0x3C2EFE6] == bytes.fromhex("41 ff d5")

    raw(0x3C128A8, "49 89 d4")
    raw(0x3C128AB, "48 83 f8 01")
    assert edge(0x3C128AF, "0f84") == 0x3C129ED
    assert edge(0x3C128D7, "0f85") == 0x3C12A16
    raw(0x3C1298F, "4c 89 e0")
    raw(0x2CC1AA6, "83 b8 e8 10 00 00 01")
    assert edge(0x2CC1AAD, "0f85") == 0x2CC1CFD
    assert edge(0x2CC1ABE, "0f82") == 0x2CC3DDE
    assert edge(0x2CC1AC4, "0f85") == 0x2CC1CFD

    reset_offsets = tuple(base + 0x90 for base in materialized)
    for opcode, sites in (
        (bytes.fromhex("6641c78424"), (0x3C12959, 0x3C12964)),
        (bytes.fromhex("6641c786"), (0x2CC1CD9, 0x2CC1CE3)),
    ):
        for site, offset in zip(sites, reset_offsets, strict=True):
            assert windows[site] == opcode + struct.pack("<IH", offset, 0)
    assert materialized[-1] + 0x91 == 0x3EE1
    assert operand(0x55F1A42, "410fb68f") == 0x3EE0
    raw(0x55F1A4A, "41 80 bf e1 3e 00 00 00")
    assert edge(0x55F1A52, "74") == 0x55F1A78
    assert operand(0x55F1A54, "410f108f") == 0x3EE2
    assert operand(0x55F1A5C, "410f1097") == 0x3EF2
    raw(0x55F1A74, "b2 01")
    raw(0x55F1A78, "31 d2")
    copy_source = operand(0x55F26F4, "488db424")
    assert operand(0x55F1B23, "888c24") - copy_source == 0x90
    assert operand(0x55F1B2A, "889424") - copy_source == 0x91
    assert operand(0x55F1B41, "0f118424") - copy_source == 0x92
    assert operand(0x55F1B49, "0f118c24") - copy_source == 0xA2
    assert operand(0x55F26ED, "498dbe") == materialized[-1]
    assert operand(0x55F26FC, "ba") == record_count

    pointer_array = operand(0x4E35317, "488dbc24")
    assert edge(0x4E35324, "e8") == 0x54423C0
    for lea, save, load, slot in (
        (0x4E35128, 0x4E3512F, 0x54429C4, 56),
        (0x4E35137, 0x4E3513E, 0x54429E2, 57),
    ):
        assert operand(lea, "498d87") == materialized[slot - 56]
        pointer = operand(save, "48898424") - pointer_array
        assert pointer == 8 * (slot + 15) == operand(load, "488b87")
    vtable = edge(0x54429F1, "488d05")
    assert vtable == 0x64A8818
    assert (operand(0x54429E9, "48898424") - 0x10) // 0x10 == 57
    assert operand(0x54429F8, "48898424") == operand(0x54429E9, "48898424") + 8
    assert edge(0x54435B7, "e8") == 0x57C3B30
    rela = sections[".rela.dyn"]
    relocs = {addr: (kind, target) for addr, kind, target
              in struct.iter_unpack("<QQq", at(".rela.dyn", rela["va"], rela["size"]))}
    assert relocs[edge(0x3C128A2, "ff15")] == (8, 0x3C13520)
    assert relocs[vtable + 0x18] == (8, 0x5AD07C0)
    assert operand(0x5AD0835, "4881c7") == 0x90
    raw(0x5AD083C, "48 89 7c 24 58")
    raw(0x5AD0848, "48 89 4c 24 60")
    assert relocs[edge(0x5AD0841, "488d0d") + 0x18] == (8, 0x5AD0940)
    raw(0x5AD08C1, "48 8d 4c 24 58")
    raw(0x5AD08C6, "48 89 8c 24 b8 00 00 00")
    raw(0x5AD08DA, "48 8d 74 24 68")
    assert edge(0x5AD08E2, "e8") == 0x4E1AB10
    raw(0x4E1AE44, "4c 8b 7d 00")
    raw(0x4E1AE48, "48 8b 5d 08")
    raw(0x4E1AE2A, "ff 53 18")
    raw(0x5AD0960, "48 83 7e 10 02")
    assert edge(0x5AD0999, "ff15") == 0x64DF4F0  # first child, policy byte
    raw(0x5AD099F, "3c 04")
    raw(0x5AD09A3, "48 ff c3")
    raw(0x5AD09A6, "49 83 c6 18")
    assert edge(0x5AD09D4, "e8") == 0x4D3EAC0    # second child, optional digest
    raw(0x4D3EAD3, "80 3f 01")
    assert edge(0x4D3EAD6, "0f85") == 0x4D3EB72
    raw(0x4D3EAF8, "48 ff c7")
    assert edge(0x4D3EB2F, "ff15") == 0x64E4DD0 # present path passes bytes after tag
    absent = edge(0x4D3EBB7, "488d3d")
    assert absent == edge(0x4D3EB94, "488d35") == 0x459348
    assert edge(0x4D3EBC1, "ff15") == 0x64DF538
    assert relocs[0x64DF4F0] == (8, 0x1419D40)
    assert relocs[0x64DF538] == (8, 0x14199B0)
    assert at(".rodata", absent, 8) == bytes(8)

    assert not matches_window(0x3C12964, bytes.fromhex("66 41 c7 84 24 e2 3e 00 00 00 00"))
    assert not matches_window(0x55F1A52, bytes.fromhex("75 24"))
    assert not matches_window(0x4D3EAD3, bytes.fromhex("80 3f 00"))
    print(f"verified {len(windows)} instruction windows, {len(bounds)} FDEs and three negative controls")
    print("both restored trackers: reset writes q/presence pairs, without overwriting either digest region")
    print("ABCI tracker clone skips absent payload; compact root slot 57 uses static absent-value descriptor")


if __name__ == "__main__":
    main()
