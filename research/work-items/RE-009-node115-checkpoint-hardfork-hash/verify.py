"""Check the selected checkpoint hardfork hash wire paths without executing the ELF."""

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
    entries = (0x4214250, 0x4308E50, 0x33B2A30, 0x322E740, 0x303D1C0, 0x27606D0)
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

    def target(table, index):
        offset = int.from_bytes(at(".rodata", table + index * 4, 4), "little", signed=True)
        return table + offset

    def literal(address, opcode, expected):
        assert at(".rodata", edge(address, opcode), len(expected)) == expected

    def raw(address, expected):
        assert windows[address] == bytes.fromhex(expected)

    raw(0x42143F8, "49 81 c6 90 00 00 00")
    assert edge(0x4214408, "e8") == 0x4308E50
    literal(0x4308E6D, "488d35", b"h")
    literal(0x4308EF1, "488d35", b"q")
    literal(0x4308F57, "488d35", b"l")
    for site in (0x4308E74, 0x4308EF8, 0x4308F5E):
        assert operand(site, "ba") == 1
    for site in (0x4308E7C, 0x4308F00, 0x4308F66, 0x4308FB9):
        assert edge(site, "e8") == 0x41C6110
    assert operand(0x4308E98, "ba") == operand(0x4308ED1, "ba") == 2
    assert edge(0x4308E9D, "e8") == 0x3D4F6D0
    assert edge(0x4308ED6, "e8") == 0x3D50270
    raw(0x4308EE5, "45 0f b6 3c 24")
    boolean_marker = operand(0x4308F29, "4180cf")
    assert (boolean_marker | 0, boolean_marker | 1) == (0xC2, 0xC3)
    assert edge(0x4308F31, "e8") == 0x3D52310
    raw(0x4308F47, "44 88 3c 28")
    raw(0x4308F76, "80 7a 01 01")
    assert edge(0x4308F7A, "75") == 0x4308FDB
    assert operand(0x4308F7C, "4883c2") == 2
    assert operand(0x4308FA0, "be") == 66 and operand(0x4308FA5, "b9") == 32
    raw(0x4308FAA, "45 31 c0")
    assert edge(0x4308FAD, "ff15") == 0x64E4D08
    assert operand(0x4308FFB, "c60430") == 0xC0

    tracker_dispatch = edge(0x33B2C3A, "4c8d2d")
    assert target(tracker_dispatch, 5) == 0x33B2E84
    assert edge(0x33B2E9B, "0f85") == 0x33B4C20
    literal(0x33B4C45, "488d05", b"h")
    assert edge(0x33B2EB3, "e8") == 0x322E740
    raw(0x33B2EB8, "80 bc 24 78 01 00 00 01")
    raw(0x33B2EC6, "0f b6 94 24 79 01 00 00")
    raw(0x33B2ECE, "0f b6 84 24 7a 01 00 00")
    raw(0x33B2ED6, "89 44 24 2c")
    assert edge(0x33B2F98, "e9") == 0x33B2BE3
    raw(0x33B2BE3, "89 54 24 30")
    raw(0x33B3D15, "44 8b 4c 24 30")
    raw(0x33B3D1A, "44 8b 54 24 2c")
    raw(0x33B3D1F, "41 80 f9 02")
    raw(0x33B3D25, "45 31 c9")
    raw(0x33B3D28, "45 31 d2")
    raw(0x33B3FAD, "44 88 8c 24 50 03 00 00")
    raw(0x33B3FB5, "44 88 94 24 51 03 00 00")
    component = operand(0x33B4088, "488db424")
    assert operand(0x33B3FAD, "44888c24") - component == 0x90
    assert operand(0x33B3FB5, "44889424") - component == 0x91
    assert operand(0x33B4090, "ba") == operand(0x33B40B9, "ba") == 0xB8
    assert edge(0x33B4095, "ff15") == edge(0x33B40C1, "ff15") == 0x64DF508

    assert edge(0x322E88F, "e8") == 0x303D1C0
    table = edge(0x322E8AD, "4c8d3d")
    assert operand(0x303D6C7, "3c") == ord("l")
    assert operand(0x303D6D2, "3c") == ord("q")
    raw(0x303D6CE, "28 ca")
    raw(0x303D6D0, "31 f6")
    raw(0x303D6D7, "0f 44 ce")
    assert target(table, 0) == 0x322F12A and target(table, 1) == 0x322F244
    assert edge(0x322F1A9, "ff15") == 0x64E2590
    assert operand(0x322F2FE, "3c") == 0xC0
    assert edge(0x322F300, "74") == 0x322F37B
    literal(0x322F308, "488d15", b"AbciDigest")
    assert operand(0x322F314, "b9") == len(b"AbciDigest")
    assert edge(0x322F319, "e8") == 0x2F52FA0
    raw(0x322F4C2, "88 5c 24 09")
    raw(0x322F4C6, "40 88 6c 24 0a")

    raw(0x2760742, "80 bb 90 00 00 00 00")
    raw(0x276075C, "c6 82 91 00 00 00 01")
    assert operand(0x2760771, "f30f7f82") == 0x92
    assert operand(0x2760779, "f30f7f8a") == 0xA2
    def stack_operand(address):
        raw = windows[address]
        width = 1 if raw[-2] == 0x24 else 4
        return int.from_bytes(raw[-width:], "little")

    # Run the selected parsed-payload copies on uniquely numbered source bytes.
    # Widths are the scalar byte/word/dword/qword widths in windows.txt.
    source = operand(0x33B2EDA, "488d8c24")
    memory = {source + i: i for i in range(32)}
    for width, src, dst in (
        (1, source + 4, stack_operand(0x33B2EE6)),
        (4, source, stack_operand(0x33B2EEF)),
        (1, stack_operand(0x33B2EF6), stack_operand(0x33B2EFE)),
        (1, stack_operand(0x33B2F02), stack_operand(0x33B2F0A)),
        (2, source + 11, stack_operand(0x33B2F12)),
        (4, source + 7, stack_operand(0x33B2F1D)),
        (8, stack_operand(0x33B2F24), stack_operand(0x33B2F2C)),
        (8, source + 21, stack_operand(0x33B2F38)),
        (4, source + 28, stack_operand(0x33B2F43)),
        (4, stack_operand(0x33B2F4A), stack_operand(0x33B2F51)),
        (2, stack_operand(0x33B2F58), stack_operand(0x33B2F60)),
        (4, stack_operand(0x33B2F68), stack_operand(0x33B2F6F)),
        (8, stack_operand(0x33B2F76), stack_operand(0x33B2F7E)),
        (1, stack_operand(0x33B3D77), stack_operand(0x33B3D7F)),
        (4, stack_operand(0x33B3D86), stack_operand(0x33B3D8D)),
        (4, stack_operand(0x33B3D94), stack_operand(0x33B3D9B)),
        (2, stack_operand(0x33B3DA2), stack_operand(0x33B3DAA)),
        (8, stack_operand(0x33B3DB2), stack_operand(0x33B3DBA)),
        (4, stack_operand(0x33B3DC2), stack_operand(0x33B3DC9)),
        (1, stack_operand(0x33B3EE4), stack_operand(0x33B3EEC)),
        (4, stack_operand(0x33B3EF3), stack_operand(0x33B3EFA)),
        (2, stack_operand(0x33B3F01), stack_operand(0x33B3F09)),
        (4, stack_operand(0x33B3F11), stack_operand(0x33B3F18)),
        (4, stack_operand(0x33B3F1F), stack_operand(0x33B3F26)),
        (8, stack_operand(0x33B3F2D), stack_operand(0x33B3F35)),
        (1, stack_operand(0x33B3FBD), stack_operand(0x33B3FC2)),
        (1, stack_operand(0x33B3FC9), stack_operand(0x33B3FCE)),
        (8, stack_operand(0x33B3FD5), stack_operand(0x33B3FDD)),
    ):
        values = [memory[src + offset] for offset in range(width)]
        memory.update({dst + offset: value for offset, value in enumerate(values)})
    sequence = bytes(memory[component + 0x92 + i] for i in range(32))
    assert sequence == bytes(range(32))
    assert sequence != bytes(reversed(range(32)))

    reloc = sections[".rela.dyn"]
    assert [
        (kind, target)
        for address, kind, target in struct.iter_unpack("<QQq", at(".rela.dyn", reloc["va"], reloc["size"]))
        if address == 0x64E4D08
    ] == [(8, 0x2EABB50)]
    assert not matches_window(0x4308FFB, bytes.fromhex("c6 04 30 c2"))
    assert not matches_window(0x276075C, bytes.fromhex("c6 82 90 00 00 00 01"))
    print(f"verified {len(windows)} instruction windows in {len(bounds)} FDEs and three negative controls")
    print("checkpoint tracker h: q boolean at +0x90; l presence and digest at +0x91/+0x92")
    print("payload copy: all 32 distinct bytes reach +0x92 in order")


if __name__ == "__main__":
    main()
