"""Verify #115 periodic payload, status marker and rolling link roles."""

import csv
import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

PACKET = Path(__file__).parent


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert hashlib.sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, address, size):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + size <= section["size"]
        offset = section["offset"] + delta
        return image[offset:offset + size]

    def section_bytes(name):
        section = sections[name]
        return read(name, section["va"], section["size"])

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(section_bytes(".eh_frame"), frame["va"])
    bounds = {fde["entry"]: fde["end"] for fde in fdes}
    windows = {}
    owners = set()
    with (PACKET / "instructions.tsv").open() as source:
        for row in csv.DictReader(source, delimiter="\t"):
            owner, address = (int(row[field], 16) for field in ("fde", "va"))
            raw = bytes.fromhex(row["bytes"])
            assert owner <= address < address + len(raw) <= bounds[owner]
            assert address not in windows and read(".text", address, len(raw)) == raw
            windows[address] = raw
            owners.add(owner)

    def edge(site, opcode):
        raw = windows[site]
        assert raw[:-4] == bytes.fromhex(opcode)
        return site + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    relocations = {va: (info, target) for va, info, target in
                   struct.iter_unpack("<QQq", section_bytes(".rela.dyn"))}

    for site, target in (
        (0x38D8292, 0x38D8100), (0x5485FBB, 0x38D8240),
        (0x54860A0, 0x1505A50), (0x54860C9, 0x38D7F20),
        (0x1505A69, 0x1500D20), (0x1505B37, 0x15024A0), (0x4E4B4D3, 0x15024A0),
        (0x38D803D, 0x5C9CCE0), (0x38D8080, 0x1502DA0),
    ):
        assert relocations[edge(site, "ff15")] == (8, target)
    assert edge(0x5486000, "e8") == 0x5942870

    for site, opcode, name in (
        (0x38D813F, "488d05", b"periodic_abci_states"),
        (0x38D82C0, "488d05", b"periodic_abci_state_statuses"),
    ):
        record = edge(site, opcode)
        assert read(".data.rel.ro", record + 8, 8) == struct.pack("<Q", len(name))
        info, pointer = relocations[record]
        assert info == 8 and read(".rodata", pointer, len(name)) == name

    for site, literal in ((0x38D81AB, b"\xc0\x01/\xc0\x01/\xc0\x04.rmp\x00"),
                          (0x38D8328, b"\xc0\x01/\xc0\x01/\xc0\x00")):
        assert read(".rodata", edge(site, "488d35"), len(literal)) == literal

    info, addend = relocations[edge(0x5C9CF77, "ff15")]
    assert (info & 0xFFFFFFFF, addend) == (6, 0)
    symbol_name = struct.unpack_from("<I", section_bytes(".dynsym"), (info >> 32) * 24)[0]
    symbols = section_bytes(".dynstr")
    assert symbols[symbol_name:symbols.index(b"\0", symbol_name)] == b"linkat"

    assert windows[0x1500DDA] == bytes.fromhex("b800f00000")
    assert windows[0x1500DE3] == bytes.fromhex("3d00800000")
    assert windows[0x1505B2C] == bytes.fromhex("31f6")
    print(f"PASS: {len(windows)} exact #115 spans in {len(owners)} FDEs, SHA-256 {TARGET_SHA256}")
    print("PASS: distinct payload/status templates, separate writer inputs and resolved linkat route")


if __name__ == "__main__":
    main()
