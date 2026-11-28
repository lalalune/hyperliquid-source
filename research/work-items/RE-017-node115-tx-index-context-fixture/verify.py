"""Authenticate native transaction-index completion, copy and replay stores."""

import csv
from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

INT_DESTINATIONS = (
    0x14B7B77, 0x14B7BE9, 0x14B7B54, 0x14B7CC0,
    0x14B7C5C, 0x14B7BB2, 0x14B7B1B, 0x14B7C8D,
)


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, address, size):
        section = sections[name]
        offset = address - section["va"]
        assert 0 <= offset <= offset + size <= section["size"]
        start = section["offset"] + offset
        return image[start:start + size]

    f = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", f["va"], f["size"]), f["va"])
    bounds = {fde["entry"]: fde["end"] for fde in fdes}
    entries = set()
    loaded = {}
    with Path(__file__).with_name("spans.tsv").open() as source:
        for row in csv.DictReader(source, delimiter="\t"):
            entry, address = (int(row[key], 16) for key in ("fde", "address"))
            expected = bytes.fromhex(row["bytes"])
            assert entry <= address < address + len(expected) <= bounds[entry]
            assert address not in loaded and read(".text", address, len(expected)) == expected
            loaded[address] = expected
            entries.add(entry)

    def relative(address, width=4):
        raw = loaded[address]
        return address + len(raw) + int.from_bytes(raw[-width:], "little", signed=True)

    assert relative(0x30D2415) == relative(0x30D3846) == 0x451C540
    assert relative(0x30D3D8D) == 0x30D2ED1
    assert relative(0x451C5C8, 1) == 0x451C5D4
    assert relative(0x451C5D2, 1) == 0x451C601
    assert relative(0x451C5E4) == 0x64DFEB0
    rela = sections[".rela.dyn"]
    assert (0x64DFEB0, 8, 0x14B7AA0) in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"]),
    )
    table = relative(0x14B7AB5)
    assert table == 0x462EB4
    assert tuple(table + struct.unpack("<i", read(".rodata", table + (marker - 0xC0) * 4, 4))[0]
                 for marker in range(0xCC, 0xD4)) == INT_DESTINATIONS
    print(f"PASS: #115 {TARGET_SHA256}, {len(loaded)} spans across {len(entries)} FDEs")
    print("PASS: named omission default, nil/write distinction, positional copy, integer table and replay reset")


if __name__ == "__main__":
    main()
