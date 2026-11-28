"""Verify the #115 ordinary loader's ordered direct store and helper boundaries."""

import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

SPANS = {
    0x3C128CA: "498b442428",
    0x3C128D4: "4c39f8",
    0x3C128D7: "0f8539010000",
    0x3C128DD: "4d897c2410",
    0x3C128E2: "498b442418",
    0x3C128E7: "498b742430",
    0x3C128EC: "48ffc0",
    0x3C128EF: "48c7c1ffffffff",
    0x3C128F6: "480f45c8",
    0x3C128FA: "49894c2418",
    0x3C128FF: "4989742420",
    0x3C12904: "49c78424e810000000000000",
    0x3C12910: "4989b424f00d0000",
    0x3C12923: "e898905f00",
    0x3C1292B: "ff15d7258d02",
    0x3C12931: "498b742430",
    0x3C12936: "4989b424f80e0000",
    0x3C12946: "e8b58f5f00",
    0x3C12953: "ff15b7258d02",
    0x3C12959: "6641c78424283e00000000",
    0x3C12964: "6641c78424e03e00000000",
    0x3C1296F: "41c68424b039000002",
    0x3C1298F: "4c89e0",
}


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert hashlib.sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, address, size):
        section = sections[name]
        offset = address - section["va"]
        assert 0 <= offset <= offset + size <= section["size"]
        offset += section["offset"]
        return image[offset:offset + size]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", frame["va"], frame["size"]), frame["va"])
    bounds = {fde["entry"]: fde["end"] for fde in fdes}
    for address, raw in SPANS.items():
        data = bytes.fromhex(raw)
        assert 0x3C12800 <= address < address + len(data) <= bounds[0x3C12800]
        assert read(".text", address, len(data)) == data, hex(address)

    def edge(address):
        data = bytes.fromhex(SPANS[address])
        return address + len(data) + int.from_bytes(data[-4:], "little", signed=True)

    assert edge(0x3C128D7) == 0x3C12A16
    assert edge(0x3C12923) == 0x420B9C0
    assert edge(0x3C12946) == 0x420B900
    rela = sections[".rela.dyn"]
    targets = {slot: target for slot, info, target in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"]),
    ) if info == 8}
    assert targets[edge(0x3C1292B)] == 0x3C374E0
    assert targets[edge(0x3C12953)] == 0x3BEC320

    print(f"PASS: #115 {TARGET_SHA256}, {len(SPANS)} exact loader spans in FDE 0x3c12800")
    print("PASS: checked height, ordered direct writes, round reload and four helper bindings")


if __name__ == "__main__":
    main()
