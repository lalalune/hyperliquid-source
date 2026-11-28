"""Authenticate the post-command EVM archive disposition in node #115."""

from hashlib import sha256
from pathlib import Path
from struct import iter_unpack
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def data(name):
        section = sections[name]
        return image[section["offset"]:section["offset"] + section["size"]]

    _, fdes = walk_eh_frame(data(".eh_frame"), sections[".eh_frame"]["va"])
    bounds = {record["entry"]: record["end"] for record in fdes}
    text = data(".text")
    base = sections[".text"]["va"]

    def read(entry, address, encoded):
        expected = bytes.fromhex(encoded)
        assert entry <= address < address + len(expected) <= bounds[entry]
        offset = address - base
        assert text[offset:offset + len(expected)] == expected, hex(address)
        return expected

    def relative(entry, address, encoded, target, width=4):
        raw = read(entry, address, encoded)
        assert address + len(raw) + int.from_bytes(raw[-width:], "little", signed=True) == target

    owner = 0x38C40F0
    predicate = 0x1500D20
    cleanup = 0x1502B80
    mover = 0x1502DA0
    relative(owner, 0x38C4A3E, "0f8468020000", 0x38C4CAC)
    read(owner, 0x38C44AD, "488bbc24e8000000")
    relative(owner, 0x38C44B5, "ff1595c4c102", 0x64E0950)
    read(owner, 0x38C4948, "488b8424980000004889842478020000")
    read(owner, 0x38C4CCF, "488bbc24e8000000488bb424f0000000")
    relative(owner, 0x38C4CDF, "ff156bbcc102", 0x64E0950)
    relative(owner, 0x38C4CE7, "742b", 0x38C4D14, width=1)
    read(owner, 0x38C4CEC, "488bb42498000000488b9424f8000000")
    relative(owner, 0x38C4CFC, "ff1526bdc102", 0x64E0A28)
    read(owner, 0x38C4D14, "488bbc2498000000488bb424f8000000")
    relative(owner, 0x38C4D24, "ff1526bcc102", 0x64E0950)
    relative(owner, 0x38C4D2C, "743a", 0x38C4D68, width=1)
    read(owner, 0x38C4D2E, "488b9424e8000000488b8c24f0000000")
    read(owner, 0x38C4D45, "488bbc2498000000488bb424f8000000")
    relative(owner, 0x38C4D55, "ff15a5bcc102", 0x64E0A00)

    slots = {slot: (info, target)
             for slot, info, target in iter_unpack("<QQq", data(".rela.dyn"))}
    assert slots[0x64E0950] == (8, predicate)
    assert slots[0x64E0A28] == (8, cleanup)
    assert slots[0x64E0A00] == (8, mover)
    read(predicate, 0x1500DDA, "b800f00000234424483d008000000f94c0")
    relative(cleanup, 0x1502BA8, "ff15a2ddfd04", 0x64E0950)
    relative(cleanup, 0x1502BB2, "0f8443010000", 0x1502CFB)
    relative(cleanup, 0x1502C0E, "ff1524defd04", 0x64E0A38)
    info, addend = slots[0x64E0A38]
    assert info & 0xffffffff == 6 and addend == 0
    names = data(".dynstr")
    symbol = (info >> 32) * 24
    name_offset = int.from_bytes(data(".dynsym")[symbol:symbol + 4], "little")
    assert names[name_offset:names.index(b"\x00", name_offset)] == b"unlink"

    relative(mover, 0x1502E07, "488d05fe2bf6fe", 0x465A0C)
    offset = 0x465A0C - sections[".rodata"]["va"]
    assert data(".rodata")[offset:offset + 6] == b"mvtmp\x00"
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: final regular file takes precedence; native temporary cleanup uses unlink and promotion uses mvtmp")


if __name__ == "__main__":
    main()
