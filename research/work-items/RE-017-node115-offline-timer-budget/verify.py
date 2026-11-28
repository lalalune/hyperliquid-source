"""Authenticate the primary and secondary timer-drain decisions."""

from hashlib import sha256
from pathlib import Path
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

    caller = 0x5AFA030
    walk = 0x51520F0
    read(caller, 0x5AFA044, "488d7e60488b4678")
    read(caller, 0x5AFA04E, "482de8030000480f43f0")
    read(caller, 0x5AFA058, "488974243848c744244000000000")
    relative(caller, 0x5AFA0A0, "e89b642eff", 0x4DE0540)
    relative(walk, 0x515230E, "e98b020000", 0x515259E)
    relative(walk, 0x5152315, "0f8583020000", 0x515259E)
    relative(walk, 0x515233B, "f20f1005d57330fb", 0x459718)
    offset = 0x459718 - sections[".rodata"]["va"]
    assert data(".rodata")[offset:offset + 8] == bytes.fromhex("0000000000004e40")
    read(walk, 0x515249A, "488b4128488b5130488b08483b0a")
    relative(walk, 0x51524A8, "0f82ef010000", 0x515269D)
    relative(walk, 0x51525BB, "e830582200", 0x5377DF0)
    read(walk, 0x515269D, "48ffc1488908")
    relative(walk, 0x51526A3, "e941010000", 0x51527E9)
    read(walk, 0x51527E9, "498b460848ff08")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: primary reaches digest extraction; secondary uses the 60-second threshold and its own count budget")


if __name__ == "__main__":
    main()
