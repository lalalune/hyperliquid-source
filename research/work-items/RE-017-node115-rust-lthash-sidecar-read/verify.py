"""Authenticate the native decimal byte-array LtHash sidecar format."""

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

    writer = 0x38C2230
    relative(writer, 0x38C22DA, "e8113ae0ff", 0x36C5CF0)
    relative(writer, 0x38C2346, "e8a539e0ff", 0x36C5CF0)
    relative(writer, 0x38C23B5, "e83639e0ff", 0x36C5CF0)
    relative(0x36C5CF0, 0x36C5DB2, "e809e8f800", 0x46545C0)
    read(0x46545C0, 0x4654603, "b900080000")
    relative(0x46545C0, 0x465460E, "e8cdc40100", 0x4670AE0)
    read(0x4670AE0, 0x4670C20, "488b04240fb6004883f863")
    read(0x4670AE0, 0x4670DDA, "4c897f104c3933742a488b430842c604305d")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: three named lanes call the 2,048-element unsigned byte-array writer")


if __name__ == "__main__":
    main()
