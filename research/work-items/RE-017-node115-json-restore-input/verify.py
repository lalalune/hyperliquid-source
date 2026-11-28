"""Authenticate the selected named JSON restore input branches in node #115."""

import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

OWNERS = {
    0x2740770: {
        0x27407B3: "b9726f756e",          # round literal prefix
        0x2740933: "48b9636f6e73656e7375",
        0x2740940: "48ba75735f726f756e64",  # consensus_round literal tail
        0x2740965: "b104",
    },
    0x1F8E960: {
        0x1F8F600: "e8db7cdeff",          # selected height unsigned visitor
        0x1F8F53A: "e8a17ddeff",          # selected round unsigned visitor
        0x1F8F7BF: "f644246801",
        0x1F8F7C4: "0f849c020000",        # height needed
        0x1F8F7CA: "31c0",
        0x1F8F7E6: "f68424e000000001",
        0x1F8F7F6: "4c0f44e0",           # absent round zero
        0x1F8F83F: "660f72e01f",
        0x1F8F844: "660fdbc1",            # absent hardfork pair zero
        0x1F8EC97: "0f11431848896b284c896330",
    },
    0x1D7F620: {
        0x1D80844: "4883bc24a800000002",
        0x1D8084D: "0f85aca30000",        # selected duplicate
        0x1D8ABFF: "488d05c29c84fe",
        0x1D821BD: "e80e555200",
        0x1D87B7F: "4531ed488b8424a80000004883f8024c0f45e8",
        0x1D909D6: "4d89ac24e8100000",
        0x1D909E6: "49898424f0100000",
    },
    0x22A76D0: {
        0x22A773C: "4183f96e",
        0x22A7762: "4080ff75",
        0x22A777A: "4180f86c",
        0x22A7792: "80f96c",
        0x22A7797: "31c0",
        0x22A779E: "e83dfbacff",
        0x22A77A3: "48ffc048895308488903",
    },
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
    windows = {}
    for owner, spans in OWNERS.items():
        for address, encoding in spans.items():
            raw = bytes.fromhex(encoding)
            assert owner <= address < address + len(raw) <= bounds[owner]
            assert read(".text", address, len(raw)) == raw, hex(address)
            windows[address] = raw

    def edge(site):
        raw = windows[site]
        return site + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    assert edge(0x1F8F600) == edge(0x1F8F53A) == edge(0x22A779E) == 0x1D772E0
    assert edge(0x1D821BD) == 0x22A76D0
    assert edge(0x1F8F7C4) == 0x1F8FA66
    assert edge(0x1D8084D) == 0x1D8ABFF
    assert read(".rodata", edge(0x1D8ABFF), 23) == b"scheduled_freeze_height"
    print(f"PASS: #115 {TARGET_SHA256}, {len(windows)} exact spans in {len(OWNERS)} FDEs")
    print("PASS: independent height/round/hardfork outputs and duplicate/optional freeze route")


if __name__ == "__main__":
    main()
