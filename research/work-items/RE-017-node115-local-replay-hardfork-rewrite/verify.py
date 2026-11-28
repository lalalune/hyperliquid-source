"""Check the selected #115 startup rewrite and late replay input read."""
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKET.parents[2] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__, "run without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {item["name"]: item for item in parse_sections(data)}

    def at(name, address, length):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + length <= section["size"]
        offset = section["offset"] + delta
        return data[offset:offset + length]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(at(".eh_frame", frame["va"], frame["size"]), frame["va"])
    indexed = {row["entry"]: row["end"] for row in fdes}
    entries = (0x2CC1120,)
    bounds = [(entry, indexed[entry]) for entry in entries]
    windows = {}
    for line in (PACKET / "windows.txt").read_text().splitlines():
        address, encoding, _ = line.split("\t", maxsplit=2)
        address = int(address, 16)
        raw = bytes.fromhex(encoding)
        assert any(start <= address < address + len(raw) <= end for start, end in bounds)
        assert address not in windows and at(".text", address, len(raw)) == raw
        windows[address] = raw

    def edge(address, opcode):
        raw = windows[address]
        assert raw[:-4] == bytes.fromhex(opcode)
        return address + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    expected = {
        # Materialized pointer and the distinct, pre-rewrite future copy.
        0x2CC19F0: "4c8b3424",
        0x2CC19F4: "498986e0000000",
        0x2CC1A1B: "498b86e0000000",
        0x2CC1A29: "0f104818",
        0x2CC1A64: "410f114e68",
        # Low dword freeze marker and unsigned target/height operands.
        0x2CC1AA6: "83b8e810000001",
        0x2CC1AB3: "488b4828",
        0x2CC1AB7: "483988f0100000",
        # Re-read the state pointer and rewrite the original array, not its copy.
        0x2CC1C5A: "488b0424",
        0x2CC1C5E: "4c8bb0e0000000",
        0x2CC1C65: "498b4618",
        0x2CC1C71: "498b7630",
        0x2CC1C75: "48ffc0",
        0x2CC1C78: "48c7c1ffffffff",
        0x2CC1C7F: "480f45c8",
        0x2CC1C83: "49894e18",
        0x2CC1C87: "49897620",
        # Selected normal handoff pins the same slot, then reads through R15.
        0x2CC2BB1: "4c8b3c24",
        0x2CC2BBD: "498b9fe0000000",
        0x2CC12A0: "49895f20",
        0x2CC1651: "4c8b7820",
        0x2CC24B2: "410f104718",
        0x2CC24B7: "0f29442410",
        0x2CC2756: "0f28442410",
        0x2CC275B: "0f298424d0080000",
        0x2CC280A: "488dbc24d0070000",
        0x2CC7F3B: "0f0b",
    }
    for address, raw in expected.items():
        assert windows[address] == bytes.fromhex(raw), hex(address)
    assert edge(0x2CC1AAD, "0f85") == edge(0x2CC1AC4, "0f85") == 0x2CC1CFD
    assert edge(0x2CC1ABE, "0f82") == 0x2CC3DDE
    assert edge(0x2CC3DFC, "e9") == 0x2CC7F3B
    assert edge(0x2CC2BDC, "e9") == 0x2CC1295
    assert edge(0x2CC16B9, "0f84") == 0x2CC180E
    assert edge(0x2CC1958, "e9") == 0x2CC22CC
    assert edge(0x2CC281F, "ff15") == 0x64E74D8
    assert 0x8D0 - 0x7D0 == 0x100

    print(f"PASS: pinned #115 {TARGET_SHA256}, {len(windows)} spans in startup FDE")
    print("PASS: startup saves the original pair at future+0x68/+0x70 before the freeze guard")
    print("PASS: equality rewrites materialized +0x18/+0x20; both bypass arms preserve the pair at this boundary")
    print("PASS: stale freeze height reaches a failure arm and ud2 if its helper returns")
    print("PASS: selected replay spawn subsequently reads the materialized object, not the earlier future copy")


if __name__ == "__main__":
    main()
