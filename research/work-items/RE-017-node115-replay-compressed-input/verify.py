"""Verify the selected #115 compressed replay input handoff against the pinned ELF."""
import hashlib
from pathlib import Path
import struct
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
    entries = (0x5A806F0, 0x5AB4390, 0x477F8C0)
    bounds = [(entry, indexed[entry]) for entry in entries]
    assert bounds == [(0x5A806F0, 0x5A81584), (0x5AB4390, 0x5AB5B4D),
                      (0x477F8C0, 0x4780322)]
    windows = {}
    for line in (PACKET / "windows.txt").read_text().splitlines():
        address, encoding, _ = line.split("\t", maxsplit=2)
        address = int(address, 16)
        raw = bytes.fromhex(encoding)
        assert any(start <= address < address + len(raw) <= end for start, end in bounds)
        assert address not in windows and at(".text", address, len(raw)) == raw
        windows[address] = raw

    def edge(address, opcode, width=4):
        raw = windows[address]
        assert raw[:-width] == bytes.fromhex(opcode)
        return address + len(raw) + int.from_bytes(raw[-width:], "little", signed=True)

    def check(encodings):
        for address, encoding in encodings.items():
            assert windows[address] == bytes.fromhex(encoding), hex(address)

    check({
        0x5A80C33: "488b83c8080000",       # saved input copied into reader
        0x5A80C41: "488b9380060000",       # fourth argument source before reader copy
        0x5A80C94: "488993b0060000",
        0x5A80C79: "48898390060000",
        0x5A80CA2: "4c8dab90060000",
        0x5A80CB1: "4c89ee",
        0x5AB43A6: "4889f3",
        0x5AB43D8: "488b0b",
        0x5AB43ED: "48894b40",
        0x5AB43DB: "488b4320",
        0x5AB43DF: "48894328",
        0x5AB57A7: "807b5000",           # zero selects direct return
        0x5AB57C1: "488b4b28",
        0x5AB57C5: "488b7368",
        0x5AB57C9: "488b5370",
        0x5AB57CD: "488dbc24c0000000",
    })
    assert edge(0x5A80CB9, "e8") == 0x5AB4390
    assert edge(0x5AB57AB, "0f84") == 0x5AB586C

    check({
        0x477F8E9: "48897c2430",          # LZ4 result pointer
        0x477FF73: "488b442450",
        0x477FF78: "4c39e8",
        0x477FF7B: "490f43c5",
        0x477FF7F: "488b4c2430",
        0x477FF84: "4c8929",
        0x477FF87: "4c897908",
        0x477FF8B: "48894110",
        0x5AB57DB: "4c8ba424c0000000",
        0x5AB57E3: "488bac24c8000000",
        0x5AB57F5: "4939c4",
        0x5AB588A: "4c8bb424d0000000",
        0x5AB5954: "807b4900",           # compressed allocation still live
        0x5AB595E: "488b7360",
        0x5AB596B: "488b7b68",
        0x5AB596F: "31d2",
        0x5AB587C: "c6434900",
        0x5AB5880: "4c89a42490010000",
        0x5AB43A9: "48897c2448",
        0x5AB5817: "488b442448",
        0x5AB581C: "488b8c2490010000",
        0x5AB5824: "488908",
        0x5AB5827: "48896808",
        0x5AB582B: "4c897010",
        0x5A80CA9: "488dbc24f0000000",
        0x5A80D2B: "488bac24f8000000",
        0x5A80D33: "4c8bbc2400010000",
        0x5A80DE1: "4889ee",
        0x5A80DE4: "4c89fa",
    })
    assert edge(0x5AB57F8, "0f85") == 0x5AB588A
    assert edge(0x5AB5958, "0f84") == edge(0x5AB5965, "0f84") == 0x5AB587C
    assert edge(0x5AB5977, "e9") == 0x5AB587C
    assert edge(0x5AB5888, "eb", 1) == 0x5AB5817
    assert edge(0x5A80CD6, "75", 1) == 0x5A80D2B
    assert edge(0x5A80D6B, "75", 1) == 0x5A80DB8
    assert edge(0x5A80DE7, "e8") == 0x5860BB0

    rela = sections[".rela.dyn"]
    relative = {offset: target for offset, info, target in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if info == 8}
    assert relative[edge(0x5AB57D5, "ff15")] == 0x477F8C0
    assert relative[edge(0x5AB5971, "ff15")] == 0x635DE30
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: compressed completion calls the pinned LZ4 adapter with saved input base, length and reader limit")
    print("PASS: compressed storage release uses the original buffer; output reuses the transformed base and length")
    print("PASS: replay decoder receives the transformed base and returned length on the selected arm")


if __name__ == "__main__":
    main()
