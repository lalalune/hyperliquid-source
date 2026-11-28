"""Verify the selected #115 selected replay reader buffer handoff against the pinned ELF."""
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
    entries = (0x5A806F0, 0x5AB4390)
    bounds = [(entry, indexed[entry]) for entry in entries]
    assert bounds == [(0x5A806F0, 0x5A81584), (0x5AB4390, 0x5AB5B4D)]
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

    def check(encodings):
        for address, encoding in encodings.items():
            assert windows[address] == bytes.fromhex(encoding), hex(address)

    check({
        0x5AB4BFA: "4c897358",            # requested byte count
        0x5AB4BFE: "4c397328",
        0x5AB4DA1: "0f944350",
        0x5AB4DAF: "4c89f6",              # allocation size
        0x5AB4E12: "b801000000",          # empty span pointer sentinel
        0x5AB4E17: "4c897360",
        0x5AB4E1B: "48894368",
        0x5AB4E1F: "4c897370",
        0x5AB4E27: "48c7437800000000",
        0x5AB5536: "4d85f6",
        0x5AB553F: "488b4378",
        0x5AB5543: "48038380000000",
        0x5AB5559: "48897b78",
        0x5AB56ED: "488b4358",
        0x5AB56F1: "4829f8",
        0x5AB56FA: "483d00093d00",
        0x5AB5705: "480f42c8",
        0x5AB5709: "48898b80000000",
        0x5AB5736: "48037b68",
        0x5AB5761: "4889bba0000000",
        0x5AB5768: "4889b3a8000000",
        0x5AB57A7: "807b5000",
    })
    assert edge(0x5AB4C02, "0f83") == 0x5AB4D9D
    assert edge(0x5AB4E31, "e9") == 0x5AB56ED
    assert edge(0x5AB53F8, "e8") == 0x5AB3A50
    assert edge(0x5AB5539, "0f85") == 0x5AB57FE
    assert edge(0x5AB56F4, "0f86") == 0x5AB57A7
    assert edge(0x5AB57AB, "0f84") == 0x5AB586C

    check({
        0x5AB43A9: "48897c2448",          # save output address
        0x5AB5870: "4c8b6360",
        0x5AB5874: "488b6b68",
        0x5AB5878: "4c8b7370",
        0x5AB5880: "4c89a42490010000",
        0x5AB5817: "488b442448",
        0x5AB581C: "488b8c2490010000",
        0x5AB5824: "488908",
        0x5AB5827: "48896808",
        0x5AB582B: "4c897010",
        0x5AB5845: "c3",
        0x5A80CA9: "488dbc24f0000000",    # caller's output location
        0x5A80CBE: "4c8bac24f0000000",
        0x5A80D2B: "488bac24f8000000",
        0x5A80D33: "4c8bbc2400010000",
        0x5A80DE1: "4889ee",
        0x5A80DE4: "4c89fa",
        0x5A80DEC: "80bc24e803000012",
        0x5A80E12: "4889ef",
        0x5A80E15: "4c89ee",
        0x5A80E18: "31d2",
    })
    assert windows[0x5AB5888] == bytes.fromhex("eb8d")
    assert 0x5AB588A + int.from_bytes(windows[0x5AB5888][1:], "little", signed=True) == 0x5AB5817
    assert edge(0x5A80CB9, "e8") == 0x5AB4390
    assert windows[0x5A80CD6] == bytes.fromhex("7553")
    assert 0x5A80CD8 + windows[0x5A80CD6][1] == 0x5A80D2B
    assert windows[0x5A80D6B] == bytes.fromhex("754b")
    assert 0x5A80D6D + windows[0x5A80D6B][1] == 0x5A80DB8
    assert edge(0x5A80DE7, "e8") == 0x5860BB0

    rela = sections[".rela.dyn"]
    relative = {offset: target for offset, info, target in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if info == 8}
    assert relative[edge(0x5AB4DB2, "ff15")] == 0x6355900
    assert relative[edge(0x5A80E1A, "ff15")] == 0x635DE30
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: selected read future stores the requested span and advances its cursor by each completed chunk")
    print("PASS: ordinary return writes allocation size, base and span length at output +0/+8/+16")
    print("PASS: producer calls decoder with the returned base and length, then conditionally releases the buffer")


if __name__ == "__main__":
    main()
