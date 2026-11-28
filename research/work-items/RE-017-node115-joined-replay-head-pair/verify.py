"""Verify the selected #115 joined startup and replay head-field join against the pinned ELF."""
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
    entries = (0x56467D0, 0x3C13610, 0x3C2E860, 0x2AD7140, 0x2AF45F0,
               0x3C12800)
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

    def operand(address, opcode):
        prefix = bytes.fromhex(opcode)
        raw = windows[address]
        assert raw.startswith(prefix), hex(address)
        return int.from_bytes(raw[len(prefix):], "little", signed=True)

    def expect(address, encoding):
        assert windows[address] == bytes.fromhex(encoding), hex(address)

    rela = sections[".rela.dyn"]
    relative = {offset: target for offset, info, target in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if info == 8}
    expect(0x56467EC, "4989d4")
    expect(0x564687A, "4d89e6")
    assert operand(0x5646881, "4c8b60") == 0x18
    assert operand(0x56469FE, "498b5c24") == 0x28
    expect(0x5646A06, "4c39f3")
    assert edge(0x5646A09, "0f85") == 0x5646B07
    expect(0x5646B9F, "4c89e7")
    assert relative[edge(0x5646BA2, "ff15")] == 0x3C13610
    assert edge(0x5646BDB, "e8") == 0x4E46090
    assert edge(0x5646CAD, "0f84") == 0x5646DF7
    assert operand(0x5646BC1, "48894424") == operand(0x5646EEB, "488b4424") == 0x48
    assert operand(0x5646EF0, "498945") == 8
    expect(0x5646EF8, "41c6450044")

    expect(0x3C1365C, "4889fb")
    expect(0x3C1365F, "4889e7")
    expect(0x3C13662, "4889de")
    assert relative[edge(0x3C13665, "ff15")] == 0x3C2E860
    expect(0x3C2E8A7, "4989f6")
    expect(0x3C2E8AA, "4889fb")
    expect(0x3C2F004, "4889df")
    expect(0x3C2F007, "4c89f6")
    expect(0x3C2F00A, "41ffd5")
    memcpy_slot = edge(0x3C2EC6A, "4c8b2d")
    assert edge(0x3C13689, "ff15") == memcpy_slot == 0x64DF508
    assert operand(0x3C2EFFF, "ba") == 0xBA0
    assert operand(0x3C1367E, "ba") == 0x42C8
    expect(0x3C1367B, "4889e6")
    expect(0x3C13683, "4889c7")
    expect(0x3C1369F, "4c89f0")

    assert relative[edge(0x2AD9FCC, "ff15")] == 0x56467D0
    assert operand(0x2ADA440, "488b8424") - operand(0x2AD9FA6, "4c8da424") == 8
    assert edge(0x2AD9FDD, "0f84") == 0x2ADA41C
    assert operand(0x2ADA448, "48894424") == operand(0x2ADA53C, "4c8b7424") == 0x18
    expect(0x2ADA550, "4c89f1")
    assert operand(0x2ADA5E2, "48894c24") == operand(0x2ADA6F6, "488b4c24") == 0x28
    assert operand(0x2ADAA69, "48898c24") - operand(0x2ADB58E, "488db424") == 0x30
    assert operand(0x2ADB596, "ba") == operand(0x2ADB5C4, "ba") == 0x98
    assert edge(0x2ADB59B, "ff15") == edge(0x2ADB5D4, "ff15") == memcpy_slot
    assert operand(0x2AF4D51, "4c8bbc24") - 0x640 == 0x30
    assert operand(0x2AF523A, "4c897c24") == operand(0x2AF5797, "488b4424") == 0x10
    first = operand(0x2AF579C, "0f1040")
    pair = (first, first + 8)
    assert pair == (0x18, 0x20) and pair[1] + 8 <= operand(0x3C2EFFF, "ba")

    assert operand(0x3C128CA, "498b4424") == 0x28
    assert operand(0x3C128E2, "498b4424") == operand(0x3C128FA, "49894c24") == pair[0]
    assert operand(0x3C128E7, "498b7424") == 0x30
    assert operand(0x3C128FF, "49897424") == pair[1]
    expect(0x3C128EC, "48ffc0")

    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: selected join compares source +0x28 to its input word and passes the source to the builder")
    print("PASS: direct builder copies +0x18/+0x20 unchanged before the tag-0x44 and outer result handoffs")
    print("PASS: replay caller reads the boxed +0x18/+0x20 pair; separate loader patch writes the same offsets")


if __name__ == "__main__":
    main()
