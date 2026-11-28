"""Verify the selected #115 replay non-null Block pair gate against the pinned ELF."""
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
    entries = (0x5A82670,)
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

    def offset(address, opcode):
        expected = bytes.fromhex(opcode)
        raw = windows[address]
        assert raw.startswith(expected), hex(address)
        return int.from_bytes(raw[len(expected):], "little", signed=True)

    def expect(address, encoding):
        assert windows[address] == bytes.fromhex(encoding), hex(address)

    assert edge(0x5A87080, "0f85") == 0x5A8724F
    assert edge(0x5A8729E, "0f84") == 0x5A8869D
    assert offset(0x5A872B9, "488983") == 0x2D70
    assert offset(0x5A872C0, "48898b") == 0x2D78

    marker = offset(0x5A872CB, "48ba") + 1
    assert marker == -(1 << 63) + 1
    expect(0x5A872D5, "48ffc2")
    assert offset(0x5A872C7, "488b48") == 0x28
    expect(0x5A872D8, "4839d1")
    assert edge(0x5A872DB, "0f85") == 0x5A8748B
    assert edge(0x5A872E5, "e9") == 0x5A874A1
    expect(0x5A8749D, "480f44f7")

    identity_bases = (
        offset(0x5A872E1, "488d70"),
        offset(0x5A8748B, "488d78"),
        offset(0x5A8748F, "488db0"),
    )
    assert identity_bases == (0x30, 0x28, 0xB8)
    assert offset(0x5A87496, "483990") == identity_bases[2]
    identity_offsets = (offset(0x5A874A1, "488b7e"), offset(0x5A874A5, "488b76"))
    assert tuple(tuple(base + word for word in identity_offsets) for base in identity_bases) == (
        (0x50, 0x58), (0x48, 0x50), (0xD8, 0xE0)
    )
    assert offset(0x5A874B9, "483bbb") == offset(0x5A88AFF, "488d93") == 0x100
    assert offset(0x5A874C6, "483bb3") == 0x108
    assert edge(0x5A874C0, "0f85") == edge(0x5A874CD, "0f85") == 0x5A88AFF
    assert edge(0x5A88B19, "ff15") == 0x64E80E0
    assert edge(0x5A88B1F, "e9") == 0x5A85279
    expect(0x5A85279, "0f0b")

    successor_base = (offset(0x5A874DA, "4883c0"), offset(0x5A874D3, "488db0"))
    successor_word = offset(0x5A874E5, "488b40")
    assert tuple(base + successor_word for base in successor_base) == (0x60, 0xB0)
    expect(0x5A874E1, "480f45c6")
    expect(0x5A874E9, "48ffc0")
    expect(0x5A874EC, "48c7c1ffffffff")
    expect(0x5A874F3, "480f45c8")
    assert offset(0x5A874F7, "48898b") == 0x1B0
    assert offset(0x5A87513, "f30f6f83") == 0x2D70
    assert offset(0x5A8751B, "f30f7f83") == 0x1D8
    assert offset(0x5A8756C, "488bb3") == 0x1D8
    assert offset(0x5A87573, "488b93") == 0x1E0
    assert offset(0x5A8757A, "4889b3") == 0x1B8
    assert offset(0x5A87581, "488993") == 0x1C0

    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in FDE {bounds[0][0]:#x}..{bounds[0][1]:#x}")
    print("PASS: all three identity address pairs and the distinct zero-first-word route match")
    print("PASS: both mismatches converge before the success-path successor and pair staging")
    print("PASS: successful non-null Block stages the same two owner words and saturates successor on wrap")


if __name__ == "__main__":
    main()
