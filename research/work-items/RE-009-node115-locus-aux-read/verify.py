"""Check the selected named Locus aux decoder without executing the ELF."""

import hashlib
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(Path.cwd() / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__, "run without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def at(name, address, length):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + length <= section["size"]
        offset = section["offset"] + delta
        return data[offset:offset + length]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(at(".eh_frame", frame["va"], frame["size"]), frame["va"])
    indexed = {row["entry"]: row["end"] for row in fdes}
    entries = (0x2FD7260, 0x332C430, 0x2FBBD20, 0x31D5E50)
    bounds = [(entry, indexed[entry]) for entry in entries]
    def matches_window(address, raw):
        return (any(start <= address < address + len(raw) <= end for start, end in bounds)
                and at(".text", address, len(raw)) == raw)

    windows = {}
    for line in (PACKET / "windows.txt").read_text().splitlines():
        address, encoding, _ = line.split("\t", maxsplit=2)
        address = int(address, 16)
        raw = bytes.fromhex(encoding)
        assert address not in windows
        assert matches_window(address, raw)
        windows[address] = raw

    def operand(address, opcode):
        prefix = bytes.fromhex(opcode)
        raw = windows[address]
        assert raw.startswith(prefix) and len(raw) > len(prefix)
        return int.from_bytes(raw[len(prefix):], "little")

    def edge(address, opcode):
        prefix = bytes.fromhex(opcode)
        raw = windows[address]
        assert raw.startswith(prefix) and len(raw) > len(prefix)
        return address + len(raw) + int.from_bytes(raw[len(prefix):], "little", signed=True)

    assert edge(0x2FD78DC, "e8") == 0x332C430
    assert operand(0x332C775, "80f9") == 0xA0
    assert operand(0x332C786, "4080e6") == 0x1F
    assert operand(0x332C78A, "80f9") == 0xC0
    assert edge(0x332C78D, "0f82") == 0x332D56A
    assert windows[0x332D57D] == bytes.fromhex("49 8d 0c 2c")
    assert windows[0x332D581] == bytes.fromhex("49 89 4f 10")
    assert windows[0x332D585] == bytes.fromhex("49 89 47 18")
    assert edge(0x332D5B8, "e8") == 0x2FBBD20

    length = operand(0x2FBBD20, "4883fa")
    assert length == 3
    minimum = -int.from_bytes(windows[0x2FBBD2D][-1:], "little", signed=True)
    count = operand(0x2FBBD30, "83f8") + 1
    assert minimum == ord("b") and minimum + count - 1 == ord("v")
    assert edge(0x2FBBD33, "0f87") == 0x2FBBE76
    unknown = operand(0x2FBBE76, "b0")
    assert unknown == 16 and windows[0x2FBBE7B] == bytes.fromhex("c6 07 09")
    assert edge(0x332D5DE, "e9") == 0x332C7C1
    table = edge(0x332C7D9, "488d0d")
    delta, = struct.unpack("<i", at(".rodata", table + 4 * unknown, 4))
    assert table + delta == 0x332CA10
    assert operand(0x332CA1B, "ba") == 1
    assert edge(0x332CA20, "e8") == 0x31D5E50

    assert windows[0x31D5E7A] == bytes.fromhex("48 ff c9")
    assert windows[0x31D5E80] == bytes.fromhex("48 ff c2")
    assert windows[0x31D5E83] == bytes.fromhex("48 89 53 10")
    assert windows[0x31D5E87] == bytes.fromhex("48 89 4b 18")
    lower = operand(0x31D5EAD, "3c")
    upper = operand(0x31D5EBA, "3c")
    assert (lower, upper) == (0x90, 0xA0)
    child_mask = operand(0x31D5EBE, "24")
    assert child_mask == 0x0F
    assert edge(0x31D5EC2, "e9") == 0x31D5FD6
    assert edge(0x31D5FF5, "74") == 0x31D6031
    assert windows[0x31D6033] == bytes.fromhex("66 89 43 22")
    assert windows[0x31D6037] == bytes.fromhex("c6 07 09")
    assert operand(0x332CA2D, "4080fd") == 9
    assert edge(0x332CA31, "0f84") == 0x332C717
    assert windows[0x332C717] == bytes.fromhex("ff 4c 24 30")

    # The prefix is the canonical aux pair followed by a second field and value.
    # Normal UTF-8 and reader depth are explicit fixture assumptions.
    sample = b"\xa3aux\x90\xa3ctx\xc0"
    assert sample[0] & operand(0x332C786, "4080e6") == length
    key = sample[1:1 + length]
    assert (key[0] - minimum) % (1 << 32) >= count
    value_at = 1 + length
    marker = sample[value_at]
    assert lower <= marker < upper and marker & child_mask == 0
    assert sample[value_at + 1:] == b"\xa3ctx\xc0"
    assert (ord("b") - minimum) % (1 << 32) < count
    assert (lower | 1) & child_mask == 1
    assert not matches_window(0x332CA1B, bytes.fromhex("ba 02 00 00 00"))
    print(f"verified {len(windows)} instruction windows in {len(bounds)} FDEs")
    print("named aux: unknown field 16; empty array skips one marker and returns to Locus pair count")
    print("controls: known-key first-byte class, nonempty array tag, wrong skip argument")


if __name__ == "__main__":
    main()
