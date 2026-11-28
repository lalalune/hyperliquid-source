"""Verify the selected #115 replay local history prune against the pinned ELF."""
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
    entries = (0x5A04E40,)
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

    assert windows[0x5A05EA1] == bytes.fromhex("41807c241000")
    assert edge(0x5A05EA7, "0f84") == 0x5A05FC1
    assert windows[0x5A05EAD] == bytes.fromhex("498b442418")
    assert windows[0x5A05EB2] == bytes.fromhex("48ffc0")
    assert windows[0x5A05EB5] == bytes.fromhex("48c7c1ffffffff")
    assert windows[0x5A05EBC] == bytes.fromhex("480f45c8")
    assert windows[0x5A05EC8] == bytes.fromhex("498d9c2400040000")
    assert edge(0x5A05EE3, "e8") == 0x4DE5AD0
    assert edge(0x5A05FC9, "e8") == 0x5A07EC0
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} history pruning spans")
    print("PASS: cutoff saturates, the optional split precedes the end selector")



if __name__ == "__main__":
    main()
