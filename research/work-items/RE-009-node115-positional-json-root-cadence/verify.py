"""Check the selected positional checkpoint-root cadence path without executing the ELF."""

import hashlib
from pathlib import Path
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
    entries = (0x3EFB050, 0x400CEC0, 0x3F4CB30, 0x3EF15E0)
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

    assert edge(0x3EFD286, "e8") == 0x400CEC0
    assert operand(0x400CF51, "83fe") == ord("[")
    assert edge(0x400CF54, "0f84") == 0x400DB7D
    assert operand(0x400DBA6, "498946") == 0x28
    assert operand(0x400DBAA, "4c897424") == operand(0x400DBBF, "488d7424") == 0x78
    assert operand(0x400DBAF, "c68424") == 0x0100000080
    assert edge(0x400DBC4, "e8") == edge(0x3EF15EE, "e8") == 0x3F4CB30
    assert operand(0x400FB74, "488d7c24") == 0x78
    assert edge(0x400FB79, "e8") == 0x3EF15E0

    assert operand(0x3F4CBAD, "4183fb") == ord("]")
    assert edge(0x3F4CBB1, "75") != 0x3F4CBB3
    assert windows[0x3F4CBB3] == bytes.fromhex("c6410100")
    assert edge(0x3F4CBB7, "eb") == 0x3F4CC2F
    assert windows[0x3F4CC2F] == bytes.fromhex("31c0")
    assert windows[0x3F4CC31] == bytes.fromhex("8801")
    assert windows[0x3EF15F3] == bytes.fromhex("803c2401")
    assert edge(0x3EF15F7, "75") == 0x3EF1609
    assert operand(0x3EF15FE, "b8") == 1
    assert windows[0x3EF1609] == bytes.fromhex("31d2")
    assert windows[0x3EF160B] == bytes.fromhex("807c240101")
    assert operand(0x3EF1610, "b8") == 0
    assert edge(0x3EF1615, "75") == 0x3EF1603
    assert edge(0x3EF161A, "e8") == edge(0x400DA69, "e8") == 0x3FD23D0
    assert windows[0x3EF161F] == bytes.fromhex("83e001")

    assert operand(0x400FB7E, "4883f8") == 1
    assert edge(0x400FB82, "75") == 0x400FBB1
    assert windows[0x400FBB1] == bytes.fromhex("4885d2")
    assert operand(0x400FBB4, "b8") == 1000
    assert windows[0x400FBB9] == bytes.fromhex("480f45c2")
    assert edge(0x400FD08, "e9") == 0x400DC38
    assert edge(0x400DC70, "e8") == 0x3EF3560
    assert windows[0x400DCDD] == bytes.fromhex("4d85e4")
    assert edge(0x400DCE0, "0f85") == 0x400ED18
    assert edge(0x400DCF6, "e9") == 0x400ED40
    assert edge(0x400ED53, "eb") == 0x400ED6F
    assert edge(0x400ED73, "0f84") != 0x400ED79
    assert edge(0x400ED4D, "ff15") == edge(0x400ED8A, "ff15") == 0x64DF508

    def copy(position, source, destination, size):
        assert source <= position and position + 8 <= source + size
        return destination + position - source

    position = operand(0x400FCB5, "48898424")
    position = copy(position, operand(0x400DCEE, "488db424"),
                    operand(0x400ED40, "488dbc24"), operand(0x400ED48, "ba"))
    position = copy(position, operand(0x400ED7D, "488db424"),
                    operand(0x400ED79, "488d7b"), operand(0x400ED85, "ba"))
    assert position == 0xC0

    assert not matches_window(0x3F4CBAD, bytes.fromhex("4183fb7d"))  # brace
    assert not matches_window(0x400FBB9, bytes.fromhex("480f44c2"))  # CMOVE
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} instruction windows")
    print("FDEs: " + ", ".join(f"{start:#x}..{end:#x}" for start, end in bounds))
    print("PASS: positional JSON array probe uses the keyed arm's scalar reader when present")
    print("PASS: closing bracket without a value and decoded zero select 1000; nonzero is preserved")
    print("PASS: published ExchangeMisc cadence at +0xc0; wrong delimiter and selection controls fail")


if __name__ == "__main__":
    main()
