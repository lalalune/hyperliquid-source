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
    entries = (0x2FD7260, 0x31050E0, 0x3041E40, 0x3D2F090)
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

    assert edge(0x2FD8164, "e8") == 0x31050E0
    assert windows[0x3105156] == bytes.fromhex("3ca0")
    assert windows[0x310515A] == bytes.fromhex("240f")
    assert windows[0x310515C] == bytes.fromhex("89c6")
    assert edge(0x310515E, "e9") == 0x31052B0
    assert windows[0x31052B0] == bytes.fromhex("440fb6fe")
    assert operand(0x31052D0, "4c89b424") == 0xC0
    assert edge(0x3D2F0B5, "74") == 0x3D2F112
    assert operand(0x3D2F11A, "ba") == 12
    assert edge(0x3D2F11F, "e8") == 0x3D50270
    assert edge(0x3D2F48B, "e8") == 0x3D33060
    assert edge(0x3D2F49A, "eb") == 0x3D2F4C5

    assert operand(0x31074A1, "488d7c24") == 0x60
    assert operand(0x31074A6, "488db424") == 0xC0
    assert edge(0x31074AE, "e8") == 0x3041E40
    assert operand(0x3041E48, "8b46") == operand(0x3041E51, "8946") == 8
    assert windows[0x3041E4B] == bytes.fromhex("85c0")
    assert edge(0x3041E4D, "74") == 0x3041E8E
    assert windows[0x3041E4F] == bytes.fromhex("ffc8")
    assert operand(0x3041E8E, "48c74308") == 0
    assert operand(0x3041E96, "c603") == 9
    assert edge(0x3041EE1, "ff15") == 0x64E2588
    assert operand(0x3041EF0, "80f9") == operand(0x3041EF9, "c603") == 9
    assert operand(0x3041EF5, "488943") == 8
    assert operand(0x31074B3, "440fb66c24") == 0x60
    assert operand(0x31074B9, "4180fd") == 9
    assert edge(0x31074BD, "0f85") == 0x31076F8
    assert operand(0x31074C3, "488b4c24") == 0x68
    assert windows[0x31074C8] == bytes.fromhex("4885c9")
    default = operand(0x31074CB, "b8")
    assert default == 1000
    assert windows[0x31074D0] == bytes.fromhex("480f45c1")

    writer_slot = operand(0x3D2F47C, "498b97")
    offset = operand(0x3107669, "48898424") - operand(0x3107763, "488db424")
    assert offset == writer_slot == 0xC0
    assert operand(0x310776B, "ba") == operand(0x3106B15, "ba") == 0xF8
    assert offset + 8 <= 0xF8
    assert edge(0x31076BE, "0f84") == 0x310775B
    assert operand(0x310775B, "488dbc24") == operand(0x310778C, "488db424")
    assert edge(0x3107770, "ff15") == edge(0x3106B1D, "ff15") == 0x64DF508
    assert edge(0x3107794, "e9") == 0x3106B15

    wrong_move = bytes.fromhex("480f44c1")  # CMOVE in place of CMOVNE
    wrong_slot = bytes.fromhex("488b4c2460")  # read the tag slot instead
    assert not matches_window(0x31074D0, wrong_move)
    assert not matches_window(0x31074C3, wrong_slot)
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} instruction windows")
    print("FDEs: " + ", ".join(f"{start:#x}..{end:#x}" for start, end in bounds))
    print("PASS: positional reader and unnamed 12-field writer reach ExchangeMisc +0xc0")
    print("PASS: exhausted-input zero and decoded zero select 1000; nonzero is preserved")
    print("PASS: wrong selection opcode and result-coordinate controls differ")


if __name__ == "__main__":
    main()
