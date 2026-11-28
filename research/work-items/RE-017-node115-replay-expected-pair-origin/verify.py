"""Verify the selected #115 joined startup origin of the expected replay Block words against the pinned ELF."""
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
    entries = (0x2AF45F0, 0x5A81ED0, 0x5A82670)
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
    assert edge(0x2AF4D07, "e8") == 0x2AD7140
    expect(0x2AF4D43, "83bc244006000002")
    assert edge(0x2AF4D4B, "0f85") == 0x2AF5ECE
    assert operand(0x2AF4D51, "4c8bbc24") - 0x640 == 0x30
    assert operand(0x2AF523A, "4c897c24") == operand(0x2AF5797, "488b4424") == 0x10
    assert operand(0x2AF579C, "0f1040") == 0x18
    assert operand(0x2AF57A0, "0f294424") == operand(0x2AF5A38, "0f284424") == 0x60
    caller_one_field = operand(0x2AF5A3D, "0f298424") - operand(0x2AF5AEE, "488dbc24")

    assert caller_one_field == 0x100
    assert edge(0x2AF5B03, "ff15") == 0x64E74D8
    assert relative[0x64E74D8] == 0x5A81ED0
    scratch = operand(0x5A81FB3, "488d7c24")
    assert operand(0x5A82002, "488d7424") == scratch == 0x10
    assert caller_one_field + 16 <= operand(0x5A81FB8, "ba") == 0x118
    assert operand(0x5A82007, "ba") == 0x2D80
    expect(0x5A81F1F, "4889fb")
    expect(0x5A81FBD, "4889de")
    expect(0x5A8200C, "4889df")
    expect(0x5A82024, "4889da")
    memcpy_slot = edge(0x5A81FC0, "ff15")
    assert edge(0x5A8200F, "ff15") == memcpy_slot == 0x64DF508
    assert relative[edge(0x5A82036, "ff25")] == 0x15D6EF0
    assert relative[edge(0x5A82015, "488d0d") + 0x18] == 0x5A82670
    name = b"nv_stream_forward_client_blocks"
    assert at(".rodata", edge(0x5A81FF1, "488d05"), len(name)) == name
    assert operand(0x5A874B9, "483bbb") == caller_one_field
    assert operand(0x5A874C6, "483bb3") == caller_one_field + 8

    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: startup result pointer +0x18/+0x20 feeds input +0x100/+0x108")
    print("PASS: task copy preserves both words and the pinned poll consumes them in order")


if __name__ == "__main__":
    main()
