"""Check the selected positional checkpoint-root cadence path without executing the ELF."""

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
    entries = (0x4E4B860, 0x4E36140, 0x4E48EE0, 0x5484670, 0x457CF60, 0x5480950, 0x452AAB0)
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

    # Follow the pointer and length through the normal return path of the producer.
    vector = operand(0x4E4B8B8, "488d4424")
    assert vector == 0x70
    assert windows[0x4E4B8BD] == bytes.fromhex("48890424")
    encoded_config = operand(0x4E4B8C1, "c74424")
    assert encoded_config == 0x0100040008
    assert operand(0x548096E, "807a") == 0x0B
    assert (encoded_config >> 32) == 1
    assert edge(0x4E4B8DE, "e8") == 0x5480950
    assert windows[0x4E4B8F2] == bytes.fromhex("498d4704")
    assert windows[0x4E4B8F6] == bytes.fromhex("4939c6")
    assert operand(0x4E4B8FF, "488b4424") == vector
    assert operand(0x4E4B904, "48894424") == operand(0x4E4BAFE, "488b4424")
    assert operand(0x4E4B909, "488b4424") == vector + 8
    assert operand(0x4E4B90E, "48894424") == operand(0x4E4BB06, "488b4424")
    assert operand(0x4E4B913, "4c8bb424") == vector + 16
    assert windows[0x4E4BB03] == bytes.fromhex("488903")
    assert operand(0x4E4BB0B, "488943") == 8
    assert operand(0x4E4BB0F, "4c8973") == 16
    assert edge(0x4E361A4, "74") == 0x4E361F3
    serialized = operand(0x4E361F3, "488d7c24")
    assert edge(0x4E361FB, "e8") == 0x4E4B860
    assert operand(0x4E36212, "0f104424") == serialized
    assert windows[0x4E36217] == bytes.fromhex("0f1103")
    assert operand(0x4E3621A, "488b4424") == serialized + 16
    assert operand(0x4E3621F, "488943") == 16
    assert windows[0x4E48F72] == bytes.fromhex("4889df")
    assert edge(0x4E48F7E, "e8") == 0x4E36140
    worker_out = operand(0x5484694, "488d7c24")
    assert edge(0x54846A3, "e8") == 0x4E48EE0
    assert operand(0x54846AD, "4c8b7424") == worker_out + 8
    assert operand(0x54846B2, "4c8b6424") == worker_out + 16

    rela = sections[".rela.dyn"]
    relocations = {
        slot: (info, target) for slot, info, target in struct.iter_unpack(
            "<QQq", at(".rela.dyn", rela["va"], rela["size"])
        )
    }
    assert relocations[edge(0x54846F7, "ff15")] == (8, 0x41C5140)
    record = operand(0x54847A0, "488d7424")
    assert operand(0x548477A, "4c897424") == record
    assert operand(0x548477F, "4c896424") == record + 8
    assert operand(0x5484784, "488d4424") == operand(0x5484770, "0f294424")
    assert operand(0x5484789, "48894424") == record + 16
    assert operand(0x5484793, "48894424") == record + 24
    assert edge(0x54847AA, "e8") == 0x452AAB0

    assert windows[0x452AC5B] == windows[0x452AD49] == bytes.fromhex("4889df")
    assert windows[0x452AC5E] == windows[0x452AD4C] == bytes.fromhex("4c89fe")
    assert edge(0x452AC61, "e8") == edge(0x452AD4F, "e8") == 0x457CF60
    assert windows[0x457CF71] == bytes.fromhex("4989f6")
    assert windows[0x457CF8A] == bytes.fromhex("4d8b3e")
    assert operand(0x457CF8D, "4d8b6e") == 8
    assert windows[0x457D041] == bytes.fromhex("4c89fe")
    assert windows[0x457D044] == bytes.fromhex("4c89ea")
    assert relocations[edge(0x457D02F, "488b2d")] == (8, 0x160B3A0)
    assert relocations[edge(0x457D049, "4c8b3d")] == (8, 0x160BCD0)
    assert operand(0x457D050, "488dbc24") == operand(0x457D123, "0f108424")
    assert operand(0x457D066, "498b46") == 16
    assert windows[0x457D06A] == bytes.fromhex("0f1000")
    assert operand(0x457D06D, "0f1048") == 16
    root = operand(0x457D079, "0f118424")
    assert operand(0x457D071, "0f118c24") == root + 16
    assert operand(0x457D157, "0f108424") == root
    assert operand(0x457D15F, "0f108c24") == root + 16
    assert operand(0x457D14A, "ba") == operand(0x457D171, "ba") == 32
    assert windows[0x457D047] == windows[0x457D155] == windows[0x457D17C] == bytes.fromhex("ffd5")
    assert windows[0x457D05B] == windows[0x457D186] == bytes.fromhex("41ffd7")
    assert operand(0x457D195, "660f114b") == 16
    assert windows[0x457D19A] == bytes.fromhex("660f1103")

    assert not matches_window(0x457CF8D, bytes.fromhex("4d8b6e10"))
    assert not matches_window(0x457D066, bytes.fromhex("498b4618"))
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} instruction windows")
    print("FDEs: " + ", ".join(f"{start:#x}..{end:#x}" for start, end in bounds))
    print("PASS: exact serializer pointer/length reach the first BLAKE3 update")
    print("PASS: two 32-byte updates bind the state hash then raw ABCI digest")
    print("PASS: changed state length and wrong metadata pointer controls are rejected")


if __name__ == "__main__":
    main()
