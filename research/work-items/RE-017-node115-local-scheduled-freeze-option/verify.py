"""Verify the local MessagePack scheduled-freeze option and materializer."""
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
    entries = (0x1850600, 0x199CE60, 0x1B44F30, 0x3C2E860, 0x3C13610, 0x2CC1120)
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

    def expect(address, raw):
        assert windows[address] == bytes.fromhex(raw), hex(address)

    table = edge(0x18507E4, "4c8d35")
    assert table + struct.unpack("<i", at(".rodata", table + 13 * 4, 4))[0] == 0x1851F82
    assert edge(0x1850C29, "ff15") == 0x64E27B0
    assert edge(0x1851F8B, "0f85") == 0x185B0C1
    assert at(".rodata", edge(0x185B0C1, "488d05"), 23) == b"scheduled_freeze_height"
    expect(0x185B0D0, "48c78424c82c000017000000")

    # Three option states: unseen/2, seen nil/0, seen scalar/1.
    expect(0x185083D, "b902000000")
    expect(0x1850842, "48898c2460010000")
    expect(0x1851F82, "4883bc246001000002")
    expect(0x1853640, "3cc0")
    expect(0x1853644, "48c784246001000000000000")
    assert edge(0x185367F, "ff15") == 0x64E2580
    expect(0x185368D, "3c09")
    assert edge(0x185368F, "0f85") == 0x18566EC
    expect(0x1853695, "488b8424000c0000")
    expect(0x185369D, "b901000000")
    expect(0x18536A2, "48898c2460010000")
    expect(0x18536AA, "4889842458020000")

    expect(0x1856EDB, "31c9")
    expect(0x1856EDD, "488b842460010000")
    expect(0x1856EE5, "4883f802")
    expect(0x1856EE9, "480f45c8")
    expect(0x1856EED, "48894c2468")
    expect(0x185DB7E, "488b442468")
    expect(0x185DB83, "488983e8100000")
    expect(0x185DB8A, "488b842458020000")
    expect(0x185DB92, "488983f0100000")

    assert edge(0x1B45512, "e8") == 0x199CE60
    assert edge(0x199CFCC, "e8") == 0x1850600
    expect(0x199CFBC, "488dbc2460400000")
    expect(0x199D111, "488db42488400000")
    expect(0x199D119, "488dbc2420980000")
    expect(0x199D121, "ba80270000")
    assert edge(0x199D126, "ff15") == 0x64DF508
    assert 0x4060 + 0x10E8 - 0x4088 == 0x97F8 + 0x10E8 - 0x9820
    expect(0x199D697, "baa8270000")
    expect(0x199D758, "baa8270000")
    expect(0x1B4510A, "baa8270000")

    expect(0x3C2EB57, "410f1086e8100000")
    expect(0x3C2EB5F, "0f298424d0000000")
    expect(0x3C2F057, "0f288424d0000000")
    expect(0x3C2F05F, "0f1183e8100000")
    expect(0x3C1367E, "bac8420000")
    assert edge(0x3C13689, "ff15") == 0x64DF508
    expect(0x2CC1AA6, "83b8e810000001")
    expect(0x2CC1AB7, "483988f0100000")

    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: Exchange field 13 identifies scheduled_freeze_height via its duplicate diagnostic")
    print("PASS: omitted and nil yield tag 0; unsigned value yields tag 1 and a payload")
    print("PASS: materializer preserves option offsets tested by local startup")


if __name__ == "__main__":
    main()
