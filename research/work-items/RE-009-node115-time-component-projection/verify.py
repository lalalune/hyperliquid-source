"""Verify the selected #115 parsed time component projection against the pinned ELF."""
from datetime import time
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
    entries = (0x472E8C0, 0x1627E60)
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

    rela = sections[".rela.dyn"]
    relative = {offset: target for offset, info, target in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if info == 8}
    assert relative[edge(0x472E9C4, "ff15")] == 0x1627E60
    assert relative[edge(0x1627E7C, "ff15")] == 0x1627430
    assert edge(0x1627F50, "0f84") == 0x1628397
    assert windows[0x16283ED] == bytes.fromhex("7577")
    assert 0x16283ED + 2 + windows[0x16283ED][1] == 0x1628466
    assert windows[0x1628397] == bytes.fromhex("48c1e820")
    assert windows[0x162839B] + windows[0x162839E] == bytes.fromhex("8d0c7f418d0c88")
    assert windows[0x16283A2][:2] == bytes.fromhex("69f9")
    assert windows[0x16283A8][:3] == bytes.fromhex("416bc9")
    seconds_per_hour = int.from_bytes(windows[0x16283A2][2:], "little")
    seconds_per_minute = windows[0x16283A8][-1]
    assert seconds_per_hour == 3600 and seconds_per_minute == 60
    assert windows[0x16283AC] == bytes.fromhex("4401d9")
    assert windows[0x16283E7] == bytes.fromhex("01f9")
    assert windows[0x1627EF6] == bytes.fromhex("4183fb3c")
    assert windows[0x1627F00] == bytes.fromhex("41bb3b000000")
    assert windows[0x1627F06][:2] == bytes.fromhex("41ba")
    leap_bias = int.from_bytes(windows[0x1627F06][2:], "little")
    assert leap_bias == 10**9 and windows[0x1627F31] == bytes.fromhex("4401d2")
    assert windows[0x1628466] == bytes.fromhex("8903")
    assert windows[0x1628468] == bytes.fromhex("894b04")
    assert windows[0x162846B] == bytes.fromhex("895308")
    assert windows[0x472E9DB] == bytes.fromhex("48894304")
    assert windows[0x472E9D4] == bytes.fromhex("89430c")

    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in two FDEs")
    for hour, minute, second in ((0, 0, 0), (12, 34, 56), (23, 59, 59)):
        period, hour12 = divmod(hour, 12)
        packed_seconds = seconds_per_hour * (period * 12 + hour12) + seconds_per_minute * minute + second
        reference = time(hour, minute, second)
        assert packed_seconds == reference.hour * 3600 + reference.minute * 60 + reference.second
        print(f"PASS: model {reference.isoformat()} -> {packed_seconds} seconds of day")
    assert (23 * seconds_per_hour + 59 * seconds_per_minute + 59, leap_bias + 123_000_000) == (
        86_399, 1_123_000_000,
    )
    print("PASS: model 23:59:60.123 -> seconds 86399, fractional word 1123000000")



if __name__ == "__main__":
    main()
