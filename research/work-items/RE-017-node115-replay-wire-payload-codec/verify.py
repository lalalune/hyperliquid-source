"""Verify the selected #115 native calls reused by the replay wire decoder against the pinned ELF."""
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
    entries = (0x4EFF5F0, 0x4E052F0, 0x4E04E90)
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

    for caller, callee in (
        (0x4EFF60C, 0x5821150),   # compact variant
        (0x4EFF642, 0x5824B60),   # Tx blob
        (0x4EFF6DB, 0x4FB7760),   # Block
        (0x4EFF82F, 0x4E052F0),   # attachment option
        (0x4E05366, 0x5824840),   # present attachment vector
        (0x4E04EF4, 0x5824B60),   # common blob child
    ):
        assert edge(caller, "e8") == callee
    assert edge(0x4E0535A, "488d15") == 0x4E04E90
    for test_zero, branch_zero, expected_zero, cmp_one, branch_other, expected_other in (
        (0x4EFF622, 0x4EFF624, 0x4EFF6D0, 0x4EFF62A, 0x4EFF62D, 0x4EFF748),
        (0x4E05346, 0x4E05348, 0x4E053DF, 0x4E0534E, 0x4E05351, 0x4E053F1),
    ):
        assert windows[test_zero] == b"\x85\xc0"
        assert edge(branch_zero, "0f84") == expected_zero
        assert windows[cmp_one] == b"\x83\xf8\x01"
        assert edge(branch_other, "0f85") == expected_other
    assert windows[0x4E05313] == bytes.fromhex("4c8d4801")
    assert windows[0x4E05317] == bytes.fromhex("4c894e20")
    assert windows[0x4E05335] == bytes.fromhex("0fb602")
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} witness spans in {len(bounds)} FDEs")
    print("PASS: replay tag, option byte and child calls match the codec composition")


if __name__ == "__main__":
    main()
