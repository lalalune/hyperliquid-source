"""Verify the selected #115 native replay parent certificate projections against the pinned ELF."""
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
    entries = (0x5A82670, 0x4EFF5F0, 0x4FB7760, 0x59D5EA0, 0x5968D20,
               0x5968F10, 0x4E05180)
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

    def expect(address, raw):
        assert windows[address] == bytes.fromhex(raw), hex(address)

    for caller, target in (
        (0x4EFF6DB, 0x4FB7760), (0x4FB77FF, 0x59D5EA0),
        (0x59D5FB7, 0x5968D20), (0x59D60EC, 0x5968F10),
        (0x59D6275, 0x4E05180), (0x5968F50, 0x5968D20),
        (0x4E051F6, 0x5968D20), (0x5968F35, 0x5821250),
        (0x5968D3C, 0x5821250), (0x5968D5B, 0x5821250),
        (0x5968D7A, 0x5821250),
    ):
        assert edge(caller, "e8") == target
    for address, raw in (
        (0x5968D4E, "4c8b7c2410"), (0x5968D6D, "4c8b642410"),
        (0x5968D8C, "4c8b6c2410"), (0x5968EF0, "4c897b20"),
        (0x5968EF4, "4c896328"), (0x5968EF8, "4c896b30"),
        (0x4FB781C, "0f10842448040000"), (0x4FB7824, "0f298424a0000000"),
        (0x4FB790B, "0f284c2440"), (0x4FB7918, "0f118c24d0020000"),
        (0x59D5FC6, "4c8d4d01"), (0x59D63FF, "4c894b18"),
        (0x59D61BC, "0f29842410010000"), (0x59D6443, "0f114348"),
        (0x59D6109, "488b7c2430"), (0x59D624D, "4889bc2400010000"),
        (0x59D6320, "488bac2400010000"), (0x59D640F, "48896b38"),
        (0x59D61F9, "0f10442438"), (0x59D6225, "0f11842478010000"),
        (0x59D6328, "488bbc2478010000"), (0x59D6413, "48897b40"),
        (0x5968F43, "4c8b7c2410"), (0x59D61D4, "48898424d8010000"),
        (0x59D6378, "0f108c24d0010000"), (0x59D6380, "0f298c2430020000"),
        (0x59D644F, "0f288c2430020000"), (0x59D645E, "0f118b98000000"),
        (0x4E0528E, "488908"), (0x59D6465, "488983a8000000"),
        (0x59D62A4, "488b542430"), (0x59D62A9, "48899424a8000000"),
        (0x59D63A0, "4c8b9424a8000000"), (0x59D6481, "4c8993c8000000"),
        (0x59D62E9, "0f10442438"), (0x59D6315, "0f298424e0010000"),
        (0x59D6488, "0f288424e0010000"), (0x59D64BD, "0f1183d0000000"),
    ):
        expect(address, raw)
    assert edge(0x59D5FDC, "0f85") == 0x59D6190
    assert edge(0x59D61C7, "e9") == 0x59D63B0
    assert operand(0x4E0524A, "48b9") == -(1 << 63) + 1
    assert operand(0x4E0529C, "0f104424") - operand(0x4E051F1, "488d7c24") == 0x28
    assert operand(0x4E052BF, "0f1143") == 0x28
    assert operand(0x5968FCD, "0f104424") - 8 == 0x28
    assert operand(0x5968FF9, "0f118424") - operand(0x59690B5, "0f108424") == 0x28
    assert operand(0x59690D5, "0f298424") == operand(0x5969125, "488db424") == 0x180
    assert operand(0x596913B, "4c89bb") == 0x88

    # The header suffix is copied at the same relative offset into the Block,
    # and the Block begins 16 bytes after the owner's address.
    header_tail = operand(0x4FB786F, "488db424") - operand(0x4FB77F4, "488dbc24")
    assert header_tail == operand(0x4FB78E6, "488dbc24") - operand(0x4FB7AB2, "488db424") == 0x28
    assert operand(0x4EFF798, "488db424") - operand(0x4EFF6D0, "488dbc24") == 0x28
    owner_header_offset = operand(0x4EFF7A0, "488d7c24") - operand(0x4EFF80F, "488d7424") - header_tail
    assert owner_header_offset == 0x10

    bases = (
        operand(0x5A872E1, "488d70"), operand(0x5A8748B, "488d78"),
        operand(0x5A8748F, "488db0"),
    )
    offsets = (operand(0x5A874A1, "488b7e"), operand(0x5A874A5, "488b76"))
    pairs = tuple(tuple(base + word - owner_header_offset for word in offsets) for base in bases)
    assert pairs == ((0x40, 0x48), (0x38, 0x40), (0xC8, 0xD0))
    assert operand(0x5A872C7, "488b48") - owner_header_offset == 0x18
    assert operand(0x5A87496, "483990") - owner_header_offset == 0xA8
    successor_bases = (operand(0x5A874DA, "4883c0"), operand(0x5A874D3, "488db0"))
    assert tuple(base + operand(0x5A874E5, "488b40") - owner_header_offset
                 for base in successor_bases) == (0x50, 0xA0)
    expect(0x5A874E9, "48ffc0")
    expect(0x5A874F3, "480f45c8")
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: comparison uses the first two QC scalars on each of the three parent paths")
    print("PASS: direct QC takes scalar three as successor basis; timeout takes its own leading scalar")


if __name__ == "__main__":
    main()
