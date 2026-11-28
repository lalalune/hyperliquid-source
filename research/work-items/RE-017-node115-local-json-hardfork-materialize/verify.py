"""Verify the local JSON pair from its staging slots into the materialized startup state."""
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
    entries = (0x1F7E100, 0x1F2BD40, 0x1F3D760, 0x1D74270, 0x26A3610, 0x2CC1120, 0x3C13610, 0x3C2E860)
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

    def stack_pair(load, load_opcode, source, store, store_opcode, destination):
        expect(load, load_opcode + source.to_bytes(4, "little").hex())
        expect(store, store_opcode + destination.to_bytes(4, "little").hex())

    stack_pair(0x1F815B8, "0f108424", 0x2C0, 0x1F815F0, "0f118424", 0x1770)
    stack_pair(0x1F815C0, "0f108c24", 0x2D0, 0x1F815E8, "0f118c24", 0x1780)
    assert edge(0x1F81709, "e9") == 0x1F7FD8B

    def stack_copy(dest_addr, src_addr, count_addr, call, dest, src, count, binding):
        expect(dest_addr, "488dbc24" + dest.to_bytes(4, "little").hex())
        expect(src_addr, "488db424" + src.to_bytes(4, "little").hex())
        expect(count_addr, "ba" + count.to_bytes(4, "little").hex())
        if binding == "slot":
            assert edge(call, "ff15") == 0x64DF508
        else:
            expect(call, binding)

    for copy in (
        (0x1F7FD8B, 0x1F7FD93, 0x1F7FD9B, 0x1F7FDA0, 0x2490, 0x1760, 0xBA0, "slot"),
        (0x1F7FDB1, 0x1F7FDB9, 0x1F7FDC1, 0x1F7FDC6, 0x338, 0x2490, 0xBA0, "slot"),
        (0x1F7FE4A, 0x1F7FE42, 0x1F7FE52, 0x1F7FE57, 0x3218, 0x348, 0xB90, "slot"),
        (0x1F2BFB2, 0x1F2BFAA, 0x1F2BFBA, 0x1F2BFBF, 0x6AF0, 0xC30, 0xB90, "slot"),
        (0x1F2E5E8, 0x1F2E5F0, 0x1F2E5F8, 0x1F2E5FD, 0xC20, 0x6AE0, 0xBA0, "ffd5"),
        (0x1F2EBA5, 0x1F2EBB2, 0x1F2EBAD, 0x1F2EBBA, 0x3488, 0xC20, 0x10E8, "ffd5"),
        (0x1F2C0DD, 0x1F2C0E5, 0x1F2C0ED, 0x1F2C0F2, 0x7680, 0x3488, 0x27A8, "slot"),
        (0x1F2C103, 0x1F2C10B, 0x1F2C113, 0x1F2C118, 0xC20, 0x7680, 0x27A8, "slot"),
        (0x1F2C1A0, 0x1F2C198, 0x1F2C1A8, 0x1F2C1AD, 0xA9D0, 0xC30, 0x2798, "slot"),
    ):
        stack_copy(*copy)
    expect(0x1F7FE66, "488d7d10")
    expect(0x1F7FE6A, "488db42418320000")
    expect(0x1F7FE72, "ba900b0000")
    assert edge(0x1F7FE77, "ff15") == 0x64DF508
    assert edge(0x1F2E5DA, "488b2d") == 0x64DF508
    assert edge(0x1F2EED4, "e9") == 0x1F2C0DD
    expect(0x1F2C1BD, "488d7b10")
    expect(0x1F2C1C1, "488db424d0a90000")
    expect(0x1F2C1C9, "ba98270000")
    assert edge(0x1F2C1CE, "ff15") == 0x64DF508

    for address, target in (
        (0x1F2BF4D, 0x1F7E100), (0x1F3D9D6, 0x1F2BD40),
        (0x1D742BA, 0x1F3D760), (0x26A382E, 0x1D74270), (0x2CC1249, 0x26A3610),
    ):
        assert edge(address, "e8") == target
    expect(0x1F3D9F8, "4c8db424d0270000")
    assert edge(0x1F3D9E3, "4c8b3d") == 0x64DF508
    expect(0x1F3DA1A, "baa8270000")
    expect(0x1F3DA27, "4c89f6")
    expect(0x1F3DA2A, "41ffd7")
    expect(0x1F3DA1F, "4889442408")
    expect(0x1F3DBE6, "488b542408")
    expect(0x1D74325, "31db")
    expect(0x26A3833, "4889d3")
    expect(0x26A37F6, "4889da")

    rela = sections[".rela.dyn"]
    bindings = {a: dst for a, info, dst in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if info == 8}
    expect(0x2CC124E, "4989d7")
    expect(0x2CC19E4, "4c89ff")
    assert bindings[edge(0x2CC19EA, "ff15")] == 0x3C13610
    expect(0x2CC19F4, "498986e0000000")
    assert bindings[edge(0x3C13665, "ff15")] == 0x3C2E860
    expect(0x3C2EFFF, "baa00b0000")
    expect(0x3C2F00A, "41ffd5")
    assert edge(0x3C13689, "ff15") == 0x64DF508
    offsets = (0x1778 - 0x1760, 0x1780 - 0x1760)
    assert offsets == (0x18, 0x20) and offsets[-1] + 8 <= 0xBA0

    print(f"PASS: pinned #115 {TARGET_SHA256}, {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: local JSON Locus and Exchange aggregate copies preserve pair +0x18/+0x20")
    print("PASS: selected JSON allocation reaches the local state materializer")


if __name__ == "__main__":
    main()
