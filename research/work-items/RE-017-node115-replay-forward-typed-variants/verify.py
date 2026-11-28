"""Check nonopaque #115 outer-writer dispatch and ordered child targets."""
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

# index, branch, emitted-tag site, ordered child (call site, target) pairs
CASES = (
    (1, 0x581f439, 0x581f447, ((0x581f461, 0x5822910), (0x581f481, 0x5966a30), (0x581f4ae, 0x51ffde0))),
    (2, 0x581f2ff, 0x581f30d, ((0x581f365, 0x59681d0), (0x581f384, 0x5967060))),
    (3, 0x581f39d, 0x581f3ab, ((0x581f3fd, 0x59681d0), (0x581f420, 0x5966b90))),
    (4, 0x581f25d, 0x581f26b, ((0x581f2c3, 0x59681d0), (0x581f2e6, 0x59676c0))),
    (5, 0x581f4c7, 0x581f4d5, ((0x581f52d, 0x59681d0), (0x581f550, 0x5b561e0))),
    (6, 0x581f569, 0x581f577, ((0x581f5c0, 0x59681d0), (0x581f5df, 0x5b5b360))),
)


def direct(address, encoding):
    assert len(encoding) == 5 and encoding[0] == 0xe8
    return address + 5 + struct.unpack("<i", encoding[1:])[0]


def main():
    assert __debug__, "run without -O"
    data = (ROOT / TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def read(name, address, size):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + size <= section["size"]
        offset = section["offset"] + delta
        return data[offset:offset + size]

    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    start, end = 0x581f160, 0x581f797
    assert any(fde["entry"] == start and fde["end"] == end for fde in fdes)
    assert read(".text", 0x581f19a, 10) == bytes.fromhex("49bd0000000000000080")
    assert read(".text", 0x581f1c1, 15) == bytes.fromhex("4c31e94885c0b802000000480f48c1")
    lea = read(".text", 0x581f1d4, 7)
    assert lea[:3] == bytes.fromhex("488d0d")
    table = 0x581f1db + struct.unpack("<i", lea[3:])[0]
    assert table == 0x935b40
    assert read(".text", 0x581f1db, 9) == bytes.fromhex("486304814801c8ffe0")
    assert table + struct.unpack("<i", read(".rodata", table, 4))[0] == 0x581f1e4
    for tag, branch, site, calls in CASES:
        offset = struct.unpack("<i", read(".rodata", table + 4 * tag, 4))[0]
        assert table + offset == branch
        assert table + (offset ^ 1) != branch
        assert branch < site < calls[0][0] < end
        assert read(".text", site, 4) == bytes((0xc6, 0x04, 0x30, tag))
        for address, callee in calls:
            assert site < address < end
            raw = read(".text", address, 5)
            assert direct(address, raw) == callee
            assert direct(address, raw[:-1] + bytes((raw[-1] ^ 1,))) != callee
        print(f"slot {tag} -> {branch:#x}, tag {tag}: " + ", ".join(hex(callee) for _, callee in calls))
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; FDE {start:#x}..{end:#x}")
    print("PASS: signed relative table, nonopaque child order, changed displacement controls")


if __name__ == "__main__":
    main()
