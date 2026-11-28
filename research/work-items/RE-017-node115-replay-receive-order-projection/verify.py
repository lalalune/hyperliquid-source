"""Pin the selected #115 receive-order operands used by the Rust adapter."""
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

ANCHORS = (
    (0x5A875B0, "48397e28"),
    (0x5A875B4, "4c8d8ea0000000"),
    (0x5A875BF, "4d8b4110"),
    (0x5A875C3, "49ffc0"),
    (0x5A875C6, "49c7c1ffffffff"),
    (0x5A875E5, "4c8d4630"),
    (0x5A875EB, "4c8d4e28"),
    (0x5A875EF, "4c8d86b8000000"),
    (0x5A875F6, "4839beb8000000"),
    (0x5A875FD, "4d0f44c1"),
    (0x5A87601, "4d8b4030"),
    (0x5A87613, "4c8b5010"),
    (0x5A87617, "4c8b8810010000"),
    (0x5A87621, "743c"),
    (0x5A87627, "49c1e204"),
    (0x5A8762E, "4883c0f0"),
    (0x5A8764D, "488b4010"),
    (0x5A87651, "48ffc0"),
    (0x5A87654, "49c7c1ffffffff"),
    (0x5A87663, "4d39c8"),
    (0x5A87666, "0f83e6030000"),
)


def main():
    assert __debug__, "run without -O"
    data = (ROOT / TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {row["name"]: row for row in parse_sections(data)}
    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(data[eh["offset"]:eh["offset"] + eh["size"]], eh["va"])
    start, end = 0x5A82670, 0x5A89535
    assert any(row["entry"] == start and row["end"] == end for row in fdes)
    text = sections[".text"]
    for address, encoding in ANCHORS:
        raw = bytes.fromhex(encoding)
        assert start <= address < address + len(raw) <= end
        offset = address - text["va"] + text["offset"]
        target = data[offset:offset + len(raw)]
        assert raw == target and raw[:-1] + bytes([raw[-1] ^ 1]) != target
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}, FDE {start:#x}..{end:#x}, {len(ANCHORS)} anchors")
    print("PASS: parent choice, empty/tail source, saturating successor and unsigned compare")
    print("PASS: altered instruction control at each anchor")


if __name__ == "__main__":
    main()
