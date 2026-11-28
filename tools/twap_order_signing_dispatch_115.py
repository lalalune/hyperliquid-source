#!/usr/bin/env python3
"""Verify the node #115 0xaa signing-dispatch handoff without executing it."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105_896_032


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def verify(data, check_identity=True):
    require(len(data) == TARGET_SIZE, "target size")
    digest = hashlib.sha256(data).hexdigest()
    if check_identity:
        require(digest == TARGET_SHA256, "target SHA-256")

    sec = sections(data)
    executable = [s for s in sec if s["name"] == ".text"]
    require(len(executable) == 1, "unique .text")
    text = executable[0]

    def read(va, size):
        matches = [s for s in sec if s["type"] != 8 and s["address"] <= va
                   and va + size <= s["address"] + s["size"]]
        require(len(matches) == 1, f"unique file mapping at {va:#x}")
        s = matches[0]
        off = s["offset"] + va - s["address"]
        return data[off:off + size]

    _, fdes = eh_frame_records(data, sec)
    expected_fdes = {
        0x36AA9A0: 0x36AADE6,
        0x36B1600: 0x36B3F7D,
        0x3C20F20: 0x3C213BB,
    }
    fde_records = {}
    for start, end in expected_fdes.items():
        rows = [row for row in fdes if row["start"] == start and row["end"] == end]
        require(len(rows) == 1, f"exact FDE {start:#x}..{end:#x}")
        fde_records[hex(start)] = {
            "end": hex(end),
            "body_sha256": hashlib.sha256(read(start, end - start)).hexdigest(),
        }

    # Dispatcher selector: tag - 0x86, signed 32-bit offsets from table base.
    require(read(0x36AA9F6, 5) == bytes.fromhex("e8056c0000"), "serializer dispatcher call")
    require(0x36AA9FB + struct.unpack("<i", read(0x36AA9F7, 4))[0] == 0x36B1600,
            "serializer dispatcher target")
    require(read(0x36B1600, 8) == bytes.fromhex("534883ec50488b06"), "dispatcher prologue")
    require(read(0x36B1608, 6) == bytes.fromhex("482d86000000"), "tag base subtraction")
    require(read(0x36B161A, 7) == bytes.fromhex("488d053b890efd"), "jump-table address load")
    table_base = 0x36B1621 + struct.unpack("<i", read(0x36B161D, 4))[0]
    require(table_base == 0x799F5C, "jump-table base")
    index = 0xAA - 0x86
    entry_va = table_base + index * 4
    relative = struct.unpack("<i", read(entry_va, 4))[0]
    arm = table_base + relative
    require(arm == 0x36B1EAF, "tag 0xaa arm target")

    # The selected arm constructs pointer/length descriptors and hands them to
    # the distinct serializer wrapper at 0x3c20f20.
    anchors = {
        0x36B1EAF: "4883c608",       # advance past the tag word
        0x36B1EB3: "488d05ecb60efd", # descriptor string at 0x79d5a6
        0x36B1EC8: "488d054fb80efd", # descriptor string at 0x79d71e
        0x36B1EDD: "488d056082dafc", # descriptor string at 0x45a144
        0x36B1EF2: "488d0599a90efd", # descriptor string at 0x79c892
        0x36B1F14: "e807f05600",     # direct call to 0x3c20f20
    }
    for va, raw in anchors.items():
        require(read(va, len(bytes.fromhex(raw))) == bytes.fromhex(raw), f"instruction anchor {va:#x}")
    require(0x36B1F19 + struct.unpack("<i", read(0x36B1F15, 4))[0] == 0x3C20F20,
            "selected writer call target")

    literals = {
        0x79D5A6: b"Action",
        0x79D71E: b"TwapOrder",
        0x45A144: b"type",
        0x79C892: b"twapOrder",
    }
    for va, literal in literals.items():
        require(read(va, len(literal)) == literal, f"literal {va:#x}")

    require(read(0x3C20F20, 8) == bytes.fromhex("5541574156415541"), "writer wrapper prologue")
    require(read(0x3C20F52, 7) == bytes.fromhex("488d05d6adb9fc"), "writer descriptor dispatch")
    return {
        "target_sha256": digest,
        "target_size": len(data),
        "dispatcher_fde": fde_records[hex(0x36B1600)],
        "writer_fde": fde_records[hex(0x3C20F20)],
        "table_base": hex(table_base),
        "tag": "0xaa",
        "table_index": index,
        "table_entry_va": hex(entry_va),
        "arm": hex(arm),
        "writer_call": {"site": "0x36b1f14", "target": "0x3c20f20"},
        "literals": {hex(va): value.decode("ascii") for va, value in literals.items()},
        "claim_limit": "selected static dispatch and handoff only; no full action preimage, hash, runtime value, or equivalence with other writer copies",
    }


def self_test(data):
    verify(data)
    cases = [
        (0x799F5C + (0xAA - 0x86) * 4, 0),
        (0x36B1F14, 0),
        (0x79D71E, 0),
    ]
    all_sections = sections(data)
    for va, relative in cases:
        mutated = bytearray(data)
        sec = next(s for s in all_sections if s["type"] != 8
                   and s["address"] <= va < s["address"] + s["size"])
        off = sec["offset"] + va - sec["address"]
        mutated[off + relative] ^= 1
        try:
            verify(mutated, check_identity=False)
        except EvidenceError:
            continue
        raise EvidenceError(f"mutation accepted at {va:#x}")
    return {"positive": 1, "mutations_rejected": len(cases)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    data = args.target.read_bytes()
    result = self_test(data) if args.self_test else verify(data)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
