#!/usr/bin/env python3
"""Static byte and relocation checks for the node #115 HIP-3 identity lookup."""
import argparse
import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records

PIN = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CALLERS = (
    # Call-site prefix, helper call, false-result branch.
    (0x2C48585, "4883c7500fb6d1488db424d0020000", 0x2C48594, "e8d75ba501", "0f844f010000"),
    (0x55AD945, "4883c7500fb6d1488db424d0020000", 0x55AD954, "e817080fff", "0f844f010000"),
    (0x55B3645, "4883c7500fb6d1488db424d0020000", 0x55B3654, "e817ab0eff", "0f844f010000"),
)
FACTS = {
    0x469E184: "88542407",  # selector byte saved from DL
    0x469E22F: "4c8b251a19e401",  # load GOT comparison function
    0x469E265: "4c8d7614ba14000000",  # next element; compare 20 bytes
    0x469E271: "41ffd4",  # indirect comparison call
    0x469E281: "49ffc5",  # advance through selected identity array
    0x469E2A5: "4983ef01",  # exhausted selected array returns false
    0x469E2C1: "b001",  # equality path returns true
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def mapped(data, secs, va, size):
    found = [s for s in secs if s["type"] != 8 and s["address"] <= va and va + size <= s["address"] + s["size"]]
    require(len(found) == 1, f"unmapped/ambiguous VA {va:#x}")
    s = found[0]
    off = s["offset"] + va - s["address"]
    return data[off:off + size]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    args = parser.parse_args()
    data = args.target.read_bytes()
    require(hashlib.sha256(data).hexdigest() == PIN, "target SHA-256")
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    expected_fdes = {
        0x469E170: 0x469E2D2,
        0x2C47660: 0x2C4D2E9,
        0x55ACA20: 0x55B271B,
        0x55B2720: 0x55B841B,
        0x35BF6C0: 0x35BF830,
        0x4552D70: 0x4553089,
    }
    indexed_fdes = {row["start"]: row["end"] for row in fdes}
    for start, end in expected_fdes.items():
        require(indexed_fdes.get(start) == end, f"FDE extent {start:#x}")
    for address, code in FACTS.items():
        require(mapped(data, secs, address, len(bytes.fromhex(code))) == bytes.fromhex(code), f"instruction bytes {address:#x}")
    for setup, prefix, call, call_bytes, false_branch in CALLERS:
        require(mapped(data, secs, setup, len(bytes.fromhex(prefix))) == bytes.fromhex(prefix), f"caller setup {setup:#x}")
        require(mapped(data, secs, call, len(bytes.fromhex(call_bytes))) == bytes.fromhex(call_bytes), f"helper call {call:#x}")
        require(mapped(data, secs, call + 14, len(bytes.fromhex(false_branch))) == bytes.fromhex(false_branch), f"false-result branch {call + 14:#x}")
    reloc = next(s for s in secs if s["name"] == ".rela.dyn")
    matches = []
    for off in range(reloc["offset"], reloc["offset"] + reloc["size"], 24):
        slot, info, addend = struct.unpack_from("<QQq", data, off)
        if slot == 0x64DFB50:
            matches.append((info, addend))
    require(len(matches) == 1 and matches[0][0] & 0xFFFFFFFF == 6, "memcmp GOT relocation")
    dynsym = next(s for s in secs if s["name"] == ".dynsym")
    dynstr = next(s for s in secs if s["name"] == ".dynstr")
    symbol_index = matches[0][0] >> 32
    sym_name, = struct.unpack_from("<I", data, dynsym["offset"] + symbol_index * 24)
    start = dynstr["offset"] + sym_name
    end = data.find(b"\0", start, dynstr["offset"] + dynstr["size"])
    require(data[start:end] == b"memcmp", "comparison import name")
    print("PASS: pinned target, selector-call byte paths, 20-byte identity compare, and memcmp relocation")


if __name__ == "__main__":
    main()
