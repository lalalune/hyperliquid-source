#!/usr/bin/env python3
"""Check named digest-vote writers against the authenticated #115 capture."""
import csv
import hashlib
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

TARGET = ROOT / "artifacts/node/115/hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def window(data, sec, address, width):
    offset = sec["offset"] + address - sec["address"]
    if not sec["offset"] <= offset or offset + width > sec["offset"] + sec["size"]:
        raise ValueError(f"window outside {sec['name']} at {address:#x}")
    return data[offset : offset + width]


def require_equal(actual, expected, address):
    if actual != expected:
        raise ValueError(f"changed window at {address:#x}")


def main():
    data = TARGET.read_bytes()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError("wrong #115 capture")
    secs = sections(data)
    text = next(sec for sec in secs if sec["name"] == ".text")
    rodata = next(sec for sec in secs if sec["name"] == ".rodata")
    _, index = unwind_index(data)
    indexed = {(r["start"], r["fde"]) for r in index}
    _, extents = eh_frame_records(data, secs)
    bounds = {r["start"]: r["end"] for r in extents if (r["start"], r["fde"]) in indexed}
    verified = 0
    with (PACKET / "instructions.tsv").open(newline="") as rows:
        for row in csv.DictReader(rows, delimiter="\t"):
            start, address = (int(row[k], 16) for k in ("fde", "va"))
            expected = bytes.fromhex(row["bytes"])
            if not start <= address < address + len(expected) <= bounds[start]:
                raise ValueError(f"invalid unwind range at {address:#x}")
            actual = window(data, text, address, len(expected))
            require_equal(actual, expected, address)
            literal = row["rip_literal"]
            if literal:
                delta, = struct.unpack_from("<i", actual, len(actual) - 4)
                expected_literal = literal.encode("ascii")
                target = address + len(actual) + delta
                require_equal(window(data, rodata, target, len(expected_literal)), expected_literal, target)
            try:
                require_equal(bytes([actual[0] ^ 1]) + actual[1:], expected, address)
            except ValueError:
                verified += 1
            else:
                raise AssertionError(f"missed byte mutation at {address:#x}")
    if not verified:
        raise ValueError("no instructions checked")
    print(f"{verified} instructions checked; {verified} mutations rejected")


if __name__ == "__main__":
    main()
