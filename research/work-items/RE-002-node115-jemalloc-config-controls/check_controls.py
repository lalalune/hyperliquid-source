#!/usr/bin/env python3
"""Check that a same-value callback swap is visible and disagreeing output stores fail."""
import argparse
import json
import struct
from pathlib import Path

import verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("crate", type=Path)
    args = parser.parse_args()
    roots, leaves = verify.declaration(args.crate)
    directory = verify.HERE.parent / "RE-002-node115-native-libs-wave2-census"
    census = json.loads(verify.checked(directory / "census.json", verify.CENSUS_SHA))
    blob = (directory / "bodies.bin").read_bytes()
    image = bytearray(verify.checked(verify.ROOT / "artifacts/node/115/hl-node", verify.NODE_SHA))

    def walk():
        return verify.analyze(image, roots, leaves, census, blob)["controls"]

    original = walk()
    records = {r["name"]: r for r in original}
    pair = [records["config.fill"], records["config.stats"]]
    fields = [int(r["leaf"], 16) + 32 for r in pair]
    sections = {s["name"]: s for s in verify.sections(image)}
    rel = sections[".rela.dyn"]
    positions = {}
    for off in range(rel["offset"], rel["offset"] + rel["size"], 24):
        va, info, addend = struct.unpack_from("<QQq", image, off)
        if va in fields and info == 8:
            positions[va] = off + 16
    verify.require(set(fields) == positions.keys(), "missing callback relocation")
    offsets = [positions[field] for field in fields]
    handlers = [int(r["handler"], 16) for r in pair]
    for off, value in zip(offsets, reversed(handlers)):
        struct.pack_into("<q", image, off, value)
    swapped = walk()
    verify.require([r["value"] for r in original] == [r["value"] for r in swapped], "swap changed values")
    changed = [r for before, r in zip(original, swapped) if before != r]
    verify.require([r["name"] for r in changed] == [r["name"] for r in pair]
                   and [int(r["handler"], 16) for r in changed] == handlers[::-1], "swap went undetected")
    for off, value in zip(offsets, handlers):
        struct.pack_into("<q", image, off, value)
    text = sections[".text"]
    image[text["offset"] + handlers[0] - text["address"] + 60] ^= 1
    try:
        walk()
    except ValueError as exc:
        if str(exc) != "bool temporary, caller length or output store differs":
            raise
    else:
        raise AssertionError("disagreeing stores accepted")
    print("Detected same-value callback swap and rejected contradictory bool stores.")


if __name__ == "__main__":
    main()
