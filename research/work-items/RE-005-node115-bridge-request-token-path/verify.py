#!/usr/bin/env python3
"""Verify selected static bridge token facts against node #115; never executes it."""
import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def require(ok, message):
    if not ok:
        raise ValueError(message)


class Overlay:
    def __init__(self, image, address, data):
        self.image, self.address, self.data = image, address, data
        self.sections = image.sections

    def get(self, address, size):
        b = bytearray(self.image.get(address, size))
        for i, value in enumerate(self.data):
            j = self.address + i - address
            if 0 <= j < size:
                b[j] = value
        return bytes(b)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    args = p.parse_args()
    rec = json.loads((HERE / "records.json").read_text())
    data = args.target.read_bytes()
    require(hashlib.sha256(data).hexdigest() == PIN == rec["target_sha256"], "target digest")
    helper_path = ROOT / "research/work-items/RE-001-node115-registry-row-labels/verify.py"
    spec = importlib.util.spec_from_file_location("node115_packet_support", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    image = helper.Image(data)
    relocs = image.relocs()
    _, fdes = helper.eh_frame_records(data, image.sections)
    for w in rec["windows"]:
        start, end = int(w["start"], 16), int(w["end"], 16)
        matches = [f for f in fdes if f["start"] == start and f["end"] == end]
        require(len(matches) == 1, "exact FDE " + w["name"])
    for f in rec["facts"]:
        address = int(f["address"], 16)
        expected = bytes.fromhex(f["hex"])
        require(image.get(address, len(expected)) == expected, f["label"])
    for t in rec["tables"]:
        base = int(t["base"], 16)
        for entry in t["entries"]:
            at = base + 4 * entry["index"]
            dest = base + struct.unpack("<i", image.get(at, 4))[0]
            require(dest == int(entry["target"], 16), t["name"] + " entry " + str(entry["index"]))
    for r in rec["relocations"]:
        found = relocs.get(int(r["address"], 16))
        require(found is not None and found[0] == r["type"] and found[1] == int(r["target"], 16), "relocation " + r["address"])
    control = rec["controls"][0]
    address = int(control["address"], 16)
    altered = Overlay(image, address, bytes.fromhex(control["replacement_hex"]))
    require(altered.get(address, len(bytes.fromhex(control["replacement_hex"]))) != image.get(address, len(bytes.fromhex(control["replacement_hex"]))), "negative control changes bytes")
    require(not all(altered.get(int(f["address"], 16), len(bytes.fromhex(f["hex"]))) == bytes.fromhex(f["hex"]) for f in rec["facts"] if f["address"] == control["address"]), "negative control rejected")
    print(json.dumps({"target_sha256": PIN, "windows": len(rec["windows"]), "facts": len(rec["facts"]), "jump_table_entries": sum(len(t["entries"]) for t in rec["tables"]), "relocations": len(rec["relocations"]), "negative_control": "rejected", "scope": "static selected facts only"}, indent=2))


if __name__ == "__main__":
    main()
