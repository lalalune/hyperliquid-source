#!/usr/bin/env python3
"""Verify selected bridge ABI-layout evidence against node #115; no execution."""
import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Overlay:
    def __init__(self, image, address, data):
        self.image, self.address, self.data = image, address, data
        self.sections = image.sections

    def get(self, address, size):
        result = bytearray(self.image.get(address, size))
        for i, value in enumerate(self.data):
            relative = self.address + i - address
            if 0 <= relative < size:
                result[relative] = value
        return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    args = parser.parse_args()
    packet = json.loads((HERE / "records.json").read_text())
    data = args.target.read_bytes()
    require(hashlib.sha256(data).hexdigest() == PIN == packet["target_sha256"], "target SHA-256")
    support_path = ROOT / "research/work-items/RE-001-node115-registry-row-labels/verify.py"
    spec = importlib.util.spec_from_file_location("node115_abi_layout_support", support_path)
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    image = support.Image(data)
    _, fdes = support.eh_frame_records(data, image.sections)
    for window in packet["windows"]:
        start, end = int(window["start"], 16), int(window["end"], 16)
        matches = [fde for fde in fdes if fde["start"] == start and fde["end"] == end]
        require(len(matches) == 1, "exact FDE " + window["name"])
    for fact in packet["facts"]:
        address = int(fact["address"], 16)
        expected = bytes.fromhex(fact["hex"])
        require(image.get(address, len(expected)) == expected, fact["label"])
    for table in packet["tables"]:
        base = int(table["base"], 16)
        for entry in table["entries"]:
            slot = base + entry["index"] * 4
            destination = base + struct.unpack("<i", image.get(slot, 4))[0]
            require(destination == int(entry["target"], 16), table["name"] + " entry " + str(entry["index"]))
    relocations = image.relocs()
    for row in packet["relocations"]:
        found = relocations.get(int(row["address"], 16))
        require(found is not None and found[0] == row["type"] and found[1] == int(row["target"], 16), "relocation " + row["address"])

    layout = packet["layout"]
    normalized = [({0: 0, 4: 0, 6: 2}[tag]) for tag in layout["raw_tags"]]
    tail_words = (layout["label_length"] + 31) // 32 + 1
    expected = {
        "normalized_tags": normalized,
        "head_words": len(layout["raw_tags"]),
        "dynamic_offset": len(layout["raw_tags"]) * 32,
        "dynamic_tail_words": tail_words,
        "total_bytes": (len(layout["raw_tags"]) + tail_words) * 32,
    }
    for name, value in expected.items():
        require(layout[name] == value, "derived layout " + name)
    control = packet["controls"][0]
    address = int(control["address"], 16)
    replacement = bytes.fromhex(control["replacement_hex"])
    altered = Overlay(image, address, replacement)
    require(altered.get(address, len(replacement)) != image.get(address, len(replacement)), "negative control changes input")
    require(not all(altered.get(int(f["address"], 16), len(bytes.fromhex(f["hex"]))) == bytes.fromhex(f["hex"]) for f in packet["facts"] if f["address"] == control["address"]), "negative control rejected")
    print(json.dumps({
        "target_sha256": PIN,
        "exact_fdes": len(packet["windows"]),
        "instruction_facts": len(packet["facts"]),
        "selected_jump_table_entries": sum(len(table["entries"]) for table in packet["tables"]),
        "relocations": len(packet["relocations"]),
        "normalized_tags": normalized,
        "head_bytes": expected["dynamic_offset"],
        "tail_bytes": tail_words * 32,
        "serialized_length": expected["total_bytes"],
        "negative_control": "rejected",
        "scope": "static ABI shape; not runtime output",
    }, indent=2))


if __name__ == "__main__":
    main()
