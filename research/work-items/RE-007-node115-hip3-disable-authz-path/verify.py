#!/usr/bin/env python3
"""Check a bounded authorization-path evidence packet against pinned ELF bytes."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

import capstone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def require(condition, label):
    if not condition:
        raise ValueError(label)


class Overlay:
    def __init__(self, image, address, replacement):
        self.image = image
        self.address = address
        self.replacement = replacement

    def get(self, address, size):
        result = bytearray(self.image.get(address, size))
        for i, value in enumerate(self.replacement):
            relative = self.address + i - address
            if 0 <= relative < size:
                result[relative] = value
        return bytes(result)


def check_facts(image, facts, instructions):
    for fact in facts:
        address = int(fact["address"], 16)
        expected = bytes.fromhex(fact["hex"])
        require(instructions.get(address) == expected, fact["label"] + " instruction bytes")
        require(image.get(address, len(expected)) == expected, fact["label"] + " ELF bytes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    args = parser.parse_args()
    data = args.target.read_bytes()
    require(hashlib.sha256(data).hexdigest() == PIN, "target SHA-256")
    support = ROOT / "research/work-items/RE-001-node115-registry-row-labels/verify.py"
    spec = importlib.util.spec_from_file_location("node115_elf_support", support)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    image = helper.Image(data)
    _, fdes = helper.eh_frame_records(data, image.sections)
    records = json.loads((HERE / "records.json").read_text())
    require(capstone.__version__ == "5.0.7", "use recorded Capstone 5.0.7")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    instructions = {}
    for window in records["windows"]:
        start = int(window["start"], 16)
        end = int(window["end"], 16)
        enclosing = [f for f in fdes if f["start"] <= start and end <= f["end"]]
        require(len(enclosing) == 1, "unique enclosing FDE: " + window["label"])
        require([hex(enclosing[0]["start"]), hex(enclosing[0]["end"])] == window["fde"],
                "FDE identity: " + window["label"])
        raw = image.get(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == window["sha256"],
                "window SHA-256: " + window["label"])
        rows = list(decoder.disasm(raw, start))
        require(rows and rows[0].address == start and
                rows[-1].address + rows[-1].size == end,
                "instruction boundaries: " + window["label"])
        for row in rows:
            instructions[row.address] = row.bytes
    check_facts(image, records["facts"], instructions)
    for fact in records["facts"]:
        address = int(fact["address"], 16)
        expected = bytes.fromhex(fact["hex"])
        changed = bytes([expected[0] ^ 1]) + expected[1:]
        try:
            check_facts(Overlay(image, address, changed), [fact], instructions)
        except ValueError:
            continue
        raise ValueError("instruction-byte corruption accepted: " + fact["label"])
    print(json.dumps({"target_sha256": PIN, "windows": len(records["windows"]),
                      "pinned_instruction_facts": len(records["facts"]),
                      "instruction_byte_controls_rejected": len(records["facts"]),
                      "result": "PASS", "scope": "static selected bytes and FDEs"}, indent=2))


if __name__ == "__main__":
    main()
