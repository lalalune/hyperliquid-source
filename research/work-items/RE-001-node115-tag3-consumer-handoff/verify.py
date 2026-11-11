#!/usr/bin/env python3
"""Verify the node #115 raw-tag-3 consumer handoff packet without execution."""
import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def require(ok, label):
    if not ok:
        raise ValueError(label)


class Overlay:
    def __init__(self, image, address, replacement):
        self.image, self.address, self.replacement = image, address, replacement
        self.sections = image.sections

    def get(self, address, size):
        raw = bytearray(self.image.get(address, size))
        start = max(address, self.address)
        end = min(address + size, self.address + len(self.replacement))
        if start < end:
            raw[start - address:end - address] = self.replacement[start - self.address:end - self.address]
        return bytes(raw)


def check_facts(image, relocations, facts, decoder):
    for fact in facts:
        address = int(fact["address"], 16)
        kind = fact["kind"]
        if kind == "bytes":
            expected = bytes.fromhex(fact["hex"])
            require(image.get(address, len(expected)) == expected, fact["label"])
            continue
        if kind == "relative_word":
            disp = struct.unpack("<i", image.get(address, 4))[0]
            require(int(fact["base"], 16) + disp == int(fact["target"], 16), fact["label"])
            continue
        if kind == "relocation":
            actual = relocations.get(address)
            require(actual is not None and actual[0] == 8 and actual[1] == int(fact["target"], 16), fact["label"])
            continue
        rows = list(decoder.disasm(image.get(address, 15), address, count=1))
        require(len(rows) == 1, fact["label"])
        row = rows[0]
        if kind == "instruction":
            require((row.mnemonic, row.op_str) == (fact["mnemonic"], fact["operands"]), fact["label"])
        elif kind == "direct":
            require(row.mnemonic == fact["mnemonic"] and len(row.operands) == 1 and
                    row.operands[0].type == X86_OP_IMM and row.operands[0].imm == int(fact["target"], 16), fact["label"])
        elif kind == "rip":
            operands = [o for o in row.operands if o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP]
            require(row.mnemonic == fact["mnemonic"] and len(operands) == 1 and
                    row.address + row.size + operands[0].mem.disp == int(fact["target"], 16), fact["label"])
            if "register" in fact:
                require(row.reg_name(row.operands[0].reg) == fact["register"], fact["label"])
        else:
            raise ValueError("unknown fact kind: " + kind)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    args = parser.parse_args()
    packet = json.loads((HERE / "records.json").read_text())
    data = args.target.read_bytes()
    require(hashlib.sha256(data).hexdigest() == PIN == packet["target_sha256"], "target SHA-256")
    require(capstone.__version__ == "5.0.7", "use recorded Capstone 5.0.7")
    helper_path = ROOT / "research/work-items/RE-001-node115-registry-row-labels/verify.py"
    spec = importlib.util.spec_from_file_location("node115_elf_support", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    image = helper.Image(data)
    relocs = image.relocs()
    _, fdes = helper.eh_frame_records(data, image.sections)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    byte_count = instruction_count = 0
    for window in packet["windows"]:
        start, end = int(window["start"], 16), int(window["end"], 16)
        owners = [f for f in fdes if f["start"] <= start and end <= f["end"]]
        require(len(owners) == 1 and [hex(owners[0]["start"]), hex(owners[0]["end"])] == window["fde"], "FDE extent")
        owner = owners[0]
        decoded = list(decoder.disasm(image.get(owner["start"], owner["end"] - owner["start"]), owner["start"]))
        rows = [r for r in decoded if start <= r.address < end]
        require(rows and rows[0].address == start and rows[-1].address + rows[-1].size == end, "window instruction boundaries")
        raw = image.get(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == window["sha256"], "window SHA-256")
        actual = [[hex(r.address), r.bytes.hex(), r.mnemonic + " " + r.op_str] for r in rows]
        require(actual == window["rows"], "retained instruction rows")
        byte_count += len(raw)
        instruction_count += len(rows)
    check_facts(image, relocs, packet["facts"], decoder)
    rejected = []
    for control in packet["controls"]:
        changed_image, changed_relocs = image, relocs
        address = int(control["address"], 16)
        if control["kind"] == "bytes":
            replacement = bytes.fromhex(control["replacement_hex"])
            require(image.get(address, len(replacement)) != replacement, "control does not change input")
            changed_image = Overlay(image, address, replacement)
        elif control["kind"] == "relocation":
            changed_relocs = dict(relocs)
            old = relocs[address]
            target = int(control["target"], 16)
            require((old[0], old[1]) != (8, target), "control does not change relocation")
            changed_relocs[address] = (8, target, old[2])
        try:
            check_facts(changed_image, changed_relocs, packet["facts"], decoder)
        except ValueError:
            rejected.append(control["label"])
        else:
            raise ValueError("semantic corruption accepted: " + control["label"])
    print(json.dumps({"issue": packet["issue"], "target_sha256": PIN,
                      "windows": len(packet["windows"]), "bytes": byte_count,
                      "instructions": instruction_count, "facts": len(packet["facts"]),
                      "corruptions_rejected": rejected,
                      "scope": "static tag-3 selector-to-consumer handoff; runtime publication semantics remain open"}, indent=2))


if __name__ == "__main__":
    main()
