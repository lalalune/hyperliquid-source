#!/usr/bin/env python3
"""Verify a bounded static packet against the original pinned node #115 ELF.

No native code is executed. Corruption controls exercise semantic checks with
in-memory overlays after the original target digest has been authenticated.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def require(condition, label):
    if not condition:
        raise ValueError(label)


class Overlay:
    def __init__(self, image, address, replacement):
        self.image, self.address, self.replacement = image, address, replacement

    def get(self, address, size):
        result = bytearray(self.image.get(address, size))
        for i, value in enumerate(self.replacement):
            relative = self.address + i - address
            if 0 <= relative < size:
                result[relative] = value
        return bytes(result)


def check_facts(image, relocations, packet, decoder):
    for fact in packet["facts"]:
        address = int(fact["address"], 16)
        kind = fact["kind"]
        if kind == "literal":
            require(image.get(address, len(fact["ascii"])) == fact["ascii"].encode("ascii"), fact["label"])
            continue
        if kind == "relocation":
            observed = relocations.get(address)
            require(observed is not None and observed[0] == 8 and observed[1] == int(fact["target"], 16), fact["label"])
            continue
        rows = list(decoder.disasm(image.get(address, 15), address, count=1))
        require(len(rows) == 1, fact["label"])
        row = rows[0]
        if kind == "instruction":
            require((row.mnemonic, row.op_str) == (fact["mnemonic"], fact["operands"]), fact["label"])
        elif kind == "direct":
            require(row.mnemonic == fact["mnemonic"] and len(row.operands) == 1 and row.operands[0].type == X86_OP_IMM and row.operands[0].imm == int(fact["target"], 16), fact["label"])
        elif kind == "rip":
            operands = [o for o in row.operands if o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP]
            require(row.mnemonic == fact["mnemonic"] and len(operands) == 1 and row.address + row.size + operands[0].mem.disp == int(fact["target"], 16), fact["label"])
            if "register" in fact:
                require(row.reg_name(row.operands[0].reg) == fact["register"], fact["label"])
        else:
            raise ValueError("unknown fact kind")


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
    relocations = image.relocs()
    _, fdes = helper.eh_frame_records(data, image.sections)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    byte_count = row_count = 0
    for window in packet["windows"]:
        start, end = int(window["start"], 16), int(window["end"], 16)
        enclosing = [f for f in fdes if f["start"] <= start and end <= f["end"]]
        require(len(enclosing) == 1 and [hex(enclosing[0]["start"]), hex(enclosing[0]["end"])] == window["fde"], "enclosing FDE")
        # Decode from the FDE boundary so an interior byte cannot impersonate
        # an instruction start, then retain only the selected window.
        f = enclosing[0]
        decoded = list(decoder.disasm(image.get(f["start"], f["end"] - f["start"]), f["start"]))
        rows = [r for r in decoded if start <= r.address < end]
        require(rows and rows[0].address == start and rows[-1].address + rows[-1].size == end, "window instruction boundaries")
        raw = image.get(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == window["sha256"], "window SHA-256")
        actual = [[hex(r.address), r.bytes.hex(), r.mnemonic + " " + r.op_str] for r in rows]
        require(actual == window["rows"], "retained instruction rows")
        byte_count += len(raw)
        row_count += len(rows)
    check_facts(image, relocations, packet, decoder)
    rejected = []
    for control in packet["controls"]:
        altered_image, altered_relocations = image, relocations
        address = int(control["address"], 16)
        if control["kind"] == "bytes":
            replacement = bytes.fromhex(control["replacement_hex"])
            require(image.get(address, len(replacement)) != replacement, "control must change input")
            altered_image = Overlay(image, address, replacement)
        elif control["kind"] == "relocation":
            altered_relocations = dict(relocations)
            old = relocations[address]
            new_target = int(control["target"], 16)
            require(old[1] != new_target, "control must change relocation")
            altered_relocations[address] = (old[0], new_target, old[2])
        else:
            raise ValueError("unknown control")
        try:
            # Intentionally bypass the global digest/window comparisons here:
            # each corruption must be caught by the semantic fact checks.
            check_facts(altered_image, altered_relocations, packet, decoder)
        except ValueError:
            rejected.append(control["label"])
        else:
            raise ValueError("semantic corruption accepted: " + control["label"])
    print(json.dumps({"issue": packet["issue"], "target_sha256": PIN,
                      "selected_windows": len(packet["windows"]), "selected_bytes": byte_count,
                      "selected_instructions": row_count, "semantic_facts": len(packet["facts"]),
                      "semantic_corruptions_rejected": rejected,
                      "scope": "selected static windows, not full component or runtime equivalence"}, indent=2))


if __name__ == "__main__":
    main()
