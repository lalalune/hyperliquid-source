#!/usr/bin/env python3
"""Authenticate native bytes and a qualified static relation; never run a capture."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records

FREEZE_SHA = "5bece039bc93d4766db761711d189aa445874862845868e3b383ccdc98f1a4fc"
RX = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}[ \t]+)+)(\S.*)$", re.M)
MASK = (1 << 64) - 1


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, data, patches=None):
        self.data, self.patches = data, patches or {}
        pos = struct.unpack_from("<Q", data, 32)[0]
        self.loads = [struct.unpack_from("<IIQQQQQQ", data, pos + i * 56)
                      for i in range(struct.unpack_from("<H", data, 56)[0])]

    def read(self, address, size):
        offsets = [r[2] + address - r[3] for r in self.loads
                   if r[0] == 1 and r[3] <= address and address + size <= r[3] + r[5]]
        require(len(offsets) == 1, "unique file-backed range")
        result = bytearray(self.data[offsets[0]:offsets[0] + size])
        for va, value in self.patches.items():
            if address <= va < address + size:
                result[va - address] = value
        return bytes(result)


def parameters(image):
    """Read the operative native operands, with complete instruction families.

    This is a finite algebraic projection, not an x86 interpreter. Error paths
    and all modes/markers outside the frozen domain have no defined relation.
    """
    def exact(va, code):
        require(image.read(va, len(bytes.fromhex(code))) == bytes.fromhex(code), f"native site {va:#x}")

    def immediate(va, prefix):
        exact(va, prefix)
        return image.read(va + len(bytes.fromhex(prefix)), 1)[0]

    exact(0x466BF6E, "4989f64889fb833e01")
    exact(0x466BF79, "498b4620")
    bound = immediate(0x466BF7D, "4883f8")
    reserve = immediate(0x466BF8B, "488d50")
    require((bound - 256) & MASK == MASK - reserve, "reserve overflow bound")
    exact(0x466BF81, "7715")
    exact(0x466BF83, "498b4e084d8d6620")
    exact(0x466BF8F, "49891424")
    exact(0x466BF93, "4839ca7616")
    initial = immediate(0x466BFAE, "4883c0")
    exact(0x466BFB2, "49890424")
    exact(0x466BD11, "833e01")
    exact(0x466BD1A, "4883f8f77711")
    scalar = immediate(0x466BD24, "4883c0")
    exact(0x466BD28, "488946204839c87608")
    exact(0x466BD3D, "4883f808766e")
    exact(0x466BD47, "0fb6114881fafb0000007308")
    exact(0x466BD5B, "81c205ffffff83fa037777")
    exact(0x466BD66, "4c8d053bb108fc496314904c01c2ffe2")
    table = struct.unpack("<iiii", image.read(0x6F6EA8, 16))
    require(0x6F6EA8 + table[2] == 0x466BD82, "FD fast dispatch")
    exact(0x466BD82, "488b5101")
    width = struct.unpack("<I", image.read(0x466BD88, 4))[0]
    exact(0x466BD86, "41b8")
    exact(0x466BD8C, "eb09")
    exact(0x466BD97, "4c01c14c29c048894e104889461848895708c60712")
    refunds = []
    for call, check13, check12, branch, value, guard, refund in [
        (0x466BFBE, 0x466BFC8, 0x466BFD5, 0x466BFD7, 0x466BFD0, 0x466BFDD, 0x466BFF1),
        (0x466C001, 0x466C00B, 0x466C018, 0x466C01A, 0x466C013, 0x466C020, 0x466C034),
        (0x466C044, 0x466C04E, 0x466C05B, 0x466C05D, 0x466C056, 0x466C05F, 0x466C073),
        (0x466C083, 0x466C08D, 0x466C09A, 0x466C09C, 0x466C095, None, None),
    ]:
        exact(call - 8, "488d7c24084c89f6")
        exact(call, "e8")
        require(call + 5 + struct.unpack("<i", image.read(call + 1, 4))[0] == 0x466BD10, "scalar call target")
        exact(check13, "3c13")
        exact(check13 + 2, "0f84")
        require(check13 + 8 + struct.unpack("<i", image.read(check13 + 4, 4))[0] == 0x466C125, "unreachable panic branch")
        exact(check12, "3c12")
        exact(branch, "0f85" if branch < 0x466C05D else "75")
        branch_size = 6 if branch < 0x466C05D else 2
        displacement = struct.unpack("<i" if branch_size == 6 else "b", image.read(branch + branch_size - (4 if branch_size == 6 else 1), 4 if branch_size == 6 else 1))[0]
        require(branch + branch_size + displacement == {0x466BFD7: 0x466C0AC, 0x466C01A: 0x466C0B3,
                0x466C05D: 0x466C0BD, 0x466C09C: 0x466C0C7}[branch], "scalar failure branch target")
        exact(value, {0x466BFD0: "4c8b7c2410", 0x466C013: "4c8b6c2410",
                      0x466C056: "488b6c2410", 0x466C095: "488b4c2410"}[value])
        if guard:
            exact(guard, "49833e007416498b04244883f8080f82")
            exact(refund, "4883c0")
            refunds.append(struct.unpack("b", image.read(refund + 3, 1))[0])
            exact(refund + 4, "49890424")
    exact(0x466C09E, "4c89fe")
    shift = immediate(0x466C0A1, "48c1ee")
    exact(0x466C0A5, "31ff4489f8eb4d")
    exact(0x466C0F9, "48893b48c1e6080fb6c04809f0")
    destinations = []
    for va, prefix in [(0x466C106, "488943"), (0x466C10A, "4c896b"), (0x466C10E, "48896b")]:
        destinations.append(immediate(va, prefix))
    exact(0x466C112, "4889")
    final_modrm = image.read(0x466C114, 1)[0]
    require(final_modrm in (0x4B, 0x6B), "last qword source register")
    destinations.append(image.read(0x466C115, 1)[0])
    exact(0x466C116, "4883c4285b415c415d415e415f5dc3")
    exact(0x466BDAC, "4889f85bc3")
    exact(0x4C7E41A, "488d7c24284c89f6e839db9eff")
    exact(0x4C7E44B, "807c2428000f849d000000")
    return {"reserve": reserve, "initial_refund_result": initial, "scalar_charge": scalar,
            "interword_refunds": refunds, "wire_width": width, "word0_right_shift": shift,
            "destinations": destinations, "last_source_word": 3 if final_modrm == 0x4B else 2}


def relation(p, row):
    """Static final-state consequence of the qualified four-success path."""
    wire = bytes.fromhex(row["wire_hex"])
    charge, limit = int(row["charge"]), int(row["limit"])
    require(charge + p["reserve"] <= MASK and charge + p["reserve"] <= limit, "qualified reserve")
    require(p["wire_width"] == 9 and len(wire) >= 36 and all(wire[i] == 0xFD for i in (0, 9, 18, 27)), "qualified FD domain")
    trace = [charge + p["reserve"], charge + p["initial_refund_result"]]
    current = trace[-1]
    for i in range(4):
        current += p["scalar_charge"]
        require(current <= MASK and current <= limit, "qualified scalar charge")
        trace.append(current)
        if i < 3:
            current += p["interword_refunds"][i]
            require(current >= 0, "qualified refund")
            trace.append(current)
    words = [int.from_bytes(wire[i + 1:i + 9], "little") for i in (0, 9, 18, 27)]
    first = (((words[0] >> p["word0_right_shift"]) << 8) & MASK) | (words[0] & 0xFF)
    values = [first, words[1], words[2], words[p["last_source_word"]]]
    output = bytearray.fromhex(row["output_before_hex"])
    output[0:8] = bytes(8)
    for at, value in zip(p["destinations"], values):
        require(8 <= at <= 32, "bounded qword store")
        output[at:at + 8] = value.to_bytes(8, "little")
    return {"id": row["id"], "charge": str(current), "consumed": "36",
            "suffix_hex": wire[36:].hex() or "-", "output_hex": output.hex()}, trace


def rows(path):
    with path.open() as file:
        return list(csv.DictReader(file, delimiter="\t"))


def native(binary, ranges, tool, args, image):
    parts = []
    for window in ranges:
        start, end = int(window["start"], 16), int(window["end"], 16)
        text = subprocess.check_output([tool, *args, f"--start-address={start}", f"--stop-address={end}", str(binary)], text=True)
        current = start
        for match in RX.finditer(text):
            va, code = int(match[1], 16), bytes.fromhex(match[2])
            require(va == current and image.read(va, len(code)) == code, "complete native partition")
            current += len(code)
        require(current == end, "complete native end")
        parts.append(text.replace(str(binary), "artifacts/node/94/hl-node"))
    return "".join(parts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--llvm", default=os.environ.get("LLVM_OBJDUMP") or shutil.which("llvm-objdump"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(args.llvm, "supply --llvm or LLVM_OBJDUMP, or put llvm-objdump on PATH")
    freeze_bytes = (HERE / "PRE-RUST-FREEZE.json").read_bytes()
    require(sha(freeze_bytes) == FREEZE_SHA, "pre-Rust freeze changed")
    frozen = json.loads(freeze_bytes)
    data = args.target.read_bytes()
    require(len(data) == frozen["target"]["size"] and sha(data) == frozen["target"]["sha256"], "authenticated node94")
    image = Image(data)
    _, fdes = eh_frame_records(data)
    _, index = unwind_index(data)
    for function in frozen["functions"]:
        start, end = int(function["start"], 16), int(function["end"], 16)
        matches = [f for f in fdes if f["start"] == start]
        require(len(matches) == 1 and matches[0]["end"] == end and matches[0]["lsda"] is None, "FDE extent")
        require(sum(i["start"] == start and i["fde"] == matches[0]["fde"] for i in index) == 1, "unwind index binding")
        fde = int(function["fde"]["fde"], 16)
        require(data[fde:fde + len(bytes.fromhex(function["fde_hex"]))].hex() == function["fde_hex"], "full FDE record")
        require(sha(image.read(start, end - start)) == function["body_sha256"], "complete body hash")
    for name, pin in frozen["fixtures"].items():
        require(sha((HERE / name).read_bytes()) == pin["sha256"], "frozen fixture " + name)
    inputs, expected = rows(HERE / "inputs.tsv"), rows(HERE / "expected.tsv")
    p = parameters(image)
    for case, wanted in zip(inputs, expected, strict=True):
        actual, trace = relation(p, case)
        require(actual == wanted, "native-derived vector " + case["id"])
        require(trace == [int(case["charge"]) + n for n in frozen["charge_writes_relative_to_C"]], "native charge write order")
    for _ in range(2):
        for label, tool, flags in [("gnu", "objdump", ["-d", "-M", "intel", "--insn-width=16"]),
                                   ("llvm", args.llvm, ["-d", "--x86-asm-syntax=intel"])]:
            require(native(args.target, frozen["native_exports"]["ranges"], tool, flags, image) == (HERE / f"native.{label}.txt").read_text(), "exact native regeneration")
    controls = []
    for mutation in frozen["native_controls"]:
        va = int(mutation["va"], 16)
        require(image.read(va, 1).hex() == mutation["before"], "native mutation origin")
        # Identity is deliberately bypassed only here. No captured code is run.
        changed = Image(data, {va: int(mutation["after"], 16)})
        altered = parameters(changed)
        differences = [case["id"] for case, wanted in zip(inputs, expected, strict=True) if relation(altered, case)[0] != wanted]
        require(differences, "operative native control " + mutation["name"])
        controls.append({"name": mutation["name"], "different": len(differences), "first_witness": differences[0],
                         "classification": "static normal-domain algebraic counterexample, not executed"})
    report = {"target": frozen["target"], "freeze_sha256": FREEZE_SHA, "cases": len(inputs),
              "native_functions": len(frozen["functions"]), "native_regenerations": 2,
              "parameters": p, "controls": controls, "captured_execution": False,
              "limits": "Selected success-domain mathematical relation; no native execution, original ABI or failure semantics"}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"PASS: {len(inputs)} frozen vectors; {len(controls)} operative static controls; two exact GNU/LLVM generations")


if __name__ == "__main__":
    main()
