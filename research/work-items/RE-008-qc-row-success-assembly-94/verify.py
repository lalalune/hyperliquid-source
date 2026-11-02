#!/usr/bin/env python3
"""Static node94 QC-row copy binding and frozen source/destination controls.

The captured ELF is only read or disassembled. This script never invokes it.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))
from node115_field_adapter_drift import Image, selected_frame  # noqa: E402

START, END = 0x4C7E340, 0x4C7E60D
WINDOW_START, WINDOW_END = 0x4C7E546, 0x4C7E5F7
TARGET = ROOT / "artifacts/node/94/hl-node"
ROW = re.compile(r"^\s*([0-9a-f]+):")
HEX_BYTE = re.compile(r"^[0-9a-f]{2}$")


def need(test, message):
    if not test:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(text, start, end):
    rows = []
    for line in text.splitlines():
        match = ROW.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        if not start <= address < end:
            continue
        rest = line[match.end():].lstrip(" \t")
        columns = rest.split("\t", 1)
        tokens = columns[0].split()
        need(tokens and all(HEX_BYTE.fullmatch(token) for token in tokens),
             f"missing instruction bytes at {address:#x}")
        rows.append((address, bytes.fromhex("".join(tokens)), columns[1].strip() if len(columns) > 1 else ""))
    need(rows and rows[0][0] == start, "decode does not start at selected boundary")
    cursor = start
    for address, raw, _ in rows:
        need(address == cursor, f"decode gap/overlap at {address:#x}")
        cursor += len(raw)
    need(cursor == end, "decode does not end at selected boundary")
    return rows


def disassemble(binary, llvm, start, end):
    options = [
        (["objdump", "-d", "-M", "intel", "--insn-width=16",
          f"--start-address={start:#x}", f"--stop-address={end:#x}", str(binary)], "gnu"),
        ([str(llvm), "--disassemble", "--x86-asm-syntax=intel",
          f"--start-address={start:#x}", f"--stop-address={end:#x}", str(binary)], "llvm"),
    ]
    exports = {}
    for command, name in options:
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        need(result.returncode == 0, f"{name} objdump failed: {result.stderr[:1000]}")
        exports[name] = (result.stdout, decode(result.stdout, start, end))
    need([(a, raw) for a, raw, _ in exports["gnu"][1]]
         == [(a, raw) for a, raw, _ in exports["llvm"][1]],
         "GNU/LLVM instruction partition or raw-byte disagreement")
    return exports


def vector_output(vector, mutation=None):
    """Independent source-byte projection of the observed store order only."""
    raw = bytes.fromhex(vector["source_raw20_hex"])
    first = bytes.fromhex(vector["source_group1_hex"])
    second = bytes.fromhex(vector["source_group2_hex"])
    recovery = bytes.fromhex(vector["source_recovery_hex"])
    prefill = int(vector["prefill_byte_hex"], 16)
    need((len(raw), len(first), len(second), len(recovery)) == (20, 32, 32, 1),
         "invalid frozen vector widths")
    out = bytearray([prefill] * 104)
    out[0x44:0x48] = second[4:8]                  # 0x4c7e56e
    out[0x41:0x45] = (first if mutation == "second-group-source-alias"
                      else second)[1:5]          # 0x4c7e571
    out[0x50:0x60] = second[16:32]                # 0x4c7e579
    out[0x24:0x28] = first[4:8]                   # 0x4c7e5c3
    out[0x21:0x25] = first[1:5]                   # 0x4c7e5c6
    out[0x30:0x40] = first[16:32]                 # 0x4c7e5d1
    raw_offset = 0x10 if mutation == "raw16-destination" else 0x08
    out[raw_offset:raw_offset + 16] = raw[:16]   # 0x4c7e5da
    out[0x18:0x1c] = raw[16:20]                   # 0x4c7e5e5
    out[0x20] = first[0]                          # 0x4c7e5e8
    first_word = 0x30 if mutation == "first-group-qword-destination" else 0x28
    out[first_word:first_word + 8] = first[8:16] # 0x4c7e5ec
    second_byte = 0x41 if mutation == "second-group-first-byte-destination" else 0x40
    out[second_byte] = second[0]                  # 0x4c7e5f0
    second_word = 0x50 if mutation == "second-group-qword-destination" else 0x48
    out[second_word:second_word + 8] = second[8:16] # 0x4c7e5f3
    out[0x60] = recovery[0]                       # prior one-byte finding, context only
    out[0:8] = b"\0" * 8                         # 0x4c7e4df success tag
    return bytes(out)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--llvm", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    freeze_raw = (HERE / "freeze.json").read_bytes()
    freeze = json.loads(freeze_raw)
    data = TARGET.read_bytes()
    need(len(data) == 91774280 and sha(data) == freeze["target_sha256"],
         "node94 target size/hash mismatch")
    image = Image(data, 3)
    frame = selected_frame(image, START, END - START)
    need(frame["FDE_VA"] == 0xF443AC
         and frame["body_sha256"] == freeze["owner_fde"]["body_sha256"],
         "owner FDE/body mismatch")
    window, file_offset, section = image.virtual(WINDOW_START, WINDOW_END - WINDOW_START, code=True)
    need(file_offset == int(freeze["scoped_window"]["file_offset"], 16)
         and section["name"] == ".text"
         and sha(window) == freeze["scoped_window"]["sha256"], "scoped copy window mismatch")

    # These edges are outside the copy corridor but make its entry and return
    # conditional on the row callback's prior successful reads.
    contexts = {
        0x4779FDB: "488d155e435000",   # QC reader LEA of row callback
        0x4779FEA: "e831f5e0ff",       # QC reader calls vector
        0x4589531: "4889542428",       # vector saves callback
        0x45896A1: "ff542428",         # vector invokes callback
        0x4C7E358: "e8e3dd9eff",      # raw20 read
        0x4C7E395: "e8c6db9eff",      # first group
        0x4C7E422: "e839db9eff",      # second group
        0x4C7E450: "0f849d000000",    # second group success enters byte field
        0x4C7E5F7: "885360",          # prior finding: recovery byte store
        0x4C7E5FA: "31c0e9defeffff",  # zero success tag and jump to common store
        0x4C7E4DF: "488903",          # result tag store
    }
    for va, expected in contexts.items():
        need(image.virtual(va, len(expected) // 2, code=True)[0].hex() == expected,
             f"context byte mismatch at {va:#x}")
    for control in freeze["negative_native_controls"]:
        va = int(control["va"], 16)
        need(image.virtual(va, 1, code=True)[0].hex() == control["original"],
             f"site original byte mismatch at {va:#x}")

    original = disassemble(TARGET, args.llvm, START, END)
    rows = original["gnu"][1]
    need(len(rows) == 168, "owner instruction count changed")
    need(b"".join(raw for _, raw, _ in rows) == image.virtual(START, END - START, code=True)[0],
         "decoded owner does not equal authenticated bytes")
    scoped_rows = [(a, b) for a, b, _ in rows if WINDOW_START <= a < WINDOW_END]
    need(scoped_rows and b"".join(b for _, b in scoped_rows) == window,
         "scoped corridor is not exactly instruction-partitioned")
    need(not any(re.match(r"^(j[a-z]+|call|ret)\b", asm.strip(), re.I)
                 for a, _, asm in rows if WINDOW_START <= a < WINDOW_END),
         "unexpected control transfer in straight-line success corridor")
    for vector in freeze["vectors"]:
        need(vector_output(vector).hex() == vector["expected_output_104_hex"],
             f"frozen expected output mismatch: {vector['id']}")
        expected = bytes.fromhex(vector["expected_output_104_hex"])
        prefill = int(vector["prefill_byte_hex"], 16)
        need(expected[0x1C:0x20] == bytes([prefill]) * 4
             and expected[0x61:0x68] == bytes([prefill]) * 7,
             "untouched-byte witness mismatch")

    controls = []
    with tempfile.TemporaryDirectory(prefix="re008-row-success-") as temporary:
        mutant_path = Path(temporary) / "node94-inert-mutant"
        fd = os.open(mutant_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
        except BaseException:
            mutant_path.unlink(missing_ok=True)
            raise
        for control in freeze["negative_native_controls"]:
            va = int(control["va"], 16)
            offset = image.virtual(va, 1, code=True)[1]
            original_byte = bytes.fromhex(control["original"])
            changed_byte = bytes.fromhex(control["mutation"])
            need(data[offset:offset + 1] == original_byte and changed_byte != original_byte,
                 "invalid mutation input")
            with mutant_path.open("r+b") as handle:
                handle.seek(offset)
                handle.write(changed_byte)
            try:
                mutated = disassemble(mutant_path, args.llvm, WINDOW_START, WINDOW_END)
                need(len(mutated["gnu"][1]) == len(scoped_rows), "mutant changed instruction extent count")
                changed = [(a, b) for a, b, _ in mutated["gnu"][1]]
                need([(a, len(b)) for a, b in changed]
                     == [(a, len(b)) for a, b in scoped_rows],
                     "mutant changed instruction boundaries")
                patched = bytearray(window)
                patched[va - WINDOW_START] = changed_byte[0]
                need(b"".join(raw for _, raw in changed) == patched,
                     "mutant decode differs from one-byte patch")
                differences = []
                for vector in freeze["vectors"]:
                    before = vector_output(vector)
                    after = vector_output(vector, control["id"])
                    indices = [index for index, (a, b) in enumerate(zip(before, after)) if a != b]
                    need(indices, f"mutant did not change frozen output: {control['id']}")
                    differences.append({"vector": vector["id"], "changed_output_offsets": indices})
                controls.append({"id": control["id"], "va": control["va"],
                                 "both_decoders_same_extents": True, "differences": differences})
            finally:
                with mutant_path.open("r+b") as handle:
                    handle.seek(offset)
                    handle.write(original_byte)

    args.out.mkdir(parents=True, exist_ok=True)
    for name in ("gnu", "llvm"):
        (args.out / f"native.{name}.txt").write_text(original[name][0])
    result = {
        "target_sha256": sha(data), "target_size": len(data), "freeze_sha256": sha(freeze_raw),
        "owner_fde": {"start": hex(START), "end": hex(END), "fde": hex(frame["FDE_VA"]),
                      "body_sha256": frame["body_sha256"], "instructions": len(rows)},
        "window": {"start": hex(WINDOW_START), "end": hex(WINDOW_END),
                   "file_offset": hex(file_offset), "sha256": sha(window),
                   "instructions": len(scoped_rows)},
        "vectors_passed": len(freeze["vectors"]),
        "static_site_controls_passed": len(controls),
        "controls": controls, "captured_binary_executed": False,
        "control_limit": "One-byte static decode/operand bindings plus a manually derived store-order projection; no native symbolic execution",
        "scope": "Conditional row-success byte projection; no prior-helper or whole-QC semantics",
    }
    (args.out / "RESULTS.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: result[k] for k in ("owner_fde", "window", "vectors_passed",
                                             "static_site_controls_passed",
                                             "captured_binary_executed")},
                     sort_keys=True))


if __name__ == "__main__":
    main()
