#!/usr/bin/env python3
"""Revalidate the full target, selected bytes, FDE and naming relocation.

Only parses/disassembles data; never executes captured instructions.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = ROOT / "artifacts/node/94/hl-node"
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
START, END, PAD_END = 0x16488E0, 0x1648946, 0x1648950
BODY_SHA = "5377cd2a2ec106f3e005d2cde837a3804ed6d7d61db07f4a9907395d01685562"
CIE = bytes.fromhex("1400000000000000017a5200017810011b0c070890010000")
FDE = bytes.fromhex("10000000f80b0200cc6794006600000000000000")


def require(ok, why):
    if not ok:
        raise ValueError(why)


def view(data, secs, va, size):
    found = [s for s in secs if s["type"] != 8 and s["address"] <= va
             and va + size <= s["address"] + s["size"]]
    require(len(found) == 1, "ambiguous or absent file-backed range")
    offset = found[0]["offset"] + va - found[0]["address"]
    return bytes(data[offset:offset + size]), offset


def inspect(data, *, authenticate=True):
    if authenticate:
        require(len(data) == 91774280, "target size")
        require(hashlib.sha256(data).hexdigest() == TARGET_SHA, "target SHA-256")
    secs = sections(data)
    require(len({s["name"] for s in secs}) == len(secs), "duplicate section names")
    byname = {s["name"]: s for s in secs}
    body, body_off = view(data, secs, START, END - START)
    require(hashlib.sha256(body).hexdigest() == BODY_SHA, "selected body")
    require(view(data, secs, END, 10)[0] == bytes([0xCC]) * 10, "padding")
    eh = byname[".eh_frame"]
    require(view(data, secs, eh["address"], len(CIE))[0] == CIE, "CIE")
    require(view(data, secs, eh["address"] + 0x20BF4, len(FDE))[0] == FDE, "FDE")
    cies, fdes = eh_frame_records(data, secs)
    selected = [f for f in fdes if f["start"] == START]
    require(len(selected) == 1 and selected[0]["end"] == END, "decoded FDE extent")
    require(selected[0]["fde"] == eh["address"] + 0x20BF4 and selected[0]["cie"] == eh["address"], "decoded CIE/FDE relationship")
    following = [f for f in fdes if f["start"] == PAD_END]
    require(len(following) == 1 and following[0]["end"] == 0x1648999, "following FDE")
    naming, entries = [], 0
    for sec in secs:
        if sec["type"] != 4:
            continue
        require(sec["size"] % 24 == 0, "RELA size")
        for offset in range(sec["offset"], sec["offset"] + sec["size"], 24):
            slot, info, addend = struct.unpack_from("<QQq", data, offset)
            entries += 1
            if slot == 0x57709E8 or addend == START:
                naming.append({"section": sec["name"], "file_offset": hex(offset),
                               "slot_va": hex(slot), "info": info, "addend_va": hex(addend),
                               "raw_hex": bytes(data[offset:offset + 24]).hex()})
    require(len(naming) == 1 and naming[0]["slot_va"] == "0x57709e8"
            and naming[0]["addend_va"] == hex(START) and naming[0]["info"] == 8,
            "R_X86_64_RELATIVE naming slot")
    slot, slot_off = view(data, secs, 0x57709E8, 8)
    # Retain raw slot content separately from its relocation semantics.
    require(slot == bytes(8), "zero-in-file relocation slot contents")
    return {"target_sha256": TARGET_SHA, "target_size": len(data),
            "coordinate_system": "linked ELF virtual addresses; sections resolve file offsets",
            "body": {"start": hex(START), "end": hex(END), "file_offset": hex(body_off),
                     "size": len(body), "sha256": BODY_SHA, "hex": body.hex()},
            "fde": {k: hex(v) if isinstance(v, int) else v for k, v in selected[0].items()},
            "fde_section_offset": "0x20bf4", "fde_hex": FDE.hex(), "cie_hex": CIE.hex(),
            "padding_hex": "cc" * 10, "relocation": naming[0], "rela_entries_scanned": entries,
            "slot": {"file_offset": hex(slot_off), "hex": slot.hex()},
            "calls_inside_body": 0, "branches": [
                {"source": "0x16488f3", "target": "0x164893f", "condition": "masked length is zero"},
                {"source": "0x1648907", "target": "0x164893f", "condition": "unsigned forward pointer >= backward end"},
                {"source": "0x164893d", "target": "0x1648900", "condition": "remaining multiple of 16 is nonzero"}],
            "captured_execution": False, "instruction_emulation": False}


def decoded_rows(raw):
    rows = []
    for line in raw.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$", line)
        if not match:
            continue
        va, encoded, assembly = int(match[1], 16), bytes.fromhex(match[2]), match[3].strip()
        if assembly:
            rows.append([va, encoded, assembly])
        else:
            require(rows and rows[-1][0] + len(rows[-1][1]) == va, "disassembly continuation")
            rows[-1][1] += encoded
    require(rows and rows[0][0] == START, "disassembly begins at target")
    cursor = START
    for va, encoded, _ in rows:
        require(va == cursor, "complete contiguous disassembly")
        cursor += len(encoded)
    require(cursor == PAD_END, "disassembly endpoint")
    return rows


def collect(out):
    data = TARGET.read_bytes()
    record = inspect(data)
    gnu = os.environ.get("GNU_OBJDUMP", "/opt/homebrew/opt/binutils/bin/objdump")
    llvm = os.environ.get("LLVM_OBJDUMP", "/usr/bin/objdump")
    out.mkdir(parents=True, exist_ok=True)
    decoders = []
    for name, tool in (("gnu", gnu), ("llvm", llvm)):
        command = [tool, "-d", f"--start-address={START:#x}", f"--stop-address={PAD_END:#x}", "artifacts/node/94/hl-node"]
        raw = subprocess.check_output(command, cwd=ROOT, text=True)
        rows = decoded_rows(raw)
        require(b"".join(row[1] for row in rows) == bytes.fromhex(record["body"]["hex"] + record["padding_hex"]), "decoded bytes")
        decoders.append([(va, code.hex()) for va, code, _ in rows])
        (out / f"{name}.txt").write_text(raw)
    require(decoders[0] == decoders[1], "GNU/LLVM instruction partition disagreement")
    record["body_instructions"] = sum(va < END for va, _ in decoders[0])
    record["decoder_partitions_agree"] = True
    # Preserve selected raw GNU frame output without retaining a huge dump.
    process = subprocess.Popen([gnu, "--dwarf=frames", "artifacts/node/94/hl-node"], cwd=ROOT, stdout=subprocess.PIPE, text=True)
    excerpt, keep = [], False
    for line in process.stdout:
        if re.match(r"^[0-9a-f]{8} ", line):
            keep = line.startswith(("00000000 ", "00020bf4 ", "00020c08 "))
        if keep:
            excerpt.append(line)
    require(process.wait() == 0, "GNU frame export")
    frames = "".join(excerpt)
    require("pc=00000000016488e0..0000000001648946" in frames, "GNU FDE extent")
    (out / "frames.txt").write_text(frames)
    (out / "records.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"PASS static evidence: {record['body_instructions']} instructions, 102 bytes, FDE, RELATIVE slot; GNU/LLVM agree")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    collect(parser.parse_args().out)
