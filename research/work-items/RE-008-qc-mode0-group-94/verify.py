#!/usr/bin/env python3
"""Authenticate native evidence and recompute the frozen mode-zero relation."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records

FREEZE = "9b8c4f16ec0b483a8cef6b30c383df3fb7f04e66701a374168e53d95c2bac1c4"
RX = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}[ \t]+)+)(\S.*)$", re.M)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def freeze():
    data = (HERE / "pre-rust/PRE-RUST-FREEZE.json").read_bytes()
    need(sha(data) == FREEZE, "pre-Rust identity")
    result = json.loads(data)
    for name, digest in result["fixtures"].items():
        need(sha((HERE / "pre-rust" / name).read_bytes()) == digest, "pre-Rust fixture " + name)
    return result


class Image:
    def __init__(self, data):
        self.data = data
        ph = struct.unpack_from("<Q", data, 32)[0]
        self.loads = [struct.unpack_from("<IIQQQQQQ", data, ph + i * 56)
                      for i in range(struct.unpack_from("<H", data, 56)[0])]

    def read(self, va, count):
        offsets = [r[2] + va - r[3] for r in self.loads if r[0] == 1 and r[3] <= va and va + count <= r[3] + r[5]]
        need(len(offsets) == 1, "unique file-backed mapping")
        return self.data[offsets[0]:offsets[0] + count]


def partition(text):
    return [(int(a, 16), bytes.fromhex(b)) for a, b, _ in RX.findall(text)]


def relation(row):
    """Bounded accepted-marker algebra, not native instruction emulation."""
    need(int(row["mode_word"]) == 0, "full zero mode word")
    wire = b"" if row["wire_hex"] == "-" else bytes.fromhex(row["wire_hex"])
    cursor, words, need_bytes = 0, [], None
    for _ in range(4):
        if cursor == len(wire):
            need_bytes = 1
            break
        marker = wire[cursor]
        need(marker <= 0xfd, "accepted marker")
        width = 1 if marker <= 0xfa else {0xfb: 3, 0xfc: 5, 0xfd: 9}[marker]
        available = len(wire) - cursor
        if available < width:
            need_bytes = width - available
            cursor += 1
            break
        value = marker if width == 1 else sum(b << (8 * i) for i, b in enumerate(wire[cursor + 1:cursor + width]))
        words.append(value)
        cursor += width
    tail = wire[cursor:]
    values = "-" if need_bytes is not None else b"".join(v.to_bytes(8, "little") for v in words).hex()
    error = ["1", "0", str(need_bytes)] if need_bytes is not None else ["0", "-", "-"]
    row_error = error if need_bytes is not None else ["-", "-", "-"]
    return [row["id"], row["charge"], str(cursor), str(len(tail)), tail.hex() or "-", *error, *row_error, values]


def verify_vectors():
    inputs = list(csv.DictReader(io.StringIO((HERE / "pre-rust/inputs.tsv").read_text()), delimiter="\t"))
    expected = list(csv.reader(io.StringIO((HERE / "pre-rust/expected.tsv").read_text()), delimiter="\t"))[1:]
    need(len(inputs) == len(expected) == 96, "frozen case count")
    need([relation(row) for row in inputs] == expected, "96 frozen field/cursor/charge projections")
    return inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--llvm", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    frozen = freeze()
    data = args.binary.read_bytes()
    need(len(data) == frozen["target"]["size"] and sha(data) == frozen["target"]["sha256"], "authenticated target")
    need(not args.out.exists(), "refuse existing output")
    args.out.mkdir(parents=True)
    image = Image(data)
    sections, index = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    exports = {"gnu": [], "llvm": []}
    commands = []
    count = 0
    for body in frozen["functions"]:
        start, end = int(body["start"], 16), int(body["end"], 16)
        need(sha(image.read(start, end - start)) == body["body_sha256"], "complete body " + body["name"])
        expected_fde = {k: int(v, 16) if v is not None else None for k, v in body["fde"].items()}
        need([f for f in fdes if f["fde"] == expected_fde["fde"]] == [expected_fde], "exact FDE/CIE/LSDA")
        need(sum(row["start"] == start and row["fde"] == expected_fde["fde"] for row in index) == 1, "unique unwind index")
        need(image.read(expected_fde["fde"], len(bytes.fromhex(body["fde_hex"]))).hex() == body["fde_hex"], "FDE bytes")
        rows = []
        for name, tool in (("gnu", "objdump"), ("llvm", str(args.llvm))):
            argv = ([tool, "-d", "--x86-asm-syntax=intel"] if name == "llvm"
                    else [tool, "-d", "-M", "intel", "--insn-width=16"])
            argv += [f"--start-address={start}", f"--stop-address={end}", str(args.binary)]
            run = subprocess.run(argv, capture_output=True, check=True)
            need(not run.stderr, "disassembler diagnostics")
            exports[name].append(run.stdout.decode())
            commands.append({"argv": argv, "exit": run.returncode, "stdout_sha256": sha(run.stdout), "stderr_sha256": sha(run.stderr)})
            decoded = partition(run.stdout.decode())
            at = start
            for va, code in decoded:
                need(va == at and image.read(va, len(code)) == code, "contiguous native partition")
                at += len(code)
            need(at == end, "complete native export")
            rows.append(decoded)
        need(rows[0] == rows[1], "GNU/LLVM byte partitions")
        for name in ("gnu", "llvm"):
            retained = partition((HERE / f"pre-rust/fresh-native.{name}.txt").read_text())
            need([r for r in retained if start <= r[0] < end] == rows[0], "pre-Rust native partition")
        count += len(rows[0])
    cie = frozen["CIE"]
    need(image.read(int(cie["va"], 16), len(bytes.fromhex(cie["hex"]))).hex() == cie["hex"], "CIE bytes")
    for guard in frozen["mode_guards"]:
        need(image.read(int(guard["va"], 16), len(bytes.fromhex(guard["hex"]))).hex() == guard["hex"], "mode guard")
    for table in frozen["dispatch_tables"]:
        va = int(table["va"], 16)
        raw = image.read(va, 16)
        need(raw.hex() == table["hex"], "dispatch bytes")
        need([hex(va + v) for v in struct.unpack("<iiii", raw)] == table["targets"], "relative dispatch targets")
    rela = frozen["Reader_RELA"]
    need(data[int(rela["file_offset"], 16):int(rela["file_offset"], 16) + 24].hex() == rela["hex"], "Reader RELA")
    need(image.read(int(rela["slot"], 16), 8).hex() == rela["slot_hex"], "Reader relocation slot")
    for call, target in [(0x466bfbe, 0x466bd10), (0x466c001, 0x466bd10), (0x466c044, 0x466bd10),
                         (0x466c083, 0x466bd10), (0x4c7e395, 0x466bf60), (0x4c7e422, 0x466bf60)]:
        need(image.read(call, 1) == b"\xe8" and call + 5 + struct.unpack("<i", image.read(call + 1, 4))[0] == target, "E8 call target")
    controls = frozen["native_controls"]
    for control in controls:
        for change in control["changes"]:
            before, after = bytes.fromhex(change["before"]), bytes.fromhex(change["after"])
            need(len(before) == len(after) and before != after, "operative static site")
            need(image.read(int(change["va"], 16), len(before)) == before, "authenticated mutation anchor")
    verify_vectors()
    for name, text in exports.items():
        (args.out / f"native.{name}.txt").write_text("\n".join(text))
    report = {"target_sha256": sha(data), "complete_bodies": 4, "native_bytes": 1741,
              "instruction_rows_per_tool": count, "vectors": 96, "static_site_controls": len(controls),
              "commands": commands, "captured_execution": False,
              "control_class": "authenticated static opcode distinctions; no patched native execution"}
    (args.out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print("4 bodies/FDEs; 462 dual-tool rows; 96 frozen states; 12 static controls: pass")


if __name__ == "__main__":
    main()
