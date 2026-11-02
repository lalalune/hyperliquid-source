#!/usr/bin/env python3
"""Native static binding for one QC row field; never evaluate captured instructions."""
import argparse
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
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
RANGES = {"row-field-owner": (0x4C7E340, 0x4C7E60D),
          "prior-four-word-helper": (0x466BF60, 0x466C13F),
          "payload-caller-context": (0x47AD520, 0x47AD690),
          "qc-callback-context": (0x4779EB0, 0x477A064),
          "vector-callback-context": (0x4589520, 0x45897E5)}
ENTRY, SUCCESS = 0x4C7E4F3, 0x4C7E5FA
MANDATORY = [0x4C7E535, 0x4C7E53E, 0x4C7E542, 0x4C7E5F7]
CALLS = [(0x47AD543, 0x466C140), (0x47AD57C, 0x466BD10), (0x47AD59B, 0x4779EB0),
         (0x4779FEA, 0x4589520), (0x4C7E358, 0x466C140),
         (0x4C7E395, 0x466BF60), (0x4C7E422, 0x466BF60),
         (0x466BFBE, 0x466BD10), (0x466C001, 0x466BD10), (0x466C044, 0x466BD10), (0x466C083, 0x466BD10)]
LINE = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}[ \t]+)+)(\S.*)$")


def require(ok, why):
    if not ok:
        raise ValueError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, data, identity=True):
        self.data = data
        require(not identity or sha(data) == SHA, "target SHA-256 mismatch")
        require(data[:6] == b"\x7fELF\x02\x01", "ELF64 little endian required")
        pos = struct.unpack_from("<Q", data, 32)[0]
        width, count = struct.unpack_from("<HH", data, 54)
        require(width == 56 and pos + width * count <= len(data), "program table")
        self.loads = []
        for i in range(count):
            kind, flags, off, va, _, size, _, _ = struct.unpack_from("<IIQQQQQQ", data, pos + i * width)
            if kind == 1:
                require(off + size <= len(data), "PT_LOAD outside file")
                self.loads.append((va, va + size, off))

    def offset(self, va, size=1):
        hits = [off + va - lo for lo, hi, off in self.loads if lo <= va and va + size <= hi]
        require(len(hits) == 1 and size >= 0, "VA not uniquely file-backed")
        return hits[0]

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def record(self, va):
        size = struct.unpack("<I", self.read(va, 4))[0] + 4
        return {"va": hex(va), "hex": self.read(va, size).hex()}


def decode_rows(text):
    rows = []
    for line in text.splitlines():
        match = LINE.match(line)
        if match:
            rows.append((int(match[1], 16), bytes.fromhex(match[2]), match[3]))
    return rows


def native(binary, start, end, llvm):
    commands = [["objdump", "-d", "-M", "intel", "--insn-width=16", f"--start-address={start}", f"--stop-address={end}", str(binary)],
                [llvm, "-d", "--x86-asm-syntax=intel", f"--start-address={start}", f"--stop-address={end}", str(binary)]]
    texts = [subprocess.check_output(cmd, text=True).replace(str(binary), "artifacts/node/94/hl-node") for cmd in commands]
    rows = [decode_rows(text) for text in texts]
    require([(a, raw) for a, raw, _ in rows[0]] == [(a, raw) for a, raw, _ in rows[1]], "native instruction partitions differ")
    return texts, rows[0]


def branch(image, va):
    raw = image.read(va, 6)
    if raw[0] in (0x74, 0x75):
        return va + 2 + int.from_bytes(raw[1:2], "little", signed=True)
    require(raw[:2] in (b"\x0f\x84", b"\x0f\x83"), "field branch condition")
    return va + 6 + struct.unpack("<i", raw[2:])[0]


def derive(image):
    def operand(va, prefix):
        require(image.read(va, len(prefix)) == prefix, f"operand family {va:#x}")
        return image.read(va + len(prefix), 1)[0]
    pointer = operand(0x4C7E531, b"\x49\x8b\x7e")
    remaining = operand(0x4C7E524, b"\x49\x8b\x76")
    charge = operand(0x4C7E4F9, b"\x49\x8b\x7e")
    require(operand(0x4C7E517, b"\x4d\x89\x4e") == charge, "charge state-field agreement")
    require(operand(0x4C7E53E, b"\x49\x89\x7e") == pointer and
            operand(0x4C7E542, b"\x49\x89\x76") == remaining and len({charge, pointer, remaining}) == 3,
            "cursor state-field agreement")
    read = image.read(0x4C7E535, 3)
    require(read in (b"\x0f\xb6\x17", b"\x0f\xb7\x17"), "input load family")
    width = 1 if read[1] == 0xB6 else 2
    ptr_op, len_op = image.read(0x4C7E538, 3), image.read(0x4C7E53B, 3)
    require(ptr_op == b"\x48\xff\xc7" and len_op == b"\x48\xff\xce" and width == 1,
            "field width/cursor direction")
    need = struct.unpack("<I", image.read(0x4C7E602, 4))[0]
    require(image.read(0x4C7E601, 1) == b"\xba" and need == width, "empty shortfall/field width")
    require(image.read(0x4C7E606, 2) == b"\x31\xf6", "empty error kind zero")
    require(image.read(0x4C7E51E, 2) == b"\x0f\x83", "limit comparison must reject equality")
    require(image.read(0x4C7E505, 4) == b"\x48\x83\xff\xff", "charge overflow guard")
    require(image.read(0x4C7E513, 4) == b"\x4c\x8d\x4f\x01", "charge increment")
    require({hex(va): hex(branch(image, va)) for va in (0x4C7E4F7, 0x4C7E509, 0x4C7E51E, 0x4C7E52B)} ==
            {"0x4c7e4f7": "0x4c7e524", "0x4c7e509": "0x4c7e482", "0x4c7e51e": "0x4c7e482", "0x4c7e52b": "0x4c7e601"},
            "field guard destinations")
    require(image.read(0x4C7E5FA, 2) == b"\x31\xc0" and image.read(0x4C7E4DA, 5) == b"\xb8\x01\0\0\0", "result tag values")
    return {"charged_mode": operand(0x4C7E4F3, b"\x41\x83\x3e"), "charge_offset": hex(charge),
            "limit_offset": hex(operand(0x4C7E50F, b"\x4d\x8b\x46")), "pointer_offset": hex(pointer),
            "remaining_offset": hex(remaining), "width": width, "empty_need": need,
            "output_byte_offset": hex(operand(0x4C7E5F7, b"\x88\x53")),
            "error_kind_offset": hex(operand(0x4C7E4B8, b"\x40\x88\x73")),
            "charge_error_kind": operand(0x4C7E4FD, b"\x40\xb6"),
            "empty_kind": 0, "success_tag": 0, "failure_tag": 1}


def local_graph(rows):
    starts = {a for a, _, _ in rows}
    graph, transfers = {}, []
    for va, raw, asm in rows:
        after = va + len(raw); edges = []; kind = "ordinary"
        if raw[0] == 0xC3:
            kind = "return"
        elif raw[0] == 0xE9 or raw[0] == 0xEB:
            edges.append(after + int.from_bytes(raw[1:], "little", signed=True)); kind = "jump"
        elif 0x70 <= raw[0] <= 0x7F or raw[:1] == b"\x0f" and len(raw) == 6 and 0x80 <= raw[1] <= 0x8F:
            edges.append(after + int.from_bytes(raw[1:] if len(raw) == 2 else raw[2:], "little", signed=True)); kind = "conditional"
        elif asm.split()[0].startswith("j") or asm.split()[0].startswith("ret"):
            raise ValueError("unhandled native control transfer")
        if kind not in ("jump", "return") and after in starts:
            edges.append(after)
        require(all(a in starts for a in edges), "local transfer outside instruction boundaries")
        graph[va] = edges
        if kind != "ordinary":
            transfers.append([hex(va), raw.hex(), kind, [hex(a) for a in edges]])
    return graph, transfers


def reachable(graph, start, banned=None):
    seen, todo = set(), [start]
    while todo:
        va = todo.pop()
        if va not in seen and va != banned:
            seen.add(va); todo.extend(graph[va])
    return seen


def check_graph(rows):
    graph, transfers = local_graph(rows)
    require(ENTRY in reachable(graph, 0x4C7E340) and
            all(ENTRY not in reachable(graph, 0x4C7E340, site) for site in (0x4C7E358, 0x4C7E395, 0x4C7E422)),
            "field entry bypasses prior reads")
    require(SUCCESS in reachable(graph, ENTRY), "vacuous field success")
    require(all(SUCCESS not in reachable(graph, ENTRY, va) for va in MANDATORY), "field success bypasses read/cursor/output")
    require(all(later not in reachable(graph, ENTRY, earlier) for earlier, later in zip(MANDATORY, MANDATORY[1:])),
            "field operations reordered")
    return {"entry": hex(ENTRY), "success": hex(SUCCESS), "ordered_required_nodes": [hex(a) for a in MANDATORY],
            "prior_read_nodes": ["0x4c7e358", "0x4c7e395", "0x4c7e422"], "transfers": transfers, "nonvacuous": True}


def project_field(params, mode, charge, limit, remaining, value, pointer=0x1000):
    """Mathematical projection of the proven field relation; not an x86 evaluator."""
    require(0 <= mode < 2**32 and all(0 <= n < 2**64 for n in (charge, limit, remaining)) and 0 <= value < 256,
            "projection domain")
    require(0 <= pointer < 2**64 and (remaining == 0 or pointer < 2**64-1), "nonwrapping pointer domain")
    writes = []
    def result(status, consumed, kind=None):
        return {"status": status, "charge_after": charge, "consumed": consumed, "kind": kind,
                "value": value if consumed else None, "pointer_after": pointer + consumed,
                "remaining_after": remaining - consumed, "state_writes": writes,
                "result_tag": params["success_tag"] if consumed else params["failure_tag"]}
    if mode == params["charged_mode"]:
        if charge == 2**64 - 1:
            return result("error", 0, params["charge_error_kind"])
        charge += 1
        writes.append(["charge", charge])
        if charge > limit:
            return result("error", 0, params["charge_error_kind"])
    if remaining == 0:
        return result("error", 0, params["empty_kind"])
    writes.extend([["pointer", pointer + 1], ["remaining", remaining - 1]])
    return result("ok", 1)


def collect(binary, llvm, output):
    image = Image(binary.read_bytes()); params = derive(image)
    freeze = json.loads((HERE / "freeze.json").read_text())
    for site in freeze["windows"]:
        raw = bytes.fromhex(site["hex"]); require(image.read(int(site["va"], 16), len(raw)) == raw, "frozen window " + site["name"])
    cies, fdes = eh_frame_records(image.data); _, index = unwind_index(image.data)
    records = {"target_sha256": SHA, "coordinate_system": "linked ELF virtual addresses; half-open FDEs", "parameters": params,
               "functions": [], "cies": {}, "captured_execution": False, "instruction_evaluation": False}
    records["caller_bindings"] = []
    for va, target in CALLS:
        raw = image.read(va, 5)
        require(raw[0] == 0xE8 and va + 5 + struct.unpack("<i", raw[1:])[0] == target, "caller target")
        records["caller_bindings"].append([hex(va), raw.hex(), hex(target)])
    raw = image.read(0x4779FDB, 7)
    require(raw[:3] == b"\x48\x8d\x15" and 0x4779FE2 + struct.unpack("<i", raw[3:])[0] == 0x4C7E340,
            "QC callback address")
    require(image.read(0x4589531, 5) == b"\x48\x89\x54\x24\x28" and
            image.read(0x45896A1, 4) == b"\xff\x54\x24\x28", "vector callback slot")
    records["callback_handoff"] = {"qc_lea": "0x4779fdb", "target": "0x4c7e340",
                                    "vector_save": "0x4589531", "vector_call": "0x45896a1", "stack_slot": "0x28"}
    combined = [[], []]; total = 0
    for name, (start, end) in RANGES.items():
        fs = [f for f in fdes if f["start"] == start]
        require(len(fs) == 1 and fs[0]["end"] == end, "FDE extent " + name); f = fs[0]
        require(sum(r["start"] == start and r["fde"] == f["fde"] for r in index) == 1, "FDE index " + name)
        texts, rows = native(binary, start, end, llvm); cursor = start
        for va, raw, _ in rows:
            require(va == cursor and image.read(va, len(raw)) == raw, "complete native bytes " + name); cursor += len(raw)
        require(cursor == end, "complete native range " + name); total += len(rows)
        for i, text in enumerate(texts):combined[i].append(text)
        records["functions"].append({"name": name, "start": hex(start), "end": hex(end), "bytes": end-start,
            "file_offset": hex(image.offset(start, end-start)),
            "body_sha256": sha(image.read(start, end-start)), "fde": image.record(f["fde"]), "cie": hex(f["cie"]),
            "lsda": None if f["lsda"] is None else hex(f["lsda"]), "instructions": len(rows)})
        records["cies"][hex(f["cie"])] = image.record(f["cie"])
        if name == "row-field-owner":records["field_graph"] = check_graph(rows)
    records["summary"] = {"complete_fdes": len(RANGES), "bytes": sum(e-s for s,e in RANGES.values()), "instructions": total,
                          "native_partitions_agree": True, "component_gates_changed": 0}
    output.mkdir(parents=True, exist_ok=True)
    for label, texts in zip(("gnu", "llvm"), combined): (output / f"native.{label}.txt").write_text("".join(texts))
    # Transfer rows stay compact; all native instructions remain in the exports.
    text = json.dumps(records, indent=2, sort_keys=True)
    for row in records["field_graph"]["transfers"]:
        pretty = json.dumps(row, indent=2)
        # The indented list is replaced only as an exact JSON value.
        text = text.replace(pretty.replace("\n", "\n      "), json.dumps(row))
    (output / "records.json").write_text(text + "\n")
    return records


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "artifacts/node/94/hl-node")
    parser.add_argument("--llvm", default=os.environ.get("LLVM_OBJDUMP") or shutil.which("llvm-objdump"))
    parser.add_argument("--out", type=Path, required=True); args = parser.parse_args()
    if not args.llvm:parser.error("pass --llvm, set LLVM_OBJDUMP, or add llvm-objdump to PATH")
    result = collect(args.binary, args.llvm, args.out)
    print(json.dumps(result["summary"], sort_keys=True))
