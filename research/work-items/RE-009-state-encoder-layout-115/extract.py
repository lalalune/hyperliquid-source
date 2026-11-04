#!/usr/bin/env python3
"""Authenticate and map one Node115 state serializer; no target execution/emulation."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

import capstone
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from fde_extents import eh_frame_records

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
START, END = 0x5480950, 0x548168c
STRING, MAP, SEQUENCE = 0x57cf860, 0x57ce100, 0x57ceba0
FORMAT_CALLS = {STRING, MAP, SEQUENCE}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def identity(data):
    need(len(data) == 105896032, "Node115 size mismatch")
    need(hashlib.sha256(data).hexdigest() == TARGET_SHA, "Node115 SHA256 mismatch")


def loads(data):
    need(data[:6] == b"\x7fELF\x02\x01", "Expected ELF64 LE")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    entsize, count = struct.unpack_from("<HH", data, 54)
    need(entsize >= 56 and phoff + entsize * count <= len(data), "Invalid program headers")
    result = []
    for index in range(count):
        typ, flags, off, va, _, size, memsize, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * entsize)
        if typ == 1:
            need(off + size <= len(data) and size <= memsize, "Invalid PT_LOAD")
            result.append((off, va, size, flags))
    return result


def file_offset(mapping, va, size):
    matches = [off + va - start for off, start, length, _ in mapping
               if size > 0 and start <= va and va + size <= start + length]
    need(len(matches) == 1, f"Ambiguous/unbacked VA {va:#x}+{size}")
    return matches[0]


def instruction(row):
    return {"va": hex(row.address), "bytes": row.bytes.hex(),
            "mnemonic": row.mnemonic, "operands": row.op_str}


def immediate_definition(window, register):
    for row in reversed(window):
        if row.operands and row.operands[0].type == X86_OP_REG:
            if row.reg_name(row.operands[0].reg) == register:
                if row.mnemonic == "mov" and row.operands[1].type == X86_OP_IMM:
                    return row.operands[1].imm
                return None
    return None


def rip_definition(window, register):
    """Recognize only a local LEA or one MOV from a locally defined LEA."""
    for index in range(len(window) - 1, -1, -1):
        row = window[index]
        if not row.operands or row.operands[0].type != X86_OP_REG:
            continue
        if row.reg_name(row.operands[0].reg) != register:
            continue
        if row.mnemonic == "lea" and row.operands[1].type == X86_OP_MEM:
            operand = row.operands[1]
            if operand.mem.base == X86_REG_RIP:
                return row, row.address + row.size + operand.mem.disp
        if row.mnemonic == "mov" and row.operands[1].type == X86_OP_REG:
            source = row.reg_name(row.operands[1].reg)
            for prior in reversed(window[:index]):
                if (prior.mnemonic == "lea" and prior.operands[0].type == X86_OP_REG
                        and prior.reg_name(prior.operands[0].reg) == source
                        and prior.operands[1].type == X86_OP_MEM
                        and prior.operands[1].mem.base == X86_REG_RIP):
                    return prior, prior.address + prior.size + prior.operands[1].mem.disp
                if prior.operands and prior.operands[0].type == X86_OP_REG:
                    if prior.reg_name(prior.operands[0].reg) == source:
                        break
        return None
    return None


def first_key_call(rows):
    return next((i for i, row in enumerate(rows)
                 if row.mnemonic == "call" and row.operands[0].type == X86_OP_IMM
                 and row.operands[0].imm == STRING), None)


def literal(data, mapping, definition, length):
    need(definition is not None and length is not None and 1 <= length <= 80,
         "Key pointer/length not established")
    row, va = definition
    off = file_offset(mapping, va, length)
    raw = data[off:off + length]
    need(all(32 <= byte < 127 for byte in raw), "Key is not exact printable ASCII")
    return {"text": raw.decode("ascii"), "va": hex(va), "fileOffset": hex(off),
            "length": length, "bytes": raw.hex(), "pointerInstruction": instruction(row)}


def analyze(data):
    mapping = loads(data)
    _, fdes = eh_frame_records(data)
    by_start = {}
    for row in fdes:
        by_start.setdefault(row["start"], []).append(row)
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    engine.detail = True
    decoded = {}

    def decode(start):
        if start in decoded:
            return decoded[start]
        candidates = by_start.get(start, [])
        need(len(candidates) == 1, f"Expected one FDE at {start:#x}")
        fde = candidates[0]
        size = fde["end"] - start
        need(0 < size <= 10000, f"Outside selected static context budget: {size}")
        off = file_offset(mapping, start, size)
        need(any(flags & 1 and va <= start and fde["end"] <= va + length
                 for _, va, length, flags in mapping), "FDE not executable/file-backed")
        body = data[off:off + size]
        rows = list(engine.disasm(body, start))
        need(sum(row.size for row in rows) == size, "Incomplete instruction partition")
        record = {"start": hex(start), "end": hex(fde["end"]), "fde": hex(fde["fde"]),
                  "fileOffset": hex(off), "size": size, "sha256": hashlib.sha256(body).hexdigest(),
                  "instructions": [instruction(row) for row in rows]}
        decoded[start] = (rows, record)
        return rows, record

    outer, outer_record = decode(START)
    need(outer_record["end"] == hex(END), "Outer FDE end changed")
    fields = []
    previous = 0
    headers = []
    calls = []
    for index, row in enumerate(outer):
        if row.mnemonic != "call":
            continue
        need(row.operands[0].type == X86_OP_IMM, "Unexpected indirect outer call")
        target = row.operands[0].imm
        calls.append({"site": hex(row.address), "target": hex(target)})
        if target in (MAP, SEQUENCE):
            count = immediate_definition(outer[max(0, index - 6):index], "edx")
            need(count is not None, "Container count not established")
            headers.append({"call": hex(row.address), "target": hex(target), "count": count})
        if target in FORMAT_CALLS:
            continue
        helper, _ = decode(target)
        segment = outer[previous:index]
        previous = index + 1
        # Explicit outer key takes precedence over nested helper keys/type labels.
        key_indices = [i for i, x in enumerate(segment) if x.mnemonic == "call"
                       and x.operands[0].type == X86_OP_IMM and x.operands[0].imm == STRING]
        key_index = key_indices[-1] if key_indices else None
        if key_index is not None:
            window = segment[max(0, key_index - 10):key_index]
            key = literal(data, mapping, rip_definition(window, "rsi"),
                          immediate_definition(window, "edx"))
            key_origin = "outer-direct"
        else:
            parent_pointer = rip_definition(segment, "rdx")
            if parent_pointer is not None:
                length = immediate_definition(segment, "ecx")
                if length is None:
                    first = first_key_call(helper)
                    need(first is not None, "Dynamic helper lacks key writer")
                    length = immediate_definition(helper[:first], "edx")
                key = literal(data, mapping, parent_pointer, length)
                key_origin = "outer-argument/helper-key-writer"
            else:
                first = first_key_call(helper)
                need(first is not None, "Helper has no established key")
                window = helper[max(0, first - 12):first]
                key = literal(data, mapping, rip_definition(window, "rsi"),
                              immediate_definition(window, "edx"))
                key_origin = "helper-fixed"
        following = outer[index + 1:index + 4]
        need(len(following) == 3 and following[0].mnemonic == "mov"
             and following[0].op_str == "rax, qword ptr [rsp]"
             and following[1].mnemonic == "cmp" and following[1].op_str == "rax, r12"
             and following[2].mnemonic == "jne" and following[2].operands[0].imm == 0x5481684,
             "Value success/error guard changed")
        # These are native instructions, not inferred Rust field types or widths.
        source = [instruction(x) for x in segment if
                  any(op.type == X86_OP_MEM and x.reg_name(op.mem.base) == "r15"
                      for op in x.operands)
                  or (x.mnemonic == "add" and x.op_str == "r15, 0x3908")]
        # Initial source dereference establishes the root, not a ctx field load.
        if not fields:
            source = [x for x in source if x["operands"] != "r15, qword ptr [r15]"]
        fields.append({"ordinal": len(fields) + 1,
                       "scope": "exchange.locus" if len(fields) < 17 else "exchange",
                       "key": key, "keyOrigin": key_origin, "call": hex(row.address),
                       "helper": hex(target), "sourceInstructions": source,
                       "resultGuard": [instruction(x) for x in following]})
    need(len(fields) == 75, "Expected75 value dispatches")
    need([h["count"] for h in headers] == [1, 1, 59, 59, 17, 17],
         "Container header order/count changed")
    need(fields[0]["key"]["text"] == "ctx" and fields[16]["key"]["text"] == "aux"
         and fields[17]["key"]["text"] == "perp_dexs"
         and fields[-1]["key"]["text"] == "msc", "Scope transition changed")
    need(len({(x["scope"], x["key"]["text"]) for x in fields}) == 75,
         "Duplicate field key in selected scope")
    # Authenticate complete direct format callees as context, without claiming closure.
    for target in FORMAT_CALLS:
        decode(target)
    return {"targetSha256": TARGET_SHA,
            "rangeInterpretation": "Unwind FDEs, not asserted source function boundaries",
            "targetExecuted": False, "targetEmulated": False,
            "outer": outer_record, "headers": headers, "calls": calls, "fields": fields,
            "directCalleeContexts": [decoded[k][1] for k in sorted(decoded) if k != START],
            "limitations": ["Nested value encodings, deep helper/data/relocation closure unresolved",
                            "Keys and native operands do not establish full source types or wire equivalence",
                            "No source reconstruction, component gate or byte-equivalence credit"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    identity(data)
    result = analyze(data)
    if args.check:
        expected = json.loads(args.check.read_text(encoding="utf-8"))
        need(result == expected, "Retained field-layout evidence differs")
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"fields": len(result["fields"]),
                      "directCallees": len(result["directCalleeContexts"]),
                      "outerInstructions": len(result["outer"]["instructions"]),
                      "targetExecuted": False, "targetEmulated": False,
                      "capstone": capstone.__version__}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print(f"state-encoder-layout: {error}", file=sys.stderr)
        sys.exit(1)
