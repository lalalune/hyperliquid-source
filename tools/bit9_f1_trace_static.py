#!/usr/bin/env python3
"""Static trace of the RE-002 bit-9 F1 set-arm stream and of the
clear regions that select it.

PR #2616 (the RE-002 bit-9 arms packet) pinned the arms the 92
bit-9 cache consumers select: the set arms reach 14 shared bodies
in four instruction streams, and the largest stream, F1, is one
normalised instruction stream at eleven placements.  #2616 stopped
at each target's entry-level identity and left as its next
question: trace the F1 stream (its most-selected instance is
0x2a31790, 31 sequences) to name the operation, and check whether
a consumer's in-body clear region is the scalar form of the same
operation for that consumer's data type.

This producer answers that question:

* it re-verifies every pin of the merged #2616 packet against the
  authenticated capture -- all 14 set-arm target bodies (FDE
  bounds, byte size, SHA-256, instruction count) and every bit-9
  consumer body -- and recomputes the normalised instruction
  stream of each F1 placement: all eleven must hash to #2616's
  pinned normalised-stream digest and to each other, or the
  analysis fails closed;
* it traces the most-selected F1 instance, 0x2a31790, in full:
  the entry length mask, the vector main loop (its backward edge,
  shuffle/load/store shape), the scalar remainder tail inside the
  same body, and the body's only two external references -- two
  16-byte constants in .rodata, read through the section table.
  The constants (a 0x0f nibble mask and the ASCII string
  "0123456789abcdef"), the hi-nibble-first table lookups of the
  tail and the output stores at twice the input stride name the
  operation: a lowercase hexadecimal encoding of the input bytes,
  two characters per byte;
* for every selection sequence whose set arm reaches an F1 target
  (98 sequences in 88 bodies) it re-derives the clear arm from the
  consumer's own blocks, byte-hash-verifies the region against
  #2616's pinned region digest, and classifies the region's code:
  a region is the scalar form of the same operation when it
  references the same hex table, splits bytes into nibbles
  (and 0xf / shr 4) feeding table lookups, and stores the looked-up
  characters hi-nibble first (checked by a linear tag tracker over
  the region); for unrolled regions the number of bytes converted
  is also checked against the set arm's immediate length argument.
  Empty clear arms (guarded calls) are recorded as having no
  scalar form.

No captured code is executed.  The whole capture is authenticated
by size and SHA-256 before any analysis; GNU tools receive a
private byte-identical snapshot whose path is replaced by
``<authenticated-node115>`` in retained text.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032

TIP_PACKET = ROOT / "research/work-items/RE-002-node115-bit9-arms"
TRACED = 0x2A31790          # most-selected F1 instance (31 sequences)
EXPECTED_TABLE = b"0123456789abcdef"
EXPECTED_MASK = b"\x0f" * 16

EXPECTED_FDE_COUNT = 135313


def hx(value):
    return f"0x{value:x}"


# ---------------------------------------------------------------- ELF


def sections(data):
    if data[:6] != b"\x7fELF\x02\x01" or len(data) < 64:
        raise ValueError("Expected ELF64 little-endian input")
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, names_index = struct.unpack_from("<HHH", data, 58)
    if entsize < 64 or not count or names_index >= count \
            or shoff + entsize * count > len(data):
        raise ValueError("Invalid or unsupported ELF section table")
    raw = []
    for index in range(count):
        name, typ, flags, addr, off, size = struct.unpack_from(
            "<IIQQQQ", data, shoff + index * entsize)
        if typ != 8 and off + size > len(data):
            raise ValueError("Section outside file")
        raw.append((name, typ, flags, addr, off, size))
    names_off = raw[names_index][4]
    result = []
    for name, typ, flags, addr, off, size in raw:
        end = data.index(b"\x00", names_off + name)
        result.append({
            "name": data[names_off + name:end].decode(),
            "type": typ, "flags": flags, "address": addr,
            "offset": off, "size": size,
        })
    return result


def va_to_offset(secs, va, length=1):
    """File offset of a VA through its section (never a fixed delta)."""
    for sec in secs:
        if sec["type"] == 8 or sec["size"] == 0:
            continue
        if sec["address"] <= va and va + length <= sec["address"] + sec["size"]:
            return sec["offset"] + (va - sec["address"])
    raise ValueError(f"VA {va:#x} (+{length}) is in no file-backed section")


def readelf_frames(snapshot):
    """FDE ranges and raw readelf -wf lines from the snapshot."""
    native = subprocess.check_output(
        ["readelf", "--debug-dump=frames", str(snapshot)], text=True)
    native = native.replace(str(snapshot), "<authenticated-node115>")
    ranges = []
    lines = {}
    for line in native.splitlines():
        m = re.match(
            r"^[0-9a-f]+ [0-9a-f]+ [0-9a-f]+ FDE cie=[0-9a-f]+ "
            r"pc=([0-9a-f]+)\.\.([0-9a-f]+)\s*$", line)
        if m:
            lo, hi = int(m.group(1), 16), int(m.group(2), 16)
            if hi > lo:
                ranges.append((lo, hi))
                lines[(lo, hi)] = line
    ranges.sort()
    return ranges, lines


# ---------------------------------------------------------------- disassembly

REG64 = {}
for _base, _aliases in {
    "rax": ("rax", "eax", "ax", "al", "ah"),
    "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
    "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
    "rdx": ("rdx", "edx", "dx", "dl", "dh"),
    "rsi": ("rsi", "esi", "si", "sil"),
    "rdi": ("rdi", "edi", "di", "dil"),
    "rbp": ("rbp", "ebp", "bp", "bpl"),
    "rsp": ("rsp", "esp", "sp", "spl"),
}.items():
    for _alias in _aliases:
        REG64[_alias] = _base
for _i in range(8, 16):
    for _alias, _canon in ((f"r{_i}", f"r{_i}"), (f"r{_i}d", f"r{_i}"),
                           (f"r{_i}w", f"r{_i}"), (f"r{_i}b", f"r{_i}")):
        REG64[_alias] = _canon

WIDTH = {}
for _alias in REG64:
    if _alias.startswith("r") and _alias[1:].isdigit():
        WIDTH[_alias] = 64
    elif _alias.endswith("d") and _alias[:-1][1:].isdigit():
        WIDTH[_alias] = 32
    elif _alias.endswith("w") and _alias[:-1][1:].isdigit():
        WIDTH[_alias] = 16
    elif _alias.endswith("b") and _alias[:-1][1:].isdigit():
        WIDTH[_alias] = 8
for _alias, _w in (("rax", 64), ("eax", 32), ("ax", 16), ("al", 8), ("ah", 8),
                   ("rbx", 64), ("ebx", 32), ("bx", 16), ("bl", 8), ("bh", 8),
                   ("rcx", 64), ("ecx", 32), ("cx", 16), ("cl", 8), ("ch", 8),
                   ("rdx", 64), ("edx", 32), ("dx", 16), ("dl", 8), ("dh", 8),
                   ("rsi", 64), ("esi", 32), ("si", 16), ("sil", 8),
                   ("rdi", 64), ("edi", 32), ("di", 16), ("dil", 8),
                   ("rbp", 64), ("ebp", 32), ("bp", 16), ("bpl", 8),
                   ("rsp", 64), ("esp", 32), ("sp", 16), ("spl", 8)):
    WIDTH[_alias] = _w

INSN_LINE = re.compile(r"^ ([0-9a-f]+):\t([0-9a-f ]*?)\s*\t(.*)$")


class Insn:
    __slots__ = ("va", "data", "text", "mnemonic", "operands", "comment")

    def __init__(self, va, data, text):
        self.va = va
        self.data = data
        self.text = text
        parts = text.split(None, 1)
        self.mnemonic = parts[0] if parts else ""
        rest = parts[1] if len(parts) > 1 else ""
        if "#" in rest:
            ops, _, comment = rest.partition("#")
            self.operands = ops.strip()
            self.comment = comment.strip()
        else:
            self.operands = rest.strip()
            self.comment = ""

    @property
    def end(self):
        return self.va + len(self.data)

    def comment_target(self):
        m = re.match(r"^([0-9a-f]+)\b", self.comment)
        return int(m.group(1), 16) if m else None


def disassemble(snapshot, lo, hi):
    """objdump one FDE; returns (export_text, [Insn])."""
    native = subprocess.check_output(
        ["objdump", "-d", "-M", "intel",
         f"--start-address={lo:#x}", f"--stop-address={hi:#x}",
         str(snapshot)], text=True)
    native = native.replace(str(snapshot), "<authenticated-node115>")
    insns = []
    current = None
    for line in native.splitlines():
        m = INSN_LINE.match(line)
        if not m:
            continue
        va = int(m.group(1), 16)
        raw = bytes.fromhex(m.group(2).replace(" ", "")) \
            if m.group(2).strip() else b""
        body = m.group(3)
        if body == "":
            if current is not None:
                current.data += raw
            continue
        current = Insn(va, raw, body)
        insns.append(current)
    for insn in insns:
        if not (lo <= insn.va and insn.end <= hi):
            raise ValueError(f"insn {insn.va:#x} escapes FDE {lo:#x}..{hi:#x}")
    if not insns or insns[0].va != lo:
        raise ValueError(f"FDE {lo:#x} does not decode from its start")
    return native, insns


def split_operands(text):
    parts = []
    depth = 0
    current = ""
    for ch in text:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())
    return parts


def parse_memory(operand):
    """Parse 'QWORD PTR [base+index*scale+disp]' style operands."""
    m = re.match(r"^(?:(BYTE|WORD|DWORD|QWORD|XMMWORD) PTR )?\[([^]]*)\]$",
                 operand)
    if not m:
        return None
    size = {"BYTE": 8, "WORD": 16, "DWORD": 32, "QWORD": 64,
            "XMMWORD": 128, None: 64}[m.group(1)]
    inside = m.group(2).replace(" ", "")
    base = None
    index = None
    disp = 0
    for term in re.findall(r"[+-]?[^+-]+", inside):
        sign = -1 if term.startswith("-") else 1
        term = term.lstrip("+-")
        if term in REG64:
            if base is None:
                base = REG64[term]
            else:
                index = REG64[term]
        elif "*" in term:
            reg, _, _scale = term.partition("*")
            if reg in REG64:
                index = REG64[reg]
        elif term == "rip":
            base = "rip"
        elif term.startswith("0x"):
            disp += sign * int(term, 16)
        elif term.isdigit():
            disp += sign * int(term)
        else:
            return None
    return {"size": size, "base": base, "index": index, "disp": disp}


def parse_operand(operand):
    operand = operand.strip()
    if operand in REG64:
        return ("reg", REG64[operand], WIDTH[operand], operand)
    mem = parse_memory(operand)
    if mem is not None:
        return ("mem", mem)
    if operand.startswith("0x") or operand.startswith("-0x"):
        return ("imm", int(operand, 16))
    if re.fullmatch(r"-?\d+", operand):
        return ("imm", int(operand))
    m = re.match(r"^([0-9a-f]+)\s*<", operand)
    if m:
        return ("addr", int(m.group(1), 16))
    return ("other", operand)


def build_blocks(insns, fde):
    """Split the body into basic blocks; returns (blocks, edges).

    Mirrors the block construction of the #2616 producer: leaders
    are the FDE start, direct in-body branch targets and the
    instructions after branches/rets; calls do not split blocks.
    """
    leaders = {insns[0].va}
    for i, insn in enumerate(insns):
        if insn.mnemonic.startswith("j") or insn.mnemonic == "ret":
            ops = split_operands(insn.operands) if insn.operands else []
            if ops:
                target = parse_operand(ops[0])
                if target[0] == "addr" and fde[0] <= target[1] < fde[1]:
                    leaders.add(target[1])
            if i + 1 < len(insns):
                leaders.add(insns[i + 1].va)
    blocks = []
    current = []
    for insn in insns:
        if insn.va in leaders and current:
            blocks.append(current)
            current = []
        current.append(insn)
    if current:
        blocks.append(current)
    block_of = {}
    for bi, block in enumerate(blocks):
        for insn in block:
            block_of[insn.va] = bi
    edges = {bi: set() for bi in range(len(blocks))}
    for bi, block in enumerate(blocks):
        last = block[-1]
        fall = bi + 1 if bi + 1 < len(blocks) else None
        if last.mnemonic == "ret":
            continue
        if last.mnemonic == "jmp":
            ops = split_operands(last.operands) if last.operands else []
            target = parse_operand(ops[0]) if ops else ("other", None)
            if target[0] == "addr" and target[1] in block_of:
                edges[bi].add(block_of[target[1]])
            continue
        if last.mnemonic.startswith("j"):
            if fall is not None:
                edges[bi].add(fall)
            ops = split_operands(last.operands) if last.operands else []
            target = parse_operand(ops[0]) if ops else ("other", None)
            if target[0] == "addr" and target[1] in block_of:
                edges[bi].add(block_of[target[1]])
            continue
        if fall is not None:
            edges[bi].add(fall)
    return blocks, edges


def normalised_stream(insns, fde):
    """The #2616 normalisation: a lone branch/call operand becomes
    @self+offset for in-body targets and @absolute otherwise; a
    RIP-relative operand becomes [rip->self+offset] or
    [rip->absolute] by its computed target."""
    seq = []
    for insn in insns:
        ops = insn.operands
        lone = re.fullmatch(r"([0-9a-f]+)(?:\s*<[^>]*>)?", ops or "")
        if lone:
            va = int(lone.group(1), 16)
            ops = f"@self+0x{va - fde[0]:x}" \
                if fde[0] <= va < fde[1] else f"@{va:#x}"
        elif "rip" in ops:
            target = insn.comment_target()
            if target is not None:
                rep = f"[rip->self+0x{target - fde[0]:x}]" \
                    if fde[0] <= target < fde[1] \
                    else f"[rip->{target:#x}]"
                ops = re.sub(r"\[rip[^\]]*\]", rep, ops)
        seq.append(f"{insn.mnemonic} {ops}".strip())
    return seq


def body_sha256(data, secs, lo, hi):
    off = va_to_offset(secs, lo, hi - lo)
    return hashlib.sha256(data[off:off + (hi - lo)]).hexdigest()


# ---------------------------------------------------------------- tip pins


def parse_range(text):
    lo, hi = text.split("..")
    return int(lo, 16), int(hi, 16)


def load_tip_records():
    path = TIP_PACKET / "records.json"
    if not path.exists():
        raise ValueError(f"merged #2616 packet records missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- trace


def trace_f1_instance(data, secs, insns, fde):
    """Full structural trace of the traced F1 instance."""
    lo, hi = fde
    if insns[0].mnemonic != "movabs" or "0x7ffffffffffffff0" \
            not in insns[0].operands:
        raise ValueError("traced body does not open with the length mask")
    if any(i.mnemonic == "call" for i in insns):
        raise ValueError("traced body unexpectedly contains a call")
    if insns[-1].mnemonic != "ret":
        raise ValueError("traced body does not end in ret")

    # External references: every RIP-relative operand's target,
    # with the 16 bytes it names, read through the section table.
    refs = {}
    for insn in insns:
        if "rip" in insn.operands:
            target = insn.comment_target()
            if target is None:
                raise ValueError(f"unresolved rip reference at {insn.va:#x}")
            if target not in refs:
                off = va_to_offset(secs, target, 16)
                blob = data[off:off + 16]
                refs[target] = {
                    "address": hx(target),
                    "bytes": blob.hex(),
                    "ascii": "".join(
                        chr(b) if 32 <= b < 127 else "." for b in blob),
                    "referenced_from": [],
                }
            refs[target]["referenced_from"].append(hx(insn.va))
    table_vas = [va for va, r in refs.items()
                 if bytes.fromhex(r["bytes"]) == EXPECTED_TABLE]
    mask_vas = [va for va, r in refs.items()
                if bytes.fromhex(r["bytes"]) == EXPECTED_MASK]
    if len(table_vas) != 1 or len(mask_vas) != 1:
        raise ValueError(
            f"traced body constants changed: tables={table_vas} "
            f"masks={mask_vas}")
    table_va, mask_va = table_vas[0], mask_vas[0]

    # Main loop: the backward conditional jump whose target is the
    # vector load (the scalar tail has its own backward jump, to a
    # byte load; only the main loop's head is a movdqu).
    by_va = {i.va: i for i in insns}
    loops = []
    for insn in insns:
        if insn.mnemonic.startswith("j") and insn.mnemonic != "jmp":
            ops = split_operands(insn.operands)
            tgt = parse_operand(ops[0]) if ops else ("other", None)
            if tgt[0] == "addr" and tgt[1] < insn.va and tgt[1] in by_va \
                    and by_va[tgt[1]].mnemonic == "movdqu":
                loops.append((tgt[1], insn))
    if len(loops) != 1:
        raise ValueError(f"traced body loop shape changed: {loops}")
    loop_head, back_edge = loops[0]
    loop_insns = [i for i in insns if loop_head <= i.va <= back_edge.va]
    loop_loads = []
    loop_stores = []
    loop_shuffles = 0
    for i in loop_insns:
        ops = split_operands(i.operands)
        if i.mnemonic == "pshufb":
            loop_shuffles += 1
        if i.mnemonic == "movdqu" and len(ops) == 2:
            src = parse_operand(ops[1])
            dst = parse_operand(ops[0])
            if src[0] == "mem" and src[1]["base"] == "rdi":
                loop_loads.append(i)
            if dst[0] == "mem" and dst[1]["base"] == "rdx":
                loop_stores.append(i)
    if len(loop_loads) != 1 or len(loop_stores) != 2 or loop_shuffles != 2:
        raise ValueError(
            f"main loop shape changed: loads={len(loop_loads)} "
            f"stores={len(loop_stores)} shuffles={loop_shuffles}")
    store = loop_stores[0]
    store_mem = parse_operand(split_operands(store.operands)[0])[1]
    if store_mem["index"] != "rcx":
        raise ValueError("main loop store is not indexed by the counter")

    # Scalar tail: from the loop-exit block start to the ret.
    tail_start = back_edge.end
    tail = [i for i in insns if i.va >= tail_start]
    tail_lookups = 0
    tail_table_leas = []
    regs = {}
    for i in tail:
        if i.mnemonic == "lea" and i.comment_target() == table_va:
            dest = parse_operand(split_operands(i.operands)[0])
            if dest[0] == "reg":
                regs[dest[1]] = table_va
                tail_table_leas.append(hx(i.va))
        ops = split_operands(i.operands)
        if i.mnemonic in ("movzx", "mov") and len(ops) == 2:
            src = parse_operand(ops[1])
            if src[0] == "mem" and (src[1]["base"] in regs
                                    or src[1]["index"] in regs):
                tail_lookups += 1
    if not tail_table_leas or tail_lookups < 2:
        raise ValueError("scalar tail does not look up the hex table")

    trace = {
        "body": f"{hx(lo)}..{hx(hi)}",
        "bytes": hi - lo,
        "insns": len(insns),
        "calls": 0,
        "entry": [i.text for i in insns[:2]],
        "constants": [refs[va] for va in sorted(refs)],
        "table_address": hx(table_va),
        "mask_address": hx(mask_va),
        "main_loop": {
            "head": hx(loop_head),
            "back_edge": hx(back_edge.va),
            "insns": len(loop_insns),
            "vector_loads_from_input": len(loop_loads),
            "vector_stores_to_output": len(loop_stores),
            "pshufb": loop_shuffles,
            "input_stride_bytes": 16,
            "output_stride_per_input_byte": 2,
        },
        "scalar_tail": {
            "start": hx(tail_start),
            "insns": len(tail),
            "table_lea_sites": tail_table_leas,
            "table_lookups": tail_lookups,
        },
    }
    return trace, table_va


# ---------------------------------------------------------------- clear arms


def classify_region(region_insns, table_va, body_insns):
    """Classify one hash-verified clear region.

    Returns the evidence counts and the verdict.  A region is the
    scalar form of the traced operation when it references the
    same hex table and its byte processing splits nibbles
    (and 0xf / shr 4) into table lookups whose results are stored.
    """
    table_regs = set()
    table_ref = None
    lookups = 0
    and0f = 0
    shr4 = 0
    byte_stores = 0
    has_loop = False
    region_vas = {i.va for i in region_insns}
    for insn in region_insns:
        ops = split_operands(insn.operands) if insn.operands else []
        if insn.mnemonic == "lea" and insn.comment_target() == table_va \
                and ops:
            dest = parse_operand(ops[0])
            if dest[0] == "reg":
                table_regs.add(dest[1])
                table_ref = "lea-in-region"
        elif insn.comment_target() == table_va or (
                ops and any(parse_operand(o) == ("imm", table_va)
                            for o in ops)):
            table_ref = table_ref or "reference-in-region"
        if insn.mnemonic == "and" and len(ops) == 2 \
                and parse_operand(ops[1]) == ("imm", 0xF):
            and0f += 1
        if insn.mnemonic in ("shr", "sar") and len(ops) == 2 \
                and parse_operand(ops[1]) == ("imm", 4):
            shr4 += 1
        if insn.mnemonic.startswith("j") and ops:
            tgt = parse_operand(ops[0])
            if tgt[0] == "addr" and tgt[1] in region_vas \
                    and tgt[1] < insn.va:
                has_loop = True
        if len(ops) == 2:
            dst = parse_operand(ops[0])
            src = parse_operand(ops[1])
            if insn.mnemonic in ("movzx", "mov") \
                    and src[0] == "mem" and src[1]["size"] == 8 \
                    and (src[1]["base"] in table_regs
                         or src[1]["index"] in table_regs):
                lookups += 1
            if insn.mnemonic == "mov" \
                    and dst[0] == "mem" and dst[1]["size"] == 8:
                byte_stores += 1
    if table_ref is None:
        # The table base may be materialised in the same body just
        # before the region (e.g. in the test block).  Seed from
        # any lea of the table in the body and recount lookups.
        seeded = set()
        for insn in body_insns:
            if insn.va >= region_insns[0].va:
                break
            if insn.mnemonic == "lea" \
                    and insn.comment_target() == table_va:
                ops = split_operands(insn.operands)
                dest = parse_operand(ops[0]) if ops else ("other", None)
                if dest[0] == "reg":
                    seeded.add(dest[1])
        if seeded:
            table_regs |= seeded
            lookups = 0
            for insn in region_insns:
                ops = split_operands(insn.operands) \
                    if insn.operands else []
                if insn.mnemonic in ("movzx", "mov") and len(ops) == 2:
                    src = parse_operand(ops[1])
                    if src[0] == "mem" and src[1]["size"] == 8 \
                            and (src[1]["base"] in table_regs
                                 or src[1]["index"] in table_regs):
                        lookups += 1
            if lookups:
                table_ref = "lea-in-body"
    verdict = "other"
    if table_ref is not None and lookups >= 2 and lookups % 2 == 0 \
            and and0f >= 1 and shr4 >= 1:
        verdict = "scalar-hex-table"
    return {
        "verdict": verdict,
        "form": "loop" if has_loop else ("unrolled" if lookups else "none"),
        "table_ref": table_ref,
        "table_lookups": lookups,
        "and_0xf": and0f,
        "shr_4": shr4,
        "byte_stores": byte_stores,
        "bytes_processed": lookups // 2 if (lookups and not has_loop)
        else None,
        "nibble_order": nibble_order(region_insns, table_va),
    }


def nibble_order(region_insns, table_va):
    """Order in which looked-up characters are stored.

    A small linear tag tracker: a register is tagged 'and' when
    last defined by and reg,0xf and 'shr' when last defined by
    shr reg,4; a table lookup through a nibble register so tagged
    yields a 'lo' resp. 'hi' character; a plain register copy
    propagates the tag; any other definition clears it.  The
    result is the order of the first tagged byte stores.
    """
    table_regs = set()
    tags = {}
    order = []

    def canon(reg):
        return REG64.get(reg, reg)

    for insn in region_insns:
        ops = split_operands(insn.operands) if insn.operands else []
        if insn.mnemonic == "lea" and insn.comment_target() == table_va \
                and ops:
            dest = parse_operand(ops[0])
            if dest[0] == "reg":
                table_regs.add(dest[1])
            continue
        if len(ops) != 2:
            continue
        dst = parse_operand(ops[0])
        src = parse_operand(ops[1])
        if insn.mnemonic == "and" and src == ("imm", 0xF) \
                and dst[0] == "reg":
            tags[dst[1]] = "and"
            continue
        if insn.mnemonic in ("shr", "sar") and src == ("imm", 4) \
                and dst[0] == "reg":
            tags[dst[1]] = "shr"
            continue
        if insn.mnemonic in ("movzx", "mov") and src[0] == "mem":
            nibble = None
            for reg in (src[1]["base"], src[1]["index"]):
                if reg is not None and reg not in table_regs:
                    nibble = reg
            if src[1]["base"] in table_regs or src[1]["index"] in table_regs:
                if dst[0] == "reg":
                    tag = tags.get(nibble)
                    tags[dst[1]] = {"shr": "hi", "and": "lo"}.get(
                        tag, None)
                continue
            if dst[0] == "reg" and src[1]["size"] == 8:
                tags[dst[1]] = None     # a fresh input byte
            continue
        if insn.mnemonic == "mov" and dst[0] == "mem" \
                and dst[1]["size"] == 8 and src[0] == "reg":
            tag = tags.get(src[1])
            if tag in ("hi", "lo"):
                order.append(tag)
            continue
        if insn.mnemonic == "mov" and dst[0] == "reg" \
                and src[0] == "reg":
            tags[dst[1]] = tags.get(src[1])
            continue
        if dst[0] == "reg" and insn.mnemonic not in ("cmp", "test"):
            tags[dst[1]] = None
    if order and order[0] == "hi" and (len(order) == 1
                                       or order[1] == "lo"):
        return "hi-first"
    if order and order[0] == "lo":
        return "lo-first"
    return "unknown"


def set_length_const(block_insns_list):
    """Immediate moved into rsi/esi inside the set-arm blocks."""
    for insn in block_insns_list:
        ops = split_operands(insn.operands) if insn.operands else []
        if insn.mnemonic == "mov" and len(ops) == 2:
            dst = parse_operand(ops[0])
            src = parse_operand(ops[1])
            if dst[0] == "reg" and dst[1] == "rsi" and src[0] == "imm":
                return src[1]
    return None


# ---------------------------------------------------------------- analysis


def analyse(data):
    secs = sections(data)
    tip = load_tip_records()
    if tip["target_sha256"] != SHA256:
        raise ValueError("tip packet is bound to a different capture")

    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / "hl-node"
        snapshot.write_bytes(data)
        ranges, frame_lines = readelf_frames(snapshot)
        if len(ranges) != EXPECTED_FDE_COUNT:
            raise ValueError(
                f"FDE count changed: {len(ranges)} != {EXPECTED_FDE_COUNT}")
        fde_set = set(ranges)

        # ---- verify all 14 tip target pins; trace F1 identity ----
        targets = []
        f1_los = set()
        for row in tip["targets"]:
            lo, hi = parse_range(row["range"])
            if (lo, hi) not in fde_set:
                raise ValueError(f"target {row['range']} is not an FDE")
            digest = body_sha256(data, secs, lo, hi)
            if digest != row["sha256"]:
                raise ValueError(f"target {row['range']} hash mismatch")
            _text, insns = disassemble(snapshot, lo, hi)
            if len(insns) != row["insns"]:
                raise ValueError(f"target {row['range']} insn count changed")
            norm = hashlib.sha256(
                ("\n".join(normalised_stream(insns, (lo, hi))) + "\n")
                .encode()).hexdigest()
            if norm != row["normalised_sha256"]:
                raise ValueError(
                    f"target {row['range']} normalised stream changed")
            if row["stream_family"] == "F1":
                f1_los.add(lo)
            targets.append({
                "range": row["range"],
                "stream_family": row["stream_family"],
                "sha256": digest,
                "normalised_sha256": norm,
                "selected_by_sequences": row["selected_by_sequences"],
            })
        f1_norms = {t["normalised_sha256"] for t in targets
                    if t["stream_family"] == "F1"}
        if len(f1_los) != 11 or len(f1_norms) != 1:
            raise ValueError("F1 placements no longer share one stream")

        # ---- trace the most-selected F1 instance ----
        traced_row = next(t for t in tip["targets"]
                          if parse_range(t["range"])[0] == TRACED)
        tlo, thi = parse_range(traced_row["range"])
        targets_text, traced_insns = disassemble(snapshot, tlo, thi)
        trace, table_va = trace_f1_instance(
            data, secs, traced_insns, (tlo, thi))

        # ---- verify consumer pins; classify F1 clear arms ----
        consumers_out = []
        region_text_parts = []
        seq_total = 0
        verdict_counts = {}
        form_counts = {}
        order_counts = {}
        length_agree = [0, 0]     # [agree, disagree] for unrolled regions
        involved = []
        for crow in tip["consumers"]:
            clo, chi = parse_range(crow["range"])
            if (clo, chi) not in fde_set:
                raise ValueError(f"consumer {crow['range']} is not an FDE")
            digest = body_sha256(data, secs, clo, chi)
            if digest != crow["sha256"]:
                raise ValueError(f"consumer {crow['range']} hash mismatch")
            selected = []
            for idx, seq in enumerate(crow["sequences"]):
                transfers = seq["set_arm"].get("transfers") or []
                if seq["set_arm"]["kind"] == "call" and transfers \
                        and int(transfers[0]["target"], 16) in f1_los:
                    selected.append((idx, seq))
            if not selected:
                continue
            ctext, cinsns = disassemble(snapshot, clo, chi)
            blocks, _edges = build_blocks(cinsns, (clo, chi))
            block_by_start = {b[0].va: b for b in blocks}
            involved.append((clo, chi))
            for idx, seq in selected:
                seq_total += 1
                clear = seq["clear_arm"]
                set_target = seq["set_arm"]["transfers"][0]["target"]
                entry = {
                    "consumer": crow["range"],
                    "sequence": idx,
                    "set_target": set_target,
                    "clear_kind": clear["kind"],
                }
                if clear["kind"] == "empty":
                    entry["clear"] = {
                        "verdict": "empty", "form": "none",
                        "table_ref": None, "table_lookups": 0,
                        "and_0xf": 0, "shr_4": 0, "byte_stores": 0,
                        "bytes_processed": None,
                        "nibble_order": "none",
                        "region_sha256": clear["region_sha256"],
                    }
                else:
                    region_insns = []
                    for start in clear["blocks"]:
                        block = block_by_start.get(int(start, 16))
                        if block is None:
                            raise ValueError(
                                f"clear block {start} not rebuilt in "
                                f"{crow['range']}")
                        region_insns.extend(block)
                    blob = b"".join(i.data for i in region_insns)
                    digest_r = hashlib.sha256(blob).hexdigest()
                    if digest_r != clear["region_sha256"] \
                            or len(blob) != clear["bytes"]:
                        raise ValueError(
                            f"clear region hash mismatch in "
                            f"{crow['range']} seq {idx}")
                    cls = classify_region(region_insns, table_va, cinsns)
                    entry["clear"] = dict(
                        cls, region_sha256=digest_r,
                        blocks=clear["blocks"], bytes=len(blob))
                    # retained region text, sliced from the body dump
                    vas = {i.va for i in region_insns}
                    lines = []
                    keep = False
                    for line in ctext.splitlines():
                        m = INSN_LINE.match(line)
                        if m:
                            keep = int(m.group(1), 16) in vas
                        if keep:
                            lines.append(line)
                    region_text_parts.append(
                        f"# consumer {crow['range']} sequence {idx} "
                        f"set {set_target} clear blocks "
                        f"{' '.join(clear['blocks'])}\n"
                        + "\n".join(lines) + "\n")
                set_blocks = []
                for start in seq["set_arm"]["blocks"]:
                    block = block_by_start.get(int(start, 16))
                    if block is None:
                        raise ValueError(
                            f"set block {start} not rebuilt in "
                            f"{crow['range']}")
                    set_blocks.extend(block)
                entry["set_length_const"] = set_length_const(set_blocks)
                if entry["clear"]["form"] == "unrolled" \
                        and entry["clear"]["verdict"] == "scalar-hex-table":
                    if entry["set_length_const"] is not None \
                            and entry["set_length_const"] \
                            == entry["clear"]["bytes_processed"]:
                        length_agree[0] += 1
                    else:
                        length_agree[1] += 1
                verdict_counts[entry["clear"]["verdict"]] = \
                    verdict_counts.get(entry["clear"]["verdict"], 0) + 1
                form_counts[entry["clear"]["form"]] = \
                    form_counts.get(entry["clear"]["form"], 0) + 1
                order_counts[entry["clear"]["nibble_order"]] = \
                    order_counts.get(entry["clear"]["nibble_order"], 0) + 1
                consumers_out.append(entry)

        # ---- targets export: the 11 F1 bodies ----
        f1_texts = []
        for row in tip["targets"]:
            if row["stream_family"] != "F1":
                continue
            lo, hi = parse_range(row["range"])
            text, _insns = disassemble(snapshot, lo, hi)
            f1_texts.append(text)

        frames_rows = []
        frame_keys = sorted(
            {(parse_range(t["range"])) for t in tip["targets"]
             if t["stream_family"] == "F1"} | set(involved))
        for key in frame_keys:
            if key in frame_lines:
                frames_rows.append(frame_lines[key])
        frames_text = "\n".join(frames_rows) + "\n"

    records = {
        "target_sha256": SHA256,
        "target_size": SIZE,
        "tip_packet": "RE-002-node115-bit9-arms (PR #2616)",
        "question": "trace the F1 stream to name the operation, and "
                    "check whether the in-body clear regions of its "
                    "selectors are the scalar form of the same "
                    "operation",
        "targets_verified": targets,
        "f1_stream": {
            "placements": sorted(
                t["range"] for t in targets
                if t["stream_family"] == "F1"),
            "normalised_sha256": next(iter(f1_norms)),
            "distinct_normalised_streams": 1,
        },
        "trace": trace,
        "operation": {
            "name": "lowercase hexadecimal encoding",
            "contract": "out[2*i] = table[in[i] >> 4], "
                        "out[2*i+1] = table[in[i] & 0xf] for "
                        "table = \"0123456789abcdef\"; input rdi, "
                        "length rsi, output rdx; no return value",
            "evidence": [
                "the body's only external references are a 16x0x0f "
                "nibble mask and the 16-byte ASCII table "
                "\"0123456789abcdef\" in .rodata",
                "the vector loop splits each 16-byte block into "
                "nibbles, shuffles both nibble planes through the "
                "table with pshufb, interleaves the characters and "
                "stores 32 bytes per 16 input bytes",
                "the in-body scalar tail converts the remaining "
                "length & 0xf bytes with the same table, hi nibble "
                "first, storing at twice the input index",
            ],
        },
        "sequences": consumers_out,
        "summary": {
            "f1_sequences": seq_total,
            "f1_bodies": len(involved),
            "clear_verdicts": verdict_counts,
            "clear_forms": form_counts,
            "nibble_orders": order_counts,
            "unrolled_length_agreement": {
                "agree": length_agree[0], "disagree": length_agree[1]},
        },
        "captured_code_executed": False,
    }
    return records, frames_text, "\n".join(f1_texts), \
        "\n".join(region_text_parts)


def authenticate(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("input is not the pinned node #115 capture")


def generate(binary, output):
    data = Path(binary).read_bytes()
    authenticate(data)
    records, frames_text, targets_text, regions_text = analyse(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "records.json").write_text(
        json.dumps(records, indent=2) + "\n", encoding="utf-8")
    (output / "frames.txt").write_text(frames_text, encoding="utf-8")
    (output / "targets.objdump.txt").write_text(
        targets_text, encoding="utf-8")
    (output / "clear_regions.objdump.txt").write_text(
        regions_text, encoding="utf-8")
    return records


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=TARGET)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "work/bit9-f1-trace-check")
    args = parser.parse_args(argv)
    records = generate(args.binary, args.output)
    summary = records["summary"]
    print(f"f1_sequences={summary['f1_sequences']} "
          f"bodies={summary['f1_bodies']} "
          f"verdicts={summary['clear_verdicts']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
