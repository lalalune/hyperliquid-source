#!/usr/bin/env python3
"""Static trace of the RE-002 bit-9 F2 set-arm stream, of the
clear region that selects it, and of its direct transfers.

PR #2616 (the RE-002 bit-9 arms packet) pinned the arms the 92
bit-9 cache consumers select: the set arms reach 14 shared bodies
in four instruction streams.  PRs #2650, #2694 and #2739 traced
F1, F4 and F3 -- all one lowercase hex encoder at three shapes.
PR #2739 left as its next question, verbatim: "trace the F2
tail-jump body at 0x5bba120 -- at 1,758 bytes with a prologue
that loads two 32-byte halves of its input record, it does not
have the encoder's shape at all, so the question is what
operation the last bit-9 set arm actually selects, and where
its tail jump lands."

This producer answers that question:

* it re-verifies every pin of the merged #2616 packet against
  the authenticated capture -- all 14 set-arm target bodies (FDE
  bounds, byte size, SHA-256, instruction count, normalised
  stream) and every bit-9 consumer body -- or the analysis
  fails closed;
* it traces the sole F2 placement, 0x5bba120, in full: the
  entry loads three 16-byte rows of its state record (bytes
  0x00..0x30) and builds four 64-bit-counter variants
  (+0/+1/+2/+3) from the counter word at [rdi+0x20]; a
  test esi,esi gate sends a zero round count to a path that
  loads the doubled sigma constant; the round loop (head
  0x5bba230, dec esi / jne back edge) runs two ChaCha double
  rounds per iteration -- paddd/pxor quarter rounds with
  rotations 16/12/8/7 and pshufd lane rotations; after the
  loop the sigma row is added into the constant rows, and a
  shared epilogue advances the counter by 4, stores the
  rebuilt counter/nonce row back at [rdi+0x20] and writes
  256 bytes (four feed-forward ChaCha blocks) to rdx.  The
  constants name the operation: the 16-byte ASCII string
  "expand 32-byte k" at 0x4519c0 is the ChaCha sigma, its
  per-word double at 0x456c50 serves the zero-round path,
  and the two pshufb masks at 0x4531c0 / 0x452ec0 are the
  SSSE3 byte rotations -- F2 is the SSSE3 form of the ChaCha
  block function, four blocks in parallel;
* it analyses the one selecting body, 0x5bba800..0x5bbb030 --
  the family's only tailjmp/inbody sequence: a CPU-feature
  dispatcher over the cached feature word (slot 0x64dfa60,
  refreshed through 0x64dfa68) that walks its feature tests
  in order (sign, 0x4000, 0x400, then bit 9 = 0x200, cpuid
  leaf 1 ecx bit 9 = SSSE3) and tail-jumps to a per-feature
  body; the bit-9 set arm unwinds the dispatcher frame and
  jumps to 0x5bba120 with the caller's arguments, while a
  clear bit 9 falls through into the body's inline form of
  the same computation;
* it re-derives that clear region from the dispatcher's own
  blocks, byte-hash-verifies it against #2616's pinned region
  digest, and classifies it with the rule fixed for this
  family: the same operation in SSE2 form iff it references
  the same sigma and doubled-sigma constants, builds the
  same counter variants, runs a dec/jne round loop with
  rotations 16/12/8/7 whose 8-rotation is shift-based
  (psrld 0x18 / pslld 0x8, no pshufb anywhere) and shares
  the epilogue shape (counter += 4, one [rdi+0x20]
  write-back, 16 output stores);
* it censuses every direct E8/E9 transfer in .text whose
  target is the traced body (each raw hit validated against
  the disassembly of its containing FDE) and, in addition,
  every direct transfer to the dispatcher body itself.

No captured code is executed.  The whole capture is
authenticated by size and SHA-256 before any analysis; GNU
tools receive a private byte-identical snapshot whose path
is replaced by ``<authenticated-node115>`` in retained text.
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
TRACED = 0x5BBA120          # sole F2 placement (1 sequence)

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

SIGMA_VA = 0x4519C0
DOUBLE_SIGMA_VA = 0x456C50
ROT8_MASK_VA = 0x4531C0
ROT16_MASK_VA = 0x452EC0

SIGMA = b"expand 32-byte k"
DOUBLE_SIGMA = b"".join(
    struct.pack("<I", (word * 2) & 0xFFFFFFFF)
    for word in struct.unpack("<4I", SIGMA))
ROT8_MASK = bytes([3, 0, 1, 2, 7, 4, 5, 6,
                   11, 8, 9, 10, 15, 12, 13, 14])
ROT16_MASK = bytes([14, 15, 12, 13, 2, 3, 0, 1,
                    6, 7, 4, 5, 10, 11, 8, 9])
EXPECTED_CONSTANTS = {
    SIGMA_VA: SIGMA,
    DOUBLE_SIGMA_VA: DOUBLE_SIGMA,
    ROT8_MASK_VA: ROT8_MASK,
    ROT16_MASK_VA: ROT16_MASK,
}

DISPATCHER = (0x5BBA800, 0x5BBB030)
SET_ARM_BLOCK = 0x5BBB01E
SET_ARM_SITE = 0x5BBB02B
ZERO_PATH = 0x5BBA6BC
LOOP_HEAD = 0x5BBA230
LOOP_BACK = 0x5BBA693
MERGE = 0x5BBA6FD


def branch_target(insn):
    ops = split_operands(insn.operands) if insn.operands else []
    if not ops:
        return None
    parsed = parse_operand(ops[0])
    return parsed[1] if parsed[0] == "addr" else None


def rip_refs(data, secs, insns):
    """Every RIP-relative target named by the body, with bytes."""
    refs = {}
    for insn in insns:
        if "rip" in insn.operands:
            target = insn.comment_target()
            if target is None:
                raise ValueError(
                    f"unresolved rip reference at {insn.va:#x}")
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
    return refs


def trace_f2_instance(data, secs, insns, fde):
    """Full structural trace of the sole F2 placement."""
    lo, hi = fde
    by_va = {i.va: i for i in insns}
    if insns[0].mnemonic != "sub" or insns[0].operands != "rsp,0x38":
        raise ValueError("traced body frame shape changed")
    if insns[-1].mnemonic != "ret":
        raise ValueError("traced body does not end in ret")
    if any(i.mnemonic == "call" for i in insns):
        raise ValueError("traced body unexpectedly contains a call")

    # Branches: exactly the round-count gate, the loop back edge
    # and the post-loop jump into the shared epilogue.
    branches = []
    for insn in insns:
        if insn.mnemonic.startswith("j"):
            branches.append({
                "site": hx(insn.va), "kind": insn.mnemonic,
                "target": hx(branch_target(insn))})
    expected_branches = [
        {"site": hx(0x5BBA1E2), "kind": "je", "target": hx(ZERO_PATH)},
        {"site": hx(LOOP_BACK), "kind": "jne", "target": hx(LOOP_HEAD)},
        {"site": hx(0x5BBA6BA), "kind": "jmp", "target": hx(MERGE)},
    ]
    if branches != expected_branches:
        raise ValueError(f"traced body branches changed: {branches}")

    # Input loads: three 16-byte rows at [rdi], [rdi+0x10],
    # [rdi+0x20] (48 of the record's bytes), plus the 64-bit
    # counter word loaded into rax from [rdi+0x20].
    row_loads = []
    counter_load = []
    for insn in insns:
        if insn.va >= LOOP_HEAD:
            break
        ops = split_operands(insn.operands)
        if insn.mnemonic == "movdqa" and len(ops) == 2:
            src = parse_operand(ops[1])
            if src[0] == "mem" and src[1]["base"] == "rdi":
                row_loads.append((hx(insn.va), src[1]["disp"]))
        if insn.mnemonic == "mov" and len(ops) == 2:
            src = parse_operand(ops[1])
            if src[0] == "mem" and src[1]["base"] == "rdi" \
                    and src[1]["disp"] == 0x20:
                counter_load.append(hx(insn.va))
    if sorted(d for _s, d in row_loads) != [0, 0x10, 0x20] \
            or len(counter_load) != 1:
        raise ValueError(
            f"traced body input loads changed: {row_loads} "
            f"{counter_load}")

    # Counter variants: lea rcx,[rax+0x1/+0x2/+0x3] before the
    # gate (the +0 row is the loaded row itself).
    counter_leas = [hx(i.va) for i in insns
                    if i.mnemonic == "lea" and i.va < 0x5BBA1BC
                    and any(f"[rax+0x{k}]" in i.operands
                            for k in (1, 2, 3))]
    if len(counter_leas) != 3:
        raise ValueError(
            f"counter variant construction changed: {counter_leas}")

    # The round-count gate: test esi,esi; je zero-round path.
    gate = by_va.get(0x5BBA1BC)
    if gate is None or gate.mnemonic != "test" \
            or gate.operands != "esi,esi":
        raise ValueError("round-count gate changed")

    # Constants: exactly the four .rodata references, byte-pinned.
    refs = rip_refs(data, secs, insns)
    if set(refs) != set(EXPECTED_CONSTANTS):
        raise ValueError(
            f"traced body constants changed: {sorted(refs)}")
    for va, expected in EXPECTED_CONSTANTS.items():
        if bytes.fromhex(refs[va]["bytes"]) != expected:
            raise ValueError(f"constant at {va:#x} changed")

    # The round loop: head, dec esi immediately before the back
    # edge, and the rotation/shuffle census inside it.
    loop_insns = [i for i in insns if LOOP_HEAD <= i.va <= LOOP_BACK]
    dec = by_va.get(0x5BBA691)
    if dec is None or dec.mnemonic != "dec" \
            or dec.operands != "esi":
        raise ValueError("loop counter decrement changed")

    def count(mnemonic, imm=None, within=loop_insns):
        n = 0
        for i in within:
            if i.mnemonic != mnemonic:
                continue
            if imm is not None:
                ops = split_operands(i.operands)
                if not ops \
                        or parse_operand(ops[-1]) != ("imm", imm):
                    continue
            n += 1
        return n

    loop_pshufb = count("pshufb")
    if loop_pshufb == 0:
        raise ValueError("loop lost its pshufb rotations")
    pshufd_imms = {}
    for i in loop_insns:
        if i.mnemonic == "pshufd":
            ops = split_operands(i.operands)
            imm = parse_operand(ops[-1])[1]
            pshufd_imms[hx(imm)] = pshufd_imms.get(hx(imm), 0) + 1
    if set(pshufd_imms) != {"0x39", "0x4e", "0x93"}:
        raise ValueError(f"loop lane rotations changed: {pshufd_imms}")
    rotations = {
        "rot16_word_swaps_pshuflw_0xb1": count("pshuflw", 0xB1),
        "rot16_word_swaps_pshufhw_0xb1": count("pshufhw", 0xB1),
        "rot12_psrld_0x14": count("psrld", 0x14),
        "rot12_pslld_0xc": count("pslld", 0xC),
        "rot7_psrld_0x19": count("psrld", 0x19),
        "rot7_pslld_0x7": count("pslld", 0x7),
        "pshufb": loop_pshufb,
        "pshufd_lane_rotations": pshufd_imms,
        "paddd": count("paddd"),
        "pxor": count("pxor"),
    }
    if rotations["rot12_psrld_0x14"] == 0 \
            or rotations["rot7_psrld_0x19"] == 0 \
            or rotations["rot16_word_swaps_pshuflw_0xb1"] == 0:
        raise ValueError(f"loop rotations changed: {rotations}")

    # Post-loop: the sigma row is added into the four a-rows
    # (feed-forward for the constant row, whose original is the
    # sigma constant itself), then control joins the epilogue.
    sigma_add = by_va.get(0x5BBA699)
    if sigma_add is None or sigma_add.mnemonic != "movdqa" \
            or sigma_add.comment_target() != SIGMA_VA:
        raise ValueError("post-loop sigma load changed")
    ff_adds = [hx(i.va) for i in insns
               if 0x5BBA699 < i.va < 0x5BBA6BA and i.mnemonic == "paddd"]
    if len(ff_adds) != 4:
        raise ValueError(f"post-loop feed-forward adds changed: {ff_adds}")

    # Zero-round path: its first instruction loads the doubled
    # sigma (2 * sigma per word) -- the constant row's feed-
    # forward sum precomputed, so the path needs no add.
    zero_first = by_va.get(ZERO_PATH)
    if zero_first is None or zero_first.mnemonic != "movdqa" \
            or zero_first.comment_target() != DOUBLE_SIGMA_VA:
        raise ValueError("zero-round doubled-sigma load changed")

    # Shared epilogue from the merge point: counter += 4 with a
    # 16-byte write-back at [rdi+0x20], then 16 vector stores of
    # 16 bytes each to [rdx+0x00..0xf0] (256 bytes = 4 blocks).
    epi = [i for i in insns if i.va >= MERGE]
    if epi[0].mnemonic != "add" or epi[0].operands != "rax,0x4":
        raise ValueError("epilogue counter advance changed")
    writeback = [hx(i.va) for i in epi if i.mnemonic == "movdqa"
                 and split_operands(i.operands)
                 and parse_operand(split_operands(i.operands)[0])[0]
                 == "mem"
                 and parse_operand(split_operands(i.operands)[0])[1]
                 ["base"] == "rdi"]
    if len(writeback) != 1:
        raise ValueError(f"epilogue write-back changed: {writeback}")
    out_stores = []
    for i in epi:
        if i.mnemonic == "movdqu":
            dst = parse_operand(split_operands(i.operands)[0])
            if dst[0] == "mem" and dst[1]["base"] == "rdx":
                out_stores.append(dst[1]["disp"])
    if out_stores != list(range(0, 0x100, 0x10)):
        raise ValueError(f"epilogue output stores changed: {out_stores}")
    epi_adds = sum(1 for i in epi if i.mnemonic == "paddd")

    trace = {
        "body": f"{hx(lo)}..{hx(hi)}",
        "bytes": hi - lo,
        "insns": len(insns),
        "calls": 0,
        "entry": [i.text for i in insns[:8]],
        "branches": branches,
        "input": {
            "record_pointer": "rdi",
            "row_loads": [{"site": s, "disp": d} for s, d in row_loads],
            "bytes_read": "0x00..0x30 of the record (three 16-byte "
                          "rows); bytes 0x30.. of the record are "
                          "never read",
            "counter_load": counter_load[0],
            "counter": "the 64-bit word at [rdi+0x20]; variants "
                       "+0/+1/+2/+3 built at "
                       + ", ".join(counter_leas)
                       + " (carry into the high dword via shr "
                         "0x20), one per block",
        },
        "round_count_gate": {
            "test_site": hx(gate.va),
            "zero_target": hx(ZERO_PATH),
            "parameter": "esi = iterations of the round loop; "
                         "each iteration runs two double rounds "
                         "(four ChaCha rounds)",
        },
        "constants": [refs[va] for va in sorted(refs)],
        "round_loop": {
            "head": hx(LOOP_HEAD),
            "back_edge": hx(LOOP_BACK),
            "decrement_site": hx(dec.va),
            "insns": len(loop_insns),
            "rotations": rotations,
        },
        "post_loop_feed_forward": {
            "sigma_load": hx(sigma_add.va),
            "a_row_adds": ff_adds,
            "note": "the four constant rows receive the sigma add "
                    "here; every other row's feed-forward add "
                    "happens in the shared epilogue from the "
                    "entry-saved originals",
        },
        "zero_round_path": {
            "entry": hx(ZERO_PATH),
            "doubled_sigma_load": hx(zero_first.va),
            "note": "with esi == 0 no round runs: the constant "
                    "rows are loaded with 2*sigma per word (the "
                    "feed-forward sum precomputed) and the other "
                    "rows are doubled by the epilogue adds, so "
                    "the output is exactly initial + initial",
        },
        "epilogue": {
            "merge": hx(MERGE),
            "counter_advance": "rax += 4 at " + hx(epi[0].va),
            "counter_writeback_site": writeback[0],
            "counter_writeback": "16 bytes stored at [rdi+0x20]: "
                                 "the rebuilt counter/nonce row "
                                 "with the 64-bit counter advanced "
                                 "by 4",
            "output_stores": [hx(d) for d in out_stores],
            "output_bytes": 256,
            "feed_forward_adds": epi_adds,
        },
    }
    return trace


# ------------------------------------------------------- clear region

def classify_clear_region(region_insns):
    """Classify the dispatcher's hash-verified clear region.

    The analogue of the earlier packets' scalar-form rule for
    this family: the region is the same operation in its SSE2
    form when it references the same sigma and doubled-sigma
    constants, builds the same +1/+2/+3 counter variants, runs
    a dec/jne round loop whose rotations are 16/12/8/7 with the
    8-rotation done by shifts (psrld 0x18 / pslld 0x8) instead
    of pshufb -- no pshufb at all -- and shares the epilogue
    shape (counter += 4, one [rdi+0x20] write-back, 16 output
    stores).
    """
    def refs_of(va):
        return [i.va for i in region_insns
                if i.comment_target() == va]

    def count(mnemonic, imm=None):
        n = 0
        for i in region_insns:
            if i.mnemonic != mnemonic:
                continue
            if imm is not None:
                ops = split_operands(i.operands)
                if not ops \
                        or parse_operand(ops[-1]) != ("imm", imm):
                    continue
            n += 1
        return n

    out_stores = 0
    writeback = 0
    for i in region_insns:
        ops = split_operands(i.operands) if i.operands else []
        if not ops:
            continue
        dst = parse_operand(ops[0])
        if i.mnemonic == "movdqu" and dst[0] == "mem" \
                and dst[1]["base"] == "rdx":
            out_stores += 1
        if i.mnemonic == "movdqa" and dst[0] == "mem" \
                and dst[1]["base"] == "rdi" \
                and dst[1]["disp"] == 0x20:
            writeback += 1
    counter_leas = sum(
        1 for i in region_insns if i.mnemonic == "lea"
        and any(f"[rax+0x{k}]" in i.operands for k in (1, 2, 3)))
    counts = {
        "sigma_refs": len(refs_of(SIGMA_VA)),
        "doubled_sigma_refs": len(refs_of(DOUBLE_SIGMA_VA)),
        "pshufb": count("pshufb"),
        "rot16_word_swaps": count("pshuflw", 0xB1)
        + count("pshufhw", 0xB1),
        "rot12_pairs": min(count("psrld", 0x14), count("pslld", 0xC)),
        "rot8_shift_pairs": min(count("psrld", 0x18),
                                count("pslld", 0x8)),
        "rot7_pairs": min(count("psrld", 0x19), count("pslld", 0x7)),
        "counter_variant_leas": counter_leas,
        "output_stores": out_stores,
        "counter_writebacks": writeback,
        "counter_advance_adds": sum(
            1 for i in region_insns if i.mnemonic == "add"
            and i.operands == "rax,0x4"),
    }
    same = counts["sigma_refs"] >= 1 \
        and counts["doubled_sigma_refs"] >= 1 \
        and counts["pshufb"] == 0 \
        and counts["rot8_shift_pairs"] >= 4 \
        and counts["rot12_pairs"] >= 4 \
        and counts["rot7_pairs"] >= 4 \
        and counts["rot16_word_swaps"] >= 4 \
        and counts["counter_variant_leas"] == 3 \
        and counts["output_stores"] == 16 \
        and counts["counter_writebacks"] == 1 \
        and counts["counter_advance_adds"] == 1
    return {
        "verdict": "same-operation-sse2-form" if same else "other",
        "form": "loop",
        "counts": counts,
    }


# ---------------------------------------------------------- dispatcher

def dispatcher_analysis(insns):
    """Structural pins of the selecting body 0x5bba800..0x5bbb030.

    The body is a CPU-feature dispatcher over a cached feature
    word (slot 0x64dfa60, refreshed through slot 0x64dfa68): it
    walks feature bits in a fixed order and tail-jumps to a
    per-feature body; bit 9 (0x200, cpuid leaf 1 ecx bit 9 =
    SSSE3 per the #2616 driver table) selects the F2 body, and
    when bit 9 is clear control falls through into the body's
    own inline SSE2 form of the same computation.
    """
    by_va = {i.va: i for i in insns}
    slot_load = by_va.get(0x5BBA80D)
    if slot_load is None or slot_load.comment_target() != 0x64DFA60:
        raise ValueError("dispatcher feature-slot load changed")
    refresh_calls = [hx(i.va) for i in insns if i.mnemonic == "call"
                     and i.comment_target() == 0x64DFA68]
    if len(refresh_calls) != 4:
        raise ValueError(
            f"dispatcher refresh calls changed: {refresh_calls}")

    def test_sites(imm):
        return [hx(i.va) for i in insns if i.mnemonic == "test"
                and split_operands(i.operands)
                and parse_operand(split_operands(i.operands)[1])
                == ("imm", imm)]

    bit9_sites = test_sites(0x200)
    if bit9_sites != [hx(0x5BBA863), hx(0x5BBB013)]:
        raise ValueError(f"dispatcher bit-9 tests changed: {bit9_sites}")
    exits = []
    for i in insns:
        if i.mnemonic == "jmp":
            target = branch_target(i)
            if target is not None \
                    and DISPATCHER[0] <= target < DISPATCHER[1]:
                continue        # in-body jump (e.g. into the epilogue)
            exits.append({"site": hx(i.va), "target": hx(target)})
    expected_exits = [
        {"site": hx(0x5BBAF92), "target": hx(0x5BBB630)},
        {"site": hx(0x5BBAFC5), "target": hx(0x5BBB030)},
        {"site": hx(0x5BBAFF8), "target": hx(0x5BB9A60)},
        {"site": hx(SET_ARM_SITE), "target": hx(TRACED)},
    ]
    if exits != expected_exits:
        raise ValueError(f"dispatcher exits changed: {exits}")
    set_block = [by_va[va] for va in
                 (0x5BBB01E, 0x5BBB025, 0x5BBB026, 0x5BBB028,
                  0x5BBB02A, SET_ARM_SITE)]
    if [i.mnemonic for i in set_block] != \
            ["add", "pop", "pop", "pop", "pop", "jmp"]:
        raise ValueError("set-arm tail-jump block changed")
    return {
        "body": f"{hx(DISPATCHER[0])}..{hx(DISPATCHER[1])}",
        "feature_slot": "0x64dfa60",
        "feature_slot_load": hx(slot_load.va),
        "refresh_slot": "0x64dfa68",
        "refresh_call_sites": refresh_calls,
        "bit_tests": {
            "sign": [hx(i.va) for i in insns
                     if i.mnemonic == "js"],
            "0x4000": test_sites(0x4000),
            "0x400": test_sites(0x400),
            "0x200_bit9": bit9_sites,
        },
        "exits": exits,
        "set_arm": {
            "block": hx(SET_ARM_BLOCK),
            "shape": "add rsp,0xa8; pop rbx; pop r14; pop r15; "
                     "pop rbp; jmp -- the dispatcher's frame is "
                     "fully unwound before the jump, so the F2 "
                     "body is entered with the caller's own "
                     "arguments (rdi, esi, rdx) and its ret "
                     "returns straight to the dispatcher's caller",
            "tail_jump_site": hx(SET_ARM_SITE),
            "target": hx(TRACED),
        },
        "clear_fallthrough": "0x5bba86e",
    }


# ---------------------------------------------------------------- census

def direct_transfer_census(data, secs, snapshot, ranges, target):
    """Every direct E8 (call) / E9 (jmp) in .text naming `target`.

    Raw byte hits are only candidates: each is validated against
    the disassembly of its containing FDE (the hit must be an
    instruction boundary whose operand target is `target`).
    Returns {"call": [sites], "jmp": [sites]} with hex strings.
    """
    text_sec = next(s for s in secs if s["name"] == ".text")
    blob = data[text_sec["offset"]:text_sec["offset"] + text_sec["size"]]
    base = text_sec["address"]
    raw = {"call": [], "jmp": []}
    for m in re.finditer(rb"[\xe8\xe9]", blob):
        i = m.start()
        if i + 5 > len(blob):
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        va = base + i
        if va + 5 + rel == target:
            raw["call" if blob[i] == 0xE8 else "jmp"].append(va)
    fde_of = {}
    for lo, hi in ranges:
        for va in raw["call"] + raw["jmp"]:
            if lo <= va < hi:
                fde_of[va] = (lo, hi)
    validated = {"call": [], "jmp": []}
    dis_cache = {}
    for kind in ("call", "jmp"):
        for va in raw[kind]:
            fde = fde_of.get(va)
            if fde is None:
                raise ValueError(
                    f"direct transfer candidate {va:#x} is in no FDE")
            if fde not in dis_cache:
                _t, dinsns = disassemble(snapshot, fde[0], fde[1])
                dis_cache[fde] = {i.va: i for i in dinsns}
            insn = dis_cache[fde].get(va)
            if insn is None or insn.mnemonic != kind:
                continue        # byte hit inside another instruction
            ops = split_operands(insn.operands)
            tgt = parse_operand(ops[0]) if ops else ("other", None)
            if tgt[0] == "addr" and tgt[1] == target:
                validated[kind].append(va)
    return {kind: [hx(v) for v in sorted(set(sites))]
            for kind, sites in validated.items()}


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

        # ---- verify all 14 tip target pins ----
        targets = []
        f2_los = set()
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
            if row["stream_family"] == "F2":
                f2_los.add(lo)
            targets.append({
                "range": row["range"],
                "stream_family": row["stream_family"],
                "sha256": digest,
                "normalised_sha256": norm,
                "selected_by_sequences": row["selected_by_sequences"],
            })
        if f2_los != {TRACED}:
            raise ValueError(f"F2 placements changed: {f2_los}")

        # ---- trace the sole F2 placement ----
        traced_row = next(t for t in tip["targets"]
                          if parse_range(t["range"])[0] == TRACED)
        tlo, thi = parse_range(traced_row["range"])
        targets_text, traced_insns = disassemble(snapshot, tlo, thi)
        trace = trace_f2_instance(data, secs, traced_insns, (tlo, thi))

        # ---- census direct transfers to the traced body and
        # ---- to its dispatcher ----
        census = direct_transfer_census(data, secs, snapshot,
                                        ranges, TRACED)
        if census != {"call": [], "jmp": [hx(SET_ARM_SITE)]}:
            raise ValueError(
                f"direct transfer census for F2 changed: {census}")
        dispatcher_census = direct_transfer_census(
            data, secs, snapshot, ranges, DISPATCHER[0])
        if dispatcher_census != {"call": [], "jmp": []}:
            raise ValueError(
                "dispatcher unexpectedly gained a direct transfer: "
                f"{dispatcher_census}")

        # ---- verify consumer pins; analyse the F2 sequence ----
        consumers_verified = 0
        sequence_out = None
        dispatcher_out = None
        dispatcher_text = None
        region_text_parts = []
        for crow in tip["consumers"]:
            clo, chi = parse_range(crow["range"])
            if (clo, chi) not in fde_set:
                raise ValueError(f"consumer {crow['range']} is not an FDE")
            digest = body_sha256(data, secs, clo, chi)
            if digest != crow["sha256"]:
                raise ValueError(f"consumer {crow['range']} hash mismatch")
            consumers_verified += 1
            selected = []
            for idx, seq in enumerate(crow["sequences"]):
                transfers = seq["set_arm"].get("transfers") or []
                if transfers and int(transfers[0]["target"], 16) in f2_los:
                    selected.append((idx, seq))
            if not selected:
                continue
            if (clo, chi) != DISPATCHER:
                raise ValueError(
                    f"F2 selected from unexpected body {crow['range']}")
            dispatcher_text, cinsns = disassemble(snapshot, clo, chi)
            dispatcher_out = dispatcher_analysis(cinsns)
            blocks, _edges = build_blocks(cinsns, (clo, chi))
            block_by_start = {b[0].va: b for b in blocks}
            for idx, seq in selected:
                if seq["set_arm"]["kind"] != "tailjmp":
                    raise ValueError("F2 set arm is not the tailjmp arm")
                clear = seq["clear_arm"]
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
                        f"clear region hash mismatch in {crow['range']}")
                cls = classify_clear_region(region_insns)
                if cls["verdict"] != "same-operation-sse2-form":
                    raise ValueError(
                        f"clear region is not the SSE2 form: {cls}")
                sequence_out = {
                    "consumer": crow["range"],
                    "sequence": idx,
                    "set_target": seq["set_arm"]["transfers"][0]["target"],
                    "set_kind": seq["set_arm"]["kind"],
                    "clear_kind": clear["kind"],
                    "clear": dict(cls, region_sha256=digest_r,
                                  blocks=clear["blocks"],
                                  bytes=len(blob)),
                }
                vas = {i.va for i in region_insns}
                lines = []
                keep = False
                for line in dispatcher_text.splitlines():
                    m = INSN_LINE.match(line)
                    if m:
                        keep = int(m.group(1), 16) in vas
                    if keep:
                        lines.append(line)
                region_text_parts.append(
                    f"# consumer {crow['range']} sequence {idx} "
                    f"set {sequence_out['set_target']} clear blocks "
                    f"{' '.join(clear['blocks'])}\n"
                    + "\n".join(lines) + "\n")
        if sequence_out is None or dispatcher_out is None:
            raise ValueError("the F2 sequence was not analysed")

        frames_rows = []
        for key in sorted({(tlo, thi), DISPATCHER}):
            if key in frame_lines:
                frames_rows.append(frame_lines[key])
        frames_text = "\n".join(frames_rows) + "\n"

    records = {
        "target_sha256": SHA256,
        "target_size": SIZE,
        "tip_packet": "RE-002-node115-bit9-arms (PR #2616); question "
                      "left by RE-002-node115-bit9-f3-trace (PR #2739)",
        "question": "trace the F2 tail-jump body at 0x5bba120 to "
                    "name the operation its set arm selects, pin "
                    "where the tail jump lands, check whether the "
                    "selecting body's clear region is the same "
                    "operation in another form, and census the "
                    "body's direct transfers",
        "targets_verified": targets,
        "consumers_verified": consumers_verified,
        "f2_stream": {
            "placements": [f"{hx(tlo)}..{hx(thi)}"],
            "normalised_sha256": traced_row["normalised_sha256"],
            "distinct_normalised_streams": 1,
            "selected_by_sequences": traced_row["selected_by_sequences"],
        },
        "trace": trace,
        "direct_transfers": {
            "validated_direct_calls": census["call"],
            "validated_direct_jumps": census["jmp"],
            "dispatcher_validated_direct_calls":
                dispatcher_census["call"],
            "dispatcher_validated_direct_jumps":
                dispatcher_census["jmp"],
            "note": "every E8/E9 byte hit in .text was validated "
                    "against its containing FDE's disassembly; the "
                    "sole direct transfer to the F2 body is the "
                    "dispatcher's tail jump at 0x5bbb02b, and no "
                    "direct transfer reaches the dispatcher body "
                    "itself (it is entered indirectly only -- the "
                    "census covers direct E8/E9 transfers only)",
        },
        "dispatcher": dispatcher_out,
        "operation": {
            "name": "ChaCha block function (SSSE3 form): four "
                    "blocks in parallel with feed-forward, the "
                    "state's 64-bit counter advanced by 4",
            "contract": "input rdi = a state record of which "
                        "bytes 0x00..0x30 are read (key rows at "
                        "+0x00/+0x10 and the counter/nonce row "
                        "at +0x20, whose first 64-bit word is "
                        "the counter); esi = round-loop "
                        "iterations (two double rounds each); "
                        "output rdx receives 256 bytes -- four "
                        "64-byte ChaCha blocks for counters "
                        "c, c+1, c+2, c+3, each the sum of its "
                        "worked state and its initial state -- "
                        "and the counter word at [rdi+0x20] is "
                        "stored back advanced by 4; no return "
                        "value",
            "evidence": [
                "the body's round constants are the ChaCha "
                "constants: the 16-byte ASCII string \"expand "
                "32-byte k\" at 0x4519c0 (the sigma row) and, "
                "for the zero-round path, its exact double at "
                "0x456c50 (per-word 2*sigma)",
                "the round loop is the ChaCha quarter-round "
                "network on 32-bit words: paddd/pxor with "
                "rotations 16 (pshuflw/pshufhw 0xb1 word "
                "swaps), 12 (psrld 0x14 / pslld 0xc), 8 "
                "(pshufb through the byte-rotation mask at "
                "0x4531c0) and 7 (psrld 0x19 / pslld 0x7), "
                "with pshufd 0x39/0x4e/0x93 lane rotations "
                "for the diagonal rounds and a second byte "
                "mask at 0x452ec0",
                "the entry builds four counter rows from the "
                "64-bit counter at [rdi+0x20] (+0/+1/+2/+3, "
                "carry into the high dword) -- four blocks "
                "are worked in lockstep, one counter step "
                "apart, in transposed (row-per-register) form",
                "the epilogue is the ChaCha feed-forward: "
                "worked rows are added to the entry-saved "
                "initial rows (the constant rows receive "
                "their sigma add just after the loop) and "
                "stored as 16 vector stores covering 256 "
                "bytes, and the counter row is stored back "
                "at [rdi+0x20] with the counter advanced "
                "by 4",
                "with esi == 0 the body still writes the "
                "full 256 bytes: initial + initial, the "
                "constant rows via the precomputed doubled "
                "sigma -- the esi parameter counts loop "
                "iterations, so the caller chooses the "
                "round count (each iteration is two double "
                "rounds)",
                "the set arm is the family's only tail-jump "
                "arm: the dispatcher unwinds its own frame "
                "and jumps, so the F2 body runs with the "
                "dispatcher's caller arguments and returns "
                "to that caller directly",
                "the dispatcher's clear region is the same "
                "ChaCha computation in SSE2 form (1,753 "
                "bytes, hash-verified against the #2616 "
                "pin): same sigma/doubled-sigma constants, "
                "same counter construction, same epilogue, "
                "and no pshufb anywhere -- the 8-rotation "
                "is done with psrld 0x18 / pslld 0x8 shift "
                "pairs, which is exactly the SSSE3 gap bit "
                "9 tests",
            ],
        },
        "sequences": [sequence_out],
        "summary": {
            "f2_sequences": 1,
            "f2_bodies": 1,
            "clear_verdicts": {"same-operation-sse2-form": 1},
            "clear_forms": {"loop": 1},
        },
        "captured_code_executed": False,
    }
    return records, frames_text, targets_text, \
        "\n".join(region_text_parts), dispatcher_text


def authenticate(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("input is not the pinned node #115 capture")


def generate(binary, output):
    data = Path(binary).read_bytes()
    authenticate(data)
    records, frames_text, targets_text, regions_text, \
        dispatcher_text = analyse(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "records.json").write_text(
        json.dumps(records, indent=2) + "\n", encoding="utf-8")
    (output / "frames.txt").write_text(frames_text, encoding="utf-8")
    (output / "targets.objdump.txt").write_text(
        targets_text, encoding="utf-8")
    (output / "clear_regions.objdump.txt").write_text(
        regions_text, encoding="utf-8")
    (output / "dispatcher.objdump.txt").write_text(
        dispatcher_text, encoding="utf-8")
    return records


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=TARGET)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "work/bit9-f2-trace-check")
    args = parser.parse_args(argv)
    records = generate(args.binary, args.output)
    summary = records["summary"]
    print(f"f2_sequences={summary['f2_sequences']} "
          f"bodies={summary['f2_bodies']} "
          f"verdicts={summary['clear_verdicts']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
