#!/usr/bin/env python3
"""Static trace of the RE-002 CPU-feature dispatcher's
0x400-exit body at 0x5bb9a60.

PR #2749 (the RE-002 bit-9 F2 trace packet) traced the
dispatcher's bit-9 set-arm body, 0x5bba120 -- the SSSE3 form
of the ChaCha block function: four blocks worked in parallel
in transposed form, with feed-forward, and the state record's
64-bit counter advanced by 4 -- and pinned the dispatcher's
other exits without tracing them.  PR #2754 (the 0x4000-exit
packet) then traced the 0x4000-exit body 0x5bbb030 as the AVX
(VEX-encoded, 128-bit) form of the same function, and the
sign-exit packet traced the sign-bit exit body 0x5bbb630 as
the AVX2 (256-bit ymm) form.  The sign-exit packet left as
its next question, verbatim: "trace the dispatcher's
0x400-exit body at 0x5bb9a60..0x5bba11a (1,722 bytes) -- the
last untraced feature exit -- and name its operation:
whether it is a fourth form of the same ChaCha block
function, and how its counter/output contract compares to
the SSSE3, AVX and AVX2 forms now pinned."

This producer answers that question:

* it authenticates the whole capture (size + SHA-256) before
  any analysis, then pins the traced body by its FDE range
  (0x5bb9a60..0x5bba11a, 1,722 bytes) and by its SHA-256,
  re-derived from the binary alone through the section
  table;
* it traces the body in full: the entry (sub rsp,0x28) loads
  the same record rows at rdi (three 16-byte rows at
  [rdi], [rdi+0x10], [rdi+0x20]) and builds the same four
  counter rows (+0/+1/+2/+3) from the 64-bit counter at
  [rdi+0x20] -- here with pinsrd pairs, the construction
  the AVX form uses (vpinsrd), legacy-encoded, where the
  SSSE3 form builds its rows with movd and shuffle/or
  merging.  A test esi,esi gate sends a zero round count
  to a path that loads the doubled sigma; the round loop
  (head 0x5bb9b40, dec esi / jne back edge) runs the same
  ChaCha quarter-round network, and its rotation census is
  identical to the F2/AVX loop census on every count
  (32 paddd, 32 pxor, 16 pshufb, rotations 16/12/8/7 at
  8 each, pshufd lane rotations 0x39/0x4e/0x93 at 8/8/4).
  A shared epilogue advances the counter by 4, stores the
  rebuilt counter/nonce row back at [rdi+0x20] and writes
  256 bytes (four feed-forward ChaCha blocks) to rdx in
  16 vector stores, with the four constant-row sigma adds
  just before the merge and the other twelve inside the
  epilogue -- exactly the F2/AVX arrangement and contract;
* it names the difference, which is the instruction-set
  floor, one step above the SSSE3 form's: this is a fourth
  form of the same ChaCha block function, legacy-encoded
  like the SSSE3 form (no VEX prefix, no ymm operand, no
  vzeroupper) but built with pinsrd (SSE4.1) counter
  construction on top of the SSSE3 pshufb rotations -- an
  SSE4.1 form.  Corollaries: 1,722 bytes / 324 instructions
  against the SSSE3 form's 1,758 / 340, the AVX form's
  1,530 / 301 and the AVX2 form's 868 / 173; a
  214-instruction loop against 217, 189 and 84; a 0x28-byte
  frame against 0x38 (SSSE3), 0x68 (AVX) and none (AVX2);
  the same four 16-byte constants with the same reference
  pattern as the SSSE3/AVX forms (sigma twice, rotate-by-8
  mask twice, swap mask once, doubled sigma once on the
  zero-round path) where the AVX2 form reads 32-byte
  two-lane constants and never references the doubled
  sigma.  Part of the transposed state is stack-resident
  through the loop (four working slots at
  [rsp-0x80]..[rsp-0x50] are loaded and stored inside the
  loop), a pattern this body shares with the SSSE3 and AVX
  forms -- only the AVX2 form keeps its state in registers;
* it re-pins the selecting dispatcher (0x5bba800..0x5bbb030):
  the cached feature word through slot 0x64dfa60, all four
  exits in test order, and the 0x400 exit block (0x5bbafeb:
  add rsp,0xa8, four pops, jmp), whose jump enters this
  body with the dispatcher's own caller arguments
  (rdi, esi, rdx), so the body's ret returns straight to
  that caller;
* it censuses every direct E8/E9 transfer in .text whose
  target is the traced body (each raw hit validated
  against the disassembly of its containing FDE): exactly
  one jump, the dispatcher's 0x400 exit jump at 0x5bbaff8,
  and no call.

The comparison bodies (F2, 0x5bba120..0x5bba7fe, the AVX
form, 0x5bbb030..0x5bbb62a, and the AVX2 form,
0x5bbb630..0x5bbb994) are themselves hash-pinned and
re-traced for the shared contract points (loop rotation
census, counter advance and write-back, output stores,
epilogue feed-forward adds, stack summary, counter
construction counts), so the same-contract verdict is
re-derived, not quoted.

No captured code is executed.  GNU tools receive a private
byte-identical snapshot whose path is replaced by
``<authenticated-node115>`` in retained text.
"""

import hashlib
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032

BODY = (0x5BB9A60, 0x5BBA11A)
BODY_SHA256 = "24663d382ee225bf024a091df6fcf0293aaa29a6059c320ef321561f4c4e46f0"
BODY_INSNS = 324
F2_BODY = (0x5BBA120, 0x5BBA7FE)
F2_SHA256 = "e787f6af5ff38fbe899147dac51fec44e1d6887fa0a5ef131bd0a528c38f0245"
F2_INSNS = 340
AVX_BODY = (0x5BBB030, 0x5BBB62A)
AVX_SHA256 = "c04bc82ee291c06eb8e65fe73d86dd880a11f4ff06aec15c62956a579b916892"
AVX_INSNS = 301
SIGN_BODY = (0x5BBB630, 0x5BBB994)
SIGN_SHA256 = "963fe9acf58718076c5a6fa97b4cfc297cd0b8d73719ac18d50b7242bf72a944"
SIGN_INSNS = 173
DISPATCHER = (0x5BBA800, 0x5BBB030)
EXIT_JUMP = 0x5BBAFF8
EXPECTED_FDE_COUNT = 135313

SIGMA_VA = 0x4519C0
DBL_SIGMA_VA = 0x456C50
ROT8_VA = 0x4531C0
SWAP_VA = 0x452EC0

SIGMA = b"expand 32-byte k"
DBL_SIGMA = b"".join(
    struct.pack("<I", 2 * struct.unpack_from("<I", SIGMA, i)[0])
    for i in range(0, 16, 4))
ROT8_MASK = bytes([3, 0, 1, 2, 7, 4, 5, 6,
                   11, 8, 9, 10, 15, 12, 13, 14])
SWAP_MASK = bytes([14, 15, 12, 13, 2, 3, 0, 1,
                   6, 7, 4, 5, 10, 11, 8, 9])
EXPECTED_CONSTANTS = {
    SIGMA_VA: SIGMA,
    DBL_SIGMA_VA: DBL_SIGMA,
    ROT8_VA: ROT8_MASK,
    SWAP_VA: SWAP_MASK,
}
CONSTANT_SIZES = {
    SIGMA_VA: 16,
    DBL_SIGMA_VA: 16,
    ROT8_VA: 16,
    SWAP_VA: 16,
}

GATE = 0x5BB9AC5
GATE_JE = 0x5BB9ADA
LOOP_HEAD = 0x5BB9B40
LOOP_DEC = 0x5BB9F9E
LOOP_BACK = 0x5BB9FA0
SIGMA_ADD_LOAD = 0x5BB9FA6
ZERO_PATH = 0x5BB9FE5
POST_LOOP_JMP = 0x5BB9FE3
MERGE = 0x5BBA03B
WRITEBACK = 0x5BBA059
FRAME_RESTORE = 0x5BBA115


def hx(value):
    return f"0x{value:x}"


def shx(value):
    """Signed hex for stack displacements (-0x80, 0x0, 0x10)."""
    return f"-0x{-value:x}" if value < 0 else f"0x{value:x}"


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
    m = re.match(r"^(?:(BYTE|WORD|DWORD|QWORD|XMMWORD|YMMWORD) PTR )?\[([^]]*)\]$",
                 operand)
    if not m:
        return None
    size = {"BYTE": 8, "WORD": 16, "DWORD": 32, "QWORD": 64,
            "XMMWORD": 128, "YMMWORD": 256, None: 64}[m.group(1)]
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


def base_mnemonic(mnemonic):
    """Strip the VEX 'v' prefix so the AVX and legacy-SSE forms
    of one vector instruction share a census name."""
    if mnemonic.startswith("v") and mnemonic not in ("vzeroupper",):
        return mnemonic[1:]
    return mnemonic


def body_sha256(data, secs, lo, hi):
    off = va_to_offset(secs, lo, hi - lo)
    return hashlib.sha256(data[off:off + (hi - lo)]).hexdigest()


def branch_target(insn):
    ops = split_operands(insn.operands) if insn.operands else []
    if not ops:
        return None
    parsed = parse_operand(ops[0])
    return parsed[1] if parsed[0] == "addr" else None


def rip_refs(data, secs, insns):
    refs = {}
    for insn in insns:
        if "rip" in insn.operands:
            target = insn.comment_target()
            if target is None:
                raise ValueError(
                    f"unresolved rip reference at {insn.va:#x}")
            if target not in refs:
                size = CONSTANT_SIZES.get(target, 16)
                off = va_to_offset(secs, target, size)
                blob = data[off:off + size]
                refs[target] = {
                    "address": hx(target),
                    "bytes": blob.hex(),
                    "ascii": "".join(
                        chr(b) if 32 <= b < 127 else "." for b in blob),
                    "referenced_from": [],
                }
            refs[target]["referenced_from"].append(hx(insn.va))
    return refs


# ---------------------------------------------------------------- trace


def loop_census(insns, head, back):
    loop = [i for i in insns if head <= i.va <= back]

    def count(name, imm=None):
        n = 0
        for i in loop:
            if base_mnemonic(i.mnemonic) != name:
                continue
            if imm is not None:
                ops = split_operands(i.operands)
                if not ops \
                        or parse_operand(ops[-1]) != ("imm", imm):
                    continue
            n += 1
        return n

    pshufd_imms = {}
    for i in loop:
        if base_mnemonic(i.mnemonic) == "pshufd":
            imm = parse_operand(split_operands(i.operands)[-1])[1]
            pshufd_imms[hx(imm)] = pshufd_imms.get(hx(imm), 0) + 1
    return loop, {
        "paddd": count("paddd"),
        "pxor": count("pxor"),
        "pshufb": count("pshufb"),
        "rot16_pshuflw_0xb1": count("pshuflw", 0xB1),
        "rot16_pshufhw_0xb1": count("pshufhw", 0xB1),
        "rot12_psrld_0x14": count("psrld", 0x14),
        "rot12_pslld_0xc": count("pslld", 0xC),
        "rot7_psrld_0x19": count("psrld", 0x19),
        "rot7_pslld_0x7": count("pslld", 0x7),
        "pshufd_lane_rotations": pshufd_imms,
    }


EXPECTED_LOOP_CENSUS = {
    "paddd": 32,
    "pxor": 32,
    "pshufb": 16,
    "rot16_pshuflw_0xb1": 8,
    "rot16_pshufhw_0xb1": 8,
    "rot12_psrld_0x14": 8,
    "rot12_pslld_0xc": 8,
    "rot7_psrld_0x19": 8,
    "rot7_pslld_0x7": 8,
    "pshufd_lane_rotations": {"0x39": 8, "0x4e": 8, "0x93": 4},
}


SIGN_LOOP_CENSUS = {
    "paddd": 16,
    "pxor": 16,
    "pshufb": 8,
    "rot16_pshuflw_0xb1": 4,
    "rot16_pshufhw_0xb1": 4,
    "rot12_psrld_0x14": 4,
    "rot12_pslld_0xc": 4,
    "rot7_psrld_0x19": 4,
    "rot7_pslld_0x7": 4,
    "pshufd_lane_rotations": {"0x39": 4, "0x4e": 4, "0x93": 2},
}


def epilogue_contract(insns, merge):
    """The shared contract points of a ChaCha-form epilogue:
    counter advance add, the [rdi+0x20] write-back, the output
    stores to rdx and the feed-forward add count."""
    epi = [i for i in insns if i.va >= merge]
    if not epi or epi[0].mnemonic != "add" \
            or epi[0].operands != "rax,0x4":
        raise ValueError(f"epilogue at {merge:#x} does not advance "
                         "the counter by 4")
    writeback = []
    out_stores = []
    for i in epi:
        ops = split_operands(i.operands) if i.operands else []
        if not ops:
            continue
        dst = parse_operand(ops[0])
        if dst[0] != "mem":
            continue
        if base_mnemonic(i.mnemonic) == "movdqa" \
                and dst[1]["base"] == "rdi" and dst[1]["disp"] == 0x20:
            writeback.append(hx(i.va))
        if base_mnemonic(i.mnemonic) in ("movdqu", "movups") \
                and dst[1]["base"] == "rdx":
            out_stores.append(dst[1]["disp"])
    if len(writeback) != 1:
        raise ValueError(f"epilogue write-back changed: {writeback}")
    if out_stores != list(range(0, 0x100, 0x10)):
        raise ValueError(f"epilogue output stores changed: {out_stores}")
    return {
        "merge": hx(merge),
        "counter_advance": "rax += 4 at " + hx(epi[0].va),
        "counter_writeback_site": writeback[0],
        "output_stores": [hx(d) for d in out_stores],
        "output_bytes": 256,
        "feed_forward_adds": sum(
            1 for i in epi if base_mnemonic(i.mnemonic) == "paddd"),
    }


def stack_summary(insns, head, back):
    """Uniform stack metric for every form: the rsp adjustment
    (frame size, or None when the body never adjusts rsp), the
    set of rsp-relative slots touched, and how many accesses
    fall inside the round loop.  An access is a store when the
    rsp-relative operand is the destination (operand 0) and a
    load otherwise."""
    frame = None
    for i in insns:
        if i.mnemonic == "sub" and i.operands.startswith("rsp,"):
            frame = parse_operand(split_operands(i.operands)[1])[1]
            break
    slots = {}
    for i in insns:
        ops = split_operands(i.operands) if i.operands else []
        for pos, operand in enumerate(ops):
            parsed = parse_operand(operand)
            if parsed[0] == "mem" and parsed[1]["base"] == "rsp":
                entry = slots.setdefault(
                    parsed[1]["disp"],
                    {"stores": 0, "loads": 0, "in_loop": 0})
                entry["stores" if pos == 0 else "loads"] += 1
                if head <= i.va <= back:
                    entry["in_loop"] += 1
    return {
        "frame_bytes": frame,
        "slots": {shx(d): slots[d] for d in sorted(slots)},
        "accesses": sum(v["stores"] + v["loads"] for v in slots.values()),
        "in_loop_accesses": sum(v["in_loop"] for v in slots.values()),
        "working_slots_in_loop": [
            shx(d) for d in sorted(slots) if slots[d]["in_loop"] > 0],
    }


def trace_body(data, secs, insns):
    lo, hi = BODY
    by_va = {i.va: i for i in insns}
    if insns[-1].mnemonic != "ret":
        raise ValueError("traced body does not end in ret")
    if any(i.mnemonic == "call" for i in insns):
        raise ValueError("traced body unexpectedly contains a call")

    # Frame: exactly one sub rsp,0x28 at the entry and one
    # add rsp,0x28 before the ret; nothing else adjusts rsp.
    adj = [(hx(i.va), i.mnemonic, i.operands) for i in insns
           if i.mnemonic in ("sub", "add")
           and i.operands.startswith("rsp")]
    if adj != [(hx(BODY[0]), "sub", "rsp,0x28"),
               (hx(FRAME_RESTORE), "add", "rsp,0x28")]:
        raise ValueError(f"traced body frame changed: {adj}")

    # Width: legacy encoding throughout -- no VEX-prefixed
    # mnemonic, no ymm operand, no vzeroupper.
    ymm_insns = [hx(i.va) for i in insns if "ymm" in i.text]
    if ymm_insns:
        raise ValueError(f"traced body gained ymm operands: {ymm_insns}")
    vex = sum(1 for i in insns if i.mnemonic.startswith("v"))
    if vex:
        raise ValueError(f"traced body gained VEX forms: {vex}")
    if any(i.mnemonic == "vzeroupper" for i in insns):
        raise ValueError("traced body gained a vzeroupper")

    branches = []
    for insn in insns:
        if insn.mnemonic.startswith("j"):
            branches.append({
                "site": hx(insn.va), "kind": insn.mnemonic,
                "target": hx(branch_target(insn))})
    expected_branches = [
        {"site": hx(GATE_JE), "kind": "je", "target": hx(ZERO_PATH)},
        {"site": hx(LOOP_BACK), "kind": "jne", "target": hx(LOOP_HEAD)},
        {"site": hx(POST_LOOP_JMP), "kind": "jmp", "target": hx(MERGE)},
    ]
    if branches != expected_branches:
        raise ValueError(f"traced body branches changed: {branches}")

    # Entry, up to the round-count gate: three 16-byte record
    # rows loaded with movdqa, the counter word into rax, three
    # lea variants (+1/+2/+3) and six pinsrd that build the
    # variant counter rows out of the loaded counter/nonce row.
    row_loads = []
    counter_load = []
    for insn in insns:
        if insn.va >= GATE:
            break
        ops = split_operands(insn.operands)
        if len(ops) != 2:
            continue
        src = parse_operand(ops[1])
        if src[0] != "mem" or src[1]["base"] != "rdi":
            continue
        if insn.mnemonic == "movdqa":
            row_loads.append((hx(insn.va), src[1]["disp"]))
        if insn.mnemonic == "mov" and src[1]["disp"] == 0x20:
            counter_load.append(hx(insn.va))
    if row_loads != [(hx(0x5BB9A64), 0), (hx(0x5BB9A68), 0x10),
                     (hx(0x5BB9A6E), 0x20)]:
        raise ValueError(f"traced body record loads changed: {row_loads}")
    if counter_load != [hx(0x5BB9A73)]:
        raise ValueError(f"traced body counter load changed: {counter_load}")
    counter_leas = [hx(i.va) for i in insns
                    if i.mnemonic == "lea" and i.va < GATE
                    and any(f"[rax+0x{k}]" in i.operands
                            for k in (1, 2, 3))]
    if counter_leas != [hx(0x5BB9A77), hx(0x5BB9A8F), hx(0x5BB9AAA)]:
        raise ValueError(
            f"counter variant construction changed: {counter_leas}")
    entry_pinsrd = [hx(i.va) for i in insns
                    if base_mnemonic(i.mnemonic) == "pinsrd"
                    and i.va < GATE]
    if entry_pinsrd != [hx(0x5BB9A7F), hx(0x5BB9A89), hx(0x5BB9A98),
                        hx(0x5BB9AA3), hx(0x5BB9AB3), hx(0x5BB9ABE)]:
        raise ValueError(
            f"counter pinsrd construction changed: {entry_pinsrd}")
    if any(base_mnemonic(i.mnemonic) == "movd" and i.va < GATE
           for i in insns):
        raise ValueError("traced body entry gained a movd construction")

    gate = by_va.get(GATE)
    if gate is None or gate.mnemonic != "test" \
            or gate.operands != "esi,esi":
        raise ValueError("round-count gate changed")

    # Constants: the same four 16-byte constants as the SSSE3
    # and AVX forms, with the same reference pattern (sigma
    # twice, rotate-by-8 mask twice, swap mask once, doubled
    # sigma once).
    refs = rip_refs(data, secs, insns)
    if set(refs) != set(EXPECTED_CONSTANTS):
        raise ValueError(f"traced body constants changed: {sorted(refs)}")
    for va, expected in EXPECTED_CONSTANTS.items():
        if bytes.fromhex(refs[va]["bytes"]) != expected:
            raise ValueError(f"constant at {va:#x} changed")
    expected_refs = {
        SIGMA_VA: [hx(0x5BB9AE0), hx(SIGMA_ADD_LOAD)],
        ROT8_VA: [hx(0x5BB9C5D), hx(0x5BB9EA0)],
        SWAP_VA: [hx(0x5BB9DB4)],
        DBL_SIGMA_VA: [hx(ZERO_PATH)],
    }
    for va, sites in expected_refs.items():
        if refs[va]["referenced_from"] != sites:
            raise ValueError(
                f"constant {va:#x} reference sites changed: "
                f"{refs[va]['referenced_from']}")

    loop_insns, census = loop_census(insns, LOOP_HEAD, LOOP_BACK)
    if census != EXPECTED_LOOP_CENSUS:
        raise ValueError(f"round-loop census changed: {census}")
    dec = by_va.get(LOOP_DEC)
    if dec is None or dec.mnemonic != "dec" or dec.operands != "esi":
        raise ValueError("loop counter decrement changed")

    # pshufb occurs only inside the loop (the rotate-by-8
    # step); every one of the 16 is a loop instruction.
    pshufb_sites = [hx(i.va) for i in insns
                    if base_mnemonic(i.mnemonic) == "pshufb"]
    if len(pshufb_sites) != census["pshufb"] or any(
            not (LOOP_HEAD <= i.va <= LOOP_BACK)
            for i in insns if base_mnemonic(i.mnemonic) == "pshufb"):
        raise ValueError(f"pshufb placement changed: {pshufb_sites}")

    zero_first = by_va.get(ZERO_PATH)
    if zero_first is None or zero_first.mnemonic != "movdqa" \
            or zero_first.comment_target() != DBL_SIGMA_VA:
        raise ValueError("zero-round doubled-sigma load changed")

    # The four constant-row sigma adds sit between the back
    # edge and the merge, fed by the sigma load at
    # SIGMA_ADD_LOAD.
    pre_merge = [hx(i.va) for i in insns
                 if LOOP_BACK < i.va < MERGE
                 and base_mnemonic(i.mnemonic) == "paddd"]
    if pre_merge != [hx(0x5BB9FAF), hx(0x5BB9FB4),
                     hx(0x5BB9FB9), hx(0x5BB9FC4)]:
        raise ValueError(f"pre-merge sigma adds changed: {pre_merge}")

    epilogue = epilogue_contract(insns, MERGE)
    if epilogue["counter_writeback_site"] != hx(WRITEBACK) \
            or epilogue["feed_forward_adds"] != 12:
        raise ValueError(f"epilogue contract changed: {epilogue}")

    stack = stack_summary(insns, LOOP_HEAD, LOOP_BACK)
    if stack["frame_bytes"] != 0x28 \
            or stack["accesses"] != 45 \
            or stack["in_loop_accesses"] != 22 \
            or stack["working_slots_in_loop"] != [
                shx(-0x80), shx(-0x70), shx(-0x60), shx(-0x50)]:
        raise ValueError(f"traced body stack shape changed: {stack}")
    for disp in (-0x40, -0x30, -0x20, -0x10, 0x0, 0x10):
        slot = stack["slots"].get(shx(disp))
        if slot != {"stores": 1, "loads": 1, "in_loop": 0}:
            raise ValueError(
                f"initial-row slot {disp:#x} shape changed: {slot}")

    return {
        "body": f"{hx(lo)}..{hx(hi)}",
        "bytes": hi - lo,
        "insns": len(insns),
        "sha256": BODY_SHA256,
        "calls": 0,
        "entry": [i.text for i in insns[:8]],
        "frame": "sub rsp,0x28 at the entry (0x5bb9a60), "
                 "restored by add rsp,0x28 just before the ret "
                 "(0x5bba115); ten rsp-relative slots are "
                 "touched, [rsp-0x80]..[rsp+0x10] (the SSSE3 "
                 "form's frame is 0x38 bytes, the AVX form's "
                 "0x68, the AVX2 form has no frame at all)",
        "branches": branches,
        "input": {
            "record_pointer": "rdi",
            "record_row_loads": [
                {"site": s, "disp": d} for s, d in row_loads],
            "bytes_read": "0x00..0x30 of the record (three "
                          "16-byte rows at +0x00/+0x10/+0x20); "
                          "bytes 0x30.. of the record are "
                          "never read",
            "counter_load": counter_load[0],
            "counter": "the 64-bit word at [rdi+0x20]; variants "
                       "+0/+1/+2/+3 built at "
                       + ", ".join(counter_leas)
                       + " -- each variant row is the loaded "
                         "counter/nonce row with its first two "
                         "dwords replaced by the variant counter "
                         "(pinsrd $0 with the lea result's low "
                         "dword, pinsrd $1 with its shr 0x20 "
                         "high dword), one row per block; this "
                         "is the construction the AVX form uses "
                         "(vpinsrd), legacy-encoded, where the "
                         "SSSE3 form builds its rows with movd "
                         "and shuffle/or merging (its body "
                         "contains no pinsrd at all)",
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
            "rotations": census,
            "note": "the census equals the F2 (SSSE3) and AVX "
                    "loop censuses on every count; the AVX2 "
                    "form's loop census is exactly half of it "
                    "at twice the width",
        },
        "zero_round_path": {
            "entry": hx(ZERO_PATH),
            "doubled_sigma_load": hx(zero_first.va),
            "note": "with esi == 0 no round runs: the constant "
                    "rows are loaded with the doubled sigma at "
                    "0x456c50 (each sigma dword doubled), as in "
                    "the SSSE3 and AVX forms, so the shared "
                    "epilogue's adds produce exactly initial "
                    "+ initial",
        },
        "pre_merge_sigma_adds": pre_merge,
        "epilogue": epilogue,
        "stack": stack,
        "encoding": {
            "vex_prefixed_insns": vex,
            "ymm_insns": len(ymm_insns),
            "vector_width_bits": 128,
            "vzeroupper_site": None,
            "pshufb_insns": len(pshufb_sites),
            "pinsrd_insns": sum(
                1 for i in insns
                if base_mnemonic(i.mnemonic) == "pinsrd"),
            "note": "every instruction is legacy-encoded (no "
                    "VEX prefix anywhere, no ymm operand, no "
                    "vzeroupper), as in the SSSE3 form; what "
                    "separates this form from it is the "
                    "instruction floor: pshufb (SSSE3) for the "
                    "rotate-by-8 step and pinsrd (SSE4.1) for "
                    "the counter construction -- one feature "
                    "step above the SSSE3 form's floor, and "
                    "the dispatcher tests 0x400 after 0x4000 "
                    "and before bit 9",
        },
    }



def trace_form_contract(data, secs, insns, body, sha256, insns_n,
                        loop_head, loop_back, merge, writeback,
                        ff_adds, expected_census):
    """Re-derive a comparison form's shared contract points so
    the comparison is computed, not quoted."""
    digest = body_sha256(data, secs, body[0], body[1])
    if digest != sha256:
        raise ValueError(f"comparison body {body[0]:#x} hash mismatch")
    if len(insns) != insns_n:
        raise ValueError(
            f"comparison body {body[0]:#x} insn count changed")
    _loop, census = loop_census(insns, loop_head, loop_back)
    if census != expected_census:
        raise ValueError(f"comparison loop census changed: {census}")
    epilogue = epilogue_contract(insns, merge)
    if epilogue["counter_writeback_site"] != hx(writeback) \
            or epilogue["feed_forward_adds"] != ff_adds:
        raise ValueError(f"comparison epilogue changed: {epilogue}")
    return {
        "body": f"{hx(body[0])}..{hx(body[1])}",
        "bytes": body[1] - body[0],
        "insns": len(insns),
        "sha256": digest,
        "round_loop": {"head": hx(loop_head),
                       "back_edge": hx(loop_back),
                       "insns": sum(1 for i in insns
                                    if loop_head <= i.va <= loop_back),
                       "rotations": census},
        "epilogue": epilogue,
        "vex_prefixed_insns": sum(
            1 for i in insns if i.mnemonic.startswith("v")),
        "ymm_operands": sum(1 for i in insns if "ymm" in i.text),
        "pinsrd_insns": sum(
            1 for i in insns if base_mnemonic(i.mnemonic) == "pinsrd"),
        "movd_insns": sum(
            1 for i in insns if base_mnemonic(i.mnemonic) == "movd"),
        "stack": stack_summary(insns, loop_head, loop_back),
    }


# ---------------------------------------------------------- dispatcher


def dispatcher_analysis(insns):
    by_va = {i.va: i for i in insns}
    slot_load = by_va.get(0x5BBA80D)
    if slot_load is None or slot_load.comment_target() != 0x64DFA60:
        raise ValueError("dispatcher feature-slot load changed")

    def test_sites(imm):
        return [hx(i.va) for i in insns if i.mnemonic == "test"
                and split_operands(i.operands)
                and parse_operand(split_operands(i.operands)[1])
                == ("imm", imm)]

    sites_4000 = test_sites(0x4000)
    if sites_4000 != [hx(0x5BBA835), hx(0x5BBAFAD)]:
        raise ValueError(f"dispatcher 0x4000 tests changed: {sites_4000}")
    sites_400 = test_sites(0x400)
    if sites_400 != [hx(0x5BBA84C), hx(0x5BBAFE0)]:
        raise ValueError(f"dispatcher 0x400 tests changed: {sites_400}")
    sites_200 = test_sites(0x200)
    if sites_200 != [hx(0x5BBA863), hx(0x5BBB013)]:
        raise ValueError(f"dispatcher bit-9 tests changed: {sites_200}")
    exits = []
    for i in insns:
        if i.mnemonic == "jmp":
            target = branch_target(i)
            if target is not None \
                    and DISPATCHER[0] <= target < DISPATCHER[1]:
                continue
            exits.append({"site": hx(i.va), "target": hx(target)})
    expected_exits = [
        {"site": hx(0x5BBAF92), "target": hx(SIGN_BODY[0])},
        {"site": hx(0x5BBAFC5), "target": hx(AVX_BODY[0])},
        {"site": hx(EXIT_JUMP), "target": hx(BODY[0])},
        {"site": hx(0x5BBB02B), "target": hx(F2_BODY[0])},
    ]
    if exits != expected_exits:
        raise ValueError(f"dispatcher exits changed: {exits}")
    block = [by_va[va] for va in
             (0x5BBAFEB, 0x5BBAFF2, 0x5BBAFF3, 0x5BBAFF5,
              0x5BBAFF7, EXIT_JUMP)]
    if [i.mnemonic for i in block] != \
            ["add", "pop", "pop", "pop", "pop", "jmp"]:
        raise ValueError("0x400 exit block changed")
    return {
        "body": f"{hx(DISPATCHER[0])}..{hx(DISPATCHER[1])}",
        "feature_slot": "0x64dfa60",
        "feature_slot_load": hx(slot_load.va),
        "bit_tests": {
            "0x4000": sites_4000,
            "0x400": sites_400,
            "0x200_bit9": sites_200,
        },
        "exits": exits,
        "exit_400": {
            "block": hx(0x5BBAFEB),
            "shape": "add rsp,0xa8; pop rbx; pop r14; pop r15; "
                     "pop rbp; jmp -- the dispatcher's frame is "
                     "fully unwound before the jump, so the "
                     "0x400-exit body is entered with the "
                     "caller's own arguments (rdi, esi, rdx) "
                     "and its ret returns straight to the "
                     "dispatcher's caller",
            "jump_site": hx(EXIT_JUMP),
            "target": hx(BODY[0]),
        },
    }


# ---------------------------------------------------------------- census


def direct_transfer_census(data, secs, snapshot, ranges, target):
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
                continue
            ops = split_operands(insn.operands)
            tgt = parse_operand(ops[0]) if ops else ("other", None)
            if tgt[0] == "addr" and tgt[1] == target:
                validated[kind].append(va)
    return {kind: [hx(v) for v in sorted(set(sites))]
            for kind, sites in validated.items()}


# ---------------------------------------------------------------- analysis


def analyse(data):
    secs = sections(data)
    if body_sha256(data, secs, BODY[0], BODY[1]) != BODY_SHA256:
        raise ValueError("traced body hash mismatch")

    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / "hl-node"
        snapshot.write_bytes(data)
        ranges, frame_lines = readelf_frames(snapshot)
        if len(ranges) != EXPECTED_FDE_COUNT:
            raise ValueError(
                f"FDE count changed: {len(ranges)} != {EXPECTED_FDE_COUNT}")
        fde_set = set(ranges)
        for fde in (BODY, F2_BODY, AVX_BODY, SIGN_BODY, DISPATCHER):
            if fde not in fde_set:
                raise ValueError(f"{fde} is not an FDE range")

        targets_text, insns = disassemble(snapshot, BODY[0], BODY[1])
        if len(insns) != BODY_INSNS:
            raise ValueError("traced body insn count changed")
        trace = trace_body(data, secs, insns)

        _f2_text, f2_insns = disassemble(snapshot, F2_BODY[0], F2_BODY[1])
        f2 = trace_form_contract(
            data, secs, f2_insns, F2_BODY, F2_SHA256, F2_INSNS,
            0x5BBA230, 0x5BBA693, 0x5BBA6FD, 0x5BBA72F, 12,
            EXPECTED_LOOP_CENSUS)

        _avx_text, avx_insns = disassemble(
            snapshot, AVX_BODY[0], AVX_BODY[1])
        avx = trace_form_contract(
            data, secs, avx_insns, AVX_BODY, AVX_SHA256, AVX_INSNS,
            0x5BBB100, 0x5BBB4AD, 0x5BBB55B, 0x5BBB572, 12,
            EXPECTED_LOOP_CENSUS)

        _sign_text, sign_insns = disassemble(
            snapshot, SIGN_BODY[0], SIGN_BODY[1])
        sign = trace_form_contract(
            data, secs, sign_insns, SIGN_BODY, SIGN_SHA256, SIGN_INSNS,
            0x5BBB6D0, 0x5BBB85F, 0x5BBB892, 0x5BBB8A9, 16,
            SIGN_LOOP_CENSUS)

        dispatcher_text, dinsns = disassemble(
            snapshot, DISPATCHER[0], DISPATCHER[1])
        dispatcher = dispatcher_analysis(dinsns)

        census = direct_transfer_census(data, secs, snapshot,
                                        ranges, BODY[0])
        if census != {"call": [], "jmp": [hx(EXIT_JUMP)]}:
            raise ValueError(
                f"direct transfer census changed: {census}")

        frames_rows = []
        for key in sorted({BODY, F2_BODY, AVX_BODY, SIGN_BODY,
                           DISPATCHER}):
            if key in frame_lines:
                frames_rows.append(frame_lines[key])
        frames_text = "\n".join(frames_rows) + "\n"

    records = {
        "target_sha256": SHA256,
        "target_size": SIZE,
        "tip_packet": "RE-002-node115-dispatcher-sign-exit",
        "question": "trace the dispatcher 0x5bba800's 0x400-exit "
                    "body at 0x5bb9a60..0x5bba11a and name its "
                    "operation: whether it is a fourth form of "
                    "the same ChaCha block function, and how its "
                    "counter/output contract compares to the "
                    "SSSE3 (F2), AVX (0x4000-exit) and AVX2 "
                    "(sign-exit) forms",
        "trace": trace,
        "comparison_f2": f2,
        "comparison_avx": avx,
        "comparison_sign": sign,
        "comparison": {
            "verdict": "same-operation-sse41-form",
            "same": [
                "input: bytes 0x00..0x30 of the record at rdi "
                "(three 16-byte rows at +0x00/+0x10 and the "
                "counter/nonce row at +0x20); the counter is "
                "the 64-bit word at [rdi+0x20], with "
                "+0/+1/+2/+3 variant rows, one per block",
                "round-count contract: esi counts round-loop "
                "iterations, each running two double rounds; "
                "esi == 0 takes a zero-round path and the "
                "output is exactly initial + initial",
                "round loop: the ChaCha quarter-round network "
                "-- the rotation census equals the F2/AVX "
                "census on every count (32 paddd, 32 pxor, "
                "16 pshufb, rotations 16/12/8/7 at 8 each, "
                "pshufd lane rotations 0x39/0x4e/0x93 at "
                "8/8/4); the AVX2 form's census is exactly "
                "half of it at twice the width",
                "feed-forward: worked rows are added to the "
                "initial rows -- the four constant-row sigma "
                "adds just before the merge and twelve in the "
                "shared epilogue, the F2/AVX arrangement (the "
                "AVX2 form keeps all sixteen in its epilogue) "
                "-- and stored as 16 vector stores covering "
                "256 bytes at rdx (four 64-byte blocks)",
                "counter/output contract: the counter word at "
                "[rdi+0x20] is stored back advanced by 4, and "
                "256 bytes -- four 64-byte ChaCha blocks for "
                "counters c, c+1, c+2, c+3 -- are stored to "
                "rdx; no return value",
                "constants: the same four 16-byte constants "
                "with the same reference pattern as the "
                "SSSE3/AVX forms -- sigma at 0x4519c0 twice, "
                "rotate-by-8 mask at 0x4531c0 twice, swap mask "
                "at 0x452ec0 once, doubled sigma at 0x456c50 "
                "once (the zero-round path)",
                "structure: no calls, exactly three branches, "
                "all internal, and a single ret",
            ],
            "different": [
                "instruction floor: this form is legacy-encoded "
                "like the SSSE3 form (no VEX prefix, no ymm "
                "operand, no vzeroupper) but its counter "
                "construction uses pinsrd (SSE4.1) -- measured "
                "pinsrd-family counts across the four bodies: "
                "SSSE3 form 0 (it builds its rows with movd "
                "and shuffle/or merging), this form 8 pinsrd, "
                "AVX form 8 vpinsrd, AVX2 form 8 vpinsrd -- so "
                "the form's floor is SSSE3 (pshufb) plus "
                "SSE4.1 (pinsrd), one feature step above the "
                "SSSE3 form's; the dispatcher tests 0x400 "
                "after 0x4000 and before bit 9",
                "size: 1,722 bytes / 324 instructions against "
                "the SSSE3 form's 1,758 bytes / 340, the AVX "
                "form's 1,530 / 301 and the AVX2 form's "
                "868 / 173; the round loop is 214 instructions "
                "against 217, 189 and 84",
                "frame and stack: a 0x28-byte frame against "
                "0x38 (SSSE3), 0x68 (AVX) and none (AVX2); ten "
                "rsp-relative slots ([rsp-0x80]..[rsp+0x10]) "
                "of which the four lowest are working slots "
                "loaded and stored inside the loop (22 of the "
                "body's 45 stack accesses fall in the loop) "
                "-- the SSSE3 form (11 slots, 24 in-loop "
                "accesses) and the AVX form (14 slots, 34) "
                "share this stack-resident pattern, and only "
                "the AVX2 form keeps its state in registers "
                "(a single red-zone slot, no in-loop access)",
                "zero-round path: loads the doubled sigma at "
                "0x456c50, as in the SSSE3 and AVX forms; the "
                "AVX2 form instead loads its two-lane sigma "
                "constant and never references the doubled "
                "sigma",
            ],
        },
        "dispatcher": dispatcher,
        "direct_transfers": {
            "validated_direct_calls": census["call"],
            "validated_direct_jumps": census["jmp"],
            "note": "every E8/E9 byte hit in .text was validated "
                    "against its containing FDE's disassembly; "
                    "the sole direct transfer to the traced body "
                    "is the dispatcher's 0x400 exit jump at "
                    "0x5bbaff8, and there is no call",
        },
        "operation": {
            "name": "ChaCha block function (SSE4.1 / "
                    "legacy-encoded form): four blocks in "
                    "parallel with feed-forward, the state's "
                    "64-bit counter advanced by 4",
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
                        "value.  The contract is identical to "
                        "the SSSE3 form at 0x5bba120, the AVX "
                        "form at 0x5bbb030 and the AVX2 form at "
                        "0x5bbb630 in every observable respect",
            "evidence": [
                "the body's round constants are the ChaCha "
                "constants, the same four 16-byte constants "
                "the SSSE3/AVX forms read: the ASCII string "
                "\"expand 32-byte k\" (the sigma row) at "
                "0x4519c0, its exact per-word double at "
                "0x456c50, the rotate-by-8 pshufb mask at "
                "0x4531c0 and the swap mask at 0x452ec0",
                "the round loop is the ChaCha quarter-round "
                "network on 32-bit words: paddd/pxor with "
                "rotations 16 (pshuflw/pshufhw 0xb1 word "
                "swaps), 12 (psrld 0x14 / pslld 0xc), 8 "
                "(pshufb through the byte-rotation mask at "
                "0x4531c0) and 7 (psrld 0x19 / pslld 0x7), "
                "with pshufd 0x39/0x4e/0x93 lane rotations "
                "for the diagonal rounds -- its census "
                "equals the SSSE3/AVX census on every count",
                "the entry builds four counter rows from the "
                "64-bit counter at [rdi+0x20] (+0/+1/+2/+3) "
                "with lea/pinsrd groups -- four blocks worked "
                "in lockstep, one counter step apart",
                "the epilogue is the ChaCha feed-forward: "
                "worked rows are added to the initial rows "
                "(four sigma adds before the merge, twelve "
                "in the epilogue) and stored as 16 vector "
                "stores covering 256 bytes, and the counter "
                "row is stored back at [rdi+0x20] with the "
                "counter advanced by 4",
                "the reduced/other-operation hypotheses fail "
                "on the census: the loop performs the full "
                "quarter-round network at the full 128-bit "
                "width with the family's exact rotation "
                "counts -- only the encoding and the "
                "counter construction differ from the SSSE3 "
                "form, and only the encoding differs from "
                "the AVX form's construction",
            ],
        },
        "summary": {
            "bodies_traced": 1,
            "comparison_bodies_retraced": 3,
            "verdict": "same-operation-sse41-form",
            "fourth_form": True,
            "wider_vector": False,
            "reduced_form": False,
            "direct_calls": 0,
            "direct_jumps": 1,
        },
        "captured_code_executed": False,
    }
    return records, frames_text, targets_text, dispatcher_text


def authenticate(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("input is not the pinned node #115 capture")


def generate(binary, output):
    data = Path(binary).read_bytes()
    authenticate(data)
    records, frames_text, targets_text, dispatcher_text = analyse(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "records.json").write_text(
        json.dumps(records, indent=2) + "\n", encoding="utf-8")
    (output / "frames.txt").write_text(frames_text, encoding="utf-8")
    (output / "targets.objdump.txt").write_text(
        targets_text, encoding="utf-8")
    (output / "dispatcher.objdump.txt").write_text(
        dispatcher_text, encoding="utf-8")
    return records


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=str(TARGET))
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    generate(args.binary, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
