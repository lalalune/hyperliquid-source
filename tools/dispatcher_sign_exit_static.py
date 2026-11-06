#!/usr/bin/env python3
"""Static trace of the RE-002 CPU-feature dispatcher's
sign-bit exit body at 0x5bbb630.

PR #2749 (the RE-002 bit-9 F2 trace packet) traced the
dispatcher's bit-9 set-arm body, 0x5bba120 -- the SSSE3 form
of the ChaCha block function: four blocks worked in parallel
in transposed form, with feed-forward, and the state record's
64-bit counter advanced by 4 -- and pinned the dispatcher's
other exits without tracing them.  PR #2754 (the 0x4000-exit
packet) then traced the 0x4000-exit body 0x5bbb030 as the AVX
(VEX-encoded, 128-bit) form of the same function, with an
identical contract, and left as its next question, verbatim:
"trace the dispatcher's sign-bit exit body at
0x5bbb630..0x5bbb994 (868 bytes) -- the first feature exit in
test order -- and name its operation: whether it is a scalar
(or otherwise reduced) form of the same ChaCha block
function, and how its counter/output contract compares to
the SSSE3 and AVX forms now pinned."

This producer answers that question:

* it authenticates the whole capture (size + SHA-256) before
  any analysis, then pins the traced body by its FDE range
  (0x5bbb630..0x5bbb994, 868 bytes) and by its SHA-256,
  re-derived from the binary alone through the section
  table;
* it traces the body in full: the entry loads the same
  record rows at rdi -- the counter/nonce row as an xmm
  (0x5bbb630) and bytes 0x00..0x30 as two 32-byte ymm loads
  (0x5bbb675, 0x5bbb679) -- builds the same four counter
  rows (+0/+1/+2/+3) from the 64-bit counter at [rdi+0x20]
  with vpinsrd pairs, and fans the rows out to 256-bit
  form with four vinserti128: the two key rows are
  duplicated into both lanes (the same row serves all four
  blocks) while the counter rows pair up as
  [+0,+1] and [+2,+3] -- two blocks per ymm register,
  the four blocks held as register pairs.  A test esi,esi
  gate sends a zero round count to a path that loads the
  two-lane sigma constant; the round loop (head 0x5bbb6d0,
  dec esi / jne back edge) runs the same ChaCha
  quarter-round network, and its rotation census is
  exactly half the F2/AVX loop census on every count
  (16 paddd, 16 pxor, 8 pshufb, rotations 16/12/8/7 at
  4 each, pshufd lane rotations 0x39/0x4e/0x93 at 4/4/2)
  because every instruction works on 256 bits instead of
  128 -- the per-bit work is identical.  A shared
  epilogue advances the counter by 4, stores the rebuilt
  counter/nonce row back at [rdi+0x20] and writes 256
  bytes (four feed-forward ChaCha blocks) to rdx in 16
  vector stores, with all 16 feed-forward adds inside the
  epilogue (the constant rows' sigma add is one of them)
  and vextracti128 pulling the high lanes down for the
  upper blocks' stores -- exactly the F2/AVX contract;
* it names the difference, which is the width, in the
  opposite direction from the question's hypothesis: this
  is not a scalar or reduced form.  It is the AVX2
  (256-bit ymm) form of the same ChaCha block function --
  the widest of the three forms -- with the same
  four-block parallelism.  Corollaries: 173 instructions
  in 868 bytes against the AVX form's 301 in 1,530 and
  the SSSE3 form's 340 in 1,758; an 84-instruction loop
  against 189 and 217; no stack frame at all (the F2 form
  takes 0x38 bytes, the AVX form 0x68) -- the sole stack
  access is a red-zone save/restore of the +3 counter row;
  32-byte constants (the sigma row and the rotate-by-8
  mask each duplicated per lane, the swap mask's high
  lane offset by 0x10) where the narrower forms read the
  16-byte originals; the doubled-sigma constant of the
  narrower forms is not referenced -- the zero-round path
  loads the two-lane sigma and lets the epilogue's sigma
  add complete initial + initial; and a vzeroupper before
  ret, as in the AVX form;
* it re-pins the selecting dispatcher (0x5bba800..0x5bbb030):
  the cached feature word through slot 0x64dfa60, all four
  exits in test order, and the sign exit block (0x5bbaf85:
  add rsp,0xa8, four pops, jmp), whose jump enters this
  body with the dispatcher's own caller arguments
  (rdi, esi, rdx), so the body's ret returns straight to
  that caller;
* it censuses every direct E8/E9 transfer in .text whose
  target is the traced body (each raw hit validated
  against the disassembly of its containing FDE): exactly
  one jump, the dispatcher's sign exit jump at 0x5bbaf92,
  and no call.

The comparison bodies (F2, 0x5bba120..0x5bba7fe, and the
AVX form, 0x5bbb030..0x5bbb62a) are themselves hash-pinned
and re-traced for the shared contract points (loop
rotation census, counter advance and write-back, output
stores, epilogue feed-forward adds), so the same-contract
verdict is re-derived, not quoted.

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

BODY = (0x5BBB630, 0x5BBB994)
BODY_SHA256 = "963fe9acf58718076c5a6fa97b4cfc297cd0b8d73719ac18d50b7242bf72a944"
BODY_INSNS = 173
F2_BODY = (0x5BBA120, 0x5BBA7FE)
F2_SHA256 = "e787f6af5ff38fbe899147dac51fec44e1d6887fa0a5ef131bd0a528c38f0245"
F2_INSNS = 340
AVX_BODY = (0x5BBB030, 0x5BBB62A)
AVX_SHA256 = "c04bc82ee291c06eb8e65fe73d86dd880a11f4ff06aec15c62956a579b916892"
AVX_INSNS = 301
DISPATCHER = (0x5BBA800, 0x5BBB030)
EXIT_JUMP = 0x5BBAF92
EXPECTED_FDE_COUNT = 135313

SIGMA_VA = 0x4519C0
SIGMA32_VA = 0x458660
ROT8_32_VA = 0x458120
SWAP32_VA = 0x457CA0

SIGMA = b"expand 32-byte k"
ROT8_MASK = bytes([3, 0, 1, 2, 7, 4, 5, 6,
                   11, 8, 9, 10, 15, 12, 13, 14])
ROT16_MASK = bytes([14, 15, 12, 13, 2, 3, 0, 1,
                    6, 7, 4, 5, 10, 11, 8, 9])
EXPECTED_CONSTANTS = {
    SIGMA_VA: SIGMA,
    SIGMA32_VA: SIGMA * 2,
    ROT8_32_VA: ROT8_MASK * 2,
    SWAP32_VA: ROT16_MASK + bytes((b + 0x10) & 0xFF
                                  for b in ROT16_MASK),
}
CONSTANT_SIZES = {
    SIGMA_VA: 16,
    SIGMA32_VA: 32,
    ROT8_32_VA: 32,
    SWAP32_VA: 32,
}

GATE = 0x5BBB696
LOOP_HEAD = 0x5BBB6D0
LOOP_DEC = 0x5BBB85D
LOOP_BACK = 0x5BBB85F
ZERO_PATH = 0x5BBB87D
POST_LOOP_JMP = 0x5BBB87B
MERGE = 0x5BBB892
VZEROUPPER = 0x5BBB990
WRITEBACK = 0x5BBB8A9


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


def trace_body(data, secs, insns):
    lo, hi = BODY
    by_va = {i.va: i for i in insns}
    if insns[-1].mnemonic != "ret":
        raise ValueError("traced body does not end in ret")
    if any(i.mnemonic == "call" for i in insns):
        raise ValueError("traced body unexpectedly contains a call")

    # No stack frame at all: no sub/add rsp anywhere; the sole
    # stack access is the red-zone save/restore of xmm15.
    frame_ops = [hx(i.va) for i in insns
                 if i.mnemonic in ("sub", "add")
                 and i.operands.startswith("rsp")]
    if frame_ops:
        raise ValueError(f"traced body gained a frame: {frame_ops}")
    save = by_va.get(0x5BBB69E)
    if save is None or save.mnemonic != "vmovdqa" \
            or "[rsp-0x18]" not in save.operands \
            or split_operands(save.operands)[-1] != "xmm15":
        raise ValueError("red-zone save of the +3 counter row changed")
    restore = by_va.get(0x5BBB875)
    if restore is None or restore.mnemonic != "vmovdqa" \
            or "[rsp-0x18]" not in restore.operands \
            or split_operands(restore.operands)[0] != "xmm15":
        raise ValueError("red-zone restore of xmm15 changed")

    # Width: 256-bit ymm operands throughout the vector work.
    ymm_insns = [hx(i.va) for i in insns if "ymm" in i.text]
    if not ymm_insns:
        raise ValueError("traced body lost its ymm operands")
    vex = sum(1 for i in insns if i.mnemonic.startswith("v"))
    vzero = [hx(i.va) for i in insns if i.mnemonic == "vzeroupper"]
    if vzero != [hx(VZEROUPPER)]:
        raise ValueError(f"vzeroupper placement changed: {vzero}")

    branches = []
    for insn in insns:
        if insn.mnemonic.startswith("j"):
            branches.append({
                "site": hx(insn.va), "kind": insn.mnemonic,
                "target": hx(branch_target(insn))})
    expected_branches = [
        {"site": hx(GATE + 2), "kind": "je", "target": hx(ZERO_PATH)},
        {"site": hx(LOOP_BACK), "kind": "jne", "target": hx(LOOP_HEAD)},
        {"site": hx(POST_LOOP_JMP), "kind": "jmp", "target": hx(MERGE)},
    ]
    if branches != expected_branches:
        raise ValueError(f"traced body branches changed: {branches}")

    # Entry, up to the round-count gate: the counter/nonce row
    # as an xmm, the counter word into rax, three lea variants
    # (+1/+2/+3), six vpinsrd, two 32-byte record loads and
    # four vinserti128 that fan the rows out to 256-bit form.
    counter_row_load = []
    counter_load = []
    wide_loads = []
    insert_sites = []
    for insn in insns:
        if insn.va >= GATE:
            break
        ops = split_operands(insn.operands)
        if insn.mnemonic == "vmovdqa" and len(ops) == 2:
            src = parse_operand(ops[1])
            if src[0] == "mem" and src[1]["base"] == "rdi":
                counter_row_load.append((hx(insn.va), src[1]["disp"]))
        if insn.mnemonic == "mov" and len(ops) == 2:
            src = parse_operand(ops[1])
            if src[0] == "mem" and src[1]["base"] == "rdi" \
                    and src[1]["disp"] == 0x20:
                counter_load.append(hx(insn.va))
        if insn.mnemonic == "vmovdqu" and len(ops) == 2:
            src = parse_operand(ops[1])
            if src[0] == "mem" and src[1]["base"] == "rdi":
                wide_loads.append((hx(insn.va), src[1]["disp"]))
        if insn.mnemonic == "vinserti128":
            insert_sites.append(hx(insn.va))
    if counter_row_load != [(hx(0x5BBB630), 0x20)] \
            or counter_load != [hx(0x5BBB635)]:
        raise ValueError(
            f"traced body counter loads changed: "
            f"{counter_row_load} {counter_load}")
    if wide_loads != [(hx(0x5BBB675), 0), (hx(0x5BBB679), 0x10)]:
        raise ValueError(f"traced body wide loads changed: {wide_loads}")
    if insert_sites != [hx(0x5BBB67E), hx(0x5BBB684),
                        hx(0x5BBB68A), hx(0x5BBB690)]:
        raise ValueError(f"vinserti128 fan-out changed: {insert_sites}")
    counter_leas = [hx(i.va) for i in insns
                    if i.mnemonic == "lea" and i.va < GATE
                    and any(f"[rax+0x{k}]" in i.operands
                            for k in (1, 2, 3))]
    if counter_leas != [hx(0x5BBB639), hx(0x5BBB64D), hx(0x5BBB661)]:
        raise ValueError(
            f"counter variant construction changed: {counter_leas}")
    entry_pinsrd = [hx(i.va) for i in insns
                    if i.mnemonic == "vpinsrd" and i.va < GATE]
    if len(entry_pinsrd) != 6:
        raise ValueError(
            f"counter vpinsrd construction changed: {entry_pinsrd}")

    gate = by_va.get(GATE)
    if gate is None or gate.mnemonic != "test" \
            or gate.operands != "esi,esi":
        raise ValueError("round-count gate changed")

    # Constants: three 32-byte two-lane constants plus the
    # 16-byte sigma the epilogue adds; the doubled sigma of
    # the narrower forms is not referenced.
    refs = rip_refs(data, secs, insns)
    if set(refs) != set(EXPECTED_CONSTANTS):
        raise ValueError(f"traced body constants changed: {sorted(refs)}")
    for va, expected in EXPECTED_CONSTANTS.items():
        if bytes.fromhex(refs[va]["bytes"]) != expected:
            raise ValueError(f"constant at {va:#x} changed")
    expected_refs = {
        SIGMA32_VA: [hx(0x5BBB6A4), hx(ZERO_PATH)],
        ROT8_32_VA: [hx(0x5BBB6AC)],
        SWAP32_VA: [hx(0x5BBB6B4)],
        SIGMA_VA: [hx(0x5BBB8AE)],
    }
    for va, sites in expected_refs.items():
        if refs[va]["referenced_from"] != sites:
            raise ValueError(
                f"constant {va:#x} reference sites changed: "
                f"{refs[va]['referenced_from']}")

    loop_insns, census = loop_census(insns, LOOP_HEAD, LOOP_BACK)
    if census != SIGN_LOOP_CENSUS:
        raise ValueError(f"round-loop census changed: {census}")
    doubled = {k: (v * 2 if isinstance(v, int) else
                   {kk: vv * 2 for kk, vv in v.items()})
               for k, v in census.items()}
    if doubled != EXPECTED_LOOP_CENSUS:
        raise ValueError(
            f"doubled loop census is not the F2/AVX census: {doubled}")
    dec = by_va.get(LOOP_DEC)
    if dec is None or dec.mnemonic != "dec" or dec.operands != "esi":
        raise ValueError("loop counter decrement changed")

    zero_first = by_va.get(ZERO_PATH)
    if zero_first is None or zero_first.mnemonic != "vmovdqa" \
            or zero_first.comment_target() != SIGMA32_VA:
        raise ValueError("zero-round two-lane sigma load changed")

    epilogue = epilogue_contract(insns, MERGE)
    if epilogue["counter_writeback_site"] != hx(WRITEBACK) \
            or epilogue["feed_forward_adds"] != 16:
        raise ValueError(f"epilogue contract changed: {epilogue}")
    extracts = [hx(i.va) for i in insns
                if i.mnemonic == "vextracti128" and i.va >= MERGE]
    if len(extracts) != 8:
        raise ValueError(f"epilogue lane extracts changed: {extracts}")

    return {
        "body": f"{hx(lo)}..{hx(hi)}",
        "bytes": hi - lo,
        "insns": len(insns),
        "sha256": BODY_SHA256,
        "calls": 0,
        "entry": [i.text for i in insns[:8]],
        "frame": "no stack-pointer adjustment anywhere in the "
                 "body; the sole stack access is a red-zone "
                 "save of the +3 counter row (xmm15) at "
                 "[rsp-0x18] before the loop (0x5bbb69e), "
                 "restored at 0x5bbb875 (the SSSE3 form's "
                 "frame is 0x38 bytes, the AVX form's 0x68)",
        "branches": branches,
        "input": {
            "record_pointer": "rdi",
            "counter_row_load": counter_row_load[0][0],
            "wide_row_loads": [
                {"site": s, "disp": d} for s, d in wide_loads],
            "insert_sites": insert_sites,
            "bytes_read": "0x00..0x30 of the record (the "
                          "counter/nonce row at +0x20 as an "
                          "xmm, then bytes 0x00..0x20 and "
                          "0x10..0x30 as two overlapping "
                          "32-byte ymm loads); bytes 0x30.. "
                          "of the record are never read",
            "counter_load": counter_load[0],
            "counter": "the 64-bit word at [rdi+0x20]; variants "
                       "+0/+1/+2/+3 built at "
                       + ", ".join(counter_leas)
                       + " -- each variant row is the loaded "
                         "counter/nonce row with its first two "
                         "dwords replaced by the variant counter "
                         "(vpinsrd $0 with the lea result's low "
                         "dword, vpinsrd $1 with its shr 0x20 "
                         "high dword), one row per block; four "
                         "vinserti128 then fan the rows out to "
                         "256-bit form: the [rdi] and [rdi+0x10] "
                         "rows are duplicated into both lanes "
                         "(the same row serves all four blocks) "
                         "while the counter rows pair up as "
                         "[+0,+1] and [+2,+3] -- two blocks per "
                         "ymm register, the four blocks held "
                         "as register pairs",
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
            "note": "every count is exactly half the F2/AVX "
                    "loop census because every instruction "
                    "works on 256 bits instead of 128; the "
                    "producer requires the doubled census to "
                    "equal the F2/AVX census exactly",
        },
        "zero_round_path": {
            "entry": hx(ZERO_PATH),
            "sigma32_load": hx(zero_first.va),
            "note": "with esi == 0 no round runs: the constant "
                    "rows are loaded with the two-lane sigma "
                    "constant at 0x458660 (the plain sigma row "
                    "duplicated per lane, not the doubled "
                    "sigma the narrower forms load) and the "
                    "remaining worked rows are pre-loaded "
                    "with the initial rows, so the shared "
                    "epilogue's adds produce exactly initial "
                    "+ initial",
        },
        "epilogue": epilogue,
        "epilogue_lane_extracts": extracts,
        "encoding": {
            "vex_prefixed_insns": vex,
            "ymm_insns": len(ymm_insns),
            "vector_width_bits": 256,
            "vzeroupper_site": vzero[0],
            "note": "every vector instruction is VEX-encoded "
                    "and the round loop works entirely on "
                    "256-bit ymm registers (two blocks per "
                    "register); the entry counter construction "
                    "and the epilogue's stores are 128-bit, "
                    "with vextracti128 pulling the high lanes "
                    "down for the upper blocks' stores",
        },
    }


def trace_form_contract(data, secs, insns, body, sha256, insns_n,
                        loop_head, loop_back, merge, writeback,
                        ff_adds):
    """Re-derive a comparison form's shared contract points so
    the comparison is computed, not quoted."""
    digest = body_sha256(data, secs, body[0], body[1])
    if digest != sha256:
        raise ValueError(f"comparison body {body[0]:#x} hash mismatch")
    if len(insns) != insns_n:
        raise ValueError(
            f"comparison body {body[0]:#x} insn count changed")
    _loop, census = loop_census(insns, loop_head, loop_back)
    if census != EXPECTED_LOOP_CENSUS:
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
    exits = []
    for i in insns:
        if i.mnemonic == "jmp":
            target = branch_target(i)
            if target is not None \
                    and DISPATCHER[0] <= target < DISPATCHER[1]:
                continue
            exits.append({"site": hx(i.va), "target": hx(target)})
    expected_exits = [
        {"site": hx(EXIT_JUMP), "target": hx(BODY[0])},
        {"site": hx(0x5BBAFC5), "target": hx(AVX_BODY[0])},
        {"site": hx(0x5BBAFF8), "target": hx(0x5BB9A60)},
        {"site": hx(0x5BBB02B), "target": hx(F2_BODY[0])},
    ]
    if exits != expected_exits:
        raise ValueError(f"dispatcher exits changed: {exits}")
    block = [by_va[va] for va in
             (0x5BBAF85, 0x5BBAF8C, 0x5BBAF8D, 0x5BBAF8F,
              0x5BBAF91, EXIT_JUMP)]
    if [i.mnemonic for i in block] != \
            ["add", "pop", "pop", "pop", "pop", "jmp"]:
        raise ValueError("sign exit block changed")
    return {
        "body": f"{hx(DISPATCHER[0])}..{hx(DISPATCHER[1])}",
        "feature_slot": "0x64dfa60",
        "feature_slot_load": hx(slot_load.va),
        "bit_tests": {
            "0x4000": sites_4000,
            "0x400": test_sites(0x400),
            "0x200_bit9": test_sites(0x200),
        },
        "exits": exits,
        "exit_sign": {
            "block": hx(0x5BBAF85),
            "shape": "add rsp,0xa8; pop rbx; pop r14; pop r15; "
                     "pop rbp; jmp -- the dispatcher's frame is "
                     "fully unwound before the jump, so the "
                     "sign-exit body is entered with the "
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
        for fde in (BODY, AVX_BODY, F2_BODY, DISPATCHER):
            if fde not in fde_set:
                raise ValueError(f"{fde} is not an FDE range")

        targets_text, insns = disassemble(snapshot, BODY[0], BODY[1])
        if len(insns) != BODY_INSNS:
            raise ValueError("traced body insn count changed")
        trace = trace_body(data, secs, insns)

        _f2_text, f2_insns = disassemble(snapshot, F2_BODY[0], F2_BODY[1])
        f2 = trace_form_contract(
            data, secs, f2_insns, F2_BODY, F2_SHA256, F2_INSNS,
            0x5BBA230, 0x5BBA693, 0x5BBA6FD, 0x5BBA72F, 12)

        _avx_text, avx_insns = disassemble(
            snapshot, AVX_BODY[0], AVX_BODY[1])
        avx = trace_form_contract(
            data, secs, avx_insns, AVX_BODY, AVX_SHA256, AVX_INSNS,
            0x5BBB100, 0x5BBB4AD, 0x5BBB55B, 0x5BBB572, 12)

        dispatcher_text, dinsns = disassemble(
            snapshot, DISPATCHER[0], DISPATCHER[1])
        dispatcher = dispatcher_analysis(dinsns)

        census = direct_transfer_census(data, secs, snapshot,
                                        ranges, BODY[0])
        if census != {"call": [], "jmp": [hx(EXIT_JUMP)]}:
            raise ValueError(
                f"direct transfer census changed: {census}")

        frames_rows = []
        for key in sorted({BODY, AVX_BODY, F2_BODY, DISPATCHER}):
            if key in frame_lines:
                frames_rows.append(frame_lines[key])
        frames_text = "\n".join(frames_rows) + "\n"

    records = {
        "target_sha256": SHA256,
        "target_size": SIZE,
        "tip_packet": "RE-002-node115-dispatcher-4000-exit (PR #2754)",
        "question": "trace the dispatcher 0x5bba800's sign-bit-exit "
                    "body at 0x5bbb630..0x5bbb994 and name its "
                    "operation: whether it is a scalar (or "
                    "otherwise reduced) form of the same ChaCha "
                    "block function, and how its counter/output "
                    "contract compares to the SSSE3 (F2) and AVX "
                    "(0x4000-exit) forms",
        "trace": trace,
        "comparison_f2": f2,
        "comparison_avx": avx,
        "comparison": {
            "verdict": "same-operation-avx2-form",
            "same": [
                "input: bytes 0x00..0x30 of the record at rdi "
                "(rows at +0x00/+0x10 and the counter/nonce row "
                "at +0x20); the counter is the 64-bit word at "
                "[rdi+0x20], with +0/+1/+2/+3 variant rows, "
                "one per block, built by the same lea/vpinsrd "
                "construction as the AVX form",
                "round-count contract: esi counts round-loop "
                "iterations, each running two double rounds; "
                "esi == 0 takes a zero-round path and the "
                "output is exactly initial + initial",
                "round loop: the ChaCha quarter-round network "
                "-- the rotation census is half the F2/AVX "
                "census on every count (16 paddd, 16 pxor, "
                "8 pshufb, rotations 16/12/8/7 at 4 each, "
                "pshufd lane rotations 0x39/0x4e/0x93 at "
                "4/4/2) because every instruction works on "
                "256 bits instead of 128; doubled, it equals "
                "the F2/AVX census exactly",
                "feed-forward: worked rows are added to the "
                "initial rows and stored as 16 vector stores "
                "covering 256 bytes at rdx (four 64-byte "
                "blocks); all 16 adds sit in the shared "
                "epilogue here, where the narrower forms "
                "split them 4 pre-merge + 12 in the epilogue",
                "counter/output contract: the counter word at "
                "[rdi+0x20] is stored back advanced by 4, and "
                "256 bytes -- four 64-byte ChaCha blocks for "
                "counters c, c+1, c+2, c+3 -- are stored to "
                "rdx; no return value",
                "structure: no calls, exactly three branches, "
                "all internal, and a single ret",
            ],
            "different": [
                "width and layout: 256-bit ymm registers "
                "throughout the round loop -- two blocks per "
                "register, the four blocks held as register "
                "pairs, the entry rows fanned out with "
                "vinserti128 and the epilogue de-fanned with "
                "vextracti128 -- against 128-bit xmm in both "
                "the SSSE3 and the AVX forms: this is the "
                "widest form, not a scalar or reduced one",
                "size: 868 bytes / 173 instructions against "
                "the AVX form's 1,530 bytes / 301 instructions "
                "and the SSSE3 form's 1,758 bytes / 340; the "
                "round loop is 84 instructions against 189 "
                "and 217",
                "frame: none at all -- no stack-pointer "
                "adjustment, only a red-zone save/restore of "
                "the +3 counter row -- against 0x68 bytes "
                "(AVX form) and 0x38 bytes (SSSE3 form)",
                "constants: 32-byte two-lane constants (the "
                "sigma row at 0x458660 and the rotate-by-8 "
                "mask at 0x458120, each the 16-byte original "
                "duplicated per lane; the swap mask at "
                "0x457ca0, whose high lane is the F2 swap "
                "mask with every byte raised by 0x10) where "
                "the narrower forms read the 16-byte "
                "originals at 0x4519c0/0x4531c0/0x452ec0",
                "zero-round path: loads the two-lane sigma "
                "constant instead of the doubled sigma at "
                "0x456c50, which this body never references; "
                "the epilogue's sigma add completes initial "
                "+ initial",
                "a vzeroupper at 0x5bbb990 before ret, as in "
                "the AVX form and unlike the SSSE3 form",
            ],
        },
        "dispatcher": dispatcher,
        "direct_transfers": {
            "validated_direct_calls": census["call"],
            "validated_direct_jumps": census["jmp"],
            "note": "every E8/E9 byte hit in .text was validated "
                    "against its containing FDE's disassembly; "
                    "the sole direct transfer to the traced body "
                    "is the dispatcher's sign exit jump at "
                    "0x5bbaf92, and there is no call",
        },
        "operation": {
            "name": "ChaCha block function (AVX2 / 256-bit ymm "
                    "form): four blocks in parallel with "
                    "feed-forward, the state's 64-bit counter "
                    "advanced by 4",
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
                        "the SSSE3 form at 0x5bba120 and the AVX "
                        "form at 0x5bbb030 in every observable "
                        "respect",
            "evidence": [
                "the body's round constants are the ChaCha "
                "constants at 256-bit width: the 32-byte "
                "constant at 0x458660 is the ASCII string "
                "\"expand 32-byte k\" (the sigma row) twice, "
                "once per lane, and the epilogue adds the "
                "16-byte sigma at 0x4519c0 itself",
                "the round loop is the ChaCha quarter-round "
                "network on 32-bit words: vpaddd/vpxor with "
                "rotations 16 (vpshuflw/vpshufhw 0xb1 word "
                "swaps), 12 (vpsrld 0x14 / vpslld 0xc), 8 "
                "(vpshufb through the two-lane byte-rotation "
                "mask at 0x458120) and 7 (vpsrld 0x19 / "
                "vpslld 0x7), with vpshufd 0x39/0x4e/0x93 "
                "lane rotations for the diagonal rounds and "
                "a second two-lane byte mask at 0x457ca0 -- "
                "every count exactly half the SSSE3/AVX "
                "census at exactly twice the width",
                "the entry builds four counter rows from the "
                "64-bit counter at [rdi+0x20] (+0/+1/+2/+3) "
                "and fans them out with vinserti128 -- the "
                "key rows duplicated into both lanes, the "
                "counter rows paired [+0,+1] and [+2,+3] -- "
                "four blocks worked in lockstep, one counter "
                "step apart",
                "the epilogue is the ChaCha feed-forward: "
                "worked rows are added to the initial rows "
                "(16 vpaddd, the constant rows' addend being "
                "the sigma row itself) and stored as 16 "
                "vector stores covering 256 bytes, the high "
                "lanes pulled down with vextracti128, and "
                "the counter row is stored back at "
                "[rdi+0x20] with the counter advanced by 4",
                "the scalar/reduced hypothesis fails on the "
                "operands: the round loop works entirely on "
                "256-bit ymm registers -- wider than either "
                "comparison form -- and the body is the "
                "shortest of the three precisely because "
                "each instruction does twice the work",
            ],
        },
        "summary": {
            "bodies_traced": 1,
            "comparison_bodies_retraced": 2,
            "verdict": "same-operation-avx2-form",
            "wider_vector": True,
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
