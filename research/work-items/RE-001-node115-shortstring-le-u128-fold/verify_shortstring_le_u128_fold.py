#!/usr/bin/env python3
"""Static verification for the node #115 short-string -> u128 fold at 0x15472b0.

This script performs NO native execution of the captured binary. It never
relocates, loads, or writes the capture. It reads the 89 bytes of the function
body read-only and interprets them with a tiny, in-process x86-64 emulator that
decodes exactly the instruction encodings present in this body (no general CPU,
no new dependency). Concretely it:

  1. authenticates the captured ELF by SHA-256 BEFORE any other byte
     interpretation;
  2. pins the 89-byte body length and body SHA-256 of the function;
  3. confirms the three GOT slots referenced by the body resolve through
     R_X86_64_RELATIVE (type 8) relocations to the recovered addends
     (self 0x15472b0, bounds panic 0x1680cbf, overflow panic 0x1681dc0);
  4. confirms the two panic location descriptors decode to
     base/src/short_string.rs 52:9 and 52:28, with the file-name string at
     0x435643;
  5. DECODES the real 89 body bytes instruction-by-instruction, asserting the
     exact opcode sequence (shl/shld/or/shr rdx,0x38/cmp/je/jae/jne/call...),
     then EMULATES that decoded body over a test grid and compares the emulated
     u128 (returned in rdx:rax) against both the pure-Python recurrence model
     AND an independent little-endian pack. The emulated binary is the ground
     truth; model agreement is only credited when the emulator agrees too;
  6. demonstrates the VALUE-DEPENDENT overflow domain: a 17-byte input whose
     last byte is 0 does NOT panic (its little-endian value still fits in 128
     bits); a 17-byte input with a nonzero byte at index >= 16 panics. Both the
     model and the emulated body are checked to agree on which inputs panic;
  7. runs reproducible negative controls by PATCHING the body bytes IN MEMORY
     (jne->je at 0x15472d3; shld->5x nop at 0x15472d8) and re-emulating the
     patched body, showing the overflow guard inverts / the high-limb carry is
     lost. The committed control-*.objdump.txt files are the static-disassembly
     view of these same in-memory patches.

No PC/register/memory state of the real process is advanced; the emulator runs
only over the pinned body bytes with a synthetic input buffer.
"""
import hashlib
import struct
import sys

BIN = "artifacts/node/115/hl-node"
BIN_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BIN_SIZE = 105896032

# Function (FDE extent, exclusive end) -> 89 bytes.
FUNC_VA = 0x15472B0
FUNC_END = 0x1547309
FUNC_LEN = FUNC_END - FUNC_VA  # 89
FUNC_SHA256 = "be131836977ceb1a02f296cfff40e71654c16b97ce774faec0f4ebe8f2728456"

# GOT slots dereferenced by the three `call` sites and their R_X86_64_RELATIVE
# target addends (recovered from .rela.dyn).
GOT_SELF = (0x64E0FE0, 0x15472B0)   # recursive / tail-called self
GOT_BOUNDS = (0x64DF620, 0x1680CBF)  # slice index-out-of-bounds panic
GOT_OVERFLOW = (0x64DF870, 0x1681DC0)  # arithmetic-overflow panic

# Panic location descriptors (in .data.rel.ro): {&str ptr, u64 len, u32 line,
# u32 col}. ptr is itself an R_X86_64_RELATIVE pointing at the file-name string.
LOC_BOUNDS_VA = 0x63FDC68   # short_string.rs:52:9
LOC_OVERFLOW_VA = 0x63FDC80  # short_string.rs:52:28
FILE_STR_VA = 0x435643
FILE_STR = b"base/src/short_string.rs"
R_X86_64_RELATIVE = 8

MASK64 = (1 << 64) - 1
U128 = 1 << 128
LIMIT_2_120 = 1 << 120  # (hi >> 56) != 0  <=>  acc >= 2**120


# ---------------------------------------------------------------------------
# ELF helpers (read-only; pure parsing of the pinned bytes).
# ---------------------------------------------------------------------------
def read(path):
    with open(path, "rb") as f:
        return f.read()


def authenticate(data):
    if len(data) != BIN_SIZE:
        raise SystemExit(f"capture size mismatch: {len(data)} != {BIN_SIZE}")
    got = hashlib.sha256(data).hexdigest()
    if got != BIN_SHA256:
        raise SystemExit(f"capture SHA-256 mismatch: {got}")


def sections(data):
    """Minimal ELF64 section table: list of (name, type, addr, off, size)."""
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    raw = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        name_off = struct.unpack_from("<I", data, b)[0]
        s_type = struct.unpack_from("<I", data, b + 4)[0]
        addr = struct.unpack_from("<Q", data, b + 16)[0]
        off = struct.unpack_from("<Q", data, b + 24)[0]
        size = struct.unpack_from("<Q", data, b + 32)[0]
        raw.append((name_off, s_type, addr, off, size))
    str_off = raw[e_shstrndx][3]

    def nm(n):
        end = data.index(b"\0", str_off + n)
        return data[str_off + n:end].decode()

    return [(nm(n), t, a, o, s) for (n, t, a, o, s) in raw]


def va_to_off(secs, va):
    for _name, t, a, o, s in secs:
        if t != 8 and a != 0 and a <= va < a + s:  # skip SHT_NOBITS (.bss)
            return o + (va - a)
    raise SystemExit(f"VA not in any section: {hex(va)}")


def relocations(data, secs):
    """{r_offset: (r_type, r_addend)} over every RELA section."""
    out = {}
    for _name, t, _a, o, s in secs:
        if t != 4:  # SHT_RELA
            continue
        for p in range(o, o + s, 24):
            r_off, r_info, r_add = struct.unpack_from("<QQq", data, p)
            out[r_off] = (r_info & 0xFFFFFFFF, r_add)
    return out


def check_relative(relocs, slot, addend, label):
    if slot not in relocs:
        raise SystemExit(f"{label}: no relocation for slot {hex(slot)}")
    rtype, radd = relocs[slot]
    if rtype != R_X86_64_RELATIVE:
        raise SystemExit(f"{label}: slot {hex(slot)} type {rtype} != RELATIVE")
    if radd != addend:
        raise SystemExit(f"{label}: slot {hex(slot)} addend {hex(radd)} != {hex(addend)}")


def decode_loc(data, secs, relocs, va):
    """Decode a panic Location {ptr,len,line,col}; ptr via its relocation."""
    o = va_to_off(secs, va)
    length, line, col = struct.unpack_from("<QII", data, o + 8)
    if va not in relocs or relocs[va][0] != R_X86_64_RELATIVE:
        raise SystemExit(f"loc {hex(va)}: missing RELATIVE ptr relocation")
    ptr = relocs[va][1]
    return ptr, length, line, col


# ---------------------------------------------------------------------------
# Tiny x86-64 interpreter for EXACTLY the encodings in the 0x15472b0 body.
#
# This is not a general CPU: every instruction form below is one that occurs in
# this 89-byte body, and `decode()` raises on anything else. Decoding the whole
# body with zero leftover bytes is itself the byte-level opcode assertion the
# review asked for; emulate() then executes the decoded stream.
# ---------------------------------------------------------------------------
class EmuBounds(Exception):
    """Models the slice index-out-of-bounds panic call (GOT 0x64df620)."""


class EmuOverflow(Exception):
    """Models the arithmetic-overflow panic call (GOT 0x64df870)."""


class EmuError(Exception):
    """Unknown / unexpected encoding: the body is not what we modelled."""


# Expected mnemonic stream (used only to assert the decode covers the body).
EXPECTED_DECODE = [
    (0x15472B0, "push rbx"),
    (0x15472B1, "xor eax,eax"),
    (0x15472B3, "mov ecx,0x0"),
    (0x15472B8, "cmp rdx,rsi"),
    (0x15472BB, "je 0x15472e4"),
    (0x15472BD, "jae 0x15472e9"),
    (0x15472BF, "movzx ebx,byte [rdi+rdx]"),
    (0x15472C3, "inc rdx"),
    (0x15472C6, "call [rip->got 0x64e0fe0]"),
    (0x15472CC, "mov rcx,rdx"),
    (0x15472CF, "shr rdx,0x38"),
    (0x15472D3, "jne 0x15472fc"),
    (0x15472D5, "movzx edx,bl"),
    (0x15472D8, "shld rcx,rax,0x8"),
    (0x15472DD, "shl rax,0x8"),
    (0x15472E1, "or rax,rdx"),
    (0x15472E4, "mov rdx,rcx"),
    (0x15472E7, "pop rbx"),
    (0x15472E8, "ret"),
    (0x15472E9, "lea rax,[rip->0x63fdc68]"),
    (0x15472F0, "mov rdi,rdx"),
    (0x15472F3, "mov rdx,rax"),
    (0x15472F6, "call [rip->got 0x64df620]"),
    (0x15472FC, "lea rdi,[rip->0x63fdc80]"),
    (0x1547303, "call [rip->got 0x64df870]"),
]


def decode(body, base=FUNC_VA):
    """Linear-sweep decode of the body. Returns {va: (length, mnem, operands)}.

    Raises EmuError on any byte pattern not present in the known body, so a
    clean decode asserts the exact opcode sequence over all FUNC_LEN bytes.
    """
    insns = {}
    i = 0
    n = len(body)
    while i < n:
        va = base + i
        b = body[i]
        # single-byte
        if b == 0x53:
            insns[va] = (1, "push", ("rbx",)); i += 1; continue
        if b == 0x5B:
            insns[va] = (1, "pop", ("rbx",)); i += 1; continue
        if b == 0xC3:
            insns[va] = (1, "ret", ()); i += 1; continue
        if b == 0x90:
            insns[va] = (1, "nop", ()); i += 1; continue
        if b == 0x31 and body[i + 1] == 0xC0:
            insns[va] = (2, "xor", ("eax", "eax")); i += 2; continue
        if b == 0xB9:  # mov ecx, imm32
            imm = struct.unpack_from("<I", body, i + 1)[0]
            insns[va] = (5, "mov", ("ecx", imm)); i += 5; continue
        if b == 0x74:  # je rel8
            tgt = va + 2 + struct.unpack_from("<b", body, i + 1)[0]
            insns[va] = (2, "je", (tgt,)); i += 2; continue
        if b == 0x73:  # jae rel8
            tgt = va + 2 + struct.unpack_from("<b", body, i + 1)[0]
            insns[va] = (2, "jae", (tgt,)); i += 2; continue
        if b == 0x75:  # jne rel8
            tgt = va + 2 + struct.unpack_from("<b", body, i + 1)[0]
            insns[va] = (2, "jne", (tgt,)); i += 2; continue
        if b == 0x0F and body[i + 1] == 0xB6:  # movzx r32, r/m8
            modrm = body[i + 2]
            if modrm == 0x1C and body[i + 3] == 0x17:  # ebx, [rdi+rdx*1]
                insns[va] = (4, "movzx", ("ebx", ("mem", "rdi", "rdx"))); i += 4; continue
            if modrm == 0xD3:  # edx, bl
                insns[va] = (3, "movzx", ("edx", "bl")); i += 3; continue
            raise EmuError(f"unknown movzx modrm {modrm:#x} @ {va:#x}")
        if b == 0x48:  # REX.W prefix group
            b1 = body[i + 1]
            if b1 == 0x39 and body[i + 2] == 0xF2:  # cmp rdx,rsi
                insns[va] = (3, "cmp", ("rdx", "rsi")); i += 3; continue
            if b1 == 0xFF and body[i + 2] == 0xC2:  # inc rdx
                insns[va] = (3, "inc", ("rdx",)); i += 3; continue
            if b1 == 0x89 and body[i + 2] == 0xD1:  # mov rcx,rdx
                insns[va] = (3, "mov", ("rcx", "rdx")); i += 3; continue
            if b1 == 0x89 and body[i + 2] == 0xCA:  # mov rdx,rcx
                insns[va] = (3, "mov", ("rdx", "rcx")); i += 3; continue
            if b1 == 0x89 and body[i + 2] == 0xD7:  # mov rdi,rdx
                insns[va] = (3, "mov", ("rdi", "rdx")); i += 3; continue
            if b1 == 0x89 and body[i + 2] == 0xC2:  # mov rdx,rax
                insns[va] = (3, "mov", ("rdx", "rax")); i += 3; continue
            if b1 == 0xC1 and body[i + 2] == 0xEA:  # shr rdx, imm8
                insns[va] = (4, "shr", ("rdx", body[i + 3])); i += 4; continue
            if b1 == 0xC1 and body[i + 2] == 0xE0:  # shl rax, imm8
                insns[va] = (4, "shl", ("rax", body[i + 3])); i += 4; continue
            if b1 == 0x09 and body[i + 2] == 0xD0:  # or rax,rdx
                insns[va] = (3, "or", ("rax", "rdx")); i += 3; continue
            if b1 == 0x0F and body[i + 2] == 0xA4 and body[i + 3] == 0xC1:  # shld rcx,rax,imm8
                insns[va] = (5, "shld", ("rcx", "rax", body[i + 4])); i += 5; continue
            if b1 == 0x8D and body[i + 2] in (0x05, 0x3D):  # lea r64,[rip+disp32]
                disp = struct.unpack_from("<i", body, i + 3)[0]
                dst = "rax" if body[i + 2] == 0x05 else "rdi"
                insns[va] = (7, "lea", (dst, va + 7 + disp)); i += 7; continue
            raise EmuError(f"unknown 0x48-prefixed op {b1:#x} @ {va:#x}")
        if b == 0xFF and body[i + 1] == 0x15:  # call [rip+disp32]
            disp = struct.unpack_from("<i", body, i + 2)[0]
            slot = va + 6 + disp
            insns[va] = (6, "call", (slot,)); i += 6; continue
        raise EmuError(f"unknown opcode {b:#x} @ {va:#x}")
    return insns


def assert_decode_matches(insns):
    """Assert the decoded stream equals the pinned opcode sequence."""
    got = []
    for va in sorted(insns):
        length, mnem, ops = insns[va]
        got.append((va, _fmt(mnem, ops)))
    if got != EXPECTED_DECODE:
        for (gva, gm), (eva, em) in zip(got, EXPECTED_DECODE):
            if (gva, gm) != (eva, em):
                raise SystemExit(f"decode mismatch @ {gva:#x}: {gm!r} != {em!r}")
        raise SystemExit(f"decode length mismatch: {len(got)} vs {len(EXPECTED_DECODE)}")


def _fmt(mnem, ops):
    if mnem == "push":
        return "push rbx"
    if mnem == "pop":
        return "pop rbx"
    if mnem == "ret":
        return "ret"
    if mnem == "xor":
        return "xor eax,eax"
    if mnem == "mov" and ops == ("ecx", 0):
        return "mov ecx,0x0"
    if mnem == "cmp":
        return "cmp rdx,rsi"
    if mnem == "je":
        return f"je {ops[0]:#x}"
    if mnem == "jae":
        return f"jae {ops[0]:#x}"
    if mnem == "jne":
        return f"jne {ops[0]:#x}"
    if mnem == "movzx" and ops[0] == "ebx":
        return "movzx ebx,byte [rdi+rdx]"
    if mnem == "movzx":
        return "movzx edx,bl"
    if mnem == "inc":
        return "inc rdx"
    if mnem == "call":
        return f"call [rip->got {ops[0]:#x}]"
    if mnem == "mov":
        return f"mov {ops[0]},{ops[1]}"
    if mnem == "shr":
        return f"shr rdx,{ops[1]:#x}"
    if mnem == "shl":
        return f"shl rax,{ops[1]:#x}"
    if mnem == "or":
        return "or rax,rdx"
    if mnem == "shld":
        return f"shld rcx,rax,{ops[2]:#x}"
    if mnem == "lea":
        return f"lea {ops[0]},[rip->{ops[1]:#x}]"
    if mnem == "nop":
        return "nop"
    raise SystemExit(f"unformattable {mnem} {ops}")


def emulate_call(insns, ptr_base, buf, length, index, depth=0):
    """Execute the decoded body as a SysV call: rdi=ptr, rsi=len, rdx=index.

    Returns the u128 value held in rdx:rax on `ret`. Raises EmuBounds/EmuOverflow
    at the two panic call sites, mirroring the real control flow.
    """
    if depth > 4096:
        raise EmuError("runaway recursion")
    reg = {"rax": 0, "rbx": 0, "rcx": 0, "rdx": index & MASK64,
           "rsi": length & MASK64, "rdi": ptr_base & MASK64}
    zf = cf = 0
    va = FUNC_VA
    while True:
        length_i, mnem, ops = insns[va]
        nxt = va + length_i
        if mnem in ("push", "pop", "nop"):
            pass
        elif mnem == "xor":  # xor eax,eax
            reg["rax"] = 0
        elif mnem == "mov":
            dst, src = ops
            if dst == "ecx":
                reg["rcx"] = src & MASK64
            elif dst in ("rcx", "rdx", "rdi"):
                reg[dst] = reg[src]
            else:
                raise EmuError(f"mov dst {dst}")
        elif mnem == "cmp":  # cmp rdx,rsi
            a, b = reg["rdx"], reg["rsi"]
            zf = int(a == b)
            cf = int(a < b)
        elif mnem == "je":
            if zf:
                va = ops[0]; continue
        elif mnem == "jae":
            if not cf:
                va = ops[0]; continue
        elif mnem == "jne":
            if not zf:
                va = ops[0]; continue
        elif mnem == "movzx":
            dst, src = ops
            if dst == "ebx":  # [rdi+rdx]
                off = (reg["rdi"] - ptr_base) + reg["rdx"]
                if off < 0 or off >= len(buf):
                    raise EmuError("emulated OOB read")
                reg["rbx"] = buf[off]
            else:  # edx, bl
                reg["rdx"] = reg["rbx"] & 0xFF
        elif mnem == "inc":  # inc rdx
            reg["rdx"] = (reg["rdx"] + 1) & MASK64
        elif mnem == "call":
            slot = ops[0]
            if slot == GOT_SELF[0]:
                hi, lo = emulate_call(insns, ptr_base, buf, reg["rsi"],
                                      reg["rdx"], depth + 1)
                reg["rdx"], reg["rax"] = hi, lo
            elif slot == GOT_BOUNDS[0]:
                raise EmuBounds(f"slice bounds panic at {va:#x}")
            elif slot == GOT_OVERFLOW[0]:
                raise EmuOverflow(f"overflow panic at {va:#x}")
            else:
                raise EmuError(f"unknown call slot {slot:#x}")
        elif mnem == "shr":  # shr rdx, imm
            reg["rdx"] = (reg["rdx"] >> ops[1]) & MASK64
            zf = int(reg["rdx"] == 0)
        elif mnem == "shl":  # shl rax, imm
            reg["rax"] = (reg["rax"] << ops[1]) & MASK64
        elif mnem == "shld":  # shld rcx,rax,imm
            cnt = ops[2]
            reg["rcx"] = ((reg["rcx"] << cnt) | (reg["rax"] >> (64 - cnt))) & MASK64
        elif mnem == "or":  # or rax,rdx
            reg["rax"] = (reg["rax"] | reg["rdx"]) & MASK64
        elif mnem == "lea":
            pass  # loc-descriptor address; only feeds a panic call
        elif mnem == "ret":
            return reg["rdx"], reg["rax"]
        else:
            raise EmuError(f"unhandled {mnem} @ {va:#x}")
        va = nxt


def emulate_fold(insns, buf):
    """Emulate fold(ptr, len, 0) over `buf`; returns the u128 value."""
    hi, lo = emulate_call(insns, 0, buf, len(buf), 0)
    return (hi << 64) | lo


# ---------------------------------------------------------------------------
# Pure-Python recurrence model (a reading of the disassembly).
# ---------------------------------------------------------------------------
def model_fold(buf, i=0, shift=True, overflow_check=True):
    """Pure-Python model of the decoded recursive body.

    fold(i) = 0                       if i == len
            = panic_bounds            if i >  len   (unreachable via index 0)
            = panic_overflow          if fold(i+1) >= 2**120   (overflow_check)
            = (fold(i+1) << 8) | buf[i]                        otherwise

    `shift=False` drops the <<8; `overflow_check=False` removes the guard.
    """
    n = len(buf)
    if i == n:
        return 0
    if i > n:
        raise IndexError("slice bounds")
    rest = model_fold(buf, i + 1, shift=shift, overflow_check=overflow_check)
    if overflow_check and rest >= LIMIT_2_120:
        raise OverflowError("shl-by-8 would overflow u128")
    if shift:
        acc = ((rest << 8) | buf[i]) & (U128 - 1)
    else:
        acc = (rest | buf[i]) & (U128 - 1)
    return acc


def ref_le_pack(buf):
    """INDEPENDENT little-endian pack of buf[0..] into a u128 integer."""
    return int.from_bytes(bytes(buf), "little")


def ref_be_pack(buf):
    return int.from_bytes(bytes(buf), "big")


def classify(buf):
    """Reference oracle: does the little-endian pack fit in 128 bits?

    Panic iff any byte at index >= 16 is nonzero (value >= 2**128); otherwise
    it returns the full little-endian value. This is value-dependent, not a
    fixed length cut-off.
    """
    if any(buf[k] for k in range(16, len(buf))):
        return ("panic", None)
    return ("ok", ref_le_pack(buf))


# ---------------------------------------------------------------------------
# Grid. Includes the value-dependent domain vectors the review asked for.
# ---------------------------------------------------------------------------
GRID = [
    b"",                                    # empty -> 0
    b"\x41",                                # 1 byte
    b"\x41\x42",                            # 2 bytes
    b"HLP-node",                            # 8 bytes
    bytes(range(1, 16)),                    # 15 bytes
    bytes(range(1, 17)),                    # 16 bytes (max that always fits)
    b"\x00\xff\x00\xff\x00\xff\x00\xff",    # 0x00 and 0xff
    b"\xff" * 16,                           # all 0xff, exactly 128 bits
    b"\x00" * 16,                           # all zero
    b"a\x00b",                              # interior NUL
    bytes(range(1, 17)) + b"\x00",          # 17 bytes, LAST byte 0 -> fits, NO panic
    bytes(16) + b"\x00",                    # 17 bytes, all zero -> fits, NO panic
    b"\x00" * 20,                           # 20 bytes all zero -> fits, NO panic
    bytes(15) + b"\x07\x00\x00\x00",        # 19 bytes, nonzero only at idx 15 -> fits
]

# Inputs that MUST panic (a byte at index >= 16 is nonzero).
PANIC_GRID = [
    bytes(range(1, 18)),                    # 17 bytes, 0x11 at idx 16 -> panic
    bytes(range(1, 17)) + b"\x01",          # 17 bytes, 0x01 at idx 16 -> panic
    bytes(16) + b"\x01",                    # 17 bytes, zero prefix, 0x01 at 16 -> panic
    b"\xff" * 17,                           # 17 x 0xff -> panic
    bytes(18) + b"\x05",                    # 19 bytes, nonzero at idx 18 -> panic
]


def main():
    data = read(BIN)
    authenticate(data)  # identity gate BEFORE any other byte interpretation

    secs = sections(data)
    text = next(s for s in secs if s[0] == ".text")
    _, _, text_va, text_off, _ = text

    def foff(va):
        return va - text_va + text_off

    body = data[foff(FUNC_VA):foff(FUNC_END)]
    if len(body) != FUNC_LEN:
        raise SystemExit(f"body length {len(body)} != {FUNC_LEN}")
    body_sha = hashlib.sha256(body).hexdigest()
    if body_sha != FUNC_SHA256:
        raise SystemExit(f"body sha mismatch: {body_sha}")

    relocs = relocations(data, secs)
    check_relative(relocs, *GOT_SELF, "self/recursion")
    check_relative(relocs, *GOT_BOUNDS, "bounds panic")
    check_relative(relocs, *GOT_OVERFLOW, "overflow panic")

    fs = data[va_to_off(secs, FILE_STR_VA):va_to_off(secs, FILE_STR_VA) + len(FILE_STR)]
    if fs != FILE_STR:
        raise SystemExit(f"file string mismatch: {fs!r}")

    locs = {}
    for va, want in ((LOC_BOUNDS_VA, (52, 9)), (LOC_OVERFLOW_VA, (52, 28))):
        ptr, length, line, col = decode_loc(data, secs, relocs, va)
        if ptr != FILE_STR_VA or length != len(FILE_STR):
            raise SystemExit(f"loc {hex(va)}: ptr/len {hex(ptr)}/{length}")
        if (line, col) != want:
            raise SystemExit(f"loc {hex(va)}: {line}:{col} != {want[0]}:{want[1]}")
        locs[va] = (line, col)

    # --- Decode the real body bytes and assert the exact opcode sequence. ---
    insns = decode(body)
    assert_decode_matches(insns)
    decoded_bytes = sum(insns[va][0] for va in insns)
    if decoded_bytes != FUNC_LEN:
        raise SystemExit(f"decode covered {decoded_bytes} != {FUNC_LEN} bytes")

    # --- Emulate the decoded body; it is the ground truth. ----------------
    emu_agree = 0
    for buf in GRID:
        emu = emulate_fold(insns, buf)         # emulated binary
        mod = model_fold(buf)                  # recurrence model
        ref = ref_le_pack(buf)                 # independent LE pack
        formula = sum(b << (8 * k) for k, b in enumerate(buf))
        if not (emu == mod == ref == formula):
            raise SystemExit(f"emu/model/LE disagree buf={buf!r}: "
                             f"emu={emu:#x} mod={mod:#x} ref={ref:#x}")
        # cross-check the value-dependent oracle too
        kind, val = classify(buf)
        if kind != "ok" or val != emu:
            raise SystemExit(f"classify disagreement buf={buf!r}")
        emu_agree += 1

    # --- Value-dependent overflow domain: emulated body and model agree ---
    #     on WHICH inputs panic. 17 bytes with last byte 0 does NOT panic.
    for buf in PANIC_GRID:
        kind, _ = classify(buf)
        if kind != "panic":
            raise SystemExit(f"PANIC_GRID oracle wrong buf={buf!r}")
        emu_panicked = model_panicked = False
        try:
            emulate_fold(insns, buf)
        except EmuOverflow:
            emu_panicked = True
        try:
            model_fold(buf)
        except OverflowError:
            model_panicked = True
        if not (emu_panicked and model_panicked):
            raise SystemExit(f"expected panic not raised buf={buf!r}: "
                             f"emu={emu_panicked} model={model_panicked}")

    # The pivotal value-dependence case, asserted explicitly:
    fits_17 = bytes(range(1, 17)) + b"\x00"   # last byte 0 -> fits
    over_17 = bytes(range(1, 17)) + b"\x01"   # byte at idx 16 nonzero -> panics
    if emulate_fold(insns, fits_17) != ref_le_pack(fits_17):
        raise SystemExit("17B last-byte-0 should fold without panic")
    try:
        emulate_fold(insns, over_17)
        raise SystemExit("17B nonzero-at-16 should panic")
    except EmuOverflow:
        pass

    # Bounds path: feed index > len directly; emulated body must panic exactly
    # where the model raises IndexError (the jae edge).
    emu_b = mod_b = False
    try:
        emulate_call(insns, 0, b"abc", 3, 5)   # index 5 > len 3
    except EmuBounds:
        emu_b = True
    try:
        model_fold(b"abc", i=5)
    except IndexError:
        mod_b = True
    if not (emu_b and mod_b):
        raise SystemExit(f"bounds edge mismatch: emu={emu_b} model={mod_b}")

    # --- Model-only negative controls (semantics) -------------------------
    controls = {}
    be_div = any(ref_be_pack(b) != model_fold(b) for b in GRID
                 if len(b) >= 2 and len(set(b)) > 1)
    if not be_div:
        raise SystemExit("CONTROL big-endian failed to diverge")
    controls["big-endian pack != little-endian decode"] = True

    noshift_div = any(model_fold(b, shift=False) != model_fold(b) for b in GRID
                      if len(b) >= 2 and len(set(b)) > 1)
    if not noshift_div:
        raise SystemExit("CONTROL drop-shift failed to diverge")
    controls["drop <<8 (OR only) != little-endian decode"] = True

    # --- Reproducible byte-patch controls: patch the body IN MEMORY and ----
    #     re-emulate the patched body (same interpreter).
    patch_notes = []

    # (1) jne (75) -> je (74) at 0x15472d3. Inverts the overflow guard: the
    #     branch now fires on the (hi>>56)==0 (normal) case, so a small input
    #     that folds cleanly on the real body instead takes the overflow stub.
    p1 = bytearray(body)
    off_jne = 0x15472D3 - FUNC_VA
    assert p1[off_jne] == 0x75, "control-1 anchor"
    p1[off_jne] = 0x74
    insns1 = decode(bytes(p1))
    small = b"\x41\x42"                         # folds to 0x4241 on the real body
    if emulate_fold(insns, small) != ref_le_pack(small):
        raise SystemExit("CONTROL-1 precondition: real body should fold 'AB'")
    now_panics = False
    try:
        emulate_fold(insns1, small)            # patched body: guard inverted
    except EmuOverflow:
        now_panics = True
    if not now_panics:
        raise SystemExit("CONTROL jne->je: patched body did not invert the guard")
    controls["patch jne->je @0x15472d3: guard inverted, 'AB' now panics (re-emulated)"] = True
    patch_notes.append("control-1-jne-to-je.objdump.txt")

    # (2) shld rcx,rax,0x8 (48 0f a4 c1 08) -> 5x nop at 0x15472d8. Removes the
    #     high-limb carry; packing no longer reaches the high 64 bits, so any
    #     input wider than 8 bytes diverges from the little-endian pack.
    p2 = bytearray(body)
    off_shld = 0x15472D8 - FUNC_VA
    assert p2[off_shld:off_shld + 5] == b"\x48\x0f\xa4\xc1\x08", "control-2 anchor"
    p2[off_shld:off_shld + 5] = b"\x90\x90\x90\x90\x90"
    insns2 = decode(bytes(p2))
    wide = bytes(range(1, 16))  # 15 bytes -> needs the high limb
    patched_val = emulate_fold(insns2, wide)
    if patched_val == ref_le_pack(wide) or patched_val >> 64 != 0:
        raise SystemExit("CONTROL shld->nop did not drop the high limb")
    # low 64 bits are still the low-limb pack; the high limb is gone.
    if patched_val != (ref_le_pack(wide) & MASK64):
        raise SystemExit("CONTROL shld->nop low-limb mismatch")
    controls["patch shld->nop @0x15472d8: high limb lost (re-emulated)"] = True
    patch_notes.append("control-2-shld-to-nop.objdump.txt")

    # Report -------------------------------------------------------------
    print(f"binary_sha256       {BIN_SHA256}  OK")
    print(f"binary_size         {len(data)}  OK")
    print(f"func {hex(FUNC_VA)}..{hex(FUNC_END)} ({FUNC_LEN}B) sha {body_sha}  OK")
    print(f"decode              {len(insns)} insns, {decoded_bytes}/{FUNC_LEN} bytes, opcode sequence OK")
    print(f"GOT self     {hex(GOT_SELF[0])} -> {hex(GOT_SELF[1])}  RELATIVE OK")
    print(f"GOT bounds   {hex(GOT_BOUNDS[0])} -> {hex(GOT_BOUNDS[1])}  RELATIVE OK")
    print(f"GOT overflow {hex(GOT_OVERFLOW[0])} -> {hex(GOT_OVERFLOW[1])}  RELATIVE OK")
    print(f"loc {hex(LOC_BOUNDS_VA)}   {FILE_STR.decode()}:{locs[LOC_BOUNDS_VA][0]}:{locs[LOC_BOUNDS_VA][1]}  OK")
    print(f"loc {hex(LOC_OVERFLOW_VA)}   {FILE_STR.decode()}:{locs[LOC_OVERFLOW_VA][0]}:{locs[LOC_OVERFLOW_VA][1]}  OK")
    print(f"emulated==model==LE {emu_agree}/{len(GRID)} vectors  OK")
    print(f"value-dependent domain: 17B last-byte-0 folds; 17B nonzero@16 panics (emu & model)  OK")
    print(f"panic-grid agree    {len(PANIC_GRID)}/{len(PANIC_GRID)} inputs panic (emu & model)  OK")
    print(f"bounds edge         index>len panics in emulated body & model  OK")
    for name in controls:
        print(f"control             {name}  OK")
    for note in patch_notes:
        print(f"control artifact    {note} is the static-disasm view of this in-memory patch")
    print("RESULT: PASS")


if __name__ == "__main__":
    sys.exit(main())
