#!/usr/bin/env python3
"""Static verification for the node #115 short-string -> u128 fold leaf at 0x15472b0.

This script performs NO execution of the captured binary. It never copies,
relocates, or writes the capture. It:

  1. authenticates the captured ELF by SHA-256 BEFORE any other byte
     interpretation;
  2. pins the 89-byte body length and body SHA-256 of the leaf;
  3. confirms the three GOT slots referenced by the body resolve through
     R_X86_64_RELATIVE (type 8) relocations to the recovered addends
     (self 0x15472b0, bounds panic 0x1680cbf, overflow panic 0x1681dc0);
  4. confirms the two panic location descriptors decode to
     base/src/short_string.rs 52:9 and 52:28, with the file-name string at
     0x435643;
  5. models the decoded recursive fold in pure Python and checks it, bit-exact,
     against an INDEPENDENT little-endian pack (int.from_bytes(buf, 'little'))
     over a boundary grid (0, 1, 2, 8, 15, 16 bytes; 0x00 / 0xff / ascending);
  6. runs negative controls (big-endian pack, drop-the-shift, drop the overflow
     check) that MUST diverge from little-endian pack or take the panic path.

The model is a reading of the disassembly, not a claim of byte equivalence to
any particular public source revision. No PC/register/memory state of the
capture is advanced.
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

# GOT slots dereferenced by the three `call`/recursion sites and their
# R_X86_64_RELATIVE target addends (recovered from .rela.dyn).
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
# Decoded algorithm model.
# ---------------------------------------------------------------------------
U128 = 1 << 128
LIMIT_2_120 = 1 << 120  # (hi >> 56) != 0  <=>  acc >= 2**120


def model_fold(buf, i=0, shift=True, overflow_check=True):
    """Pure-Python model of the decoded recursive leaf.

    fold(i) = 0                       if i == len
            = panic_bounds            if i >  len   (unreachable via this entry)
            = panic_overflow          if fold(i+1) >= 2**120   (overflow_check)
            = (fold(i+1) << 8) | buf[i]                        otherwise

    `shift=False` drops the <<8 (OR successive bytes); `overflow_check=False`
    removes the >=2**120 guard. Returns the u128 value, or raises OverflowError
    to model the panic edge.
    """
    n = len(buf)
    if i == n:
        return 0
    if i > n:
        raise IndexError("slice bounds")  # models the bounds panic
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


# ---------------------------------------------------------------------------
GRID = [
    b"",                                   # empty -> 0
    b"\x41",                               # 1 byte
    b"\x41\x42",                           # 2 bytes
    b"HLP-node",                           # 8 bytes
    bytes(range(1, 16)),                   # 15 bytes, ascending 0x01..0x0f
    bytes(range(1, 17)),                   # 16 bytes, ascending 0x01..0x10 (max)
    b"\x00\xff\x00\xff\x00\xff\x00\xff",   # includes 0x00 and 0xff
    b"\xff" * 16,                          # all 0xff, max width
    b"\x00" * 16,                          # all zero
    b"a\x00b",                             # interior NUL
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

    # File-name string the two descriptors share.
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

    # Positive grid: decoded model == independent little-endian pack, bit-exact.
    agree = 0
    total = 0
    for buf in GRID:
        total += 1
        got = model_fold(buf)
        ref = ref_le_pack(buf)
        if got != ref:
            raise SystemExit(f"LE mismatch buf={buf!r}: {got:#x} != {ref:#x}")
        # Also assert the byte-formula directly: b0 | b1<<8 | ...
        formula = sum(b << (8 * k) for k, b in enumerate(buf))
        if got != formula:
            raise SystemExit(f"formula mismatch buf={buf!r}")
        agree += 1

    # Negative controls --------------------------------------------------
    controls = {}

    # (a) big-endian pack diverges from the little-endian decode on >=2 bytes.
    be_div = any(ref_be_pack(b) != model_fold(b) for b in GRID if len(b) >= 2
                 and len(set(b)) > 1)
    if not be_div:
        raise SystemExit("CONTROL big-endian failed to diverge")
    controls["big-endian pack != little-endian decode"] = True

    # (b) drop the <<8 (OR bytes together): diverges on multi-byte, multi-value.
    noshift_div = any(model_fold(b, shift=False) != model_fold(b) for b in GRID
                      if len(b) >= 2 and len(set(b)) > 1)
    if not noshift_div:
        raise SystemExit("CONTROL drop-shift failed to diverge")
    controls["drop <<8 (OR only) != little-endian decode"] = True

    # (c) overflow check: 17 bytes MUST panic with the check, and WOULD wrap
    #     (lose the top byte past 128 bits) without it.
    seventeen = bytes(range(1, 18))  # 0x01..0x11, 17 bytes
    panicked = False
    try:
        model_fold(seventeen)
    except OverflowError:
        panicked = True
    if not panicked:
        raise SystemExit("CONTROL overflow: 17 bytes did not panic with the check")
    without = model_fold(seventeen, overflow_check=False)
    full = sum(b << (8 * k) for k, b in enumerate(seventeen))
    if without == full or without >= U128:
        raise SystemExit("CONTROL overflow: dropping the check did not wrap")
    controls["17 bytes: panic with check, silent u128 wrap without"] = True

    # 16-byte max width is the last successful width; 17 is the first panic.
    if model_fold(bytes(range(1, 17))) != ref_le_pack(bytes(range(1, 17))):
        raise SystemExit("16-byte boundary mismatch")

    # Report -------------------------------------------------------------
    print(f"binary_sha256       {BIN_SHA256}  OK")
    print(f"binary_size         {len(data)}  OK")
    print(f"func {hex(FUNC_VA)}..{hex(FUNC_END)} ({FUNC_LEN}B) sha {body_sha}  OK")
    print(f"GOT self     {hex(GOT_SELF[0])} -> {hex(GOT_SELF[1])}  RELATIVE OK")
    print(f"GOT bounds   {hex(GOT_BOUNDS[0])} -> {hex(GOT_BOUNDS[1])}  RELATIVE OK")
    print(f"GOT overflow {hex(GOT_OVERFLOW[0])} -> {hex(GOT_OVERFLOW[1])}  RELATIVE OK")
    print(f"loc {hex(LOC_BOUNDS_VA)}   {FILE_STR.decode()}:{locs[LOC_BOUNDS_VA][0]}:{locs[LOC_BOUNDS_VA][1]}  OK")
    print(f"loc {hex(LOC_OVERFLOW_VA)}   {FILE_STR.decode()}:{locs[LOC_OVERFLOW_VA][0]}:{locs[LOC_OVERFLOW_VA][1]}  OK")
    print(f"LE-pack agreements  {agree}/{total}  OK")
    for name in controls:
        print(f"control diverges    {name}  OK")
    print("RESULT: PASS")


if __name__ == "__main__":
    sys.exit(main())
