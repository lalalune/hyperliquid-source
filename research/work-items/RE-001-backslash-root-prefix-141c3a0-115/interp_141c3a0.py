r"""Independent byte-level oracle for node #115 routine 0x141c3a0.

This module does NOT read the model
(tools/backslash_root_prefix_141c3a0_115.py). It instead reads the
51 raw instruction bytes for virtual address 0x141c3a0 directly out
of the ELF file (mapping vaddr -> file offset through the program
headers), decodes ONLY the opcodes this routine actually contains,
executes them with honest x86 flag semantics over a synthetic byte
buffer, and returns the ``al`` byte the routine would leave. It is a
second, mechanically-independent witness for the hand-written model:
the model is a reading of the disassembly; this is an execution of
the bytes.

Decoded opcode set (exactly the instructions present in the routine):

    48 85 f6                 test  %rsi,%rsi
    74 cb / 7c cb / 77 cb    je / jl / ja  rel8
    b0 ib                    mov   $imm8,%al
    80 3f ib                 cmpb  $imm8,(%rdi)
    80 7f disp8 ib           cmpb  $imm8,disp8(%rdi)
    48 83 fe ib              cmp   $imm8,%rsi   (imm8 sign-extended)
    31 c0                    xor   %eax,%eax
    c3                       ret
    66 81 7f disp8 iw        cmpw  $imm16,disp8(%rdi)
    0f 94 c0                 sete  %al

Any other opcode raises ``UnknownOpcode``. Two extra conditional
jumps (7d jge, 73 jae) are recognised ONLY when ``allow_patched_jcc``
is set; the corruption controls use that to demonstrate genuine
semantic divergence from a patched routine rather than a decode
crash. The unpatched oracle never sees them.

Flag model (standard x86):
  * cmp computes ``a - b`` at the operand width; ZF=(a==b),
    CF=(a<b unsigned borrow), SF=sign bit of the result,
    OF=signed overflow of the subtraction.
  * ``test r,r`` sets ZF=(r==0), SF=sign bit, clears OF and CF.
  * jl=(SF!=OF), je=ZF, ja=(CF==0 and ZF==0); plus jge=(SF==OF) and
    jae=(CF==0) under ``allow_patched_jcc``.

Reads through the buffer are recorded; a read of an index >= the
supplied length raises ``OutOfBounds`` -- the routine is claimed
never to do this, so for every in-length buffer the oracle must
stay in bounds. That doubles as the proof of the
"never reads index >= 4 / byte[3] only when len>3" claims: the set
of indices the oracle touches is returned alongside ``al``.
"""

import struct
import sys
from pathlib import Path

BASE_VADDR = 0x141C3A0
ROUTINE_SIZE = 51  # FDE 0x141c3a0..0x141c3d3


class UnknownOpcode(Exception):
    """Raised when the decoder meets a byte sequence it does not model."""


class OutOfBounds(Exception):
    """Raised when execution reads a buffer index >= the supplied length."""

    def __init__(self, index, length):
        super().__init__("read index %d of a length-%d buffer" % (index, length))
        self.index = index
        self.length = length


def _default_binary():
    root = Path(__file__).resolve().parent.parents[2]
    artifact = root / "artifacts" / "node" / "115" / "hl-node"
    if artifact.is_file() and artifact.stat().st_size > 1 << 20:
        return artifact
    return root / "work" / "hl-node-115.bin"


def read_routine_bytes(path=None, vaddr=BASE_VADDR, size=ROUTINE_SIZE):
    """Return ``size`` bytes at ``vaddr``, mapped via ELF program headers.

    Parses only what is needed from a little-endian ELF64 file: the
    program-header table, then the single PT_LOAD segment whose
    file-backed virtual range covers ``vaddr``. No external tools.
    """
    if path is None:
        path = _default_binary()
    data = Path(path).read_bytes()
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file: %s" % path)
    if data[4] != 1 and data[4] != 2:
        raise ValueError("unexpected EI_CLASS")
    if data[4] != 2:
        raise ValueError("expected ELF64")
    if data[5] != 1:
        raise ValueError("expected little-endian ELF")
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    PT_LOAD = 1
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type != PT_LOAD:
            continue
        p_offset = struct.unpack_from("<Q", data, off + 0x08)[0]
        p_vaddr = struct.unpack_from("<Q", data, off + 0x10)[0]
        p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
        if p_vaddr <= vaddr and vaddr + size <= p_vaddr + p_filesz:
            file_off = p_offset + (vaddr - p_vaddr)
            return data[file_off:file_off + size]
    raise ValueError("no PT_LOAD segment covers vaddr %#x" % vaddr)


# --- flag helpers -----------------------------------------------------------

def _sub_flags(a, b, bits):
    """Flags (ZF, SF, OF, CF) for ``a - b`` at ``bits`` width.

    ``a`` and ``b`` are non-negative operand values (already the
    unsigned bit pattern at that width).
    """
    mask = (1 << bits) - 1
    a &= mask
    b &= mask
    res = (a - b) & mask
    sign = 1 << (bits - 1)
    zf = res == 0
    cf = a < b                      # unsigned borrow
    sf = bool(res & sign)
    sa = bool(a & sign)
    sb = bool(b & sign)
    sr = sf
    of = (sa != sb) and (sa != sr)  # signed overflow of subtraction
    return zf, sf, of, cf


# --- interpreter ------------------------------------------------------------

def run(code, buf, allow_patched_jcc=False):
    """Execute ``code`` over buffer ``buf`` (rsi = len(buf)); return (al, reads).

    ``reads`` is the sorted set of buffer indices the routine touched.
    Raises ``OutOfBounds`` on an index >= len(buf) and ``UnknownOpcode``
    on an unmodelled byte sequence.
    """
    rsi = len(buf)
    al = 0
    zf = sf = of = cf = False
    reads = set()
    ip = 0  # offset within the routine blob

    def read_byte(disp):
        idx = disp
        if idx >= rsi or idx < 0:
            raise OutOfBounds(idx, rsi)
        reads.add(idx)
        return buf[idx]

    steps = 0
    while True:
        steps += 1
        if steps > 10000:
            raise RuntimeError("interpreter did not halt")
        op = code[ip]

        # test %rsi,%rsi   (48 85 f6)
        if op == 0x48 and code[ip + 1] == 0x85 and code[ip + 2] == 0xF6:
            zf = rsi == 0
            sf = bool(rsi & (1 << 63))
            of = False
            cf = False
            ip += 3
            continue

        # cmp $imm8,%rsi   (48 83 fe ib) -- imm8 sign-extended to 64
        if op == 0x48 and code[ip + 1] == 0x83 and code[ip + 2] == 0xFE:
            imm = code[ip + 3]
            if imm >= 0x80:
                imm -= 0x100
            zf, sf, of, cf = _sub_flags(rsi, imm & ((1 << 64) - 1), 64)
            ip += 4
            continue

        # cmpb $imm8,(%rdi)  (80 3f ib)  /  cmpb $imm8,disp8(%rdi) (80 7f disp8 ib)
        if op == 0x80:
            modrm = code[ip + 1]
            reg = (modrm >> 3) & 7
            if reg != 7:
                raise UnknownOpcode("80 /%d at offset %d" % (reg, ip))
            mod = modrm >> 6
            rm = modrm & 7
            if rm != 7:
                raise UnknownOpcode("80 modrm rm=%d at offset %d" % (rm, ip))
            if mod == 0:
                disp = 0
                imm = code[ip + 2]
                size = 3
            elif mod == 1:
                disp = code[ip + 2]
                imm = code[ip + 3]
                size = 4
            else:
                raise UnknownOpcode("80 modrm mod=%d at offset %d" % (mod, ip))
            mem = read_byte(disp)
            zf, sf, of, cf = _sub_flags(mem, imm, 8)
            ip += size
            continue

        # cmpw $imm16,disp8(%rdi)  (66 81 7f disp8 iw)
        if op == 0x66 and code[ip + 1] == 0x81 and code[ip + 2] == 0x7F:
            disp = code[ip + 3]
            imm = code[ip + 4] | (code[ip + 5] << 8)
            lo = read_byte(disp)
            hi = read_byte(disp + 1)
            mem = lo | (hi << 8)
            zf, sf, of, cf = _sub_flags(mem, imm, 16)
            ip += 6
            continue

        # mov $imm8,%al  (b0 ib)
        if op == 0xB0:
            al = code[ip + 1]
            ip += 2
            continue

        # xor %eax,%eax  (31 c0)
        if op == 0x31 and code[ip + 1] == 0xC0:
            al = 0
            zf = True
            sf = False
            of = False
            cf = False
            ip += 2
            continue

        # sete %al  (0f 94 c0)
        if op == 0x0F and code[ip + 1] == 0x94 and code[ip + 2] == 0xC0:
            al = 1 if zf else 0
            ip += 3
            continue

        # ret (c3)
        if op == 0xC3:
            return al, sorted(reads)

        # conditional short jumps
        if op in (0x74, 0x7C, 0x77) or (allow_patched_jcc and op in (0x7D, 0x73)):
            rel = code[ip + 1]
            if rel >= 0x80:
                rel -= 0x100
            if op == 0x74:        # je
                taken = zf
            elif op == 0x7C:      # jl
                taken = sf != of
            elif op == 0x77:      # ja
                taken = (not cf) and (not zf)
            elif op == 0x7D:      # jge (patched)
                taken = sf == of
            else:                 # 0x73 jae (patched)
                taken = not cf
            ip += 2
            if taken:
                ip += rel
            continue

        raise UnknownOpcode("byte %#02x at offset %d" % (op, ip))


def al_for(buf, path=None, code=None, allow_patched_jcc=False):
    """Convenience: return just the ``al`` byte for ``buf``."""
    if code is None:
        code = read_routine_bytes(path)
    al, _ = run(code, buf, allow_patched_jcc=allow_patched_jcc)
    return al


if __name__ == "__main__":
    blob = read_routine_bytes()
    print("routine bytes (%d):" % len(blob), blob.hex())
    for probe in (b"", b"\\", b"C", b"C:", b"C:\\", b"C:/", b"C:\\a", b"C:\\\x80"):
        try:
            al, reads = run(blob, probe)
            print("%-10r -> al=%d reads=%s" % (probe, al, reads))
        except (OutOfBounds, UnknownOpcode) as exc:
            print("%-10r -> %s" % (probe, exc))
    sys.exit(0)
