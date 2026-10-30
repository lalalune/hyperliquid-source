#!/usr/bin/env python3
"""RE-004: scaling of a 256-bit EVM amount to a core u64 in node #94 (static, no execution).

The function at 0x3281770 takes an i8 exponent in `sil` and a pointer to a little-endian
U256 in `rdx`, and returns (al & 1, rdx) as an Option<u64>:

    k = |e|, as an unsigned byte; 10^k by a checked u64 power; k >= 20 gives None
    e >= 0: quotient = amount / 10^k, floor, remainder dropped
    e <  0: product = amount * 10^k, checked in 256 bits; overflow gives None
    Some(v) only when the upper limbs are zero and the low limb is below 0xccccccccccccccc

This tool bounds the function and its two ruint helpers with their FDEs, reads them with
objdump and interprets the real instructions in a small Python x86-64 evaluator.  Nothing
from the binary runs natively.  The evaluator stops on an unmodelled mnemonic, a read of
an unset register, flag or stack byte, a call to an unknown target, or any write outside
its own RAM.

    python3 tools/evm_amount_scale.py --out <dir>

writes evidence.json, exponent-table.tsv, boundaries.tsv and function-bytes.txt.  Only the
Python standard library and GNU objdump are used.
"""

import argparse
import bisect
import hashlib
import json
import re
import struct
import subprocess
import sys
from functools import partial
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gnu_binutils import gnu_objdump  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK = (1 << 64) - 1
U256 = 1 << 256
SEED = b'RE-004-evm-amount-scale-94'
SIZES = {'BYTE': 1, 'WORD': 2, 'DWORD': 4, 'QWORD': 8, 'XMMWORD': 16}

SCALE = 0x3281770
SCALE_END = 0x328195c
DIV_HELPER = 0x32d6ad0
MUL_HELPER = 0x32d7e40
LADDER_DONE = 0x3281828          # first instruction after the power ladder
ZERO_EXPONENT = 0x328187f        # e == 0 stores the literal 1 here and skips the ladder
CAP = 0xccccccccccccccc
CAP_INSN = 0x328191e
CALL_DIV = 0x3281901
CALL_MUL = 0x3281859
PANIC_LEA = 0x3281943
PANIC_LOCATION = 0x56dfb58
PANIC_TEXT = 0x2048d0
RUINT_PATH = b'ruint-1.12.3/src/div.rs'
TOKEN_EXP_OFFSET = 0xd1
TOKEN_FLAG_OFFSET = 0xbc
RECORD_STRIDE = 0xe8
NATIVE_ADDRESS_A, NATIVE_ADDRESS_B = 0x203c60, 0x203fc0
SITES = {0x342753a: 'native', 0x342782e: 'map', 0x3baf539: 'token', 0x3baf779: 'token'}
CALLERS = (0x34273d0, 0x3baedf0)
LADDER_CONSTANTS = {0x3281799: 10, 0x32817ad: 100, 0x32817c4: 10_000, 0x32817de: 100_000_000,
                    0x32817ff: 10 ** 16}

RET_MAGIC = 0x7fff0000
MEMSET_STUB, MEMCPY_STUB = 0x7fff0010, 0x7fff0020
RAM_BASE, RAM_SIZE = 0x7000000, 0x10000
STACK_TOP = RAM_BASE + 0xf000 - 8    # entry rsp + 8 is 16-aligned, as the ABI requires
BUFFER = RAM_BASE + 0x100
DIVISOR_SLOT = STACK_TOP - 8 - 0x40  # rsp inside the function: push rbx, then sub rsp,0x40

REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
REGS = {name: (i, 8) for i, name in enumerate(REG64)}
for i, name in enumerate(['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
                          'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']):
    REGS[name] = (i, 4)
for i, name in enumerate(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
                          'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']):
    REGS[name] = (i, 2)
for i, name in enumerate(['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
                          'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']):
    REGS[name] = (i, 1)


class EvidenceError(Exception):
    pass


class Unmodelled(Exception):
    pass


def check_digest(data, expected=SHA256):
    got = hashlib.sha256(data).hexdigest()
    if got != expected:
        raise EvidenceError(f'sha256 mismatch: {got} != {expected}')
    return got


# ------------------------------------------------------------------- ELF / FDE

def sections(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise EvidenceError('not an ELF64 little-endian file')
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    raw = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    stroff = raw[shstrndx][4]
    out = {}
    for name, _typ, _flags, addr, off, size, *_ in raw:
        end = data.index(b'\0', stroff + name)
        out[data[stroff + name:end].decode()] = (addr, off, size)
    return out


class Image:
    def __init__(self, data):
        self.data = data
        self.sec = sections(data)

    def off(self, va, size=1):
        for addr, off, sz in self.sec.values():
            if addr and addr <= va and va + size <= addr + sz:
                return off + va - addr
        raise EvidenceError(f'VA {va:#x} is outside every allocated section')

    def read(self, va, size):
        o = self.off(va, size)
        return self.data[o:o + size]

    def text(self):
        addr, off, size = self.sec['.text']
        return addr, self.data[off:off + size]

    def in_rodata(self, va, size):
        addr, _, sz = self.sec['.rodata']
        return addr <= va and va + size <= addr + sz

    def slots(self):
        """GOT contents after load: RELATIVE addends, plus the two libc symbols the helpers use."""
        _, off, size = self.sec['.rela.dyn']
        _, sym_off, _ = self.sec['.dynsym']
        _, str_off, _ = self.sec['.dynstr']
        got = self.sec['.got']
        stubs = {b'memset': MEMSET_STUB, b'memcpy': MEMCPY_STUB}
        out = {}
        for where, info, addend in struct.iter_unpack('<QQq', self.data[off:off + size]):
            typ, sym = info & 0xffffffff, info >> 32
            if not got[0] <= where < got[0] + got[2]:
                continue
            if typ == 8:
                out[where] = addend & MASK
            elif typ == 6:
                n = struct.unpack_from('<I', self.data, sym_off + sym * 24)[0]
                name = self.data[str_off + n:self.data.index(b'\0', str_off + n)]
                if name in stubs:
                    out[where] = stubs[name]
        return out

    def relative_relocs(self):
        _, off, size = self.sec['.rela.dyn']
        return {where: addend for where, info, addend in
                struct.iter_unpack('<QQq', self.data[off:off + size]) if info & 0xffffffff == 8}


def uleb(buf, i):
    val = shift = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7f) << shift
        shift += 7
        if b < 0x80:
            return val, i


def read_enc(img, va, enc):
    size, code = {0x03: (4, '<I'), 0x0b: (4, '<i'), 0x04: (8, '<Q'), 0x0c: (8, '<q')}[enc & 0x0f]
    val = struct.unpack(code, img.read(va, size))[0]
    if enc & 0x70 == 0x10:
        val += va
    elif enc & 0x70 != 0x00:
        raise EvidenceError(f'unsupported pointer encoding {enc:#x}')
    return val & MASK, size


class Fdes:
    """Binary-search table from .eh_frame_hdr; ranges from each FDE body."""

    def __init__(self, img):
        self.img = img
        hdr = img.sec['.eh_frame_hdr'][0]
        version, ptr_enc, cnt_enc, tbl_enc = img.read(hdr, 4)
        if (version, cnt_enc, tbl_enc) != (1, 0x03, 0x3b):
            raise EvidenceError('unexpected .eh_frame_hdr encodings')
        _, n = read_enc(img, hdr + 4, ptr_enc)
        count = struct.unpack('<I', img.read(hdr + 4 + n, 4))[0]
        table = img.read(hdr + 8 + n, count * 8)
        self.starts, self.fde = [], []
        for i in range(count):
            loc, fde = struct.unpack_from('<ii', table, i * 8)
            self.starts.append(hdr + loc)
            self.fde.append(hdr + fde)
        self.count = count

    def cie_r_encoding(self, cie):
        body = self.img.read(cie + 4, 64)
        if struct.unpack_from('<I', body, 0)[0] != 0:
            raise EvidenceError('CIE id is not zero')
        version = body[4]
        end = body.index(b'\0', 5)
        aug = body[5:end].decode()
        i = end + 1
        _, i = uleb(body, i)
        _, i = uleb(body, i)
        if version == 1:
            i += 1
        else:
            _, i = uleb(body, i)
        if not aug.startswith('z'):
            raise EvidenceError('CIE without z augmentation')
        _, i = uleb(body, i)
        for ch in aug[1:]:
            if ch == 'R':
                return body[i]
            if ch == 'L':
                i += 1
            elif ch == 'P':
                penc = body[i]
                i += 1 + {0x03: 4, 0x0b: 4, 0x04: 8, 0x0c: 8}[penc & 0x0f]
            else:
                raise EvidenceError(f'unsupported augmentation {aug!r}')
        raise EvidenceError('CIE has no R augmentation')

    def range_of(self, va):
        k = bisect.bisect_right(self.starts, va) - 1
        if k < 0:
            raise EvidenceError(f'{va:#x} precedes every FDE')
        fde = self.fde[k]
        cie_ptr = struct.unpack('<I', self.img.read(fde + 4, 4))[0]
        enc = self.cie_r_encoding(fde + 4 - cie_ptr)
        begin, n = read_enc(self.img, fde + 8, enc)
        length, _ = read_enc(self.img, fde + 8 + n, enc & 0x0f)
        if begin != self.starts[k]:
            raise EvidenceError(f'FDE {fde:#x} pc_begin disagrees with .eh_frame_hdr')
        if not begin <= va < begin + length:
            raise EvidenceError(f'{va:#x} is outside FDE [{begin:#x},{begin + length:#x})')
        return {'start': begin, 'end': begin + length, 'fde': fde}


# ------------------------------------------------------------ instruction reader

def disassemble(binary, start, end):
    objdump, why = gnu_objdump()
    if objdump is None:
        raise EvidenceError(f'{why}; the listing parser reads GNU objdump Intel syntax only')
    cmd = [objdump, '-d', '-M', 'intel', '--no-show-raw-insn',
           f'--start-address={start:#x}', f'--stop-address={end:#x}', str(binary)]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


LINE_RE = re.compile(r'^\s*([0-9a-f]+):\t(.*)$')
MEM_RE = re.compile(r'^(?:(BYTE|WORD|DWORD|QWORD|XMMWORD) PTR )?\[(.*)\]$')
HEX_RE = re.compile(r'0x[0-9a-f]+')
SHIFTS = ('shl', 'shr', 'sar')


def parse_operand(text, comment):
    if text in REGS:
        idx, size = REGS[text]
        return ('r', idx, size)
    if re.fullmatch(r'xmm[0-9]+', text):
        return ('x', int(text[3:]))
    if HEX_RE.fullmatch(text):
        return ('i', int(text, 16))
    m = MEM_RE.match(text)
    if m:
        size = SIZES.get(m.group(1), 8)
        inner = m.group(2)
        if inner.startswith('rip'):
            return ('a', size, comment)
        base = index = None
        scale, disp = 1, 0
        for part in re.findall(r'[+-]?[^+-]+', inner):
            neg = part[0] == '-'
            part = part.lstrip('+-')
            if '*' in part:
                reg, mul = part.split('*')
                index, scale = REGS[reg][0], int(mul)
            elif part in REGS:
                base = REGS[part][0]
            else:
                disp = -int(part, 16) if neg else int(part, 16)
        return ('m', size, base, index, scale, disp)
    if re.fullmatch(r'[0-9a-f]+', text):
        return ('t', int(text, 16))
    raise EvidenceError(f'unparsed operand {text!r}')


def parse_listing(listing):
    """objdump text -> ordered list of (va, mnemonic, operands, next_va)."""
    rows = []
    for line in listing.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        va, body = int(m.group(1), 16), m.group(2).strip()
        comment = None
        if '#' in body:
            body, tail = body.split('#', 1)
            comment = int(tail.split()[0], 16)
        body = re.sub(r'<[^>]*>', '', body).strip()
        if 'nop' in body or body == 'xchg   ax,ax':
            rows.append((va, 'nop', ()))
            continue
        parts = body.split(None, 1)
        mn = parts[0] if parts else 'nop'
        ops = ()
        if len(parts) > 1:
            try:
                ops = tuple(parse_operand(p.strip(), comment) for p in parts[1].split(','))
            except (EvidenceError, KeyError, ValueError):
                mn, ops = 'unparsed', ()         # stops the evaluator only if reached
        if mn in SHIFTS and ops[-1:] == (('t', 1),):
            ops = ops[:-1] + (('i', 1),)
        rows.append((va, mn, ops))
    return [(va, mn, ops, rows[i + 1][0] if i + 1 < len(rows) else None)
            for i, (va, mn, ops) in enumerate(rows)]


# ------------------------------------------------------------------ evaluator

def signed(val, bits):
    return val - (1 << bits) if val >> (bits - 1) else val


class Machine:
    """Byte-accurate integer and SSE-move subset.  Unset state is tracked and never guessed."""

    CC = {'e': lambda s: s.flag('zf'), 'ne': lambda s: not s.flag('zf'),
          'b': lambda s: s.flag('cf'), 'ae': lambda s: not s.flag('cf'),
          'a': lambda s: not (s.flag('cf') or s.flag('zf')), 'be': lambda s: s.flag('cf') or s.flag('zf'),
          's': lambda s: s.flag('sf'), 'ns': lambda s: not s.flag('sf'),
          'o': lambda s: s.flag('of'), 'no': lambda s: not s.flag('of')}

    def __init__(self, insns, img, slots):
        self.img = img
        self.slots = slots
        table = {name[2:]: getattr(self, name) for name in dir(self) if name.startswith('i_')}
        for cc in self.CC:
            table['j' + cc] = partial(self.jcc, cc)
            table['cmov' + cc] = partial(self.cmov, cc)
            table['set' + cc] = partial(self.setcc, cc)
        self.code = {}
        for va, mn, ops, nxt in insns:
            handler = table.get(mn) or partial(self.unknown, mn, va)
            self.code[va] = (handler, ops, nxt)
        self.seen = set()
        self.reset()

    def reset(self):
        self.regs = [0] * 16
        self.known = [0] * 16
        self.xmm = [None] * 16
        self.ram = bytearray(RAM_SIZE)
        self.valid = bytearray(RAM_SIZE)
        self.cf = self.zf = self.sf = self.of = None
        self.steps = 0
        self.pc = None

    # state access

    def setreg(self, idx, val):
        self.regs[idx] = val & MASK
        self.known[idx] = MASK

    def poison(self, *idxs):
        for idx in idxs:
            self.known[idx] = 0

    def flag(self, name):
        val = getattr(self, name)
        if val is None:
            raise Unmodelled(f'read of unset {name} at {self.pc:#x}')
        return val

    def ea(self, op):
        _, _, base, index, scale, disp = op
        val = disp
        if base is not None:
            if self.known[base] != MASK:
                raise Unmodelled(f'unset base at {self.pc:#x}')
            val += self.regs[base]
        if index is not None:
            if self.known[index] != MASK:
                raise Unmodelled(f'unset index at {self.pc:#x}')
            val += self.regs[index] * scale
        return val & MASK

    def load(self, ea, size):
        lo = ea - RAM_BASE
        if 0 <= lo and lo + size <= RAM_SIZE:
            if 0 in self.valid[lo:lo + size]:
                raise Unmodelled(f'read of unset memory {ea:#x}/{size} at {self.pc:#x}')
            return int.from_bytes(self.ram[lo:lo + size], 'little')
        if size == 8 and ea in self.slots:
            return self.slots[ea]
        if self.img.in_rodata(ea, size):
            return int.from_bytes(self.img.read(ea, size), 'little')
        raise Unmodelled(f'read outside the model {ea:#x}/{size} at {self.pc:#x}')

    def store(self, ea, size, val):
        lo = ea - RAM_BASE
        if not (0 <= lo and lo + size <= RAM_SIZE):
            raise Unmodelled(f'write outside RAM {ea:#x} at {self.pc:#x}')
        self.ram[lo:lo + size] = (val & ((1 << (size * 8)) - 1)).to_bytes(size, 'little')
        self.valid[lo:lo + size] = b'\x01' * size

    def rd(self, op):
        kind = op[0]
        if kind == 'r':
            idx, size = op[1], op[2]
            mask = (1 << (size * 8)) - 1
            if self.known[idx] & mask != mask:
                raise Unmodelled(f'read of unset {REG64[idx]} at {self.pc:#x}')
            return self.regs[idx] & mask
        if kind == 'i':
            return op[1]
        if kind == 'm':
            return self.load(self.ea(op), op[1])
        if kind == 'a':
            return self.load(op[2], op[1])
        raise Unmodelled(f'operand {op} at {self.pc:#x}')

    def wr(self, op, val):
        kind = op[0]
        if kind == 'r':
            idx, size = op[1], op[2]
            if size >= 4:
                self.regs[idx] = val & (MASK if size == 8 else 0xffffffff)
                self.known[idx] = MASK
            else:
                mask = (1 << (size * 8)) - 1
                self.regs[idx] = (self.regs[idx] & ~mask) | (val & mask)
                self.known[idx] |= mask
        elif kind == 'm':
            self.store(self.ea(op), op[1], val)
        elif kind == 'a':
            raise Unmodelled(f'write to a static address at {self.pc:#x}')
        else:
            raise Unmodelled(f'write to {op} at {self.pc:#x}')

    def size(self, op):
        return op[2] if op[0] == 'r' else op[1]

    def nz(self, res, bits):
        self.zf = res == 0
        self.sf = bool(res >> (bits - 1))

    # moves

    def i_nop(self, ops):
        pass

    def i_mov(self, ops):
        dst, src = ops
        if dst[0] == 'r' and src[0] == 'r' and dst[2] >= 4:
            self.regs[dst[1]] = self.regs[src[1]] & (MASK if dst[2] == 8 else 0xffffffff)
            self.known[dst[1]] = self.known[src[1]] if dst[2] == 8 else (self.known[src[1]] & 0xffffffff) | ~0xffffffff & MASK
            return
        self.wr(dst, self.rd(src))

    i_movabs = i_mov

    def i_movzx(self, ops):
        self.wr(ops[0], self.rd(ops[1]))

    def i_lea(self, ops):
        dst, src = ops
        self.wr(dst, src[2] if src[0] == 'a' else self.ea(src))

    def i_push(self, ops):
        idx = ops[0][1]
        rsp = self.regs[RSP] - 8
        self.regs[RSP] = rsp
        lo = rsp - RAM_BASE
        self.ram[lo:lo + 8] = self.regs[idx].to_bytes(8, 'little')
        self.valid[lo:lo + 8] = bytes((self.known[idx] >> (8 * i)) & 1 for i in range(8))

    def i_pop(self, ops):
        idx = ops[0][1]
        rsp = self.regs[RSP]
        lo = rsp - RAM_BASE
        self.regs[idx] = int.from_bytes(self.ram[lo:lo + 8], 'little')
        self.known[idx] = sum(0xff << (8 * i) for i in range(8) if self.valid[lo + i])
        self.regs[RSP] = rsp + 8

    # integer arithmetic

    def arith(self, ops, carry_in, subtract, store=True):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        a, b = self.rd(ops[0]), self.rd(ops[1]) & mask
        c = int(self.flag('cf')) if carry_in else 0
        if subtract:
            raw = a - b - c
            res = raw & mask
            self.cf = raw < 0
            self.of = bool((((a ^ b) & (a ^ res)) >> (bits - 1)) & 1)
        else:
            raw = a + b + c
            res = raw & mask
            self.cf = raw > mask
            self.of = bool((((a ^ res) & (b ^ res)) >> (bits - 1)) & 1)
        self.nz(res, bits)
        if store:
            self.wr(ops[0], res)

    def i_add(self, ops):
        self.arith(ops, False, False)

    def i_adc(self, ops):
        self.arith(ops, True, False)

    def i_sub(self, ops):
        self.arith(ops, False, True)

    def i_sbb(self, ops):
        self.arith(ops, True, True)

    def i_cmp(self, ops):
        self.arith(ops, False, True, store=False)

    def logic(self, ops, fn, store=True):
        bits = self.size(ops[0]) * 8
        res = fn(self.rd(ops[0]), self.rd(ops[1]) & ((1 << bits) - 1))
        self.cf = self.of = False
        self.nz(res, bits)
        if store:
            self.wr(ops[0], res)

    def i_and(self, ops):
        self.logic(ops, lambda a, b: a & b)

    def i_or(self, ops):
        self.logic(ops, lambda a, b: a | b)

    def i_xor(self, ops):
        if ops[0] == ops[1] and ops[0][0] == 'r':
            self.wr(ops[0], 0)
            self.cf = self.of = self.sf = False
            self.zf = True
            return
        self.logic(ops, lambda a, b: a ^ b)

    def i_test(self, ops):
        self.logic(ops, lambda a, b: a & b, store=False)

    def i_inc(self, ops):
        bits = self.size(ops[0]) * 8
        res = (self.rd(ops[0]) + 1) & ((1 << bits) - 1)
        self.of = res == 1 << (bits - 1)
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_dec(self, ops):
        bits = self.size(ops[0]) * 8
        a = self.rd(ops[0])
        res = (a - 1) & ((1 << bits) - 1)
        self.of = a == 1 << (bits - 1)
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_neg(self, ops):
        bits = self.size(ops[0]) * 8
        a = self.rd(ops[0])
        res = -a & ((1 << bits) - 1)
        self.cf = a != 0
        self.of = a == 1 << (bits - 1)
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_not(self, ops):
        bits = self.size(ops[0]) * 8
        self.wr(ops[0], ~self.rd(ops[0]) & ((1 << bits) - 1))

    def shift(self, ops, kind):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        count = self.rd(ops[1]) & (63 if bits == 64 else 31)
        if count == 0:
            return
        a = self.rd(ops[0])
        if kind == 'shl':
            raw = a << count
            self.cf = bool((raw >> bits) & 1)
        elif kind == 'shr':
            raw = a >> count
            self.cf = bool((a >> (count - 1)) & 1)
        else:
            sa = signed(a, bits)
            raw = sa >> count
            self.cf = bool((sa >> (count - 1)) & 1)
        res = raw & mask
        self.of = None
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_shl(self, ops):
        self.shift(ops, 'shl')

    def i_shr(self, ops):
        self.shift(ops, 'shr')

    def i_sar(self, ops):
        self.shift(ops, 'sar')

    def i_shld(self, ops):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        count = self.rd(ops[2]) & (63 if bits == 64 else 31)
        if count == 0:
            return
        a, b = self.rd(ops[0]), self.rd(ops[1])
        wide = (a << bits | b) << count
        self.cf = bool((wide >> (2 * bits)) & 1)
        res = (wide >> bits) & mask
        self.of = None
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_shrd(self, ops):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        count = self.rd(ops[2]) & (63 if bits == 64 else 31)
        if count == 0:
            return
        a, b = self.rd(ops[0]), self.rd(ops[1])
        wide = b << bits | a
        self.cf = bool((a >> (count - 1)) & 1)
        res = (wide >> count) & mask
        self.of = None
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_bsr(self, ops):
        src = self.rd(ops[1])
        if src == 0:
            raise Unmodelled(f'bsr of zero at {self.pc:#x}')
        self.zf = False
        self.cf = self.of = self.sf = None
        self.wr(ops[0], src.bit_length() - 1)

    def i_mul(self, ops):
        size = self.size(ops[0])
        bits = size * 8
        lo_op, hi_op = ('r', RAX, size), ('r', RDX, size)
        raw = self.rd(lo_op) * self.rd(ops[0])
        self.wr(lo_op, raw)
        self.wr(hi_op, raw >> bits)
        self.cf = self.of = raw >> bits != 0
        self.zf = self.sf = None

    def i_imul(self, ops):
        bits = self.size(ops[0]) * 8
        if len(ops) == 2:
            a, b = self.rd(ops[0]), self.rd(ops[1])
        elif len(ops) == 3:
            a, b = self.rd(ops[1]), self.rd(ops[2])
        else:
            raise Unmodelled(f'one-operand imul at {self.pc:#x}')
        b &= (1 << bits) - 1
        raw = signed(a, bits) * signed(b, bits)
        res = raw & ((1 << bits) - 1)
        self.cf = self.of = signed(res, bits) != raw
        self.zf = self.sf = None
        self.wr(ops[0], res)

    def i_div(self, ops):
        size = self.size(ops[0])
        bits = size * 8
        lo_op, hi_op = ('r', RAX, size), ('r', RDX, size)
        num = (self.rd(hi_op) << bits) | self.rd(lo_op)
        den = self.rd(ops[0])
        if den == 0 or num // den >> bits:
            raise Unmodelled(f'divide fault at {self.pc:#x}')
        self.wr(lo_op, num // den)
        self.wr(hi_op, num % den)
        self.cf = self.of = self.zf = self.sf = None

    # control flow

    def jcc(self, cc, ops):
        if self.CC[cc](self):
            self.pc = ops[0][1]

    def cmov(self, cc, ops):
        dst, src = ops
        val = self.rd(src)
        if self.CC[cc](self):
            self.wr(dst, val)
        elif dst[2] == 4:
            self.wr(dst, self.rd(dst))

    def setcc(self, cc, ops):
        self.wr(ops[0], int(bool(self.CC[cc](self))))

    def target(self, op):
        return op[1] if op[0] == 't' else self.rd(op)

    def i_jmp(self, ops):
        self.pc = self.target(ops[0])

    def i_call(self, ops):
        dest = self.target(ops[0])
        self.regs[RSP] -= 8
        self.store(self.regs[RSP], 8, self.pc)
        self.pc = dest

    def i_ret(self, ops):
        self.pc = self.load(self.regs[RSP], 8)
        self.regs[RSP] += 8

    # SSE moves

    def xrd(self, op):
        if op[0] == 'x':
            if self.xmm[op[1]] is None:
                raise Unmodelled(f'read of unset xmm at {self.pc:#x}')
            return self.xmm[op[1]]
        return self.rd(op)

    def xwr(self, op, val):
        if op[0] == 'x':
            self.xmm[op[1]] = val
        else:
            self.wr(op, val)

    def i_movups(self, ops):
        self.xwr(ops[0], self.xrd(ops[1]))

    def i_movaps(self, ops):
        for op in ops:
            if op[0] == 'm' and self.ea(op) % 16:
                raise Unmodelled(f'misaligned movaps at {self.pc:#x}')
        self.xwr(ops[0], self.xrd(ops[1]))

    def i_xorps(self, ops):
        if ops[0] != ops[1]:
            raise Unmodelled(f'xorps of distinct operands at {self.pc:#x}')
        self.xmm[ops[0][1]] = 0

    def unknown(self, mn, va, ops):
        raise Unmodelled(f'mnemonic {mn} at {va:#x}')

    # libc stubs

    def after_stub(self, result):
        self.setreg(RAX, result)
        self.poison(RCX, RDX, RSI, RDI, R8, R9, R10, R11)
        self.cf = self.zf = self.sf = self.of = None
        self.i_ret(())

    def memset(self):
        dst, val, n = self.regs[RDI], self.regs[RSI] & 0xff, self.regs[RDX]
        for i in range(n):
            self.store(dst + i, 1, val)
        self.after_stub(dst)

    def memcpy(self):
        dst, src, n = self.regs[RDI], self.regs[RSI], self.regs[RDX]
        for i in range(n):
            self.store(dst + i, 1, self.load(src + i, 1))
        self.after_stub(dst)

    def run(self, entry, stop=(), limit=20000):
        self.pc = entry
        code = self.code
        seen = self.seen
        while True:
            pc = self.pc
            if pc == RET_MAGIC or pc in stop:
                return pc
            if pc == MEMSET_STUB:
                self.memset()
                continue
            if pc == MEMCPY_STUB:
                self.memcpy()
                continue
            ins = code.get(pc)
            if ins is None:
                raise Unmodelled(f'no instruction at {pc:#x}')
            self.steps += 1
            if self.steps > limit:
                raise Unmodelled('step limit')
            seen.add(pc)
            self.pc = ins[2]
            ins[0](ins[1])


def enter(machine, exponent, amount):
    """Fresh state for one call: only sil, rdx, rsp and the amount buffer are set."""
    machine.reset()
    machine.setreg(RSP, STACK_TOP)
    machine.store(STACK_TOP, 8, RET_MAGIC)
    machine.setreg(RSI, exponent & 0xff)
    machine.setreg(RDX, BUFFER)
    machine.store(BUFFER, 32, amount)


def run_scale(machine, exponent, amount):
    """(value or None, the 32 bytes left in the amount buffer)."""
    enter(machine, exponent, amount)
    machine.run(SCALE)
    if machine.regs[RSP] != STACK_TOP + 8:
        raise Unmodelled('unbalanced stack')
    left = machine.load(BUFFER, 32)
    return (machine.regs[RDX] if machine.rd(('r', RAX, 1)) & 1 else None), left


def run_multiply(machine, left, right):
    """The multiply helper alone: (the 256-bit output, overflow flag)."""
    out, operand = RAM_BASE + 0x200, RAM_BASE + 0x300
    enter(machine, 0, left)
    machine.store(out, 32, 0)
    machine.store(operand, 32, right)
    machine.setreg(RDI, out)
    machine.setreg(RSI, 4)
    machine.setreg(RDX, BUFFER)
    machine.setreg(RCX, operand)
    machine.run(MUL_HELPER)
    return machine.load(out, 32), machine.rd(('r', RAX, 1)) & 1


def dead_divisor_slot(machine):
    """The 32 bytes the divide helper left in the caller's divisor buffer after the last run."""
    return machine.load(DIVISOR_SLOT, 32)


def ladder_power(machine, exponent):
    """10^k from the ladder alone, with the amount pointer left unset: None when it exits None."""
    machine.reset()
    machine.setreg(RSP, STACK_TOP)
    machine.store(STACK_TOP, 8, RET_MAGIC)
    machine.setreg(RSI, exponent & 0xff)
    stopped = machine.run(SCALE, stop={LADDER_DONE, ZERO_EXPONENT})
    if stopped == LADDER_DONE:
        return machine.regs[RAX]
    if stopped == ZERO_EXPONENT:
        return 1
    if machine.rd(('r', RAX, 1)) & 1:
        raise Unmodelled('ladder exit with the flag set')
    return None


# --------------------------------------------------------------------- models

def scale_model(exponent, amount):
    """Closed form for sil read as i8.  Returns (value or None, buffer afterwards)."""
    k = abs(exponent)
    if k >= 20:
        return None, amount
    power = 10 ** k
    if exponent >= 0:
        wide, left = amount // power, amount // power
    else:
        wide, left = amount * power, amount
    return (wide if wide < CAP else None), left


def lead_u64(exponent, amount):
    """Reference lead `evm_amount_to_internal_wei`, for comparison only.  None for any error."""
    k = abs(exponent)
    if k >= 20:
        return None
    power = 10 ** k
    if exponent >= 0:
        wide = amount * power
        return wide if wide <= MASK else None
    return amount // power if amount % power == 0 else None


def admitted_bound(exponent):
    """Largest admitted amount, or None when no amount is admitted."""
    k = abs(exponent)
    if k >= 20:
        return None
    return CAP * 10 ** k - 1 if exponent >= 0 else (CAP - 1) // 10 ** k


def amount_base():
    out = [0, 1, 2, 9, 10, 99, 100, 10 ** 8, 10 ** 10, 10 ** 18, CAP - 1, CAP, CAP + 1, 2 ** 63, 2 ** 64 - 1,
           2 ** 64, 2 ** 64 + 1, 2 ** 96, 2 ** 128 - 1, 2 ** 128, 2 ** 192, 2 ** 255, U256 - 1]
    return out


def seeded_amounts(count):
    out = []
    for i in range(count):
        raw = hashlib.sha256(SEED + i.to_bytes(4, 'little')).digest()
        out.append(int.from_bytes(raw, 'little') >> (raw[0] % 256))
    return out


def edge_amounts(exponent):
    """Values around the cap, the 2^256 product limit and the limb borders for one exponent."""
    power = 10 ** abs(exponent)
    out = []
    if exponent >= 0:
        centres = [CAP * power, 2 ** 64 * power, power, 2 ** 128]
    else:
        centres = [CAP // power, (CAP - 1) // power + 1, U256 // power, U256 // power + 1, 2 ** 64,
                   U256 >> abs(exponent)]      # the last one wraps to exactly zero without the overflow flag
    for centre in centres:
        out.extend(c for c in range(centre - 2, centre + 3) if 0 <= c < U256)
    return out


def vector_grid():
    """(exponent, amount) pairs: every i8 on the base set, then edges and seeded for -19..=19."""
    base = amount_base()
    seeded = seeded_amounts(160)
    for exponent in range(-128, 128):
        for amount in base:
            yield exponent, amount
    for exponent in range(-19, 20):
        for amount in edge_amounts(exponent) + seeded:
            yield exponent, amount


# ------------------------------------------------------------------ analysis

def call_sites(img, target):
    addr, text = img.text()
    out = []
    i = text.find(b'\xe8')
    while i >= 0:
        if i + 5 <= len(text) and addr + i + 5 + struct.unpack_from('<i', text, i + 1)[0] == target:
            out.append(addr + i)
        i = text.find(b'\xe8', i + 1)
    return out


def checked(cond, message):
    if not cond:
        raise EvidenceError(message)


def load_code(binary, fdes, starts):
    insns, ranges = [], {}
    for start in starts:
        rng = fdes.range_of(start)
        checked(rng['start'] == start, f'{start:#x} is not an FDE start')
        insns.extend(parse_listing(disassemble(binary, rng['start'], rng['end'])))
        ranges[start] = rng
    return insns, ranges


def find(insns, va):
    for ins in insns:
        if ins[0] == va:
            return ins
    raise EvidenceError(f'no instruction at {va:#x}')


def check_constants(insns):
    """The cap, the ladder multipliers and the two helper calls, as decoded instructions."""
    for va, value in LADDER_CONSTANTS.items():
        ins = find(insns, va)
        checked(ins[2][-1] == ('i', value), f'ladder constant at {va:#x} is not {value}')
    checked(find(insns, CAP_INSN)[2][1] == ('i', CAP), 'cap constant changed')
    checked(find(insns, CALL_DIV)[2][0] == ('t', DIV_HELPER), 'divide call target changed')
    checked(find(insns, CALL_MUL)[2][0] == ('t', MUL_HELPER), 'multiply call target changed')


def exponent_source(insns, site):
    """Describe how esi is set before one call site, from the caller's own instructions."""
    pos = next(i for i, ins in enumerate(insns) if ins[0] == site)
    for ins in reversed(insns[max(0, pos - 6):pos]):
        if ins[2] and ins[2][0] == ('r', RSI, 4):
            if ins[1] == 'mov' and ins[2][1][0] == 'i':
                return {'form': 'immediate', 'value': ins[2][1][1], 'set_at': ins[0]}
            if ins[1] == 'movzx' and ins[2][1][0] == 'r':
                reg = ins[2][1][1]
                for src in reversed(insns[:pos - 6]):
                    if src[1] == 'movzx' and src[2][0][1] == reg and src[2][0][0] == 'r' and src[2][1][0] == 'm':
                        return {'form': 'byte-load', 'set_at': ins[0], 'load_at': src[0],
                                'load_offset': src[2][1][5]}
    raise EvidenceError(f'no esi source before {site:#x}')


def check_sites(binary, img, fdes):
    sites = call_sites(img, SCALE)
    checked(tuple(sites) == tuple(SITES), f'unexpected callers {sites}')
    rows = []
    for site, kind in SITES.items():
        rng = fdes.range_of(site)
        checked(rng['start'] in CALLERS, f'{site:#x} left its caller')
        insns = parse_listing(disassemble(binary, rng['start'], rng['end']))
        source = exponent_source(insns, site)
        ins = find(insns, site)
        after = find(insns, ins[3])
        checked(after[1] == 'test' and after[2] == (('r', RAX, 1), ('i', 1)), f'no flag test after {site:#x}')
        rows.append({'site': site, 'kind': kind, 'caller': rng['start'], 'caller_end': rng['end'],
                     'exponent': source})
    by_site = {row['site']: row['exponent'] for row in rows}
    checked(by_site[0x342753a].get('value') == 10, 'native site exponent changed')
    for site in (0x3baf539, 0x3baf779):
        checked(by_site[site].get('load_offset') == TOKEN_EXP_OFFSET, 'token site offset changed')
    checked(by_site[0x342782e].get('load_offset') == 0, 'map site load changed')
    return rows


def check_native_address(img):
    raw = img.read(NATIVE_ADDRESS_A, 16) + img.read(NATIVE_ADDRESS_B, 4)
    checked(raw == b'\x22' * 20, 'native address bytes changed')
    return raw.hex()


def check_caller_pins(binary, fdes):
    """Instructions around the sites: the address builder and the token record guards."""
    insns = parse_listing(disassemble(binary, CALLERS[0], fdes.range_of(CALLERS[0])['end']))
    checked(find(insns, 0x342767c)[2] == (('r', RBX, 8), ('i', 0x2222222222222222)), 'native limb changed')
    checked(find(insns, 0x3427692)[2] == (('r', R14, 1), ('i', 0x22)), 'native first byte changed')
    checked(find(insns, 0x342769a)[1] == 'bswap', 'token index is no longer byte-swapped')
    checked(find(insns, 0x34276ad)[2] == (('r', R14, 1), ('i', 0x20)), 'system first byte changed')
    insns = parse_listing(disassemble(binary, CALLERS[1], fdes.range_of(CALLERS[1])['end']))
    rows = []
    for stride_at, guard_at, load_at in ((0x3baf482, 0x3baf489, 0x3baf4ad), (0x3baf6d9, 0x3baf6e0, 0x3baf6ff)):
        checked(find(insns, stride_at)[2][2] == ('i', RECORD_STRIDE), 'token record stride changed')
        guard = find(insns, guard_at)
        checked(guard[1] == 'cmp' and guard[2][0][5] == TOKEN_FLAG_OFFSET and guard[2][1] == ('i', 1),
                'token guard changed')
        checked(find(insns, load_at)[2][1][5] == TOKEN_EXP_OFFSET, 'token exponent load changed')
        rows.append({'stride_at': stride_at, 'guard_at': guard_at, 'exponent_load_at': load_at})
    return rows


def check_quotient_reads(insns):
    """After the divide call the only memory reads are the numerator limbs through rbx."""
    pos = next(i for i, ins in enumerate(insns) if ins[0] == CALL_DIV)
    reads = [ins for ins in insns[pos + 1:] if ins[0] < CAP_INSN and any(op[0] == 'm' for op in ins[2])]
    checked(len(reads) == 4, 'unexpected reads after the divide call')
    checked(all(ins[2][1][2] == RBX for ins in reads), 'a read after the divide call is not through rbx')
    return [ins[0] for ins in reads]


def check_panic(img):
    """The only panic in the function, and the ruint Location it names."""
    relocs = img.relative_relocs()
    path = relocs[PANIC_LOCATION]
    length, line, col = struct.unpack('<QII', img.read(PANIC_LOCATION + 8, 16))
    name = img.read(path, length)
    checked(name.endswith(RUINT_PATH), 'panic Location path changed')
    checked(img.read(PANIC_TEXT, 16) == b'Division by zero', 'panic text changed')
    return {'path_tail': RUINT_PATH.decode(), 'line': line, 'column': col, 'text': 'Division by zero'}


def analyse(binary, data):
    check_digest(data)
    img = Image(data)
    fdes = Fdes(img)
    insns, ranges = load_code(binary, fdes, (SCALE, DIV_HELPER, MUL_HELPER))
    checked(ranges[SCALE]['end'] == SCALE_END, 'FDE end of the function changed')
    scale_insns = [ins for ins in insns if SCALE <= ins[0] < SCALE_END]
    check_constants(scale_insns)
    sites = check_sites(binary, img, fdes)
    native = check_native_address(img)
    panic = check_panic(img)
    guards = check_caller_pins(binary, fdes)
    quotient_reads = check_quotient_reads(scale_insns)
    machine = Machine(insns, img, img.slots())

    table = []
    for exponent in range(-128, 128):
        power = ladder_power(machine, exponent)
        expected = 10 ** abs(exponent) if abs(exponent) < 20 else None
        checked(power == expected, f'ladder disagrees at {exponent}')
        table.append((exponent, abs(exponent), power))

    digest = hashlib.sha256()
    total = admitted = capped = overflow = remainders = 0
    steps_max = 0
    for exponent, amount in vector_grid():
        got = run_scale(machine, exponent, amount)
        want = scale_model(exponent, amount)
        if got != want:
            raise EvidenceError(f'mismatch at e={exponent} amount={amount}: {got} != {want}')
        total += 1
        steps_max = max(steps_max, machine.steps)
        if got[0] is None:
            if abs(exponent) < 20:
                capped += 1
        else:
            admitted += 1
        if exponent < 0 and abs(exponent) < 20 and amount * 10 ** abs(exponent) >= U256:
            overflow += 1
        if 0 <= exponent < 20:
            checked(dead_divisor_slot(machine) == amount % 10 ** exponent, f'remainder at e={exponent}')
            remainders += 1
        digest.update(f'{exponent} {amount} {got[0]} {got[1]}\n'.encode())

    helper_digest = hashlib.sha256()
    helper_total_vectors = helper_overflows = 0
    for left in amount_base() + seeded_amounts(160):
        for k in range(20):
            got = run_multiply(machine, left, 10 ** k)
            wide = left * 10 ** k
            if got != (wide % U256, int(wide >= U256)):
                raise EvidenceError(f'multiply helper mismatch at {left} * 10^{k}')
            helper_total_vectors += 1
            helper_overflows += got[1]
            helper_digest.update(f'{left} {k} {got[0]} {got[1]}\n'.encode())

    bounds = []
    for exponent in range(-19, 20):
        top = admitted_bound(exponent)
        first = top + 1
        got_top = run_scale(machine, exponent, top)[0]
        got_first = run_scale(machine, exponent, first)[0]
        checked(got_top is not None and got_first is None, f'bound fails at {exponent}')
        bounds.append((exponent, 10 ** abs(exponent), top, got_top, first))
    checked(max(row[3] for row in bounds) == CAP - 1, 'largest result is not CAP - 1')

    executed = sorted(ins[0] for ins in scale_insns if ins[0] in machine.seen)
    missed = [ins for ins in scale_insns if ins[0] not in machine.seen and ins[1] != 'int3']
    helper_total = {name: sum(1 for ins in insns if ranges[start]['start'] <= ins[0] < ranges[start]['end'])
                    for name, start in (('divide', DIV_HELPER), ('multiply', MUL_HELPER))}
    helper_seen = {name: sum(1 for ins in insns if ranges[start]['start'] <= ins[0] < ranges[start]['end']
                             and ins[0] in machine.seen)
                   for name, start in (('divide', DIV_HELPER), ('multiply', MUL_HELPER))}

    lead_witness = []
    for exponent, amount in ((2, 1000), (2, 1001), (-2, 1000), (-2, 1001), (10, 10 ** 19), (0, 2 ** 64 - 1)):
        lead_witness.append({'exponent': exponent, 'amount': amount,
                             'binary': scale_model(exponent, amount)[0], 'lead': lead_u64(exponent, amount)})

    result = {
        'target': {'path': BINARY, 'sha256': SHA256, 'coordinates': 'ELF virtual addresses'},
        'function': {'start': SCALE, 'end': SCALE_END, 'instructions': len(scale_insns)},
        'helpers': {
            'divide': {'start': ranges[DIV_HELPER]['start'], 'end': ranges[DIV_HELPER]['end'],
                       'instructions': helper_total['divide'], 'executed': helper_seen['divide']},
            'multiply': {'start': ranges[MUL_HELPER]['start'], 'end': ranges[MUL_HELPER]['end'],
                         'instructions': helper_total['multiply'], 'executed': helper_seen['multiply']},
        },
        'constants': {'cap': CAP, 'cap_hex': hex(CAP), 'cap_is_i64_max_div_10': CAP == (2 ** 63 - 1) // 10,
                      'ladder_multipliers': {hex(k): v for k, v in LADDER_CONSTANTS.items()}},
        'sites': sites,
        'token_guards': guards,
        'quotient_reads': quotient_reads,
        'native_address_hex': native,
        'panic': panic,
        'ladder': {'exponents': 256, 'admitted': sum(1 for row in table if row[2] is not None),
                   'admitted_min': -19, 'admitted_max': 19},
        'vectors': {'total': total, 'some': admitted, 'none_after_ladder': capped,
                    'u256_product_overflows': overflow, 'remainders_checked': remainders, 'mismatches': 0,
                    'max_steps': steps_max, 'sha256': digest.hexdigest()},
        'multiply_helper_vectors': {'total': helper_total_vectors, 'overflows': helper_overflows, 'mismatches': 0,
                                    'sha256': helper_digest.hexdigest()},
        'coverage': {'function_executed': len(executed), 'function_not_executed': [ins[0] for ins in missed]},
        'largest_result': CAP - 1,
        'lead': {'name': 'evm_amount_to_internal_wei', 'witnesses': lead_witness},
    }
    return result, table, bounds, scale_insns


def write_outputs(out, result, table, bounds, data):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=1, sort_keys=True) + '\n')
    lines = ['exponent_i8\tabs\tpower_or_none']
    lines += [f'{e}\t{k}\t{p if p is not None else "none"}' for e, k, p in table]
    (out / 'exponent-table.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['exponent_i8\tpower\tlargest_admitted_amount\tresult_there\tfirst_rejected_amount']
    lines += ['\t'.join(str(v) for v in row) for row in bounds]
    (out / 'boundaries.tsv').write_text('\n'.join(lines) + '\n')
    img = Image(data)
    rows = [f'# {SCALE:#x}..{SCALE_END:#x} raw bytes, VA then hex']
    for va in range(SCALE, SCALE_END, 16):
        rows.append(f'{va:#x} {img.read(va, min(16, SCALE_END - va)).hex()}')
    (out / 'function-bytes.txt').write_text('\n'.join(rows) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    binary = ROOT / BINARY
    data = binary.read_bytes()
    result, table, bounds, _ = analyse(binary, data)
    write_outputs(args.out, result, table, bounds, data)
    v = result['vectors']
    print(f"vectors {v['total']}, mismatches {v['mismatches']}, sites {len(result['sites'])}, "
          f"not executed {len(result['coverage']['function_not_executed'])}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
