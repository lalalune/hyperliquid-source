#!/usr/bin/env python3
"""Reconstruct the node #115 `Action` type-name matcher and prove it against the bytes.

The matcher turns the wire `type` string of an `Action` into the variant index
(0..91) or calls serde's unknown_variant error with the 92-entry VARIANTS slice.
This tool:

1. checks the input digest and reads the VARIANTS slice (`&[&str]`, 16-byte
   pointer/length pairs filled by R_X86_64_RELATIVE relocations);
2. interprets the original matcher bytes with a fixed-pattern x86-64 subset
   interpreter (no external programs, the binary is never run);
3. compares every interpreted outcome with a pure reconstruction
   (`reconstructed_match`) over thousands of names built from the bytes;
4. proves full instruction coverage, a one-to-one name -> success-store map and
   that wrong reconstructions (mutants) are rejected.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402

BINARY = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
VARIANT_COUNT = 92

# (label, function start, FDE end, VARIANTS slice, unknown_variant callee)
COPIES = (
    ('A', 0x2ba1af0, 0x2ba2bde, 0x644cc40, 0x17fbba0),
    ('B', 0x3662730, 0x366381e, 0x6467f98, 0x2f7fef0),
)
# Same-shape matchers whose single arms are already read by merged packets;
# this tool never decodes them.
EXCLUDED = (
    ('0x2ba0a70', 'RE-010-gov-vote-path-115 (govVote arm)'),
    ('0x36616b0', 'RE-010-set-referrer-path-115 (length-11 arm)'),
    ('0x4d67530', 'RE-010-claim-rewards-path-115 (claimRewards arm)'),
)

IN_BASE, OUT_BASE, STACK_TOP = 0x7000_0000_0000, 0x7100_0000_0000, 0x7200_0000_0000
ERR_MARK = bytes(range(0xe0, 0x100))  # 32 bytes the stubbed error writer stores
MASK64 = (1 << 64) - 1
REG = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
       'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']


class Fault(Exception):
    pass


class Image:
    def __init__(self, data):
        if hashlib.sha256(data).hexdigest() != SHA256:
            raise ValueError('input binary SHA-256 mismatch')
        self.data = data
        # NOBITS sections carry no file bytes and are excluded from VA reads.
        self.secs = [s for s in sections(data) if s['type'] != 8 and s['address'] and s['size']]
        self.by_name = {s['name']: s for s in self.secs}
        self.relative, self.symbolic = {}, {}
        rd = self.by_name['.rela.dyn']
        for i in range(rd['size'] // 24):
            off, info, add = struct.unpack_from('<QQq', data, rd['offset'] + i * 24)
            if info & 0xffffffff == 8:
                self.relative[off] = add
            else:
                self.symbolic[off] = (info >> 32, info & 0xffffffff)

    def off(self, va, n=1):
        for s in self.secs:
            if s['address'] <= va and va + n <= s['address'] + s['size']:
                return s['offset'] + va - s['address']
        raise Fault(f'unmapped static read {va:#x}+{n}')

    def read(self, va, n):
        o = self.off(va, n)
        return self.data[o:o + n]

    def symbol_name(self, index):
        dynsym, dynstr = self.by_name['.dynsym'], self.by_name['.dynstr']
        name = struct.unpack_from('<I', self.data, dynsym['offset'] + 24 * index)[0]
        start = dynstr['offset'] + name
        return self.data[start:self.data.index(b'\0', start)].decode()

    def variants(self, va):
        names = []
        for i in range(VARIANT_COUNT):
            slot = va + 16 * i
            if slot not in self.relative:
                raise ValueError(f'VARIANTS slot {slot:#x} has no RELATIVE relocation')
            length = struct.unpack_from('<Q', self.read(slot + 8, 8))[0]
            names.append(self.read(self.relative[slot], length))
        return names


def sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


class Insn:
    __slots__ = ('va', 'size', 'op', 'a', 'b', 'w', 'raw')


def decode(img, va):
    """Decode one instruction of the fixed subset used by the matcher copies."""
    b = img.read(va, 16)
    p, opsz, rep, rex = 0, None, False, 0
    while b[p] in (0x66, 0xf3):
        opsz = 16 if b[p] == 0x66 else opsz
        rep = rep or b[p] == 0xf3
        p += 1
    if 0x40 <= b[p] <= 0x4f:
        rex = b[p]
        p += 1
    W, R, X, B = rex >> 3 & 1, rex >> 2 & 1, rex >> 1 & 1, rex & 1
    width = 64 if W else (opsz or 32)
    ins = Insn()
    ins.va, ins.w, ins.a, ins.b = va, width, None, None

    def modrm():
        nonlocal p
        m = b[p]
        p += 1
        mod, reg, rm = m >> 6, (m >> 3 & 7) | R << 3, m & 7
        if mod == 3:
            return reg, ('r', rm | B << 3)
        base, index, scale, rip = None, None, 1, False
        if rm == 4:
            sib = b[p]
            p += 1
            scale, idx, bs = 1 << (sib >> 6), (sib >> 3 & 7) | X << 3, sib & 7
            index = None if idx == 4 else idx
            if bs == 5 and mod == 0:
                base, disp = None, struct.unpack_from('<i', b, p)[0]
                p += 4
            else:
                base = bs | B << 3
        elif rm == 5 and mod == 0:
            rip = True
        else:
            base = rm | B << 3
        if rip or (mod == 0 and rm == 4 and base is None):
            if rip:
                disp = struct.unpack_from('<i', b, p)[0]
                p += 4
        elif mod == 1:
            disp = sx(b[p], 8)
            p += 1
        elif mod == 2:
            disp = struct.unpack_from('<i', b, p)[0]
            p += 4
        else:
            disp = 0
        return reg, ('m', base, index, scale, disp, rip)

    def imm(n):
        nonlocal p
        v = int.from_bytes(b[p:p + n], 'little')
        p += n
        return v

    op = b[p]
    p += 1
    alu = {0x01: 'add', 0x03: 'add', 0x09: 'or', 0x0b: 'or', 0x31: 'xor', 0x33: 'xor',
           0x39: 'cmp', 0x3b: 'cmp', 0x85: 'test', 0x89: 'mov', 0x8b: 'mov'}
    grp = {0: 'add', 1: 'or', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp'}
    if op in alu:
        reg, rm = modrm()
        ins.op = alu[op]
        ins.a, ins.b = (rm, ('r', reg)) if op in (0x01, 0x09, 0x31, 0x39, 0x85, 0x89) else (('r', reg), rm)
    elif op in (0x81, 0x83, 0x80):
        reg, rm = modrm()
        if (reg & 7) not in grp:
            raise Fault(f'unsupported group op at {va:#x}')
        ins.op = grp[reg & 7]
        if op == 0x80:
            ins.w = 8
            ins.b = ('i', imm(1))
        elif op == 0x83:
            ins.b = ('i', sx(imm(1), 8) & ((1 << width) - 1))
        else:
            n = 2 if width == 16 else 4
            ins.b = ('i', sx(imm(n), n * 8) & ((1 << width) - 1))
        ins.a = rm
    elif op == 0x8d:
        reg, rm = modrm()
        ins.op, ins.a, ins.b = 'lea', ('r', reg), rm
    elif op == 0x63:
        reg, rm = modrm()
        ins.op, ins.a, ins.b = 'movsxd', ('r', reg), rm
    elif op == 0xc7:
        reg, rm = modrm()
        n = 2 if width == 16 else 4
        ins.op, ins.a, ins.b = 'mov', rm, ('i', sx(imm(n), n * 8) & ((1 << width) - 1))
    elif 0xb8 <= op <= 0xbf:
        ins.op, ins.a = 'mov', ('r', (op - 0xb8) | B << 3)
        ins.b = ('i', imm(8 if W else 4))
    elif 0x50 <= op <= 0x57:
        ins.op, ins.a, ins.w = 'push', ('r', (op - 0x50) | B << 3), 64
    elif 0x58 <= op <= 0x5f:
        ins.op, ins.a, ins.w = 'pop', ('r', (op - 0x58) | B << 3), 64
    elif 0x70 <= op <= 0x7f:
        ins.op, ins.a = 'j', op & 15
        ins.b = sx(imm(1), 8)
    elif op == 0xeb:
        ins.op, ins.b = 'jmp', sx(imm(1), 8)
    elif op == 0xe9:
        ins.op, ins.b = 'jmp', sx(imm(4), 32)
    elif op == 0xe8:
        ins.op, ins.b = 'call', sx(imm(4), 32)
    elif op == 0xc3:
        ins.op = 'ret'
    elif op == 0xff:
        reg, rm = modrm()
        ins.op = {4: 'jmpr', 2: 'callr'}.get(reg & 7)
        if ins.op is None:
            raise Fault(f'unsupported ff form at {va:#x}')
        ins.a, ins.w = rm, 64
    elif op == 0x0f:
        op2 = b[p]
        p += 1
        if 0x80 <= op2 <= 0x8f:
            ins.op, ins.a, ins.b = 'j', op2 & 15, sx(imm(4), 32)
        elif op2 in (0xb6, 0xb7):
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'movzx', ('r', reg), rm
            ins.w = 8 if op2 == 0xb6 else 16
        elif op2 == 0x6f and rep:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'xload', reg, rm
        elif op2 == 0x7f and rep:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'xstore', rm, reg
        elif op2 == 0x7e and rep:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'movq', reg, rm
        elif op2 == 0x74 and opsz == 16:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'pcmpeqb', reg, rm
        elif op2 == 0xdb and opsz == 16:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'pand', reg, rm
        elif op2 == 0xd7 and opsz == 16:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'pmovmskb', reg, rm
        elif op2 == 0x6e and opsz == 16:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'movd', reg, rm
        else:
            raise Fault(f'unsupported 0f {op2:02x} at {va:#x}')
    else:
        raise Fault(f'unsupported opcode {op:02x} at {va:#x}')
    ins.size = p
    ins.raw = bytes(b[:p])
    return ins


MNEMONIC_COND = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g']


class Machine:
    def __init__(self, img, copy, cache):
        self.img, self.copy, self.cache = img, copy, cache

    def run(self, name, limit=400):
        label, start, end, variants_va, err_callee = self.copy
        self.inp = bytes(name)
        self.out = bytearray(32)
        self.stack = bytearray(0x200)
        self.r = [0] * 16
        self.x = [bytes(16)] * 16
        self.r[7], self.r[6], self.r[2] = OUT_BASE, IN_BASE, len(name)
        self.r[4] = STACK_TOP - 8
        self.flags = dict(z=0, c=0, s=0, o=0)
        self.calls, self.trace = [], []
        pc = start
        for _ in range(limit):
            if not start <= pc < end:
                raise Fault(f'left function at {pc:#x}')
            ins = self.cache.get(pc)
            if ins is None:
                ins = self.cache[pc] = decode(self.img, pc)
            self.trace.append(pc)
            nxt = pc + ins.size
            res = self.step(ins, nxt)
            if res == 'ret':
                return self.outcome()
            pc = nxt if res is None else res
        raise Fault('step limit')

    def outcome(self):
        if self.out[0] == 9 and not any(self.out[2:]):
            return ('ok', self.out[1])
        if bytes(self.out) == ERR_MARK:
            return ('unknown', None)
        raise Fault('unrecognised output ' + self.out.hex())

    # memory -------------------------------------------------------------
    def addr(self, m, nxt):
        _, base, index, scale, disp, rip = m
        a = nxt + disp if rip else disp
        if base is not None:
            a += self.r[base]
        if index is not None:
            a += self.r[index] * scale
        return a & MASK64

    def region(self, a, n):
        for base, buf in ((IN_BASE, self.inp), (OUT_BASE, self.out), (STACK_TOP - len(self.stack), self.stack)):
            if base <= a < base + len(buf) + 64:
                if a + n > base + len(buf):
                    raise Fault(f'read past buffer {a:#x}+{n}')
                return buf, a - base
        return None, None

    def load(self, a, n):
        buf, o = self.region(a, n)
        if buf is None:
            return self.img.read(a, n)
        return bytes(buf[o:o + n])

    def store(self, a, data):
        buf, o = self.region(a, len(data))
        if buf is None or buf is self.inp:
            raise Fault(f'store outside writable buffers {a:#x}')
        buf[o:o + len(data)] = data

    def get(self, opnd, w, nxt):
        if opnd[0] == 'r':
            return self.r[opnd[1]] & ((1 << w) - 1)
        if opnd[0] == 'i':
            return opnd[1]
        return int.from_bytes(self.load(self.addr(opnd, nxt), w // 8), 'little')

    def put(self, opnd, w, v, nxt):
        v &= (1 << w) - 1
        if opnd[0] == 'r':
            n = opnd[1]
            if w == 64 or w == 32:
                self.r[n] = v
            else:
                self.r[n] = (self.r[n] & ~((1 << w) - 1) & MASK64) | v
        else:
            self.store(self.addr(opnd, nxt), v.to_bytes(w // 8, 'little'))

    def xget(self, opnd, nxt, n=16):
        if isinstance(opnd, int):
            return self.x[opnd]
        if opnd[0] == 'r':
            return self.x[opnd[1]]
        return self.load(self.addr(opnd, nxt), n)

    def setf(self, w, res, a=None, b=None, kind='logic'):
        m = (1 << w) - 1
        r = res & m
        self.flags['z'] = int(r == 0)
        self.flags['s'] = r >> (w - 1) & 1
        if kind == 'logic':
            self.flags['c'] = self.flags['o'] = 0
        elif kind == 'sub':
            self.flags['c'] = int(a < b)
            self.flags['o'] = int(sx(a, w) - sx(b, w) != sx(r, w))
        else:
            self.flags['c'] = int(a + b > m)
            self.flags['o'] = int(sx(a, w) + sx(b, w) != sx(r, w))
        return r

    def cond(self, cc):
        f = self.flags
        base = cc >> 1
        v = [f['o'], f['c'], f['z'], f['c'] | f['z'], f['s'], None,
             int(f['s'] != f['o']), int(f['z'] or f['s'] != f['o'])][base]
        if v is None:
            raise Fault('parity flag not modelled')
        return bool(v) ^ bool(cc & 1)

    def step(self, ins, nxt):
        op, w = ins.op, ins.w
        if op in ('add', 'or', 'xor', 'and', 'sub', 'cmp', 'test'):
            a, b = self.get(ins.a, w, nxt), self.get(ins.b, w, nxt)
            if op in ('add',):
                r = self.setf(w, a + b, a, b, 'add')
            elif op in ('sub', 'cmp'):
                r = self.setf(w, a - b, a, b, 'sub')
            else:
                r = self.setf(w, {'or': a | b, 'xor': a ^ b, 'and': a & b, 'test': a & b}[op])
            if op not in ('cmp', 'test'):
                self.put(ins.a, w, r, nxt)
        elif op == 'mov':
            self.put(ins.a, w, self.get(ins.b, w, nxt), nxt)
        elif op == 'lea':
            self.put(ins.a, w, self.addr(ins.b, nxt), nxt)
        elif op == 'movsxd':
            self.put(ins.a, 64, sx(self.get(ins.b, 32, nxt), 32) & MASK64, nxt)
        elif op == 'movzx':
            self.put(ins.a, 32, self.get(ins.b, w, nxt), nxt)
        elif op == 'push':
            self.r[4] -= 8
            self.store(self.r[4], self.r[ins.a[1]].to_bytes(8, 'little'))
        elif op == 'pop':
            self.r[ins.a[1]] = int.from_bytes(self.load(self.r[4], 8), 'little')
            self.r[4] += 8
        elif op == 'j':
            return nxt + ins.b if self.cond(ins.a) else None
        elif op == 'jmp':
            return nxt + ins.b
        elif op == 'jmpr':
            return self.get(ins.a, 64, nxt)
        elif op == 'ret':
            if self.r[4] != STACK_TOP - 8:
                raise Fault('unbalanced stack at ret')
            return 'ret'
        elif op in ('call', 'callr'):
            return self.call(ins, nxt)
        elif op == 'xload':
            self.x[ins.a] = self.xget(ins.b, nxt)
        elif op == 'xstore':
            self.store(self.addr(ins.a, nxt), self.x[ins.b])
        elif op == 'movq':
            self.x[ins.a] = self.xget(ins.b, nxt, 8) + bytes(8)
        elif op == 'movd':
            self.x[ins.a] = (self.get(ins.b, 32, nxt)).to_bytes(4, 'little') + bytes(12)
        elif op == 'pcmpeqb':
            o = self.xget(ins.b, nxt)
            self.x[ins.a] = bytes(0xff if p == q else 0 for p, q in zip(self.x[ins.a], o))
        elif op == 'pand':
            o = self.xget(ins.b, nxt)
            self.x[ins.a] = bytes(p & q for p, q in zip(self.x[ins.a], o))
        elif op == 'pmovmskb':
            v = self.x[ins.b[1]]
            self.r[ins.a] = sum(1 << i for i, c in enumerate(v) if c & 0x80)
        else:
            raise Fault(f'no semantics for {op}')
        return None

    def call(self, ins, nxt):
        if ins.op == 'callr':
            slot = self.addr(ins.a, nxt)
            sym = self.img.symbolic.get(slot)
            name = self.img.symbol_name(sym[0]) if sym else None
            if name not in ('bcmp', 'memcmp'):
                raise Fault(f'indirect call through {slot:#x} ({name})')
            a = self.load(self.r[7], self.r[2])
            b = self.load(self.r[6], self.r[2])
            self.r[0] = 0 if a == b else 1
            self.calls.append((name, self.r[2]))
            return None
        target = nxt + ins.b
        label, start, end, variants_va, err_callee = self.copy
        if target != err_callee:
            raise Fault(f'unexpected direct call {target:#x}')
        # unknown_variant(out=rdi, value=(rsi, rdx), expected=(rcx, r8))
        if (self.r[6], self.r[2], self.r[1], self.r[8]) != (IN_BASE, len(self.inp), variants_va, VARIANT_COUNT):
            raise Fault('unknown_variant arguments differ from (input, VARIANTS, 92)')
        self.calls.append(('unknown_variant', target))
        self.store(self.r[7], ERR_MARK)
        for n in (1, 2, 6, 7, 8, 9, 10, 11):
            self.r[n] = 0xdead_0000 + n  # caller-saved registers are clobbered
        return None


# reconstruction --------------------------------------------------------------
def reconstructed_match(name, wire_names):
    """Pure reconstruction: exact, case-sensitive, whole-string match, no aliases."""
    for index, wire in enumerate(wire_names):
        if name == wire:
            return ('ok', index)
    return ('unknown', None)


MUTANTS = {
    'case_insensitive': lambda s, w: next((('ok', i) for i, n in enumerate(w) if s.lower() == n.lower()), ('unknown', None)),
    'prefix_match': lambda s, w: next((('ok', i) for i, n in enumerate(w) if s and n.startswith(s)), ('unknown', None)),
    'pascal_alias': lambda s, w: reconstructed_match(s[:1].lower() + s[1:], w),
    'rust_suffix_alias': lambda s, w: reconstructed_match(s[:-6] if s.endswith(b'Action') else s, w),
    'drop_last_variant': lambda s, w: reconstructed_match(s, w[:-1]),
    'off_by_one_index': lambda s, w: (lambda r: ('ok', r[1] + 1) if r[0] == 'ok' else r)(reconstructed_match(s, w)),
    'swap_order_cancel': lambda s, w: reconstructed_match(s, [w[i] for i in (lambda l: l[:3] + [l[4], l[3]] + l[5:])(list(range(len(w))))]),
    'length_only_check': lambda s, w: next((('ok', i) for i, n in enumerate(w) if len(s) == len(n) and s[:4] == n[:4]), ('unknown', None)),
    'ignore_last_byte': lambda s, w: next((('ok', i) for i, n in enumerate(w) if len(s) == len(n) and s[:-1] == n[:-1]), ('unknown', None)),
    'accept_trailing_nul': lambda s, w: reconstructed_match(s.rstrip(b'\0'), w),
}


def build_cases(names):
    seen, cases = set(), []

    def add(kind, s):
        if s not in seen:
            seen.add(s)
            cases.append((kind, s))
    for n in names:
        add('exact', n)
    for n in names:
        for i in range(len(n)):
            c = n[i]
            if 0x41 <= c <= 0x5a or 0x61 <= c <= 0x7a:
                add('case_flip', n[:i] + bytes([c ^ 0x20]) + n[i + 1:])
            add('byte_plus1', n[:i] + bytes([(c + 1) & 0xff]) + n[i + 1:])
        add('truncate', n[:-1])
        add('extend_s', n + b's')
        add('extend_nul', n + b'\0')
        add('pascal', n[:1].upper() + n[1:])
        add('strip_action', n[:-6] if n.endswith(b'Action') else n + b'Action')
    for length in range(0, 49):
        add('filler', b'a' * length)
    return cases


def coverage_sweep(img, start, end):
    """Linear sweep of the FDE extent; every byte must belong to a decoded instruction."""
    pc, out = start, []
    while pc < end:
        ins = decode(img, pc)
        out.append(ins)
        pc += ins.size
    if pc != end:
        raise Fault('sweep overran FDE end')
    return out


def jump_table(img, insns):
    """Read the length switch: lea rcx,[rdx-K]; cmp rcx,N; ja; lea rdi,[rip+T]; movsxd; add; jmp rcx."""
    i0, i1, i3 = insns[5], insns[6], insns[8]
    if i0.op != 'lea' or i1.op != 'cmp' or i3.op != 'lea' or insns[9].op != 'movsxd' or insns[11].op != 'jmpr':
        raise Fault('length switch prologue shape differs')
    bias = -i0.b[4]
    count = i1.b[1] + 1
    table = i3.va + i3.size + i3.b[4]
    rows = []
    for k in range(count):
        rel = struct.unpack('<i', img.read(table + 4 * k, 4))[0]
        rows.append((bias + k, table + rel))
    return bias, count, table, rows


def generate(out_dir):
    data = BINARY.read_bytes()
    img = Image(data)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {'binary_sha256': SHA256, 'variant_count': VARIANT_COUNT, 'copies': [],
               'excluded_same_shape_copies': [{'start': a, 'owner': o} for a, o in EXCLUDED]}
    names_ref = None
    case_rows = ['copy\tkind\tinput_hex\tlength\tinterpreted\treconstructed\tunknown_variant_calls\tbcmp_calls\tsteps']
    name_rows = ['copy\tindex\twire_name\tlength\tswitch_arm\tsuccess_store_va\tresult_word\tsteps']
    table_rows = ['copy\tlength\tarm_va\tarm_kind\tnames_of_this_length']
    insn_rows = ['copy\tva\tbytes\top\texecuted_cases']
    mutant_rows = ['mutant\tfirst_disagreeing_case\tdisagreements\tkilled']
    all_cases = []
    for copy in COPIES:
        label, start, end, variants_va, err_callee = copy
        names = img.variants(variants_va)
        if names_ref is None:
            names_ref = names
        elif names != names_ref:
            raise Fault('VARIANTS slices differ between copies')
        if len(set(names)) != VARIANT_COUNT:
            raise Fault('duplicate wire names')
        insns = coverage_sweep(img, start, end)
        bias, count, table, rows = jump_table(img, insns)
        cache = {i.va: i for i in insns}
        m = Machine(img, copy, cache)
        cases = build_cases(names)
        executed = {}
        stores, mismatch = {}, 0
        for kind, s in cases:
            got = m.run(s)
            want = reconstructed_match(s, names)
            mismatch += got != want
            for pc in set(m.trace):
                executed[pc] = executed.get(pc, 0) + 1
            uv = sum(1 for c in m.calls if c[0] == 'unknown_variant')
            bc = sum(1 for c in m.calls if c[0] != 'unknown_variant')
            fmt = lambda r: f'ok:{r[1]}' if r[0] == 'ok' else 'unknown'
            case_rows.append(f'{label}\t{kind}\t{s.hex()}\t{len(s)}\t{fmt(got)}\t{fmt(want)}\t{uv}\t{bc}\t{len(m.trace)}')
            if kind == 'exact':
                store = next(pc for pc in reversed(m.trace) if cache[pc].op == 'mov' and cache[pc].a[0] == 'm' and cache[pc].w == 16)
                stores.setdefault(store, []).append(s)
                arm = m.trace[m.trace.index(insns[11].va) + 1] if insns[11].va in m.trace else None
                word = cache[store].b[1]
                name_rows.append(f'{label}\t{got[1]}\t{s.decode()}\t{len(s)}\t{arm:#x}\t{store:#x}\t{word:#06x}\t{len(m.trace)}')
            if label == 'A':
                all_cases.append((kind, s, got))
        by_len = {}
        for n in names:
            by_len.setdefault(len(n), []).append(n.decode())
        fail_targets = {}
        for length, target in rows:
            fail_targets[target] = fail_targets.get(target, 0) + 1
        default_target = max(fail_targets, key=lambda t: (fail_targets[t], -t))
        for length, target in rows:
            kind = 'unknown_variant' if target == default_target else 'compare_arm'
            table_rows.append(f'{label}\t{length}\t{target:#x}\t{kind}\t{",".join(by_len.get(length, [])) or "-"}')
        for ins in insns:
            insn_rows.append(f'{label}\t{ins.va:#x}\t{ins.raw.hex()}\t{ins.op}\t{executed.get(ins.va, 0)}')
        unexecuted = [i.va for i in insns if i.va not in executed]
        arm_lengths = sorted(l for l, t in rows if t != default_target)
        summary['copies'].append({
            'label': label, 'start': f'{start:#x}', 'fde_end': f'{end:#x}', 'bytes': end - start,
            'variants_slice': f'{variants_va:#x}', 'instructions': len(insns),
            'instructions_executed': len(insns) - len(unexecuted), 'unexecuted': [f'{v:#x}' for v in unexecuted],
            'length_switch': {'bias': bias, 'entries': count, 'table': f'{table:#x}',
                              'compare_arm_lengths': arm_lengths, 'default_target': f'{default_target:#x}'},
            'name_lengths': sorted(by_len), 'cases': len(cases), 'mismatches': mismatch,
            'success_stores': len(stores), 'success_stores_one_to_one': all(len(v) == 1 for v in stores.values()) and len(stores) == VARIANT_COUNT,
            'outcomes': {'ok': sum(1 for r in case_rows if r.startswith(label + '\t') and '\tok:' in r),
                         'unknown': sum(1 for r in case_rows if r.startswith(label + '\t') and '\tunknown\t' in r)},
        })
    kill_total = 0
    for mname in sorted(MUTANTS):
        fn = MUTANTS[mname]
        bad = [(k, s) for k, s, got in all_cases if fn(s, names_ref) != got]
        killed = bool(bad)
        kill_total += killed
        first = f'{bad[0][0]}:{bad[0][1].hex()}' if bad else '-'
        mutant_rows.append(f'{mname}\t{first}\t{len(bad)}\t{"yes" if killed else "no"}')
    summary['mutants'] = {'total': len(MUTANTS), 'killed': kill_total}
    summary['image_mutants'] = image_mutants(data, names_ref)
    rs = ['// Reconstructed from node #115 bytes by tools/re010_action_type_matcher_115.py.',
          '// serde field visitor for the internally tagged `Action` enum `type` key.',
          'fn action_variant_from_type(value: &str) -> Result<u8, Error> {',
          '    match value {']
    for i, n in enumerate(names_ref):
        rs.append(f'        "{n.decode()}" => Ok({i}),')
    rs += ['        _ => Err(Error::unknown_variant(value, VARIANTS)), // VARIANTS.len() == 92',
           '    }', '}']
    files = {
        'summary.json': json.dumps(summary, indent=2, sort_keys=True) + '\n',
        'names.tsv': '\n'.join(name_rows) + '\n',
        'length-switch.tsv': '\n'.join(table_rows) + '\n',
        'cases.tsv': '\n'.join(case_rows) + '\n',
        'insns.tsv': '\n'.join(insn_rows) + '\n',
        'mutants.tsv': '\n'.join(mutant_rows) + '\n',
        'type_matcher.rs.txt': '\n'.join(rs) + '\n',
    }
    for name, text in files.items():
        (out_dir / name).write_text(text, encoding='utf-8')
    return summary


def image_mutants(data, names):
    """Corrupt one compared byte per sampled arm in a private copy and require a detected divergence."""
    label, start, end, variants_va, err_callee = COPIES[0]
    base = Image.__new__(Image)
    Image.__init__(base, data)
    insns = coverage_sweep(base, start, end)
    sites = [i for i in insns if i.op in ('cmp', 'xor', 'mov') and i.b and i.b[0] == 'i' and i.w >= 32 and i.a[0] == 'r'
             or i.op == 'cmp' and i.b and i.b[0] == 'i' and i.a[0] == 'm']
    picked = sites[::max(1, len(sites) // 12)][:12]
    rows, killed = [], 0
    for ins in picked:
        buf = bytearray(data)
        off = base.off(ins.va + ins.size - 1)
        buf[off] ^= 0x01
        mut = Image.__new__(Image)
        mut.data, mut.secs, mut.by_name = bytes(buf), base.secs, base.by_name
        mut.relative, mut.symbolic = base.relative, base.symbolic
        m = Machine(mut, COPIES[0], {})
        diverged = False
        for n in names + [b'a' * k for k in range(49)]:
            try:
                if m.run(n) != reconstructed_match(n, names):
                    diverged = True
                    break
            except Fault:
                diverged = True
                break
        killed += diverged
        rows.append({'va': f'{ins.va:#x}', 'flipped_byte': f'{ins.va + ins.size - 1:#x}', 'killed': diverged})
    return {'total': len(rows), 'killed': killed, 'sites': rows}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    s = generate(args.out)
    for c in s['copies']:
        print(f"copy {c['label']} {c['start']}: {c['cases']} cases, {c['mismatches']} mismatches, "
              f"{c['instructions_executed']}/{c['instructions']} instructions executed")
    print(f"mutants {s['mutants']['killed']}/{s['mutants']['total']}, image mutants "
          f"{s['image_mutants']['killed']}/{s['image_mutants']['total']}")
    bad = any(c['mismatches'] or c['unexecuted'] or not c['success_stores_one_to_one'] for c in s['copies'])
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
