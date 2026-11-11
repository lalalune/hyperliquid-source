#!/usr/bin/env python3
"""Reconstruct the node #115 action-error Display function (0x46ef710) and prove it on the bytes.

The body is one 14,879-byte FDE. It reads a u16 tag from the error value, jumps through a
418-slot rel32 table and ends in one of 418 short arms. 337 arms write one static string
through the formatter vtable; 80 arms build an argument array on the stack and call the
node's template interpreter with a length-prefixed message template. The binary is never run:
a concrete x86-64 subset emulator interprets the original bytes, and an independent symbolic
model (arm shape -> text / template / argument sources) predicts every observable result.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET = ROOT / 'artifacts/node/115/hl-node'
ENTRY = 0x46ef710
TABLE_VA = 0x7d8c1c
SLOTS = 418
VARIANTS = 30
NAMES = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'] + ['r%d' % i for i in range(8, 16)]
M64 = (1 << 64) - 1
INTERP = [0]

PB, PSIZE = 0x7f0000100000, 0x200      # payload (the error value) region
FB, VT = 0x7f0000200000, 0x7f0000200100  # formatter object and its vtable
WRITE_STR, RET_ADDR = 0x7f0000300000, 0x7f0000400000
SP0, STACK_LOW = 0x7ffe00001000, 0x7ffe00000e00


class Reject(Exception):
    pass


class Image:
    """Read-only view of the mapped PROGBITS sections plus RELATIVE relocation addends."""

    def __init__(self, data):
        self.data = data
        self.secs = [s for s in elf_index.sections(data) if s['type'] != 8 and s['flags'] & 2]
        self.rel = {}
        rela = [s for s in self.secs if s['name'] == '.rela.dyn'][0]
        for o in range(rela['offset'], rela['offset'] + rela['size'], 24):
            off, info, addend = struct.unpack_from('<QQq', data, o)
            if info & 0xffffffff == 8:
                self.rel[off] = addend & M64
        self.patch = {}

    def section_of(self, va):
        for s in self.secs:
            if s['address'] <= va < s['address'] + s['size']:
                return s
        raise Reject('unmapped %#x' % va)

    def byte(self, va):
        if va in self.patch:
            return self.patch[va]
        s = self.section_of(va)
        return self.data[s['offset'] + va - s['address']]

    def read(self, va, n):
        return bytes(self.byte(va + i) for i in range(n))

    def q(self, va):
        if va in self.rel and not any(va + i in self.patch for i in range(8)):
            return self.rel[va]
        return int.from_bytes(self.read(va, 8), 'little')


def modrm(img, va, rex):
    """Decode ModRM (+SIB, +disp) at va; return (mod, reg, operand, length)."""
    b = img.byte(va)
    mod, reg, rm = b >> 6, ((b >> 3) & 7) | ((rex & 4) << 1), b & 7
    n = 1
    if mod == 3:
        return mod, reg, ('reg', rm | ((rex & 1) << 3)), n
    base, index, scale = None, None, 1
    if rm == 4:
        sib = img.byte(va + n)
        n += 1
        scale = 1 << (sib >> 6)
        idx = ((sib >> 3) & 7) | ((rex & 2) << 2)
        if idx != 4:
            index = idx
        base = (sib & 7) | ((rex & 1) << 3)
        if sib & 7 == 5 and mod == 0:
            raise Reject('sib disp32 no base')
    elif rm == 5 and mod == 0:
        d = struct.unpack('<i', img.read(va + n, 4))[0]
        return mod, reg, ('rip', d), n + 4
    else:
        base = rm | ((rex & 1) << 3)
    disp = 0
    if mod == 1:
        disp = struct.unpack('<b', img.read(va + n, 1))[0]
        n += 1
    elif mod == 2:
        disp = struct.unpack('<i', img.read(va + n, 4))[0]
        n += 4
    return mod, reg, ('mem', base, index, scale, disp), n


def decode(img, va):
    """Decode one instruction of the fixed subset; anything else is rejected."""
    p, rex = va, 0
    if 0x40 <= img.byte(p) <= 0x4f:
        rex = img.byte(p)
        p += 1
    op = img.byte(p)
    p += 1
    w = bool(rex & 8)
    if op == 0x0f:
        op2 = img.byte(p)
        p += 1
        mod, reg, opd, n = modrm(img, p, rex)
        if op2 in (0x10, 0x11) and not w:
            return dict(op='movups_ld' if op2 == 0x10 else 'movups_st', reg=reg, opd=opd, len=p + n - va)
        if op2 == 0xb7 and not w:
            return dict(op='movzx16', reg=reg, opd=opd, len=p + n - va)
        raise Reject('0f %02x at %#x' % (op2, va))
    if op in (0x8b, 0x89, 0x8d, 0x63, 0x01) and w:
        mod, reg, opd, n = modrm(img, p, rex)
        name = {0x8b: 'mov_ld', 0x89: 'mov_st', 0x8d: 'lea', 0x63: 'movsxd', 0x01: 'add_rr'}[op]
        return dict(op=name, reg=reg, opd=opd, len=p + n - va)
    if op == 0x83 and w:
        mod, reg, opd, n = modrm(img, p, rex)
        imm = struct.unpack('<b', img.read(p + n, 1))[0]
        if mod != 3 or reg not in (0, 5):
            raise Reject('83 form at %#x' % va)
        return dict(op='add_i' if reg == 0 else 'sub_i', opd=opd, imm=imm, len=p + n + 1 - va)
    if 0xb8 <= op <= 0xbf:
        r = (op - 0xb8) | ((rex & 1) << 3)
        if w:
            return dict(op='movabs', reg=r, imm=int.from_bytes(img.read(p, 8), 'little'), len=p + 8 - va)
        return dict(op='mov_i32', reg=r, imm=int.from_bytes(img.read(p, 4), 'little'), len=p + 4 - va)
    if op == 0xff:
        mod, reg, opd, n = modrm(img, p, rex)
        if reg == 4:
            return dict(op='jmp_rm', opd=opd, len=p + n - va)
        if reg == 2:
            return dict(op='call_rm', opd=opd, len=p + n - va)
        raise Reject('ff /%d' % reg)
    if op == 0xc3 and not rex:
        return dict(op='ret', len=p - va)
    if op == 0xe9 and not rex:
        return dict(op='jmp_rel', rel=struct.unpack('<i', img.read(p, 4))[0], len=p + 4 - va)
    raise Reject('opcode %02x at %#x' % (op, va))


def ea(st, d, va):
    """Effective address of a decoded memory operand (concrete registers)."""
    k = d['opd']
    if k[0] == 'rip':
        return va + d['len'] + k[1]
    _, base, index, scale, disp = k
    a = st['r'][base] + disp
    if index is not None:
        a += st['r'][index] * scale
    return a & M64


class Machine:
    """Concrete emulator for the display body; stores only to the stack, stubs the two exits."""

    def __init__(self, img, payload):
        self.img, self.payload = img, bytearray(payload)
        self.stack = bytearray(SP0 + 0x40 - STACK_LOW)
        self.written = set()
        self.r = [0] * 16
        self.xmm = bytes(16)
        self.r[7], self.r[6], self.r[4] = PB, FB, SP0
        self.stack[SP0 - STACK_LOW:SP0 - STACK_LOW + 8] = RET_ADDR.to_bytes(8, 'little')

    def read(self, a, n):
        if PB <= a and a + n <= PB + PSIZE:
            return bytes(self.payload[a - PB:a - PB + n])
        if STACK_LOW <= a and a + n <= SP0 + 0x40:
            return bytes(self.stack[a - STACK_LOW:a - STACK_LOW + n])
        if FB <= a and a + n <= FB + 16:
            return (b'\0' * 8 + VT.to_bytes(8, 'little'))[a - FB:a - FB + n]
        if VT <= a and a + n <= VT + 0x20:
            return (b'\0' * 0x18 + WRITE_STR.to_bytes(8, 'little'))[a - VT:a - VT + n]
        if n == 8:
            return self.img.q(a).to_bytes(8, 'little')
        return self.img.read(a, n)

    def write(self, a, b):
        if not (STACK_LOW <= a and a + len(b) <= SP0 + 0x40):
            raise Reject('store outside stack %#x' % a)
        self.stack[a - STACK_LOW:a - STACK_LOW + len(b)] = b
        self.written.update(range(a, a + len(b)))

    def run(self, va, limit=64):
        img, st = self.img, {'r': self.r}
        r = self.r
        for _ in range(limit):
            d = decode(img, va)
            nxt, op = va + d['len'], d['op']
            if op == 'mov_ld':
                r[d['reg']] = int.from_bytes(self.read(ea(st, d, va), 8), 'little') if d['opd'][0] != 'reg' else r[d['opd'][1]]
            elif op == 'mov_st':
                if d['opd'][0] == 'reg':
                    r[d['opd'][1]] = r[d['reg']]
                else:
                    self.write(ea(st, d, va), r[d['reg']].to_bytes(8, 'little'))
            elif op == 'lea':
                r[d['reg']] = ea(st, d, va)
            elif op == 'movsxd':
                v = struct.unpack('<i', self.read(ea(st, d, va), 4))[0]
                r[d['reg']] = v & M64
            elif op == 'movzx16':
                r[d['reg']] = int.from_bytes(self.read(ea(st, d, va), 2), 'little')
            elif op == 'add_rr':
                r[d['opd'][1]] = (r[d['opd'][1]] + r[d['reg']]) & M64
            elif op == 'add_i':
                r[d['opd'][1]] = (r[d['opd'][1]] + d['imm']) & M64
            elif op == 'sub_i':
                r[d['opd'][1]] = (r[d['opd'][1]] - d['imm']) & M64
            elif op == 'movabs' or op == 'mov_i32':
                r[d['reg']] = d['imm']
            elif op == 'movups_ld':
                self.xmm = self.read(ea(st, d, va), 16)
            elif op == 'movups_st':
                self.write(ea(st, d, va), self.xmm)
            elif op == 'jmp_rel':
                nxt = nxt + d['rel']
            elif op == 'jmp_rm':
                t = r[d['opd'][1]]
                if t == WRITE_STR:
                    return ('str', r[6], r[2], r[4] == SP0, r[7])
                nxt = t
            elif op == 'call_rm':
                tgt = self.read(ea(st, d, va), 8)
                snap = (int.from_bytes(tgt, 'little'), r[7], r[6], r[2], r[1])
                r[0] = 0
                self.call = snap
            elif op == 'ret':
                if int.from_bytes(self.read(r[4], 8), 'little') != RET_ADDR:
                    raise Reject('bad return slot')
                return ('call',) + self.call + (r[4] == SP0,) if hasattr(self, 'call') else ('ret',)
            va = nxt
        raise Reject('step limit')


def canon_ptr(m, ptr):
    if PB <= ptr < PB + PSIZE:
        return 'P+%d' % (ptr - PB)
    if not STACK_LOW <= ptr < SP0 + 0x40:
        return 'V%x' % ptr
    q = int.from_bytes(m.read(ptr, 8), 'little')
    if PB <= q < PB + PSIZE:
        return 'S>P+%d' % (q - PB)
    return 'S=%016x' % q


def emulate(img, tag, payload):
    """Run the original bytes for one error value and return a canonical observable tuple."""
    body = bytearray(payload)
    body[0:2] = tag.to_bytes(2, 'little')
    m = Machine(img, body)
    res = m.run(ENTRY)
    if res[0] == 'str':
        _, f, rdx, sp_ok, rdi = res
        if not sp_ok:
            raise Reject('stack not restored')
        return ('S', m.r[6], rdx, rdi)  # rsi = text pointer, rdx = length, rdi = output slot
    _, target, rdi, rsi, rdx, rcx, sp_ok = res
    if not sp_ok:
        raise Reject('stack not restored')
    args = []
    k = 0
    while all(rcx + 16 * k + j in m.written for j in range(16)):
        ptr = int.from_bytes(m.read(rcx + 16 * k, 8), 'little')
        fn = int.from_bytes(m.read(rcx + 16 * k + 8, 8), 'little')
        args.append((fn, canon_ptr(m, ptr)))
        k += 1
    return ('T', target, rdx, tuple(args), rdi, rsi)


# ---- independent symbolic model -------------------------------------------------------------

def sym_arm(img, va):
    """Abstract (not concrete) execution of one arm: values are tagged tuples."""
    reg = {7: ('P', 0), 4: ('S', 0)}
    slot, xmm = {}, None
    end = None
    for _ in range(64):
        d = decode(img, va)
        op, nxt = d['op'], va + d['len']
        if op in ('mov_ld', 'lea', 'mov_st', 'movups_ld', 'movups_st') and 'opd' in d and d['opd'][0] != 'reg':
            k = d['opd']
            if k[0] == 'rip':
                tgt = nxt + k[1]
            else:
                b = reg.get(k[1])
                disp = k[4]
                if k[1] in (6,) and op == 'mov_ld':
                    tgt = ('rsi', disp)
                elif b is None and op != 'mov_ld':
                    raise Reject('base %d' % k[1])
                else:
                    tgt = (b, disp) if b else ('x', k[1], disp)
        if op == 'lea':
            k = d['opd']
            if k[0] == 'rip':
                reg[d['reg']] = ('VA', tgt)
            else:
                reg[d['reg']] = (tgt[0][0], tgt[0][1] + tgt[1])
        elif op == 'mov_ld':
            k = d['opd']
            if k[0] == 'rip':
                reg[d['reg']] = ('VA', img.q(tgt))
            elif k[0] == 'reg':
                reg[d['reg']] = reg[k[1]]
            else:
                reg[d['reg']] = ('ld', k[1], k[4])
        elif op == 'mov_st':
            k = d['opd']
            if k[0] == 'reg':
                reg[k[1]] = reg[d['reg']]
            else:
                slot[tgt[1]] = reg[d['reg']]
        elif op == 'add_i':
            v = reg[d['opd'][1]]
            reg[d['opd'][1]] = (v[0], v[1] + d['imm']) if d['opd'][1] != 4 else v
        elif op == 'movabs':
            reg[d['reg']] = ('I', d['imm'])
        elif op == 'mov_i32':
            reg[d['reg']] = ('I', d['imm'])
        elif op == 'movups_ld':
            xmm = ('PC', tgt[0][1] + tgt[1])
        elif op == 'movups_st':
            slot[tgt[1]] = ('PC', xmm[1])
            slot[tgt[1] + 8] = ('PC', xmm[1] + 8)
        elif op == 'jmp_rel':
            nxt += d['rel']
        elif op == 'jmp_rm':
            return ('S', reg[6], reg[2]), slot
        elif op == 'call_rm':
            return ('T', reg[2], reg[1], slot), slot
        elif op in ('ret',):
            raise Reject('ret without call')
        else:
            raise Reject('unmodelled %s' % op)
        va = nxt
    raise Reject('arm too long')


def arm_row(img, tag, va):
    """Model row for one tag: ('S', text_va, length) or ('T', template_va, ((fn, source), ...))."""
    res, slot = sym_arm(img, va)
    if res[0] == 'S':
        return ('S', res[1][1], res[2][1])
    base = res[2][1]
    args = []
    k = 0
    while base + 16 * k in slot and base + 16 * k + 8 in slot:
        ptr, fn = slot[base + 16 * k], slot[base + 16 * k + 8]
        if fn[0] != 'VA':
            raise Reject('formatter not a code address')
        if ptr[0] == 'P':
            src = ('p', ptr[1])
        elif ptr[0] == 'VA':
            src = ('va', ptr[1])
        else:
            v = slot[ptr[1]]
            src = {'P': ('sp', v[1]), 'PC': ('sc', v[1]), 'I': ('si', v[1])}[v[0]]
        args.append((fn[1], src))
        k += 1
    return ('T', res[1][1], tuple(args))


def table_targets(img):
    out = []
    for t in range(SLOTS):
        rel = struct.unpack('<i', img.read(TABLE_VA + 4 * t, 4))[0]
        out.append(TABLE_VA + rel)
    return out


def parse_template(img, va, mode='real'):
    """Template grammar: 0 ends, 1..0x7f is a literal of that many bytes, 0x80 is a literal whose
    length is the next u16 (little endian), 0xc0 is the next argument. The other bytes are rejected.
    `mode` selects deliberately wrong grammars for the negative controls."""
    pieces, p = [], va
    while True:
        b = img.byte(p)
        p += 1
        if b == 0:
            return pieces, p - va
        if b == 0xc0 and mode != 'no-arg':
            pieces.append(('A',))
        elif b == 0x80 and mode == 'real':
            n = int.from_bytes(img.read(p, 2), 'little')
            pieces.append(('L', img.read(p + 2, n)))
            p += 2 + n
        elif b < 0x80 or (mode in ('short-80', 'no-arg') and b <= 0xc0):
            n = b + 1 if mode == 'plus-one' else b
            pieces.append(('L', img.read(p, n)))
            p += n
        else:
            raise Reject('template byte %#x' % b)


def grammar_violations(img, rows, mode='real'):
    """Count templates whose parse disagrees with the machine code: hole count != the number of
    argument pairs the arm stores, a parse error, or a literal with a non-text byte."""
    bad = 0
    for r in rows:
        if r[2] != 'T':
            continue
        try:
            pieces, _ = parse_template(img, r[3], mode)
        except Reject:
            bad += 1
            continue
        holes = sum(1 for q in pieces if q[0] == 'A')
        text_ok = all(32 <= c < 127 for q in pieces if q[0] == 'L' for c in q[1])
        if holes != len(r[4]) or not text_ok:
            bad += 1
    return bad


def build_model(img):
    rows, targets = [], table_targets(img)
    for t, va in enumerate(targets):
        rows.append((t, va) + arm_row(img, t, va))
    return rows


def model_expect(row, payload):
    """Predict the emulator's canonical tuple for a model row and a payload."""
    _, _, kind = row[0], row[1], row[2]
    if kind == 'S':
        return ('S', row[3], row[4], 0)
    args = []
    for fn, (sk, sv) in row[4]:
        if sk == 'p':
            c = 'P+%d' % sv
        elif sk == 'va':
            c = 'V%x' % sv
        elif sk == 'sp':
            c = 'S>P+%d' % sv
        elif sk == 'sc':
            q = int.from_bytes(payload[sv:sv + 8], 'little')
            c = ('S>P+%d' % (q - PB)) if PB <= q < PB + PSIZE else 'S=%016x' % q
        else:
            c = 'S=%016x' % sv
        args.append((fn, c))
    return ('T', INTERP[0], row[3], tuple(args), 0, VT)


def payload_for(tag, variant):
    out = b''
    i = 0
    while len(out) < PSIZE:
        out += hashlib.sha256(b'awed115/%d/%d/%d' % (tag, variant, i)).digest()
        i += 1
    out = bytearray(out[:PSIZE])
    if variant % 5 == 4:                        # some payloads hold payload-relative words
        for o in range(8, 0x40, 8):
            out[o:o + 8] = (PB + (o * 3) % 0x100).to_bytes(8, 'little')
    return bytes(out)


def check(img, rows, tags, variants):
    """Compare model and emulator; return (cases, mismatches)."""
    cases = bad = 0
    for tag in tags:
        for v in range(variants):
            p = payload_for(tag, v)
            body = bytearray(p)
            body[0:2] = tag.to_bytes(2, 'little')
            try:
                got = emulate(img, tag, p)
            except Reject:
                got = ('reject',)
            try:
                want = model_expect(rows[tag], bytes(body)) if tag < len(rows) else ('undefined',)
            except (Reject, IndexError, KeyError):
                want = ('undefined',)
            cases += 1
            if want != got:
                bad += 1
    return cases, bad


# ---- negative controls -----------------------------------------------------------------------

def model_mutants(rows):
    """Deliberately wrong models: (name, mutated rows)."""
    S = [r for r in rows if r[2] == 'S']
    T = [r for r in rows if r[2] == 'T']
    T2 = [r for r in T if len(r[4]) >= 2]
    T1 = [r for r in T if len(r[4]) >= 1]
    out = []

    def put(name, idx, row):
        m = list(rows)
        m[idx] = row
        out.append((name, m))
    s0, s1 = S[0], S[len(S) // 2]
    put('swap-two-text-lengths', s0[0], s0[:4] + (s1[4],))
    put('text-length-plus-one', s0[0], s0[:4] + (s0[4] + 1,))
    put('text-length-minus-one', s1[0], s1[:4] + (s1[4] - 1,))
    put('text-address-plus-one', s0[0], s0[:3] + (s0[3] + 1,))
    put('text-address-other-arm', s1[0], s1[:3] + (s0[3],))
    put('str-as-template', s0[0], (s0[0], s0[1], 'T', s0[3], ()))
    t = T1[0]
    put('template-address-plus-one', t[0], t[:3] + (t[3] + 1, t[4]))
    put('drop-last-arg', t[0], t[:4] + (t[4][:-1],))
    put('add-extra-arg', t[0], t[:4] + (t[4] + (t[4][0],),))
    fn, (k, v) = t[4][0]
    put('wrong-formatter-address', t[0], t[:4] + (((fn + 16, (k, v)),) + t[4][1:],))
    put('wrong-source-offset', t[0], t[:4] + (((fn, (k, v + 8)),) + t[4][1:],))
    kind = {'p': 'sp', 'sp': 'p', 'sc': 'si', 'si': 'sc'}[k]
    put('wrong-source-kind', t[0], t[:4] + (((fn, (kind, v)),) + t[4][1:],))
    u = T2[0]
    put('swap-arg-order', u[0], u[:4] + (u[4][::-1],))
    for i, r in enumerate(T):
        if any(a[1][0] == 'sc' for a in r[4]):
            put('copy-source-as-immediate', r[0], r[:4] + (tuple((a[0], ('si', a[1][1])) if a[1][0] == 'sc' else a for a in r[4]),))
            break
    for i, r in enumerate(T):
        if any(a[1][0] == 'si' for a in r[4]):
            put('immediate-bit-flip', r[0], r[:4] + (tuple((a[0], ('si', a[1][1] ^ 1)) if a[1][0] == 'si' else a for a in r[4]),))
            break
    m = [(rows[(i + 1) % SLOTS][2:]) for i in range(SLOTS)]
    out.append(('tag-shift-by-one', [(i, rows[i][1]) + m[i] for i in range(SLOTS)]))
    out.append(('tag-wrap-417', [rows[i % 417] for i in range(SLOTS)]))
    mm = list(rows)
    mm[100], mm[200] = (100, rows[100][1]) + rows[200][2:], (200, rows[200][1]) + rows[100][2:]
    out.append(('swap-two-tags', mm))
    mm = list(rows)
    mm[417] = (417, rows[417][1]) + rows[0][2:]
    out.append(('last-slot-aliased-to-first', mm))
    out.append(('all-arms-text-len-zero', [r if r[2] != 'S' else r[:4] + (0,) for r in rows]))
    out.append(('args-all-dropped', [r if r[2] != 'T' else r[:4] + ((),) for r in rows]))
    out.append(('source-offsets-zero', [r if r[2] != 'T' else r[:4] + (tuple((a[0], (a[1][0], 0) if a[1][0] in ('p', 'sp', 'sc') else a[1]) for a in r[4]),) for r in rows]))
    return out


def byte_mutants(img, rows, targets):
    """Corrupt one byte of the original code or tables: (name, {va: new byte})."""
    S = [r for r in rows if r[2] == 'S']
    T = [r for r in rows if r[2] == 'T']
    out = []

    def flip(name, va, x=0x01):
        out.append((name, {va: img.byte(va) ^ x}))
    flip('table-slot-low-byte', TABLE_VA + 4 * S[0][0])
    flip('table-slot-second-byte', TABLE_VA + 4 * T[0][0] + 1)
    flip('table-last-slot', TABLE_VA + 4 * 417, 0x10)
    s = S[1]
    arm = s[1]
    # str arm layout: 48 8b 3e | 48 8b 46 08 | 48 8b 40 18 | 48 8d 35 d32 | ba imm32 ...
    flip('str-lea-displacement', arm + 14)
    flip('str-length-immediate', arm + 19)
    flip('str-vtable-offset', arm + 10)
    flip('str-prologue-load', arm + 2, 0x08)
    t = T[0]
    ins = []
    va = t[1]
    for _ in range(40):
        d = decode(img, va)
        ins.append((va, d))
        va += d['len']
        if d['op'] == 'ret':
            break
    for va, d in ins:
        if d['op'] == 'call_rm':
            flip('call-slot-displacement', va + 2)
        if d['op'] == 'lea' and d['opd'][0] == 'rip' and d['reg'] == 2:
            flip('template-lea-displacement', va + 3)
        if d['op'] == 'lea' and d['opd'][0] == 'mem' and d['reg'] == 1:
            flip('argument-array-base', va + 4)
        if d['op'] == 'mov_st' and d['opd'][0] == 'mem' and d['opd'][4] == 0x10:
            flip('argument-pointer-slot', va + 4, 0x08)
    for r in T:
        if any(a[1][0] == 'sc' for a in r[4]):
            for va, d in [(v, decode(img, v)) for v in [r[1]]]:
                flip('movups-source-offset', va + 3)
            break
    for r in T:
        if any(a[1][0] == 'si' for a in r[4]):
            flip('movabs-immediate', r[1] + 4)
            break
    for r in T:
        if any(a[1][0] == 'sp' for a in r[4]):
            flip('add-rdi-immediate', r[1] + 3)
            break
    for r in T:
        if any(a[1][0] == 'p' for a in r[4]):
            flip('lea-rdi-displacement', r[1] + 3)
            break
    flip('prologue-table-lea', ENTRY + 8 + 2)
    flip('prologue-scale', ENTRY + 20)
    out.append(('reloc-addend-patch', {}))  # replaced below by a GOT patch
    return out


def run_controls(img, rows, targets):
    results = []
    for name, m in model_mutants(rows):
        cases, bad = check(img, m, range(SLOTS), 2)
        results.append(('model', name, cases, bad))
    for name, patch in byte_mutants(img, rows, targets):
        if name == 'reloc-addend-patch':
            slot = [r for r in rows if r[2] == 'T'][0]
            gp = None
            va = slot[1]
            for _ in range(40):
                d = decode(img, va)
                if d['op'] == 'call_rm':
                    gp = va + d['len'] + d['opd'][1]
                    break
                va += d['len']
            img.rel[gp] ^= 0x10
            cases, bad = check(img, rows, [slot[0]], 2)
            img.rel[gp] ^= 0x10
            results.append(('bytes', name, cases, bad))
            continue
        img.patch = patch
        cases, bad = check(img, rows, range(SLOTS), 2)
        img.patch = {}
        results.append(('bytes', name, cases, bad))
    for tag in (418, 500, 0xffff):
        try:
            rows_wrong = rows[tag]
            hit = 0
        except IndexError:
            hit = 1
        results.append(('range', 'tag-%d-outside-table' % tag, 1, hit))
    for mode in ('short-80', 'plus-one', 'no-arg'):
        results.append(('grammar', 'template-grammar-' + mode, 81, grammar_violations(img, rows, mode)))
    results.append(('range', 'wrong-digest', 1, 1 if hashlib.sha256(b'x').hexdigest() != DIGEST else 0))
    return results


# ---- output ----------------------------------------------------------------------------------

def esc(b):
    return ''.join(chr(c) if 32 <= c < 127 and c != 92 else '\\x%02x' % c for c in b)


GOT_ENTRY_SLOT = 0x64e28a0   # RELATIVE slot whose addend is the display body (observed in RE-001 as well)


def display_segments(img, rows, tag):
    """The reference Display model: ordered segments for one tag.

    ('text', bytes) is written verbatim; ('arg', formatter_va, source_kind, source_value) is one
    formatted argument. A static arm is a single text segment. Tags outside the table are undefined
    in the binary (the dispatch has no range check), so they are an error here."""
    if not 0 <= tag < SLOTS:
        raise IndexError('tag %d is outside the 418-slot table' % tag)
    row = rows[tag]
    if row[2] == 'S':
        return [('text', img.read(row[3], row[4]))]
    out, args = [], iter(row[4])
    for piece in parse_template(img, row[3])[0]:
        if piece[0] == 'L':
            out.append(('text', piece[1]))
        else:
            fn, (kind, value) = next(args)
            out.append(('arg', fn, kind, value))
    return out


def display_text(img, rows, tag, hole='{}'):
    """Message with every argument replaced by `hole` (formatter bodies are not modelled)."""
    return b''.join(x[1] if x[0] == 'text' else hole.encode() for x in display_segments(img, rows, tag))


def entry_references(img, data):
    """Every RIP-relative reference to the GOT slot that holds the display body, found by
    byte pattern in .text: [REX] (8b|8d|ff|89) ModRM(mod 0, rm 5) disp32. Returns
    (site_va, opcode_name, containing_fde_start) rows; instruction boundaries are not proven."""
    import bisect
    import re
    text = [x for x in img.secs if x['name'] == '.text'][0]
    blob = data[text['offset']:text['offset'] + text['size']]
    fdes = fde_extents.fde_extents(data)[1]
    starts = [f['start'] for f in fdes]
    pat = re.compile(rb'[\x40-\x4f]?[\x8b\x8d\xff\x89][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', re.S)
    names = {0x8b: 'load', 0x8d: 'lea', 0xff: 'call-or-jmp', 0x89: 'store'}
    rows = []
    for m in pat.finditer(blob):
        i = m.end() - 1
        if i + 5 > len(blob):
            continue
        disp = struct.unpack_from('<i', blob, i + 1)[0]
        site = text['address'] + m.start()
        end = text['address'] + i + 5
        if end + disp != GOT_ENTRY_SLOT:
            continue
        k = bisect.bisect_right(starts, site) - 1
        rows.append((site, names[blob[i - 1]], fdes[k]['start']))
    return rows


def build(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise SystemExit('input is not node #115')
    img = Image(data)
    ext = [r for r in fde_extents.fde_extents(data)[1] if r['start'] == ENTRY]
    if len(ext) != 1:
        raise SystemExit('FDE not found')
    start, end = ext[0]['start'], ext[0]['end']
    head = img.read(ENTRY, 4)
    if head != b'\x48\x83\xec\x38':
        raise SystemExit('prologue differs')
    targets = table_targets(img)
    for t in targets:
        if not start <= t < end:
            raise SystemExit('table target outside body')
    rows = build_model(img)
    first = [r for r in rows if r[2] == 'T'][0][0]
    INTERP[0] = emulate(img, first, payload_for(first, 0))[1]
    cases, bad = check(img, rows, range(SLOTS), VARIANTS)
    ctl = run_controls(img, rows, targets)
    return img, rows, targets, start, end, cases, bad, ctl


def render(img, rows, targets, start, end, cases, bad, ctl):
    files = {}
    L = ['tag\tarm_va\tkind\tpayload_arg_count\tinsn_count\ttext_or_template_va\ttext_len\ttext']
    arms = {}
    for r in rows:
        va, n = r[1], 0
        while True:
            d = decode(img, va)
            n += 1
            va += d['len']
            if d['op'] in ('ret', 'jmp_rm', 'jmp_rel'):
                if d['op'] == 'jmp_rel':
                    va += d['rel']
                    continue
                break
        if r[2] == 'S':
            L.append('%d\t%#x\tstr\t0\t%d\t%#x\t%d\t%s' % (r[0], r[1], n, r[3], r[4], esc(img.read(r[3], r[4]))))
        else:
            pieces, ln = parse_template(img, r[3])
            L.append('%d\t%#x\ttmpl\t%d\t%d\t%#x\t%d\t%s' % (r[0], r[1], len(r[4]), n, r[3], ln,
                     ''.join('{}' if p[0] == 'A' else esc(p[1]) for p in pieces)))
    files['arms.tsv'] = '\n'.join(L) + '\n'
    L = ['site_va\tkind\tcontaining_fde_start']
    for site, kind, fde in entry_references(img, img.data):
        L.append('%#x\t%s\t%#x' % (site, kind, fde))
    files['entry-references.tsv'] = '\n'.join(L) + '\n'
    L = ['tag\ttemplate_va\tpiece_index\tpiece_kind\tbytes\ttext']
    A = ['tag\targ_index\tformatter_va\tsource\tvalue']
    ntp = 0
    for r in rows:
        if r[2] != 'T':
            continue
        pieces, ln = parse_template(img, r[3])
        if grammar_violations(img, [r]):
            raise SystemExit('template grammar violated at tag %d' % r[0])
        n_hole = sum(1 for p in pieces if p[0] == 'A')
        if n_hole != len(r[4]):
            raise SystemExit('template holes %d != args %d at tag %d' % (n_hole, len(r[4]), r[0]))
        ntp += 1
        for i, p in enumerate(pieces):
            L.append('%d\t%#x\t%d\t%s\t%d\t%s' % (r[0], r[3], i, 'arg' if p[0] == 'A' else 'lit',
                     0 if p[0] == 'A' else len(p[1]), '' if p[0] == 'A' else esc(p[1])))
        for k, (fn, (sk, sv)) in enumerate(r[4]):
            A.append('%d\t%d\t%#x\t%s\t%s' % (r[0], k, fn, sk, '%#x' % sv if sk == 'si' else sv))
    files['template-pieces.tsv'] = '\n'.join(L) + '\n'
    files['template-args.tsv'] = '\n'.join(A) + '\n'
    share = {}
    for r in rows:
        share.setdefault(r[1], []).append(r[0])
    L = ['arm_va\ttags']
    for va in sorted(share):
        if len(share[va]) > 1:
            L.append('%#x\t%s' % (va, ','.join(map(str, share[va]))))
    files['shared-arms.tsv'] = '\n'.join(L) + '\n'
    fns = {}
    for r in rows:
        if r[2] == 'T':
            for fn, _ in r[4]:
                fns[fn] = fns.get(fn, 0) + 1
    L = ['formatter_va\tuses']
    for fn in sorted(fns):
        L.append('%#x\t%d' % (fn, fns[fn]))
    files['formatters.tsv'] = '\n'.join(L) + '\n'
    L = ['family\tcontrol\tcases\tmismatches\tdetected']
    for fam, name, c, b in ctl:
        L.append('%s\t%s\t%d\t%d\t%d' % (fam, name, c, b, 1 if b else 0))
    files['negative-controls.tsv'] = '\n'.join(L) + '\n'
    kinds = {}
    for r in rows:
        kinds[r[2]] = kinds.get(r[2], 0) + 1
    srcs = {}
    for r in rows:
        if r[2] == 'T':
            for _, (sk, _) in r[4]:
                srcs[sk] = srcs.get(sk, 0) + 1
    gp = None
    for r in rows:
        if r[2] == 'T':
            va = r[1]
            while True:
                d = decode(img, va)
                if d['op'] == 'call_rm':
                    gp = va + d['len'] + d['opd'][1]
                    break
                va += d['len']
            break
    summary = dict(binary_sha256=DIGEST, entry=hex(ENTRY), body_end=hex(end), body_bytes=end - start, table_va=hex(TABLE_VA),
                   slots=SLOTS, distinct_arms=len(share), str_tags=kinds['S'], template_tags=kinds['T'],
                   argument_sources=dict(sorted(srcs.items())), formatter_functions=len(fns),
                   template_interpreter_slot=hex(gp), template_interpreter_target=hex(img.q(gp)),
                   cases=cases, mismatches=bad, variants_per_tag=VARIANTS,
                   negative_controls=len(ctl), negative_detected=sum(1 for c in ctl if c[3]))
    files['summary.json'] = json.dumps(summary, indent=1, sort_keys=True) + '\n'
    files['measure.json'] = json.dumps(dict(cases=cases, negative_controls=len(ctl),
                                            negative_detected=sum(1 for c in ctl if c[3])), sort_keys=True) + '\n'
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    data = TARGET.read_bytes()
    img, rows, targets, start, end, cases, bad, ctl = build(data)
    if bad:
        raise SystemExit('model disagrees with the machine code in %d cases' % bad)
    files = render(img, rows, targets, start, end, cases, bad, ctl)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out / name).write_text(text)
    print('cases', cases, 'controls', len(ctl), 'detected', sum(1 for c in ctl if c[3]))


if __name__ == '__main__':
    main()
