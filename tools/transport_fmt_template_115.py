#!/usr/bin/env python3
"""Node #115 compact format-template interpreter (0x1680500) and the peer/client-block
error Display body (0x564ad60) that drives it.

The packet does not execute hl-node.  It decodes the two function bodies out of the ELF
bytes with a small stdlib x86-64 decoder, runs those bytes on the repository's integer
`Machine` (tools/evm_amount_scale.py) with every external call stubbed, and compares the
result with an independent Python model on generated cases.
"""
import argparse
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import evm_amount_scale as eng  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

ROOT = HERE.parent
BINARY = 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
FMT_VA = 0x1680500
DISP_VA = 0x564ad60
JUMP_TABLE = 0x92882c
JUMP_ENTRIES = 22
SLOT_FMT = 0x64df6f0
DEFAULT_FLAGS = 0x60000020
MASK = eng.MASK
RAM = eng.RAM_BASE

# fake external code addresses (outside RAM and outside the ELF)
S_WRITE = 0x7fff1000
S_ARG = 0x7fff2000          # + 0x10 * n for argument printers
S_COUNT = 0x7fff3000        # entries used only as width / precision counters
TEMPLATE_BASE = RAM + 0x2000
ARGS_BASE = RAM + 0x3000
WRITER_BASE = RAM + 0x4000
FMTOBJ_BASE = RAM + 0x4100
VTABLE_BASE = RAM + 0x4200
SELF_BASE = RAM + 0x5000
PAYLOAD_BASE = RAM + 0x5100


class Mismatch(Exception):
    pass


def require(ok, message):
    if not ok:
        raise ValueError(message)


# ---------------------------------------------------------------- decoder

CCS = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g']


class Decoder:
    """x86-64 subset decoder yielding Machine tuples (va, mnemonic, operands, next)."""

    def __init__(self, code, base):
        self.c = code
        self.base = base

    def modrm(self, pos, rex, size, end_extra):
        c = self.c
        b = c[pos]
        pos += 1
        mod, reg, rm = b >> 6, (b >> 3) & 7 | ((rex & 4) << 1), b & 7
        if mod == 3:
            return pos, reg, ('r', rm | ((rex & 1) << 3), size), mod
        base = index = None
        scale = 1
        disp = 0
        if rm == 4:
            sib = c[pos]
            pos += 1
            scale = 1 << (sib >> 6)
            i = (sib >> 3) & 7 | ((rex & 2) << 2)
            bs = sib & 7
            if i != 4:
                index = i
            if bs == 5 and mod == 0:
                disp = struct.unpack_from('<i', c, pos)[0]
                pos += 4
            else:
                base = bs | ((rex & 1) << 3)
        elif rm == 5 and mod == 0:
            disp = struct.unpack_from('<i', c, pos)[0]
            pos += 4
            return pos, reg, ('rip', size, disp), mod
        else:
            base = rm | ((rex & 1) << 3)
        if mod == 1:
            disp = struct.unpack_from('<b', c, pos)[0]
            pos += 1
        elif mod == 2:
            disp = struct.unpack_from('<i', c, pos)[0]
            pos += 4
        return pos, reg, ('m', size, base, index, scale, disp), mod

    def decode(self, pos):
        c = self.c
        start = pos
        rex = 0
        opsz = 4
        p66 = False
        while c[pos] in (0x66, 0x2e):
            if c[pos] == 0x66:
                opsz = 2
                p66 = True
            pos += 1
        if 0x40 <= c[pos] <= 0x4f:
            rex = c[pos]
            pos += 1
            if rex & 8:
                opsz = 8
        op = c[pos]
        pos += 1
        va = self.base + start

        def fix(o, nxt):
            # rip-relative operands become absolute once the instruction length is known
            if o[0] == 'rip':
                return ('a', o[1], self.base + nxt + o[2])
            return o

        def done(mn, ops, nxt):
            return (va, mn, [fix(o, nxt) for o in ops], self.base + nxt)

        def reg8(idx, size):
            require(size != 1 or rex or idx < 4 or idx >= 8, 'high byte register')
            return ('r', idx, size)

        if 0x50 <= op <= 0x5f:
            r = (op & 7) | ((rex & 1) << 3)
            return done('push' if op < 0x58 else 'pop', [('r', r, 8)], pos)
        if op in (0x88, 0x89, 0x8a, 0x8b, 0x84, 0x85, 0x01, 0x03, 0x29, 0x2b, 0x31, 0x33, 0x39, 0x3b, 0x8d):
            size = 1 if op in (0x88, 0x8a, 0x84) else opsz
            pos, reg, rm, _ = self.modrm(pos, rex, size, 0)
            r = reg8(reg, size)
            if op in (0x88, 0x89):
                return done('mov', [rm, r], pos)
            if op in (0x8a, 0x8b):
                return done('mov', [r, rm], pos)
            if op == 0x8d:
                return done('lea', [r, rm], pos)
            if op in (0x84, 0x85):
                return done('test', [rm, r], pos)
            mn = {0x01: 'add', 0x03: 'add', 0x29: 'sub', 0x2b: 'sub', 0x31: 'xor', 0x33: 'xor', 0x39: 'cmp', 0x3b: 'cmp'}[op]
            return done(mn, [rm, r] if op in (0x01, 0x29, 0x31, 0x39) else [r, rm], pos)
        if op == 0x63:
            pos, reg, rm, _ = self.modrm(pos, rex, 4, 0)
            return done('movslq', [('r', reg, opsz), rm], pos)
        if op in (0xc6, 0xc7):
            size = 1 if op == 0xc6 else opsz
            pos, reg, rm, _ = self.modrm(pos, rex, size, 0)
            require(reg & 7 == 0, 'mov group')
            if size == 1:
                imm = c[pos]
                pos += 1
            elif size == 2:
                imm = struct.unpack_from('<H', c, pos)[0]
                pos += 2
            else:
                imm = struct.unpack_from('<i', c, pos)[0] & (MASK if size == 8 else 0xffffffff)
                pos += 4
            return done('mov', [rm, ('i', imm)], pos)
        if 0xb0 <= op <= 0xb7:
            r = (op & 7) | ((rex & 1) << 3)
            return done('mov', [reg8(r, 1), ('i', c[pos])], pos + 1)
        if 0xb8 <= op <= 0xbf and rex & 8:
            r = (op & 7) | ((rex & 1) << 3)
            return done('mov', [('r', r, 8), ('i', struct.unpack_from('<Q', c, pos)[0])], pos + 8)
        if 0xb8 <= op <= 0xbf:
            r = (op & 7) | ((rex & 1) << 3)
            return done('mov', [('r', r, 4), ('i', struct.unpack_from('<I', c, pos)[0])], pos + 4)
        if op in (0xa8, 0x3c, 0x2c):
            mn = {0xa8: 'test', 0x3c: 'cmp', 0x2c: 'sub'}[op]
            return done(mn, [('r', 0, 1), ('i', c[pos])], pos + 1)
        if op == 0xf7 and (c[pos] >> 3) & 7 == 4:
            pos, reg, rm, _ = self.modrm(pos, rex, opsz, 0)
            return done('mul', [rm], pos)
        if op == 0x6b:
            pos, reg, rm, _ = self.modrm(pos, rex, opsz, 0)
            imm = struct.unpack_from('<b', c, pos)[0] & ((1 << (8 * opsz)) - 1)
            return done('imul', [('r', reg, opsz), rm, ('i', imm)], pos + 1)
        if op == 0x69:
            pos, reg, rm, _ = self.modrm(pos, rex, opsz, 0)
            imm = struct.unpack_from('<i', c, pos)[0] & ((1 << (8 * opsz)) - 1)
            return done('imul', [('r', reg, opsz), rm, ('i', imm)], pos + 4)
        if op in (0xf6, 0xf7, 0x80, 0x81, 0x83):
            size = 1 if op in (0xf6, 0x80) else opsz
            pos, reg, rm, _ = self.modrm(pos, rex, size, 0)
            sub = reg & 7
            if op in (0xf6, 0x80, 0x83):
                imm = struct.unpack_from('<b' if op != 0xf6 else '<B', c, pos)[0] & ((1 << (8 * size)) - 1)
                pos += 1
            else:
                imm = struct.unpack_from('<i', c, pos)[0] & ((1 << (8 * size)) - 1)
                pos += 4
            if op == 0xf6:
                require(sub == 0, 'f6 group')
                return done('test', [rm, ('i', imm)], pos)
            mn = {0: 'add', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp'}[sub]
            return done(mn, [rm, ('i', imm)], pos)
        if op in (0xc1, 0xd1):
            pos, reg, rm, _ = self.modrm(pos, rex, opsz, 0)
            if op == 0xc1:
                imm = c[pos]
                pos += 1
            else:
                imm = 1
            return done({4: 'shl', 5: 'shr'}[reg & 7], [rm, ('i', imm)], pos)
        if op == 0xff:
            pos, reg, rm, _ = self.modrm(pos, rex, 8 if (reg_peek := (c[pos] >> 3) & 7) in (2, 4) else opsz, 0)
            if reg_peek == 0:
                return done('inc', [rm], pos)
            if reg_peek == 1:
                return done('dec', [rm], pos)
            if reg_peek == 2:
                return done('call', [rm], pos)
            require(reg_peek == 4, 'ff group')
            return done('jmp', [rm], pos)
        if op == 0xe9 or op == 0xe8:
            rel = struct.unpack_from('<i', c, pos)[0]
            nxt = pos + 4
            return done('jmp' if op == 0xe9 else 'call', [('t', self.base + nxt + rel)], nxt)
        if op == 0xeb:
            rel = struct.unpack_from('<b', c, pos)[0]
            return done('jmp', [('t', self.base + pos + 1 + rel)], pos + 1)
        if 0x70 <= op <= 0x7f:
            rel = struct.unpack_from('<b', c, pos)[0]
            return done('j' + CCS[op - 0x70], [('t', self.base + pos + 1 + rel)], pos + 1)
        if op == 0xc3:
            return done('ret', [], pos)
        if op == 0xcc:
            return done('int3', [], pos)
        if op == 0x0f:
            op2 = c[pos]
            pos += 1
            if 0x80 <= op2 <= 0x8f:
                rel = struct.unpack_from('<i', c, pos)[0]
                return done('j' + CCS[op2 - 0x80], [('t', self.base + pos + 4 + rel)], pos + 4)
            if p66 and op2 in (0x6e, 0x7e):
                pos, reg, rm, _ = self.modrm(pos, rex, 4, 0)
                x = ('x', reg)
                return done('movd', [x, rm] if op2 == 0x6e else [rm, x], pos)
            if p66 and op2 == 0xc4:
                pos, reg, rm, _ = self.modrm(pos, rex, 2, 0)
                return done('pinsrw', [('x', reg), rm, ('i', c[pos])], pos + 1)
            if op2 in (0xb6, 0xb7):
                pos, reg, rm, _ = self.modrm(pos, rex, 1 if op2 == 0xb6 else 2, 0)
                return done('movzx', [('r', reg, opsz if opsz != 2 else 4), rm], pos)
            if 0x40 <= op2 <= 0x4f:
                pos, reg, rm, _ = self.modrm(pos, rex, opsz, 0)
                return done('cmov' + CCS[op2 - 0x40], [('r', reg, opsz), rm], pos)
            if op2 == 0x1f:
                pos, reg, rm, _ = self.modrm(pos, rex, opsz, 0)
                return done('nop', [], pos)
        raise ValueError(f'undecodable byte {op:#x} at {va:#x}')


class Machine(eng.Machine):
    def i_movslq(self, ops):
        v = self.rd(ops[1])
        self.wr(ops[0], v | (MASK ^ 0xffffffff) if v >> 31 else v)

    def i_movd(self, ops):
        dst, src = ops
        if dst[0] == 'x':
            self.xmm[dst[1]] = self.rd(src) & 0xffffffff
        else:
            if self.xmm[src[1]] is None:
                raise eng.Unmodelled(f'read of unset xmm at {self.pc:#x}')
            self.wr(dst, self.xmm[src[1]] & 0xffffffff)

    def i_pinsrw(self, ops):
        dst, src, imm = ops
        shift = 16 * (imm[1] & 7)
        old = self.xmm[dst[1]]
        if old is None:
            raise eng.Unmodelled(f'read of unset xmm at {self.pc:#x}')
        self.xmm[dst[1]] = (old & ~(0xffff << shift)) | ((self.rd(src) & 0xffff) << shift)

    def i_int3(self, ops):
        raise eng.Unmodelled(f'int3 at {self.pc:#x}')


def fde_end(data, start):
    _, fdes = eh_frame_records(data)
    for f in fdes:
        if f['start'] == start:
            return f['end']
    raise ValueError(f'no FDE starts at {start:#x}')


# ---------------------------------------------------------------- binary context

class Binary:
    def __init__(self, data):
        require(len(data) == 105896032 and hashlib.sha256(data).hexdigest() == SHA256, 'Wrong node115 target')
        self.data = data
        self.img = eng.Image(data)
        self.slots = self.img.slots()
        _, fdes = eh_frame_records(data)
        self.fde_map = {f['start']: f['end'] for f in fdes}
        self.fmt_end = self.fde_map[FMT_VA]
        self.disp_end = self.fde_map[DISP_VA]
        self.decoded = {}
        self.fmt_code, _ = self.decode_fn(FMT_VA, self.fmt_end)
        self.disp_code, _ = self.decode_fn(DISP_VA, self.disp_end)

    def decode_fn(self, start, end):
        code = self.img.read(start, end - start)
        dec = Decoder(code, start)
        out = []
        pos = 0
        while pos < len(code):
            if code[pos] == 0xcc:
                pos += 1
                continue
            ins = dec.decode(pos)
            out.append(ins)
            pos = ins[3] - start
        return out, pos

    def machine(self, insns, slots=None):
        return Machine(insns, self.img, dict(self.slots if slots is None else slots))



    def decode_bytes(self, code, start):
        dec = Decoder(code, start)
        out = []
        pos = 0
        while pos < len(code):
            if code[pos] == 0xcc:
                pos += 1
                continue
            ins = dec.decode(pos)
            out.append(ins)
            pos = ins[3] - start
        return out

    def fmt_bytes(self):
        return bytes(self.img.read(FMT_VA, self.fmt_end - FMT_VA))

    def disp_bytes(self):
        return bytes(self.img.read(DISP_VA, self.disp_end - DISP_VA))

    def machine_for(self, fmt_code, disp_code=None):
        return self.machine(list(fmt_code) + list(disp_code or []))


# ---------------------------------------------------------------- reference model of 0x1680500

class Sink:
    """write_str target: records every write and fails the `fail_at`-th (1-based) one."""

    def __init__(self, fail_at=None):
        self.fail_at = fail_at
        self.n = 0
        self.events = []

    def write(self, data):
        self.n += 1
        self.events.append(('w', bytes(data)))
        return self.fail_at is not None and self.n == self.fail_at


def marker(key):
    if isinstance(key, tuple):
        return ('<%s>' % ':'.join('%x' % k for k in key)).encode()
    return ('<%x>' % key).encode()


def u16(t, pos):
    return t[pos] | t[pos + 1] << 8


def model_format(template, args, sink, plain=None, mut=None):
    """Independent model of the interpreter.  args: list of dicts {key, count}.
    Returns the al result (1 = a sink call failed)."""
    err = 0 if mut == 'error-status-zero' else 1
    if plain is not None:
        return err if sink.write(plain) else 0
    pos = 0
    counter = 0
    while True:
        b = template[pos]
        if b == 0:
            return 0
        if b < 0x80:
            n = b + 1 if mut == 'short-literal-plus-one' else b
            if sink.write(template[pos + 1:pos + 1 + n]):
                return err
            pos += 1 + n
            continue
        if b == 0x80:
            n = (template[pos + 1] << 8 | template[pos + 2]) if mut == 'long-length-big-endian' else u16(template, pos + 1)
            if sink.write(template[pos + 3:pos + 3 + n]):
                return err
            pos += 3 + n + (1 if mut == 'long-literal-skips-one' else 0)
            continue
        pos += 1
        flags = 0x20 if mut == 'default-flags-0x20' else DEFAULT_FLAGS
        width = prec = 0
        idx = counter
        if b != 0xc0:
            if b & 1:
                flags = struct.unpack_from('>I' if mut == 'flags-big-endian' else '<I', template, pos)[0]
                pos += 4
            order = (4, 2) if mut == 'precision-before-width' else (2, 4)
            for bit in order:
                if b & bit:
                    if bit == 2:
                        width = u16(template, pos)
                    else:
                        prec = u16(template, pos)
                    pos += 2
            if b & 8:
                idx = u16(template, pos)
                pos += 2
            if b & 0x10 and mut != 'width-count-ignored':
                width = args[width]['count']
            if b & 0x20 and mut != 'precision-count-ignored':
                prec = args[prec]['count']
        a = args[idx]
        sink.events.append(('a', a['key'], flags, width, prec))
        if sink.write(marker(a['key'])):
            return err
        counter = idx + (2 if mut == 'counter-skips' else 1)
        if mut == 'explicit-index-keeps-counter' and b != 0xc0 and b & 8:
            counter = idx


def model_run(template, args, fail_at, plain=None, mut=None):
    sink = Sink(fail_at)
    status = model_format(template, args, sink, plain, mut)
    return status, sink.events


# ---------------------------------------------------------------- emulator drivers

def put(m, addr, data):
    lo = addr - RAM
    require(0 <= lo and lo + len(data) <= eng.RAM_SIZE, 'harness data outside RAM')
    m.ram[lo:lo + len(data)] = data
    m.valid[lo:lo + len(data)] = b'\x01' * len(data)


def ret(m, status):
    m.setreg(eng.RAX, status)
    m.cf = m.zf = m.sf = m.of = None
    m.i_ret(())


def drive(m, entry, stops, hooks, limit=400000):
    pc = entry
    while True:
        pc = m.run(pc, stop=stops, limit=limit)
        if pc == eng.RET_MAGIC:
            return m.regs[eng.RAX] & 0xff
        ret(m, hooks[pc](m))
        pc = m.pc


def start(m, rdi, rsi, rdx, rcx):
    m.setreg(eng.RSP, eng.STACK_TOP)
    eng.Machine.store(m, eng.STACK_TOP, 8, eng.RET_MAGIC)
    for r, v in ((eng.RDI, rdi), (eng.RSI, rsi), (eng.RDX, rdx), (eng.RCX, rcx)):
        m.setreg(r, v)


def read_mem(m, addr, n):
    if RAM <= addr < RAM + eng.RAM_SIZE:
        return bytes(m.load(addr + i, 1) for i in range(n))
    return bytes(m.img.read(addr, n))


def write_hook(sink):
    def hook(m):
        return 1 if sink.write(read_mem(m, m.regs[eng.RSI], m.regs[eng.RDX])) else 0
    return hook


def arg_hook(sink, keyfn):
    def hook(m):
        rec = m.regs[eng.RSI]
        key = keyfn(m)
        sink.events.append(('a', key, m.load(rec + 0x10, 4), m.load(rec + 0x14, 2), m.load(rec + 0x16, 2)))
        return 1 if sink.write(marker(key)) else 0
    return hook


def prepare_writer(m):
    put(m, WRITER_BASE, struct.pack('<QQQQ', 0, 0, 0, S_WRITE))
    put(m, FMTOBJ_BASE, struct.pack('<QQ', 0x1111, WRITER_BASE))


def emu_format(binary, fmt_code, template, args, fail_at, plain=None):
    """Run the 0x1680500 bytes.  args: list of dicts {key, count, printer, stub}."""
    m = binary.machine_for(fmt_code)
    prepare_writer(m)
    sink = Sink(fail_at)
    if plain is not None:
        put(m, TEMPLATE_BASE, plain)
        start(m, 0x1111, WRITER_BASE, TEMPLATE_BASE, len(plain) << 1 | 1)
    else:
        put(m, TEMPLATE_BASE, template)
        tab = b''.join(struct.pack('<QQ', 0xA000 + i, a['stub'] if a['printer'] else a['count'])
                       for i, a in enumerate(args))
        put(m, ARGS_BASE, tab)
        start(m, 0x1111, WRITER_BASE, TEMPLATE_BASE, ARGS_BASE)
    stops = {S_WRITE} | {a['stub'] for a in args if a['printer']}
    hooks = {S_WRITE: write_hook(sink)}
    for a in args:
        if a['printer']:
            hooks[a['stub']] = arg_hook(sink, (lambda key: (lambda m: key))(a['key']))
    return drive(m, FMT_VA, stops, hooks), sink.events


# ---------------------------------------------------------------- Display body (0x564ad60)

# arm index -> (kind, template or string VA, length for plain strings, [(printer VA, field offset)])
ARMS = [
    ('t', 0x431d68, 0, [(0x4f0df50, 8)]),
    ('t', 0x4450ac, 0, [(0x4f0df50, 8)]),
    ('t', 0x43f583, 0, [(0x53d57b0, 8)]),
    ('t', 0x44f856, 0, [(0x5a2ee40, 0)]),
    ('t', 0x4450c1, 0, [(0x53d57b0, 8), (0x53d57b0, 0x10)]),
    ('p', 0x92aa54, 9, []),
    ('p', 0x92aa5d, 0x1c, []),
    ('p', 0x92aa79, 0x14, []),
    ('p', 0x92aa8d, 0x16, []),
    ('p', 0x92aaa3, 0x1a, []),
    ('p', 0x92aabd, 0x1d, []),
    ('p', 0x92aada, 0x1b, []),
    ('t', 0x43d210, 0, [(0x5616370, 8), (0x5616370, 0x10)]),
    ('t', 0x433cbd, 0, [(0x57d1030, 1), (0x57d1030, 0x21)]),
    ('t', 0x432ea8, 0, [(0x53d55c0, 1), (0x53d55c0, 0x21)]),
    ('p', 0x92aaf5, 0x11, []),
    ('t', 0x43f5a9, 0, [(0x4f0df50, 8)]),
    ('t', 0x449260, 0, [(0x4f0df50, 8)]),
    ('t', 0x4450ea, 0, [(0x4f0df50, 8)]),
    ('t', 0x44bf5f, 0, [(0x4f0df50, 8), (0x4f0df50, 0x20)]),
    ('p', 0x92ab06, 0x11, []),
    ('p', 0x92ab17, 0xf, []),
]
TAG_BASE = 0x2e
MAX_TAG = TAG_BASE + len(ARMS) - 1
PRINTERS = sorted({fn for arm in ARMS for fn, _ in arm[3]})


def arm_for_tag(tag):
    """Dispatcher: tag - 0x2e as an unsigned byte; tags below 0x2e borrow and select arm 3."""
    return tag - TAG_BASE if tag >= TAG_BASE else 3


def jump_table(binary):
    raw = binary.img.read(JUMP_TABLE, JUMP_ENTRIES * 4)
    return [JUMP_TABLE + struct.unpack_from('<i', raw, 4 * i)[0] for i in range(JUMP_ENTRIES)]


def display_model(binary, tag, fail_at, mut=None):
    idx = arm_for_tag(tag)
    if mut == 'wrap-arm-zero' and tag < TAG_BASE:
        idx = 0
    kind, va, ln, fields = ARMS[idx]
    if kind == 'p':
        return model_run(None, [], fail_at, plain=bytes(binary.img.read(va, ln)), mut=mut)
    args = [dict(key=(fn, off), count=0) for fn, off in fields]
    return model_run(bytes(binary.img.read(va, 255)), args, fail_at, mut=mut)


def display_emu(binary, fmt_code, disp_code, tag, fail_at):
    m = binary.machine_for(fmt_code, disp_code)
    prepare_writer(m)
    put(m, SELF_BASE, bytes([tag]) + bytes(range(1, 0x40)))
    sink = Sink(fail_at)
    start(m, SELF_BASE, FMTOBJ_BASE, 0, 0)
    hooks = {S_WRITE: write_hook(sink)}
    stops = {S_WRITE} | set(PRINTERS)
    for fn in PRINTERS:
        hooks[fn] = arg_hook(sink, (lambda fn: (lambda m: (fn, m.load(m.regs[eng.RDI], 8) - SELF_BASE)))(fn))
    return drive(m, DISP_VA, stops, hooks), sink.events


# ---------------------------------------------------------------- byte-derived census of 0x1680500 callers

LEA_RDX = b'\x48\x8d\x15'


def call_sites(binary):
    """Every `call *slot(%rip)` through the formatter slot, with the nearest preceding
    `lea disp(%rip),%rdx` in the same FDE extent (the static template pointer)."""
    img = binary.img
    t_va, t_off, t_size = img.section('.text')
    text = binary.data[t_off:t_off + t_size]
    extents = sorted(binary.fde_map.items())
    starts = [s for s, _ in extents]
    import bisect
    rows = []
    pos = 0
    while True:
        p = text.find(b'\xff\x15', pos)
        if p < 0:
            break
        pos = p + 1
        if t_va + p + 6 + struct.unpack_from('<i', text, p + 2)[0] != SLOT_FMT:
            continue
        va = t_va + p
        i = bisect.bisect_right(starts, va) - 1
        fs, fe = extents[i]
        require(fs <= va < fe, 'call site outside every FDE')
        tmpl = None
        q = text.rfind(LEA_RDX, max(0, fs - t_va), p)
        if q >= 0 and va - (t_va + q) <= 0x200:
            tmpl = t_va + q + 7 + struct.unpack_from('<i', text, q + 3)[0]
        rows.append((va, fs, fe, tmpl))
    return rows


def parse_template(binary, va, limit=4096):
    """Static walk of a template; returns dict or None when it does not terminate in .rodata."""
    img = binary.img
    r_va, _, r_size = img.section('.rodata')
    if not (r_va <= va < r_va + r_size):
        return None
    end = min(va + limit, r_va + r_size)
    raw = bytes(img.read(va, end - va))
    pos = 0
    pieces = []
    need = 0
    counter = 0
    try:
        while True:
            b = raw[pos]
            if b == 0:
                break
            if b < 0x80:
                pieces.append(('lit', raw[pos + 1:pos + 1 + b]))
                require(pos + 1 + b < len(raw), 'literal past window')
                pos += 1 + b
            elif b == 0x80:
                n = u16(raw, pos + 1)
                pieces.append(('lit', raw[pos + 3:pos + 3 + n]))
                require(pos + 3 + n < len(raw), 'literal past window')
                pos += 3 + n
            else:
                pos += 1
                idx = counter
                wref = pref = None
                flags = None
                width = prec = 0
                if b != 0xc0:
                    if b & 1:
                        flags = struct.unpack_from('<I', raw, pos)[0]
                        pos += 4
                    if b & 2:
                        width = u16(raw, pos)
                        pos += 2
                    if b & 4:
                        prec = u16(raw, pos)
                        pos += 2
                    if b & 8:
                        idx = u16(raw, pos)
                        pos += 2
                    if b & 0x10:
                        wref = width
                    if b & 0x20:
                        pref = prec
                need = max(need, idx + 1, (wref or 0) + (1 if wref is not None else 0),
                           (pref or 0) + (1 if pref is not None else 0))
                pieces.append(('arg', b, idx, flags, wref, pref))
                counter = idx + 1
            require(pos < len(raw), 'template past window')
    except (IndexError, ValueError, struct.error):
        return None
    return dict(length=pos + 1, pieces=pieces, nargs=need, bytes=raw[:pos + 1])


def census(binary):
    sites = call_sites(binary)
    templates = {}
    for va, fs, fe, tmpl in sites:
        if tmpl is None:
            continue
        info = parse_template(binary, tmpl)
        if info is None:
            continue
        rec = templates.setdefault(tmpl, dict(info, sites=0, first=va))
        rec['sites'] += 1
    return sites, templates


def synthetic_args(nargs, rng=None):
    args = []
    for i in range(nargs):
        stub = S_ARG + 0x10 * i
        args.append(dict(key=(i,), printer=True, stub=stub, count=stub & 0xffff))
    return args


# ---------------------------------------------------------------- random template generator

def gen_case(rng):
    nprint = rng.randint(1, 5)
    ncount = rng.randint(0, 3)
    args = []
    for i in range(nprint + ncount):
        stub = S_ARG + 0x10 * i
        if i < nprint:
            args.append(dict(key=(i,), printer=True, stub=stub, count=stub & 0xffff))
        else:
            args.append(dict(key=(i,), printer=False, stub=stub, count=rng.randint(0, 0xffff)))
    out = bytearray()
    counter = 0
    for _ in range(rng.randint(0, 7)):
        t = rng.random()
        if t < 0.3:
            n = rng.randint(1, 0x7f)
            out += bytes([n]) + bytes(rng.randrange(256) for _ in range(n))
        elif t < 0.4:
            n = rng.choice([0, 1, 127, 128, 255, 256, rng.randint(0, 600)])
            out += b'\x80' + struct.pack('<H', n) + bytes(rng.randrange(256) for _ in range(n))
        else:
            if counter >= nprint and rng.random() < 0.7:
                continue
            if t < 0.55 and counter < nprint:
                out.append(0xc0)
                counter += 1
                continue
            b = rng.randrange(0x81, 0x100)
            if b == 0xc0:
                b = 0xc1
            idx = counter
            piece = bytearray([b])
            if b & 1:
                piece += struct.pack('<I', rng.randrange(1 << 32))
            if b & 2:
                piece += struct.pack('<H', rng.randrange(1 << 16))
            if b & 4:
                piece += struct.pack('<H', rng.randrange(1 << 16))
            if b & 8:
                idx = rng.randrange(nprint)
                piece += struct.pack('<H', idx)
            elif idx >= nprint:
                continue
            # patch width / precision references that must name an existing entry
            pos = 1 + (4 if b & 1 else 0)
            if b & 2:
                if b & 0x10:
                    piece[pos:pos + 2] = struct.pack('<H', rng.randrange(len(args)))
                pos += 2
            if b & 4:
                if b & 0x20:
                    piece[pos:pos + 2] = struct.pack('<H', rng.randrange(len(args)))
                pos += 2
            out += piece
            counter = idx + 1
    out.append(0)
    return bytes(out), args, rng.choice([None, None, None, 1, 2, 3, 4, 6])


# ---------------------------------------------------------------- case suites

def digest(status, events):
    h = hashlib.sha256()
    h.update(bytes([status]))
    for e in events:
        h.update(repr(e).encode())
    return h.hexdigest()[:16]


def check_format(binary, fmt_code, template, args, fail_at, plain=None, mut=None):
    got = emu_format(binary, fmt_code, template, args, fail_at, plain)
    want = model_run(template, args, fail_at, plain, mut)
    return got == want, got, want


def random_cases(count, seed=115):
    rng = random.Random(seed)
    return [gen_case(rng) for _ in range(count)]


def run_random(binary, count):
    rows = []
    ok = 0
    for i, (tmpl, args, fail) in enumerate(random_cases(count)):
        same, got, want = check_format(binary, binary.fmt_code, tmpl, args, fail)
        if not same:
            raise Mismatch(f'random case {i}: emulator {got} model {want}')
        ok += 1
        rows.append((i, len(tmpl), fail, got[0], digest(*got)))
    return ok, rows


def run_census(binary, templates):
    rows = []
    ok = skipped = 0
    for va in sorted(templates):
        info = templates[va]
        if info['nargs'] > 40:
            skipped += 1
            continue
        args = synthetic_args(info['nargs'])
        for fail in (None, 1, 2, 3, 5):
            same, got, want = check_format(binary, binary.fmt_code, info['bytes'], args, fail)
            if not same:
                raise Mismatch(f'template {va:#x} fail {fail}: emulator {got} model {want}')
            ok += 1
            rows.append((va, info['nargs'], fail, got[0], digest(*got)))
    return ok, skipped, rows


def run_display(binary, fails=(None, 1, 2, 3, 4)):
    rows = []
    ok = 0
    for tag in range(0, MAX_TAG + 1):
        for fail in fails:
            got = display_emu(binary, binary.fmt_code, binary.disp_code, tag, fail)
            want = display_model(binary, tag, fail)
            if got != want:
                raise Mismatch(f'tag {tag:#x} fail {fail}: emulator {got} model {want}')
            ok += 1
            rows.append((tag, arm_for_tag(tag), fail, got[0], digest(*got)))
    return ok, rows


# ---------------------------------------------------------------- negative controls

MODEL_MUTANTS = ['short-literal-plus-one', 'long-length-big-endian', 'long-literal-skips-one',
                 'default-flags-0x20', 'flags-big-endian', 'precision-before-width',
                 'width-count-ignored', 'precision-count-ignored', 'counter-skips',
                 'explicit-index-keeps-counter', 'error-status-zero']
DISPLAY_MODEL_MUTANTS = ['wrap-arm-zero', 'error-status-zero', 'short-literal-plus-one']


def control_set(binary):
    return random_cases(400, seed=7)


def find_all(code, pattern):
    out = []
    pos = code.find(pattern)
    while pos >= 0:
        out.append(pos)
        pos = code.find(pattern, pos + 1)
    return out


def byte_mutations(binary):
    """(name, function, offset, replacement) derived by byte-pattern search in the bodies."""
    f = binary.fmt_bytes()
    d = binary.disp_bytes()
    muts = []

    def one(code, which, name, pattern, delta, nth=0, new=None):
        pos = find_all(code, pattern)
        require(len(pos) > nth, f'pattern for {name} not found')
        at = pos[nth] + delta
        repl = new if new is not None else bytes([code[at] ^ 1])
        muts.append((name, which, at, repl))

    one(f, 'fmt', 'long-literal-tag-0x80-to-0x81', b'\x3c\x80', 1)
    one(f, 'fmt', 'default-arg-tag-0xc0-to-0xc1', b'\x41\x81\xff\xc0', 3)
    one(f, 'fmt', 'default-flags-imm-low', b'\x48\xc7\x45\xc8\x20\x00\x00\x60', 4)
    one(f, 'fmt', 'default-flags-imm-high', b'\x48\xc7\x45\xc8\x20\x00\x00\x60', 7, new=b'\x40')
    one(f, 'fmt', 'counter-shift-4-to-3', b'\x48\xc1\xe0\x04', 3, new=b'\x03')
    one(f, 'fmt', 'flag-bit-1-mask', b'\xa8\x01', 1, new=b'\x41')
    one(f, 'fmt', 'flag-bit-2-mask', b'\xa8\x02', 1, new=b'\x42')
    one(f, 'fmt', 'flag-bit-4-mask', b'\xa8\x04', 1, new=b'\x44')
    one(f, 'fmt', 'flag-bit-8-mask', b'\xa8\x08', 1, new=b'\x48')
    one(f, 'fmt', 'flag-bit-10-mask', b'\xa8\x10', 1, new=b'\x50')
    one(f, 'fmt', 'flag-bit-20-mask', b'\xa8\x20', 1, new=b'\x60')
    one(f, 'fmt', 'long-literal-offset-3-to-4', b'\x49\x8d\x75\x03', 3, new=b'\x04')
    one(f, 'fmt', 'long-literal-length-field-offset', b'\x45\x0f\xb7\x7d\x01', 4, new=b'\x02')
    one(f, 'fmt', 'short-literal-advance-to-sub', b'\x4d\x01\xfc', 0, new=b'\x4d\x29\xfc')
    one(f, 'fmt', 'counter-increment-to-decrement', b'\x49\xff\xc7', 1, new=b'\xff\xcf')
    one(f, 'fmt', 'terminator-test-jump-inverted', b'\x84\xc0\x0f\x84\x4b\x01', 3, new=b'\x85')
    one(f, 'fmt', 'error-return-value-0', b'\xb0\x01', 1, new=b'\x00')
    one(f, 'fmt', 'plain-string-shift-removed', b'\x48\xd1\xeb', 1, new=b'\xe3')
    one(f, 'fmt', 'writer-vtable-slot-0x18-to-0x10', b'\x48\x8b\x4e\x18', 3, new=b'\x10')
    one(d, 'disp', 'tag-bias-0x2e-to-0x2f', b'\x2c\x2e', 1, new=b'\x2f')
    one(d, 'disp', 'out-of-range-arm-3-to-4', b'\xb9\x03\x00\x00\x00', 1, new=b'\x04')
    one(d, 'disp', 'plain-length-0x1b-to-0x1a', b'\xba\x1b\x00\x00\x00', 1, new=b'\x1a')
    one(d, 'disp', 'plain-length-0x1c-to-0x1d', b'\xba\x1c\x00\x00\x00', 1, new=b'\x1d')
    one(d, 'disp', 'field-offset-0x21-to-0x22', b'\x48\x83\xc7\x21', 3, new=b'\x22')
    one(d, 'disp', 'second-field-offset-0x10-to-0x18', b'\x48\x83\xc7\x10', 3, new=b'\x18')
    one(d, 'disp', 'first-field-offset-8-to-0x10', b'\x48\x8d\x47\x08', 3, new=b'\x10')
    one(d, 'disp', 'template-pointer-displacement', b'\x48\x8d\x15', 3)
    one(d, 'disp', 'frame-slot-0x30-to-0x38', b'\x48\x89\x44\x24\x30', 4, new=b'\x38')
    one(d, 'disp', 'argument-count-slot', b'\x48\x8d\x4c\x24\x10', 4, new=b'\x18')
    return muts


def apply_mutation(binary, mut):
    name, which, at, repl = mut
    f, d = bytearray(binary.fmt_bytes()), bytearray(binary.disp_bytes())
    target = f if which == 'fmt' else d
    target[at:at + len(repl)] = repl
    try:
        fc = binary.decode_bytes(bytes(f), FMT_VA)
        dc = binary.decode_bytes(bytes(d), DISP_VA)
    except (ValueError, IndexError, struct.error):
        return None, None
    return fc, dc


def detects(binary, mut, cases, tags):
    """True when the mutated body disagrees with the reference model (or fails to run)."""
    fc, dc = apply_mutation(binary, mut)
    if fc is None:
        return True
    try:
        if mut[1] == 'fmt':
            for tmpl, args, fail in cases:
                if emu_format(binary, fc, tmpl, args, fail) != model_run(tmpl, args, fail):
                    return True
        for tag in tags:
            for fail in (None, 1, 2):
                if display_emu(binary, fc, dc, tag, fail) != display_model(binary, tag, fail):
                    return True
    except (eng.Unmodelled, KeyError, IndexError, ValueError, struct.error):
        return True
    return False


def model_differs(want_fn, got):
    try:
        return want_fn() != got
    except (IndexError, KeyError, ValueError, struct.error):
        return True


def run_controls(binary):
    cases = control_set(binary)
    tags = list(range(0, MAX_TAG + 1))
    rows = []
    emu = [emu_format(binary, binary.fmt_code, t, a, f) for t, a, f in cases]
    for mut in MODEL_MUTANTS:
        hit = any(model_differs(lambda: model_run(t, a, f, mut=mut), emu[i]) for i, (t, a, f) in enumerate(cases))
        rows.append(('model', mut, 'detected' if hit else 'survived'))
    emu_disp = {(tag, fail): display_emu(binary, binary.fmt_code, binary.disp_code, tag, fail)
                for tag in tags for fail in (None, 1, 2)}
    for mut in DISPLAY_MODEL_MUTANTS:
        hit = any(model_differs(lambda: display_model(binary, k[0], k[1], mut=mut), emu_disp[k]) for k in emu_disp)
        rows.append(('display-model', mut, 'detected' if hit else 'survived'))
    for mut in byte_mutations(binary):
        rows.append(('bytes', mut[0], 'detected' if detects(binary, mut, cases[:120], tags) else 'survived'))
    # range / identity controls
    for mut in printer_mutations():
        rows.append(('printer-bytes', mut[0], 'detected' if printer_detects(binary, mut) else 'survived'))
    for tag in (MAX_TAG + 1, MAX_TAG + 2, 0xff):
        try:
            display_emu(binary, binary.fmt_code, binary.disp_code, tag, None)
            rows.append(('range', f'tag-{tag:#x}', 'survived'))
        except (eng.Unmodelled, KeyError, IndexError):
            rows.append(('range', f'tag-{tag:#x}', 'detected'))
    for name, data in (('wrong-length', bytes(binary.data[:-1])), ('flipped-byte', bytes(binary.data[:100]) + bytes([binary.data[100] ^ 1]) + bytes(binary.data[101:]))):
        try:
            Binary(data)
            rows.append(('identity', name, 'survived'))
        except ValueError:
            rows.append(('identity', name, 'detected'))
    return rows


# ---------------------------------------------------------------- rendering and evidence files

def esc(raw):
    out = []
    for c in raw:
        if c == 0x5c:
            out.append('\\\\')
        elif c == 0x09:
            out.append('\\t')
        elif c == 0x0a:
            out.append('\\n')
        elif 0x20 <= c < 0x7f:
            out.append(chr(c))
        else:
            out.append('\\x%02x' % c)
    return ''.join(out)


def render_template(pieces):
    out = []
    for p in pieces:
        if p[0] == 'lit':
            out.append(esc(p[1]))
            continue
        _, b, idx, flags, wref, pref = p
        extra = []
        if flags is not None:
            extra.append('flags=%#x' % flags)
        if wref is not None:
            extra.append('width=arg%d' % wref)
        if pref is not None:
            extra.append('prec=arg%d' % pref)
        out.append('{%d%s}' % (idx, (':' + ','.join(extra)) if extra else ''))
    return ''.join(out)


def spec_signature(pieces):
    sig = []
    for p in pieces:
        sig.append('L' if p[0] == 'lit' else ('D' if p[1] == 0xc0 else '%02x' % p[1]))
    return '.'.join(sig)


def function_digest(code):
    return hashlib.sha256(code).hexdigest()


def lines(rows):
    return ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def build(binary, out):
    sites, templates = census(binary)
    random_ok, random_rows = run_random(binary, RANDOM_CASES)
    census_ok, skipped, census_rows = run_census(binary, templates)
    display_ok, display_rows = run_display(binary)
    printer_ok, printer_rows = run_printers(binary)
    controls = run_controls(binary)
    detected = sum(1 for r in controls if r[2] == 'detected')
    require(detected == len(controls), 'a negative control survived')
    cases = random_ok + census_ok + display_ok + printer_ok
    kinds = {}
    for t in templates.values():
        for p in t['pieces']:
            key = 'literal' if p[0] == 'lit' else ('default-arg' if p[1] == 0xc0 else 'spec-%02x' % p[1])
            kinds[key] = kinds.get(key, 0) + 1
    arm_rows = []
    table = jump_table(binary)
    for tag in range(0, MAX_TAG + 1):
        idx = arm_for_tag(tag)
        kind, va, ln, fields = ARMS[idx]
        if kind == 'p':
            text = esc(bytes(binary.img.read(va, ln)))
        else:
            text = render_template(parse_template(binary, va)['pieces'])
        arm_rows.append((hex(tag), idx, hex(table[idx]), kind, hex(va),
                         ','.join('%s+%s' % (hex(fn), hex(off)) for fn, off in fields) or '-', text))
    records = dict(
        target=dict(binary=BINARY, size=len(binary.data), sha256=SHA256),
        interpreter=dict(start=hex(FMT_VA), end=hex(binary.fmt_end), instructions=len(binary.fmt_code),
                         bytes_sha256=function_digest(binary.fmt_bytes()), slot=hex(SLOT_FMT),
                         slot_addend=hex(binary.slots[SLOT_FMT]), default_flags=hex(DEFAULT_FLAGS)),
        display=dict(start=hex(DISP_VA), end=hex(binary.disp_end), instructions=len(binary.disp_code),
                     bytes_sha256=function_digest(binary.disp_bytes()), jump_table=hex(JUMP_TABLE),
                     jump_entries=JUMP_ENTRIES, tag_base=hex(TAG_BASE), max_tag=hex(MAX_TAG),
                     printers=[hex(p) for p in PRINTERS]),
        census=dict(call_sites=len(sites), sites_with_template=sum(1 for s in sites if s[3]),
                    functions=len({s[1] for s in sites}), distinct_templates=len(templates),
                    skipped_wide=skipped, piece_kinds=dict(sorted(kinds.items()))),
        cases=dict(random=random_ok, random_seed=115, census=census_ok, display=display_ok, printers=printer_ok, total=cases),
        random_digest=hashlib.sha256(lines(random_rows).encode()).hexdigest(),
        negative_controls=dict(total=len(controls), detected=detected),
    )
    measure = dict(cases=cases, negative_controls=len(controls), negative_detected=detected, equivalent=0)
    files = {
        'records.json': json.dumps(records, indent=2, sort_keys=True) + '\n',
        'measure.json': json.dumps(measure, indent=2, sort_keys=True) + '\n',
        'display-arms.tsv': lines([('tag', 'arm', 'arm_va', 'kind', 'data_va', 'printers', 'rendered')] + arm_rows),
        'templates.tsv': lines([('template_va', 'bytes', 'nargs', 'sites', 'signature', 'rendered')] + [
            (hex(va), t['length'], t['nargs'], t['sites'], spec_signature(t['pieces']), render_template(t['pieces']))
            for va, t in sorted(templates.items())]),
        'call-sites.tsv': lines([('call_va', 'function_start', 'function_end', 'template_va')] + [
            (hex(va), hex(fs), hex(fe), hex(t) if t else '-') for va, fs, fe, t in sites]),
        'census-cases.tsv': lines([('template_va', 'nargs', 'fail_at', 'status', 'digest')] + [
            (hex(a), b, c if c is not None else '-', d, e) for a, b, c, d, e in census_rows]),
        'display-cases.tsv': lines([('tag', 'arm', 'fail_at', 'status', 'digest')] + [
            (hex(a), b, c if c is not None else '-', d, e) for a, b, c, d, e in display_rows]),
        'printer-cases.tsv': lines([('printer', 'input', 'digest')] + printer_rows[:PRINTER_SAMPLE]),
        'random-cases.tsv': lines([('case', 'template_bytes', 'fail_at', 'status', 'digest')] + [
            (a, b, c if c is not None else '-', d, e) for a, b, c, d, e in random_rows[:RANDOM_SAMPLE]]),
        'controls.tsv': lines([('family', 'control', 'result')] + controls),
    }
    out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out / name).write_text(text)
    return records, measure


RANDOM_CASES = 8000
RANDOM_SAMPLE = 1000
PRINTER_SAMPLE = 800


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', required=True)
    ap.add_argument('--binary', default=str(ROOT / BINARY))
    args = ap.parse_args()
    data = Path(args.binary).read_bytes()
    binary = Binary(data)
    records, measure = build(binary, Path(args.out))
    print(json.dumps(measure, sort_keys=True))


# ---------------------------------------------------------------- argument printers used by the Display body

P_STR, P_U64, P_REF, P_WRAP = 0x4f0df50, 0x5616370, 0x5a2ee40, 0x53d57b0
SLOT_STR, SLOT_PAD, SLOT_REF, SLOT_WRAP_FN = 0x64df720, 0x64dfa00, 0x64ebf90, 0x64e0a98
WRAP_TEMPLATE = 0x43b857
VALUE_CELL = RAM + 0x6000
POINTER_CELL = RAM + 0x6010
STRING_CELL = RAM + 0x6100
STRING_DATA = RAM + 0x6200


def printer_machine(binary, va):
    end = fde_end(binary.data, va)
    return binary.machine(binary.decode_bytes(bytes(binary.img.read(va, end - va)), va)), end


def run_printer(binary, va, setup, targets, fmt_too=False, regs=None, code=None):
    """Run one printer body.  `targets` maps stub addresses to hook functions; every call that
    leaves the body must land on one of them."""
    if code is not None:
        insns = binary.decode_bytes(code, va)
    else:
        if va not in binary.decoded:
            binary.decoded[va] = binary.decode_bytes(bytes(binary.img.read(va, binary.fde_map[va] - va)), va)
        insns = binary.decoded[va]
    if fmt_too:
        insns = insns + binary.fmt_code
    m = binary.machine(insns)
    prepare_writer(m)
    setup(m)
    rdi, rsi = regs
    start(m, rdi, rsi, 0, 0)
    log = []
    hooks = {t: (lambda h: (lambda m: h(m, log)))(h) for t, h in targets.items()}
    status = drive(m, va, set(targets), hooks)
    return status, log


def hook_log(name):
    def hook(m, log):
        log.append((name, m.regs[eng.RDI], m.regs[eng.RSI], m.regs[eng.RDX], m.regs[eng.RCX],
                    m.regs[eng.R8], m.regs[eng.R9]))
        return 0
    return hook


def u64_emu(binary, value, code=None):
    def setup(m):
        put(m, VALUE_CELL, struct.pack('<Q', value))
        put(m, POINTER_CELL, struct.pack('<Q', VALUE_CELL))

    def pad(m, log):
        buf = read_mem(m, m.regs[eng.R8], m.regs[eng.R9])
        log.append(('pad_integral', m.regs[eng.RDI], m.regs[eng.RSI], m.regs[eng.RDX], m.regs[eng.RCX], buf))
        return 0
    return run_printer(binary, P_U64, setup, {binary.slots[SLOT_PAD]: pad}, regs=(POINTER_CELL, FMTOBJ_BASE), code=code)


def u64_model(value):
    return 0, [('pad_integral', FMTOBJ_BASE, 1, 1, 0, str(value).encode())]


def string_emu(binary, ptr, length, code=None):
    def setup(m):
        put(m, STRING_CELL, struct.pack('<QQQ', 0x77, ptr, length))
        put(m, POINTER_CELL, struct.pack('<Q', STRING_CELL))

    def tgt(m, log):
        log.append(('str', m.regs[eng.RDI], m.regs[eng.RSI], m.regs[eng.RDX]))
        return 0
    return run_printer(binary, P_STR, setup, {binary.slots[SLOT_STR]: tgt}, regs=(POINTER_CELL, FMTOBJ_BASE), code=code)


def string_model(ptr, length):
    return 0, [('str', FMTOBJ_BASE, ptr, length)]


def ref_emu(binary, inner, code=None):
    def setup(m):
        put(m, POINTER_CELL, struct.pack('<Q', inner))

    def tgt(m, log):
        log.append(('ref', m.regs[eng.RDI], m.regs[eng.RSI]))
        return 0
    return run_printer(binary, P_REF, setup, {binary.slots[SLOT_REF]: tgt}, regs=(POINTER_CELL, FMTOBJ_BASE), code=code)


def ref_model(inner):
    return 0, [('ref', inner, FMTOBJ_BASE)]


def wrap_emu(binary, value, fail_at):
    """0x53d57b0: builds a one-argument table {value, fn} and runs the interpreter on
    the shared template 0x43b857 (a lone default argument)."""
    def setup(m):
        put(m, POINTER_CELL, struct.pack('<Q', VALUE_CELL))
        put(m, VALUE_CELL, struct.pack('<Q', value))

    sink = Sink(fail_at)
    fn = binary.slots[SLOT_WRAP_FN]

    def arg(m, log):
        rec = m.regs[eng.RSI]
        log.append(('arg', m.regs[eng.RDI], fn, m.load(rec + 0x10, 4), m.load(rec + 0x14, 2), m.load(rec + 0x16, 2)))
        return 1 if sink.write(b'<wrapped>') else 0
    status, log = run_printer(binary, P_WRAP, setup, {fn: arg, S_WRITE: write_hook(sink)}, fmt_too=True,
                              regs=(POINTER_CELL, FMTOBJ_BASE))
    return status, log + sink.events


def wrap_model(binary, value, fail_at):
    tmpl = bytes(binary.img.read(WRAP_TEMPLATE, 8))
    sink = Sink(fail_at)
    status = 0
    pieces = parse_template(binary, WRAP_TEMPLATE)['pieces']
    require(len(pieces) == 1 and pieces[0][0] == 'arg' and pieces[0][1] == 0xc0 and tmpl[:2] == b'\xc0\x00', 'unexpected wrap template')
    log = [('arg', VALUE_CELL, binary.slots[SLOT_WRAP_FN], DEFAULT_FLAGS, 0, 0)]
    if sink.write(b'<wrapped>'):
        status = 1
    return status, log + sink.events


def interesting_u64():
    vals = {0, 1, 9, 10, 11, 99, 100, 101, 999, 1000, 1001, 9999, 10000, 99999, 100000, 999999, 1000000,
            9999999, 10000000, 9999999 + 1, 99999999, 100000000, 10 ** 15, 10 ** 19, 2 ** 32 - 1, 2 ** 32,
            2 ** 63 - 1, 2 ** 63, 2 ** 64 - 1, 2 ** 64 - 2, 18446744073709551610}
    for k in range(1, 20):
        vals.update({10 ** k - 1, 10 ** k, 10 ** k + 1})
    return sorted(v for v in vals if v < 2 ** 64)


def run_printers(binary, count=2500):
    rng = random.Random(1155)
    rows = []
    ok = 0
    values = interesting_u64() + [rng.getrandbits(rng.randint(1, 64)) for _ in range(count)]
    for v in values:
        got, want = u64_emu(binary, v), u64_model(v)
        if got != want:
            raise Mismatch(f'u64 {v}: emulator {got} model {want}')
        ok += 1
        rows.append(('u64', v, digest(*got)))
    for _ in range(200):
        ptr, ln = rng.getrandbits(48), rng.getrandbits(20)
        got, want = string_emu(binary, ptr, ln), string_model(ptr, ln)
        if got != want:
            raise Mismatch(f'string {ptr} {ln}')
        ok += 1
        rows.append(('string', '%x:%x' % (ptr, ln), digest(*got)))
        inner = rng.getrandbits(40)
        got, want = ref_emu(binary, inner), ref_model(inner)
        if got != want:
            raise Mismatch(f'ref {inner}')
        ok += 1
        rows.append(('ref', '%x' % inner, digest(*got)))
        v = rng.getrandbits(64)
        for fail in (None, 1):
            got, want = wrap_emu(binary, v, fail), wrap_model(binary, v, fail)
            if got != want:
                raise Mismatch(f'wrap {v} {fail}: {got} {want}')
            ok += 1
            rows.append(('wrap', '%x/%s' % (v, fail), digest(*got)))
    return ok, rows


def printer_mutations():
    """(name, printer VA, byte pattern, delta, replacement)."""
    return [('u64-table-scale-2-to-1', P_U64, b'\x0f\xb7\x04\x47', 3, b'\x07'),
            ('u64-hundred-multiplier', P_U64, b'\x6b\xd8\x64', 2, b'\x65'),
            ('u64-pad-nonneg-flag', P_U64, b'\xbe\x01\x00\x00\x00', 1, b'\x00'),
            ('u64-buffer-length-0x14', P_U64, b'\x41\xb9\x14\x00\x00\x00', 2, b'\x13'),
            ('u64-division-shift', P_U64, b'\x48\xc1\xea\x0b', 3, b'\x0a'),
            ('u64-ten-thousand-multiplier', P_U64, b'\x69\xc2\x10\x27', 2, b'\x11'),
            ('u64-small-threshold', P_U64, b'\x49\x81\xf8\xe8\x03', 3, b'\xe9'),
            ('string-length-offset', P_STR, b'\x48\x8b\x51\x10', 3, b'\x08'),
            ('ref-no-deref', P_REF, b'\x48\x8b\x3f', 1, b'\x89\xff')]


def printer_detects(binary, mut, count=40):
    name, va, pattern, delta, repl = mut
    code = bytearray(binary.img.read(va, binary.fde_map[va] - va))
    at = bytes(code).find(pattern)
    require(at >= 0, f'pattern for {name} not found')
    code[at + delta:at + delta + len(repl)] = repl
    code = bytes(code)
    rng = random.Random(3)
    try:
        for _ in range(count):
            if va == P_U64:
                for v in interesting_u64():
                    if u64_emu(binary, v, code) != u64_model(v):
                        return True
                v = rng.getrandbits(rng.randint(1, 64))
                if u64_emu(binary, v, code) != u64_model(v):
                    return True
            elif va == P_STR:
                ptr, ln = rng.getrandbits(40), rng.getrandbits(16) | 0x100
                if string_emu(binary, ptr, ln, code) != string_model(ptr, ln):
                    return True
            else:
                inner = rng.getrandbits(40)
                if ref_emu(binary, inner, code) != ref_model(inner):
                    return True
    except (eng.Unmodelled, ValueError, KeyError, IndexError, struct.error):
        return True
    return False


if __name__ == '__main__':
    main()
