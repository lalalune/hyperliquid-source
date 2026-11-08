#!/usr/bin/env python3
"""Reconstruct the node #115 action-handler prior-key wrapper template (ten clones).

The ten functions below share one 1087-byte body that differs only in
position-dependent rel32 fields and in the final tail call.  The tool decodes
the real bytes with a small x86-64 interpreter (only the instruction forms the
template uses; anything else fails closed), runs every clone on generated
machine states with all callees replaced by recording stubs, and compares the
observable behaviour with an independent pure-Python model.  Nothing is
executed from the binary: bytes are only read and interpreted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import elf_index  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
COPIES = [0x2c05370, 0x2c05c70, 0x2c0e9a0, 0x2c13570, 0x2c14de0,
          0x2c15220, 0x2c16020, 0x2c182b0, 0x2c1aee0, 0x2c1c240]
SIZE = 1087
TAIL_SITE = 0x307  # offset of the final call opcode inside the template (checked at run time)
CASES_PER_COPY = 1100
OUT_FILES = ['template.tsv', 'cases-sample.tsv', 'controls.tsv', 'summary.json', 'measure.json']

# stub call targets (absolute) and GOT slots used by the template
T_LOOKUP, T_HASH, T_PROBE = 0x2a8ab70, 0x4717440, 0x3ed25b0
T_FIRST, T_SECOND, T_DROP = 0x2c202b0, 0x2c206b0, 0x2443a40
T_CLEANUP = 0x2474630
G_MEMCMP, G_PANIC, G_ABORT = 0x64dfb50, 0x64df620, 0x64df4c0
KEY_LEN = 20
REJECT_TAG, REJECT_CODE = 0xf, 0x120
OK_CODE = 0x1a2

OUT, CTX, KEY, STACK, RET_MAGIC = 0x10000000, 0x20000000, 0x30000000, 0x7ffe0000, 0xdead0000
M64 = (1 << 64) - 1


class Fail(Exception):
    pass


class Panic(Exception):
    pass


# --------------------------------------------------------------------------- ELF access
def load_binary(path=BINARY):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise Fail('input binary digest differs from node #115')
    text = next(s for s in elf_index.sections(data) if s['name'] == '.text')
    return data, text


class Code:
    def __init__(self, data, text):
        self.data, self.text = data, text

    def byte_at(self, va):
        t = self.text
        if not t['address'] <= va < t['address'] + t['size']:
            raise Fail('fetch outside .text: %#x' % va)
        return self.data[t['offset'] + va - t['address']]

    def slice(self, va, n):
        return bytes(self.byte_at(va + i) for i in range(n))


# --------------------------------------------------------------------------- interpreter
class Machine:
    def __init__(self, code, stubs):
        self.code, self.stubs = code, stubs
        self.r = [0] * 16
        self.x = [0] * 16
        self.f = dict(z=0, s=0, c=0, o=0)
        self.m = {}
        self.rip = 0
        self.steps = 0
        self.fields = set()
        self.jcc = set()

    # memory
    def rd(self, a, n):
        m = self.m
        return int.from_bytes(bytes(m.get(a + i, 0) for i in range(n)), 'little')

    def wr(self, a, n, v):
        for i, b in enumerate((v & ((1 << (8 * n)) - 1)).to_bytes(n, 'little')):
            self.m[a + i] = b

    def put(self, a, blob):
        for i, b in enumerate(blob):
            self.m[a + i] = b

    def get(self, a, n):
        return bytes(self.m.get(a + i, 0) for i in range(n))

    # registers
    def setr(self, i, size, v):
        if size == 8:
            self.r[i] = v & M64
        elif size == 4:
            self.r[i] = v & 0xffffffff
        elif size == 2:
            self.r[i] = (self.r[i] & ~0xffff & M64) | (v & 0xffff)
        else:
            self.r[i] = (self.r[i] & ~0xff & M64) | (v & 0xff)

    def getr(self, i, size):
        return self.r[i] & ((1 << (8 * size)) - 1)

    # flags
    def arith(self, op, a, b, size):
        bits = 8 * size
        mask = (1 << bits) - 1
        a &= mask
        b &= mask
        if op in ('sub', 'cmp'):
            res = (a - b) & mask
            self.f['c'] = int(a < b)
            self.f['o'] = ((a ^ b) & (a ^ res)) >> (bits - 1) & 1
        elif op == 'add':
            full = a + b
            res = full & mask
            self.f['c'] = int(full > mask)
            self.f['o'] = (~(a ^ b) & (a ^ res)) >> (bits - 1) & 1
        else:
            res = {'and': a & b, 'or': a | b, 'xor': a ^ b, 'test': a & b}[op]
            self.f['c'] = self.f['o'] = 0
        self.f['z'] = int(res == 0)
        self.f['s'] = res >> (bits - 1) & 1
        return res

    def cond(self, cc):
        f = self.f
        v = [f['o'], f['c'], f['z'], f['c'] | f['z'], f['s'], 0,
             int(f['s'] != f['o']), f['z'] | int(f['s'] != f['o'])][cc >> 1]
        if cc >> 1 == 5:
            raise Fail('parity condition not modelled')
        return bool(v) != bool(cc & 1)

    # decoding helpers
    def fetch(self):
        b = self.code.byte_at(self.rip)
        self.rip += 1
        return b

    def imm(self, n, signed=True):
        v = int.from_bytes(bytes(self.fetch() for _ in range(n)), 'little')
        if signed and v >> (8 * n - 1):
            v -= 1 << (8 * n)
        return v

    def modrm(self, rex):
        b = self.fetch()
        mod, reg, rm = b >> 6, (b >> 3 & 7) | (rex >> 2 & 1) << 3, b & 7
        if mod == 3:
            return mod, reg, ('r', rm | (rex & 1) << 3)
        base = index = None
        scale = 1
        if rm == 4:
            sib = self.fetch()
            scale = 1 << (sib >> 6)
            ix = (sib >> 3 & 7) | (rex >> 1 & 1) << 3
            bs = sib & 7
            index = None if ix == 4 else ix
            if bs == 5 and mod == 0:
                base, disp = None, self.imm(4)
            else:
                base = bs | (rex & 1) << 3
                disp = 0
        elif rm == 5 and mod == 0:
            disp = self.imm(4)
            self.fields.add(self.rip - 4)
            return mod, reg, ('rip', disp)
        else:
            base, disp = rm | (rex & 1) << 3, 0
        if mod == 1:
            disp = self.imm(1)
        elif mod == 2:
            disp = self.imm(4)
        return mod, reg, ('m', base, index, scale, disp)

    def addr(self, op):
        if op[0] == 'rip':
            return (self.rip + op[1]) & M64
        _, base, index, scale, disp = op
        a = disp + (self.r[base] if base is not None else 0) + (self.r[index] * scale if index is not None else 0)
        return a & M64

    def read_rm(self, op, size):
        return self.getr(op[1], size) if op[0] == 'r' else self.rd(self.addr(op), size)

    def write_rm(self, op, size, v):
        if op[0] == 'r':
            self.setr(op[1], size, v)
        else:
            self.wr(self.addr(op), size, v)

    def push(self, v):
        self.r[4] = (self.r[4] - 8) & M64
        self.wr(self.r[4], 8, v)

    def pop(self):
        v = self.rd(self.r[4], 8)
        self.r[4] = (self.r[4] + 8) & M64
        return v

    def do_call(self, key):
        stub = self.stubs.get(key)
        if stub is None:
            raise Fail('call to unmodelled target %#x' % key)
        stub(self)

    # one instruction
    def step(self):
        self.steps += 1
        if self.steps > 20000:
            raise Fail('step budget exceeded')
        p66 = pf3 = False
        rex = 0
        b = self.fetch()
        while b in (0x66, 0xf3, 0x2e):
            p66 |= b == 0x66
            pf3 |= b == 0xf3
            b = self.fetch()
        if 0x40 <= b <= 0x4f:
            rex = b
            b = self.fetch()
        w = bool(rex & 8)
        size = 8 if w else (2 if p66 else 4)
        if 0x50 <= b <= 0x57:
            return self.push(self.r[b - 0x50 | (rex & 1) << 3])
        if 0x58 <= b <= 0x5f:
            self.r[b - 0x58 | (rex & 1) << 3] = self.pop()
            return
        if b == 0xc3:
            self.rip = self.pop()
            return
        if b == 0xcc or b == 0x90:
            if b == 0xcc:
                raise Fail('int3 reached')
            return
        if b == 0x98:
            if w:
                v = self.getr(0, 4)
                self.r[0] = (v - (1 << 32) if v >> 31 else v) & M64
            return
        if b == 0xe8:
            d = self.imm(4)
            self.fields.add(self.rip - 4)
            self.do_call((self.rip + d) & M64)
            return
        if b == 0xe9 or b == 0xeb:
            d = self.imm(4 if b == 0xe9 else 1)
            if b == 0xe9:
                self.fields.add(self.rip - 4)
            self.rip = (self.rip + d) & M64
            return
        if 0x70 <= b <= 0x7f:
            d = self.imm(1)
            self.jcc.add(self.rip - 2)
            if self.cond(b & 15):
                self.rip = (self.rip + d) & M64
            return
        if 0xb8 <= b <= 0xbf:
            self.setr(b - 0xb8 | (rex & 1) << 3, size, self.imm(8 if w else 4, False))
            return
        if b == 0x3c:
            self.arith('cmp', self.getr(0, 1), self.imm(1, False), 1)
            return
        if b == 0xa8:
            self.arith('test', self.getr(0, 1), self.imm(1, False), 1)
            return
        if b in (0x01, 0x03, 0x09, 0x0b, 0x21, 0x23, 0x29, 0x2b, 0x31, 0x33, 0x39, 0x3b, 0x85,
                 0x00, 0x28, 0x30, 0x38, 0x84, 0x88, 0x89, 0x8a, 0x8b, 0x8d):
            _, reg, op = self.modrm(rex)
            sz = 1 if b in (0x00, 0x28, 0x30, 0x38, 0x84, 0x88, 0x8a) else size
            if b == 0x8d:
                self.setr(reg, size, self.addr(op))
                return
            if b in (0x88, 0x89):
                self.write_rm(op, sz, self.getr(reg, sz))
                return
            if b in (0x8a, 0x8b):
                self.setr(reg, sz, self.read_rm(op, sz))
                return
            names = {0x01: 'add', 0x03: 'add', 0x09: 'or', 0x0b: 'or', 0x21: 'and', 0x23: 'and', 0x29: 'sub',
                     0x2b: 'sub', 0x31: 'xor', 0x33: 'xor', 0x39: 'cmp', 0x3b: 'cmp', 0x85: 'test',
                     0x00: 'add', 0x28: 'sub', 0x30: 'xor', 0x38: 'cmp', 0x84: 'test'}
            reverse = b in (0x03, 0x0b, 0x23, 0x2b, 0x33, 0x3b)
            nm = names[b]
            if reverse:
                res = self.arith(nm, self.getr(reg, sz), self.read_rm(op, sz), sz)
                if nm not in ('cmp', 'test'):
                    self.setr(reg, sz, res)
            else:
                res = self.arith(nm, self.read_rm(op, sz), self.getr(reg, sz), sz)
                if nm not in ('cmp', 'test'):
                    self.write_rm(op, sz, res)
            return
        if b in (0x80, 0x81, 0x83):
            _, reg, op = self.modrm(rex)
            sz = 1 if b == 0x80 else size
            iv = self.imm(1 if b != 0x81 else (2 if sz == 2 else 4))
            nm = {0: 'add', 1: 'or', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp'}[reg & 7]
            res = self.arith(nm, self.read_rm(op, sz), iv, sz)
            if nm != 'cmp':
                self.write_rm(op, sz, res)
            return
        if b in (0xc6, 0xc7):
            _, reg, op = self.modrm(rex)
            if reg & 7:
                raise Fail('bad c6/c7 form')
            sz = 1 if b == 0xc6 else size
            iv = self.imm(1 if sz == 1 else (2 if sz == 2 else 4))
            self.write_rm(op, sz, iv)
            return
        if b == 0xc1:
            _, reg, op = self.modrm(rex)
            n = self.imm(1, False)
            if reg & 7 != 4:
                raise Fail('shift form not modelled')
            v = self.read_rm(op, size)
            res = (v << n) & ((1 << (8 * size)) - 1)
            self.write_rm(op, size, res)
            self.f['z'] = int(res == 0)
            self.f['s'] = res >> (8 * size - 1) & 1
            return
        if b == 0xff:
            _, reg, op = self.modrm(rex)
            if reg & 7 == 0:
                v = self.read_rm(op, size)
                bits = 8 * size
                res = (v + 1) & ((1 << bits) - 1)
                self.f['z'], self.f['s'] = int(res == 0), res >> (bits - 1) & 1
                self.f['o'] = int(res == 1 << (bits - 1))
                self.write_rm(op, size, res)
                return
            if reg & 7 == 2 and op[0] == 'rip':
                self.do_call(self.addr(op))
                return
            raise Fail('ff form not modelled')
        if b == 0x0f:
            return self.two_byte(rex, p66, pf3, size)
        raise Fail('opcode %#x not modelled at %#x' % (b, self.rip - 1))

    def two_byte(self, rex, p66, pf3, size):
        b = self.fetch()
        if b == 0x1f:
            self.modrm(rex)
            return
        if 0x80 <= b <= 0x8f:
            d = self.imm(4)
            self.fields.add(self.rip - 4)
            self.jcc.add(self.rip - 6)
            if self.cond(b & 15):
                self.rip = (self.rip + d) & M64
            return
        if 0x90 <= b <= 0x9f:
            _, _, op = self.modrm(rex)
            self.write_rm(op, 1, int(self.cond(b & 15)))
            return
        if b in (0xb6, 0xb7):
            _, reg, op = self.modrm(rex)
            self.setr(reg, size, self.read_rm(op, 1 if b == 0xb6 else 2))
            return
        mod, reg, op = self.modrm(rex)
        if b in (0x10, 0x28, 0x6f) and not (b == 0x6f and not (p66 or pf3)):
            self.x[reg] = self.xread(op)
        elif b in (0x11, 0x29, 0x7f):
            if op[0] == 'r':
                self.x[op[1]] = self.x[reg]
            else:
                self.wr(self.addr(op), 16, self.x[reg])
        elif b == 0x6e and p66:
            self.x[reg] = self.read_rm(op, 8 if rex & 8 else 4)
        elif b == 0x74 and p66:
            a, c = self.x[reg], self.xread(op)
            self.x[reg] = sum(0xff << (8 * i) for i in range(16) if (a >> 8 * i & 0xff) == (c >> 8 * i & 0xff))
        elif b == 0xdb and p66:
            self.x[reg] &= self.xread(op)
        elif b == 0xd7 and p66:
            self.setr(reg, 4, sum((self.x[op[1]] >> (8 * i + 7) & 1) << i for i in range(16)))
        else:
            raise Fail('0f %#x not modelled' % b)

    def xread(self, op):
        return self.x[op[1]] if op[0] == 'r' else self.rd(self.addr(op), 16)

    def run(self, entry, args):
        self.r[4] = STACK
        self.push(RET_MAGIC)
        for i, v in zip((7, 6, 2, 1), args):
            self.r[i] = v
        self.rip = entry
        saved = list(self.r[i] for i in (3, 5, 12, 13, 14, 15))
        while self.rip != RET_MAGIC:
            self.step()
        now = [self.r[i] for i in (3, 5, 12, 13, 14, 15)]
        if now != saved:
            raise Fail('callee-saved register not restored')
        if self.r[4] != STACK:
            raise Fail('stack pointer not balanced')


# --------------------------------------------------------------------------- state generation
FRAME = STACK - 0x130  # rsp after the template prologue (return address, six pushes, sub $0xf8)
SENTINEL = 0xa5
CAP = [11, 143, 1715]  # keys held by a B-tree of height 0, 1, 2 at most (11 keys, 12 children per node)


def rkey(rng):
    return bytes(rng.randrange(256) for _ in range(KEY_LEN))


def near(rng, k):
    """A key differing from k in one byte, so every byte position of the memcmp order is used."""
    i = rng.randrange(KEY_LEN)
    return k[:i] + bytes([(k[i] + rng.choice((1, 255, 2, 254))) & 255]) + k[i + 1:]


class Node:
    def __init__(self, keys, children=None):
        self.keys, self.children = keys, children


def build(rng, keys, height):
    if height == 0:
        return Node(list(keys))
    n = len(keys)
    if n < 12:  # sparse internal node: every key is a separator, children are empty subtrees
        return Node(list(keys), [build(rng, [], height - 1) for _ in range(n + 1)])
    for _ in range(40):
        groups = rng.randint(2, 12)
        if n < groups - 1:
            continue
        seps = sorted(rng.sample(range(n), groups - 1))
        parts, prev = [], 0
        for s in seps:
            parts.append(keys[prev:s])
            prev = s + 1
        parts.append(keys[prev:])
        if all(len(p) <= CAP[height - 1] for p in parts):
            return Node([keys[s] for s in seps], [build(rng, p, height - 1) for p in parts])
    cut = sorted({min(n - 1, (i + 1) * n // 12) for i in range(11)})
    parts, prev = [], 0
    for c in cut:
        parts.append(keys[prev:c])
        prev = c + 1
    parts.append(keys[prev:])
    seps = [keys[c] for c in cut]
    return Node(seps, [build(rng, p, height - 1) for p in parts])


def all_keys(node):
    out = list(node.keys)
    for child in node.children or []:
        out += all_keys(child)
    return out


def lay_tree(m, node, cursor):
    """Write a node and its subtree: keys at +8, u16 count at +0xe6, child pointers at +0xe8."""
    base = cursor[0]
    cursor[0] += 0x160
    for i, k in enumerate(node.keys):
        m.put(base + 8 + KEY_LEN * i, k)
    m.wr(base + 0xe6, 2, len(node.keys))
    for i, child in enumerate(node.children or []):
        m.wr(base + 0xe8 + 8 * i, 8, lay_tree(m, child, cursor))
    return base


def make_state(rng):
    nkeys = rng.choice((0, 1, 2, 5, 11, 12, 30, 90, 143, 200))
    keys = sorted({rkey(rng) for _ in range(nkeys)})
    height = 0
    while len(keys) > CAP[height]:
        height += 1
    if height < 2 and len(keys) >= 12 and rng.random() < 0.15:
        height += 1
    tree = build(rng, keys, height)
    members = keys or [rkey(rng)]
    key = rng.choice((rng.choice(members), rng.choice(members), near(rng, rng.choice(members)), rkey(rng)))
    count = rng.choice((0, 1, 1, 2, 3, 6))
    table = [(rng.choice((key, rng.choice(members), rkey(rng))), rng.choice((key, rng.choice(members), rkey(rng))))
             for _ in range(count)]
    if count == 1 and rng.random() < 0.6:
        table[0] = (key, table[0][1])
    elif count == 1 and rng.random() < 0.4:
        table[0] = (near(rng, key), table[0][1])
    probe_idx = rng.randrange(count) if count and rng.random() < 0.9 else rng.randrange(count, count + 3)
    return dict(key=key, keys=keys, tree=tree if rng.random() > 0.08 else None, height=height, count=count,
                table=table, lookup_tag=int(rng.random() < 0.2), payload=rng.choice((key, rng.choice(members), rkey(rng))),
                probe_hit=int(rng.random() < 0.55), probe_idx=probe_idx, first_ok=int(rng.random() < 0.75),
                second_ok=int(rng.random() < 0.75), hash=rng.getrandbits(64), arg4=rng.getrandbits(64),
                noise=rng.getrandbits(64))


def set_state(m, st):
    m.put(OUT, bytes([SENTINEL]) * 0x80)
    m.put(KEY, st['key'])
    m.wr(CTX + 0x3cb0, 8, st['count'])
    table = CTX + 0x100000
    m.wr(CTX + 0x3ca8, 8, table)
    m.wr(CTX + 0x3cd8, 8, st['noise'])
    m.wr(CTX + 0x3ce0, 8, st['noise'] ^ 0x5555)
    for i, (k, v) in enumerate(st['table']):
        m.put(table + 48 * i + 8, k)
        m.put(table + 48 * i + 0x1c, v)
    if st['tree'] is not None:
        m.wr(CTX + 0xb78, 8, lay_tree(m, st['tree'], [CTX + 0x200000]))
        m.wr(CTX + 0xb80, 8, st['height'])


def norm(v):
    if FRAME <= v < FRAME + 0x130:
        return 'sp+%d' % (v - FRAME)
    if v == OUT:
        return 'OUT'
    return v


def fail_bytes(st, name):
    salt = 3 if name == 'second' else 1
    raw = bytearray(((st['noise'] >> ((i % 8) * 8)) ^ (i * 7) ^ salt) & 255 for i in range(0x70))
    raw[0:2] = b'\x77\x00'
    return bytes(raw)


def make_stubs(st, log, tail_target):
    def rec(name, *vals):
        log.append((name,) + tuple(norm(v) if isinstance(v, int) else v for v in vals))

    def lookup(m):
        rec('lookup', m.r[7])
        m.wr(m.r[7], 1, st['lookup_tag'])
        if st['lookup_tag']:
            m.put(m.r[7] + 1, st['payload'])

    def hasher(m):
        rec('hash', m.r[7], m.r[6], m.get(m.r[2], KEY_LEN))
        m.r[0] = st['hash']

    def probe(m):
        rec('probe', m.r[7], m.r[6], m.get(m.r[2], KEY_LEN))
        m.r[0] = st['probe_hit']
        m.r[2] = st['probe_idx']

    def result(name, flag):
        def f(m):
            rec(name, m.r[7], m.r[6], m.get(m.r[2], KEY_LEN), m.r[1], m.r[8] if name == 'second' else 0)
            if st[flag]:
                m.wr(m.r[7], 2, OK_CODE)
            else:
                m.put(m.r[7], fail_bytes(st, name))
        return f

    def drop(m):
        rec('drop', m.r[7], m.r[6])
        m.wr(m.r[7], 8, 0)

    def tail(m):
        rec('tail@%#x' % tail_target, m.r[7], m.r[6], m.get(m.r[2], KEY_LEN), m.r[1])

    def memcmp(m):
        a, b = m.get(m.r[7], m.r[2]), m.get(m.r[6], m.r[2])
        m.r[0] = ((a > b) - (a < b)) & M64

    def panic(m):
        raise Panic('bounds')

    return {T_LOOKUP: lookup, T_HASH: hasher, T_PROBE: probe, T_FIRST: result('first', 'first_ok'),
            T_SECOND: result('second', 'second_ok'), T_DROP: drop, T_CLEANUP: lambda m: None,
            G_MEMCMP: memcmp, G_PANIC: panic, G_ABORT: panic, tail_target: tail}


# --------------------------------------------------------------------------- the model
def cmp3(a, b):
    return (a > b) - (a < b)


def tree_has(read, root, height, target, mut):
    """In-node linear search then descent, exactly the walk the template performs."""
    node = root
    while True:
        n = read(node + 0xe6, 2)
        if 'skip-last-key' in mut:
            n = max(0, n - 1)
        idx = 0
        while idx < n:
            c = cmp3(target, read(node + 8 + KEY_LEN * idx, KEY_LEN).to_bytes(KEY_LEN, 'little'))
            if 'reverse-order' in mut:
                c = -c
            if c == 0:
                return 'ignore-equal' not in mut
            if c < 0:
                break
            idx += 1
        if height == 0:
            return False
        node = read(node + 0xe8 + 8 * idx, 8)
        height -= 1


def model(st, read, tail_target, mut=frozenset()):
    """Statement of the template's behaviour: (panicked, out bytes, call log)."""
    log, out = [], bytearray([SENTINEL]) * 0x80
    key = st['key']
    log.append(('lookup', 'sp+80'))
    if st['lookup_tag'] and 'ignore-override' not in mut:
        value = st['payload']
    else:
        value, count = key, st['count']
        if count:
            if count == 1:
                hit = st['table'][0][0][:15 if 'short-compare' in mut else KEY_LEN] == key[:15 if 'short-compare' in mut else KEY_LEN]
                idx = 0 if hit or 'always-first' in mut else None
            else:
                if 'no-hash' not in mut:
                    log.append(('hash', read(CTX + 0x3cd8, 8), read(CTX + 0x3ce0, 8), key))
                log.append(('probe', CTX + 0x3ca0, st['hash'], key))
                idx = None
                if st['probe_hit']:
                    if st['probe_idx'] > count if 'bounds-off-by-one' in mut else st['probe_idx'] >= count:
                        return True, bytes(out), log, None
                    idx = st['probe_idx']
            if idx is not None:
                value = key if 'value-is-key' in mut else st['table'][idx][1]
    root = read(CTX + 0xb78, 8)
    if root:
        height = max(0, read(CTX + 0xb80, 8) - (1 if 'height-minus-one' in mut else 0))
        hit = ('skip-key-walk' not in mut and tree_has(read, root, height, key, mut)) or \
              ('skip-value-walk' not in mut and tree_has(read, root, height, value, mut))
        if hit:
            out[0] = REJECT_TAG
            out[0x10:0x12] = (REJECT_CODE + (1 if 'reject-code' in mut else 0)).to_bytes(2, 'little')
            if 'reject-tag' in mut:
                out[0] = 0xe
            return False, bytes(out), log, value
    steps = ['first', 'second']
    if 'swap-calls' in mut:
        steps.reverse()
    for name in steps:
        if name == 'first':
            log.append(('first', 'sp+80', CTX, value, 'sp+224', 0))
            ok = st['first_ok']
        else:
            if 'skip-second' in mut:
                continue
            log.append(('second', 'sp+80', CTX, value, 'sp+224', 0))
            ok = st['second_ok']
        if not ok:
            out[0] = 0xf
            out[0x10:0x80] = fail_bytes(st, name)
            if name == 'first' and 'no-drop' not in mut:
                log.append(('drop', 'sp+32', 'sp+80'))
            return False, bytes(out), log, value
    log.append(('tail@%#x' % tail_target, 'OUT', st['arg4'], key if 'tail-value' not in mut else value, CTX))
    return False, bytes(out), log, value


def run_case(code, entry, tail_target, st, probe=None):
    """Interpret the real bytes: (panicked, out bytes, call log)."""
    log = []
    m = Machine(code, make_stubs(st, log, tail_target))
    m.probe = probe
    set_state(m, st)
    try:
        m.run(entry, (OUT, CTX, KEY, st['arg4']))
        panicked = False
    except Panic:
        panicked = True
    return panicked, m.get(OUT, 0x80), log


# --------------------------------------------------------------------------- verification driver
class PatchedCode(Code):
    def __init__(self, base, patches):
        super().__init__(base.data, base.text)
        self.patches = patches

    def byte_at(self, va):
        return self.patches.get(va, super().byte_at(va))


def kind_of(panicked, out, log):
    if panicked:
        return 'panic'
    if out[0] == REJECT_TAG and out[0x10:0x12] == REJECT_CODE.to_bytes(2, 'little') and not any(
            e[0] in ('first', 'second') for e in log):
        return 'rejected'
    if out[0] == 0xf:
        return 'first-failed' if log[-1][0] == 'drop' else 'second-failed'
    return 'dispatched'


def digest(panicked, out, log):
    return hashlib.sha256(repr((panicked, out, log)).encode()).hexdigest()[:16]


def sink_of(code, entry):
    """Absolute target of the template's final call (the per-clone handler body)."""
    if code.byte_at(entry + TAIL_SITE) != 0xe8:
        raise Fail('tail call opcode not found')
    rel = struct.unpack('<i', code.slice(entry + TAIL_SITE + 1, 4))[0]
    return entry + TAIL_SITE + 5 + rel


def reader_for(st):
    probe = Machine(None, {})
    set_state(probe, st)
    return probe.rd


def evaluate(code, entry, sink, st):
    """Run the real bytes and the model; return (agree, emulator result, model result)."""
    real = run_case(code, entry, sink, st)
    mod = model(st, reader_for(st), sink)
    return real == mod[:3], real, mod


def semantic_ok(st, mod):
    """Valid-tree check: a reject happens exactly when the key or the effective value is a stored key."""
    panicked, out, log, value = mod
    if panicked or st['tree'] is None:
        return True
    stored = set(st['keys'])
    rejected = out[0] == REJECT_TAG and out[0x10:0x12] == REJECT_CODE.to_bytes(2, 'little') and not any(
        e[0] in ('first', 'second') for e in log)
    return rejected == (st['key'] in stored or value in stored)


MODEL_MUTANTS = ['reject-code', 'reject-tag', 'skip-key-walk', 'skip-value-walk', 'reverse-order', 'ignore-equal',
                 'skip-last-key', 'height-minus-one', 'short-compare', 'always-first', 'bounds-off-by-one',
                 'ignore-override', 'value-is-key', 'swap-calls', 'skip-second', 'no-drop', 'no-hash', 'tail-value']
# (name, byte pattern in the template, replacement) - each pattern must occur at least once
BYTE_PATCHES = [
    ('imm-reject-code', b'\x66\xc7\x40\x10\x20\x01', b'\x66\xc7\x40\x10\x21\x01'),
    ('memcmp-length', b'\xba\x14\x00\x00\x00', b'\xba\x13\x00\x00\x00'),
    ('count-offset', b'\xb0\x3c\x00\x00', b'\xb8\x3c\x00\x00'),
    ('node-length-offset', b'\xe6\x00\x00\x00', b'\xe4\x00\x00\x00'),
    ('reject-tag-imm', b'\xc6\x00\x0f', b'\xc6\x00\x0e'),
    ('ok-code-imm', b'\xa2\x01', b'\xa3\x01'),
    ('root-offset', b'\x78\x0b\x00\x00', b'\x70\x0b\x00\x00'),
]


def find(body, pattern):
    return [i for i in range(len(body) - len(pattern) + 1) if body[i:i + len(pattern)] == pattern]


def rebase_report(code, fields):
    """Differences between each clone and the first, split into rel32/disp32 windows seen while decoding."""
    base = code.slice(COPIES[0], SIZE)
    window = set()
    for f in fields:
        window.update(range(f, f + 4))
    rows, outside = [], set()
    for a in COPIES:
        body = code.slice(a, SIZE)
        diff = [i for i in range(SIZE) if body[i] != base[i]]
        outside.update(i for i in diff if i not in window)
        inside = sum(i in window for i in diff)
        rows.append((a, len(diff), inside, len(diff) - inside, sink_of(code, a),
                     hashlib.sha256(body).hexdigest()))
    return rows, outside


def generate(data, text, cases_per_clone=CASES_PER_COPY):
    code = Code(data, text)
    stats = dict(cases=0, mismatches=0, semantic=0, semantic_bad=0, kinds={}, steps_max=0)
    fields, jcc = set(), set()
    sample = []
    control_ref = []
    sinks = {a: sink_of(code, a) for a in COPIES}
    for a in COPIES:
        for k in range(cases_per_clone):
            st = make_state(random.Random(k))
            real = None
            m_agree, real, mod = evaluate_with_marks(code, a, sinks[a], st, fields, jcc)
            stats['cases'] += 1
            stats['mismatches'] += not m_agree
            ok = semantic_ok(st, mod)
            stats['semantic'] += st['tree'] is not None and not mod[0]
            stats['semantic_bad'] += not ok
            kd = kind_of(*mod[:3])
            stats['kinds'][kd] = stats['kinds'].get(kd, 0) + 1
            if k % 14 == 0:
                sample.append((a, k, kd, sinks[a], len(mod[2]), digest(*mod[:3])))
            if a == COPIES[0] and k < CONTROL_CASES:
                control_ref.append(real)
    return code, stats, fields, jcc, sample, control_ref, sinks


CONTROL_CASES = 300


def evaluate_with_marks(code, entry, sink, st, fields, jcc):
    log = []
    m = Machine(code, make_stubs(st, log, sink))
    set_state(m, st)
    try:
        m.run(entry, (OUT, CTX, KEY, st['arg4']))
        panicked = False
    except Panic:
        panicked = True
    for f in m.fields:
        fields.add(f - entry)
    for j in m.jcc:
        jcc.add(j - entry)
    real = (panicked, m.get(OUT, 0x80), log)
    mod = model(st, reader_for(st), sink)
    return real == mod[:3], real, mod


def controls(code, sinks, jcc, reference, data):
    """Each control must be detected: a changed model, damaged bytes or out-of-range input."""
    entry, sink = COPIES[0], sinks[COPIES[0]]
    states = [make_state(random.Random(k)) for k in range(CONTROL_CASES)]
    rows = []

    def first_diff_model(mut):
        for k, st in enumerate(states):
            try:
                got = model(st, reader_for(st), sink, frozenset([mut]))[:3]
            except IndexError:  # the mutant reads past the table: the model itself is rejected
                return k
            if got != reference[k]:
                return k
        return -1

    for name in MODEL_MUTANTS:
        k = first_diff_model(name)
        rows.append((name, 'model-mutant', int(k >= 0), k))

    def first_diff_code(patched):
        for k, st in enumerate(states):
            try:
                got = run_case(patched, entry, sink, st)
            except (Fail, KeyError, IndexError, ValueError):
                return k
            if got != reference[k]:
                return k
        return -1

    body = code.slice(entry, SIZE)
    for name, pattern, repl in BYTE_PATCHES:
        offs = find(body, pattern)
        if not offs:
            raise Fail('patch pattern missing: ' + name)
        patches = {entry + offs[0] + i: b for i, b in enumerate(repl)}
        k = first_diff_code(PatchedCode(code, patches))
        rows.append((name, 'byte-damage', int(k >= 0), k))
    for off in sorted(jcc):
        op = body[off]
        if 0x70 <= op <= 0x7f:
            patches = {entry + off: op ^ 1}
        elif op == 0x0f and 0x80 <= body[off + 1] <= 0x8f:
            patches = {entry + off + 1: body[off + 1] ^ 1}
        else:
            raise Fail('jcc offset %#x not a conditional jump' % off)
        k = first_diff_code(PatchedCode(code, patches))
        rows.append(('invert-jcc-%#05x' % off, 'byte-damage', int(k >= 0), k))
    # out-of-range and mismatched inputs
    st = states[next(k for k, r in enumerate(reference) if r[2] and r[2][-1][0].startswith('tail@'))]
    probes = [
        ('entry-outside-text', lambda: run_case(code, 0x1000, sink, st)),
        ('entry-past-section', lambda: run_case(code, code.text['address'] + code.text['size'] + 8, sink, st)),
        ('wrong-tail-target', lambda: run_case(code, entry, sink + 16, st)),
        ('wrong-binary-digest', lambda: check_digest(data[:-1])),
        ('int3-at-entry', lambda: run_case(PatchedCode(code, {entry: 0xcc}), entry, sink, st)),
        ('tail-opcode-damaged', lambda: sink_of(PatchedCode(code, {entry + TAIL_SITE: 0x90}), entry)),
    ]
    for name, thunk in probes:
        try:
            thunk()
            rows.append((name, 'out-of-range', 0, -1))
        except (Fail, KeyError, IndexError, ValueError):
            rows.append((name, 'out-of-range', 1, 0))
    return rows


def check_digest(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise Fail('input binary digest differs from node #115')


def write_outputs(out_dir, data, text):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    code, stats, fields, jcc, sample, reference, sinks = generate(data, text)
    ctl = controls(code, sinks, jcc, reference, data)
    rebase, outside = rebase_report(code, fields)
    detected = sum(r[2] for r in ctl)
    with open(out / 'template.tsv', 'w', newline='\n') as fh:
        fh.write('clone\tdiff_bytes_vs_first\tin_decoded_rel32_fields\toutside_decoded_fields\tsink_handler\tbody_sha256\n')
        for a, d, i, o, s, h in rebase:
            fh.write('%#x\t%d\t%d\t%d\t%#x\t%s\n' % (a, d, i, o, s, h))
    with open(out / 'cases-sample.tsv', 'w', newline='\n') as fh:
        fh.write('clone\tstate_seed\toutcome\tsink_handler\tcalls\tbehaviour_digest\n')
        for a, k, kd, s, n, h in sample:
            fh.write('%#x\t%d\t%s\t%#x\t%d\t%s\n' % (a, k, kd, s, n, h))
    with open(out / 'controls.tsv', 'w', newline='\n') as fh:
        fh.write('control\tkind\tdetected\tfirst_differing_case\n')
        for r in ctl:
            fh.write('%s\t%s\t%d\t%d\n' % r)
    summary = {
        'binary_sha256': SHA256,
        'clones': ['%#x' % a for a in COPIES],
        'template_bytes': SIZE,
        'cases_per_clone': CASES_PER_COPY,
        'cases': stats['cases'],
        'mismatches': stats['mismatches'],
        'semantic_checks': stats['semantic'],
        'semantic_failures': stats['semantic_bad'],
        'outcomes': dict(sorted(stats['kinds'].items())),
        'decoded_rel32_fields': sorted('%#x' % f for f in fields),
        'executed_conditional_jumps': sorted('%#x' % j for j in jcc),
        'offsets_outside_decoded_fields': sorted('%#x' % i for i in outside),
        'diff_outside_decoded_fields': {'%#x' % r[0]: r[3] for r in rebase},
    }
    (out / 'summary.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
    (out / 'measure.json').write_text(json.dumps(
        {'cases': stats['cases'], 'negative_controls': len(ctl), 'negative_detected': detected},
        indent=1, sort_keys=True) + '\n')
    return stats, ctl


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True)
    ap.add_argument('--binary', default=str(BINARY))
    args = ap.parse_args()
    data, text = load_binary(args.binary)
    stats, ctl = write_outputs(args.out, data, text)
    print('cases=%d mismatches=%d controls=%d detected=%d' % (
        stats['cases'], stats['mismatches'], len(ctl), sum(r[2] for r in ctl)))
    return 0 if not stats['mismatches'] and all(r[2] for r in ctl) else 1


if __name__ == '__main__':
    sys.exit(main())
