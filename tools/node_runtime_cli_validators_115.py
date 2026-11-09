#!/usr/bin/env python3
"""Reconstruct the node #115 CLI argument validators for u64, bool, IPv4 and address.

Five clap value-parser callbacks (0x56544b0 u64, 0x56547d0 bool, 0x56546c0
IPv4, 0x5654920 and 0x5654a90 address wrappers) and the IPv4 reader they call (0x167ccb0) are replayed from the ELF
bytes by a small interpreter for exactly the x86-64 subset those bodies use.
Pure Python models of the observed behaviour are then compared with the replay
on generated inputs.  The target binary is never executed; every callee outside
the four bodies is a documented stub (see HOOKS).
"""
import argparse
import hashlib
import json
import os
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BINARY = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
FUNCS = {'u64': 0x56544b0, 'ip': 0x56546c0, 'bool': 0x56547d0, 'ipv4_reader': 0x167ccb0, 'addr_val': 0x5654920,
         'addr_sig': 0x5654a90}
PARSE, FMT_A, FMT_B, DROP_RES, FAKE_DROP = 0x150d640, 0x46ef710, 0x1456ae0, 0x5630000, 0x7ffffe00
MIN64 = 1 << 63
M64 = (1 << 64) - 1
MSG = {'empty': (0x479018, 38), 'digit': (0x47903e, 29), 'big': (0x47905b, 38), 'bool': (0x478fe8, 41)}
HOOK_PAD, HOOK_FREE, HOOK_RESERVE, HOOK_PANIC = 0x167fa70, 0x635de30, 0x5963a10, 0x1680c30
IP_ERR = (0x453ab0, 16)
STACK_TOP = 0x7ff00000
HEAP = 0x10000000
STOP = 0x7fffff00


class Unsupported(Exception):
    pass


class Image:
    """Alloc, non-NOBITS section bytes of the ELF, plus RELATIVE slot targets."""

    def __init__(self, data):
        self.data = data
        self.secs = [s for s in elf_index.sections(data) if s['type'] != 8 and s['flags'] & 2 and s['size']]
        self.relative = {}
        for s in elf_index.sections(data):
            if s['name'] == '.rela.dyn':
                for i in range(s['size'] // 24):
                    off, info, add = struct.unpack_from('<QQq', data, s['offset'] + 24 * i)
                    if info & 0xffffffff == 8:
                        self.relative[off] = add

    def read(self, va, n):
        for s in self.secs:
            if s['address'] <= va and va + n <= s['address'] + s['size']:
                o = s['offset'] + va - s['address']
                return self.data[o:o + n]
        raise ValueError('address outside alloc sections: %#x' % va)


def load(path=BINARY):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('input binary digest mismatch')
    return Image(data)


def extents(img):
    _, rows, _ = fde_extents.fde_extents(img.data)
    return {r['start']: r['end'] for r in rows}


COND = {
    0: lambda e: e.of, 1: lambda e: not e.of, 2: lambda e: e.cf, 3: lambda e: not e.cf,
    4: lambda e: e.zf, 5: lambda e: not e.zf, 6: lambda e: e.cf or e.zf, 7: lambda e: not (e.cf or e.zf),
    8: lambda e: e.sf, 9: lambda e: not e.sf, 10: lambda e: e.pf, 11: lambda e: not e.pf,
    12: lambda e: e.sf != e.of, 13: lambda e: e.sf == e.of,
    14: lambda e: e.zf or e.sf != e.of, 15: lambda e: not e.zf and e.sf == e.of,
}


class Emu:
    def __init__(self, img, patches=None, max_steps=20000):
        self.img, self.patches, self.max_steps = img, patches or {}, max_steps
        self.reset()

    def reset(self):
        self.mem = {}
        self.regs = [0] * 16
        self.xmm = [0] * 16
        self.cf = self.zf = self.sf = self.of = self.pf = 0
        self.heap = HEAP
        self.frees = []
        self.pads = []
        self.steps = 0
        self.cov = None
        self.events = []
        self.vtables = set()
        self.vtable = 0
        self.script = {}
        self.regs[4] = STACK_TOP

    # ---- memory
    def rb(self, a):
        v = self.mem.get(a)
        if v is not None:
            return v
        if a in self.patches:
            return self.patches[a]
        return self.img.read(a, 1)[0]

    def rd(self, a, n):
        return int.from_bytes(bytes(self.rb(a + i) for i in range(n)), 'little')

    def wr(self, a, n, v):
        v &= (1 << (8 * n)) - 1
        for i in range(n):
            self.mem[a + i] = (v >> (8 * i)) & 255

    def fetch(self, a, n):
        return bytes(self.patches.get(a + i, None) if (a + i) in self.patches else self.img.read(a + i, 1)[0] for i in range(n))

    def alloc(self, n):
        a = self.heap
        self.heap += (n + 15) & ~15 or 16
        return a

    def put(self, data):
        a = self.alloc(len(data))
        for i, b in enumerate(data):
            self.mem[a + i] = b
        return a

    # ---- registers
    def getr(self, i, size, rex):
        if size == 1 and not rex and 4 <= i < 8:
            return (self.regs[i - 4] >> 8) & 255
        return self.regs[i] & ((1 << (8 * size)) - 1)

    def setr(self, i, size, rex, v):
        if size == 8:
            self.regs[i] = v & M64
        elif size == 4:
            self.regs[i] = v & 0xffffffff
        elif size == 2:
            self.regs[i] = (self.regs[i] & ~0xffff) | (v & 0xffff)
        elif not rex and 4 <= i < 8:
            self.regs[i - 4] = (self.regs[i - 4] & ~0xff00) | ((v & 255) << 8)
        else:
            self.regs[i] = (self.regs[i] & ~0xff) | (v & 255)

    # ---- flags
    def szp(self, r, size):
        m = (1 << (8 * size)) - 1
        r &= m
        self.zf = int(r == 0)
        self.sf = (r >> (8 * size - 1)) & 1
        self.pf = int(bin(r & 255).count('1') % 2 == 0)

    def alu(self, op, a, b, size):
        m = (1 << (8 * size)) - 1
        sb = 1 << (8 * size - 1)
        if op in (0, 2):
            c = self.cf if op == 2 else 0
            r = a + b + c
            self.cf = int(r > m)
            self.of = int(bool(~(a ^ b) & (a ^ r) & sb))
        elif op in (5, 7, 3):
            c = self.cf if op == 3 else 0
            r = a - b - c
            self.cf = int(a < b + c)
            self.of = int(bool((a ^ b) & (a ^ r) & sb))
        else:
            r = {1: a | b, 4: a & b, 6: a ^ b}[op]
            self.cf = self.of = 0
        self.szp(r, size)
        return r & m

    # ---- decoding helpers
    def modrm(self, a, rex, ip_after_fn):
        b = self.fetch(a, 1)[0]
        mod, reg, rm = b >> 6, ((b >> 3) & 7) | ((rex & 4) << 1), b & 7
        n = 1
        if mod == 3:
            return n, mod, reg, ('r', rm | ((rex & 1) << 3))
        base, index, scale, disp, rip = None, None, 1, 0, False
        if rm == 4:
            s = self.fetch(a + n, 1)[0]
            n += 1
            scale = 1 << (s >> 6)
            idx = ((s >> 3) & 7) | ((rex & 2) << 2)
            if idx != 4:
                index = idx
            bs = s & 7
            if bs == 5 and mod == 0:
                disp = struct.unpack('<i', self.fetch(a + n, 4))[0]
                n += 4
            else:
                base = bs | ((rex & 1) << 3)
        elif rm == 5 and mod == 0:
            rip = True
            disp = struct.unpack('<i', self.fetch(a + n, 4))[0]
            n += 4
        else:
            base = rm | ((rex & 1) << 3)
        if mod == 1:
            disp = struct.unpack('<b', self.fetch(a + n, 1))[0]
            n += 1
        elif mod == 2:
            disp = struct.unpack('<i', self.fetch(a + n, 4))[0]
            n += 4
        return n, mod, reg, ('m', base, index, scale, disp, rip)

    def ea(self, mem, end):
        _, base, index, scale, disp, rip = mem
        v = disp + (end if rip else 0)
        if base is not None:
            v += self.regs[base]
        if index is not None:
            v += self.regs[index] * scale
        return v & M64

    def run(self, entry, max_steps=None):
        """Run from entry until the return address STOP is popped."""
        self.regs[4] -= 8
        self.wr(self.regs[4], 8, STOP)
        self.ip = entry
        limit = max_steps or self.max_steps
        while self.ip != STOP:
            self.steps += 1
            if self.steps > limit:
                raise Unsupported('step limit')
            self.step()
        return self.regs[0]

    def push(self, v):
        self.regs[4] = (self.regs[4] - 8) & M64
        self.wr(self.regs[4], 8, v)

    def pop(self):
        v = self.rd(self.regs[4], 8)
        self.regs[4] = (self.regs[4] + 8) & M64
        return v

    def call(self, target):
        if target in (HOOK_PAD, HOOK_FREE, HOOK_RESERVE, HOOK_PANIC):
            self.hook(target)
            return
        if target in (PARSE, FMT_A, FMT_B, DROP_RES, FAKE_DROP):
            self.wrapper_hook(target)
            return
        self.push(self.ip)
        self.ip = target

    def wrapper_hook(self, target):
        """Stubs for the callees of the two address wrappers; the script says what each returns."""
        r = self.regs
        sc = self.script
        if target == PARSE:
            self.events.append(('parse', r[2]))
            if sc['parse_err']:
                obj = self.alloc(16)
                self.wr(obj, 8, self.vtable)
                self.wr(r[7] + 8, 8, obj)
                self.wr(r[7], 1, 1)
                sc['obj'] = obj
            else:
                self.wr(r[7], 1, 0)
        elif target in (FMT_A, FMT_B):
            if target == FMT_A:
                self.events.append(('fmt', self.rd(r[7], 1)))
            else:
                self.events.append(('fmt', r[7] == sc['obj']))
            fmt = self.rd(r[6], 8)
            body = sc['text']
            p = self.put(body)
            self.wr(fmt, 8, len(body))
            self.wr(fmt + 8, 8, p)
            self.wr(fmt + 16, 8, len(body))
            r[0] = sc['fmt_fail']
        elif target == DROP_RES:
            self.events.append(('dropres', self.rd(r[7], 1)))
        else:
            self.events.append(('vdrop', r[7] == sc['obj']))

    def hook(self, target):
        r = self.regs
        if target == HOOK_PAD:
            fmt = self.rd(r[7], 8)
            ptr, ln = r[6], r[2]
            body = bytes(self.rb(ptr + i) for i in range(ln)) if ln < 4096 else b''
            self.pads.append(body)
            p = self.put(body)
            self.wr(fmt, 8, ln)
            self.wr(fmt + 8, 8, p)
            self.wr(fmt + 16, 8, ln)
            r[0] = 0
        elif target == HOOK_FREE:
            self.frees.append((r[7], r[6], r[2]))
        elif target == HOOK_RESERVE:
            vec = r[7]
            self.wr(vec, 8, r[2])
            self.wr(vec + 8, 8, self.alloc(r[2]))
            r[0] = 0
        else:
            raise Unsupported('panic hook reached')

    def step(self):
        at = self.ip
        rex = 0
        p = at
        opsz16 = False
        while True:
            b = self.fetch(p, 1)[0]
            if b == 0x66:
                opsz16 = True
                p += 1
            elif 0x40 <= b <= 0x4f:
                rex = b
                p += 1
                break
            else:
                break
        op = self.fetch(p, 1)[0]
        p += 1
        w = 8 if rex & 8 else (2 if opsz16 else 4)
        R = self.regs
        if op == 0x0f:
            self.twobyte(p, at, rex, w, opsz16)
            return
        if op < 0x40 and (op & 7) < 6 and op not in (0x0f,) and (op & 6) != 6 or (op < 0x40 and (op & 7) < 4):
            kind = op >> 3
            low = op & 7
            if low < 4:
                size = 1 if low % 2 == 0 else w
                n, mod, reg, rm = self.modrm(p, rex, None)
                end = p + n
                self.ip = end
                regv = self.getr(reg, size, rex)
                if rm[0] == 'r':
                    cur = self.getr(rm[1], size, rex)
                else:
                    addr = self.ea(rm, end)
                    cur = self.rd(addr, size)
                if low < 2:
                    res = self.alu(kind, cur, regv, size)
                    dst_is_rm = True
                else:
                    res = self.alu(kind, regv, cur, size)
                    dst_is_rm = False
                if kind != 7:
                    if dst_is_rm:
                        if rm[0] == 'r':
                            self.setr(rm[1], size, rex, res)
                        else:
                            self.wr(addr, size, res)
                    else:
                        self.setr(reg, size, rex, res)
                return
            if low == 4:
                imm = self.fetch(p, 1)[0]
                self.ip = p + 1
                res = self.alu(kind, R[0] & 255, imm, 1)
                if kind != 7:
                    self.setr(0, 1, rex, res)
                return
            if low == 5:
                sz = 2 if opsz16 else 4
                imm = int.from_bytes(self.fetch(p, sz), 'little')
                if sz == 4 and w == 8:
                    imm = struct.unpack('<i', self.fetch(p, 4))[0] & M64
                self.ip = p + sz
                res = self.alu(kind, self.getr(0, w, rex), imm & ((1 << 8 * w) - 1), w)
                if kind != 7:
                    self.setr(0, w, rex, res)
                return
        if 0x50 <= op <= 0x57:
            self.ip = p
            self.push(R[(op & 7) | ((rex & 1) << 3)])
            return
        if 0x58 <= op <= 0x5f:
            self.ip = p
            R[(op & 7) | ((rex & 1) << 3)] = self.pop()
            return
        if 0x70 <= op <= 0x7f:
            rel = struct.unpack('<b', self.fetch(p, 1))[0]
            self.ip = p + 1
            taken = int(bool(COND[op & 15](self)))
            if self.cov is not None:
                self.cov.setdefault(at, [0, 0])[taken] += 1
            if taken:
                self.ip += rel
            return
        if op in (0x80, 0x81, 0x83):
            size = 1 if op == 0x80 else w
            n, mod, reg, rm = self.modrm(p, rex, None)
            isz = 4 if op == 0x81 and not opsz16 else (2 if op == 0x81 else 1)
            raw = self.fetch(p + n, isz)
            imm = int.from_bytes(raw, 'little', signed=True) & ((1 << 8 * size) - 1)
            end = p + n + isz
            self.ip = end
            kind = reg & 7
            if rm[0] == 'r':
                cur = self.getr(rm[1], size, rex)
            else:
                addr = self.ea(rm, end)
                cur = self.rd(addr, size)
            res = self.alu(kind, cur, imm, size)
            if kind != 7:
                if rm[0] == 'r':
                    self.setr(rm[1], size, rex, res)
                else:
                    self.wr(addr, size, res)
            return
        if op in (0x84, 0x85):
            size = 1 if op == 0x84 else w
            n, mod, reg, rm = self.modrm(p, rex, None)
            end = p + n
            self.ip = end
            cur = self.getr(rm[1], size, rex) if rm[0] == 'r' else self.rd(self.ea(rm, end), size)
            self.alu(4, cur, self.getr(reg, size, rex), size)
            return
        if op in (0x88, 0x89, 0x8a, 0x8b, 0x8d):
            size = 1 if op in (0x88, 0x8a) else w
            n, mod, reg, rm = self.modrm(p, rex, None)
            end = p + n
            self.ip = end
            if op == 0x8d:
                self.setr(reg, w, rex, self.ea(rm, end))
            elif op in (0x88, 0x89):
                v = self.getr(reg, size, rex)
                if rm[0] == 'r':
                    self.setr(rm[1], size, rex, v)
                else:
                    self.wr(self.ea(rm, end), size, v)
            else:
                v = self.getr(rm[1], size, rex) if rm[0] == 'r' else self.rd(self.ea(rm, end), size)
                self.setr(reg, size, rex, v)
            return
        if op == 0x90:
            self.ip = p
            return
        if 0xb0 <= op <= 0xb7:
            self.ip = p + 1
            self.setr((op & 7) | ((rex & 1) << 3), 1, rex, self.fetch(p, 1)[0])
            return
        if 0xb8 <= op <= 0xbf:
            sz = w
            v = int.from_bytes(self.fetch(p, sz), 'little')
            self.ip = p + sz
            self.setr((op & 7) | ((rex & 1) << 3), w, rex, v)
            return
        if op in (0xc6, 0xc7):
            size = 1 if op == 0xc6 else w
            n, mod, reg, rm = self.modrm(p, rex, None)
            isz = min(size, 4)
            v = int.from_bytes(self.fetch(p + n, isz), 'little', signed=True)
            end = p + n + isz
            self.ip = end
            if rm[0] == 'r':
                self.setr(rm[1], size, rex, v)
            else:
                self.wr(self.ea(rm, end), size, v)
            return
        if op in (0xc1, 0xd1, 0xd3):
            n, mod, reg, rm = self.modrm(p, rex, None)
            isz = 1 if op == 0xc1 else 0
            cnt = self.fetch(p + n, 1)[0] if isz else (1 if op == 0xd1 else R[1] & 255)
            end = p + n + isz
            self.ip = end
            cnt &= 63 if w == 8 else 31
            cur = self.getr(rm[1], w, rex) if rm[0] == 'r' else self.rd(self.ea(rm, end), w)
            m = (1 << 8 * w) - 1
            kind = reg & 7
            if cnt:
                if kind == 4:
                    res = (cur << cnt) & m
                    self.cf = (cur >> (8 * w - cnt)) & 1
                elif kind == 5:
                    res = cur >> cnt
                    self.cf = (cur >> (cnt - 1)) & 1
                else:
                    raise Unsupported('shift kind %d' % kind)
                self.szp(res, w)
                self.of = 0
                if rm[0] == 'r':
                    self.setr(rm[1], w, rex, res)
                else:
                    self.wr(self.ea(rm, end), w, res)
            return
        if op == 0xc3:
            self.ip = self.pop()
            return
        if op == 0xe8:
            rel = struct.unpack('<i', self.fetch(p, 4))[0]
            self.ip = p + 4
            self.call(self.ip + rel)
            return
        if op in (0xe9, 0xeb):
            sz = 4 if op == 0xe9 else 1
            rel = int.from_bytes(self.fetch(p, sz), 'little', signed=True)
            self.ip = p + sz + rel
            return
        if op in (0xf6, 0xf7):
            size = 1 if op == 0xf6 else w
            n, mod, reg, rm = self.modrm(p, rex, None)
            kind = reg & 7
            isz = min(size, 4) if kind in (0, 1) else 0
            end = p + n + isz
            self.ip = end
            addr = None if rm[0] == 'r' else self.ea(rm, end)
            cur = self.getr(rm[1], size, rex) if rm[0] == 'r' else self.rd(addr, size)
            m = (1 << 8 * size) - 1
            if kind in (0, 1):
                imm = int.from_bytes(self.fetch(p + n, isz), 'little', signed=True) & m
                self.alu(4, cur, imm, size)
                return
            if kind == 2:
                res = ~cur & m
            elif kind == 3:
                res = (-cur) & m
                self.cf = int(cur != 0)
                self.szp(res, size)
                self.of = int(cur == 1 << (8 * size - 1))
            elif kind == 4 and size == 8:
                prod = R[0] * cur
                R[0], R[2] = prod & M64, prod >> 64
                self.cf = self.of = int(R[2] != 0)
                return
            else:
                raise Unsupported('f7 kind %d' % kind)
            if rm[0] == 'r':
                self.setr(rm[1], size, rex, res)
            else:
                self.wr(addr, size, res)
            return
        if op in (0xfe, 0xff):
            size = 1 if op == 0xfe else w
            n, mod, reg, rm = self.modrm(p, rex, None)
            kind = reg & 7
            end = p + n
            self.ip = end
            if kind in (0, 1):
                addr = None if rm[0] == 'r' else self.ea(rm, end)
                cur = self.getr(rm[1], size, rex) if rm[0] == 'r' else self.rd(addr, size)
                keep = self.cf
                res = self.alu(0 if kind == 0 else 5, cur, 1, size)
                self.cf = keep
                if rm[0] == 'r':
                    self.setr(rm[1], size, rex, res)
                else:
                    self.wr(addr, size, res)
                return
            if kind == 2 and rm[0] == 'm':
                slot = self.ea(rm, end)
                target = self.img.relative.get(slot)
                if target is None and slot in self.vtables:
                    target = self.rd(slot, 8)
                if target is None:
                    raise Unsupported('indirect call through non-RELATIVE slot %#x' % slot)
                self.call(target)
                return
            raise Unsupported('ff kind %d' % kind)
        raise Unsupported('opcode %#x at %#x' % (op, at))

    def twobyte(self, p, at, rex, w, opsz16):
        op = self.fetch(p, 1)[0]
        p += 1
        R = self.regs
        if 0x80 <= op <= 0x8f:
            rel = struct.unpack('<i', self.fetch(p, 4))[0]
            self.ip = p + 4
            taken = int(bool(COND[op & 15](self)))
            if self.cov is not None:
                self.cov.setdefault(at, [0, 0])[taken] += 1
            if taken:
                self.ip += rel
            return
        if 0x90 <= op <= 0x9f:
            n, mod, reg, rm = self.modrm(p, rex, None)
            end = p + n
            self.ip = end
            v = int(bool(COND[op & 15](self)))
            if rm[0] == 'r':
                self.setr(rm[1], 1, rex, v)
            else:
                self.wr(self.ea(rm, end), 1, v)
            return
        if 0x40 <= op <= 0x4f:
            n, mod, reg, rm = self.modrm(p, rex, None)
            end = p + n
            self.ip = end
            v = self.getr(rm[1], w, rex) if rm[0] == 'r' else self.rd(self.ea(rm, end), w)
            if COND[op & 15](self):
                self.setr(reg, w, rex, v)
            elif w == 4:
                self.setr(reg, 4, rex, self.getr(reg, 4, rex))
            return
        if op in (0xb6, 0xb7):
            n, mod, reg, rm = self.modrm(p, rex, None)
            end = p + n
            self.ip = end
            size = 1 if op == 0xb6 else 2
            v = self.getr(rm[1], size, rex) if rm[0] == 'r' else self.rd(self.ea(rm, end), size)
            self.setr(reg, w, rex, v)
            return
        if op in (0x10, 0x11, 0x28, 0x29):
            n, mod, reg, rm = self.modrm(p, rex, None)
            end = p + n
            self.ip = end
            if rm[0] == 'r':
                raise Unsupported('xmm reg-reg move')
            addr = self.ea(rm, end)
            if op in (0x10, 0x28):
                self.xmm[reg] = self.rd(addr, 16)
            else:
                self.wr(addr, 16, self.xmm[reg])
            return
        if op == 0x1f:
            n, mod, reg, rm = self.modrm(p, rex, None)
            self.ip = p + n
            return
        if op == 0x0b:
            raise Unsupported('ud2 reached')
        raise Unsupported('opcode 0f %#x at %#x' % (op, at))


# ---- harness: call a validator callback the way clap does
def call_callback(img, name, text, cap=0, patches=None, max_steps=20000, cov=None):
    e = Emu(img, patches, max_steps)
    e.cov = cov
    buf = text if isinstance(text, bytes) else text.encode('latin-1')
    p = e.put(buf)
    arg = e.alloc(24)
    out = e.alloc(24)
    e.wr(arg, 8, cap)
    e.wr(arg + 8, 8, p)
    e.wr(arg + 16, 8, len(buf))
    e.regs[7], e.regs[2] = out, arg
    e.regs[3] = e.regs[12] = e.regs[13] = e.regs[14] = e.regs[15] = 0
    e.run(FUNCS[name])
    first = e.rd(out, 8)
    if first == MIN64:
        res = ('ok',)
    else:
        res = ('err', first, e.rd(out + 16, 8), bytes(e.rb(e.rd(out + 8, 8) + i) for i in range(e.rd(out + 16, 8))))
    frees = e.frees
    return res, frees, p, e.steps


def call_wrapper(img, name, text, cap, parse_err, fmt_text, fmt_fail, patches=None):
    """Replay an address wrapper with scripted callees; return (outcome, events, frees, input_ptr)."""
    e = Emu(img, patches)
    buf = text
    p = e.put(buf)
    arg = e.alloc(24)
    out = e.alloc(24)
    e.vtable = e.alloc(16)
    e.wr(e.vtable, 8, FAKE_DROP)
    e.vtables.add(e.vtable)
    e.script = {'parse_err': parse_err, 'text': fmt_text, 'fmt_fail': fmt_fail, 'obj': None}
    e.wr(arg, 8, cap)
    e.wr(arg + 8, 8, p)
    e.wr(arg + 16, 8, len(buf))
    e.regs[7], e.regs[2] = out, arg
    e.regs[12] = 0
    e.run(FUNCS[name])
    first = e.rd(out, 8)
    if first == MIN64:
        res = ('ok',)
    else:
        n = e.rd(out + 16, 8)
        res = ('err', e.rd(out, 8) == n, bytes(e.rb(e.rd(out + 8, 8) + i) for i in range(n)))
    return res, e.events, e.frees, p


def model_wrapper(name, text, cap, parse_err, fmt_text, fmt_fail):
    """Observed wrapper contract: (outcome, events, frees) or None when the format-failure panic path is taken."""
    ev = [('parse', len(text))]
    if not parse_err:
        res = ('ok',)
    elif name == 'addr_val':
        ev += [('vdrop', True), ('fmt', 0xb3)]
        if fmt_fail:
            return None
        ev.append(('dropres', 0xb3))
        res = ('err', True, fmt_text)
    else:
        ev.append(('fmt', True))
        if fmt_fail:
            return None
        ev.append(('vdrop', True))
        res = ('err', True, fmt_text)
    return res, ev, cap


def wrapper_cases(rng, count):
    texts = [b'', b'a', b'0x' + b'ab' * 20, b'\xff\x00', b'x' * 70]
    fmts = [b'', b'bad address', b'y' * 300, b'\x00\xff']
    for i in range(count):
        t = rng.choice(texts) if i % 2 else bytes(rng.randrange(256) for _ in range(rng.randrange(0, 90)))
        yield (t, rng.choice([0, 0, 24, 48]), rng.random() < 0.6, rng.choice(fmts), int(rng.random() < 0.1))


def compare_wrapper(img, name, count, seed, patches=None, stop_on_diff=False, model=None):
    rng = random.Random(seed)
    total = bad = 0
    for text, cap, perr, ftext, ffail in wrapper_cases(rng, count):
        want = (model or model_wrapper)(name, text, cap, perr, ftext, ffail)
        try:
            res, ev, frees, ptr = call_wrapper(img, name, text, cap, perr, ftext, ffail, patches)
            ok = want is not None and (res, ev) == want[:2] and frees == ([(ptr, want[2], 0)] if want[2] else [])
        except (Unsupported, ValueError, struct.error):
            ok = want is None
        total += 1
        bad += int(not ok)
        if bad and stop_on_diff:
            break
    return total, bad


# ---- models (independent restatement of the observed behaviour)
def model_u64(s):
    if not s:
        return ('err', 'empty')
    t = s[1:] if s[:1] == b'+' else s
    if not t:
        return ('err', 'digit')
    if len(t) < 17:
        return ('ok',) if all(48 <= c <= 57 for c in t) else ('err', 'digit')
    acc = 0
    for c in t:
        d = c - 48
        if acc * 10 > M64:
            return ('err', 'big') if 0 <= d < 10 else ('err', 'digit')
        if not 0 <= d < 10:
            return ('err', 'digit')
        acc = acc * 10 + d
        if acc > M64:
            return ('err', 'big')
    return ('ok',)


def model_bool(s):
    return ('ok',) if s in (b'true', b'false') else ('err', 'bool')


def parse_ipv4(s):
    parts = s.split(b'.')
    if len(parts) != 4:
        return False
    for q in parts:
        if not 1 <= len(q) <= 3 or not all(48 <= c <= 57 for c in q):
            return False
        if len(q) > 1 and q[0] == 48:
            return False
        if int(q) > 255:
            return False
    return True


def model_ip(s):
    return ('ok',) if len(s) <= 15 and parse_ipv4(s) else ('err', 'ip')


def model_dispatch(name):
    return {'u64': model_u64, 'bool': model_bool, 'ip': model_ip}[name]


def classify(img, name, res):
    if res[0] == 'ok':
        return ('ok',)
    body = res[3]
    for k, (va, n) in MSG.items():
        if body == img.read(va, n) and name != 'ip' and res[1] == len(body) and res[2] == len(body):
            return ('err', k)
    if name == 'ip' and body == img.read(*IP_ERR) and res[1] == 16:
        return ('err', 'ip')
    return ('err', 'unknown', body)


# ---- case generation
def u64_cases(rng, count):
    fixed = [b'', b'+', b'-', b'0', b'+0', b'-0', b'-1', b'00', b'+00000000000000000000000000', b' 1', b'1 ', b'1_0',
             b'18446744073709551615', b'18446744073709551616', b'18446744073709551619', b'18446744073709551620',
             b'99999999999999999999', b'184467440737095516150', b'1844674407370955161', b'+18446744073709551615',
             b'-18446744073709551615', b'0000000000000000000018446744073709551615', b'1' + b'0' * 19, b'1' + b'0' * 20,
             b'9' * 16, b'9' * 17, b'9' * 19, b'9' * 20, b'9' * 21, b'1234567890123456', b'12345678901234567',
             b'+1234567890123456', b'\xff', b'\x80' * 3, b'1844674407370955161a', b'18446744073709551616a',
             b'184467440737095516150a', b'a18446744073709551615']
    for s in fixed:
        yield s
    for i in range(count - len(fixed)):
        k = i % 8
        if k == 0:
            n = rng.randrange(1, 40)
            yield bytes(rng.choice(b'0123456789') for _ in range(n))
        elif k == 1:
            n = rng.randrange(1, 40)
            yield b'+' + bytes(rng.choice(b'0123456789') for _ in range(n))
        elif k == 2:
            n = rng.randrange(0, 24)
            yield bytes(rng.choice(b'0123456789+-a. x\xff') for _ in range(n))
        elif k == 3:
            v = rng.choice([M64, M64 - 1, M64 + 1, M64 * 10 // 9, 10 ** 19, 2 ** 63, 2 ** 64 - rng.randrange(1, 100),
                            2 ** 64 + rng.randrange(0, 100), rng.randrange(0, 2 ** 70)])
            yield str(v).encode()
        elif k == 4:
            s = bytearray(str(rng.choice([M64, rng.randrange(0, M64)])).encode())
            s[rng.randrange(len(s))] = rng.choice(b'+-a. /:\x00')
            yield bytes(s)
        elif k == 5:
            n = rng.randrange(14, 20)
            yield bytes(rng.choice(b'0123456789') for _ in range(n)) + rng.choice([b'', b'x', b'-', b'+', b'0'])
        elif k == 6:
            n = rng.randrange(16, 22)
            yield b'1' * rng.randrange(0, 3) + bytes(rng.choice(b'9876') for _ in range(n))
        else:
            n = rng.randrange(1, 5)
            yield bytes(rng.choice(b'0123456789+') for _ in range(n))


def bool_cases(rng, count):
    fixed = [b'true', b'false', b'', b'True', b'False', b'TRUE', b'FALSE', b'tru', b'truee', b'fals', b'falsee', b't',
             b'f', b'1', b'0', b'yes', b'no', b'true ', b' true', b'false ', b'fAlse', b'tRue', b'falsf', b'trud',
             b'faLse', b'fa\x00se', b'tru\x00', b'\x00rue', b'on', b'off']
    for s in fixed:
        yield s
    for i in range(count - len(fixed)):
        base = rng.choice([b'true', b'false'])
        k = i % 4
        if k == 0:
            s = bytearray(base)
            s[rng.randrange(len(s))] = rng.randrange(256)
            yield bytes(s)
        elif k == 1:
            yield base[:rng.randrange(len(base))] + base[rng.randrange(len(base)):][:rng.randrange(3)]
        elif k == 2:
            yield bytes(rng.randrange(256) for _ in range(rng.choice([4, 5, 4, 5, rng.randrange(0, 9)])))
        else:
            yield base + bytes(rng.choice(b' \n\x00a') for _ in range(rng.randrange(0, 3)))


def ip_cases(rng, count):
    fixed = [b'', b'0.0.0.0', b'255.255.255.255', b'127.0.0.1', b'1.2.3.4', b'1.2.3', b'1.2.3.4.5', b'1.2.3.', b'.1.2.3',
             b'1..2.3', b'01.2.3.4', b'1.02.3.4', b'1.2.3.04', b'00.0.0.0', b'0.0.0.00', b'256.1.1.1', b'1.1.1.256',
             b'999.1.1.1', b'1.2.3.4 ', b' 1.2.3.4', b'1.2.3.4\n', b'a.b.c.d', b'1.2.3.-4', b'+1.2.3.4', b'1.2.3.4a',
             b'255.255.255.2555', b'100.100.100.100', b'192.168.100.200', b'1111.1.1.1', b'1.1.1.1111', b'0x1.2.3.4',
             b'1.2.3.4.', b'....', b'.', b'1', b'12345678901234567', b'255.255.255.255.', b'::1', b'1.2.3.4/32']
    for s in fixed:
        yield s
    for i in range(count - len(fixed)):
        k = i % 8
        if k == 0:
            yield '.'.join(str(rng.randrange(0, 256)) for _ in range(4)).encode()
        elif k == 1:
            yield '.'.join(str(rng.choice([0, 1, 9, 10, 99, 100, 199, 200, 249, 250, 255, 256, 259, 260, 299, 300, 999]))
                           for _ in range(4)).encode()
        elif k == 2:
            yield '.'.join(rng.choice(['0', '00', '01', '001', '010', '1', '0255', '000', '10']) for _ in range(4)).encode()
        elif k == 3:
            yield bytes(rng.choice(b'0123456789.') for _ in range(rng.randrange(0, 18)))
        elif k == 4:
            s = bytearray('.'.join(str(rng.randrange(0, 256)) for _ in range(4)).encode())
            s[rng.randrange(len(s))] = rng.choice(b'.0a- +:\xff9')
            yield bytes(s)
        elif k == 5:
            n = rng.randrange(1, 6)
            yield '.'.join(str(rng.randrange(0, 256)) for _ in range(n)).encode()
        elif k == 6:
            s = '.'.join(str(rng.randrange(0, 256)) for _ in range(4)).encode()
            yield s + rng.choice([b'', b'.', b'0', b'.0', b' ', b'\x00'])
        else:
            yield bytes(rng.choice(b'0123456789....') for _ in range(rng.randrange(7, 17)))


GENS = {'u64': u64_cases, 'bool': bool_cases, 'ip': ip_cases}
DEFAULT_COUNTS = {'u64': 6400, 'bool': 1800, 'ip': 6400}
DEFAULT_SEED = 115


def compare(img, name, model, cases, patches=None, stop_on_diff=False, sink=None, cov=None):
    """Replay every case; return (count, mismatches, hist)."""
    total = bad = 0
    hist = {}
    for i, s in enumerate(cases):
        cap = 0 if i % 3 else 32
        try:
            res, frees, ptr, steps = call_callback(img, name, s, cap, patches, cov=cov)
            got = classify(img, name, res)
            want = model(s)
            want_frees = [(ptr, cap, 0)] if cap else []
            ok = got == want and frees == want_frees
        except (Unsupported, ValueError, struct.error):
            got, want, ok = ('crash',), model(s), False
        total += 1
        key = want[-1] if want[0] == 'err' else 'ok'
        hist[key] = hist.get(key, 0) + 1
        if not ok:
            bad += 1
            if stop_on_diff:
                return total, bad, hist
        if sink is not None:
            sink(name, s, want, got, ok)
    return total, bad, hist


# ---- negative controls
def wrong_models():
    def u64_allow_minus(s):
        return model_u64(s[1:]) if s[:1] == b'-' and len(s) > 1 else model_u64(s)

    def u64_max_minus_one(s):
        t = s[1:] if s[:1] == b'+' else s
        return ('err', 'big') if t.isdigit() and int(t) == M64 else model_u64(s)

    def u64_no_plus(s):
        return model_u64(s) if s[:1] != b'+' else ('err', 'digit')

    def u64_signed(s):
        r = model_u64(s)
        t = s[1:] if s[:1] == b'+' else s
        return ('err', 'big') if r == ('ok',) and t.isdigit() and int(t) > 2 ** 63 - 1 else r

    def u64_empty_digit(s):
        return ('err', 'digit') if not s else model_u64(s)

    def u64_big_as_digit(s):
        r = model_u64(s)
        return ('err', 'digit') if r == ('err', 'big') else r

    def bool_cases_ci(s):
        return ('ok',) if s.lower() in (b'true', b'false') else ('err', 'bool')

    def bool_yes(s):
        return ('ok',) if s in (b'true', b'false', b'yes') else ('err', 'bool')

    def bool_prefix(s):
        return ('ok',) if s[:4] == b'true' or s == b'false' else ('err', 'bool')

    def bool_one(s):
        return ('ok',) if s in (b'true', b'false', b'1') else ('err', 'bool')

    def ip_octet_256(s):
        parts = s.split(b'.')
        if len(s) <= 15 and len(parts) == 4 and any(p == b'256' for p in parts):
            return ('ok',) if all(p == b'256' or parse_ipv4(p + b'.0.0.0') for p in parts) else ('err', 'ip')
        return model_ip(s)

    def ip_len14(s):
        return ('ok',) if len(s) <= 14 and parse_ipv4(s) else ('err', 'ip')

    def ip_leading_zero(s):
        parts = s.split(b'.')
        if len(s) <= 15 and len(parts) == 4 and all(p.isdigit() and len(p) <= 3 and int(p) <= 255 for p in parts):
            return ('ok',)
        return ('err', 'ip')

    def ip_trailing_ok(s):
        return ('ok',) if len(s) <= 15 and parse_ipv4(s.rstrip(b'.')) else ('err', 'ip')

    def ip_three(s):
        parts = s.split(b'.')
        if len(s) <= 15 and len(parts) == 3 and parse_ipv4(s + b'.0'):
            return ('ok',)
        return model_ip(s)

    def ip_max_254(s):
        parts = s.split(b'.')
        if any(p == b'255' for p in parts):
            return ('err', 'ip')
        return model_ip(s)

    return [
        ('u64', 'accepts-minus', u64_allow_minus), ('u64', 'max-minus-one', u64_max_minus_one),
        ('u64', 'no-plus', u64_no_plus), ('u64', 'signed-range', u64_signed),
        ('u64', 'empty-as-digit', u64_empty_digit), ('u64', 'big-as-digit', u64_big_as_digit),
        ('bool', 'case-insensitive', bool_cases_ci), ('bool', 'accepts-yes', bool_yes),
        ('bool', 'prefix-true', bool_prefix), ('bool', 'accepts-one', bool_one),
        ('ip', 'octet-256', ip_octet_256), ('ip', 'len-14', ip_len14), ('ip', 'leading-zero-ok', ip_leading_zero),
        ('ip', 'trailing-dot-ok', ip_trailing_ok), ('ip', 'three-octets-ok', ip_three), ('ip', 'max-254', ip_max_254),
    ]


def wrapper_wrong_models():
    def val_fmt_first(name, text, cap, perr, ftext, ffail):
        r = model_wrapper(name, text, cap, perr, ftext, ffail)
        if r is None or not perr or name != 'addr_val':
            return r
        ev = list(r[1])
        ev[1], ev[2] = ev[2], ev[1]
        return r[0], ev, r[2]

    def sig_drop_first(name, text, cap, perr, ftext, ffail):
        r = model_wrapper(name, text, cap, perr, ftext, ffail)
        if r is None or not perr or name != 'addr_sig':
            return r
        ev = list(r[1])
        ev[1], ev[2] = ev[2], ev[1]
        return r[0], ev, r[2]

    def val_no_dropres(name, text, cap, perr, ftext, ffail):
        r = model_wrapper(name, text, cap, perr, ftext, ffail)
        if r is None or name != 'addr_val':
            return r
        return r[0], [e for e in r[1] if e[0] != 'dropres'], r[2]

    def val_tag_a0(name, text, cap, perr, ftext, ffail):
        r = model_wrapper(name, text, cap, perr, ftext, ffail)
        if r is None or name != 'addr_val':
            return r
        return r[0], [('fmt', 0xa0) if e[0] == 'fmt' else (('dropres', 0xa0) if e[0] == 'dropres' else e) for e in r[1]], r[2]

    def no_free_on_err(name, text, cap, perr, ftext, ffail):
        r = model_wrapper(name, text, cap, perr, ftext, ffail)
        return r if r is None or not perr else (r[0], r[1], 0)

    def ok_text(name, text, cap, perr, ftext, ffail):
        r = model_wrapper(name, text, cap, perr, ftext, ffail)
        return r if r is None or r[0] != ('ok',) else (('err', True, b''), r[1], r[2])

    def fail_is_ok(name, text, cap, perr, ftext, ffail):
        return model_wrapper(name, text, cap, perr, ftext, 0)

    return [('addr_val', 'format-before-drop', val_fmt_first), ('addr_sig', 'drop-before-format', sig_drop_first),
            ('addr_val', 'no-result-drop', val_no_dropres), ('addr_val', 'tag-a0', val_tag_a0),
            ('addr_sig', 'no-release-on-error', no_free_on_err), ('addr_val', 'ok-has-text', ok_text),
            ('addr_sig', 'format-failure-ignored', fail_is_ok)]


def wrapper_mutations():
    return [('addr-val-error-byte-compare-1-to-0', 'addr_val', {0x565494c: 0}),
            ('addr-val-branch-jne-to-je', 'addr_val', {0x565494e: 0x84}),
            ('addr-val-tag-0xb3-to-0xb4', 'addr_val', {0x5654962: 0xb4}),
            ('addr-sig-error-byte-compare-1-to-0', 'addr_sig', {0x5654abb: 0}),
            ('addr-sig-branch-jne-to-je', 'addr_sig', {0x5654abd: 0x84}),
            ('addr-sig-format-test-flipped', 'addr_sig', {0x5654b0f: 0x84}),
            ('addr-val-format-test-flipped', 'addr_val', {0x56549af: 0x84})]


def byte_mutations(img):
    """(label, name, {va: byte}) single-byte damage to the retained bodies."""
    rows = []
    def at(label, name, va, new):
        rows.append((label, name, {va: new}))
    at('u64-short-limit-0x11-to-0x12', 'u64', 0x5654522, 0x12)
    at('u64-plus-compare-0x2b-to-0x2c', 'u64', 0x565450c, 0x2c)
    at('u64-digit-bias-0xd0-to-0xcf', 'u64', 0x5654545, 0xcf)
    at('u64-digit-limit-9-to-8', 'u64', 0x5654548, 0x8)
    at('u64-long-radix-10-to-9', 'u64', 0x565457e, 0x9)
    at('u64-minus-compare-0x2d-to-0x2e', 'u64', 0x56544f0, 0x2e)
    at('u64-empty-jump-flipped', 'u64', 0x56544cf, 0x75)
    at('bool-true-word-t-to-s', 'bool', 0x56547f9, 0x73)
    at('bool-len4-to-len3', 'bool', 0x56547f4, 0x3)
    at('bool-len5-to-len6', 'bool', 0x56547ea, 0x6)
    at('bool-false-word-f-to-g', 'bool', 0x565488b, 0x67)
    at('bool-trailing-e-to-f', 'bool', 0x5654896, 0x66)
    at('ip-error-text-pointer-low-byte', 'ip', 0x5654759, 0xaf)
    at('ip-len-limit-0xf-to-0xe', 'ip', 0x56546da, 0x0e)
    at('ip-eof-test-flipped', 'ip', 0x56546f4, 0x01)
    at('ip-success-jump-inverted', 'ip', 0x56546fc, 0x75)
    return rows


def damage_cases(img):
    """Byte damage that must change behaviour, plus out-of-range controls."""
    yield 'wrong-digest', lambda: load_bytes_with_flip()
    yield 'address-outside-alloc', lambda: Image(BINARY.read_bytes()).read(0xffffffffff, 1)
    yield 'nobits-excluded', lambda: Image(BINARY.read_bytes()).read(0x64e9000 + 0x10000000, 1)
    yield 'unknown-opcode-rejected', lambda: _unknown_opcode(img)
    yield 'indirect-call-needs-slot', lambda: _bad_slot(img)
    yield 'step-limit', lambda: _spin(img)


def load_bytes_with_flip():
    data = bytearray(BINARY.read_bytes())
    data[100] ^= 1
    if hashlib.sha256(bytes(data)).hexdigest() != SHA:
        raise ValueError('input binary digest mismatch')


def _unknown_opcode(img):
    e = Emu(img, {0x56544b0: 0x06})
    e.regs[7] = e.regs[2] = e.alloc(24)
    e.run(FUNCS['u64'])


def _bad_slot(img):
    call_callback(img, 'u64', b'1', 0, {0x56544b0: 0xff, 0x56544b1: 0x15, 0x56544b2: 0, 0x56544b3: 0, 0x56544b4: 0, 0x56544b5: 0})


def _spin(img):
    call_callback(img, 'u64', b'1', 0, {0x56544b0: 0xeb, 0x56544b1: 0xfe})


def fde_checks(img):
    ext = extents(img)
    rows = []
    for name, va in FUNCS.items():
        rows.append((name, va, ext[va]))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    img = load()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(DEFAULT_SEED)
    cases = bad = 0
    cov = {}
    tsv = ['# name\tinput_hex\texpected\treplayed\tmatch']
    summary = {}
    for name in ('u64', 'bool', 'ip'):
        n = DEFAULT_COUNTS[name]
        kept = []

        def sink(nm, s, want, got, ok, kept=kept):
            if len(kept) < 100:
                kept.append('%s\t%s\t%s\t%s\t%d' % (nm, s.hex(), '/'.join(map(str, want)), '/'.join(map(str, got[:2])), ok))
        t, b, hist = compare(img, name, model_dispatch(name), GENS[name](rng, n), sink=sink, cov=cov)
        cases += t
        bad += b
        summary[name] = {'cases': t, 'mismatches': b, 'verdicts': dict(sorted(hist.items()))}
        tsv.extend(kept)
    ext = extents(img)
    owner = lambda a: next((nm for nm, va in FUNCS.items() if va <= a < ext[va]), '?')
    crow = ['# function\tjcc_address\tnot_taken\ttaken']
    for a in sorted(cov):
        crow.append('%s\t%#x\t%d\t%d' % (owner(a), a, cov[a][0], cov[a][1]))
    (out / 'branch-coverage.tsv').write_text('\n'.join(crow) + '\n')
    (out / 'replay-sample.tsv').write_text('\n'.join(tsv) + '\n')
    # negative controls
    neg = det = 0
    rows = ['# kind\tlabel\ttarget\tdetected']
    for name, label, wrong in wrong_models():
        sub = random.Random(DEFAULT_SEED + 1)
        t, b, _ = compare(img, name, wrong, GENS[name](sub, 900), stop_on_diff=True)
        neg += 1
        det += int(b > 0)
        rows.append('wrong-model\t%s\t%s\t%d' % (label, name, int(b > 0)))
    for label, name, patch in byte_mutations(img):
        sub = random.Random(DEFAULT_SEED + 2)
        t, b, _ = compare(img, name, model_dispatch(name), GENS[name](sub, 900), patch, stop_on_diff=True)
        neg += 1
        det += int(b > 0)
        rows.append('byte-damage\t%s\t%s\t%d' % (label, name, int(b > 0)))
    for name in ('addr_val', 'addr_sig'):
        t, b = compare_wrapper(img, name, 1500, DEFAULT_SEED + 3)
        cases += t
        bad += b
        summary[name] = {'cases': t, 'mismatches': b}
    for name, label, wrong in wrapper_wrong_models():
        t, b = compare_wrapper(img, name, 400, DEFAULT_SEED + 4, stop_on_diff=True, model=wrong)
        neg += 1
        det += int(b > 0)
        rows.append('wrong-model\t%s\t%s\t%d' % (label, name, int(b > 0)))
    for label, name, patch in wrapper_mutations():
        t, b = compare_wrapper(img, name, 400, DEFAULT_SEED + 5, patch, stop_on_diff=True)
        neg += 1
        det += int(b > 0)
        rows.append('byte-damage\t%s\t%s\t%d' % (label, name, int(b > 0)))
    for label, fn in damage_cases(img):
        neg += 1
        try:
            fn()
            ok = 0
        except (Unsupported, ValueError, struct.error):
            ok = 1
        det += ok
        rows.append('range-or-input\t%s\t-\t%d' % (label, ok))
    (out / 'negative-controls.tsv').write_text('\n'.join(rows) + '\n')
    fde = fde_checks(img)
    (out / 'function-extents.tsv').write_text('# name\tstart\tfde_end\n' + ''.join('%s\t%#x\t%#x\n' % r for r in fde))
    summary['functions'] = {n: {'start': hex(s), 'end': hex(e)} for n, s, e in fde}
    measure = {'cases': cases, 'negative_controls': neg, 'negative_detected': det, 'mismatches': bad}
    (out / 'measure.json').write_text(json.dumps(measure, indent=1, sort_keys=True) + '\n')
    (out / 'summary.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
    print(json.dumps(measure))
    return 0 if bad == 0 and det == neg else 1


if __name__ == '__main__':
    sys.exit(main())
