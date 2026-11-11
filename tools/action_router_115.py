#!/usr/bin/env python3
"""Reconstruct the node 115 action router at 0x2bda7c0 and check it against its bytes.

The tool carries (1) an executable model of the router (tag -> variant index,
latency-timer gate, handler choice, argument shape, timer record) and (2) a
small x86-64 interpreter restricted to the instruction forms found in the
router, its 92 arms and its epilogue.  Every case runs the real bytes with
stubbed external calls and compares the recorded call trace, the 128-byte
result copy and the callee-saved registers against the model.  Nothing from
the binary is executed natively and no other program is invoked.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from elf_index import sections


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

ROUTER = 0x2bda7c0
ROUTER_END = 0x2bdb225
JOIN = 0x2bdb167
TABLE = 0x609f00
FLAG_SLOT = 0x64e1028
NOW_FN = 0x5c842e0
RECORD_FN = 0x5c84210
M64 = (1 << 64) - 1

# Handler entry per variant index (arm call targets, read from the arm bytes).
HANDLERS = tuple(int(x, 16) for x in (
    '2c11290 2c05c70 2c12050 2c0ede0 2c1fd40 2c03ed0 2c182b0 2c0da60 2c1c240 2c08ad0 '
    '2c18c40 2c1d070 2c09ff0 2c07730 2c168e0 2c0d190 2c06da0 2c0f350 2c06530 2c08600 '
    '2c1da50 2c13570 2c1df30 2c143d0 2c04e30 2c1aee0 2c1b320 2c0e9a0 2c12c10 2c09980 '
    '2c1edc0 2c03970 2c057b0 2c186f0 2c060b0 2c0a610 2c1f370 2c13e70 2c09400 2c11af0 '
    '2c17dc0 2c103b0 2c0df40 2c1a3f0 2c0ab50 2c14de0 2c07c10 2c08130 2c1e440 2c1f910 '
    '2c19100 2c1b7d0 2c12690 2c08f00 2c0b030 2c15220 2c0ba40 2c10d70 2c19a40 2c139b0 '
    '2c172e0 2c16460 2c17820 2c1cbd0 2c116b0 2c1d590 2c0b5a0 2c068b0 2c1c680 2c1a930 '
    '2c13070 2c0c520 2c1e920 2c1bcb0 2c07260 2c04350 2c048a0 2c0e420 2c15660 2c19f20 '
    '2c16020 2c0fdb0 2c0cb20 2c0d630 2c05370 2c149b0 2c16eb0 2c19610 2c108a0 2c0bfa0 '
    '2c15b40 2c0f810').split())
NO_EXTRA = frozenset((0, 5, 18, 22, 28, 35, 61, 64, 65, 72, 78))   # arms without a tag-pointer fourth argument
# Arms that instead load fourth/fifth arguments by value: index -> ((rcx offset, size), (r8 offset, size) or None)
ARG_LOADS = {18: ((8, 8), (16, 8)), 22: ((16, 8), (24, 8)), 28: ((8, 4), None), 35: ((8, 8), (16, 4)),
             61: ((0x28, 8), None), 65: ((8, 4), None), 78: ((8, 4), None)}
TAG_POINTER = frozenset((20,))
LOCAL_RESULT = 0x7ff000 - 0xf0

REAL = dict(base=0x86, default=20, mask=0x501d, maxbit=14, sentinel=1000000000,
            flag_arg=50, flag_polarity=True, timed_always=False, timed_never=False,
            swap_record=False, skip_second_now=False, handlers=HANDLERS, no_extra=NO_EXTRA, arg_loads=ARG_LOADS,
            tag_pointer=TAG_POINTER)


class Image:
    def __init__(self, data):
        self.parts = []
        for s in sections(data):
            if s['type'] != 8 and s['flags'] & 2 and s['size']:
                self.parts.append((s['address'], data[s['offset']:s['offset'] + s['size']]))
        self.patches = {}

    def byte(self, va):
        if va in self.patches:
            return self.patches[va]
        for base, blob in self.parts:
            if base <= va < base + len(blob):
                return blob[va - base]
        raise ValueError('unmapped read at %#x' % va)

    def read(self, va, n):
        return bytes(self.byte(va + i) for i in range(n))


def payload_word(k):
    """Deterministic 8-byte word k of the action payload that follows the tag word."""
    return (0x1122334455667788 + k * 0x0101010101010101) & M64


def payload_at(offset, size):
    """Value a load of `size` bytes at tag pointer + offset sees (offset is a multiple of 8, >= 8)."""
    return payload_word((offset - 8) // 8) & ((1 << (8 * size)) - 1)


class EmuError(Exception):
    pass


class Emu:
    """Interpreter for the router's instruction subset (flags: CF and ZF only)."""

    def __init__(self, image, tag, flag, nows, ptrs):
        self.img = image
        self.mem = {}
        self.r = [0] * 16
        self.cf = self.zf = False
        self.trace = []
        self.visited = set()
        self.flag = flag
        self.nows = list(nows)
        self.rbx_out, self.r_in, self.r_ctx, self.r_tag = ptrs
        # Argument layout: rdi=out, rsi=ctx, rdx=ctx2, rcx=pointer to the tag word.
        self.r[7], self.r[6], self.r[2], self.r[1] = ptrs
        self.w64(self.r_tag, tag)
        for k in range(8):
            self.w64(self.r_tag + 8 + 8 * k, payload_word(k))
        self.r[4] = 0x7ff000
        self.ret_sentinel = 0xdead0000
        self.r[4] -= 8
        self.w64(self.r[4], self.ret_sentinel)
        self.saved = {i: 0x1000 + i * 0x111 for i in (3, 5, 12, 13, 14, 15)}
        for i, v in self.saved.items():
            self.r[i] = v
        # entry args override callee-saved choices made above for rdi/rsi/rdx/rcx only
        self.rip = ROUTER

    def w8(self, a, v):
        self.mem[a] = v & 0xff

    def r8(self, a):
        if a in self.mem:
            return self.mem[a]
        return self.img.byte(a)

    def rn(self, a, n):
        return int.from_bytes(bytes(self.r8(a + i) for i in range(n)), 'little')

    def wn(self, a, v, n):
        for i, b in enumerate((v & ((1 << (8 * n)) - 1)).to_bytes(n, 'little')):
            self.mem[a + i] = b

    def w64(self, a, v):
        self.wn(a, v, 8)

    # -- decode helpers
    def u8(self, p):
        return self.img.byte(p)

    def s8(self, p):
        v = self.img.byte(p)
        return v - 256 if v > 127 else v

    def s32(self, p):
        return struct.unpack('<i', self.img.read(p, 4))[0]

    def modrm(self, p, rex, imm=0):
        m = self.u8(p)
        mod, reg, rm = m >> 6, ((m >> 3) & 7) | ((rex & 4) << 1), m & 7
        p += 1
        if mod == 3:
            return p, reg, ('r', rm | ((rex & 1) << 3))
        if rm == 4:
            sib = self.u8(p)
            p += 1
            base, idx, sc = (sib & 7) | ((rex & 1) << 3), ((sib >> 3) & 7) | ((rex & 2) << 2), sib >> 6
            if (sib & 7) == 5 and mod == 0:
                raise EmuError('sib without base')
            addr = self.r[base] + (0 if idx == 4 else self.r[idx] << sc)
        elif rm == 5 and mod == 0:
            disp = self.s32(p)
            p += 4
            return p, reg, ('m', (p + imm + disp) & M64)
        else:
            addr = self.r[rm | ((rex & 1) << 3)]
        if mod == 1:
            addr += self.s8(p)
            p += 1
        elif mod == 2:
            addr += self.s32(p)
            p += 4
        return p, reg, ('m', addr & M64)

    def get(self, op, size):
        if op[0] == 'r':
            return self.r[op[1]] & ((1 << (8 * size)) - 1)
        return self.rn(op[1], size)

    def put(self, op, val, size):
        if op[0] == 'r':
            if size == 8:
                self.r[op[1]] = val & M64
            elif size == 4:
                self.r[op[1]] = val & 0xffffffff
            else:
                self.r[op[1]] = (self.r[op[1]] & ~0xff & M64) | (val & 0xff)
        else:
            self.wn(op[1], val, size)

    def cmpflags(self, a, b, size):
        mask = (1 << (8 * size)) - 1
        a &= mask
        b &= mask
        self.cf = a < b
        self.zf = a == b

    def call(self, target, ret):
        kind = ('now' if target == NOW_FN else 'record' if target == RECORD_FN else
                'flag' if target == FLAG_SLOT else 'handler' if target in HANDLERS else None)
        if kind is None:
            raise EmuError('unexpected call target %#x' % target)
        r = self.r
        if kind == 'flag':
            self.trace.append(('flag', r[7] & 0xffffffff))
            r[0] = 1 if self.flag else 0
        elif kind == 'now':
            self.trace.append(('now', r[7] & 0xffffffff))
            sec, ns = self.nows.pop(0)
            r[0], r[2] = sec, ns
        elif kind == 'record':
            def pair(a):
                return (self.rn(a, 8), self.rn(a + 8, 4))
            self.trace.append(('record', pair(r[6]), pair(r[2])))
        else:
            self.trace.append(('handler', target, r[7], r[6], r[2], r[1], r[8]))
            seed = target * 0x9e3779b97f4a7c15 & M64
            for i in range(16):
                seed = (seed * 6364136223846793005 + 1442695040888963407) & M64
                self.w64(r[7] + 8 * i, seed)
        for i in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            if not (kind in ('flag', 'now') and i in (0, 2)):
                r[i] = 0xc0c0c0c0 + i
        self.rip = ret

    def step(self):
        p = self.rip
        self.visited.add(p)
        r = self.r
        rex = 0
        b = self.u8(p)
        if 0x40 <= b <= 0x4f:
            rex = b
            p += 1
            b = self.u8(p)
        W = 8 if rex & 8 else 4
        B = (rex & 1) << 3
        p += 1
        if 0x50 <= b <= 0x57:
            r[4] -= 8
            self.w64(r[4], r[(b - 0x50) | B])
        elif 0x58 <= b <= 0x5f:
            r[(b - 0x58) | B] = self.rn(r[4], 8)
            r[4] += 8
        elif b == 0xc3:
            self.rip = self.rn(r[4], 8)
            r[4] += 8
            return
        elif b in (0x81, 0x83):
            n = 4 if b == 0x81 else 1
            p, reg, op = self.modrm(p, rex, n)
            imm = self.s32(p) if n == 4 else self.s8(p)
            p += n
            sub = reg & 7
            a = self.get(op, W)
            if sub == 0:
                self.put(op, a + imm, W)
            elif sub == 5:
                self.cmpflags(a, imm, W)
                self.put(op, a - imm, W)
            elif sub == 7:
                self.cmpflags(a, imm, W)
            else:
                raise EmuError('group1 /%d' % sub)
        elif b in (0x89, 0x8b, 0x8d, 0x01, 0x63, 0x84):
            p, reg, op = self.modrm(p, rex)
            if b == 0x89:
                self.put(op, self.get(('r', reg), W), W)
            elif b == 0x8b:
                self.put(('r', reg), self.get(op, W), W)
            elif b == 0x8d:
                self.put(('r', reg), op[1], W)
            elif b == 0x01:
                self.put(op, self.get(op, W) + self.get(('r', reg), W), W)
            elif b == 0x63:
                v = self.get(op, 4)
                self.put(('r', reg), v - (1 << 32) if v >> 31 else v, 8)
            else:
                self.zf = (self.get(op, 1) & self.get(('r', reg), 1)) == 0
                self.cf = False
        elif b == 0x3d or b == 0x2d:
            imm = self.s32(p)
            p += 4
            a = self.get(('r', 0), W)
            self.cmpflags(a, imm, W)
            if b == 0x2d:
                self.put(('r', 0), a - imm, W)
        elif b == 0x3c:
            self.cmpflags(r[0], self.u8(p), 1)
            p += 1
        elif 0xb8 <= b <= 0xbf:
            r[(b - 0xb8) | B] = struct.unpack('<I', self.img.read(p, 4))[0]
            p += 4
        elif b == 0x0f:
            b2 = self.u8(p)
            p += 1
            if b2 == 0xb6:
                p, reg, op = self.modrm(p, rex)
                self.put(('r', reg), self.get(op, 1), 4)
            elif b2 == 0x43:
                p, reg, op = self.modrm(p, rex)
                v = self.get(op, W) if not self.cf else self.get(('r', reg), W)
                self.put(('r', reg), v, W)
            elif b2 == 0xa3:
                p, reg, op = self.modrm(p, rex)
                self.cf = bool((self.get(op, W) >> (self.get(('r', reg), W) % (8 * W))) & 1)
            elif b2 in (0x28, 0x29):
                p, reg, op = self.modrm(p, rex)
                if op[0] != 'm':
                    raise EmuError('movaps reg-reg')
                xmm = self.xmm.setdefault(reg, 0) if hasattr(self, 'xmm') else None
                if not hasattr(self, 'xmm'):
                    self.xmm = {}
                if b2 == 0x28:
                    self.xmm[reg] = self.rn(op[1], 16)
                else:
                    self.wn(op[1], self.xmm.get(reg, 0), 16)
            else:
                raise EmuError('0f %02x' % b2)
        elif b in (0x73, 0x74, 0x75, 0x77, 0xeb):
            d = self.s8(p)
            p += 1
            take = {0x73: not self.cf, 0x74: self.zf, 0x75: not self.zf,
                    0x77: (not self.cf) and not self.zf, 0xeb: True}[b]
            if take:
                p += d
        elif b == 0xe9:
            d = self.s32(p)
            p += 4 + d
        elif b == 0xe8:
            d = self.s32(p)
            p += 4
            self.call((p + d) & M64, p)
            return
        elif b == 0xff:
            p, reg, op = self.modrm(p, rex)
            sub = reg & 7
            if sub == 2 and op[0] == 'm' and op[1] == FLAG_SLOT:
                self.call(FLAG_SLOT, p)
                return
            if sub == 4 and op[0] == 'r':
                p = r[op[1]]
            else:
                raise EmuError('ff /%d' % sub)
        else:
            raise EmuError('opcode %02x at %#x' % (b, self.rip))
        self.rip = p

    def run(self):
        for _ in range(3000):
            if self.rip == self.ret_sentinel:
                break
            self.step()
        else:
            raise EmuError('step limit')
        out = bytes(self.r8(self.rbx_out + i) for i in range(128))
        saved_ok = all(self.r[i] == v for i, v in self.saved.items()) and self.r[4] == 0x7ff000
        return tuple(self.trace), out, saved_ok


# -- model ---------------------------------------------------------------------

def handler_fill(target):
    out = bytearray()
    seed = target * 0x9e3779b97f4a7c15 & M64
    for _ in range(16):
        seed = (seed * 6364136223846793005 + 1442695040888963407) & M64
        out += seed.to_bytes(8, 'little')
    return bytes(out[:128])


def accepts(tag, nows, params=REAL):
    """Input domain the reconstruction speaks about (tags with a table slot)."""
    if tag >= params['base']:
        if tag - params['base'] >= 92:
            return False
    return all(0 <= ns < params['sentinel'] for _, ns in nows)


def model(tag, flag, nows, ptrs, params=REAL):
    out_p, ctx, ctx2, tag_p = ptrs
    index = tag - params['base'] if tag >= params['base'] else params['default']
    low = ((tag - params['base']) & 0xff) if tag >= params['base'] else params['default']
    gated = low <= params['maxbit'] and (params['mask'] >> low) & 1
    trace = []
    timed = True
    if gated and not params['timed_always']:
        trace.append(('flag', params['flag_arg']))
        timed = bool(flag) == params['flag_polarity']
    if params['timed_never']:
        timed = False
    nows = list(nows)
    start = None
    if timed:
        trace.append(('now', 1))
        start = nows.pop(0)
    r8 = None
    if index in params['no_extra']:
        spec = params['arg_loads'].get(index)
        if spec is None:
            extra = ('none', tag_p)
        else:
            extra = payload_at(*spec[0])
            r8 = payload_at(*spec[1]) if spec[1] else None
    else:
        extra = tag_p if index in params['tag_pointer'] else tag_p + 8
    target = params['handlers'][index]
    trace.append(('handler', target, LOCAL_RESULT, ctx, ctx2, extra, r8))
    # The epilogue compares the saved start nanoseconds with the sentinel
    # that the untimed path loads, so a timed start never matches it.
    if timed and start[1] != params['sentinel']:
        if not params['skip_second_now']:
            trace.append(('now', 1))
        end = nows.pop(0) if not params['skip_second_now'] else start
        a, b = (start, end) if params['swap_record'] else (end, start)
        trace.append(('record', (a[0], a[1]), (b[0], b[1])))
    return tuple(trace), handler_fill(target)


def compare(real, mod, extra_ok=True):
    """Equality of (trace, result) ignoring rcx for arms that do not set it."""
    t1, o1, ok = real
    t2, o2 = mod
    if not ok or o1 != o2 or len(t1) != len(t2):
        return False
    for a, b in zip(t1, t2):
        if a[0] == 'handler':
            if a[:5] != b[:5]:
                return False
            if isinstance(b[5], tuple):
                if a[5] in (b[5][1], b[5][1] + 8):
                    return False
            elif a[5] != b[5]:
                return False
            if b[6] is not None and a[6] != b[6]:
                return False
        elif a != b:
            return False
    return True


# -- cases ----------------------------------------------------------------------

NOWS = (
    ((1700000000, 5), (1700000000, 999999999)),
    ((0, 0), (0, 0)),
    ((1794169131, 123456789), (1794169131, 123456790)),
    ((2**63, 999999999), (2**63 + 1, 0)),
    ((7, 500000000), (8, 499999999)),
    ((2**64 - 1, 1), (0, 2)),
    ((11, 999999999), (11, 999999999)),
    ((100, 0), (99, 5)),
)
PTRS = (
    (0x600000, 0x500000, 0x510000, 0x520000),
    (0x601000, 0x501230, 0x511230, 0x521230),
    (0x7000, 0x8000, 0x9000, 0xa000),
    (0x610000, 0x510008, 0x520008, 0x530008),
)


def valid_tags():
    return list(range(0, 0x86)) + list(range(0x86, 0x86 + 92))


def case_inputs(per_tag):
    for tag in valid_tags():
        for v in range(per_tag):
            yield tag, v & 1, NOWS[(v // 2 + tag) % len(NOWS)], PTRS[(v * 3 + tag) % len(PTRS)]


def run_real(image, tag, flag, nows, ptrs):
    emu = Emu(image, tag, flag, nows, ptrs)
    res = emu.run()
    return res, emu.visited


def load():
    data = Path(TARGET).read_bytes()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise SystemExit('input binary digest mismatch')
    return Image(data)


# -- controls ----------------------------------------------------------------------

def model_mutants():
    def tweak(**kw):
        p = dict(REAL)
        p.update(kw)
        return p
    hs = list(HANDLERS)
    swapped = hs[:]
    swapped[3], swapped[4] = swapped[4], swapped[3]
    swapped2 = hs[:]
    swapped2[89], swapped2[91] = swapped2[91], swapped2[89]
    off = hs[:]
    off[19] += 0x10
    out = [
        ('base_minus_one', tweak(base=0x85)), ('base_plus_one', tweak(base=0x87)),
        ('default_19', tweak(default=19)), ('default_21', tweak(default=21)),
        ('maxbit_13', tweak(maxbit=13)), ('gate_bit_15_added', tweak(maxbit=15, mask=REAL['mask'] | (1 << 15))),
        ('sentinel_minus_one', tweak(sentinel=999999999)),
        ('flag_arg_51', tweak(flag_arg=51)), ('flag_inverted', tweak(flag_polarity=False)),
        ('timed_always', tweak(timed_always=True)), ('timed_never', tweak(timed_never=True)),
        ('swap_record', tweak(swap_record=True)), ('skip_second_now', tweak(skip_second_now=True)),
        ('swap_handlers_3_4', tweak(handlers=tuple(swapped))),
        ('swap_handlers_89_91', tweak(handlers=tuple(swapped2))),
        ('handler_19_plus_16', tweak(handlers=tuple(off))),
        ('extra_arg_added_noop', tweak(no_extra=NO_EXTRA - {0})),
        ('arm18_rcx_offset_16', tweak(arg_loads={**ARG_LOADS, 18: ((16, 8), (16, 8))})),
        ('arm28_rcx_widened', tweak(arg_loads={**ARG_LOADS, 28: ((8, 8), None)})),
        ('arm35_r8_widened', tweak(arg_loads={**ARG_LOADS, 35: ((8, 8), (16, 8))})),
        ('arm61_rcx_offset_8', tweak(arg_loads={**ARG_LOADS, 61: ((8, 8), None)})),
        ('arm22_r8_narrowed', tweak(arg_loads={**ARG_LOADS, 22: ((16, 8), (24, 4))})),
        ('tag_pointer_arm_plus8', tweak(tag_pointer=frozenset())),
        ('extra_arg_dropped_last', tweak(no_extra=NO_EXTRA | {91})),
        ('extra_arg_dropped_display', tweak(no_extra=NO_EXTRA | {19})),
    ]
    for bit in (0, 2, 3, 4, 12, 14):
        out.append(('mask_clear_bit_%d' % bit, tweak(mask=REAL['mask'] & ~(1 << bit))))
    for bit in (1, 5, 13):
        out.append(('mask_set_bit_%d' % bit, tweak(mask=REAL['mask'] | (1 << bit))))
    return out


def byte_damage():
    return [
        ('mask_imm', 0x2bda7fc, 0x1d, 0x1f), ('maxbit_cmp', 0x2bda7f5, 0x0e, 0x0d),
        ('flag_edi', 0x2bda806, 0x32, 0x33), ('sentinel_imm', 0x2bda829, 0x3b, 0x3a),
        ('table_entry_5', TABLE + 20, 0xb4, 0xb0), ('sub_base', 0x2bda82f, 0x86, 0x85),
        ('default_ecx', 0x2bda834, 0x14, 0x15), ('arm_extra_imm', 0x2bdad08, 0x08, 0x10),
        ('join_cmp', 0x2bdb169, 0x00, 0x01), ('record_arg_swap', 0x2bdb18a, 0xb4, 0xac),
    ]


ARM_PROLOGUE = bytes.fromhex('4983c708')   # add $8,%r15
ARM_ARGS = bytes.fromhex('4889e7' '4c89ee' '4c89e2')   # mov %rsp,%rdi; mov %r13,%rsi; mov %r12,%rdx
ARM_RCX = bytes.fromhex('4c89f9')   # mov %r15,%rcx
# mov disp8(%r15),%rcx / %ecx / %r8 / %r8d: two-byte head -> (register, size)
LOAD_FORMS = {bytes.fromhex('498b'): ('rcx', 8), bytes.fromhex('418b'): ('rcx', 4),
              bytes.fromhex('4d8b'): ('r8', 8), bytes.fromhex('458b'): ('r8', 4)}


def shape_of(i):
    if i in ARG_LOADS:
        rcx, r8 = ARG_LOADS[i]
        parts = ['rcx=[%d:%d]' % rcx] + (['r8=[%d:%d]' % r8] if r8 else [])
        return 'loads(%s)' % ','.join(sorted(parts))
    return 'none' if i in NO_EXTRA else 'tag_pointer' if i in TAG_POINTER else 'tag_pointer_plus_8'


def decode_arm(image, index):
    """Decode arm `index` from the jump table by fixed byte patterns.

    Returns (arm_va, handler_va, shape, join_target) where shape is
    'tag_pointer_plus_8' (prologue add then rcx = r15), 'tag_pointer'
    (rcx = r15 only) or 'none'.  Raises ValueError for any other layout.
    """
    if not 0 <= index < 92:
        raise ValueError('arm index outside the 92-slot table')
    entry = struct.unpack('<i', image.read(TABLE + 4 * index, 4))[0]
    arm = TABLE + entry
    pos = arm
    plus8 = image.read(pos, 4) == ARM_PROLOGUE
    if plus8:
        pos += 4
    loads = {}
    while image.read(pos, 2) in LOAD_FORMS and image.byte(pos + 2) in (0x4f, 0x47):
        head = image.read(pos, 2)
        reg, size = LOAD_FORMS[head]
        if (reg == 'rcx') != (image.byte(pos + 2) == 0x4f):
            raise ValueError('arm %d has a malformed argument load' % index)
        loads[reg] = (image.byte(pos + 3), size)
        pos += 4
    for part in (ARM_ARGS[:3], ARM_ARGS[3:6], ARM_ARGS[6:]):
        if image.read(pos, 3) != part:
            raise ValueError('arm %d lacks the fixed argument moves' % index)
        pos += 3
    has_rcx = image.read(pos, 3) == ARM_RCX
    if has_rcx:
        pos += 3
    if image.byte(pos) != 0xe8:
        raise ValueError('arm %d has no direct call' % index)
    handler = (pos + 5 + struct.unpack('<i', image.read(pos + 1, 4))[0]) & M64
    pos += 5
    if image.byte(pos) == 0xe9:
        join = (pos + 5 + struct.unpack('<i', image.read(pos + 1, 4))[0]) & M64
    elif pos == JOIN:
        join = pos
    elif image.byte(pos) == 0xeb:
        join = pos + 2 + struct.unpack('<b', image.read(pos + 1, 1))[0]
    else:
        raise ValueError('arm %d does not jump to the join' % index)
    if plus8 and not has_rcx:
        raise ValueError('arm %d adds to r15 without passing it' % index)
    if loads and (plus8 or has_rcx):
        raise ValueError('arm %d mixes loaded and pointer arguments' % index)
    if loads:
        shape = 'loads(%s)' % ','.join('%s=[%d:%d]' % (r, loads[r][0], loads[r][1]) for r in sorted(loads))
    else:
        shape = ('tag_pointer_plus_8' if plus8 else 'tag_pointer') if has_rcx else 'none'
    return arm, handler, shape, join


def verify_arms(image):
    """Check HANDLERS / NO_EXTRA / TAG_POINTER against the arm bytes."""
    for i in range(92):
        arm, handler, shape, join = decode_arm(image, i)
        want = shape_of(i)
        if handler != HANDLERS[i] or shape != want or join != JOIN:
            raise SystemExit('arm %d disagrees with the model table' % i)
        if not ROUTER <= arm < ROUTER_END:
            raise SystemExit('arm %d lies outside the router FDE' % i)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    image = load()
    verify_arms(image)
    per_tag = 46
    cases = 0
    fails = 0
    visited = {}
    sample = []
    arm_rows = {}
    for n, (tag, flag, nows, ptrs) in enumerate(case_inputs(per_tag)):
        real, seen = run_real(image, tag, flag, nows, ptrs)
        mod = model(tag, flag, nows, ptrs)
        cases += 1
        ok = compare(real, mod)
        fails += not ok
        for a in seen:
            visited[a] = visited.get(a, 0) + 1
        if n % 40 == 0:
            sample.append((n, tag, flag, nows, ptrs, ok, real[0]))
        if tag >= 0x86 and tag - 0x86 not in arm_rows:
            arm_rows[tag - 0x86] = [t for t in real[0] if t[0] == 'handler'][0]
    if fails:
        raise SystemExit('model disagrees with bytes on %d cases' % fails)

    # controls: detection set = every tag x 8 variants
    detect = list(case_inputs(8))
    reals = [run_real(image, *c)[0] for c in detect]
    controls = []
    for name, params in model_mutants():
        hit = any(not compare(r, model(*c, params=params)) for r, c in zip(reals, detect))
        controls.append(('model-mutant', name, hit))
    for name, va, old, new in byte_damage():
        if image.byte(va) != old:
            raise SystemExit('damage anchor %s is not %#x at %#x' % (name, old, va))
        image.patches[va] = new
        hit = False
        for c in detect:
            try:
                res, _ = run_real(image, *c)
            except (EmuError, ValueError, IndexError):
                hit = True
                break
            if not compare(res, model(*c)):
                hit = True
                break
        image.patches.clear()
        controls.append(('byte-damage', name, hit))
    for name, tag, nows in (('tag_just_past_table', 0x86 + 92, NOWS[0]), ('tag_large', 1 << 40, NOWS[1]),
                            ('tag_u64_max', M64, NOWS[2]), ('nanos_equals_sentinel', 0x86, ((1, 1000000000), (2, 0)))):
        controls.append(('out-of-domain', name, not accepts(tag, nows)))
    controls.append(('out-of-domain', 'start_nanos_over_sentinel', not accepts(0x86, ((1, 2000000000), (2, 0)))))
    detected = sum(1 for c in controls if c[2])

    (out / 'arms.tsv').write_text(
        'index\ttag\thandler_va\tfourth_argument\tgated_by_flag_50\n' + ''.join(
            '%d\t%#x\t%#x\t%s\t%d\n' % (
                i, 0x86 + i, HANDLERS[i],
                shape_of(i),
                i in (0, 2, 3, 4, 12, 14))
            for i in range(92)))
    (out / 'coverage.tsv').write_text(
        'instruction_va\tcases_reaching\n' + ''.join('%#x\t%d\n' % (a, visited[a]) for a in sorted(visited)))
    lines = ['case\ttag\tflag\tstart\tend\tpointers\tagree\tcalls\n']
    for n, tag, flag, nows, ptrs, ok, tr in sample:
        lines.append('%d\t%#x\t%d\t%s\t%s\t%s\t%d\t%s\n' % (
            n, tag, flag, nows[0], nows[1], ','.join('%#x' % p for p in ptrs), ok,
            ';'.join('%s' % (t[0] if t[0] != 'handler' else 'handler@%#x' % t[1]) for t in tr)))
    (out / 'cases-sample.tsv').write_text(''.join(lines))
    (out / 'controls.tsv').write_text('kind\tname\tdetected\n' + ''.join('%s\t%s\t%d\n' % (k, n, d) for k, n, d in controls))
    (out / 'summary.json').write_text(json.dumps({
        'router_start': hex(ROUTER), 'router_end': hex(ROUTER_END), 'join': hex(JOIN), 'table': hex(TABLE),
        'binary_sha256': DIGEST, 'arms': 92, 'instructions_reached': len(visited),
        'plus8_argument_arms': 92 - len(NO_EXTRA) - len(TAG_POINTER), 'tag_pointer_arms': len(TAG_POINTER), 'no_argument_arms': len(NO_EXTRA) - len(ARG_LOADS), 'loaded_argument_arms': len(ARG_LOADS), 'flag_gated_indices': [0, 2, 3, 4, 12, 14],
        'sentinel': REAL['sentinel'], 'flag_argument': REAL['flag_arg'], 'cases': cases,
    }, indent=1, sort_keys=True) + '\n')
    (out / 'measure.json').write_text(json.dumps({
        'cases': cases, 'negative_controls': len(controls), 'negative_detected': detected,
    }, indent=1, sort_keys=True) + '\n')
    print('cases', cases, 'controls', len(controls), 'detected', detected)


if __name__ == '__main__':
    main()
