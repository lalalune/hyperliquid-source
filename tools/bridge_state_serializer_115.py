#!/usr/bin/env python3
"""Reconstruct the node #115 Bridge2 state serializer (msgpack struct) and prove it.

The Bridge2 state struct of the bridge component is written through a serde
struct serializer whose three monomorphised copies sit at 0x291e600, 0x44d2370
and 0x5afb950 of node #115.  Each copy has one shape: a header call chosen by
the serializer's flag byte at +0xb (0: array header, else map header, fifteen
members), five literal member names written only when that flag is exactly 1,
an optional ring section (a `VecDeque`-like record at state +0x160..+0x178
turned into a nine word slice descriptor, element size 0x68), fifteen member
writers in a fixed order, a double read from +0x1c0, a u64 at +0x1c8, a u64 at
+0x1d0 and a u32 at +0x1e4, and one error exit family that either wraps the
write error (`0x8000000000000000`, rax, rdx) or copies the callee's three word
result unchanged.  Success stores the marker `0x8000000000000004` in word 0.

This tool authenticates the #115 capture, locates the three bodies by their
unwind (FDE) extents, decodes them with the fixed instruction subset of the
merged bridge event codec interpreter plus imul, cmovae, setne, movsd, test
imm8 and aligned moves, and runs the original machine code with recording
stubs for every callee.  Failures are injected at every call position with
several result shapes.  Each run is compared with an independent pure-Python
reconstruction (`model_run`); deliberately wrong reconstructions, corrupted
bytes and out-of-range inputs must all be caught.

Only the standard library and the repository's shared ELF/unwind parsers and
interpreter are used.  The capture is never executed; no external program runs.
"""
import argparse
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bridge_event_name_codec_115 as B  # noqa: E402
import fde_extents  # noqa: E402

TARGET = B.TARGET
SHA115 = B.SHA115
Reject, Insn, u64, sx, MASK = B.Reject, B.Insn, B.u64, B.sx, B.MASK

COPIES = (0x291e600, 0x44d2370, 0x5afb950)
OK_MARK = 0x8000000000000004
ERR_NICHE = 0x8000000000000000
BEGIN_OK_TAG = 2
KEY_OK = 2
ELEM = 0x68
FRAME = B.STACK_TOP - 0x90
OUT_ADDR = 0x2000_0000
STATE_ADDR = 0x3000_0000
STATE_SIZE = 0x200
SER_ADDR = 0x3100_0000
SER_SIZE = 0x40
CANARY = (0xa1a1a1a1a1a1a1a1, 0xb2b2b2b2b2b2b2b2, 0xc3c3c3c3c3c3c3c3)
KEYS = (b'eth_id_to_deposit_votes', b'finished_deposits_data', b'dvp', b'dvpd', b'dvs')
NAMED_TAIL = (b'bal', b'last_pruned_deposit_block_number', b'oaw')
# member writers in call order: (role, state displacement or None)
FIELD_ORDER = (('eth', 0x18), ('ring', None), ('f60', 0x60), ('f64', None), ('f180', 0x180), ('f1d8', 0x1d8),
               ('f80', 0x80), ('fb8', 0xb8), ('f1a0', 0x1a0), ('ff0', 0xf0), ('f128', 0x128),
               ('bal', 0x1c8), ('pruned', 0x1d0), ('oaw', 0x1e4), ('tail', None))


# ---------------------------------------------------------------- interpreter extension

def extra_decode(image, va):
    raw = image.read(va, 16)
    i = 0
    pre = 0
    if raw[i] in (0xf2, 0x66):
        pre = raw[i]
        i += 1
    rex = 0
    if 0x40 <= raw[i] <= 0x4f:
        rex = raw[i]
        i += 1
    w = bool(rex & 8)
    op = raw[i]
    i += 1
    if op == 0x0f:
        op = 0x0f00 | raw[i]
        i += 1
    if op not in (0x6b, 0x69, 0x0f43, 0x0f95, 0x0f10, 0x0f11, 0x0f42, 0x0f92, 0x0f96, 0x0f97, 0x0f29, 0x0f28, 0xf6):
        return None
    if op in (0x0f10, 0x0f11) and pre != 0xf2:
        return None
    m = raw[i]
    i += 1
    mod, reg, rm = m >> 6, ((m >> 3) & 7) | (((rex >> 2) & 1) << 3), m & 7
    if mod == 3:
        rmo = ('reg', rm | ((rex & 1) << 3))
    else:
        if rm == 5 and mod == 0:
            raise Reject('unsupported addressing in extra form at 0x%x' % va)
        if rm == 4:
            sib = raw[i]
            i += 1
            if (sib >> 3) & 7 != 4 or (sib & 7) == 5:
                raise Reject('unsupported sib in extra form at 0x%x' % va)
            base = (sib & 7) | ((rex & 1) << 3)
        else:
            base = rm | ((rex & 1) << 3)
        disp = 0
        if mod == 1:
            disp = sx(raw[i], 8)
            i += 1
        elif mod == 2:
            disp = sx(struct.unpack_from('<I', raw, i)[0], 32)
            i += 4
        rmo = ('mem', base, None, 1, disp, False)
    kw = dict(va=va, w=w, size=8 if w else 4, reg=reg, rm=rmo)
    if op == 0xf6:
        if reg & 7 != 0:
            raise Reject('unsupported f6 form at 0x%x' % va)
        kw.update(op='test', size=1, imm=raw[i], ext='imm')
        i += 1
        kw['length'] = i
        kw['raw'] = bytes(raw[:i])
        return Insn(**kw)
    if op in (0x0f29, 0x0f28):
        kw.update(op='movups_store' if op == 0x0f29 else 'movups_load', size=16)
        kw['length'] = i
        kw['raw'] = bytes(raw[:i])
        return Insn(**kw)
    if op in (0x6b, 0x69):
        if op == 0x6b:
            v = sx(raw[i], 8)
            i += 1
        else:
            v = sx(struct.unpack_from('<I', raw, i)[0], 32)
            i += 4
        kw.update(op='imul3', imm=v)
    elif op == 0x0f43:
        kw.update(op='cmovae')
    elif op == 0x0f42:
        kw.update(op='cmovb')
    elif op in (0x0f95, 0x0f92, 0x0f96, 0x0f97):
        kw.update(op={0x0f95: 'setne', 0x0f92: 'setb', 0x0f96: 'setbe', 0x0f97: 'seta'}[op], size=1)
    elif op == 0x0f10:
        kw.update(op='movsd_load', size=8)
    else:
        kw.update(op='movsd_store', size=8)
    kw['length'] = i
    kw['raw'] = bytes(raw[:i])
    return Insn(**kw)


_orig_decode = B.decode  # the merged interpreter decoder


def decode(image, va):
    if va in image.cache:
        return image.cache[va]
    ins = extra_decode(image, va)
    if ins is None:
        ins = _orig_decode(image, va)
    else:
        image.cache[va] = ins
    return ins


class Machine(B.Machine):
    """Same interpreter; run() adds imul, cmovae/b, setcc and movsd."""

    def run(self, entry, limit=2000):
        self.regs[4] = B.STACK_TOP - 8
        self.store(self.regs[4], B.RETURN_SENTINEL, 8)
        pc = entry
        for _ in range(limit):
            ins = decode(self.image, pc)
            self.trace.append(pc)
            nxt = pc + ins.length
            op, size = ins.op, ins.size
            m = (1 << (8 * size)) - 1
            if op in ('add', 'sub', 'cmp', 'xor', 'or', 'and', 'test'):
                if ins.ext == 'imm':
                    a, b, dst = self.get(ins.rm, size), ins.imm & m, ins.rm
                elif ins.ext == 'to_reg':
                    a, b, dst = self.regs[ins.reg] & m, self.get(ins.rm, size), ('reg', ins.reg)
                else:
                    a, b, dst = self.get(ins.rm, size), self.regs[ins.reg] & m, ins.rm
                top = 1 << (8 * size - 1)
                if op == 'add':
                    r = a + b
                    self.setflags(r, size, r > m, bool(~(a ^ b) & (a ^ r) & top))
                    self.put(dst, r, size)
                elif op in ('sub', 'cmp'):
                    r = (a - b) & m
                    self.setflags(r, size, a < b, bool((a ^ b) & (a ^ r) & top))
                    if op == 'sub':
                        self.put(dst, r, size)
                elif op == 'test':
                    self.setflags(a & b, size)
                else:
                    r = {'xor': a ^ b, 'or': a | b, 'and': a & b}[op]
                    self.setflags(r, size)
                    self.put(dst, r, size)
            elif op == 'imul3':
                r = (sx(self.get(ins.rm, size), 8 * size) * ins.imm) & m
                self.put(('reg', ins.reg), r, size)
            elif op in ('cmovae', 'cmovb'):
                take = (not self.cf) if op == 'cmovae' else self.cf
                if take:
                    self.put(('reg', ins.reg), self.get(ins.rm, size), size)
                elif size == 4:
                    self.put(('reg', ins.reg), self.regs[ins.reg], 4)
            elif op in ('setne', 'setb', 'setbe', 'seta'):
                v = {'setne': not self.zf, 'setb': self.cf, 'setbe': self.cf or self.zf,
                     'seta': not (self.cf or self.zf)}[op]
                self.put(ins.rm, 1 if v else 0, 1)
            elif op == 'movsd_load':
                self.xmm[ins.reg] = self.get(ins.rm, 8)
            elif op == 'movsd_store':
                self.put(ins.rm, self.xmm[ins.reg] & MASK, 8)
            elif op == 'mov':
                if ins.ext == 'imm':
                    self.put(ins.rm, ins.imm, size)
                elif ins.ext == 'to_reg':
                    self.put(('reg', ins.reg), self.get(ins.rm, size), size)
                else:
                    self.put(ins.rm, self.regs[ins.reg], size)
            elif op == 'movimm':
                self.put(('reg', ins.reg), ins.imm, size)
            elif op == 'lea':
                self.put(('reg', ins.reg), self.ea(ins.rm), size)
            elif op == 'movsxd':
                self.regs[ins.reg] = u64(sx(self.get(ins.rm, 4), 32))
            elif op == 'movzx8':
                self.put(('reg', ins.reg), self.get(ins.rm, 1), max(size, 4))
            elif op == 'movzx16':
                self.put(('reg', ins.reg), self.get(ins.rm, 2), max(size, 4))
            elif op == 'movups_load':
                self.xmm[ins.reg] = self.xget(ins.rm)
            elif op == 'movups_store':
                if ins.rm[0] == 'reg':
                    self.xmm[ins.rm[1]] = self.xmm[ins.reg]
                else:
                    self.store(self.ea(ins.rm), self.xmm[ins.reg], 16)
            elif op in ('inc', 'dec'):
                r = (self.get(ins.rm, size) + (1 if op == 'inc' else -1)) & m
                self.zf = r == 0
                self.sf = bool(r >> (8 * size - 1))
                self.put(ins.rm, r, size)
            elif op in ('je', 'jne', 'jb', 'jae', 'jbe', 'ja', 'jle', 'jg'):
                le = self.zf or (self.sf != self.of)
                take = {'je': self.zf, 'jne': not self.zf, 'jb': self.cf, 'jae': not self.cf,
                        'jbe': self.cf or self.zf, 'ja': not (self.cf or self.zf),
                        'jle': le, 'jg': not le}[op]
                if take:
                    nxt = ins.target
            elif op == 'jmp':
                nxt = ins.target
            elif op == 'push':
                self.regs[4] -= 8
                self.store(self.regs[4], self.regs[ins.reg], 8)
            elif op == 'pop':
                self.regs[ins.reg] = self.load(self.regs[4], 8)
                self.regs[4] += 8
            elif op in ('call', 'callslot'):
                key = ins.target if op == 'call' else ('slot', ins.rm[4])
                if key not in self.stubs:
                    raise Reject('call to unmodelled target %s at 0x%x' % (key, pc))
                args = tuple(self.regs[r] for r in (7, 6, 2, 1, 8))
                self.calls.append((pc, key, args))
                res = self.stubs[key](self, args)
                self.regs[0] = res[0] if isinstance(res, tuple) else res
                for r in (1, 2, 6, 7, 8, 9, 10, 11):
                    self.regs[r] = B.CLOBBER
                if isinstance(res, tuple):
                    self.regs[2] = res[1]
            elif op == 'ret':
                target = self.load(self.regs[4], 8)
                self.regs[4] += 8
                if target == B.RETURN_SENTINEL:
                    if self.regs[4] != B.STACK_TOP:
                        raise Reject('unbalanced stack at return 0x%x' % pc)
                    return
                raise Reject('return to unexpected address at 0x%x' % pc)
            else:
                raise Reject('no semantics for %s' % op)
            pc = nxt
        raise Reject('step limit reached')


B.decode = decode


# ---------------------------------------------------------------- reconstruction

DEFAULT_KNOBS = dict(
    named=lambda flag: flag == 1, arm=lambda flag: flag != 0, elem=ELEM, niche=ERR_NICHE, cap_ge=True,
    swap_at=-1, bal_src=0x1c8, oaw_mask=0xffffffff, wrap=('key', 'f64'), ok=OK_MARK,
    f64_src=0x1c0, key_swap=False, count=0xf, some_nonzero=True, last_len=False, ring_out=0x48,
    success_clear=False, begin_identity=False, no_cmp=False, tail_swap=False, bal_len=3, pruned_len=0x20,
    wrap_first=False, third_delta=0)
KNOBS = dict(DEFAULT_KNOBS)


def ring_words(w160, w168, w170, w178):
    """The nine word slice descriptor the body builds at rsp for the ring member."""
    k = KNOBS
    if w160 == k['niche']:
        some = 1 if (w168 != 0 if k['some_nonzero'] else w168 > 1) else 0
        last = w178 if (w168 != 0 or k['last_len']) else w168
        return [some, 0, w168, w170, some, 0, w168, w170, last]
    if w178 == 0:
        first = second = third = 0
    else:
        cap, head = w170, w160
        ge = cap >= head if k['cap_ge'] else cap > head
        base = head if ge else 0
        if k['no_cmp']:
            base = head
        first = u64(cap - base)
        gap = u64(head - first)
        if w178 > gap:
            second, third = head, u64(w178 - gap + k['third_delta'])
        else:
            second, third = u64(w178 + first), 0
    p, e = w168, k['elem']
    return [2, u64(first * e + p), u64(second * e + p), p, u64(third * e + p), 0,
            u64(second * e + p), p, third]


def model_events(flag, st, var=(False, False)):
    """Ordered (role, arguments) a clean run issues; `st` holds the state words used."""
    k = KNOBS
    ev = []
    cnt = k['count']
    ev.append(('begin1' if k['arm'](flag) else 'begin0', FRAME, 'ser', cnt))
    named = k['named'](flag)
    keys = list(KEYS)
    if k['key_swap']:
        keys[2], keys[3] = keys[3], keys[2]

    def key(i):
        if named:
            ev.append(('key', 'ser', keys[i]))

    fields = list(FIELD_ORDER)
    if k['swap_at'] >= 0:
        i = k['swap_at']
        fields[i], fields[i + 1] = fields[i + 1], fields[i]
    key(0)
    for role, disp in fields[:1]:
        ev.append((role, FRAME, 's+0x%x' % disp, 'ser'))
    key(1)
    ev.append(('ring', FRAME + k['ring_out'], 'ser', tuple(ring_words(st[0x160], st[0x168], st[0x170], st[0x178]))))
    key(2)
    ev.append(('f60', FRAME, 'ser', 's+0x60'))
    key(3)
    if var[1]:
        ev.append(('f64', FRAME, 'ser', st[k['f64_src']]))
    else:
        ev.append(('f64', 'ser', st[k['f64_src']]))
    key(4)
    ev.append(('f180', FRAME, 's+0x180', 'ser'))
    for role, disp in fields[5:11]:
        ev.append((role, FRAME, 'ser', 's+0x%x' % disp))
    ev.append(('bal', FRAME, 'ser', NAMED_TAIL[0], k['bal_len'], st[k['bal_src']]))
    if var[0]:
        ev.append(('pruned', FRAME, 'ser', st[0x1d0]))
    else:
        ev.append(('pruned', FRAME, 'ser', NAMED_TAIL[1], k['pruned_len'], st[0x1d0]))
    ev.append(('oaw', FRAME, 'ser', NAMED_TAIL[2], 3, st[0x1e4] & k['oaw_mask']))
    ev.append(('tail', FRAME, 'ser', 's+0x0') if not k['tail_swap'] else ('tail', FRAME, 's+0x0', 'ser'))
    return ev


def model_run(flag, st, fail_k, shape, var=(False, False)):
    """Return (events, out words) for a run whose call number `fail_k` (or none) fails with `shape`."""
    k = KNOBS
    full = model_events(flag, st, var)
    if fail_k < 0:
        if k['success_clear']:
            return full, (k['ok'], 0, 0)
        return full, (k['ok'], CANARY[1], CANARY[2])
    ev = full[:fail_k + 1]
    role = ev[-1][0]
    if role in ('begin0', 'begin1'):
        tag, a, _ = shape
        if k['begin_identity']:
            return ev, tuple(shape)
        return ev, (ERR_NICHE, tag, a)
    if (role in k['wrap'] and not (role == 'f64' and var[1])) or (k['wrap_first'] and role == 'eth'):
        return ev, (ERR_NICHE, shape[0], shape[1])
    return ev, tuple(shape)


def fail_possible(role, shape, var=(False, False)):
    """A callee result counts as a failure unless it equals the success marker of that role."""
    if role in ('begin0', 'begin1'):
        return shape[0] != BEGIN_OK_TAG
    if role == 'key' or (role == 'f64' and not var[1]):
        return shape[0] != KEY_OK
    return shape[0] != OK_MARK


# ---------------------------------------------------------------- harness

class Run:
    __slots__ = ('n', 'fail_k', 'shape', 'events')

    def __init__(self, fail_k, shape):
        self.n = 0
        self.fail_k = fail_k
        self.shape = shape
        self.events = []


def norm(v):
    if v == SER_ADDR:
        return 'ser'
    if STATE_ADDR <= v < STATE_ADDR + STATE_SIZE:
        return 's+0x%x' % (v - STATE_ADDR)
    return v


def text_at(m, ptr, n):
    return bytes(m.load(ptr + k, 1) for k in range(n))


def make_stubs(roles_by_target, run):
    def begin(role):
        def stub(m, args):
            run.n += 1
            k = run.n - 1
            run.events.append((role, args[0], norm(args[1]), args[2]))
            if k == run.fail_k:
                for i, v in enumerate(run.shape):
                    m.store(args[0] + 8 * i, v, 8)
            else:
                m.store(args[0], BEGIN_OK_TAG, 8)
            return args[0]
        return stub

    def key(m, args):
        run.n += 1
        k = run.n - 1
        run.events.append(('key', norm(args[0]), text_at(m, args[1], args[2])))
        if k == run.fail_k:
            return (run.shape[0], run.shape[1])
        return (KEY_OK, B.CLOBBER)

    def f64(m, args):
        run.n += 1
        k = run.n - 1
        run.events.append(('f64', norm(args[0]), m.xmm[0] & MASK))
        if k == run.fail_k:
            return (run.shape[0], run.shape[1])
        return (KEY_OK, B.CLOBBER)

    def f64buf(role):
        def stub(m, args):
            run.n += 1
            k = run.n - 1
            run.events.append((role, args[0], norm(args[1]), m.xmm[0] & MASK))
            if k == run.fail_k:
                for i, v in enumerate(run.shape):
                    m.store(args[0] + 8 * i, v, 8)
            else:
                m.store(args[0], OK_MARK, 8)
            return args[0]
        return stub

    def field(role, kind):
        def stub(m, args):
            run.n += 1
            k = run.n - 1
            if kind == 'ring':
                words = tuple(m.load(args[2] + 8 * i, 8) for i in range(9))
                ev = (role, args[0], norm(args[1]), words)
            elif kind == 'valued':
                ev = (role, args[0], norm(args[1]), args[2])
            elif kind == 'named':
                ev = (role, args[0], norm(args[1]), text_at(m, args[2], args[3]), args[3], args[4])
            else:
                ev = (role, args[0], norm(args[1]), norm(args[2]))
            run.events.append(ev)
            if k == run.fail_k:
                for i, v in enumerate(run.shape):
                    m.store(args[0] + 8 * i, v, 8)
            else:
                m.store(args[0], OK_MARK, 8)
            return args[0]
        return stub

    stubs = {}
    for target, (role, kind) in roles_by_target.items():
        if kind == 'begin':
            stubs[target] = begin(role)
        elif kind == 'key':
            stubs[target] = key
        elif kind == 'f64':
            stubs[target] = f64
        elif kind == 'f64buf':
            stubs[target] = f64buf(role)
        else:
            stubs[target] = field(role, kind)
    return stubs


def sequence_of(image, rows):
    """Call targets of the linear decode in text order."""
    return [r.target for r in rows if r.op == 'call']


def assign_roles(seq, var=(False, False)):
    """Roles by text position of the 22 direct calls (two header arms, five key writes, f64, 15 members)."""
    if len(seq) != 22:
        raise Reject('expected 22 direct calls, found %d' % len(seq))
    names = ['begin1', 'begin0', 'key', 'eth', 'key', 'ring', 'key', 'f60', 'key', 'f64', 'key', 'f180',
             'f1d8', 'f80', 'fb8', 'f1a0', 'ff0', 'f128', 'bal', 'pruned', 'oaw', 'tail']
    roles = {}
    for target, role in zip(seq, names):
        if role == 'key':
            kind = 'key'
        elif role in ('begin0', 'begin1'):
            kind = 'begin'
        elif role == 'f64':
            kind = 'f64buf' if var[1] else 'f64'
        elif role == 'ring':
            kind = 'ring'
        elif role == 'pruned' and var[0]:
            kind = 'valued'
        elif role in ('bal', 'pruned', 'oaw'):
            kind = 'named'
        else:
            kind = 'plain'
        if target in roles and roles[target] != (role, kind):
            if not (kind == 'key' and roles[target][1] == 'key'):
                raise Reject('callee 0x%x serves two roles' % target)
        roles[target] = (role, kind)
    return roles


def execute(image, entry, roles, flag, st, serbytes, fail_k, shape, limit=2000):
    run = Run(fail_k, shape)
    m = Machine(image, make_stubs(roles, run))
    for i in range(0, STATE_SIZE, 8):
        m.store(STATE_ADDR + i, st['raw'][i // 8], 8)
    for i in range(SER_SIZE):
        m.store(SER_ADDR + i, serbytes[i], 1)
    m.store(SER_ADDR + 0xb, flag, 1)
    for i, v in enumerate(CANARY):
        m.store(OUT_ADDR + 8 * i, v, 8)
    m.regs[7], m.regs[6], m.regs[2] = OUT_ADDR, STATE_ADDR, SER_ADDR
    m.run(entry, limit)
    out = tuple(m.load(OUT_ADDR + 8 * i, 8) for i in range(3))
    return run.events, out, len(m.trace)


def make_state(rng, kind):
    raw = [rng.getrandbits(64) for _ in range(STATE_SIZE // 8)]
    st = {'raw': raw}
    for disp in (0x160, 0x168, 0x170, 0x178, 0x1c0, 0x1c8, 0x1d0, 0x1e4):
        st[disp] = raw[disp // 8] if disp != 0x1e4 else (raw[0x1e0 // 8] >> 32) & 0xffffffff
    return st


def set_ring(st, w160, w168, w170, w178):
    for disp, v in ((0x160, w160), (0x168, w168), (0x170, w170), (0x178, w178)):
        st[disp] = v
        st['raw'][disp // 8] = v


RING_FIXED = (
    ('niche_null', ERR_NICHE, 0, 5, 9), ('niche_ptr', ERR_NICHE, 0x4000_0000, 5, 9),
    ('niche_ptr_len0', ERR_NICHE, 0x4000_0000, 0, 0), ('niche_ptr_one', ERR_NICHE, 1, 5, 9), ('empty', 3, 0x4000_0000, 8, 0),
    ('head0_full', 0, 0x4000_0000, 8, 8), ('head_mid_wrap', 6, 0x4000_0000, 8, 5),
    ('head_mid_nowrap', 2, 0x4000_0000, 8, 5), ('head_eq_cap', 8, 0x4000_0000, 8, 3),
    ('head_gt_cap', 12, 0x4000_0000, 8, 3), ('len_eq_gap', 5, 0x4000_0000, 8, 3),
    ('len_below_gap', 5, 0x4000_0000, 8, 2), ('len_above_gap', 5, 0x4000_0000, 8, 4),
    ('cap0_len1', 0, 0x4000_0000, 0, 1), ('huge_head', MASK, 0x4000_0000, 8, 2),
    ('huge_cap', 1, 0x4000_0000, MASK, 2), ('huge_len', 1, 0x4000_0000, 8, MASK),
    ('ptr_wrap', 2, MASK - 0x100, 8, 4), ('niche_near', ERR_NICHE + 1, 0x4000_0000, 8, 4),
    ('niche_below', ERR_NICHE - 1, 0x4000_0000, 8, 4),
)


def ring_cases(rng, count):
    out = [(name, a, p, h, l) for name, a, p, h, l in RING_FIXED]
    while len(out) < count:
        cap = rng.choice((0, 1, 2, 7, 8, 16, 64, rng.getrandbits(6)))
        head = rng.choice((0, 1, cap, cap + 1, rng.getrandbits(7), max(cap - 1, 0)))
        ln = rng.choice((0, 1, cap, max(cap - head, 0), max(cap - head, 0) + 1, rng.getrandbits(7)))
        ptr = rng.choice((0, rng.getrandbits(32) << 4, rng.getrandbits(64)))
        out.append(('rand%d' % len(out), head, ptr, cap, ln))
    return out


FAIL_SHAPES = (
    (0, 0x1111, 0x2222), (1, 0x3333, 0x4444), (3, 0x5555, 0x6666), (MASK, 0x7777, 0x8888),
    (OK_MARK, 0x9999, 0xaaaa), (ERR_NICHE, 0xbbbb, 0xcccc), (OK_MARK + 1, 0xdddd, 0xeeee),
    (2, 0x1234, 0x5678),
)


# ---------------------------------------------------------------- bodies, cases, controls

SAMPLE_EVERY = 4
SUBSET_EVERY = 13
PATCH_CASES = 160
RING_COUNT = 40
FLAGS = (0, 1, 2, 0xff)


class PatchedImage(B.Image):
    def __init__(self, data, patches):
        super().__init__(data)
        self.patches = dict(patches)

    def read(self, va, n):
        raw = bytearray(super().read(va, n))
        for k in range(n):
            if va + k in self.patches:
                raw[k] = self.patches[va + k]
        return bytes(raw)


INLINE_GUESS = {0x291e600: (False, False), 0x44d2370: (True, True), 0x5afb950: (True, False)}


def inline_map(bodies):
    return {va: bodies[va][3] for va in bodies}


def check_sha(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')


def load_bodies(image, recs_by_start, entries=COPIES):
    bodies = {}
    for va in entries:
        if va not in recs_by_start:
            raise Reject('0x%x is not an FDE start' % va)
        rec = recs_by_start[va]
        rows = B.linear(image, va, rec['end'])
        calls = [r for r in rows if r.op == 'call']
        if len(calls) != 22:
            raise Reject('expected 22 direct calls, found %d' % len(calls))
        between = [r for r in rows if calls[18].va < r.va < calls[19].va]
        inline = not any(r.op == 'lea' and r.rm[5] for r in between)
        after = next(r for r in rows if r.va > calls[9].va)
        var = (inline, after.rm[0] == 'mem')
        bodies[va] = (rec, rows, assign_roles(sequence_of(image, rows), var), var)
    return bodies


def role_list(flag, inline=(False, False)):
    dummy = {k: 0 for k in (0x160, 0x168, 0x170, 0x178, 0x1c0, 0x1c8, 0x1d0, 0x1e4)}
    return [e[0] for e in model_events(flag, dummy, inline)]


def possible_shapes(role, var):
    return [i for i, s in enumerate(FAIL_SHAPES) if fail_possible(role, s, var)]


def case_stream(bodies_inline, every=1, offset=0):
    """Deterministic (index, copy, flag, ring row, fail position, shape index, state, ser bytes)."""
    rng = random.Random(0x115b21d)
    rings = ring_cases(rng, RING_COUNT)
    idx = 0
    for copy in COPIES:
        for flag in FLAGS:
            roles = role_list(flag, bodies_inline[copy])
            for ri, ring in enumerate(rings):
                st = make_state(rng, ring[0])
                set_ring(st, ring[1], ring[2], ring[3], ring[4])
                ser = bytes(rng.getrandbits(8) for _ in range(SER_SIZE))
                for k in range(-1, len(roles)):
                    if k < 0:
                        picks = [None]
                    else:
                        poss = possible_shapes(roles[k], bodies_inline[copy])
                        picks = [poss[(k + ri) % len(poss)], poss[(k * 3 + ri + 1) % len(poss)]]
                        if picks[0] == picks[1]:
                            picks = picks[:1]
                    for sh in picks:
                        if idx % every == offset:
                            yield idx, copy, flag, ring, k, sh, st, ser
                        idx += 1


def engine_case(image, bodies, copy, flag, st, ser, k, sh):
    shape = FAIL_SHAPES[sh] if sh is not None else (0, 0, 0)
    return execute(image, copy, bodies[copy][2], flag, st, ser, k, shape)


def model_case(flag, st, k, sh, inline):
    shape = FAIL_SHAPES[sh] if sh is not None else (0, 0, 0)
    return model_run(flag, st, k if sh is not None else -1, shape, inline)


class Knobs:
    def __init__(self, **kw):
        self.kw = kw

    def __enter__(self):
        KNOBS.update(self.kw)

    def __exit__(self, *a):
        KNOBS.clear()
        KNOBS.update(DEFAULT_KNOBS)


MUTANTS = (
    ('begin_arms_swapped', dict(arm=lambda f: f == 0)),
    ('named_when_nonzero_bit0', dict(named=lambda f: bool(f & 1))),
    ('named_when_nonzero', dict(named=lambda f: f != 0)),
    ('array_arm_by_bit0', dict(arm=lambda f: bool(f & 1))),
    ('element_size_0x60', dict(elem=0x60)),
    ('niche_off_by_one', dict(niche=ERR_NICHE + 1)),
    ('capacity_compare_strict', dict(cap_ge=False)),
    ('third_slice_off_by_one', dict(third_delta=1)),
    ('swap_f1d8_f80', dict(swap_at=5)),
    ('swap_f1a0_ff0', dict(swap_at=8)),
    ('bal_reads_pruned_word', dict(bal_src=0x1d0)),
    ('oaw_reads_16_bits', dict(oaw_mask=0xffff)),
    ('f64_error_not_wrapped', dict(wrap=('key',))),
    ('eth_error_wrapped', dict(wrap_first=True)),
    ('ok_marker_plus_one', dict(ok=OK_MARK + 1)),
    ('f64_reads_bal_word', dict(f64_src=0x1c8)),
    ('names_dvp_dvpd_swapped', dict(key_swap=True)),
    ('member_count_14', dict(count=0xe)),
    ('niche_some_when_gt1', dict(some_nonzero=False)),
    ('niche_last_always_len', dict(last_len=True)),
    ('ring_out_slot_0x40', dict(ring_out=0x40)),
    ('success_clears_out_words', dict(success_clear=True)),
    ('begin_error_copied', dict(begin_identity=True)),
    ('ring_without_capacity_compare', dict(no_cmp=True)),
    ('tail_arguments_swapped', dict(tail_swap=True)),
    ('bal_name_length_4', dict(bal_len=4)),
    ('pruned_name_length_0x1f', dict(pruned_len=0x1f)),
    ('no_error_wrapped', dict(wrap=())),
)


def find_patch_sites(rows, entry):
    """Byte patches (va -> byte) that each corrupt one decoded operand of the root copy."""
    out = {}
    for name, disp in (('load_0x1c8', 0x1c8), ('load_0x1d0', 0x1d0), ('load_0x1e4', 0x1e4), ('load_0x1c0', 0x1c0),
                       ('load_0x178', 0x178), ('load_0x160', 0x160), ('lea_0x60', 0x60), ('lea_0x18', 0x18)):
        r = next(x for x in rows if x.rm and x.rm[0] == 'mem' and x.rm[1] == 14 and not x.rm[5] and x.rm[4] == disp)
        pos = r.length - (4 if disp > 127 else 1)
        out[name] = (r.va + pos, (r.raw[pos] + 1) & 0xff)
    cmp1 = next(x for x in rows if x.op == 'cmp' and x.ext == 'imm' and x.imm == 1 and x.rm[0] == 'mem')
    out['flag_compare_imm'] = (cmp1.va + cmp1.length - 1, 2)
    imul = next(x for x in rows if x.op == 'imul3')
    out['imul_scale'] = (imul.va + imul.length - 1, 0x60)
    return out


def run_controls(data, image, bodies, recs_by_start, subset):
    results = []
    # 1. wrong reconstructions against the cached engine results of the subset
    for name, knobs in MUTANTS:
        bad = 0
        with Knobs(**knobs):
            for params, (ev_e, out_e) in subset:
                flag, st, k, sh, inline = params
                if model_case(flag, st, k, sh, inline) != (ev_e, out_e):
                    bad += 1
        results.append((name, 'wrong_reconstruction', len(subset), bad))
    # 2. corrupted bytes in the root copy, base model
    root_rows = bodies[COPIES[0]][1]
    sites = find_patch_sites(root_rows, COPIES[0])
    stream = list(case_stream(inline_map(bodies), every=max(1, 17000 // PATCH_CASES), offset=3))
    for name in sorted(sites):
        va, val = sites[name]
        pimg = PatchedImage(data, {va: val})
        pbod = dict(bodies)
        bad = ran = 0
        for idx, copy, flag, ring, k, sh, st, ser in stream:
            if copy != COPIES[0]:
                continue
            ran += 1
            try:
                ev_e, out_e, _ = engine_case(pimg, pbod, copy, flag, st, ser, k, sh)
            except Reject:
                bad += 1
                continue
            if model_case(flag, st, k, sh, pbod[copy][3]) != (ev_e, out_e):
                bad += 1
        results.append((name, 'byte_corruption', ran, bad))
    # 3. out-of-range inputs
    results.append(('wrong_digest', 'out_of_range', 1, _raises(lambda: check_sha(bytes([data[0] ^ 1]) + data[1:]))))
    results.append(('entry_not_an_fde_start', 'out_of_range',
                    1, _raises(lambda: load_bodies(image, recs_by_start, (COPIES[0] + 1,)))))
    short = dict(recs_by_start)
    short[COPIES[0]] = dict(recs_by_start[COPIES[0]], end=COPIES[0] + 0x200)
    results.append(('fde_end_inside_body', 'out_of_range', 1, _raises(lambda: load_bodies(image, short, (COPIES[0],)))))
    results.append(('callee_without_stub', 'out_of_range', 1, _raises(lambda: _missing_stub(image, bodies))))
    results.append(('step_limit_tiny', 'out_of_range', 1, _raises(lambda: _tiny_limit(image, bodies))))
    results.append(('state_bytes_unset', 'out_of_range', 1, _raises(lambda: _unset_state(image, bodies))))
    return results


def _raises(fn):
    try:
        fn()
    except Reject:
        return 1
    return 0


def _case_inputs():
    for idx, copy, flag, ring, k, sh, st, ser in case_stream(INLINE_GUESS, every=997):
        return copy, flag, st, ser, k, sh


def _missing_stub(image, bodies):
    copy, flag, st, ser, k, sh = _case_inputs()
    roles = dict(bodies[COPIES[0]][2])
    roles.pop(next(iter(roles)))
    execute(image, COPIES[0], roles, 1, st, ser, -1, (0, 0, 0))


def _tiny_limit(image, bodies):
    copy, flag, st, ser, k, sh = _case_inputs()
    execute(image, COPIES[0], bodies[COPIES[0]][2], 1, st, ser, -1, (0, 0, 0), limit=40)


def _unset_state(image, bodies):
    copy, flag, st, ser, k, sh = _case_inputs()
    run = Run(-1, (0, 0, 0))
    m = Machine(image, make_stubs(bodies[COPIES[0]][2], run))
    m.regs[7], m.regs[6], m.regs[2] = OUT_ADDR, STATE_ADDR, SER_ADDR
    m.run(COPIES[0])


# ---------------------------------------------------------------- build

def hexs(vals):
    return ','.join('%x' % v for v in vals)


def build(data):
    check_sha(data)
    image = B.Image(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = {r['start']: r for r in recs}
    bodies = load_bodies(image, by_start)

    functions, instructions, role_rows, state_rows, literal_rows = [], [], [], [], []
    for va in COPIES:
        rec, rows, roles, _ = bodies[va]
        body = image.read(va, rec['end'] - va)
        functions.append(('0x%x' % va, '0x%x' % rec['end'], rec['end'] - va, len(rows),
                          hashlib.sha256(body).hexdigest(), sum(1 for r in rows if r.op == 'call')))
        for r in rows:
            instructions.append(('0x%x' % va, '0x%x' % r.va, r.length, r.raw.hex(), r.op,
                                 '' if r.target is None else '0x%x' % r.target))
            if r.rm and r.rm[0] == 'mem' and r.rm[1] in (14, 3) and not r.rm[5]:
                state_rows.append(('0x%x' % va, '0x%x' % r.va, 'state' if r.rm[1] == 14 else 'out',
                                   '0x%x' % (r.rm[4] & 0xfff), r.op, r.size))
        for target, (role, kind) in sorted(roles.items()):
            role_rows.append(('0x%x' % va, '0x%x' % target, role, kind))

    # literal key names as they reach the writer, read from the file bytes
    for va in COPIES:
        run = Run(-1, (0, 0, 0))
        m = Machine(image, make_stubs(bodies[va][2], run))
        rng = random.Random(7)
        st = make_state(rng, 'lit')
        set_ring(st, 1, 0x4000_0000, 8, 3)
        ptrs = []
        orig = m.stubs

        for target, fn in list(orig.items()):
            kind = bodies[va][2][target][1]
            if kind in ('key', 'named'):
                def wrap(fn=fn, kind=kind):
                    def stub(mm, args):
                        ptrs.append((args[1] if kind == 'key' else args[2], args[2] if kind == 'key' else args[3]))
                        return fn(mm, args)
                    return stub
                orig[target] = wrap()
        for i in range(0, STATE_SIZE, 8):
            m.store(STATE_ADDR + i, st['raw'][i // 8], 8)
        for i in range(SER_SIZE):
            m.store(SER_ADDR + i, 0x11, 1)
        m.store(SER_ADDR + 0xb, 1, 1)
        for i, v in enumerate(CANARY):
            m.store(OUT_ADDR + 8 * i, v, 8)
        m.regs[7], m.regs[6], m.regs[2] = OUT_ADDR, STATE_ADDR, SER_ADDR
        m.run(va)
        for i, (p, n) in enumerate(ptrs):
            section = image.section_of(p)['name']
            literal_rows.append(('0x%x' % va, i, '0x%x' % p, n, section, image.read(p, n).decode('ascii')))

    # main comparison
    total = ok = 0
    steps_total = 0
    per_copy = {va: [0, 0] for va in COPIES}
    path_counts = {}
    role_fail = {}
    sampled = []
    subset = []
    ring_classes = {}
    inl = inline_map(bodies)
    for idx, copy, flag, ring, k, sh, st, ser in case_stream(inl):
        ev_e, out_e, steps = engine_case(image, bodies, copy, flag, st, ser, k, sh)
        ev_m, out_m = model_case(flag, st, k, sh, inl[copy])
        match = (ev_e, out_e) == (ev_m, out_m)
        total += 1
        ok += match
        steps_total += steps
        per_copy[copy][0] += 1
        per_copy[copy][1] += match
        stop = ev_e[-1][0] if ev_e else '-'
        pkey = (copy, flag if flag in (0, 1) else 2, stop, 'fail' if sh is not None else 'ok')
        path_counts[pkey] = path_counts.get(pkey, 0) + 1
        if sh is not None:
            role_fail[stop] = role_fail.get(stop, 0) + 1
        cls = ring[0] if not ring[0].startswith('rand') else 'random'
        ring_classes[cls] = ring_classes.get(cls, 0) + 1
        if idx % SAMPLE_EVERY == 0:
            sampled.append((idx, '0x%x' % copy, flag, ring[0], k, '-' if sh is None else sh, steps,
                            len(ev_e), stop, hexs(out_e), 'match' if match else 'MISMATCH'))
        if idx % SUBSET_EVERY == 1:
            subset.append(((flag, st, k, sh, inl[copy]), (ev_e, out_e)))
    controls = run_controls(data, image, bodies, by_start, subset)
    detected = sum(1 for c in controls if c[3] > 0)

    ring_rows = []
    for name, a, p, h, l in RING_FIXED:
        w = ring_words(a, p, h, l)
        ring_rows.append((name, hexs((a, p, h, l)), hexs(w)))

    summary = dict(
        target='node115', sha256=SHA115, component='bridge', task='none',
        copies=['0x%x' % v for v in COPIES], cases=total, matches=ok, steps_total=steps_total,
        per_copy={'0x%x' % va: {'cases': per_copy[va][0], 'matches': per_copy[va][1]} for va in COPIES},
        member_count=0xf, flag_offset=0xb, ok_marker='0x%x' % OK_MARK, error_niche='0x%x' % ERR_NICHE,
        ring_element_size=ELEM, key_names=[k.decode() for k in KEYS],
        tail_names=[k.decode() for k in NAMED_TAIL], failures_by_role=dict(sorted(role_fail.items())),
        negative_controls=len(controls), negative_detected=detected,
        reconstruction_matches_all=(ok == total), all_negative_controls_caught=(detected == len(controls)))
    measure = dict(cases=total, negative_controls=len(controls), negative_detected=detected)
    return dict(functions=functions, instructions=instructions, roles=role_rows, state=state_rows,
                literals=literal_rows, ring=ring_rows, sampled=sampled, controls=controls,
                paths=[(('0x%x' % k[0],) + k[1:] + (n,)) for k, n in sorted(path_counts.items())],
                ring_classes=sorted(ring_classes.items()), summary=summary, measure=measure)


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def render(result):
    return {
        'functions.tsv': tsv(('entry', 'fde_end', 'bytes', 'instructions', 'sha256', 'direct_calls'), result['functions']),
        'instructions.tsv': tsv(('function', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'callee-roles.tsv': tsv(('function', 'callee', 'role', 'kind'), result['roles']),
        'state-accesses.tsv': tsv(('function', 'va', 'base', 'displacement', 'op', 'size'), result['state']),
        'key-literals.tsv': tsv(('function', 'ordinal', 'va', 'length', 'section', 'text'), result['literals']),
        'ring-descriptors.tsv': tsv(('case', 'w160,w168,w170,w178', 'descriptor_words'), result['ring']),
        'ring-classes.tsv': tsv(('ring_class', 'cases'), result['ring_classes']),
        'paths.tsv': tsv(('function', 'flag_class', 'last_call', 'outcome', 'cases'), result['paths']),
        'cases-sample.tsv': tsv(('index', 'function', 'flag', 'ring', 'fail_position', 'shape', 'steps', 'calls',
                                 'last_call', 'out_words', 'verdict'), result['sampled']),
        'negative-controls.tsv': tsv(('control', 'kind', 'cases', 'mismatching'), result['controls']),
        'summary.json': json.dumps(result['summary'], indent=2, sort_keys=True) + '\n',
        'measure.json': json.dumps(result['measure'], indent=2, sort_keys=True) + '\n',
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', required=True)
    ap.add_argument('--binary', default=str(TARGET))
    args = ap.parse_args(argv)
    data = Path(args.binary).read_bytes()
    try:
        result = build(data)
    except Reject as exc:
        print('rejected: %s' % exc, file=sys.stderr)
        return 1
    s = result['summary']
    if not s['reconstruction_matches_all'] or not s['all_negative_controls_caught']:
        print('reconstruction or negative controls failed', file=sys.stderr)
        print(json.dumps(s, indent=1, sort_keys=True), file=sys.stderr)
        for c in result['controls']:
            if c[3] == 0:
                print('not caught:', c, file=sys.stderr)
        return 1
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)
    for name, text in render(result).items():
        (out / name).write_text(text, encoding='ascii', newline='\n')
    print('cases %d/%d, controls caught %d/%d' % (s['matches'], s['cases'], s['negative_detected'],
                                                s['negative_controls']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
