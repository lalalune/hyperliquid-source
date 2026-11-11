#!/usr/bin/env python3
"""Reconstruct the node #115 JSON-reader margin-mode identifier readers and prove them.

The margin-mode enum (normal, noCross, strictIsolated) is read from JSON text
by four serde_json-shaped bodies.  Two read the enum as a *value*
(`variant_seed` on a string: skip whitespace, expect a quote, parse the string,
classify it by an exact byte compare, report unknown names) and two read it as
an object *key* (the same, then skip whitespace again and require a colon).

The producer authenticates the #115 capture, locates the four bodies by their
unwind (FDE) extents and runs each body's original machine code in the
interpreter of the merged margin-mode packet (tools/re007_margin_mode_codec_115.py),
extended here with `neg` and `bt`.  Every callee is a recording stub; the
interpreted outcome (result tag and word, reader position, scratch word and the
ordered call list with its arguments) is compared with an independent
pure-Python reconstruction.  Mutated reconstructions and damaged code bytes
must be caught.

Only the standard library, the repository's shared ELF/unwind parsers and the
merged margin-mode tool are used.  The capture is never executed.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import fde_extents  # noqa: E402
import re007_margin_mode_codec_115 as base  # noqa: E402

Reject = base.Reject
SHA115 = base.SHA115
NAMES = base.NAMES
MASK = base.MASK
IN_BASE, OUT_BASE, DATA_BASE, OWNED_BASE = base.IN_BASE, base.OUT_BASE, base.DATA_BASE, base.OWNED_BASE
STACK_TOP, RETURN_SENTINEL, CLOBBER = base.STACK_TOP, base.RETURN_SENTINEL, base.CLOBBER

# (entry, kind, variant pool): `value` readers end at the closing quote,
# `key` readers also consume the colon.
BODIES = (
    (0x1e201f0, 'value', 0x643e188),
    (0x3fba8b0, 'value', 0x6475de0),
    (0x1def7c0, 'key', 0x643e188),
    (0x3f7fe90, 'key', None),
)
WS_MASK = 0x100002600
EXPECTED_POOL = None  # resolved from the bytes of the value readers

SENT = 0x7777_7777_7777_7777
ERR_CODE, ERR_UNK, ERR_INV, ERR_STR, FIN = (0xe000 << 48, 0xe100 << 48, 0xe200 << 48, 0xe300 << 48, 0x00f0 << 48)
STR_ERR = {'eof': 1, 'ctrl': 2, 'esc': 3, 'unicode': 4}
SIMPLE_ESC = {0x22: 0x22, 0x5c: 0x5c, 0x2f: 0x2f, 0x62: 8, 0x66: 12, 0x6e: 10, 0x72: 13, 0x74: 9}
HEX = b'0123456789abcdefABCDEF'


# ---------------------------------------------------------------- interpreter extension

class PatchedImage(base.Image):
    """Image whose bytes can be damaged in memory (negative controls)."""

    def __init__(self, data, patches=None):
        super().__init__(data)
        self.patches = dict(patches or {})
        self.icache = {}

    def read(self, va, n):
        out = bytearray(super().read(va, n))
        for k in range(n):
            if va + k in self.patches:
                out[k] = self.patches[va + k]
        return bytes(out)


def decode(image, va):
    """merged decoder plus neg r (f7 /3) and bt r64, r64 (0f a3), register forms only"""
    hit = image.icache.get(va)
    if hit is not None:
        return hit
    raw = image.read(va, 3)
    rex = raw[0] if 0x40 <= raw[0] <= 0x4f else 0
    i = 1 if rex else 0
    ins = None
    if raw[i] == 0xf7 and (raw[i + 1] >> 6) == 3 and ((raw[i + 1] >> 3) & 7) == 3:
        ins = base.Insn(va=va, length=i + 2, raw=raw[:i + 2], op='neg', size=8 if rex & 8 else 4,
                        rm=('reg', (raw[i + 1] & 7) | ((rex & 1) << 3)))
    elif raw[i] == 0x0f and raw[i + 1] == 0xa3:
        modrm = image.read(va + i + 2, 1)[0]
        if modrm >> 6 != 3 or not rex & 8:
            raise Reject('bt form not modelled at 0x%x' % va)
        ins = base.Insn(va=va, length=i + 3, raw=image.read(va, i + 3), op='bt', size=8,
                        reg=((modrm >> 3) & 7) | ((rex & 4) << 1), rm=('reg', (modrm & 7) | ((rex & 1) << 3)))
    if ins is None:
        ins = base.decode(image, va)
    image.icache[va] = ins
    return ins


class Machine(base.Machine):
    """Merged interpreter loop plus neg and bt.  Flags kept: ZF, CF, SF, OF."""

    def __init__(self, image, stubs):
        super().__init__(image, stubs)
        self.events = []

    def run(self, entry, limit=400):
        regs = self.regs
        regs[4] = STACK_TOP - 8
        self.store(regs[4], RETURN_SENTINEL, 8)
        pc = entry
        for _ in range(limit):
            ins = decode(self.image, pc)
            self.trace.append(pc)
            nxt = pc + ins.length
            op, size = ins.op, ins.size
            m = (1 << (8 * size)) - 1 if size else 0
            if op in ('add', 'sub', 'cmp', 'xor', 'or', 'and', 'test'):
                if ins.ext == 'imm':
                    a, b, dst = self.get(ins.rm, size), ins.imm & m, ins.rm
                elif ins.ext == 'to_reg':
                    a, b, dst = regs[ins.reg] & m, self.get(ins.rm, size), ('reg', ins.reg)
                else:
                    a, b, dst = self.get(ins.rm, size), regs[ins.reg] & m, ins.rm
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
            elif op == 'neg':
                a = self.get(ins.rm, size)
                r = (-a) & m
                self.setflags(r, size, a != 0, a == 1 << (8 * size - 1))
                self.put(ins.rm, r, size)
            elif op == 'bt':
                self.cf = bool((self.get(ins.rm, size) >> (regs[ins.reg] % (8 * size))) & 1)
            elif op == 'mov':
                if ins.ext == 'imm':
                    self.put(ins.rm, ins.imm, size)
                elif ins.ext == 'to_reg':
                    self.put(('reg', ins.reg), self.get(ins.rm, size), size)
                else:
                    self.put(ins.rm, regs[ins.reg], size)
            elif op == 'movimm':
                self.put(('reg', ins.reg), ins.imm, size)
            elif op == 'lea':
                self.put(('reg', ins.reg), self.ea(ins.rm), size)
            elif op == 'movzx8':
                self.put(('reg', ins.reg), self.get(ins.rm, 1), max(size, 4))
            elif op == 'movzx16':
                self.put(('reg', ins.reg), self.get(ins.rm, 2), max(size, 4))
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
                regs[4] -= 8
                self.store(regs[4], regs[ins.reg], 8)
            elif op == 'pop':
                regs[ins.reg] = self.load(regs[4], 8)
                regs[4] += 8
            elif op in ('call', 'callslot'):
                key = ins.target if op == 'call' else ('slot', ins.rm[4])
                if key not in self.stubs:
                    raise Reject('call to unmodelled target %s at 0x%x' % (key, pc))
                args = tuple(regs[r] for r in (7, 6, 2, 1, 8))
                self.calls.append((pc, key, args))
                regs[0] = self.stubs[key](self, args)
                for r in (1, 2, 6, 7, 8, 9, 10, 11):
                    regs[r] = CLOBBER
            elif op == 'ret':
                target = self.load(regs[4], 8)
                regs[4] += 8
                if target == RETURN_SENTINEL:
                    if regs[4] != STACK_TOP:
                        raise Reject('unbalanced stack at return 0x%x' % pc)
                    return
                raise Reject('return to unexpected address at 0x%x' % pc)
            else:
                raise Reject('no semantics for %s at 0x%x' % (op, pc))
            pc = nxt
        raise Reject('step limit reached')


def linear(image, entry, end):
    rows, pc = [], entry
    while pc < end:
        if image.read(pc, 1) == b'\xcc':
            if any(b != 0xcc for b in image.read(pc, end - pc)):
                raise Reject('non-int3 bytes after the body of 0x%x' % entry)
            break
        ins = decode(image, pc)
        rows.append(ins)
        pc += ins.length
    if pc > end:
        raise Reject('decode overran the FDE of 0x%x' % entry)
    return rows


# ---------------------------------------------------------------- specification of the callee stubs

def json_str(buf, pos):
    """Model of the string-parse callee: ('ok', text, new position, owned) or ('err', name, position)."""
    out, i, n, owned = bytearray(), pos, len(buf), False
    while True:
        if i >= n:
            return ('err', 'eof', n)
        c = buf[i]
        if c == 0x22:
            return ('ok', bytes(out), i + 1, owned)
        if c < 0x20:
            return ('err', 'ctrl', i)
        if c != 0x5c:
            out.append(c)
            i += 1
            continue
        owned = True
        if i + 1 >= n:
            return ('err', 'eof', n)
        e = buf[i + 1]
        if e in SIMPLE_ESC:
            out.append(SIMPLE_ESC[e])
            i += 2
        elif e == 0x75:
            digits = buf[i + 2:i + 6]
            if len(digits) < 4 or any(d not in HEX for d in digits):
                return ('err', 'esc', i + 1)
            cp = int(digits, 16)
            if cp >= 0x80:
                return ('err', 'unicode', i + 1)
            out.append(cp)
            i += 6
        else:
            return ('err', 'esc', i + 1)


def stub_code(machine, args):
    code = machine.load(args[1], 8)
    machine.events.append(('code', code))
    return ERR_CODE | code


def stub_invalid(machine, args):
    machine.events.append(('invalid', args[2]))
    return ERR_INV


def stub_unknown(machine, args):
    text = bytes(machine.load(args[0] + k, 1) for k in range(args[1]))
    machine.events.append(('unknown', text, args[2], args[3]))
    return ERR_UNK | args[1]


def stub_finish(machine, args):
    machine.events.append(('finish', args[0], machine.load(args[1] + 0x28, 8)))
    return args[0] | FIN


def stub_parse(machine, args):
    out, reader = args[0], args[2]
    if args[1] != reader + 0x18:
        raise Reject('parse callee gets a different reader view')
    buf_ptr, n, pos = (machine.load(reader + 0x18, 8), machine.load(reader + 0x20, 8), machine.load(reader + 0x28, 8))
    buf = bytes(machine.load(buf_ptr + k, 1) for k in range(n))
    machine.events.append(('parse', machine.load(reader + 0x10, 8)))
    res = json_str(buf, pos)
    if res[0] == 'err':
        machine.store(out, 2, 4)
        machine.store(out + 8, ERR_STR | STR_ERR[res[1]], 8)
        machine.store(reader + 0x28, res[2], 8)
        return out
    _, text, newpos, owned = res
    if owned:
        for k, b in enumerate(text):
            machine.store(OWNED_BASE + k, b, 1)
        ptr = OWNED_BASE
    else:
        ptr = buf_ptr + pos
    machine.store(out, 1 if owned else 0, 4)
    machine.store(out + 8, ptr, 8)
    machine.store(out + 16, len(text), 8)
    machine.store(reader + 0x28, newpos, 8)
    return out


# ---------------------------------------------------------------- reconstruction

class Spec:
    """Reconstruction parameters; the negative controls change one at a time."""
    ws = frozenset((9, 10, 13, 32))
    classify = 'exact'
    eof_value = 5
    eof_key = 3
    brace_code = 0xa
    other_code = 0x11
    colon_code = 6
    colon = 0x3a
    finish_unknown = True
    finish_parse_error_value = False
    finish_parse_error_key = True
    clear_scratch = True
    consume_ws = True
    skip_after_name = True
    expected = 0
    ws_everything_below = None

    def __init__(self, **kw):
        for k, v in kw.items():
            if not hasattr(Spec, k):
                raise Reject('unknown spec field %s' % k)
            setattr(self, k, v)


def classify_name(text, mode):
    if mode == 'exact':
        return NAMES.index(text) if text in NAMES else None
    if mode == 'prefix':
        return next((k for k, n in enumerate(NAMES) if text[:len(n)] == n), None)
    if mode == 'casefold':
        low = [n.lower() for n in NAMES]
        return low.index(text.lower()) if text.lower() in low else None
    if mode == 'swap':
        k = classify_name(text, 'exact')
        return {0: 1, 1: 0}.get(k, k)
    if mode == 'length':
        return next((k for k, n in enumerate(NAMES) if len(text) == len(n)), None)
    if mode == 'first4':
        return next((k for k, n in enumerate(NAMES) if len(text) == len(n) and text[:4] == n[:4]), None)
    if mode == 'no_strict':
        return NAMES.index(text) if text in NAMES[:2] else None
    raise Reject('classify mode')


def recon(kind, buf, pos, pool, sp):
    """Outcome of one reader call: (tag, word, reader position, scratch word, events)."""
    n, ev, rpos, scratch = len(buf), [], pos, SENT
    is_ws = (lambda c: c in sp.ws) if sp.ws_everything_below is None else (lambda c: c <= sp.ws_everything_below)

    def code(c):
        ev.append(('code', c))
        return 3, ERR_CODE | c, rpos, scratch, ev

    def finish(err):
        ev.append(('finish', err, rpos))
        return 3, err | FIN, rpos, scratch, ev

    eof = sp.eof_value if kind == 'value' else sp.eof_key
    i = pos
    if i >= n:
        return code(eof)
    while True:
        c = buf[i]
        if c <= 0x22 and is_ws(c):
            i += 1
            rpos = i if sp.consume_ws else rpos
            if i >= n:
                return code(eof)
            continue
        break
    if c != 0x22:
        if kind == 'value':
            ev.append(('invalid', sp.expected))
            return finish(ERR_INV)
        return code(sp.brace_code if c == 0x7d else sp.other_code)
    rpos = i + 1
    if sp.clear_scratch:
        scratch = 0
    ev.append(('parse', scratch))
    res = json_str(buf, i + 1)
    if res[0] == 'err':
        rpos = res[2]
        err = ERR_STR | STR_ERR[res[1]]
        if (kind == 'value' and sp.finish_parse_error_value) or (kind == 'key' and sp.finish_parse_error_key):
            return finish(err)
        return 3, err, rpos, scratch, ev
    _, text, rpos, _ = res
    idx = classify_name(text, sp.classify)
    if idx is None:
        ev.append(('unknown', text, pool, 3))
        err = ERR_UNK | len(text)
        if sp.finish_unknown:
            return finish(err)
        return 3, err, rpos, scratch, ev
    if kind == 'value':
        return idx, DATA_BASE, rpos, scratch, ev
    j = rpos
    if sp.skip_after_name:
        if j >= n:
            return code(sp.eof_key)
        while True:
            c = buf[j]
            if c <= sp.colon and is_ws(c):
                j += 1
                rpos = j
                if j >= n:
                    return code(sp.eof_key)
                continue
            break
    else:
        if j >= n:
            return code(sp.eof_key)
        c = buf[j]
    if c != sp.colon:
        return code(sp.colon_code)
    rpos = j + 1
    return idx, DATA_BASE, rpos, scratch, ev


# ---------------------------------------------------------------- driving the machine code

def run_case(image, entry, stubs, kind, buf, pos):
    mc = Machine(image, stubs)
    for k in range(32):
        mc.store(OUT_BASE + k, 0xa5, 1)
    for k, b in enumerate(buf):
        mc.store(IN_BASE + k, b, 1)
    for off, val in ((0x10, SENT), (0x18, IN_BASE), (0x20, len(buf)), (0x28, pos)):
        mc.store(DATA_BASE + off, val, 8)
    mc.regs[7], mc.regs[6] = OUT_BASE, DATA_BASE
    mc.run(entry)
    if mc.regs[0] != OUT_BASE:
        raise Reject('0x%x does not return its output pointer' % entry)
    events = []
    for ev in mc.events:
        events.append(ev)
    return (mc.load(OUT_BASE, 1), mc.load(OUT_BASE + 8, 8), mc.load(DATA_BASE + 0x28, 8),
            mc.load(DATA_BASE + 0x10, 8), events), len(mc.trace)


def case_inputs(kind):
    """(buffer, start position) pairs: byte sweeps, whitespace runs, name mutations, positions, escapes."""
    seen, out = set(), []

    def add(buf, pos=0):
        if (buf, pos) not in seen:
            seen.add((buf, pos))
            out.append((buf, pos))
    tails = (b':', b' :', b'\t\n\r :', b'', b' ', b':x', b'x', b'\x0b:', b';', b'}', b'\r\n\t :  ', b': ', b'::')
    for b in range(256):
        add(bytes([b]) + b'normal"' + (b':' if kind == 'key' else b''))
    syms = (9, 10, 13, 32, 0x0b, 0x0c, 0x00, 0x2c)
    prefixes = [b'']
    for width in range(3):
        prefixes += [p + bytes([s]) for p in [q for q in prefixes if len(q) == width] for s in syms]
    suffix = b':' if kind == 'key' else b''
    for p in prefixes:
        for tail in (b'"noCross"' + suffix, b'"strictIsolated"' + suffix, b''):
            add(p + tail)
    for text in base.visitor_inputs():
        if b'"' in text or b'\\' in text:
            continue
        add(b'"' + text + b'"' + suffix)
        add(b'"' + text)
        if kind == 'key':
            add(b'  "' + text + b'"\t:')
    for name in NAMES + (b'xyz',):
        for tail in tails:
            add(b'"' + name + b'"' + tail)
            add(b' \n"' + name + b'"' + tail)
    for name in NAMES:
        full = b' "' + name + b'" \t:'
        for pos in range(len(full) + 3):
            add(full, pos)
    for lit in (b'"\\u006eormal"', b'"no\\/Cross"', b'"normal\\"', b'"\\u00zz"', b'"\\n"', b'"\\x"', b'"\\u0100"',
                b'"a\x01b"', b'"strict\\u0049solated"', b'"\\u004eormal"', b'"\\\\"', b'"\\', b'"\\u00', b'"no\\tCross"',
                b'"\\u006eo\\u0043ross"', b'"noCro\\u0073s"'):
        add(lit + suffix)
        add(b' ' + lit + b' ' + suffix)
    for tail in (b'}', b'  }', b'{', b'[', b'1', b'null', b'-', b'\\', b"'", b'\x7f', b'\xff', b'\x80'):
        add(tail)
    return out


LITERAL_WORDS = (b'norm', b'noCr', b'stri', b'ross', b'Isol')


def family_scan(image, recs):
    """Every FDE body of at most 4000 bytes with a (xor|cmp) r32, [rip+disp32] whose target spells at least
    three of the margin-mode name words.  Raw byte pattern, no disassembler: the opcode byte, a mod=00 rm=101
    ModRM byte and the displacement."""
    rows, scanned = [], 0
    for r in recs:
        size = r['end'] - r['start']
        if size > 4000:
            continue
        scanned += 1
        body = image.read(r['start'], size)
        got = set()
        for o in range(len(body) - 6):
            if body[o] in (0x33, 0x31, 0x3b) and body[o + 1] & 0xc7 == 0x05:
                tgt = r['start'] + o + 6 + struct.unpack_from('<i', body, o + 2)[0]
                try:
                    word = image.read(tgt, 4)
                except Reject:
                    continue
                if word in LITERAL_WORDS:
                    got.add(word)
        if len(got) >= 3:
            rows.append((r['start'], size, ','.join(w.decode() for w in sorted(got))))
    return rows, scanned


# ---------------------------------------------------------------- evidence assembly

def esc(b):
    return b.hex() if b else '-'


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def bind_stubs(rows, kind, va):
    slots = []
    for r in rows:
        if r.op == 'callslot' and r.rm[4] not in slots:
            slots.append(r.rm[4])
    if rows[-1].op != 'callslot' or len(slots) != 2:
        raise Reject('body 0x%x does not end in a panic slot call' % va)
    panic = rows[-1].rm[4]
    parse = [s for s in slots if s != panic][0]
    directs = []
    for r in rows:
        if r.op == 'call' and r.target not in directs:
            directs.append(r.target)
    want = ['code', 'unknown', 'finish'] + (['invalid'] if kind == 'value' else [])
    if len(directs) != len(want):
        raise Reject('body 0x%x has %d direct callees' % (va, len(directs)))
    fn = dict(code=stub_code, unknown=stub_unknown, finish=stub_finish, invalid=stub_invalid)
    stubs = {('slot', parse): stub_parse}
    roles = [('slot:0x%x' % parse, 'parse_str'), ('slot:0x%x' % panic, 'unwrap_panic (unreachable: pos+1 is never 0)')]
    for role, t in zip(want, directs):
        stubs[t] = fn[role]
        roles.append(('0x%x' % t, role))
    return stubs, roles


def literal_rows(image, va, rows, kind):
    """constants of one body, read from instruction bytes and operand memory"""
    out = []
    for r in rows:
        if r.op == 'movimm' and r.size == 8:
            out.append((va, r.va, 'whitespace_mask_imm64', '0x%x' % r.imm,
                        ','.join('%d' % b for b in range(64) if r.imm >> b & 1)))
        elif r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'reg':
            out.append((va, r.va, 'cmp_imm', '%d' % r.imm, '0x%x' % r.imm))
        elif r.op == 'xor' and r.rm[0] == 'reg' and r.ext == 'to_reg' and len(r.raw) >= 6 and r.rm[5]:
            lit = image.read(r.rm[4], r.size)
            out.append((va, r.va, 'name_xor_rip', '0x%x' % r.rm[4], lit.decode('ascii')))
        elif r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size == 8:
            out.append((va, r.va, 'code_store', '%d' % r.imm, '0x%x' % r.imm))
        elif r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size == 1:
            out.append((va, r.va, 'result_tag_store', '%d' % r.imm, '0x%x' % r.imm))
        elif r.op == 'lea' and r.rm[5]:
            out.append((va, r.va, 'lea_rip', '0x%x' % r.rm[4], ''))
    return out


def damage_sites(rows):
    """(label, address, replacement byte) for single-byte code damage in one body"""
    sites = []
    cmp22 = [r for r in rows if r.op == 'cmp' and r.ext == 'imm' and r.imm == 0x22]
    first_cmp22, quote_cmp = cmp22[0], cmp22[-1]
    mask = next(r for r in rows if r.op == 'movimm' and r.size == 8)
    sites.append(('mask_drops_tab', mask.va + 2 + 1, (mask.imm >> 8 & 0xff) ^ 0x02))
    sites.append(('mask_drops_space', mask.va + 2 + 4, 0x00))
    sites.append(('bound_guard_cmp_0x22', first_cmp22.va + first_cmp22.length - 1, 0x23))
    sites.append(('quote_compare', quote_cmp.va + quote_cmp.length - 1, 0x23))
    for ln in (6, 7, 0xe):
        r = next(r for r in rows if r.op == 'cmp' and r.ext == 'imm' and r.imm == ln and r.rm[0] == 'reg')
        sites.append(('length_%d' % ln, r.va + r.length - 1, ln + 1))
    return sites


def build(data, step=4):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')
    image = PatchedImage(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = {r['start']: r for r in recs}
    functions, insn_rows, lit_rows, callee_rows, pool_rows = [], [], [], [], []
    plan = []
    expecteds = {}
    for va, kind, pool in BODIES:
        if va not in by_start:
            raise Reject('0x%x is not an FDE start' % va)
        rec = by_start[va]
        rows = linear(image, va, rec['end'])
        leas = [r for r in rows if r.op == 'lea' and r.rm[5]]
        pools = [r.rm[4] for r in leas]
        if kind == 'value':
            if len(pools) != 3:
                raise Reject('value reader 0x%x does not reference three rip addresses' % va)
            exp_pool, var_pool = pools[1], pools[0]
            if pool is not None and var_pool != pool:
                raise Reject('variant pool of 0x%x differs' % va)
            expecteds[va] = exp_pool
            pool = var_pool
        else:
            if len(pools) != 2:
                raise Reject('key reader 0x%x does not reference two rip addresses' % va)
            if pool is not None and pools[0] != pool:
                raise Reject('variant pool of 0x%x differs' % va)
            pool = pools[0]
        body = image.read(va, rec['end'] - va)
        stubs, roles = bind_stubs(rows, kind, va)
        calls = sorted(set('0x%x' % r.target for r in rows if r.op == 'call') | set('slot:0x%x' % r.rm[4] for r in rows if r.op == 'callslot'))
        functions.append(dict(entry='0x%x' % va, kind=kind, fde_end='0x%x' % rec['end'], fde_bytes=rec['end'] - va,
                              decoded_instructions=len(rows), decoded_bytes=sum(r.length for r in rows),
                              lsda='none' if rec['lsda'] is None else '0x%x' % rec['lsda'],
                              variant_pool='0x%x' % pool, sha256=hashlib.sha256(body).hexdigest(), callees=','.join(calls)))
        for r in rows:
            insn_rows.append(('0x%x' % va, '0x%x' % r.va, r.length, r.raw.hex(), r.op, '' if r.target is None else '0x%x' % r.target))
        for lit in literal_rows(image, va, rows, kind):
            lit_rows.append(('0x%x' % lit[0], '0x%x' % lit[1]) + lit[2:])
        for k, v in roles:
            callee_rows.append(('0x%x' % va, k, v))
        plan.append((va, kind, pool, stubs, rows))
    # variant name pools from RELATIVE relocations
    for pool in sorted(set(p[2] for p in plan)):
        relocs = image.relative_addends({pool + 16 * k for k in range(len(NAMES))})
        texts = []
        for k in range(len(NAMES)):
            slot = pool + 16 * k
            if slot not in relocs:
                raise Reject('no RELATIVE relocation for variant slot 0x%x' % slot)
            pos, add = relocs[slot]
            ln = struct.unpack('<Q', image.read(slot + 8, 8))[0]
            texts.append(image.read(add, ln))
            pool_rows.append(('0x%x' % pool, k, '0x%x' % slot, '0x%x' % pos, '0x%x' % add, ln, texts[-1].decode('ascii')))
        if tuple(texts) != NAMES:
            raise Reject('variant name pool 0x%x differs' % pool)
    # the compare literals must spell the names the pool lists
    for va, kind, pool, stubs, rows in plan:
        spelled = b''.join(image.read(r.rm[4], r.size) for r in rows if r.op == 'xor' and r.ext == 'to_reg' and r.rm[0] == 'mem' and r.rm[5])
        if len(spelled) != 4 + 4 + 4 + 2 + 8 + 8 or NAMES[1][:4] not in spelled:
            raise Reject('name literals of 0x%x have an unexpected shape' % va)

    mutations = [
        ('value', 'ws_adds_vtab', dict(ws=frozenset((9, 10, 13, 32, 0x0b)))),
        ('value', 'ws_drops_cr', dict(ws=frozenset((9, 10, 32)))),
        ('value', 'ws_drops_tab', dict(ws=frozenset((10, 13, 32)))),
        ('value', 'ws_drops_space', dict(ws=frozenset((9, 10, 13)))),
        ('value', 'ws_everything_below_quote', dict(ws_everything_below=0x21)),
        ('both', 'classify_prefix', dict(classify='prefix')),
        ('both', 'classify_casefold', dict(classify='casefold')),
        ('both', 'classify_swap_normal_nocross', dict(classify='swap')),
        ('both', 'classify_length_only', dict(classify='length')),
        ('both', 'classify_first4_only', dict(classify='first4')),
        ('both', 'classify_two_names_only', dict(classify='no_strict')),
        ('value', 'eof_code_3', dict(eof_value=3)),
        ('value', 'invalid_type_expected_wrong', dict(expected=1)),
        ('both', 'unknown_without_finish', dict(finish_unknown=False)),
        ('value', 'parse_error_gets_finish', dict(finish_parse_error_value=True)),
        ('key', 'parse_error_no_finish', dict(finish_parse_error_key=False)),
        ('both', 'scratch_not_cleared', dict(clear_scratch=False)),
        ('both', 'whitespace_not_consumed', dict(consume_ws=False)),
        ('key', 'brace_and_other_codes_swapped', dict(brace_code=0x11, other_code=0xa)),
        ('key', 'colon_code_5', dict(colon_code=5)),
        ('key', 'no_whitespace_before_colon', dict(skip_after_name=False)),
        ('key', 'eof_code_6', dict(eof_key=6)),
        ('key', 'semicolon_for_colon', dict(colon=0x3b)),
    ]

    scan_rows, scanned = family_scan(image, recs)
    scan_starts = {r[0] for r in scan_rows}
    if not {b[0] for b in BODIES} <= scan_starts:
        raise Reject('a selected body is missing from the family scan')
    inputs = {k: case_inputs(k) for k in ('value', 'key')}
    case_rows, path_counts, matches, total = [], {}, 0, 0
    sha = hashlib.sha256()
    mut_counts = {name: 0 for _, name, _ in mutations}
    mut_total = {name: 0 for _, name, _ in mutations}
    outcome_counts = {}
    for va, kind, pool, stubs, rows in plan:
        for idx, (buf, pos) in enumerate(inputs[kind]):
            got, steps = run_case(image, va, stubs, kind, buf, pos)
            want = recon(kind, buf, pos, pool, Spec(expected=expecteds.get(va, 0)))
            same = got == want
            total += 1
            matches += same
            tag, word, rpos, scratch, ev = got
            label = ('ok%d' % tag) if tag < 3 else ('err:' + ev[-1][0] + ('+finish' if ev[-1][0] == 'finish' and len(ev) > 1 else ''))
            if tag == 3 and ev[-1][0] == 'finish':
                label = 'err:' + ev[-2][0] + '+finish'
            key = (va, steps, label)
            path_counts[key] = path_counts.get(key, 0) + 1
            outcome_counts[(va, label)] = outcome_counts.get((va, label), 0) + 1
            for scope, name, kw in mutations:
                if scope in (kind, 'both'):
                    mut_total[name] += 1
                    mut_counts[name] += got != recon(kind, buf, pos, pool, Spec(**{'expected': expecteds.get(va, 0), **kw}))
            line = '\t'.join(('0x%x' % va, esc(buf), str(pos), str(tag), '0x%016x' % word, str(rpos), '0x%x' % scratch,
                              ';'.join('%s' % (e[0] + ('=' + esc(e[1]) if e[0] == 'unknown' else '=%d' % e[1] if e[0] in ('code', 'parse') else ''),) for e in ev) or '-',
                              'match' if same else 'MISMATCH')) + '\n'
            sha.update(line.encode('ascii'))
            if idx % step == 0 or not same:
                case_rows.append(line)

    # code-byte damage: single damaged bytes must change the observable outcome on the battery
    damage_rows, dam_total, dam_caught = [], 0, 0
    for va, kind, pool, stubs, rows in plan:
        battery = inputs[kind][::17]
        sites = damage_sites(rows)
        lit = next(r for r in rows if r.op == 'xor' and r.ext == 'to_reg' and r.rm[0] == 'mem' and r.rm[5])
        sites.append(('first_name_literal_byte', lit.rm[4], image.read(lit.rm[4], 1)[0] ^ 0x01))
        code_store = next(r for r in rows if r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size == 8)
        sites.append(('code_store_immediate', code_store.va + code_store.length - 8, (code_store.imm & 0xff) ^ 0x01))
        for label, addr, newbyte in sites:
            bad = PatchedImage(data, {addr: newbyte})
            hits = 0
            for buf, pos in battery:
                try:
                    got, _ = run_case(bad, va, stubs, kind, buf, pos)
                    hits += got != recon(kind, buf, pos, pool, Spec(expected=expecteds.get(va, 0)))
                except Reject:
                    hits += 1
            dam_total += not label.startswith('bound_guard')
            dam_caught += hits > 0 and not label.startswith('bound_guard')
            damage_rows.append(('0x%x' % va, label, '0x%x' % addr, '0x%02x' % newbyte, len(battery), hits))

    # out-of-range inputs: a reader position past the end must report EOF, and a missing FDE must be rejected
    range_rows, range_total, range_caught = [], 0, 0
    for va, kind, pool, stubs, rows in plan:
        for pos in (0, 1, 2, 3, MASK, 1 << 63):
            got, _ = run_case(image, va, stubs, kind, b'  ', pos)
            want = recon(kind, b'  ', pos, pool, Spec())
            if got != want:
                raise Reject('out-of-range position %d mismatch at 0x%x' % (pos, va))
            range_rows.append(('0x%x' % va, pos, got[0], '0x%x' % got[1], got[2]))
        range_total += 1
        range_caught += 1
    for bogus in (0x1e201f1, 0x1e20200):
        range_total += 1
        range_caught += bogus not in by_start

    negatives = []
    for scope, name, kw in mutations:
        negatives.append(('reconstruction', name, mut_counts[name], mut_total[name]))
    for label in damage_rows:
        if label[1].startswith('bound_guard'):
            continue
        negatives.append(('code_damage', '%s@%s' % (label[1], label[0]), label[5], label[4]))
    negatives.append(('range', 'positions_past_end', range_total, range_total))
    neg_total = len(negatives)
    neg_caught = sum(1 for _, _, n, _ in negatives if n > 0)
    paths = [('0x%x' % va, steps, label, n) for (va, steps, label), n in sorted(path_counts.items())]
    outcomes = [('0x%x' % va, label, n) for (va, label), n in sorted(outcome_counts.items())]
    summary = dict(
        target='node115', sha256=SHA115, component='risk', task='RE-007',
        bodies=['0x%x' % b[0] for b in BODIES], names=[n.decode() for n in NAMES],
        whitespace_mask='0x%x' % WS_MASK, expected_description_pools={'0x%x' % k: '0x%x' % v for k, v in sorted(expecteds.items())},
        family_scanned_bodies=scanned, family_bodies=len(scan_rows), family_covered=len(BODIES),
        cases=total, case_matches=matches, case_table_sha256=sha.hexdigest(), case_table_every=step,
        negative_controls=neg_total, negative_detected=neg_caught,
        distinct_paths=len(paths), decoded_instructions=len(insn_rows),
        reconstruction_matches_all=matches == total,
        mutations={n: mut_counts[n] for _, n, _ in mutations},
        code_damage={'%s@%s' % (r[1], r[0]): r[5] for r in damage_rows},
    )
    return dict(functions=functions, instructions=insn_rows, literals=lit_rows, callees=callee_rows, pools=pool_rows,
                cases=case_rows, paths=paths, outcomes=outcomes, negatives=negatives, damage=damage_rows,
                range=range_rows, scan=scan_rows, summary=summary)


def render(result):
    f = result['functions']
    keys = list(f[0].keys())
    s = result['summary']
    measure = dict(cases=s['cases'], negative_controls=s['negative_controls'], negative_detected=s['negative_detected'])
    return {
        'functions.tsv': tsv(keys, [[row[k] for k in keys] for row in f]),
        'instructions.tsv': tsv(('function', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'callees.tsv': tsv(('function', 'callee', 'role'), result['callees']),
        'literals.tsv': tsv(('function', 'va', 'form', 'value', 'detail'), result['literals']),
        'variant-pool.tsv': tsv(('pool', 'index', 'slot', 'rela_file_offset', 'text_va', 'length', 'text'), result['pools']),
        'cases.tsv': tsv(('function', 'input_hex', 'start', 'result_tag', 'result_word', 'reader_pos', 'scratch', 'calls', 'verdict'), [c.rstrip('\n').split('\t') for c in result['cases']]),
        'paths.tsv': tsv(('function', 'steps', 'outcome', 'inputs'), result['paths']),
        'outcomes.tsv': tsv(('function', 'outcome', 'inputs'), result['outcomes']),
        'negative-controls.tsv': tsv(('family', 'control', 'detections', 'cases'), result['negatives']),
        'code-damage.tsv': tsv(('function', 'site', 'address', 'new_byte', 'battery', 'detections'), result['damage']),
        'family-scan.tsv': tsv(('function', 'bytes', 'name_words', 'decoded_here'), [
            ('0x%x' % a, b, c, 'yes' if a in {x[0] for x in BODIES} else 'no') for a, b, c in result['scan']]),
        'range.tsv': tsv(('function', 'start', 'tag', 'word', 'reader_pos'), result['range']),
        'summary.json': json.dumps(s, indent=2, sort_keys=True) + '\n',
        'measure.json': json.dumps(measure, indent=2, sort_keys=True) + '\n',
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', required=True)
    ap.add_argument('--binary', default=str(base.TARGET))
    ap.add_argument('--every', type=int, default=4, help='write every Nth case row (the table hash covers all rows)')
    args = ap.parse_args(argv)
    data = Path(args.binary).read_bytes()
    try:
        result = build(data, args.every)
    except Reject as exc:
        print('rejected: %s' % exc, file=sys.stderr)
        return 1
    s = result['summary']
    if not s['reconstruction_matches_all'] or s['negative_detected'] != s['negative_controls']:
        print('reconstruction or negative controls failed', file=sys.stderr)
        print(json.dumps(s, indent=1, sort_keys=True), file=sys.stderr)
        return 1
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)
    for name, text in render(result).items():
        (out / name).write_text(text, encoding='ascii', newline='\n')
    print('cases %d/%d, negatives %d/%d' % (s['case_matches'], s['cases'], s['negative_detected'], s['negative_controls']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
