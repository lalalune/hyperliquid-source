#!/usr/bin/env python3
"""Reconstruct the node #115 oracle outcome enum's serde_json entry and prove it.

The clearinghouse oracle enum (name pool next to `l1/src/clearinghouse/oracle/
oracle.rs`; wire names StandaloneOutcome, Question, QuestionOutcome) is read
from JSON by two copies of one `deserialize_enum` body (0x25d8cb0 and
0x4490cd0).  The merged outcome-kind packet reconstructed the leaf readers
(bare-identifier reader, variant-key reader).  This tool reconstructs the
entry that calls them, from the file bytes:

* skip JSON whitespace; a `"` takes the bare-identifier path, where only the
  second name is a unit variant and the other two fail with an invalid-type
  error; a `{` takes the map path; anything else is a peek error;
* the map path charges the recursion budget (disabled flag at +0x48,
  remaining depth at +0x49), reads the variant key, then reads the payload:
  `null` for the unit variant, an opaque struct payload (one named field)
  for the other two, then requires the closing `}`;
* every failure exit with its error code, the budget refund and the payload
  drop on the trailing-character exits.

The entry body is run as original machine code in the merged packet's x86-64
interpreter (imported, extended with three forms).  The two leaf readers and
the `null` matcher are run as original code too (nested); only the struct
payload readers, the string scanner and the error constructors are stubs.
Every interpreted result is compared with an independent pure-Python
reconstruction; deliberately wrong reconstructions and corrupted code bytes
must be caught.  The capture is never executed and no external program runs.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import fde_extents  # noqa: E402
import risk_outcome_kind_codec_115 as base  # noqa: E402

Reject = base.Reject
TARGET = base.TARGET
SHA115 = base.SHA115
NICHE = 0x8000000000000002
UNIT_WORD = 0x8000000000000000
WS = b' \t\n\r'
NAMES = base.NAMES
NULL_EXPECTED = {}   # family -> expected-type argument of the null matcher, read from its lea
FIELD_POOLS = {}   # family -> (pool of payload0, pool of payload2), read from the lea before each call

# (entry, family, key reader, ident reader, null matcher, payload readers)
ENTRIES = (
    (0x25d8cb0, 1, 0x1debf40, 0x1e21040, 0x1e3e7c0, (0x1e0c420, 0x1e07570)),
    (0x4490cd0, 2, 0x3f7ea60, 0x3fba720, 0x3fd2750, (0x3f96950, 0x3fa9340)),
)
EXPECTED = {1: 0x6423c60, 2: 0x647f038}
KEY_CODES = dict(eof=3, close=10, other=17, colon=6)
IDENT_CODES = dict(eof=5)
ENTRY_ROLES = ('peek', 'ident', 'key', 'payload0', 'payload2', 'null', 'error_at', 'drop')
SLOT_ROLES = ('invalid_unit', 'panic_add', 'panic_sub', 'unreachable')
DEPTH_STATES = ((0, 128), (0, 2), (0, 1), (0, 0), (1, 0), (1, 7))
BYTE_CODE = dict(eof=5, bad=9)


class Panic(Exception):
    pass


# ---------------------------------------------------------------- decoder

class _Fake:
    def __init__(self, raw):
        self.raw, self.cache = raw, {}

    def read(self, va, n):
        return self.raw


_base_decode = base.decode


def decode(image, va):
    """Merged decoder plus `cmp al,imm8`, byte test/inc/dec and ud2."""
    if va in image.cache:
        return image.cache[va]
    raw = image.read(va, 16)
    i = 0
    while raw[i] in (0x66, 0xf3):
        i += 1
    if 0x40 <= raw[i] <= 0x4f:
        i += 1
    op = raw[i]
    if op in (0x84, 0xfe):
        mod = bytearray(raw)
        mod[i] = 0x85 if op == 0x84 else 0xff
        ins = _base_decode(_Fake(bytes(mod)), va)
        if op == 0xfe and ins.op not in ('inc', 'dec'):
            raise Reject('unsupported fe form at 0x%x' % va)
        ins.size, ins.raw = 1, bytes(raw[:ins.length])
    elif op == 0x3c:
        ins = base.Insn(va=va, length=i + 2, raw=bytes(raw[:i + 2]), op='cmp', rm=('reg', 0), imm=raw[i + 1],
                        size=1, ext='imm')
    elif raw[i:i + 2] == b'\x0f\x0b':
        ins = base.Insn(va=va, length=i + 2, raw=bytes(raw[:i + 2]), op='ud2', size=0)
    else:
        return _base_decode(image, va)
    image.cache[va] = ins
    return ins


base.decode = decode


# ---------------------------------------------------------------- models

def skip_ws(text, i):
    while i < len(text) and text[i] in WS:
        i += 1
    return i


def payload_skip(text, i):
    """Stand-in for a struct payload reader: consume one JSON value."""
    n = len(text)
    i = skip_ws(text, i)
    if i >= n:
        return ('err', n)
    c = text[i]
    if c in b'{[':
        stack, k = [], i
        while k < n:
            ch = text[k]
            if ch == 0x22:
                k += 1
                while k < n and text[k] != 0x22:
                    k += 2 if text[k] == 0x5c else 1
                if k >= n:
                    return ('err', n)
            elif ch in b'{[':
                stack.append(ch)
            elif ch in b'}]':
                if not stack or (ch == 0x7d) != (stack[-1] == 0x7b):
                    return ('err', k)
                stack.pop()
                if not stack:
                    return ('ok', k + 1)
            k += 1
        return ('err', n)
    if c == 0x22:
        k = i + 1
        while k < n and text[k] != 0x22:
            k += 2 if text[k] == 0x5c else 1
        return ('err', n) if k >= n else ('ok', k + 1)
    k = i
    while k < n and text[k] not in b',}] \t\n\r':
        k += 1
    return ('err', i) if k == i else ('ok', k)


def payload_words(which, start, end, pool):
    return (0x1000000000000000 | which << 32 | start, end, pool, 0xaaaa000000000000 | which,
            0xbbbb000000000000 | end, 0xcccc000000000000 | start)


def reader_at(kind, text, i, pool, expected, M):
    """The base reader model started at index `i` (the base one starts at 0)."""
    codes = KEY_CODES if kind == 'key' else IDENT_CODES
    n = len(text)
    ws = WS.replace(b'\t', b'') if M.get('no_tab') else WS
    while i < n and text[i] in ws:
        i += 1
    if i >= n:
        return ('err', ('peek_error', codes['eof'], i), i)
    c = text[i]
    if c != 0x22:
        if kind == 'ident':
            return ('err', ('fix_position', ('invalid_type', i, expected)), i)
        return ('err', ('peek_error', codes['close'] if c == 0x7d else codes['other'], i), i)
    i += 1
    got = base.scan_string(text, i)
    if got[0] == 'err':
        err = ('scan', got[1])
        return ('err', ('fix_position', err) if kind == 'key' else err, i)
    start, end = got[1], got[2]
    i = end + 1
    name = text[start:end]
    tag = NAMES.index(name) if name in NAMES else None
    if M.get('prefix_name') and tag is None:
        tag = next((k for k, v in enumerate(NAMES) if v.startswith(name) and name), None)
    if tag is None:
        return ('err', ('fix_position', ('unknown_variant', name, pool, 3)), i)
    if kind == 'ident':
        return ('ok', tag, i)
    i = skip_ws(text, i)
    if i >= n:
        return ('err', ('peek_error', codes['eof'], i), i)
    if text[i] != 0x3a:
        return ('err', ('peek_error', codes['colon'], i), i)
    return ('ok', tag, i + 1)


def null_at(text, i, expected):
    """The `null` matcher: whitespace, then n,u,l,l with EOF and mismatch exits."""
    n = len(text)
    i = skip_ws(text, i)
    if i >= n:
        return ('err', ('peek_error', 5, i), i)
    if text[i] != 0x6e:
        return ('err', ('fix_position', ('peek_invalid_type', i, expected)), i)
    for k, ch in enumerate(b'ull'):
        if i + 1 + k >= n:
            return ('err', ('error_at', 5, i + 1 + k), i + 1 + k)
        if text[i + 1 + k] != ch:
            return ('err', ('error_at', 9, i + 2 + k), i + 2 + k)
    return ('ok', None, i + 4)


def recon_enum(text, flag, rem, fam, M=None):
    """Observable effect of the entry: (outcome, final index, final budget, call roles)."""
    M = M or {}
    pool = base.VARIANT_POOLS[fam - 1]
    expected = EXPECTED[fam]
    seq = []
    n = len(text)
    i = skip_ws(text, 0)
    if i >= n:
        return (('err', ('peek_error', 5, i)), i, rem, ['peek'])
    c = text[i]
    if c == 0x22:
        seq.append('ident')
        st, val, idx = reader_at('ident', text, i, pool, expected, M)
        if st == 'err':
            return (('err', val), idx, rem, seq)
        if val == 1:
            return (('unit',), idx, rem, seq)
        if M.get('bare_struct_ok'):
            return (('unit',), idx, rem, seq)
        return (('err', ('invalid_unit', 0xd)), idx, rem, seq + ['invalid_unit'])
    if c != (0x7c if M.get('brace_off') else 0x7b):
        return (('err', ('peek_error', 10, i)), i, rem, ['peek'])
    if flag == 0 or M.get('limit_always'):
        if rem == 0:
            raise Panic('sub', i, rem)
        rem -= 1
        if rem == (1 if M.get('depth_off') else 0):
            return (('err', ('peek_error', 0x17 if M.get('code_off') else 0x18, i)), i, rem, ['peek'])
    seq.append('key')
    st, tag, idx = reader_at('key', text, i + 1, pool, None, M)
    refund = (flag == 0) and not M.get('no_refund')
    if st == 'err':
        return (('err', tag), idx, rem + 1 if refund else rem, seq)
    if M.get('swap_tags') and tag != 1:
        tag = 2 - tag
    if tag == 1:
        seq.append('null')
        st, val, idx = null_at(text, idx, NULL_EXPECTED[fam])
        payload = ('unit',)
    else:
        seq.append('payload0' if tag == 0 else 'payload2')
        which = 0 if tag == 0 else 2
        start = idx
        st, end = payload_skip(text, idx)
        if st == 'err':
            val, idx = ('payload_err', FIELD_POOLS[fam][0 if tag == 0 else 1], end), end
        else:
            payload = ('words', payload_words(which, start, end, FIELD_POOLS[fam][0 if tag == 0 else 1]))
            idx = end
    if st == 'err':
        return (('err', val), idx, rem + 1 if refund else rem, seq)
    rem2 = rem + 1 if refund else rem
    if M.get('refund_when_off') and flag != 0:
        rem2 += 1
    k = skip_ws(text, idx)
    if k >= n:
        return (('err', ('error_at', 3, k)), k, rem2, seq + ['error_at', 'drop'])
    if text[k] != (0x7e if M.get('close_off') else 0x7d):
        return (('err', ('error_at', 10, k)), k, rem2, seq + ['error_at', 'drop'])
    return (payload, k + 1, rem2, seq)


# ---------------------------------------------------------------- interpreter side

class Rig:
    """Roles, stubs and nested readers for one image."""

    def __init__(self, image, recs):
        self.image = image
        self.by_start = {r['start']: r for r in recs}
        self.inner = {}
        for _, fam, key, ident, null, payloads in ENTRIES:
            for va in (key, ident):
                rows = base.linear(image, va, self.by_start[va]['end'])
                self.inner[va] = base.bind_reader_roles(image, rows, va)
        for entry, fam, key, ident, null, payloads in ENTRIES:
            rows, droles, _ = self.roles_for(entry)
            pools = {}
            for k, r in enumerate(rows):
                role = droles.get(r.target) if r.op == 'call' else None
                if role in ('payload0', 'payload2'):
                    lea = [x for x in rows[max(0, k - 5):k] if x.op == 'lea' and x.reg == 2 and x.rm[5]]
                    if len(lea) != 1:
                        raise Reject('no unique pool lea before the %s call' % role)
                    pools[role] = lea[0].rm[4]
            FIELD_POOLS[fam] = (pools['payload0'], pools['payload2'])
            nrows = base.linear(image, null, self.by_start[null]['end'])
            leas = [x.rm[4] for x in nrows if x.op == 'lea' and x.reg == 2 and x.rm[5]]
            if len(leas) != 1:
                raise Reject('null matcher 0x%x has no unique expected-type lea' % null)
            NULL_EXPECTED[fam] = leas[0]

    def roles_for(self, entry):
        rows = base.linear(self.image, entry, self.by_start[entry]['end'])
        direct = []
        for r in rows:
            if r.op == 'call' and r.target not in direct:
                direct.append(r.target)
        slots = []
        for r in rows:
            if r.op == 'callslot' and r.rm[4] not in slots:
                slots.append(r.rm[4])
        if len(direct) != 10 or len(slots) != 4:
            raise Reject('entry 0x%x has %d direct and %d slot callees' % (entry, len(direct), len(slots)))
        return rows, dict(zip(direct[:8], ENTRY_ROLES)), dict(zip(slots, SLOT_ROLES))

    def null_roles(self, va):
        rows = base.linear(self.image, va, self.by_start[va]['end'])
        direct = []
        for r in rows:
            if r.op == 'call' and r.target not in direct:
                direct.append(r.target)
        slots = sorted(set(r.rm[4] for r in rows if r.op == 'callslot'))
        if len(direct) != 4 or len(slots) != 1:
            raise Reject('null matcher 0x%x callee shape differs' % va)
        return dict(zip(direct, ('peek_error', 'error_at', 'peek_invalid_type', 'fix_position'))), slots[0]


def make_stubs(rig, entry, fam, key, ident, null, payloads, errors):
    image = rig.image
    _, droles, sroles = rig.roles_for(entry)
    nroles, nslot = rig.null_roles(null)
    inner = rig.inner

    def err_code(machine, args, name):
        if args[0] != base.DE_BASE:
            raise Reject('%s deserializer argument differs' % name)
        return errors.new((name, machine.load(args[1], 8), base.de_state(machine)[2]))

    def run_nested(machine, entry_va, stubs, rdi, rsi):
        nm = base.Machine(image, stubs)
        nm.mem = machine.mem
        nm.regs[7], nm.regs[6] = rdi, rsi
        old = base.STACK_TOP
        base.STACK_TOP = (machine.regs[4] - 0x400) & ~0xf
        try:
            nm.run(entry_va, limit=4000)
        finally:
            base.STACK_TOP = old
        return nm.regs[0]

    def reader(va):
        def f(machine, args):
            if args[1] != base.DE_BASE:
                raise Reject('reader deserializer argument differs')
            return run_nested(machine, va, base.reader_stubs(inner[va], errors), args[0], args[1])
        return f

    def null_stub(machine, args):
        stubs = {}
        for key_va, role in nroles.items():
            if role == 'peek_error':
                stubs[key_va] = lambda m, a: err_code(m, a, 'peek_error')
            elif role == 'error_at':
                stubs[key_va] = lambda m, a: err_code(m, a, 'error_at')
            elif role == 'peek_invalid_type':
                stubs[key_va] = lambda m, a: errors.new(('peek_invalid_type', base.de_state(m)[2], a[2]))
            else:
                stubs[key_va] = lambda m, a: errors.new(('fix_position', errors.name(a[0])))

        def panic(m, a):
            raise Panic('null')
        stubs[('slot', nslot)] = panic
        return run_nested(machine, null, stubs, args[0], 0)

    def payload(which, va):
        def f(machine, args):
            out, de, pool, count = args[:4]
            if de != base.DE_BASE or pool != FIELD_POOLS[fam][which // 2] or count != 1:
                raise Reject('payload reader %d arguments differ: %x %x %x' % (which, de, pool, count))
            ptr, length, idx = base.de_state(machine)
            text = bytes(machine.load(ptr + k, 1) for k in range(length))
            st, end = payload_skip(text, idx)
            if st == 'err':
                machine.store(out, NICHE, 8)
                machine.store(out + 8, errors.new(('payload_err', pool, end)), 8)
                machine.store(base.DE_BASE + 0x28, end, 8)
                return out
            for k, w in enumerate(payload_words(which, idx, end, pool)):
                machine.store(out + 8 * k, w, 8)
            machine.store(base.DE_BASE + 0x28, end, 8)
            return out
        return f

    def drop(machine, args):
        return 0

    def invalid_unit(machine, args):
        return errors.new(('invalid_unit', machine.load(args[0], 1)))

    def panic_add(machine, args):
        raise Panic('add')

    def panic_sub(machine, args):
        raise Panic('sub')

    def unreachable(machine, args):
        raise Reject('unreachable slot called')
    stubs = {}
    for va, role in droles.items():
        stubs[va] = {'peek': lambda m, a: err_code(m, a, 'peek_error'),
                     'error_at': lambda m, a: err_code(m, a, 'error_at'),
                     'ident': reader(ident), 'key': reader(key), 'null': null_stub,
                     'payload0': payload(0, va), 'payload2': payload(2, va), 'drop': drop}[role]
    for va, role in sroles.items():
        stubs[('slot', va)] = {'invalid_unit': invalid_unit, 'panic_add': panic_add, 'panic_sub': panic_sub,
                               'unreachable': unreachable}[role]
    roles = dict(droles)
    roles.update({('slot', va): r for va, r in sroles.items()})
    return stubs, roles


def run_enum(rig, spec, text, flag, rem):
    entry, fam, key, ident, null, payloads = spec
    errors = base.ReaderErrors()
    stubs, roles = make_stubs(rig, entry, fam, key, ident, null, payloads, errors)
    m = base.Machine(rig.image, stubs)
    for k in range(0x60):
        m.store(base.OUT_BASE + k, 0xa5, 1)
    for k in range(0x100):
        m.store(base.STACK_TOP - 0x100 + k, 0xa5, 1)
    for k, b in enumerate(text):
        m.store(base.DATA_BASE + k, b, 1)
    m.store(base.DE_BASE, 0, 8)
    m.store(base.DE_BASE + 8, 0, 8)
    m.store(base.DE_BASE + 0x10, base.CLOBBER, 8)
    m.store(base.DE_BASE + 0x18, base.DATA_BASE, 8)
    m.store(base.DE_BASE + 0x20, len(text), 8)
    m.store(base.DE_BASE + 0x28, 0, 8)
    for k in range(0x28, 0x48):
        m.store(base.DE_BASE + 0x10 + k, 0, 1) if False else None
    m.store(base.DE_BASE + 0x48, flag, 1)
    m.store(base.DE_BASE + 0x49, rem, 1)
    m.regs[7], m.regs[6] = base.OUT_BASE, base.DE_BASE
    try:
        m.run(entry, limit=3000)
    except Panic as exc:
        return ('panic', exc.args[0]), m.load(base.DE_BASE + 0x28, 8), m.load(base.DE_BASE + 0x49, 1), None
    if m.regs[0] != base.OUT_BASE:
        raise Reject('entry 0x%x does not return its output pointer' % entry)
    q0 = m.load(base.OUT_BASE, 8)
    if q0 == NICHE:
        outcome = ('err', errors.name(m.load(base.OUT_BASE + 8, 8)))
    elif q0 == UNIT_WORD:
        outcome = ('unit',)
    else:
        outcome = ('words', tuple(m.load(base.OUT_BASE + 8 * k, 8) for k in range(6)))
    seq = [roles[k] for _, k, _ in m.calls if k in roles]
    return outcome, m.load(base.DE_BASE + 0x28, 8), m.load(base.DE_BASE + 0x49, 1), seq


def recon_view(text, flag, rem, fam, M=None):
    try:
        outcome, idx, rem2, seq = recon_enum(text, flag, rem, fam, M)
    except Panic as exc:
        return ('panic', exc.args[0]), exc.args[1], exc.args[2], None
    return outcome, idx, rem2, seq


def norm(view):
    """Compare the call roles that the entry makes itself (not the nested leaf work)."""
    outcome, idx, rem, seq = view
    if seq is not None:
        seq = [s for s in seq if s not in ('payload0', 'payload2')] and seq
    return outcome, idx, rem, tuple(seq) if seq is not None else None


# ---------------------------------------------------------------- inputs

BASES = (
    b'', b' \t',
    b'"Question"', b'"StandaloneOutcome"', b'"QuestionOutcome"', b'"Quest"',
    b'{"Question":null}', b'{ "Question" : null }', b'{"Question":nul}', b'{"Question":nulX}',
    b'{"StandaloneOutcome":{}', b'{"StandaloneOutcome":{}x}', b'{"QuestionOutcome":{"parent":1}',
    b'{"Question":{}}', b'{"Question":null,}', b'{\t"Question"\t:\tnull\t}',
    b'{"StandaloneOutcome":{"side_names":[]}}', b'{"StandaloneOutcome":{"side_names":["a","b"]}}',
    b'{"StandaloneOutcome":[1,{"x":"}"}]}', b'{"StandaloneOutcome":"s"}', b'{"StandaloneOutcome":12}',
    b'{"QuestionOutcome":{"parent":1}}', b'{"QuestionOutcome":{"parent":{"a":[]}}}', b'{"QuestionOutcome":true}',
    b'{"Other":1}', b'{1:2}', b'{}', b'[1]', b'nul', b'{"Question"}', b'{"Question";null}',
    b' \t\r\n"Question"', b'\x0b"Question"', b'{"StandaloneOutcome":{}} ', b'{"StandaloneOutcome":{}}x',
    b'{"QuestionOutcome":{"parent":"\\"}"}}',
)
SUBSTS = (b'"', b'{', b'}', b':', b' ', b'\t', b'n', b'x', b'\\', b'\x00', b'[', b',')


def inputs():
    seen = set()
    for base_text in BASES:
        for k in range(len(base_text) + 1):
            seen.add(base_text[:k])
        for k in range(len(base_text)):
            for s in SUBSTS:
                seen.add(base_text[:k] + s + base_text[k + 1:])
            seen.add(base_text[:k] + base_text[k + 1:])
    for w in (b'', b' ', b'  \n', b'\t\t'):
        for b0 in BASES[:20:3]:
            seen.add(w + b0)
            seen.add(b0 + w)
    return sorted(seen)


def case_list():
    texts = inputs()[::2]
    for text in texts:
        yield text, DEPTH_STATES[0]
    for text in texts[::3]:
        for st in DEPTH_STATES[1:]:
            yield text, st


# ---------------------------------------------------------------- negative controls

RECON_MUTANTS = (
    ('recon: tab is not whitespace in the readers', dict(no_tab=True)),
    ('recon: prefix name match in the readers', dict(prefix_name=True)),
    ('recon: bare struct variant accepted', dict(bare_struct_ok=True)),
    ('recon: map opener is 0x7c', dict(brace_off=True)),
    ('recon: budget limit hits at 1', dict(depth_off=True)),
    ('recon: budget code 0x17', dict(code_off=True)),
    ('recon: budget charged when disabled', dict(limit_always=True)),
    ('recon: no budget refund', dict(no_refund=True)),
    ('recon: refund when disabled', dict(refund_when_off=True)),
    ('recon: closer is 0x7e', dict(close_off=True)),
    ('recon: struct tags swapped', dict(swap_tags=True)),
)

# (name, offset from entry, expected old byte, new byte) - applied to both copies
BYTE_MUTANTS = (
    ('code: quote compare 0x22 -> 0x21 (identifier path test)', 0x87, 0x22, 0x21),
    ('code: map opener compare 0x7b -> 0x7c', 0xc1, 0x7b, 0x7c),
    ('code: closer compare 0x7d -> 0x7e', 0x258, 0x7d, 0x7e),
    ('code: budget error code 0x18 -> 0x19', 0x2c2, 0x18, 0x19),
    ('code: non-brace error code 0xa -> 0xb', 0x2b5, 0x0a, 0x0b),
    ('code: eof error code 5 -> 6', 0x5c, 0x05, 0x06),
    ('code: eof-in-object code 3 -> 4', 0x237, 0x03, 0x04),
    ('code: trailing error code 0xa -> 0xb', 0x2cf, 0x0a, 0x0b),
    ('code: unit-variant kind 0xd -> 0xe', 0x294, 0x0d, 0x0e),
    ('code: disabled-flag compare 0 -> 1', 0xcb, 0x00, 0x01),
    ('code: budget dec -> inc', 0xdb, 0xc9, 0xc1),
    ('code: budget refund inc -> dec', 0x1ec, 0xc0, 0xc8),
    ('code: whitespace mask loses tab', 0x28, 0x26, 0x24),
    ('code: payload field count 1 -> 2 (first payload)', 0x12d, 0x01, 0x02),
    ('code: payload field count 1 -> 2 (second payload)', 0x164, 0x01, 0x02),
)
# (name, table base, entry i, entry j): swap two relative jump-table entries (first copy only)
TABLE_MUTANTS = (
    ('table: ident tags 0 and 1 swapped', 0x5efff4, 0, 1),
    ('table: key tags 0 and 2 swapped', 0x5f0004, 0, 2),
    ('table: key tags 1 and 2 swapped', 0x5f0004, 1, 2),
    ('table: ident tags 0 and 3 swapped', 0x5efff4, 0, 3),
)


def patch_copy(data, edits):
    out = bytearray(data)
    for off, new in edits:
        out[off:off + len(new)] = new
    return bytes(out)


def file_offset(image, va):
    s = image.section_of(va)
    return s['offset'] + va - s['address']


def kill_set(texts):
    """A fixed subset covering every arm, used for the mutant runs."""
    return [(t, st) for t in BASES for st in DEPTH_STATES] + texts[::29]


# ---------------------------------------------------------------- driver

def compare(rig, spec, text, flag, rem, M=None):
    got = run_enum(rig, spec, text, flag, rem)
    want = recon_view(text, flag, rem, spec[1], M)
    return norm(got) == norm(want)


def mutant_lost(rig, spec, text, flag, rem):
    """1 if the corrupted image is rejected or disagrees with the reconstruction."""
    try:
        got = run_enum(rig, spec, text, flag, rem)
    except (Reject, IndexError, KeyError):
        return 1
    return int(norm(got) != norm(recon_view(text, flag, rem, spec[1])))


def build(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')
    image = base.Image(data)
    _, recs, _ = fde_extents.fde_extents(data)
    rig = Rig(image, recs)
    by_start = rig.by_start
    cases = list(case_list())
    total = mismatches = 0
    paths = {}
    sample = []
    for spec in ENTRIES:
        fam = spec[1]
        for k, (text, (flag, rem)) in enumerate(cases):
            got = run_enum(rig, spec, text, flag, rem)
            want = recon_view(text, flag, rem, fam)
            total += 1
            ok = norm(got) == norm(want)
            if not ok:
                mismatches += 1
            kind = got[0][0] if got[0][0] != 'err' else 'err:' + str(got[0][1][0])
            key = (fam, flag, min(rem, 3), kind, tuple(got[3]) if got[3] is not None else None)
            paths[key] = paths.get(key, 0) + 1
            if k % 29 == 0:
                sample.append((fam, flag, rem, text, got[0], got[1], got[2], ok))
    # negative controls
    kills = kill_set([c for c in cases])
    controls = []
    for name, M in RECON_MUTANTS:
        lost = 0
        for spec in ENTRIES:
            for text, (flag, rem) in kills:
                got = run_enum(rig, spec, text, flag, rem)
                if norm(got) != norm(recon_view(text, flag, rem, spec[1], M)):
                    lost += 1
        controls.append((name, lost))
    for name, off, old, new in BYTE_MUTANTS:
        lost = 0
        for spec in ENTRIES:
            at = spec[0] + off
            fo = file_offset(image, at)
            if data[fo] != old:
                raise Reject('mutant %s precondition at 0x%x: %02x' % (name, at, data[fo]))
            mimage = base.Image(patch_copy(data, [(fo, bytes([new]))]))
            mrig = Rig(mimage, recs)
            for text, (flag, rem) in kills:
                lost += mutant_lost(mrig, spec, text, flag, rem)
        controls.append((name, lost))
    for name, table, i, j in TABLE_MUTANTS:
        fo = file_offset(image, table)
        ei, ej = data[fo + 4 * i:fo + 4 * i + 4], data[fo + 4 * j:fo + 4 * j + 4]
        mimage = base.Image(patch_copy(data, [(fo + 4 * i, ej), (fo + 4 * j, ei)]))
        mrig = Rig(mimage, recs)
        lost = 0
        for text, (flag, rem) in kills:
            lost += mutant_lost(mrig, ENTRIES[0], text, flag, rem)
        controls.append((name, lost))
    return dict(total=total, mismatches=mismatches, paths=paths, sample=sample, controls=controls,
                cases=len(cases), by_start=by_start, rig=rig, image=image)


def esc(b):
    return ''.join(chr(c) if 0x20 <= c < 0x7f and c != 0x5c else '\\x%02x' % c for c in b)


def tsv(header, rows):
    return '\n'.join('\t'.join(str(x) for x in r) for r in [header] + list(rows)) + '\n'


def render(result):
    rig, image = result['rig'], result['image']
    files = {}
    func_rows, insn_rows, role_rows, table_rows = [], [], [], []
    for spec in ENTRIES:
        entry, fam, key, ident, null, payloads = spec
        rec = result['by_start'][entry]
        rows, droles, sroles = rig.roles_for(entry)
        body = image.read(entry, rec['end'] - entry)
        func_rows.append(('0x%x' % entry, fam, rec['end'] - entry, len(rows), hashlib.sha256(body).hexdigest(),
                          'none' if rec['lsda'] is None else '0x%x' % rec['lsda']))
        for r in rows:
            insn_rows.append(('0x%x' % entry, '0x%x' % r.va, r.length, r.raw.hex(), r.op,
                              '' if r.target is None else '0x%x' % r.target))
        for va, role in droles.items():
            role_rows.append(('0x%x' % entry, 'call', '0x%x' % va, role))
        for va, role in sroles.items():
            role_rows.append(('0x%x' % entry, 'slot', '0x%x' % va, role))
        for pos, va in zip(('key', 'ident', 'null', 'payload0', 'payload2'), (key, ident, null) + payloads):
            role_rows.append(('0x%x' % entry, 'nested' if pos in ('key', 'ident', 'null') else 'stub',
                              '0x%x' % va, pos))
    for va, name, n in ((0x5efff4, 'ident result tag', 4), (0x5f0004, 'key result tag', 4)):
        for k in range(n):
            rel = int.from_bytes(image.read(va + 4 * k, 4), 'little', signed=True)
            table_rows.append((name, k, '0x%x' % (va + 4 * k), '0x%x' % (va + rel)))
    files['functions.tsv'] = tsv(('entry', 'family', 'fde_bytes', 'instructions', 'sha256', 'lsda'), func_rows)
    files['instructions.tsv'] = tsv(('entry', 'va', 'length', 'bytes', 'op', 'target'), insn_rows)
    files['callee-roles.tsv'] = tsv(('entry', 'kind', 'address', 'role'), role_rows)
    files['jump-tables.tsv'] = tsv(('table', 'index', 'slot', 'target'), table_rows)
    path_rows = [(f, fl, rm, kind, ','.join(seq) if seq is not None else 'panic', n)
                 for (f, fl, rm, kind, seq), n in sorted(result['paths'].items(), key=lambda kv: str(kv[0]))]
    files['paths.tsv'] = tsv(('family', 'budget_disabled', 'remaining_clamped', 'outcome', 'entry_calls', 'cases'),
                             path_rows)
    files['cases-sample.tsv'] = tsv(
        ('family', 'budget_disabled', 'remaining', 'input', 'outcome', 'index', 'remaining_after', 'match'),
        [(f, fl, rem, esc(t), str(o)[:90], i, r, ok) for f, fl, rem, t, o, i, r, ok in result['sample']])
    files['negative-controls.tsv'] = tsv(('control', 'cases_lost'), result['controls'])
    detected = sum(1 for _, lost in result['controls'] if lost)
    summary = dict(cases=result['total'], mismatches=result['mismatches'], distinct_inputs=result['cases'],
                   negative_controls=len(result['controls']), negative_detected=detected,
                   paths=len(result['paths']))
    files['summary.json'] = json.dumps(summary, indent=1, sort_keys=True) + '\n'
    files['measure.json'] = json.dumps(dict(cases=summary['cases'], negative_controls=summary['negative_controls'],
                                            negative_detected=detected), indent=1, sort_keys=True) + '\n'
    return files, summary


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
    files, summary = render(result)
    if summary['mismatches'] or summary['negative_detected'] != summary['negative_controls']:
        print(json.dumps(summary, indent=1, sort_keys=True), file=sys.stderr)
        return 1
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out / name).write_text(text, encoding='ascii', newline='\n')
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
