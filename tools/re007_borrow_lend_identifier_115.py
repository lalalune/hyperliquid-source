#!/usr/bin/env python3
"""Reconstruct the node #115 borrowLend operation-identifier deserializers and prove them.

The borrowLend operation enum (borrow, supply, repay, withdraw) is read from a
serde `Content` buffer through an identifier-plus-value pair deserializer: it
takes a 0x40-byte pair (the identifier Content at +0x00, the value Content at
+0x20) and returns the variant index together with the untouched value
Content, or an error.  Unlike the margin-mode pair deserializers, these bodies
do not compare names themselves: the string-like Content arms delegate to the
operation-name visitors that the merged borrowLend packet already
reconstructed.

The producer authenticates the #115 capture, locates five bodies by their
unwind (FDE) extents, and runs each body's original machine code in the
interpreter of the merged margin-identifier packet
(tools/re007_margin_identifier_115.py):

* three 742-byte bodies (three copy families) that write the result and the
  error into a tagged record, and
* two 591-byte bodies (families 1 and 2) that return the same decisions as a
  one-byte `Result` with a boxed error pointer.

The identifier Content is dispatched through a 15-entry jump table; the U8 and
U64 arms use a second four-entry table (values 0..3 are the four operations,
anything larger is an invalid-value error), String and Str call the `&str`
name visitor, ByteBuf and Bytes the `&[u8]` name visitor (owned buffers are
freed afterwards), and every other tag is an invalid-type error.  The two
tables are decoded from the file bytes.  The name visitors, drop, free and the
error constructors are recording stubs; the order and arguments of those calls
are part of the comparison.

Every interpreted result is compared with an independent pure-Python
reconstruction.  Deliberately wrong reconstructions, damaged code bytes and
out-of-range inputs must all be caught.

Only the standard library, the repository's shared ELF/unwind parsers and the
merged margin-identifier tool are used.  The capture is never executed.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re007_margin_identifier_115 as base  # noqa: E402

Reject = base.Reject
Image, Machine, Case, decode = base.Image, base.Machine, base.Case, base.decode
TARGET, SHA115 = base.TARGET, base.SHA115
IN_BASE, OUT_BASE, DATA_BASE, OWNED_BASE = base.IN_BASE, base.OUT_BASE, base.DATA_BASE, base.OWNED_BASE
STACK_TOP, NICHE_TAG = base.STACK_TOP, base.NICHE_TAG
FILL_BASE, SENTINEL, fill_for = base.FILL_BASE, base.SENTINEL, base.fill_for

# (entry, copy family, output form).  The tagged form leaves a 32-byte record
# at out+8 on error; the result form leaves a boxed error pointer at out+8.
BODIES = (
    (0x1fb06e0, 1, 'tagged'),
    (0x3940b60, 2, 'tagged'),
    (0x5686460, 3, 'tagged'),
    (0x1fab480, 1, 'result'),
    (0x394e020, 2, 'result'),
)
NAMES = (b'borrow', b'supply', b'repay', b'withdraw')
# name visitors (reconstructed by the borrowLend codec packet) called by the bodies
VISITORS = {(1, 'tagged'): (0x2691210, 0x2690fb0), (1, 'result'): (0x2691150, 0x2690e20),
            (2, 'tagged'): (0x3d440a0, 0x3d43d70), (2, 'result'): (0x3d44140, 0x3d43f10),
            (3, 'tagged'): (0x57c3760, 0x57c35c0)}
# first appearance order of the distinct callees inside every body
ROLE_ORDER = ('visit_str', 'visit_bytes', 'free', 'drop', 'invalid_type', 'invalid_value', 'resume', 'unwind')
ARMS = {1: 'int8', 4: 'int64', 12: 'string', 13: 'str', 14: 'bytebuf', 15: 'bytes'}
OK_MAX = 3
ERR_HEAD = 4
EXPECTED_SIZE = {'tagged': 742, 'result': 591}
SENTINEL = dict(SENTINEL, unknown_variant=0xe772_0000_0000_0001)


def call_key(r):
    return base.call_key(r)


def body_roles(rows):
    keys = []
    for r in rows:
        if r.op in ('call', 'callslot') and call_key(r) not in keys:
            keys.append(call_key(r))
    if len(keys) != len(ROLE_ORDER):
        raise Reject('body has %d distinct callees, expected %d' % (len(keys), len(ROLE_ORDER)))
    return dict(zip(ROLE_ORDER, keys))


def classify(text):
    return NAMES.index(text) if text in NAMES else None


# ---------------------------------------------------------------- recording stubs

class Recorder:
    """Callee stubs that append one event per call."""

    def __init__(self, form):
        self.form = form
        self.events = []
        self.inner = base.Recorder(form, None)
        self.inner.events = self.events

    def _visit(self, kind, m, args):
        out, ptr, ln = args[:3]
        text = bytes(m.load(ptr + k, 1) for k in range(ln))
        self.events.append((kind, text))
        tag = classify(text)
        if self.form == 'tagged':
            if tag is not None:
                m.store(out, 0x09, 1)
                m.store(out + 1, tag, 1)
            else:
                for k, b in enumerate(fill_for('unknown_variant')):
                    m.store(out + k, b, 1)
            return out
        if tag is not None:
            m.store(out, 0, 1)
            m.store(out + 1, tag, 1)
        else:
            m.store(out, 1, 1)
            m.store(out + 8, SENTINEL['unknown_variant'], 8)
        return out

    def visit_str(self, m, args):
        return self._visit('vs', m, args)

    def visit_bytes(self, m, args):
        return self._visit('vb', m, args)

    def invalid_value(self, m, args):
        return self.inner.invalid_value(m, args)

    def invalid_type(self, m, args):
        return self.inner.invalid_type(m, args)

    def drop(self, m, args):
        return self.inner.drop(m, args)

    def free(self, m, args):
        return self.inner.free(m, args)


_FDE_CACHE = {}


def fde_index(image):
    return base.fde_index(image)


def bind_stubs(image, entry, family, form):
    by_start = fde_index(image)
    rows = base.linear(image, entry, by_start[entry]['end'])
    roles = body_roles(rows)
    if (roles['visit_str'], roles['visit_bytes']) != VISITORS[(family, form)]:
        raise Reject('visitor callees of 0x%x are not the expected name visitors' % entry)
    rec = Recorder(form)
    stubs = {roles['visit_str']: rec.visit_str, roles['visit_bytes']: rec.visit_bytes,
             roles['invalid_value']: rec.invalid_value, roles['invalid_type']: rec.invalid_type,
             roles['drop']: rec.drop, roles['free']: rec.free}
    return stubs, rec, roles, rows


# ---------------------------------------------------------------- cases

MUTATION_BYTES = (0x00, 0x0a, 0x80, 0xff, 0x20, 0x41, 0x7a)
INT_VALUES = tuple(range(0, 9)) + (0x7f, 0x80, 0xff, 0x100, 0x101, 0xffff, 0x10000, 0x100000000, 0x100000001,
                                   0x8000000000000000, 0xfffffffffffffffe, 0xffffffffffffffff,
                                   0x0100000000000000, 0x0200000000000000, 0x0300000000000000)
OTHER_TAGS = (0, 2, 3, 5, 6, 7, 8, 9, 10, 11, 16, 17, 18, 19, 20, 21, 22, 23, 0x7f, 0x80, 0xff)
C2_TAGS = (NICHE_TAG, 0x03, 0x0d, 0x01)


def text_inputs():
    seen, have = [], set()

    def add(t):
        if t not in have:
            have.add(t)
            seen.append(t)
    add(b'')
    for n in NAMES:
        add(n)
        for k in range(len(n) + 1):
            add(n[:k])
        add(n + b'x')
        add(n + b'\0')
        add(n.lower())
        add(n.upper())
        add(n.capitalize())
        add(n[:-1] + b'\xff')
        for pos in range(len(n)):
            for v in MUTATION_BYTES:
                add(n[:pos] + bytes([v]) + n[pos + 1:])
            add(n[:pos] + bytes([n[pos] ^ 0x20]) + n[pos + 1:])
    for a in NAMES:
        for b in NAMES:
            if a != b:
                add(a[:len(a) // 2] + b[len(b) // 2:])
    for ln in range(0, 20):
        add(b'A' * ln)
        add(b'\x80' * ln)
    return seen


def case_list():
    texts = text_inputs()
    out = []
    for v in INT_VALUES:
        for c2 in C2_TAGS:
            if v <= 0xff:
                out.append(Case('int8', 1, value=v, c2=c2))
            out.append(Case('int64', 4, value=v, c2=c2))
    for t in OTHER_TAGS:
        for c2 in C2_TAGS:
            out.append(Case('other', t, c2=c2))
    for arm, tag in (('str', 13), ('bytes', 15), ('string', 12), ('bytebuf', 14)):
        for i, t in enumerate(texts):
            for j, c2 in enumerate(C2_TAGS):
                cap = 0 if (i + j) % 2 == 0 else len(t) + 3
                if arm in ('str', 'bytes') and cap:
                    cap = 0
                out.append(Case(arm, tag, data=t, cap=cap, c2=c2))
    return out


# ---------------------------------------------------------------- reconstruction

class Flaws:
    """Switches that turn the reconstruction into a deliberately wrong one."""
    ALL = ('int_bound', 'int64_low_byte', 'swap_first_two', 'swap_last_two', 'no_drop_c1', 'free_always',
           'drop_c2_always', 'string_drops_c1', 'int16_as_int8', 'drop_c2_on_ok', 'unknown_is_last',
           'bytebuf_drops_c1', 'invalid_type_drops_c1', 'drop_before_visit', 'string_uses_bytes',
           'bytes_uses_str', 'free_before_visit', 'int_tag_plus_one', 'invalid_value_drops_c2_first',
           'ok_drops_c1', 'withdraw_unknown')


def recon(case, flaws=frozenset()):
    """(outcome, events).  outcome = ('ok', index) or ('err', role)."""
    ev = []
    arm = ARMS.get(case.tag)
    if 'int16_as_int8' in flaws and case.tag in (2, 3):
        arm = 'int8'
    result = None

    def visit(kind, text):
        t = classify(text)
        if 'swap_first_two' in flaws:
            t = {0: 1, 1: 0}.get(t, t)
        if 'swap_last_two' in flaws:
            t = {2: 3, 3: 2}.get(t, t)
        if 'withdraw_unknown' in flaws and t == 3:
            t = None
        ev.append((kind, text))
        return t

    if arm in ('int8', 'int64'):
        v = case.value & 0xff if (arm == 'int64' and 'int64_low_byte' in flaws) else case.value
        limit = 2 if 'int_bound' in flaws else OK_MAX
        if v <= limit:
            result = ('ok', v + 1 if 'int_tag_plus_one' in flaws and v < OK_MAX else v)
        else:
            ev.append(('iv', 1, v))
            result = ('err', 'invalid_value')
    elif arm in ('str', 'string', 'bytes', 'bytebuf'):
        kind = 'vs' if arm in ('str', 'string') else 'vb'
        if 'string_uses_bytes' in flaws and arm == 'string':
            kind = 'vb'
        if 'bytes_uses_str' in flaws and arm == 'bytes':
            kind = 'vs'
        if 'drop_before_visit' in flaws and arm in ('str', 'bytes'):
            ev.append(('drop', 'c1', case.tag))
        if 'free_before_visit' in flaws and arm in ('string', 'bytebuf') and case.cap:
            ev.append(('free', DATA_BASE, case.cap, 0))
        t = visit(kind, case.data)
        result = ('ok', t) if t is not None else ('err', 'unknown_variant')
    else:
        ev.append(('it', case.tag, 0))
        result = ('err', 'invalid_type')
        if 'invalid_type_drops_c1' in flaws:
            ev.append(('drop', 'c1', case.tag))
    owned = arm in ('string', 'bytebuf')
    if owned:
        if (case.cap or 'free_always' in flaws) and 'free_before_visit' not in flaws:
            ev.append(('free', DATA_BASE, case.cap, 0))
        if (arm == 'string' and 'string_drops_c1' in flaws) or (arm == 'bytebuf' and 'bytebuf_drops_c1' in flaws):
            ev.append(('drop', 'c1', case.tag))
    elif arm is not None and 'no_drop_c1' not in flaws and not ('drop_before_visit' in flaws and arm in ('str', 'bytes')):
        ev.append(('drop', 'c1', case.tag))
    if result[0] == 'ok' and 'ok_drops_c1' in flaws and arm is not None and owned:
        ev.append(('drop', 'c1', case.tag))
    if result[0] == 'err' and result[1] == 'invalid_value' and 'invalid_value_drops_c2_first' in flaws:
        ev.insert(1, ('drop', 'c2', case.c2))
    if result[0] == 'err' and (case.c2 != NICHE_TAG or 'drop_c2_always' in flaws):
        ev.append(('drop', 'c2', case.c2))
    elif result[0] == 'ok' and 'drop_c2_on_ok' in flaws:
        ev.append(('drop', 'c2', case.c2))
    if 'unknown_is_last' in flaws and result == ('err', 'unknown_variant'):
        result = ('ok', 3)
    return result, ev


def fix_it_pool(events, pool):
    return [('it', e[1], pool) if e[0] == 'it' else e for e in events]


# ---------------------------------------------------------------- interpretation driver

def run_case(image, entry, form, stubs, rec, case):
    """Run one body.  Returns (outcome, events, steps)."""
    rec.events[:] = []
    m = Machine(image, stubs)
    for k in range(0x400):
        m.store(STACK_TOP - 8 - k, 0xa5, 1)
    for k in range(64):
        m.store(OUT_BASE + k, 0xa5, 1)
    base.load_case(m, case)
    m.regs[7], m.regs[6] = OUT_BASE, IN_BASE
    m.run(entry)
    if m.regs[0] != OUT_BASE:
        raise Reject('body 0x%x does not return its output pointer' % entry)
    head = m.load(OUT_BASE, 1)
    if head <= OK_MAX:
        got = bytes(m.load(OUT_BASE + 8 + k, 1) for k in range(32))
        if got != base.c2_bytes(case.c2):
            raise Reject('Ok result does not carry the value Content unchanged')
        return ('ok', head), list(rec.events), len(m.trace)
    if head != ERR_HEAD:
        raise Reject('unexpected result byte %d' % head)
    if form == 'tagged':
        blob = bytes(m.load(OUT_BASE + 8 + k, 1) for k in range(32))
        role = next((r for r in ('invalid_value', 'unknown_variant', 'invalid_type') if blob == fill_for(r)), None)
    else:
        word = m.load(OUT_BASE + 8, 8)
        role = next((r for r, s in SENTINEL.items() if s == word), None)
    if role is None:
        raise Reject('error payload is not one of the recorded error records')
    return ('err', role), list(rec.events), len(m.trace)


def gather_it_pool(rows, roles):
    return base.gather_it_pool(rows, roles)


# ---------------------------------------------------------------- static derivation

def int_tables(image, rows, entries):
    """For the U8 (tag 1) and U64 (tag 4) arms: (table va, bound, [operation tag per value], invalid target)."""
    out = {}
    targets = dict(entries)
    for tag in (1, 4):
        start = next(i for i, r in enumerate(rows) if r.va == targets[tag])
        stop = next(i for i in range(start, len(rows)) if rows[i].op == 'jmpind')
        window = rows[start:stop + 1]
        lea = next(q for q in reversed(window) if q.op == 'lea' and q.rm[5])
        cmp_ = next(q for q in window if q.op == 'cmp' and q.ext == 'imm')
        ja = next(q for q in window if q.op == 'ja')
        table = lea.rm[4]
        ops = []
        for k in range(cmp_.imm + 1):
            off = base.sx(struct.unpack('<I', image.read(table + 4 * k, 4))[0], 32)
            ins = decode(image, table + off)
            if ins.op != 'mov' or ins.ext != 'imm':
                raise Reject('int table target is not an immediate store')
            ops.append(ins.imm >> 8 if ins.size == 2 else ins.imm)
        out[tag] = (table, cmp_.imm, ops, ja.target)
    return out


def esc(b):
    return b.hex() if b else '-'


def event_text(events):
    parts = []
    for e in events:
        if e[0] in ('vs', 'vb'):
            parts.append('%s(%s)' % (e[0], esc(e[1])))
        else:
            parts.append('%s(%s)' % (e[0], ','.join(str(x) for x in e[1:])))
    return ';'.join(parts) or '-'


# ---------------------------------------------------------------- damage controls

JCC_SHORT = range(0x70, 0x80)


def damage_sites(rows, executed):
    """Executed compare immediates (flip bit 3) and executed conditional jumps (invert the condition)."""
    sites = []
    for r in rows:
        if r.va not in executed:
            continue
        if r.op == 'cmp' and r.ext == 'imm' and len(r.raw) >= 3:
            sites.append((r.va + r.length - 1, 'cmp_imm_%x' % r.imm, r.raw[-1], r.raw[-1] ^ 0x08))
        elif r.op in ('je', 'jne', 'jb', 'jae', 'jbe', 'ja', 'jle', 'jg') and r.raw[0] in JCC_SHORT:
            sites.append((r.va, 'invert_%s' % r.op, r.raw[0], r.raw[0] ^ 1))
    return sites


def run_damage(data, entry, family, form, patches, cases):
    """First case label on which the damaged body disagrees with the reconstruction (or is rejected)."""
    image = Image(data)
    image.patches = dict(patches)
    try:
        stubs, rec, roles, rows = bind_stubs(image, entry, family, form)
        it_pool = gather_it_pool(rows, roles)
    except (Reject, ValueError, StopIteration):
        return 'bind'
    for case in cases:
        try:
            got, ev, _ = run_case(image, entry, form, stubs, rec, case)
        except Reject:
            return case.label()
        want, wev = recon(case)
        if (got, ev) != (want, fix_it_pool(wev, it_pool)):
            return case.label()
    return None


def executed_pcs(image, entry, form, stubs, rec, cases):
    seen = set()
    for case in cases:
        rec.events[:] = []
        m = Machine(image, stubs)
        for k in range(0x400):
            m.store(STACK_TOP - 8 - k, 0xa5, 1)
        for k in range(64):
            m.store(OUT_BASE + k, 0xa5, 1)
        base.load_case(m, case)
        m.regs[7], m.regs[6] = OUT_BASE, IN_BASE
        m.run(entry)
        seen.update(m.trace)
    return seen


def check_sha(data):
    if hashlib.sha256(bytes(data)).hexdigest() != SHA115:
        raise Reject('input is not node #115')


def control_subset(cases):
    """Interleaved sample that touches every arm early: damaged bodies are caught fast."""
    return cases[::13] + cases[5::97]


# ---------------------------------------------------------------- build

def build(data, sample_rows=4800):
    check_sha(data)
    image = Image(data)
    by_start = fde_index(image)
    functions, insn_rows, table_rows, callee_rows, int_rows = [], [], [], [], []
    case_rows, path_counts, damage_rows = [], {}, []
    flaw_counts = {f: 0 for f in Flaws.ALL}
    total = ok = 0
    all_cases = case_list()
    controls = control_subset(all_cases)
    stride = max(1, len(all_cases) * len(BODIES) // sample_rows)
    for entry, family, form in BODIES:
        if entry not in by_start:
            raise Reject('0x%x is not an FDE start' % entry)
        stubs, rec, roles, rows = bind_stubs(image, entry, family, form)
        end = by_start[entry]['end']
        if end - entry != EXPECTED_SIZE[form]:
            raise Reject('unexpected body size for 0x%x' % entry)
        functions.append(('0x%x' % entry, family, form, '0x%x' % end, end - entry, len(rows),
                          'none' if by_start[entry]['lsda'] is None else '0x%x' % by_start[entry]['lsda'],
                          hashlib.sha256(image.read(entry, end - entry)).hexdigest()))
        for r in rows:
            insn_rows.append(('0x%x' % entry, '0x%x' % r.va, r.length, r.raw.hex(), r.op,
                              '' if r.target is None else '0x%x' % r.target))
        it_pool = gather_it_pool(rows, roles)
        for role in ROLE_ORDER:
            key = roles[role]
            callee_rows.append(('0x%x' % entry, role, 'slot:0x%x' % key[1] if isinstance(key, tuple) else '0x%x' % key))
        callee_rows.append(('0x%x' % entry, 'type_pool_invalid_type', '0x%x' % it_pool))
        table, entries, default = base.jump_table(image, rows)
        base.check_arms(entries, default)
        for tag, target in entries:
            table_rows.append(('0x%x' % entry, '0x%x' % table, tag, '0x%x' % target, ARMS.get(tag, 'invalid_type')))
        for tag, (itable, bound, ops, bad) in sorted(int_tables(image, rows, entries).items()):
            if ops != list(range(OK_MAX + 1)) or bound != OK_MAX:
                raise Reject('int table of 0x%x is not the identity on 0..3' % entry)
            int_rows.append(('0x%x' % entry, ARMS[tag], '0x%x' % itable, bound, ','.join(str(o) for o in ops),
                             '0x%x' % bad))
        for i, case in enumerate(all_cases):
            got, ev, steps = run_case(image, entry, form, stubs, rec, case)
            want, wev = recon(case)
            same = (got, ev) == (want, fix_it_pool(wev, it_pool))
            total += 1
            ok += same
            key = ('0x%x' % entry, case.arm, got[0] if got[0] == 'ok' else got[1])
            lo, hi, n = path_counts.get(key, (steps, steps, 0))
            path_counts[key] = (min(lo, steps), max(hi, steps), n + 1)
            if i % stride == 0 or not same:
                case_rows.append(('0x%x' % entry, case.label(), '%s:%s' % got, event_text(ev), steps,
                                  'match' if same else 'MISMATCH'))
            for flaw in Flaws.ALL:
                fw, fev = recon(case, frozenset([flaw]))
                if (got, ev) != (fw, fix_it_pool(fev, it_pool)):
                    flaw_counts[flaw] += 1
        executed = executed_pcs(image, entry, form, stubs, rec, controls)
        for pos, kind, before, after in damage_sites(rows, executed):
            found = run_damage(data, entry, family, form, {pos: after}, controls)
            damage_rows.append(('0x%x' % entry, kind, '0x%x' % pos, '%02x>%02x' % (before, after),
                                'detected' if found else 'UNDETECTED', found or '-'))
        for tag_from, tag_to in ((4, 1), (13, 12), (15, 14), (12, 14)):
            new = struct.pack('<i', dict(entries)[tag_to] - table)
            pos = table + 4 * (tag_from - 1)
            found = run_damage(data, entry, family, form, {pos + k: new[k] for k in range(4)}, controls)
            damage_rows.append(('0x%x' % entry, 'table_tag%d_as_tag%d' % (tag_from, tag_to), '0x%x' % pos,
                                '4 bytes', 'detected' if found else 'UNDETECTED', found or '-'))
    range_rows = []
    try:
        check_sha(bytes(data[:-1]))
        range_rows.append(('truncated_binary', 'UNDETECTED'))
    except Reject:
        range_rows.append(('truncated_binary', 'detected'))
    try:
        bind_stubs(image, 0x1fb06e1, 1, 'tagged')
        range_rows.append(('entry_not_fde_start', 'UNDETECTED'))
    except (Reject, KeyError):
        range_rows.append(('entry_not_fde_start', 'detected'))
    try:
        stubs, rec, roles, rows = bind_stubs(image, 0x1fb06e0, 1, 'tagged')
        del stubs[roles['drop']]
        run_case(image, 0x1fb06e0, 'tagged', stubs, rec, Case('int8', 1, value=0))
        range_rows.append(('missing_drop_stub', 'UNDETECTED'))
    except Reject:
        range_rows.append(('missing_drop_stub', 'detected'))
    try:
        bind_stubs(image, 0x1fb06e0, 2, 'tagged')
        range_rows.append(('wrong_family_visitors', 'UNDETECTED'))
    except Reject:
        range_rows.append(('wrong_family_visitors', 'detected'))
    try:
        stubs, rec, roles, rows = bind_stubs(image, 0x1fab480, 1, 'result')
        run_case(image, 0x1fab480, 'tagged', stubs, rec, Case('int8', 1, value=9))
        range_rows.append(('wrong_output_form', 'UNDETECTED'))
    except Reject:
        range_rows.append(('wrong_output_form', 'detected'))
    paths = [(k[0], k[1], k[2], v[0], v[1], v[2]) for k, v in sorted(path_counts.items())]
    undetected_damage = [r for r in damage_rows if r[4] != 'detected']
    damage_ok = [r for r in damage_rows if r[4] == 'detected']
    negatives = ([('model_flaw', f, n, total) for f, n in sorted(flaw_counts.items())]
                 + [('damaged_code', '%s %s@%s' % (r[0], r[1], r[2]), 1, 1) for r in damage_ok]
                 + [('out_of_range', r[0], 1 if r[1] == 'detected' else 0, 1) for r in range_rows])
    detected = sum(1 for _, _, n, _ in negatives if n > 0)
    summary = dict(target='node115', sha256=SHA115, component='risk', task='RE-007', bodies=len(BODIES),
                   cases=total, matches=ok, reconstruction_matches_all=(ok == total),
                   negative_controls=len(negatives), negative_detected=detected,
                   model_flaws=len(Flaws.ALL), damaged_code_sites=len(damage_ok),
                   equivalent_damage_sites=len(undetected_damage), range_controls=len(range_rows))
    return dict(functions=functions, instructions=insn_rows, tables=table_rows, ints=int_rows, callees=callee_rows,
                cases=case_rows, paths=paths, negatives=negatives, damage=damage_rows, summary=summary)


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def render(result):
    s = result['summary']
    return {
        'functions.tsv': tsv(('entry', 'family', 'form', 'fde_end', 'fde_bytes', 'decoded_instructions', 'lsda', 'sha256'),
                             result['functions']),
        'instructions.tsv': tsv(('function', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'jump-tables.tsv': tsv(('function', 'table', 'tag', 'target', 'arm'), result['tables']),
        'int-tables.tsv': tsv(('function', 'arm', 'table', 'bound', 'operation_per_value', 'invalid_target'),
                              result['ints']),
        'callees.tsv': tsv(('function', 'role', 'value'), result['callees']),
        'cases.tsv': tsv(('function', 'case', 'result', 'events', 'steps', 'verdict'), result['cases']),
        'paths.tsv': tsv(('function', 'arm', 'outcome', 'min_steps', 'max_steps', 'cases'), result['paths']),
        'damage-controls.tsv': tsv(('function', 'kind', 'byte_va', 'change', 'verdict', 'first_case'), result['damage']),
        'negative-controls.tsv': tsv(('family', 'control', 'detections', 'cases'), result['negatives']),
        'summary.json': json.dumps(s, indent=2, sort_keys=True) + '\n',
        'measure.json': json.dumps(dict(cases=s['cases'], negative_controls=s['negative_controls'],
                                        negative_detected=s['negative_detected']), indent=2, sort_keys=True) + '\n',
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
    print('cases %d/%d, negative controls %d/%d' % (s['matches'], s['cases'], s['negative_detected'], s['negative_controls']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
