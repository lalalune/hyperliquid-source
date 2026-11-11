#!/usr/bin/env python3
"""Reconstruct the node #115 bridge event-name identifier deserializers and prove them.

The bridge event enum (Deposit, InvalidatedWithdrawal, RequestedWithdrawal,
FinalizedWithdrawal, FinalizedValidatorSetUpdate, RequestedValidatorSetUpdateEvent)
is read from a serde `Content` buffer through an identifier-plus-value pair
deserializer: it takes a 0x40-byte pair (the identifier Content at +0x00, the
value Content at +0x20) and returns the variant index together with the
untouched value Content, or an error.  The producer authenticates the #115
capture, locates five bodies by their unwind (FDE) extents and runs each
body's original machine code in a small interpreter for the fixed x86-64
subset those bodies use:

* two 610-byte bodies (copy families 1 and 2) that call the one-byte `Result`
  form of the already reconstructed name visitors, and
* three 760-byte bodies (families 1, 2 and 3) that call the tagged 32-byte
  form of the same visitors.

The identifier Content is dispatched through a 15-entry jump table: U8 and U64
select the variant index through a second six-entry table (values 0..5), String
and Str go to the str name visitor, ByteBuf and Bytes to the bytes name visitor
(those visitors run for real inside every case, so the 26-row length table and
the byte compares are exercised), and every other tag is an invalid-type error.
Drop, free, invalid-value and invalid-type callees are replaced by recording
stubs; the order and the arguments of those calls are part of the comparison.

Every interpreted result is compared with an independent pure-Python
reconstruction.  Deliberately wrong reconstructions, damaged code bytes,
swapped jump-table entries and out-of-range inputs must all be caught.

Only the standard library and the repository's shared ELF/unwind parsers are
used (the interpreter and decoder come from the merged margin identifier and
bridge event name packets).  The capture is never executed; no external program
is invoked.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bridge_event_name_codec_115 as ev  # noqa: E402
import fde_extents  # noqa: E402
import re007_margin_identifier_115 as mi  # noqa: E402

TARGET = mi.TARGET
SHA115 = mi.SHA115
Reject = mi.Reject
IN_BASE, OUT_BASE, DATA_BASE, OWNED_BASE, STACK_TOP = mi.IN_BASE, mi.OUT_BASE, mi.DATA_BASE, mi.OWNED_BASE, mi.STACK_TOP

# (entry, family, form of the visitors it calls)
HOSTS = (
    (0x1fae860, 1, 'result'),
    (0x3952710, 2, 'result'),
    (0x1fabc40, 1, 'tagged'),
    (0x394d730, 2, 'tagged'),
    (0x56835d0, 3, 'tagged'),
)
NAMES = ev.NAMES
COUNT = len(NAMES)
VIS = {va: (fam, kind, form) for va, fam, kind, form, _ in ev.VISITORS}
ARMS = {1: 'int8', 4: 'int64', 12: 'string', 13: 'str', 14: 'bytebuf', 15: 'bytes'}
NICHE_TAG = 0x16
INT_LIMIT = 5
# error records written by the recording stubs
FILL = {'invalid_value': 0xa0, 'invalid_type': 0xe0}
SENT = {'invalid_value': 0xe771_0000_0000_0001, 'invalid_type': 0xe773_0000_0000_0001}


def fill_for(role):
    return bytes((FILL[role] + k) & 0xff for k in range(32))


# ---------------------------------------------------------------- recording stubs

class Recorder:
    """Callee stubs of one host.  `events` is the ordered call record."""

    def __init__(self, form, image, by_start):
        self.form = form
        self.image = image
        self.by_start = by_start
        self.events = []
        self.vstubs = {}

    # host callees -------------------------------------------------------
    def invalid_value(self, m, args):
        if self.form == 'tagged':
            out, struct_ptr = args[0], m.load(args[2], 8)
            self.events.append(('iv', m.load(struct_ptr, 1), m.load(struct_ptr + 8, 8)))
            for k, b in enumerate(fill_for('invalid_value')):
                m.store(out + k, b, 1)
            return out
        self.events.append(('iv', m.load(args[0], 1), m.load(args[0] + 8, 8)))
        return SENT['invalid_value']

    def invalid_type(self, m, args):
        if self.form == 'tagged':
            out, content, pool = args[0], args[1], args[3]
        else:
            out, content, pool = None, args[0], args[2]
        self.events.append(('it', m.load(content, 1), pool))
        if self.form == 'tagged':
            for k, b in enumerate(fill_for('invalid_type')):
                m.store(out + k, b, 1)
            return out
        return SENT['invalid_type']

    def drop(self, m, args):
        which = {IN_BASE: 'c1', IN_BASE + 0x20: 'c2'}.get(args[0])
        if which is None:
            raise Reject('drop of an unknown object 0x%x' % args[0])
        self.events.append(('drop', which, m.load(args[0], 1)))
        return 0

    def free(self, m, args):
        self.events.append(('free', args[0], args[1], args[2]))
        return 0

    def visit(self, entry):
        def run(m, args):
            sub = mi.Machine(m.image, self.vstubs[entry])
            sub.mem = m.mem
            sub.regs[7], sub.regs[6], sub.regs[2] = args[0], args[1], args[2]
            sub.run(entry, stack_top=STACK_TOP - 0x2000)
            m.trace.extend(sub.trace)
            return sub.regs[0]
        return run

    # visitor callees ----------------------------------------------------
    def vlossy(self, m, args):
        out, ptr, ln = args[0], args[1], args[2]
        self.events.append(('lossy', bytes(m.load(ptr + k, 1) for k in range(ln))))
        return ev.lossy_stub(m, args)

    def vfree(self, m, args):
        self.events.append(('vfree', args[0], args[1], args[2]))
        return 0

    def vunknown(self, form):
        def run(m, args):
            if form == 'result':
                ptr, ln, pool, count = args[0], args[1], args[2], args[3]
            else:
                ptr, ln, pool, count = args[1], args[2], args[3], args[4]
            self.events.append(('uv', bytes(m.load(ptr + k, 1) for k in range(ln)), pool, count))
            return ev.unknown_ptr_stub(m, args) if form == 'result' else ev.unknown_fill_stub(m, args)
        return run


def unique(seq):
    out = []
    for x in seq:
        if x not in out:
            out.append(x)
    return out


def bind_visitor(image, rec, entry, kind, form):
    rows = mi.linear(image, entry, rec.by_start[entry]['end'])
    slots = unique(r.rm[4] for r in rows if r.op == 'callslot')
    calls = [r.target for r in rows if r.op == 'call']
    st = {}
    if kind == 'bytes':
        if len(slots) != 2:
            raise Reject('bytes visitor 0x%x does not use two slots' % entry)
        st[('slot', slots[0])] = rec.vlossy
        st[('slot', slots[1])] = rec.vfree
        direct = unique(calls[:-1])
    else:
        if slots:
            raise Reject('str visitor 0x%x calls through a slot' % entry)
        direct = unique(calls)
    for t in direct:
        st[t] = rec.vunknown(form)
    rec.vstubs[entry] = st
    return rows


def bind_host(image, entry, family, form):
    """(stubs, recorder, roles, rows) for one host.  Roles come from the body shape."""
    by_start = mi.fde_index(image)
    rows = mi.linear(image, entry, by_start[entry]['end'])
    rec = Recorder(form, image, by_start)
    direct = unique(r.target for r in rows if r.op == 'call')
    slots = unique(r.rm[4] for r in rows if r.op == 'callslot')
    visitors = [t for t in direct if t in VIS]
    others = [t for t in direct if t not in VIS]
    roles = {}
    for t in visitors:
        fam, kind, vform = VIS[t]
        if (fam, vform) != (family, form):
            raise Reject('visitor 0x%x does not belong to family %d / %s' % (t, family, form))
        roles[kind + '_visitor'] = t
    if sorted(roles) != ['bytes_visitor', 'str_visitor']:
        raise Reject('host does not call one str and one bytes visitor')
    if form == 'result':
        if len(others) != 3 or len(slots) != 3:
            raise Reject('result host callee count')
        roles['drop'], roles['invalid_type'], roles['unwind'] = others
        roles['free'], roles['invalid_value'], roles['resume'] = ('slot', slots[0]), ('slot', slots[1]), ('slot', slots[2])
    else:
        if len(others) != 4 or len(slots) != 2:
            raise Reject('tagged host callee count')
        roles['drop'], roles['invalid_type'], roles['invalid_value'], roles['unwind'] = others
        roles['free'], roles['resume'] = ('slot', slots[0]), ('slot', slots[1])
    stubs = {roles['drop']: rec.drop, roles['invalid_type']: rec.invalid_type, roles['invalid_value']: rec.invalid_value,
             roles['free']: rec.free,
             roles['str_visitor']: rec.visit(roles['str_visitor']), roles['bytes_visitor']: rec.visit(roles['bytes_visitor'])}
    for kind in ('str', 'bytes'):
        va = roles[kind + '_visitor']
        bind_visitor(image, rec, va, kind, form)
    return stubs, rec, roles, rows


def it_pool_of(rows, roles):
    """The invalid-type pool: the last rip-relative lea before the invalid-type call."""
    key = roles['invalid_type']
    for i, r in enumerate(rows):
        if r.op in ('call', 'callslot') and mi.call_key(r) == key:
            for q in reversed(rows[max(0, i - 8):i]):
                if q.op == 'lea' and q.rm[5]:
                    return q.rm[4]
    raise Reject('no pool before the invalid-type call')


def tables_of(image, rows):
    """Every jump table of the body: (table va, entry count, [target va ...])."""
    out = []
    for idx, r in enumerate(rows):
        if r.op != 'jmpind':
            continue
        lea = next(q for q in reversed(rows[max(0, idx - 5):idx]) if q.op == 'lea' and q.rm[5])
        cmp_ = next(q for q in reversed(rows[:idx]) if q.op == 'cmp' and q.ext == 'imm' and q.rm[0] == 'reg')
        n = cmp_.imm + 1
        table = lea.rm[4]
        targets = [table + mi.sx(struct.unpack('<I', image.read(table + 4 * k, 4))[0], 32) for k in range(n)]
        out.append((table, n, targets))
    return out


# ---------------------------------------------------------------- cases

MUTATION_COUNT_SAMPLE = 7


def case_list():
    texts = ev.visitor_inputs()
    out = []
    for v in mi.INT_VALUES:
        for c2 in mi.C2_TAGS:
            if v <= 0xff:
                out.append(mi.Case('int8', 1, value=v, c2=c2))
            out.append(mi.Case('int64', 4, value=v, c2=c2))
    for t in mi.OTHER_TAGS:
        for c2 in mi.C2_TAGS:
            out.append(mi.Case('other', t, c2=c2))
    for arm, tag in (('str', 13), ('bytes', 15), ('string', 12), ('bytebuf', 14)):
        for i, t in enumerate(texts):
            cap = 0
            if arm in ('string', 'bytebuf'):
                cap = 0 if i % 2 == 0 else len(t) + 3
            out.append(mi.Case(arm, tag, data=t, cap=cap, c2=mi.C2_TAGS[i % 3]))
    return out


# ---------------------------------------------------------------- reconstruction

class Flaws:
    """Switches that turn the reconstruction into a deliberately wrong one."""
    VISITOR = ('prefix', 'casefold', 'swap', 'alphabetical', 'first4', 'last16', 'length_only', 'first_byte',
               'short_table')
    ALL = ('int_bound_low', 'int_bound_high', 'int64_low_byte', 'int16_as_int8', 'no_drop_c1', 'string_drops_c1',
           'bytebuf_drops_c1', 'free_always', 'free_never', 'drop_c2_always', 'drop_c2_on_ok', 'invalid_type_drops_c1',
           'drop_before_visit', 'str_lossy', 'bytes_no_lossy', 'bytes_raw_text', 'unknown_is_last', 'ok_index_plus_one',
           'free_before_visit', 'drop_c2_first') + VISITOR


def classify(text, flaws):
    for name in Flaws.VISITOR:
        if name in flaws:
            return getattr(ev, 'wrong_' + name)(text, NAMES)
    return ev.recon_classify(text, NAMES)


def visitor_events(kind, text, pool, flaws, events):
    """Events of one name visitor run and its index (None on a miss)."""
    t = classify(text, flaws)
    if t is not None:
        return t
    if kind == 'bytes' and 'bytes_no_lossy' not in flaws or kind == 'str' and 'str_lossy' in flaws:
        events.append(('lossy', text))
        shown, owned = ev.lossy(text)
        if 'bytes_raw_text' in flaws:
            shown = text
        events.append(('uv', shown, pool, COUNT))
        if owned:
            events.append(('vfree', OWNED_BASE, len(shown), 0))
    else:
        events.append(('uv', text, pool, COUNT))
    return None


def recon(case, family, it_pool, flaws=frozenset()):
    """(outcome, events).  outcome = ('ok', index) or ('err', role)."""
    pool = ev.VARIANT_POOLS[family - 1]
    events = []
    arm = ARMS.get(case.tag)
    if 'int16_as_int8' in flaws and case.tag in (2, 3):
        arm = 'int8'
    drop_c1_done = False
    if arm in ('int8', 'int64'):
        v = case.value if arm == 'int8' else (case.value & 0xff if 'int64_low_byte' in flaws else case.value)
        limit = 4 if 'int_bound_low' in flaws else 6 if 'int_bound_high' in flaws else INT_LIMIT
        if v <= limit:
            result = ('ok', v + 1 if 'ok_index_plus_one' in flaws else v)
        else:
            events.append(('iv', 1, v))
            result = ('err', 'invalid_value')
    elif arm in ('str', 'string', 'bytes', 'bytebuf'):
        kind = 'str' if arm in ('str', 'string') else 'bytes'
        if 'drop_before_visit' in flaws and arm == 'bytes':
            events.append(('drop', 'c1', case.tag))
            drop_c1_done = True
        if 'free_before_visit' in flaws and arm in ('string', 'bytebuf') and case.cap:
            events.append(('free', DATA_BASE, case.cap, 0))
        t = visitor_events(kind, case.data, pool, flaws, events)
        result = ('ok', t) if t is not None else ('err', 'unknown_variant')
    else:
        events.append(('it', case.tag, it_pool))
        result = ('err', 'invalid_type')
        if 'invalid_type_drops_c1' in flaws:
            events.append(('drop', 'c1', case.tag))
    if arm in ('string', 'bytebuf'):
        if ((case.cap and 'free_never' not in flaws) or 'free_always' in flaws) and 'free_before_visit' not in flaws:
            events.append(('free', DATA_BASE, case.cap, 0))
        if (arm == 'string' and 'string_drops_c1' in flaws) or (arm == 'bytebuf' and 'bytebuf_drops_c1' in flaws):
            events.append(('drop', 'c1', case.tag))
    elif arm is not None and 'no_drop_c1' not in flaws and not drop_c1_done:
        events.append(('drop', 'c1', case.tag))
    if result[0] == 'err' and (case.c2 != NICHE_TAG or 'drop_c2_always' in flaws):
        if 'drop_c2_first' in flaws:
            events.insert(0, ('drop', 'c2', case.c2))
        else:
            events.append(('drop', 'c2', case.c2))
    elif result[0] == 'ok' and 'drop_c2_on_ok' in flaws:
        events.append(('drop', 'c2', case.c2))
    if 'unknown_is_last' in flaws and result == ('err', 'unknown_variant'):
        result = ('ok', COUNT - 1)
    return result, events


# ---------------------------------------------------------------- interpretation driver

def run_case(image, entry, form, stubs, rec, case):
    """Run one host.  Returns (outcome, events, steps)."""
    rec.events = []
    m = mi.Machine(image, stubs)
    for k in range(0x400):
        m.store(STACK_TOP - 8 - k, 0xa5, 1)
    for k in range(64):
        m.store(OUT_BASE + k, 0xa5, 1)
    mi.load_case(m, case)
    m.regs[7], m.regs[6] = OUT_BASE, IN_BASE
    m.run(entry)
    if m.regs[0] != OUT_BASE:
        raise Reject('host 0x%x does not return its output pointer' % entry)
    head = m.load(OUT_BASE, 1)
    if head < COUNT:
        if bytes(m.load(OUT_BASE + 8 + k, 1) for k in range(32)) != mi.c2_bytes(case.c2):
            raise Reject('Ok result does not carry the value Content unchanged')
        return ('ok', head), list(rec.events), len(m.trace)
    if head != COUNT:
        raise Reject('unexpected result byte %d' % head)
    if form == 'tagged':
        blob = bytes(m.load(OUT_BASE + 8 + k, 1) for k in range(32))
        role = next((r for r in FILL if blob == fill_for(r)), None)
        if role is None and blob == ev.ERR_FILL:
            role = 'unknown_variant'
    else:
        word = m.load(OUT_BASE + 8, 8)
        role = next((r for r, s in SENT.items() if s == word), None)
        if role is None and word == ev.ERR_SENTINEL:
            role = 'unknown_variant'
    if role is None:
        raise Reject('error payload is not one of the recorded error records')
    return ('err', role), list(rec.events), len(m.trace)


def executed_pcs(image, entry, form, stubs, rec, cases):
    pcs = set()
    for case in cases:
        rec.events = []
        m = mi.Machine(image, stubs)
        for k in range(0x400):
            m.store(STACK_TOP - 8 - k, 0xa5, 1)
        for k in range(64):
            m.store(OUT_BASE + k, 0xa5, 1)
        mi.load_case(m, case)
        m.regs[7], m.regs[6] = OUT_BASE, IN_BASE
        m.run(entry)
        pcs.update(m.trace)
    return pcs


def damage_sites(rows, executed):
    """Executed `cmp reg/mem, imm8` instructions: flipping bit 3 of the immediate byte."""
    sites = []
    for r in rows:
        if r.va in executed and r.op == 'cmp' and r.ext == 'imm' and r.imm in (1, 5, 9, 0xe, 0x16):
            sites.append((r.va + r.length - 1, 'cmp_imm_%x' % r.imm, r.raw[-1], r.raw[-1] ^ 0x08))
    return sites


def run_damage(data, entry, family, form, patches, cases):
    """First case label on which the damaged body disagrees with the reconstruction (or is rejected)."""
    image = mi.Image(data)
    image.patches = dict(patches)
    try:
        stubs, rec, roles, rows = bind_host(image, entry, family, form)
        pool = it_pool_of(rows, roles)
    except (Reject, StopIteration, KeyError):
        return 'bind'
    for case in cases:
        try:
            got, events, _ = run_case(image, entry, form, stubs, rec, case)
        except (Reject, KeyError):
            return case.label()
        want, wev = recon(case, family, pool)
        if (got, events) != (want, wev):
            return case.label()
    return None


def swap_patch(table, targets, k, j):
    """Patch table entry k so that it points where entry j points."""
    new = struct.pack('<i', targets[j] - table)
    pos = table + 4 * k
    return {pos + i: new[i] for i in range(4)}, pos


def check_sha(data):
    if hashlib.sha256(bytes(data)).hexdigest() != SHA115:
        raise Reject('input is not node #115')


def esc(b):
    return b.hex() if b else '-'


def event_text(events):
    parts = []
    for e in events:
        if e[0] in ('uv', 'lossy'):
            parts.append('%s(%s%s)' % (e[0], esc(e[1]), ''.join(',%x' % x for x in e[2:])))
        else:
            parts.append('%s(%s)' % (e[0], ','.join('%x' % x if isinstance(x, int) else str(x) for x in e[1:])))
    return ';'.join(parts) or '-'


# ---------------------------------------------------------------- build

def build(data, sample_rows=4100, control_stride=23):
    check_sha(data)
    image = mi.Image(data)
    by_start = mi.fde_index(image)
    functions, insn_rows, table_rows, callee_rows = [], [], [], []
    case_rows, path_counts, damage_rows = [], {}, []
    flaw_counts = {f: 0 for f in Flaws.ALL}
    total = ok = 0
    all_cases = case_list()
    # every integer and non-name case, plus a thinned set of name cases
    control_cases = [c for c in all_cases if c.arm in ('int8', 'int64', 'other')] + all_cases[::control_stride]
    stride = max(1, len(all_cases) * len(HOSTS) // sample_rows)
    for entry, family, form in HOSTS:
        if entry not in by_start:
            raise Reject('0x%x is not an FDE start' % entry)
        stubs, rec, roles, rows = bind_host(image, entry, family, form)
        end = by_start[entry]['end']
        functions.append(('0x%x' % entry, family, form, '0x%x' % end, end - entry, len(rows),
                          'none' if by_start[entry]['lsda'] is None else '0x%x' % by_start[entry]['lsda'],
                          hashlib.sha256(image.read(entry, end - entry)).hexdigest()))
        for r in rows:
            insn_rows.append(('0x%x' % entry, '0x%x' % r.va, r.length, r.raw.hex(), r.op,
                              '' if r.target is None else '0x%x' % r.target))
        pool = it_pool_of(rows, roles)
        for role in sorted(roles):
            key = roles[role]
            callee_rows.append(('0x%x' % entry, role, 'slot:0x%x' % key[1] if isinstance(key, tuple) else '0x%x' % key))
        callee_rows.append(('0x%x' % entry, 'variant_pool_unknown', '0x%x' % ev.VARIANT_POOLS[family - 1]))
        callee_rows.append(('0x%x' % entry, 'type_pool_invalid_type', '0x%x' % pool))
        tables = tables_of(image, rows)
        if [t[1] for t in tables] != [15, 6, 6] and [t[1] for t in tables] != [15, 6, 6][:len(tables)]:
            raise Reject('unexpected jump table sizes in 0x%x' % entry)
        top = tables[0]
        for tag, target in enumerate(top[2], 1):
            table_rows.append(('0x%x' % entry, '0x%x' % top[0], tag, '0x%x' % target, ARMS.get(tag, 'invalid_type')))
        for tab in tables[1:]:
            for value, target in enumerate(tab[2]):
                table_rows.append(('0x%x' % entry, '0x%x' % tab[0], value, '0x%x' % target, 'index'))
        default = [r for r in rows if r.op == 'ja'][0].target
        for tag, target in enumerate(top[2], 1):
            if (tag in ARMS) == (target == default):
                raise Reject('arm map disagrees with the jump table at tag %d' % tag)
        for i, case in enumerate(all_cases):
            got, events, steps = run_case(image, entry, form, stubs, rec, case)
            want, wev = recon(case, family, pool)
            same = (got, events) == (want, wev)
            total += 1
            ok += same
            key = ('0x%x' % entry, case.arm, got[0] if got[0] == 'ok' else got[1])
            lo, hi, n = path_counts.get(key, (steps, steps, 0))
            path_counts[key] = (min(lo, steps), max(hi, steps), n + 1)
            if i % stride == 0 or not same:
                case_rows.append(('0x%x' % entry, case.label(), '%s:%s' % got, event_text(events), steps,
                                  'match' if same else 'MISMATCH'))
            for flaw in Flaws.ALL:
                fw, fev = recon(case, family, pool, frozenset([flaw]))
                if (got, events) != (fw, fev):
                    flaw_counts[flaw] += 1
        executed = executed_pcs(image, entry, form, stubs, rec, control_cases)
        for pos, kind, before, after in damage_sites(rows, executed):
            found = run_damage(data, entry, family, form, {pos: after}, control_cases)
            damage_rows.append(('0x%x' % entry, kind, '0x%x' % pos, '%02x>%02x' % (before, after),
                                'detected' if found else 'UNDETECTED', found or '-'))
        for tag_from, tag_to in ((4, 1), (13, 12), (15, 14)):
            patch, pos = swap_patch(top[0], top[2], tag_from - 1, tag_to - 1)
            found = run_damage(data, entry, family, form, patch, control_cases)
            damage_rows.append(('0x%x' % entry, 'table_tag%d_as_tag%d' % (tag_from, tag_to), '0x%x' % pos, '4 bytes',
                                'detected' if found else 'UNDETECTED', found or '-'))
        for n, tab in enumerate(tables[1:], 1):
            patch, pos = swap_patch(tab[0], tab[2], 2, 4)
            found = run_damage(data, entry, family, form, patch, control_cases)
            damage_rows.append(('0x%x' % entry, 'int_table%d_value2_as_value4' % n, '0x%x' % pos, '4 bytes',
                                'detected' if found else 'UNDETECTED', found or '-'))
    range_rows = []
    try:
        check_sha(bytes(data[:-1]))
        range_rows.append(('truncated_binary', 'UNDETECTED'))
    except Reject:
        range_rows.append(('truncated_binary', 'detected'))
    try:
        bind_host(image, 0x1fae861, 1, 'result')
        range_rows.append(('entry_not_fde_start', 'UNDETECTED'))
    except (Reject, KeyError):
        range_rows.append(('entry_not_fde_start', 'detected'))
    try:
        bind_host(image, 0x1fae860, 2, 'result')
        range_rows.append(('wrong_family_visitors', 'UNDETECTED'))
    except Reject:
        range_rows.append(('wrong_family_visitors', 'detected'))
    try:
        stubs, rec, roles, rows = bind_host(image, 0x1fae860, 1, 'result')
        del stubs[roles['drop']]
        run_case(image, 0x1fae860, 'result', stubs, rec, mi.Case('str', 13, data=b'Deposit'))
        range_rows.append(('missing_drop_stub', 'UNDETECTED'))
    except Reject:
        range_rows.append(('missing_drop_stub', 'detected'))
    try:
        stubs, rec, roles, rows = bind_host(image, 0x1fae860, 1, 'result')
        stubs[roles['drop']] = lambda m, args: rec.drop(m, [0x1234])
        run_case(image, 0x1fae860, 'result', stubs, rec, mi.Case('str', 13, data=b'Deposit'))
        range_rows.append(('drop_of_foreign_object', 'UNDETECTED'))
    except Reject:
        range_rows.append(('drop_of_foreign_object', 'detected'))
    paths = [(k[0], k[1], k[2], v[0], v[1], v[2]) for k, v in sorted(path_counts.items())]
    negatives = ([('model_flaw', f, n, total) for f, n in sorted(flaw_counts.items())]
                 + [('damaged_code', '%s %s@%s' % (r[0], r[1], r[2]), 1 if r[4] == 'detected' else 0, 1) for r in damage_rows]
                 + [('out_of_range', r[0], 1 if r[1] == 'detected' else 0, 1) for r in range_rows])
    detected = sum(1 for _, _, n, _ in negatives if n > 0)
    summary = dict(target='node115', sha256=SHA115, component='bridge', hosts=len(HOSTS),
                   cases=total, matches=ok, reconstruction_matches_all=(ok == total),
                   negative_controls=len(negatives), negative_detected=detected,
                   model_flaws=len(Flaws.ALL), damaged_code_sites=len(damage_rows), range_controls=len(range_rows))
    return dict(functions=functions, instructions=insn_rows, tables=table_rows, callees=callee_rows,
                cases=case_rows, paths=paths, negatives=negatives, damage=damage_rows, summary=summary)


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def render(result):
    s = result['summary']
    return {
        'functions.tsv': tsv(('entry', 'family', 'form', 'fde_end', 'fde_bytes', 'decoded_instructions', 'lsda', 'sha256'),
                             result['functions']),
        'instructions.tsv': tsv(('function', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'jump-tables.tsv': tsv(('function', 'table', 'index', 'target', 'arm'), result['tables']),
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
