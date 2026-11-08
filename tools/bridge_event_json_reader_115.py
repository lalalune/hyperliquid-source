#!/usr/bin/env python3
"""Reconstruct the node #115 JSON-text readers of the bridge event-name enum and prove them.

The bridge event enum (Deposit, InvalidatedWithdrawal, RequestedWithdrawal,
FinalizedWithdrawal, FinalizedValidatorSetUpdate, RequestedValidatorSetUpdateEvent)
is read from JSON text by four serde_json-shaped bodies in two copy families.
Two read the enum as a *value* (skip whitespace, expect a quote, parse the
string, hand the text to the `&str` name visitor, finish unknown names with the
error finisher) and two read it as an object *key* (the same, then skip
whitespace again and require a colon).

Unlike the margin-mode readers of the merged JSON packet, these bodies hold no
name compare of their own: the compare lives in the `&str` result visitors
0x2864e60 / 0x44466c0 of the merged event-name packet.  This producer runs the
reader's original machine code in the interpreter of the merged margin-mode
tool and, whenever the reader calls its visitor, runs the original visitor body
in the interpreter of the merged event-name tool, so the whole path from JSON
bytes to the event tag is executed from file bytes.  Only the string parser,
the code-error constructor, the invalid-type constructor and the error finisher
are recording stubs.  Every outcome (result tag and word, reader position,
scratch word, ordered call list with arguments) is compared with an independent
pure-Python reconstruction; mutated reconstructions, damaged reader code bytes
and damaged visitor code bytes must be caught.

The producer also lists every direct call site of the ten merged name visitors
(raw rel32 scan of .text) and the host function of each one.

Only the standard library, the repository's shared ELF/unwind parsers and the
merged margin-mode, JSON-reader and event-name tools are used.  The capture is
never executed and no external program is invoked.
"""
import argparse
import bisect
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402
import re007_json_identifier_reader_115 as jr  # noqa: E402
import bridge_event_name_codec_115 as ev  # noqa: E402

base = jr.base
Reject = jr.Reject
SHA115 = ev.SHA115
NAMES = ev.NAMES
TARGET = ev.TARGET
DATA_BASE, OWNED_BASE, IN_BASE, OUT_BASE = jr.DATA_BASE, jr.OWNED_BASE, jr.IN_BASE, jr.OUT_BASE
SENT, ERR_CODE, ERR_INV, ERR_STR, FIN = jr.SENT, jr.ERR_CODE, jr.ERR_INV, jr.ERR_STR, jr.FIN
STR_ERR = jr.STR_ERR
ERR_VIS = 0xe400 << 48
ERR_TAG = 6
PARSE_SLOT = 0x64e08f8  # GOT slot of the JSON string parser (shared with the merged margin-mode readers)
WS_MASK = jr.WS_MASK

# (entry, kind, family, name visitor, code-error ctor, invalid-type ctor, error finisher)
BODIES = (
    (0x1e20b30, 'value', 1, 0x2864e60, 0x1d75420, 0x1d76fd0, 0x2cf8390),
    (0x1dee070, 'key', 1, 0x2864e60, 0x1d75420, None, 0x2cf8390),
    (0x3fb9fa0, 'value', 2, 0x44466c0, 0x3ef1a90, 0x3ef2ab0, 0x4671240),
    (0x3f7bff0, 'key', 2, 0x44466c0, 0x3ef1a90, None, 0x4671240),
)
VISITOR_ENTRIES = tuple(v[0] for v in ev.VISITORS)


# ---------------------------------------------------------------- multi-byte nop padding

_decode_merged = jr.decode


def decode_with_nop(image, va):
    """merged decoder plus the multi-byte nop (66/2e prefixes, 0f 1f /0 with a register-base modrm); the nop is
    modelled as a jump to the next instruction, which has the same effect on registers, memory and flags"""
    hit = image.icache.get(va)
    if hit is not None:
        return hit
    raw = image.read(va, 16)
    i = 0
    while raw[i] in (0x66, 0x2e) and i < 8:
        i += 1
    if raw[i] == 0x0f and raw[i + 1] == 0x1f:
        modrm = raw[i + 2]
        mod, rm = modrm >> 6, modrm & 7
        if mod == 3:
            raise Reject('nop with a register operand at 0x%x' % va)
        length = i + 3 + (1 if rm == 4 else 0) + {0: 4 if rm == 5 else 0, 1: 1, 2: 4}[mod]
        ins = base.Insn(va=va, length=length, raw=image.read(va, length), op='jmp', size=0, target=va + length)
        image.icache[va] = ins
        return ins
    return _decode_merged(image, va)


jr.decode = decode_with_nop


# ---------------------------------------------------------------- the real visitor inside a reader run

class EvPatched(ev.Image):
    """Image of the event-name tool whose bytes can be damaged in memory (negative controls)."""

    def __init__(self, data, patches=None):
        super().__init__(data)
        self.patches = dict(patches or {})

    def read(self, va, n):
        out = bytearray(super().read(va, n))
        for k in range(n):
            if va + k in self.patches:
                out[k] = self.patches[va + k]
        return bytes(out)


class VisitorBinding:
    """One `&str` result visitor run from file bytes: stubs, roles and variant pool read from its own rows."""

    def __init__(self, image, entry, end):
        self.entry = entry
        rows = ev.linear(image, entry, end)
        targets = sorted(set(r.target for r in rows if r.op == 'call'))
        if len(targets) != 1 or any(r.op == 'callslot' for r in rows):
            raise Reject('visitor 0x%x does not have exactly one direct callee and no slot call' % entry)
        self.rows = rows
        self.stubs = {targets[0]: ev.unknown_ptr_stub}
        self.roles = {targets[0]: 'unknown_variant_result'}
        pools = [r.rm[4] for r in rows if r.op == 'lea' and r.rm[5] and r.rm[4] in ev.VARIANT_POOLS]
        if len(pools) != 1:
            raise Reject('visitor 0x%x does not reference one variant pool' % entry)
        self.pool = pools[0]

    def run(self, image, text):
        got, m = ev.run_visitor(image, self.entry, 'str', 'result', 'event', self.stubs, self.roles, text, self.pool)
        return got, m


def make_visit_stub(vis, vimage, counter):
    def stub(machine, args):
        out, ptr, ln = args[0], args[1], args[2]
        text = bytes(machine.load(ptr + k, 1) for k in range(ln))
        got, m = vis.run(vimage, text)
        counter[0] += 1
        if got[0] == 'ok':
            machine.store(out, 0, 1)
            machine.store(out + 1, got[1], 1)
        else:
            site, key, cargs = m.calls[-1]
            shown = bytes(m.load(cargs[0] + k, 1) for k in range(cargs[1]))
            machine.events.append(('unknown', shown, cargs[2], cargs[3]))
            machine.store(out, 1, 1)
            machine.store(out + 8, ERR_VIS | ln, 8)
        return out
    return stub


def bind_reader(rows, spec, vis, vimage, counter):
    entry, kind, fam, visitor, code, invalid, finish = spec
    slots = []
    for r in rows:
        if r.op == 'callslot' and r.rm[4] not in slots:
            slots.append(r.rm[4])
    if len(slots) != 2 or PARSE_SLOT not in slots:
        raise Reject('body 0x%x does not call the string parser slot and one panic slot' % entry)
    parse = PARSE_SLOT
    panic = [s for s in slots if s != PARSE_SLOT][0]
    directs = sorted(set(r.target for r in rows if r.op == 'call'))
    want = sorted(t for t in (visitor, code, invalid, finish) if t is not None)
    if directs != want:
        raise Reject('direct callees of 0x%x differ from the expected roles' % entry)
    stubs = {('slot', parse): jr.stub_parse, code: jr.stub_code, finish: jr.stub_finish,
             visitor: make_visit_stub(vis, vimage, counter)}
    roles = [('slot:0x%x' % parse, 'parse_str'), ('slot:0x%x' % panic, 'unwrap_panic (unreachable: pos+1 is never 0)'),
             ('0x%x' % visitor, 'name_visitor_str_result'), ('0x%x' % code, 'code_error'),
             ('0x%x' % finish, 'error_finisher')]
    if invalid is not None:
        stubs[invalid] = jr.stub_invalid
        roles.append(('0x%x' % invalid, 'invalid_type'))
    return stubs, sorted(roles)


# ---------------------------------------------------------------- reconstruction

class Spec(jr.Spec):
    """Reader parameters plus the name classifier; negative controls change one at a time."""
    names = NAMES
    classifier = staticmethod(ev.recon_classify)

    def __init__(self, **kw):
        for k, v in kw.items():
            if not hasattr(Spec, k):
                raise Reject('unknown spec field %s' % k)
            setattr(self, k, v)


def recon(kind, buf, pos, pool, sp):
    """Outcome of one reader call: (tag, word, reader position, scratch word, events)."""
    n, evs, rpos, scratch = len(buf), [], pos, SENT
    is_ws = (lambda c: c in sp.ws) if sp.ws_everything_below is None else (lambda c: c <= sp.ws_everything_below)

    def code(c):
        evs.append(('code', c))
        return ERR_TAG, ERR_CODE | c, rpos, scratch, evs

    def finish(err):
        evs.append(('finish', err, rpos))
        return ERR_TAG, err | FIN, rpos, scratch, evs

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
            evs.append(('invalid', sp.expected))
            return finish(ERR_INV)
        return code(sp.brace_code if c == 0x7d else sp.other_code)
    rpos = i + 1
    if sp.clear_scratch:
        scratch = 0
    evs.append(('parse', scratch))
    res = jr.json_str(buf, i + 1)
    if res[0] == 'err':
        rpos = res[2]
        err = ERR_STR | STR_ERR[res[1]]
        if (kind == 'value' and sp.finish_parse_error_value) or (kind == 'key' and sp.finish_parse_error_key):
            return finish(err)
        return ERR_TAG, err, rpos, scratch, evs
    _, text, rpos, _ = res
    idx = sp.classifier(text, sp.names)
    if idx is None:
        evs.append(('unknown', text, pool, len(NAMES)))
        err = ERR_VIS | len(text)
        if sp.finish_unknown:
            return finish(err)
        return ERR_TAG, err, rpos, scratch, evs
    if kind == 'value':
        return idx, DATA_BASE, rpos, scratch, evs
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
    return idx, DATA_BASE, rpos, scratch, evs


def run_case(image, entry, stubs, buf, pos):
    mc = jr.Machine(image, stubs)
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
    return (mc.load(OUT_BASE, 1), mc.load(OUT_BASE + 8, 8), mc.load(DATA_BASE + 0x28, 8),
            mc.load(DATA_BASE + 0x10, 8), list(mc.events)), len(mc.trace)


# ---------------------------------------------------------------- case inputs

def utf8_ok(t):
    try:
        t.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def case_inputs(kind):
    """(buffer, start position) pairs: byte sweeps, whitespace runs, name mutations, positions, escapes."""
    seen, out = set(), []

    def add(buf, pos=0):
        if (buf, pos) not in seen:
            seen.add((buf, pos))
            out.append((buf, pos))
    suffix = b':' if kind == 'key' else b''
    tails = (b':', b' :', b'\t\n\r :', b'', b' ', b':x', b'x', b'\x0b:', b';', b'}', b'\r\n\t :  ', b': ', b'::')
    for b in range(256):
        add(bytes([b]) + b'"Deposit"' + suffix)
    syms = (9, 10, 13, 32, 0x0b, 0x0c, 0x00, 0x2c)
    prefixes = [b'']
    for width in range(2):
        prefixes += [p + bytes([s]) for p in [q for q in prefixes if len(q) == width] for s in syms]
    for p in prefixes:
        for tail in (b'"RequestedWithdrawal"' + suffix, b'"FinalizedValidatorSetUpdate"' + suffix, b''):
            add(p + tail)
    texts = [t for t in ev.visitor_inputs() if utf8_ok(t) and b'"' not in t and b'\\' not in t]
    for text in texts:
        add(b'"' + text + b'"' + suffix)
        add(b'"' + text)
    if kind == 'key':
        for text in texts[::3]:
            add(b'  "' + text + b'"\t:')
    for name in NAMES + (b'xyz',):
        for tail in tails:
            add(b'"' + name + b'"' + tail)
            add(b' \n"' + name + b'"' + tail)
    for name in NAMES:
        full = b' "' + name + b'" \t:'
        for pos in range(len(full) + 3):
            add(full, pos)
    for lit in (b'"\\u0044eposit"', b'"Deposi\\/t"', b'"Deposit\\"', b'"\\u00zz"', b'"\\n"', b'"\\x"', b'"\\u0100"',
                b'"a\x01b"', b'"Requested\\u0057ithdrawal"', b'"\\u0046inalizedWithdrawal"', b'"\\\\"', b'"\\', b'"\\u00',
                b'"Invalidated\\tWithdrawal"', b'"\\u0044\\u0065posit"', b'"Deposi\\u0074"',
                b'"RequestedValidatorSetUpdate\\u0045vent"', b'"FinalizedValidatorSetUpdat\\u0065"'):
        add(lit + suffix)
        add(b' ' + lit + b' ' + suffix)
    for tail in (b'}', b'  }', b'{', b'[', b'1', b'null', b'-', b'\\', b"'", b'\x7f', b'\xff', b'\x80'):
        add(tail)
    return out


# ---------------------------------------------------------------- census of visitor call sites

def visitor_call_census(data, recs):
    """Direct rel32 call sites of the ten merged name visitors: raw byte scan of .text, no disassembler."""
    secs = [s for s in elf_index.sections(data) if s['name'] == '.text' and s['type'] != 8]
    if len(secs) != 1:
        raise Reject('expected one .text')
    text = secs[0]
    tb = data[text['offset']:text['offset'] + text['size']]
    t0 = text['address']
    starts = [r['start'] for r in recs]
    byo = {r['start']: r for r in recs}
    wanted = set(VISITOR_ENTRIES)
    sites = []
    p = tb.find(b'\xe8')
    while p >= 0:
        if p + 5 <= len(tb):
            tgt = t0 + p + 5 + struct.unpack_from('<i', tb, p + 1)[0]
            if tgt in wanted:
                sites.append((t0 + p, tgt))
        p = tb.find(b'\xe8', p + 1)
    rows = []
    for va, tgt in sites:
        i = bisect.bisect_right(starts, va) - 1
        r = byo[starts[i]]
        if not r['start'] <= va < r['end']:
            raise Reject('call site 0x%x is outside every FDE' % va)
        rows.append((va, tgt, r['start'], r['end'] - r['start'], 'lsda' if r['lsda'] else 'none'))
    return rows


# ---------------------------------------------------------------- evidence assembly

def esc(b):
    return b.hex() if b else '-'


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def literal_rows(image, va, rows):
    out = []
    for r in rows:
        if r.op == 'movimm' and r.size == 8:
            out.append((va, r.va, 'whitespace_mask_imm64', '0x%x' % r.imm,
                        ','.join('%d' % b for b in range(64) if r.imm >> b & 1)))
        elif r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'reg':
            out.append((va, r.va, 'cmp_imm', '%d' % r.imm, '0x%x' % r.imm))
        elif r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'mem':
            out.append((va, r.va, 'cmp_mem_imm', '%d' % r.imm, '0x%x' % r.imm))
        elif r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size == 8:
            out.append((va, r.va, 'code_store', '%d' % r.imm, '0x%x' % r.imm))
        elif r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size == 1:
            out.append((va, r.va, 'result_tag_store', '%d' % r.imm, '0x%x' % r.imm))
        elif r.op == 'lea' and r.rm[5]:
            out.append((va, r.va, 'lea_rip', '0x%x' % r.rm[4], ''))
    return out


def reader_damage_sites(rows):
    """(label, address, replacement byte) for single-byte damage in one reader body"""
    sites = []
    cmp22 = [r for r in rows if r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'reg' and r.imm == 0x22]
    quote_cmp = cmp22[-1]
    mask = next(r for r in rows if r.op == 'movimm' and r.size == 8)
    sites.append(('mask_drops_tab', mask.va + 2 + 1, (mask.imm >> 8 & 0xff) ^ 0x02))
    sites.append(('mask_drops_space', mask.va + 2 + 4, 0x00))
    sites.append(('quote_compare', quote_cmp.va + quote_cmp.length - 1, 0x23))
    code_store = next(r for r in rows if r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size == 8)
    sites.append(('code_store_immediate', code_store.va + code_store.length - 8, (code_store.imm & 0xff) ^ 0x01))
    tag_store = next(r for r in rows if r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size == 1)
    sites.append(('error_tag_store', tag_store.va + tag_store.length - 1, ERR_TAG ^ 0x01))
    colon = [r for r in rows if r.op == 'cmp' and r.ext == 'imm' and r.imm == 0x3a]
    if colon:
        # the first compare with 0x3a is the bound guard of the whitespace bit test, the last one is the colon test
        sites.append(('colon_compare', colon[-1].va + colon[-1].length - 1, 0x3b))
    return sites


def visitor_damage_sites(rows):
    """damage inside the real visitor: length bound, the first literal immediate, the table base"""
    bound = next(r for r in rows if r.op == 'cmp' and r.ext == 'imm' and r.imm == ev.LENGTH_ROWS - 1)
    sites = [('length_bound', bound.va + bound.length - 1, ev.LENGTH_ROWS - 2)]
    bias = next(r for r in rows if r.op == 'lea' and not r.rm[5] and r.rm[4] == -ev.LENGTH_BIAS)
    sites.append(('length_bias', bias.va + bias.length - 1, (-(ev.LENGTH_BIAS + 1)) & 0xff))
    dwords = [r for r in rows if r.op == 'movimm' and r.size == 4 and all(0x20 <= c < 0x7f for c in r.imm.to_bytes(4, 'little'))]
    if dwords:
        r = dwords[0]
        sites.append(('first_dword_literal', r.va + r.length - 4, (r.imm & 0xff) ^ 0x01))
    return sites


def build(data, step=8):
    if hashlib.sha256(data).hexdigest() != SHA115 or jr.SHA115 != SHA115:
        raise Reject('input is not node #115')
    image = jr.PatchedImage(data)
    vimage = EvPatched(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = {r['start']: r for r in recs}
    census = visitor_call_census(data, recs)
    hosts = sorted(set(r[2] for r in census))
    for spec in BODIES:
        if spec[0] not in hosts:
            raise Reject('reader 0x%x does not call a name visitor' % spec[0])

    visitors = {}
    for va in sorted({b[3] for b in BODIES}):
        visitors[va] = VisitorBinding(vimage, va, by_start[va]['end'])

    functions, insn_rows, lit_rows, callee_rows = [], [], [], []
    plan, counter = [], [0]
    expecteds = {}
    for spec in BODIES:
        va, kind, fam, vis_va = spec[0], spec[1], spec[2], spec[3]
        rec = by_start[va]
        rows = jr.linear(image, va, rec['end'])
        leas = [r.rm[4] for r in rows if r.op == 'lea' and r.rm[5]]
        if len(leas) != (2 if kind == 'value' else 1):
            raise Reject('reader 0x%x has an unexpected rip-relative lea count' % va)
        expecteds[va] = leas[0] if kind == 'value' else 0
        stubs, roles = bind_reader(rows, spec, visitors[vis_va], vimage, counter)
        calls = sorted(set('0x%x' % r.target for r in rows if r.op == 'call') | set('slot:0x%x' % r.rm[4] for r in rows if r.op == 'callslot'))
        body = image.read(va, rec['end'] - va)
        functions.append(dict(entry='0x%x' % va, kind=kind, family=fam, fde_end='0x%x' % rec['end'], fde_bytes=rec['end'] - va,
                              decoded_instructions=len(rows), decoded_bytes=sum(r.length for r in rows),
                              lsda='none' if rec['lsda'] is None else '0x%x' % rec['lsda'],
                              visitor='0x%x' % vis_va, visitor_pool='0x%x' % visitors[vis_va].pool,
                              sha256=hashlib.sha256(body).hexdigest(), callees=','.join(calls)))
        for r in rows:
            insn_rows.append(('0x%x' % va, '0x%x' % r.va, r.length, r.raw.hex(), r.op, '' if r.target is None else '0x%x' % r.target))
        for lit in literal_rows(image, va, rows):
            lit_rows.append(('0x%x' % lit[0], '0x%x' % lit[1]) + lit[2:])
        for k, v in roles:
            callee_rows.append(('0x%x' % va, k, v))
        plan.append((va, kind, visitors[vis_va].pool, stubs, rows, vis_va))
    for vva, vb in sorted(visitors.items()):
        for r in vb.rows:
            insn_rows.append(('0x%x' % vva, '0x%x' % r.va, r.length, r.raw.hex(), r.op, '' if r.target is None else '0x%x' % r.target))
        functions.append(dict(entry='0x%x' % vva, kind='visitor', family=0, fde_end='0x%x' % by_start[vva]['end'],
                              fde_bytes=by_start[vva]['end'] - vva, decoded_instructions=len(vb.rows),
                              decoded_bytes=sum(r.length for r in vb.rows),
                              lsda='none' if by_start[vva]['lsda'] is None else '0x%x' % by_start[vva]['lsda'],
                              visitor='-', visitor_pool='0x%x' % vb.pool,
                              sha256=hashlib.sha256(vimage.read(vva, by_start[vva]['end'] - vva)).hexdigest(),
                              callees=','.join('0x%x' % t for t in vb.stubs)))

    mutations = [
        ('value', 'ws_adds_vtab', dict(ws=frozenset((9, 10, 13, 32, 0x0b)))),
        ('value', 'ws_drops_cr', dict(ws=frozenset((9, 10, 32)))),
        ('value', 'ws_drops_tab', dict(ws=frozenset((10, 13, 32)))),
        ('value', 'ws_drops_space', dict(ws=frozenset((9, 10, 13)))),
        ('value', 'ws_everything_below_quote', dict(ws_everything_below=0x21)),
        ('both', 'classify_prefix', dict(classifier=lambda t, n: ev.wrong_prefix(t, n))),
        ('both', 'classify_casefold', dict(classifier=lambda t, n: ev.wrong_casefold(t, n))),
        ('both', 'classify_swap_withdrawals', dict(classifier=lambda t, n: ev.wrong_swap(t, n))),
        ('both', 'classify_alphabetical_tags', dict(classifier=lambda t, n: ev.wrong_alphabetical(t, n))),
        ('both', 'classify_first4_only', dict(classifier=lambda t, n: ev.wrong_first4(t, n))),
        ('both', 'classify_last16_only', dict(classifier=lambda t, n: ev.wrong_last16(t, n))),
        ('both', 'classify_length_only', dict(classifier=lambda t, n: ev.wrong_length_only(t, n))),
        ('both', 'classify_first_byte_only', dict(classifier=lambda t, n: ev.wrong_first_byte(t, n))),
        ('both', 'classify_25_row_table', dict(classifier=lambda t, n: ev.wrong_short_table(t, n))),
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

    inputs = {k: case_inputs(k) for k in ('value', 'key')}
    case_rows, path_counts, matches, total = [], {}, 0, 0
    sha = hashlib.sha256()
    mut_counts = {name: 0 for _, name, _ in mutations}
    mut_total = {name: 0 for _, name, _ in mutations}
    outcome_counts = {}
    accepted = 0
    for va, kind, pool, stubs, rows, vis_va in plan:
        for idx, (buf, pos) in enumerate(inputs[kind]):
            got, steps = run_case(image, va, stubs, buf, pos)
            want = recon(kind, buf, pos, pool, Spec(expected=expecteds[va]))
            same = got == want
            total += 1
            matches += same
            tag, word, rpos, scratch, evs = got
            if tag < ERR_TAG:
                label = 'ok%d' % tag
                accepted += 1
            else:
                names = [e[0] for e in evs]
                label = 'err:' + '+'.join(names[-2:] if names and names[-1] == 'finish' else names[-1:])
            key = (va, steps, label)
            path_counts[key] = path_counts.get(key, 0) + 1
            outcome_counts[(va, label)] = outcome_counts.get((va, label), 0) + 1
            for scope, name, kw in mutations:
                if scope in (kind, 'both'):
                    mut_total[name] += 1
                    mut_counts[name] += got != recon(kind, buf, pos, pool, Spec(**{'expected': expecteds[va], **kw}))
            line = '\t'.join(('0x%x' % va, esc(buf), str(pos), str(tag), '0x%016x' % word, str(rpos), '0x%x' % scratch,
                              ';'.join(e[0] + ('=' + esc(e[1]) if e[0] == 'unknown' else '=%d' % e[1] if e[0] in ('code', 'parse') else '')
                                       for e in evs) or '-',
                              'match' if same else 'MISMATCH')) + '\n'
            sha.update(line.encode('ascii'))
            if idx % step == 0 or not same:
                case_rows.append(line)

    # reader code damage: single damaged bytes must change the observable outcome on the battery
    damage_rows, dam_total, dam_caught = [], 0, 0
    for va, kind, pool, stubs, rows, vis_va in plan:
        battery = inputs[kind][::13]
        for label, addr, newbyte in reader_damage_sites(rows):
            bad = jr.PatchedImage(data, {addr: newbyte})
            hits = 0
            for buf, pos in battery:
                try:
                    got, _ = run_case(bad, va, stubs, buf, pos)
                    hits += got != recon(kind, buf, pos, pool, Spec(expected=expecteds[va]))
                except Reject:
                    hits += 1
            dam_total += 1
            dam_caught += hits > 0
            damage_rows.append(('0x%x' % va, label, '0x%x' % addr, '0x%02x' % newbyte, len(battery), hits))
    # visitor code damage: the damaged visitor is called by the reader, outcomes must leave the reconstruction
    for vva, vb in sorted(visitors.items()):
        for va, kind, pool, stubs, rows, vis_va in plan:
            if vis_va != vva or kind != 'value':
                continue
            battery = inputs[kind][::5]
            for label, addr, newbyte in visitor_damage_sites(vb.rows):
                bad_v = EvPatched(data, {addr: newbyte})
                bad_stubs = dict(stubs)
                bad_stubs[vva] = make_visit_stub(vb, bad_v, [0])
                hits = 0
                for buf, pos in battery:
                    try:
                        got, _ = run_case(image, va, bad_stubs, buf, pos)
                        hits += got != recon(kind, buf, pos, pool, Spec(expected=expecteds[va]))
                    except Reject:
                        hits += 1
                dam_total += 1
                dam_caught += hits > 0
                damage_rows.append(('0x%x' % vva, 'visitor_' + label, '0x%x' % addr, '0x%02x' % newbyte, len(battery), hits))

    # out-of-range inputs: a start position past the end must report EOF; a non-FDE address must be rejected
    range_rows, range_total = [], 0
    for va, kind, pool, stubs, rows, vis_va in plan:
        for pos in (0, 1, 2, 3, base.MASK, 1 << 63):
            got, _ = run_case(image, va, stubs, b'  ', pos)
            want = recon(kind, b'  ', pos, pool, Spec())
            if got != want:
                raise Reject('out-of-range position %d mismatch at 0x%x' % (pos, va))
            range_rows.append(('0x%x' % va, pos, got[0], '0x%x' % got[1], got[2]))
        range_total += 1
    bogus_rejected = 0
    for bogus in (0x1e20b31, 0x1dee080, 0x3fb9fa1, 0x3f7c000):
        range_total += 1
        bogus_rejected += bogus not in by_start
    if bogus_rejected != 4:
        raise Reject('a mid-function address is an FDE start')

    negatives = []
    for scope, name, kw in mutations:
        negatives.append(('reconstruction', name, mut_counts[name], mut_total[name]))
    for label in damage_rows:
        negatives.append(('code_damage', '%s_in_%s' % (label[1], label[0]), label[5], label[4]))
    negatives.append(('range', 'positions_past_end_and_non_fde', range_total, range_total))
    neg_total = len(negatives)
    neg_caught = sum(1 for _, _, n, _ in negatives if n > 0)
    paths = [('0x%x' % va, steps, label, n) for (va, steps, label), n in sorted(path_counts.items())]
    outcomes = [('0x%x' % va, label, n) for (va, label), n in sorted(outcome_counts.items())]
    summary = dict(
        target='node115', sha256=SHA115, component='bridge', task='none',
        readers=['0x%x' % b[0] for b in BODIES], visitors=['0x%x' % v for v in sorted(visitors)],
        names=[n.decode() for n in NAMES], whitespace_mask='0x%x' % WS_MASK,
        invalid_type_description_pools={'0x%x' % k: '0x%x' % v for k, v in sorted(expecteds.items()) if v},
        visitor_call_sites=len(census), visitor_hosts=len(hosts), hosts_decoded_here=len(BODIES),
        cases=total, case_matches=matches, accepted_cases=accepted, real_visitor_runs=counter[0],
        case_table_sha256=sha.hexdigest(), case_table_every=step,
        negative_controls=neg_total, negative_detected=neg_caught,
        distinct_paths=len(paths), decoded_instructions=len(insn_rows),
        reconstruction_matches_all=matches == total,
        mutations={n: mut_counts[n] for _, n, _ in mutations},
        code_damage={'%s_in_%s' % (r[1], r[0]): r[5] for r in damage_rows},
    )
    return dict(functions=functions, instructions=insn_rows, literals=lit_rows, callees=callee_rows, census=census,
                cases=case_rows, paths=paths, outcomes=outcomes, negatives=negatives, damage=damage_rows,
                range=range_rows, summary=summary)


def render(result):
    f = result['functions']
    keys = list(f[0].keys())
    s = result['summary']
    measure = dict(cases=s['cases'], negative_controls=s['negative_controls'], negative_detected=s['negative_detected'])
    decoded = {b[0] for b in BODIES}
    return {
        'functions.tsv': tsv(keys, [[row[k] for k in keys] for row in f]),
        'instructions.tsv': tsv(('function', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'callees.tsv': tsv(('function', 'callee', 'role'), result['callees']),
        'literals.tsv': tsv(('function', 'va', 'form', 'value', 'detail'), result['literals']),
        'visitor-call-sites.tsv': tsv(('call_site', 'visitor', 'host', 'host_bytes', 'host_lsda', 'decoded_here'), [
            ('0x%x' % a, '0x%x' % b, '0x%x' % c, d, e, 'yes' if c in decoded else 'no') for a, b, c, d, e in result['census']]),
        'cases.tsv': tsv(('function', 'input_hex', 'start', 'result_tag', 'result_word', 'reader_pos', 'scratch', 'calls', 'verdict'),
                         [c.rstrip('\n').split('\t') for c in result['cases']]),
        'paths.tsv': tsv(('function', 'steps', 'outcome', 'inputs'), result['paths']),
        'outcomes.tsv': tsv(('function', 'outcome', 'inputs'), result['outcomes']),
        'negative-controls.tsv': tsv(('family', 'control', 'detections', 'cases'), result['negatives']),
        'code-damage.tsv': tsv(('function', 'site', 'address', 'new_byte', 'battery', 'detections'), result['damage']),
        'range.tsv': tsv(('function', 'start', 'tag', 'word', 'reader_pos'), result['range']),
        'summary.json': json.dumps(s, indent=2, sort_keys=True) + '\n',
        'measure.json': json.dumps(measure, indent=2, sort_keys=True) + '\n',
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
    print('cases %d/%d, negatives %d/%d' % (s['case_matches'], s['cases'], s['negative_detected'], s['negative_controls']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
