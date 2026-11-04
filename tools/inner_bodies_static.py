#!/usr/bin/env python3
"""Pin the two RE-006 inner bodies and the B-wrapper producer helpers.

Question (RE-006 packet after innermost-records #2598): (A) who produces
the records inside the two inner bodies left as boundaries there --
0x2bbbba0 (3 calls from sub-lookup 0x2bb7270) and 0x2bbd0b0 (3 calls
from helper_s3a 0x2c62820) -- and (B) what the caller FDEs' own
lookup-phase inputs are one level up: the queries and collections
consumed by the helpers that stand behind the B-wrapper caller-frame
records in #2598's shape X/Y (0x2761cd0, 0x2761fe0, 0x5490660,
0x5492440, 0x5630000, plus 0x2aae850, which #2598's own census pairs
with the bwc_a1 first site).

Method: the authenticated node-115 ELF is decoded with the pinned
objdump wrapper from foundation_millis (via innermost_records_static).
Every call site is recorded with the last writer of each argument
register in the rows before it; every frame buffer's production is the
census of direct stores and memcpy destinations into its range before
the call.  GOT slot references are resolved from the raw instruction
bytes (ff15/ff25/rip-relative loads), never from objdump comments.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from foundation_millis import decode_export as _foundation_decode  # noqa: E402

MEMCPY_SLOT = 0x64DF508

PACKET_DIR = ROOT / 'research' / 'work-items' / 'RE-006-node115-inner-bodies'
UPSTREAM_MAIN = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
NODE_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
NODE_SIZE = 105896032

DECODE = 0x24CB0A0
SIBLING = 0x35BF460
FALLBACK = 0x4556410
CURSOR_NEXT = 0x2388380
DIV_SLOT = 0x64DFAF8
GATE_SLOT = 0x64E71B8
PANIC_SLOT = 0x64E4EA8
WRAPPER_TARGETS = (0x2A892F0, 0x55A03C0, 0x55A05D0)

BODIES = {
    'inner_ca': (0x2BBBBA0, 0x2BBC74D, True),
    'inner_s3': (0x2BBD0B0, 0x2BBDB9A, True),
    'sublookup_ca': (0x2BB7270, 0x2BB9893, False),
    'helper_s3a': (0x2C62820, 0x2C64862, False),
    'help_cd0': (0x2761CD0, 0x2761FD6, True),
    'help_fe0': (0x2761FE0, 0x27622E6, True),
    'help_e850': (0x2AAE850, 0x2AAEA38, True),
    'help_660': (0x5490660, 0x549118E, True),
    'help_440': (0x5492440, 0x5493013, True),
    'help_563': (0x5630000, 0x563034A, True),
    'bwc_a1': (0x2A84E60, 0x2A8829E, False),
    'bwc_a2': (0x2A8BC40, 0x2A8BDF1, True),
    'bwc_a3': (0x2C3E8B0, 0x2C3EDA8, True),
    'bwc_b1': (0x54D57B0, 0x54DB474, False),
    'bwc_b2': (0x5582180, 0x5585283, False),
    'bwc_b3': (0x55983F0, 0x55988E8, True),
    'bwc_b4': (0x5609FB0, 0x560A161, True),
    'bwc_c1': (0x54CFA90, 0x54D57A4, False),
    'bwc_c2': (0x5585290, 0x5588393, False),
    'bwc_c3': (0x559C260, 0x559C758, True),
    'bwc_c4': (0x5609DF0, 0x5609FA1, True),
}

INNER_OF_CALLER = {'sublookup_ca': 'inner_ca', 'helper_s3a': 'inner_s3'}
RESULT_DISP = {'sublookup_ca': 0x140, 'helper_s3a': 0xA0}

PRODUCER_SITES = [
    # caller, producer call, helper body, wrapper record disp (#2598)
    ('bwc_a1', 0x2A8666B, 'help_e850', 0xD0),
    ('bwc_a1', 0x2A86BA7, 'help_fe0', 0xD0),
    ('bwc_a2', 0x2A8BD14, 'help_fe0', 0x190),
    ('bwc_a3', 0x2C3EB8E, 'help_cd0', 0x1D0),
    ('bwc_b1', 0x54D7AB5, 'help_563', 0xA0),
    ('bwc_b2', 0x558374B, 'help_563', 0xB0),
    ('bwc_b2', 0x5583C87, 'help_440', 0xB0),
    ('bwc_b4', 0x560A084, 'help_440', 0x190),
    ('bwc_c1', 0x54D1DD8, 'help_563', 0xB0),
    ('bwc_c2', 0x558685B, 'help_563', 0xB0),
    ('bwc_c2', 0x5586D97, 'help_440', 0xB0),
    ('bwc_c4', 0x5609EC4, 'help_440', 0x190),
    ('bwc_b3', 0x55986CE, 'help_660', 0x1D0),
    ('bwc_c3', 0x559C53E, 'help_660', 0x1D0),
]
INSPECTORS = ('help_e850', 'help_563')
# registers through which each producer helper reads its query (rdx) and
# context (rsi) arguments in its prologue, after any register save
QUERY_REGS = {'help_cd0': ('rdx',), 'help_fe0': ('rdx',),
              'help_660': ('rdx', 'rbx'), 'help_440': ('rdx',),
              'help_e850': ('rdi',), 'help_563': ('rdi',)}
CONTEXT_REGS = {'help_cd0': (), 'help_fe0': ('rax',),
                'help_660': (), 'help_440': ('rsi',)}

_ALIASES = {'rax': ('rax', 'eax', 'ax', 'al'), 'rbx': ('rbx', 'ebx', 'bx', 'bl'),
            'rcx': ('rcx', 'ecx', 'cx', 'cl'), 'rdx': ('rdx', 'edx', 'dx', 'dl'),
            'rsi': ('rsi', 'esi', 'si', 'sil'), 'rdi': ('rdi', 'edi', 'di', 'dil'),
            'rbp': ('rbp', 'ebp', 'bp', 'bpl'), 'rsp': ('rsp', 'esp', 'sp', 'spl')}
for _i in range(8, 16):
    _ALIASES[f'r{_i}'] = (f'r{_i}', f'r{_i}d', f'r{_i}w', f'r{_i}b')
_MNEM_RE = re.compile(
    r'^(lea|mov|movabs|xor|movzbl|movzwl|movsbl|movswl|movslq|movsbq|'
    r'movzbq|movzwq|add|sub|imul|and|or|shl|shr|sar|neg|not|pop|inc|dec|'
    r'cdqe|movupd|movups|movdqa|movdqu|movaps|movapd)\s+(.*)$')


def _last_writer(rows, reg, before, window=16):
    names = _ALIASES.get(reg, (reg,))
    addrs = [a for a in sorted(rows) if a < before][-window:]
    for addr in reversed(addrs):
        text = rows[addr][1]
        match = _MNEM_RE.match(text)
        if not match:
            continue
        parts = [p.strip() for p in match.group(2).split(',')]
        dst = parts[-1].lstrip('%')
        if dst not in names:
            continue
        src = parts[0] if len(parts) > 1 else ''
        out = {'addr': _hx(addr), 'text': text}
        if match.group(1) == 'lea':
            found = re.match(r'^(-?0x[0-9a-f]+)\(%rsp\)$', src)
            if found:
                out.update(form='lea_rsp', disp=int(found.group(1), 16))
            else:
                out.update(form='lea_other', src=src)
            return out
        if src.startswith('%'):
            return dict(out, form='reg', reg=src[1:])
        found = re.match(r'^(-?0x[0-9a-f]+)\(%rsp\)$', src)
        if found:
            return dict(out, form='load_rsp', disp=int(found.group(1), 16))
        found = re.match(r'^\$(-?0x[0-9a-f]+|\d+)$', src)
        if found:
            return dict(out, form='imm', value=int(found.group(1), 0))
        if match.group(1) == 'xor' and src == '%' + dst:
            return dict(out, form='imm', value=0)
        return dict(out, form='other', src=src)
    return None


def _bindings(rows, call, regs=('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'),
              window=16):
    return {reg: _last_writer(rows, reg, call, window) for reg in regs}


def _slot_refs_all(rows):
    out = {}
    for addr in sorted(rows):
        raw, _text = rows[addr]
        blob = bytes.fromhex(raw)
        if raw.startswith('ff15') and len(blob) == 6:
            out[addr] = ('call', addr + 6 + struct.unpack('<i', blob[2:6])[0])
        elif raw.startswith('ff25') and len(blob) == 6:
            out[addr] = ('jmp', addr + 6 + struct.unpack('<i', blob[2:6])[0])
        elif len(blob) == 7 and blob[0] in (0x48, 0x4C) and blob[1] == 0x8B \
                and (blob[2] & 0xC7) == 0x05:
            out[addr] = ('load', addr + 7 + struct.unpack('<i', blob[3:7])[0])
    return out


def _direct_calls(rows):
    return {_hx(a): _hx(_e8_target(rows, a)) for a in sorted(rows)
            if rows[a][1].startswith('call') and rows[a][0].startswith('e8')}


def _memcpy_sites(rows):
    calls, loads = _slot_refs(rows, MEMCPY_SLOT)
    out = set(calls)
    loadset = set(loads)
    for addr in sorted(rows):
        match = re.match(r'^call\s+\*%(\w+)$', rows[addr][1])
        if match:
            writer = _last_writer(rows, match.group(1), addr, 40)
            if writer and int(writer['addr'], 16) in loadset:
                out.add(addr)
    return sorted(out)


def _memcpy_bindings(rows, call):
    binds = _bindings(rows, call, ('rdi', 'rsi', 'rdx'), 14)
    def simp(bind):
        if bind is None:
            return None
        if bind['form'] == 'lea_rsp':
            return bind['disp']
        if bind['form'] == 'imm':
            return bind['value']
        if bind['form'] == 'reg':
            return 'reg:' + bind['reg']
        return bind['form']
    return {'dst': simp(binds['rdi']), 'src': simp(binds['rsi']),
            'size': simp(binds['rdx'])}


def _production(rows, disp, size, cutoff, since=None):
    stores = [_hx(a) for a, d, b, _w, _t in _stores(rows)
              if b == 'rsp' and disp <= d < disp + size and a < cutoff
              and (since is None or a > since)]
    mc = []
    for addr in _memcpy_sites(rows):
        if addr >= cutoff or (since is not None and addr <= since):
            continue
        binds = _memcpy_bindings(rows, addr)
        if isinstance(binds['dst'], int) and disp <= binds['dst'] < disp + size:
            mc.append({'addr': _hx(addr), 'dst': binds['dst'],
                       'src': binds['src'], 'size': binds['size']})
    return {'stores': stores, 'memcpy_into': mc}


def _prev_call(rows, cutoff):
    prev = None
    for addr in sorted(rows):
        if addr >= cutoff:
            break
        raw, text = rows[addr]
        if text.startswith('call'):
            prev = addr
    return prev


def _last_store(rows, disp, cutoff):
    cand = [(a, t) for a, d, b, _w, t in _stores(rows)
            if b == 'rsp' and d == disp and a < cutoff]
    if not cand:
        return None
    addr, text = cand[-1]
    return {'addr': _hx(addr), 'text': text}


def _store_source_row(rows, store_addr):
    """The row that produced the value a store writes (its source register's
    last writer before the store), one level."""
    text = rows[store_addr][1]
    match = re.match(r'^mov\w*\s+%(\w+),', text)
    if not match:
        return None
    writer = _last_writer(rows, match.group(1), store_addr, 6)
    return writer


def _inner_body(rows):
    saves = {}
    for addr in sorted(rows)[:14]:
        match = re.match(r'^mov\s+%r(di|si|dx|cx|8|9),0x([0-9a-f]+)\(%rsp\)$',
                         rows[addr][1])
        if match:
            saves['r' + match.group(1)] = {'addr': _hx(addr),
                                           'disp': int(match.group(2), 16)}
    direct = _direct_calls(rows)
    slots = _slot_refs_all(rows)
    stores = _stores(rows)
    by_base = {}
    for _a, _d, base, _w, _t in stores:
        by_base[base] = by_base.get(base, 0) + 1
    non_rsp = [[_hx(a), d, b, w] for a, d, b, w, _t in stores if b != 'rsp']
    # exit blocks: the success block stores six qwords + tag 0 through the
    # saved rdi; the failure block stores a code byte + tag 1.
    addrs = sorted(rows)
    success = None
    failure = None
    arms = {}
    for i, addr in enumerate(addrs):
        text = rows[addr][1]
        match = re.match(r'^movb\s+\$0x0,\(%(\w+)\)$', text)
        if match:
            base = match.group(1)
            found = []
            pointer_load = None
            for prev in reversed(addrs[max(0, i - 24):i]):
                ptext = rows[prev][1]
                store = re.match(
                    r'^mov\s+%\w+,0x([0-9a-f]+)\(%' + base + r'\)$', ptext)
                if store:
                    found.append([_hx(prev), int(store.group(1), 16), 8])
                    continue
                if re.match(r'^mov\s+0x[0-9a-f]+\(%rsp\),%' + base + r'$',
                            ptext):
                    pointer_load = _hx(prev)
                    break
            success = {'tag_store': _hx(addr), 'tag_value': 0,
                       'pointer_load': pointer_load,
                       'stores': sorted(found, key=lambda s: s[1])}
        match = re.match(r'^movb\s+\$0x1,\(%(\w+)\)$', text)
        if match:
            base = match.group(1)
            failure = {'tag_store': _hx(addr), 'tag_value': 1}
            for prev in reversed(addrs[max(0, i - 6):i]):
                ptext = rows[prev][1]
                if re.match(r'^mov\s+%cl,0x1\(%' + base + r'\)$', ptext):
                    failure['code_store'] = _hx(prev)
                if re.match(r'^mov\s+0x[0-9a-f]+\(%rsp\),%' + base + r'$',
                            ptext):
                    failure['pointer_load'] = _hx(prev)
                    break
        match = re.match(r'^mov\s+\$(0x[0-9a-f]+),%cl$', text)
        if match:
            arms[_hx(addr)] = int(match.group(1), 16)
    search = {'cursor_next': [], 'decode': [], 'sibling': [], 'fallback': []}
    for addr, target in direct.items():
        tval = int(target, 16)
        if tval == CURSOR_NEXT:
            search['cursor_next'].append(addr)
        elif tval == DECODE:
            search['decode'].append(addr)
        elif tval == SIBLING:
            search['sibling'].append(addr)
        elif tval == FALLBACK:
            search['fallback'].append(addr)
    return {
        'argument_saves': saves,
        'direct_calls': direct,
        'slot_refs': {_hx(a): [kind, _hx(slot)]
                      for a, (kind, slot) in sorted(slots.items())},
        'memcpy_slot_refs': [_hx(a) for a, (_k, slot) in sorted(slots.items())
                             if slot == MEMCPY_SLOT],
        'store_census': {'total': len(stores), 'by_base': by_base,
                         'non_rsp_stores': non_rsp},
        'exit': {'success': success, 'failure': failure,
                 'failure_arms': arms},
        'search_calls': search,
    }


def _inner_sites(caller, rows):
    inner = INNER_OF_CALLER[caller]
    start, end, _e = BODIES[inner]
    result_disp = RESULT_DISP[caller]
    sites = []
    for call in [a for a in sorted(rows)
                 if rows[a][1].startswith('call')
                 and rows[a][0].startswith('e8')
                 and _e8_target(rows, a) == start]:
        binds = _bindings(rows, call)
        after = [a for a in sorted(rows) if a > call]
        tag = {'addr': _hx(after[0]), 'text': rows[after[0]][1]}
        reads = []
        for addr in after[:60]:
            match = re.match(r'^mov\w*\s+(0x[0-9a-f]+)\(%rsp\),',
                             rows[addr][1])
            if match:
                disp = int(match.group(1), 16)
                if result_disp <= disp < result_disp + 0x38:
                    reads.append([_hx(addr), disp])
        site = {'caller': caller, 'call': _hx(call), 'target': inner,
                'bindings': binds, 'tag_test': tag, 'payload_reads': reads}
        # shared argument origins: the prologue store behind each frame slot
        origins = {}
        for reg in ('rsi', 'rcx', 'rdx'):
            bind = binds[reg]
            if bind and bind['form'] == 'load_rsp':
                store = _last_store(rows, bind['disp'], call)
                origins[reg] = {
                    'slot_disp': bind['disp'], 'store': store,
                    'source_row': _store_source_row(
                        rows, int(store['addr'], 16)) if store else None}
        site['origins'] = origins
        if binds['r9'] is None:
            writer = _last_writer(rows, 'r9', call, 100000)
            site['r9_last_writer_in_fde'] = writer
        if binds['rdx'] and binds['rdx']['form'] == 'reg' \
                and binds['rdx']['reg'] == 'r10':
            prelude = int(binds['rdi']['addr'], 16)
            jumps = [_hx(a) for a in sorted(rows)
                     if a < call and f'{prelude:#x}' in rows[a][1]
                     and rows[a][1].split()[0].startswith('j')]
            reloads = [_hx(a) for a in sorted(rows)
                       if a < call and rows[a][1].startswith('mov')
                       and rows[a][1].rstrip().endswith(',%r10')
                       and '(%rsp)' in rows[a][1]]
            site['rdx_r10'] = {'prelude_block': _hx(prelude),
                               'jump_sources': jumps,
                               'frame_reloads': reloads}
        if binds['rsi'] and binds['rsi']['form'] == 'lea_rsp':
            disp = binds['rsi']['disp']
            site['descriptor_production'] = _production(rows, disp, 0x28, call)
            phase = None
            for addr in sorted(rows):
                if addr >= call:
                    break
                if rows[addr][1].startswith('call') \
                        and rows[addr][0].startswith('e8'):
                    other = _bindings(rows, addr)
                    if other['rsi'] and other['rsi'].get('disp') == disp \
                            and other['rsi'].get('addr'):
                        gap = addr - int(other['rsi']['addr'], 16)
                        if phase is None or gap < phase[0]:
                            phase = (gap, {'addr': _hx(addr),
                                           'target': _hx(_e8_target(rows, addr)),
                                           'bindings': other})
            site['descriptor_phase_call'] = phase[1] if phase else None
        sites.append(site)
    return sites


def _helper(rows, name):
    stores = _stores(rows)
    by_base = {}
    for addr, disp, base, width, _t in stores:
        if base != 'rsp':
            by_base.setdefault(base, []).append([_hx(addr), disp, width])
    first_call = min(a for a in sorted(rows) if rows[a][1].startswith('call'))
    reads = {'query': set(), 'context': set()}
    load_re = re.compile(
        r'^(?:mov|movzbl|movzwl|movsbl|movswl|movslq|movupd|movups|'
        r'movdqa|movdqu|lea)\w*\s+(-?0x[0-9a-f]+|0)?\(%(\w+)\),')
    for addr in sorted(rows):
        if addr >= first_call:
            break
        match = load_re.match(rows[addr][1])
        if not match:
            continue
        off = int(match.group(1) or '0', 16)
        if match.group(2) in QUERY_REGS.get(name, ()):
            reads['query'].add(off)
        if match.group(2) in CONTEXT_REGS.get(name, ()):
            reads['context'].add(off)
    memcpys = [{'addr': _hx(a), 'bindings': _memcpy_bindings(rows, a)}
               for a in _memcpy_sites(rows)]
    return {
        'store_total': len(stores),
        'stores_by_non_rsp_base': by_base,
        'direct_calls': _direct_calls(rows),
        'slot_refs': {_hx(a): [kind, _hx(slot)]
                      for a, (kind, slot) in sorted(_slot_refs_all(rows).items())},
        'memcpy_calls': memcpys,
        'prologue_reads': {'query': sorted(reads['query']),
                           'context': sorted(reads['context'])},
        'first_call': _hx(first_call),
    }


def _producer_site(rows, caller, call, helper, record_disp):
    binds = _bindings(rows, call)
    site = {'caller': caller, 'call': _hx(call), 'helper': helper,
            'record_disp': record_disp, 'bindings': binds}
    # the wrapper call that consumes the record after this producer call
    for addr in sorted(rows):
        if addr <= call:
            continue
        if rows[addr][1].startswith('call') and rows[addr][0].startswith('e8') \
                and _e8_target(rows, addr) in WRAPPER_TARGETS:
            wbinds = _bindings(rows, addr)
            site['wrapper_call'] = {
                'addr': _hx(addr), 'target': _hx(_e8_target(rows, addr)),
                'r8': wbinds['r8']}
            break
    prev = _prev_call(rows, call)
    if helper in INSPECTORS:
        head = []
        for addr, disp, base, _w, text in _stores(rows):
            if base == 'rsp' and record_disp <= disp < record_disp + 0x70 \
                    and prev < addr < call:
                head.append({'addr': _hx(addr), 'disp': disp, 'text': text})
        site['head_copy_stores'] = head
        preceding = {'addr': _hx(prev),
                     'target': _hx(_e8_target(rows, prev))
                     if rows[prev][0].startswith('e8') else None,
                     'bindings': _bindings(rows, prev)}
        site['preceding_call'] = preceding
        if preceding['bindings']['rdi'] and \
                preceding['bindings']['rdi']['form'] == 'lea_rsp':
            out_disp = preceding['bindings']['rdi']['disp']
            site['preceding_out_disp'] = out_disp
            if preceding['bindings']['rsi'] and \
                    preceding['bindings']['rsi']['form'] == 'load_rsp':
                sdisp = preceding['bindings']['rsi']['disp']
                store = _last_store(rows, sdisp, prev)
                site['preceding_rsi_origin'] = {
                    'slot_disp': sdisp, 'store': store,
                    'source_row': _store_source_row(
                        rows, int(store['addr'], 16)) if store else None}
            if preceding['bindings']['rdx'] and \
                    preceding['bindings']['rdx']['form'] == 'lea_rsp':
                qdisp = preceding['bindings']['rdx']['disp']
                site['preceding_query_production'] = _production(
                    rows, qdisp, 0x68, prev)
        return site
    out_disp = binds['rdi']['disp']
    site['out_disp'] = out_disp
    if binds['rdx'] and binds['rdx']['form'] == 'lea_rsp':
        qdisp = binds['rdx']['disp']
        site['query_production'] = {
            'all': _production(rows, qdisp, 0x68, call),
            'since_prev_call': _production(rows, qdisp, 0x68, call, since=prev),
            'prev_call': _hx(prev)}
    if binds['rsi']:
        rsi = binds['rsi']
        if rsi['form'] == 'load_rsp':
            store = _last_store(rows, rsi['disp'], call)
            site['ctx_production'] = {
                'form': 'frame_slot', 'slot_disp': rsi['disp'],
                'store_count': len([1 for a, d, b, _w, _t in _stores(rows)
                                    if b == 'rsp' and d == rsi['disp']
                                    and a < call]),
                'last_store': store,
                'source_row': _store_source_row(
                    rows, int(store['addr'], 16)) if store else None}
        elif rsi['form'] == 'reg':
            site['ctx_production'] = {
                'form': 'register',
                'writer': _last_writer(rows, rsi['reg'], call, 100000)}
        elif rsi['form'] == 'lea_other':
            base = re.search(r'\((%\w+)\)', rsi['src'])
            site['ctx_production'] = {
                'form': 'lea_other', 'src': rsi['src'],
                'base_writer': _last_writer(
                    rows, base.group(1)[1:], call, 100000) if base else None}
    # record transfer: tag/byte loads of the produced record, memcpy chain
    after = [a for a in sorted(rows) if a > call][:80]
    tag = byte = None
    for addr in after:
        match = re.match(r'^mov\w*\s+(0x[0-9a-f]+)\(%rsp\),', rows[addr][1])
        if match:
            disp = int(match.group(1), 16)
            if disp == out_disp and tag is None:
                tag = _hx(addr)
            if disp == out_disp + 8 and byte is None:
                byte = _hx(addr)
    chain = []
    for addr in _memcpy_sites(rows):
        if addr <= call:
            continue
        binds_mc = _memcpy_bindings(rows, addr)
        if binds_mc['src'] == out_disp + 9 or binds_mc['dst'] == record_disp + 9:
            chain.append({'addr': _hx(addr), 'bindings': binds_mc})
    final = {'tag_store': None, 'byte_store': None}
    for addr, disp, base, _w, _t in _stores(rows):
        if base == 'rsp' and addr > call:
            if disp == record_disp and final['tag_store'] is None:
                final['tag_store'] = _hx(addr)
            if disp == record_disp + 8 and final['byte_store'] is None:
                final['byte_store'] = _hx(addr)
    site['record_transfer'] = {'tag_load': tag, 'byte_load': byte,
                               'tail_memcpys': chain,
                               'final_record_stores': final}
    return site


def _hx(value):
    return f'0x{value:x}'


def _section_bytes(data, secs, start, end):
    for sec in secs:
        if sec['type'] != 8 and sec['address'] <= start \
                and end <= sec['address'] + sec['size']:
            off = sec['offset'] + (start - sec['address'])
            return data[off:off + end - start]
    raise AssertionError(f'no file-backed section covers {start:#x}..{end:#x}')


def _digest(data, secs, start, end):
    return hashlib.sha256(_section_bytes(data, secs, start, end)).hexdigest()


_LINE_RE = re.compile(r'^\s*([0-9a-f]+):\t([0-9a-f ]+?)\s*(?:\t(.*))?$')


def _decode(data, secs, start, end):
    body = _section_bytes(data, secs, start, end)
    handle = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
    try:
        handle.write(body)
        handle.close()
        out = subprocess.check_output(
            ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
             f'--adjust-vma={start:#x}', handle.name], text=True)
    finally:
        Path(handle.name).unlink()
    _foundation_decode(out, start, end, body)
    rows = {}
    last = None
    for line in out.splitlines():
        match = _LINE_RE.match(line)
        if not match:
            continue
        addr = int(match.group(1), 16)
        raw = re.sub(r'\s', '', match.group(2))
        text = (match.group(3) or '').strip().split('#')[0].rstrip()
        if not text and last is not None \
                and addr == last + len(bytes.fromhex(rows[last][0])):
            rows[last] = (rows[last][0] + raw, rows[last][1])
        else:
            rows[addr] = (raw, text)
            last = addr
    cursor = start
    for addr in sorted(rows):
        if addr != cursor:
            raise AssertionError(f'decode gap at {addr:#x} != {cursor:#x}')
        cursor += len(bytes.fromhex(rows[addr][0]))
    if cursor != end:
        raise AssertionError(f'decode ends at {cursor:#x} != {end:#x}')
    return rows


def _check_pins(rows, pins, what):
    if rows != pins:
        for address in sorted(set(rows) | set(pins)):
            if rows.get(address) != pins.get(address):
                raise AssertionError(
                    f'{what} instruction at {address:#x} differs: '
                    f'{rows.get(address)!r} != {pins.get(address)!r}')
        raise AssertionError(f'{what} instructions differ')
    return rows


def _check_pins_subset(rows, pins, what):
    for address, want in pins.items():
        if rows.get(address) != want:
            raise AssertionError(
                f'{what} instruction at {address:#x} differs: '
                f'{rows.get(address)!r} != {want!r}')
    return rows


def _rela_entries(data, secs):
    entries = []
    for sec in secs:
        if sec['type'] != 4:
            continue
        blob = _section_bytes(data, secs, sec['address'],
                              sec['address'] + sec['size'])
        for off in range(0, len(blob) - 23, 24):
            r_offset, r_info, r_addend = struct.unpack_from('<QQq', blob, off)
            entries.append((r_offset, r_info & 0xFFFFFFFF, r_info >> 32,
                            r_addend))
    return entries


def _dynsym_name(data, secs, index):
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize = struct.unpack_from('<H', data, 58)[0]
    dynsym_idx = next(i for i, s in enumerate(secs) if s['type'] == 11)
    link = struct.unpack_from('<I', data, shoff + dynsym_idx * entsize + 40)[0]
    dynsym = secs[dynsym_idx]
    dynstr = secs[link]
    st_name = struct.unpack_from(
        '<I', data, dynsym['offset'] + index * 24)[0]
    table = _section_bytes(data, secs, dynstr['address'],
                           dynstr['address'] + dynstr['size'])
    end = table.find(b'\0', st_name)
    return table[st_name:end].decode('utf-8')


def _slot_fact(data, secs, relas, slot, want_type, want_sym=None):
    hits = [e for e in relas if e[0] == slot]
    if len(hits) != 1:
        raise AssertionError(f'slot {_hx(slot)} has {len(hits)} relocations')
    _off, rtype, sym, addend = hits[0]
    if rtype != want_type:
        raise AssertionError(f'slot {_hx(slot)} relocation type is {rtype}')
    fact = {'slot': _hx(slot), 'rela_type': rtype}
    if want_sym is not None:
        name = _dynsym_name(data, secs, sym)
        if name != want_sym:
            raise AssertionError(
                f'slot {_hx(slot)} binds {name!r}, not {want_sym!r}')
        fact['symbol'] = name
    content = struct.unpack_from(
        '<Q', _section_bytes(data, secs, slot, slot + 8), 0)[0]
    if content != 0:
        raise AssertionError(f'slot {_hx(slot)} initialised content is not zero')
    fact['initialised_content'] = '0x0'
    return fact


_REG64 = {}
for _full, _base in [('rax', 'rax'), ('eax', 'rax'), ('ax', 'rax'),
                     ('al', 'rax'), ('ah', 'rax'), ('rbx', 'rbx'),
                     ('ebx', 'rbx'), ('bx', 'rbx'), ('bl', 'rbx'),
                     ('bh', 'rbx'), ('rcx', 'rcx'), ('ecx', 'rcx'),
                     ('cx', 'rcx'), ('cl', 'rcx'), ('ch', 'rcx'),
                     ('rdx', 'rdx'), ('edx', 'rdx'), ('dx', 'rdx'),
                     ('dl', 'rdx'), ('dh', 'rdx'), ('rsi', 'rsi'),
                     ('esi', 'rsi'), ('si', 'rsi'), ('sil', 'rsi'),
                     ('rdi', 'rdi'), ('edi', 'rdi'), ('di', 'rdi'),
                     ('dil', 'rdi'), ('rbp', 'rbp'), ('ebp', 'rbp'),
                     ('bp', 'rbp'), ('bpl', 'rbp'), ('rsp', 'rsp'),
                     ('esp', 'rsp'), ('sp', 'rsp'), ('spl', 'rsp')]:
    _REG64[_full] = _base
for _i in range(8, 16):
    for _suf in ('', 'd', 'w', 'b'):
        _REG64[f'r{_i}{_suf}'] = f'r{_i}'

_REG_WIDTH = {}
for _base in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp'):
    _REG_WIDTH[_base] = 8
for _i in range(8, 16):
    _REG_WIDTH[f'r{_i}'] = 8
for _n32 in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'):
    _REG_WIDTH[_n32] = 4
for _i in range(8, 16):
    _REG_WIDTH[f'r{_i}d'] = 4
    _REG_WIDTH[f'r{_i}w'] = 2
    _REG_WIDTH[f'r{_i}b'] = 1
for _n16 in ('ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp'):
    _REG_WIDTH[_n16] = 2
for _n8 in ('al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh',
            'sil', 'dil', 'bpl', 'spl'):
    _REG_WIDTH[_n8] = 1

_MEMFULL_RE = re.compile(
    r'^(-?0x[0-9a-f]+)?\(%([a-z0-9]+)(?:,%([a-z0-9]+)(?:,([0-9]+))?)?\)$')
_STORE_BASES = {'mov', 'movabs', 'movups', 'movaps', 'movdqa', 'movdqu',
                'movupd', 'movapd', 'movsd', 'movss'}
_XMM_STORES = {'movups', 'movaps', 'movdqa', 'movdqu', 'movupd', 'movapd'}


def _split_ops(text):
    parts = text.split(None, 1)
    if len(parts) < 2:
        return (parts[0] if parts else ''), []
    ops, depth, cur = [], 0, ''
    for ch in parts[1]:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == ',' and depth == 0:
            ops.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        ops.append(cur.strip())
    return parts[0], ops


def _base_mnem(mnem):
    if mnem in _STORE_BASES:
        return mnem
    if mnem and mnem[-1] in 'bwlq' and mnem[:-1] in _STORE_BASES:
        return mnem[:-1]
    return mnem


def _store_width(mnem, base_mnem, src_tok):
    if base_mnem in _XMM_STORES:
        return 16
    if mnem != base_mnem and mnem[-1] in 'bwlq':
        return {'b': 1, 'w': 2, 'l': 4, 'q': 8}[mnem[-1]]
    if src_tok.startswith('%xmm'):
        return 16
    if src_tok.startswith('%'):
        return _REG_WIDTH.get(src_tok[1:], 8)
    return 8


def _stores(rows):
    """All stores to memory: (addr, disp, base_reg, width, text)."""
    out = []
    for addr in sorted(rows):
        _b, text = rows[addr]
        mnem, ops = _split_ops(text)
        base_mnem = _base_mnem(mnem)
        if base_mnem not in _STORE_BASES or len(ops) < 2:
            continue
        match = _MEMFULL_RE.match(ops[-1])
        if not match:
            continue
        disp = int(match.group(1), 16) if match.group(1) else 0
        if match.group(1) and match.group(1).startswith('-'):
            disp = -int(match.group(1)[1:], 16)
        base = _REG64.get(match.group(2), match.group(2))
        out.append((addr, disp, base,
                    _store_width(mnem, base_mnem, ops[0]), text))
    return out


def _rsp_stores_in(rows, lo, hi):
    return [[_hx(a), _hx(d)] for (a, d, b, _w, _t) in _stores(rows)
            if b == 'rsp' and lo <= d < hi]


def _slot_refs(rows, slot):
    """(ff15 call sites, register-load sites) referencing `slot`."""
    calls, loads = [], []
    for addr in sorted(rows):
        raw, _text = rows[addr]
        blob = bytes.fromhex(raw)
        if raw.startswith('ff15') and len(blob) == 6:
            if addr + 6 + struct.unpack('<i', blob[2:6])[0] == slot:
                calls.append(addr)
        elif len(blob) == 7 and blob[0] in (0x48, 0x4C) and blob[1] == 0x8B \
                and (blob[2] & 0xC7) == 0x05:
            if addr + 7 + struct.unpack('<i', blob[3:7])[0] == slot:
                loads.append(addr)
    return calls, loads


def _binding_before(rows, reg, before, window=10):
    addrs = [a for a in sorted(rows) if a < before][-window:]
    found = {}
    for addr in addrs:
        _b, text = rows[addr]
        mnem, ops = _split_ops(text)
        if len(ops) < 2:
            continue
        dst = ops[-1]
        if not dst.startswith('%'):
            continue
        dst_reg = _REG64.get(dst[1:])
        if dst_reg is None or dst_reg == 'rsp':
            continue
        src = ops[0]
        lea = _MEMFULL_RE.match(src)
        if mnem == 'lea' and lea and _REG64.get(lea.group(2)) == 'rsp' \
                and not lea.group(3):
            disp = int(lea.group(1), 16) if lea.group(1) else 0
            found[dst_reg] = ('stack', disp)
        elif mnem == 'lea' and lea and not lea.group(3):
            base = _REG64.get(lea.group(2))
            disp = int(lea.group(1), 16) if lea.group(1) else 0
            found[dst_reg] = ('lea', base, disp)
        elif src.startswith('%'):
            src_reg = _REG64.get(src[1:])
            if src_reg == 'rsp':
                found[dst_reg] = ('stack', 0)
            elif src_reg in found:
                found[dst_reg] = found[src_reg]
            else:
                found[dst_reg] = ('reg', src_reg)
        elif src.startswith('$'):
            found[dst_reg] = ('imm', int(src[1:], 16))
        else:
            found.pop(dst_reg, None)
    return found.get(reg)


def _fmt_bind(value):
    if value is None:
        return None
    if value[0] in ('stack', 'imm'):
        return value[1]
    if value[0] == 'reg':
        return 'reg:' + value[1]
    if value[0] == 'lea':
        return f'lea:{value[1]}+{value[2]:#x}'
    return str(value)


def _memcpy_args(rows, call_addr):
    return (_fmt_bind(_binding_before(rows, 'rdi', call_addr)),
            _fmt_bind(_binding_before(rows, 'rsi', call_addr)),
            _fmt_bind(_binding_before(rows, 'rdx', call_addr)))


def _memcpy_census(rows):
    """All memcpy executions: ff15 slot calls + `call *%r14` rows (the
    slot pointer loaded into r14), as {site: [dst, src, size]}."""
    calls, loads = _slot_refs(rows, MEMCPY_SLOT)
    sites = set(calls)
    for addr in sorted(rows):
        if rows[addr][1] == 'call   *%r14':
            sites.add(addr)
    table = {}
    for site in sorted(sites):
        table[_hx(site)] = list(_memcpy_args(rows, site))
    return {'ff15_calls': [_hx(a) for a in calls],
            'slot_loads': [_hx(a) for a in loads],
            'call_sites': [_hx(a) for a in sorted(sites)],
            'table': table}


def _e8_target(rows, addr):
    raw, _text = rows[addr]
    return addr + 5 + struct.unpack('<i', bytes.fromhex(raw[2:10]))[0]




def _frames(data):
    retained = {(start, end) for start, end, _e in BODIES.values()}
    handle = tempfile.NamedTemporaryFile(suffix='.elf', delete=False)
    try:
        handle.write(data)
        handle.close()
        out = subprocess.check_output(
            ['readelf', '--debug-dump=frames', handle.name], text=True)
    finally:
        Path(handle.name).unlink()
    lines = []
    for line in out.splitlines():
        if ' FDE ' not in line:
            continue
        match = re.search(r'pc=([0-9a-f]+)\.\.([0-9a-f]+)', line)
        if match and (int(match.group(1), 16),
                      int(match.group(2), 16)) in retained:
            lines.append(line)
    if len(lines) != len(retained):
        raise AssertionError(
            f'frames cover {len(lines)} of {len(retained)} FDEs')
    return '\n'.join(lines) + '\n'


def _body_export(data, start, end):
    handle = tempfile.NamedTemporaryFile(suffix='.elf', delete=False)
    try:
        handle.write(data)
        handle.close()
        out = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', '--insn-width=16',
             f'--start-address={start:#x}', f'--stop-address={end:#x}',
             handle.name], text=True)
    finally:
        Path(handle.name).unlink()
    return out.replace(handle.name, '<authenticated-node115>')


def _export_name(name, start, end):
    return f'{name}_full_body_{start:x}_{end:x}_objdump.txt'


class PacketError(AssertionError):
    """The artifact does not authenticate against node 115."""


def _slot_resolution(data, secs, relas, slot):
    hits = [e for e in relas if e[0] == slot]
    if len(hits) != 1:
        raise PacketError(f'slot {_hx(slot)} has {len(hits)} relocations')
    _off, rtype, sym, addend = hits[0]
    content = struct.unpack_from(
        '<Q', _section_bytes(data, secs, slot, slot + 8), 0)[0]
    if content != 0:
        raise PacketError(f'slot {_hx(slot)} initialised content is not zero')
    fact = {'slot': _hx(slot), 'rela_type': rtype,
            'initialised_content': '0x0'}
    if rtype == 8:
        fact['addend'] = _hx(addend)
    elif rtype == 6:
        fact['symbol'] = _dynsym_name(data, secs, sym)
    return fact


PINNED_ROWS = {'inner_ca': {45857696: ('55', 'push   %rbp'), 45858216: ('e8d3c57cff', 'call   0x2388380'), 45858429: ('e81ef290ff', 'call   0x24cb0a0'), 45858715: ('e800f190ff', 'call   0x24cb0a0'), 45858826: ('e85134a000', 'call   0x35bf460'), 45858875: ('e8d0a39901', 'call   0x4556410'), 45860606: ('48894208', 'mov    %rax,0x8(%rdx)'), 45860645: ('c60200', 'movb   $0x0,(%rdx)'), 45860661: ('884801', 'mov    %cl,0x1(%rax)'), 45860664: ('c60001', 'movb   $0x1,(%rax)'), 45860654: ('b109', 'mov    $0x9,%cl')}, 'inner_s3': {45863088: ('55', 'push   %rbp'), 45863637: ('e8a6b07cff', 'call   0x2388380'), 45863853: ('e8eedc90ff', 'call   0x24cb0a0'), 45863994: ('e82120a000', 'call   0x35bf460'), 45864085: ('e8768f9901', 'call   0x4556410'), 45865799: ('48894208', 'mov    %rax,0x8(%rdx)'), 45865842: ('c60200', 'movb   $0x0,(%rdx)'), 45865858: ('884801', 'mov    %cl,0x1(%rax)'), 45865861: ('c60001', 'movb   $0x1,(%rax)'), 45865851: ('b109', 'mov    $0x9,%cl')}, 'sublookup_ca': {45839051: ('488b4220', 'mov    0x20(%rdx),%rax'), 45839055: ('4889442418', 'mov    %rax,0x18(%rsp)'), 45839083: ('488b4228', 'mov    0x28(%rdx),%rax'), 45839087: ('4889842488000000', 'mov    %rax,0x88(%rsp)'), 45839312: ('4889b42490000000', 'mov    %rsi,0x90(%rsp)'), 45841337: ('e8e23f0000', 'call   0x2bbbba0'), 45841342: ('80bc244001000001', 'cmpb   $0x1,0x140(%rsp)'), 45846412: ('e80f2c0000', 'call   0x2bbbba0'), 45847829: ('e886260000', 'call   0x2bbbba0'), 45844845: ('48898424f8000000', 'mov    %rax,0xf8(%rsp)'), 45844867: ('e838ab1f00', 'call   0x2db34c0')}, 'helper_s3a': {46540890: ('488b4210', 'mov    0x10(%rdx),%rax'), 46540894: ('4889442450', 'mov    %rax,0x50(%rsp)'), 46541028: ('4c89642460', 'mov    %r12,0x60(%rsp)'), 46541282: ('4c896c2418', 'mov    %r13,0x18(%rsp)'), 46542840: ('e8b3a0f5ff', 'call   0x2bbd0b0'), 46542845: ('80bc24a000000001', 'cmpb   $0x1,0xa0(%rsp)'), 46544262: ('e8259bf5ff', 'call   0x2bbd0b0'), 46548178: ('e8d98bf5ff', 'call   0x2bbd0b0'), 46546641: ('48898424c8010000', 'mov    %rax,0x1c8(%rsp)'), 46546671: ('e8ccf51400', 'call   0x2db34c0')}, 'help_cd0': {41295056: ('55', 'push   %rbp'), 41295158: ('ff155447d803', 'call   *0x3d84754(%rip)'), 41295347: ('e8e84a4500', 'call   0x2bb68e0'), 41295427: ('ff15bfd6d703', 'call   *0x3d7d6bf(%rip)'), 41295543: ('ff154bd6d703', 'call   *0x3d7d64b(%rip)')}, 'help_fe0': {41295840: ('55', 'push   %rbp'), 41296026: ('ff15f843d803', 'call   *0x3d843f8(%rip)'), 41296150: ('e8a5274500', 'call   0x2bb48c0'), 41296214: ('ff15acd3d703', 'call   *0x3d7d3ac(%rip)'), 41296326: ('ff153cd3d703', 'call   *0x3d7d33c(%rip)')}, 'help_e850': {44755024: ('4156', 'push   %r14'), 44755142: ('ff15d40ba303', 'call   *0x3a30bd4(%rip)')}, 'help_660': {88671840: ('55', 'push   %rbp'), 88672559: ('e8fceaffff', 'call   0x548f430'), 88672888: ('e8e3e912fe', 'call   0x35bf460'), 88672949: ('e856590cff', 'call   0x4556410'), 88673160: ('e843e0ffff', 'call   0x548ebd0'), 88674360: ('ff15cae40401', 'call   *0x104e4ca(%rip)')}, 'help_440': {88679488: ('55', 'push   %rbp'), 88680301: ('e8beccffff', 'call   0x548f430'), 88680657: ('e88acb12fe', 'call   0x35bf460'), 88680696: ('e8133b0cff', 'call   0x4556410'), 88680962: ('e8c9c1ffff', 'call   0x548ebd0'), 88682189: ('ff1535c60401', 'call   *0x104c635(%rip)')}, 'help_563': {90374144: ('4157', 'push   %r15'), 90374261: ('ff1525f4ea00', 'call   *0xeaf425(%rip)')}, 'bwc_a1': {44590631: ('e8b4b9cdff', 'call   0x2761fe0'), 44590699: ('e8e0810200', 'call   0x2aae850'), 44592039: ('e834b4cdff', 'call   0x2761fe0')}, 'bwc_a2': {44612884: ('e8c762cdff', 'call   0x2761fe0')}, 'bwc_a3': {46394254: ('e83d31b2ff', 'call   0x2761cd0')}, 'bwc_b1': {88963618: ('e8e9920a00', 'call   0x5580d10'), 88963765: ('e846851500', 'call   0x5630000')}, 'bwc_b2': {89667335: ('e834edf0ff', 'call   0x5492440'), 89667403: ('e8b0c80a00', 'call   0x5630000'), 89668743: ('e8b4e7f0ff', 'call   0x5492440')}, 'bwc_b3': {89753294: ('e88d7fefff', 'call   0x5490660')}, 'bwc_b4': {90218628: ('e8b783e8ff', 'call   0x5492440')}, 'bwc_c1': {88939845: ('e896e90a00', 'call   0x55806e0'), 88939992: ('e823e21500', 'call   0x5630000')}, 'bwc_c2': {89679895: ('e824bcf0ff', 'call   0x5492440'), 89679963: ('e8a0970a00', 'call   0x5630000'), 89681303: ('e8a4b6f0ff', 'call   0x5492440')}, 'bwc_c3': {89769278: ('e81d41efff', 'call   0x5490660')}, 'bwc_c4': {90218180: ('e87785e8ff', 'call   0x5492440')}}

EXPECTED_BODIES = {'bwc_a1': {'end': '0x2a8829e', 'exported': False, 'instructions': 2629, 'sha256': '7bca2f033becd6f8a8f0d184a434cdd74677915f45e0c9ab31aa61970bbaaace', 'size': 13374, 'start': '0x2a84e60'}, 'bwc_a2': {'end': '0x2a8bdf1', 'exported': True, 'instructions': 96, 'sha256': 'b45e239ca04d7a57848bc12ba89762bcd836ffc909e7c5996d066673e9ffebe8', 'size': 433, 'start': '0x2a8bc40'}, 'bwc_a3': {'end': '0x2c3eda8', 'exported': True, 'instructions': 257, 'sha256': 'c1c4b3774cd1c2de34c46374fa9f9a4b8344bfc732f96dacaad5f542815008f6', 'size': 1272, 'start': '0x2c3e8b0'}, 'bwc_b1': {'end': '0x54db474', 'exported': False, 'instructions': 4102, 'sha256': '155583f5bcc0b7aff8164fb7aacf8e4792ba836bb17ae19c2d03e9e437d18ba4', 'size': 23748, 'start': '0x54d57b0'}, 'bwc_b2': {'end': '0x5585283', 'exported': False, 'instructions': 2460, 'sha256': '0dce413fbb40e408ffca0831ec0ee804509e99cbde0b23f565bbb9b71dd2f19f', 'size': 12547, 'start': '0x5582180'}, 'bwc_b3': {'end': '0x55988e8', 'exported': True, 'instructions': 257, 'sha256': '6f533c250a2367373730365e336d44997afa8200de1858a7431c9eabf0950d81', 'size': 1272, 'start': '0x55983f0'}, 'bwc_b4': {'end': '0x560a161', 'exported': True, 'instructions': 96, 'sha256': '5b23a89bba537eed46d967ad3afde6bcbaaa108fe158a0b9f617eae09a7ff77d', 'size': 433, 'start': '0x5609fb0'}, 'bwc_c1': {'end': '0x54d57a4', 'exported': False, 'instructions': 4092, 'sha256': '824e0d4571ca1e4393eb87acd38dd36b9e9d87e1762905e464cc6942e698b1cf', 'size': 23828, 'start': '0x54cfa90'}, 'bwc_c2': {'end': '0x5588393', 'exported': False, 'instructions': 2460, 'sha256': '0c80314b405562e1053ce3a5195ee216628d43b51d5e84e4833c900b19fe051a', 'size': 12547, 'start': '0x5585290'}, 'bwc_c3': {'end': '0x559c758', 'exported': True, 'instructions': 257, 'sha256': 'c085bb074f81eea81d0e5e69ae498b13f7c3c4b761936d122b86d4f16471d35c', 'size': 1272, 'start': '0x559c260'}, 'bwc_c4': {'end': '0x5609fa1', 'exported': True, 'instructions': 96, 'sha256': '925c2098402d2dac58c01f90b8adcad3c31c11f9e109226604dca31e63ccc78e', 'size': 433, 'start': '0x5609df0'}, 'help_440': {'end': '0x5493013', 'exported': True, 'instructions': 570, 'sha256': '51550e60c680bb4717b73bdacb40ffb13dbc5f8fb1a26dba33ed15356324663f', 'size': 3027, 'start': '0x5492440'}, 'help_563': {'end': '0x563034a', 'exported': True, 'instructions': 235, 'sha256': '6cd0a9a6ceb53606e9090b5c50eeb0738617ae2f88242fcb65a2d82ed16d28ae', 'size': 842, 'start': '0x5630000'}, 'help_660': {'end': '0x549118e', 'exported': True, 'instructions': 539, 'sha256': '439fe08e21070afa42fb7028862c87a840aca1f68bbbabde6b6681e099899e64', 'size': 2862, 'start': '0x5490660'}, 'help_cd0': {'end': '0x2761fd6', 'exported': True, 'instructions': 160, 'sha256': '7c6d7007bde599b745503f081733f11410b1ef721d2c81be1455b8e050df366c', 'size': 774, 'start': '0x2761cd0'}, 'help_e850': {'end': '0x2aaea38', 'exported': True, 'instructions': 136, 'sha256': 'fc8a8aeea916ea025a728d488e9a29b90d8e4d2b07260793e2a0893e5af36365', 'size': 488, 'start': '0x2aae850'}, 'help_fe0': {'end': '0x27622e6', 'exported': True, 'instructions': 162, 'sha256': '2bdaafeeac7b788c0f3aaa1999651e92190fa1c5e15993011cc80b6ccbd397b9', 'size': 774, 'start': '0x2761fe0'}, 'helper_s3a': {'end': '0x2c64862', 'exported': False, 'instructions': 1667, 'sha256': '9176b5c3361b91321a3b0cd99c2e90bf4538c1d7b21a68d63f68d5082e33fe96', 'size': 8258, 'start': '0x2c62820'}, 'inner_ca': {'end': '0x2bbc74d', 'exported': True, 'instructions': 675, 'sha256': 'f3e69ec027f6e24352c49415a533d2cc5e75443ce6681b3c6b51331a3446fa35', 'size': 2989, 'start': '0x2bbbba0'}, 'inner_s3': {'end': '0x2bbdb9a', 'exported': True, 'instructions': 632, 'sha256': '889874f504716879ed3af8bfab1a9f7909972bfee409b4125910ce5a114c1a6e', 'size': 2794, 'start': '0x2bbd0b0'}, 'sublookup_ca': {'end': '0x2bb9893', 'exported': False, 'instructions': 1974, 'sha256': '6dbf7f8390953d24bdd5b7a225e83f3e1614fb79ee6b3f40d423f8728d44234b', 'size': 9763, 'start': '0x2bb7270'}}

EXPECTED_INNER = {'inner_ca': {'argument_saves': {'r8': {'addr': '0x2bbbbb9', 'disp': 216}, 'r9': {'addr': '0x2bbbbb1', 'disp': 224}, 'rcx': {'addr': '0x2bbbbc1', 'disp': 16}, 'rdi': {'addr': '0x2bbbbcb', 'disp': 80}, 'rdx': {'addr': '0x2bbbbc6', 'disp': 96}}, 'direct_calls': {'0x2bbbda8': '0x2388380', '0x2bbbe7d': '0x24cb0a0', '0x2bbbf9b': '0x24cb0a0', '0x2bbc00a': '0x35bf460', '0x2bbc03b': '0x4556410'}, 'exit': {'failure': {'code_store': '0x2bbc735', 'pointer_load': '0x2bbc730', 'tag_store': '0x2bbc738', 'tag_value': 1}, 'failure_arms': {'0x2bbc5b6': 3, '0x2bbc5e2': 7, '0x2bbc6e7': 3, '0x2bbc6eb': 7, '0x2bbc72a': 2, '0x2bbc72e': 9}, 'success': {'pointer_load': '0x2bbc6f9', 'stores': [['0x2bbc6fe', 8, 8], ['0x2bbc702', 16, 8], ['0x2bbc70b', 24, 8], ['0x2bbc70f', 32, 8], ['0x2bbc718', 40, 8], ['0x2bbc721', 48, 8]], 'tag_store': '0x2bbc725', 'tag_value': 0}}, 'memcpy_slot_refs': [], 'search_calls': {'cursor_next': ['0x2bbbda8'], 'decode': ['0x2bbbe7d', '0x2bbbf9b'], 'fallback': ['0x2bbc03b'], 'sibling': ['0x2bbc00a']}, 'slot_refs': {'0x2bbc098': ['call', '0x64dfaf8'], '0x2bbc0cc': ['call', '0x64e71b8'], '0x2bbc139': ['call', '0x64dfaf8'], '0x2bbc18d': ['call', '0x64e71b8'], '0x2bbc235': ['load', '0x64dfaf8'], '0x2bbc28c': ['call', '0x64dfaf8'], '0x2bbc2e0': ['call', '0x64e71b8'], '0x2bbc318': ['call', '0x64e4ea8'], '0x2bbc38f': ['load', '0x64dfaf8'], '0x2bbc421': ['call', '0x64e71b8'], '0x2bbc4c6': ['load', '0x64dfaf8'], '0x2bbc520': ['call', '0x64e71b8'], '0x2bbc588': ['load', '0x64dfaf8'], '0x2bbc5dc': ['call', '0x64e71b8'], '0x2bbc633': ['call', '0x64e4ea8'], '0x2bbc65b': ['call', '0x64e4ea8'], '0x2bbc680': ['call', '0x64e4ea8'], '0x2bbc6a8': ['call', '0x64e4ea8'], '0x2bbc6c9': ['call', '0x64e4ea8']}, 'store_census': {'by_base': {'r12': 2, 'rax': 2, 'rdx': 8, 'rsp': 39}, 'non_rsp_stores': [['0x2bbbd56', 0, 'rdx', 16], ['0x2bbc107', 0, 'r12', 8], ['0x2bbc334', 0, 'r12', 8], ['0x2bbc6fe', 8, 'rdx', 8], ['0x2bbc702', 16, 'rdx', 8], ['0x2bbc70b', 24, 'rdx', 8], ['0x2bbc70f', 32, 'rdx', 8], ['0x2bbc718', 40, 'rdx', 8], ['0x2bbc721', 48, 'rdx', 8], ['0x2bbc725', 0, 'rdx', 1], ['0x2bbc735', 1, 'rax', 1], ['0x2bbc738', 0, 'rax', 1]], 'total': 51}}, 'inner_s3': {'argument_saves': {'r8': {'addr': '0x2bbd0c9', 'disp': 208}, 'r9': {'addr': '0x2bbd0c1', 'disp': 216}, 'rcx': {'addr': '0x2bbd0d1', 'disp': 8}, 'rdi': {'addr': '0x2bbd0db', 'disp': 64}, 'rdx': {'addr': '0x2bbd0d6', 'disp': 88}}, 'direct_calls': {'0x2bbd2d5': '0x2388380', '0x2bbd3ad': '0x24cb0a0', '0x2bbd43a': '0x35bf460', '0x2bbd495': '0x4556410'}, 'exit': {'failure': {'code_store': '0x2bbdb82', 'pointer_load': '0x2bbdb7d', 'tag_store': '0x2bbdb85', 'tag_value': 1}, 'failure_arms': {'0x2bbda05': 3, '0x2bbda35': 7, '0x2bbdb30': 3, '0x2bbdb34': 7, '0x2bbdb77': 2, '0x2bbdb7b': 9}, 'success': {'pointer_load': '0x2bbdb42', 'stores': [['0x2bbdb47', 8, 8], ['0x2bbdb4b', 16, 8], ['0x2bbdb53', 24, 8], ['0x2bbdb5c', 32, 8], ['0x2bbdb65', 40, 8], ['0x2bbdb6e', 48, 8]], 'tag_store': '0x2bbdb72', 'tag_value': 0}}, 'memcpy_slot_refs': [], 'search_calls': {'cursor_next': ['0x2bbd2d5'], 'decode': ['0x2bbd3ad'], 'fallback': ['0x2bbd495'], 'sibling': ['0x2bbd43a']}, 'slot_refs': {'0x2bbd207': ['load', '0x64dfaf8'], '0x2bbd243': ['load', '0x64dfaf8'], '0x2bbd524': ['call', '0x64e71b8'], '0x2bbd58c': ['call', '0x64dfaf8'], '0x2bbd5e0': ['call', '0x64e71b8'], '0x2bbd6dc': ['call', '0x64dfaf8'], '0x2bbd730': ['call', '0x64e71b8'], '0x2bbd768': ['call', '0x64e4ea8'], '0x2bbd7de': ['call', '0x64dfaf8'], '0x2bbd827': ['load', '0x64dfaf8'], '0x2bbd873': ['call', '0x64e71b8'], '0x2bbd8c2': ['call', '0x64dfaf8'], '0x2bbd91a': ['load', '0x64dfaf8'], '0x2bbd974': ['call', '0x64e71b8'], '0x2bbd9d7': ['load', '0x64dfaf8'], '0x2bbda18': ['call', '0x64dfaf8'], '0x2bbda2f': ['call', '0x64e71b8'], '0x2bbda7c': ['call', '0x64e4ea8'], '0x2bbdaa4': ['call', '0x64e4ea8'], '0x2bbdac9': ['call', '0x64e4ea8'], '0x2bbdaf1': ['call', '0x64e4ea8'], '0x2bbdb12': ['call', '0x64e4ea8']}, 'store_census': {'by_base': {'r12': 2, 'rax': 2, 'rdx': 8, 'rsp': 38}, 'non_rsp_stores': [['0x2bbd27f', 0, 'rdx', 16], ['0x2bbd55a', 0, 'r12', 8], ['0x2bbd784', 0, 'r12', 8], ['0x2bbdb47', 8, 'rdx', 8], ['0x2bbdb4b', 16, 'rdx', 8], ['0x2bbdb53', 24, 'rdx', 8], ['0x2bbdb5c', 32, 'rdx', 8], ['0x2bbdb65', 40, 'rdx', 8], ['0x2bbdb6e', 48, 'rdx', 8], ['0x2bbdb72', 0, 'rdx', 1], ['0x2bbdb82', 1, 'rax', 1], ['0x2bbdb85', 0, 'rax', 1]], 'total': 50}}}

EXPECTED_INNER_SITES = [{'bindings': {'r8': {'addr': '0x2bb7bb6', 'form': 'reg', 'reg': 'r8d', 'text': 'xor    %r8d,%r8d'}, 'r9': None, 'rcx': {'addr': '0x2bb7bae', 'disp': 136, 'form': 'load_rsp', 'text': 'mov    0x88(%rsp),%rcx'}, 'rdi': {'addr': '0x2bb7ba0', 'form': 'reg', 'reg': 'rbp', 'text': 'mov    %rbp,%rdi'}, 'rdx': {'addr': '0x2bb7bab', 'form': 'reg', 'reg': 'r10', 'text': 'mov    %r10,%rdx'}, 'rsi': {'addr': '0x2bb7ba3', 'disp': 144, 'form': 'load_rsp', 'text': 'mov    0x90(%rsp),%rsi'}}, 'call': '0x2bb7bb9', 'caller': 'sublookup_ca', 'origins': {'rcx': {'slot_disp': 136, 'source_row': {'addr': '0x2bb72eb', 'form': 'other', 'src': '0x28(%rdx)', 'text': 'mov    0x28(%rdx),%rax'}, 'store': {'addr': '0x2bb72ef', 'text': 'mov    %rax,0x88(%rsp)'}}, 'rsi': {'slot_disp': 144, 'source_row': None, 'store': {'addr': '0x2bb73d0', 'text': 'mov    %rsi,0x90(%rsp)'}}}, 'payload_reads': [['0x2bb7c86', 328], ['0x2bb7c93', 344], ['0x2bb7ca0', 352]], 'r9_last_writer_in_fde': {'addr': '0x2bb77e3', 'form': 'reg', 'reg': 'rdi', 'text': 'add    %rdi,%r9'}, 'rdx_r10': {'frame_reloads': ['0x2bb7545', '0x2bb7652', '0x2bb774e', '0x2bb7870', '0x2bb78cc', '0x2bb7963'], 'jump_sources': ['0x2bb7885', '0x2bb78f9', '0x2bb7986'], 'prelude_block': '0x2bb7ba0'}, 'tag_test': {'addr': '0x2bb7bbe', 'text': 'cmpb   $0x1,0x140(%rsp)'}, 'target': 'inner_ca'}, {'bindings': {'r8': {'addr': '0x2bb8f6b', 'form': 'imm', 'text': 'mov    $0x1,%r8d', 'value': 1}, 'r9': {'addr': '0x2bb8f89', 'form': 'reg', 'reg': 'r15', 'text': 'mov    %r15,%r9'}, 'rcx': {'addr': '0x2bb8f81', 'disp': 136, 'form': 'load_rsp', 'text': 'mov    0x88(%rsp),%rcx'}, 'rdi': {'addr': '0x2bb8f71', 'form': 'reg', 'reg': 'rbp', 'text': 'mov    %rbp,%rdi'}, 'rdx': {'addr': '0x2bb8f7c', 'disp': 24, 'form': 'load_rsp', 'text': 'mov    0x18(%rsp),%rdx'}, 'rsi': {'addr': '0x2bb8f74', 'disp': 144, 'form': 'load_rsp', 'text': 'mov    0x90(%rsp),%rsi'}}, 'call': '0x2bb8f8c', 'caller': 'sublookup_ca', 'origins': {'rcx': {'slot_disp': 136, 'source_row': {'addr': '0x2bb72eb', 'form': 'other', 'src': '0x28(%rdx)', 'text': 'mov    0x28(%rdx),%rax'}, 'store': {'addr': '0x2bb72ef', 'text': 'mov    %rax,0x88(%rsp)'}}, 'rdx': {'slot_disp': 24, 'source_row': {'addr': '0x2bb72cb', 'form': 'other', 'src': '0x20(%rdx)', 'text': 'mov    0x20(%rdx),%rax'}, 'store': {'addr': '0x2bb72cf', 'text': 'mov    %rax,0x18(%rsp)'}}, 'rsi': {'slot_disp': 144, 'source_row': None, 'store': {'addr': '0x2bb73d0', 'text': 'mov    %rsi,0x90(%rsp)'}}}, 'payload_reads': [['0x2bb8f9f', 328]], 'tag_test': {'addr': '0x2bb8f91', 'text': 'cmpb   $0x0,0x140(%rsp)'}, 'target': 'inner_ca'}, {'bindings': {'r8': {'addr': '0x2bb9512', 'form': 'reg', 'reg': 'r8d', 'text': 'xor    %r8d,%r8d'}, 'r9': None, 'rcx': {'addr': '0x2bb950a', 'disp': 136, 'form': 'load_rsp', 'text': 'mov    0x88(%rsp),%rcx'}, 'rdi': {'addr': '0x2bb94ff', 'form': 'reg', 'reg': 'rbp', 'text': 'mov    %rbp,%rdi'}, 'rdx': None, 'rsi': {'addr': '0x2bb9502', 'disp': 248, 'form': 'lea_rsp', 'text': 'lea    0xf8(%rsp),%rsi'}}, 'call': '0x2bb9515', 'caller': 'sublookup_ca', 'descriptor_phase_call': {'addr': '0x2bb8983', 'bindings': {'r8': None, 'r9': None, 'rcx': {'addr': '0x2bb895c', 'form': 'other', 'src': '0x10(%rdx)', 'text': 'mov    0x10(%rdx),%rcx'}, 'rdi': {'addr': '0x2bb8975', 'form': 'reg', 'reg': 'rbp', 'text': 'mov    %rbp,%rdi'}, 'rdx': {'addr': '0x2bb8980', 'form': 'reg', 'reg': 'r15', 'text': 'mov    %r15,%rdx'}, 'rsi': {'addr': '0x2bb8978', 'disp': 248, 'form': 'lea_rsp', 'text': 'lea    0xf8(%rsp),%rsi'}}, 'target': '0x2db34c0'}, 'descriptor_production': {'memcpy_into': [], 'stores': ['0x2bb896d']}, 'origins': {'rcx': {'slot_disp': 136, 'source_row': {'addr': '0x2bb72eb', 'form': 'other', 'src': '0x28(%rdx)', 'text': 'mov    0x28(%rdx),%rax'}, 'store': {'addr': '0x2bb72ef', 'text': 'mov    %rax,0x88(%rsp)'}}}, 'payload_reads': [['0x2bb9528', 328]], 'r9_last_writer_in_fde': {'addr': '0x2bb8f89', 'form': 'reg', 'reg': 'r15', 'text': 'mov    %r15,%r9'}, 'tag_test': {'addr': '0x2bb951a', 'text': 'cmpb   $0x0,0x140(%rsp)'}, 'target': 'inner_ca'}, {'bindings': {'r8': {'addr': '0x2c62ff5', 'form': 'reg', 'reg': 'r8d', 'text': 'xor    %r8d,%r8d'}, 'r9': None, 'rcx': {'addr': '0x2c62ff0', 'disp': 96, 'form': 'load_rsp', 'text': 'mov    0x60(%rsp),%rcx'}, 'rdi': {'addr': '0x2c62fe0', 'disp': 160, 'form': 'lea_rsp', 'text': 'lea    0xa0(%rsp),%rdi'}, 'rdx': {'addr': '0x2c62fed', 'form': 'reg', 'reg': 'r13', 'text': 'mov    %r13,%rdx'}, 'rsi': {'addr': '0x2c62fe8', 'disp': 80, 'form': 'load_rsp', 'text': 'mov    0x50(%rsp),%rsi'}}, 'call': '0x2c62ff8', 'caller': 'helper_s3a', 'origins': {'rcx': {'slot_disp': 96, 'source_row': {'addr': '0x2c628dd', 'form': 'imm', 'text': 'add    $0x90,%r12', 'value': 144}, 'store': {'addr': '0x2c628e4', 'text': 'mov    %r12,0x60(%rsp)'}}, 'rsi': {'slot_disp': 80, 'source_row': {'addr': '0x2c6285a', 'form': 'other', 'src': '0x10(%rdx)', 'text': 'mov    0x10(%rdx),%rax'}, 'store': {'addr': '0x2c6285e', 'text': 'mov    %rax,0x50(%rsp)'}}}, 'payload_reads': [['0x2c6300b', 168], ['0x2c63018', 184], ['0x2c63025', 192]], 'r9_last_writer_in_fde': {'addr': '0x2c62c83', 'form': 'reg', 'reg': 'rdi', 'text': 'add    %rdi,%r9'}, 'tag_test': {'addr': '0x2c62ffd', 'text': 'cmpb   $0x1,0xa0(%rsp)'}, 'target': 'inner_s3'}, {'bindings': {'r8': {'addr': '0x2c63566', 'form': 'imm', 'text': 'mov    $0x1,%r8d', 'value': 1}, 'r9': {'addr': '0x2c63583', 'form': 'reg', 'reg': 'r15', 'text': 'mov    %r15,%r9'}, 'rcx': {'addr': '0x2c6357e', 'disp': 96, 'form': 'load_rsp', 'text': 'mov    0x60(%rsp),%rcx'}, 'rdi': {'addr': '0x2c6356c', 'disp': 160, 'form': 'lea_rsp', 'text': 'lea    0xa0(%rsp),%rdi'}, 'rdx': {'addr': '0x2c63579', 'disp': 24, 'form': 'load_rsp', 'text': 'mov    0x18(%rsp),%rdx'}, 'rsi': {'addr': '0x2c63574', 'disp': 80, 'form': 'load_rsp', 'text': 'mov    0x50(%rsp),%rsi'}}, 'call': '0x2c63586', 'caller': 'helper_s3a', 'origins': {'rcx': {'slot_disp': 96, 'source_row': {'addr': '0x2c628dd', 'form': 'imm', 'text': 'add    $0x90,%r12', 'value': 144}, 'store': {'addr': '0x2c628e4', 'text': 'mov    %r12,0x60(%rsp)'}}, 'rdx': {'slot_disp': 24, 'source_row': None, 'store': {'addr': '0x2c629e2', 'text': 'mov    %r13,0x18(%rsp)'}}, 'rsi': {'slot_disp': 80, 'source_row': {'addr': '0x2c6285a', 'form': 'other', 'src': '0x10(%rdx)', 'text': 'mov    0x10(%rdx),%rax'}, 'store': {'addr': '0x2c6285e', 'text': 'mov    %rax,0x50(%rsp)'}}}, 'payload_reads': [['0x2c63599', 168]], 'tag_test': {'addr': '0x2c6358b', 'text': 'cmpb   $0x0,0xa0(%rsp)'}, 'target': 'inner_s3'}, {'bindings': {'r8': {'addr': '0x2c644cf', 'form': 'reg', 'reg': 'r8d', 'text': 'xor    %r8d,%r8d'}, 'r9': None, 'rcx': {'addr': '0x2c644ca', 'disp': 96, 'form': 'load_rsp', 'text': 'mov    0x60(%rsp),%rcx'}, 'rdi': {'addr': '0x2c644b5', 'disp': 160, 'form': 'lea_rsp', 'text': 'lea    0xa0(%rsp),%rdi'}, 'rdx': {'addr': '0x2c644c5', 'disp': 24, 'form': 'load_rsp', 'text': 'mov    0x18(%rsp),%rdx'}, 'rsi': {'addr': '0x2c644bd', 'disp': 456, 'form': 'lea_rsp', 'text': 'lea    0x1c8(%rsp),%rsi'}}, 'call': '0x2c644d2', 'caller': 'helper_s3a', 'descriptor_phase_call': {'addr': '0x2c63eef', 'bindings': {'r8': None, 'r9': None, 'rcx': {'addr': '0x2c63ec0', 'form': 'other', 'src': '0x10(%rdx)', 'text': 'mov    0x10(%rdx),%rcx'}, 'rdi': {'addr': '0x2c63ee1', 'form': 'reg', 'reg': 'r13', 'text': 'mov    %r13,%rdi'}, 'rdx': {'addr': '0x2c63eec', 'form': 'reg', 'reg': 'r15', 'text': 'mov    %r15,%rdx'}, 'rsi': {'addr': '0x2c63ee4', 'disp': 456, 'form': 'lea_rsp', 'text': 'lea    0x1c8(%rsp),%rsi'}}, 'target': '0x2db34c0'}, 'descriptor_production': {'memcpy_into': [], 'stores': ['0x2c63ed1']}, 'origins': {'rcx': {'slot_disp': 96, 'source_row': {'addr': '0x2c628dd', 'form': 'imm', 'text': 'add    $0x90,%r12', 'value': 144}, 'store': {'addr': '0x2c628e4', 'text': 'mov    %r12,0x60(%rsp)'}}, 'rdx': {'slot_disp': 24, 'source_row': None, 'store': {'addr': '0x2c629e2', 'text': 'mov    %r13,0x18(%rsp)'}}}, 'payload_reads': [['0x2c64536', 168]], 'r9_last_writer_in_fde': {'addr': '0x2c6423d', 'form': 'reg', 'reg': 'r9d', 'text': 'xor    %r9d,%r9d'}, 'tag_test': {'addr': '0x2c644d7', 'text': 'cmpb   $0x0,0xa0(%rsp)'}, 'target': 'inner_s3'}]

EXPECTED_HELPERS = {'help_440': {'direct_calls': {'0x549276d': '0x548f430', '0x54928d1': '0x35bf460', '0x54928f8': '0x4556410', '0x5492a02': '0x548ebd0', '0x5492ccd': '0x51e06d0', '0x5492dab': '0x51e06d0', '0x5492f02': '0x5248d30', '0x5492f3d': '0x5639000', '0x5492f85': '0x5637a30', '0x5493000': '0x5628210', '0x5493008': '0x63f0a50'}, 'first_call': '0x5492536', 'memcpy_calls': [{'addr': '0x5492a44', 'bindings': {'dst': 1304, 'size': 255, 'src': 297}}, {'addr': '0x5492a86', 'bindings': {'dst': 297, 'size': 255, 'src': 1304}}, {'addr': '0x5492b34', 'bindings': {'dst': 1562, 'size': 255, 'src': 297}}, {'addr': '0x5492b5f', 'bindings': {'dst': 665, 'size': 255, 'src': 1562}}, {'addr': '0x5492e0d', 'bindings': {'dst': 1817, 'size': 271, 'src': 665}}, {'addr': '0x5492e50', 'bindings': {'dst': 1033, 'size': 271, 'src': 1817}}, {'addr': '0x5492ecd', 'bindings': {'dst': 'reg:rbx', 'size': 280, 'src': 1024}}, {'addr': '0x5492fbe', 'bindings': {'dst': 665, 'size': 255, 'src': 1562}}], 'prologue_reads': {'context': [332, 333], 'query': [0, 8, 16, 24, 32, 40, 48, 56, 76, 92, 96, 97]}, 'slot_refs': {'0x5492536': ['call', '0x64e6498'], '0x5492a3d': ['load', '0x64df508'], '0x5492a86': ['call', '0x64df508'], '0x5492aa5': ['call', '0x64e7828'], '0x5492b34': ['call', '0x64df508'], '0x5492b5f': ['call', '0x64df508'], '0x5492ba2': ['call', '0x64e4ea8'], '0x5492bc7': ['call', '0x64e4ea8'], '0x5492c8e': ['call', '0x64df4a0'], '0x5492e0d': ['call', '0x64df508'], '0x5492e50': ['call', '0x64df508'], '0x5492eb3': ['call', '0x64e64a0'], '0x5492ecd': ['call', '0x64df508'], '0x5492f27': ['call', '0x64df4a0'], '0x5492f47': ['call', '0x64df4c0'], '0x5492f8c': ['call', '0x64df4c0'], '0x5492fbe': ['call', '0x64df508'], '0x549300d': ['call', '0x64df4c0']}, 'store_total': 106, 'stores_by_non_rsp_base': {'rbx': [['0x5492e1e', 8, 1], ['0x5492e22', 0, 8], ['0x5492ed8', 8, 1], ['0x5492edc', 0, 8]], 'rcx': [['0x5492648', 8, 4], ['0x5492653', 0, 8], ['0x549265d', 28, 4], ['0x5492669', 12, 16], ['0x5492984', 16, 4], ['0x5492990', 0, 16]], 'rdi': [['0x54924e1', 8, 1], ['0x54924e5', 0, 8]]}}, 'help_563': {'direct_calls': {'0x56301c4': '0x5631740', '0x5630345': '0x63f0a50'}, 'first_call': '0x5630075', 'memcpy_calls': [], 'prologue_reads': {'context': [], 'query': [0, 8, 16]}, 'slot_refs': {'0x5630075': ['call', '0x64df4a0'], '0x56300f1': ['jmp', '0x64df4a0'], '0x563015a': ['call', '0x64df4a0'], '0x5630263': ['call', '0x64df4a0'], '0x56302f1': ['jmp', '0x64df4a0'], '0x563033c': ['call', '0x64df4a0']}, 'store_total': 0, 'stores_by_non_rsp_base': {}}, 'help_660': {'direct_calls': {'0x549092f': '0x548f430', '0x5490a78': '0x35bf460', '0x5490ab5': '0x4556410', '0x5490b88': '0x548ebd0', '0x5490e4d': '0x51e06d0', '0x5490f1b': '0x51e06d0', '0x549106e': '0x5248d30', '0x54910a9': '0x5639000', '0x54910f1': '0x5637a30', '0x549117b': '0x5628210', '0x5491183': '0x63f0a50'}, 'first_call': '0x54906e1', 'memcpy_calls': [{'addr': '0x5490f79', 'bindings': {'dst': 1801, 'size': 271, 'src': 553}}, {'addr': '0x5490fbc', 'bindings': {'dst': 1017, 'size': 271, 'src': 1801}}, {'addr': '0x5491038', 'bindings': {'dst': 'reg:r14', 'size': 280, 'src': 1008}}, {'addr': '0x5491129', 'bindings': {'dst': 553, 'size': 255, 'src': 1546}}], 'prologue_reads': {'context': [], 'query': [0, 8, 16, 24, 32, 40, 48, 56, 76, 92, 96]}, 'slot_refs': {'0x54906e1': ['call', '0x64e6490'], '0x5490725': ['call', '0x64e6498'], '0x54907fd': ['load', '0x64df508'], '0x5490c7b': ['call', '0x64e7828'], '0x5490d2d': ['call', '0x64e4ea8'], '0x5490d52': ['call', '0x64e4ea8'], '0x5490e18': ['call', '0x64df4a0'], '0x5490f79': ['call', '0x64df508'], '0x5490fbc': ['call', '0x64df508'], '0x549101e': ['call', '0x64e64a0'], '0x5491038': ['call', '0x64df508'], '0x5491093': ['call', '0x64df4a0'], '0x54910b3': ['call', '0x64df4c0'], '0x54910f8': ['call', '0x64df4c0'], '0x5491129': ['call', '0x64df508'], '0x5491188': ['call', '0x64df4c0']}, 'store_total': 103, 'stores_by_non_rsp_base': {'r14': [['0x5490f36', 8, 1], ['0x5490f8a', 8, 1], ['0x5490f8e', 0, 8], ['0x5491043', 8, 1], ['0x5491048', 0, 8]], 'rcx': [['0x549083d', 8, 4], ['0x5490848', 0, 8], ['0x5490852', 28, 4], ['0x549085e', 12, 16], ['0x5490b19', 16, 4], ['0x5490b25', 0, 16]]}}, 'help_cd0': {'direct_calls': {'0x2761df3': '0x2bb68e0', '0x2761fa6': '0x2444fa0', '0x2761fc3': '0x2780be0', '0x2761fcb': '0x63f0a50'}, 'first_call': '0x2761d36', 'memcpy_calls': [{'addr': '0x2761e43', 'bindings': {'dst': 457, 'size': 271, 'src': 169}}, {'addr': '0x2761eb7', 'bindings': {'dst': 'reg:r15', 'size': 280, 'src': 448}}], 'prologue_reads': {'context': [], 'query': [0, 16, 24, 32, 40, 48, 56, 96]}, 'slot_refs': {'0x2761d36': ['call', '0x64e6490'], '0x2761d6d': ['call', '0x64e6498'], '0x2761e43': ['call', '0x64df508'], '0x2761e9d': ['call', '0x64e64a0'], '0x2761eb7': ['call', '0x64df508'], '0x2761f62': ['call', '0x64df4a0'], '0x2761fd0': ['call', '0x64df4c0']}, 'store_total': 39, 'stores_by_non_rsp_base': {'r15': [['0x2761e0e', 8, 1], ['0x2761e12', 0, 8], ['0x2761e1e', 8, 1], ['0x2761e22', 0, 8], ['0x2761ed2', 8, 1], ['0x2761ed7', 0, 8]]}}, 'help_e850': {'direct_calls': {'0x2aaea0b': '0x2ab0780', '0x2aaea33': '0x63f0a50'}, 'first_call': '0x2aae8c6', 'memcpy_calls': [], 'prologue_reads': {'context': [], 'query': [0, 8, 16]}, 'slot_refs': {'0x2aae8c6': ['call', '0x64df4a0'], '0x2aae944': ['jmp', '0x64df4a0'], '0x2aae9ab': ['call', '0x64df4a0'], '0x2aaea2a': ['call', '0x64df4a0']}, 'store_total': 0, 'stores_by_non_rsp_base': {}}, 'help_fe0': {'direct_calls': {'0x2762116': '0x2bb48c0', '0x27622b6': '0x2444fa0', '0x27622d3': '0x2780be0', '0x27622db': '0x63f0a50'}, 'first_call': '0x276209a', 'memcpy_calls': [{'addr': '0x2762156', 'bindings': {'dst': 441, 'size': 271, 'src': 153}}, {'addr': '0x27621c6', 'bindings': {'dst': 'reg:rbx', 'size': 280, 'src': 432}}], 'prologue_reads': {'context': [332, 333], 'query': [0, 16, 32, 40, 48, 56, 76, 96, 97]}, 'slot_refs': {'0x276209a': ['call', '0x64e6498'], '0x2762156': ['call', '0x64df508'], '0x27621ac': ['call', '0x64e64a0'], '0x27621c6': ['call', '0x64df508'], '0x2762270': ['call', '0x64df4a0'], '0x27622e0': ['call', '0x64df4c0']}, 'store_total': 37, 'stores_by_non_rsp_base': {'rbx': [['0x276203f', 8, 1], ['0x2762043', 0, 8], ['0x2762131', 8, 1], ['0x2762135', 0, 8], ['0x27621e1', 8, 1], ['0x27621e5', 0, 8]]}}}

EXPECTED_SITES = [{'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x2a86663', 'disp': 208, 'form': 'lea_rsp', 'text': 'lea    0xd0(%rsp),%rdi'}, 'rdx': {'addr': '0x2a8661f', 'disp': 760, 'form': 'lea_rsp', 'text': 'lea    0x2f8(%rsp),%rdx'}, 'rsi': {'addr': '0x2a86617', 'disp': 696, 'form': 'load_rsp', 'text': 'mov    0x2b8(%rsp),%rsi'}}, 'call': '0x2a8666b', 'caller': 'bwc_a1', 'head_copy_stores': [{'addr': '0x2a86642', 'disp': 208, 'text': 'movw   $0xf1,0xd0(%rsp)'}, {'addr': '0x2a8664c', 'disp': 210, 'text': 'mov    %bl,0xd2(%rsp)'}, {'addr': '0x2a8665b', 'disp': 216, 'text': 'mov    %rax,0xd8(%rsp)'}], 'helper': 'help_e850', 'preceding_call': {'addr': '0x2a86627', 'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x2a8660f', 'disp': 864, 'form': 'lea_rsp', 'text': 'lea    0x360(%rsp),%rdi'}, 'rdx': {'addr': '0x2a8661f', 'disp': 760, 'form': 'lea_rsp', 'text': 'lea    0x2f8(%rsp),%rdx'}, 'rsi': {'addr': '0x2a86617', 'disp': 696, 'form': 'load_rsp', 'text': 'mov    0x2b8(%rsp),%rsi'}}, 'target': '0x2761fe0'}, 'preceding_out_disp': 864, 'preceding_query_production': {'memcpy_into': [], 'stores': ['0x2a85c1b', '0x2a865b1', '0x2a865b9', '0x2a865c5', '0x2a865cd', '0x2a865d9', '0x2a865eb', '0x2a865fb', '0x2a86603']}, 'preceding_rsi_origin': {'slot_disp': 696, 'source_row': {'addr': '0x2a855b1', 'form': 'lea_other', 'src': '0x670(%r13)', 'text': 'lea    0x670(%r13),%rax'}, 'store': {'addr': '0x2a855b8', 'text': 'mov    %rax,0x2b8(%rsp)'}}, 'record_disp': 208, 'wrapper_call': {'addr': '0x2a86709', 'r8': {'addr': '0x2a866fe', 'disp': 208, 'form': 'lea_rsp', 'text': 'lea    0xd0(%rsp),%r8'}, 'target': '0x2a892f0'}}, {'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x2a86b8f', 'disp': 864, 'form': 'lea_rsp', 'text': 'lea    0x360(%rsp),%rdi'}, 'rdx': {'addr': '0x2a86b9f', 'disp': 760, 'form': 'lea_rsp', 'text': 'lea    0x2f8(%rsp),%rdx'}, 'rsi': {'addr': '0x2a86b97', 'disp': 696, 'form': 'load_rsp', 'text': 'mov    0x2b8(%rsp),%rsi'}}, 'call': '0x2a86ba7', 'caller': 'bwc_a1', 'ctx_production': {'form': 'frame_slot', 'last_store': {'addr': '0x2a855b8', 'text': 'mov    %rax,0x2b8(%rsp)'}, 'slot_disp': 696, 'source_row': {'addr': '0x2a855b1', 'form': 'lea_other', 'src': '0x670(%r13)', 'text': 'lea    0x670(%r13),%rax'}, 'store_count': 1}, 'helper': 'help_fe0', 'out_disp': 864, 'query_production': {'all': {'memcpy_into': [], 'stores': ['0x2a85c1b', '0x2a865b1', '0x2a865b9', '0x2a865c5', '0x2a865cd', '0x2a865d9', '0x2a865eb', '0x2a865fb', '0x2a86603', '0x2a86b31', '0x2a86b39', '0x2a86b45', '0x2a86b4d', '0x2a86b59', '0x2a86b6b', '0x2a86b7b', '0x2a86b83']}, 'prev_call': '0x2a86af5', 'since_prev_call': {'memcpy_into': [], 'stores': ['0x2a86b31', '0x2a86b39', '0x2a86b45', '0x2a86b4d', '0x2a86b59', '0x2a86b6b', '0x2a86b7b', '0x2a86b83']}}, 'record_disp': 208, 'record_transfer': {'byte_load': '0x2a86bb4', 'final_record_stores': {'byte_store': '0x2a86bf8', 'tag_store': '0x2a86bf0'}, 'tag_load': '0x2a86bac', 'tail_memcpys': [{'addr': '0x2a86be2', 'bindings': {'dst': 1504, 'size': 271, 'src': 873}}, {'addr': '0x2a86c14', 'bindings': {'dst': 217, 'size': 271, 'src': 1504}}]}, 'wrapper_call': {'addr': '0x2a86c5a', 'r8': {'addr': '0x2a86c4f', 'disp': 208, 'form': 'lea_rsp', 'text': 'lea    0xd0(%rsp),%r8'}, 'target': '0x2a892f0'}}, {'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x2a8bd03', 'disp': 112, 'form': 'lea_rsp', 'text': 'lea    0x70(%rsp),%rdi'}, 'rdx': {'addr': '0x2a8bd08', 'disp': 8, 'form': 'lea_rsp', 'text': 'lea    0x8(%rsp),%rdx'}, 'rsi': {'addr': '0x2a8bd0d', 'form': 'lea_other', 'src': '0x670(%r14)', 'text': 'lea    0x670(%r14),%rsi'}}, 'call': '0x2a8bd14', 'caller': 'bwc_a2', 'ctx_production': {'base_writer': {'addr': '0x2a8bc5a', 'form': 'reg', 'reg': 'rsi', 'text': 'mov    %rsi,%r14'}, 'form': 'lea_other', 'src': '0x670(%r14)'}, 'helper': 'help_fe0', 'out_disp': 112, 'query_production': {'all': {'memcpy_into': [], 'stores': ['0x2a8bc6b', '0x2a8bc70', '0x2a8bc78', '0x2a8bc8e', '0x2a8bc97', '0x2a8bca6', '0x2a8bcaf', '0x2a8bcb7', '0x2a8bcbc', '0x2a8bcc1', '0x2a8bcc6', '0x2a8bcd3', '0x2a8bce0', '0x2a8bcec', '0x2a8bcf0', '0x2a8bcf5', '0x2a8bcfa']}, 'prev_call': '0x2a8bc85', 'since_prev_call': {'memcpy_into': [], 'stores': ['0x2a8bc8e', '0x2a8bc97', '0x2a8bca6', '0x2a8bcaf', '0x2a8bcb7', '0x2a8bcbc', '0x2a8bcc1', '0x2a8bcc6', '0x2a8bcd3', '0x2a8bce0', '0x2a8bcec', '0x2a8bcf0', '0x2a8bcf5', '0x2a8bcfa']}}, 'record_disp': 400, 'record_transfer': {'byte_load': '0x2a8bd1e', 'final_record_stores': {'byte_store': '0x2a8bd68', 'tag_store': '0x2a8bd60'}, 'tag_load': '0x2a8bd19', 'tail_memcpys': [{'addr': '0x2a8bd4a', 'bindings': {'dst': 681, 'size': 271, 'src': 121}}, {'addr': '0x2a8bd85', 'bindings': {'dst': 409, 'size': 271, 'src': 681}}]}, 'wrapper_call': {'addr': '0x2a8bdc2', 'r8': {'addr': '0x2a8bdb4', 'disp': 400, 'form': 'lea_rsp', 'text': 'lea    0x190(%rsp),%r8'}, 'target': '0x2a892f0'}}, {'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x2c3eb7b', 'disp': 464, 'form': 'lea_rsp', 'text': 'lea    0x1d0(%rsp),%rdi'}, 'rdx': {'addr': '0x2c3eb83', 'disp': 208, 'form': 'lea_rsp', 'text': 'lea    0xd0(%rsp),%rdx'}, 'rsi': {'addr': '0x2c3eb8b', 'form': 'reg', 'reg': 'r15', 'text': 'mov    %r15,%rsi'}}, 'call': '0x2c3eb8e', 'caller': 'bwc_a3', 'ctx_production': {'form': 'register', 'writer': {'addr': '0x2c3eaac', 'form': 'lea_other', 'src': '0x670(%r13)', 'text': 'lea    0x670(%r13),%r15'}}, 'helper': 'help_cd0', 'out_disp': 464, 'query_production': {'all': {'memcpy_into': [], 'stores': ['0x2c3eaba', '0x2c3eac7', '0x2c3ead4', '0x2c3eaf3', '0x2c3eaff', '0x2c3eb12', '0x2c3eb1e', '0x2c3eb2a', '0x2c3eb32', '0x2c3eb3a', '0x2c3eb42', '0x2c3eb4f', '0x2c3eb57', '0x2c3eb5f', '0x2c3eb67', '0x2c3eb6f']}, 'prev_call': '0x2c3eaea', 'since_prev_call': {'memcpy_into': [], 'stores': ['0x2c3eaf3', '0x2c3eaff', '0x2c3eb12', '0x2c3eb1e', '0x2c3eb2a', '0x2c3eb32', '0x2c3eb3a', '0x2c3eb42', '0x2c3eb4f', '0x2c3eb57', '0x2c3eb5f', '0x2c3eb67', '0x2c3eb6f']}}, 'record_disp': 464, 'record_transfer': {'byte_load': '0x2c3eb9b', 'final_record_stores': {'byte_store': '0x2c3ec25', 'tag_store': '0x2c3ec1d'}, 'tag_load': '0x2c3eb93', 'tail_memcpys': [{'addr': '0x2c3ebd2', 'bindings': {'dst': 208, 'size': 255, 'src': 473}}, {'addr': '0x2c3ec17', 'bindings': {'dst': 473, 'size': 255, 'src': 208}}]}, 'wrapper_call': {'addr': '0x2c3ec71', 'r8': {'addr': '0x2c3ec5e', 'disp': 464, 'form': 'lea_rsp', 'text': 'lea    0x1d0(%rsp),%r8'}, 'target': '0x2a892f0'}}, {'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x54d7aad', 'disp': 160, 'form': 'lea_rsp', 'text': 'lea    0xa0(%rsp),%rdi'}, 'rdx': None, 'rsi': None}, 'call': '0x54d7ab5', 'caller': 'bwc_b1', 'head_copy_stores': [{'addr': '0x54d7a3f', 'disp': 256, 'text': 'movaps %xmm0,0x100(%rsp)'}, {'addr': '0x54d7a4f', 'disp': 240, 'text': 'movaps %xmm0,0xf0(%rsp)'}, {'addr': '0x54d7a5f', 'disp': 224, 'text': 'movaps %xmm0,0xe0(%rsp)'}, {'addr': '0x54d7a8a', 'disp': 208, 'text': 'movaps %xmm3,0xd0(%rsp)'}, {'addr': '0x54d7a92', 'disp': 192, 'text': 'movapd %xmm2,0xc0(%rsp)'}, {'addr': '0x54d7a9b', 'disp': 176, 'text': 'movdqa %xmm1,0xb0(%rsp)'}, {'addr': '0x54d7aa4', 'disp': 160, 'text': 'movdqa %xmm0,0xa0(%rsp)'}], 'helper': 'help_563', 'preceding_call': {'addr': '0x54d7a22', 'bindings': {'r8': {'addr': '0x54d7a04', 'form': 'imm', 'text': 'mov    $0x1,%r8d', 'value': 1}, 'r9': {'addr': '0x54d7a1f', 'form': 'reg', 'reg': 'rbp', 'text': 'mov    %rbp,%r9'}, 'rcx': {'addr': '0x54d79e9', 'form': 'other', 'src': '0x58(%r15', 'text': 'mov    0x58(%r15,%rbx,1),%rcx'}, 'rdi': {'addr': '0x54d7a0a', 'disp': 1840, 'form': 'lea_rsp', 'text': 'lea    0x730(%rsp),%rdi'}, 'rdx': {'addr': '0x54d7a17', 'disp': 960, 'form': 'lea_rsp', 'text': 'lea    0x3c0(%rsp),%rdx'}, 'rsi': {'addr': '0x54d7a12', 'disp': 32, 'form': 'load_rsp', 'text': 'mov    0x20(%rsp),%rsi'}}, 'target': '0x5580d10'}, 'preceding_out_disp': 1840, 'preceding_query_production': {'memcpy_into': [], 'stores': ['0x54d60bf', '0x54d60c7', '0x54d60cf', '0x54d60d7', '0x54d611d', '0x54d66c1', '0x54d66cd', '0x54d66d9', '0x54d6b22', '0x54d6b29', '0x54d6b31', '0x54d6ebf', '0x54d6ee0', '0x54d6ef8', '0x54d6f04', '0x54d6f10', '0x54d6fa2', '0x54d6ffa', '0x54d7005']}, 'preceding_rsi_origin': {'slot_disp': 32, 'source_row': None, 'store': {'addr': '0x54d57fd', 'text': 'mov    %rsi,0x20(%rsp)'}}, 'record_disp': 160, 'wrapper_call': {'addr': '0x54d7b9a', 'r8': {'addr': '0x54d7b8f', 'disp': 160, 'form': 'lea_rsp', 'text': 'lea    0xa0(%rsp),%r8'}, 'target': '0x55a03c0'}}, {'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x5583743', 'disp': 176, 'form': 'lea_rsp', 'text': 'lea    0xb0(%rsp),%rdi'}, 'rdx': {'addr': '0x55836ff', 'disp': 1016, 'form': 'lea_rsp', 'text': 'lea    0x3f8(%rsp),%rdx'}, 'rsi': {'addr': '0x55836f7', 'disp': 688, 'form': 'load_rsp', 'text': 'mov    0x2b0(%rsp),%rsi'}}, 'call': '0x558374b', 'caller': 'bwc_b2', 'head_copy_stores': [{'addr': '0x5583722', 'disp': 176, 'text': 'movw   $0xf1,0xb0(%rsp)'}, {'addr': '0x558372c', 'disp': 178, 'text': 'mov    %bl,0xb2(%rsp)'}, {'addr': '0x558373b', 'disp': 184, 'text': 'mov    %rax,0xb8(%rsp)'}], 'helper': 'help_563', 'preceding_call': {'addr': '0x5583707', 'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x55836ef', 'disp': 736, 'form': 'lea_rsp', 'text': 'lea    0x2e0(%rsp),%rdi'}, 'rdx': {'addr': '0x55836ff', 'disp': 1016, 'form': 'lea_rsp', 'text': 'lea    0x3f8(%rsp),%rdx'}, 'rsi': {'addr': '0x55836f7', 'disp': 688, 'form': 'load_rsp', 'text': 'mov    0x2b0(%rsp),%rsi'}}, 'target': '0x5492440'}, 'preceding_out_disp': 736, 'preceding_query_production': {'memcpy_into': [], 'stores': ['0x5582edb', '0x5583691', '0x5583699', '0x55836a5', '0x55836ad', '0x55836b9', '0x55836cb', '0x55836db', '0x55836e3']}, 'preceding_rsi_origin': {'slot_disp': 688, 'source_row': {'addr': '0x55828b6', 'form': 'lea_other', 'src': '0x670(%r13)', 'text': 'lea    0x670(%r13),%rax'}, 'store': {'addr': '0x55828bd', 'text': 'mov    %rax,0x2b0(%rsp)'}}, 'record_disp': 176, 'wrapper_call': {'addr': '0x55837e5', 'r8': {'addr': '0x55837da', 'disp': 176, 'form': 'lea_rsp', 'text': 'lea    0xb0(%rsp),%r8'}, 'target': '0x55a03c0'}}, {'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x5583c6f', 'disp': 736, 'form': 'lea_rsp', 'text': 'lea    0x2e0(%rsp),%rdi'}, 'rdx': {'addr': '0x5583c7f', 'disp': 1016, 'form': 'lea_rsp', 'text': 'lea    0x3f8(%rsp),%rdx'}, 'rsi': {'addr': '0x5583c77', 'disp': 688, 'form': 'load_rsp', 'text': 'mov    0x2b0(%rsp),%rsi'}}, 'call': '0x5583c87', 'caller': 'bwc_b2', 'ctx_production': {'form': 'frame_slot', 'last_store': {'addr': '0x55828bd', 'text': 'mov    %rax,0x2b0(%rsp)'}, 'slot_disp': 688, 'source_row': {'addr': '0x55828b6', 'form': 'lea_other', 'src': '0x670(%r13)', 'text': 'lea    0x670(%r13),%rax'}, 'store_count': 1}, 'helper': 'help_440', 'out_disp': 736, 'query_production': {'all': {'memcpy_into': [], 'stores': ['0x5582edb', '0x5583691', '0x5583699', '0x55836a5', '0x55836ad', '0x55836b9', '0x55836cb', '0x55836db', '0x55836e3', '0x5583c11', '0x5583c19', '0x5583c25', '0x5583c2d', '0x5583c39', '0x5583c4b', '0x5583c5b', '0x5583c63']}, 'prev_call': '0x5583bd5', 'since_prev_call': {'memcpy_into': [], 'stores': ['0x5583c11', '0x5583c19', '0x5583c25', '0x5583c2d', '0x5583c39', '0x5583c4b', '0x5583c5b', '0x5583c63']}}, 'record_disp': 176, 'record_transfer': {'byte_load': '0x5583c94', 'final_record_stores': {'byte_store': '0x5583cda', 'tag_store': '0x5583cd2'}, 'tag_load': '0x5583c8c', 'tail_memcpys': [{'addr': '0x5583cc5', 'bindings': {'dst': 'reg:r15', 'size': 271, 'src': 745}}, {'addr': '0x5583cf1', 'bindings': {'dst': 185, 'size': 271, 'src': 'reg:r15'}}]}, 'wrapper_call': {'addr': '0x5583d36', 'r8': {'addr': '0x5583d2b', 'disp': 176, 'form': 'lea_rsp', 'text': 'lea    0xb0(%rsp),%r8'}, 'target': '0x55a03c0'}}, {'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x560a073', 'disp': 112, 'form': 'lea_rsp', 'text': 'lea    0x70(%rsp),%rdi'}, 'rdx': {'addr': '0x560a078', 'disp': 8, 'form': 'lea_rsp', 'text': 'lea    0x8(%rsp),%rdx'}, 'rsi': {'addr': '0x560a07d', 'form': 'lea_other', 'src': '0x670(%r14)', 'text': 'lea    0x670(%r14),%rsi'}}, 'call': '0x560a084', 'caller': 'bwc_b4', 'ctx_production': {'base_writer': {'addr': '0x5609fca', 'form': 'reg', 'reg': 'rsi', 'text': 'mov    %rsi,%r14'}, 'form': 'lea_other', 'src': '0x670(%r14)'}, 'helper': 'help_440', 'out_disp': 112, 'query_production': {'all': {'memcpy_into': [], 'stores': ['0x5609fdb', '0x5609fe0', '0x5609fe8', '0x5609ffe', '0x560a007', '0x560a016', '0x560a01f', '0x560a027', '0x560a02c', '0x560a031', '0x560a036', '0x560a043', '0x560a050', '0x560a05c', '0x560a060', '0x560a065', '0x560a06a']}, 'prev_call': '0x5609ff5', 'since_prev_call': {'memcpy_into': [], 'stores': ['0x5609ffe', '0x560a007', '0x560a016', '0x560a01f', '0x560a027', '0x560a02c', '0x560a031', '0x560a036', '0x560a043', '0x560a050', '0x560a05c', '0x560a060', '0x560a065', '0x560a06a']}}, 'record_disp': 400, 'record_transfer': {'byte_load': '0x560a08e', 'final_record_stores': {'byte_store': '0x560a0d8', 'tag_store': '0x560a0d0'}, 'tag_load': '0x560a089', 'tail_memcpys': [{'addr': '0x560a0ba', 'bindings': {'dst': 681, 'size': 271, 'src': 121}}, {'addr': '0x560a0f5', 'bindings': {'dst': 409, 'size': 271, 'src': 681}}]}, 'wrapper_call': {'addr': '0x560a132', 'r8': {'addr': '0x560a124', 'disp': 400, 'form': 'lea_rsp', 'text': 'lea    0x190(%rsp),%r8'}, 'target': '0x55a03c0'}}, {'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x54d1dd0', 'disp': 176, 'form': 'lea_rsp', 'text': 'lea    0xb0(%rsp),%rdi'}, 'rdx': None, 'rsi': None}, 'call': '0x54d1dd8', 'caller': 'bwc_c1', 'head_copy_stores': [{'addr': '0x54d1d62', 'disp': 272, 'text': 'movaps %xmm0,0x110(%rsp)'}, {'addr': '0x54d1d72', 'disp': 256, 'text': 'movaps %xmm0,0x100(%rsp)'}, {'addr': '0x54d1d82', 'disp': 240, 'text': 'movaps %xmm0,0xf0(%rsp)'}, {'addr': '0x54d1dad', 'disp': 224, 'text': 'movaps %xmm3,0xe0(%rsp)'}, {'addr': '0x54d1db5', 'disp': 208, 'text': 'movdqa %xmm2,0xd0(%rsp)'}, {'addr': '0x54d1dbe', 'disp': 192, 'text': 'movdqa %xmm1,0xc0(%rsp)'}, {'addr': '0x54d1dc7', 'disp': 176, 'text': 'movdqa %xmm0,0xb0(%rsp)'}], 'helper': 'help_563', 'preceding_call': {'addr': '0x54d1d45', 'bindings': {'r8': {'addr': '0x54d1d27', 'form': 'imm', 'text': 'mov    $0x1,%r8d', 'value': 1}, 'r9': {'addr': '0x54d1d42', 'form': 'reg', 'reg': 'rbp', 'text': 'mov    %rbp,%r9'}, 'rcx': {'addr': '0x54d1d0c', 'form': 'other', 'src': '0x58(%r15', 'text': 'mov    0x58(%r15,%rbx,1),%rcx'}, 'rdi': {'addr': '0x54d1d2d', 'disp': 1840, 'form': 'lea_rsp', 'text': 'lea    0x730(%rsp),%rdi'}, 'rdx': {'addr': '0x54d1d3a', 'disp': 976, 'form': 'lea_rsp', 'text': 'lea    0x3d0(%rsp),%rdx'}, 'rsi': {'addr': '0x54d1d35', 'disp': 32, 'form': 'load_rsp', 'text': 'mov    0x20(%rsp),%rsi'}}, 'target': '0x55806e0'}, 'preceding_out_disp': 1840, 'preceding_query_production': {'memcpy_into': [], 'stores': ['0x54d039f', '0x54d03a7', '0x54d03af', '0x54d03b7', '0x54d03fd', '0x54d09a1', '0x54d09ad', '0x54d09b9', '0x54d0e44', '0x54d0e4f', '0x54d0e56', '0x54d11fd', '0x54d1215', '0x54d1221', '0x54d122d', '0x54d12c2', '0x54d131a', '0x54d1325']}, 'preceding_rsi_origin': {'slot_disp': 32, 'source_row': None, 'store': {'addr': '0x54d0316', 'text': 'mov    %r13,0x20(%rsp)'}}, 'record_disp': 176, 'wrapper_call': {'addr': '0x54d1ebd', 'r8': {'addr': '0x54d1eb2', 'disp': 176, 'form': 'lea_rsp', 'text': 'lea    0xb0(%rsp),%r8'}, 'target': '0x55a05d0'}}, {'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x5586853', 'disp': 176, 'form': 'lea_rsp', 'text': 'lea    0xb0(%rsp),%rdi'}, 'rdx': {'addr': '0x558680f', 'disp': 1016, 'form': 'lea_rsp', 'text': 'lea    0x3f8(%rsp),%rdx'}, 'rsi': {'addr': '0x5586807', 'disp': 688, 'form': 'load_rsp', 'text': 'mov    0x2b0(%rsp),%rsi'}}, 'call': '0x558685b', 'caller': 'bwc_c2', 'head_copy_stores': [{'addr': '0x5586832', 'disp': 176, 'text': 'movw   $0xf1,0xb0(%rsp)'}, {'addr': '0x558683c', 'disp': 178, 'text': 'mov    %bl,0xb2(%rsp)'}, {'addr': '0x558684b', 'disp': 184, 'text': 'mov    %rax,0xb8(%rsp)'}], 'helper': 'help_563', 'preceding_call': {'addr': '0x5586817', 'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x55867ff', 'disp': 736, 'form': 'lea_rsp', 'text': 'lea    0x2e0(%rsp),%rdi'}, 'rdx': {'addr': '0x558680f', 'disp': 1016, 'form': 'lea_rsp', 'text': 'lea    0x3f8(%rsp),%rdx'}, 'rsi': {'addr': '0x5586807', 'disp': 688, 'form': 'load_rsp', 'text': 'mov    0x2b0(%rsp),%rsi'}}, 'target': '0x5492440'}, 'preceding_out_disp': 736, 'preceding_query_production': {'memcpy_into': [], 'stores': ['0x5585feb', '0x55867a1', '0x55867a9', '0x55867b5', '0x55867bd', '0x55867c9', '0x55867db', '0x55867eb', '0x55867f3']}, 'preceding_rsi_origin': {'slot_disp': 688, 'source_row': {'addr': '0x55859c6', 'form': 'lea_other', 'src': '0x670(%r13)', 'text': 'lea    0x670(%r13),%rax'}, 'store': {'addr': '0x55859cd', 'text': 'mov    %rax,0x2b0(%rsp)'}}, 'record_disp': 176, 'wrapper_call': {'addr': '0x55868f5', 'r8': {'addr': '0x55868ea', 'disp': 176, 'form': 'lea_rsp', 'text': 'lea    0xb0(%rsp),%r8'}, 'target': '0x55a05d0'}}, {'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x5586d7f', 'disp': 736, 'form': 'lea_rsp', 'text': 'lea    0x2e0(%rsp),%rdi'}, 'rdx': {'addr': '0x5586d8f', 'disp': 1016, 'form': 'lea_rsp', 'text': 'lea    0x3f8(%rsp),%rdx'}, 'rsi': {'addr': '0x5586d87', 'disp': 688, 'form': 'load_rsp', 'text': 'mov    0x2b0(%rsp),%rsi'}}, 'call': '0x5586d97', 'caller': 'bwc_c2', 'ctx_production': {'form': 'frame_slot', 'last_store': {'addr': '0x55859cd', 'text': 'mov    %rax,0x2b0(%rsp)'}, 'slot_disp': 688, 'source_row': {'addr': '0x55859c6', 'form': 'lea_other', 'src': '0x670(%r13)', 'text': 'lea    0x670(%r13),%rax'}, 'store_count': 1}, 'helper': 'help_440', 'out_disp': 736, 'query_production': {'all': {'memcpy_into': [], 'stores': ['0x5585feb', '0x55867a1', '0x55867a9', '0x55867b5', '0x55867bd', '0x55867c9', '0x55867db', '0x55867eb', '0x55867f3', '0x5586d21', '0x5586d29', '0x5586d35', '0x5586d3d', '0x5586d49', '0x5586d5b', '0x5586d6b', '0x5586d73']}, 'prev_call': '0x5586ce5', 'since_prev_call': {'memcpy_into': [], 'stores': ['0x5586d21', '0x5586d29', '0x5586d35', '0x5586d3d', '0x5586d49', '0x5586d5b', '0x5586d6b', '0x5586d73']}}, 'record_disp': 176, 'record_transfer': {'byte_load': '0x5586da4', 'final_record_stores': {'byte_store': '0x5586dea', 'tag_store': '0x5586de2'}, 'tag_load': '0x5586d9c', 'tail_memcpys': [{'addr': '0x5586dd5', 'bindings': {'dst': 'reg:r15', 'size': 271, 'src': 745}}, {'addr': '0x5586e01', 'bindings': {'dst': 185, 'size': 271, 'src': 'reg:r15'}}]}, 'wrapper_call': {'addr': '0x5586e46', 'r8': {'addr': '0x5586e3b', 'disp': 176, 'form': 'lea_rsp', 'text': 'lea    0xb0(%rsp),%r8'}, 'target': '0x55a05d0'}}, {'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x5609eb3', 'disp': 112, 'form': 'lea_rsp', 'text': 'lea    0x70(%rsp),%rdi'}, 'rdx': {'addr': '0x5609eb8', 'disp': 8, 'form': 'lea_rsp', 'text': 'lea    0x8(%rsp),%rdx'}, 'rsi': {'addr': '0x5609ebd', 'form': 'lea_other', 'src': '0x670(%r14)', 'text': 'lea    0x670(%r14),%rsi'}}, 'call': '0x5609ec4', 'caller': 'bwc_c4', 'ctx_production': {'base_writer': {'addr': '0x5609e0a', 'form': 'reg', 'reg': 'rsi', 'text': 'mov    %rsi,%r14'}, 'form': 'lea_other', 'src': '0x670(%r14)'}, 'helper': 'help_440', 'out_disp': 112, 'query_production': {'all': {'memcpy_into': [], 'stores': ['0x5609e1b', '0x5609e20', '0x5609e28', '0x5609e3e', '0x5609e47', '0x5609e56', '0x5609e5f', '0x5609e67', '0x5609e6c', '0x5609e71', '0x5609e76', '0x5609e83', '0x5609e90', '0x5609e9c', '0x5609ea0', '0x5609ea5', '0x5609eaa']}, 'prev_call': '0x5609e35', 'since_prev_call': {'memcpy_into': [], 'stores': ['0x5609e3e', '0x5609e47', '0x5609e56', '0x5609e5f', '0x5609e67', '0x5609e6c', '0x5609e71', '0x5609e76', '0x5609e83', '0x5609e90', '0x5609e9c', '0x5609ea0', '0x5609ea5', '0x5609eaa']}}, 'record_disp': 400, 'record_transfer': {'byte_load': '0x5609ece', 'final_record_stores': {'byte_store': '0x5609f18', 'tag_store': '0x5609f10'}, 'tag_load': '0x5609ec9', 'tail_memcpys': [{'addr': '0x5609efa', 'bindings': {'dst': 681, 'size': 271, 'src': 121}}, {'addr': '0x5609f35', 'bindings': {'dst': 409, 'size': 271, 'src': 681}}]}, 'wrapper_call': {'addr': '0x5609f72', 'r8': {'addr': '0x5609f64', 'disp': 400, 'form': 'lea_rsp', 'text': 'lea    0x190(%rsp),%r8'}, 'target': '0x55a05d0'}}, {'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x55986bb', 'disp': 464, 'form': 'lea_rsp', 'text': 'lea    0x1d0(%rsp),%rdi'}, 'rdx': {'addr': '0x55986c3', 'disp': 208, 'form': 'lea_rsp', 'text': 'lea    0xd0(%rsp),%rdx'}, 'rsi': {'addr': '0x55986cb', 'form': 'reg', 'reg': 'r15', 'text': 'mov    %r15,%rsi'}}, 'call': '0x55986ce', 'caller': 'bwc_b3', 'ctx_production': {'form': 'register', 'writer': {'addr': '0x55985ec', 'form': 'lea_other', 'src': '0x670(%r13)', 'text': 'lea    0x670(%r13),%r15'}}, 'helper': 'help_660', 'out_disp': 464, 'query_production': {'all': {'memcpy_into': [], 'stores': ['0x55985fa', '0x5598607', '0x5598614', '0x5598633', '0x559863f', '0x5598652', '0x559865e', '0x559866a', '0x5598672', '0x559867a', '0x5598682', '0x559868f', '0x5598697', '0x559869f', '0x55986a7', '0x55986af']}, 'prev_call': '0x559862a', 'since_prev_call': {'memcpy_into': [], 'stores': ['0x5598633', '0x559863f', '0x5598652', '0x559865e', '0x559866a', '0x5598672', '0x559867a', '0x5598682', '0x559868f', '0x5598697', '0x559869f', '0x55986a7', '0x55986af']}}, 'record_disp': 464, 'record_transfer': {'byte_load': '0x55986db', 'final_record_stores': {'byte_store': '0x5598765', 'tag_store': '0x559875d'}, 'tag_load': '0x55986d3', 'tail_memcpys': [{'addr': '0x5598712', 'bindings': {'dst': 208, 'size': 255, 'src': 473}}, {'addr': '0x5598757', 'bindings': {'dst': 473, 'size': 255, 'src': 208}}]}, 'wrapper_call': {'addr': '0x55987b1', 'r8': {'addr': '0x559879e', 'disp': 464, 'form': 'lea_rsp', 'text': 'lea    0x1d0(%rsp),%r8'}, 'target': '0x55a03c0'}}, {'bindings': {'r8': None, 'r9': None, 'rcx': None, 'rdi': {'addr': '0x559c52b', 'disp': 464, 'form': 'lea_rsp', 'text': 'lea    0x1d0(%rsp),%rdi'}, 'rdx': {'addr': '0x559c533', 'disp': 208, 'form': 'lea_rsp', 'text': 'lea    0xd0(%rsp),%rdx'}, 'rsi': {'addr': '0x559c53b', 'form': 'reg', 'reg': 'r15', 'text': 'mov    %r15,%rsi'}}, 'call': '0x559c53e', 'caller': 'bwc_c3', 'ctx_production': {'form': 'register', 'writer': {'addr': '0x559c45c', 'form': 'lea_other', 'src': '0x670(%r13)', 'text': 'lea    0x670(%r13),%r15'}}, 'helper': 'help_660', 'out_disp': 464, 'query_production': {'all': {'memcpy_into': [], 'stores': ['0x559c46a', '0x559c477', '0x559c484', '0x559c4a3', '0x559c4af', '0x559c4c2', '0x559c4ce', '0x559c4da', '0x559c4e2', '0x559c4ea', '0x559c4f2', '0x559c4ff', '0x559c507', '0x559c50f', '0x559c517', '0x559c51f']}, 'prev_call': '0x559c49a', 'since_prev_call': {'memcpy_into': [], 'stores': ['0x559c4a3', '0x559c4af', '0x559c4c2', '0x559c4ce', '0x559c4da', '0x559c4e2', '0x559c4ea', '0x559c4f2', '0x559c4ff', '0x559c507', '0x559c50f', '0x559c517', '0x559c51f']}}, 'record_disp': 464, 'record_transfer': {'byte_load': '0x559c54b', 'final_record_stores': {'byte_store': '0x559c5d5', 'tag_store': '0x559c5cd'}, 'tag_load': '0x559c543', 'tail_memcpys': [{'addr': '0x559c582', 'bindings': {'dst': 208, 'size': 255, 'src': 473}}, {'addr': '0x559c5c7', 'bindings': {'dst': 473, 'size': 255, 'src': 208}}]}, 'wrapper_call': {'addr': '0x559c621', 'r8': {'addr': '0x559c60e', 'disp': 464, 'form': 'lea_rsp', 'text': 'lea    0x1d0(%rsp),%r8'}, 'target': '0x55a05d0'}}]

EXPECTED_SLOT_FACTS = {'0x64df508': {'initialised_content': '0x0', 'rela_type': 6, 'slot': '0x64df508', 'symbol': 'memcpy'}, '0x64dfaf8': {'addend': '0x63efec0', 'initialised_content': '0x0', 'rela_type': 8, 'slot': '0x64dfaf8'}, '0x64e4ea8': {'addend': '0x4524e40', 'initialised_content': '0x0', 'rela_type': 8, 'slot': '0x64e4ea8'}, '0x64e71b8': {'addend': '0x434f790', 'initialised_content': '0x0', 'rela_type': 8, 'slot': '0x64e71b8'}}


def analyze(data):
    if hashlib.sha256(data).hexdigest() != NODE_SHA256 \
            or len(data) != NODE_SIZE:
        raise PacketError('artifact SHA-256 mismatch')
    secs = sections(data)
    _summary, ordered, _gaps = fde_extents(data)
    fde_set = {(o['start'], o['end']) for o in ordered}
    rows = {}
    bodies = {}
    for name, (start, end, exported) in BODIES.items():
        if (start, end) not in fde_set:
            raise PacketError(f'{name} range is not an FDE extent')
        rows[name] = _decode(data, secs, start, end)
        bodies[name] = {'start': _hx(start), 'end': _hx(end),
                        'size': end - start,
                        'sha256': _digest(data, secs, start, end),
                        'instructions': len(rows[name]), 'exported': exported}
    inner = {name: _inner_body(rows[name])
             for name in ('inner_ca', 'inner_s3')}
    inner_sites = []
    for caller in ('sublookup_ca', 'helper_s3a'):
        inner_sites.extend(_inner_sites(caller, rows[caller]))
    helpers = {name: _helper(rows[name], name) for name in
               ('help_cd0', 'help_fe0', 'help_e850', 'help_660', 'help_440',
                'help_563')}
    sites = [_producer_site(rows[caller], caller, call, helper, record_disp)
             for caller, call, helper, record_disp in PRODUCER_SITES]
    relas = _rela_entries(data, secs)
    slot_facts = {}
    for slot in (DIV_SLOT, GATE_SLOT, PANIC_SLOT, MEMCPY_SLOT):
        slot_facts[_hx(slot)] = _slot_resolution(data, secs, relas, slot)
    if bodies != EXPECTED_BODIES or inner != EXPECTED_INNER \
            or inner_sites != EXPECTED_INNER_SITES \
            or helpers != EXPECTED_HELPERS or sites != EXPECTED_SITES \
            or slot_facts != EXPECTED_SLOT_FACTS:
        raise PacketError('inner-bodies analysis drift')
    for name, body_rows in rows.items():
        _check_pins_subset(body_rows, PINNED_ROWS.get(name, {}),
                           f'{name} pins')
    counters = {
        'bodies': len(BODIES),
        'exported_bodies': sum(1 for _s, _e, x in BODIES.values() if x),
        'inner_bodies': len(inner),
        'inner_call_sites': len(inner_sites),
        'producer_helpers': len(helpers),
        'producer_sites': len(sites),
        'inspector_helpers': len(INSPECTORS),
        'inspector_stores': sum(helpers[n]['store_total'] for n in INSPECTORS),
        'inner_memcpy_slot_refs': sum(
            len(inner[n]['memcpy_slot_refs']) for n in inner),
        'inner_non_frame_stores': sum(
            len(inner[n]['store_census']['non_rsp_stores']) for n in inner),
    }
    return {
        'artifact': {'sha256': NODE_SHA256, 'size': NODE_SIZE},
        'upstream_main': UPSTREAM_MAIN,
        'bodies': bodies,
        'counters': counters,
        'inner_bodies': inner,
        'inner_call_sites': inner_sites,
        'producer_helpers': helpers,
        'producer_sites': sites,
        'slot_facts': slot_facts,
        'verdict': 'inner_ca and inner_s3 produce no record of the '
                   '{tag, byte, 0x10f tail} family: each writes one tagged '
                   'result struct through its first argument (tag 0 + six '
                   'accumulated qwords on success, tag 1 + a code byte in '
                   '{2, 3, 7, 9} on failure) and stores nowhere else except '
                   'its own frame; of the six producer helpers, four '
                   '(0x2761cd0, 0x2761fe0, 0x5490660, 0x5492440) produce the '
                   '0x118 record through their rdi out pointer, and two '
                   '(0x5630000, 0x2aae850) are zero-store serialised-form '
                   'inspectors mislabelled as producers upstream',
    }


def generate(data, out_dir):
    records = analyze(data)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (out_dir / 'frames.txt').write_text(_frames(data))
    for name, (start, end, exported) in BODIES.items():
        if exported:
            (out_dir / _export_name(name, start, end)).write_text(
                _body_export(data, start, end))
    return records


def main(argv):
    if len(argv) != 3 or argv[1] != 'generate':
        raise SystemExit(
            'usage: inner_bodies_static.py generate <out-dir>')
    artifact = ROOT / 'artifacts/node/115/hl-node'
    generate(artifact.read_bytes(), argv[2])
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
