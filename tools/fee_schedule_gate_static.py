#!/usr/bin/env python3
"""RE-001: node115 fee-schedule ordering/range gate and its fees.rs:259 window helper.

Static, target-bound mapping of one bounded region of the #115 function that
owns the `l1/src/fees/fees.rs` Location used by the outlined window helper.
The certificate is derived from captured bytes: element kind, comparison
operand order, branch condition codes, entry thresholds, failure targets and
literal bounds are decoded, never asserted from a narrative. No captured code
is executed.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT/'artifacts/node/115/hl-node'
PACKET = ROOT/'research/work-items/RE-001-node115-fee-schedule-gate'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
HELPER = (0x36e1b10, 0x36e1b81)
CALLER = (0x36a1c20, 0x36a31ff)
BODY_SHA = {HELPER: '797d92bc053c6234472fd132891f7dc29d47559c59d973c407e3a68deb22a886',
            CALLER: '45568f355844c8f90a4946e95dc2be74d014377b5745225cdf31f5e2c205a697'}
# Half-open caller windows exported for review: the ordering/range chain, the
# post-pair cap/range tail, and the shared normal-return failure path.
WINDOWS = {'chain': (0x36a265e, 0x36a2899), 'tail': (0x36a2a0d, 0x36a2a8b),
           'failure': (0x36a2ad6, 0x36a2c12), 'once': (0x36a2c12, 0x36a2c56)}
LOCATION = (0x6468b98, 'l1/src/fees/fees.rs', 259, 57)
PANIC_SLOT, PANIC_TARGET = 0x64df620, 0x1680cbf
PANIC_TEMPLATE = (0x4400ef, b' index out of bounds: the len is ')
FAIL, RANGE_FAIL = 0x36a2ad6, 0x36a2ae4
ONCE = (0x36a2c12, 0x36a2c56)   # Once-state side branch of the first failure entry
# (block start, loop head) of each inlined slice-window check, in order.
LOOPS = [(0x36a2674, 0x36a2690), (0x36a26ad, 0x36a26d0), (0x36a26ed, 0x36a2710),
         (0x36a272d, 0x36a2750), (0x36a276d, 0x36a2780), (0x36a279d, 0x36a27b0),
         (0x36a27cd, 0x36a27db), (0x36a27f6, 0x36a27fa)]
NOPS = {bytes.fromhex(h) for h in ['0f1f840000000000', '0f1f440000',
                                   '666666666666' '2e0f1f840000000000']}
CC = {0x72: 'jb', 0x73: 'jae', 0x76: 'jbe', 0x77: 'ja', 0x84: 'je', 0x86: 'jbe', 0x87: 'ja'}
# Vector seeds: the first element stored before each local vector's (cap, ptr, len)
# triple is published. Addresses are instruction starts in the caller body.
SEEDS = [{'vector': 'rsp+0x90', 'element0': 'input+0x68 f64',
          'sites': {0x36a1c34: 'f20f104768', 0x36a1c92: 'f20f10842430010000', 0x36a1c9b: 'f20f1100', 0x36a1d11: '4c89b42490000000'}},
         {'vector': 'rsp+0xa8', 'element0': 'input+0x70 f64',
          'sites': {0x36a1c42: 'f20f104770', 0x36a1cbf: 'f20f1100', 0x36a1d31: '4c89bc24a8000000'}},
         {'vector': 'rsp+0xc0', 'element0': 'input+0x78 f64',
          'sites': {0x36a1c50: 'f20f104778', 0x36a1ce3: 'f20f1100', 0x36a1d51: '4c89a424c0000000'}},
         {'vector': 'rsp+0xd8', 'element0': 'input+0x80 f64',
          'sites': {0x36a1c5e: 'f20f108780000000', 0x36a1d01: 'f20f1100', 0x36a1d71: '48898424d8000000'}},
         {'vector': 'rsp+0x68', 'element0': 'u64 0',
          'sites': {0x36a1d99: '48c70000000000', 0x36a1da9: '4889442468'}},
         {'vector': 'rsp+0x50', 'element0': 'f64 1.0 (0x3ff0000000000000)',
          'sites': {0x36a1dcb: '48b9000000000000f03f', 0x36a1dd5: '488908', 0x36a1de1: '4889442450'}}]
INPUT_BINDINGS = {0x36a265e: '660f28842400010000', 0x36a2667: '660f15c0', 0x36a266b: '660f29842410010000',
                  0x36a1c31: '4889fb', 0x36a1c6c: '0f108788000000', 0x36a1c73: '0f29842400010000',
                  0x36a1def: '48899c2438010000', 0x36a20ad: '488bac2438010000',
                  0x36a2847: '488b5538', 0x36a284b: '488b4d40'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read(data, va, n):
    rows = [s for s in sections(data) if s['type'] != 8 and s['address'] <= va and va+n <= s['address']+s['size']]
    require(len(rows) == 1, 'expected one file-backed mapping')
    s = rows[0]
    o = s['offset']+va-s['address']
    return o, bytes(data[o:o+n])


def code(data, va, n):
    return read(data, va, n)[1]


def rel8(va, b, length=2):
    return va+length+struct.unpack('<b', b[length-1:length])[0]


def rel32(va, b, length):
    return va+length+struct.unpack('<i', b[length-4:length])[0]


def flags(kind, lhs, rhs):
    """CF/ZF after `ucomisd lhs, rhs` (f64) or unsigned `cmp lhs, rhs` (u64)."""
    if kind == 'f64' and (math.isnan(lhs) or math.isnan(rhs)):
        return True, True
    return lhs < rhs, lhs == rhs


def taken(cc, cf, zf):
    return {'jb': cf, 'jae': not cf, 'jbe': cf or zf, 'ja': not (cf or zf)}[cc]


def parse_loop(data, start, head):
    """Decode one inlined `slice.windows(2)` style check from its bytes."""
    at = start
    b = code(data, at, 4)
    if b == bytes.fromhex('498d4608'):          # lea rax,[r14+8]: register-held slice
        source = {'pointer': 'r14', 'length': 'rbx'}
        at += 4
        lenreg = 'rbx'
    else:
        source = {}
        for reg, short, long_ in [('pointer', '488b4424', '488b8424'), ('length', '488b4c24', '488b8c24')]:
            b = code(data, at, 8)
            if b[:4] == bytes.fromhex(short):
                source[reg] = f'rsp+{b[4]:#x}'
                at += 5
            elif b[:4] == bytes.fromhex(long_):
                source[reg] = f"rsp+{struct.unpack_from('<I', b, 4)[0]:#x}"
                at += 8
            else:
                raise ValueError('slice load changed')
        require(code(data, at, 4) == bytes.fromhex('4883c008'), 'element advance changed')
        at += 4
        lenreg = 'rcx'
    while at < head:
        n = next((len(x) for x in NOPS if code(data, at, len(x)) == x), None)
        require(n is not None, 'loop alignment padding changed')
        at += n
    require(at == head, 'loop head moved')
    b = code(data, at, 6)
    require(b[:3] == (bytes.fromhex('4883f9') if lenreg == 'rcx' else bytes.fromhex('4883fb')), 'length test changed')
    threshold, entry_cc = b[3], CC.get(b[4])
    require(entry_cc in ('jb', 'jbe'), 'length exit condition changed')
    exit_to = rel8(at+4, b[4:6])
    at += 6
    require(code(data, at, 3) == (bytes.fromhex('48ffc9') if lenreg == 'rcx' else bytes.fromhex('48ffcb')), 'length decrement changed')
    at += 3
    forms = {bytes.fromhex('f20f100066 0f2e40f8'.replace(' ', '')): ('f64', 'next', 'prev'),
             bytes.fromhex('f20f1040f8660f2e00'): ('f64', 'prev', 'next'),
             bytes.fromhex('488b50f8483b10'): ('u64', 'prev', 'next')}
    form = None
    for raw, meaning in forms.items():
        if code(data, at, len(raw)) == raw:
            form, at = meaning, at+len(raw)
            break
    require(form is not None, 'element comparison changed')
    require(code(data, at, 4) == bytes.fromhex('488d4008'), 'cursor advance changed')
    at += 4
    b = code(data, at, 2)
    loop_cc = CC.get(b[0])
    require(loop_cc in ('jb', 'jbe', 'ja', 'jae') and rel8(at, b) == head, 'loop back-edge changed')
    at += 2
    b = code(data, at, 5)
    require(b[0] == 0xe9, 'failure jump changed')
    fail = rel32(at, b, 5)
    return {'start': hex(start), 'head': hex(head), 'source': source, 'element': form[0],
            'lhs': form[1], 'rhs': form[2], 'continue_if': loop_cc,
            'exit_when_remaining': f'{entry_cc} {threshold}', 'exit_to': hex(exit_to),
            'fail_to': hex(fail)}, at+5


def loop_passes(desc, values):
    """Independent interpretation of a decoded certificate (not a CPU model)."""
    cc, threshold = desc['exit_when_remaining'].split()
    threshold = int(threshold)
    remaining, i = len(values), 0
    while True:
        cf, zf = remaining < threshold, remaining == threshold
        if taken(cc, cf, zf):
            return True
        remaining -= 1
        pair = {'prev': values[i], 'next': values[i+1]}
        cf, zf = flags(desc['element'], pair[desc['lhs']], pair[desc['rhs']])
        if not taken(desc['continue_if'], cf, zf):
            return False
        i += 1


def parse_helper(data):
    a = HELPER[0]
    b = code(data, a, HELPER[1]-a)
    require(b[0x01:0x0c] == bytes.fromhex('488b7710488b17488b4f08'), 'helper window-state loads changed')
    require(b[0x0c:0x10] == bytes.fromhex('4883fe02') and b[0x10] == 0x72 and rel8(a+0x10, b[0x10:0x12]) == a+0x43, 'helper size test changed')
    require(b[0x12:0x16] == bytes.fromhex('4883c208'), 'helper element advance changed')
    loop = 0x20
    require(b[loop:loop+6] == bytes.fromhex('4839ce0f96c0'), 'helper size/remaining comparison changed')
    exit_cc = CC.get(b[0x26])
    require(exit_cc in ('ja', 'jae', 'jb', 'jbe') and rel8(a+0x26, b[0x26:0x28]) == a+0x41, 'helper loop exit changed')
    require(b[0x28:0x32] == bytes.fromhex('48ffc948891748894f08'), 'helper window-state stores changed')
    require(b[0x32:0x3b] == bytes.fromhex('f20f1002660f2e42f8'), 'helper element comparison changed')
    require(b[0x3b:0x3f] == bytes.fromhex('488d5208'), 'helper cursor advance changed')
    cont_cc = CC.get(b[0x3f])
    require(cont_cc in ('ja', 'jae', 'jb', 'jbe') and rel8(a+0x3f, b[0x3f:0x41]) == a+loop, 'helper back-edge changed')
    require(b[0x41:0x43] == bytes.fromhex('59c3'), 'helper result return changed')
    require(b[0x43:0x46] == bytes.fromhex('4885c9') and b[0x46] == 0x75 and rel8(a+0x46, b[0x46:0x48]) == a+0x4c, 'helper empty test changed')
    require(b[0x48:0x4c] == bytes.fromhex('31c059c3'), 'helper empty result changed')
    require(b[0x5a:0x5d] == bytes.fromhex('488d15') and b[0x61] == 0xbf and b[0x66] == 0xbe and b[0x6b:0x6d] == b'\xff\x15', 'helper panic call changed')
    loc = rel32(a+0x5a, b[0x5a:0x61], 7)
    slot = rel32(a+0x6b, b[0x6b:0x71], 6)
    index, length = struct.unpack_from('<I', b, 0x62)[0], struct.unpack_from('<I', b, 0x67)[0]
    return {'state': {'cursor': '+0x0', 'remaining': '+0x8', 'window_size': '+0x10'},
            'exit_if': f'size {exit_cc} remaining', 'continue_if': f'next {cont_cc} prev',
            'result_on_comparison_exit': 'AL from setbe(size<=remaining) at loop top',
            'result_on_size_exit': 'AL from setbe(size<=remaining) at loop top',
            'result_size_below_2_empty': 'AL=0',
            'size_below_2_nonempty': {'index': index, 'len': length, 'location': hex(loc), 'slot': hex(slot)},
            'state_stores': 'cursor +0x0 and remaining +0x8 are written back before each comparison'}


def helper_any(desc, size, values):
    """Independent interpretation of the decoded helper certificate."""
    exit_cc = desc['exit_if'].split()[1]
    cont_cc = desc['continue_if'].split()[1]
    remaining, i = len(values), 0
    if size < 2:
        if remaining == 0:
            return False
        bad = desc['size_below_2_nonempty']
        raise IndexError((bad['index'], bad['len']))
    while True:
        result = size <= remaining
        if taken(exit_cc, size < remaining, size == remaining):
            return result
        remaining -= 1
        cf, zf = flags('f64', values[i+1], values[i])
        i += 1
        if not taken(cont_cc, cf, zf):
            return result


def parse_pairs_and_ranges(data):
    at = 0x36a2817
    b = code(data, at, 0x30)
    require(b[:6] == bytes.fromhex('660f10442450'), 'helper slice source changed')
    require(b[0xf:0x17] == bytes.fromhex('48c7842450010000'), 'helper size store changed')
    require(b[0x6:0xf] == bytes.fromhex('660f11842440010000') and b[0x1b:0x23] == bytes.fromhex('488dbc2440010000'), 'helper state construction changed')
    size = struct.unpack_from('<I', b, 0x17)[0]
    call = 0x36a283a
    cb = code(data, call, 5)
    require(cb[0] == 0xe8 and rel32(call, cb, 5) == HELPER[0], 'helper call changed')
    jb = code(data, 0x36a283f, 8)
    require(jb[:4] == bytes.fromhex('84c00f85') and rel32(0x36a2841, jb[2:], 6) == FAIL, 'helper result gate changed')
    p = code(data, 0x36a2847, 0x52)
    require(p[:8] == bytes.fromhex('488b5538488b4d40'), 'pair slice load changed')
    require(p[0xb:0xf] == bytes.fromhex('48c1e604'), 'pair stride changed')
    require(p[0x13:0x1b] == bytes.fromhex('660f57c9660f57c0'), 'pair initial values changed')
    require(p[0x1b:0x20] == bytes.fromhex('4885f60f84') and rel32(0x36a2865, p[0x1e:0x24], 6) == 0x36a2a0d, 'pair empty exit changed')
    require(p[0x24:0x28] == bytes.fromhex('f20f1012') and p[0x28:0x2c] == bytes.fromhex('660f2ed1'), 'pair first comparison changed')
    first_cc = CC.get(p[0x2d])
    require(p[0x2c] == 0x0f and rel32(0x36a2873, p[0x2c:0x32], 6) == FAIL, 'pair first failure changed')
    require(p[0x32:0x37] == bytes.fromhex('f20f105a08') and p[0x3f:0x43] == bytes.fromhex('660f2ed8'), 'pair second comparison changed')
    second_cc = CC.get(p[0x4b])
    require(rel8(0x36a2892, p[0x4b:0x4d]) == 0x36a2862, 'pair back-edge changed')
    require(p[0x4d] == 0xe9 and rel32(0x36a2894, p[0x4d:0x52], 5) == FAIL, 'pair failure changed')
    caps = []
    for site, reg, modrm in [(0x36a2a0d, 'first', 0x0d), (0x36a2a1b, 'second', 0x05)]:
        c = code(data, site, 14)
        require(c[:3] == bytes.fromhex('660f2e') and c[3] == modrm, 'pair cap comparison changed')
        const = rel32(site, c, 8)
        cc = CC.get(c[9])
        require(c[8] == 0x0f and rel32(site+8, c[8:14], 6) == FAIL, 'pair cap failure changed')
        caps.append({'component': reg, 'const_va': hex(const), 'value': struct.unpack('<d', code(data, const, 8))[0], 'fail_if': cc})
    ranges = []
    for name, disp, lo_site, hi_site in [('input+0x88', 0x100, 0x36a2a47, 0x36a2a5f), ('input+0x90', 0x110, 0x36a2a6d, 0x36a2a81)]:
        lo = code(data, lo_site, 15)
        require(lo[:5] == bytes.fromhex('660f2e8424') and struct.unpack_from('<I', lo, 5)[0] == disp, 'range lower comparison changed')
        require(code(data, hi_site-9, 9) == bytes.fromhex('660f288424') + struct.pack('<I', disp), 'range upper operand load changed')
        lo_cc = CC.get(lo[10] if lo[9] == 0x0f else lo[9])
        lo_target = rel32(lo_site+9, lo[9:15], 6) if lo[9] == 0x0f else rel8(lo_site+9, lo[9:11])
        hi = code(data, hi_site, 10)
        require(hi[:4] == bytes.fromhex('660f2e05'), 'range upper comparison changed')
        const = rel32(hi_site, hi, 8)
        hi_cc = CC.get(hi[8])
        hi_target = rel8(hi_site+8, hi[8:10])
        require(lo_target == RANGE_FAIL and hi_target == RANGE_FAIL, 'range failure target changed')
        ranges.append({'value': name, 'lower': 0.0, 'lower_fail_if': f'0.0 {lo_cc} value',
                       'upper_const_va': hex(const), 'upper': struct.unpack('<d', code(data, const, 8))[0],
                       'upper_fail_if': f'value {hi_cc} upper'})
    require(code(data, 0x36a2a69, 4) == bytes.fromhex('660f57c0') and code(data, 0x36a2a29, 4) == bytes.fromhex('660f57c0'), 'range zero operand changed')
    return {'helper_window_size': size, 'pairs': {'source': {'pointer': 'input+0x38', 'length': 'input+0x40'},
            'stride': 16, 'initial_previous': [0.0, 0.0],
            'first_component_fail_if': f'first {first_cc} previous_first', 'second_component_continue_if': f'second {second_cc} previous_second',
            'caps_on_last_or_initial': caps}, 'ranges': ranges}


def pair_passes(desc, pairs):
    prev_a = prev_b = 0.0
    fa = desc['first_component_fail_if'].split()[1]
    sb = desc['second_component_continue_if'].split()[1]
    for a, b in pairs:
        cf, zf = flags('f64', a, prev_a)
        if taken(fa, cf, zf):
            return False
        cf, zf = flags('f64', b, prev_b)
        if not taken(sb, cf, zf):
            return False
        prev_a, prev_b = a, b
    for cap, v in zip(desc['caps_on_last_or_initial'], (prev_a, prev_b)):
        cf, zf = flags('f64', v, cap['value'])
        if taken(cap['fail_if'], cf, zf):
            return False
    return True


def range_passes(desc, value):
    cf, zf = flags('f64', 0.0, value)
    if taken(desc['lower_fail_if'].split()[1], cf, zf):
        return False
    cf, zf = flags('f64', value, desc['upper'])
    return not taken(desc['upper_fail_if'].split()[1], cf, zf)


def certificate(data):
    """Byte-derived semantic certificate; does not enforce the pinned body hashes."""
    loops, at = [], None
    for start, head in LOOPS:
        require(at is None or at == start, 'checks are not contiguous')
        desc, at = parse_loop(data, start, head)
        loops.append(desc)
    for i, desc in enumerate(loops):
        nxt = LOOPS[i+1][0] if i+1 < len(LOOPS) else 0x36a2817
        require(int(desc['exit_to'], 16) == nxt, 'loop exit does not reach next check')
        require(int(desc['fail_to'], 16) == FAIL, 'loop failure does not reach the shared failure entry')
    tail = parse_pairs_and_ranges(data)
    return {'loops': loops, 'helper': parse_helper(data), **tail}


def analyze(data):
    """Public entry: authenticates the entire capture before any parsing."""
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA, 'expected pinned node115')
    return _analyze(data)


def _analyze(data):
    """Obligation checks below the identity gate (used by corruption controls)."""
    cert = certificate(data)
    _, fs, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs}
    secs = sections(data)
    rs = next(s for s in secs if s['name'] == '.rela.dyn')
    rels = {}
    for a, i, v in struct.iter_unpack('<QQq', data[rs['offset']:rs['offset']+rs['size']]):
        require(a not in rels, 'duplicate relocation slot')
        rels[a] = (i, v)
    slot, path, line, column = LOCATION
    info, target = rels.get(slot, (None, None))
    require(info == 8 and code(data, target, len(path)) == path.encode()
            and code(data, slot+8, 16) == struct.pack('<QII', len(path), line, column), 'fees.rs Location changed')
    require(rels.get(PANIC_SLOT) == (8, PANIC_TARGET), 'bounds-panic slot changed')
    require(code(data, PANIC_TEMPLATE[0], len(PANIC_TEMPLATE[1])) == PANIC_TEMPLATE[1], 'bounds-panic template changed')
    require(cert['helper']['size_below_2_nonempty']['location'] == hex(slot)
            and cert['helper']['size_below_2_nonempty']['slot'] == hex(PANIC_SLOT), 'helper panic binding changed')
    pc = code(data, PANIC_TARGET, 0x3d)
    require(rel32(PANIC_TARGET+0x30, pc[0x30:0x37], 7) == PANIC_TEMPLATE[0], 'bounds-panic template reference changed')
    for seed in SEEDS:
        for site, hexa in seed['sites'].items():
            require(code(data, site, len(hexa)//2) == bytes.fromhex(hexa), 'vector seed changed')
    for site, hexa in INPUT_BINDINGS.items():
        require(code(data, site, len(hexa)//2) == bytes.fromhex(hexa), 'input binding changed')
    for site, hexa in {0x36a2b5b: '31ed', 0x36a2b5d: 'bb00000000', 0x36a2b78: '89eb', 0x36a2bfe: '89d8', 0x36a2c11: 'c3'}.items():
        require(code(data, site, len(hexa)//2) == bytes.fromhex(hexa), 'failure return changed')
    owners = []
    for role, (a, b) in [('window_helper', HELPER), ('fee_schedule_validator', CALLER)]:
        require((a, b) in fdes, 'scope FDE changed')
        offset, raw = read(data, a, b-a)
        require(hashlib.sha256(raw).hexdigest() == BODY_SHA[(a, b)], 'scope body changed')
        f = fdes[(a, b)]
        records = {}
        for kind in ['fde', 'cie']:
            v = f[kind]
            n = struct.unpack('<I', code(data, v, 4))[0]+4
            records[kind] = {'va': hex(v), 'bytes_hex': code(data, v, n).hex()}
        owners.append({'role': role, 'start': hex(a), 'end': hex(b), 'file_offset': hex(offset),
                       'bytes': b-a, 'sha256': BODY_SHA[(a, b)], 'frames': records})
    return {'target_sha256': SHA, 'owners': owners,
            'claimed_windows': {k: [hex(a), hex(b)] for k, (a, b) in WINDOWS.items()},
            'location': {'slot': hex(slot), 'path_va': hex(target), 'path': path, 'line': line, 'column': column},
            'bounds_panic': {'slot': hex(PANIC_SLOT), 'target': hex(PANIC_TARGET), 'template_va': hex(PANIC_TEMPLATE[0])},
            'vector_seeds': [{'vector': s['vector'], 'element0': s['element0'], 'sites': sorted(hex(x) for x in s['sites'])} for s in SEEDS],
            'certificate': cert,
            'failure_return': 'both failure entries reach `mov ebx,0`, `mov ebx,ebp` (EBP=0) and `mov eax,ebx; ret` on the normal-call path',
            'captured_code_executed': False,
            'limits': 'Bounded windows of one validator only. Contents appended to the local vectors after element 0, the r14/rbx and rsp+0x20/0x38 vector origins, the 0x3d3b6c0 gate, the success path and all non-claimed caller code are not recovered. Calls are assumed to return normally with ABI-preserved registers; panic/unwind and allocator failure are excluded. No source type, field name or progress gate is claimed.'}


CFG_TERMINAL = re.compile(r'^(ret|ud2|int3|hlt)\b')


def native_cfg(asm, start, end):
    """Basic CFG of the caller from native GNU decoding (direct edges only)."""
    rows = []
    for line in asm.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\t(?:[0-9a-f]{2} )+\s*\t(.*)$', line)
        if m:
            rows.append((int(m[1], 16), m[2].strip()))
    addrs = [a for a, _ in rows]
    succ, text, indirect = {}, dict(rows), []
    for i, (a, ins) in enumerate(rows):
        nxt = addrs[i+1] if i+1 < len(addrs) else None
        m = re.match(r'^(j[a-z]+)\s+([0-9a-f]+)\b', ins)
        if m:
            t = int(m[2], 16)
            succ[a] = [t] if m[1] == 'jmp' else [t, nxt]
        elif ins.startswith('jmp'):
            succ[a] = []
            indirect.append(a)
        elif CFG_TERMINAL.match(ins):
            succ[a] = []
        else:
            succ[a] = [nxt]
    return succ, text, indirect


def writes(ins, regs):
    m = re.match(r'^([a-z0-9]+)\s+([a-z0-9]+)\b', ins)
    if not m:
        return False
    op, dst = m[1], m[2]
    if op in ('cmp', 'test', 'ucomisd', 'push', 'call') or op.startswith('j'):
        return False
    return dst in regs


def forward_only(text, start, stop):
    """Every direct branch in [start, stop) targets a later address <= stop."""
    for a, ins in text.items():
        if start <= a < stop and ins.startswith('j'):
            m = re.match(r'^j[a-z]+\s+([0-9a-f]+)\b', ins)
            if not m or not a < int(m[1], 16) <= stop:
                return False
    return True


def reach_until(succ, src, stop):
    """Instructions reachable from src along direct edges without passing stop."""
    seen, stack = set(), [src]
    while stack:
        a = stack.pop()
        if a is None or a in seen or a == stop:
            continue
        seen.add(a)
        stack.extend(succ.get(a, []))
    return seen


def path_through(succ, src, dst, bad):
    """True if some direct-edge path src->...->dst visits an instruction in `bad`."""
    def reach(start, avoid_dst=False):
        seen, stack = set(), [start]
        while stack:
            a = stack.pop()
            if a in seen or a is None:
                continue
            seen.add(a)
            for s in succ.get(a, []):
                stack.append(s)
        return seen
    from_src = reach(src)
    return any(b in from_src and dst in reach(b) for b in bad)


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('expected pinned node115')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    with tempfile.TemporaryDirectory() as directory:
        snap = Path(directory)/'node115.elf'
        snap.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snap)], text=True)
        for a, b in [HELPER, CALLER]:
            matched = [l for l in frames.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            require(len(matched) == 1, 'native FDE disagreement')
            rows.extend(matched)

        def dis(a, b):
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                           f'--start-address={a:#x}', f'--stop-address={b:#x}', str(snap)], text=True)
            return asm, decode_export(asm, a, b, code(data, a, b-a))
        asm, ins = dis(*HELPER)
        (output/'helper.objdump.txt').write_bytes(asm.replace(str(snap), '<authenticated-node115>').encode('utf-8'))
        full, full_ins = dis(*CALLER)
        sites = {int(x['head'], 16) for x in report['certificate']['loops']} | {int(x['start'], 16) for x in report['certificate']['loops']}
        sites |= set(INPUT_BINDINGS) | {s for seed in SEEDS for s in seed['sites']} | {0x36a283a, 0x36a2847, 0x36a2a0d, 0x36a2a47, 0x36a2a81, FAIL, RANGE_FAIL}
        require(sites <= set(full_ins), 'claimed site is not a native instruction start')
        for name, (a, b) in WINDOWS.items():
            w, _ = dis(a, b)
            (output/f'{name}.objdump.txt').write_bytes(w.replace(str(snap), '<authenticated-node115>').encode('utf-8'))
        succ, text, indirect = native_cfg(full, *CALLER)
        rbx_w = {a for a, t in text.items() if writes(t, {'rbx', 'ebx', 'bx', 'bl'})}
        rbp_w = {a for a, t in text.items() if writes(t, {'rbp', 'ebp', 'bp', 'bpl'})}
        slot_w = {a for a, t in text.items() if re.match(r'^mov\s+QWORD PTR \[rsp\+0x138\],', t)}
        x100_w = {a for a, t in text.items() if re.match(r'^\w+\s+\w+ PTR \[rsp\+0x10[0-9a-f]\],', t)}
        dataflow = {
            'native_instructions_in_caller': len(text),
            'indirect_jumps_in_caller': [hex(a) for a in indirect],
            'rbx_written_on_direct_path_rdi_copy_to_spill': path_through(succ, succ[0x36a1c31][0], 0x36a1def, rbx_w - {0x36a1c31}),
            'spill_slot_rsp_0x138_stores': sorted(hex(a) for a in slot_w),
            'rbp_written_on_direct_path_reload_to_pair_load': path_through(succ, succ[0x36a20ad][0], 0x36a2847, rbp_w - {0x36a20ad}),
            'rsp_0x100_0x10f_stores': sorted(hex(a) for a in x100_w),
            'failure_path_rbx_writes_before_return_copy': sorted(hex(a) for a in rbx_w if WINDOWS['failure'][0] <= a < 0x36a2bfe or ONCE[0] <= a < ONCE[1]),
            'failure_path_branch_targets_forward_in_window': forward_only(text, RANGE_FAIL, 0x36a2bfe),
            'failure_entry_once_branch': [text[0x36a2ade].split()[0], text[ONCE[1]-5].split()[0]+' '+text[ONCE[1]-5].split()[1]],
            'indirect_jumps_reachable_from_rdi_copy_before_spill': sorted(hex(a) for a in indirect if a in reach_until(succ, succ[0x36a1c31][0], 0x36a1def)),
            'indirect_jumps_reachable_from_reload_before_pair_load': sorted(hex(a) for a in indirect if a in reach_until(succ, succ[0x36a20ad][0], 0x36a2847)),
            'scope': 'direct-edge GNU decode only; indirect jumps are listed, not followed; memory aliasing through non-RSP pointers is not excluded'}
        require(not dataflow['rbx_written_on_direct_path_rdi_copy_to_spill'] and dataflow['spill_slot_rsp_0x138_stores'] == ['0x36a1def']
                and not dataflow['rbp_written_on_direct_path_reload_to_pair_load'] and dataflow['rsp_0x100_0x10f_stores'] == ['0x36a1c73']
                and dataflow['failure_path_rbx_writes_before_return_copy'] == ['0x36a2b5d', '0x36a2b78'] and dataflow['failure_path_branch_targets_forward_in_window']
                and dataflow['failure_entry_once_branch'] == ['jne', 'jmp 36a2ae4']
                and not dataflow['indirect_jumps_reachable_from_rdi_copy_before_spill'],
                'native dataflow disagreement')
        relocs = subprocess.check_output(['readelf', '-rW', str(snap)], text=True)
        chosen = [l for l in relocs.splitlines() if re.match(r'^0000000006468b98\s|^00000000064df620\s', l)]
        require(len(chosen) == 2, 'native relocation disagreement')
        (output/'selected-relocations.txt').write_bytes(('\n'.join(chosen)+'\n').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(rows)+'\n').encode('utf-8'))
    (output/'dataflow.json').write_bytes((json.dumps(dataflow, indent=2)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report, indent=2)+'\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--output', type=Path, default=ROOT/'work/fee-schedule-gate115')
    args = p.parse_args()
    r = generate(args.binary, args.output)
    print(json.dumps({'checks': len(r['certificate']['loops'])+4, 'executed': False}))
