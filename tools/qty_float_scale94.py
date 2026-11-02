#!/usr/bin/env python3
"""Static, digest-bound study of two #94 quantity-by-binary64 conversion paths.

Reads the ELF, never executes it. All floating-point calculations below use exact
integers/Fraction and explicit IEEE-754 round-to-nearest-even, not host floats.
"""
import argparse
import hashlib
import json
import struct
from fractions import Fraction
from pathlib import Path

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK = (1 << 64) - 1
SIGN = 1 << 63
FRAC = (1 << 52) - 1
INF = 0x7ff0000000000000
QNAN = 0x7ff8000000000000
I64MIN = -(1 << 63)
I64MAX = (1 << 63) - 1
ONE = 0x3ff0000000000000

# Instruction starts and interpretations were checked against the original bytes.
# The complete FDE contents are pinned below, so the mappings fail closed on any
# change, including an opcode, register, RIP displacement or branch operand.
FUNCS = {
    'direct_nonnegative': {
        'start': 0x3c06160, 'end': 0x3c0620a,
        'sha256': '7182f118bff4cdbae8c62b2fc452ff2f04d503c0bdd56166dd43ec2b87684593',
        'location': 0x5714c10,
        'instructions': [
            (0x160,'test rdi,rdi'), (0x163,'js error'), (0x165,'signed i64 to binary64'),
            (0x16a,'multiply factor by converted quantity'), (0x16e,'move product bits to rax'),
            (0x173,'load signed maximum mask'), (0x17d,'clear product sign bit'),
            (0x180,'set candidate to positive zero'), (0x184,'load largest finite binary64 bits'),
            (0x18e,'compare absolute product bits to finite bound'), (0x191,'jg convert'),
            (0x193,'load negative 2^63'), (0x19b,'compare lower bound with product'),
            (0x19f,'ja clamp'), (0x1a1,'compare product with positive 2^63'),
            (0x1a9,'ja clamp'), (0x1ab,'copy product to candidate'), (0x1af,'jmp convert'),
            (0x1b1,'max lower bound and product'), (0x1b5,'load positive 2^63'),
            (0x1bd,'min upper bound and result'), (0x1c1,'convert candidate toward zero to i64'),
            (0x1c6,'compare candidate with largest binary64 below positive 2^63'),
            (0x1ce,'cmova signed maximum'), (0x1d2,'zero scratch register'),
            (0x1d4,'compare candidate with itself'), (0x1d8,'cmovp zero'),
            (0x1dc,'test converted signed value'), (0x1df,'cmovle zero'), (0x1e3,'return'),
            (0x1e4,'error edge: save stack slot'), (0x1e5,'load error text'),
            (0x1ec,'load error formatting data'), (0x1f3,'load source location'),
            (0x1fa,'load local error argument'), (0x1ff,'load error text length'),
            (0x204,'call through error slot'),
        ],
    },
    'complement_signed': {
        'start': 0x4cda1a0, 'end': 0x4cda253,
        'sha256': '85be9531efd115b8f651d4093f2e6d7da03e0ae582f3a11aedf510bfd1901784',
        'location': 0x57444f0,
        'instructions': [
            (0x1a0,'test rdi,rdi'), (0x1a3,'js error'), (0x1a9,'load binary64 one'),
            (0x1b1,'signed i64 to binary64'), (0x1b6,'subtract factor from one'),
            (0x1ba,'multiply converted quantity by complement'), (0x1be,'move product bits to rcx'),
            (0x1c3,'load signed maximum mask'), (0x1cd,'clear product sign bit'),
            (0x1d0,'set candidate to positive zero'), (0x1d4,'load largest finite binary64 bits'),
            (0x1de,'compare absolute product bits to finite bound'), (0x1e1,'jg convert'),
            (0x1e3,'load negative 2^63'), (0x1eb,'compare lower bound with product'),
            (0x1ef,'ja clamp'), (0x1f1,'compare product with positive 2^63'),
            (0x1f9,'ja clamp'), (0x1fb,'copy product to candidate'), (0x1ff,'jmp convert'),
            (0x201,'max lower bound and product'), (0x205,'load positive 2^63'),
            (0x20d,'min upper bound and result'), (0x211,'convert candidate toward zero to i64'),
            (0x216,'compare candidate with largest binary64 below positive 2^63'),
            (0x21e,'cmova signed maximum'), (0x222,'zero return register'),
            (0x224,'compare candidate with itself'), (0x228,'cmovnp converted value'), (0x22c,'return'),
            (0x22d,'error edge: save stack slot'), (0x22e,'load error text'),
            (0x235,'load error formatting data'), (0x23c,'load source location'),
            (0x243,'load local error argument'), (0x248,'load error text length'),
            (0x24d,'call through error slot'),
        ],
    },
}


def checked_target(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('node #94 SHA-256 mismatch')
    return data


def file_offset(secs, va, size=1):
    if size < 0:
        raise ValueError('negative byte range')
    matches = [s['offset'] + va - s['address'] for s in secs
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('virtual address is not uniquely file-backed')
    return matches[0]


def read_va(data, secs, va, size):
    off = file_offset(secs, va, size)
    return bytes(data[off:off + size])


def fde_map(data, secs):
    _, records = eh_frame_records(data, secs)
    result = {}
    for row in records:
        result.setdefault(row['start'], []).append(row)
    return result


def check_code(data, secs, frames):
    result = {}
    for name, f in FUNCS.items():
        entries = frames.get(f['start'], [])
        if len(entries) != 1 or entries[0]['end'] != f['end']:
            raise ValueError('missing, duplicate or changed FDE extent')
        raw = read_va(data, secs, f['start'], f['end'] - f['start'])
        if hashlib.sha256(raw).hexdigest() != f['sha256']:
            raise ValueError('instruction bytes changed')
        result[name] = {'fde_va': entries[0]['fde'], 'file_offset': file_offset(secs, f['start'], len(raw)), 'raw': raw}
    return result


def branch_target(addr, raw):
    if len(raw) == 2 and raw[0] in (0x78, 0x7f, 0x77, 0xeb):
        return addr + 2 + struct.unpack('<b', raw[1:])[0]
    if len(raw) == 6 and raw[:2] == b'\x0f\x88':
        return addr + 6 + struct.unpack('<i', raw[2:])[0]
    raise ValueError('unexpected branch encoding')


def instructions(data, secs, code):
    rows, branches = [], []
    for name, f in FUNCS.items():
        base = f['start'] & ~0xfff
        starts = [(base + off, text) for off, text in f['instructions']]
        if starts[0][0] != f['start'] or sorted(a for a, _ in starts) != [a for a, _ in starts]:
            raise ValueError('bad instruction starts')
        for i, (va, meaning) in enumerate(starts):
            end = starts[i + 1][0] if i + 1 < len(starts) else f['end']
            raw = read_va(data, secs, va, end - va)
            rows.append((name, va, raw.hex(), meaning))
            if meaning.startswith(('js ', 'jg ', 'ja ', 'jmp ')):
                dest = branch_target(va, raw)
                if dest not in {a for a, _ in starts}:
                    raise ValueError('branch does not land on a pinned instruction')
                branches.append((name, va, meaning.split()[0], dest))
    return rows, branches


def rip_targets(insns):
    # The pinned instructions have a final signed disp32 relative to next RIP.
    expected = {
        0x3c06193: ('lower_bound', 0x20acb8), 0x3c061a1: ('upper_bound', 0x20a7f0),
        0x3c061b5: ('upper_bound', 0x20a7f0), 0x3c061c6: ('cast_threshold', 0x20a2c8),
        0x3c061e5: ('error_text', 0x5b9862), 0x3c061f3: ('source_location', 0x5714c10),
        0x3c06204: ('error_call_slot', 0x576e048),
        0x4cda1a9: ('one', 0x20a730), 0x4cda1e3: ('lower_bound', 0x20acb8),
        0x4cda1f1: ('upper_bound', 0x20a7f0), 0x4cda205: ('upper_bound', 0x20a7f0),
        0x4cda216: ('cast_threshold', 0x20a2c8), 0x4cda22e: ('error_text', 0x715670),
        0x4cda23c: ('source_location', 0x57444f0), 0x4cda24d: ('error_call_slot', 0x576e048),
    }
    rows = []
    for name, va, hexbytes, _ in insns:
        if va not in expected:
            continue
        raw = bytes.fromhex(hexbytes)
        target = va + len(raw) + struct.unpack('<i', raw[-4:])[0]
        label, want = expected[va]
        if target != want:
            raise ValueError('RIP-relative target changed')
        rows.append((name, va, label, target))
    if len(rows) != len(expected):
        raise ValueError('missing RIP-relative instruction')
    return rows


def relocations(data, secs):
    rela = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(rela) != 1 or rela[0]['size'] % 24:
        raise ValueError('unexpected dynamic relocation section')
    result = {}
    s = rela[0]
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        where, info, value = struct.unpack_from('<QQq', data, off)
        if info & 0xffffffff == 8:
            if where in result:
                raise ValueError('duplicate relative relocation')
            result[where] = value
    return result


def location(data, secs, rels, va):
    if va not in rels:
        raise ValueError('location path relocation missing')
    raw = read_va(data, secs, va + 8, 16)
    length, line, col = struct.unpack('<QII', raw)
    if not 0 < length < 256:
        raise ValueError('location path length invalid')
    path = read_va(data, secs, rels[va], length)
    if not path.endswith(b'l1/src/qtys/mod.rs') or (line, col) != (843, 1):
        raise ValueError('unexpected location record')
    # The imported path has a machine-specific prefix; keep only the source suffix.
    return {'record_va': hex(va), 'source_suffix': 'l1/src/qtys/mod.rs', 'line': line, 'column': col}


def round_quotient(n, d):
    q, r = divmod(n, d)
    return q + (2 * r > d or (2 * r == d and q & 1))


def round_binary64(value, zero_sign=0):
    """Nearest-even binary64 encoding of an exact rational, including subnormals."""
    if not value:
        return SIGN if zero_sign else 0
    sign = SIGN if value < 0 else 0
    value = abs(value)
    n, d = value.numerator, value.denominator
    e = n.bit_length() - d.bit_length()
    if (n < (d << e) if e >= 0 else (n << -e) < d):
        e -= 1
    if e < -1022:
        mant = round_quotient(n << 1074, d)
        if mant == 0:
            return sign
        if mant < 1 << 52:
            return sign | mant
        return sign | (1 << 52)
    shift = 52 - e
    mant = round_quotient(n << shift, d) if shift >= 0 else round_quotient(n, d << -shift)
    if mant == 1 << 53:
        mant >>= 1
        e += 1
    if e > 1023:
        return sign | INF
    return sign | ((e + 1023) << 52) | (mant - (1 << 52))


def finite(bits):
    return (bits & INF) != INF


def fraction(bits):
    if not finite(bits):
        raise ValueError('non-finite binary64')
    exponent, mant = (bits >> 52) & 0x7ff, bits & FRAC
    if exponent:
        mant |= 1 << 52
        shift = exponent - 1023 - 52
    else:
        shift = -1074
    value = Fraction(mant << shift, 1) if shift >= 0 else Fraction(mant, 1 << -shift)
    return -value if bits & SIGN else value


def complement(bits):
    if not finite(bits):
        return (bits | (1 << 51)) if bits & FRAC else bits ^ SIGN
    return round_binary64(Fraction(1) - fraction(bits))


def product(bits, quantity):
    """Multiply binary64 factor by the separately rounded nonnegative i64."""
    if not 0 <= quantity <= I64MAX:
        raise ValueError('quantity outside nonnegative signed range')
    integer_bits = round_binary64(Fraction(quantity))
    if not finite(bits):
        if bits & FRAC:
            return bits | (1 << 51)
        if quantity == 0:
            return SIGN | QNAN
        return bits & (SIGN | INF)
    sign = bool((bits ^ integer_bits) & SIGN)
    return round_binary64(fraction(bits) * fraction(integer_bits), sign)


def trunc(value):
    return value.numerator // value.denominator if value >= 0 else -((-value.numerator) // value.denominator)


def machine_tail(bits, nonnegative):
    """The bounded machine branches after multiplication, with named branch coverage."""
    absolute = bits & I64MAX
    coverage = set()
    candidate = 0
    if absolute > 0x7fefffffffffffff:
        coverage.add('nonfinite_to_zero')
    else:
        x = fraction(bits)
        if x < I64MIN or x > (1 << 63):
            coverage.add('finite_clamp')
            x = max(Fraction(I64MIN), min(Fraction(1 << 63), x))
            candidate = round_binary64(x)
        else:
            coverage.add('finite_in_range')
            candidate = bits
    x = fraction(candidate)
    result = trunc(x) if I64MIN <= x < (1 << 63) else I64MIN
    if x > fraction(0x43dfffffffffffff):
        result = I64MAX
        coverage.add('positive_cast_saturates')
    if nonnegative and result <= 0:
        result = 0
        coverage.add('negative_or_zero_to_zero')
    return result, coverage


def specification(bits, nonnegative):
    """Independent closed form for the post-product conversion."""
    if not finite(bits):
        return 0
    n = trunc(fraction(bits))
    n = min(I64MAX, max(I64MIN, n))
    return max(0, n) if nonnegative else n


def calculate(name, quantity, factor_bits):
    if not 0 <= quantity <= MASK or not 0 <= factor_bits <= MASK:
        raise ValueError('inputs must be 64-bit words')
    if quantity & SIGN:
        return {'status': 'error_edge', 'coverage': {'negative_quantity'}}
    factor = factor_bits if name == 'direct_nonnegative' else complement(factor_bits)
    y = product(factor, quantity)
    output, covered = machine_tail(y, name == 'direct_nonnegative')
    expected = specification(y, name == 'direct_nonnegative')
    if output != expected:
        raise ValueError('machine branch model disagrees with specification')
    return {'status': 'return', 'converted_bits': round_binary64(Fraction(quantity)),
            'factor_bits': factor, 'product_bits': y, 'result': output, 'coverage': covered}



def execute(name, quantity, factor_bits, insns):
    """Walk the pinned instruction map; stop on the error edge or a return.

    Binary64 arithmetic uses the exact-integer helpers above. Each named operation
    is tied to a full-body hash and the actual branch displacement is decoded.
    The error helper is deliberately not executed or modelled.
    """
    desc = FUNCS[name]
    program = {va: (bytes.fromhex(raw), meaning) for n, va, raw, meaning in insns if n == name}
    pc = desc['start']
    integer = {'rdi': quantity, 'rax': 0, 'rcx': 0, 'rdx': 0}
    xmm = {'xmm0': factor_bits, 'xmm1': 0, 'xmm2': 0}
    sf = zf = pf = cf = gt = False
    visited, edges = set(), set()

    def compare_float(a, b):
        if not finite(a) and a & FRAC or not finite(b) and b & FRAC:
            return True, True, True
        def ordered(bits):
            if not finite(bits):
                return None
            return fraction(bits)
        x, y = ordered(a), ordered(b)
        if x is None:
            comparison = -1 if a & SIGN else 1
            if y is None:
                comparison = ((not bool(a & SIGN)) > (not bool(b & SIGN))) - ((not bool(a & SIGN)) < (not bool(b & SIGN)))
        elif y is None:
            comparison = 1 if b & SIGN else -1
        else:
            comparison = (x > y) - (x < y)
        return comparison == 0, comparison < 0, False

    for _ in range(80):
        if pc not in program:
            raise ValueError('instruction pointer left pinned program')
        raw, op = program[pc]
        visited.add(pc)
        next_pc = pc + len(raw)
        if op.startswith(('js ', 'jg ', 'ja ', 'jmp ')):
            take = sf if op.startswith('js ') else gt if op.startswith('jg ') else (not cf and not zf) if op.startswith('ja ') else True
            target = branch_target(pc, raw)
            edges.add((pc, take))
            if take and op == 'js error':
                return {'status': 'error_edge', 'visited': visited, 'edges': edges}
            if take:
                next_pc = target
        elif op == 'test rdi,rdi':
            sf, zf = bool(integer['rdi'] & SIGN), integer['rdi'] == 0
        elif op == 'signed i64 to binary64':
            xmm['xmm1'] = round_binary64(Fraction(quantity))
        elif op == 'load binary64 one':
            xmm['xmm2'] = ONE
        elif op == 'subtract factor from one':
            if xmm['xmm2'] != ONE:
                raise ValueError('unexpected subtraction input')
            xmm['xmm2'] = complement(xmm['xmm0'])
        elif op == 'multiply factor by converted quantity':
            if xmm['xmm1'] != round_binary64(Fraction(quantity)):
                raise ValueError('unexpected multiplier')
            xmm['xmm0'] = product(xmm['xmm0'], quantity)
        elif op == 'multiply converted quantity by complement':
            if xmm['xmm1'] != round_binary64(Fraction(quantity)):
                raise ValueError('unexpected multiplier')
            xmm['xmm1'] = product(xmm['xmm2'], quantity)
        elif op == 'move product bits to rax':
            integer['rax'] = xmm['xmm0']
        elif op == 'move product bits to rcx':
            integer['rcx'] = xmm['xmm1']
        elif op == 'load signed maximum mask':
            integer['rcx' if name == 'direct_nonnegative' else 'rax'] = I64MAX
        elif op == 'clear product sign bit':
            reg = 'rax' if name == 'direct_nonnegative' else 'rcx'
            integer[reg] &= I64MAX
        elif op == 'set candidate to positive zero':
            xmm['xmm1' if name == 'direct_nonnegative' else 'xmm0'] = 0
        elif op == 'load largest finite binary64 bits':
            integer['rdx'] = 0x7fefffffffffffff
        elif op == 'compare absolute product bits to finite bound':
            val = integer['rax' if name == 'direct_nonnegative' else 'rcx']
            gt = val > integer['rdx']  # Both sign bits are clear.
        elif op == 'load negative 2^63':
            xmm['xmm2'] = 0xc3e0000000000000
        elif op == 'compare lower bound with product':
            zf, cf, pf = compare_float(xmm['xmm2'], xmm['xmm0' if name == 'direct_nonnegative' else 'xmm1'])
        elif op == 'compare product with positive 2^63':
            zf, cf, pf = compare_float(xmm['xmm0' if name == 'direct_nonnegative' else 'xmm1'], 0x43e0000000000000)
        elif op == 'copy product to candidate':
            if name == 'direct_nonnegative': xmm['xmm1'] = xmm['xmm0']
            else: xmm['xmm0'] = xmm['xmm1']
        elif op == 'max lower bound and product':
            val = xmm['xmm0' if name == 'direct_nonnegative' else 'xmm1']
            if not finite(val): raise ValueError('nonfinite value reached clamp')
            if fraction(val) >= fraction(xmm['xmm2']): xmm['xmm2'] = val
        elif op == 'load positive 2^63':
            xmm['xmm1' if name == 'direct_nonnegative' else 'xmm0'] = 0x43e0000000000000
        elif op == 'min upper bound and result':
            reg = 'xmm1' if name == 'direct_nonnegative' else 'xmm0'
            if fraction(xmm['xmm2']) <= fraction(xmm[reg]): xmm[reg] = xmm['xmm2']
        elif op == 'convert candidate toward zero to i64':
            x = fraction(xmm['xmm1' if name == 'direct_nonnegative' else 'xmm0'])
            val = trunc(x) if I64MIN <= x < 1 << 63 else I64MIN
            integer['rax' if name == 'direct_nonnegative' else 'rcx'] = val & MASK
        elif op == 'compare candidate with largest binary64 below positive 2^63':
            zf, cf, pf = compare_float(xmm['xmm1' if name == 'direct_nonnegative' else 'xmm0'], 0x43dfffffffffffff)
        elif op == 'cmova signed maximum':
            edges.add((pc, not cf and not zf))
            if not cf and not zf:
                integer['rax' if name == 'direct_nonnegative' else 'rcx'] = I64MAX
        elif op == 'zero scratch register':
            integer['rcx'] = 0
        elif op == 'zero return register':
            integer['rax'] = 0
        elif op == 'compare candidate with itself':
            val = xmm['xmm1' if name == 'direct_nonnegative' else 'xmm0']
            zf, cf, pf = compare_float(val, val)
        elif op == 'cmovp zero':
            edges.add((pc, pf))
            if pf: integer['rax'] = integer['rcx']
        elif op == 'cmovnp converted value':
            edges.add((pc, not pf))
            if not pf: integer['rax'] = integer['rcx']
        elif op == 'test converted signed value':
            sf, zf = bool(integer['rax'] & SIGN), integer['rax'] == 0
        elif op == 'cmovle zero':
            edges.add((pc, sf or zf))
            if sf or zf: integer['rax'] = integer['rcx']
        elif op == 'return':
            result = integer['rax']
            if result & SIGN: result -= 1 << 64
            return {'status': 'return', 'result': result, 'visited': visited, 'edges': edges}
        else:
            raise ValueError('unmodelled pinned instruction: ' + op)
        pc = next_pc
    raise ValueError('instruction walk exceeded bound')


def bit_patterns():
    # All exponent classes, both signs and four mantissas exercise the post-product
    # branches; the algebraic proof in the README does not depend on this sample.
    for sign in (0, SIGN):
        for exponent in range(2048):
            for mantissa in (0, 1, 1 << 51, FRAC):
                yield sign | exponent << 52 | mantissa


def vectors():
    factors = [0, SIGN, ONE, ONE | SIGN, 0x3fe0000000000000, 0x3ff8000000000000,
               0x4004000000000000, 1, SIGN | 1, 0x0010000000000000,
               0x7fefffffffffffff, 0xffefffffffffffff, INF, SIGN | INF, QNAN,
               0x7ff0000000000001, 0xfff8000000000042, 0x43dfffffffffffff,
               0x43e0000000000000, 0xc3e0000000000000, 0x3fefffffffffffff,
               0x3ff0000000000001, 0x3fee1506db4daeb5]
    state = 0x4d595df4d0f33173
    for _ in range(96):
        state ^= (state << 13) & MASK
        state ^= state >> 7
        state ^= (state << 17) & MASK
        factors.append(state & MASK)
    quantities = [0, 1, 2, 3, 7, (1 << 53) - 1, 1 << 53, (1 << 53) + 1,
                  I64MAX, 8791338280601638520, SIGN, MASK]
    for name in FUNCS:
        for q in quantities:
            for f in factors:
                yield name, q, f



def prove_tail_intervals(max_finite_bits, upper_bits, below_upper_bits, lower_bits):
    """Symbolically partition all encodings into monotone comparison intervals.

    The table describes instruction-level branches and their terminal formulas;
    it does not simulate every individual encoding or prove input reachability.
    """
    if max_finite_bits != INF - 1 or upper_bits != 0x43e0000000000000:
        raise ValueError('unexpected finite or i64-bound encoding')
    if below_upper_bits + 1 != upper_bits or lower_bits != SIGN | upper_bits:
        raise ValueError('unexpected binary64 bound adjacency or sign')
    intervals = [
        (0, below_upper_bits, 'finite below positive endpoint', 'truncate', 'truncate'),
        (upper_bits, upper_bits, 'exact endpoint', 'i64_max', 'i64_min'),
        (upper_bits + 1, max_finite_bits, 'finite beyond endpoint', 'i64_max', 'i64_min'),
        (max_finite_bits + 1, I64MAX, 'infinity or NaN', 'zero', 'zero'),
    ]
    if intervals[0][0] != 0 or intervals[-1][1] != I64MAX:
        raise ValueError('incomplete signless encoding domain')
    if any(a[1] + 1 != b[0] for a, b in zip(intervals, intervals[1:])):
        raise ValueError('gap or overlap in conversion partition')
    rows = []
    for sign in (0, 1):
        for lo, hi, condition, positive_result, negative_result in intervals:
            signed_result = negative_result if sign else positive_result
            direct_result = 'zero' if sign else signed_result
            rows.append((sign, lo, hi, hi - lo + 1, condition, signed_result, direct_result))
    if sum(row[3] for row in rows) != 1 << 64:
        raise ValueError('incomplete 64-bit conversion partition')
    return rows


def write_tsv(path, header, rows):
    lines = ['\t'.join(header)]
    lines.extend('\t'.join(str(value) for value in row) for row in rows)
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def generate(data, out):
    checked_target(data)
    secs = sections(data)
    code = check_code(data, secs, fde_map(data, secs))
    insns, branches = instructions(data, secs, code)
    operands = rip_targets(insns)
    rels = relocations(data, secs)
    locs = {name: location(data, secs, rels, f['location']) for name, f in FUNCS.items()}
    message = b'called `Result::unwrap()` on an `Err` value'
    for va in (0x5b9862, 0x715670):
        if read_va(data, secs, va, len(message)) != message:
            raise ValueError('error message changed')
    constants = []
    for label, va in [('one', 0x20a730), ('negative_2_63', 0x20acb8),
                      ('positive_2_63', 0x20a7f0), ('below_positive_2_63', 0x20a2c8)]:
        bits = struct.unpack('<Q', read_va(data, secs, va, 8))[0]
        constants.append((label, va, bits, file_offset(secs, va, 8)))
    if [row[2] for row in constants] != [ONE, 0xc3e0000000000000, 0x43e0000000000000, 0x43dfffffffffffff]:
        raise ValueError('floating-point constants changed')
    finite_bound_1 = struct.unpack('<Q', read_va(data, secs, 0x3c06186, 8))[0]
    finite_bound_2 = struct.unpack('<Q', read_va(data, secs, 0x4cda1d6, 8))[0]
    if finite_bound_1 != finite_bound_2:
        raise ValueError('conversion paths disagree on finite bound')
    proof_rows = prove_tail_intervals(finite_bound_1, constants[2][2], constants[3][2], constants[1][2])
    all_rows = []
    cover = {name: set() for name in FUNCS}
    statuses = {'return': 0, 'error_edge': 0}
    observed_insns, observed_edges = set(), set()
    for name, q, f in vectors():
        result = calculate(name, q, f)
        run = execute(name, q, f, insns)
        if run['status'] != result['status'] or run.get('result') != result.get('result'):
            raise ValueError('instruction walk disagrees with arithmetic model')
        observed_insns.update((name, va) for va in run['visited'])
        observed_edges.update((name, va, taken) for va, taken in run['edges'])
        statuses[result['status']] += 1
        cover[name].update(result['coverage'])
        all_rows.append((name, f'{q:016x}', f'{f:016x}', result['status'],
                         f"{result['converted_bits']:016x}" if result['status'] == 'return' else '-',
                         f"{result['factor_bits']:016x}" if result['status'] == 'return' else '-',
                         f"{result['product_bits']:016x}" if result['status'] == 'return' else '-',
                         result.get('result', '-'), ','.join(sorted(result['coverage']))))
    tail_checks = 0
    for bits in bit_patterns():
        for nonnegative in (False, True):
            got, _ = machine_tail(bits, nonnegative)
            if got != specification(bits, nonnegative):
                raise ValueError('tail partition sample disagrees with specification')
            tail_checks += 1
    required = {'negative_quantity', 'nonfinite_to_zero', 'finite_clamp', 'finite_in_range', 'positive_cast_saturates'}
    for name in FUNCS:
        expected = required | ({'negative_or_zero_to_zero'} if name == 'direct_nonnegative' else set())
        if not expected <= cover[name]:
            raise ValueError('vector branch coverage incomplete')
    # Partition all 64-bit IEEE encodings by sign, exponent and fraction.
    # The thresholds are obtained from the stored bound encodings above.
    exponent_at_limit = (constants[2][2] >> 52) & 0x7ff
    if exponent_at_limit != 1086 or constants[3][2] + 1 != constants[2][2]:
        raise ValueError('unexpected binary64 conversion bound')
    class_rows = []
    for sign in (0, 1):
        class_rows += [
            (sign, '0..1085', 'all', exponent_at_limit * (1 << 52), 'finite magnitude below 2^63'),
            (sign, '1086', 'zero', 1, 'finite magnitude equal to 2^63'),
            (sign, '1086', 'nonzero', (1 << 52) - 1, 'finite magnitude above 2^63'),
            (sign, '1087..2046', 'all', (2047 - exponent_at_limit - 1) * (1 << 52), 'finite magnitude above 2^63'),
            (sign, '2047', 'all', 1 << 52, 'nonfinite product becomes zero'),
        ]
    if sum(row[3] for row in class_rows) != 1 << 64:
        raise ValueError('binary64 partition is incomplete')
    # Counterexample to reassociating rounded q*(1-f) as q - round(q*f).
    counter_q, counter_f = 8791338280601638520, 0x3fee1506db4daeb5
    real = calculate('complement_signed', counter_q, counter_f)
    rounded_q = round_binary64(Fraction(counter_q))
    other_product = product(counter_f, counter_q)
    reassociated = round_binary64(fraction(rounded_q) - fraction(other_product))
    other_result = specification(reassociated, False)
    if real['result'] == other_result:
        raise ValueError('rounding-order counterexample no longer separates')
    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out / 'rounding-order.tsv',
              ('quantity', 'factor_bits', 'quantity_bits', 'complement_bits', 'actual_product_bits',
               'actual_result', 'other_product_bits', 'other_subtract_bits', 'other_result'),
              [(counter_q, f'{counter_f:016x}', f'{rounded_q:016x}', f"{real['factor_bits']:016x}",
                f"{real['product_bits']:016x}", real['result'], f'{other_product:016x}',
                f'{reassociated:016x}', other_result)])
    write_tsv(out / 'tail-intervals.tsv',
              ('sign_bit', 'abs_bits_low', 'abs_bits_high', 'encoding_count', 'condition', 'signed_result', 'nonnegative_result'),
              ((sign, f'{lo:016x}', f'{hi:016x}', count, condition, signed, nonnegative)
               for sign, lo, hi, count, condition, signed, nonnegative in proof_rows))
    write_tsv(out / 'tail-classes.tsv', ('sign_bit', 'biased_exponent', 'fraction', 'encoding_count', 'class'), class_rows)
    write_tsv(out / 'instructions.tsv', ('function', 'va', 'bytes', 'interpretation'),
              ((n, hex(va), raw, m) for n, va, raw, m in insns))
    write_tsv(out / 'operands.tsv', ('function', 'instruction_va', 'role', 'target_va'),
              ((n, hex(va), role, hex(dest)) for n, va, role, dest in operands))
    decisions = [(name, va, kind) for name, va, kind, _ in branches]
    decisions += [(name, va, meaning.split()[0]) for name, va, _, meaning in insns if meaning.startswith(('cmova ', 'cmovp ', 'cmovnp ', 'cmovle '))]
    write_tsv(out / 'walk-coverage.tsv', ('function', 'va', 'kind', 'taken', 'observed'),
              ((name, hex(va), kind, str(take).lower(), str((name, va, take) in observed_edges).lower())
               for name, va, kind in decisions for take in ((True,) if kind == 'jmp' else (False, True))))
    write_tsv(out / 'branches.tsv', ('function', 'va', 'kind', 'target_va'),
              ((n, hex(va), kind, hex(dest)) for n, va, kind, dest in branches))
    write_tsv(out / 'constants.tsv', ('name', 'va', 'little_endian_u64', 'file_offset'),
              ((n, hex(va), f'{bits:016x}', hex(off)) for n, va, bits, off in constants))
    write_tsv(out / 'vectors.tsv', ('function', 'quantity_hex', 'input_factor_bits', 'status',
                                   'quantity_binary64_bits', 'effective_factor_bits', 'product_bits', 'result_i64', 'covered'), all_rows)
    summary = {
        'artifact_sha256': SHA256,
        'coordinate_system': 'ELF virtual addresses; file offsets explicitly labelled',
        'function_extents': {name: {'start_va': hex(f['start']), 'end_va_exclusive': hex(f['end']),
                                    'fde_va': hex(code[name]['fde_va']), 'file_offset': hex(code[name]['file_offset']),
                                    'body_sha256': f['sha256'], 'location': locs[name]}
                             for name, f in FUNCS.items()},
        'instruction_count': len(insns), 'instruction_walk_visited': len(observed_insns),
        'observed_branch_and_cmov_edges': len(observed_edges), 'instruction_walk_mismatches': 0,
        'direct_branch_count': len(branches), 'rip_operands_count': len(operands),
        'constants_count': len(constants), 'vector_count': len(all_rows), 'statuses': statuses,
        'tail_sample_checks': tail_checks, 'tail_sample_mismatches': 0,
        'tail_encoding_classes': len(class_rows), 'tail_symbolic_intervals': len(proof_rows), 'tail_encodings_partitioned': str(1 << 64),
        'coverage': {name: sorted(items) for name, items in cover.items()},
        'assumptions': ['binary64 operations round to nearest, ties to even',
                        'floating-point exceptions masked; denormals not flushed',
                        'unwind extent alone does not prove complete function ownership'],
    }
    (out / 'evidence.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    summary = generate(TARGET.read_bytes(), args.out)
    print(json.dumps({'vectors': summary['vector_count'], 'tail_checks': summary['tail_sample_checks']}, sort_keys=True))


if __name__ == '__main__':
    main()
