#!/usr/bin/env python3
"""Statically compare two checked integer blob-price loops in node 94."""
import argparse
import csv
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

BINARY = 'artifacts/node/94/hl-node'
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BODIES = {
    0x134beb0: '80dfed4a6f87c04a4fe883fee6a840f3c666d71936a05bdf5c8cdb424f6df017',
    0x134c4e0: 'f91bffad15932651077e2c4be38775ed3e4d8e498d0db70a729672a1042fa265',
    0x4e4ad50: '0b2adce9c678acb32fcb8c02d7b5bb67bde886fa6b79627416a00ab7098e7ea5',
    0x4ea1e00: 'bced2690cbbdef973dc27c20662c7318f81d4d9bf2954753772a5cbb7d6367a3',
}
# Each pattern is an instruction-aligned window. Displacements are pinned as part of each window.
SITES = [
 ('fixed_select', 0x4ea1e24, '85d20f84c1000000'),
 ('fixed_true_denominator', 0x4ea1e2c, 'b964694c00'),
 ('fixed_false_denominator', 0x4ea1eed, 'b9edf03200'),
 ('fixed_sum_carry', 0x4ea1e40, '4801cf4811d60f8294010000'),
 ('fixed_term_product', 0x4ea1e4c, '4889d04c8b44241849f7e04989c2410f90c14889c849f7e04989c64889d34c01d30f92c04408c8'),
 ('fixed_iteration_denominator', 0x4ea1e83, '4889e8bf64694c0048f7e74889c1400f90c64c89e848f7e74989c44989d74901cf0f92c04008f00f85230100004983c5014883d500'),
 ('fixed_loop_divide', 0x4ea1ec4, 'ff15dec28c00'),
 ('fixed_loop_condition', 0x4ea1ecd, '4d39e64c19fb488b7c2410488b7424080f835dffffff'),
 ('fixed_final_divide', 0x4ea1fa4, '31c9ff15fcc18c00488b4c2420488b7424184889711048890148895108'),
 ('fixed_failure_paths', 0x4ea1fd3, '488d3dbed88a00ff15d0c18c00488d3d81d88a00ff152bc18c00488d3d8cd88a00ff15b6c18c00'),
 ('caller_version_targets', 0x4e4ae35, '3c12b900000c00b800000600480f43c1'),
 ('caller_presence_and_saturating_sub', 0x4e4ae4a, '837a20017520837a1001751a488b4a2848034a180f82690700004531ed4829c14c0f43e9eb0d4531ed4080fd11'),
 ('caller_flag_and_call', 0x4e4ae7d, '31d24080fd120f93c2488dbc24300100004c89eeff1579bf9200'),
 ('generic_parent_target_shift', 0x134bef2, '4889ce48c1ee2f0f852c02000048c1e11131f64829c8480f43f0'),
 ('generic_parent_factor', 0x134bf24, '488b4a10488b42184885db0f95c24885c0410f95c04120d049f7e34889c6410f90c14889d848f7e1410f90c24508ca4508c24801c64889c849f7e34889c14801f20f92c04408d00f85c7010000'),
 ('generic_parent_sum', 0x134bfa0, '4801cf4811d60f8231010000'),
 ('generic_parent_term_product', 0x134bfac, '4889d04c8b44242049f7e04989c6410f90c14889c849f7e04989c44889d54c01f50f92c04408c80f8511010000'),
 ('generic_parent_divide', 0x134c05e, 'ff15442142044889c14d39fc4c19f54989db488b5c2418488b7c2428488b7424300f831bffffff'),
 ('generic_parent_final', 0x134c08b, '4c89da4889d9ff1511214204488b7c24104889571848894710b80100000031c9'),
 ('generic_current_presence', 0x134c4ee, '31c0837e2001b9000000000f85a70100004c8b3a4c8b62084c89f84c09e00f84ad010000'),
 ('generic_current_factor', 0x134c512, '488b4a10488b42184d85e40f95c24885c0410f95c04120d049f7e74989c3410f90c14c89e048f7e1410f90c24508ca4508c24d8d04034889c849f7e74889c14c01c20f92c04408d00f85b9010000'),
 ('generic_current_sum', 0x134c5a0, '4801cf4811d60f822c010000'),
 ('generic_current_term_product', 0x134c5ac, '4889d04c8b44242849f7e04989c2410f90c14889c849f7e04889c54889d34c01d30f92c04408c80f850c010000'),
 ('generic_current_divide', 0x134c659, 'ff15491b42044889c14c39e54c19fb4c8b7c24184c8b6424204c89f7488b7424300f8320ffffff'),
]
BRANCHES = [
 ('fixed_select', 0x4ea1e26, 0x4ea1eed),
 ('fixed_true_sum_overflow', 0x4ea1e46, 0x4ea1fe0),
 ('fixed_true_term_overflow', 0x4ea1e73, 0x4ea1fed),
 ('fixed_true_denominator_overflow', 0x4ea1eaa, 0x4ea1fd3),
 ('fixed_true_back_edge', 0x4ea1edd, 0x4ea1e40),
 ('fixed_true_final', 0x4ea1ee8, 0x4ea1fa4),
 ('fixed_false_sum_overflow', 0x4ea1f06, 0x4ea1fe0),
 ('fixed_false_term_overflow', 0x4ea1f33, 0x4ea1fed),
 ('fixed_false_denominator_overflow', 0x4ea1f6a, 0x4ea1fd3),
 ('fixed_false_back_edge', 0x4ea1f99, 0x4ea1f00),
 ('caller_height_overflow', 0x4e4ae11, 0x4e4b5b5),
 ('caller_first_absent', 0x4e4ae4e, 0x4e4ae70),
 ('caller_second_absent', 0x4e4ae54, 0x4e4ae70),
 ('caller_add_overflow', 0x4e4ae5e, 0x4e4b5cd),
 ('caller_missing_skip', 0x4e4ae77, 0x4e4afcf),
 ('current_absent', 0x134c4f9, 0x134c6a6),
 ('current_zero_denominator', 0x134c50c, 0x134c6bf),
 ('current_initial_product_overflow', 0x134c55a, 0x134c719),
 ('current_zero_initial', 0x134c56b, 0x134c682),
 ('current_sum_overflow', 0x134c5a6, 0x134c6d8),
 ('current_term_overflow', 0x134c5d3, 0x134c6e5),
 ('current_denominator_overflow', 0x134c623, 0x134c6f2),
 ('current_iteration_divide_zero', 0x134c62f, 0x134c6ff),
 ('current_increment_overflow', 0x134c644, 0x134c70c),
 ('current_back_edge', 0x134c67a, 0x134c5a0),
 ('parent_first_absent', 0x134bec9, 0x134c0ab),
 ('parent_second_absent', 0x134beda, 0x134c0ab),
 ('parent_add_overflow', 0x134bee8, 0x134c11e),
 ('parent_target_shift_overflow', 0x134bef9, 0x134c12b),
 ('parent_zero_denominator', 0x134bf1e, 0x134c0c4),
 ('parent_initial_product_overflow', 0x134bf6b, 0x134c138),
 ('parent_zero_initial', 0x134bf7c, 0x134c087),
 ('parent_sum_overflow', 0x134bfa6, 0x134c0dd),
 ('parent_term_overflow', 0x134bfd3, 0x134c0ea),
 ('parent_denominator_overflow', 0x134c023, 0x134c0f7),
 ('parent_iteration_divide_zero', 0x134c034, 0x134c104),
 ('parent_increment_overflow', 0x134c049, 0x134c111),
 ('parent_back_edge', 0x134c07f, 0x134bfa0),
]
MASK = (1 << 64) - 1
MAX128 = (1 << 128) - 1


def digest(data):
    return hashlib.sha256(data).hexdigest()


def image(data, expected=SHA):
    if digest(data) != expected:
        raise ValueError('artifact SHA-256 mismatch')
    sections = elf_index.sections(data)
    _, records = fde_extents.eh_frame_records(data, sections)
    selected = {}
    for row in records:
        start = row['start']
        if start in BODIES:
            if start in selected:
                raise ValueError('ambiguous selected FDE start')
            selected[start] = row
    return sections, selected


def at(data, sections, va, length):
    if length < 0 or va < 0:
        raise ValueError('invalid address or length')
    found = [s for s in sections if s['type'] != 8 and s['flags'] & 2 and s['address'] <= va and va + length <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('address does not have one file-backed mapping')
    off = found[0]['offset'] + va - found[0]['address']
    return data[off:off + length]


def validate(data, expected=SHA):
    sections, fdes = image(data, expected)
    funcs = []
    for start, want in sorted(BODIES.items()):
        if start not in fdes:
            raise ValueError('missing FDE')
        row = fdes[start]
        body = at(data, sections, start, row['end'] - start)
        if not any(sec['type'] != 8 and sec['flags'] & 4 and sec['address'] <= start and row['end'] <= sec['address'] + sec['size'] for sec in sections):
            raise ValueError('FDE outside executable file-backed section')
        if digest(body) != want:
            raise ValueError('function bytes changed')
        funcs.append(row)
    for label, va, raw in SITES:
        if not any(f['start'] <= va and va + len(bytes.fromhex(raw)) <= f['end'] for f in funcs):
            raise ValueError('instruction window outside selected FDEs')
        if at(data, sections, va, len(bytes.fromhex(raw))) != bytes.fromhex(raw):
            raise ValueError('instruction window changed: ' + label)
    return sections, funcs


def branch_rows(data, sections):
    result = []
    for name, site, expected_target in BRANCHES:
        prefix = at(data, sections, site, 2)
        if prefix[0] == 0x0f and 0x80 <= prefix[1] <= 0x8f:
            raw = at(data, sections, site, 6)
            displacement = struct.unpack_from('<i', raw, 2)[0]
        elif 0x70 <= prefix[0] <= 0x7f:
            raw = prefix
            displacement = struct.unpack_from('<b', raw, 1)[0]
        elif prefix[0] == 0xe9:
            raw = at(data, sections, site, 5)
            displacement = struct.unpack_from('<i', raw, 1)[0]
        else:
            raise ValueError('unexpected branch opcode: ' + name)
        dest = site + len(raw) + displacement
        if dest != expected_target:
            raise ValueError('unexpected branch target: ' + name)
        at(data, sections, dest, 1)
        result.append((name, hex(site), raw.hex(), hex(dest)))
    return result

def checked_mul_128_64(value, x):
    """Lift the unsigned two-limb mul/carry sequence at the fixed loop."""
    if not 0 <= value <= MAX128 or not 0 <= x <= MASK:
        raise ValueError('limb input outside range')
    lo, hi = value & MASK, value >> 64
    hi_product = hi * x
    lo_product = lo * x
    high_sum = (lo_product >> 64) + (hi_product & MASK)
    if hi_product >> 64 or high_sum >> 64:
        return None
    return ((high_sum & MASK) << 64) | (lo_product & MASK)


def checked_sum(a, b):
    low_sum = (a & MASK) + (b & MASK)
    high_sum = (a >> 64) + (b >> 64) + (low_sum >> 64)
    if high_sum >> 64:
        return None
    return ((high_sum & MASK) << 64) | (low_sum & MASK)


def lifted(x, d):
    """The instruction lift; division helper is modeled as unsigned floor division."""
    if not 0 <= x <= MASK or d not in (3338477, 5007716):
        raise ValueError('input outside fixed-loop domain')
    accum, term, i = 0, d, 1
    while term:
        accum = checked_sum(accum, term)
        if accum is None:
            return ('sum_overflow', i, None)
        numerator = checked_mul_128_64(term, x)
        if numerator is None:
            return ('term_product_overflow', i, None)
        denominator = checked_mul_128_64(i, d)
        if denominator is None:
            return ('iteration_product_overflow', i, None)
        term = numerator // denominator
        i += 1
    return ('ok', i - 1, accum // d)


def specification(x, d):
    """Separate arithmetic model, including checks in instruction order."""
    if not 0 <= x <= MASK or d <= 0:
        raise ValueError('invalid model input')
    total, t, n = 0, d, 1
    while t:
        if total + t > MAX128:
            return ('sum_overflow', n, None)
        total += t
        if t * x > MAX128:
            return ('term_product_overflow', n, None)
        if n * d > MAX128:
            return ('iteration_product_overflow', n, None)
        t = (t * x) // (n * d)
        n += 1
    return ('ok', n - 1, total // d)


def threshold(d):
    """Find the boundary; monotonic checked-term proof is explained in README."""
    lo, hi = 0, 1 << 64
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if lifted(mid, d)[0] == 'ok':
            lo = mid
        else:
            hi = mid
    return lo, lifted(lo, d), hi, lifted(hi, d)


def generic(x, d, factor, present=True):
    """Manual lift of the configurable current-excess path, with checked u128 arithmetic."""
    if not 0 <= x <= MASK or not 0 <= d <= MAX128 or not 0 <= factor <= MAX128:
        raise ValueError('generic input outside range')
    if not present:
        return ('absent', None)
    if d == 0:
        return ('zero_denominator', None)
    if factor * d > MAX128:
        return ('initial_product_overflow', None)
    term, accum, i = factor * d, 0, 1
    while term:
        if accum + term > MAX128:
            return ('sum_overflow', i)
        accum += term
        if term * x > MAX128:
            return ('term_product_overflow', i)
        if i * d > MAX128:
            return ('iteration_product_overflow', i)
        denom = i * d
        if i == MAX128:
            return ('iteration_overflow', i)
        term = term * x // denom
        i += 1
    return ('ok', accum // d)


def parent_excess(excess, used, target, both_present=True):
    """Manual lift of checked addition, checked shift and saturating subtraction."""
    if any(not 0 <= z <= MASK for z in (excess, used, target)):
        raise ValueError('parent input outside u64')
    if not both_present:
        return ('absent', None)
    if excess + used > MASK:
        return ('addition_overflow', None)
    if target >> 47:
        return ('target_product_overflow', None)
    return ('ok', max(excess + used - (target << 17), 0))


def select_excess(version, excess, used, excess_present, used_present, old_target, new_target):
    if not 0 <= version <= 255 or any(not 0 <= x <= MASK for x in (excess, used)):
        raise ValueError('caller input outside range')
    newer = version >= 18
    target = new_target if newer else old_target
    if excess_present and used_present:
        if excess + used > MASK:
            return ('addition_overflow', None, int(newer))
        return ('call', max(excess + used - target, 0), int(newer))
    if version == 17:
        return ('call', 0, 0)
    return ('skip', None, int(newer))


def call_links(data, sections):
    relocs = relative_relocations(data, sections)
    rows = []
    calls = [(0x4e4ae91, 'fixed_loop'), (0x4ea1ec4, 'divide'), (0x4ea1f80, 'divide'),
             (0x4ea1fa6, 'divide'), (0x134c05e, 'divide'), (0x134c091, 'divide'),
             (0x134c659, 'divide'), (0x134c68c, 'divide')]
    div_target = None
    for site, role in calls:
        raw = at(data, sections, site, 6)
        if raw[:2] != b'\xff\x15':
            raise ValueError('unexpected indirect call')
        slot = site + 6 + struct.unpack_from('<i', raw, 2)[0]
        if slot not in relocs:
            raise ValueError('call slot has no relative relocation')
        target = relocs[slot]
        if role == 'fixed_loop' and target != 0x4ea1e00:
            raise ValueError('fixed loop call target differs')
        if role == 'divide':
            if div_target is not None and target != div_target:
                raise ValueError('division calls no longer share a target')
            div_target = target
        rows.append((hex(site), raw.hex(), hex(slot), role,
                     hex(target) if role == 'fixed_loop' else 'shared helper, not analyzed'))
    return rows

def relative_relocations(data, sections):
    rela = [s for s in sections if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(rela) != 1 or rela[0]['size'] % 24:
        raise ValueError('unsupported relocation section')
    sec = rela[0]
    result = {}
    for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, pos)
        if info & 0xffffffff == 8:
            result[where] = addend
    return result


def locations(data, sections):
    relocs = relative_relocations(data, sections)
    rows = []
    for address in (0x574f868, 0x574f880, 0x574f898, 0x56635b0, 0x56635c8, 0x56635e0, 0x56635f8, 0x5663610, 0x5663628, 0x5663718, 0x5663730):
        if address not in relocs:
            raise ValueError('location pointer missing relocation')
        length, line, column = struct.unpack('<QII', at(data, sections, address + 8, 16))
        if not 0 < length < 300:
            raise ValueError('invalid location length')
        raw = at(data, sections, relocs[address], length)
        # Keep the crate-relative suffix only; build-machine prefixes are not evidence.
        positions = [raw.find(prefix) for prefix in (b'revm-primitives-', b'alloy-eips-')]
        positions = [x for x in positions if x >= 0]
        if len(positions) != 1:
            raise ValueError('unexpected source location')
        label = raw[positions[0]:].decode('ascii')
        rows.append((hex(address), hex(relocs[address]), length, line, column, label))
    return rows

def execute_fixed_loop(data, sections, x, d, coverage=None):
    """Walk the fixed loop's x86 bytes. The indirect division is an explicit model hook."""
    if not 0 <= x <= MASK or d not in (3338477, 5007716):
        raise ValueError('invalid interpreter input')
    newer = d == 5007716
    start, stop = (0x4ea1e40, 0x4ea1ee3) if newer else (0x4ea1f00, 0x4ea1f9f)
    failures = {0x4ea1fe0: 'sum_overflow', 0x4ea1fed: 'term_product_overflow',
                0x4ea1fd3: 'iteration_product_overflow'}
    reg = {k: 0 for k in ('rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r12','r13','r14','r15','rbp')}
    reg['rcx'], reg['r13'] = d, 1
    stack = {0x18: x}
    moves = {
      bytes.fromhex(k): v for k,v in {
        '4889d0': ('rax','rdx'), '4989c2': ('r10','rax'), '4889c8': ('rax','rcx'),
        '4989c6': ('r14','rax'), '4889d3': ('rbx','rdx'), '4889e8': ('rax','rbp'),
        '4889c1': ('rcx','rax'), '4c89e8': ('rax','r13'), '4989c4': ('r12','rax'),
        '4989d7': ('r15','rdx'), '4c89f7': ('rdi','r14'), '4889de': ('rsi','rbx'),
        '4c89e2': ('rdx','r12'), '4c89f9': ('rcx','r15'),
      }.items()
    }
    loads = {bytes.fromhex('4c8b442418'): ('r8',0x18),
             bytes.fromhex('488b7c2410'): ('rdi',0x10),
             bytes.fromhex('488b742408'): ('rsi',0x08)}
    stores = {bytes.fromhex('4889742408'): ('rsi',0x08),
              bytes.fromhex('48897c2410'): ('rdi',0x10)}
    adds = {bytes.fromhex('4801cf'): ('rdi','rcx',False),
            bytes.fromhex('4811d6'): ('rsi','rdx',True),
            bytes.fromhex('4c01d3'): ('rbx','r10',False),
            bytes.fromhex('4901cf'): ('r15','rcx',False)}
    cf = of = zf = 0
    pc = start
    iterations = 0
    steps = 0
    text = next(sec for sec in sections if sec['name'] == '.text' and sec['type'] != 8 and sec['flags'] & 4)
    while True:
        if pc == stop:
            return ('ok', iterations, ((reg['rsi'] << 64) | reg['rdi']) // d)
        if pc in failures:
            return (failures[pc], iterations, None)
        if not start <= pc < stop:
            raise ValueError('interpreter branch left fixed loop')
        if pc == start:
            iterations += 1
        steps += 1
        if steps > 100000:
            raise ValueError('interpreter step limit')
        if coverage is not None:
            coverage[pc] = coverage.get(pc, 0) + 1
        offset = text['offset'] + pc - text['address']
        raw = data[offset:offset + 6]
        matched = False
        for table in (moves, loads, stores, adds):
            for opcode, args in table.items():
                if raw.startswith(opcode):
                    if table is moves:
                        reg[args[0]] = reg[args[1]]
                    elif table is loads:
                        if args[1] not in stack:
                            raise ValueError('uninitialized modeled stack')
                        reg[args[0]] = stack[args[1]]
                    elif table is stores:
                        stack[args[1]] = reg[args[0]]
                    else:
                        dest, src, use_cf = args
                        v = reg[dest] + reg[src] + (cf if use_cf else 0)
                        reg[dest], cf = v & MASK, int(v > MASK)
                    pc += len(opcode)
                    matched = True
                    break
            if matched:
                break
        if matched:
            continue
        if raw[:3] in (bytes.fromhex('49f7e0'), bytes.fromhex('48f7e7')):
            operand = reg['r8'] if raw[0] == 0x49 else reg['rdi']
            product = reg['rax'] * operand
            reg['rax'], reg['rdx'] = product & MASK, product >> 64
            cf = of = int(reg['rdx'] != 0)
            pc += 3
        elif raw.startswith(bytes.fromhex('410f90c1')):
            reg['r9'] = (reg['r9'] & ~255) | of
            pc += 4
        elif raw.startswith(bytes.fromhex('400f90c6')):
            reg['rsi'] = (reg['rsi'] & ~255) | of
            pc += 4
        elif raw.startswith(bytes.fromhex('0f92c0')):
            reg['rax'] = (reg['rax'] & ~255) | cf
            pc += 3
        elif raw.startswith(bytes.fromhex('4408c8')):
            low = (reg['rax'] | reg['r9']) & 255
            reg['rax'] = (reg['rax'] & ~255) | low
            zf, cf, of = int(low == 0), 0, 0
            pc += 3
        elif raw.startswith(bytes.fromhex('4008f0')):
            low = (reg['rax'] | reg['rsi']) & 255
            reg['rax'] = (reg['rax'] & ~255) | low
            zf, cf, of = int(low == 0), 0, 0
            pc += 3
        elif raw[0] == 0xbf:
            immediate = struct.unpack_from('<I', raw, 1)[0]
            if immediate != d:
                raise ValueError('interpreter denominator changed')
            reg['rdi'] = immediate
            pc += 5
        elif raw.startswith(bytes.fromhex('4983c501')):
            value = reg['r13'] + 1
            reg['r13'], cf = value & MASK, int(value > MASK)
            pc += 4
        elif raw.startswith(bytes.fromhex('4883d500')):
            value = reg['rbp'] + cf
            reg['rbp'], cf = value & MASK, int(value > MASK)
            pc += 4
        elif raw.startswith(bytes.fromhex('4d39e6')):
            cf = int(reg['r14'] < reg['r12'])
            pc += 3
        elif raw.startswith(bytes.fromhex('4c19fb')):
            value = reg['rbx'] - reg['r15'] - cf
            reg['rbx'], cf = value & MASK, int(value < 0)
            pc += 3
        elif raw[:2] == b'\xff\x15':
            slot = pc + 6 + struct.unpack_from('<i', raw, 2)[0]
            if slot != 0x576e1a8:
                raise ValueError('unexpected division slot')
            numerator = (reg['rsi'] << 64) | reg['rdi']
            denominator = (reg['rcx'] << 64) | reg['rdx']
            if denominator == 0:
                raise ValueError('division by zero in modeled hook')
            quotient = numerator // denominator
            reg['rax'], reg['rdx'] = quotient & MASK, quotient >> 64
            pc += 6
        elif raw[:2] in (b'\x0f\x82', b'\x0f\x83', b'\x0f\x85'):
            take = cf if raw[1] == 0x82 else (not cf if raw[1] == 0x83 else not zf)
            target = pc + 6 + struct.unpack_from('<i', raw, 2)[0]
            pc = target if take else pc + 6
        elif raw[0] == 0x75:
            target = pc + 2 + struct.unpack_from('<b', raw, 1)[0]
            pc = target if not zf else pc + 2
        else:
            raise ValueError('unmodeled instruction in fixed loop')


def saturating_comparison(x, d):
    """Arithmetic comparison: replace each checked operation by a u128 saturation."""
    if not 0 <= x <= MASK or d <= 0 or d > MASK:
        raise ValueError('invalid saturation model input')
    term, total, index = d, 0, 1
    while term:
        total = min(MAX128, total + term)
        numerator = min(MAX128, term * x)
        divisor = min(MAX128, index * d)
        term = numerator // divisor
        index += 1
        if index > 1000:
            raise ValueError('saturation comparison did not terminate')
    return total // d

def exponential_floor(x, d):
    """Exact rational lower and upper bounds on exp(x/d), when both floors agree."""
    s, term, i = Fraction(0), Fraction(1), 0
    while i < 500:
        s += term
        i += 1
        term = term * x / (d * i)
        # When x/(d*(i+1)) <= 1/2 the omitted tail is at most twice the next term.
        if x * 2 <= d * (i + 1):
            upper = s + 2 * term
            if s.numerator // s.denominator == upper.numerator // upper.denominator:
                return s.numerator // s.denominator, i
    raise ValueError('series bound did not settle')


def handler_rows(data, sections, location_rows):
    names = [
        ('fixed_denominator_overflow', 0x4ea1fd3), ('fixed_sum_overflow', 0x4ea1fe0),
        ('fixed_term_overflow', 0x4ea1fed), ('current_sum_overflow', 0x134c6d8),
        ('current_term_overflow', 0x134c6e5), ('current_denominator_overflow', 0x134c6f2),
        ('current_iteration_divide_zero', 0x134c6ff), ('current_increment_overflow', 0x134c70c),
        ('current_initial_product_overflow', 0x134c719), ('parent_sum_overflow', 0x134c0dd),
        ('parent_term_overflow', 0x134c0ea), ('parent_denominator_overflow', 0x134c0f7),
        ('parent_iteration_divide_zero', 0x134c104), ('parent_increment_overflow', 0x134c111),
        ('parent_add_overflow', 0x134c11e), ('parent_target_overflow', 0x134c12b),
        ('parent_initial_product_overflow', 0x134c138),
    ]
    known = {int(r[0], 16): r for r in location_rows}
    result = []
    for label, va in names:
        raw = at(data, sections, va, 13)
        if raw[:3] != b'\x48\x8d\x3d' or raw[7:9] != b'\xff\x15':
            raise ValueError('unexpected failure-handler pattern')
        location = va + 7 + struct.unpack_from('<i', raw, 3)[0]
        slot = va + 13 + struct.unpack_from('<i', raw, 9)[0]
        if location not in known:
            raise ValueError('failure handler location not in selected source records')
        r = known[location]
        result.append((label, hex(va), raw.hex(), hex(location), r[3], r[4], r[5], hex(slot)))
    return result

def tsv(path, header, rows):
    with path.open('w', newline='', encoding='utf-8') as out:
        w = csv.writer(out, delimiter='\t', lineterminator='\n')
        w.writerow(header)
        w.writerows(rows)


def generate(data, out, expected=SHA):
    sections, funcs = validate(data, expected)
    out.mkdir(parents=True, exist_ok=True)
    funcs_rows = []
    for f in funcs:
        start, end = f['start'], f['end']
        body = at(data, sections, start, end-start)
        funcs_rows.append((hex(start), hex(end), hex(f['fde']), len(body), digest(body)))
    tsv(out / 'functions.tsv', ('start_va', 'end_va', 'fde_va', 'size', 'sha256'), funcs_rows)
    pins = [(name, hex(va), len(bytes.fromhex(pattern)), at(data, sections, va, len(bytes.fromhex(pattern))).hex()) for name, va, pattern in SITES]
    tsv(out / 'windows.tsv', ('name', 'va', 'length', 'bytes'), pins)
    links = call_links(data, sections)
    tsv(out / 'links.tsv', ('call_va', 'bytes', 'slot_va', 'role', 'target'), links)
    branches = branch_rows(data, sections)
    tsv(out / 'branches.tsv', ('name', 'branch_va', 'bytes', 'target_va'), branches)
    locs = locations(data, sections)
    tsv(out / 'locations.tsv', ('location_va', 'path_va', 'original_length', 'line', 'column', 'crate_relative_path'), locs)
    handlers = handler_rows(data, sections, locs)
    tsv(out / 'handlers.tsv', ('reason', 'handler_va', 'bytes', 'location_va', 'line', 'column', 'crate_relative_path', 'call_slot_va'), handlers)
    d1 = struct.unpack('<I', at(data, sections, 0x4ea1eed + 1, 4))[0]
    d2 = struct.unpack('<I', at(data, sections, 0x4ea1e2c + 1, 4))[0]
    target_old = struct.unpack('<I', at(data, sections, 0x4e4ae3d, 4))[0]
    target_new = struct.unpack('<I', at(data, sections, 0x4e4ae38, 4))[0]
    selector_rows = []
    for version, x, y, p1, p2 in ((16, 1, 2, True, True), (17, 0, 0, False, True),
                                    (18, 0, 0, False, False), (19, 2, 3, True, False),
                                    (17, target_old, 1, True, True),
                                    (18, target_new, 1, True, True),
                                    (18, MASK, 1, True, True)):
        result = select_excess(version, x, y, p1, p2, target_old, target_new)
        selector_rows.append((version, x, y, int(p1), int(p2), *result))
    tsv(out / 'selector-cases.tsv', ('version', 'excess', 'used', 'excess_present', 'used_present', 'outcome', 'selected_excess', 'selector'), selector_rows)
    selector_table = []
    for version in range(256):
        for p1 in (False, True):
            for p2 in (False, True):
                result = select_excess(version, target_old, 1, p1, p2, target_old, target_new)
                selector_table.append((version, int(p1), int(p2), *result))
    tsv(out / 'selector-table.tsv', ('version', 'excess_present', 'used_present', 'outcome', 'selected_excess', 'selector'), selector_table)
    bounds = []
    samples = []
    comparisons = []
    saturation_rows = []
    walk_cases = []
    walk_coverage = {}
    for d in (d1, d2):
        lo, a, hi, b = threshold(d)
        bounds.append((d, lo, a[0], a[1], a[2], hi, b[0], b[1]))
        if d == d1:
            for x in (lo, hi):
                fixed_status = lifted(x, d)
                saturation_rows.append((d, x, fixed_status[0], fixed_status[2], saturating_comparison(x, d)))
        xs = {0, 1, d-1, d, d+1, 2*d, 3*d, 10*d, 21*d, 22*d,
              lo-1, lo, hi, hi+1, MASK}
        for x in sorted(xs):
            if x > MASK:
                continue
            got = lifted(x, d)
            expected_result = specification(x, d)
            if got != expected_result:
                raise ValueError('lift and arithmetic specification disagree')
            samples.append((d, x, *got))
            walked = execute_fixed_loop(data, sections, x, d, walk_coverage)
            if walked != got:
                raise ValueError('byte walk and arithmetic specification disagree')
            walk_cases.append((d, x, *walked, *expected_result, int(walked == expected_result)))
        for k in range(1, 17):
            x = (lo * k) // 17
            walked = execute_fixed_loop(data, sections, x, d, walk_coverage)
            expected_result = specification(x, d)
            if walked != expected_result:
                raise ValueError('byte walk and arithmetic specification disagree')
            walk_cases.append((d, x, *walked, *expected_result, int(walked == expected_result)))
        x = (21 if d == d1 else 22) * d
        exact, terms = exponential_floor(x, d)
        comparisons.append((d, x, lifted(x, d)[2], exact, terms))
    generic_rows = []
    for d in (d1, d2):
        edge = threshold(d)[0]
        for x in (0, 1, d, 3*d, edge, edge+1):
            status, value = generic(x, d, 1)
            fixed = lifted(x, d)
            if status != fixed[0] or (status == 'ok' and value != fixed[2]):
                raise ValueError('fixed and configurable lifts disagree')
            generic_rows.append((x, d, 1, 1, status, value))
    for x, d, factor, present in ((0, 0, 1, True), (0, 0, 1, False), (0, d1, 0, True),
                                   (d1, d1, 2, True), (0, MAX128, 2, True),
                                   (1, MAX128, 1, True), (MASK, 1, 1, True)):
        status, value = generic(x, d, factor, present)
        generic_rows.append((x, d, factor, int(present), status, value))
    tsv(out / 'generic-cases.tsv', ('excess', 'denominator', 'factor', 'present', 'status', 'value_or_iteration'), generic_rows)
    parent_rows = []
    for a, b, t, present in ((0, 0, 3, True), (131072, 262144, 3, True),
                              (131073, 262144, 3, True), (MASK, 1, 3, True),
                              (0, 0, 1 << 47, True), (MASK, 0, 0, True),
                              (MASK, 1, 1 << 47, False)):
        status, value = parent_excess(a, b, t, present)
        parent_rows.append((a, b, t, int(present), status, value))
    tsv(out / 'parent-cases.tsv', ('old_excess', 'used', 'target_count', 'both_present', 'status', 'excess'), parent_rows)
    tsv(out / 'walk-cases.tsv', ('denominator', 'excess', 'walk_status', 'walk_iteration', 'walk_price', 'spec_status', 'spec_iteration', 'spec_price', 'equal'), walk_cases)
    tsv(out / 'walk-sites.tsv', ('instruction_va', 'visits'), [(hex(pc), visits) for pc, visits in sorted(walk_coverage.items())])
    tsv(out / 'saturation-comparison.tsv', ('denominator', 'excess', 'checked_status', 'checked_price', 'saturated_price'), saturation_rows)
    tsv(out / 'bounds.tsv', ('denominator', 'largest_success', 'status', 'iterations', 'price', 'first_overflow', 'overflow_kind', 'overflow_iteration'), bounds)
    tsv(out / 'cases.tsv', ('denominator', 'excess', 'status', 'iteration', 'price'), samples)
    tsv(out / 'series-comparison.tsv', ('denominator', 'excess', 'staged_floor_price', 'exact_exp_floor', 'terms_in_bound'), comparisons)
    summary = {'artifact': BINARY, 'sha256': SHA, 'fdes': len(funcs), 'pinned_windows': len(pins),
               'old_denominator': d1, 'new_denominator': d2,
               'old_target': target_old, 'new_target': target_new,
               'boundary_rows': len(bounds), 'case_rows': len(samples), 'comparison_rows': len(comparisons),
               'generic_rows': len(generic_rows), 'parent_rows': len(parent_rows), 'location_rows': len(locs), 'handler_rows': len(handlers),
               'selector_rows': len(selector_rows), 'selector_table_rows': len(selector_table),
               'linked_calls': len(links), 'branch_rows': len(branches),
               'byte_walk_cases': len(walk_cases), 'byte_walk_sites': len(walk_coverage),
               'saturation_comparison_rows': len(saturation_rows),
               'model_note': 'Fixed loop byte walk and static lifts; division helper modeled, not executed. FDEs are unwind ranges.'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate((ROOT / BINARY).read_bytes(), args.out)


if __name__ == '__main__':
    main()
