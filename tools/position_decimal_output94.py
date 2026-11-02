#!/usr/bin/env python3
"""Extract a #94 position-output path from authenticated ELF bytes, without execution."""
import argparse
import csv
from fractions import Fraction
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
# FDE extents and hashes are locks, not an exhaustive function census.
FUNCTIONS = {
    0x2a31160: (0x2a312aa, '785b9a08ae6a1db530dfce3e7380a49e44f9ccf26d8f541f15c200285f156d2d', 'outer'),
    0x2a05f30: (0x2a06161, '3990836e0ccb001438111d771d9900df0541d83aa722c0bbbe270d094ac30264', 'object_adapter'),
    0x2a3d0a0: (0x2a3d30a, 'a188e54a144156ee8f20bb3dc76ad3f94ae81f0f70504bf00915a0c03e4bb7b8', 'position_fields'),
    0x29fa3d0: (0x29fa626, 'f4e4da6b87376926c98c8f36435d1bc2a6fcf3eaef8945fd34d5d601c919ae14', 'optional_adapter'),
    0x2a342b0: (0x2a343a1, 'cc4ae6ab8c01e47f7bc0ac4b7547856b9280113ec034334ed294b657de9bed16', 'float_text_adapter'),
}
# Key name, record offset, source addressing bytes, key-LEA, immediate length,
# call, expected callee, and class. The bytes are checked before use.
FIELDS = [
 ('coin', 0x20, 0x2a3d10e, '498d4e20', 0x2a3d112, 0x2a3d11c, 0x2a3d121, 0x2a007e0, 'other'),
 ('szi', 0x48, 0x2a3d12f, '498d4e48', 0x2a3d133, 0x2a3d13d, 0x2a3d142, 0x2a01350, 'float_writer'),
 ('leverage', 0x38, 0x2a3d150, '498d4e38', 0x2a3d154, 0x2a3d15e, 0x2a3d163, 0x29faa80, 'other'),
 ('entryPx', 0, 0x2a3d180, '4c89f1', 0x2a3d171, 0x2a3d17b, 0x2a3d183, 0x29fa3d0, 'optional_float'),
 ('positionValue', 0x50, 0x2a3d191, '498d4e50', 0x2a3d195, 0x2a3d19f, 0x2a3d1a4, 0x2a01350, 'float_writer'),
 ('unrealizedPnl', 0x58, 0x2a3d1b2, '498d4e58', 0x2a3d1b6, 0x2a3d1c0, 0x2a3d1c5, 0x2a01350, 'float_writer'),
 ('returnOnEquity', 0x60, 0x2a3d1d3, '498d4e60', 0x2a3d1d7, 0x2a3d1e1, 0x2a3d1e6, 0x2a01350, 'float_writer'),
 ('liquidationPx', 0x10, 0x2a3d1f0, '498d4e10', 0x2a3d1f4, 0x2a3d1fe, 0x2a3d203, 0x29fa3d0, 'optional_float'),
 ('marginUsed', 0x68, 0x2a3d20d, '498d4e68', 0x2a3d211, 0x2a3d21b, 0x2a3d220, 0x2a01350, 'float_writer'),
 ('maxLeverage', 0x88, 0x2a3d22a, '498d8e88000000', 0x2a3d231, 0x2a3d23b, 0x2a3d240, 0x2a02870, 'other'),
 ('cumFunding', 0x70, 0x2a3d24a, '4983c670', 0x2a3d24e, 0x2a3d258, 0x2a3d260, 0x29f89e0, 'other'),
]
# Pinned decisions include local conditional exits and optional-value selection.
BRANCHES = [
 (0x2a311ec, 'outer_type', 'nonzero_result_to_error', '75', 0x2a3120a),
 (0x2a31208, 'outer_position', 'zero_result_to_success', '74', 0x2a3122d),
 (0x2a05ff1, 'nested_carrier', 'not_error_sentinel_to_copy', '75', 0x2a0601c),
 (0x29fa3eb, 'optional_entry', 'signed_subtraction_overflow', '0f80', 0x29fa5ac),
 (0x29fa5b0, 'optional_sentinel_key_length', 'length_not_30_to_alternate_exit', '75', 0x29fa5de),
 (0x29fa47f, 'optional_tag', 'tag_not_one_skips_float_call', '75', 0x29fa4c5),
 (0x29fa49a, 'optional_carrier', 'not_error_sentinel_to_copy', '75', 0x29fa4ca),
 (0x2a34309, 'text_length', 'signed_length_nonnegative', '79', 0x2a34318),
 (0x2a34318, 'text_length', 'zero_length_skips_allocation', '74', 0x2a3432d),
 (0x2a34326, 'text_allocation', 'null_allocation_to_failure', '74', 0x2a3437b),
]
CONDITIONS = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
              's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')
ANCHORS = {
 0x2a311ce: '488d359f8e7dfd488d0d7442ca024889e7ba04000000e847abfcff4885c0751c488d351b9b7dfd4889e7ba080000004c89f1e82b4dfdff4885c07423',
 0x2a05fdb: '488d7c24684c89fee8b87003004983c5054c396c24687529',
 0x29fa3e6: '31c0483b070f80bb010000',
 0x29fa47b: '41833f017544f3410f7e4708488d7c2468e81f9e0300',
 0x29fa5ac: '4883fb1e752c',
 0x2a342bb: '4989fef20f11442418488d44241848890424488b0544a7d3024889442408488d35786a7dfd488d5c24204889e24889dfff154f9dd3024889e74889dee85410db00',
 0x2a34342: '48b803000000000000804989064d897e084d896610',
}


def offset(sections, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid virtual address or size')
    matches = [s['offset'] + va - s['address'] for s in sections
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address lacks a unique file-backed section')
    return matches[0]


def read(data, sections, va, size):
    p = offset(sections, va, size)
    raw = data[p:p + size]
    if len(raw) != size:
        raise ValueError('short read')
    return raw


def verify_digest(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('node artifact digest mismatch')


def expect(data, secs, va, expected):
    raw = bytes.fromhex(expected)
    if read(data, secs, va, len(raw)) != raw:
        raise ValueError(f'instruction bytes changed at {va:#x}')


def rel32(data, secs, va, prefix):
    raw = read(data, secs, va, len(prefix) + 4)
    if not raw.startswith(prefix):
        raise ValueError(f'invalid rel32 encoding at {va:#x}')
    return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]


def branch(data, secs, va):
    head = read(data, secs, va, 2)
    if 0x70 <= head[0] <= 0x7f:
        return head.hex(), va + 2 + struct.unpack('<b', head[1:])[0]
    if head[0] == 0x0f and 0x80 <= head[1] <= 0x8f:
        raw = read(data, secs, va, 6)
        return raw.hex(), va + 6 + struct.unpack_from('<i', raw, 2)[0]
    raise ValueError(f'unsupported conditional branch at {va:#x}')


def relocation(data, secs, target_slot):
    matches = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(matches) != 1 or matches[0]['size'] % 24:
        raise ValueError('invalid relocation section')
    sec = matches[0]
    found = []
    for p in range(sec['offset'], sec['offset'] + sec['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, p)
        if where == target_slot:
            found.append((info, addend))
    if len(found) != 1 or found[0][0] != 8:
        raise ValueError('expected unique symbol-free RELATIVE relocation')
    return found[0][1]


def describe(data):
    """Validate locks and return selected raw facts. Digest is checked by the caller."""
    secs = elf_index.sections(data)
    _, fdes = fde_extents.eh_frame_records(data, secs)
    functions = []
    for start, (end, digest, label) in sorted(FUNCTIONS.items()):
        found = [f for f in fdes if f['start'] == start]
        if len(found) != 1 or found[0]['end'] != end:
            raise ValueError('unexpected or ambiguous FDE extent')
        raw = read(data, secs, start, end - start)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f'function lock changed at {start:#x}')
        sec = [s for s in secs if s['type'] != 8 and s['flags'] & 4 and s['address'] <= start and end <= s['address'] + s['size']]
        if len(sec) != 1:
            raise ValueError('function not in one executable file-backed section')
        functions.append({'role': label, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                          'fde_va': hex(found[0]['fde']), 'file_offset': hex(offset(secs, start, len(raw))),
                          'size': len(raw), 'sha256': digest, 'bytes': raw.hex()})
    for va, encoded in ANCHORS.items():
        expect(data, secs, va, encoded)
    if rel32(data, secs, 0x2a31200, b'\xe8') != 0x2a05f30 or rel32(data, secs, 0x2a05fe3, b'\xe8') != 0x2a3d0a0:
        raise ValueError('outer path changed')
    if rel32(data, secs, 0x29fa48c, b'\xe8') != 0x2a342b0:
        raise ValueError('optional path changed')
    if rel32(data, secs, 0x2a342d9, b'\x48\x8d\x35') != 0x20ad58:
        raise ValueError('format descriptor changed')
    if rel32(data, secs, 0x2a342f7, b'\xe8') != 0x37e5350:
        raise ValueError('trim boundary changed')
    descriptor = read(data, secs, 0x20ad58, 8)
    if descriptor != bytes.fromhex('c5200000700a0000'):
        raise ValueError('format descriptor bytes changed')
    # Under the previously established compact-request relation, c5 has an
    # immediate options word and second u16, with no row indirection.
    tag = descriptor[0]
    options = struct.unpack_from('<I', descriptor, 1)[0]
    precision = struct.unpack_from('<H', descriptor, 5)[0]
    if tag != 0xc5 or options != 0x70000020 or precision != 10 or descriptor[7] != 0:
        raise ValueError('format request layout changed')
    if rel32(data, secs, 0x2a342cd, b'\x48\x8b\x05') != 0x576ea18:
        raise ValueError('float callback slot changed')
    if rel32(data, secs, 0x2a342eb, b'\xff\x15') != 0x576e040:
        raise ValueError('format call slot changed')
    callback, formatter = relocation(data, secs, 0x576ea18), relocation(data, secs, 0x576e040)
    if callback != 0x1571d50 or formatter != 0x1344760:
        raise ValueError('format relocation changed')
    strings = []
    for slot, size, wanted in [(0x56d5450, 14, b'FAssetPosition'), (0x56d5460, 6, b'oneWay')]:
        target = relocation(data, secs, slot)
        if read(data, secs, target, size) != wanted or struct.unpack('<Q', read(data, secs, slot + 8, 8))[0] != size:
            raise ValueError('outer type descriptor changed')
        strings.append({'slot_va': hex(slot), 'target_va': hex(target), 'length': size, 'text': wanted.decode('ascii')})
    outer = []
    for lea, length, call, want in [(0x2a311ce, 4, 0x2a311e4, 'type'), (0x2a311ee, 8, 0x2a31200, 'position')]:
        target = rel32(data, secs, lea, b'\x48\x8d\x35')
        text = read(data, secs, target, length).decode('ascii')
        if text != want:
            raise ValueError('outer field mismatch')
        outer.append({'key': text, 'key_va': hex(target), 'call_va': hex(call),
                      'callee_va': hex(rel32(data, secs, call, b'\xe8'))})
    fields, decisions = [], []
    for name, field_off, src, raw, lea, movlen, call, callee, kind in FIELDS:
        expect(data, secs, src, raw)
        target = rel32(data, secs, lea, b'\x48\x8d\x35')
        encoded = read(data, secs, movlen, 5)
        if encoded[0] != 0xba:
            raise ValueError('invalid key-length instruction')
        length = struct.unpack_from('<I', encoded, 1)[0]
        if read(data, secs, target, length) != name.encode('ascii'):
            raise ValueError('field key mismatch')
        actual_callee = rel32(data, secs, call, b'\xe8')
        if actual_callee != callee or read(data, secs, call + 5, 3) != b'\x48\x85\xc0':
            raise ValueError('field call or result test changed')
        br = call + 8
        raw_branch, dst = branch(data, secs, br)
        expected_condition = '74' if name == 'cumFunding' else ('0f85' if br < 0x2a3d1ee else '75')
        if not raw_branch.startswith(expected_condition):
            raise ValueError('field branch condition changed')
        if dst != (0x2a3d28d if name == 'cumFunding' else 0x2a3d26a):
            raise ValueError('field branch destination changed')
        fields.append({'key': name, 'record_offset': hex(field_off), 'key_va': hex(target), 'key_length': length,
                       'source_va': hex(src), 'source_bytes': raw, 'call_va': hex(call),
                       'callee_va': hex(actual_callee), 'class': kind})
        condition_byte = bytes.fromhex(raw_branch)[1 if raw_branch.startswith('0f') else 0]
        decisions.append({'site_va': hex(br), 'encoding': raw_branch,
                          'condition': CONDITIONS[condition_byte & 15],
                          'target_va': hex(dst), 'fallthrough_va': hex(br + len(bytes.fromhex(raw_branch))),
                          'context': name, 'taken_effect': 'zero_result_to_success' if name == 'cumFunding' else 'nonzero_result_to_error'})
    for va, context, effect, prefix, expected_target in BRANCHES:
        raw, dest = branch(data, secs, va)
        if not raw.startswith(prefix) or dest != expected_target:
            raise ValueError('selected branch condition or destination changed')
        condition_byte = bytes.fromhex(raw)[1 if raw.startswith('0f') else 0]
        decisions.append({'site_va': hex(va), 'encoding': raw,
                          'condition': CONDITIONS[condition_byte & 15],
                          'target_va': hex(dest), 'fallthrough_va': hex(va + len(bytes.fromhex(raw))),
                          'context': context, 'taken_effect': effect})
    optional_unequal = branch(data, secs, 0x29fa47f)[1]
    if optional_unequal != 0x29fa4c5:
        raise ValueError('optional tag branch changed')
    return {'binary_sha256': SHA256, 'coordinate_system': 'linked ELF virtual address before load bias',
            'functions': functions, 'outer_fields': outer, 'outer_type': strings,
            'format_descriptor': {'va': '0x20ad58', 'bytes': descriptor.hex(), 'tag': hex(tag),
                                  'options': hex(options), 'immediate_second_u16': precision,
                                  'float_callback_slot': '0x576ea18', 'float_callback_va': hex(callback),
                                  'formatter_slot': '0x576e040', 'formatter_va': hex(formatter)},
            'optional_tag_compare': {'site_va': '0x29fa47b', 'width_bits': 32, 'equal': 1,
                                     'equal_call_va': '0x29fa48c', 'other_target_va': hex(optional_unequal)},
            'fields': fields, 'branches': decisions,
            'windows': [{'start_va': hex(va), 'end_va_exclusive': hex(va + len(bytes.fromhex(raw))),
                         'bytes': read(data, secs, va, len(bytes.fromhex(raw))).hex()}
                        for va, raw in sorted(ANCHORS.items())]}


def rational_from_binary64(bits):
    if not isinstance(bits, int) or not 0 <= bits < 1 << 64:
        raise ValueError('binary64 bits outside u64')
    exponent, fraction = (bits >> 52) & 0x7ff, bits & ((1 << 52) - 1)
    if exponent == 0x7ff:
        raise ValueError('non-finite input')
    if exponent == 0:
        significand, power = fraction, -1074
    else:
        significand, power = (1 << 52) | fraction, exponent - 1075
    val = Fraction(significand << power, 1) if power >= 0 else Fraction(significand, 1 << -power)
    return -val if bits >> 63 else val


def ideal_fixed_ten(bits):
    """Conditional reference model; does not interpret the target formatter."""
    value = rational_from_binary64(bits)
    scaled = abs(value) * 10**10
    q, r = divmod(scaled.numerator, scaled.denominator)
    q += int(2*r > scaled.denominator or (2*r == scaled.denominator and q & 1))
    whole, frac = divmod(q, 10**10)
    suffix = str(frac).zfill(10).rstrip('0') or '0'
    return ('-' if value < 0 and q else '') + str(whole) + '.' + suffix


def conditional_zero_region(precision):
    """Prove the binary64 zero-output interval for an ideal fixed-decimal model.

    Positive finite IEEE-754 encodings increase with their exact values. Bisection
    therefore finds the boundary without enumerating the 2**63 sign/magnitude
    patterns. An odd factor in the midpoint denominator excludes an exact tie.
    """
    if precision != 10:
        raise ValueError('model is restricted to the captured ten-place request')
    midpoint = Fraction(1, 2 * 10**precision)
    denominator = midpoint.denominator
    if denominator & (denominator - 1) == 0:
        raise ValueError('midpoint may be exactly binary-representable')
    lo, hi = 0, 0x7ff0000000000000  # +infinity is an exclusive sentinel.
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if rational_from_binary64(mid) < midpoint:
            lo = mid
        else:
            hi = mid
    if not (rational_from_binary64(lo) < midpoint < rational_from_binary64(hi)):
        raise ValueError('unexpected midpoint or boundary')
    rows = []
    for sign in (0, 1):
        sign_mask = sign << 63
        if ideal_fixed_ten(sign_mask | lo) != '0.0':
            raise ValueError('model inside boundary is nonzero')
        outside = ideal_fixed_ten(sign_mask | hi)
        if outside != ('-' if sign else '') + '0.0000000001':
            raise ValueError('model outside boundary differs')
        rows.append({'sign': sign, 'first_bits': f'{sign_mask:016x}',
                     'last_bits': f'{sign_mask | lo:016x}', 'patterns': lo + 1,
                     'first_outside_bits': f'{sign_mask | hi:016x}',
                     'first_outside_value': outside})
    return rows


def tsv(rows, keys):
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=keys, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def first_failure(mask):
    """Interpret the checked call-result branches; 1 bits mean nonzero returns."""
    if not isinstance(mask, int) or not 0 <= mask < 1 << len(FIELDS):
        raise ValueError('invalid failure mask')
    for i in range(len(FIELDS)):
        if mask & (1 << i):
            return i
    return None


def outputs(data):
    verify_digest(data)
    evidence = describe(data)
    model_inputs = [0, 0x8000000000000000, 0x3ff0000000000000, 0x4000000000000000,
                    0x3da5fd7fe1796495, 0x3ddb7cdfd9d7bdbb, 0x3ff000000002bfb0,
                    0x3ff0000000041f88, 0x3f40000000000000, 0x3f58000000000000,
                    0x3fd5555555555555, 0x4330000000000000, 0xbfd5555555555555,
                    0x0000000000000001, 0x7fefffffffffffff]
    cases = [{'input_bits': f'{bits:016x}', 'ideal_ties_even': ideal_fixed_ten(bits)} for bits in model_inputs]
    counts = [0] * (len(FIELDS) + 1)
    for mask in range(1 << len(FIELDS)):
        first = first_failure(mask)
        independent = next((i for i in range(len(FIELDS)) if (mask >> i) & 1), None)
        if first != independent:
            raise ValueError('failure model mismatch')
        counts[len(FIELDS) if first is None else first] += 1
    flow = [{'first_failure': FIELDS[i][0] if i < len(FIELDS) else 'none', 'combinations': count}
            for i, count in enumerate(counts)]
    # The anchored 64-bit compare sets signed overflow precisely for INT64_MIN.
    # The two authenticated key lengths are 7 and 13, so both take the !=30
    # edge on this special builder state before the optional tag is inspected.
    if [f['key_length'] for f in evidence['fields'] if f['class'] == 'optional_float'] != [7, 13]:
        raise ValueError('unexpected optional-field key length')
    sentinel = 1 << 63
    entry_classes = [
        {'first_word': f'{lo:#018x}', 'last_word': f'{hi:#018x}',
         'signed_overflow': overflow, 'path': path}
        for lo, hi, overflow, path in (
            (0, sentinel - 1, False, 'normal'),
            (sentinel, sentinel, True, 'alternate_skips_direct_float_call'),
            (sentinel + 1, (1 << 64) - 1, False, 'normal'))
    ]
    tags = [{'first': 0, 'last': 0, 'calls_float_adapter_if_reached': False},
            {'first': 1, 'last': 1, 'calls_float_adapter_if_reached': True},
            {'first': 2, 'last': (1 << 32) - 1, 'calls_float_adapter_if_reached': False}]
    zero_region = conditional_zero_region(evidence['format_descriptor']['immediate_second_u16'])
    return {
        'optional-entry-classes.tsv': tsv(entry_classes, ['first_word', 'last_word', 'signed_overflow', 'path']),
        'conditional-zero-region.tsv': tsv(zero_region, ['sign', 'first_bits', 'last_bits', 'patterns', 'first_outside_bits', 'first_outside_value']),
        'tag-classes.tsv': tsv(tags, ['first', 'last', 'calls_float_adapter_if_reached']),
        'windows.tsv': tsv(evidence['windows'], ['start_va', 'end_va_exclusive', 'bytes']),
        'failure-model.tsv': tsv(flow, ['first_failure', 'combinations']),
        'evidence.json': (json.dumps(evidence, indent=2, sort_keys=True) + '\n').encode(),
        'fields.tsv': tsv(evidence['fields'], ['key', 'record_offset', 'key_va', 'key_length', 'source_va', 'source_bytes', 'call_va', 'callee_va', 'class']),
        'branches.tsv': tsv(evidence['branches'], ['site_va', 'encoding', 'condition', 'target_va', 'fallthrough_va', 'context', 'taken_effect']),
        'conditional-model.tsv': tsv(cases, ['input_bits', 'ideal_ties_even']),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = outputs(BINARY.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(result.items()):
        (args.out / name).write_bytes(content)


if __name__ == '__main__':
    main()
