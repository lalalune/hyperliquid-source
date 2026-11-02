#!/usr/bin/env python3
"""Qualify one node #94 fixed table and its million-scale vector projection.

This is a static byte extractor and a separate arithmetic model, not an x86
emulator. Only the two FDEs listed below are interpreted in this item.
"""
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
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64_MAX = (1 << 64) - 1
FUNCTIONS = (
    (0x2a10250, 0x2a10584, 'vector-projection', '28e5b09b96bc4fb42d163874268e71dafb511c1627bec4f4f8c0823470bcf8f4'),
    (0x2a44500, 0x2a44562, 'default-constructor', '7d5bd3223fa3acf2dd1b74b5ed631de152bac4b282d39b54d872d280c3586c88'),
)
# Curated branch starts; no text emitted by an external disassembler is parsed.
BRANCHES = {
    0x2a1026e: 'base-pointer-null',
    0x2a10273: 'optional-flag-zero',
    0x2a1028b: 'count-add-no-carry',
    0x2a102e8: 'allocation-size-valid',
    0x2a102f5: 'zero-allocation-size',
    0x2a10306: 'allocation-return-nonnull',
    0x2a10349: 'base-pointer-null-second-count',
    0x2a10358: 'optional-flag-zero-second-count',
    0x2a10362: 'second-count-add-no-carry',
    0x2a1038e: 'second-count-exceeds-capacity',
    0x2a10399: 'base-pointer-null-no-elements',
    0x2a103a2: 'base-empty',
    0x2a103af: 'base-span-not-one-element',
    0x2a103b7: 'one-element-remainder-present',
    0x2a10469: 'pair-loop-continues',
    0x2a10475: 'no-odd-base-element',
    0x2a104c1: 'optional-flag-zero-tail',
    0x2a104cd: 'optional-range-empty',
    0x2a10554: 'base-pointer-nonnull-after-grow',
    0x2a10569: 'unwind-capacity-zero',
}
# Default constructor path with a successful, nonaliasing allocation. This is
# a manual control-flow lift, not execution of the captured instructions.
DEFAULT_EDGES = {
    0x2a1026e: False, 0x2a10273: False, 0x2a1028b: True,
    0x2a102e8: True, 0x2a102f5: False, 0x2a10306: True,
    0x2a10349: False, 0x2a10358: False, 0x2a10362: True,
    0x2a1038e: False, 0x2a10399: False, 0x2a103a2: False,
    0x2a103af: True, 0x2a103b7: None, 0x2a10469: False,
    0x2a10475: False, 0x2a104c1: False, 0x2a104cd: False,
    0x2a10554: None, 0x2a10569: None,
}
# Each short window is deliberately anchored, in addition to full FDE hashes.
ANCHORS = {
    0x2a10264: bytes.fromhex('4c8b7e280fb62e4d85ff74364084ed7445'),
    0x2a102c5: bytes.fromhex('4c89ee48c1e6044c89e848c1e83c0f95c0'),
    0x2a103a8: bytes.fromhex('4d29fc4983fc10751131d241f6c410'),
    0x2a10400: bytes.fromhex('470fb64c07e8f2430f105c07f00f14d8660f5cd9660f28e3660f15e3f20f58e3f20f5ee246884c06e8f2420f116406f0'),
    0x2a10430: bytes.fromhex('470fb64c07f8f2430f101c070f14d8660f5cd9660f28e3660f15e3f20f58e3f20f5ee246884c06f8f2420f112406'),
    0x2a10477: bytes.fromhex('48c1e204410fb63417f2410f10441708'),
    0x2a10496: bytes.fromhex('660f28c8660f15c8f20f58c8'),
    0x2a104be: bytes.fromhex('4084ed744d488b542420483b5424187441410fb65618f2410f104620'),
    0x2a104e9: bytes.fromhex('660f28c8660f15c8f20f58c8'),
    0x2a10510: bytes.fromhex('48894c241048894b100f1004240f11034889d8'),
    0x2a44508: bytes.fromhex('48c74424080100000048c74424100000000048c744241801000000c64424200148b8'),
    0x2a44532: bytes.fromhex('4889442428'),
    0x2a4453e: bytes.fromhex('4889442430'),
    0x2a4454a: bytes.fromhex('4889442438488d742408'),
}


def check_digest(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('target SHA-256 mismatch')


def section_offset(secs, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size < 0:
        raise ValueError('invalid address or length')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               s['address'] <= va and va + size <= s['address'] + s['size'] and
               (size > 0 or va < s['address'] + s['size'])]
    if len(matches) != 1:
        raise ValueError('address is not in exactly one file-backed section')
    section = matches[0]
    return section['offset'] + va - section['address']


def read_va(data, secs, va, size):
    offset = section_offset(secs, va, size)
    raw = data[offset:offset + size]
    if len(raw) != size:
        raise ValueError('truncated read')
    return raw


def rel32(data, secs, va, prefix):
    raw = read_va(data, secs, va, len(prefix) + 4)
    if not raw.startswith(prefix):
        raise ValueError('wrong instruction prefix')
    return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]


def branch(data, secs, va):
    raw = read_va(data, secs, va, 2)
    if 0x70 <= raw[0] <= 0x7f:
        return raw[0] & 15, va + 2 + struct.unpack('<b', raw[1:])[0], 2
    if raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        disp = struct.unpack('<i', read_va(data, secs, va + 2, 4))[0]
        return raw[1] & 15, va + 6 + disp, 6
    raise ValueError('expected conditional branch')


def relative_slot(data, secs, slot, expected):
    """Resolve a unique R_X86_64_RELATIVE slot from the file's RELA section."""
    matches = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(matches) != 1 or matches[0]['size'] % 24:
        raise ValueError('missing or malformed dynamic relocations')
    section = matches[0]
    found = []
    for off in range(section['offset'], section['offset'] + section['size'], 24):
        destination, info, addend = struct.unpack_from('<QQq', data, off)
        if destination == slot:
            found.append((off, info, addend))
    if len(found) != 1 or found[0][1] != 8 or found[0][2] != expected:
        raise ValueError('missing, duplicate or changed relative slot')
    section_offset(secs, slot, 8)
    return found[0][0]


def round_ratio_bits(numerator, denominator):
    """Round a nonnegative rational to finite, normal binary64, ties to even.

    The caller only supplies u64 or its first rounded value divided by 1e6;
    every nonzero result is normal and below 2**65.
    """
    if numerator < 0 or denominator <= 0:
        raise ValueError('bad rational')
    if numerator == 0:
        return 0
    exponent = numerator.bit_length() - denominator.bit_length()
    if exponent >= 0:
        if numerator < (denominator << exponent):
            exponent -= 1
    elif (numerator << -exponent) < denominator:
        exponent -= 1
    shift = 52 - exponent
    if shift >= 0:
        num, den = numerator << shift, denominator
    else:
        num, den = numerator, denominator << -shift
    q, r = divmod(num, den)
    if 2 * r > den or (2 * r == den and q & 1):
        q += 1
    if q == 1 << 53:
        q >>= 1
        exponent += 1
    if not (1 << 52 <= q < 1 << 53 and -1022 <= exponent <= 1023):
        raise ValueError('unsupported result class')
    return ((exponent + 1023) << 52) | (q - (1 << 52))


def bits_fraction(bits):
    if bits == 0:
        return Fraction(0)
    exponent = ((bits >> 52) & 0x7ff) - 1023 - 52
    mantissa = (1 << 52) | (bits & ((1 << 52) - 1))
    if exponent >= 0:
        return Fraction(mantissa << exponent)
    return Fraction(mantissa, 1 << -exponent)


def scaled_bits(value):
    if not 0 <= value <= U64_MAX:
        raise ValueError('expected u64')
    first = bits_fraction(round_ratio_bits(value, 1))
    scaled = first / 1_000_000
    return round_ratio_bits(scaled.numerator, scaled.denominator)


def lifted_scale_bits(value, prefix, bias, divisor_bytes):
    """Lift the observed unpack/subtract/add/divide operations to host binary64.

    This is a numeric lift, not an instruction interpreter. Floating-point
    operations assume the host uses round-to-nearest, ties-to-even.
    """
    if not 0 <= value <= U64_MAX:
        raise ValueError('expected u64')
    low_prefix, high_prefix = struct.unpack_from('<II', prefix)
    low_bits = (low_prefix << 32) | (value & 0xffffffff)
    high_bits = (high_prefix << 32) | (value >> 32)
    low = struct.unpack('<d', struct.pack('<Q', low_bits))[0]
    high = struct.unpack('<d', struct.pack('<Q', high_bits))[0]
    low_bias, high_bias = struct.unpack('<dd', bias)
    divisor = struct.unpack('<d', divisor_bytes)[0]
    result = ((high - high_bias) + (low - low_bias)) / divisor
    return struct.unpack('<Q', struct.pack('<d', result))[0]


def count_plan(base_present, base_count, optional_flag, optional_span):
    """Predict count and capacity checks under the documented valid-range assumptions."""
    if any(not isinstance(x, int) or x < 0 or x > U64_MAX for x in (base_count, optional_span)):
        raise ValueError('counts must be u64')
    if base_count > U64_MAX // 16:
        raise ValueError('base count cannot arise from a u64 byte span')
    n = base_count if base_present else 0
    pending_count = optional_span if optional_flag else 0
    if n + pending_count > U64_MAX:
        return {'status': 'count-overflow'}
    capacity = n + pending_count
    if capacity > ((1 << 63) - 8) // 16:
        return {'status': 'allocation-size-overflow'}
    # The tail path checks only whether the optional range is empty.
    return {'status': 'allocate' if capacity else 'empty', 'capacity': capacity,
            'output_len': n + int(bool(optional_flag and optional_span)),
            'pair_iterations': n // 2, 'odd_base': n & 1}


def qualify(data, verify_digest=True):
    if verify_digest:
        check_digest(data)
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    relocation = relative_slot(data, secs, 0x5774f98, 0x2a44500)
    records = []
    for start, end, name, digest in FUNCTIONS:
        matches = [f for f in fdes if f['start'] == start and f['end'] == end]
        if len(matches) != 1:
            raise ValueError('missing or ambiguous FDE')
        raw = read_va(data, secs, start, end - start)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('function bytes changed')
        records.append({'name': name, 'start_va': hex(start), 'end_va': hex(end),
                        'file_offset': hex(section_offset(secs, start, len(raw))),
                        'fde_va': hex(matches[0]['fde']), 'bytes': raw.hex(), 'sha256': digest})
    for va, expected in ANCHORS.items():
        if read_va(data, secs, va, len(expected)) != expected:
            raise ValueError('instruction anchor changed')
    start = rel32(data, secs, 0x2a44537, b'\x48\x8d\x05')
    end = rel32(data, secs, 0x2a44543, b'\x48\x8d\x05')
    call = rel32(data, secs, 0x2a44554, b'\xe8')
    if start != 0x421bb8 or end != 0x421be8 or call != FUNCTIONS[0][0] or end - start != 48:
        raise ValueError('constructor operand changed')
    divisor = rel32(data, secs, 0x2a104a2, b'\xf2\x0f\x5e\x0d')
    divisor2 = rel32(data, secs, 0x2a104f5, b'\xf2\x0f\x5e\x0d')
    if divisor != divisor2 or read_va(data, secs, divisor, 8) != struct.pack('<d', 1_000_000.0):
        raise ValueError('divisor changed')
    # The pair loop loads its divisor into a register before the loop.
    divisor3 = rel32(data, secs, 0x2a103f2, b'\xf2\x0f\x10\x15')
    if divisor3 != divisor:
        raise ValueError('pair-loop divisor changed')
    raw_table = read_va(data, secs, start, end - start)
    duplicate = read_va(data, secs, 0x5995d8, len(raw_table))
    if duplicate != raw_table:
        raise ValueError('duplicated table changed')
    rows = []
    for off in range(0, len(raw_table), 16):
        tag = raw_table[off]
        value = struct.unpack_from('<Q', raw_table, off + 8)[0]
        rows.append({'tag': tag, 'raw': value, 'source_va': hex(start + off)})
    immediate = struct.unpack('<Q', read_va(data, secs, 0x2a4452a, 8))[0]
    rows.append({'tag': read_va(data, secs, 0x2a44527, 1)[0], 'raw': immediate,
                 'source_va': hex(0x2a4452a)})
    if [(r['tag'], r['raw']) for r in rows] != [(25, 30000000000000), (20, 5000000000000),
                                                (10, 2000000000000), (1, 500000000000)]:
        raise ValueError('default rows changed')
    for insn, op, expected in (
        (0x2a103e2, b'\xf2\x0f\x10\x05', 0x203e80),
        (0x2a103ea, b'\x66\x0f\x28\x0d', 0x202ea0),
        (0x2a10487, b'\x0f\x14\x05', 0x203e80),
        (0x2a1048e, b'\x66\x0f\x5c\x05', 0x202ea0),
        (0x2a104da, b'\x0f\x14\x05', 0x203e80),
        (0x2a104e1, b'\x66\x0f\x5c\x05', 0x202ea0),
    ):
        if rel32(data, secs, insn, op) != expected:
            raise ValueError('SIMD constant reference changed')
    prefix = read_va(data, secs, 0x203e80, 16)
    bias = read_va(data, secs, 0x202ea0, 16)
    if prefix.hex() != '00003043000030450000000000000000' or bias.hex() != '00000000000030430000000000003045':
        raise ValueError('SIMD constants changed')
    edges = []
    for va, meaning in sorted(BRANCHES.items()):
        condition, target, length = branch(data, secs, va)
        if not (FUNCTIONS[0][0] <= target < FUNCTIONS[0][1]):
            raise ValueError('branch target outside selected FDE')
        choice = DEFAULT_EDGES[va]
        default = 'unreached' if choice is None else ('taken' if choice else 'fallthrough')
        edges.append({'source': hex(va), 'condition_code': condition, 'target': hex(target),
                      'fallthrough': hex(va + length), 'meaning': meaning,
                      'default_model_edge': default})
    flag = struct.unpack('<I', read_va(data, secs, 0x2a4450d, 4))[0]
    optional_start = struct.unpack('<I', read_va(data, secs, 0x2a44516, 4))[0]
    optional_end = struct.unpack('<I', read_va(data, secs, 0x2a4451f, 4))[0]
    plan = count_plan(1, (end - start) // 16, flag, optional_end - optional_start)
    if plan != {'status': 'allocate', 'capacity': 4, 'output_len': 4,
                'pair_iterations': 1, 'odd_base': 1}:
        raise ValueError('constructor count plan changed')
    plan['requested_allocation_bytes'] = plan['capacity'] * 16
    return {'target_sha256': SHA256, 'functions': records, 'rows': rows,
            'constructor_relocation': {'slot_va': hex(0x5774f98),
                                       'rela_file_offset': hex(relocation),
                                       'relative_addend': hex(0x2a44500)},
            'constructor_object': {'flag': flag, 'optional_start': optional_start,
                                   'optional_end': optional_end, 'table_start': hex(start),
                                   'table_end': hex(end), 'predicted_plan': plan},
            'table_bytes': raw_table.hex(), 'duplicate_table_va': hex(0x5995d8),
            'divisor_va': hex(divisor), 'divisor_bytes': read_va(data, secs, divisor, 8).hex(),
            'simd_prefix_bytes': prefix.hex(), 'simd_bias_bytes': bias.hex(), 'branches': edges}


def csv_text(fieldnames, rows):
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=fieldnames, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def generate(data):
    report = qualify(data)
    defaults = []
    for i, row in enumerate(report['rows']):
        bits = scaled_bits(row['raw'])
        exact = Fraction(row['raw'], 1_000_000)
        defaults.append({'index': i, **row, 'f64_bits': f'0x{bits:016x}',
                         'exact_integer': int(exact) if exact.denominator == 1 else '',
                         'one_round_same': int(bits == round_ratio_bits(row['raw'], 1_000_000))})
    values = {0, 1, 999999, 1000000, 1000001, U64_MAX}
    for power in range(1, 65):
        for delta in (-2, -1, 0, 1, 2):
            x = (1 << power) + delta
            if 0 <= x <= U64_MAX:
                values.add(x)
    for exponent in range(0, 14):
        x = 1_000_000 * (10 ** exponent)
        for delta in (-1, 0, 1):
            if 0 <= x + delta <= U64_MAX:
                values.add(x + delta)
    # These deterministic inputs exercise intermediate rounding, around 2**63.
    for x in range((1 << 63) - 12000, (1 << 63) + 12001, 127):
        values.add(x)
    numeric = []
    for x in sorted(values):
        first = round_ratio_bits(x, 1)
        twice = scaled_bits(x)
        once = round_ratio_bits(x, 1_000_000)
        lifted = lifted_scale_bits(x, bytes.fromhex(report['simd_prefix_bytes']),
                                   bytes.fromhex(report['simd_bias_bytes']),
                                   bytes.fromhex(report['divisor_bytes']))
        if lifted != twice:
            raise ValueError('numeric lift disagrees with integer-rational model')
        numeric.append({'input_u64': x, 'input_f64_bits': f'0x{first:016x}',
                        'two_round_bits': f'0x{twice:016x}', 'lifted_bits': f'0x{lifted:016x}',
                        'one_round_bits': f'0x{once:016x}', 'different': int(twice != once)})
    plans = []
    for base_present in (0, 1):
        for n in (0, 1, 2, 3, 4, 5):
            for flag in (0, 1):
                for span in (0, 1, 2):
                    result = count_plan(base_present, n, flag, span)
                    plans.append({'base_present': base_present, 'base_count': n, 'flag': flag,
                                  'optional_span': span, **result})
    for n, span in ((1, U64_MAX), ((1 << 59) - 1, 0), (1 << 59, 0)):
        plans.append({'base_present': 1, 'base_count': n, 'flag': 1, 'optional_span': span,
                      **count_plan(1, n, 1, span)})
    report['models'] = {'numeric_cases': len(numeric),
                        'two_round_differs': sum(r['different'] for r in numeric),
                        'count_plan_cases': len(plans),
                        'method': 'integer-rational predictions, not target execution'}
    return {'evidence.json': json.dumps(report, indent=2, sort_keys=True) + '\n',
            'default-rows.tsv': csv_text(['index', 'tag', 'raw', 'source_va', 'f64_bits', 'exact_integer', 'one_round_same'], defaults),
            'numeric-model.tsv': csv_text(['input_u64', 'input_f64_bits', 'two_round_bits', 'lifted_bits', 'one_round_bits', 'different'], numeric),
            'count-model.tsv': csv_text(['base_present', 'base_count', 'flag', 'optional_span', 'status', 'capacity', 'output_len', 'pair_iterations', 'odd_base'], plans),
            'branches.tsv': csv_text(['source', 'condition_code', 'target', 'fallthrough', 'meaning', 'default_model_edge'], report['branches'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    # Complete all checks before creating any output.
    result = generate(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in result.items():
        (args.out / name).write_text(content, encoding='utf-8', newline='\n')


if __name__ == '__main__':
    main()
