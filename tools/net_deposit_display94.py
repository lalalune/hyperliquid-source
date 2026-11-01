#!/usr/bin/env python3
"""Extract the node 94 DEX deposit display path from authenticated ELF bytes."""
import argparse
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

TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {
    0x2588fa0: (0x258915b, 'e34aabc4f06c42c0aa3b71caf3d3f54d2fb4c8c345b91491bc0a7b6becd5bc27'),
    0x27d6040: (0x27d645f, '763761757e7c3bd7726c7f1fcd5f8cdcb1fdcf1dd3f1ec9f25ed0e01e0e21d03'),
    0x2a2e340: (0x2a2e47c, '99befac20e24a3cffaef4c1e47f038e2f0e5f759138b8780edbc4873be6dba73'),
    0x2a33860: (0x2a341df, 'b734bd55d584945c9b1470efa8bd225c74efd99ad1fb8679b54a828fedfde567'),
}
BRANCHES = {
    0x2588fa0: (0x258904f, 0x258905e, 0x2589068, 0x2589072, 0x258907c, 0x25890f2, 0x2589132, 0x2589141),
    0x2a2e340: (0x2a2e35d, 0x2a2e3ce),
    0x2a33860: (),
    0x27d6040: (0x27d6089,0x27d609b,0x27d60a7,0x27d60fb,0x27d6166,0x27d6197,0x27d6199,0x27d61f2,0x27d621b,0x27d6273,0x27d6318,0x27d6381,0x27d6390,0x27d63a0,0x27d63b1,0x27d63da,0x27d63e7,0x27d63f2,0x27d6401,0x27d6410,0x27d642e,0x27d6436,0x27d6457),
}
# Each anchor is a complete instruction, or a contiguous instruction sequence.
ANCHORS = {
    'caller_call': (0x2588fe5, 'e856d02400'),
    'caller_sum': (0x2589039, 'f20f588c24e0000000'),
    'caller_threshold': (0x2589047, '660f2e0d691ac8fd'),
    'lookup_call': (0x27d6159, 'ff15a9e5f902'),
    'status_compare': (0x27d615f, '66817c24208601'),
    'signed_i64': (0x27d6170, 'f2480f2a8038020000'),
    'divide': (0x27d6179, 'f20f5e05df4ca3fd'),
    'success_payload': (0x27d6181, 'f20f118424a8000000'),
    'success_tag': (0x27d618a, '66c78424a00000008601'),
    'error_head': (0x27d61b5, '660f10442420'),
    'error_tail': (0x27d619b, '0f10442470'),
    'variant_dispatch': (0x2a3386a, '488b06488d48fe4883f802b815000000480f43c1'),
    'variant_input': (0x2a34033, 'f20f104608'),
    'variant_call': (0x2a3403d, 'e8fea2ffff'),
    'object_key': (0x2a2e3b0, '488d35581c9ffd'),
    'object_write_call': (0x2a2e3c6, 'e8852ffdff'),
    'outer_copy': (0x258907e, '0f28442460'),
}


def read_target(path=TARGET):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('node 94 SHA-256 mismatch')
    return data


def resolve(data, va, size):
    if size <= 0:
        raise ValueError('invalid size')
    hits = [s for s in elf_index.sections(data) if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError('address does not resolve to one file-backed section')
    s = hits[0]
    return s['offset'] + va - s['address']


def at(data, va, size):
    p = resolve(data, va, size)
    return bytes(data[p:p+size])


def branch(data, va, start, end):
    b = at(data, va, 2)
    if b[0] == 0xeb or 0x70 <= b[0] <= 0x7f:
        n = 2
        disp = struct.unpack('<b', b[1:])[0]
    elif b[0] == 0xe9:
        n = 5
        disp = struct.unpack('<i', at(data, va + 1, 4))[0]
    elif b[0] == 0x0f and 0x80 <= b[1] <= 0x8f:
        n = 6
        disp = struct.unpack('<i', at(data, va + 2, 4))[0]
    else:
        raise ValueError('unexpected branch encoding')
    dest = va + n + disp
    if not start <= dest < end:
        raise ValueError('branch leaves selected FDE')
    return {'va': hex(va), 'bytes': at(data, va, n).hex(), 'target_va': hex(dest)}


def round_even(n, d):
    q, r = divmod(n, d)
    return q + (2*r > d or (2*r == d and q & 1))


def f64_bits(x):
    """Correctly round a finite Fraction in this model to binary64, ties even."""
    x = Fraction(x)
    sign = int(x < 0)
    x = abs(x)
    if not x:
        return sign << 63
    n, d = x.numerator, x.denominator
    exponent = n.bit_length() - d.bit_length()
    if exponent >= 0:
        if n < d << exponent:
            exponent -= 1
    elif n << -exponent < d:
        exponent -= 1
    if not -1022 <= exponent <= 1023:
        raise ValueError('model limited to normal finite results')
    shift = 52 - exponent
    sig = round_even(n << shift, d) if shift >= 0 else round_even(n, d << -shift)
    if sig == 1 << 53:
        sig >>= 1
        exponent += 1
    if exponent > 1023:
        raise ValueError('overflow')
    return (sign << 63) | ((exponent + 1023) << 52) | (sig - (1 << 52))


def fraction_from_bits(bits):
    exponent = (bits >> 52) & 0x7ff
    if exponent == 0:
        if bits & ((1 << 52) - 1):
            raise ValueError('subnormal model input')
        return Fraction(0)
    if exponent == 0x7ff:
        raise ValueError('nonfinite model input')
    mantissa = (1 << 52) | (bits & ((1 << 52) - 1))
    shift = exponent - 1023 - 52
    value = Fraction(mantissa << shift) if shift >= 0 else Fraction(mantissa, 1 << -shift)
    return -value if bits >> 63 else value


def display_bits(x):
    if not -(1 << 63) <= x < (1 << 63):
        raise ValueError('outside signed 64-bit domain')
    first = f64_bits(x)
    return f64_bits(fraction_from_bits(first) / 1_000_000)


def checked(data):
    secs = elf_index.sections(data)
    _, fdes = fde_extents.eh_frame_records(data, secs)
    by_start = {f['start']: f for f in fdes}
    output = []
    for start, (end, digest) in sorted(FUNCTIONS.items()):
        f = by_start.get(start)
        if f is None or f['end'] != end:
            raise ValueError('FDE extent changed')
        body = at(data, start, end-start)
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError('function bytes changed')
        output.append({'start_va': hex(start), 'end_va': hex(end), 'file_offset': hex(resolve(data,start,end-start)),
                       'fde_va': hex(f['fde']), 'cie_va': hex(f['cie']), 'body_sha256': digest, 'body_hex': body.hex()})
    anchors = {}
    for name, (va, expected) in sorted(ANCHORS.items()):
        raw = at(data, va, len(bytes.fromhex(expected)))
        if raw.hex() != expected:
            raise ValueError('instruction anchor changed: ' + name)
        anchors[name] = {'va': hex(va), 'file_offset': hex(resolve(data,va,len(raw))), 'bytes': raw.hex()}
    response_name = at(data, 0x42000f, 15)
    if response_name != b'totalNetDeposit':
        raise ValueError('response key changed')
    table_entry = at(data, 0x41fe50, 4)
    if 0x41fdb4 + struct.unpack('<i', table_entry)[0] != 0x2a34033:
        raise ValueError('variant table changed')
    if 0x2a34042 + struct.unpack('<i', at(data, 0x2a3403d, 5)[1:])[0] != 0x2a2e340:
        raise ValueError('serializer call changed')
    name = at(data, 0x598c55, 17)
    if name != b'total_net_deposit':
        raise ValueError('field key changed')
    divisor = at(data, 0x20ae60, 8)
    threshold = at(data, 0x20aab8, 8)
    if divisor != struct.pack('<d', 1_000_000.0) or threshold != struct.pack('<d', 3.0):
        raise ValueError('floating constant changed')
    # Resolve the lookup slot via the existing ELF section parser, not a dynamic loader.
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    entries = []
    for p in range(rela['offset'], rela['offset'] + rela['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, p)
        if where == 0x5774708:
            entries.append((info, addend))
    if entries != [(8, 0x3332270)]:
        raise ValueError('lookup relocation changed')
    call = at(data, 0x2588fe5, 5)
    if 0x2588fea + struct.unpack('<i',call[1:])[0] != 0x27d6040:
        raise ValueError('call target changed')
    slot = at(data, 0x27d6159, 6)
    if 0x27d615f + struct.unpack('<i',slot[2:])[0] != 0x5774708:
        raise ValueError('lookup slot changed')
    # For every nonzero i64, the first conversion magnitude is within [1, 2^63].
    # Division therefore lies within [10^-6, 2^63 / 10^6], strictly normal.
    if not (Fraction(1, 1000000) > Fraction(1, 1 << 20) and
            Fraction(1 << 63, 1000000) < 1 << 44):
        raise ValueError('binary64 range proof failed')
    branches = {hex(start): [branch(data, va, start, end) for va in BRANCHES[start]] for start,(end,_) in sorted(FUNCTIONS.items())}
    return {'target_sha256': SHA256, 'coordinates':'ELF virtual addresses; end exclusive', 'functions':output,
            'anchors':anchors, 'branches':branches,
            'divisor':{'va':'0x20ae60','file_offset':hex(resolve(data,0x20ae60,8)),'bytes':divisor.hex()},
            'timing_threshold':{'va':'0x20aab8','bytes':threshold.hex()},
            'field_key':{'va':'0x598c55','bytes':name.hex()},
            'response_key':{'va':'0x42000f','bytes':response_name.hex()},
            'variant':{'tag':41,'table_base_va':'0x41fdb4','entry_va':'0x41fe50','entry_bytes':table_entry.hex(),'target_va':'0x2a34033'},
            'normal_range_proof': {'nonzero_lower_exclusive': '2^-20', 'upper_exclusive': '2^44', 'assumption': 'round-to-nearest ties-to-even'},
            'lookup_slot':{'va':'0x5774708','relative_relocation_addend':'0x3332270'},
            'limits':'FDEs are unwind ranges; numeric rows are a static arithmetic model, not target execution.'}


def write_outputs(data, out):
    evidence = checked(data)
    out.mkdir(parents=True, exist_ok=True)
    (out/'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True)+'\n')
    points = {-(1<<63), -(1<<63)+1, -10**12, -1, 0, 1, 10**6, 10**12, (1<<63)-1}
    for k in (52,53,54,62):
        for delta in (-2,-1,0,1,2):
            points.add((1<<k)+delta)
            points.add(-((1<<k)+delta))
    rows = ['signed_input\tfirst_round_bits\tstaged_result_bits\tone_round_bits']
    for x in sorted(points):
        if -(1<<63) <= x < (1<<63):
            rows.append(f'{x}\t{f64_bits(x):016x}\t{display_bits(x):016x}\t{f64_bits(Fraction(x,1000000)):016x}')
    (out/'vectors.tsv').write_text('\n'.join(rows)+'\n')
    decisions = [
        ('lookup', 'status == 0x186', 'read signed word +0x238; round to binary64; divide by 1000000; retain success tag'),
        ('lookup', 'status != 0x186', 'copy the 96-byte lookup error record; do not read the word or divide'),
        ('cleanup', 'input allocation length == 0', 'skip deallocation'),
        ('cleanup', 'input allocation length != 0', 'call deallocator before returning'),
        ('wrapper', 'sum of two timing values > 3.0', 'conditional logging path; copy the same 96-byte result'),
        ('wrapper', 'sum of two timing values <= 3.0 or unordered', 'skip logging path; copy the same 96-byte result'),
        ('response dispatch', 'tag == 41', 'load binary64 at input +8; call keyed object builder'),
        ('object builder', 'field helper returns nonzero', 'return tagged error and drop temporary object'),
        ('object builder', 'field helper returns zero', 'pass temporary object to finalization helper'),
    ]
    (out/'decisions.tsv').write_text('stage\tcondition\tlocal_consequence\n' + ''.join('\t'.join(row)+'\n' for row in decisions))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    write_outputs(read_target(), args.out)


if __name__ == '__main__':
    main()
