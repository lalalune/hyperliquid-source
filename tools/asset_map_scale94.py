#!/usr/bin/env python3
"""Static node 94 asset-keyed scaled-value conversion; no target execution."""
import argparse
import hashlib
import json
from fractions import Fraction
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = 'artifacts/node/94/hl-node'
TOP = (1 << 64) - 1
# Fixed instruction sequences are verified before assigning their semantic labels.
PATTERNS = {
    'empty_input': (0x26b38ad, '4885ed0f840c030000'),
    'reciprocal': (0x26b38cd, '49bb4b598638d6c56d34'),
    'convert_and_store': (0x26b3905, '66490f6ec4660f62c2660f5cc3660f28c8660f15c8f20f58c8f20f5ecc4c89e848c1e00549891c014d8974010849895c0110f2410f114c0118'),
    'iterator_checks': (0x26b3948, '4885ed0f8471020000f6c1010f848d020000'),
    'key_and_lookup': (0x26b3af7, '488b4cf2084c8b64f2604889c849f7e348c1ea0b41be01000000493b52300f85e5fdffff4869c2102700004829c1493b4a100f83d1fdffff'),
    'name_and_alloc': (0x26b3b40, '488b740808488b5c08104885db741f48897424184889dfff157ba40b034885c00f84900000004989c6488b742418'),
    'copy_name': (0x26b3b6e, '4c89f74889daff1566a40b03'),
    'write_length': (0x26b3bc2, '488b04244c89284883c4285b415c415d415e415f5dc3'),
    'iterator_panics': (0x26b3bd8, '488d3d61190103ff158ba80b03eb1d488d3d02fc0003ff157ca80b03'),
    'allocation_bound': (0x27ed850, '49bff8ffffffffffff7f4c8b66404d89e649c1e6054c89e048c1e83b0f95c04d39fe0f97c108c1740b31ff4c89f6ff153407f802'),
    'allocation': (0x27ed884, '4889fb4d85f674224c89f74989f5ff154007f8024c89ee4885c07516bf080000004c89f6ff150a07f802'),
    'builder_call': (0x27ed8e1, '488d4424404889f74889c6e89f5fecff'),
    'zero_and_one': (0x27ed905, '4885f60f84ae000000488b7c2428488d44240848894424404883fe010f85d3000000'),
    'empty_return': (0x27ed9bc, '48c7030000000048c7431000000000488b7424204885f67411488b7c242848c1e60531d2ff152a06f802'),
    'sort_threshold': (0x27ed9fa, '4883fe15731ce8dba30500e91dffffffbf08000000be70010000ff150606f8020f0b488d542440ff15a175f802e9fbfeffff'),
    'outer_result_tag': (0x27d6834, '6681bc24800000008601751d'),
    'outer_mode': (0x27d6840, '4c8bb424880000004180be30020000030f850402000031c0e9f5020000'),
    'outer_map_iterator': (0x27d6a5a, '498b8e08020000488b41304885c0740c660f104138b901000000eb06660f57c031c948894c242048c7442428000000004889442430660f1344243848894c244048c7442448000000004889442450660f114424584c89742468'),
    'outer_call': (0x27d6ab3, '488d7c2408488d742420e87e6d0100'),
}
BRANCHES = [
    (0x27d683e, 'lookup result tag versus 0x186', 'not equal', 0x27d685d),
    (0x27d6850, 'object mode versus 3', 'not equal', 0x27d6a5a),
    (0x27d6a68, 'map root', 'zero', 0x27d6a76),
    (0x26b38b0, 'empty count', 'zero', 0x26b3bc2),
    (0x26b394b, 'remaining count', 'zero', 0x26b3bc2),
    (0x26b3954, 'iterator valid bit', 'zero', 0x26b3be7),
    (0x26b3a36, 'iterator parent pointer', 'zero', 0x26b3bd8),
    (0x26b3b15, 'key quotient versus metadata id', 'not equal', 0x26b3900),
    (0x26b3b29, 'key remainder versus row count', 'above or equal', 0x26b3900),
    (0x26b3b4d, 'name length', 'zero', 0x26b3b6e),
    (0x26b3b60, 'name allocation result', 'zero', 0x26b3bf6),
    (0x27ed877, 'allocation size check', 'zero', 0x27ed884),
    (0x27ed88a, 'allocation size', 'zero', 0x27ed8ae),
    (0x27ed89e, 'allocation result', 'nonzero', 0x27ed8b6),
    (0x27ed908, 'generated row count', 'zero', 0x27ed9bc),
    (0x27ed921, 'generated row count versus one', 'not equal', 0x27ed9fa),
    (0x27ed9fe, 'generated row count versus 21', 'above or equal', 0x27eda1c),
]
OPCODES = {0x74:'zero',0x75:'not equal',0x73:'above or equal',0x84:'zero',0x85:'not equal',0x83:'above or equal'}

class Image:
    def __init__(self, data, verify=True):
        if verify and hashlib.sha256(data).hexdigest() != SHA:
            raise ValueError('target SHA-256 mismatch')
        self.data = data
        self.sections = elf_index.sections(data)
        _, records = fde_extents.eh_frame_records(data, self.sections)
        self.fdes = {}
        for record in records:
            if record['start'] in self.fdes:
                raise ValueError('duplicate FDE start')
            self.fdes[record['start']] = record

    def read(self, va, size):
        matches = [s for s in self.sections if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1 or size < 0:
            raise ValueError('address range is not uniquely file backed')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return self.data[off:off + size]

    def location(self, va):
        s = next(s for s in self.sections if s['name'] == '.rela.dyn')
        ptr = None
        for i in range(s['offset'], s['offset'] + s['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', self.data, i)
            if where == va and info & 0xffffffff == 8:
                if ptr is not None:
                    raise ValueError('duplicate relocation')
                ptr = addend
        if ptr is None:
            raise ValueError('location has no relative relocation')
        n, line, col = struct.unpack('<QII', self.read(va + 8, 16))
        if n > 256:
            raise ValueError('location string too long')
        path = self.read(ptr, n).decode('ascii')
        # The absolute compiler path is intentionally not exported.
        return {'va': hex(va), 'path_suffix': path.split('/library/')[-1], 'line': line, 'column': col}


def checked_patterns(image):
    rows = []
    for label, (va, expected) in PATTERNS.items():
        value = image.read(va, len(bytes.fromhex(expected)))
        if value != bytes.fromhex(expected):
            raise ValueError('instruction bytes changed: ' + label)
        rows.append({'label':label, 'va':hex(va), 'bytes':value.hex()})
    return rows


def branch(image, va):
    raw = image.read(va, 2)
    if raw[0] == 0x0f and raw[1] in OPCODES:
        length, condition = 6, OPCODES[raw[1]]
        disp = struct.unpack('<i', image.read(va + 2, 4))[0]
    elif raw[0] in OPCODES:
        length, condition = 2, OPCODES[raw[0]]
        disp = struct.unpack('<b', raw[1:])[0]
    else:
        raise ValueError('unsupported conditional branch')
    return condition, va + length + disp


def rounded_ratio(n, d):
    q, r = divmod(n, d)
    return q + (2*r > d or (2*r == d and q & 1))


def binary64(n, d=1):
    """Exact non-negative rational to nearest-even binary64 bits; range used is normal."""
    if n == 0:
        return 0
    e = n.bit_length() - d.bit_length()
    if (n < d << e) if e >= 0 else ((n << -e) < d):
        e -= 1
    shift = 52 - e
    m = rounded_ratio(n << shift, d) if shift >= 0 else rounded_ratio(n, d << -shift)
    if m == 1 << 53:
        m >>= 1
        e += 1
    if not (-1022 <= e <= 1023 and (1 << 52) <= m < (1 << 53)):
        raise ValueError('unsupported binary64 range')
    return ((e + 1023) << 52) | (m - (1 << 52))


def value(bits):
    if bits == 0:
        return Fraction(0)
    e = ((bits >> 52) & 0x7ff) - 1023 - 52
    m = (1 << 52) | (bits & ((1 << 52) - 1))
    return Fraction(m << e, 1) if e >= 0 else Fraction(m, 1 << -e)


def scaled_bits(x):
    if not 0 <= x <= TOP:
        raise ValueError('outside u64')
    first = value(binary64(x)) / 1000000
    return binary64(first.numerator, first.denominator)


def inspect(image):
    patterns = checked_patterns(image)
    boundaries = []
    for start, end in ((0x26b3890,0x26b3c17),(0x27ed840,0x27eda58),(0x27d6710,None)):
        f = image.fdes.get(start)
        if not f:
            raise ValueError('missing FDE')
        # The outer routine is included only for its call site, not its complete body.
        if end is not None and f['end'] != end:
            raise ValueError('FDE endpoint changed')
        boundaries.append({'start':hex(start),'end':hex(f['end']),'fde':hex(f['fde']),
                           'sha256':hashlib.sha256(image.read(start, f['end']-start)).hexdigest()})
    branches = []
    for va, subject, condition, target in BRANCHES:
        got, actual = branch(image, va)
        if got != condition and not (got == 'not equal' and condition == 'nonzero'):
            raise ValueError('conditional opcode changed')
        if actual != target:
            raise ValueError('conditional target changed')
        branches.append({'va':hex(va),'subject':subject,'condition':condition,'target':hex(actual)})
    constants = {hex(a):image.read(a,n).hex() for a,n in ((0x20ae60,8),(0x203e80,8),(0x202ea0,16))}
    if constants != {'0x20ae60':'0000000080842e41','0x203e80':'0000304300003045','0x202ea0':'00000000000030430000000000003045'}:
        raise ValueError('floating point constants changed')
    multiplier = struct.unpack('<Q',image.read(0x26b38cf,8))[0]
    delta = multiplier * 10000 - (1 << 75)
    bound = (TOP // 10000) * delta + 9999 * multiplier
    if not (delta >= 0 and bound < (1 << 75)):
        raise ValueError('reciprocal proof failed')
    return {'target_sha256':SHA, 'coordinate':'ELF virtual address', 'fdes':boundaries, 'patterns':patterns,
            'branches':branches, 'floating_constants':constants,
            'reciprocal_proof':{'multiplier':hex(multiplier),'divisor':10000,'shift':75,
             'delta':delta,'max_error_numerator_bound':str(bound),'denominator':str(1 << 75)},
            'panic_locations':[image.location(0x56c5540), image.location(0x56c37f0)],
            'limits':'Byte patterns are not a general disassembler. FDE ranges describe unwind coverage; no target instructions were executed.'}


def generate(image, out):
    record = inspect(image)
    out.mkdir(parents=True, exist_ok=True)
    (out/'evidence.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    cases = {0,1,9,10,9999,10000,999999,1000000,1000001,(1<<53)-1,1<<53,(1<<53)+1,(1<<53)+2,TOP-1,TOP}
    for k in range(1, 21):
        v=10**k
        cases.update(x for x in (v-1,v,v+1) if x <= TOP)
    rows=['raw_u64\tcast_bits\tscaled_bits\tdirect_scaled_bits\texact_scaled_equal\terror_numerator\terror_denominator']
    for x in sorted(cases):
        cast = binary64(x); bits = scaled_bits(x)
        error = value(bits) - Fraction(x,1000000)
        rows.append(f'{x}\t0x{cast:016x}\t0x{bits:016x}\t0x{binary64(x, 1000000):016x}\t{str(error == 0).lower()}\t{error.numerator}\t{error.denominator}')
    (out/'rounding-vectors.tsv').write_text('\n'.join(rows)+'\n')


def main():
    p=argparse.ArgumentParser(); p.add_argument('--out',required=True,type=Path); args=p.parse_args()
    generate(Image((ROOT/BINARY).read_bytes()), args.out)

if __name__ == '__main__':
    main()
