#!/usr/bin/env python3
"""Static node #94 schema cap view: fixed-byte landmarks and model cases."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
FUNCTIONS = {
    0x26b3890: (0x26b3c17, '83e0f8e780fa12299e81d01d2aa2732ec460d1081405ed27413a48129fca95a7'),
    0x27ed840: (0x27eda58, '143530bf850ac3feec3c7b513d5945378df790db94c8f72a2d93800191f32fb1'),
    0x27d6710: (0x27d6c68, 'dcfcbf203f58f1aa54b0347a2b94c6bac236926913d6432d4152b13e1435563a'),
}
PINS = {
    'mode_gate': (0x27d6834, '6681bc24800000008601751d4c8bb424880000004180be30020000030f8504020000'),
    'schema_map': (0x27d6a5a, '498b8e08020000488b41304885c0740c660f104138b901000000eb06660f57c031c948894c242048c744'),
    'view_call': (0x27d6aae, '4c89742468488d7c2408488d742420e87e6d0100'),
    'capacity_check': (0x27ed85a, '4c8b66404d89e649c1e6054c89e048c1e83b0f95c04d39fe0f97c108c1740b31ff4c89f6ff153407f802'),
    'map_call': (0x27ed8e1, '488d4424404889f74889c6e89f5fecff'),
    'length_gate': (0x27ed905, '4885f60f84ae000000488b7c2428488d44240848894424404883fe01'),
    'sort_gate': (0x27ed9fa, '4883fe15731ce8dba30500e91dffffffbf08000000be70010000ff150606f8020f0b488d542440ff15a175f802'),
    'scale_loads': (0x26b38cd, '49bb4b598638d6c56d34f30f7e15a105b5fd660f281db9f5b4fdf20f10257175b5fd'),
    'asset_split': (0x26b3af7, '488b4cf2084c8b64f2604889c849f7e348c1ea0b41be01000000493b52300f85e5fdffff4869c2102700004829c1493b4a100f83d1fdffff'),
    'fallback_and_value': (0x26b3900, '31db48ffcd66490f6ec4660f62c2660f5cc3660f28c8660f15c8f20f58c8f20f5ecc4c89e848c1e00549891c014d8974010849895c0110f2410f114c011849ffc5b101'),
    'name_copy': (0x26b3b34, '498b4208488d0c4948c1e104488b740808488b5c08104885db741f48897424184889dfff157ba40b034885c00f84900000004989c6488b7424184c89f74889daff1566a40b034c8b4c24'),
    'error_edges': (0x26b3bd8, '488d3d61190103ff158ba80b03eb1d488d3d02fc0003ff157ca80b03eb0ebf010000004889deff15b4a30b030f0b'),
}

class Image:
    def __init__(self, data, verify_digest=True):
        if verify_digest and hashlib.sha256(data).hexdigest() != DIGEST:
            raise ValueError('node 94 digest mismatch')
        self.data = data
        self.sections = [s for s in elf_index.sections(data) if s['type'] != 8]
        _, fdes = fde_extents.eh_frame_records(data, self.sections)
        self.fdes = fdes

    def read(self, va, size):
        if va < 0 or size < 0:
            raise ValueError('negative address or size')
        matches = [s for s in self.sections if s['address'] <= va and va + size <= s['address'] + s['size'] and size > 0]
        if len(matches) != 1:
            raise ValueError('address range lacks unique file-backed section')
        s = matches[0]
        offset = s['offset'] + va - s['address']
        return self.data[offset:offset + size]

    def check(self):
        functions = []
        for start, (end, digest) in sorted(FUNCTIONS.items()):
            found = [f for f in self.fdes if f['start'] == start and f['end'] == end]
            if len(found) != 1:
                raise ValueError('FDE mismatch')
            body = self.read(start, end - start)
            if hashlib.sha256(body).hexdigest() != digest:
                raise ValueError('function bytes mismatch')
            functions.append({'start': hex(start), 'end': hex(end), 'fde': hex(found[0]['fde']),
                              'length': len(body), 'sha256': digest, 'bytes_hex': body.hex()})
        pins = []
        for name, (va, expected) in PINS.items():
            raw = bytes.fromhex(expected)
            if self.read(va, len(raw)) != raw:
                raise ValueError('landmark mismatch: ' + name)
            if not any(start <= va and va + len(raw) <= end for start, (end, _) in FUNCTIONS.items()):
                raise ValueError('landmark outside function')
            pins.append({'name': name, 'va': hex(va), 'bytes': raw.hex()})
        if self.read(0x203e80, 16) != bytes.fromhex('00003043000030450000000000000000') or self.read(0x202ea0, 16) != bytes.fromhex('00000000000030430000000000003045'):
            raise ValueError('conversion constants mismatch')
        if self.read(0x20ae60, 8) != bytes.fromhex('0000000080842e41'):
            raise ValueError('divisor mismatch')
        for site, target in ((0x27d6abd, 0x27ed840), (0x27ed8ec, 0x26b3890)):
            raw = self.read(site, 5)
            if raw[0] != 0xe8 or site + 5 + struct.unpack('<i', raw[1:])[0] != target:
                raise ValueError('call mismatch')
        return functions, pins


def model(asset, dex, count, value):
    if not all(0 <= x < 1 << 64 for x in (asset, dex, count, value)):
        raise ValueError('u64 required')
    q, r = divmod(asset, 10000)
    # The float is an independently written model of the observed conversion.
    f = float(value) / 1000000.0
    return {'quotient': q, 'remainder': r, 'lookup_valid': q == dex and r < count,
            'value_bits': struct.pack('<d', f).hex()}


def produce(data, out):
    image = Image(data)
    functions, pins = image.check()
    magic = struct.unpack('<Q', image.read(0x26b38cf, 8))[0]
    excess = 10000 * magic - (1 << 75)
    if not (0 < excess and ((1 << 64) - 1) * excess < (1 << 75)):
        raise ValueError('reciprocal proof failed')
    result = {'target_sha256': DIGEST, 'coordinate_system': 'ELF virtual address',
              'functions': functions, 'landmarks': pins,
              'conversion_constants': [{'va': hex(v), 'bytes': image.read(v, 16).hex()} for v in (0x203e80, 0x202ea0)],
              'calls': [{'site': '0x27d6abd', 'target': '0x27ed840'},
                        {'site': '0x27ed8ec', 'target': '0x26b3890'}],
              'divisor': {'va': '0x20ae60', 'bytes': image.read(0x20ae60, 8).hex(), 'binary64': 1000000},
              'reciprocal_proof': {'divisor': 10000, 'multiplier': magic, 'shift': 75,
                                   'excess': excess, 'max_error_numerator': ((1 << 64) - 1) * excess,
                                   'bound': 1 << 75},
              'limits': 'FDEs describe unwind ranges; pins are not a complete control-flow proof. Sort, tree and allocator callees are not analysed.'}
    cases = []
    for a, d, n in [(0,0,0),(0,0,1),(9999,0,9999),(9999,0,10000),
                    (10000,0,1),(10000,1,1),(10001,1,1),(10001,1,2),
                    ((1 << 64)-1, ((1 << 64)-1)//10000, 10000)]:
        for v in (0,1,999999,1000000,(1 << 53)-1,1 << 53,(1 << 53)+1,(1 << 64)-1):
            cases.append({'asset': a, 'dex': d, 'count': n, 'raw_value': v, **model(a,d,n,v)})
    out.mkdir(parents=True, exist_ok=True)
    for name, obj in [('evidence.json', result), ('model-cases.json', cases)]:
        (out / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    produce(BINARY.read_bytes(), args.out)

if __name__ == '__main__':
    main()
