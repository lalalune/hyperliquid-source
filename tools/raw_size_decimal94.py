#!/usr/bin/env python3
"""Static evidence for the node 94 raw-size decimal writer; never runs the ELF."""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {
    0x3276830: ('schedule_outer_b', 0x3276b99, 'e498ae099548c34f71c0a8ea9a1249c7ace1b88908b7c9312a84c54c76944794'),
    0x3276ba0: ('schedule_outer_a', 0x3276f09, '3945fac99f5274bab450d18ca17d6c5127511de3a78c5ac18cea9869207709a6'),
    0x3303d20: ('decimal_writer', 0x3303ecc, '6ac020b08f11b28471d4a322f081b86c9fa85205a010c63f927f6576ad1bd73f'),
    0x3277a40: ('size_writer_a', 0x3277cd3, 'f46c2eace56321bb83320df5581053633ebf129b075ba453bd46586fb1b739a6'),
    0x3277ce0: ('size_writer_b', 0x3277fc6, 'ad01ff966d72ff9919736a1c3d48ccad616eee9012e717ead4fec7003aedc4ad'),
    0x3262d80: ('order_size_writer', 0x326300b, '13a5a7859be9f74270d1de18a686f11fe8de9c397fcfcc8e1df688ae16779717'),
}
SITES = ((0x3277b21, 0x3277b74, 0x58411f, b'sz', 8),
         (0x3277df3, 0x3277e46, 0x58411f, b'sz', 8),
         (0x3262dd5, 0x3262e2b, 0x20b030, b'order_sz', 24),
         (0x32769f1, 0x3276a47, 0x58442d, b'executed_sz', 40),
         (0x3276d61, 0x3276db7, 0x58442d, b'executed_sz', 40))
TABLE = 0x5853df
SCHEDULE = ((0x327690c, 0x3276961, 0x3277ce0),
            (0x3276c7c, 0x3276cd1, 0x3277a40))
BRANCHES = (0x3303d3b, 0x3303d6d, 0x3303dab, 0x3303dd3, 0x3303dd9,
            0x3303ddf, 0x3303de4, 0x3303dfa, 0x3303e00, 0x3303e36,
            0x3303e3c, 0x3303e52, 0x3303e6a)
MAX = (1 << 64) - 1


def digest(data):
    actual = hashlib.sha256(data).hexdigest()
    if actual != DIGEST:
        raise ValueError('target SHA-256 mismatch')
    return actual


class Image:
    def __init__(self, data, authenticate=True):
        if authenticate:
            digest(data)
        self.data = data
        sections = elf_index.sections(data)
        self.sections = [s for s in sections if s['type'] != 8 and s['address']]
        _, records = fde_extents.eh_frame_records(data, sections)
        self.fdes = {}
        for row in records:
            if row['start'] in FUNCTIONS:
                if row['start'] in self.fdes:
                    raise ValueError('duplicate target FDE')
                self.fdes[row['start']] = row

    def offset(self, va, size=1):
        if size < 0:
            raise ValueError('negative size')
        matches = [s for s in self.sections if s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('address is not uniquely file-backed')
        s = matches[0]
        return s['offset'] + va - s['address']

    def read(self, va, size):
        o = self.offset(va, size)
        return self.data[o:o + size]

    def rel_target(self, va, prefix):
        ins = self.read(va, len(prefix) + 4)
        if ins[:len(prefix)] != prefix:
            raise ValueError('unexpected relative instruction')
        return va + len(ins) + struct.unpack_from('<i', ins, len(prefix))[0]

    def validate(self):
        result = []
        for va, (role, end, expected) in FUNCTIONS.items():
            fde = self.fdes.get(va)
            if fde is None or fde['end'] != end:
                raise ValueError('FDE extent mismatch')
            raw = self.read(va, end - va)
            h = hashlib.sha256(raw).hexdigest()
            if h != expected:
                raise ValueError('qualified function bytes changed')
            result.append({'role': role, 'start_va': hex(va), 'end_va': hex(end),
                           'file_offset': hex(self.offset(va, len(raw))), 'body_sha256': h,
                           'body_hex': raw.hex()})
        table = self.read(TABLE, 200)
        expected = ''.join(f'{i:02d}' for i in range(100)).encode('ascii')
        if table != expected:
            raise ValueError('digit-pair table differs')
        links = []
        for lea, call, key_va, key, field in SITES:
            if self.rel_target(lea, b'\x48\x8d\x35') != key_va or self.read(key_va, len(key)) != key:
                raise ValueError('field key changed')
            if self.rel_target(call, b'\xe8') != 0x3303d20:
                raise ValueError('writer call target changed')
            if self.read(call - 7, 7) != bytes((0x48,0x8b,0x73,field,0x49,0x8b,0x3f)):
                raise ValueError('field value load changed')
            links.append({'key': key.decode(), 'key_va': hex(key_va), 'key_file_offset': hex(self.offset(key_va, len(key))),
                          'key_load_va': hex(lea), 'field_offset': field, 'call_va': hex(call),
                          'call_target_va': hex(self.rel_target(call, b'\xe8'))})
        schedule_edges = []
        for lea, call, target in SCHEDULE:
            key_va = self.rel_target(lea, b'\x48\x8d\x35')
            if self.read(key_va, 8) != b'schedule' or self.rel_target(call, b'\xe8') != target:
                raise ValueError('nested schedule edge changed')
            if self.read(call + 5, 5) != b'\x48\x85\xc0\x0f\x85':
                raise ValueError('nested schedule error branch changed')
            failure = call + 14 + struct.unpack('<i', self.read(call + 10, 4))[0]
            schedule_edges.append({'key_va': hex(key_va), 'key_load_va': hex(lea),
                                   'call_va': hex(call), 'target_va': hex(target),
                                   'nonzero_error_target_va': hex(failure)})
        # Constants are read from qualified instructions, not from disassembler output.
        if self.read(0x3303d46, 2) != b'\x48\xbf' or self.read(0x3303d8f, 3) != b'\x45\x69\xd1':
            raise ValueError('arithmetic instruction changed')
        reciprocal = struct.unpack('<Q', self.read(0x3303d48, 8))[0]
        pair_reciprocal = struct.unpack('<I', self.read(0x3303d92, 4))[0]
        if reciprocal != 0x346dc5d63886594b or pair_reciprocal != 0x147b:
            raise ValueError('reciprocal differs')
        if self.rel_target(0x3303d50, b'\x4c\x8d\x05') != TABLE:
            raise ValueError('digit table reference changed')
        branches = []
        for va in BRANCHES:
            first = self.read(va, 2)
            if first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
                raw = self.read(va, 6)
                dest = va + 6 + struct.unpack_from('<i', raw, 2)[0]
            elif 0x70 <= first[0] <= 0x7f:
                raw = first
                dest = va + 2 + struct.unpack_from('<b', raw, 1)[0]
            else:
                raise ValueError('unexpected branch bytes')
            if not 0x3303d20 <= dest < 0x3303ecc:
                raise ValueError('branch target outside FDE')
            branches.append({'va': hex(va), 'bytes': raw.hex(), 'target_va': hex(dest)})
        thresholds = {'loop_entry': struct.unpack('<I', self.read(0x3303d37, 4))[0],
                      'loop_last': struct.unpack('<I', self.read(0x3303dcc, 4))[0],
                      'capacity': struct.unpack('<I', self.read(0x3303d30, 4))[0]}
        if thresholds != {'loop_entry': 10000, 'loop_last': 99999999, 'capacity': 20}:
            raise ValueError('threshold changed')
        return result, links, table, reciprocal, pair_reciprocal, branches, thresholds, schedule_edges


def lifted(n, table, reciprocal, pair_reciprocal):
    """Lift the qualified digit-building slice, with its original integer widths."""
    if not 0 <= n <= MAX or len(table) != 200:
        raise ValueError('invalid input or table')
    buf = bytearray(20)
    index = 20
    while n >= 10000:
        quotient = (n * reciprocal) >> 75
        rem = n - quotient * 10000
        hi = ((rem >> 2) * pair_reciprocal) >> 17
        lo = rem - hi * 100
        if not 0 <= hi < 100 or not 0 <= lo < 100:
            raise ValueError('digit-pair index outside table')
        index -= 4
        if index < 0:
            raise ValueError('digit buffer underflow')
        buf[index:index + 4] = table[2 * hi:2 * hi + 2] + table[2 * lo:2 * lo + 2]
        n = quotient
    if n >= 100:
        quotient = ((n >> 2) * pair_reciprocal) >> 17
        rem = n - quotient * 100
        if not 0 <= rem < 100:
            raise ValueError('digit-pair index outside table')
        index -= 2
        buf[index:index + 2] = table[2 * rem:2 * rem + 2]
        n = quotient
    if n >= 10:
        index -= 2
        buf[index:index + 2] = table[2 * n:2 * n + 2]
    else:
        index -= 1
        buf[index] = n | 0x30
    if not 0 <= index < 20:
        raise ValueError('digit buffer index outside range')
    return bytes(buf[index:])


def values():
    result = {0, 1, MAX, MAX - 1, 1 << 63, (1 << 63) - 1}
    for k in range(1, 20):
        for delta in (-1, 0, 1):
            x = 10 ** k + delta
            if 0 <= x <= MAX:
                result.add(x)
    for k in range(1, 65):
        for delta in (-1, 0, 1):
            x = (1 << k) + delta
            if 0 <= x <= MAX:
                result.add(x)
    x = 0x123456789abcdef0
    for _ in range(1000):
        x = (x * 6364136223846793005 + 1442695040888963407) & MAX
        result.add(x)
    return sorted(result)


def collect(data):
    image = Image(data)
    functions, links, table, reciprocal, pair_reciprocal, branches, thresholds, schedule_edges = image.validate()
    # Exact reciprocal proof: M = ceil(2^75/10000); worst error cannot
    # bridge even the smallest distance to the next multiple of 10000.
    error = 10000 * reciprocal - (1 << 75)
    if not (0 <= error and MAX * error < (1 << 75)):
        raise ValueError('u64 reciprocal proof failed')
    bad = sum((((r >> 2) * pair_reciprocal) >> 17) != r // 100 for r in range(10000))
    if bad:
        raise ValueError('pair reciprocal proof failed')
    rows = []
    for n in values():
        actual = lifted(n, table, reciprocal, pair_reciprocal).decode('ascii')
        if actual != str(n):
            raise ValueError('digit model mismatch')
        rows.append((n, actual))
    evidence = {'target_sha256': DIGEST, 'coordinate': 'ELF virtual address', 'functions': functions,
                'field_sites': links, 'schedule_edges': schedule_edges, 'digit_branches': branches, 'thresholds': thresholds, 'digit_table': {'va': hex(TABLE), 'file_offset': hex(image.offset(TABLE, 200)),
                'hex': table.hex(), 'entries': len(table) // 2},
                'arithmetic': {'reciprocal_10000': hex(reciprocal), 'shift': 75, 'reciprocal_error': error,
                'max_error_product': str(MAX * error), 'bound': str(1 << 75), 'reciprocal_100': pair_reciprocal,
                'pair_shift_before': 2, 'pair_shift_after': 17, 'pair_domain': 10000, 'pair_mismatches': bad},
                'model_cases': len(rows), 'model_mismatches': 0}
    vectors = 'input_u64\tdigits\n' + ''.join(f'{n}\t{v}\n' for n, v in rows)
    return evidence, vectors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    evidence, vectors = collect(TARGET.read_bytes())
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (out / 'vectors.tsv').write_text(vectors, encoding='ascii')


if __name__ == '__main__':
    main()
