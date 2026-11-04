#!/usr/bin/env python3
"""Verify the bounded Node115 shutdown observation; never execute the capture."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from fde_extents import sections, eh_frame_records

DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
# Exact instruction encodings underpinning the bounded prose claims. No masks.
ANCHORS = {
    0x5ce0b31: '8b7f18', 0x5ce0b34: '83ffff', 0x5ce0b39: 'be01000000',
    0x5ce0b3e: 'ff155cfb7f00', 0x5ce0b44: '83f8ff',
    0x5ce0b4f: '8b18', 0x5ce0b51: '48c1e320', 0x5ce0b55: '4883cb02',
    0x5ce0b61: '3c07', 0x5ce0b63: '750a', 0x5ce0b6d: '31db',
    0x5ce0b6f: '31c0', 0x5ce0b71: '4889da',
    0x5cdf718: '89f8', 0x5cdf71a: '83e003', 0x5cdf71d: '8d48fe',
    0x5cdf720: '83f902', 0x5cdf723: '7205', 0x5cdf72a: '4883c408',
    0x5cdf735: 'c3',
    0x2b03480: '488d0da94f9403',
    0x2b04505: '418b7f18', 0x2b04512: 'be01000000',
    0x2b0451d: '83f8ff', 0x2b04520: '7528',
    0x2b04528: '8b18', 0x2b0452a: '48c1e320', 0x2b0452e: '4883cb02',
    0x2b0453a: '3c07', 0x2b0453c: '0f85b3010000',
    0x2b0455d: '498b87c0010000', 0x2b04564: '49c787c001000000000000',
    0x2b0456f: '4885c0', 0x2b04572: '0f85c9030000',
    0x2b04578: '488b442478', 0x2b0457d: '48c70000000000',
    0x2b046f5: '48895c2438', 0x2b04708: '0f872a020000',
    0x2b04938: '4889df', 0x2b04941: '488b4c2478',
    0x2b04946: '48c70102000000', 0x2b0494d: '48894108',
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)

    def offset(self, va, size):
        matches = [s['offset'] + va - s['address'] for s in self.secs
                   if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'VA mapping ambiguous/missing: {va:#x}')
        return matches[0]

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def direct_call(self, va, expected):
        raw = self.read(va, 5)
        require(raw[0] == 0xe8 and va + 5 + struct.unpack('<i', raw[1:])[0] == expected,
                f'Direct call changed: {va:#x}')

    def got_call(self, va, slot):
        raw = self.read(va, 6)
        require(raw[:2] == b'\xff\x15'
                and va + 6 + struct.unpack('<i', raw[2:])[0] == slot,
                f'GOT call changed: {va:#x}')

    def imported_slot(self, wanted_slot, wanted_name):
        byname = {s['name']: s for s in self.secs}
        rel = byname['.rela.dyn']; syms = byname['.dynsym']; strings = byname['.dynstr']
        rows = []
        for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
            slot, info, _ = struct.unpack_from('<QQq', self.data, off)
            if slot != wanted_slot:
                continue
            nameoff = struct.unpack_from('<I', self.data, syms['offset'] + (info >> 32) * 24)[0]
            begin = strings['offset'] + nameoff
            end = self.data.index(b'\0', begin, strings['offset'] + strings['size'])
            rows.append((info & 0xffffffff, self.data[begin:end].decode('ascii')))
        require(rows == [(6, wanted_name)], f'Import relocation changed: {wanted_slot:#x}')


def check_observations(image):
    """Internal byte/relocation observer, also attacked with mutated captures.

    The public CLI always checks whole-target identity first. This internal
    observer has no identity bypass flag and does not execute/emulate code.
    """
    for va, want in ANCHORS.items():
        require(image.read(va, len(want) // 2).hex() == want, f'Anchor changed: {va:#x}')
    for va in (0x5ce0b3e, 0x2b04517):
        image.got_call(va, 0x64e06a0)
    for va in (0x5ce0b49, 0x2b04522):
        image.got_call(va, 0x64dffc8)
    image.imported_slot(0x64e06a0, 'shutdown')
    image.imported_slot(0x64dffc8, '__errno_location')
    for va in (0x5ce0b5c, 0x2b04535):
        image.direct_call(va, 0x5cdf1b0)
    for va in (0x5ce0b68, 0x2b04545):
        image.direct_call(va, 0x5cdf710)
    # Source-path association is an inference grounded in a real data relocation.
    rela = next(s for s in image.secs if s['name'] == '.rela.dyn')
    refs = [struct.unpack_from('<QQq', image.data, p)
            for p in range(rela['offset'], rela['offset'] + rela['size'], 24)
            if struct.unpack_from('<Q', image.data, p)[0] == 0x6448440]
    require(refs == [(0x6448440, 8, 0x43ebc6)], 'HTTP source-path relocation changed')
    require(image.read(0x43ebc6, len(b'z_forks/hyper-fork/src/proto/h1/conn.rs\0')) == b'z_forks/hyper-fork/src/proto/h1/conn.rs\0',
            'HTTP source-path bytes changed')
    # Shared classifier context already studied in PR2032: validate, don't claim recovery.
    tag_base = 0x94c7a4
    tags = [tag_base + struct.unpack('<i', image.read(tag_base + 4*i, 4))[0]
            for i in range(4)]
    require(tags == [0x5cdf1c5, 0x5cdf1fc, 0x5cdf1ca, 0x5cdf1ec], 'Low-tag table changed')
    table = image.read(0x94c7b4, 122 * 4)
    require(hashlib.sha256(table).hexdigest() ==
            '2247367d9676d325616463eab2e4eae16436a3ba2948213332bf7932ac7bee79',
            'Errno dispatch table changed')
    targets = [0x94c7b4 + struct.unpack_from('<i', table, 4*i)[0] for i in range(122)]
    require([i+1 for i, target in enumerate(targets) if target == 0x5cdf207] == [107],
            'Raw class7 dispatch changed')
    require(image.read(0x5cdf207, 3) == bytes.fromhex('b007c3'), 'Raw class7 return changed')


def check_exports(image, exports, records):
    cies, fdes = eh_frame_records(image.data, image.secs)
    byfde = {r['fde']: r for r in fdes}
    nbytes = nins = 0
    require(set(exports) == {r['start'] for r in records['ranges']}, 'Export range set changed')
    for r in records['ranges']:
        start, end, fde = (int(r[k], 16) for k in ('start', 'end', 'fde'))
        actual = byfde[fde]
        require((actual['start'], actual['end'], actual['lsda']) == (start, end, r['lsda']),
                'FDE extent or LSDA changed')
        require(actual['cie'] == int(r['cieVA'], 16)
                and cies[actual['cie']]['fde_encoding'] == 0x1b, 'CIE changed')
        e = exports[r['start']]
        require(e['start'] == r['start'] and e['end'] == r['end']
                and e['fde'] == r['fde'] and e['cie'] == cies[actual['cie']]
                and e['lsda'] == actual['lsda'], 'Export unwind metadata changed')
        body = image.read(start, end-start)
        require(hashlib.sha256(body).hexdigest() == r['sha256'] == e['bodySHA256'],
                'Full extent digest changed')
        pairs = []; cursor = start
        for row in e['instructions']:
            va = int(row['va'], 16); raw = bytes.fromhex(row['bytes'])
            require(va == cursor and raw and image.read(va, len(raw)) == raw,
                    f'Export address/byte mismatch: {va:#x}')
            pairs.append((va, raw)); cursor += len(raw)
        require(cursor == end and len(pairs) == r['instructions']
                and len(body) == r['bytes'], 'Export denominator changed')
        native = gzip.decompress((HERE/(r['start']+'.objdump.txt.gz')).read_bytes()).decode()
        got = []
        for line in native.splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)', line)
            if match and start <= int(match[1], 16) < end:
                got.append((int(match[1], 16), bytes.fromhex(match[2])))
        require(got == pairs, 'GNU/Capstone address-byte pairs differ')
        nbytes += len(body); nins += len(pairs)
    require((nbytes, nins) == (15620, 2904), 'Curated denominator changed')
    return {'ranges': 4, 'bytes': nbytes, 'instructions': nins,
            'dualDecoderAddressBytePairsEqual': True, 'normalizations': [],
            'sourceBinaryComparisons': 0, 'targetExecutedOrEmulated': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT/'artifacts/node/115/hl-node')
    args = parser.parse_args()
    data = args.target.read_bytes()
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == DIGEST,
            'Wrong target size/digest; only authenticated Node115 is accepted')
    image = Image(data)
    check_observations(image)
    exports = json.loads(gzip.decompress((HERE/'capstone.json.gz').read_bytes()))
    records = json.loads((HERE/'records.json').read_text())
    result = check_exports(image, exports, records)
    print(json.dumps(dict(targetSHA256=DIGEST, **result), sort_keys=True))


if __name__ == '__main__':
    main()
