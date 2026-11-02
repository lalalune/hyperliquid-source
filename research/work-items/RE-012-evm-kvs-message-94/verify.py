#!/usr/bin/env python3
"""Authenticate static EvmKvsMsg and checkpoint-context evidence; no target execution."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from tcp_frame_read_static import Image

PACKET = Path(__file__).resolve().parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
ANCHORS = json.loads((PACKET / 'anchors.json').read_text())


def require(ok, message):
    if not ok:
        raise ValueError(message)


def metadata_ranges():
    codec = ANCHORS['codec_metadata']; context = ANCHORS['context_observations']
    for row in [codec['u32_table'], codec['type_name'], codec['variant_metadata_prefix']]:
        yield int(row['address']), bytes.fromhex(row['bytes'])
    for row in context['literals']:
        yield int(row['address'], 16), bytes.fromhex(row['bytes'])
    guard = ANCHORS['transfer_guard']
    yield guard['error_address'], bytes.fromhex(guard['error_bytes'])
    receive = ANCHORS['guard_observations']
    for row in receive['literals']:
        yield int(row['address'], 16), bytes.fromhex(row['bytes'])
    rtti = receive['write_batch_rtti']
    yield int(rtti['name'], 16), bytes.fromhex(rtti['name_bytes'])
    for row in context['formats']:
        yield int(row['address'], 16), bytes.fromhex(row['raw_prefix'])


def relocation_ranges():
    for row in ANCHORS['codec_metadata']['relocations']:
        yield row['file_offset'], bytes.fromhex(row['bytes']), tuple(row['tuple'])
    for row in ANCHORS['context_observations']['relocations'] + ANCHORS['guard_observations']['relocations']:
        yield row['file_offset'], bytes.fromhex(row['bytes']), tuple(int(row[k], 16) for k in ['r_offset', 'r_info', 'r_addend'])


def inspect(data, layout=None):
    """Unqualified fixed-layout inspection for negative controls."""
    im = layout or Image(data)
    def read(address, count):
        off = im.offset(address)
        return data[off:off + count]
    for row in ANCHORS['facts']:
        raw = bytes.fromhex(row['bytes'])
        require(read(row['address'], len(raw)) == raw, 'instruction changed')
    for name, row in ANCHORS['ranges'].items():
        require(im.fde(row['start']) == (row['start'], row['end']), 'FDE changed')
        require(hashlib.sha256(read(row['start'], row['bytes'])).hexdigest() == row['sha256'], 'body changed: ' + name)
    for address, raw in metadata_ranges():
        require(read(address, len(raw)) == raw, 'metadata changed')
    for off, raw, triple in relocation_ranges():
        require(data[off:off + len(raw)] == raw, 'relocation changed')
        require(struct.unpack('<QQq', raw) == triple, 'relocation tuple changed')
    table = ANCHORS['codec_metadata']['u32_table']; raw = bytes.fromhex(table['bytes']); base = table['address']
    require([base + n for n in struct.unpack('<4i', raw)] == table['targets'], 'u32 target changed')
    vtable = int(ANCHORS['context_observations']['vtable']['address'], 16)
    require(struct.unpack('<QQ', read(vtable + 8, 16)) == (64, 8), 'thread closure size/alignment changed')
    guard = ANCHORS['transfer_guard']
    shift = read(0x2266b41, 4)[3]
    maximum = struct.unpack('<I', read(0x2266b45, 6)[2:])[0]
    require(guard['right_shift'] == shift and guard['maximum_shifted'] == maximum, 'size guard operands changed')
    require(((maximum + 1) << shift) == guard['first_rejected_total'] == 100_000_000_000, 'size threshold changed')
    return {'transfer_limit_exclusive': guard['first_rejected_total'], 'origin': 'unqualified structural inspection', 'codec_FDEs': sum(r['scope'] == 'codec' for r in ANCHORS['ranges'].values()),
            'codec_context_bytes': sum(r['bytes'] for r in ANCHORS['ranges'].values() if r['scope'] == 'codec'),
            'supporting_FDEs': sum(r['scope'] == 'context' for r in ANCHORS['ranges'].values()),
            'supporting_context_bytes': sum(r['bytes'] for r in ANCHORS['ranges'].values() if r['scope'] == 'context'),
            'instructions': len(ANCHORS['facts']), 'relocations': sum(1 for _ in relocation_ranges())}


def analyze(data):
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == DIGEST, 'node94 identity changed')
    result = inspect(data)
    result.update({'origin': 'authenticated node94', 'target_sha256': DIGEST, 'wire_selectors': [0, 1],
                   'domain': 'mode-1 EvmKvsMsg projection and cumulative size guard; supporting checkpoint setup only, no complete state validation'})
    return result


if __name__ == '__main__':
    result = analyze(TARGET.read_bytes()); path = PACKET / 'records.json'
    if '--write' in sys.argv:
        path.write_text(json.dumps(result, indent=2) + '\n')
    else:
        require(result == json.loads(path.read_text()), 'record changed')
        print(json.dumps(result, sort_keys=True))
