#!/usr/bin/env python3
"""Verify bounded checkpoint-hash evidence from node #94 without execution."""
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
EXPORTS = json.loads((PACKET / 'native-exports.json').read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inspect(data, layout=None, anchors=None):
    """Inspect fixed coordinates; this seam alone does not authenticate input."""
    anchors = ANCHORS if anchors is None else anchors
    image = layout or Image(data)

    def read(address, count):
        start = image.offset(address, count)
        return data[start:start + count]

    for row in anchors['facts']:
        raw = bytes.fromhex(row['bytes'])
        require(read(row['address'], len(raw)) == raw, 'instruction changed')
    for name, row in anchors['ranges'].items():
        start, end = row['start'], row['end']
        require(image.fde(start) == (start, end), 'FDE changed: ' + name)
        require(end - start == row['size'], 'body size changed: ' + name)
        require(hashlib.sha256(read(start, end - start)).hexdigest() == row['sha256'],
                'body changed: ' + name)
    metadata = {row['name']: row for row in anchors['metadata']}
    for row in metadata.values():
        raw = bytes.fromhex(row['bytes'])
        require(read(row['address'], len(raw)) == raw, 'metadata changed')
        if 'relative_i32_targets' in row:
            targets = [row['address'] + n for n in struct.unpack('<5i', raw)]
            require(targets == row['relative_i32_targets'], 'dispatch target changed')
    for row in anchors['relocations']:
        raw = bytes.fromhex(row['bytes'])
        require(data[row['file_offset']:row['file_offset'] + 24] == raw,
                'relocation changed')
        require(struct.unpack('<QQq', raw) ==
                (row['r_offset'], row['r_info'], row['r_addend']),
                'relocation tuple changed')

    require(struct.unpack('<I', read(0x394b50d, 4))[0] == 0x01000400,
            'serializer configuration changed')
    require(read(0x394b50d + 3, 1) == b'\x01', 'named-map flag changed')
    require(read(0x14fa048, 2) == b'\x0c\x08', 'root flag changed')
    require(struct.unpack('<8I', read(0x20c020, 32)) ==
            (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19),
            'BLAKE3 IV changed')
    keys = ('accounts_hash', 'contracts_hash', 'storage_hash',
            'n_elements', 'n_bytes', 'hash')
    for key in keys:
        require(bytes.fromhex(metadata['key_' + key]['bytes']) == key.encode(),
                'key metadata changed')
    location = metadata['update_source_location']
    source = metadata['blake3_versioned_source']
    _, path_length, line, column = struct.unpack('<QQII', read(location['address'], 24))
    require((path_length, line, column) ==
            (location['path_length'], location['line'], location['column']),
            'source coordinate changed')
    source_targets = [row['r_addend'] for row in anchors['relocations']
                      if row['r_offset'] == location['address'] and row['r_info'] == 8]
    require(source_targets == [source['address']], 'source location changed')
    require(location['path_address'] == source['address'] and
            location['path_length'] == len(bytes.fromhex(source['bytes'])),
            'source location changed')
    require(source['text'].endswith('/blake3-1.7.0/src/lib.rs') and
            bytes.fromhex(source['bytes']) == source['text'].encode(),
            'source version metadata changed')
    require((location['line'], location['column']) == (1201, 24),
            'source coordinate changed')
    minimum = 1 + sum(1 + len(key) for key in keys[:3]) + 3 * (
        1 + sum(1 + len(key) for key in keys[3:]) + 2 + 3 + 2048)
    return {
        'origin': 'unqualified fixed-coordinate inspection',
        'full_FDEs': len(anchors['ranges']),
        'full_FDE_bytes': sum(row['size'] for row in anchors['ranges'].values()),
        'selected_instructions': len(anchors['facts']),
        'metadata_ranges': len(anchors['metadata']),
        'relocation_tuples': len(anchors['relocations']),
        'named_map_flag': 1,
        'outer_keys': list(keys[:3]),
        'record_keys': list(keys[3:]),
        'raw_hash_bytes': 2048,
        'binary_header_hex': 'c50800',
        'minimum_encoded_bytes': minimum,
        'maximum_encoded_bytes': minimum + 6 * 8,
        'hash_order': ['caller_supplied_serialized_state', 'encoded_records'],
        'digest_bytes': 32,
    }


def verify_exports(exports=None):
    exports = EXPORTS if exports is None else exports
    require(exports['target_sha256'] == DIGEST, 'export target changed')
    seen = set()
    for row in exports['exports']:
        require(row['provider'] in ('gnu', 'llvm'), 'export provider changed')
        expected = ANCHORS['ranges'][row['name']]
        require((row['start'], row['end']) == (expected['start'], expected['end']),
                'export boundary changed')
        path = Path(row['path'])
        require(path.parts == ('native', row['name'] + '.' + row['provider'] + '.txt'),
                'export path changed')
        data = (PACKET / path).read_bytes()
        require(len(data) == row['size'] and hashlib.sha256(data).hexdigest() == row['sha256'],
                'export body changed')
        command = row['command']
        require(f"--start-address={row['start']:#x}" in command and
                f"--stop-address={row['end']:#x}" in command, 'export command changed')
        seen.add((row['name'], row['provider']))
    require(seen == {(name, provider) for name in ANCHORS['ranges']
                     for provider in ('gnu', 'llvm')}, 'missing native export')
    return len(seen)


def analyze(data):
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == DIGEST,
            'node94 identity changed')
    require(ANCHORS['target_sha256'] == DIGEST and ANCHORS['target_size'] == len(data),
            'anchor target changed')
    result = inspect(data)
    result.update({
        'origin': 'authenticated node94',
        'target_sha256': DIGEST,
        'native_exports': verify_exports(),
        'scope': 'Bounded record encoding and hash of caller-supplied canonical prefix; '
                 'no complete state serializer, native ABI equivalence, or checkpoint acceptance.',
    })
    return result


if __name__ == '__main__':
    result = analyze(TARGET.read_bytes())
    destination = PACKET / 'records.json'
    if '--write' in sys.argv:
        destination.write_text(json.dumps(result, indent=2) + '\n')
    else:
        require(result == json.loads(destination.read_text()), 'record changed')
        print(json.dumps(result, sort_keys=True))
