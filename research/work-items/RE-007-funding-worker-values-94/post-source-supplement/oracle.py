#!/usr/bin/env python3
"""Two independently specified post-source guard-order frames; no target/source calls."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct


def frame(identifier, payload):
    return struct.pack('<QI', identifier, len(payload)) + payload


def generate():
    position = struct.pack('<QIqqqqq', 0, 0, 7, 0, 0, 0, 0)
    fixed = bytes(20) + b'\x01' + bytes(12) + struct.pack('<q', 0)
    membership = struct.pack('<I', 0)
    rates = struct.pack('<IQQ', 1, 0, 0x3ff0000000000000)
    positions = struct.pack('<I', 1) + position
    input_a = fixed + membership + struct.pack('<I', 0) + rates + positions
    input_b = fixed + membership + struct.pack('<Iq', 1, 0) + rates + positions
    # Status2, asset0, raw MetadataIndex reason0. No native failure-state output.
    output_a = b'\x02' + struct.pack('<QB', 0, 0)
    # Status1, original balance/one position, no rows, sum0/no max/no requests.
    output_b = b'\x01' + struct.pack('<qI', 0, 1) + position + struct.pack('<IqBI', 0, 0, 0, 0)
    return (frame(1 << 63, input_a) + frame((1 << 63) + 1, input_b),
            frame(1 << 63, output_a) + frame((1 << 63) + 1, output_b))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise ValueError('fresh output required')
    args.out.mkdir(parents=True)
    inputs, expected = generate()
    files = {}
    for name, raw in [('inputs.bin.gz', inputs), ('expected.bin.gz', expected)]:
        stored = gzip.compress(raw, mtime=0)
        (args.out / name).write_bytes(stored)
        files[name] = {'raw_bytes': len(raw), 'raw_sha256': hashlib.sha256(raw).hexdigest(),
                       'stored_bytes': len(stored), 'stored_sha256': hashlib.sha256(stored).hexdigest()}
    record = {'phase': 'post-source independent guard-order supplement', 'count': 2,
              'files': files, 'original_pre_source_cases': 10945,
              'expected_a': {'status': 2, 'asset': 0, 'reason': 0},
              'expected_b': {'status': 1, 'state': 'unchanged', 'rows': 0,
                             'requests': 0, 'sum': 0, 'maximum': None},
              'oracle_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (args.out / 'corpus.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'cases': 2, 'input_bytes': len(inputs), 'expected_bytes': len(expected)}))


if __name__ == '__main__':
    main()
