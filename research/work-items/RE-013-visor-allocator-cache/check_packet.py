#!/usr/bin/env python3
"""Reproduce only the target-bound local cache-return packet."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from visor_allocator_cache import TARGET, collect, require


def verify(packet):
    record, exports = collect(TARGET.read_bytes())
    require(json.loads((packet / 'record.json').read_text()) == record, 'Allocator record differs from admitted target')
    for name, value in exports.items():
        require((packet / name).read_bytes() == value.encode('utf-8'), 'Allocator native export differs')
    return {'status': 'LOCAL_RETURN_PACKET_REPRODUCED', 'native_bytes': 194, 'native_rows': 37,
            'local_return_paths': 2, 'open_slow_transfers': 3,
            'allocator_correctness_or_target_execution_claimed': False}


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parent), sort_keys=True))
