#!/usr/bin/env python3
"""Bind one node94 reader's deadline stages and ready-first timer projection."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from tcp_frame_read_static import Image
import tcp_frame_read_static
import tcp_frame_write_static

PACKET = Path(__file__).resolve().parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
RANGES = {'reader': (0x2049950, 0x204ae15), 'header_timeout': (0x2037940, 0x2037ab4),
          'payload_timeout': (0x2034eb0, 0x203516e), 'sleep_poll': (0x4f68f00, 0x4f6903e),
          'write_timeout': (0x2036460, 0x20367c3)}
FACTS = [
    ('header_flag', 0x20499b1, '807b0800', None),
    ('header_flag_skip', 0x20499b5, '0f846d050000', 0x2049f28),
    ('header_seconds', 0x20499e0, '48b90000000000004440', None),
    ('header_timed_poll', 0x2049e7c, 'e8bfdafeff', 0x2037940),
    ('header_direct_poll', 0x2049f47, 'e894e6ffff', 0x20485e0),
    ('header_nonpending_branch', 0x2049e88, '752b', 0x2049eb5),
    ('header_expiry', 0x2049ec7, '83fd02', None),
    ('header_common_join', 0x2049f8c, 'e91d010000', 0x204a0ae),
    ('payload_seconds', 0x204aa70, '48b90000000000003440', None),
    ('payload_fresh_state', 0x204aa8c, 'c6833802000000', None),
    ('payload_init_jump', 0x204aaa0, 'e991f9ffff', 0x204a436),
    ('payload_timed_poll', 0x204a7d7, 'e8d4a6feff', 0x2034eb0),
    ('payload_pending_cmp', 0x204a7df, '4883f803', None),
    ('payload_expiry_cmp', 0x204a7f4, '4983fe02', None),
    ('payload_next_chunk', 0x204a9e2, '488b4358', None),
    ('header_inner_offset', 0x2037957, '4883c678', None),
    ('header_inner_poll', 0x20379b8, 'e8230c0100', 0x20485e0),
    ('header_inner_pending_cmp', 0x20379bd, '837c240802', None),
    ('header_ready_return', 0x20379c2, '755a', 0x2037a1e),
    ('header_timer_poll', 0x2037a0c, 'ff1576767303', 0x576f088),
    ('header_timer_test', 0x2037a12, '84c0', None),
    ('header_timer_ready', 0x2037a14, '7412', 0x2037a28),
    ('header_pending_result', 0x2037a16, 'c70303000000', None),
    ('header_elapsed_result', 0x2037a28, 'c70302000000', None),
    ('payload_completed_cmp', 0x2034ff9, '4883f802', None),
    ('payload_completed_skip', 0x2034fff, 'e984000000', 0x2035088),
    ('payload_pending_value', 0x203501c, 'b802000000', None),
    ('payload_timer_poll', 0x203507b, 'ff1507a07303', 0x576f088),
    ('payload_timer_result', 0x2035084, '4883c802', None),
    ('sleep_inner_poll', 0x4f68f88, 'e893060100', 0x4f79620),
    ('sleep_inner_pending', 0x4f68f8d, '3c04', None),
    ('sleep_inner_ready_branch', 0x4f68f8f, '7538', 0x4f68fc9),
    ('sleep_ready_test', 0x4f68fc9, '84c0', None),
    ('sleep_error_branch', 0x4f68fcb, '7522', 0x4f68fef),
    ('sleep_ready_result', 0x4f68fcd, '31c0', None),
    ('sleep_pending_result', 0x4f68fe0, 'b001', None),
    ('sleep_error_location', 0x4f69010, '488d15e1c07e00', 0x57550f8),
    ('writer_pending_test', 0x2036628, 'a801', None),
    ('writer_ready_branch', 0x2036631, '7457', 0x203668a),
    ('writer_timer_poll', 0x203667c, 'ff15068a7303', 0x576f088),
    ('writer_timer_result', 0x2036685, '48ffc0', None),
]


def require(ok, why):
    if not ok:
        raise ValueError(why)


def inspect(data):
    """Structural counterfactual seam; never grants authenticated origin."""
    image = Image(data)
    ranges = {}
    for name, (start, end) in RANGES.items():
        require(image.fde(start) == (start, end), 'FDE extent changed: ' + name)
        ranges[name] = {'start': hex(start), 'end': hex(end), 'bytes': end - start,
                        'sha256': hashlib.sha256(image.read(start, end - start)).hexdigest()}
    facts = []
    for name, address, encoded, destination in FACTS:
        raw = bytes.fromhex(encoded)
        require(image.read(address, len(raw)) == raw, 'instruction changed: ' + name)
        fact = {'name': name, 'address': hex(address), 'bytes': encoded}
        if destination is not None:
            target = address + len(raw) + (struct.unpack('<b', raw[-1:])[0] if len(raw) == 2
                                          else struct.unpack('<i', raw[-4:])[0])
            require(target == destination, 'reference changed: ' + name)
            fact['target'] = hex(target)
        facts.append(fact)
    rela = next(s for s in image.secs if s['name'] == '.rela.dyn')
    entries = [struct.unpack_from('<QQq', data, i)
               for i in range(rela['offset'], rela['offset'] + rela['size'], 24)]
    for slot, target in [(0x576f088, 0x4f68f00), (0x57550f8, 0x1f359c)]:
        require([r for r in entries if r[0] == slot] == [(slot, 8, target)],
                f'relocation changed: {slot:#x}')
    path = b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.44.2/src/time/sleep.rs'
    require(image.read(0x1f359c, len(path)) == path, 'Sleep source path changed')
    require(struct.unpack('<QII', image.read(0x5755100, 16)) == (len(path), 450, 23),
            'Sleep Location metadata changed')
    return {'origin': 'unqualified structural inspection', 'ranges': ranges, 'facts': facts,
            'sleep_location': {'location': '0x57550f8', 'path': path.decode(), 'line': 450, 'column': 23},
            'semantics': {'header_flag_zero': 'direct untimed header read',
                          'header_flag_nonzero': '40-second header wrapper',
                          'payload': 'fresh 20-second wrapper per payload chunk',
                          'timer_adapter': {'0': 'ready', '1': 'pending, including cooperative yield'},
                          'header_and_payload_results': {'2': 'elapsed', '3': 'pending'},
                          'write_results': {'1': 'elapsed', '2': 'pending'},
                          'ordering': 'completed I/O is returned before consulting the timer'},
            'limits': ['One reader copy qualified; caller flag defaults and all call sites remain open.',
                       'Field names and result roles are source-correspondence inferences from the selected bytes.',
                       'Timer registration/driver internals, real elapsed time, cleanup ownership, error text and ABI are not proved.']}


def analyze(data):
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == DIGEST, 'node94 identity changed')
    result = inspect(data)
    reader = tcp_frame_read_static.analyse(data)['copies'][0]
    writers = tcp_frame_write_static.analyse(data)
    require(reader['timeouts']['header']['seconds'] == 40.0 and
            reader['timeouts']['chunk']['seconds'] == 20.0, 'reader duration contract changed')
    result['reused_contracts'] = {
        'reader_timeouts': reader['timeouts'],
        'reader_chunks': reader['chunk'],
        'writer_timeouts': [row['timeout'] for row in writers['writers']],
        'writer_callers': writers['callers'],
    }
    result['origin'] = 'authenticated node94'
    result['target_sha256'] = DIGEST
    return result


if __name__ == '__main__':
    result = analyze(TARGET.read_bytes())
    path = PACKET / 'records.json'
    if '--write' in sys.argv:
        path.write_text(json.dumps(result, indent=2) + '\n')
    else:
        require(result == json.loads(path.read_text()), 'stored deadline record changed')
        print('Verified frame deadline projection: 5 FDEs and 41 instruction facts.')
