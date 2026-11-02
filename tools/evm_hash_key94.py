#!/usr/bin/env python3
"""Extract the selected 32-byte snapshot row operand encoding from node #94."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_index import unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = (
    (0x2805530, 0x280565b, '61486df68edd396c94cb71497e72a0d515db8399d9fc30a022ddb3c5ae164451'),
    (0x28068f0, 0x2806af2, '1041b74919bd0eaf3b850c43e9085fcb2994f3f6baa9d4a1ded1c8838beea51b'),
    (0x17fe9c0, 0x17ff200, '9c798aa84deeb0e4ec95ca2223564a3072048b679ac3888331c90e587bc9df6c'),
    (0x269fcb0, 0x269febf, '6f454941db80b7bd5442964b823261fb27d662f2842680ec809c1ebea077c178'),
    (0x17e8e70, 0x17e993b, '18f8b5db55852962695af0ff2000850820adabc9a6036c37db2d21e6573db97c'),
    (0x18af3f0, 0x18afc80, '35d9db1743b059ae4772cd0219f56f6899ca4c3645b665d6eb258615d90246f3'),
    (0x28fa6f0, 0x28fabf6, '26e1086f71caea3af27989ef152b35adafc410892b32966158e6017fa279d62b'),
    (0x28f8430, 0x28f89ac, 'ba6f2a9d64fe2462c654dd2d88f3fff70ec05553c30ba43e1decd08df14746d6'),
    (0x28f7810, 0x28f78d6, 'dda840fc5d8bf160553ab72023c2ba0c9023320ce02e3a6f4cc57248c545c4bd'),
    (0x25aa380, 0x25aa48c, '8b1e1f01460c30539bab758ae3c9cc72079b2260810beb88f92e0370fd7fec75'),
    (0x25aa000, 0x25aa37e, '86a31e4d496c42620e6e98dc09fe16efe99a4356af6ca9d9e0b8baf53209d7ca'),
    (0x25a9ea0, 0x25a9ffd, '777a9c4ca86b089e592059b87051f31477108cf4af830b9995bded6e3085e7c2'),
    (0x28fb0c0, 0x28fb495, 'a76c8da47cdae7d07680795c51e2d1803fd768324eebed353c8a83ccaed8a728'),
    (0x21b7410, 0x21b7473, 'a09ea0f7b02f84c80147d00422f0452609f300ad5242d11d5bbf062ec5aad2e0'),
)
WINDOWS = (
    ('row_array_and_first_context', 0x1de36a5, 0x1de36f5),
    ('row_second_context_a', 0x1de3979, 0x1de399a),
    ('row_second_context_b', 0x1de3a93, 0x1de3ab4),
    ('second_writer_a_compact', 0x28055e7, 0x28055fa),
    ('second_writer_b_compact', 0x28069bc, 0x2806a24),
    ('second_writer_a_text', 0x2805555, 0x28055e7),
    ('second_writer_b_text', 0x2806919, 0x28069bc),
    ('second_reader_length', 0x17feab7, 0x17feb01),
    ('second_reader_length_error', 0x17fec99, 0x17fecc2),
    ('reader_row_second', 0x17e941e, 0x17e9446),
    ('reader_outer_context', 0x1a01547, 0x1a01568),
    ('reader_collection_loop', 0x269fcda, 0x269fd25),
    ('reader_collection_duplicate', 0x269fd9c, 0x269fe27),
    ('reader_row_first', 0x17e937c, 0x17e943c),
    ('reader_marker_fetch', 0x18af5de, 0x18af611),
    ('reader_marker_class', 0x18af856, 0x18af869),
    ('reader_marker_class_c0', 0x18af9eb, 0x18af9fa),
    ('reader_marker_table', 0x18afa8f, 0x18afaae),
    ('reader_marker_dispatch', 0x18af3ff, 0x18af421),
    ('reader_length_byte', 0x18af4b3, 0x18af4d0),
    ('reader_range_and_reverse', 0x18af4ef, 0x18af54f),
    ('reader_short_input', 0x18af736, 0x18af77e),
    ('reader_wrong_length', 0x18afbc5, 0x18afbf3),
    ('row_preflight', 0x1de347a, 0x1de348f),
    ('row_operand_arguments', 0x1de3411, 0x1de341d),
    ('row_first_operand_call_a', 0x1de3676, 0x1de368f),
    ('row_first_operand_call_b', 0x1de36e8, 0x1de3704),
    ('writer_a_mode_and_binary', 0x28fa6fe, 0x28fa765),
    ('writer_b_mode_and_binary', 0x28f843e, 0x28f84e1),
    ('reverse_32', 0x28f782e, 0x28f78be),
    ('allocation_failure', 0x28f781a, 0x28f782e),
    ('allocation_failure_tail', 0x28f78c6, 0x28f78d6),
    ('writer_b_zero', 0x28f8903, 0x28f893f),
    ('writer_a_zero', 0x28fab4d, 0x28fab89),
    ('writer_a_significant_scan_high', 0x28fa78b, 0x28fa7c1),
    ('writer_a_significant_scan_low', 0x28fa935, 0x28fab5f),
    ('writer_a_text_loop', 0x28fa840, 0x28fa8d9),
    ('writer_b_text_loop', 0x28f85cb, 0x28f8669),
    ('byte_formatter', 0x21b7411, 0x21b7473),
    ('binary_header', 0x25aa00e, 0x25aa02d),
    ('binary_copy_and_error', 0x25aa39e, 0x25aa45f),
    ('alternate_header', 0x25a9eb1, 0x25a9f66),
    ('preflight_zero_scan', 0x28fb0ce, 0x28fb110),
)
CALLS = (0x1de3986, 0x1de3aa0, 0x28055ef, 0x28069c1, 0x17e9437,0x1a0155a, 0x269fd15, 0x269fdb4, 0x17e93b7, 0x17e93ce,0x1de3482, 0x1de3681, 0x1de36f0, 0x28fa72a, 0x28fa73f,
         0x28f846e, 0x28f8488, 0x25aa39e, 0x28fa8d4,
         0x28f8664, 0x28fab78, 0x28f892e)
BRANCHES = (0x280554f, 0x28055f8, 0x2806913, 0x28069d2, 0x28069ea, 0x2806a02, 0x17feac5, 0x17fead9, 0x17feae3, 0x17e9444,0x269fd03, 0x269fd1f, 0x269fdc0, 0x17e9398, 0x17e93a5, 0x17e93fd, 0x17e9421, 0x18af5e5, 0x18af603, 0x18af85b, 0x18af863, 0x18af913, 0x18af9ed, 0x18af4be, 0x18af4fc, 0x18af510, 0x18af519,0x28fa708, 0x28fa717, 0x28fa752, 0x28fa81c,
            0x28fa863, 0x28fa899, 0x28fa8ec, 0x28fab59,
            0x28fab81, 0x28f7828, 0x28fa7c4, 0x28f854f, 0x28f890f, 0x28f8937, 0x28f8448, 0x28f8457, 0x28f8496,
            0x28f84a6, 0x28f85a7, 0x28f85f3, 0x28f8629,
            0x28f867c, 0x25aa3ac, 0x25aa3c1, 0x25aa3d5,
            0x25aa419, 0x25aa442, 0x21b744a)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def va_bytes(data, secs, address, length):
    if address < 0 or length <= 0:
        raise ValueError('invalid virtual range')
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= address
               and address + length <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('unmapped or ambiguous file-backed range')
    sec = matches[0]
    off = sec['offset'] + address - sec['address']
    return data[off:off + length]


def direct_call(data, secs, site):
    raw = va_bytes(data, secs, site, 5)
    if raw[0] != 0xe8:
        raise ValueError('expected direct call')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def branch(data, secs, site):
    raw = va_bytes(data, secs, site, 2)
    if 0x70 <= raw[0] <= 0x7f:
        return site + 2 + struct.unpack('b', raw[1:])[0]
    if raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        return site + 6 + struct.unpack('<i', va_bytes(data, secs, site + 2, 4))[0]
    raise ValueError('expected conditional branch')


# This is the complete inspected SIMD window. No general instruction decoder is used.
SIMD = bytes.fromhex(
    'f3410f6f06f3410f6f4e10f30f7f00f30f7f4810660fefd2660f6fd9'
    '660f60da660f70db4ef20f70db1bf30f70db1b660f68ca660f70c94e'
    'f20f70c91bf30f70c91b660f67cbf30f7f08660f6fc8660f60ca'
    '660f70c94ef20f70c91bf30f70c91b660f68c2660f70c04ef20f70c01b'
    'f30f70c01b660f67c1f30f7f401048c703200000004889430848c7431020000000')


def shuffle_8_words(v):
    # pshufd 0x4e, pshuflw 0x1b, pshufhw 0x1b on eight words.
    dwords = [v[i:i + 2] for i in range(0, 8, 2)]
    v = sum((dwords[i] for i in (2, 3, 0, 1)), [])
    return v[3::-1] + v[7:3:-1]


def simd_permutation(code):
    if code != SIMD:
        raise ValueError('unexpected SIMD instruction window')
    result = []
    for half in (list(range(16, 32)), list(range(16))):
        low = shuffle_8_words(half[:8])
        high = shuffle_8_words(half[8:])
        # PACKUSWB combines the high-half lanes, then low-half lanes.
        result.extend(high + low)
    return result


def model(raw, prefix=bytes.fromhex('c420')):
    """Static candidate model; not target execution or an on-disk fixture."""
    if len(raw) != 32:
        raise ValueError('operand must be 32 bytes')
    return {'compact_hex': (prefix + raw[::-1]).hex()}


def reader_payload(data, length):
    # Conditional model of the selected reader's admitted binary payload arm.
    if len(data) < length:
        raise ValueError('truncated payload')
    if length != 32:
        raise ValueError('wrong payload length')
    return data[:length][::-1]


def read_compact(frame):
    # Model assumes entry with reader state 1 and binary-mode argument 1.
    if len(frame) < 2:
        raise ValueError('truncated header')
    if frame[0] != 0xc4:
        raise ValueError('unmodelled marker')
    return reader_payload(frame[2:], frame[1])


def model_row(key, value):
    if len(key) != 32 or len(value) != 32:
        raise ValueError('row operands must be 32 bytes')
    return b'\x92' + bytes.fromhex(model(key)['compact_hex']) + b'\xc4\x20' + value


def analyze(data, expected_digest=DIGEST):
    digest = sha(data)
    if digest != expected_digest:
        raise ValueError('node digest mismatch')
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {f['start']: f for f in fdes}
    indexed = {(i['start'], i['fde']) for i in index}
    funcs = []
    for start, end, expected in FUNCTIONS:
        f = by_start.get(start)
        if f is None or f['end'] != end or (start, f['fde']) not in indexed:
            raise ValueError('FDE mismatch')
        body = va_bytes(data, secs, start, end - start)
        if sha(body) != expected:
            raise ValueError('body mismatch')
        sec = next(s for s in secs if s['type'] != 8 and s['address'] <= start and end <= s['address'] + s['size'])
        funcs.append({'start':hex(start), 'end_exclusive':hex(end), 'fde':hex(f['fde']),
                      'file_offset':hex(sec['offset'] + start - sec['address']),
                      'size':len(body), 'sha256':sha(body)})
    windows = []
    for label, start, end in WINDOWS:
        raw = va_bytes(data, secs, start, end - start)
        windows.append({'label':label, 'start':hex(start), 'end_exclusive':hex(end), 'bytes':raw.hex()})
    calls = [{'site':hex(site), 'target':hex(direct_call(data, secs, site))} for site in CALLS]
    branches = [{'site':hex(site), 'target':hex(branch(data, secs, site))} for site in BRANCHES]
    table_base = 0x322f18
    table = []
    for index_value in (0xc4, 0xc5, 0xc6):
        displacement = struct.unpack('<i', va_bytes(data, secs, table_base + 4 * index_value, 4))[0]
        table.append({'index':index_value, 'entry':hex(table_base + 4 * index_value),
                      'target':hex(table_base + displacement)})
    if [x['target'] for x in table] != ['0x18af4b3', '0x18af484', '0x18af4d0']:
        raise ValueError('unexpected reader table')
    raw_table_base = 0x3232e4
    raw_table = []
    for marker_value in (0xc4, 0xc5, 0xc6):
        slot = raw_table_base + 4 * (marker_value - 0xc0)
        displacement = struct.unpack('<i', va_bytes(data, secs, slot, 4))[0]
        raw_table.append({'marker':marker_value, 'entry':hex(slot),
                          'target':hex(raw_table_base + displacement)})
    if [x['target'] for x in raw_table] != ['0x18af4bb', '0x18af48c', '0x18af4d8']:
        raise ValueError('unexpected raw marker table')
    literals = {hex(a):va_bytes(data, secs, a, n).decode('ascii') for a,n in
                ((0x3f6ac3,3), (0x208620,16))}
    scan = []
    for start, end in ((0x28fa70e, 0x28fa7ae), (0x28fa935, 0x28fab5f)):
        window = va_bytes(data, secs, start, end - start)
        for i in range(len(window) - 3):
            if window[i:i+2] in (b'\x80\x7e', b'\x80\x7a') and window[i+3] == 0:
                scan.append({'site':hex(start+i), 'offset':window[i+2]})
            if window[i:i+4] == b'\x41\x80\x3f\x00':
                scan.append({'site':hex(start+i), 'offset':0})
    if [x['offset'] for x in scan] != list(range(31, -1, -1)):
        raise ValueError('unexpected significant-byte scan')
    row_marker = va_bytes(data, secs, 0x1de36b6, 4)
    if row_marker != bytes.fromhex('c6040192'):
        raise ValueError('unexpected row marker store')
    allocation = va_bytes(data, secs, 0x28f781a, 5)
    marker = va_bytes(data, secs, 0x25aa025, 5)
    identity = va_bytes(data, secs, 0x25acc20, 17)
    if allocation[:1] != b'\xbf' or marker[:1] != b'\xbd' or identity != bytes.fromhex('89f80fb6c88d9140ffffff83fa207301c3'):
        raise ValueError('unexpected length or marker encoding')
    length = struct.unpack_from('<I', allocation, 1)[0]
    marker_value = struct.unpack_from('<I', marker, 1)[0]
    if length != 32 or marker_value != 0xc4:
        raise ValueError('unexpected compact representation')
    prefix = bytes((marker_value, length))
    samples = []
    for label, raw in [('zero',bytes(32)), ('one', b'\x01'+bytes(31)),
                       ('ten', b'\x0a'+bytes(31)), ('boundary', b'\x10'+bytes(31)),
                       ('sequence',bytes(range(32))), ('maximum', bytes([255])*32)]:
        samples.append({'name':label, 'memory_hex':raw.hex(), **model(raw, prefix)})
    return {'target_sha256':digest, 'coordinate_system':'unrelocated ELF virtual address',
            'functions':funcs, 'windows':windows, 'direct_calls':calls,
            'conditional_branches':branches, 'reader_jump_table':table, 'reader_raw_marker_table':raw_table, 'static_row_model':model_row(bytes(range(32)), bytes(range(32,64))).hex(), 'significant_byte_scan':scan, 'literals':literals, 'compact_prefix':prefix.hex(), 'static_models':samples,
            'simd_input_indices_in_output_order':simd_permutation(va_bytes(data, secs, 0x28f782e, 0x90))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    records = analyze((ROOT / 'artifacts/node/94/hl-node').read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evidence.json').write_text(json.dumps(records, indent=2, sort_keys=True) + '\n', encoding='utf-8')

if __name__ == '__main__':
    main()
