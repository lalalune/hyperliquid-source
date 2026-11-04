#!/usr/bin/env python3
"""RE-005: digest-bound node115 bincode field1-5 varint reader trace.

Traces one logical function of the pinned node #115 binary: the
bincode-fork scalar varint reader family whose error results carry
field1 5, present as two codegen copies (0x2cd7bb0 and 0x5821340)
that share one slow-path reader (0x5822710, reached only through
GOT slot 0x64e7f80) and the shared raw error constructor
(0x5822700, a boundary owned by the open u64-reader packet). The
reader charges 8 against the mode-1 charged count, takes its fast
route only above eight remaining bytes, accepts the u16, u32 and
u64 payload markers, rejects markers 254/255 with error field1 5,
and reports slow-path shortfalls as rawtag 0 with an
additional-byte count. Its payload ladder matches the u64 reader
family of open PR #2300; the error field1 bytes (5 on both routes,
against 2 fast / 3 slow there) and the slow-reader wiring are what
separate the families in these bytes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-005-node115-field1-5-varint-reader'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
OWNERS = {
 'copy_a': (0x2cd7bb0, 0x2cd7c95,
            '5ba5fb7e28f73bda778262d05c9175b33653a3abfc1747830a47e72ddcc7466c'),
 'copy_b': (0x5821340, 0x5821425,
            '0443b1e0c4c7e8ff87e092eda79d2e7a81a875ea63ca5a9373fa6c309fd76df1'),
 'slow_path': (0x5822710, 0x582284c,
               'f91783e2001097578700a2942e6f7cf4e039d90696ff82697b78398651610c3f')}
COPY_TABLES = {'copy_a': 0x60be9c, 'copy_b': 0x935bec}
COPY_CTOR_SLOTS = {'copy_a': 0x64e7f88, 'copy_b': 0x64e7f78}
SLOW = 0x5822710
SLOW_TABLE = 0x935c34
SLOW_SLOT = 0x64e7f80
CTOR = 0x5822700
CTOR_SLOT = 0x64e7f78
CTOR_SLOT_A = 0x64e7f88
CTOR_BODY = bytes.fromhex('4889f8c6070340887701885702c3')
U32_SLOW_SLOT = 0x64e7f70
U32_SLOW = 0x5822490
U64_SLOW_SLOT = 0x64e6c38
U64_SLOW = 0x58225c0
ERROR_FIELD2 = {254: 4, 255: 12}
LIMITS = (
 'Static trace only: no pinned bytes were executed and no live node, '
 'network, signer, or exchange state was used. The bytes test only '
 'mode == 1; the canonical mode values 0 and 1 are the domain record '
 'of the open u64-reader packet (#2300), not re-derived here. Rawtag '
 'and error-field values are reported as raw result bytes; which '
 'Rust enum variants they name is not established from these bytes. '
 'The slow-path endianness argument is 0 (little-endian) at both '
 'in-family call sites; behaviour for the big-endian setting is '
 'traced from the slow reader bytes but no in-family caller uses it. '
 'No Rust reconstruction is included or claimed.')


def read(data, va, n):
    matches = [s for s in sections(data) if s['type'] != 8
               and s['address'] <= va and va + n <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('expected one file-backed mapping')
    s = matches[0]
    o = s['offset'] + va - s['address']
    return o, bytes(data[o:o + n])


def require(condition, message):
    if not condition:
        raise ValueError(message)


def relocations(data):
    sec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    by_offset = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, off)
        by_offset.setdefault(r_offset, []).append((r_info & 0xffffffff, r_addend))
    return by_offset


def pin(body, rel, expected, message):
    require(body[rel:rel + len(expected)] == expected,
            f'{message} changed')


def copy_semantics(data, role, base, table_va):
    """Validate the shared relative layout of one fast-path copy."""
    _, body = read(data, base, OWNERS[role][1] - base)
    pins = [
     (0x00, '53', 'copy entry'),
     (0x01, '833e01', 'mode == 1 test'),
     (0x04, '7523', 'mode branch to main'),
     (0x06, '488b4620', 'charged count load at state +0x20'),
     (0x0a, '4883f8f7', 'charge overflow bound (charged > u64::MAX - 8)'),
     (0x0e, '7711', 'overflow branch to refusal'),
     (0x10, '488b4e08', 'limit load at state +0x8'),
     (0x14, '4883c008', 'mode-1 charge increment 8'),
     (0x18, '48894620', 'charged count stored before the limit compare'),
     (0x1c, '4839c8', 'charged count against limit'),
     (0x1f, '7608', 'accepted branch to main'),
     (0x21, 'c60702', 'charge refusal rawtag 2'),
     (0x29, '488b4618', 'remaining load at state +0x18'),
     (0x2d, '4883f808', 'fast route requires remaining > 8'),
     (0x31, '766e', 'short input branch to the slow call'),
     (0x33, '488b4e10', 'cursor load at state +0x10'),
     (0x37, '0fb611', 'marker load'),
     (0x3a, '4881fafb000000', 'marker boundary 251'),
     (0x41, '7308', 'payload marker branch to dispatch'),
     (0x43, '41b801000000', 'single-byte marker consumes 1'),
     (0x49, 'eb3c', 'single-byte marker branch to the store'),
     (0x4b, '81c205ffffff', 'dispatch index marker - 251'),
     (0x51, '83fa03', 'dispatch index range 0..3'),
     (0x54, '7777', 'out-of-range branch to the 255 arm'),
     (0x56, '4c8d05', 'dispatch table lea'),
     (0x66, '0fb75101', 'marker 251 u16 payload load'),
     (0x6a, '41b803000000', 'marker 251 consumes 3'),
     (0x70, 'eb15', 'marker 251 branch to the store'),
     (0x72, '488b5101', 'marker 253 u64 payload load'),
     (0x76, '41b809000000', 'marker 253 consumes 9'),
     (0x7c, 'eb09', 'marker 253 branch to the store'),
     (0x7e, '8b5101', 'marker 252 u32 payload load'),
     (0x81, '41b805000000', 'marker 252 consumes 5'),
     (0x87, '4c01c1', 'cursor advance'),
     (0x8a, '4c29c0', 'remaining decrease'),
     (0x8d, '48894e10', 'cursor store'),
     (0x91, '48894618', 'remaining store'),
     (0x95, '48895708', 'value qword store at result +0x8'),
     (0x99, 'c60712', 'success rawtag 0x12'),
     (0xa1, '4883c610', 'slow argument is state +0x10'),
     (0xa8, '31d2', 'slow endianness argument 0'),
     (0xb5, '4889fb', 'marker 254 arm saves the result pointer'),
     (0xb8, 'be05000000', 'marker 254 error field1 5'),
     (0xbd, 'ba04000000', 'marker 254 error field2 4'),
     (0xcd, '4889fb', 'marker 255 arm saves the result pointer'),
     (0xd0, 'be05000000', 'marker 255 error field1 5'),
     (0xd5, 'ba0c000000', 'marker 255 error field2 12')]
    for rel, hexs, message in pins:
        pin(body, rel, bytes.fromhex(hexs), f'{role} {message}')
    disp = struct.unpack_from('<i', body, 0x59)[0]
    require(base + 0x5d + disp == table_va,
            f'{role} dispatch table reference changed')
    slow_slot = base + 0xb0 + struct.unpack_from('<i', body, 0xac)[0]
    require(slow_slot == SLOW_SLOT, f'{role} slow-path slot changed')
    for rel in (0xc2, 0xda):
        slot = base + rel + 6 + struct.unpack_from('<i', body, rel + 2)[0]
        require(slot == COPY_CTOR_SLOTS[role],
                f'{role} error constructor slot changed')
    raw = read(data, table_va, 16)[1]
    entries = list(struct.unpack('<4i', raw))
    targets = [table_va + e for e in entries]
    require(targets == [base + 0x66, base + 0x7e, base + 0x72, base + 0xb5],
            f'{role} dispatch table targets changed')
    return {'dispatch_table': {'va': hex(table_va),
                               'entries': [hex(e) for e in entries],
                               'targets': {'251': hex(targets[0]),
                                           '252': hex(targets[1]),
                                           '253': hex(targets[2]),
                                           '254': hex(targets[3])}},
            'slow_slot': hex(SLOW_SLOT),
            'error_slot': hex(COPY_CTOR_SLOTS[role])}


def slow_semantics(data):
    _, body = read(data, SLOW, OWNERS['slow_path'][1] - SLOW)
    pins = [
     (0x000, '53', 'slow entry'),
     (0x001, '488b4608', 'remaining load at pair +0x8'),
     (0x005, '4885c0', 'remaining test'),
     (0x008, '742b', 'empty branch'),
     (0x00a, '488b0e', 'cursor load at pair +0x0'),
     (0x015, '440fb601', 'marker load'),
     (0x019, '4c890e', 'marker consumed: cursor store before classification'),
     (0x01c, '4c895608', 'marker consumed: remaining store'),
     (0x020, '4981f8fb000000', 'marker boundary 251'),
     (0x029, '4c894708', 'single-byte value store at result +0x8'),
     (0x02d, 'c60712', 'slow success rawtag 0x12'),
     (0x035, 'c60700', 'empty/shortfall rawtag 0'),
     (0x038, '48c7470801000000', 'empty additional count 1'),
     (0x045, '4181c005ffffff', 'dispatch index marker - 251'),
     (0x04c, '4183f803', 'dispatch index range 0..3'),
     (0x050, '0f87ce000000', 'out-of-range branch to the 255 arm'),
     (0x056, '4c8d0d', 'slow dispatch table lea'),
     (0x067, '4883f803', 'marker 251 total width 3'),
     (0x06d, 'b903000000', 'marker 251 shortfall width 3'),
     (0x074, '4883f809', 'marker 253 total width 9'),
     (0x07a, 'b909000000', 'marker 253 shortfall width 9'),
     (0x081, '4883f805', 'marker 252 total width 5'),
     (0x087, 'b905000000', 'marker 252 shortfall width 5'),
     (0x08c, '4829c1', 'additional is width - total remaining'),
     (0x092, '48894f08', 'additional store at result +0x8'),
     (0x09b, '4883c0f7', 'marker 253 remaining drops 9 in total'),
     (0x09f, '4c8b4101', 'marker 253 u64 payload load'),
     (0x0a3, '4883c109', 'marker 253 cursor advances 9 in total'),
     (0x0b1, '480fc8', 'marker 253 byte swap'),
     (0x0b4, '84d2', 'endianness flag test'),
     (0x0b6, '490f44c0', 'marker 253 endianness select'),
     (0x0bc, '440fb74101', 'marker 251 u16 payload load'),
     (0x0c1, '4883c103', 'marker 251 cursor advances 3 in total'),
     (0x0cb, '66c1c108', 'marker 251 byte swap'),
     (0x0cf, '4883c0fd', 'marker 251 remaining drops 3 in total'),
     (0x0d5, '410f44c8', 'marker 251 endianness select'),
     (0x0e2, '4883c0fb', 'marker 252 remaining drops 5 in total'),
     (0x0e6, '448b4101', 'marker 252 u32 payload load'),
     (0x0ea, '4883c105', 'marker 252 cursor advances 5 in total'),
     (0x0f8, '0fc8', 'marker 252 byte swap'),
     (0x0fc, '410f44c0', 'marker 252 endianness select'),
     (0x100, '48894708', 'slow success value store at result +0x8'),
     (0x104, 'c60712', 'slow success rawtag 0x12'),
     (0x10f, 'be05000000', 'marker 254 error field1 5'),
     (0x114, 'ba04000000', 'marker 254 error field2 4'),
     (0x127, 'be05000000', 'marker 255 error field1 5'),
     (0x12c, 'ba0c000000', 'marker 255 error field2 12')]
    for rel, hexs, message in pins:
        pin(body, rel, bytes.fromhex(hexs), f'slow {message}')
    disp = struct.unpack_from('<i', body, 0x59)[0]
    require(SLOW + 0x5d + disp == SLOW_TABLE,
            'slow dispatch table reference changed')
    for rel in (0x119, 0x131):
        slot = SLOW + rel + 6 + struct.unpack_from('<i', body, rel + 2)[0]
        require(slot == CTOR_SLOT, 'slow error constructor slot changed')
    raw = read(data, SLOW_TABLE, 16)[1]
    entries = list(struct.unpack('<4i', raw))
    targets = [SLOW_TABLE + e for e in entries]
    require(targets == [0x5822777, 0x5822791, 0x5822784, 0x582281c],
            'slow dispatch table targets changed')
    return {'dispatch_table': {'va': hex(SLOW_TABLE),
                               'targets': {'251': hex(targets[0]),
                                           '252': hex(targets[1]),
                                           '253': hex(targets[2]),
                                           '254': hex(targets[3])}},
            'error_slot': hex(CTOR_SLOT)}


def fast_marker_outcome(marker):
    if marker < 251:
        return {'outcome': 'value', 'payload': 'marker itself',
                'consumed': 1}
    if marker == 251:
        return {'outcome': 'value', 'payload': 'u16 little-endian',
                'consumed': 3}
    if marker == 252:
        return {'outcome': 'value', 'payload': 'u32 little-endian',
                'consumed': 5}
    if marker == 253:
        return {'outcome': 'value', 'payload': 'u64 little-endian',
                'consumed': 9}
    return {'outcome': 'error', 'field1': 5,
            'field2': ERROR_FIELD2[marker], 'consumed': 0}


def slow_outcome(marker, total):
    """total is the remaining byte count including the marker byte."""
    if total == 0:
        return {'outcome': 'need', 'additional': 1, 'consumed': 0}
    if marker < 251:
        return {'outcome': 'value', 'payload': 'marker itself',
                'consumed': 1}
    if marker == 251:
        if total >= 3:
            return {'outcome': 'value', 'payload': 'u16', 'consumed': 3}
        return {'outcome': 'need', 'additional': 3 - total, 'consumed': 1}
    if marker == 252:
        if total >= 5:
            return {'outcome': 'value', 'payload': 'u32', 'consumed': 5}
        return {'outcome': 'need', 'additional': 5 - total, 'consumed': 1}
    if marker == 253:
        if total >= 9:
            return {'outcome': 'value', 'payload': 'u64', 'consumed': 9}
        return {'outcome': 'need', 'additional': 9 - total, 'consumed': 1}
    return {'outcome': 'error', 'field1': 5,
            'field2': ERROR_FIELD2[marker], 'consumed': 1}


def census(data):
    """Direct E8 call sites and rip-relative references to the slow slot."""
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, off, size = sec['address'], sec['offset'], sec['size']
    body = data[off:off + size]
    _, fs, _ = fde_extents(data)
    fdes = sorted((f['start'], f['end']) for f in fs)
    import bisect
    starts = [s for s, _ in fdes]

    def containing(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and fdes[i][0] <= va < fdes[i][1]:
            return fdes[i]
        return None

    targets = {OWNERS[r][0]: r for r in ('copy_a', 'copy_b', 'slow_path')}
    calls = {r: [] for r in targets.values()}
    i = body.find(b'\xe8')
    while i != -1:
        va = base + i
        if va + 5 + struct.unpack_from('<i', body, i + 1)[0] in targets:
            role = targets[va + 5 + struct.unpack_from('<i', body, i + 1)[0]]
            c = containing(va)
            calls[role].append({'site': hex(va),
                                'containing_fde': (f'{c[0]:#x}..{c[1]:#x}'
                                                   if c else None)})
        i = body.find(b'\xe8', i + 1)
    slot_refs = []
    for opcode in (b'\xff\x15', b'\xff\x25'):
        j = body.find(opcode)
        while j != -1:
            slot = base + j + 6 + struct.unpack_from('<i', body, j + 2)[0]
            if slot == SLOW_SLOT:
                slot_refs.append(hex(base + j))
            j = body.find(opcode, j + 1)
    return calls, sorted(slot_refs)


FRAMES = {
 'copy_a': {
  'fde': {'va': '0xd8bc98',
          'bytes_hex': '30000000c44d0e0010bff401e500000000410e108302670e'
                       '08410e1002770e08410e10530e08410e10570e08410e1057'
                       '0e080000'},
  'cie': {'va': '0xca6ed8',
          'bytes_hex': '1400000000000000017a5200017810011b0c070890010000'}},
 'copy_b': {
  'fde': {'va': '0xf9c470',
          'bytes_hex': '300000009c552f00c84e8804e500000000410e108302670e'
                       '08410e1002770e08410e10530e08410e10570e08410e1057'
                       '0e080000'},
  'cie': {'va': '0xca6ed8',
          'bytes_hex': '1400000000000000017a5200017810011b0c070890010000'}},
 'slow_path': {
  'fde': {'va': '0xf9c73c',
          'bytes_hex': '3800000068582f00cc5f88043c01000000410e108302730e'
                       '08410e104f0e08410e1002550e08410e1002700e08410e'
                       '10570e08410e10570e08000000'},
  'cie': {'va': '0xca6ed8',
          'bytes_hex': '1400000000000000017a5200017810011b0c070890010000'}}}
REQUIRED_STARTS = {
 'copy_a': [0x2cd7bb0, 0x2cd7bd9, 0x2cd7c16, 0x2cd7c2e, 0x2cd7c22,
            0x2cd7c37, 0x2cd7c51, 0x2cd7c65, 0x2cd7c7d],
 'copy_b': [0x5821340, 0x5821369, 0x58213a6, 0x58213be, 0x58213b2,
            0x58213c7, 0x58213e1, 0x58213f5, 0x582140d],
 'slow_path': [0x5822710, 0x5822739, 0x5822745, 0x5822777, 0x5822784,
               0x5822791, 0x582279c, 0x58227ab, 0x58227cc, 0x58227f2,
               0x5822810, 0x582281c, 0x5822834]}


def analyze(data):
    by_offset = relocations(data)
    require(by_offset.get(SLOW_SLOT) == [(8, SLOW)],
            'sibling slow-path slot relocation changed')
    require(by_offset.get(CTOR_SLOT) == [(8, CTOR)],
            'error constructor slot relocation changed')
    require(by_offset.get(CTOR_SLOT_A) == [(8, CTOR)],
            'copy-a error constructor slot relocation changed')
    require(by_offset.get(U32_SLOW_SLOT) == [(8, U32_SLOW)],
            'u32 slow-path slot relocation changed')
    require(by_offset.get(U64_SLOW_SLOT) == [(8, U64_SLOW)],
            'u64 slow-path slot relocation changed')
    copies = {}
    for role in ('copy_a', 'copy_b'):
        copies[role] = copy_semantics(data, role, OWNERS[role][0],
                                      COPY_TABLES[role])
    require(copies['copy_a']['dispatch_table']['targets']
            != copies['copy_b']['dispatch_table']['targets'],
            'copies unexpectedly share one dispatch table')
    require(copies['copy_a']['error_slot'] != copies['copy_b']['error_slot'],
            'copies unexpectedly share one error constructor slot')
    slow = slow_semantics(data)
    require(read(data, CTOR, len(CTOR_BODY))[1] == CTOR_BODY,
            'error constructor body changed')
    calls, slot_refs = census(data)
    require(calls['slow_path'] == [], 'slow reader direct caller appeared')
    require(slot_refs == ['0x2cd7c5a', '0x58213ea'],
            'slow-path slot reference set changed')
    _, fs, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs}
    owners = []
    for role, (a, b, sha) in OWNERS.items():
        require((a, b) in fdes, f'{role} FDE changed')
        offset, raw = read(data, a, b - a)
        require(hashlib.sha256(raw).hexdigest() == sha,
                f'{role} body changed')
        records = {}
        for kind in ('fde', 'cie'):
            va = fdes[(a, b)][kind]
            n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
            records[kind] = {'va': hex(va),
                             'bytes_hex': read(data, va, n)[1].hex()}
        require(records == FRAMES[role], f'{role} frame records changed')
        entry = {'role': role, 'start': hex(a), 'end': hex(b),
                 'file_offset': hex(offset), 'bytes': b - a,
                 'sha256': sha, 'frames': records}
        if role in copies:
            entry['dispatch_table'] = copies[role]['dispatch_table']
            entry['slow_slot'] = copies[role]['slow_slot']
            entry['error_slot'] = copies[role]['error_slot']
        owners.append(entry)
    fast_classes = [{'markers': '0..250', **fast_marker_outcome(0)}]
    for marker in (251, 252, 253, 254, 255):
        fast_classes.append({'marker': marker, **fast_marker_outcome(marker)})
    slow_grid = []
    for marker in (0, 250, 251, 252, 253, 254, 255):
        for total in range(11):
            slow_grid.append({'marker': marker, 'total_remaining': total,
                              **slow_outcome(marker, total)})
    return {
     'target_sha256': SHA,
     'owners': owners,
     'reader_state': {
      'mode': 'state +0x0, dword; the charged route is taken iff == 1',
      'limit': 'state +0x8, u64; mode-1 bound for the charged count',
      'cursor': 'state +0x10, pointer; advanced only on success',
      'remaining': 'state +0x18, u64; decremented only on success',
      'charged_count': 'state +0x20, u64; mode-1 charge ledger'},
     'result_layout': {
      'rawtag': 'result +0x0, byte: 0x12 value, 0x02 charge refusal, '
                '0x00 slow shortfall, 0x03 error (via the constructor)',
      'value': 'result +0x8, u64, written on rawtag 0x12',
      'additional': 'result +0x8, u64, written on rawtag 0x00 (the '
                    'value and the additional count share offset +0x8; '
                    'the rawtag distinguishes them)',
      'error_fields': 'result +0x1 (field1) and +0x2 (field2), written '
                      'by the shared constructor on rawtag 0x03'},
     'charge': {
      'amount': 8,
      'stored_before_limit_compare': True,
      'overflow': 'charged > u64::MAX - 8 returns rawtag 2 with the '
                  'charged count unchanged',
      'over_limit': 'charged + 8 > limit returns rawtag 2; the +8 '
                    'charge is retained and no input is consumed',
      'uncharged_modes': 'every mode value other than 1 takes the '
                         'uncharged route in these bytes'},
     'fast_route': {
      'requires': 'remaining > 8',
      'fallback': 'remaining <= 8 calls the slow reader through slot '
                  '0x64e7f80 with state +0x10 and endianness 0',
      'marker_classes': fast_classes,
      'minimality': 'no marker-value comparison exists in either '
                    'copy: non-minimal 251/252/253 encodings of small '
                    'values are accepted'},
     'slow_path': {
      'fde': '0x5822710..0x582284c',
      'argument': 'pointer to the (cursor, remaining) pair at '
                  'state +0x10, plus an endianness flag in dl that '
                  'both copies set to 0 (little-endian)',
      'marker_consumed_before_classification': True,
      'empty': 'remaining == 0 returns rawtag 0 with additional 1 '
               'and consumes nothing',
      'grid': slow_grid,
      'dispatch_table': slow['dispatch_table']},
     'boundaries': {
      'error_constructor': {
       'fde': '0x5822700..0x582270e',
       'role': 'shared raw constructor: writes rawtag 3, field1 from '
               'esi, field2 from edx; reached through slot 0x64e7f78 '
               'by copy_b and the slow reader, and through slot '
               '0x64e7f88 by copy_a (both slots relocate to it). '
               'Owned by the open u64-reader packet (#2300), recorded '
               'here as a called boundary'},
      'u64_reader_family': {
       'role': 'copies 0x2cd7ac0/0x5821250, slow reader 0x58225c0 '
               '(via slot 0x64e6c38), raw constructor and 4x aggregate '
               'callers 0x2cd7d90/0x5821540; owned by open PR #2300. '
               'Charge (8), fast threshold (remaining > 8) and the '
               'payload ladder (251/252/253 consuming 3/5/9; slow '
               'widths 3/5/9) agree with this family, but the error '
               'results disagree on the same inputs: markers 254/255 '
               'return field1 2 on its fast route and field1 3 on its '
               'slow route, against field1 5 on both routes here. '
               'No caller calls either copy of this family four '
               'times; its per-FDE call multiplicity is at most 2.'},
      'u32_reader_family': {
       'role': 'copies 0x2cd79c0/0x5821150, slow reader 0x5822490; '
               'our open PR #2412. Disagrees on the same inputs: '
               'charge 4 against 8, fast threshold remaining > 4 '
               'against > 8, marker 253 is an error (field1 2, '
               'field2 3, consume 0 fast / 1 slow) there and a u64 '
               'payload read (consume 9 fast, 9-total shortfall '
               'slow) here, the value is a dword at result +0x4 '
               'there and a qword at +0x8 here, slow widths are 3/5 '
               'there and 3/5/9 here, and its error field1 is 2 on '
               'both routes against 5 here.'},
      'size_state': 'the encode-side varint size functions are open '
                    'PR #2257; disjoint role'},
     'call_sites': calls,
     'slow_slot_references': slot_refs,
     'relocations': {hex(SLOW_SLOT): hex(SLOW),
                     hex(CTOR_SLOT): hex(CTOR),
                     hex(CTOR_SLOT_A): hex(CTOR),
                     hex(U32_SLOW_SLOT): hex(U32_SLOW),
                     hex(U64_SLOW_SLOT): hex(U64_SLOW)},
     'captured_code_executed': False,
     'limits': LIMITS}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('pinned node115 distribution changed')
    payload = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / 'hl-node'
        snapshot.write_bytes(data)
        native = subprocess.check_output(['readelf', '-wf', str(snapshot)],
                                         text=True)
        wanted = []
        for a, b, _ in OWNERS.values():
            needle = f'pc={a:016x}..{b:016x}'
            wanted += [ln for ln in native.splitlines() if needle in ln]
        require(len(wanted) == len(OWNERS), 'owner frame lines missing')
        (output / 'frames.txt').write_text('\n'.join(wanted) + '\n')
        for role, (a, b, _) in OWNERS.items():
            asm = subprocess.check_output(
             ['objdump', '-d', '-M', 'intel', '--insn-width=16',
              f'--start-address={a:#x}', f'--stop-address={b:#x}',
              str(snapshot)], text=True)
            ins = decode_export(asm, a, b, read(data, a, b - a)[1])
            for va in REQUIRED_STARTS[role]:
                require(va in ins, f'{role} instruction start missing')
            (output / f'{role}.objdump.txt').write_bytes(
             asm.replace(str(snapshot), '<authenticated-node115>')
             .encode('utf-8'))
    (output / 'records.json').write_text(
     json.dumps(payload, indent=1, sort_keys=True) + '\n')
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('output', nargs='?', default=str(PACKET))
    args = parser.parse_args()
    payload = generate(TARGET, Path(args.output))
    for owner in payload['owners']:
        print(owner['role'], owner['start'], owner['end'],
              owner['bytes'], owner['sha256'])


if __name__ == '__main__':
    main()
