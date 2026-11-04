#!/usr/bin/env python3
"""RE-005: digest-bound node115 bincode u32 varint reader trace.

Traces one logical function of the pinned node #115 binary: the
bincode-fork scalar varint reader for the u32 width, present as two
codegen copies (0x2cd79c0 and 0x5821150) that share one slow-path
reader (0x5822490) and one raw error constructor (0x5822700, a
boundary owned by the open u64-reader packet). The reader charges 4
against the mode-1 charged count, takes its fast route only above
four remaining bytes, accepts the u16 and u32 payload markers,
rejects the u64-width marker with raw error field2 3, and reports
slow-path shortfalls as rawtag 0 with an additional-byte count.
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
PACKET = ROOT / 'research/work-items/RE-005-node115-u32-varint-reader'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
OWNERS = {
 'copy_a': (0x2cd79c0, 0x2cd7ab3,
            'a5c3798993adf6685060aa2cb82a5088b005a52b2e9b68086e5a6147ad0e2269'),
 'copy_b': (0x5821150, 0x5821243,
            'd9cbd093b853222eb99cc7f535e1ba275ee2ed6d0fb20cd42ab1d09226c31f10'),
 'slow_path': (0x5822490, 0x58225b5,
               '01255fd93b48bc057b05509c8aefd2ae286c27b62431f3159813a8b398b816f8')}
COPY_TABLES = {'copy_a': 0x60be7c, 'copy_b': 0x935bcc}
SLOW = 0x5822490
SLOW_TABLE = 0x935c14
SLOW_SLOT = 0x64e7f70
CTOR = 0x5822700
CTOR_SLOT = 0x64e7f78
CTOR_BODY = bytes.fromhex('4889f8c6070340887701885702c3')
SIBLING_SLOW_SLOT = 0x64e7f80
SIBLING_SLOW = 0x5822710
ERROR_FIELD2 = {253: 3, 254: 4, 255: 12}
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
     (0x0a, '4883f8fb', 'charge overflow bound (charged > u64::MAX - 4)'),
     (0x0e, '7711', 'overflow branch to refusal'),
     (0x10, '488b4e08', 'limit load at state +0x8'),
     (0x14, '4883c004', 'mode-1 charge increment 4'),
     (0x18, '48894620', 'charged count stored before the limit compare'),
     (0x1c, '4839c8', 'charged count against limit'),
     (0x1f, '7608', 'accepted branch to main'),
     (0x21, 'c60702', 'charge refusal rawtag 2'),
     (0x29, '488b4618', 'remaining load at state +0x18'),
     (0x2d, '4883f804', 'fast route requires remaining > 4'),
     (0x31, '7664', 'short input branch to the slow call'),
     (0x33, '488b4e10', 'cursor load at state +0x10'),
     (0x37, '0fb611', 'marker load'),
     (0x3a, '81fafb000000', 'marker boundary 251'),
     (0x40, '7308', 'payload marker branch to dispatch'),
     (0x42, '41b801000000', 'single-byte marker consumes 1'),
     (0x48, 'eb34', 'single-byte marker branch to the store'),
     (0x4a, '81c205ffffff', 'dispatch index marker - 251'),
     (0x50, '83fa03', 'dispatch index range 0..3'),
     (0x53, '0f8782000000', 'out-of-range branch to the 255 arm'),
     (0x60, '49631490', 'dispatch table entry load'),
     (0x64, '4c01c2', 'dispatch table base add'),
     (0x69, '0fb75101', 'marker 251 u16 payload load'),
     (0x6d, '41b803000000', 'marker 251 consumes 3'),
     (0x73, 'eb09', 'marker 251 branch to the store'),
     (0x75, '8b5101', 'marker 252 u32 payload load'),
     (0x78, '41b805000000', 'marker 252 consumes 5'),
     (0x7e, '4c01c1', 'cursor advance'),
     (0x81, '4c29c0', 'remaining decrease'),
     (0x84, '48894e10', 'cursor store'),
     (0x88, '48894618', 'remaining store'),
     (0x8c, '895704', 'value dword store at result +0x4'),
     (0x8f, 'c60712', 'success rawtag 0x12'),
     (0x97, '4883c610', 'slow argument is state +0x10'),
     (0x9e, '31d2', 'slow endianness argument 0'),
     (0xab, '4889fb', 'marker 254 arm saves the result pointer'),
     (0xae, 'be02000000', 'marker 254 error field1 2'),
     (0xb3, 'ba04000000', 'marker 254 error field2 4'),
     (0xc6, 'be02000000', 'marker 253 error field1 2'),
     (0xcb, 'ba03000000', 'marker 253 error field2 3'),
     (0xde, 'be02000000', 'marker 255 error field1 2'),
     (0xe3, 'ba0c000000', 'marker 255 error field2 12')]
    for rel, hexs, message in pins:
        pin(body, rel, bytes.fromhex(hexs), f'{role} {message}')
    disp = struct.unpack_from('<i', body, 0x5c)[0]
    require(base + 0x60 + disp == table_va,
            f'{role} dispatch table reference changed')
    slow_slot = base + 0xa6 + struct.unpack_from('<i', body, 0xa2)[0]
    require(slow_slot == SLOW_SLOT, f'{role} slow-path slot changed')
    for rel in (0xb8, 0xd0, 0xe8):
        slot = base + rel + 6 + struct.unpack_from('<i', body, rel + 2)[0]
        require(slot == CTOR_SLOT, f'{role} error constructor slot changed')
    raw = read(data, table_va, 16)[1]
    entries = list(struct.unpack('<4i', raw))
    targets = [table_va + e for e in entries]
    require(targets == [base + 0x69, base + 0x75, base + 0xc3, base + 0xab],
            f'{role} dispatch table targets changed')
    return {'dispatch_table': {'va': hex(table_va),
                               'entries': [hex(e) for e in entries],
                               'targets': {'251': hex(targets[0]),
                                           '252': hex(targets[1]),
                                           '253': hex(targets[2]),
                                           '254': hex(targets[3])}},
            'slow_slot': hex(SLOW_SLOT),
            'error_slot': hex(CTOR_SLOT)}


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
     (0x020, '4181f8fb000000', 'marker boundary 251'),
     (0x029, '44894704', 'single-byte value store at result +0x4'),
     (0x02d, 'c60712', 'slow success rawtag 0x12'),
     (0x035, 'c60700', 'empty/shortfall rawtag 0'),
     (0x038, '48c7470801000000', 'empty additional count 1'),
     (0x045, '4181c005ffffff', 'dispatch index marker - 251'),
     (0x04c, '4183f803', 'dispatch index range 0..3'),
     (0x050, '0f87b7000000', 'out-of-range branch to the 255 arm'),
     (0x067, '4883f803', 'marker 251 total width 3'),
     (0x06d, 'b903000000', 'marker 251 shortfall width 3'),
     (0x074, '4883f805', 'marker 252 total width 5'),
     (0x07a, 'b905000000', 'marker 252 shortfall width 5'),
     (0x07f, '4829c1', 'additional is width - total remaining'),
     (0x085, '48894f08', 'additional store at result +0x8'),
     (0x08e, '440fb74101', 'marker 251 u16 payload load'),
     (0x093, '4883c103', 'marker 251 cursor advances 3 in total'),
     (0x09d, '66c1c108', 'marker 251 byte swap'),
     (0x0a5, '84d2', 'endianness flag test'),
     (0x0a7, '410f44c8', 'marker 251 endianness select'),
     (0x0b4, '4883c0fb', 'marker 252 remaining drops 5 in total'),
     (0x0b8, '448b4101', 'marker 252 u32 payload load'),
     (0x0bc, '4883c105', 'marker 252 cursor advances 5 in total'),
     (0x0ca, '0fc8', 'marker 252 byte swap'),
     (0x0ce, '410f44c0', 'marker 252 endianness select'),
     (0x0d2, '894704', 'slow success value store at result +0x4'),
     (0x0e0, 'be02000000', 'marker 254 error field1 2'),
     (0x0e5, 'ba04000000', 'marker 254 error field2 4'),
     (0x0f8, 'be02000000', 'marker 253 error field1 2'),
     (0x0fd, 'ba03000000', 'marker 253 error field2 3'),
     (0x110, 'be02000000', 'marker 255 error field1 2'),
     (0x115, 'ba0c000000', 'marker 255 error field2 12')]
    for rel, hexs, message in pins:
        pin(body, rel, bytes.fromhex(hexs), f'slow {message}')
    disp = struct.unpack_from('<i', body, 0x59)[0]
    require(SLOW + 0x5d + disp == SLOW_TABLE,
            'slow dispatch table reference changed')
    for rel in (0xea, 0x102, 0x11a):
        slot = SLOW + rel + 6 + struct.unpack_from('<i', body, rel + 2)[0]
        require(slot == CTOR_SLOT, 'slow error constructor slot changed')
    raw = read(data, SLOW_TABLE, 16)[1]
    entries = list(struct.unpack('<4i', raw))
    targets = [SLOW_TABLE + e for e in entries]
    require(targets == [0x58224f7, 0x5822504, 0x5822585, 0x582256d],
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
    return {'outcome': 'error', 'field1': 2,
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
    return {'outcome': 'error', 'field1': 2,
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
  'fde': {'va': '0xd8bc2c',
          'bytes_hex': '34000000584d0e008cbdf401f300000000410e108302670e'
                       '08410e10026d0e08410e10530e08410e10570e08410e1057'
                       '0e08410e10570e08'},
  'cie': {'va': '0xca6ed8',
          'bytes_hex': '1400000000000000017a5200017810011b0c070890010000'}},
 'copy_b': {
  'fde': {'va': '0xf9c404',
          'bytes_hex': '3400000030552f00444d8804f300000000410e108302670e'
                       '08410e10026d0e08410e10530e08410e10570e08410e1057'
                       '0e08410e10570e08'},
  'cie': {'va': '0xca6ed8',
          'bytes_hex': '1400000000000000017a5200017810011b0c070890010000'}},
 'slow_path': {
  'fde': {'va': '0xf9c6ac',
          'bytes_hex': '3c000000d8572f00dc5d88042501000000410e108302730e'
                       '08410e104f0e08410e1002480e08410e10024e0e08410e'
                       '10570e08410e10570e08410e10570e0800'},
  'cie': {'va': '0xca6ed8',
          'bytes_hex': '1400000000000000017a5200017810011b0c070890010000'}}}
REQUIRED_STARTS = {
 'copy_a': [0x2cd79c0, 0x2cd79fa, 0x2cd7a19, 0x2cd7a29, 0x2cd7a35,
            0x2cd7a3e, 0x2cd7a57, 0x2cd7a6b, 0x2cd7a83, 0x2cd7a9b],
 'copy_b': [0x5821150, 0x582118a, 0x58211a9, 0x58211b9, 0x58211c5,
            0x58211ce, 0x58211e7, 0x58211fb, 0x5821213, 0x582122b],
 'slow_path': [0x5822490, 0x58224b0, 0x58224c5, 0x58224e6, 0x58224f7,
               0x5822504, 0x582251e, 0x5822544, 0x582256d, 0x5822585,
               0x582259d]}


def analyze(data):
    by_offset = relocations(data)
    require(by_offset.get(SLOW_SLOT) == [(8, SLOW)],
            'slow-path slot relocation changed')
    require(by_offset.get(CTOR_SLOT) == [(8, CTOR)],
            'error constructor slot relocation changed')
    require(by_offset.get(SIBLING_SLOW_SLOT) == [(8, SIBLING_SLOW)],
            'sibling slow-path slot relocation changed')
    copies = {}
    for role in ('copy_a', 'copy_b'):
        copies[role] = copy_semantics(data, role, OWNERS[role][0],
                                      COPY_TABLES[role])
    require(copies['copy_a']['dispatch_table']['targets']
            != copies['copy_b']['dispatch_table']['targets'],
            'copies unexpectedly share one dispatch table')
    slow = slow_semantics(data)
    require(read(data, CTOR, len(CTOR_BODY))[1] == CTOR_BODY,
            'error constructor body changed')
    calls, slot_refs = census(data)
    require(calls['slow_path'] == [], 'slow reader direct caller appeared')
    require(slot_refs == ['0x2cd7a60', '0x58211f0'],
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
        owners.append(entry)
    fast_classes = [{'markers': '0..250', **fast_marker_outcome(0)}]
    for marker in (251, 252, 253, 254, 255):
        fast_classes.append({'marker': marker, **fast_marker_outcome(marker)})
    slow_grid = []
    for marker in (0, 250, 251, 252, 253, 254, 255):
        for total in range(7):
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
      'value': 'result +0x4, u32, written on rawtag 0x12',
      'additional': 'result +0x8, u64, written on rawtag 0x00',
      'error_fields': 'result +0x1 (field1) and +0x2 (field2), written '
                      'by the shared constructor on rawtag 0x03'},
     'charge': {
      'amount': 4,
      'stored_before_limit_compare': True,
      'overflow': 'charged > u64::MAX - 4 returns rawtag 2 with the '
                  'charged count unchanged',
      'over_limit': 'charged + 4 > limit returns rawtag 2; the +4 '
                    'charge is retained and no input is consumed',
      'uncharged_modes': 'every mode value other than 1 takes the '
                         'uncharged route in these bytes'},
     'fast_route': {
      'requires': 'remaining > 4',
      'fallback': 'remaining <= 4 calls the slow reader through slot '
                  '0x64e7f70 with state +0x10 and endianness 0',
      'marker_classes': fast_classes,
      'minimality': 'no marker-value comparison exists in either '
                    'copy: non-minimal 251/252 encodings of small '
                    'values are accepted'},
     'slow_path': {
      'fde': '0x5822490..0x58225b5',
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
               'esi, field2 from edx; owned by the open u64-reader '
               'packet (#2300), recorded here as a called boundary'},
      'u64_reader_family': {
       'role': 'copies 0x2cd7ac0/0x5821250, slow reader 0x58225c0, '
               'raw constructor and 4x aggregates; owned by open '
               'PR #2300. On marker 253 the widths disagree: the '
               'u64 copies read an 8-byte payload (consume 9), this '
               'reader returns error field2 3 (consume 0 fast, 1 '
               'slow). Charge 8 vs 4; fast threshold remaining > 8 '
               'vs > 4.'},
      'field1_5_sibling': {
       'role': 'a second scalar-reader family with the same payload '
               'widths but constructor field1 5 (copies include '
               '0x5821340; slow reader 0x5822710 via slot '
               '0x64e7f80); excluded, not traced'},
      'size_state': 'the encode-side varint size functions are open '
                    'PR #2257; disjoint role'},
     'call_sites': calls,
     'slow_slot_references': slot_refs,
     'relocations': {hex(SLOW_SLOT): hex(SLOW),
                     hex(CTOR_SLOT): hex(CTOR),
                     hex(SIBLING_SLOW_SLOT): hex(SIBLING_SLOW)},
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
