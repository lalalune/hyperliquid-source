#!/usr/bin/env python3
"""Static, digest-bound evidence for a pending order-row filter in node 94."""
import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Half-open unwind extents; labels describe only the selected path.
FUNCTIONS = (
    ('row-filter', 0x3bc29a0, 0x3bc2bba, 'a5faed0bed8283c8462b498694deb0148f766c27665903155a181d7100161b1d'),
    ('row-drop-dispatch', 0x3bba5a0, 0x3bba7fe, '790d5191a5095a4c6657bf4a5efbc4304f413118b1726f4d8fbc581bc792779b'),
    ('order-record-drop', 0x3bbc9d0, 0x3bbcaf9, 'ff3144ec322a56c3b71f8db911005bca48bb8b44fb395f7c82eaaf61c5668fc1'),
)

# Instruction starts and branch targets were inspected manually. Every target
# is decoded again from the instruction bytes, and all opcode kinds are pinned.
BRANCHES = (
    ('empty-vector',0x3bc29b5,'je',0x3bc2b64),
    ('start-scan',0x3bc29de,'jmp',0x3bc2a03),
    ('scan-end',0x3bc29fd,'je',0x3bc2b64),
    ('outer-not-3',0x3bc2a0b,'jne',0x3bc29f0),
    ('inner-2',0x3bc2a23,'je',0x3bc2a45),
    ('inner-4',0x3bc2a29,'je',0x3bc29f0),
    ('first-key-miss',0x3bc2a41,'jne',0x3bc29f0),
    ('first-key-hit',0x3bc2a43,'jmp',0x3bc2a5d),
    ('second-key-miss',0x3bc2a5b,'jne',0x3bc29f0),
    ('flag-zero-update',0x3bc2a62,'je',0x3bc29e0),
    ('status-nonzero-update',0x3bc2a71,'jne',0x3bc29e0),
    ('first-drop-at-end',0x3bc2aa3,'jae',0x3bc2b5c),
    ('compact-outer-not-3',0x3bc2aad,'jne',0x3bc2b20),
    ('compact-inner-2',0x3bc2ac7,'je',0x3bc2ae6),
    ('compact-inner-4',0x3bc2acd,'je',0x3bc2b20),
    ('compact-first-key-hit',0x3bc2ae2,'je',0x3bc2afb),
    ('compact-first-key-miss',0x3bc2ae4,'jmp',0x3bc2b20),
    ('compact-second-key-miss',0x3bc2af9,'jne',0x3bc2b20),
    ('compact-flag-zero',0x3bc2b00,'je',0x3bc2b09),
    ('compact-status-zero-drop',0x3bc2b07,'je',0x3bc2b52),
    ('compact-next',0x3bc2b4a,'jb',0x3bc2aa9),
    ('compact-done',0x3bc2b50,'jmp',0x3bc2b5c),
    ('drop-next',0x3bc2b5a,'jmp',0x3bc2b3d),
    ('landing-pad-join',0x3bc2b79,'jmp',0x3bc2b7e),
    ('drop-tag-large',0x3bba5c1,'ja',0x3bba714),
    ('drop-inner-other',0x3bba5fa,'je',0x3bba7d2),
    ('drop-inner-2',0x3bba608,'je',0x3bba7d7),
    ('drop-inner-no-record',0x3bba60e,'jmp',0x3bba5d7),
    ('record-first-empty',0x3bbc9e4,'je',0x3bbc9f2),
    ('record-second-empty',0x3bbc9f9,'je',0x3bbca07),
    ('record-children-end',0x3bbca24,'je',0x3bbca3a),
    ('record-children-loop',0x3bbca38,'jmp',0x3bbca20),
    ('record-array-empty',0x3bbca41,'je',0x3bbca55),
    ('record-final-empty',0x3bbca5c,'je',0x3bbca78),
    ('record-unwind-children-end',0x3bbca93,'je',0x3bbcaaa),
    ('record-unwind-loop',0x3bbcaa8,'jmp',0x3bbca90),
    ('record-unwind-array',0x3bbcab1,'jne',0x3bbcac4),
    ('record-unwind-final',0x3bbcaba,'jne',0x3bbcadf),
    ('record-unwind-resume',0x3bbcadd,'je',0x3bbcabc),
)

# Selected complete semantic blocks. These are not disassembler output.
WINDOWS = (
    ('host-a-conditional-handoff',0x4d146f2,0x4d14763),
    ('host-b-conditional-handoff',0x4d16f82,0x4d16ff3),
    ('adapter-input-handoff',0x3b7bd24,0x3b7bd5b),
    ('entry-and-input-pointers',0x3bc29a0,0x3bc29de),
    ('scan-and-tag-choice',0x3bc29e0,0x3bc2a35),
    ('first-match-and-delete',0x3bc2a35,0x3bc2a91),
    ('compact-tag-choice',0x3bc2aa0,0x3bc2afb),
    ('compact-write-copy-and-delete',0x3bc2afb,0x3bc2b60),
    ('length-store-and-return',0x3bc2b60,0x3bc2b73),
    ('unwind-preserve-tail',0x3bc2b73,0x3bc2bba),
    ('drop-tag-dispatch',0x3bba5a0,0x3bba610),
    ('drop-record-address',0x3bba7d2,0x3bba7ec),
    ('record-drop-normal',0x3bbc9d0,0x3bbca87),
    ('record-drop-unwind',0x3bbca87,0x3bbcaf9),
)

# All are manually selected instruction starts; this is not a scan for every
# call or an assertion that indirect callees cannot be patched at runtime.
CALLS = (
    ('adapter-to-filter', 0x3b7bd56, 'call', 0x3bc29a0),
    ('first-drop', 0x3bc2a8c, 'call', 0x3bba5a0),
    ('later-drop', 0x3bc2b55, 'call', 0x3bba5a0),
    ('normal-compaction-copy', 0x3bc2b34, 'indirect-call', 0x576dfe0),
    ('unwind-tail-move', 0x3bc2ba1, 'indirect-call', 0x576e0e0),
    ('filter-resume', 0x3bc2bb5, 'call', 0x5660110),
    ('drop-order-record', 0x3bba7e7, 'jmp', 0x3bbc9d0),
    ('drop-record-recurse', 0x3bbca30, 'call', 0x3bbc9d0),
    ('drop-record-unwind-recurse', 0x3bbcaa0, 'call', 0x3bbc9d0),
    ('record-free-first', 0x3bbc9ec, 'indirect-call', 0x576e010),
    ('record-free-second', 0x3bbca01, 'indirect-call', 0x576e010),
    ('record-free-children', 0x3bbca4f, 'indirect-call', 0x576e010),
    ('record-free-last', 0x3bbca72, 'indirect-jmp', 0x576e010),
    ('host-a-adapter', 0x4d1475d, 'indirect-call', 0x57747b8),
    ('host-b-adapter', 0x4d16fed, 'indirect-call', 0x57747b8),
)

# Each field below is decoded from its fixed instruction encoding.
OPERANDS = (
    ('vector-length-offset', 0x3bc29ae, '4c8b7f10', 3, 'B'),
    ('vector-pointer-offset', 0x3bc29bb, '488b4708', 3, 'B'),
    ('row-stride', 0x3bc29cf, '4c8db068020000', 3, 'I'),
    ('selected-outer-tag', 0x3bc2a03, '4183be98fdffff03', 7, 'B'),
    ('other-inner-status-offset', 0x3bc2a2b, 'ba19010000', 1, 'I'),
    ('other-inner-record-offset', 0x3bc2a30, 'b930000000', 1, 'I'),
    ('key-displacement-from-record-cursor', 0x3bc2a35, '498bb40e08feffff', 4, 'i'),
    ('inner-two-status-offset', 0x3bc2a45, 'ba00010000', 1, 'I'),
    ('inner-two-record-offset', 0x3bc2a4a, 'b938000000', 1, 'I'),
    ('write-displacement-from-record-cursor', 0x3bc29e5, 'f2410f11840e20feffff', 6, 'i'),
    ('compaction-copy-size', 0x3bc2b2c, 'ba68020000', 1, 'I'),
    ('nested-record-stride', 0x3bbca26, '4c8da7a8000000', 3, 'I'),
    ('nested-allocation-stride', 0x3bbca43, '4869f0a8000000', 3, 'I'),
)

class EvidenceError(ValueError):
    pass


def authenticate(data):
    got = hashlib.sha256(data).hexdigest()
    if got != DIGEST:
        raise EvidenceError('node 94 SHA-256 mismatch')
    return got


def file_offset(secs, va, size, executable=False):
    if va < 0 or size <= 0 or va + size > (1 << 64):
        raise EvidenceError('invalid address range')
    matches = [s for s in secs if s['type'] != 8 and
               (not executable or s['flags'] & 4) and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise EvidenceError('address is not uniquely file-backed')
    return matches[0]['offset'] + va - matches[0]['address']


def read_va(data, secs, va, size, executable=False):
    off = file_offset(secs, va, size, executable)
    raw = data[off:off + size]
    if len(raw) != size:
        raise EvidenceError('truncated file bytes')
    return raw


def verify_body(raw, expected):
    if hashlib.sha256(raw).hexdigest() != expected:
        raise EvidenceError('function bytes differ')


def decode_branch(raw, va, kind, expected):
    opcodes = {'je': 4, 'jne': 5, 'jae': 3, 'jb': 2, 'ja': 7}
    if kind == 'jmp':
        if len(raw) >= 2 and raw[0] == 0xeb:
            size, displacement = 2, struct.unpack_from('<b', raw, 1)[0]
        elif len(raw) >= 5 and raw[0] == 0xe9:
            size, displacement = 5, struct.unpack_from('<i', raw, 1)[0]
        else:
            raise EvidenceError('unexpected jump opcode')
    else:
        if kind not in opcodes:
            raise EvidenceError('unsupported branch condition')
        code = opcodes[kind]
        if len(raw) >= 2 and raw[0] == 0x70 + code:
            size, displacement = 2, struct.unpack_from('<b', raw, 1)[0]
        elif len(raw) >= 6 and raw[0:2] == bytes((0x0f, 0x80 + code)):
            size, displacement = 6, struct.unpack_from('<i', raw, 2)[0]
        else:
            raise EvidenceError('unexpected branch opcode')
    destination = va + size + displacement
    if destination != expected:
        raise EvidenceError('unexpected branch destination')
    return raw[:size], destination


def decode_call(raw, va, kind, expected):
    if kind in ('call', 'jmp'):
        opcode = 0xe8 if kind == 'call' else 0xe9
        if len(raw) < 5 or raw[0] != opcode:
            raise EvidenceError('unexpected direct transfer')
        size, displacement = 5, struct.unpack_from('<i', raw, 1)[0]
    elif kind in ('indirect-call', 'indirect-jmp'):
        op = b'\xff\x15' if kind == 'indirect-call' else b'\xff\x25'
        if len(raw) < 6 or raw[:2] != op:
            raise EvidenceError('unexpected indirect transfer')
        size, displacement = 6, struct.unpack_from('<i', raw, 2)[0]
    else:
        raise EvidenceError('unsupported transfer')
    dest = va + size + displacement
    if dest != expected:
        raise EvidenceError('unexpected transfer destination')
    return raw[:size], dest


def relocations(data, secs, targets):
    found = {}
    for sec in secs:
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise EvidenceError('partial ELF64 relocation')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            if slot in targets:
                if slot in found:
                    raise EvidenceError('duplicate relocation')
                found[slot] = (info, addend, off)
    if set(found) != set(targets):
        raise EvidenceError('missing relocation')
    return found


def symbol_name(data, secs, index):
    sym = next(s for s in secs if s['name'] == '.dynsym')
    strings = next(s for s in secs if s['name'] == '.dynstr')
    if index <= 0 or index * 24 + 24 > sym['size']:
        raise EvidenceError('invalid dynamic symbol')
    name = struct.unpack_from('<I', data, sym['offset'] + 24 * index)[0]
    if name >= strings['size']:
        raise EvidenceError('invalid dynamic symbol name')
    start = strings['offset'] + name
    end = data.find(b'\0', start, strings['offset'] + strings['size'])
    if end < 0:
        raise EvidenceError('unterminated dynamic symbol name')
    return data[start:end].decode('ascii')


def lsda_calls(raw, start, end, va):
    # The actual selected LSDAs have omitted LPStart and ULEB call-site tables.
    if len(raw) < 4 or raw[0] != 0xff or raw[1] not in (0xff, 0x9b):
        raise EvidenceError('unsupported LSDA header')
    pos = 2
    try:
        if raw[1] == 0x9b:
            skip, pos = uleb(raw, pos, len(raw))
            if pos + skip > len(raw):
                raise EvidenceError('invalid LSDA type table')
        if raw[pos] != 1:
            raise EvidenceError('unsupported LSDA call-site encoding')
        size, pos = uleb(raw, pos + 1, len(raw))
        limit = pos + size
        if limit > len(raw):
            raise EvidenceError('truncated LSDA table')
        rows, previous = [], 0
        while pos < limit:
            begin = pos
            offset, pos = uleb(raw, pos, limit)
            length, pos = uleb(raw, pos, limit)
            landing, pos = uleb(raw, pos, limit)
            action, pos = uleb(raw, pos, limit)
            if offset < previous or offset + length > end - start:
                raise EvidenceError('invalid LSDA code range')
            if landing and landing >= end - start:
                raise EvidenceError('invalid LSDA landing pad')
            previous = offset + length
            rows.append({'function_va': hex(start), 'lsda_va': hex(va),
                         'record_va': hex(va + begin), 'start_va': hex(start + offset),
                         'end_va': hex(start + offset + length),
                         'landing_va': hex(start + landing) if landing else '',
                         'action': action, 'raw_hex': raw[begin:pos].hex()})
        return rows
    except (IndexError, ValueError) as exc:
        raise EvidenceError('invalid LSDA encoding') from exc


def outcome(row, key, flag):
    """Synthetic projection for a well-formed, complete row, never target execution."""
    if len(row) != 0x268:
        raise EvidenceError('row must have exactly the observed stride')
    if not 0 <= key < 1 << 64 or not 0 <= flag <= 255:
        raise EvidenceError('invalid projection input')
    if struct.unpack_from('<I', row, 0)[0] != 3:
        return 'keep', None
    inner = struct.unpack_from('<Q', row, 8)[0]
    if inner == 4:
        return 'keep', None
    key_offset, status_offset, size_offset = ((0xa8, 0x100, 0xc0) if inner == 2
                                                else (0xa0, 0x119, 0xb8))
    if struct.unpack_from('<Q', row, key_offset)[0] != key:
        return 'keep', None
    if flag != 0 and row[status_offset] == 0:
        return 'drop', None
    return 'update', size_offset


def project(rows, key, flag, value_bits):
    if not 0 <= value_bits < 1 << 64:
        raise EvidenceError('invalid replacement bits')
    result, actions = [], []
    for row in rows:
        action, offset = outcome(row, key, flag)
        actions.append(action)
        if action == 'drop':
            continue
        copy = bytearray(row)
        if action == 'update':
            struct.pack_into('<Q', copy, offset, value_bits)
        result.append(bytes(copy))
    return result, actions


def synthetic_row(tag, inner, key, status, marker):
    """Create a recognizable full-width synthetic row for the projection."""
    if not 0 <= marker <= 255:
        raise EvidenceError('invalid marker')
    row = bytearray([marker] * 0x268)
    struct.pack_into('<Q', row, 0, tag)
    struct.pack_into('<Q', row, 8, inner)
    if inner == 2:
        struct.pack_into('<Q', row, 0xa8, key)
        row[0x100] = status
    else:
        struct.pack_into('<Q', row, 0xa0, key)
        row[0x119] = status
    return bytes(row)


def project_with_drop_failure(rows, key, flag, value_bits, failed_drop):
    """Synthetic suffix-preservation projection; no exception is executed."""
    if failed_drop < 0:
        raise EvidenceError('invalid failed-drop index')
    kept, actions, count = [], [], 0
    for index, row in enumerate(rows):
        action, _ = outcome(row, key, flag)
        if action == 'drop':
            if count == failed_drop:
                actions.append('drop-throws')
                return kept + list(rows[index + 1:]), actions
            count += 1
            actions.append('drop')
        else:
            projected, _ = project([row], key, flag, value_bits)
            kept.extend(projected)
            actions.append(action)
    raise EvidenceError('requested drop failure was not reached')


def tsv(path, rows, fields):
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t', lineterminator='\n')
        w.writeheader()
        w.writerows(rows)


def generate(data, out):
    digest = authenticate(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {f['start']: f for f in fdes}
    index_by_start = {f['start']: f for f in index}
    funcs = []
    for role, start, end, expected_hash in FUNCTIONS:
        f = by_start.get(start)
        if f is None or f['end'] != end or start not in index_by_start or f['fde'] != index_by_start[start]['fde']:
            raise EvidenceError('selected FDE or unwind index changed')
        raw = read_va(data, secs, start, end - start, True)
        verify_body(raw, expected_hash)
        funcs.append({'role': role, 'start_va': hex(start), 'end_va': hex(end),
                      'size': len(raw), 'file_offset': hex(file_offset(secs, start, len(raw), True)),
                      'fde_va': hex(f['fde']), 'cie_va': hex(f['cie']),
                      'lsda_va': hex(f['lsda']) if f['lsda'] is not None else None,
                      'sha256': hashlib.sha256(raw).hexdigest(), 'raw_hex': raw.hex()})
    branches = []
    for name, site, kind, target in BRANCHES:
        raw = read_va(data, secs, site, 6, True)
        inst, dest = decode_branch(raw, site, kind, target)
        branches.append({'name': name, 'site_va': hex(site), 'raw_hex': inst.hex(),
                         'condition': kind, 'target_va': hex(dest)})
    calls = []
    for name, site, kind, target in CALLS:
        raw = read_va(data, secs, site, 6, True)
        inst, dest = decode_call(raw, site, kind, target)
        calls.append({'name': name, 'site_va': hex(site), 'raw_hex': inst.hex(),
                      'kind': kind, 'target_va': hex(dest)})
    windows = []
    for name, start, end in WINDOWS:
        raw = read_va(data, secs, start, end - start, True)
        windows.append({'name': name, 'start_va': hex(start), 'end_va': hex(end),
                        'size': len(raw), 'raw_hex': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest()})
    operands = []
    facts = {}
    for name, site, expected_hex, offset, fmt in OPERANDS:
        expected = bytes.fromhex(expected_hex)
        raw = read_va(data, secs, site, len(expected), True)
        if raw != expected:
            raise EvidenceError('operand instruction changed')
        value = struct.unpack_from('<' + fmt, raw, offset)[0]
        facts[name] = value
        operands.append({'name': name, 'site_va': hex(site), 'raw_hex': raw.hex(),
                         'value': str(value) if value < 0 else hex(value)})
    stride = facts['row-stride']
    key_disp = facts['key-displacement-from-record-cursor']
    write_disp = facts['write-displacement-from-record-cursor']
    layout = []
    for variant in ('inner-two', 'other-inner'):
        record = facts[variant + '-record-offset']
        layout.append({'variant': variant, 'record_offset': hex(record),
                       'key_offset': hex(stride + record + key_disp),
                       'value_offset': hex(stride + record + write_disp),
                       'status_offset': hex(facts[variant + '-status-offset'])})
    if stride != facts['compaction-copy-size'] or facts['nested-record-stride'] != facts['nested-allocation-stride']:
        raise EvidenceError('inconsistent operand sizes')
    slots = (0x57747b8, 0x576dfe0, 0x576e0e0, 0x576e010)
    rels = relocations(data, secs, slots)
    # The open caller research owns the adapter FDE. Validate the linkage
    # without selecting or reanalysing that function here.
    info, addend, _ = rels[0x57747b8]
    adapter = by_start.get(addend)
    if info != 8 or adapter is None or not adapter['start'] <= 0x3b7bd56 < adapter['end']:
        raise EvidenceError('host slot does not reach the adapter containing the direct call')
    if index_by_start.get(addend, {}).get('fde') != adapter['fde']:
        raise EvidenceError('adapter not present in unwind index')
    reloc_rows = []
    for slot in slots:
        info, addend, off = rels[slot]
        symbol = symbol_name(data, secs, info >> 32) if info >> 32 else ''
        if slot == 0x576dfe0 and (info & 0xffffffff != 6 or symbol != 'memcpy'):
            raise EvidenceError('copy relocation changed')
        if slot == 0x576e0e0 and (info & 0xffffffff != 6 or symbol != 'memmove'):
            raise EvidenceError('move relocation changed')
        if slot in (0x57747b8, 0x576e010) and info != 8:
            raise EvidenceError('relative relocation changed')
        # Adapter value is deliberately not selected as a function in this packet.
        reloc_rows.append({'slot_va': hex(slot), 'record_file_offset': hex(off),
                           'type': info & 0xffffffff, 'symbol': symbol,
                           'raw_hex': data[off:off + 24].hex(), 'addend': '' if slot == 0x57747b8 else hex(addend),
                           'adapter_contains_direct_call': 'true' if slot == 0x57747b8 else ''})
    table_base = 0x5b6adc
    raw = read_va(data, secs, table_base, 32)
    expected_table = (0x3bba5d7,0x3bba5e1,0x3bba6a3,0x3bba6eb,
                      0x3bba5d7,0x3bba610,0x3bba5d7,0x3bba5d7)
    table = []
    for i, expected in enumerate(expected_table):
        cell = raw[i*4:i*4+4]
        target = table_base + struct.unpack('<i', cell)[0]
        if target != expected:
            raise EvidenceError('drop dispatch table changed')
        table.append({'index': i, 'entry_va': hex(table_base + i*4),
                      'raw_hex': cell.hex(), 'target_va': hex(target)})
    section = next(s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8)
    unwind = []
    for f in funcs:
        if f['lsda_va'] is None:
            continue
        start, end, va = (int(f[k],16) for k in ('start_va','end_va','lsda_va'))
        off = file_offset(secs, va, 1)
        if not section['address'] <= va < section['address'] + section['size']:
            raise EvidenceError('LSDA outside exception section')
        raw = data[off:section['offset'] + section['size']]
        unwind.extend(lsda_calls(raw, start, end, va))
    # Test combinations demonstrate the projection. Inputs are synthetic.
    cases = []
    for inner in (0, 1, 2, 3, 4, 5, (1 << 64) - 1):
        for key_match in (False, True):
            for flag in (0, 1, 2):
                for status in (0, 1, 2):
                    row = bytearray(0x268)
                    struct.pack_into('<Q', row, 0, 3)
                    struct.pack_into('<Q', row, 8, inner)
                    ko, so = ((0xa8, 0x100) if inner == 2 else (0xa0, 0x119))
                    struct.pack_into('<Q', row, ko, 17 if key_match else 18)
                    row[so] = status
                    act, offset = outcome(bytes(row), 17, flag)
                    cases.append({'inner_word': hex(inner), 'key_matches': str(key_match).lower(),
                                  'flag_byte': flag, 'status_byte': status, 'action': act,
                                  'write_offset': '' if offset is None else hex(offset)})
    # These sequences are explicitly synthetic and contain controlled row bytes.
    scenario_inputs = [
        ('empty', [], None),
        ('all-kept', [(3,2,17,1,11), (2,0,17,0,22)], None),
        ('first-drop', [(3,2,17,0,11), (3,3,17,1,22), (2,0,17,0,33)], None),
        ('middle-drop', [(2,0,17,0,11), (3,2,17,0,22), (3,3,17,1,33)], None),
        ('last-drop', [(2,0,17,0,11), (3,2,17,0,22)], None),
        ('two-drops', [(3,2,17,0,11), (3,3,17,1,22), (3,3,17,0,33), (2,0,17,0,44)], None),
        ('first-drop-throws', [(3,2,17,0,11), (3,3,17,1,22), (2,0,17,0,33)], 0),
        ('later-drop-throws', [(3,2,17,0,11), (3,3,17,1,22), (3,3,17,0,33), (2,0,17,0,44)], 1),
    ]
    scenarios = []
    for name, params, fail in scenario_inputs:
        rows = [synthetic_row(*p) for p in params]
        if fail is None:
            retained, actions = project(rows, 17, 1, 0x3ff0000000000000)
        else:
            retained, actions = project_with_drop_failure(rows, 17, 1, 0x3ff0000000000000, fail)
        scenarios.append({'scenario': name, 'input_rows': len(rows),
                          'actions_until_return_or_throw': ','.join(actions),
                          'retained_markers': ','.join(str(row[0x20]) for row in retained),
                          'retained_rows': len(retained),
                          'retained_sha256': hashlib.sha256(b''.join(retained)).hexdigest()})
    out.mkdir(parents=True, exist_ok=True)
    (out / 'functions.json').write_text(json.dumps(funcs, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    tsv(out / 'operands.tsv', operands, ('name','site_va','raw_hex','value'))
    tsv(out / 'layout.tsv', layout, ('variant','record_offset','key_offset','value_offset','status_offset'))
    tsv(out / 'branches.tsv', branches, ('name','site_va','raw_hex','condition','target_va'))
    tsv(out / 'calls.tsv', calls, ('name','site_va','raw_hex','kind','target_va'))
    tsv(out / 'windows.tsv', windows, ('name','start_va','end_va','size','raw_hex','sha256'))
    tsv(out / 'relocations.tsv', reloc_rows, ('slot_va','record_file_offset','type','symbol','raw_hex','addend','adapter_contains_direct_call'))
    tsv(out / 'drop-table.tsv', table, ('index','entry_va','raw_hex','target_va'))
    tsv(out / 'unwind.tsv', unwind, ('function_va','lsda_va','record_va','start_va','end_va','landing_va','action','raw_hex'))
    tsv(out / 'synthetic-cases.tsv', cases, ('inner_word','key_matches','flag_byte','status_byte','action','write_offset'))
    tsv(out / 'synthetic-scenarios.tsv', scenarios, ('scenario','input_rows','actions_until_return_or_throw','retained_markers','retained_rows','retained_sha256'))
    summary = {'target_sha256': digest, 'selected_fdes': len(funcs),
               'selected_fde_bytes': sum(f['size'] for f in funcs),
               'selected_branches': len(branches), 'selected_transfers': len(calls),
               'windows': len(windows), 'operands': len(operands), 'layout_variants': len(layout), 'relocations': len(reloc_rows),
               'drop_table_entries': len(table), 'lsda_call_sites': len(unwind),
               'synthetic_rows': len(cases), 'synthetic_scenarios': len(scenarios),
               'limitations': 'Selected static extents and synthetic projections; no captured program execution or complete component coverage.'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(TARGET.read_bytes(), args.out)


if __name__ == '__main__':
    main()
