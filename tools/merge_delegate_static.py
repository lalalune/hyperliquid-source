#!/usr/bin/env python3
"""Pin the RE-015 merge delegate's later phases in node 115.

Question (the recorded next question of the assembled-record-readers
packet, #2559): what does the merge delegate 0x4748500 do in its later
phases -- how does the 0x20-byte entry vector built from both record
vectors merge with the third argument's vector (the consumer passes an
empty {0, 8, 0} vector), and what does the transform gate 0x474ba60
decide per element?  Where does the merged output go after the delegate
returns, on the consumer-exit path?

The packet pins: (1) the delegate's later phases -- the third-vector
partition loop (loop #1), the vecB loop with its UTF-8 ':' scan, the
sub-vector partition loop (loop #2), temp assembly and the epilogue
that frees both call-local hash sets; (2) the transform gate's
insert-or-find rule -- hash, hashbrown probe, found (copy freed,
return 1) versus missed (copy inserted, return 0); (3) the caller
census -- the exit reader 0x4749ab0 is the delegate's sole caller in
the whole binary (zero direct calls, one slot call), so the non-empty
third-vector case has no live caller in node 115; (4) the consumer
exit block -- the {6, ...} discriminant arm versus the verbatim
0x50-byte copy to the destination at [rsp+0x278], with nothing
re-reading the out struct before the assertion arm.
Static evidence only; no captured code is executed.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export, require

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'

DELEGATE, DELEGATE_END = 0x4748500, 0x4749aa9
DELEGATE_SHA = '7b1d3b86c285b089e030cba72aa9fc2b71cba2009d2849c91ec06977ea9b2691'
GATE, GATE_END = 0x474ba60, 0x474bcd3
GATE_SHA = '4527e1e0d1ad267cdd6951f2eb2898a962a2124d6096038fd63087ea43637d44'
READER, READER_END = 0x4749ab0, 0x4749d71
READER_SHA = '6f4caa139b97d81e99776e8cf0f570c906c02c5133d755baec41104d77e9b0bb'
HASHFN, HASHFN_END = 0x4744490, 0x47445fb
HASHFN_SHA = 'a63e8df74f90feb19a2edfb54c63f81974bac2b7c325c363bc7fe23f9c757f62'
SET_INIT, SET_INIT_END = 0x4743990, 0x4743ff0
SET_INIT_SHA = 'eeac52dec8e29f0c1c3084ba80545a9b551b44c69b974a60f2220d564f961eef'
CONSUMER, CONSUMER_END = 0x15a3b90, 0x15a6509
EXIT_START, EXIT_END = 0x15a58f2, 0x15a5981
SENTINEL = 0x8000000000000000

OWNERS = {
    'merge_delegate': (DELEGATE, DELEGATE_END, DELEGATE_SHA),
    'transform_gate': (GATE, GATE_END, GATE_SHA),
    'exit_reader': (READER, READER_END, READER_SHA),
    'hash_fn': (HASHFN, HASHFN_END, HASHFN_SHA),
    'set_init': (SET_INIT, SET_INIT_END, SET_INIT_SHA),
}
BOUNDARIES = {
    'destroy_rem_a': (
        0x47536c0, 0x475376c,
        'e3c793207685fccbf4993b8cbda1ac1b5d2c86bf2736c52186e02099d68ebc5c'),
    'destroy_rem_b': (
        0x4753770, 0x4753864,
        '95719dc118a1c123f82dd721aeba0f0488383549aa9e0cedeb045c851c246e98'),
    'drop10_subvec': (
        0x474e8a0, 0x474e98b,
        '21ec3b9046cb0e2e6cd091e7d20552f94cbe40a9da2ab582c98111a771b7417e'),
    'entry_vec_grow': (
        0x474e490, 0x474e4f4,
        'fe1531d90ea4cec8186fadce65b5b41958fc149a15603278e5d6afe7179123f3'),
    'vec40_grow': (
        0x474e420, 0x474e484,
        '447b3ab590a04170647c65d904bb5f18f8239c675c6f2d8f51fa1617f0f604d8'),
    'vec18_grow': (
        0x5c8b150, 0x5c8b1b7,
        '6555ee2a1d59fa37dbfe2f43e79c149a4322d1ab07a887b5e507ad4773fd23ae'),
    'assert_entry': (
        0x1680c30, 0x1680c82,
        '2d00fd36dc6102ab0738e08907482bb818bca6e76e32a5b941eabf431f20767a'),
    'descriptor_stub': (
        0x4747850, 0x4747861,
        'b377569e096d02820d07e894b96aca22d53b82d28b4af6a319a0cf1785eb76e9'),
}
WINDOWS = [
    ('delegate_loop1', 0x4748888, 0x4748be7),
    ('delegate_vecb', 0x4748c47, 0x4749074),
    ('delegate_loop2', 0x4749079, 0x474945d),
    ('delegate_temp_epilogue', 0x474945d, 0x47496ea),
    ('consumer_exit', EXIT_START, EXIT_END),
]
FULL_EXPORTS = [
    ('transform_gate', GATE, GATE_END),
]

DELEGATE_PINS = {
    'vec_a_sentinel': (0x474868f,
                       b'H\xb8\x00\x00\x00\x00\x00\x00\x00\x80'),
    'gate_call_a': (0x4748742, b'\xe8\x19\x33\x00\x00'),
    'entry_tag0': (0x4748772, b'H\xc7\x04\x08\x00\x00\x00\x00'),
    'loop1_head': (0x4748888, b'H\x8b\x84$\xa8\x00\x00\x00'),
    'loop1_sentinel': (0x474893e,
                       b'H\xb8\x00\x00\x00\x00\x00\x00\x00\x80'),
    'loop1_writeback': (0x4748b9d, b'H\x8b\x84$\xa8\x00\x00\x00'),
    'loop1_writeback_cap': (0x4748bb1, b'H\x85\xc0'),
    'vecb_head': (0x4748c47, b'H\x8b\x84$@\x02\x00\x00'),
    'vecb_setup_template1': (0x4748c1d, b'\x0f\x10\x05'),
    'vecb_setup_template2': (0x4748c29, b'\x0f\x10\x05'),
    'vecb_term6': (0x4748d0b, b'H\x83\xf9\x06'),
    'gate_call_b': (0x4748dae, b'\xe8\xad\x2c\x00\x00'),
    'scan_entry': (0x4748e10, b'M\x85\xed'),
    'scan_end': (0x4748e19, b'K\x8d\x04\x2e'),
    'scan_empty': (0x4748efc, b'M\x89\xf7'),
    'scan_path_b': (0x4748f19, b'M\x85\xed'),
    'scan_path_a': (0x4748f49, b'M\x85\xed'),
    'scan_path_c': (0x4748f79, b'M\x85\xed'),
    'subvec_cleanup': (0x474900b, b'L\x8b\x6c$\x08'),
    'loop2_entry': (0x4749079, b'L\x89\xb4$\x68\x02\x00\x00'),
    'loop2_writeback': (0x474940d, b'H\x8b\x84$\x10\x01\x00\x00'),
    'loop2_to_append': (0x4749444, b'\x0f\x85\x53\xf8\xff\xff'),
    'vecb_end': (0x474945d, b'H\x8d\xbc$\xf0\x01\x00\x00'),
    'temp_count': (0x47494d6, b'H\x89\x41\x60'),
    'temp_header': (0x47494df, b'\x0f\x11\x41\x50'),
    'epi_set_b': (0x474952c, b'H\x8b\\\x24\x68'),
    'epi_set_a': (0x4749607, b'H\x8b\x9c$\x28\x01\x00\x00'),
    'epi_ret': (0x47496ea, b'H\x8b\x84$\x18\x01\x00\x00'),
}
GATE_PINS = {
    'gate_init_cmp': (0x474ba86, b'H\x83\x7b\x10\x00'),
    'gate_seed': (0x474ba77, b'L\x8d\x67\x20'),
    'gate_base': (0x474ba91, b'L\x8b\x0b'),
    'gate_index': (0x474bacf, b'I\x21\xf7'),
    'gate_found': (0x474bbda, b'H\x8b\x44$\x08'),
    'gate_found_len': (0x474bbdf, b'H\x8b\x30'),
    'gate_found_free': (0x474bbf2, b'\xff\x15\xa8\x38\xd9\x01'),
    'gate_insert_ctrl': (0x474bbfa, b'C\x0f\xb6\x04\x01'),
    'gate_insert_bucket': (0x474bc50, b'K\x8d\x04\x40'),
    'gate_insert_store': (0x474bc5e, b'f\x0f\x6f\x44$\x40'),
    'gate_insert_ret0': (0x474bc6b, b'1\xdb'),
    'gate_init_call': (0x474bc91, b'\xff\x15\xf1\xf2\xd9\x01'),
}
CONSUMER_EXIT_PINS = {
    'exit_empty_cap': (0x15a58fd, b'H\xc7\x84$\xd0\x00\x00\x00\x08\x00\x00\x00'),
    'exit_empty_len': (0x15a5909,
                       b'H\xc7\x84$\xd8\x00\x00\x00\x00\x00\x00\x00'),
    'exit_disc_cmp': (0x15a5930, b'\x83\x7c\x24\x20\x06'),
    'exit_dest_load': (0x15a5940, b'H\x8b\x84$\x78\x02\x00\x00'),
    'exit_copy_high': (0x15a5948, b'\x0f\x11@@'),
    'exit_copy_low': (0x15a596c, b'\x0f\x11\x00'),
}
SLOT_CALL_PINS = {
    'delegate_call': (0x4749ac9, 0x64eafd8),
    'gate_init_call': (0x474bc91, 0x64eaf88),
    'gate_found_free': (0x474bbf2, 0x64df4a0),
    'exit_reader_call': (0x15a592a, 0x64e1480),
}
CALL_CENSUS_TARGETS = {
    'merge_delegate': 0x4748500,
    'transform_gate': 0x474ba60,
    'exit_reader': 0x4749ab0,
}
SLOT_CALL_CENSUS = {
    'merge_delegate_slot': 0x64eafd8,
    'exit_reader_slot': 0x64e1480,
    'set_init_slot': 0x64eaf88,
}
DESCRIPTOR_SLOTS = (0x64950f0, 0x64950f8, 0x6495100, 0x6495108,
                    0x6495110, 0x6495118)
DESCRIPTOR_RELOCS = {0x64950f0: 0x4747850, 0x64950f8: 0x450150,
                     0x6495118: 0x4354fc}


def read(data, va, n):
    for s in sections(data):
        if s['type'] != 8 and s['address'] <= va < s['address'] + s['size']:
            off = s['offset'] + va - s['address']
            if off + n > s['offset'] + s['size']:
                break
            return off, data[off:off + n]
    raise ValueError(f'unmapped {va:#x}')


def _pin(data, site, expected, label):
    if read(data, site, len(expected))[1] != expected:
        raise ValueError(f'{label} changed')


def _pins(data, table, role):
    for label, (site, expected) in table.items():
        _pin(data, site, expected, f'{role} {label}')


def _slot_call(data, site, slot, label):
    raw = read(data, site, 6)[1]
    require(raw[:2] in (b'\xff\x15', b'\xff%'),
            f'{label} is not a slot call')
    disp = struct.unpack('<i', raw[2:])[0]
    require(site + 6 + disp == slot, f'{label} slot changed')


def _relocations(data):
    s = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    out = {}
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        offset, info, addend = struct.unpack_from('<QQq', data, off)
        out[offset] = {'type': info & 0xffffffff,
                       'symbol': info >> 32, 'addend': addend}
    return out


def _dynsym_name(data, index):
    ds = next(s for s in sections(data) if s['name'] == '.dynsym')
    dstr = next(s for s in sections(data) if s['name'] == '.dynstr')
    name_off = struct.unpack_from('<I', data, ds['offset'] + index * 24)[0]
    start = dstr['offset'] + name_off
    return data[start:data.index(b'\0', start)].decode()


def slot_bindings(data):
    rel = _relocations(data)
    wanted = {
        'merge_delegate': 0x64eafd8, 'exit_reader': 0x64e1480,
        'entry_vec_grow': 0x64eafe0, 'vec40_grow_a': 0x64e1470,
        'vec40_grow_b': 0x64e1478, 'vec18_grow': 0x64e0c10,
        'set_init': 0x64eaf88, 'alloc': 0x64df480,
        'dealloc': 0x64df4a0, 'assert_entry': 0x64df6a0,
        'memcpy': 0x64df508, 'memcmp_bcmp': 0x64df9f8,
    }
    out = {}
    for name, slot in wanted.items():
        entry = rel[slot]
        row = {'slot': hex(slot), 'type': entry['type'],
               'addend': hex(entry['addend'])}
        if entry['type'] == 6:
            row['symbol'] = _dynsym_name(data, entry['symbol'])
        out[name] = row
    return out


def descriptor_template(data):
    rel = _relocations(data)
    out = {}
    for slot in DESCRIPTOR_SLOTS:
        off, raw = read(data, slot, 8)
        value = struct.unpack('<Q', raw)[0]
        row = {'file_qword': hex(value)}
        if slot in rel:
            row['reloc_type'] = rel[slot]['type']
            row['reloc_addend'] = hex(rel[slot]['addend'])
        out[hex(slot)] = row
    for slot, addend in DESCRIPTOR_RELOCS.items():
        row = out[hex(slot)]
        if row.get('reloc_type') != 8 or row.get('reloc_addend') != hex(addend):
            raise ValueError(f'descriptor reloc changed at {slot:#x}')
    for slot in (0x6495100, 0x6495108, 0x6495110):
        if out[hex(slot)]['file_qword'] != '0x0':
            raise ValueError(f'descriptor template word changed at {slot:#x}')
    off, raw = read(data, 0x450150, 16)
    if raw != b'\xff' * 16:
        raise ValueError('template table control prefix changed')
    off, raw = read(data, 0x4354fc, 16)
    if raw != b'/rustc/59807616e':
        raise ValueError('template name pointer target changed')
    out['template_base_control_prefix'] = read(data, 0x450150, 32)[1].hex()
    out['template_name_prefix'] = read(data, 0x4354fc, 64)[1].decode()
    return out


def direct_call_census(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, raw = sec['address'], data[sec['offset']:sec['offset'] + sec['size']]
    _, fs, _ = fde_extents(data)
    starts = sorted(f['start'] for f in fs)
    by_start = {f['start']: f for f in fs}
    found = {name: [] for name in CALL_CENSUS_TARGETS}
    wanted = {v: k for k, v in CALL_CENSUS_TARGETS.items()}
    i = raw.find(b'\xe8')
    while i != -1:
        if i + 5 <= len(raw):
            rel = struct.unpack_from('<i', raw, i + 1)[0]
            target = base + i + 5 + rel
            if target in wanted:
                j = bisect.bisect_right(starts, base + i) - 1
                owner = None
                if j >= 0:
                    f = by_start[starts[j]]
                    if f['start'] <= base + i < f['end']:
                        owner = [hex(f['start']), hex(f['end'])]
                found[wanted[target]].append(
                    {'site': hex(base + i), 'owner_fde': owner})
        i = raw.find(b'\xe8', i + 1)
    return {name: {'target': hex(CALL_CENSUS_TARGETS[name]),
                   'sites': [r['site'] for r in rows], 'rows': rows}
            for name, rows in found.items()}


def slot_call_census(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, raw = sec['address'], data[sec['offset']:sec['offset'] + sec['size']]
    _, fs, _ = fde_extents(data)
    starts = sorted(f['start'] for f in fs)
    by_start = {f['start']: f for f in fs}
    found = {name: [] for name in SLOT_CALL_CENSUS}
    wanted = {v: k for k, v in SLOT_CALL_CENSUS.items()}
    i = raw.find(b'\xff\x15')
    while i != -1:
        if i + 6 <= len(raw):
            disp = struct.unpack_from('<i', raw, i + 2)[0]
            target = base + i + 6 + disp
            if target in wanted:
                j = bisect.bisect_right(starts, base + i) - 1
                owner = None
                if j >= 0:
                    f = by_start[starts[j]]
                    if f['start'] <= base + i < f['end']:
                        owner = [hex(f['start']), hex(f['end'])]
                found[wanted[target]].append(
                    {'site': hex(base + i), 'owner_fde': owner})
        i = raw.find(b'\xff\x15', i + 1)
    return {name: {'slot': hex(SLOT_CALL_CENSUS[name]),
                   'sites': [r['site'] for r in rows], 'rows': rows}
            for name, rows in found.items()}


def analyze(data):
    bindings = slot_bindings(data)
    _pins(data, DELEGATE_PINS, 'merge_delegate')
    _pins(data, GATE_PINS, 'transform_gate')
    _pins(data, CONSUMER_EXIT_PINS, 'consumer_exit')
    for label, (site, slot) in SLOT_CALL_PINS.items():
        _slot_call(data, site, slot, label)
    if bindings['merge_delegate']['addend'] != '0x4748500':
        raise ValueError('merge delegate slot binding changed')
    if bindings['exit_reader']['addend'] != '0x4749ab0':
        raise ValueError('exit reader slot binding changed')
    if bindings['entry_vec_grow']['addend'] != '0x474e490':
        raise ValueError('entry vector grow slot binding changed')
    if bindings['vec40_grow_a']['addend'] != '0x474e420' or \
            bindings['vec40_grow_b']['addend'] != '0x474e420':
        raise ValueError('vec40 grow slot binding changed')
    if bindings['vec18_grow']['addend'] != '0x5c8b150':
        raise ValueError('vec18 grow slot binding changed')
    if bindings['set_init']['addend'] != '0x4743990':
        raise ValueError('set init slot binding changed')
    if bindings['alloc']['addend'] != '0x6355830':
        raise ValueError('alloc slot binding changed')
    if bindings['dealloc']['addend'] != '0x635de30':
        raise ValueError('dealloc slot binding changed')
    if bindings['assert_entry']['addend'] != '0x1680c30':
        raise ValueError('assert slot binding changed')
    if bindings['memcpy'].get('symbol') != 'memcpy':
        raise ValueError('memcpy slot binding changed')
    if bindings['memcmp_bcmp'].get('symbol') != 'bcmp':
        raise ValueError('memcmp slot binding changed')
    template = descriptor_template(data)
    census = direct_call_census(data)
    if census['merge_delegate']['sites'] != []:
        raise ValueError('direct delegate caller appeared')
    if census['transform_gate']['sites'] != ['0x4748742', '0x4748dae']:
        raise ValueError('gate direct call census changed')
    if census['exit_reader']['sites'] != []:
        raise ValueError('direct exit reader caller appeared')
    slot_census = slot_call_census(data)
    if slot_census['merge_delegate_slot']['sites'] != ['0x4749ac9']:
        raise ValueError('delegate slot call census changed')
    if slot_census['exit_reader_slot']['sites'] != ['0x15a592a']:
        raise ValueError('exit reader slot call census changed')
    if slot_census['set_init_slot']['sites'] != ['0x474bc91']:
        raise ValueError('set init slot call census changed')
    _, fs, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs}

    def frame_records(a, b, sha, role):
        if (a, b) not in fdes:
            raise ValueError(f'{role} scope FDE changed')
        offset, raw = read(data, a, b - a)
        digest = hashlib.sha256(raw).hexdigest()
        if sha is not None and digest != sha:
            raise ValueError(f'{role} body changed')
        records = {}
        for kind in ['fde', 'cie']:
            va = fdes[(a, b)][kind]
            n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
            records[kind] = {'va': hex(va),
                             'bytes_hex': read(data, va, n)[1].hex()}
        return {'role': role, 'start': hex(a), 'end': hex(b),
                'file_offset': hex(offset), 'bytes': b - a,
                'sha256': digest, 'frames': records}

    owners = []
    for role, (a, b, sha) in OWNERS.items():
        owners.append(frame_records(a, b, sha, role))
    boundaries = []
    for role, (a, b, sha) in BOUNDARIES.items():
        boundaries.append(frame_records(a, b, sha, role))
    return {
        'target_sha256': SHA, 'owners': owners, 'boundaries': boundaries,
        'slot_bindings': bindings, 'descriptor_template': template,
        'direct_calls': census, 'slot_calls': slot_census,
        'delegate_verdict':
            'Phase A (vecA, 0x47485d4..0x474885a): each 0x40-byte '
            'element whose word0 is not the sentinel '
            '0x8000000000000000 is staged, its string copied via '
            'alloc (slot 0x64df480) + memcpy (slot 0x64df508) for '
            'the gate call only, and gated through 0x474ba60 '
            'against set A (frame [rsp+0x120]).  Gate-true '
            '(string already present) appends a 0x20-byte entry '
            '{0, word0, original string pointer, length} to the '
            'entry vector (grow 0x474e490 via slot 0x64eafe0); '
            'gate-false (newly inserted) copies the staged '
            'element verbatim into the rejected vector at frame '
            '[rsp+0xb8] (0x40 entries, grow 0x474e420).  After the '
            'loop, helper 0x47536c0 destroys the remaining vecA '
            'elements [cursor, end).  Phase B (third-vector loop '
            '#1, 0x4748888..0x4748be7): each 0x18-byte element '
            '{size, string pointer, string length} of the third '
            'argument P\'s vector is partitioned by read-only '
            'membership in set A (hash via 0x4744490 with the '
            'saved TLS seed, SIMD group probe, length + bcmp '
            'confirm; bucket records addressed at base - 24*index '
            'as {len, pointer, len}): member -> verbatim 0x18-byte '
            'entry into the found vector at frame [rsp+0xd0] '
            '(grow 0x5c8b150 via slot 0x64e0c10); non-member -> '
            'tag-1 entry {1, word0, word1, word2} into the entry '
            'vector.  Sentinel word0 == 0x8000000000000000 '
            'terminates; post-sentinel elements\' allocations are '
            'freed.  Then P\'s vector is REPLACED by the found '
            'vector (old buffer freed at cap*0x18 when cap != 0; '
            'header written to P+8, count to P+0x18).  Phase C '
            '(vecB, 0x4748c47..0x474945d): each 0x40-byte element '
            'whose word0 is not 6 is staged (string at +0x10/+0x18) '
            'and gated through 0x474ba60 against set B (frame '
            '[rsp+0x60], reloaded from the same template at '
            '0x4748c1d/0x4748c29).  Gate-true appends a tag-2 entry '
            '{2, element+0x8, element+0x10, element+0x18}; '
            'gate-false runs the UTF-8 \':\' scan (see scan '
            'verdict).  Normal loop end (6-terminator or cursor == '
            'end) calls helper 0x4753770 to destroy remaining '
            'vecB elements, then temp assembly.  Phase D '
            '(sub-vector loop #2, 0x4749079..0x474940d, reached '
            'only from scan path (d)): the CURRENT vecB element\'s '
            'sub-vector (0x18 elements at staged+0x28/+0x30) is '
            'partitioned by the same read-only set-A rule: member '
            '-> verbatim 0x18 entry into the found vector at frame '
            '[rsp+0x100]; non-member -> tag-1 entry into the entry '
            'vector; sentinel terminates; post-sentinel '
            'allocations freed.  The element\'s sub-vector fields '
            'are then REPLACED by the found vector, and the whole '
            'staged 0x40-byte element is appended to the 0xe8 '
            'vector (0x40 entries, grow 0x474e420 via slot '
            '0x64e1478); the function proceeds to temp assembly '
            'and does NOT return to the vecB loop.  Temp assembly '
            '(0x474940d..0x4749528): temp+0x00..0x10 = P\'s first 16 '
            'bytes (leading word + post-write-back vec cap); '
            'temp+0x10..0x20 = P vec buffer + count; temp+0x20..0x30 '
            '= rejected-vecA cap + buffer; temp+0x30..0x40 = '
            'rejected-vecA count + 0xe8 cap; temp+0x40 = 0xe8 '
            'buffer; temp+0x48 = 0xe8 count; temp+0x50..0x60 = '
            'entry-vector cap + buffer; temp+0x60 = entry-vector '
            'count.  Epilogue (0x474952c..0x47496ea): frees set B\'s '
            'table (bucket strings at record word1 with size '
            'record word0, then the table allocation sized from '
            'the mask), then set A\'s table the same way, then '
            'returns.  Both sets are therefore call-local heap '
            'state, not persistent across calls.',
        'gate_verdict':
            'Transform gate 0x474ba60 (627 bytes): args rdi = set '
            'descriptor {table base, mask, init flag, name '
            'pointer}, rsi = &{len, copy pointer, len}.  If the '
            'init flag (descriptor+0x10) is 0, the set initializer '
            '0x4743990 is called through slot 0x64eaf88 with '
            '(descriptor, 1, descriptor+0x20 = saved TLS seed, 1) '
            'and the probe retries.  The string is hashed by '
            '0x4744490 (seed = descriptor+0x20\'s 16 bytes, the '
            'saved thread-local block); the probe is hashbrown '
            'style: h2 = hash >> 57, bucket index = hash & mask, '
            '16-byte control-group compare (pcmpeqb/pmovmskb/'
            'tzcnt), candidate confirmed by length then bcmp '
            '(slot 0x64df9f8, bcmp@GLIBC_2.2.5).  FOUND -> the '
            'caller\'s copy is freed through the dealloc slot '
            'with (copy pointer, len, 0) and the gate returns 1 '
            '(TRUE).  NOT FOUND -> the copy is INSERTED into the '
            'set (h2 byte written to the control byte and its '
            'wrapped mirror, counter adjusted, 24-byte bucket '
            'record {len, copy pointer, len} stored at base - '
            '24*index) and the gate returns 0 (FALSE).  The gate '
            'is therefore a test-and-insert: TRUE means the string '
            'was already present (a duplicate), FALSE means it is '
            'a first occurrence now owned by the set.  The '
            'delegate\'s entry vectors reference the ORIGINAL '
            'record strings, never the gate\'s copies.',
        'scan_verdict':
            'VecB gate-false \':\' scan (0x4748e10..0x4748f79): '
            'scans the element\'s string codepoint by codepoint '
            'with a full UTF-8 decode (1/2/3/4-byte arms), '
            'tracking a colon-run state: on \':\' with count >= 2 '
            '-> exit (a); on non-\':\' with count == 1 -> exit (b); '
            'string ends immediately after \':\' (count 1 or 2) -> '
            'exit (c); string ends after a non-\':\' codepoint with '
            'count in {0, 2} -> exit (d).  Exits (a), (b) and (c) '
            'each alloc+memcpy a fresh copy of the WHOLE string '
            'and append a tag-3 entry {3, word0, fresh copy, '
            'length} to the entry vector, then destroy the '
            'element\'s sub-vector (helper 0x474e8a0 drops the '
            '0x10-stride sub-vector at element+0x18/+0x20) and '
            'continue the vecB loop.  Exit (d) appends NO tag-3 '
            'entry: control enters loop #2 and the vecB loop is '
            'abandoned.  Zero-length strings take a tag-3 entry '
            'with pointer 1 (empty-string dangling sentinel) via '
            '0x4748efc.  In run-length terms: (a) = a run of >= 3 '
            'colons, (b) = a run of exactly 1 colon followed by a '
            'non-colon, (c) = the string ends with a colon, (d) = '
            'every colon run has length exactly 2 and the string '
            'does not end with a colon.  Reading (d) as a '
            'well-formedness check for "::"-separated strings is '
            'interpretation; the state machine above is the '
            'pinned fact.',
        'caller_verdict':
            'The exit reader 0x4749ab0 is the delegate\'s SOLE '
            'caller in node 115: zero direct E8 calls to '
            '0x4748500 anywhere in .text, and exactly one slot '
            'call through 0x64eafd8, at 0x4749ac9 inside the '
            'reader (verified additionally by a full-binary '
            'objdump grep for rip-relative references to '
            '0x64eafd8, which returns only 0x4749ac9).  The gate '
            'is likewise called only from the delegate, at '
            '0x4748742 (vecA) and 0x4748dae (vecB).  The reader '
            'itself is called only through slot 0x64e1480, at '
            '0x15a592a in the consumer exit block, with the '
            'consumer\'s empty {0, 8, 0} third vector.  Therefore '
            'the non-empty third-vector case has NO live caller '
            'in this binary: loop #1 iterates an empty vector, '
            'its write-back writes an empty found vector over an '
            'already-empty P vector, and the write-back is '
            'unobservable on the only call path.  The third-vector '
            'merge rule above is traced statically from the '
            'delegate body, not observed from a live caller.',
        'exit_verdict':
            'On the consumer-exit path the consumer builds the '
            'empty third vector {0, 8, 0} at [rsp+0xc0] and calls '
            'the exit reader 0x4749ab0 through slot 0x64e1480 '
            'with rdi = &[rsp+0x20] (out), rsi = &[rsp+0x240] '
            '(saved pair), rdx = &[rsp+0xc0].  The reader calls '
            'the delegate through slot 0x64eafd8 to fill its '
            '0x68-byte temp; if temp+0x60 (entry count) is '
            'non-zero it writes out = {6, temp+0x50, temp+0x58, '
            'temp+0x60} and destroys the temp\'s pair copy inline, '
            'else it copies temp[0..0x50] verbatim to out and '
            'frees only the entry-vector buffer.  Back in the '
            'consumer, out word == 6 branches to the assertion arm '
            'at 0x15a5b8c (slot 0x64df6a0, target 0x1680c30); '
            'otherwise the consumer copies the 0x50-byte out '
            'struct to the destination pointer loaded from '
            '[rsp+0x278] and returns.  Between the reader call and '
            'the assertion arm, the consumer reads only the out '
            'discriminant word itself and the destination pointer: '
            'no later phase re-reads the out struct before the '
            'assertion arm, and the {6, ...} form never reaches '
            'the destination copy.',
        'limits':
            'Static trace only.  The hash function 0x4744490, the '
            'set initializer 0x4743990, the destroy-remaining '
            'helpers 0x47536c0 / 0x4753770, the sub-vector drop '
            '0x474e8a0, the grow functions and the assertion entry '
            '0x1680c30 are hash-pinned boundaries, not traced.  '
            'Whether the set initializer copies the .rodata '
            'template table image at 0x450150 or starts empty is '
            'NOT established: the template\'s nominal base points '
            'into read-only .rodata, so the initializer must '
            'replace it with heap storage before any insert, but '
            'its exact allocation/copy behavior is untraced.  The '
            'meaning of the entry tags 0/1/2/3 downstream (what '
            'consumes the 0x50-byte out struct versus the {6, ...} '
            'form, and what the destination at [rsp+0x278] does '
            'with it) is not claimed.  The "::"-separated reading '
            'of scan path (d) is interpretation.  No captured code '
            'executed, no runtime value or reconstruction gate is '
            'claimed.',
        'next_question':
            'What does the set initializer 0x4743990 do with the '
            '.rodata template table image at 0x450150 -- copy it '
            'to the heap as the set\'s initial contents, or start '
            'empty -- and what strings, if any, does the initial '
            'table hold?  What consumes the entry tags 0/1/2/3 '
            'downstream of the reader (the 0x50-byte out struct '
            'versus the {6, ...} form, and the destination object '
            'at [rsp+0x278])?'}


def _objdump(path, start, end):
    return subprocess.check_output(
        ['objdump', '-d', '-M', 'intel', '--insn-width=16',
         f'--start-address={start:#x}', f'--stop-address={end:#x}',
         str(path)], text=True)


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('expected pinned node115')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    lines = []
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node115.elf'
        snapshot.write_bytes(data)
        native = subprocess.check_output(['readelf', '-wf', str(snapshot)],
                                         text=True)
        for role, (a, b, _) in list(OWNERS.items()) + \
                list(BOUNDARIES.items()):
            rows = [l for l in native.splitlines()
                    if f'pc={a:016x}..{b:016x}' in l]
            if len(rows) != 1:
                raise ValueError('native FDE disagreement')
            lines.extend(rows)
        for name, wa, wb in WINDOWS:
            wasm = _objdump(snapshot, wa, wb)
            decode_export(wasm, wa, wb, read(data, wa, wb - wa)[1])
            (output / f'{name}_window_{wa:x}_{wb:x}_objdump.txt'
             ).write_bytes(wasm.replace(
                 str(snapshot), '<authenticated-node115>').encode('utf-8'))
        for name, a, b in FULL_EXPORTS:
            easm = _objdump(snapshot, a, b)
            eins = decode_export(easm, a, b, read(data, a, b - a)[1])
            esites = {site for site, _ in GATE_PINS.values()}
            if not esites <= set(eins):
                raise ValueError(f'{name} evidence site not native '
                                 'instruction start')
            (output / f'{name}_objdump.txt').write_bytes(
                easm.replace(str(snapshot),
                             '<authenticated-node115>').encode('utf-8'))
    (output / 'frames.txt').write_bytes(
        ('\n'.join(lines) + '\n').encode('utf-8'))
    (output / 'records.json').write_bytes(
        (json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--output', type=Path,
                   default=ROOT / 'work/merge-delegate115')
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['owners']),
                      'bytes': sum(x['bytes'] for x in report['owners']),
                      'executed': False}))
