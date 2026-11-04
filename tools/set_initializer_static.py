#!/usr/bin/env python3
"""Pin the RE-015 set initializer's treatment of the .rodata template
table image in node 115.

Question (the first half of the recorded next question of the
merge-delegate packet, RE-015-node115-merge-delegate / PR #2615): what
does the set initializer 0x4743990 do with the .rodata template table
image at 0x450150 -- copy it to the heap as the set's initial contents,
or start empty -- and what strings, if any, does the initial table
hold?

The packet pins: (1) the initializer body 0x4743990..0x4743ff0 -- a
hashbrown-style reserve/rehash routine reached from the transform gate
through slot 0x64eaf88 with (descriptor, 1, &seed, 1) whenever the
descriptor's +0x10 word is 0; (2) the live first-init trace for the
delegate's two sets, whose frame descriptors are copied from the
.data.rel.ro template at 0x64950f8 ({ctrl = 0x450150, mask = 0,
growth = 0, items = 0}, seed saved at +0x20): needed = 1 exceeds
capacity 0, so the function allocates a fresh 116-byte heap table
(4 buckets x 24 bytes + 20 control bytes), memsets the control bytes
to 0xFF (EMPTY), skips the record-move loop because items == 0,
writes back {new ctrl, mask 3, growth_left 3, items 0}, and does NOT
free the old ctrl because the old mask is 0 (the static is unowned);
(3) the structural no-copy fact: the body contains no memcpy call at
all and its only bulk writes are the 0xFF memset on the grow path and
a memmove control-mirror refresh on the in-place arm -- no byte of
the .rodata image is ever a copy source; (4) the image itself: the
bytes at 0x450150 are a binary-wide shared empty-control static (62
RELATIVE relocations use it as addend), its first control byte is
0xFF (EMPTY), there are no bucket records and no relocated string
pointers anywhere in [0x450000, 0x450200), so the initial table
holds no strings -- the set starts empty.  Static evidence only; no
captured code is executed.
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

INIT, INIT_END = 0x4743990, 0x4743ff0
INIT_SHA = 'eeac52dec8e29f0c1c3084ba80545a9b551b44c69b974a60f2220d564f961eef'
HASHFN, HASHFN_END = 0x4744490, 0x47445fb
HASHFN_SHA = 'a63e8df74f90feb19a2edfb54c63f81974bac2b7c325c363bc7fe23f9c757f62'
DELEGATE, DELEGATE_END = 0x4748500, 0x4749aa9
DELEGATE_SHA = '7b1d3b86c285b089e030cba72aa9fc2b71cba2009d2849c91ec06977ea9b2691'

OWNERS = {
    'set_initializer': (INIT, INIT_END, INIT_SHA),
}
BOUNDARIES = {
    'hash_fn': (HASHFN, HASHFN_END, HASHFN_SHA),
    'merge_delegate': (DELEGATE, DELEGATE_END, DELEGATE_SHA),
}

INIT_PINS = {
    'entry_items_load': (0x47439a6, b'H\x8bG\x18'),
    'entry_items_add': (0x47439aa, b'H\x01\xc6'),
    'mask_load': (0x47439b6, b'L\x8bw\x08'),
    'grow_branch': (0x47439e0, b'\x76\x29'),
    'bucket_size_24': (0x4743a85, b'\xb9\x18\x00\x00\x00'),
    'overflow_flag_test': (0x4743ac2, b'E\x84\xc0'),
    'memset_value_ff': (0x4743b1a, b'\xbe\xff\x00\x00\x00'),
    'items_count_load': (0x4743b5e, b'L\x8b\x69\x18'),
    'items_test': (0x4743b62, b'M\x85\xed'),
    'items_skip_move': (0x4743b65, b'\x0f\x84\xc7\x03\x00\x00'),
    'deleted_vector_load': (0x4743cb8,
                            b'f\x0f\x6f\x05\xc0\x12\xd1\xfb'),
    'writeback_ctrl': (0x4743f3e, b'L\x89!'),
    'writeback_mask': (0x4743f41, b'L\x89A\x08'),
    'writeback_growth': (0x4743f45, b'L\x89y\x10'),
    'writeback_items': (0x4743f49, b'H\x89A\x18'),
    'old_mask_test': (0x4743f4d, b'H\x85\xf6'),
    'old_free_skip': (0x4743f50, b'\x74\x2e'),
    'success_const': (0x4743f80,
                      b'H\xb8\x01\x00\x00\x00\x00\x00\x00\x80'),
    'panic_literal_load': (0x4743f8f, b'H\x8d=\xea}\xd5\xfb'),
    'fits_success_const': (0x4743ef6,
                           b'H\xb8\x01\x00\x00\x00\x00\x00\x00\x80'),
}
DELEGATE_PINS = {
    'tmpl_load_hi': (0x47485a0, b'\x0f\x10\x05\x61\xcb\xd4\x01'),
    'tmpl_load_lo': (0x47485af, b'\x0f\x10\x05\x42\xcb\xd4\x01'),
    'seed_store': (0x47485c7,
                   b'f\x0f\x7f\x84\x24\x40\x01\x00\x00'),
}
SLOT_CALL_PINS = {
    'init_alloc': (0x4743ad9, 0x64df480),
    'init_memset': (0x4743b22, 0x64df750),
    'init_memmove_mirror': (0x4743d1f, 0x64df568),
    'init_dealloc': (0x4743f7a, 0x64df4a0),
    'init_panic': (0x4743fa2, 0x64df6b8),
    'gate_init_call': (0x474bc91, 0x64eaf88),
}
# Every ff 15 slot call inside the initializer body, by site.
INIT_SLOT_CALLS = {
    0x4743ad9: 0x64df480, 0x4743b22: 0x64df750,
    0x4743d1f: 0x64df568, 0x4743f7a: 0x64df4a0,
    0x4743fa2: 0x64df6b8, 0x4743fb0: 0x64df490,
    0x4743fea: 0x64df4c0,
}
MEMCPY_SLOT = 0x64df508
# Direct E8 calls to the hash function inside the initializer body.
HASH_CALL_SITES = (0x4743be4, 0x4743d5d)

DESCRIPTOR_SLOTS = (0x64950f0, 0x64950f8, 0x6495100, 0x6495108,
                    0x6495110, 0x6495118)
DESCRIPTOR_RELOCS = {0x64950f0: 0x4747850, 0x64950f8: 0x450150,
                     0x6495118: 0x4354fc}
IMAGE_BASE = 0x450150
IMAGE_CTRL32 = ('ffffffffffffffffffffffffffffffff'
                'ffff0000ffff0000ffff0000ffff0000')
IMAGE_BELOW24 = ('1414141414141414'
                 'c4819385ca384900b9cd7895823b3623')
IMAGE_ADDEND_COUNT = 62
DELETED_CONST = 0x454f80
PANIC_LITERAL = 0x49bd80


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
        'set_init': 0x64eaf88, 'alloc': 0x64df480,
        'memset': 0x64df750, 'memmove': 0x64df568,
        'dealloc': 0x64df4a0, 'panic_entry': 0x64df6b8,
        'alloc_fail': 0x64df490, 'memcpy': MEMCPY_SLOT,
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
    return out


def template_image(data):
    rel = _relocations(data)
    ctrl32 = read(data, IMAGE_BASE, 32)[1]
    if ctrl32.hex() != IMAGE_CTRL32:
        raise ValueError('template image control bytes changed')
    below = read(data, IMAGE_BASE - 24, 24)[1]
    if below.hex() != IMAGE_BELOW24:
        raise ValueError('template image bucket-area bytes changed')
    located = sorted(hex(o) for o in rel
                     if 0x450000 <= o < 0x450200)
    if located:
        raise ValueError('relocation appeared inside the template image')
    addend_refs = sum(1 for e in rel.values()
                      if e['addend'] == IMAGE_BASE)
    if addend_refs != IMAGE_ADDEND_COUNT:
        raise ValueError('template image reference count changed')
    if read(data, DELETED_CONST, 16)[1] != b'\x80' * 16:
        raise ValueError('in-place DELETED vector changed')
    if read(data, PANIC_LITERAL, 28)[1] != b'Hash table capacity overflow':
        raise ValueError('capacity-overflow literal changed')
    return {
        'base': hex(IMAGE_BASE),
        'control32_hex': ctrl32.hex(),
        'first_control_byte': hex(ctrl32[0]),
        'bucket_area_below24_hex': below.hex(),
        'relocations_located_in_image_range': located,
        'binary_wide_addend_references': addend_refs,
        'deleted_vector_hex': read(data, DELETED_CONST, 16)[1].hex(),
        'panic_literal': 'Hash table capacity overflow',
    }


def body_call_census(data):
    _, raw = read(data, INIT, INIT_END - INIT)
    slot_calls = {}
    i = raw.find(b'\xff\x15')
    while i != -1:
        if i + 6 <= len(raw):
            disp = struct.unpack_from('<i', raw, i + 2)[0]
            slot_calls[INIT + i] = INIT + i + 6 + disp
        i = raw.find(b'\xff\x15', i + 1)
    if slot_calls != INIT_SLOT_CALLS:
        raise ValueError('initializer slot-call census changed')
    if MEMCPY_SLOT in slot_calls.values():
        raise ValueError('memcpy call appeared in the initializer')
    hash_sites = []
    i = raw.find(b'\xe8')
    while i != -1:
        if i + 5 <= len(raw):
            rel = struct.unpack_from('<i', raw, i + 1)[0]
            if INIT + i + 5 + rel == HASHFN:
                hash_sites.append(INIT + i)
        i = raw.find(b'\xe8', i + 1)
    if tuple(hash_sites) != HASH_CALL_SITES:
        raise ValueError('initializer hash-call census changed')
    return {
        'slot_calls': {hex(k): hex(v) for k, v in
                       sorted(slot_calls.items())},
        'memcpy_slot_called': False,
        'hash_direct_call_sites': [hex(s) for s in hash_sites],
    }


def buckets_to_capacity(buckets):
    """Mirror of the two capacity computations in the body
    (0x47439b6..0x47439d3 and 0x4743afe..0x4743b13): buckets <= 8
    yield buckets - 1, larger tables yield buckets - buckets // 8."""
    if buckets <= 8:
        return buckets - 1
    return buckets - buckets // 8


def first_init_trace():
    """The delegate's first gate use, traced through the body:
    descriptor {ctrl = 0x450150, mask = 0, growth_left = 0,
    items = 0}, additional = 1 (the gate's argument)."""
    items, additional, mask = 0, 1, 0
    needed = items + additional
    buckets_now = mask + 1
    if needed <= buckets_to_capacity(buckets_now):
        raise ValueError('first-init unexpectedly fits')
    new_buckets = 4
    bucket_bytes = (new_buckets * 24 + 15) & ~15
    ctrl_bytes = new_buckets + 16
    return {
        'input': {'ctrl': hex(IMAGE_BASE), 'mask': mask,
                  'growth_left': 0, 'items': items,
                  'additional': additional},
        'needed': needed,
        'capacity_before': buckets_to_capacity(buckets_now),
        'path': 'grow',
        'new_buckets': new_buckets,
        'alloc_size': bucket_bytes + ctrl_bytes,
        'bucket_bytes': bucket_bytes,
        'ctrl_bytes': ctrl_bytes,
        'ctrl_fill': '0xff (EMPTY), via memset slot 0x64df750',
        'records_moved': 0,
        'image_bytes_copied': 0,
        'writeback': {'ctrl': 'alloc + bucket_bytes',
                      'mask': new_buckets - 1,
                      'growth_left':
                          buckets_to_capacity(new_buckets) - items,
                      'items': items},
        'old_table_freed': False,
        'return': '0x8000000000000001',
    }


def analyze(data):
    bindings = slot_bindings(data)
    _pins(data, INIT_PINS, 'set_initializer')
    _pins(data, DELEGATE_PINS, 'merge_delegate')
    for label, (site, slot) in SLOT_CALL_PINS.items():
        _slot_call(data, site, slot, label)
    if bindings['set_init']['addend'] != '0x4743990':
        raise ValueError('set init slot binding changed')
    if bindings['alloc']['addend'] != '0x6355830':
        raise ValueError('alloc slot binding changed')
    if bindings['dealloc']['addend'] != '0x635de30':
        raise ValueError('dealloc slot binding changed')
    if bindings['panic_entry']['addend'] != '0x1680e80':
        raise ValueError('panic entry slot binding changed')
    if bindings['memset'].get('symbol') != 'memset':
        raise ValueError('memset slot binding changed')
    if bindings['memmove'].get('symbol') != 'memmove':
        raise ValueError('memmove slot binding changed')
    template = descriptor_template(data)
    image = template_image(data)
    census = body_call_census(data)
    trace = first_init_trace()
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
        'target_sha256': SHA, 'owners': owners,
        'boundaries': boundaries, 'slot_bindings': bindings,
        'descriptor_template': template, 'template_image': image,
        'call_census': census, 'first_init_trace': trace,
        'init_verdict':
            'Set initializer 0x4743990 (1632 bytes), called only '
            'through slot 0x64eaf88 from the transform gate at '
            '0x474bc91 with (descriptor, 1, descriptor+0x20 = saved '
            'TLS seed, 1) when the descriptor word at +0x10 is 0. '
            'Descriptor layout (hashbrown RawTableInner shape): '
            '+0x00 ctrl, +0x08 bucket mask, +0x10 growth_left, '
            '+0x18 items, +0x20 seed (16 bytes, used only as the '
            'hash argument).  The function computes needed = '
            'items + additional (0x47439a6/0x47439aa), compares it '
            'against the current capacity, and takes one of three '
            'arms.  GROW arm (needed above capacity): it sizes a '
            'new power-of-two bucket count (bucket record = 24 '
            'bytes, 0x4743a85), allocates (buckets*24 rounded up '
            'to 16) + (buckets + 16) bytes through the alloc slot '
            '0x64df480 (-> 0x6355830), places the control base at '
            'alloc + bucket_bytes, memsets the buckets + 16 '
            'control bytes to 0xFF = EMPTY through the memset slot '
            '0x64df750 (fill value pinned at 0x4743b1a), then -- '
            'only when items > 0 -- walks the OLD table\'s control '
            'bytes, rehashes each live record with 0x4744490 '
            '(seed = descriptor+0x20) and copies the 24-byte '
            'record into the new table (0x4743b70..0x4743c67); the '
            'items == 0 test at 0x4743b62/0x4743b65 skips that '
            'loop entirely.  Write-back (0x4743f3e..0x4743f49): '
            'descriptor = {new ctrl, new mask, capacity - items, '
            'items}; the old table is freed through the dealloc '
            'slot 0x64df4a0 only when the old mask is non-zero '
            '(0x4743f4d/0x4743f50), so a mask-0 static table is '
            'never freed.  Success returns 0x8000000000000001 '
            '(0x4743f80).  Capacity overflow branches on the '
            'caller flag byte: panic through slot 0x64df6b8 '
            '(-> 0x1680e80, literal "Hash table capacity '
            'overflow" at 0x49bd80) or a zero return.  FITS arm '
            '(needed within capacity, unreachable on a first '
            'init): no allocation; control bytes are normalized '
            'in place with the 0x80 DELETED vector at 0x454f80 '
            '(0x4743ca9..0x4743cee), the control mirror is '
            'refreshed with memmove (slot 0x64df568, its only '
            'call site 0x4743d1f), live records are re-probed '
            'and swapped within the same table, vacated slots '
            'are reset to 0xFF, and growth_left is recomputed '
            '(0x4743ef3..0x4743f00).  The body contains NO call '
            'through the memcpy slot 0x64df508 anywhere (call '
            'census pinned): nothing in this function bulk-copies '
            'the old table, on any arm.',
        'live_case_verdict':
            'The delegate builds both set descriptors by copying '
            '32 template bytes from 0x64950f8/0x6495108 into the '
            'frame (movups loads pinned at 0x47485a0/0x47485af) '
            'and storing the saved TLS seed at +0x20 '
            '(0x47485c7): the frame descriptor is {ctrl = '
            '0x450150, mask = 0, growth_left = 0, items = 0} -- '
            'the template word at 0x6495110 (frame +0x18) is the '
            'file value 0 with no relocation, NOT the name '
            'pointer (the name word at template 0x6495118 -> '
            '.rodata 0x4354fc is outside both 16-byte loads and '
            'never reaches the descriptor).  On the first gate '
            'use of each set the initializer therefore runs with '
            'items = 0, additional = 1: needed 1 > capacity 0, '
            'grow arm, new table of 4 buckets, allocation 116 '
            'bytes (96 bucket bytes + 20 control bytes), control '
            'bytes memset to 0xFF, move loop skipped, '
            'write-back {heap ctrl, mask 3, growth_left 3, '
            'items 0}, static not freed.  No byte of the '
            '.rodata image at 0x450150 is read as table data on '
            'this path -- the initializer reads only the four '
            'scalar descriptor words -- and nothing is copied '
            'from it on any path.',
        'image_verdict':
            'The nominal table image at 0x450150 holds no '
            'strings and no bucket records.  It is the '
            'binary-wide shared empty-control static: 62 '
            'RELATIVE relocations across the binary use '
            '0x450150 as their addend (this set\'s template slot '
            '0x64950f8 is one of them).  Its first 32 bytes are '
            '18 x 0xFF followed by the repeating 00 00 ff ff '
            'pattern of the adjacent statics; the mask-0 '
            'descriptor addresses exactly one bucket, whose '
            'control byte is 0xFF = EMPTY.  The 24 bytes below '
            'the base (where bucket record 0 would sit) are '
            'unrelated .rodata constants (0x14 filler and two '
            'non-pointer words), and there is no RELATIVE '
            'relocation located anywhere in [0x450000, '
            '0x450200) -- no record pointer, hence no initial '
            'string, exists in the image.  The set starts '
            'empty; its initial contents are the zero items '
            'the descriptor already declares.',
        'limits':
            'Static trace only.  The hash function 0x4744490 '
            'and the merge delegate 0x4748500 are hash-pinned '
            'boundaries, not re-traced.  The fits/in-place arm '
            'is traced at the level of its control-byte '
            'normalization, mirror refresh and write-back; its '
            'exact trigger predicate (a halved-capacity compare '
            'at 0x47439da..0x47439e0 and a small-table special '
            'case at 0x4743a14..0x4743a35) is recorded as '
            'observed code, not reduced to a closed form, and '
            'that arm is unreachable from the delegate\'s '
            'first-init path in any case.  The allocation-'
            'failure arm (slot 0x64df490 at 0x4743fb0, return '
            'constant 0x10 observed at 0x4743f2b on the '
            'zero-flag path) is pinned by site, not traced.  '
            'What consumes the entry tags 0/1/2/3 downstream '
            '(the second half of the parent packet\'s next '
            'question) is NOT addressed here.  No captured code '
            'executed, no runtime value or reconstruction gate '
            'is claimed.',
        'next_question':
            'What consumes the entry tags 0/1/2/3 downstream of '
            'the exit reader (the 0x50-byte out struct versus '
            'the {6, ...} form, and the destination object at '
            '[rsp+0x278])?  (Carried over unchanged from the '
            'merge-delegate packet; the set-initializer half of '
            'its next question is answered by this packet.)'}


def _objdump(path, start, end):
    return subprocess.check_output(
        ['objdump', '-d', '-M', 'intel', '--insn-width=16',
         f'--start-address={start:#x}', f'--stop-address={end:#x}',
         str(path)]).decode('utf-8')


def generate(binary, output):
    data = Path(binary).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('wrong node115 capture')
    report = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
            dir=output, suffix='.elf', delete=False) as handle:
        handle.write(data)
        snapshot = Path(handle.name)
    try:
        native = subprocess.check_output(
            ['readelf', '--debug-dump=frames-interp',
             str(snapshot)]).decode('utf-8')
        lines = []
        for role, (a, b, _) in list(OWNERS.items()) + \
                list(BOUNDARIES.items()):
            rows = [l for l in native.splitlines()
                    if f'pc={a:016x}..{b:016x}' in l]
            if len(rows) != 1:
                raise ValueError('native FDE disagreement')
            lines.extend(rows)
        easm = _objdump(snapshot, INIT, INIT_END)
        eins = decode_export(easm, INIT, INIT_END,
                             read(data, INIT, INIT_END - INIT)[1])
        esites = {site for site, _ in INIT_PINS.values()}
        if not esites <= set(eins):
            raise ValueError('set_initializer evidence site not '
                             'native instruction start')
        (output / 'set_initializer_objdump.txt').write_bytes(
            easm.replace(str(snapshot),
                         '<authenticated-node115>').encode('utf-8'))
        wasm = _objdump(snapshot, 0x47485a0, 0x47485d0)
        decode_export(wasm, 0x47485a0, 0x47485d0,
                      read(data, 0x47485a0, 0x47485d0 - 0x47485a0)[1])
        (output / 'delegate_entry_template_window_47485a0_47485d0'
                  '_objdump.txt').write_bytes(wasm.replace(
                      str(snapshot),
                      '<authenticated-node115>').encode('utf-8'))
    finally:
        snapshot.unlink()
    (output / 'frames.txt').write_bytes(
        ('\n'.join(lines) + '\n').encode('utf-8'))
    (output / 'records.json').write_bytes(
        (json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--output', type=Path,
                   default=ROOT / 'work/set-initializer115')
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['owners']),
                      'bytes': sum(x['bytes'] for x in report['owners']),
                      'executed': False}))
