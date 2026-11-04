#!/usr/bin/env python3
"""Pin the RE-015 map grow body 0x4742aa0 in node 115.

Question (carried by the map-insert packet
RE-015-node115-map-insert): the map insert 0x474b620 calls
the grow body through slot 0x64eaf78 with (map, 1, map+0x20,
1) when the growth-left word at map+0x10 is 0 -- how does
0x4742aa0 (2,215 bytes) choose the new capacity from the mask
and the item count, how does it reallocate and rehash the
bucket/control block, what does it read at its map+0x20
argument, and which map words does it rewrite before the
insert's probe reloads the control pointer and the mask?

The packet pins: (1) reachability -- the whole-.text census
finds exactly one reference to slot 0x64eaf78, the insert's
call at 0x474ba06, and no direct (E8) call to 0x4742aa0
anywhere; the insert sets up (rdi = map, rsi = 1,
rdx = map+0x20, ecx = 1) at 0x474b9ee..0x474ba01; (2) entry
arithmetic -- needed = additional (rsi) + items (map+0x18),
checked; old buckets B = mask (map+0x08) + 1; old capacity
cap(B) = (B & ~7) - (B >> 3), or mask when mask < 8 (so
cap = 0, 1, 3, 7, 14, 28, 112 for B = 1, 2, 4, 8, 16, 32,
128); (3) the split -- when needed <= cap(B)/2 the body
rehashes IN PLACE (no allocation, no map word except
growth-left changes); otherwise it allocates; (4) the new
bucket count -- requested = max(cap(B)+1, needed); below 15
the count is 4 / 8 / 16 for requested < 4 / < 8 / < 15; at
or above 15 it is the smallest power of two strictly
greater than floor(8*requested/7) - 1, computed with the
0x2492492492492493 divide-by-7 magic and a bsr round-up
(15 -> 32, 28 -> 32, 29 -> 64, 100 -> 128, 113 -> 256);
(5) the allocation -- total = align16(new_buckets * 0x58)
+ (new_buckets + 16) bytes through the alloc slot
0x64df480 -> 0x6355830; the new control pointer is
base + align16(new_buckets * 0x58); the new control block
(new_buckets + 16 bytes) is filled with 0xff through the
memset slot 0x64df750 (dynsym 10, memset); the bucket area
is not initialised; (6) the rehash -- old control groups
are scanned in order, each full slot's key (bucket+0x08
ptr, bucket+0x10 len) is rehashed with the same
0xff-terminated FNV-1a as the insert and the probe (len 0
uses the constant 0xaf64724c8602eb6e), the record's 0x58
bytes are copied into the new bucket at the first special
byte of the probe run starting at hash & new_mask (group
steps of 16), the pattern byte (hash >> 0x39) is written
at the slot and at its mirror (index - 0x10) & new_mask,
and the loop ends when the item count is exhausted;
(7) the install -- map+0x00 = new control pointer,
map+0x08 = new mask, map+0x10 = cap(new_buckets) - items;
the item word at map+0x18 is NOT rewritten; the old
allocation is freed through the dealloc slot 0x64df4a0 ->
0x635de30 with its total size when the old mask is
nonzero (an empty map's static control block is not
freed); an item count of 0 skips the rehash and installs
directly; (8) the in-place path -- every control byte is
first rewritten through the 0x80-vector fixup at
0x454f80 (full (pattern) bytes become 0x80, empty/deleted
bytes become 0xff), the first 16 control bytes are
mirrored with one memmove call (slot 0x64df568, dynsym 8,
memmove), each 0x80-marked record is rehashed and either
written into a same-group slot, moved into a 0xff slot
(leaving 0xff behind), or swapped with the occupying
bucket qword by qword, and at the end only growth-left is
recomputed and stored at map+0x10 (cap(B) - items); the
control pointer, the mask and the item count are not
stored; (9) the third argument -- the body never
dereferences the incoming rdx (map+0x20): in every path
rdx is overwritten (divide-by-7 magic, group-count mask,
memmove length, bucket cursor, panic location) before any
load through it, and the [rdx] loads in the in-place loop
read through a bucket pointer the loop itself computes;
(10) failures -- a checked-add overflow, a requested
capacity above 0x1fffffffffffffff, a buckets*0x58 overflow
or a total-size overflow, and a null allocation, all
reach the stub at 0x4742bd1: with the fourth argument's
low byte (the insert passes 1) nonzero the overflow path
calls the panic formatter through slot 0x64df6b8 ->
0x1680e80 with the string at 0x49bd80 ("Hash table
capacity overflow", raw second argument 0x39) and the
location record at 0x641cc98 and then the alloc-error
slot 0x64df490 -> 0x141e251 with (0x10, total size); the
null-allocation path calls the alloc-error slot directly;
with the byte 0 the paths return instead (rax = 0 on
overflow, rax = 0x10 on null allocation).  The body
contains exactly six calls, all through slots, and no
direct call at all.  The insert caller ignores the return
registers and reloads the control pointer and the mask
from the map.  Static evidence only; no captured code is
executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
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

OWNERS = {
    'map_grow': (
        0x4742aa0, 0x4743347,
        'dddec9130ff0171ebc861ae72351d0e4d846e76cbbd9811c5bed5d56d0ac4a67'),
}
BOUNDARIES = {
    'prev_body': (
        0x4742850, 0x4742958,
        '19805cd457f128d16f1325f9b077f925f5dde1d5246cb6374881910ed5b03288'),
    'record_drop': (
        0x4742960, 0x4742a93,
        '1aae44edc7f846da821541c9455706506403ae72981926a7927dd0aa0a3069e1'),
    'next_body': (
        0x4743350, 0x474398c,
        'bc09ee782d62721d2cbc93cc2e52d6f447caebbf7ef36da19f5ae89cfef84ae4'),
    'map_insert': (
        0x474b620, 0x474ba5d,
        'f6d9ca4362a1a81c592c33e5e75d6522a738b71a143b4c6b9bcb0b1739cd6658'),
}

OWNER_PINS = {
    'prologue': (0x4742aa0,
                 bytes.fromhex('554157415641554154534883ec28')),
    'items_load': (0x4742ab0, bytes.fromhex('4c8b4f18')),
    'needed_add': (0x4742ab4, bytes.fromhex('4c01ce')),
    'mask_load': (0x4742ac0, bytes.fromhex('488b7f08')),
    'buckets_lea': (0x4742ac4, bytes.fromhex('4c8d4701')),
    'cap_and': (0x4742ad2, bytes.fromhex('4883e1f8')),
    'cap_small_cmov': (0x4742add, bytes.fromhex('480f42cf')),
    'half_cmp': (0x4742ae7, bytes.fromhex('4839c6')),
    'requested_inc': (0x4742af0, bytes.fromhex('48ffc1')),
    'small_and8': (0x4742b02, bytes.fromhex('83e008')),
    'div7_magic': (0x4742b61,
                   bytes.fromhex('48ba9324499224499224')),
    'pow2_bsr': (0x4742b81, bytes.fromhex('480fbdc9')),
    'bucket_size58': (0x4742b94, bytes.fromhex('b958000000')),
    'ctrl_extra_lea': (0x4742bb6, bytes.fromhex('4c8d7d10')),
    'newcap_save': (0x4742c24, bytes.fromhex('48894c2410')),
    'memset_imm_ff': (0x4742c2c, bytes.fromhex('beff000000')),
    'fnv_prime_new': (0x4742c48,
                      bytes.fromhex('48beb301000000010000')),
    'empty_hash_const': (0x4742cc6,
                         bytes.fromhex('48bd6eeb02864c7264af')),
    'h2_shift_new': (0x4742dd9, bytes.fromhex('48c1ed39')),
    'ctrl_store_new': (0x4742de4, bytes.fromhex('41882c14')),
    'ctrl_mirror_new': (0x4742de8, bytes.fromhex('43886c1c10')),
    'bucket_copy_qword': (0x4742dfb, bytes.fromhex('4a8b5c1f50')),
    'fixup_const_load': (0x4742ea5,
                         bytes.fromhex('660f6f05d320d1fb')),
    'fixup_cmpgt': (0x4742eb4, bytes.fromhex('66410f640c0c')),
    'fnv_basis_inplace': (0x4742f73,
                          bytes.fromhex('48bf25232284e49cf2cb')),
    'ctrl_store_inplace': (0x47430b6, bytes.fromhex('43883c14')),
    'ctrl_mirror_inplace': (0x47430be,
                            bytes.fromhex('41887c1c10')),
    'swap_cmp_ff': (0x47430c3, bytes.fromhex('4180fbff')),
    'inplace_growth_store': (0x474327e,
                             bytes.fromhex('48894d10')),
    'install_ctrl': (0x47432c3, bytes.fromhex('4c8921')),
    'install_mask': (0x47432c6, bytes.fromhex('4c897108')),
    'install_growth': (0x47432ca, bytes.fromhex('48895110')),
    'panic_msg_lea': (0x4743316,
                      bytes.fromhex('488d3d638ad5fb')),
    'panic_raw_len': (0x4743324, bytes.fromhex('be39000000')),
}
OWNER_SLOT_CALLS = {
    'alloc_call': (0x4742bf2, 0x64df480),
    'memset_call': (0x4742c34, 0x64df750),
    'memmove_call': (0x4742f33, 0x64df568),
    'dealloc_call': (0x4743301, 0x64df4a0),
    'panic_call': (0x4743329, 0x64df6b8),
    'alloc_error_call': (0x4743337, 0x64df490),
}
CALLER_PINS = {
    'lea_rdx_map20': (0x474b9ee, bytes.fromhex('488d5620')),
    'mov_esi_1': (0x474b9f7, bytes.fromhex('be01000000')),
    'mov_ecx_1': (0x474ba01, bytes.fromhex('b901000000')),
}
CALLER_SLOT_CALLS = {
    'grow_call': (0x474ba06, 0x64eaf78),
}

SLOT_BINDINGS_WANTED = {
    'alloc': 0x64df480, 'alloc_error': 0x64df490,
    'dealloc': 0x64df4a0, 'memmove': 0x64df568,
    'memset': 0x64df750, 'panic_fmt': 0x64df6b8,
    'grow_fn': 0x64eaf78,
}
EXPECTED_BINDINGS = {
    'alloc': ('rela', '0x6355830'),
    'alloc_error': ('rela', '0x141e251'),
    'dealloc': ('rela', '0x635de30'),
    'memmove': ('glob', 'memmove'),
    'memset': ('glob', 'memset'),
    'panic_fmt': ('rela', '0x1680e80'),
    'grow_fn': ('rela', '0x4742aa0'),
}

PANIC_MESSAGE_VA = 0x49bd80
PANIC_MESSAGE = b'Hash table capacity overflow'
FIXUP_VECTOR_VA = 0x454f80


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


def _dynsym_names(data):
    secs = sections(data)
    sym = next(s for s in secs if s['name'] == '.dynsym')
    strs = next(s for s in secs if s['name'] == '.dynstr')
    names = {}
    for i, off in enumerate(range(sym['offset'],
                                  sym['offset'] + sym['size'], 24)):
        noff = struct.unpack_from('<I', data, off)[0]
        end = data.index(b'\x00', strs['offset'] + noff)
        names[i] = data[strs['offset'] + noff:end].decode()
    return names


def slot_bindings(data):
    rel = _relocations(data)
    names = _dynsym_names(data)
    out = {}
    for name, slot in SLOT_BINDINGS_WANTED.items():
        entry = rel[slot]
        kind, want = EXPECTED_BINDINGS[name]
        if kind == 'rela':
            got = hex(entry['addend'])
            out[name] = {'slot': hex(slot), 'type': entry['type'],
                         'addend': got}
            if got != want:
                raise ValueError(f'slot binding {name} changed')
        else:
            got = names[entry['symbol']]
            out[name] = {'slot': hex(slot), 'type': entry['type'],
                         'symbol': entry['symbol'], 'name': got}
            if got != want:
                raise ValueError(f'slot binding {name} changed')
    return out


def _text(data):
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    return data[text['offset']:text['offset'] + text['size']], \
        text['address']


def direct_call_census(data, targets):
    raw, base = _text(data)
    found = {t: [] for t in targets}
    for m in re.finditer(rb'\xe8', raw):
        i = m.start()
        if i + 5 > len(raw):
            continue
        disp = struct.unpack_from('<i', raw, i + 1)[0]
        tgt = base + i + 5 + disp
        if tgt in found:
            found[tgt].append(base + i)
    return {hex(k): [hex(x) for x in v] for k, v in found.items()}


def slot_call_census(data, slot):
    raw, base = _text(data)
    hits = []
    for m in re.finditer(rb'\xff[\x15\x25]', raw):
        i = m.start()
        if i + 6 > len(raw):
            continue
        disp = struct.unpack_from('<i', raw, i + 2)[0]
        if base + i + 6 + disp == slot:
            hits.append(base + i)
    return [hex(x) for x in hits]


def capacity(buckets):
    """cap(B) as computed at 0x4742ac8..0x4742ae1 (and reused
    for the growth-left stores): (B & ~7) - (B >> 3), or the
    mask B-1 when the mask is below 8."""
    mask = buckets - 1
    if mask < 8:
        return mask
    return (buckets & ~7) - (buckets >> 3)


def buckets_for(requested):
    """New bucket count for a requested capacity, following
    0x4742afa..0x4742b91 including the divide-by-7 magic."""
    if requested < 15:
        if requested < 4:
            return 4
        if requested < 8:
            return 8
        return 16
    q = (8 * requested) // 7 - 1
    b = 1
    while b <= q:
        b <<= 1
    return b


def fnv1a_ff_empty():
    h = (0xcbf29ce484222325 ^ 0xff) * 0x100000001b3 % (1 << 64)
    return hex(h)


def analyze(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('wrong node115 capture')
    _pins(data, OWNER_PINS, 'map_grow')
    for label, (site, slot) in OWNER_SLOT_CALLS.items():
        _slot_call(data, site, slot, f'map_grow {label}')
    _pins(data, CALLER_PINS, 'map_insert')
    for label, (site, slot) in CALLER_SLOT_CALLS.items():
        _slot_call(data, site, slot, f'map_insert {label}')
    if read(data, PANIC_MESSAGE_VA, len(PANIC_MESSAGE))[1] != \
            PANIC_MESSAGE:
        raise ValueError('panic message changed')
    if read(data, FIXUP_VECTOR_VA, 16)[1] != b'\x80' * 16:
        raise ValueError('fixup vector changed')
    bindings = slot_bindings(data)
    census = direct_call_census(data, (0x4742aa0,))
    if census['0x4742aa0'] != []:
        raise ValueError('grow body direct-call census changed')
    slot_census = slot_call_census(data, 0x64eaf78)
    if slot_census != ['0x474ba06']:
        raise ValueError('grow slot census changed')
    if fnv1a_ff_empty() != '0xaf64724c8602eb6e':
        raise ValueError('empty-key hash constant mismatch')
    cap_samples = {str(b): capacity(b)
                   for b in (1, 2, 4, 8, 16, 32, 128, 256)}
    if cap_samples != {'1': 0, '2': 1, '4': 3, '8': 7, '16': 14,
                       '32': 28, '128': 112, '256': 224}:
        raise ValueError('capacity model mismatch')
    bucket_samples = {str(c): buckets_for(c)
                      for c in (0, 3, 4, 7, 8, 14, 15, 28, 29,
                                100, 112, 113)}
    if bucket_samples != {'0': 4, '3': 4, '4': 8, '7': 8,
                          '8': 16, '14': 16, '15': 32, '28': 32,
                          '29': 64, '100': 128, '112': 128,
                          '113': 256}:
        raise ValueError('bucket-choice model mismatch')
    _, fs, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs}

    def frame_records(a, b, sha, role):
        if (a, b) not in fdes:
            raise ValueError(f'{role} scope FDE changed')
        offset, raw = read(data, a, b - a)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != sha:
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

    owners = [frame_records(a, b, sha, role)
              for role, (a, b, sha) in OWNERS.items()]
    boundaries = [frame_records(a, b, sha, role)
                  for role, (a, b, sha) in BOUNDARIES.items()]
    return {
        'target_sha256': SHA,
        'owners': owners,
        'boundaries': boundaries,
        'slot_bindings': bindings,
        'direct_call_census': census,
        'slot_call_census': {'0x64eaf78': slot_census},
        'empty_key_hash': fnv1a_ff_empty(),
        'panic_message': {
            'address': hex(PANIC_MESSAGE_VA),
            'text': PANIC_MESSAGE.decode(),
            'raw_second_argument': '0x39',
            'location_record': '0x641cc98',
        },
        'fixup_vector': {'address': hex(FIXUP_VECTOR_VA),
                         'bytes': '0x80 repeated 16 times'},
        'call_args': {
            'rdi': 'map pointer (&S+0x20 in the insert helper)',
            'rsi': 'additional capacity requested (1 from the '
                   'insert); needed = rsi + word at map+0x18 '
                   '(items), checked add',
            'rdx': 'map+0x20 in the only call; never '
                   'dereferenced by the body (see '
                   'third_argument)',
            'rcx': 'fallibility byte in the low byte (1 from '
                   'the insert): nonzero routes failures to '
                   'the panic / alloc-error calls, zero makes '
                   'them return a tag in rax',
        },
        'third_argument': 'no instruction in the body loads '
                          'through the incoming rdx; it is '
                          'overwritten by the divide-by-7 '
                          'magic (0x4742b61), by the '
                          'group-count mask (0x4742e96), by '
                          'the memmove length (0x4742f30), '
                          'by the in-place bucket cursor '
                          '(0x47431e7) and by the panic '
                          'location (0x474331d) before any '
                          'use; the [rdx] loads in the '
                          'in-place swap loop read through '
                          'a bucket pointer the loop itself '
                          'computes from the scan index',
        'capacity_model': {
            'capacity_of_buckets': cap_samples,
            'buckets_for_requested': bucket_samples,
            'rule': 'cap(B) = (B & ~7) - (B >> 3), or B-1 '
                    'when B-1 < 8; requested = max(cap(old '
                    'buckets)+1, needed); new buckets = 4 / '
                    '8 / 16 for requested < 4 / < 8 / < 15, '
                    'else the smallest power of two strictly '
                    'greater than floor(8*requested/7) - 1',
        },
        'map_rewrites': [
            'allocation path: map+0x00 = new control pointer '
            '(alloc base + align16(new buckets * 0x58)), '
            'map+0x08 = new mask (new buckets - 1), '
            'map+0x10 = cap(new buckets) - items; map+0x18 '
            '(items) is not stored',
            'in-place path: only map+0x10 is stored, with '
            'cap(old buckets) - items; map+0x00, map+0x08 '
            'and map+0x18 are not stored',
            'failure returns store no map word',
        ],
        'phases': [
            'entry: needed = additional + items (checked); '
            'old buckets B = mask + 1; if needed <= '
            'cap(B)/2 the body takes the in-place path, '
            'otherwise the allocation path',
            'allocation size: requested = max(cap(B)+1, '
            'needed); new buckets by the capacity model; '
            'total = align16(new buckets * 0x58) + new '
            'buckets + 16, with overflow checks at each '
            'step; alloc through slot 0x64df480',
            'fresh block: new control pointer = base + '
            'align16(new buckets * 0x58); memset of new '
            'buckets + 16 control bytes to 0xff through '
            'slot 0x64df750; the bucket area is left '
            'uninitialised',
            'rehash (allocation path): old control groups '
            'scanned in order; each full slot\'s key is '
            'rehashed with the 0xff-terminated FNV-1a; '
            'the 0x58-byte record is copied to the first '
            'special byte of the probe run from hash & '
            'new mask in 16-byte group steps (a full byte '
            'there falls back to the first special byte '
            'of the first group); pattern byte = hash >> '
            '0x39 stored at the slot and its mirror '
            '(index - 0x10) & new mask; the loop ends '
            'when the item count is exhausted; items == 0 '
            'skips the loop entirely',
            'install and free: map+0x00/+0x08/+0x10 are '
            'stored as listed in map_rewrites; the old '
            'allocation base (old control pointer minus '
            'align16(old buckets * 0x58)) is freed '
            'through slot 0x64df4a0 with the old total '
            'size when the old mask is nonzero',
            'in-place fixup: every control byte is '
            'rewritten with pcmpgtb against 0 ORed with '
            'the 0x80 vector at 0x454f80 (full bytes '
            'become 0x80, empty/deleted become 0xff), '
            'one 16-byte group directly when the table '
            'has at most 16 buckets, group pairs plus a '
            'possible tail group otherwise',
            'in-place mirror and scan: one memmove call '
            '(slot 0x64df568) copies the control head '
            'into the mirror area (16 bytes from ctrl to '
            'ctrl + buckets when buckets >= 16, else '
            'buckets bytes from ctrl to ctrl + 16); the '
            'scan then visits indexes 0..mask, and for '
            'each 0x80-marked record rehashes its key '
            'and probes the same table: a destination '
            'in the same group takes only the pattern '
            'byte (and its mirror) at the destination; '
            'a 0xff destination receives the whole '
            '0x58-byte record and the source byte becomes '
            '0xff; any other destination swaps the two '
            'buckets qword by qword and the scan retries '
            'the same index',
            'in-place finish: growth left = cap(B) - '
            'items is stored at map+0x10 and the body '
            'returns; the degenerate mask == -1 entry '
            '(buckets wraps to 0) reaches only this '
            'recompute with a zero capacity word',
            'failures: checked-add overflow, requested '
            '> 0x1fffffffffffffff, buckets * 0x58 '
            'overflow, total-size overflow past '
            '0x7fffffffffffffff - 15 and a null '
            'allocation reach 0x4742bd1; with the '
            'fallibility byte nonzero, overflow first '
            'calls the panic formatter (slot 0x64df6b8, '
            'message at 0x49bd80, raw length argument '
            '0x39, location record at 0x641cc98) and '
            'then the alloc-error slot 0x64df490 with '
            '(0x10, total size), which the null path '
            'calls directly; with the byte 0 the '
            'overflow path returns rax = 0 and the null '
            'path returns rax = 0x10, storing nothing',
        ],
        'verdict': (
            'The grow body 0x4742aa0 is the hashbrown-style '
            'reserve behind the S-rooted map, reached only '
            'through slot 0x64eaf78 from the map insert '
            '(map, 1, map+0x20, 1). It forms needed = 1 + '
            'items and splits on needed <= cap(old '
            'buckets)/2: below the split it rehashes in '
            'place -- control bytes are flipped through '
            'the 0x80-vector fixup (full -> 0x80, '
            'special -> 0xff), the control head is '
            'mirrored with one memmove, marked records '
            'are re-placed by moving or swapping buckets, '
            'and only growth-left at map+0x10 is rewritten '
            '(cap - items). Above the split it allocates '
            'a fresh block sized for the smallest bucket '
            'count whose 7/8 capacity covers max(cap+1, '
            'needed), fills the new control block with '
            '0xff, rehashes every stored record with the '
            'same 0xff-terminated FNV-1a into the new '
            'table (pattern byte = hash >> 0x39, slot '
            'plus mirror), installs control pointer, '
            'mask and growth-left at map+0x00/+0x08/+0x10 '
            '-- never the item count -- and frees the old '
            'block when the old mask is nonzero. The '
            'map+0x20 third argument is never read: rdx '
            'is overwritten in every path before any load '
            'through it.'),
    }


def _objdump(path, start, end):
    return subprocess.check_output(
        ['objdump', '-d', '-M', 'intel', '--insn-width=16',
         f'--start-address={start:#x}', f'--stop-address={end:#x}',
         str(path)]).decode('utf-8')


WINDOWS = [
    ('map_grow_objdump.txt', 0x4742aa0, 0x4743347,
     [s for s, _ in OWNER_PINS.values()]
     + [s for s, _ in OWNER_SLOT_CALLS.values()]),
    ('insert_grow_callsite_objdump.txt', 0x474b9ee, 0x474ba0c,
     [s for s, _ in CALLER_PINS.values()]
     + [s for s, _ in CALLER_SLOT_CALLS.values()]),
]


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
        for name, start, end, sites in WINDOWS:
            asm = _objdump(snapshot, start, end)
            ins = decode_export(asm, start, end,
                                read(data, start, end - start)[1])
            if not set(sites) <= set(ins):
                raise ValueError(f'{name} evidence site not a '
                                 'native instruction start')
            (output / name).write_bytes(
                asm.replace(str(snapshot),
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
                   default=ROOT / 'work/map-grow115')
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['owners']),
                      'bytes': sum(x['bytes'] for x in report['owners']),
                      'executed': False}))
