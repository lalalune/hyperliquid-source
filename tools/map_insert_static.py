#!/usr/bin/env python3
"""Pin the RE-015 map insert 0x474b620 in node 115.

Question (carried by the insert-helper packet
RE-015-node115-insert-helper): the map insert 0x474b620
(1,085 bytes) is called by the insert helper 0x4741960 with
&S+0x20, a {len, ptr, len} key descriptor and a 0x40-byte S
value block -- how does it mutate the map words at
S+0x20..0x40?  How does it grow the table, where inside a
0x58-byte bucket does it write the key record and the value,
and what distinguishes the result-dword-6 variant from the
variant that hands back a displaced record?

The packet pins: (1) the whole-.text direct-call census for
0x474b620 is exactly one site, the insert helper's call at
0x4742025; the helper passes rdi = a 0x48-byte out scratch
(also the return value), rsi = the map at S+0x20,
rdx = the key descriptor {len +0x00, ptr +0x08, len +0x10},
rcx = a pointer to the 0x40-byte new value; the helper tests
the result dword at out+0x00 against 6; (2) the key bytes are
hashed with the same FNV-1a the helper's probe uses (basis
0xcbf29ce484222325, prime 0x100000001b3, a final 0xff byte
folded in; an empty key uses the constant 0xaf64724c8602eb6e,
exactly that hash of [0xff]); the control-byte pattern is the
hash's top 7 bits (hash >> 0x39); (3) before probing, when
the map word at +0x10 (growth left) is 0, the body grows the
table through slot 0x64eaf78 -> 0x4742aa0 (boundary) called
with (map, 1, map+0x20, 1) and re-reads the control pointer
and mask; (4) the probe walks 16-byte control groups
(hashbrown-style, triangular group steps); buckets are the
0x58-byte records located before the control bytes,
bucket(i) = ctrl - (i+1)*0x58, with the key record at
+0x00..0x18 ({word0 = len, ptr at +0x08, len at +0x10}) and
the 0x40-byte value at +0x18..0x58; a candidate is a hit
only when bucket+0x10 equals the key length and bcmp (slot
0x64df9f8, dynsym 11) of bucket+0x08 against the key bytes
returns 0; (5) on a hit the body copies the bucket's old
0x40-byte value into the out scratch (so the dword the
caller tests is the displaced value's own first word), copies
the new value into the bucket, frees the incoming key's
buffer through the dealloc slot 0x64df4a0 -> 0x635de30 when
the descriptor's first word is nonzero (size = that word),
keeps the bucket's stored key record, and changes no map
word; (6) on a miss the body takes the first empty (0xff) or
deleted (0x80) control byte -- a deleted slot seen earlier in
the probe is preferred once a later group proves an empty
byte exists; if the byte at the remembered index is not
special it rescans the control block from its start -- then
writes the full bucket (key descriptor's 0x18 bytes at
+0x00..0x18, the new value at +0x18..0x58), writes the
pattern byte to the control byte at the slot index and to
its mirror at (index-0x10) & mask, updates the counters at
map+0x10..0x20 with one vector subtract (items at +0x18
grows by 1 on every fresh insert; growth left at +0x10
shrinks by 1 only when the consumed slot was empty, via
old_byte & 1: 0xff -> 1, 0x80 -> 0), writes only the qword 6
at out+0x00 and returns; (7) the landing pad drops the
not-yet-inserted value argument through 0x474ac30 (a
45-byte S-value drop whose own whole-.text census is this
one site) and frees the incoming key buffer the same way
before resuming the unwind.  Static evidence only; no
captured code is executed.
"""
import argparse
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

OWNERS = {
    'map_insert': (
        0x474b620, 0x474ba5d,
        'f6d9ca4362a1a81c592c33e5e75d6522a738b71a143b4c6b9bcb0b1739cd6658'),
}
BOUNDARIES = {
    'insert_helper': (
        0x4741960, 0x4742124,
        '19ab10dcba77aea7e558737bddc7bace985b7d49bc254b69d731e23bb805136d'),
    'grow_reserve': (
        0x4742aa0, 0x4743347,
        'dddec9130ff0171ebc861ae72351d0e4d846e76cbbd9811c5bed5d56d0ac4a67'),
    'record_drop': (
        0x4742960, 0x4742a93,
        '1aae44edc7f846da821541c9455706506403ae72981926a7927dd0aa0a3069e1'),
    'value_drop': (
        0x474ac30, 0x474ac5d,
        'a40c63266a40637f39a94b76a535c5f934ad1679a466075465f8f8871e569c87'),
    'next_body': (
        0x474ba60, 0x474bcd3,
        '4527e1e0d1ad267cdd6951f2eb2898a962a2124d6096038fd63087ea43637d44'),
}

OWNER_PINS = {
    'fnv_basis': (0x474b64f,
                  bytes.fromhex('48bd25232284e49cf2cb')),
    'fnv_prime': (0x474b659,
                  b'H\xb8\xb3\x01\x00\x00\x00\x01\x00\x00'),
    'empty_hash_const': (0x474b678,
                         b'H\xbdn\xeb\x02\x86Lrd\xaf'),
    'ff_fold': (0x474b727, b'H\x81\xf5\xff\x00\x00\x00'),
    'growth_cmp': (0x474b737, b'H\x83\x7e\x10\x00'),
    'ctrl_load': (0x474b742, b'L\x8b&H'),
    'mask_load': (0x474b745, b'H\x8bV\x08'),
    'h2_shift': (0x474b74c, b'H\xc1\xeb9'),
    'bucket_len_cmp': (0x474b7d4, bytes.fromhex('4b3b4c34b8')),
    'bcmp_call': (0x474b7eb, b'A\xff\xd7'),
    'hit_copy0': (0x474b88d, b'A\x0f\x10F\xc0'),
    'keyfree_test': (0x474b8e2, b'H\x8b0H\x85\xf6\x0f'),
    'ctrl_store_a': (0x474b955, b'A\x88\x1c<'),
    'ctrl_store_b': (0x474b959, b'A\x88\\\x0c\x10'),
    'counter_store': (0x474b977, b'\xf3\x0f\x7fF\x10'),
    'bucket_first_store': (0x474b9c7, b'A\x0f\x11D\x04'),
    'tag6_store': (0x474b9d2, b'H\xc7\x03\x06\x00\x00\x00'),
}
OWNER_DIRECT_CALLS = {
    'value_drop_call': (0x474ba36, 0x474ac30),
}
OWNER_SLOT_CALLS = {
    'grow_call': (0x474ba06, 0x64eaf78),
    'dealloc_call_hit': (0x474b8f4, 0x64df4a0),
    'dealloc_call_pad': (0x474ba49, 0x64df4a0),
    'unwind_tail_call': (0x474ba57, 0x64df4c0),
}
HELPER_PINS = {
    'result_cmp': (0x474202a,
                   b'\x83\xbc$\x00\x01\x00\x00\x06'),
}
HELPER_DIRECT_CALLS = {
    'insert_call': (0x4742025, 0x474b620),
}

SLOT_BINDINGS_WANTED = {
    'bcmp': 0x64df9f8, 'dealloc': 0x64df4a0,
    'grow_fn': 0x64eaf78, 'unwind_tail': 0x64df4c0,
}
EXPECTED_BINDINGS = {
    'bcmp': ('glob', 'bcmp'),
    'dealloc': ('rela', '0x635de30'),
    'grow_fn': ('rela', '0x4742aa0'),
    'unwind_tail': ('rela', '0x1680cab'),
}


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


def _direct_call(data, site, target, label):
    raw = read(data, site, 5)[1]
    require(raw[:1] == b'\xe8', f'{label} is not a direct call')
    rel = struct.unpack('<i', raw[1:])[0]
    require(site + 5 + rel == target, f'{label} target changed')


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


def direct_call_census(data, targets):
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    raw = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    found = {t: [] for t in targets}
    for i in range(len(raw) - 5):
        if raw[i] == 0xe8:
            disp = struct.unpack_from('<i', raw, i + 1)[0]
            tgt = base + i + 5 + disp
            if tgt in found:
                found[tgt].append(base + i)
    return {hex(k): [hex(x) for x in v] for k, v in found.items()}


def fnv1a_ff_empty():
    h = (0xcbf29ce484222325 ^ 0xff) * 0x100000001b3 % (1 << 64)
    return hex(h)


def analyze(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('wrong node115 capture')
    _pins(data, OWNER_PINS, 'map_insert')
    for label, (site, target) in OWNER_DIRECT_CALLS.items():
        _direct_call(data, site, target, f'map_insert {label}')
    for label, (site, slot) in OWNER_SLOT_CALLS.items():
        _slot_call(data, site, slot, f'map_insert {label}')
    _pins(data, HELPER_PINS, 'insert_helper')
    for label, (site, target) in HELPER_DIRECT_CALLS.items():
        _direct_call(data, site, target, f'insert_helper {label}')
    bindings = slot_bindings(data)
    census = direct_call_census(data, (0x474b620, 0x474ac30))
    if census['0x474b620'] != ['0x4742025']:
        raise ValueError('map insert caller census changed')
    if census['0x474ac30'] != ['0x474ba36']:
        raise ValueError('value drop caller census changed')
    if fnv1a_ff_empty() != '0xaf64724c8602eb6e':
        raise ValueError('empty-key hash constant mismatch')
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
        'empty_key_hash': fnv1a_ff_empty(),
        'call_args': {
            'rdi': 'out scratch in the caller (returned in rax); the '
                   'caller tests the dword at +0x00 against 6',
            'rsi': 'map pointer (&S+0x20 in the insert helper)',
            'rdx': 'key descriptor {len +0x00, byte ptr +0x08, '
                   'len +0x10}',
            'rcx': 'pointer to the 0x40-byte new value block',
        },
        'map_fields': [
            {'offset': '0x00', 'role': 'control-byte base pointer; '
                                       'buckets are the 0x58-byte '
                                       'records before it'},
            {'offset': '0x08', 'role': 'bucket mask (probe indexes '
                                       'are ANDed with it)'},
            {'offset': '0x10', 'role': 'growth left: tested against '
                                       '0 before the probe (grow '
                                       'call); decremented only '
                                       'when a fresh insert '
                                       'consumes an empty (0xff) '
                                       'slot'},
            {'offset': '0x18', 'role': 'item count: the insert '
                                       'helper probes only when '
                                       'it is nonzero; incremented '
                                       'by 1 on every fresh insert'},
        ],
        'bucket_layout': {
            'size': '0x58',
            'address': 'ctrl - (index+1)*0x58',
            'key_record': [
                {'offset': '0x00', 'role': 'first descriptor word '
                                           '(the head length)'},
                {'offset': '0x08', 'role': 'key byte pointer '
                                           '(bcmp target on a '
                                           'candidate)'},
                {'offset': '0x10', 'role': 'key length (compared '
                                           'against the probe key '
                                           'length first)'},
            ],
            'value': {'offset': '0x18', 'bytes': '0x40',
                      'role': 'the stored child S block'},
        },
        'result_variants': [
            'fresh insert: only the qword 6 is stored at out+0x00; '
            'the bucket, both control bytes and the counters are '
            'the mutation',
            'replace (key already present): the full 0x40-byte '
            'displaced value is copied to out+0x00..0x40, so the '
            'dword the caller tests is the displaced value\'s own '
            'first word; the new value overwrites the bucket\'s '
            'value, the stored key record is kept, the incoming '
            'key buffer is freed through the dealloc slot when '
            'the descriptor\'s first word is nonzero, and no map '
            'word changes',
        ],
        'counter_rule': 'one psubq at 0x474b973 against the '
                        'constant {0, -1} at 0x450790, stored back '
                        'at map+0x10: items (+0x18) += 1 always; '
                        'growth left (+0x10) -= (old control byte '
                        '& 1), which is 1 for an empty (0xff) slot '
                        'and 0 for a deleted (0x80) slot',
        'phases': [
            'hash: FNV-1a over the key bytes (descriptor +0x08 '
            'ptr, +0x10 len) with a final 0xff byte folded in; '
            'len 0 uses the constant hash of [0xff]; the control '
            'pattern is hash >> 0x39',
            'grow: if map+0x10 (growth left) is 0, call slot '
            '0x64eaf78 -> 0x4742aa0 (boundary) with (map, 1, '
            'map+0x20, 1), then reload the control pointer and '
            'the mask and fall into the probe',
            'probe: 16-byte control groups from (hash & mask), '
            'triangular group steps; per candidate lane, bucket '
            'index = (group + lane) & mask; hit needs bucket+0x10 '
            '== key len and bcmp(bucket+0x08, key, len) == 0; '
            'matched lanes are peeled (mask &= mask-1) and the '
            'rest of the group is retried',
            'replace: copy the bucket value (bucket+0x18, 0x40 '
            'bytes) to the out scratch, copy the new value into '
            'the bucket, free the incoming key buffer via the '
            'dealloc slot when descriptor word0 != 0, return '
            'the out pointer',
            'fresh insert: remember the first deleted (0x80) slot '
            'of the probe; a group containing an empty (0xff) '
            'byte confirms the insertion point (the remembered '
            'deleted slot if one was seen, else the group\'s '
            'first special byte; if the byte at the remembered '
            'index is not special, rescan the control block from '
            'its start for the first special byte); write the '
            'key record and value into the bucket, set the '
            'control byte at the index and its mirror at '
            '(index-0x10) & mask to the pattern byte, apply the '
            'counter update, store qword 6 at out+0x00, return',
            'unwind: the landing pad drops the value argument '
            'through 0x474ac30 (boundary), frees the incoming '
            'key buffer through the dealloc slot when descriptor '
            'word0 != 0, and resumes the unwind (tail slot '
            '0x64df4c0 -> 0x1680cab)',
        ],
        'verdict': (
            'The map insert 0x474b620 is the hashbrown-style '
            'insert behind the S-rooted map: it FNV-1a hashes '
            'the key (0xff-terminated, as the helper\'s probe '
            'does), grows the table through 0x4742aa0 when the '
            'growth-left word at map+0x10 is 0, and probes '
            '16-byte control groups over the table at map+0x00 '
            '/ map+0x08. On a hit it swaps the value in place: '
            'the displaced 0x40-byte value is copied to the '
            'caller\'s out scratch (its own first word is the '
            'dword the caller tests), the incoming key buffer '
            'is freed, and no map word changes. On a miss it '
            'writes the {len, ptr, len} key record at bucket '
            '+0x00..0x18 and the 0x40-byte value at bucket '
            '+0x18..0x58 of the 0x58-byte bucket before the '
            'control bytes, sets the slot\'s control byte and '
            'its mirror, bumps the item count at map+0x18, '
            'charges growth left at map+0x10 only for a truly '
            'empty slot, and marks the result with the single '
            'qword 6 at out+0x00 -- the variant the caller '
            'returns on without any cleanup.'),
    }


def _objdump(path, start, end):
    return subprocess.check_output(
        ['objdump', '-d', '-M', 'intel', '--insn-width=16',
         f'--start-address={start:#x}', f'--stop-address={end:#x}',
         str(path)]).decode('utf-8')


WINDOWS = [
    ('map_insert_objdump.txt', 0x474b620, 0x474ba5d,
     [s for s, _ in OWNER_PINS.values()]
     + [s for s, _ in OWNER_DIRECT_CALLS.values()]
     + [s for s, _ in OWNER_SLOT_CALLS.values()]),
    ('insert_helper_callsite_objdump.txt', 0x474200a, 0x4742032,
     [s for s, _ in HELPER_PINS.values()]
     + [s for s, _ in HELPER_DIRECT_CALLS.values()]),
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
                   default=ROOT / 'work/map-insert115')
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['owners']),
                      'bytes': sum(x['bytes'] for x in report['owners']),
                      'executed': False}))
