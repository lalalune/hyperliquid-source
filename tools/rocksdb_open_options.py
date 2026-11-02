#!/usr/bin/env python3
"""Pin the two tuned RocksDB open wrappers of node #94 from ELF bytes only.

The tool never runs the captured binary and calls no external program. Every
value comes from section headers, .eh_frame, .rela.dyn and fixed byte patterns.
"""
import argparse
import bisect
import collections
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import elf_index  # noqa: E402
import fde_extents  # noqa: E402

BINARY = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
R_X86_64_RELATIVE = 8
SHT_NOBITS = 8

# Slot, expected target and the role this packet gives the target.
FFI = {
    'block_options_create': (0x5775cf8, 0x4f944f0),
    'lru_cache_create': (0x5775d00, 0x4f94c20),
    'set_block_cache': (0x5775d08, 0x4f954b0),
    'set_block_size': (0x5775d10, 0x4f94610),
    'options_create': (0x5773428, 0x4f95030),
    'set_create_if_missing': (0x5773a90, 0x4f94620),
    'set_write_buffer_size': (0x5775d18, 0x4f94630),
    'set_table_factory': (0x5775d20, 0x4f950b0),
    'block_options_destroy': (0x5775d28, 0x4f94de0),
    'options_destroy': (0x57730f0, 0x4f95300),
}
SETTER_BODIES = {
    'set_block_size': bytes.fromhex('f30f1efa48897758c3'),
    'set_create_if_missing': bytes.fromhex('f30f1efa4084f60f9507c3'),
    'set_write_buffer_size': bytes.fromhex('f30f1efa4889b7a8040000c3'),
}
HOT_ORDER = ['block_options_create', 'lru_cache_create', 'set_block_cache', 'set_block_size', 'options_create',
             'set_create_if_missing', 'set_write_buffer_size', 'set_table_factory']
WRAPPERS = {
    'state': {'start': 0x3421980, 'validator': 0x332eba0, 'caller': 0x3be4b40, 'caller_site': 0x3be4b7c,
              'open': 0x3c98770, 'write_buffer_prefix': bytes.fromhex('be000000084c89ff')},
    'checkpoint': {'start': 0x42c70c0, 'validator': 0x459b500, 'caller': 0x4875ba0, 'caller_site': 0x4875cc8,
                   'open': 0x4b70480, 'write_buffer_prefix': bytes.fromhex('488b7c2440be00000008')},
}
CACHE_RE = re.compile(rb'\x41\xf6\xc7\x01\xbf(.{4})\x49\x0f\x45\xfe\x48\x89\xf8\x48\xc1\xe8\x22\x0f\x85(.{4})\x48\xc1\xe7\x1e',
                      re.DOTALL)
BTREE_PINS = {
    'node_len_u16_plus_0x62': bytes.fromhex('440fb74062'),
    'node_entry_u8_plus_0x64': bytes.fromhex('440fb6543865'),
    'edge_ptr_plus_0x70': bytes.fromhex('488b44f870'),
    'value_ptr_plus_0x08': bytes.fromhex('488b4cf808'),
}
LOCATIONS = {
    'block_based_options_default': 0x574fd00,
    'options_default': 0x574fcb8,
    'lru_cache_null': 0x574fce8,
    'open_result_unwrap': 0x56eb3d0,
    'missing_home_entry': 0x56f39d0,
}
BUNDLE_PTRS, BUNDLE_LENS, BUNDLE_COUNT = 0x572d7c8, 0x6f8900, 3
ROCKSDB_FAILURE_TEXTS = {'block_options': (0x7c5d31, 0x2c), 'options': (0x20be40, 0x20)}


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = elf_index.sections(data)
        self.text = self.section('.text')
        self.rel = self.relative_relocs()

    def section(self, name):
        found = [s for s in self.secs if s['name'] == name]
        if len(found) != 1:
            raise ValueError(f'expected one {name} section')
        return found[0]

    def offset(self, va, size=1):
        for sec in self.secs:
            if sec['type'] != SHT_NOBITS and sec['flags'] & 2 and sec['address'] <= va and va + size <= sec['address'] + sec['size']:
                return sec['offset'] + va - sec['address']
        raise ValueError(f'{va:#x}+{size} is not file-backed')

    def read(self, va, size):
        off = self.offset(va, size)
        return bytes(self.data[off:off + size])

    def relative_relocs(self):
        sec = self.section('.rela.dyn')
        if sec['size'] % 24:
            raise ValueError('truncated .rela.dyn')
        rows = {}
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', self.data, off)
            if info & 0xffffffff == R_X86_64_RELATIVE:
                if where in rows:
                    raise ValueError(f'duplicate RELATIVE relocation slot {where:#x}')
                rows[where] = addend
        return rows

    def code(self):
        sec = self.text
        return bytes(self.data[sec['offset']:sec['offset'] + sec['size']]), sec['address']


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load(path=BINARY):
    data = Path(path).read_bytes()
    check_digest(data)
    return data


def check_digest(data):
    if sha256(data) != SHA256:
        raise ValueError('input binary digest mismatch')


def cache_capacity(option_gib, default_gib):
    """The arithmetic of the pinned sequence: default, 34-bit test, shift, saturate."""
    gib = default_gib if option_gib is None else option_gib
    return (1 << 64) - 1 if gib >> 34 else gib << 30


def function_index(data):
    _summary, ordered, _gaps = fde_extents.fde_extents(data)
    return [f['start'] for f in ordered], [f['end'] for f in ordered]


def extent(index, start):
    starts, ends = index
    pos = bisect.bisect_left(starts, start)
    if pos == len(starts) or starts[pos] != start:
        raise ValueError(f'{start:#x} is not an FDE start')
    return start, ends[pos]


def owner(index, va):
    starts, ends = index
    pos = bisect.bisect_right(starts, va) - 1
    return starts[pos] if pos >= 0 and va < ends[pos] else None


def expect(condition, message):
    if not condition:
        raise ValueError(message)


def check_slots(img):
    rows = []
    for name, (slot, target) in FFI.items():
        expect(img.rel.get(slot) == target, f'slot {slot:#x} does not hold {target:#x}')
        rows.append({'role': name, 'slot': hex(slot), 'target': hex(target)})
    return rows


def check_setters(img):
    rows = []
    for name, body in SETTER_BODIES.items():
        target = FFI[name][1]
        expect(img.read(target, len(body)) == body, f'{name} body differs')
        expect(img.read(target + len(body), 1) == b'\xcc', f'{name} is not followed by int3 fill')
        rows.append({'role': name, 'target': hex(target), 'bytes': body.hex()})
    return rows


def find_one(blob, pattern, label):
    hits = [m.start() for m in re.finditer(re.escape(pattern), blob)]
    expect(len(hits) == 1, f'{label}: {len(hits)} hits')
    return hits[0]


def rip_target(img, va, opcode_size, disp_offset):
    return va + opcode_size + struct.unpack('<i', img.read(va + disp_offset, 4))[0]


def check_defaults(img, index):
    """Constructor stores that fingerprint the fields behind the two raw offsets."""
    start, end = extent(index, FFI['block_options_create'][1])
    block = img.read(start, end - start)
    find_one(block, bytes.fromhex('bff8000000'), 'block options allocation size')
    find_one(block, bytes.fromhex('48c7405800100000'), 'block option +0x58 default')
    find_one(block, bytes.fromhex('48c7407000100000'), 'block option +0x70 default')
    find_one(block, bytes.fromhex('c7406801000000'), 'block option +0x68 default')
    load_pos = find_one(block, bytes.fromhex('488b15006c27fb'), 'block option +0x60 load')
    pair_va = rip_target(img, start + load_pos, 7, 3)
    find_one(block, bytes.fromhex('48895060'), 'block option +0x60 store')
    deviation, restart = struct.unpack('<ii', img.read(pair_va, 8))

    start, end = extent(index, FFI['options_create'][1])
    create = img.read(start, end - start)
    find_one(create, bytes.fromhex('bf90050000'), 'options allocation size')
    find_one(create, bytes.fromhex('488dbb90020000'), 'column family base offset')
    ctor_site = start + find_one(create, bytes.fromhex('488dbb90020000e8'), 'column family constructor call') + 7
    ctor = rip_target(img, ctor_site, 5, 1)
    ctor_start, ctor_end = extent(index, ctor)
    cf = img.read(ctor_start, ctor_end - ctor_start)
    find_one(cf, bytes.fromhex('48c7831802000000000004'), 'column family +0x218 default')
    find_one(cf, bytes.fromhex('c7838802000004000000'), 'column family +0x288 default')
    find_one(cf, bytes.fromhex('4889abb8020000'), 'column family +0x2b8 store')

    start, end = extent(index, FFI['set_table_factory'][1])
    factory = img.read(start, end - start)
    find_one(factory, bytes.fromhex('4889ab48050000'), 'options +0x548 table factory store')

    start, end = extent(index, FFI['set_block_cache'][1])
    block_cache = img.read(start, end - start)
    find_one(block_cache, bytes.fromhex('48894738'), 'block option +0x38 cache pointer store')

    start, end = extent(index, FFI['lru_cache_create'][1])
    lru = img.read(start, end - start)
    find_one(lru, bytes.fromhex('baffffffff'), 'lru shard bits -1')
    ratio_pos = find_one(lru, bytes.fromhex('f20f1005f84427fb'), 'lru pool ratio load')
    ratio_va = rip_target(img, start + ratio_pos, 8, 4)
    ratio = struct.unpack('<d', img.read(ratio_va, 8))[0]
    return {
        'block_options': {'allocation': 0xf8, 'plus_0x38': 'block cache pointer', 'plus_0x58_default': 0x1000,
                          'plus_0x60_default_i32': deviation, 'plus_0x64_default_i32': restart,
                          'plus_0x68_default_i32': 1, 'plus_0x70_default': 0x1000},
        'options': {'allocation': 0x590, 'second_base_offset': 0x290, 'second_base_constructor': hex(ctor),
                    'second_base_plus_0x218_default': 0x4000000, 'second_base_plus_0x288_default_i32': 4,
                    'second_base_plus_0x2b8': 'stored table factory', 'write_buffer_setter_offset': 0x4a8,
                    'write_buffer_setter_offset_minus_base': 0x4a8 - 0x290, 'table_factory_setter_offset': 0x548,
                    'table_factory_setter_offset_minus_base': 0x548 - 0x290},
        'lru_cache': {'shard_bits_edx': -1, 'pool_ratio_xmm0': ratio, 'pool_ratio_va': hex(ratio_va)},
    }


def ffi_sites(img, start, end):
    names = {slot: name for name, (slot, _target) in FFI.items()}
    blob = img.read(start, end - start)
    rows = []
    for match in re.finditer(rb'\xff\x15', blob):
        site = start + match.start()
        if site + 6 > end:
            continue
        name = names.get(rip_target(img, site, 6, 2))
        if name:
            rows.append((site, name))
    return rows


def calls_between(img, index, start, end):
    """Byte-scan call positions in [start, end]: relocated slots and rel32 calls that land on an FDE start."""
    roles = {slot: name for name, (slot, _target) in FFI.items()}
    blob = img.read(start, end - start)
    rows = []
    for match in re.finditer(rb'\xff\x15', blob):
        site = start + match.start()
        slot = rip_target(img, site, 6, 2)
        if slot in img.rel:
            rows.append({'site': hex(site), 'slot': hex(slot), 'target': hex(img.rel[slot]), 'role': roles.get(slot, '')})
    for match in re.finditer(rb'\xe8', blob):
        site = start + match.start()
        target = rip_target(img, site, 5, 1)
        pos = bisect.bisect_left(index[0], target)
        if pos < len(index[0]) and index[0][pos] == target:
            rows.append({'site': hex(site), 'slot': '', 'target': hex(target), 'role': ''})
    return sorted(rows, key=lambda row: int(row['site'], 16))


def esi_immediate(img, site, name, wrapper):
    if name == 'set_write_buffer_size':
        prefix = wrapper['write_buffer_prefix']
        expect(img.read(site - len(prefix), len(prefix)) == prefix, 'write buffer call prefix differs')
        return struct.unpack('<I', prefix[prefix.index(b'\xbe') + 1:prefix.index(b'\xbe') + 5])[0]
    expect(img.read(site - 5, 1) == b'\xbe', f'{name} has no esi immediate at {site:#x}')
    return struct.unpack('<I', img.read(site - 4, 4))[0]


def check_wrapper(img, index, profile):
    wrapper = WRAPPERS[profile]
    start, end = extent(index, wrapper['start'])
    blob = img.read(start, end - start)
    sites = ffi_sites(img, start, end)
    first = {}
    for site, name in sites:
        first.setdefault(name, site)
    expect(sorted(first, key=first.get)[:len(HOT_ORDER)] == HOT_ORDER, f'{profile}: call order differs')

    matches = list(CACHE_RE.finditer(blob))
    expect(len(matches) == 1, f'{profile}: cache sequence not unique')
    match = matches[0]
    default_gib = struct.unpack('<I', match.group(1))[0]
    saturate = start + match.start(2) + 4 + struct.unpack('<i', match.group(2))[0]
    expect(img.read(saturate, 7) == bytes.fromhex('48c7c7ffffffff'), f'{profile}: saturation arm differs')
    expect(rip_target(img, saturate + 7, 6, 2) == FFI['lru_cache_create'][0], f'{profile}: saturation call differs')

    size_site = first['set_block_size']
    block_size = esi_immediate(img, size_site, 'set_block_size', wrapper)
    expect(img.read(size_site - 9, 4) == bytes.fromhex('488b3c24'), f'{profile}: block size receiver differs')
    create_site = first['block_options_create']
    tail = img.read(create_site + 6, 15)
    expect(tail[:3] == bytes.fromhex('4885c0') and tail[9:13] == bytes.fromhex('48890424'),
           f'{profile}: block options are not spilled to rsp')
    factory_site = first['set_table_factory']
    expect(bytes.fromhex('488b3424') in img.read(factory_site - 9, 9), f'{profile}: table factory argument differs')
    missing_site = first['set_create_if_missing']
    flag = esi_immediate(img, missing_site, 'set_create_if_missing', wrapper)
    expect(img.read(missing_site - 8, 3) == bytes.fromhex('4889c7'), f'{profile}: create_if_missing receiver differs')
    write_buffer = esi_immediate(img, first['set_write_buffer_size'], 'set_write_buffer_size', wrapper)

    btree = {}
    for label, pin in BTREE_PINS.items():
        btree[label] = hex(start + find_one(blob, pin, f'{profile} {label}'))

    open_site = start + find_one(blob, bytes.fromhex('4531c0e8'), f'{profile} open call') + 3
    expect(rip_target(img, open_site, 5, 1) == wrapper['open'], f'{profile}: open target differs')
    expect(open_site > factory_site, f'{profile}: open call precedes the table factory')
    validator_site = start + find_one(blob, bytes.fromhex('4889f7e8'), f'{profile} validator call') + 3
    expect(rip_target(img, validator_site, 5, 1) == wrapper['validator'], f'{profile}: validator target differs')
    expect(validator_site < create_site, f'{profile}: validator runs after option creation')
    return {
        'wrapper': hex(start), 'fde_end': hex(end),
        'default_cache_gib': default_gib,
        'default_cache_bytes': cache_capacity(None, default_gib),
        'block_size': block_size,
        'create_if_missing_esi': flag,
        'write_buffer_size': write_buffer,
        'cache_bits_tested_by_shr': 0x22,
        'cache_shift_left': 0x1e,
        'saturation_arm': hex(saturate),
        'open_call': {'site': hex(open_site), 'target': hex(wrapper['open'])},
        'validator_call': {'site': hex(validator_site), 'target': hex(wrapper['validator'])},
        'ffi_calls_in_address_order': [{'site': hex(site), 'role': name} for site, name in sites],
        'all_call_positions_create_to_open': calls_between(img, index, create_site, open_site + 5),
        'home_map_btree_pins': btree,
    }


def check_checkpoint_gate(img, index):
    start, end = extent(index, WRAPPERS['checkpoint']['start'])
    blob = img.read(start, end - start)
    pos = find_one(blob, bytes.fromhex('49bd0000000000000080'), 'None niche load')
    lea = find_one(blob, bytes.fromhex('498d4501'), 'sentinel lea')
    cmp_pos = find_one(blob, bytes.fromhex('48390675'), 'sentinel compare')
    expect(pos < lea < cmp_pos, 'sentinel sequence order differs')
    expect(img.read(start + cmp_pos + 3, 5) == bytes.fromhex('75084d89ef'), 'sentinel branch differs')
    jump = start + cmp_pos + 8
    expect(img.read(jump, 1) == b'\xe9', 'sentinel exit differs')
    target = rip_target(img, jump, 5, 1)
    expect(img.read(target, 3) == bytes.fromhex('4c893b'), 'None store differs')
    first_create = ffi_sites(img, start, end)[0][0]
    state_start, state_end = extent(index, WRAPPERS['state']['start'])
    state_blob = img.read(state_start, state_end - state_start)
    expect(bytes.fromhex('49bd0000000000000080') not in state_blob, 'state wrapper holds the same gate')
    expect(start + cmp_pos < first_create, 'gate runs after option creation')
    return {'compare_site': hex(start + cmp_pos), 'first_word_equals': hex((1 << 63) + 1),
            'returns_first_word': hex(1 << 63), 'exit': hex(target), 'state_wrapper_has_gate': False}


def bundle_names(img):
    names = []
    for index_ in range(BUNDLE_COUNT):
        pointer = img.rel.get(BUNDLE_PTRS + index_ * 8)
        expect(pointer is not None, 'bundle name pointer has no relocation')
        size = struct.unpack('<Q', img.read(BUNDLE_LENS + index_ * 8, 8))[0]
        names.append(img.read(pointer, size).decode('ascii'))
    return names


def check_validators(img, index):
    names = bundle_names(img)
    start, end = extent(index, WRAPPERS['state']['validator'])
    state = img.read(start, end - start)
    find_one(state, bytes.fromhex('c644240702'), 'state forbidden bundle byte')
    start, end = extent(index, WRAPPERS['checkpoint']['validator'])
    checkpoint = img.read(start, end - start)
    find_one(checkpoint, bytes.fromhex('66c78424a00100000001'), 'checkpoint forbidden bundle bytes')
    return {'bundle_names': names, 'state_forbids': [names[2]], 'checkpoint_forbids': [names[0], names[1]]}


def check_callers(img):
    code, base = img.code()
    rows = {}
    targets = {data['start']: name for name, data in WRAPPERS.items()}
    hits = collections.defaultdict(list)
    for match in re.finditer(rb'[\xe8\xe9]', code):
        pos = match.start()
        if pos + 5 > len(code):
            break
        target = base + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
        if target in targets:
            hits[targets[target]].append(base + pos)
    for name, wrapper in WRAPPERS.items():
        expect(hits[name] == [wrapper['caller_site']], f'{name}: rel32 call sites differ')
        rows[name] = {'site': hex(wrapper['caller_site']), 'caller_fde': hex(wrapper['caller'])}
    expect(img.read(0x3be4b59, 3) == bytes.fromhex('80fb03') and img.read(0x3be4b5c, 2) == bytes.fromhex('0f84'),
           'state caller bundle 3 skip differs')
    rows['state']['skips_bundle_byte'] = 3
    rows['checkpoint']['skips_bundle_byte'] = None
    return rows


def location(img, slot):
    pointer = img.rel.get(slot)
    expect(pointer is not None, f'location {slot:#x} has no relocation')
    size, line, col = struct.unpack('<QII', img.read(slot + 8, 16))
    path = img.read(pointer, size).decode('utf-8')
    for marker in ('code_Mainnet/', 'registry/src/'):
        if marker in path:
            path = path.split(marker, 1)[1]
    if path.startswith('index.crates.io-'):
        path = path.split('/', 1)[1]
    return {'slot': hex(slot), 'file': path, 'line': line, 'col': col}


def census(img, index):
    """Every byte position that resolves to a role's slot or body."""
    code, base = img.code()
    slots = {slot: name for name, (slot, _target) in FFI.items()}
    bodies = {target: name for name, (_slot, target) in FFI.items()}
    rows = []
    for match in re.finditer(rb'\xff[\x15\x25]', code):
        pos = match.start()
        if pos + 6 > len(code):
            break
        name = slots.get(base + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0])
        if name:
            rows.append((name, 'slot_call' if code[pos + 1] == 0x15 else 'slot_jump', base + pos))
    for match in re.finditer(rb'[\xe8\xe9]', code):
        pos = match.start()
        if pos + 5 > len(code):
            break
        name = bodies.get(base + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0])
        if name:
            rows.append((name, 'rel32', base + pos))
    for slot, target in img.rel.items():
        if target in bodies and slot != FFI[bodies[target]][0]:
            rows.append((bodies[target], 'other_relative_slot', slot))
    rows.sort(key=lambda r: (HOT_ORDER.index(r[0]) if r[0] in HOT_ORDER else len(HOT_ORDER), r[0], r[2], r[1]))
    return [(name, kind, site, owner(index, site) if kind != 'other_relative_slot' else None) for name, kind, site in rows]


def census_tsv(rows):
    lines = ['role\tkind\tsite\towner_fde']
    for name, kind, site, fde in rows:
        lines.append(f"{name}\t{kind}\t{site:#x}\t{'' if fde is None else hex(fde)}")
    return '\n'.join(lines) + '\n'


def census_summary(rows):
    per_role = collections.Counter(name for name, kind, _site, _fde in rows)
    owners = collections.defaultdict(set)
    for name, _kind, _site, fde in rows:
        if fde is not None:
            owners[name].add(fde)
    create = owners['options_create']
    missing = owners['set_create_if_missing']
    tuned = owners['set_write_buffer_size'] & owners['set_block_size'] & owners['set_table_factory']
    return {
        'sites_by_role': dict(sorted(per_role.items())),
        'options_create_owners': len(create),
        'owners_with_all_three_tuning_setters': sorted(hex(x) for x in tuned),
        'owners_with_create_if_missing_only': sorted(hex(x) for x in (create & missing) - tuned),
        'owners_with_no_pinned_setter': sorted(hex(x) for x in create - missing),
    }


def build(data):
    check_digest(data)
    img = Image(data)
    index = function_index(data)
    rows = census(img, index)
    profiles = {name: check_wrapper(img, index, name) for name in WRAPPERS}
    texts = {name: img.read(va, size).decode('ascii') for name, (va, size) in ROCKSDB_FAILURE_TEXTS.items()}
    report = {
        'schema': 'rocksdb-open-options/v1',
        'binary_sha256': SHA256,
        'coordinate_system': 'ELF virtual address',
        'ffi_slots': check_slots(img),
        'setter_bodies': check_setters(img),
        'constructor_defaults': check_defaults(img, index),
        'profiles': profiles,
        'checkpoint_gate': check_checkpoint_gate(img, index),
        'validators': check_validators(img, index),
        'callers': check_callers(img),
        'locations': {name: location(img, slot) for name, slot in LOCATIONS.items()},
        'failure_texts': texts,
        'census': census_summary(rows),
    }
    return {
        'open-options.json': json.dumps(report, indent=2, sort_keys=True) + '\n',
        'ffi-site-census.tsv': census_tsv(rows),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    files = build(load())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding='utf-8')
    print(' '.join(sorted(files)))


if __name__ == '__main__':
    main()
