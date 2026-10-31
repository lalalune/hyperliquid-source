#!/usr/bin/env python3
"""Pin the computed app_hash builders of node #94.

Three builders (0x2755dc0, 0x4d7e8c0, 0x4d7c910) box 41 hash closures, run them,
and build a 32-byte value from two Keccak digests. This tool reads the closure
tables, the fields the low-lane closures capture, the hash core inside every
closure body, the height cadence at the three call sites and the two-digest
output.

Every number comes from ELF bytes read with struct: section headers through
tools/elf_index.py, FDE extents through tools/fde_extents.py, and RELATIVE
relocations from .rela.dyn. Instructions are only matched as fixed byte
patterns. No external program runs and the binary is never executed.
"""
import argparse
import bisect
import collections
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
JSON_NAME = 'app-hash-builder.json'
ROWS_NAME = 'closure-rows.tsv'
R_X86_64_RELATIVE = 8
SHT_NOBITS = 8

ROW_COUNT = 41
ROW_STRIDE = 0x20
LOW_BUILDER = 0x2755dc0
LOW_TABLE = 0x56bda38
SHARED_TABLE = 0x57446e8
LOG_TEMPLATE = 0x1ded08
LOCATION_MARK = b'/code_Mainnet/'
COUNT_CHECK_LOCATION = 0x56e9ac8
# The template holds at-signs; evidence spells them AT_MARK.
AT_SIGN = chr(0x40)
AT_MARK = '<at>'
LOG_PIECES = [None, ' WARN >>> ', None, ' <at><at> computed app_hash: ', None, '\n', None,
              '\n <at><at> [context: ', None, '] <at> [pre_hash_latency: ', None,
              '] <at> [total_latency: ', None, ']\n\n']
SLOT_UPDATE = 0x576e1d8
SLOT_FINALIZE = 0x576e1e0
SLOT_PERMUTE = 0x5777790
UPDATE_TARGET = 0x4f59a10
FINALIZE_TARGET = 0x4f59e40
PERMUTE_TARGET = 0x4f59480
ROUND_TABLE = 0x7d04c8
ROUND_WORDS = 24
# Round constants 0 to 2 of Keccak-f[1600], the head of the table the tool checks.
ROUND_HEAD = (0x1, 0x8082, 0x800000000000808a)
PARALLEL_RUN = 0x25b7ef0
DIGEST_LIST_WRITER = 0x1e5de50
BLOCK_WRITER = 0x21a34e0
HEX_SLOT = 0x5773120

# (builder, closure table, lane, caller, cadence compare bytes and VA,
#  builder call, map lea bytes and VA, map call)
SITES = [
    {'lane': 'low', 'builder': LOW_BUILDER, 'table': LOW_TABLE, 'caller': 0x2209d40,
     'cmp_va': 0x220afc2, 'cmp': '80bbf208000002', 'mode_offset': 0x8f2, 'call': 0x220b007,
     'map_va': 0x220b01e, 'map': '488db0283b0000', 'map_offset': 0x3b28, 'insert': 0x220b035},
    {'lane': 'primary', 'builder': 0x4d7e8c0, 'table': SHARED_TABLE, 'caller': 0x42e4600,
     'cmp_va': 0x42e4f8a, 'cmp': '4180bf7213000002', 'mode_offset': 0x1372, 'call': 0x42e4fcf,
     'map_va': 0x42e4fea, 'map': '498db7a8450000', 'map_offset': 0x45a8, 'insert': 0x42e5001},
    {'lane': 'secondary', 'builder': 0x4d7c910, 'table': SHARED_TABLE, 'caller': 0x42e5d40,
     'cmp_va': 0x42e665a, 'cmp': '4180bff208000002', 'mode_offset': 0x8f2, 'call': 0x42e669f,
     'map_va': 0x42e66b2, 'map': '498db7283b0000', 'map_offset': 0x3b28, 'insert': 0x42e66c9},
]
CADENCE_TAIL = bytes.fromhex('b832000000b9d0070000480f42c8')

RATE = re.compile(rb'\x48\xc7\x84\x24....\x88\x00\x00\x00', re.S)
DELIM = re.compile(rb'\x66\xc7\x84\x24....\x01\x00', re.S)
WRITER_CONFIG = re.compile(rb'\xc7(?:\x44\x24.|\x84\x24....)\x00\x04\x00\x01', re.S)
FINAL_LEN = bytes.fromhex('ba20000000')
STATE_COPY = bytes.fromhex('bae0000000')
THUNK = re.compile(rb'\x53\x48\x89\xfb\xe8(....)\x48\x89\xd8\x5b\xc3', re.S)
# Lattice digest to +0x2c8, digest list digest to +0x330, then the 16-byte reads.
OUTPUT = re.compile(rb'\x48\x8d\xbc\x24\xc8\x02\x00\x00\x4c\x89\xf6\xe8(....)'
                    rb'\x48\x8d\xbc\x24\x30\x03\x00\x00\x48\x8d\xb4\x24(....)\xe8(....)'
                    rb'\x66\x0f\x10\x84\x24\x30\x03\x00\x00'
                    rb'\x66\x0f\x29\x84\x24\xa0\x02\x00\x00'
                    rb'\x66\x0f\x10\x8c\x24\xc8\x02\x00\x00'
                    rb'\x66\x0f\x29\x8c\x24\xb0\x02\x00\x00'
                    rb'\x48\x8b\x84\x24(....)\x66\x0f\x11\x48\x10\x66\x0f\x11\x00', re.S)
SAVE_RDI = bytes.fromhex('4889bc24')
BLOCKS_LEN = bytes.fromhex('ba30180000')
BOX_ALLOC = bytes.fromhex('bf90020000')
JOB_COUNT = bytes.fromhex('48c784245003000029000000')
BLOCK_LEN = bytes.fromhex('ba10080000')

# Low-lane capture code: [start, end) of the boxing and of the fat pointer writes.
CAPTURE_START = 0x275636a
FAT_START = 0x2756b6e
FAT_END = 0x2756fb1
SINGLE = re.compile(rb'\x48\x8d\x8d(....)\x48\x89\x84\x24(....)\x48\x89\x08', re.S)
TAIL_SINGLE = re.compile(rb'\x48\x8d\x85(....)\x49\x89(\x07|\x45\x00)', re.S)
# Source register of the row -> (field write pattern, box bytes).
GROUPS = {
    'r12': (re.compile(rb'\x48\x8d\x85(....)\x49\x89(?:\x04\x24|\x44\x24(.))', re.S), 0x78),
    'rbp': (re.compile(rb'\x49\x8d\x86(....)\x48\x89\x45(.)', re.S), 0x80),
    'rax': (re.compile(rb'\x49\x8d\x8e(....)\x48\x89(?:\x08|\x48(.))', re.S), 0x40),
}
STATE_SOURCE = 0x50
# rsp slot of a row -> the Vec it boxes.
VEC_ROWS = {
    0x10: 'per-dex list of 48-byte records (dex [+0x8]/[+0x10] stride 0xd8, callee 0x23975f0)',
    0x48: '48-byte records from state+0x3388/+0x3390 (stride 0xd8, callee 0x2397ae0)',
    0x1e8: 'per-dex pointers dex+0x48',
    0x1b8: 'per-dex pointers dex+0x18',
    0xd8: 'per-dex pointers dex+0x120',
}
TAIL_ROWS = {'r15': 0, 'r13': 1}
# (VA, exact bytes, meaning)
BYTE_PINS = [
    (0x2755e39, '4d8bbc2478330000', 'mov r15, [r12+0x3378]: dex count'),
    (0x2755e41, '4d3bbc24c8050000', 'cmp r15, [r12+0x5c8]: second length must match'),
    (0x2755fbf, '4869c038010000', 'imul rax, rax, 0x138: dex stride'),
    (0x2756060, '498db680000000', 'lea rsi, [r14+0x80]: inner record argument'),
    (0x27560a8, '4981c6d8000000', 'add r14, 0xd8: per-dex inner stride'),
    (0x275615d, '498d4748', 'lea rax, [r15+0x48]: per-dex pointer'),
    (0x2756189, '498d4718', 'lea rax, [r15+0x18]: per-dex pointer'),
    (0x2755fe7, '4981c720010000', 'add r15, 0x120: per-dex pointer'),
    (0x27561cf, '4c8bbd90330000', 'mov r15, [rbp+0x3390]: record count'),
    (0x27561df, '488b9d88330000', 'mov rbx, [rbp+0x3388]: record pointer'),
    (0x27561c7, '488bac2408020000', 'mov rbp, [rsp+0x208]: state base'),
    (0x2756fb1, '48c7842450030000' + '29000000', 'job count 41'),
    (0x275701f, '498db6b80c0000', 'lea rsi, [r14+0xcb8]: first block'),
    (0x2757040, '498db6c0150000', 'lea rsi, [r14+0x15c0]: second block'),
    (0x2757057, '4981c6c81e0000', 'add r14, 0x1ec8: third block'),
    (DIGEST_LIST_WRITER + 0x28, 'c784249000000000040001', 'writer config 0x1000400'),
    (DIGEST_LIST_WRITER + 0xd1, 'be42000000', 'mov esi, 0x42: text buffer per digest'),
    (DIGEST_LIST_WRITER + 0xd6, 'b920000000', 'mov ecx, 0x20: digest bytes'),
    (DIGEST_LIST_WRITER + 0xfc, '4983c620', 'add r14, 0x20: next digest'),
    (0x28183f5, 'c744240800040001', 'writer config 0x1000400 for the block hash'),
]
# (VA, prefix, rel32 target, meaning)
RIP_PINS = [
    (0x2755e4b, '488d35', COUNT_CHECK_LOCATION, 'Location of the length check'),
    (0x2756ffe, 'e8', PARALLEL_RUN, 'job runner'),
    (0x28192ac, 'e8', DIGEST_LIST_WRITER, 'digest list writer'),
    (DIGEST_LIST_WRITER + 0x9e, '4c8b2d', HEX_SLOT, 'per-digest text helper slot'),
    (0x281840d, 'e8', BLOCK_WRITER, 'block writer'),
]


class View:
    """Read-only VA view over file-backed sections, with .rela.dyn addends."""

    def __init__(self, data):
        self.data = data
        self.sections = elf_index.sections(data)
        self.loaded = [s for s in self.sections
                       if s['type'] != SHT_NOBITS and s['address'] and s['size']]
        self.addends = {}
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        for slot, info, addend in struct.iter_unpack(
                '<QQq', data[rela['offset']:rela['offset'] + rela['size']]):
            if info & 0xffffffff == R_X86_64_RELATIVE:
                self.addends[slot] = addend

    def mem(self, va, size):
        for sec in self.loaded:
            if sec['address'] <= va and va + size <= sec['address'] + sec['size']:
                start = sec['offset'] + va - sec['address']
                return self.data[start:start + size]
        raise ValueError(f'{va:#x}+{size} is outside file-backed sections')

    def relative(self, slot):
        if slot not in self.addends:
            raise ValueError(f'no RELATIVE relocation at {slot:#x}')
        return self.addends[slot]

    def u64(self, va):
        return struct.unpack('<Q', self.mem(va, 8))[0]


class Extents:
    """FDE starts and ends, sorted, from tools/fde_extents.py."""

    def __init__(self, data):
        ordered = fde_extents.fde_extents(data)[1]
        self.rows = sorted((f['start'], f['end']) for f in ordered)
        self.starts = [row[0] for row in self.rows]

    def at(self, va):
        index = bisect.bisect_right(self.starts, va) - 1
        if index < 0 or not self.rows[index][0] <= va < self.rows[index][1]:
            raise ValueError(f'{va:#x} is not inside an FDE extent')
        return self.rows[index]

    def body(self, view, va):
        """Return (start, bytes) of the extent that starts exactly at va."""
        low, high = self.at(va)
        if low != va:
            raise ValueError(f'{va:#x} is inside the extent at {low:#x}')
        return low, view.mem(low, high - low)


def rel32(view, va, prefix):
    """Resolve prefix + rel32 at va, failing closed on different bytes."""
    if view.mem(va, len(prefix)) != prefix:
        raise ValueError(f'instruction bytes differ at {va:#x}')
    return va + len(prefix) + 4 + struct.unpack('<i', view.mem(va + len(prefix), 4))[0]


def check_byte_pins(view):
    pins = []
    for va, raw, meaning in BYTE_PINS:
        if view.mem(va, len(bytes.fromhex(raw))).hex() != raw:
            raise ValueError(f'bytes differ at {va:#x}')
        pins.append({'va': hex(va), 'bytes': raw, 'meaning': meaning})
    for va, prefix, target, meaning in RIP_PINS:
        if rel32(view, va, bytes.fromhex(prefix)) != target:
            raise ValueError(f'{va:#x} does not reach {target:#x}')
        pins.append({'va': hex(va), 'target': hex(target), 'meaning': meaning})
    return pins


def decode_template(view, va):
    """Decode a Rust format template holding literals and argument slots."""
    pieces, pos = [], va
    for _ in range(32):
        tag = view.mem(pos, 1)[0]
        pos += 1
        if tag == 0:
            return pieces
        if tag & 0xc0 == 0xc0:
            pieces.append(None)
        elif tag < 0x80:
            pieces.append(view.mem(pos, tag).decode('ascii').replace(AT_SIGN, AT_MARK))
            pos += tag
        else:
            raise ValueError(f'unsupported template tag {tag:#x} at {pos - 1:#x}')
    raise ValueError(f'unterminated template at {va:#x}')


def source_location(view, va):
    """Read a Rust Location: path pointer, length, line, column."""
    pointer = view.relative(va)
    length = view.u64(va + 8)
    line, column = struct.unpack('<II', view.mem(va + 0x10, 8))
    path = view.mem(pointer, length)
    if LOCATION_MARK not in path:
        raise ValueError(f'Location {va:#x} has no source root mark')
    return {'file': path.split(LOCATION_MARK, 1)[1].decode('ascii'), 'line': line, 'column': column}


def slot_uses(body, base, slot):
    """Count `call [rip+x]` sites in a body that name one slot."""
    count = 0
    for match in re.finditer(rb'\xff\x15(....)', body, re.S):
        count += base + match.end() + struct.unpack('<i', match.group(1))[0] == slot
    return count


def hash_core(view, extents, va):
    """Count the hash core pieces inside the extent that starts at va."""
    low, body = extents.body(view, va)
    return {'start': low, 'bytes': len(body), 'rate_136': len(RATE.findall(body)),
            'delim_1': len(DELIM.findall(body)), 'update': slot_uses(body, low, SLOT_UPDATE),
            'finalize': slot_uses(body, low, SLOT_FINALIZE), 'out_32': body.count(FINAL_LEN),
            'state_copy': body.count(STATE_COPY), 'writer_config': len(WRITER_CONFIG.findall(body))}


def require_single_core(core):
    for key in ('rate_136', 'delim_1', 'update', 'finalize', 'out_32', 'state_copy'):
        if core[key] != 1:
            raise ValueError(f"hash core at {core['start']:#x}: {key} = {core[key]}")


def table_rows(view, extents, table):
    """Read one closure table and follow each call slot to its hash body."""
    rows = []
    for index in range(ROW_COUNT):
        vtable = table + index * ROW_STRIDE
        call = view.relative(vtable + 0x18)
        low, body = extents.body(view, call)
        thunk = THUNK.fullmatch(body)
        target = low + 9 + struct.unpack('<i', thunk.group(1))[0] if thunk else call
        core = hash_core(view, extents, target)
        require_single_core(core)
        rows.append({'index': index, 'vtable': vtable, 'size': view.u64(vtable + 8),
                     'align': view.u64(vtable + 0x10), 'drop': view.addends.get(vtable, 0),
                     'call': call, 'thunk': bool(thunk), 'core': core})
    return rows


def low_boxes(view):
    """Read the box writes of the low-lane builder."""
    code = view.mem(CAPTURE_START, FAT_START - CAPTURE_START)
    slots = {}
    for match in SINGLE.finditer(code):
        slots[struct.unpack('<I', match.group(2))[0]] = struct.unpack('<i', match.group(1))[0]
    tails = [struct.unpack('<i', m.group(1))[0] for m in TAIL_SINGLE.finditer(code)]
    if len(tails) != len(TAIL_ROWS):
        raise ValueError('register-held single boxes differ')
    groups = {}
    for name, (pattern, size) in GROUPS.items():
        fields = {}
        for match in pattern.finditer(code):
            fields[match.group(2)[0] if match.group(2) else 0] = struct.unpack('<i', match.group(1))[0]
        if sorted(fields) != list(range(0, size, 8)):
            raise ValueError(f'{name} box writes are not contiguous')
        groups[name] = [fields[key] for key in sorted(fields)]
    return slots, tails, groups


def fat_sources(view):
    """Return (row, source) from the fixed fat pointer writes of the low-lane builder."""
    code = view.mem(FAT_START, FAT_END - FAT_START)
    load = re.compile(rb'\x48\x8b(?:\x4c\x24(.)|\x8c\x24(....))', re.S)
    store = re.compile(rb'\x48\x89(?:\x0b|\x4b(.)|\x8b(....))', re.S)
    reg_store = re.compile(rb'(\x4c\x89\xbb|\x4c\x89\xab|\x4c\x89\xa3|\x48\x89\xab|\x48\x89\x83)(....)', re.S)
    lea = re.compile(rb'\x48\x8d(\x0d|\x05)(....)', re.S)
    tail_store = re.compile(rb'\x48\x89\x83(....)', re.S)
    names = {b'\x4c\x89\xbb': 'r15', b'\x4c\x89\xab': 'r13', b'\x4c\x89\xa3': 'r12',
             b'\x48\x89\xab': 'rbp', b'\x48\x89\x83': 'rax'}

    def disp(match):
        if match.group(1) is not None:
            return match.group(1)[0]
        return struct.unpack('<I', match.group(2))[0] if match.group(2) else 0

    sources, pos = [], 0
    for row in range(ROW_COUNT):
        first = load.match(code, pos)
        if first:
            source = first.group(1)[0] if first.group(1) else struct.unpack('<I', first.group(2))[0]
            write = store.match(code, first.end())
            if not write:
                raise ValueError(f'row {row}: no data store')
            offset = disp(write)
        else:
            write = reg_store.match(code, pos)
            if not write:
                raise ValueError(f'row {row}: no data source at {FAT_START + pos:#x}')
            source, offset = names[write.group(1)], struct.unpack('<I', write.group(2))[0]
        if offset != row * 16:
            raise ValueError(f'row {row}: data stored at {offset:#x}')
        table = lea.match(code, write.end())
        if not table:
            raise ValueError(f'row {row}: no vtable lea')
        vtable = FAT_START + table.end() + struct.unpack('<i', table.group(2))[0]
        if vtable != LOW_TABLE + row * ROW_STRIDE:
            raise ValueError(f'row {row}: vtable {vtable:#x} out of order')
        if table.group(1) == b'\x0d':
            pointer = store.match(code, table.end())
            offset = disp(pointer) if pointer else None
        else:
            pointer = tail_store.match(code, table.end())
            offset = struct.unpack('<I', pointer.group(1))[0] if pointer else None
        if offset != row * 16 + 8:
            raise ValueError(f'row {row}: vtable stored at {offset}')
        sources.append((row, source))
        pos = pointer.end()
    return sources


def capture_rows(view):
    """Join the fat pointer writes with the boxes to give each row its captures."""
    slots, tails, groups = low_boxes(view)
    rows = []
    for row, source in fat_sources(view):
        if source == STATE_SOURCE:
            kind, fields = 'base pointer', [0]
        elif source in VEC_ROWS:
            kind, fields = 'vec', []
        elif source in slots:
            kind, fields = 'field', [slots[source]]
        elif source in TAIL_ROWS:
            kind, fields = 'field', [tails[TAIL_ROWS[source]]]
        elif source in groups:
            kind, fields = 'field group', groups[source]
        else:
            raise ValueError(f'row {row}: unknown source {source!r}')
        rows.append({'row': row, 'kind': kind, 'fields': fields,
                     'vec': VEC_ROWS.get(source, '')})
    return rows


def check_site(view, extents, site):
    """Pin one call site: modulus choice, builder call, map offset."""
    cmp_raw = bytes.fromhex(site['cmp'])
    if view.mem(site['cmp_va'], len(cmp_raw)) != cmp_raw:
        raise ValueError(f"cadence compare differs at {site['cmp_va']:#x}")
    tail = view.mem(site['cmp_va'] + len(cmp_raw), len(CADENCE_TAIL))
    if tail != CADENCE_TAIL:
        raise ValueError(f"cadence moduli differ at {site['cmp_va']:#x}")
    low_mod = struct.unpack('<I', tail[1:5])[0]
    high_mod = struct.unpack('<I', tail[6:10])[0]
    if rel32(view, site['call'], b'\xe8') != site['builder']:
        raise ValueError(f"call at {site['call']:#x} misses the builder")
    if view.mem(site['map_va'], 7).hex() != site['map']:
        raise ValueError(f"map lea differs at {site['map_va']:#x}")
    if struct.unpack('<i', view.mem(site['map_va'] + 3, 4))[0] != site['map_offset']:
        raise ValueError('map offset differs')
    insert = rel32(view, site['insert'], b'\xe8')
    for va in (site['cmp_va'], site['call'], site['map_va'], site['insert']):
        if extents.at(va)[0] != site['caller']:
            raise ValueError(f"{va:#x} is outside caller {site['caller']:#x}")
    return {'lane': site['lane'], 'caller': hex(site['caller']), 'builder': hex(site['builder']),
            'closure_table': hex(site['table']), 'mode_byte_offset': hex(site['mode_offset']),
            'mode_threshold': cmp_raw[-1], 'modulus_below_threshold': low_mod,
            'modulus_otherwise': high_mod, 'builder_call': hex(site['call']),
            'map_offset': hex(site['map_offset']), 'store_call': hex(site['insert']),
            'store_callee': hex(insert)}


def check_output(view, extents, site):
    """Pin the two digests and their 16-byte use in one builder."""
    low, body = extents.body(view, site['builder'])
    matches = list(OUTPUT.finditer(body))
    if len(matches) != 1:
        raise ValueError(f"{low:#x}: {len(matches)} output blocks")
    match = matches[0]
    lattice_call = low + match.start() + 0xb
    lattice = lattice_call + 5 + struct.unpack('<i', match.group(1))[0]
    list_call = low + match.start(3) - 1
    digests = list_call + 5 + struct.unpack('<i', match.group(3))[0]
    out_slot = match.group(4)
    if SAVE_RDI + out_slot not in body[:0x90]:
        raise ValueError(f'{low:#x}: out slot does not hold rdi')
    for name, raw, want in (('box', BOX_ALLOC, 1), ('jobs', JOB_COUNT, 1), ('blocks', BLOCKS_LEN, 1),
                            ('block', BLOCK_LEN, 3)):
        if body.count(raw) < want:
            raise ValueError(f'{low:#x}: {name} bytes missing')
    template = sum(1 for m in re.finditer(rb'\x48\x8d\x3d(....)', body, re.S)
                   if low + m.end() + struct.unpack('<i', m.group(1))[0] == LOG_TEMPLATE)
    if template != 1:
        raise ValueError(f'{low:#x}: log template uses = {template}')
    cores = {name: hash_core(view, extents, va) for name, va in
             (('lattice', lattice), ('digest_list', digests))}
    for core in cores.values():
        require_single_core(core)
    return {'builder': hex(low), 'builder_bytes': len(body), 'blocks_hash': hex(lattice),
            'digest_list_hash': hex(digests), 'blocks_hash_call': hex(lattice_call),
            'digest_list_hash_call': hex(list_call), 'out_write': hex(low + match.end() - 9),
            'out_low_16': 'digest_list_hash', 'out_high_16': 'blocks_hash'}


def check_keccak(view, extents):
    """Tie the update, finalize and permutation slots to the round table."""
    for slot, target in ((SLOT_UPDATE, UPDATE_TARGET), (SLOT_FINALIZE, FINALIZE_TARGET),
                         (SLOT_PERMUTE, PERMUTE_TARGET)):
        if view.relative(slot) != target:
            raise ValueError(f'slot {slot:#x} does not hold {target:#x}')
    words = struct.unpack(f'<{ROUND_WORDS}Q', view.mem(ROUND_TABLE, ROUND_WORDS * 8))
    if words[:3] != ROUND_HEAD:
        raise ValueError('round table differs')
    # The round constants of Keccak-f[1600] come from an LFSR over bit positions 2^j - 1.
    state = 1
    for word in words:
        expected = 0
        for j in range(7):
            state = ((state << 1) ^ ((state >> 7) * 0x71)) & 0xff
            if state & 2:
                expected ^= 1 << ((1 << j) - 1)
        if expected != word:
            raise ValueError('round table is not the Keccak LFSR sequence')
    low, body = extents.body(view, PERMUTE_TARGET)
    uses = sum(1 for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d](....)', body, re.S)
               if low + m.end() + struct.unpack('<i', m.group(1))[0] == ROUND_TABLE)
    if uses != 1:
        raise ValueError(f'permutation uses the round table {uses} times')
    return {'update': hex(UPDATE_TARGET), 'finalize': hex(FINALIZE_TARGET), 'permutation': hex(PERMUTE_TARGET),
            'round_table': hex(ROUND_TABLE), 'round_words': ROUND_WORDS, 'rate_bytes': 136,
            'delimiter': 1, 'output_bytes': 32, 'round_table_matches_lfsr': True}


def row_line(low, shared, capture):
    fields = ','.join(hex(value) for value in capture['fields'])
    return '\t'.join([
        str(low['index']), hex(low['vtable']), hex(low['size']), hex(low['drop']), hex(low['call']),
        hex(low['core']['start']), str(low['core']['bytes']), capture['kind'], fields or '-',
        capture['vec'] or '-', hex(shared['vtable']), hex(shared['size']), hex(shared['core']['start']),
        str(shared['core']['bytes'])])


def analyse(view, extents):
    pins = check_byte_pins(view)
    if decode_template(view, LOG_TEMPLATE) != LOG_PIECES:
        raise ValueError('log template differs')
    keccak = check_keccak(view, extents)
    low_rows = table_rows(view, extents, LOW_TABLE)
    shared_rows = table_rows(view, extents, SHARED_TABLE)
    captures = capture_rows(view)
    sites = [check_site(view, extents, site) for site in SITES]
    outputs = [check_output(view, extents, site) for site in SITES]
    if [r['size'] for r in low_rows] != [r['size'] for r in shared_rows]:
        raise ValueError('closure sizes differ between tables')
    for rows in (low_rows, shared_rows):
        if len({r['core']['start'] for r in rows}) != ROW_COUNT:
            raise ValueError('closure bodies repeat')
    for capture, row in zip(captures, low_rows):
        want = {'base pointer': 8, 'field': 8, 'vec': 24}.get(capture['kind'], len(capture['fields']) * 8)
        if row['size'] != want:
            raise ValueError(f"row {row['index']}: box size {row['size']:#x}, captures {want:#x}")
    fields = [value for capture in captures for value in capture['fields'] if capture['kind'] != 'base pointer']
    if len(set(fields)) != len(fields):
        raise ValueError('a field is captured twice')
    kinds = collections.Counter(capture['kind'] for capture in captures)
    summary = {
        'binary_sha256': SHA256,
        'rows_per_table': ROW_COUNT,
        'tables': [hex(LOW_TABLE), hex(SHARED_TABLE)],
        'bodies_with_one_hash_core': len(low_rows) + len(shared_rows),
        'bodies_with_writer_config': sum(r['core']['writer_config'] > 0 for r in low_rows + shared_rows),
        'low_rows_by_capture': dict(sorted(kinds.items())),
        'low_distinct_state_fields': len(fields),
        'low_field_offset_range': [hex(min(fields)), hex(max(fields))],
        'box_sizes': dict(sorted(collections.Counter(hex(r['size']) for r in low_rows).items())),
        'count_check_location': source_location(view, COUNT_CHECK_LOCATION),
        'keccak': keccak,
        'call_sites': sites,
        'outputs': outputs,
        'byte_pins': pins,
        'log_template': hex(LOG_TEMPLATE),
        'log_pieces': LOG_PIECES,
    }
    lines = ['row\tlow_vtable\tbox_size\tdrop\tcall_slot\tlow_body\tlow_body_bytes\tcapture\tstate_offsets\tvec_source\t'
             'shared_vtable\tshared_box_size\tshared_body\tshared_body_bytes']
    lines += [row_line(low, shared, capture) for low, shared, capture in zip(low_rows, shared_rows, captures)]
    return summary, '\n'.join(lines) + '\n'


def build(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('binary digest differs from node #94')
    return analyse(View(data), Extents(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    data = BINARY.read_bytes()
    summary, rows = build(data)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / JSON_NAME).write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    (args.out / ROWS_NAME).write_text(rows)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(f'app_hash_builder: {error}')
