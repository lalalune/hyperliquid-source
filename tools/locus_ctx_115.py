#!/usr/bin/env python3
"""Node #115: Locus field 0 `ctx` is the 13-field struct Context.

Open PR #6589 mapped the 16 field arms of the MessagePack Locus visitor
0x332c430 and named the decoder of field 0 (`ctx`) as 0x30d1c60. Main has no
tool, test or work item for that decoder. This tool checks what it decodes:

1. Locus calls 0x30d1c60 at two sites, 0x332c6ad and 0x332c805.
2. The expected-text record 0x6462690 has one R_X86_64_RELATIVE relocation to
   0x793562, and its length word is 31: `struct Context with 13 elements`.
3. The map path reads each key through slot 0x64e41e0 (relocated to the key
   reader 0x348eca0). On result tag 9 it takes the field index from the
   result and jumps through table 0x68ac4c. The key reader turns an integer
   key k into min(k, 13), so index 13 is the "other key" arm, which calls the
   skip reader 0x31d5e50.
4. Each arm 0..12 first tests whether its field is already set. If it is,
   the arm jumps to a block that loads the field name and its length and then
   joins one shared tail that loads the template `duplicate field `...``
   (0x43351a). This binds each index to one name. Otherwise the arm reads the
   value: 6 arms call one function, 6 integer arms reach a call through slot
   0x64e2580 (relocated to 0x348e980) or 0x64dfeb0 (relocated to 0x14b7aa0)
   and store the "set" flag that the arm tests.
5. Six fields have a block that loads the name and the template
   `missing field `...`` (0x4325c4) and calls 0x3046740, which always
   returns tag 6, not the success tag 9. These fields are required.
6. The sequence path loads the same record at exactly 6 sites, each with a
   fixed element index. The 6 indexes are the 6 required fields. The other 7
   fields have neither a missing-field block nor a sequence-length error.

The tool only compares fixed bytes at fixed addresses, jump-table entries,
branch and call targets, RIP-relative references, relocations, function
extents from .eh_frame_hdr, and strings. The captured binary is not executed.
objdump and readelf are not started. Addresses are ELF virtual addresses.
"""
import argparse
import bisect
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections, unwind_index

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-locus-ctx-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

LOCUS = 0x332c430
LOCUS_CALLS = (0x332c6ad, 0x332c805)
CTX = 0x30d1c60
CTX_EXTENT = 0x2290
KEY_CALL = 0x30d2172
KEY_SLOT = 0x64e41e0
KEY_READER = 0x348eca0
FIELD_TABLE = 0x68ac4c
FIELD_TABLE_LEA = 0x30d218a
OTHER_ARM = 0x30d20b1
SKIP_CALL = 0x30d20be
SKIP = 0x31d5e50
DUP_TAIL = 0x30d3b02
DUP_TEMPLATE_LEA = 0x30d3b13
DUP_TEMPLATE = 0x43351a
MISSING_TEMPLATE = 0x4325c4
ERROR_FMT = 0x3046740
ERROR_FMT_TAG = 0x30467bd
NAME_RECORD = 0x6462690
NAME_TEXT = b'struct Context with 13 elements'
SEQ_ERROR_CALL = 0x30d338e
SEQ_ERROR = 0x2f7fe90
INT_SLOT = 0x64e2580
INT_READER = 0x348e980
U64_SLOT = 0x64dfeb0
U64_READER = 0x14b7aa0

PINS = {   # address -> (bytes, meaning)
    0x30d217d: ('3c09', 'key result tag compared with 9'),
    0x30d2185: ('0fb6442431', 'field index taken from the key result'),
    0x30d2191: ('48630481', 'field table load'),
    0x348ed00: ('80f90db90d0000000f42c8', 'key reader: integer key clamped to 13'),
    0x348ed0e: ('c60709', 'key reader: success tag 9'),
    ERROR_FMT_TAG: ('c60306', 'error formatter: result tag 6'),
}
# index -> (arm, duplicate branch site, opcode, duplicate block, name,
#           value kind, value call site, call target or slot, flag-store site)
# 'call' arms call a function directly; 'slot' arms reach an indirect call
# through a slot from a marker branch in the arm and then store the flag that
# the arm tests.
FIELDS = {
    0: (0x30d219a, 0x30d21a3, '0f84', 0x30d3a42, 'hardfork_height', 'slot', 0x30d2c91, INT_SLOT,
        0x30d2cb6, 0x30d21bb),
    1: (0x30d249e, 0x30d24a7, '0f84', 0x30d3abb, 'hardfork', 'call', 0x30d24b7, 0x32b03e0,
        None, None),
    2: (0x30d23a6, 0x30d23af, '0f84', 0x30d3aa4, 'height', 'slot', 0x30d2be9, INT_SLOT,
        0x30d2c0e, 0x30d23c7),
    3: (0x30d23fe, 0x30d2407, '0f85', 0x30d3ac4, 'tx_index', 'call', 0x30d2415, 0x451c540,
        None, None),
    4: (0x30d22ae, 0x30d22b7, '0f84', 0x30d3ad6, 'round', 'call', 0x30d22c5, 0x4524ae0,
        None, None),
    5: (0x30d24f5, 0x30d24fd, '0f85', 0x30d3a05, 'time', 'call', 0x30d250b, 0x3d4f3c0,
        None, None),
    6: (0x30d253a, 0x30d253d, '0f85', 0x30d3a8d, 'prev_time', 'call', 0x30d254b, 0x3d4f3c0,
        None, None),
    7: (0x30d2446, 0x30d244f, '0f84', 0x30d3aed, 'next_oid', 'slot', 0x30d2c3d, INT_SLOT,
        0x30d2c62, 0x30d2467),
    8: (0x30d25bc, 0x30d25c5, '0f84', 0x30d3acd, 'next_lid', 'slot', 0x30d2ce5, INT_SLOT,
        0x30d2d0a, 0x30d25dd),
    9: (0x30d234e, 0x30d2357, '0f84', 0x30d3a76, 'next_twap_id', 'slot', 0x30d2b95, INT_SLOT,
        0x30d2bba, 0x30d236f),
    10: (0x30d2574, 0x30d257d, '0f84', 0x30d3a39, 'system_nonce', 'call', 0x30d258b, 0x421db60,
         None, None),
    11: (0x30d227f, 0x30d2283, '0f85', 0x30d3a1f, 'use_system_nonce', 'call', 0x30d2291,
         0x37ce740, None, None),
    12: (0x30d22f6, 0x30d22ff, '0f84', 0x30d3a5c, 'mac', 'slot', 0x30d2b41, U64_SLOT,
         0x30d2b66, 0x30d2317),
}
# required field name -> (name lea site, missing-template lea site, formatter call site)
MISSING = {
    'hardfork_height': (0x30d30a3, 0x30d30ce, 0x30d30df),
    'height': (0x30d3473, 0x30d349e, 0x30d34af),
    'time': (0x30d3509, 0x30d3534, 0x30d3545),
    'prev_time': (0x30d35ac, 0x30d35d7, 0x30d35e8),
    'next_oid': (0x30d3657, 0x30d3682, 0x30d3693),
    'next_lid': (0x30d3700, 0x30d372b, 0x30d373c),
}
# sequence-path record lea site -> (index operand site, element index)
SEQ_SITES = {
    0x30d322b: (0x30d323e, 0),
    0x30d3376: (0x30d3389, 2),
    0x30d39e8: (0x30d39fb, 5),
    0x30d3db9: (0x30d3dcc, 6),
    0x30d3dd6: (0x30d3de9, 7),
    0x30d3e02: (0x30d3e15, 8),
}


def read_va(data, va, size):
    hits = [s for s in sections(data)
            if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = hits[0]['offset'] + va - hits[0]['address']
    return data[off:off + size]


def rel_target(data, va, length):
    return va + length + struct.unpack('<i', read_va(data, va + length - 4, 4))[0]


def relocation(data, slot):
    rela = [s for s in sections(data) if s['name'] == '.rela.dyn']
    if len(rela) != 1 or rela[0]['size'] % 24:
        raise ValueError('invalid relocation table')
    hits = []
    for off in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, off)
        if where == slot:
            hits.append((info, addend))
    if len(hits) != 1 or hits[0][0] != 8:
        raise ValueError(f'slot {slot:#x} has no single relative relocation')
    return hits[0][1]


def pin_check(data):
    for va, (want, meaning) in PINS.items():
        raw = bytes.fromhex(want)
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'instruction bytes changed at {va:#x} ({meaning})')


def jump(data, site, op, length, target):
    if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
        raise ValueError(f'branch at {site:#x} is not to {target:#x}')
    return hex(target)


def slot_call(data, site, slot):
    if read_va(data, site, 2) != b'\xff\x15' or rel_target(data, site, 6) != slot:
        raise ValueError(f'call at {site:#x} is not through slot {slot:#x}')


def lea(data, site, target=None):
    if read_va(data, site, 3)[1:2] != b'\x8d':
        raise ValueError(f'no lea at {site:#x}')
    got = rel_target(data, site, 7)
    if target is not None and got != target:
        raise ValueError(f'lea at {site:#x} is not to {target:#x}')
    return got


def text(data, va, want):
    if read_va(data, va, len(want)) != want:
        raise ValueError(f'string at {va:#x} is not {want!r}')


def store_name(data, at):
    """At `at`: mov [rsp+0x30],rax; mov qword [rsp+0x38],imm32. Returns imm32."""
    if read_va(data, at, 10) != bytes.fromhex('488944243048c7442438'):
        raise ValueError(f'no name/length store at {at:#x}')
    return struct.unpack('<I', read_va(data, at + 10, 4))[0]


def duplicate_block(data, block):
    """Name lea, then either the name/length store or a short jump to a shared one."""
    name_va = lea(data, block)
    after = block + 7
    if read_va(data, after, 1) == b'\xeb':
        after = after + 2 + struct.unpack('<b', read_va(data, after + 1, 1))[0]
    length = store_name(data, after)
    tail = after + 14
    op = read_va(data, tail, 1)
    if op == b'\xe9':
        jump(data, tail, 'e9', 5, DUP_TAIL)
    elif op == b'\xeb':
        if tail + 2 + struct.unpack('<b', read_va(data, tail + 1, 1))[0] != DUP_TAIL:
            raise ValueError(f'duplicate block {block:#x} does not join {DUP_TAIL:#x}')
    elif tail != DUP_TAIL:
        raise ValueError(f'duplicate block {block:#x} does not join {DUP_TAIL:#x}')
    return name_va, length


def struct_name(data):
    target = relocation(data, NAME_RECORD)
    length = struct.unpack('<Q', read_va(data, NAME_RECORD + 8, 8))[0]
    if length != len(NAME_TEXT):
        raise ValueError(f'expected-text record {NAME_RECORD:#x} has length {length}')
    text(data, target, NAME_TEXT)
    return {'record': hex(NAME_RECORD), 'text_at': hex(target), 'text': NAME_TEXT.decode()}


def key_reader(data):
    slot_call(data, KEY_CALL, KEY_SLOT)
    target = relocation(data, KEY_SLOT)
    if target != KEY_READER:
        raise ValueError(f'slot {KEY_SLOT:#x} is relocated to {target:#x}, not {KEY_READER:#x}')
    return {'site': hex(KEY_CALL), 'slot': hex(KEY_SLOT), 'relocated_to': hex(target),
            'integer_key': 'min(k, 13)'}


def table_entry(data, index):
    return FIELD_TABLE + struct.unpack('<i', read_va(data, FIELD_TABLE + 4 * index, 4))[0]


def fields(data):
    lea(data, FIELD_TABLE_LEA, FIELD_TABLE)
    slots = {INT_SLOT: INT_READER, U64_SLOT: U64_READER}
    for slot, reader in slots.items():
        if relocation(data, slot) != reader:
            raise ValueError(f'slot {slot:#x} is not relocated to {reader:#x}')
    out = {}
    for index, (arm, dsite, op, block, name, kind, vsite, target, fsite, msite) in FIELDS.items():
        if table_entry(data, index) != arm:
            raise ValueError(f'field table entry {index} is not {arm:#x}')
        jump(data, dsite, op, 6, block)
        name_va, length = duplicate_block(data, block)
        if length != len(name):
            raise ValueError(f'duplicate block {block:#x} stores length {length}, not {len(name)}')
        text(data, name_va, name.encode())
        entry = {'key': name, 'arm': hex(arm), 'duplicate_block': hex(block),
                 'required': name in MISSING}
        if kind == 'call':
            jump(data, vsite, 'e8', 5, target)
            entry['decoder'] = hex(target)
        else:
            head = read_va(data, arm, 8)
            if head[:4] != bytes.fromhex('4883bc24'):
                raise ValueError(f'arm {arm:#x} does not test a stack flag')
            store = bytes.fromhex('48898424') + head[4:8]
            if read_va(data, fsite, 8) != store:
                raise ValueError(f'flag store at {fsite:#x} does not set the flag of arm {arm:#x}')
            if not msite < vsite < fsite:
                raise ValueError(f'value call {vsite:#x} is not between {msite:#x} and {fsite:#x}')
            jump(data, msite, '0f85', 6, rel_target(data, msite, 6))
            if not rel_target(data, msite, 6) <= vsite:
                raise ValueError(f'marker branch at {msite:#x} does not reach {vsite:#x}')
            slot_call(data, vsite, target)
            entry['decoder'] = f'slot {target:#x} -> {slots[target]:#x}'
        out[str(index)] = entry
    if table_entry(data, 13) != OTHER_ARM:
        raise ValueError(f'field table entry 13 is not {OTHER_ARM:#x}')
    jump(data, SKIP_CALL, 'e8', 5, SKIP)
    out['13'] = {'key': '(any other key)', 'arm': hex(OTHER_ARM), 'decoder': hex(SKIP)}
    return out


def missing(data):
    text(data, MISSING_TEMPLATE, b'\x0fmissing field `')
    text(data, DUP_TEMPLATE, b'\x11duplicate field `')
    lea(data, DUP_TEMPLATE_LEA, DUP_TEMPLATE)
    names = {f[4] for f in FIELDS.values()}
    out = {}
    for name, (nsite, tsite, csite) in MISSING.items():
        if name not in names:
            raise ValueError(f'{name} is not a field')
        text(data, lea(data, nsite), name.encode())
        lea(data, tsite, MISSING_TEMPLATE)
        jump(data, csite, 'e8', 5, ERROR_FMT)
        out[name] = {'name_at': hex(nsite), 'template_at': hex(tsite), 'call': hex(csite)}
    return out


def lea_sites(data, start, size, target):
    """All 7-byte RIP-relative lea (REX.W 8D, mod 00 r/m 101) to `target` in a range."""
    code = read_va(data, start, size)
    hits = []
    for i in range(len(code) - 6):
        if code[i] in (0x48, 0x4c) and code[i + 1] == 0x8d and code[i + 2] & 0xc7 == 0x05:
            if start + i + 7 + struct.unpack_from('<i', code, i + 3)[0] == target:
                hits.append(start + i)
    return hits


def sequence(data):
    jump(data, SEQ_ERROR_CALL, 'e8', 5, SEQ_ERROR)
    out = {}
    for site, (isite, index) in SEQ_SITES.items():
        lea(data, site, NAME_RECORD)
        want = b'\x31\xf6' if index == 0 else b'\xbe' + struct.pack('<I', index)
        if read_va(data, isite, len(want)) != want:
            raise ValueError(f'element index at {isite:#x} is not {index}')
        out[hex(site)] = index
    found = lea_sites(data, CTX, CTX_EXTENT, NAME_RECORD)
    if sorted(found) != sorted(SEQ_SITES):
        raise ValueError(f'record {NAME_RECORD:#x} is loaded at {[hex(x) for x in found]}')
    indexes = {i for _, i in SEQ_SITES.values()}
    required = {i for i, f in FIELDS.items() if f[4] in MISSING}
    if indexes != required:
        raise ValueError('sequence-length indexes are not the required fields')
    for target, want in ((MISSING_TEMPLATE, len(MISSING)), (DUP_TEMPLATE, 1)):
        got = len(lea_sites(data, CTX, CTX_EXTENT, target))
        if got != want:
            raise ValueError(f'template {target:#x} is loaded {got} times, not {want}')
    return out


def extents(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    size = {}
    for func in (CTX, LOCUS, KEY_READER, ERROR_FMT):
        i = bisect.bisect_left(starts, func)
        if i == len(starts) or starts[i] != func:
            raise ValueError(f'no unwind entry starts at {func:#x}')
        size[func] = entries[i]['next_index_upper_bound'] - func
    if size[CTX] != CTX_EXTENT:
        raise ValueError(f'ctx decoder extent is not {CTX_EXTENT:#x}')
    for site in LOCUS_CALLS:
        if not LOCUS <= site < LOCUS + size[LOCUS]:
            raise ValueError(f'site {site:#x} is not in Locus {LOCUS:#x}')
        jump(data, site, 'e8', 5, CTX)
    if not ERROR_FMT <= ERROR_FMT_TAG < ERROR_FMT + size[ERROR_FMT]:
        raise ValueError('tag store is outside the error formatter')
    return {hex(f): hex(s) for f, s in size.items()}


def bind(data):
    pin_check(data)
    result = {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'locus_calls': [hex(s) for s in LOCUS_CALLS],
        'struct_name': struct_name(data),
        'key_reader': key_reader(data),
        'fields': fields(data),
        'missing_field_blocks': missing(data),
        'sequence_length_errors': sequence(data),
        'extents': extents(data),
    }
    result['required'] = sorted(MISSING, key=lambda n: [f[4] for f in FIELDS.values()].index(n))
    result['pins'] = len(PINS)
    result['gates_changed'] = False
    return result


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    result = bind(binary.read_bytes())
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print(f"fields={len(result['fields'])} required={','.join(result['required'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
