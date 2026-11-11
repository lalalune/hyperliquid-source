#!/usr/bin/env python3
"""Node #115: Locus field 2 `scl` is the 14-field struct SpotClearinghouse.

Open PR #6589 mapped the 16 field arms of the MessagePack Locus visitor
0x332c430. Arm 2 (`scl`) calls 0x31b5450 at 0x332cd98. PR #6593 noted only
that 0x31b5450 sends a fixarray to a sequence path and a fixmap to a map path.
This tool checks what 0x31b5450 decodes:

1. The first marker byte below 0x90 (fixmap) jumps to the map path 0x31b5778.
   A marker 0x90..0x9f (fixarray) jumps to the sequence path 0x31b557f.
2. The sequence path reports a short array through the expected-text record
   0x6464940. That record has one R_X86_64_RELATIVE relocation to 0x796322,
   and its length word is 41: the text `struct SpotClearinghouse with 14
   elements`.
3. The map path reads each key through slot 0x64e3048 (relocated to
   0x33f2fe0). On result tag 9 it takes the field index from the result and
   jumps through table 0x6ce708 (15 entries). The key reader turns an integer
   key k into min(k, 14), so index 14 is the "other key" arm.
4. Each arm 0..13 first tests whether its field is already set. If it is, the
   arm jumps to a block that loads the field name and the template
   `duplicate field `...`` (0x43351a). This binds each index to one name.
   Otherwise the arm calls one field decoder. Arm 14 calls the skip reader
   0x31d5e50.
5. For 8 fields the function has a block that loads the name and the template
   `missing field `...`` (0x4325c4): these fields are required. The other 6
   names have no such block in this function.

The tool only compares fixed bytes at fixed addresses, jump-table entries,
branch and call targets, RIP-relative references, relocations, function
starts from .eh_frame_hdr, and strings. The captured binary is not executed.
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
PACKET = ROOT / 'research/work-items/RE-008-locus-scl-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

LOCUS = 0x332c430
LOCUS_CALL = 0x332cd98
SCL = 0x31b5450
MAP_PATH = 0x31b5778
SEQ_PATH = 0x31b557f
KEY_SLOT = 0x64e3048
KEY_READER = 0x33f2fe0
KEY_CALL = 0x31b5d86
FIELD_TABLE = 0x6ce708
SKIP = 0x31d5e50
SKIP_ARM = 0x31b5f3a
DUP_TEMPLATE = 0x43351a
MISSING_TEMPLATE = 0x4325c4
NAME_RECORD = 0x6464940
NAME_RECORD_LEA = 0x31b5a16
NAME_TEXT = b'struct SpotClearinghouse with 14 elements'

PINS = {   # address -> (bytes, meaning)
    0x31b54d7: ('3c907311', 'first marker compared with 0x90 (fixmap below)'),
    0x31b54ec: ('3ca0', 'first marker compared with 0xa0 (fixarray below)'),
    0x31b5d8c: ('0fb66c24704080fd09', 'key result tag compared with 9'),
    0x31b5d9b: ('0fb6442471', 'field index taken from the key result'),
    0x31b5da7: ('48630481', 'field table load'),
    0x31b5f45: ('ba01000000', 'other key: skip reader argument'),
    0x33f3040: ('80f90eb90e0000000f42c8', 'key reader: integer key clamped to 14'),
    0x33f304e: ('c60709', 'key reader: success tag 9'),
}
# index -> (arm, duplicate branch site, opcode, duplicate block, name, decoder call site, decoder,
#           duplicate-template lea site)
FIELDS = {
    0: (0x31b5db0, 0x31b5dc6, '0f85', 0x31b861f, 'meta', 0x31b5dd9, 0x323d8d0, 0x31b8653),
    1: (0x31b62b8, 0x31b62cb, '0f85', 0x31b7fb8, 'user_states', 0x31b62de, 0x31541c0, 0x31b7fec),
    2: (0x31b6160, 0x31b616f, '0f85', 0x31b84b7, 'daily_exchange_scaled_and_raw_vlms',
        0x31b6185, 0x310e930, 0x31b84eb),
    3: (0x31b61d2, 0x31b61e1, '0f85', 0x31b8307, 'token_to_genesis', 0x31b61f7, 0x3308e10, 0x31b833b),
    4: (0x31b6003, 0x31b6012, '0f85', 0x31b8031, 'token_to_max_supply', 0x31b6028, 0x3245580,
        0x31b8065),
    5: (0x31b6354, 0x31b6363, '0f85', 0x31b80aa, 'token_fees_collected', 0x31b6379, 0x3245580,
        0x31b80de),
    6: (0x31b6462, 0x31b6468, '0f85', 0x31b8215, 'native_token', 0x31b6479, 0x451c230, 0x31b8249),
    7: (0x31b6244, 0x31b624a, '0f85', 0x31b83f9, 'spot_dusting_opted_out_users', 0x31b6266,
        0x325ec80, 0x31b8437),
    8: (0x31b6515, 0x31b6524, '0f85', 0x31b85a9, 'evm_transfer_escrows', 0x31b653a, 0x3088be0,
        0x31b85dd),
    9: (0x31b60ed, 0x31b60f5, '0f85', 0x31b8530, 'eec', 0x31b6108, 0x30db2f0, 0x31b8564),
    10: (0x31b64b2, 0x31b64bb, '0f84', 0x31b8380, 'eebl', 0x31b64cc, 0x45160c0, 0x31b83b4),
    11: (0x31b5f62, 0x31b5f74, '0f85', 0x31b819c, 'token_to_pending_evm_contract', 0x31b5f8a,
         0x331e590, 0x31b81d0),
    12: (0x31b6075, 0x31b6087, '0f85', 0x31b8123, 'pmr', 0x31b609d, 0x32082b0, 0x31b8157),
    13: (0x31b63c6, 0x31b63d7, '0f85', 0x31b828e, 'soh', 0x31b63ea, 0x3089400, 0x31b82c2),
}
# required field name -> (name lea site, missing-template lea site)
MISSING = {
    'meta': (0x31b5901, 0x31b5938),
    'user_states': (0x31b69e5, 0x31b6a22),
    'token_to_genesis': (0x31b6e2d, 0x31b6e6a),
    'token_to_max_supply': (0x31b6f11, 0x31b6f4e),
    'token_fees_collected': (0x31b7237, 0x31b7274),
    'spot_dusting_opted_out_users': (0x31b7821, 0x31b785e),
    'evm_transfer_escrows': (0x31b78d5, 0x31b7912),
    'token_to_pending_evm_contract': (0x31b79cc, 0x31b7a06),
}
# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {
    LOCUS_CALL: ('e8', 5, SCL),
    0x31b54e7: ('e9', 5, MAP_PATH),
    0x31b54f4: ('e9', 5, SEQ_PATH),
    0x31b5f4a: ('e8', 5, SKIP),
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


def pin_check(data):
    for va, (want, meaning) in PINS.items():
        raw = bytes.fromhex(want)
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'instruction bytes changed at {va:#x} ({meaning})')


def jump(data, site, op, length, target):
    if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
        raise ValueError(f'branch at {site:#x} is not to {target:#x}')
    return hex(target)


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


def key_reader(data):
    if read_va(data, KEY_CALL, 2) != b'\xff\x15' or rel_target(data, KEY_CALL, 6) != KEY_SLOT:
        raise ValueError(f'call at {KEY_CALL:#x} is not through slot {KEY_SLOT:#x}')
    target = relocation(data, KEY_SLOT)
    if target != KEY_READER:
        raise ValueError(f'slot {KEY_SLOT:#x} is relocated to {target:#x}, not {KEY_READER:#x}')
    return {'site': hex(KEY_CALL), 'slot': hex(KEY_SLOT), 'relocated_to': hex(target),
            'integer_key': 'min(k, 14)'}


def struct_name(data):
    lea(data, NAME_RECORD_LEA, NAME_RECORD)
    target = relocation(data, NAME_RECORD)
    length = struct.unpack('<Q', read_va(data, NAME_RECORD + 8, 8))[0]
    if length != len(NAME_TEXT):
        raise ValueError(f'expected-text record {NAME_RECORD:#x} has length {length}')
    text(data, target, NAME_TEXT)
    return {'record': hex(NAME_RECORD), 'text_at': hex(target), 'text': NAME_TEXT.decode(),
            'loaded_at': hex(NAME_RECORD_LEA)}


def table_entry(data, index):
    return FIELD_TABLE + struct.unpack('<i', read_va(data, FIELD_TABLE + 4 * index, 4))[0]


def fields(data):
    lea(data, 0x31b5da0, FIELD_TABLE)
    out = {}
    for index, (arm, dsite, op, block, name, csite, decoder, dtpl) in FIELDS.items():
        if table_entry(data, index) != arm:
            raise ValueError(f'field table entry {index} is not {arm:#x}')
        jump(data, dsite, op, 6, block)
        name_va = lea(data, block)
        text(data, name_va, name.encode())
        length = bytes.fromhex('48c7442478') + struct.pack('<I', len(name))
        if read_va(data, block + 12, len(length)) != length:
            raise ValueError(f'duplicate block {block:#x} does not store length {len(name)}')
        lea(data, dtpl, DUP_TEMPLATE)
        jump(data, csite, 'e8', 5, decoder)
        out[str(index)] = {'key': name, 'arm': hex(arm), 'duplicate_block': hex(block),
                           'decoder': hex(decoder), 'required': name in MISSING}
    if table_entry(data, 14) != SKIP_ARM:
        raise ValueError(f'field table entry 14 is not {SKIP_ARM:#x}')
    out['14'] = {'key': '(any other key)', 'arm': hex(SKIP_ARM), 'decoder': hex(SKIP)}
    return out


def missing(data):
    text(data, MISSING_TEMPLATE, b'\x0fmissing field `')
    text(data, DUP_TEMPLATE, b'\x11duplicate field `')
    names = {f[4] for f in FIELDS.values()}
    out = {}
    for name, (nsite, tsite) in MISSING.items():
        if name not in names:
            raise ValueError(f'{name} is not a field')
        text(data, lea(data, nsite), name.encode())
        lea(data, tsite, MISSING_TEMPLATE)
        out[name] = {'name_at': hex(nsite), 'template_at': hex(tsite)}
    return out


def holders(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    sites = {LOCUS_CALL: LOCUS, 0x33f3040: KEY_READER}
    for va in list(PINS) + list(JUMPS) + [KEY_CALL, NAME_RECORD_LEA]:
        sites.setdefault(va, SCL)
    for f in FIELDS.values():
        for va in (f[0], f[1], f[3], f[5], f[7]):
            sites[va] = SCL
    for nsite, tsite in MISSING.values():
        sites[nsite] = sites[tsite] = SCL
    sites[0x33f304e] = KEY_READER
    for site, func in sites.items():
        i = bisect.bisect_right(starts, site) - 1
        if i < 0 or starts[i] != func or not site < entries[i]['next_index_upper_bound']:
            raise ValueError(f'site {site:#x} is not in function {func:#x}')
    return len(sites)


def bind(data):
    pin_check(data)
    jumps = {hex(s): jump(data, s, *v) for s, v in JUMPS.items()}
    result = {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'locus': {'index': 2, 'key': 'scl', 'visitor': hex(LOCUS), 'call': hex(LOCUS_CALL)},
        'decoder': hex(SCL),
        'paths': {'fixmap': hex(MAP_PATH), 'fixarray': hex(SEQ_PATH)},
        'struct_name': struct_name(data),
        'key_reader': key_reader(data),
        'field_table': hex(FIELD_TABLE),
        'fields': fields(data),
        'missing_field_errors': missing(data),
        'branches': jumps,
        'holders_checked': holders(data),
        'defaults_of_optional_fields': 'not proven',
        'links': {'locus_arms': '#6589', 'locus_pmu': '#6593'},
        'pins': len(PINS),
        'gates_changed': False,
    }
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
    print(f"pins={result['pins']} fields={len(result['fields'])} "
          f"required={len(result['missing_field_errors'])} name={result['struct_name']['text']!r}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
