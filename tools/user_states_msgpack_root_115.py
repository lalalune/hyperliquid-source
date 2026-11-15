#!/usr/bin/env python3
"""Node #115: the MessagePack path above the user_states reader 0x3274e70.

Open PR #6584 showed that the second per-user value visitor 0x30bcb40 is
reached through user_states (0x3274e70, field 1) and user_to_state
(0x32daf90, field 0). It left the only direct caller of 0x3274e70
(0x389a09e in 0x3899fe0) unmapped. This tool checks the three functions above
it, one direct call at a time:

1. 0x3899fe0 reads a sequence. It caps the first allocation at 0x329 entries
   of 0x510 bytes, and for each element calls 0x3274e70, the visitor that
   holds user_states. So each element is one value of that struct.
2. 0x2f4d3e0, the only direct caller of 0x3899fe0, takes the name
   `Clearinghouses` (14 bytes) from its callers. A MessagePack array
   (0x90..0x9f) goes to 0x3899fe0. A map (0x80..0x8f) goes to 0x384c960,
   which reports `invalid type`.
3. 0x332c430 calls 0x2f4d3e0 with that name for field 1 (table 0x73da1c,
   entry 1 -> 0x332d10f). A second `cls` in the input is reported as a
   duplicate field with the 3-byte name `cls` (0x794e8d). Entry 16 of the
   same table skips the value through 0x31d5e50, so fields 0 to 15 are named
   fields. The 48 bytes at 0x794e8a hold sixteen 3-byte names, starting
   `ctx`, `cls`.

So the MessagePack reader reaches the per-user values through
cls[i].user_states.user_to_state. That the 16-field struct is Locus is an
inference from its field names and field count. The two callers of 0x332c430
(0x2fd78dc in 0x2fd7260 and 0x32cb193 in 0x32caf70) are counted, not mapped.

The tool only compares fixed bytes at fixed addresses, jump-table entries,
branch and call targets, RIP-relative references, one relocation, function
starts from .eh_frame_hdr, a count of direct `call rel32` instructions in
.text, and strings. The captured binary is not executed. objdump and readelf
are not started. Addresses are ELF virtual addresses.
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
PACKET = ROOT / 'research/work-items/RE-008-user-states-msgpack-root-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

CLEARINGHOUSE = 0x3274e70  # holds user_states, field 1 (#6584)
SEQUENCE = 0x3899fe0
NEWTYPE = 0x2f4d3e0
MAP_ERROR = 0x384c960
STRUCT = 0x332c430
FIELD_TABLE = 0x73da1c
NAMES = 0x794e8a
NAME_BLOCK = 'ctxclssclftrustchnpdluaRblpqusctruacvlthcmpmumsc'

PINS = {   # address -> (bytes, meaning)
    0x3899ff6: ('8b6e0881fd2903000041bf29030000440f42fd85ed',
                'sequence: first capacity min(len, 0x329)'),
    0x389a014: ('4969df10050000', 'allocation capacity * 0x510'),
    0x389a060: ('4969fd1005000048037c2408ba10050000488db42448',
                'per element: store 0x510 bytes at index * 0x510'),
    0x389a091: ('488dbc24580a00004c89fe31d2e8cdad9dff',
                'per element: call 0x3274e70'),
    0x2f4d4ae: ('80f990731d80e10f89cae9f1000000',
                'newtype reader: fixmap -> 0x2f4d5ae'),
    0x2f4d4d0: ('80f9a0732b80e10f89cae951010000',
                'newtype reader: fixarray -> 0x2f4d630'),
    0x2f4d5b1: ('0fb74e226685c90f8438080000b00866ffc966894e220f84620400004989f6'
                '488d7c2440488db424c8000000e87ef38f00',
                'map form: depth check, call 0x384c960'),
    0x2f4d630: ('0fb6ea0fb746226685c00f84c307000066ffc86689462274794989f64889b424'
                'c800000089ac24d0000000488d7c2440488db424c8000000e873c99400',
                'array form: depth check, call 0x3899fe0'),
    0x384c9a3: ('488d05a6d6cd004889442430488d35c426c0fc488d542418e8809d7fff',
                'map form: invalid type, call 0x3046740'),
    0x332c7b0: ('488dbc24f00200004c89feff15f7751b03',
                'struct visitor: key through slot 0x64e3db8'),
    0x332c7d1: ('0fb68424f1020000488d0d3c1241fd486304814801c8ffe0',
                'struct visitor: field index through table 0x73da1c'),
    0x332d10f: ('4c39ac24d80100000f85e92b0000b90e000000488dbc24700c00004c89fe'
                '488d158b524afde8a702c2ff',
                'field 1 arm: not-seen check, name length 0xe, call 0x2f4d3e0'),
    0x332dba4: ('488d1514484afd488dbc2400060000b90e0000004c89fee820f8c1ff',
                'array form of the struct: same name, call 0x2f4d3e0'),
    0x332fd06: ('488d05805146fd48898424f002000048c78424f802000003',
                'field 1 duplicate: name 0x794e8d, length 3'),
    0x332ca10: ('488dbc24700c00004c89feba01000000e82b94eaff',
                'field 16 arm: skip through 0x31d5e50'),
}

# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {0x389a09e: ('e8', 5, CLEARINGHOUSE),
         0x2f4d4b8: ('e9', 5, 0x2f4d5ae), 0x2f4d4da: ('e9', 5, 0x2f4d630),
         0x2f4d5dd: ('e8', 5, MAP_ERROR), 0x2f4d668: ('e8', 5, SEQUENCE),
         0x384c9bb: ('e8', 5, 0x3046740),
         0x332d117: ('0f85', 6, 0x332fd06), 0x332d134: ('e8', 5, NEWTYPE),
         0x332dbbb: ('e8', 5, NEWTYPE), 0x332ca20: ('e8', 5, 0x31d5e50)}
# lea site -> (address, text or None for a pointer-only reference)
LEAS = {0x332d12d: (0x7d23bf, 'Clearinghouses'),
        0x332dba4: (0x7d23bf, 'Clearinghouses'),
        0x332fd06: (0x794e8d, 'cls'),
        0x384c9af: (0x44f07a, '\x0einvalid type: ')}
# relocated pointer -> target (struct visitor key reader)
RELOCS = {0x64e3db8: 0x33de700}
# (table, index) -> target
TABLES = {(FIELD_TABLE, 1): 0x332d10f, (FIELD_TABLE, 16): 0x332ca10}
# call site -> function that holds it (from .eh_frame_hdr)
HOLDERS = {0x389a09e: SEQUENCE, 0x2f4d668: NEWTYPE, 0x2f4d5dd: NEWTYPE,
           0x332d134: STRUCT, 0x332dbbb: STRUCT, 0x2fd78dc: 0x2fd7260,
           0x32cb193: 0x32caf70}
# function -> its direct `call rel32` sites in .text
CALLERS = {CLEARINGHOUSE: (0x389a09e,), SEQUENCE: (0x2f4d668,),
           MAP_ERROR: (0x2f4d5dd,), NEWTYPE: (0x332d134, 0x332dbbb),
           STRUCT: (0x2fd78dc, 0x32cb193)}


def read_va(data, va, size):
    hits = [s for s in sections(data)
            if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = hits[0]['offset'] + va - hits[0]['address']
    return data[off:off + size]


def rel_target(data, va, length):
    width = 1 if length == 2 else 4
    fmt = '<b' if width == 1 else '<i'
    return va + length + struct.unpack(fmt, read_va(data, va + length - width, width))[0]


def table_entry(data, table, index):
    return table + struct.unpack('<i', read_va(data, table + 4 * index, 4))[0]


def pin_check(data):
    for va, (want, meaning) in PINS.items():
        raw = bytes.fromhex(want)
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'instruction bytes changed at {va:#x} ({meaning})')


def jumps(data):
    out = {}
    for site, (op, length, target) in JUMPS.items():
        if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
            raise ValueError(f'branch at {site:#x} is not to {target:#x}')
        out[hex(site)] = hex(target)
    return out


def leas(data):
    out = {}
    for site, (addr, text) in LEAS.items():
        if read_va(data, site, 3)[1:2] != b'\x8d' or rel_target(data, site, 7) != addr:
            raise ValueError(f'lea at {site:#x} is not to {addr:#x}')
        if text is not None and read_va(data, addr, len(text)) != text.encode():
            raise ValueError(f'string at {addr:#x} is not {text!r}')
        out[hex(site)] = {'address': hex(addr), 'text': text}
    return out


def names(data):
    got = read_va(data, NAMES, len(NAME_BLOCK))
    if got != NAME_BLOCK.encode():
        raise ValueError(f'name block at {NAMES:#x} is {got!r}')
    return [NAME_BLOCK[i:i + 3] for i in range(0, len(NAME_BLOCK), 3)]


def relocations(data):
    secs = [s for s in sections(data) if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(secs) != 1 or secs[0]['size'] % 24:
        raise ValueError('unsupported dynamic relocation section')
    body = data[secs[0]['offset']:secs[0]['offset'] + secs[0]['size']]
    found = {}
    for off, info, addend in struct.iter_unpack('<QQq', body):
        if off in RELOCS:
            if off in found or info != 8:
                raise ValueError(f'ambiguous or non-relative relocation at {off:#x}')
            found[off] = addend
    out = {}
    for off, target in RELOCS.items():
        if found.get(off) != target:
            raise ValueError(f'relocation at {off:#x} is not to {target:#x}')
        out[hex(off)] = hex(target)
    return out


def tables(data):
    out = {}
    for (table, index), target in TABLES.items():
        got = table_entry(data, table, index)
        if got != target:
            raise ValueError(f'table {table:#x} entry {index} is {got:#x}, not {target:#x}')
        out[f'{table:#x}[{index}]'] = hex(target)
    return out


def holders(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    out = {}
    for site, func in HOLDERS.items():
        i = bisect.bisect_right(starts, site) - 1
        if i < 0 or starts[i] != func or not site < entries[i]['next_index_upper_bound']:
            raise ValueError(f'call site {site:#x} is not in function {func:#x}')
        out[hex(site)] = hex(func)
    return out


def callers(data):
    text = [s for s in sections(data) if s['name'] == '.text' and s['type'] != 8]
    if len(text) != 1:
        raise ValueError('expected one .text section')
    sec = text[0]
    body = data[sec['offset']:sec['offset'] + sec['size']]
    base = sec['address']
    found = {f: [] for f in CALLERS}
    pos = body.find(b'\xe8')
    while 0 <= pos <= len(body) - 5:
        target = base + pos + 5 + struct.unpack_from('<i', body, pos + 1)[0]
        if target in found:
            found[target].append(base + pos)
        pos = body.find(b'\xe8', pos + 1)
    out = {}
    for func, want in CALLERS.items():
        if tuple(found[func]) != want:
            raise ValueError(f'direct callers of {func:#x} are '
                             f'{[hex(x) for x in found[func]]}, not {[hex(x) for x in want]}')
        out[hex(func)] = [hex(x) for x in want]
    return out


def bind(data):
    pin_check(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'chain': [
            {'function': hex(STRUCT), 'field': 1, 'name': 'cls',
             'calls': hex(NEWTYPE), 'type_name': 'Clearinghouses'},
            {'function': hex(NEWTYPE), 'array_form': hex(SEQUENCE),
             'map_form': hex(MAP_ERROR), 'map_form_error': 'invalid type'},
            {'function': hex(SEQUENCE), 'element': hex(CLEARINGHOUSE),
             'first_capacity_cap': hex(0x329), 'entry_bytes': hex(0x510)},
            {'function': hex(CLEARINGHOUSE), 'field': 1, 'name': 'user_states',
             'proven_in': '#6584'},
        ],
        'struct_field_names': names(data),
        'struct_named_fields': 16,
        'tables': tables(data),
        'branches': jumps(data),
        'leas': leas(data),
        'relocations': relocations(data),
        'holders': holders(data),
        'direct_callers': callers(data),
        'upper_boundary': {'function': hex(STRUCT),
                           'callers': ['0x2fd78dc', '0x32cb193'], 'mapped': False},
        'struct_is_locus': 'inference from field names and count',
        'links': {'user_states_chain': '#6584', 'json_writer_path': '#6577'},
        'pins': len(PINS),
        'gates_changed': False,
    }


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
    print(f"pins={result['pins']} path=cls[i].user_states.user_to_state "
          f"names={len(result['struct_field_names'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
