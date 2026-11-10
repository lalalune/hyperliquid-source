#!/usr/bin/env python3
"""Node #115: the 16 field arms of the MessagePack struct visitor 0x332c430.

Open PR #6585 showed that field 1 (`cls`) of the struct visitor 0x332c430
reads the clearinghouse list, and said that the struct is Locus only by
inference. This tool checks every arm of the visitor's field table:

1. The table 0x73da1c has 17 entries. Entries 0 to 15 are named fields;
   entry 16 skips the value through 0x31d5e50 (#6585).
2. Each named arm i first tests whether the field was already seen. If it
   was, it branches to a block that loads the 3-byte name at
   0x794e8a + 3*i and stores length 3 before the `duplicate field` error.
   So arm i is the field whose short key is name i of the block
   `ctx cls scl ftr ust chn pdl uaR blp qus ctr uac vlt hcm pmu msc`.
3. Fifteen arms call one decoder each (listed by address, not mapped). Only
   arm 1 passes a type name (`Clearinghouses`, #6585). Arm 14 (`pmu`)
   reads its value inline and has no call before its first branch.
4. The same function calls 0x2fc21d0 at 0x332dd91. That helper loads the
   record 0x6464530, whose relocated pointer is 0x794eba and whose length
   is 0x1d: the text `struct Locus with 16 elements` (#6093). The 48-byte
   name block ends right where that text starts, and #6097 showed the same
   block at 0x794e8a is the Locus field-name block. So the visitor's own
   expectation text names the struct Locus.

The tool only compares fixed bytes at fixed addresses, jump-table entries,
branch and call targets, RIP-relative references, relocations, function
starts from .eh_frame_hdr, and strings. The captured binary is not
executed. objdump and readelf are not started. Addresses are ELF virtual
addresses.
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
PACKET = ROOT / 'research/work-items/RE-008-locus-msgpack-fields-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

STRUCT = 0x332c430
FIELD_TABLE = 0x73da1c
NAMES = 0x794e8a
NAME_BLOCK = 'ctxclssclftrustchnpdluaRblpqusctruacvlthcmpmumsc'
LOCUS_TEXT = 'struct Locus with 16 elements'
LOCUS_RECORD = 0x6464530
LOCUS_TEXT_VA = 0x794eba
LENGTH_HELPER = 0x2fc21d0
SKIP = 0x31d5e50
KEY_READER_SLOT = 0x64e3db8
KEY_READER = 0x33de700

# index -> (arm, arm bytes up to and including the decoder call,
#           already-seen branch site, branch opcode, duplicate block,
#           decoder call site or None, decoder or None)
ARMS = {
    0: (0x332c7e9, '4883bc2488000000020f85a0380000488dbc24700c00004c89fe31d2e85654daff',
        0x332c7f2, '0f85', 0x3330098, 0x332c805, 0x30d1c60),
    1: (0x332d10f, '4c39ac24d80100000f85e92b0000b90e000000488dbc24700c00004c89fe'
        '488d158b524afde8a702c2ff',
        0x332d117, '0f85', 0x332fd06, 0x332d134, 0x2f4d3e0),
    2: (0x332cd7d, '83bc2410280000020f8595330000488dbc24700c00004c89fe31d2e8b386e8ff',
        0x332cd85, '0f85', 0x3330120, 0x332cd98, 0x31b5450),
    3: (0x332cf72, '4c39ac24e01a00000f8576330000488dbc24700c00004c89fe31d2e8de600600',
        0x332cf7a, '0f85', 0x33302f6, 0x332cf8d, 0x3393070),
    4: (0x332cb63, '4c39ac24200200000f850d380000488dbc24700c00004c89fe31d2e8ad32d8ff',
        0x332cb6b, '0f85', 0x333037e, 0x332cb7e, 0x30afe30),
    5: (0x332d17f, '807c240f040f8504330000488dbc24700c00004c89fee8868ac0ff',
        0x332d184, '0f85', 0x333048e, 0x332d195, 0x2f35c20),
    6: (0x332d201, '80bc2498000000020f8507330000488dbc24700c00004c89fee821154a00',
        0x332d209, '0f85', 0x3330516, 0x332d21a, 0x37ce740),
    7: (0x332d051, '498d450148398424e80000000f85a3330000410fb65724488dbc24700c0000'
        '4c89fee8f8d6faff',
        0x332d05d, '0f85', 0x3330406, 0x332d073, 0x32da770),
    8: (0x332d33a, '83bc2440180000020f859e2e0000488dbc24700c00004c89fe31d2e8d6c2fdff',
        0x332d342, '0f85', 0x33301e6, 0x332d355, 0x3309630),
    9: (0x332ccf0, '4883bc24a8000000000f852732000048c78424a800000000000000488dbc24'
        '700c00004c89fe31d2e8631ff3ff',
        0x332ccf9, '0f85', 0x332ff26, 0x332cd18, 0x325ec80),
    10: (0x332d245, '837c2458000f853e2b0000488dbc24700c00004c89fe31d2e8de44f7ff',
         0x332d24a, '0f85', 0x332fd8e, 0x332d25d, 0x32a1740),
    11: (0x332ca94, '4c39ac24d80400000f85cc370000488dbc24700c00004c89fe31d2e84c5bf6ff',
         0x332ca9c, '0f85', 0x333026e, 0x332caaf, 0x3292600),
    12: (0x332cc32, '498d450148398424b80100000f855a320000410fb65724488dbc24700c0000'
         '4c89fee8d77fe8ff',
         0x332cc3e, '0f85', 0x332fe9e, 0x332cc54, 0x31b4c30),
    13: (0x332d1bd, '80bc2490000000030f854b2c0000488dbc24700c00004c89fee8e5ddc0ff',
         0x332d1c5, '0f85', 0x332fe16, 0x332d1d6, 0x2f3afc0),
    14: (0x332ca3c, '4883bc24a0000000010f84c5350000',
         0x332ca45, '0f84', 0x3330010, None, None),
    15: (0x332ce86, '498d450148398424b00000000f85e62d000048898424b0000000488dbc24'
         '700c00004c89fe31d2e89e23f6ff',
         0x332ce92, '0f85', 0x332fc7e, 0x332cead, 0x328f250),
}
# duplicate block tail: mov [rsp+0x2f0],rax ; mov qword [rsp+0x2f8],3
DUP_TAIL = '48898424f002000048c78424f802000003'

PINS = {   # address -> (bytes, meaning)
    0x332ca10: ('488dbc24700c00004c89feba01000000e82b94eaff',
                'field 16 arm: skip through 0x31d5e50'),
    0x332c7b0: ('488dbc24f00200004c89feff15f7751b03',
                'struct visitor: key through slot 0x64e3db8'),
    0x332c7d1: ('0fb68424f1020000488d0d3c1241fd486304814801c8ffe0',
                'struct visitor: field index through table 0x73da1c'),
    0x332dd86: ('488db424701c00004889dfe83a44c9ff',
                'struct visitor: call 0x2fc21d0'),
    0x2fc2201: ('488d1528234a03', 'helper: lea record 0x6464530'),
}
# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {0x332ca20: ('e8', 5, SKIP), 0x332dd91: ('e8', 5, LENGTH_HELPER)}
# lea site -> (address, text or None)
LEAS = {0x332d12d: (0x7d23bf, 'Clearinghouses'),
        0x2fc2201: (LOCUS_RECORD, None)}
# relocated pointer -> target
RELOCS = {KEY_READER_SLOT: KEY_READER, LOCUS_RECORD: LOCUS_TEXT_VA}
# call site -> function that holds it (from .eh_frame_hdr)
HOLDERS = {0x332dd91: STRUCT, 0x332d134: STRUCT, 0x332ca20: STRUCT,
           0x332c805: STRUCT, 0x332ce92: STRUCT, 0x2fc2201: LENGTH_HELPER}


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


def branch(data, site, op, length, target):
    if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
        raise ValueError(f'branch at {site:#x} is not to {target:#x}')


def names(data):
    got = read_va(data, NAMES, len(NAME_BLOCK))
    if got != NAME_BLOCK.encode():
        raise ValueError(f'name block at {NAMES:#x} is {got!r}')
    return [NAME_BLOCK[i:i + 3] for i in range(0, len(NAME_BLOCK), 3)]


def arms(data, keys):
    out = []
    for index, (arm, raw, site, op, dup, call, decoder) in sorted(ARMS.items()):
        got = table_entry(data, FIELD_TABLE, index)
        if got != arm:
            raise ValueError(f'table {FIELD_TABLE:#x} entry {index} is {got:#x}, not {arm:#x}')
        if read_va(data, arm, len(bytes.fromhex(raw))) != bytes.fromhex(raw):
            raise ValueError(f'instruction bytes changed at {arm:#x} (field {index} arm)')
        branch(data, site, op, 6, dup)
        name_va = NAMES + 3 * index
        if read_va(data, dup, 3) != bytes.fromhex('488d05') or rel_target(data, dup, 7) != name_va:
            raise ValueError(f'duplicate block {dup:#x} does not load name {index} at {name_va:#x}')
        if read_va(data, dup + 7, len(DUP_TAIL) // 2) != bytes.fromhex(DUP_TAIL):
            raise ValueError(f'duplicate block {dup:#x} does not store length 3')
        row = {'index': index, 'key': keys[index], 'arm': hex(arm),
               'duplicate_block': hex(dup), 'name_at': hex(name_va)}
        if call is not None:
            branch(data, call, 'e8', 5, decoder)
            row['decoder'] = hex(decoder)
        else:
            row['decoder'] = None
        out.append(row)
    if table_entry(data, FIELD_TABLE, 16) != 0x332ca10:
        raise ValueError(f'table {FIELD_TABLE:#x} entry 16 is not the skip arm')
    return out


def jumps(data):
    out = {}
    for site, (op, length, target) in JUMPS.items():
        branch(data, site, op, length, target)
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


def locus_record(data):
    length = struct.unpack('<Q', read_va(data, LOCUS_RECORD + 8, 8))[0]
    if length != len(LOCUS_TEXT):
        raise ValueError(f'record {LOCUS_RECORD:#x} length is {length:#x}, not {len(LOCUS_TEXT):#x}')
    if read_va(data, LOCUS_TEXT_VA, length) != LOCUS_TEXT.encode():
        raise ValueError(f'string at {LOCUS_TEXT_VA:#x} is not {LOCUS_TEXT!r}')
    if NAMES + len(NAME_BLOCK) != LOCUS_TEXT_VA:
        raise ValueError('name block does not end where the Locus text starts')
    return {'record': hex(LOCUS_RECORD), 'text_at': hex(LOCUS_TEXT_VA),
            'length': hex(length), 'text': LOCUS_TEXT}


def holders(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    out = {}
    for site, func in HOLDERS.items():
        i = bisect.bisect_right(starts, site) - 1
        if i < 0 or starts[i] != func or not site < entries[i]['next_index_upper_bound']:
            raise ValueError(f'site {site:#x} is not in function {func:#x}')
        out[hex(site)] = hex(func)
    return out


def bind(data):
    pin_check(data)
    keys = names(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'struct_visitor': hex(STRUCT),
        'field_table': hex(FIELD_TABLE),
        'fields': arms(data, keys),
        'skip_arm': {'index': 16, 'arm': '0x332ca10', 'calls': hex(SKIP)},
        'locus_expectation': locus_record(data),
        'branches': jumps(data),
        'leas': leas(data),
        'relocations': relocations(data),
        'holders': holders(data),
        'struct_is_locus': 'proven: the visitor calls 0x2fc21d0, which loads the '
                           "'struct Locus with 16 elements' record",
        'decoders_mapped': False,
        'key_reader_mapped': False,
        'links': {'cls_path': '#6585', 'locus_record': '#6093', 'locus_names': '#6097'},
        'pins': len(PINS) + len(ARMS),
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
    print(f"pins={result['pins']} fields={len(result['fields'])} "
          f"struct={result['locus_expectation']['text']!r}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
