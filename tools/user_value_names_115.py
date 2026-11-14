#!/usr/bin/env python3
"""Name sources for the node #115 per-user value (keys u, p, D, l, S, r).

Open PR #6223 found the writer 0x3beac00 that emits the per-user value as six
one-byte keys in the order u, p, D, l, S, r. Open PR #6229 gave long names for
the position item from its Debug formatters, but the per-user value itself has
no Debug formatter. This tool checks the serde name sources that remain:

1. Field identifier visitors. Every dispatch in .text that subtracts 0x44
   ('D') from a key byte and bounds it by 0x31 ('u') is found (11 sites in 5
   functions). Each one is reached only when the key length is 1; a key of any
   other length goes to the same target as an unknown letter. Each jump table
   matches exactly the letters D, S, l, p, r, u. So no visitor has a second,
   long-name arm (no #[serde(alias)]), and a long key is ignored, not matched.
2. Field indexes. In six of the tables the arms set the field index:
   u=0, p=1, D=2, l=3, S=4, r=5; index 6 is the ignore arm. This is the key
   order of the writer in #6223.
3. Error strings. The rmp-serde visitor 0x1a212f0 formats the template
   "duplicate field `{}`" with each name as a 1-byte string: S, l, r, p, D, u.
4. FIELDS arrays. No six consecutive relocated (ptr, len) pairs hold exactly
   the six one-byte names, in any order. The same window scan finds the #6229
   alias table 0x6483c28 (and a second copy at 0x6432b78) as a control.
5. "struct X with 6 elements" descriptors. The census lists the 19 names. The
   tool does not bind any of them to this value; UserStates is the container
   whose field names sit next to it in the string pool.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-user-value-names-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

KEYS = 'upDlSr'                      # writer order from #6223
LETTERS = ''.join(sorted(KEYS))      # 'DSlpru' in byte order
BASE, SPAN = 0x44, 0x31              # 'D' .. 'u'

# dispatch site (the `add/sub reg, -0x44`) -> (length guard va, guard bytes)
DISPATCH = {
    0x1a21c6a: (0x1a21c5c, '4183fc01'),            # cmp r12d, 1
    0x1a21cb1: (0x1a21c9b, '4883bc249000000001'),  # cmp qword [rsp+0x90], 1
    0x1a21d6a: (0x1a21d5d, '4883fa01'),            # cmp rdx, 1
    0x1e5bb40: (0x1e5bb31, '48837c243001'),        # cmp qword [rsp+0x30], 1
    0x30bd11b: (0x30bd10d, '4183fc01'),
    0x30bd167: (0x30bd151, '4883bc240001000001'),
    0x30bd22b: (0x30bd21e, '4883fa01'),
    0x40bcd1e: (0x40bcd10, '4883bc24a000000001'),
    0x4a4306a: (0x4a4305c, '4183fc01'),
    0x4a430b1: (0x4a4309b, '4883bc249000000001'),
    0x4a4316a: (0x4a4315d, '4883fa01'),
}
FUNCTIONS = {
    0x1a212f0: 'rmp-serde visit_map (rmp-serde decode.rs paths)',
    0x1e5b990: 'serde_json visit_map (serde_json de.rs/read.rs paths)',
    0x30bcb40: 'rmp-serde visit_map (rmp-serde decode.rs paths)',
    0x40bcb50: 'visit_map',
    0x4a426f0: 'visit_map',
}
# Where the length miss lands when it is not the letter-miss target itself.
LENGTH_MISS_PREFIX = {0x30bd11b: (0x30bd517, '488b7c2408')}  # mov rdi,[rsp+8]; then the ja target
IGNORE = (0x1a21c5a, 'b006')          # mov al, 6 before the length guard
INDEX_TABLES = (0x1a21c6a, 0x1a21cb1, 0x30bd11b, 0x30bd167, 0x4a4306a, 0x4a430b1)

DUPLICATE_TEMPLATE = 0x43351a
DUPLICATE_TEXT = b'\x11duplicate field `\xc0\x01`'
DUPLICATE_SITES = {      # lea rax,[name]; mov [rsp],rax; mov qword [rsp+8],1 ... lea rsi,[template]
    0x1a22e1f: (0x5c9f2b, 'S'),
    0x1a22e65: (0x5c8994, 'l'),
    0x1a22eab: (0x5c8baf, 'r'),
    0x1a22ef1: (0x5c9041, 'p'),
    0x1a22f37: (0x5ca378, 'D'),
    0x1a22f7a: (0x5c8d98, 'u'),
}
CONTROL_TABLE = 0x6483c28
CONTROL_NAMES = (b'l', b'leverage', b'u', b'raw_usd')


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def try_read(data, va, size):
    try:
        return read_va(data, va, size)
    except ValueError:
        return None


def relative_relocations(data):
    rel = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def branch_target(data, va):
    raw = read_va(data, va, 6)
    if raw[0] == 0x0f and raw[1] in (0x85, 0x87):
        return va + 6 + struct.unpack_from('<i', raw, 2)[0]
    if raw[0] in (0x75, 0x77):
        return va + 2 + struct.unpack_from('<b', raw, 1)[0]
    raise ValueError(f'no jne/ja at {va:#x}')


def dispatch_census(data):
    """Every `add/sub r32, -0x44|0x44` followed within 12 bytes by `cmp r32, 0x31`."""
    sec = next(s for s in sections(data) if s['name'] == '.text')
    code = data[sec['offset']:sec['offset'] + sec['size']]
    found = []
    for m in re.finditer(rb'\x04\xbc|\x2c\x44|\x80[\xc0-\xc7]\xbc|\x80[\xe8-\xef]\x44'
                         rb'|\x83[\xc0-\xc7]\xbc|\x83[\xe8-\xef]\x44', code):
        if re.search(rb'\x3c\x31|\x80[\xf8-\xff]\x31|\x83[\xf8-\xff]\x31', code[m.end():m.end() + 12]):
            found.append(sec['address'] + m.start())
    return found


def decode_table(data, site):
    """The rip-relative table after the bound check: letters whose entry differs from the default."""
    window = read_va(data, site, 40)
    m = re.search(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', window)
    if m is None:
        raise ValueError(f'no table load after {site:#x}')
    lea = site + m.start()
    table = lea + 7 + struct.unpack_from('<i', window, m.start() + 3)[0]
    raw = read_va(data, table, 4 * (SPAN + 1))
    targets = [table + struct.unpack_from('<i', raw, 4 * i)[0] for i in range(SPAN + 1)]
    default = max(set(targets), key=targets.count)
    arms = {chr(BASE + i): t for i, t in enumerate(targets) if t != default}
    return table, default, arms


def arm_index(data, va):
    raw = read_va(data, va, 2)
    if raw == b'\x31\xc0':
        return 0
    if raw[0] == 0xb0:
        return raw[1]
    raise ValueError(f'arm at {va:#x} does not set a field index')


def pair_names(data, rel):
    """slot -> text for every relocated (ptr, len) pair with a length of 1..64."""
    names = {}
    for va, target in rel.items():
        raw = try_read(data, va + 8, 8)
        if raw is None:
            continue
        size = struct.unpack('<Q', raw)[0]
        if 0 < size <= 64:
            text = try_read(data, target, size)
            if text is not None:
                names[va] = text
    return names


def windows(names, seq):
    """Slots where `seq` appears as consecutive (ptr, len) pairs, in any order of its members."""
    want = sorted(seq)
    hits = []
    for va in names:
        run = [names.get(va + 16 * i) for i in range(len(seq))]
        if None not in run and sorted(run) == want:
            hits.append(va)
    return sorted(hits)


def six_element_names(data):
    return sorted({m.group(1).decode() for m in re.finditer(rb'struct ([A-Za-z0-9_]+) with 6 elements', data)})


def bind(data):
    census = dispatch_census(data)
    if census != sorted(DISPATCH):
        raise ValueError('dispatch census changed: ' + ', '.join(hex(v) for v in census))
    if read_va(data, IGNORE[0], 2) != bytes.fromhex(IGNORE[1]):
        raise ValueError('ignore index changed')
    sites = {}
    for site, (guard, expect) in DISPATCH.items():
        raw = bytes.fromhex(expect)
        if read_va(data, guard, len(raw)) != raw:
            raise ValueError(f'length guard at {guard:#x} changed')
        length_miss = branch_target(data, guard + len(raw))
        letter_miss = branch_target(data, site + 6) if read_va(data, site + 6, 1)[0] in (0x0f, 0x77) \
            else branch_target(data, site + 11)
        if site in LENGTH_MISS_PREFIX:
            va, prefix = LENGTH_MISS_PREFIX[site]
            if length_miss != va or read_va(data, va, len(prefix) // 2) != bytes.fromhex(prefix) \
                    or va + len(prefix) // 2 != letter_miss:
                raise ValueError(f'length miss at {site:#x} changed')
        elif length_miss != letter_miss:
            raise ValueError(f'length miss at {site:#x} does not join the letter miss')
        table, default, arms = decode_table(data, site)
        if ''.join(sorted(arms)) != LETTERS:
            raise ValueError(f'table {table:#x} matches {"".join(sorted(arms))}')
        row = {'length_guard': hex(guard), 'table': hex(table), 'letters': ''.join(sorted(arms)),
               'length_miss': hex(length_miss), 'letter_miss': hex(letter_miss)}
        if site in INDEX_TABLES:
            row['index'] = {k: arm_index(data, arms[k]) for k in KEYS}
            if list(row['index'].values()) != list(range(6)):
                raise ValueError(f'field index order at {site:#x} changed')
        sites[hex(site)] = row
    if read_va(data, DUPLICATE_TEMPLATE, len(DUPLICATE_TEXT)) != DUPLICATE_TEXT:
        raise ValueError('duplicate field template changed')
    duplicates = {}
    for va, (name, letter) in DUPLICATE_SITES.items():
        raw = read_va(data, va, 47)
        if raw[:3] != b'\x48\x8d\x05' or va + 7 + struct.unpack_from('<i', raw, 3)[0] != name:
            raise ValueError(f'name load at {va:#x} changed')
        if raw[7:20] != bytes.fromhex('4889042448c744240801000000'):
            raise ValueError(f'name length at {va:#x} changed')
        if raw[40:43] != b'\x48\x8d\x35' or va + 47 + struct.unpack_from('<i', raw, 43)[0] != DUPLICATE_TEMPLATE:
            raise ValueError(f'template load at {va:#x} changed')
        if read_va(data, name, 1) != letter.encode():
            raise ValueError(f'name byte at {name:#x} changed')
        duplicates[hex(va)] = letter
    rel = relative_relocations(data)
    names = pair_names(data, rel)
    control = windows(names, CONTROL_NAMES)
    if CONTROL_TABLE not in control:
        raise ValueError('FIELDS scanner lost its control table')
    fields = windows(names, [k.encode() for k in KEYS])
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'keys_in_writer_order': list(KEYS),
        'field_visitors': {
            'functions': {hex(k): v for k, v in FUNCTIONS.items()},
            'dispatch_sites': sites,
            'ignore_index': '6 (mov al, 6 at 0x1a21c5a)',
        },
        'duplicate_field': {'template': hex(DUPLICATE_TEMPLATE), 'fn': '0x1a212f0', 'names': duplicates},
        'fields_arrays': {'six_key_windows': [hex(v) for v in fields],
                          'control_windows': [hex(v) for v in control]},
        'six_element_struct_descriptors': six_element_names(data),
        'long_names_pinned': {},
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
    v = result['field_visitors']['dispatch_sites']
    print(f"dispatch_sites={len(v)} fields_arrays={len(result['fields_arrays']['six_key_windows'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
