#!/usr/bin/env python3
"""Long field names for the node #115 position item and its f struct (stage 109).

Continues open PRs #6224 (position item {s, l, M, f, e} and f = {a, o, c})
and #6226 (field l = enum Leverage). Those PRs read the serde writers, which
use only one-letter keys. This tool reads the Debug formatters of the same
types, which carry the Rust field names, and binds them to the serde keys by
field offset:

1. the position item Debug body 0x44dbc30 calls slot 0x64e1ef0 (0x167f960,
   a five-field Debug helper; the name is an inference from the call shape)
   with the struct name "Position" and five (name, value, vtable) groups.
   The tool decodes the argument pushes and reads each field name, the
   value offset from the item base and the vtable size;
2. the position JSON writer 0x448ae20 (from #6224/#6226) writes the keys
   s, l, M, f and e from the same five offsets;
3. the f vtable's Debug body 0x44e85c0 writes "CumFunding" with three
   fields at +0x0, +0x8 and +0x10; the f writer 0x448b410 writes a, o and c
   from the same offsets;
4. the l vtable's Debug body 0x44e7cc0 writes "Isolated" {leverage +0x4,
   raw_usd +0x8} for tag 1 and "Cross" otherwise, the same names as the
   serde alias tables 0x6483c28/0x6483c68 that #6226 read.

The per-user value {u, p, D, l, S, r}, S {s, r} and D {a, c} are not bound:
no Debug formatter that names them was found (see the README limits).
The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import fixed, frame, read_va, relative_relocations, rip_target, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-user-state-long-names-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

POSITION_DEBUG = 0x44dbc30
FIELD5_SLOT, FIELD5 = 0x64e1ef0, 0x167f960
FIELD_SLOT, FIELD = 0x64dfad0, 0x167d950
POSITION_JSON = 0x448ae20
CUM_JSON = 0x448b410
CUM_DEBUG = 0x44e85c0
LEVERAGE_DEBUG = 0x44e7cc0
LEVERAGE_JSON = 0x420a0d0

# The argument set-up and call in the Position Debug body.
POSITION_WINDOW = (0x44dbc3e, 0x44dbcd7)

FIXED = {
    # Position Debug body: item base r10 = **rdi
    0x44dbc3e: '488b0f',                # mov rcx, [rdi]
    0x44dbc41: '4c8b11',                # mov r10, [rcx]
    # Position JSON writer 0x448ae20 (rbx = item)
    0x448ae2e: '4889fb',                # mov rbx, rdi
    0x448ae59: '4c8b7310',              # mov r14, [rbx+0x10]             (s)
    0x448af6c: '4c89f6',                # mov rsi, r14                    (s value)
    0x448afd6: '4889df',                # mov rdi, rbx                    (l at +0x0)
    0x448affb: '488d4b38',              # lea rcx, [rbx+0x38]             (M)
    0x448b08e: '488d7b18',              # lea rdi, [rbx+0x18]             (f)
    0x448b0ef: '4883c330',              # add rbx, 0x30                   (e)
    0x448b104: '4889d9',                # mov rcx, rbx                    (e value)
    # f JSON writer 0x448b410 (rdi = f)
    0x448b42f: '4c8b27',                # mov r12, [rdi]                  (a)
    0x448b432: '488b4f08',              # mov rcx, [rdi+0x8]
    0x448b436: '488b4710',              # mov rax, [rdi+0x10]
    0x448b440: '4889442418',            # mov [rsp+0x18], rax             (c)
    0x448b44f: '48894c2420',            # mov [rsp+0x20], rcx             (o)
    0x448b518: '4c89e6',                # mov rsi, r12                    (a value)
    0x448b524: '4c8b742420',            # mov r14, [rsp+0x20]             (o value)
    0x448b584: '4c89f6',                # mov rsi, r14
    0x448b590: '4c8b742418',            # mov r14, [rsp+0x18]             (c value)
    0x448b5ec: '4c89f6',                # mov rsi, r14
    # CumFunding Debug body 0x44e85c0 (r15 = rdi = f)
    0x44e85d0: '4989ff',                # mov r15, rdi
    0x44e85d3: '488d5f08',              # lea rbx, [rdi+0x8]
    0x44e85d7: '488d4710',              # lea rax, [rdi+0x10]
    0x44e85db: '4889442418',            # mov [rsp+0x18], rax
    0x44e85ee: 'ba0a000000',            # mov edx, 10                     ("CumFunding")
    0x44e861e: 'ba08000000',            # mov edx, 8
    0x44e8626: '4c89f9',                # mov rcx, r15                    (+0x0)
    0x44e8636: 'ba0a000000',            # mov edx, 10
    0x44e863e: '4889d9',                # mov rcx, rbx                    (+0x8)
    0x44e8655: '488d4c2418',            # lea rcx, [rsp+0x18]             (+0x10, by reference)
    0x44e865a: 'ba0c000000',            # mov edx, 12
    0x44e862c: '41ffd5',                # call r13
    0x44e8644: '41ffd5',                # call r13
    0x44e8662: '41ffd5',                # call r13
    # Leverage Debug body 0x44e7cc0
    0x44e7cce: '833f01',                # cmp dword [rdi], 1
    0x44e7cd1: '0f8593000000',          # jne 0x44e7d6a                   (Cross)
    0x44e7cd7: '4c8d7704',              # lea r14, [rdi+0x4]
    0x44e7cdb: '4883c708',              # add rdi, 0x8
    0x44e7cf2: 'ba08000000',            # mov edx, 8                      ("Isolated")
    0x44e7d22: 'ba08000000',            # mov edx, 8                      ("leverage")
    0x44e7d2a: '4c89f1',                # mov rcx, r14                    (+0x4)
    0x44e7d3e: '488d4c2430',            # lea rcx, [rsp+0x30]             (+0x8, by reference)
    0x44e7d43: 'ba07000000',            # mov edx, 7                      ("raw_usd")
    0x44e7d6a: '4883c704',              # add rdi, 0x4                    (Cross payload)
    0x44e7d85: 'ba05000000',            # mov edx, 5                      ("Cross")
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x44dbcd7, b'\xff\x15', 6, FIELD5_SLOT),
    (0x448af18, b'\x48\x8d\x35', 7, 0x7d082f),   # "s"
    (0x448af87, b'\x48\x8d\x35', 7, 0x7d0946),   # "l"
    (0x448afdc, b'\xe8', 5, LEVERAGE_JSON),
    (0x448afff, b'\x48\x8d\x35', 7, 0x7d13c1),   # "M"
    (0x448b06d, b'\x48\x8d\x35', 7, 0x7d13cd),   # "f"
    (0x448b0c3, b'\xe8', 5, CUM_JSON),
    (0x448b0f3, b'\x48\x8d\x35', 7, 0x7d0bd9),   # "e"
    (0x448b4c5, b'\x48\x8d\x35', 7, 0x7d098e),   # "a"
    (0x448b52e, b'\x48\x8d\x35', 7, 0x7d0929),   # "o"
    (0x448b59a, b'\x48\x8d\x35', 7, 0x7d0c8d),   # "c"
    (0x44e85e7, b'\x48\x8d\x35', 7, 0x7d2578),   # "CumFunding"
    (0x44e8604, b'\x48\x8d\x35', 7, 0x459428),   # "all_time"
    (0x44e8612, b'\x4c\x8b\x2d', 7, FIELD_SLOT),
    (0x44e862f, b'\x48\x8d\x35', 7, 0x7d2582),   # "since_open"
    (0x44e8647, b'\x48\x8d\x35', 7, 0x7d258c),   # "since_change"
    (0x44e7ceb, b'\x48\x8d\x35', 7, 0x459480),   # "Isolated"
    (0x44e7d08, b'\x48\x8d\x35', 7, 0x458f18),   # "leverage"
    (0x44e7d16, b'\x4c\x8b\x3d', 7, FIELD_SLOT),
    (0x44e7d30, b'\x48\x8d\x35', 7, 0x7d3347),   # "raw_usd"
    (0x44e7d7e, b'\x48\x8d\x35', 7, 0x7d3342),   # "Cross"
)
RELOCATIONS = {FIELD5_SLOT: FIELD5, FIELD_SLOT: FIELD}
STRINGS = {
    0x7d082f: b's', 0x7d0946: b'l', 0x7d13c1: b'M', 0x7d13cd: b'f', 0x7d0bd9: b'e',
    0x7d098e: b'a', 0x7d0929: b'o', 0x7d0c8d: b'c',
    0x7d2578: b'CumFunding', 0x459428: b'all_time', 0x7d2582: b'since_open',
    0x7d258c: b'since_change', 0x459480: b'Isolated', 0x458f18: b'leverage',
    0x7d3347: b'raw_usd', 0x7d3342: b'Cross',
}
# Serde key -> item offset, from the writers pinned above.
POSITION_KEYS = {'s': 0x10, 'l': 0x0, 'M': 0x38, 'f': 0x18, 'e': 0x30}
CUM_KEYS = {'a': 0x0, 'o': 0x8, 'c': 0x10}
POSITION_DEBUG_NAMES = {0x10: 'szi', 0x0: 'leverage', 0x38: 'margin_table_id', 0x18: 'cum_funding', 0x30: 'entry_ntl'}
CUM_DEBUG_FIELDS = (('all_time', 0x0), ('since_open', 0x8), ('since_change', 0x10))

REG = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
       'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')


def decode_field5(data):
    """Decode the Position Debug argument set-up into (struct name, fields).

    Only the encodings in the pinned window are accepted; any other byte stops
    the decode. Register values are ('const', va), ('item', off), ('ref', off)
    or ('imm', n)."""
    start, end = POSITION_WINDOW
    code = read_va(data, start, end - start + 6)
    regs, stack, spill, i = {}, [], None, 0
    while start + i < end:
        b = code[i:i + 7]
        rex = b[0] if 0x40 <= b[0] <= 0x4f else 0
        j = 1 if rex else 0
        op = b[j]
        if op == 0x8d and b[j + 1] & 0xc7 == 0x05:          # lea r, [rip+d32]
            r = ((rex & 4) << 1) | (b[j + 1] >> 3 & 7)
            regs[REG[r]] = ('const', start + i + j + 6 + struct.unpack_from('<i', b, j + 2)[0])
            i += j + 6
        elif op == 0x8d and b[j + 1] >> 6 == 1 and b[j + 1] & 7 != 4:  # lea r, [base+d8]
            r = ((rex & 4) << 1) | (b[j + 1] >> 3 & 7)
            base = REG[((rex & 1) << 3) | (b[j + 1] & 7)]
            if base != 'r10':
                raise ValueError(f'unexpected base at {start + i:#x}')
            regs[REG[r]] = ('item', b[j + 2])
            i += j + 3
        elif b[:5] == bytes.fromhex('4c8d742408'):           # lea r14, [rsp+8] -> spilled slot
            regs['r14'] = ('ref', spill)
            i += 5
        elif b[:4] == bytes.fromhex('48890c24'):             # mov [rsp], rcx
            spill = regs['rcx'][1]
            i += 4
        elif b[:3] in (bytes.fromhex('488b0f'), bytes.fromhex('4c8b11'),
                       bytes.fromhex('4889c7')) or b[:4] == bytes.fromhex('4883ec08'):
            i += 3 if b[:3] != bytes.fromhex('4883ec') else 4
        elif op == 0xba and not rex:                          # mov edx, imm32
            regs['rdx'] = ('imm', struct.unpack_from('<I', b, 1)[0])
            i += 5
        elif rex == 0x41 and op == 0xb8:                      # mov r8d, imm32
            regs['r8'] = ('imm', struct.unpack_from('<I', b, 2)[0])
            i += 6
        elif op == 0x6a and not rex:                          # push imm8
            stack.append(('imm', b[1]))
            i += 2
        elif 0x50 <= op <= 0x57 and rex in (0, 0x41):         # push r
            name = REG[((rex & 1) << 3) | (op - 0x50)]
            stack.append(('item', 0) if name == 'r10' else regs[name])
            i += j + 1
        else:
            raise ValueError(f'unexpected instruction at {start + i:#x}')
    args = [regs['rcx'], regs['r8'], regs['r9']] + stack[::-1]
    if regs['rsi'][0] != 'const' or regs['rdx'][0] != 'imm' or len(args) != 20:
        raise ValueError('Position Debug arguments changed')
    name = read_va(data, regs['rsi'][1], regs['rdx'][1]).decode()
    fields = []
    for k in range(5):
        fname, flen, value, vtable = args[4 * k: 4 * k + 4]
        if fname[0] != 'const' or flen[0] != 'imm' or vtable[0] != 'const' or value[0] not in ('item', 'ref'):
            raise ValueError('Position Debug field %d changed' % k)
        size = struct.unpack('<Q', read_va(data, vtable[1] + 8, 8))[0]
        fields.append({'name': read_va(data, fname[1], flen[1]).decode(), 'offset': value[1],
                       'by_reference': value[0] == 'ref', 'vtable': vtable[1], 'size': size})
    return name, fields


def slot_calls(data, slot):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xff\x15', code):
        i = m.start()
        if i + 6 <= len(code) and base + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == slot:
            out.append(base + i)
    return out


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, expect in STRINGS.items():
        if read_va(data, va, len(expect)) != expect:
            raise ValueError(f'string at {va:#x} changed')
    for va, owner in ((0x44dbcd7, POSITION_DEBUG), (0x448b0ef, POSITION_JSON), (0x448b5ec, CUM_JSON),
                      (0x44e8662, CUM_DEBUG), (0x44e7d7e, LEVERAGE_DEBUG)):
        if frame(fdes, va) != owner:
            raise ValueError(f'{va:#x} left its function')

    name, fields = decode_field5(data)
    if name != 'Position':
        raise ValueError('Position Debug struct name changed')
    by_offset = {f['offset']: f for f in fields}
    if len(by_offset) != 5 or set(by_offset) != set(POSITION_KEYS.values()):
        raise ValueError('Position Debug offsets do not match the serde writer')
    if {off: f['name'] for off, f in by_offset.items()} != POSITION_DEBUG_NAMES:
        raise ValueError('Position Debug field names changed')
    vt_fmt = {f['name']: rel.get(f['vtable'] + 0x18) for f in fields}
    if vt_fmt['leverage'] != LEVERAGE_DEBUG or vt_fmt['cum_funding'] != CUM_DEBUG:
        raise ValueError('field vtables changed')
    calls = slot_calls(data, FIELD5_SLOT)

    position = {key: {'long': by_offset[off]['name'], 'offset': hex(off), 'debug_value_size': by_offset[off]['size']}
                for key, off in POSITION_KEYS.items()}
    cum = {key: {'long': dict((o, n) for n, o in CUM_DEBUG_FIELDS)[off], 'offset': hex(off)}
           for key, off in CUM_KEYS.items()}
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'user-state',
        'position_item': {
            'debug_body': hex(POSITION_DEBUG),
            'debug_struct_name': name,
            'debug_call': '0x44dbcd7 via slot %s -> %s (five-field Debug helper; inference from the call shape)'
                          % (hex(FIELD5_SLOT), hex(FIELD5)),
            'debug_fields_in_order': [{'name': f['name'], 'offset': hex(f['offset']), 'by_reference': f['by_reference'],
                                       'vtable': hex(f['vtable']), 'vtable_size': f['size'],
                                       'vtable_fmt': hex(rel.get(f['vtable'] + 0x18, 0))} for f in fields],
            'serde_writer': hex(POSITION_JSON),
            'short_to_long': position,
        },
        'f_struct': {
            'debug_body': '%s (vtable fmt of the cum_funding field)' % hex(CUM_DEBUG),
            'debug_struct_name': 'CumFunding',
            'serde_writer': '%s (called at 0x448b0c3 with rdi = item + 0x18)' % hex(CUM_JSON),
            'short_to_long': cum,
        },
        'leverage_cross_check': {
            'debug_body': '%s (vtable fmt of the leverage field)' % hex(LEVERAGE_DEBUG),
            'tag_1': 'Isolated {leverage: +0x4, raw_usd: +0x8}',
            'other_tag': 'Cross(+0x4)',
            'serde_aliases_6226': {'l': 'leverage', 'u': 'raw_usd', 'C': 'Cross', 'I': 'Isolated'},
        },
        'field5_slot_calls': [hex(v) for v in calls],
        'not_bound': ['per-user value {u, p, D, l, S, r}', 'S {s, r}', 'D {a, c}'],
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
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
    table = {k: v['long'] for k, v in result['position_item']['short_to_long'].items()}
    table.update({'f.' + k: v['long'] for k, v in result['f_struct']['short_to_long'].items()})
    print('position %s' % table)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
