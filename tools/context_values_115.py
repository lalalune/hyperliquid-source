#!/usr/bin/env python3
"""Node #115: value decoders of struct Context fields tx_index, round, time,
prev_time and system_nonce.

Open PR #6663 (and the merged RE-009 context packet) show that the Context
map arms call 0x451c540 for `tx_index`, 0x4524ae0 for `round`, 0x3d4f3c0 for
both `time` and `prev_time`, and 0x421db60 for `system_nonce`. RE-009 leaves
"exact source-level option types" unresolved. This tool checks what these
calls decode:

1. 0x4524ae0, 0x421db60 and 0x3d4f3c0 are 3-instruction stubs. Each loads a
   name and its length and jumps to a newtype-struct reader:
   `Round` (5) -> 0x2f4f140, `SystemNonce` (11) -> 0x2f43af0,
   `Time` (4) -> 0x2f6ca60.
2. Each newtype reader first compares the name with the 10-byte MessagePack
   extension marker name `_ExtStruct` (two immediates). Only that name takes
   the extension path; the names above do not.
3. Round and SystemNonce then read the value through slot 0x64e2580
   (relocated to the integer reader 0x348e980, the same reader as the
   Context integer keys), and on tag 9 store one qword at result +8.
4. Time calls a second reader 0x2f6fa30 with the same name `Time` (4). That
   reader reads the value through slot 0x64dfec0 (relocated to 0x14b93c0)
   and on tag 9 stores 12 bytes at result +4..+0xf; the outer reader copies
   the same 12 bytes.
5. 0x451c540 (tx_index) has no name. A nil marker 0xc0 stores 0 at result +8
   and tag 9 without a read. Any other marker reads through slot 0x64dfeb0
   (relocated to 0x14b7aa0) and on tag 9 stores 1 at +8 and the value at
   +0x10. This is an option: nil is None, a value is Some.

The tool only compares fixed bytes at fixed addresses, branch and call
targets, RIP-relative references, relocations, function extents from
.eh_frame_hdr, and strings. The captured binary is not executed. objdump and
readelf are not started. Addresses are ELF virtual addresses.
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
PACKET = ROOT / 'research/work-items/RE-008-context-values-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

CTX = 0x30d1c60
INT_SLOT, INT_READER = 0x64e2580, 0x348e980
TIME_SLOT, TIME_READER = 0x64dfec0, 0x14b93c0
U64_SLOT, U64_READER = 0x64dfeb0, 0x14b7aa0
# Bytes from `cmp rcx,0xa` through `or rcx,rax`: length 10 and the two
# immediates "_ExtStru" and "ct" compared with the name.
EXT_CHECK = bytes.fromhex('4883f90a751d48b85f45787453747275483302'
                          '0fb74a084881f163740000' '4809c1')

# Context call site -> (field names, decoder)
CTX_CALLS = {
    0x30d2415: (('tx_index',), 0x451c540),
    0x30d22c5: (('round',), 0x4524ae0),
    0x30d250b: (('time',), 0x3d4f3c0),
    0x30d254b: (('prev_time',), 0x3d4f3c0),
    0x30d258b: (('system_nonce',), 0x421db60),
}
# stub -> (name address, name, newtype reader)
STUBS = {
    0x4524ae0: (0x7d3b21, b'Round', 0x2f4f140),
    0x421db60: (0x7c9469, b'SystemNonce', 0x2f43af0),
    0x3d4f3c0: (0x459f78, b'Time', 0x2f6ca60),
}
# newtype reader -> (ext check site, slot call site, slot, tag check site,
#                    tag check bytes, [(store site, bytes, meaning)])
READERS = {
    0x2f4f140: (0x2f4f148, 0x2f4f256, INT_SLOT, 0x2f4f265, '80f909',
                [(0x2f4f26a, '48894308', 'qword at +8'), (0x2f4f26e, 'c60309', 'tag 9')]),
    0x2f43af0: (0x2f43af8, 0x2f43c0b, INT_SLOT, 0x2f43c1b, '80f909',
                [(0x2f43c20, '48894308', 'qword at +8'), (0x2f43c24, 'c60309', 'tag 9')]),
    0x2f6fa30: (0x2f6fa40, 0x2f6fb80, TIME_SLOT, 0x2f6fb8a, '3c09',
                [(0x2f6fbaa, '89430c', 'dword at +0xc'), (0x2f6fbad, '48894b04', 'qword at +4'),
                 (0x2f6fbb1, 'c60309', 'tag 9')]),
}
# The outer Time reader calls the inner one with the same name.
TIME_OUTER = 0x2f6ca60
TIME_OUTER_EXT = 0x2f6ca68
TIME_NAME_LEA = 0x2f6ca8b
TIME_LEN = 0x2f6ca97
TIME_INNER_CALL = 0x2f6ca9c
TIME_INNER = 0x2f6fa30
TIME_OUTER_STORES = [(0x2f6caa6, '3c09', 'tag 9 test'), (0x2f6cabc, '894b0c', 'dword at +0xc'),
                     (0x2f6cabf, '48895304', 'qword at +4')]
# tx_index option reader
TX = 0x451c540
TX_PINS = {
    0x451c5c0: ('3cc0', 'fresh marker compared with nil 0xc0'),
    0x451c5c6: ('3cc0', 'marker compared with nil 0xc0'),
    0x451c5c8: ('750a', 'non-nil skips the None store'),
    0x451c5ca: ('48c7430800000000', 'None: 0 at +8'),
    0x451c5d2: ('eb2d', 'None joins the tag-9 store'),
    0x451c5ea: ('803c2409', 'read result compared with tag 9'),
    0x451c5f5: ('48c7430801000000', 'Some: 1 at +8'),
    0x451c5fd: ('48894310', 'Some: value at +0x10'),
    0x451c601: ('c60309', 'tag 9'),
}
TX_SLOT_CALL = 0x451c5e4
EXTENTS = {0x4524ae0: 0x20, 0x421db60: 0x20, 0x3d4f3c0: 0x20, 0x451c540: 0xf0,
           0x2f4f140: 0x2d0, 0x2f43af0: 0x300, 0x2f6ca60: 0x2f0, 0x2f6fa30: 0xa00}


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


def pin(data, va, want, meaning):
    raw = bytes.fromhex(want)
    if read_va(data, va, len(raw)) != raw:
        raise ValueError(f'instruction bytes changed at {va:#x} ({meaning})')


def jump(data, site, op, length, target):
    if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
        raise ValueError(f'branch at {site:#x} is not to {target:#x}')


def short_jump(data, site, op, target):
    raw = read_va(data, site, 2)
    if raw[0] != op or site + 2 + struct.unpack('<b', raw[1:2])[0] != target:
        raise ValueError(f'branch at {site:#x} is not to {target:#x}')


def slot_call(data, site, slot):
    if read_va(data, site, 2) != b'\xff\x15' or rel_target(data, site, 6) != slot:
        raise ValueError(f'call at {site:#x} is not through slot {slot:#x}')


def slot_calls_in(data, start, size, slot):
    code = read_va(data, start, size)
    return [start + i for i in range(len(code) - 5)
            if code[i:i + 2] == b'\xff\x15'
            and start + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == slot]


def lea(data, site, target):
    if read_va(data, site, 3)[1:2] != b'\x8d' or rel_target(data, site, 7) != target:
        raise ValueError(f'lea at {site:#x} is not to {target:#x}')


def text(data, va, want):
    if read_va(data, va, len(want)) != want:
        raise ValueError(f'string at {va:#x} is not {want!r}')


def ext_check(data, site):
    if read_va(data, site, len(EXT_CHECK)) != EXT_CHECK:
        raise ValueError(f'no _ExtStruct name check at {site:#x}')


def extents(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    out = {}
    for func, want in EXTENTS.items():
        i = bisect.bisect_left(starts, func)
        if i == len(starts) or starts[i] != func:
            raise ValueError(f'no unwind entry starts at {func:#x}')
        size = entries[i]['next_index_upper_bound'] - func
        if size != want:
            raise ValueError(f'extent of {func:#x} is {size:#x}, not {want:#x}')
        out[hex(func)] = hex(size)
    return out


def context_calls(data):
    out = {}
    for site, (names, target) in CTX_CALLS.items():
        if not CTX <= site < CTX + 0x2290:
            raise ValueError(f'site {site:#x} is outside the Context decoder')
        jump(data, site, 'e8', 5, target)
        out[hex(site)] = {'fields': list(names), 'decoder': hex(target)}
    return out


def stubs(data):
    out = {}
    for stub, (name_va, name, reader) in STUBS.items():
        lea(data, stub, name_va)
        text(data, name_va, name)
        if read_va(data, stub + 7, 5) != b'\xb9' + struct.pack('<I', len(name)):
            raise ValueError(f'stub {stub:#x} does not pass length {len(name)}')
        jump(data, stub + 12, 'e9', 5, reader)
        out[hex(stub)] = {'name': name.decode(), 'length': len(name), 'reader': hex(reader)}
    return out


def readers(data):
    for slot, reader in ((INT_SLOT, INT_READER), (TIME_SLOT, TIME_READER), (U64_SLOT, U64_READER)):
        if relocation(data, slot) != reader:
            raise ValueError(f'slot {slot:#x} is not relocated to {reader:#x}')
    out = {}
    for func, (esite, csite, slot, tsite, tbytes, stores) in READERS.items():
        ext_check(data, esite)
        slot_call(data, csite, slot)
        found = slot_calls_in(data, func, EXTENTS[func], slot)
        if found != [csite]:
            raise ValueError(f'reader {func:#x} calls slot {slot:#x} at {[hex(x) for x in found]}')
        if not csite < tsite < stores[0][0]:
            raise ValueError(f'tag test {tsite:#x} is not between the call and the stores')
        pin(data, tsite, tbytes, 'tag 9 test')
        for site, want, meaning in stores:
            pin(data, site, want, meaning)
        out[hex(func)] = {'slot': hex(slot), 'relocated_to': hex(relocation(data, slot)),
                          'call': hex(csite), 'stores': [m for _, _, m in stores]}
    # outer Time reader
    ext_check(data, TIME_OUTER_EXT)
    lea(data, TIME_NAME_LEA, STUBS[0x3d4f3c0][0])
    if read_va(data, TIME_LEN, 5) != b'\xb9\x04\x00\x00\x00':
        raise ValueError(f'outer Time reader does not pass length 4 at {TIME_LEN:#x}')
    jump(data, TIME_INNER_CALL, 'e8', 5, TIME_INNER)
    for site, want, meaning in TIME_OUTER_STORES:
        pin(data, site, want, meaning)
    out[hex(TIME_OUTER)] = {'calls': hex(TIME_INNER), 'name': 'Time',
                            'stores': [m for _, _, m in TIME_OUTER_STORES]}
    return out


def tx_index(data):
    for va, (want, meaning) in TX_PINS.items():
        pin(data, va, want, meaning)
    short_jump(data, 0x451c5c8, 0x75, 0x451c5d4)
    short_jump(data, 0x451c5d2, 0xeb, 0x451c601)
    slot_call(data, TX_SLOT_CALL, U64_SLOT)
    found = slot_calls_in(data, TX, EXTENTS[TX], U64_SLOT)
    if found != [TX_SLOT_CALL]:
        raise ValueError(f'tx_index reader calls slot {U64_SLOT:#x} at {[hex(x) for x in found]}')
    if lea_names(data, TX, EXTENTS[TX]):
        raise ValueError('tx_index reader loads a newtype name')
    return {'nil': 'None (0 at +8), tag 9, no read',
            'other': f'slot {U64_SLOT:#x} -> {U64_READER:#x}; Some (1 at +8, value at +0x10)'}


def lea_names(data, start, size):
    """RIP-relative lea in a range that targets one of the stub names."""
    code = read_va(data, start, size)
    names = {v[0] for v in STUBS.values()}
    return [start + i for i in range(len(code) - 6)
            if code[i] in (0x48, 0x4c) and code[i + 1] == 0x8d and code[i + 2] & 0xc7 == 0x05
            and start + i + 7 + struct.unpack_from('<i', code, i + 3)[0] in names]


def bind(data):
    result = {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'context_calls': context_calls(data),
        'stubs': stubs(data),
        'newtype_readers': readers(data),
        'tx_index': tx_index(data),
        'extents': extents(data),
    }
    result['fields'] = {
        'tx_index': 'option: nil -> None; else u64 slot 0x64dfeb0 -> 0x14b7aa0',
        'round': 'newtype Round: integer slot 0x64e2580 -> 0x348e980',
        'time': 'newtype Time: slot 0x64dfec0 -> 0x14b93c0, 12 bytes',
        'prev_time': 'newtype Time: slot 0x64dfec0 -> 0x14b93c0, 12 bytes',
        'system_nonce': 'newtype SystemNonce: integer slot 0x64e2580 -> 0x348e980',
    }
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
    print(f"fields={','.join(result['fields'])} stubs={len(result['stubs'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
