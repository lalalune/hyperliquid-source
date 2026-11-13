#!/usr/bin/env python3
"""Bind the node #115 node_slow_abci_engine runner built by 0x5649680 (39th stage).

0x5a6bfb0 calls the fast runner builder 0x567bd50 directly (#5916) and passes
the engine value with the 21-byte name `node_slow_abci_engine` to slot
0x64ebc98, which is relocated to 0x5649680. This tool binds:

1. the call site: lea rdx -> `node_slow_abci_engine`, ecx = 0x15, call
   [0x64ebc98]; 0x5649680 has no direct caller, the fast builder has one
   (0x5a6c21c);
2. a pool: slot 0x64e1210 (-> 0x1563a60) is called with edi = 3, esi = 0x10
   and the 23-byte name `SlowAbciThreadPool::new`; its result lands at
   runner +0xb48;
3. two f64 maps keyed by `compute_write/spawn_slow_abci_driver_apply_block`
   (0x30 bytes): 0.05 inserted by 0x51d4530 and 0.35 by 0x51d4df0, both
   B-tree inserts (len u16 +0x112, children +0x118, values +0xb8, key compare
   through memcmp);
4. the runner layout shared with the fast runner 0x567bd50: a 0x478-byte
   tagged engine value at +0x6a8, two 0x2a8-byte values at +0x158 and +0x400
   built by slot 0x64e5c00 (-> 0x47721f0, ecx 1 then 0), 1000000000 at +0x128,
   the RwLock Location net_utils/src/rw_lock.rs:110:14 passed to slot
   0x64e1078 (-> 0x154c700);
5. what only the slow runner adds: setne of the byte behind slot 0x64e5bf8 at
   +0xb40 (the fast runner stores its byte at +0xb20), the pool at +0xb48, and
   two blocks {0, 60000, 525600, 0} at +0xb20 and +0xb50.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (SHA256, direct_calls, fixed, read_va, relative_relocations,
                                 rip_target, text)

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-slow-abci-engine-115'

SLOW = 0x5649680
FAST = 0x567bd50
CALLER_SLOT = 0x64ebc98
POOL_SLOT, POOL = 0x64e1210, 0x1563a60
LOCK_SLOT, LOCK = 0x64e1078, 0x154c700
PART_SLOT, PART = 0x64e5c00, 0x47721f0
BYTE_SLOT, BYTE_CELL = 0x64e5bf8, 0x64fdc1c
MEMCPY_SLOT = 0x64df508
LOCATION = 0x64ab898
INSERT_A, INSERT_B = 0x51d4530, 0x51d4df0

STRINGS = {
    0x93afc4: b'node_slow_abci_engine',
    0x92a814: b'SlowAbciThreadPool::new',
    0x92a82b: b'compute_write/spawn_slow_abci_driver_apply_block',
    0x432e59: b'net_utils/src/rw_lock.rs',
}
F64 = {0x459038: 0.05, 0x458f50: 0.35}

FIXED = {
    # call site in 0x5a6bfb0
    0x5a6c614: 'b915000000',                  # mov ecx, 0x15 (len node_slow_abci_engine)
    # pool
    0x56496a4: 'bf03000000',                  # mov edi, 3
    0x56496a9: 'be10000000',                  # mov esi, 0x10
    0x56496ae: 'b917000000',                  # mov ecx, 0x17 (len SlowAbciThreadPool::new)
    # two maps keyed by the 0x30-byte name
    0x5649703: 'ba30000000',                  # mov edx, 0x30
    0x5649791: 'ba30000000',                  # mov edx, 0x30
    # the two 0x2a8 parts: flag 1 then 0
    0x5649b01: 'b901000000',                  # mov ecx, 1
    0x5649b5e: '31c9',                        # xor ecx, ecx
    # slow runner layout
    0x5649b66: '498dbea8060000',              # lea rdi, [r14+0x6a8]
    0x5649b7c: 'ba78040000',                  # mov edx, 0x478
    0x5649bb4: '498dbe58010000',              # lea rdi, [r14+0x158]
    0x5649bc3: 'baa8020000',                  # mov edx, 0x2a8
    0x5649bcb: '498dbe00040000',              # lea rdi, [r14+0x400]
    0x5649bda: 'baa8020000',                  # mov edx, 0x2a8
    0x5649bfa: '41c78628010000' '00ca9a3b',   # mov dword [r14+0x128], 1000000000
    0x5649c35: '49c786200b0000' '00000000',   # mov qword [r14+0xb20], 0
    0x5649c40: '49c786280b0000' '60ea0000',   # mov qword [r14+0xb28], 60000
    0x5649c4b: '49c786300b0000' '20050800',   # mov qword [r14+0xb30], 525600
    0x5649c56: '49c786380b0000' '00000000',   # mov qword [r14+0xb38], 0
    0x5649c61: '410f9586400b0000',            # setne byte [r14+0xb40]
    0x5649c69: '488b442408',                  # mov rax, [rsp+8] (pool result)
    0x5649c6e: '498986480b0000',              # mov [r14+0xb48], rax
    0x5649c75: '49c786500b0000' '00000000',   # mov qword [r14+0xb50], 0
    0x5649c80: '49c786580b0000' '60ea0000',   # mov qword [r14+0xb58], 60000
    0x5649c8b: '49c786600b0000' '20050800',   # mov qword [r14+0xb60], 525600
    0x5649c96: '49c786680b0000' '00000000',   # mov qword [r14+0xb68], 0
    # fast runner layout (same offsets)
    0x567c0c7: '498dbda8060000',              # lea rdi, [r13+0x6a8]
    0x567c0dd: 'ba78040000',                  # mov edx, 0x478
    0x567c0fa: '410f9585200b0000',            # setne byte [r13+0xb20]
    0x567c139: '498dbd58010000',              # lea rdi, [r13+0x158]
    0x567c148: 'baa8020000',                  # mov edx, 0x2a8
    0x567c14f: '498dbd00040000',              # lea rdi, [r13+0x400]
    0x567c15e: 'baa8020000',                  # mov edx, 0x2a8
    0x567c165: '41c78528010000' '00ca9a3b',   # mov dword [r13+0x128], 1000000000
    # B-tree f64 inserts
    0x51d4567: '0fb7a912010000',              # movzx ebp, word [rcx+0x112]
    0x51d45fa: '4a8b8ce918010000',            # mov rcx, [rcx+r13*8+0x118]
    0x51d461c: 'f2420f118ce8b8000000',        # movsd [rax+r13*8+0xb8], xmm1
    0x51d4e27: '0fb7a912010000',              # movzx ebp, word [rcx+0x112]
    0x51d4edc: 'f2420f118ce8b8000000',        # movsd [rax+r13*8+0xb8], xmm1
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x5a6c5fd, b'\x48\x8d\x15', 7, 0x93afc4),
    (0x5a6c619, b'\xff\x15', 6, CALLER_SLOT),
    (0x564969d, b'\x48\x8d\x15', 7, 0x92a814),
    (0x56496b3, b'\xff\x15', 6, POOL_SLOT),
    (0x56496ec, b'\x48\x8d\x35', 7, 0x92a82b),
    (0x56496fb, b'\xf2\x0f\x10\x05', 8, 0x459038),
    (0x564977a, b'\x48\x8d\x35', 7, 0x92a82b),
    (0x5649789, b'\xf2\x0f\x10\x05', 8, 0x458f50),
    (0x5649864, b'\x48\x8b\x05', 7, BYTE_SLOT),
    (0x56498c8, b'\x48\x8d\x15', 7, LOCATION),
    (0x56498df, b'\xff\x15', 6, LOCK_SLOT),
    (0x5649b06, b'\xff\x15', 6, PART_SLOT),
    (0x5649b60, b'\xff\x15', 6, PART_SLOT),
    (0x5649b75, b'\x4c\x8b\x3d', 7, MEMCPY_SLOT),
    (0x567be4e, b'\xff\x15', 6, LOCK_SLOT),
    (0x567c074, b'\xff\x15', 6, PART_SLOT),
    (0x567c0c1, b'\xff\x15', 6, PART_SLOT),
    (0x51d45ad, b'\xff\x15', 6, 0x64dfb50),
)
DIRECT = (
    (0x5649708, INSERT_A),
    (0x5649796, INSERT_B),
    (0x5a6c21c, FAST),
)
RELOCATIONS = {CALLER_SLOT: SLOW, POOL_SLOT: POOL, LOCK_SLOT: LOCK, PART_SLOT: PART,
               BYTE_SLOT: BYTE_CELL, LOCATION: 0x432e59}


def slot_calls(data, slot):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xff\x15', code):
        i = m.start()
        if i + 6 <= len(code) and base + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == slot:
            out.append(base + i)
    return out


def glob_dat_symbol(data, slot):
    from elf_index import sections
    secs = sections(data)
    for sec in secs:
        if sec['type'] != 4:
            continue
        for va, info, _ in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if va == slot and info & 0xffffffff == 6:
                index = info >> 32
                dynsym = next(s for s in secs if s['name'] == '.dynsym')
                dynstr = next(s for s in secs if s['name'] == '.dynstr')
                name_off = struct.unpack_from('<I', data, dynsym['offset'] + 24 * index)[0]
                start = dynstr['offset'] + name_off
                return data[start:data.index(b'\0', start)].decode()
    return None


def location(data, va):
    raw = read_va(data, va, 24)
    length, line, col = struct.unpack_from('<QII', raw, 8)
    return length, line, col


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, target in DIRECT:
        if va not in direct_calls(data, target):
            raise ValueError(f'direct call at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, text_bytes in STRINGS.items():
        if read_va(data, va, len(text_bytes)) != text_bytes:
            raise ValueError(f'string at {va:#x} changed')
    for va, value in F64.items():
        if struct.unpack('<d', read_va(data, va, 8))[0] != value:
            raise ValueError(f'f64 at {va:#x} changed')
    if glob_dat_symbol(data, 0x64dfb50) != 'memcmp':
        raise ValueError('B-tree key compare symbol changed')
    loc_len, loc_line, loc_col = location(data, LOCATION)
    if (loc_len, loc_line, loc_col) != (len(STRINGS[0x432e59]), 110, 14):
        raise ValueError('rw_lock Location changed')

    starts = {f['start'] for f in fdes}
    if SLOW not in starts or FAST not in starts:
        raise ValueError('runner builders no longer start an FDE')
    slow_slot_calls = slot_calls(data, CALLER_SLOT)
    slow_direct = direct_calls(data, SLOW)
    fast_direct = direct_calls(data, FAST)
    if slow_direct or fast_direct != [0x5a6c21c] or slow_slot_calls != [0x5a6c619]:
        raise ValueError('builder call census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'call_site': {
            'caller': '0x5a6bfb0',
            'fast_builder_direct_calls': [hex(v) for v in fast_direct],
            'slow_builder_direct_calls': [hex(v) for v in slow_direct],
            'slow_builder_slot': hex(CALLER_SLOT) + ' -> ' + hex(SLOW),
            'slow_builder_slot_calls': [hex(v) for v in slow_slot_calls],
            'name': STRINGS[0x93afc4].decode() + ' (ecx = 0x15)',
        },
        'pool': {
            'slot': hex(POOL_SLOT) + ' -> ' + hex(POOL),
            'args': 'edi = 3, esi = 0x10, rdx = %r, ecx = 0x17' % STRINGS[0x92a814].decode(),
            'stored_at': '+0xb48',
        },
        'maps': {
            'key': STRINGS[0x92a82b].decode(),
            'inserts': {hex(INSERT_A): 0.05, hex(INSERT_B): 0.35},
            'btree': 'len u16 +0x112, keys from +0x10 compared with memcmp, values f64 +0xb8 + 8*i, '
                     'children +0x118 + 8*i; an equal key overwrites the value',
        },
        'runner_layout': {
            'shared_with_fast': {
                '+0x6a8': '0x478 bytes: tag qword then the 0x470 engine value (#5916)',
                '+0x158': '0x2a8 bytes from slot %s -> %s, ecx = 1' % (hex(PART_SLOT), hex(PART)),
                '+0x400': '0x2a8 bytes from slot %s -> %s, ecx = 0' % (hex(PART_SLOT), hex(PART)),
                '+0x128': 'dword 1000000000',
                'lock_location': '%s:%d:%d via slot %s -> %s'
                                 % (STRINGS[0x432e59].decode(), loc_line, loc_col, hex(LOCK_SLOT), hex(LOCK)),
            },
            'fast_only': {'+0xb20': 'setne byte (source not mapped here)'},
            'slow_only': {
                '+0xb20': '{0, 60000, 525600, 0} (qwords)',
                '+0xb40': 'setne of the byte behind slot %s (-> %s)' % (hex(BYTE_SLOT), hex(BYTE_CELL)),
                '+0xb48': 'pool',
                '+0xb50': '{0, 60000, 525600, 0} (qwords)',
            },
        },
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
    print('slow builder slot calls=%s' % result['call_site']['slow_builder_slot_calls'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
