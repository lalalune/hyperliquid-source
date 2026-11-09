#!/usr/bin/env python3
"""Bind what node #115 does with the hourly mempool_txs line writer (ninth stage).

Continues the observer and writer packets. The eighth stage found that in
0x2af45f0 and 0x2cc1120 the hourly mempool_txs writer is moved to +0x18 of a
stack struct that is passed to 0x5a81ed0 through slot 0x64e74d8. This tool
binds:

1. 0x5a81ed0 spawns two boxed futures through the spawn wrapper 0x15d6ef0
   (slot 0x64e1758): a 0x60-byte future (vtable 0x64b9188, poll 0x5a820d0)
   holding an Arc taken from struct +0xf0, and a 0x2d80-byte future (vtable
   0x64b91a8, poll 0x5a82670) holding the 0x118-byte struct at +0x0 (so the
   writer at +0x18), the third argument at +0x118, the fifth at +0x120, the
   flag byte at +0x1a4 and state byte 0 at +0x1a5. The flag selects a
   31-byte task name or no name;
2. the wrapper: a null name calls 0x15ca9e0 with Location base/src/lu.rs:148:9
   and then CAS 0xcc -> 0x84 on the returned header;
3. the poll reads the writer at +0x18 at two sites only: a None-niche check
   and a pointer passed to the write 0x4e3eaa0;
4. the write 0x4e3eaa0 (one caller): wall clock 0x1629690, path rotation
   0x1546570, reopen through 0x14c3b30 when the path changes (stores date,
   hourly byte, hour), line write 0x50e6760, then an extra flush when writer
   +0xaa and the global byte at 0x64ffe50 are both set;
5. the line: '[' time ',' record ']' '\\n', written through 0x14c37f0, which
   calls the flush gate slot 0x64e0008; the record serializer 0x5a80250
   writes {"tx_hash": record+0x10, "signed_actions": record+0x0}.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import bisect
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-line-writer-consumer-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

SPAWNER, SPAWNER_SLOT = 0x5a81ed0, 0x64e74d8
WRAPPER, WRAPPER_SLOT = 0x15d6ef0, 0x64e1758
POLL_A, POLL_B = 0x5a820d0, 0x5a82670
WRITE, LINE, RECORD = 0x4e3eaa0, 0x50e6760, 0x5a80250
LINER_WRITE = 0x14c37f0

RELOCS = {
    SPAWNER_SLOT: SPAWNER,
    WRAPPER_SLOT: WRAPPER,
    0x64b9188: 0x5a5c580, 0x64b91a0: POLL_A,     # vtable A: drop, poll
    0x64b91a8: 0x5a5c610, 0x64b91c0: POLL_B,     # vtable B: drop, poll
    0x64e0990: 0x1629690,                        # wall clock
    0x64e0f80: 0x1546570,                        # path rotation
    0x64e0020: 0x14c3b30,                        # liner open
    0x64e0f88: 0x64ffe50,                        # global flush byte
    0x64e0008: 0x154ce40,                        # flush gate
    0x64014e0: 0x4326c1,                         # Location file
}
VTABLE_SIZES = {0x64b9188: (0x60, 8), 0x64b91a8: (0x2d80, 8)}
STRINGS = {
    0x93b963: b'nv_stream_apply_execution_state',
    0x93b982: b'nv_stream_forward_client_blocks',
    0x93b509: b'tx_hash',
    0x93b86f: b'signed_actions',
    0x4326c1: b'base/src/lu.rs',
}
LOCATION = (0x64014e0, 14, 148, 9)

FIXED = {
    0x5a81f06: '488b87f0000000',        # mov rax,[rdi+0xf0]
    0x5a81f0d: 'f048ff00',              # lock inc [rax]
    0x5a81f3d: 'bf60000000',            # mov edi,0x60
    0x5a81f51: '488d0d0b9aebfa',        # lea rcx,[rip+...]
    0x5a81f58: '31ff',                  # xor edi,edi
    0x5a81f5a: '4084ed',                # test bpl,bpl
    0x5a81f5d: '480f45f9',              # cmovne rdi,rcx
    0x5a81f96: '488d0deb71a300',        # lea rcx,[rip+...]
    0x5a81f9d: 'be1f000000',            # mov esi,0x1f
    0x5a81fa2: '4889c2',                # mov rdx,rax
    0x5a81fa5: 'ff15adf7a500',          # call [rip+...]
    0x5a81fab: '4c89b42428010000',      # mov [rsp+0x128],r14
    0x5a81fb3: '488d7c2410',            # lea rdi,[rsp+0x10]
    0x5a81fb8: 'ba18010000',            # mov edx,0x118
    0x5a81fbd: '4889de',                # mov rsi,rbx
    0x5a81fc0: 'ff1542d5a500',          # call [rip+...]
    0x5a81fce: '4088ac24b4010000',      # mov byte [rsp+0x1b4],bpl
    0x5a81fd6: 'c68424b501000000',      # mov byte [rsp+0x1b5],0x0
    0x5a81fde: 'bf802d0000',            # mov edi,0x2d80
    0x5a81ff1: '488d058a99ebfa',        # lea rax,[rip+...]
    0x5a81ff8: '4531f6',                # xor r14d,r14d
    0x5a81ffb: '4084ed',                # test bpl,bpl
    0x5a81ffe: '4c0f45f0',              # cmovne r14,rax
    0x5a82002: '488d742410',            # lea rsi,[rsp+0x10]
    0x5a82007: 'ba802d0000',            # mov edx,0x2d80
    0x5a8200c: '4889df',                # mov rdi,rbx
    0x5a8200f: 'ff15f3d4a500',          # call [rip+...]
    0x5a82015: '488d0d8c71a300',        # lea rcx,[rip+...]
    0x5a8201c: 'be1f000000',            # mov esi,0x1f
    0x5a82021: '4c89f7',                # mov rdi,r14
    0x5a82024: '4889da',                # mov rdx,rbx
    0x5a82027: '4881c4902d0000',        # add rsp,0x2d90
    0x5a8202e: '5b',                    # pop rbx
    0x5a8202f: '415c',                  # pop r12
    0x5a82031: '415e',                  # pop r14
    0x5a82033: '415f',                  # pop r15
    0x5a82035: '5d',                    # pop rbp
    0x5a82036: 'ff251cf7a500',          # jmp [rip+...]
    0x15d6f01: '4885ff',                # test rdi,rdi
    0x15d6f22: '488d15b7a5e204',        # lea rdx,[rip+...]
    0x15d6f37: 'b984000000',            # mov ecx,0x84
    0x15d6f3c: 'b8cc000000',            # mov eax,0xcc
    0x15d6f41: 'f0480fb10f',            # lock cmpxchg [rdi],rcx
    0x5a826b5: '0fb687a5010000',        # movzx eax,byte [rdi+0x1a5]
    0x5a887c2: '48b80000000000000080',  # movabs rax,0x8000000000000000
    0x5a887cc: '48394318',              # cmp [rbx+0x18],rax
    0x5a887d0: '0f847e010000',          # je 5a88954
    0x5a887fc: '488d7318',              # lea rsi,[rbx+0x18]
    0x5a88854: '488dbc2410230000',      # lea rdi,[rsp+0x2310]
    0x5a8885c: '488d942420140000',      # lea rdx,[rsp+0x1420]
    0x5a88864: 'e837623bff',            # call 4e3eaa0
    0x4e3eb1e: 'ff155c246a01',          # call [rip+...]
    0x4e3eb24: '31c0',                  # xor eax,eax
    0x4e3eb26: '493b4648',              # cmp rax,[r14+0x48]
    0x4e3eb2a: '488b742458',            # mov rsi,[rsp+0x58]
    0x4e3eb93: 'ff1587146a01',          # call [rip+...]
    0x4e3ebd1: '4189ae98000000',        # mov dword [r14+0x98],ebp
    0x4e3ebd8: '4588aea8000000',        # mov byte [r14+0xa8],r13b
    0x4e3ebdf: '4588a6a9000000',        # mov byte [r14+0xa9],r12b
    0x4e3ec08: '488d942488000000',      # lea rdx,[rsp+0x88]
    0x4e3ec10: '4c89ff',                # mov rdi,r15
    0x4e3ec13: 'e8487b2a00',            # call 50e6760
    0x4e3ec2c: '4180beaa00000000',      # cmp byte [r14+0xaa],0x0
    0x4e3ec36: '488b054b236a01',        # mov rax,[rip+...]
    0x50e679d: 'c6005b',                # mov byte [rax],0x5b
    0x50e67e5: 'c604302c',              # mov byte [rax+rsi*1],0x2c
    0x50e67f0: '4983c410',              # add r12,0x10
    0x50e67fc: 'e84f9a9900',            # call 5a80250
    0x50e687f: 'c604305d',              # mov byte [rax+rsi*1],0x5d
    0x50e68c6: '41c604060a',            # mov byte [r14+rax*1],0xa
    0x50e68dc: 'e80fcf3dfc',            # call 14c37f0
    0x5a80270: 'c604017b',              # mov byte [rcx+rax*1],0x7b
    0x5a80287: '488d4b10',              # lea rcx,[rbx+0x10]
    0x5a8028b: '488d3577b2ebfa',        # lea rsi,[rip+...]
    0x5a80292: '488d7c2408',            # lea rdi,[rsp+0x8]
    0x5a80297: 'ba07000000',            # mov edx,0x7
    0x5a802ad: '488d35bbb5ebfa',        # lea rsi,[rip+...]
    0x5a802b4: '488d7c2408',            # lea rdi,[rsp+0x8]
    0x5a802b9: 'ba0e000000',            # mov edx,0xe
    0x5a802be: '4889d9',                # mov rcx,rbx
    0x5a802f0: 'c604307d',              # mov byte [rax+rsi*1],0x7d
    0x14c383f: 'ff15c3c70105',          # call [rip+...]
    0x2af5b03: 'ff15cf199f03',          # call [rip+...]
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x5a81f51, b'\x48\x8d\x0d', 7, 0x93b963),
    (0x5a81f96, b'\x48\x8d\x0d', 7, 0x64b9188),
    (0x5a81fa5, b'\xff\x15', 6, WRAPPER_SLOT),
    (0x5a81ff1, b'\x48\x8d\x05', 7, 0x93b982),
    (0x5a82015, b'\x48\x8d\x0d', 7, 0x64b91a8),
    (0x5a82036, b'\xff\x25', 6, WRAPPER_SLOT),
    (0x15d6f22, b'\x48\x8d\x15', 7, LOCATION[0]),
    (0x5a88864, b'\xe8', 5, WRITE),
    (0x4e3eb1e, b'\xff\x15', 6, 0x64e0f80),
    (0x4e3eb93, b'\xff\x15', 6, 0x64e0020),
    (0x4e3ec13, b'\xe8', 5, LINE),
    (0x4e3ec36, b'\x48\x8b\x05', 7, 0x64e0f88),
    (0x50e67fc, b'\xe8', 5, RECORD),
    (0x50e68dc, b'\xe8', 5, LINER_WRITE),
    (0x5a8028b, b'\x48\x8d\x35', 7, 0x93b509),
    (0x5a802ad, b'\x48\x8d\x35', 7, 0x93b86f),
    (0x14c383f, b'\xff\x15', 6, 0x64e0008),
    (0x2af5b03, b'\xff\x15', 6, SPAWNER_SLOT),
)


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def rip_target(data, va, prefix, length):
    raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


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


def text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec['address'], data[sec['offset']:sec['offset'] + sec['size']]


def callers(data, target, slot=None):
    """Direct `call rel32` sites, plus `call [rip+slot]` sites when a slot is given."""
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code) and base + i + 5 + struct.unpack_from('<i', code, i + 1)[0] == target:
            out.append(base + i)
    if slot is not None:
        for m in re.finditer(rb'\xff\x15', code):
            i = m.start()
            if i + 6 <= len(code) and base + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == slot:
                out.append(base + i)
    return sorted(out)


def frame_of(fdes):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]

    def frame(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
            raise ValueError(f'{va:#x} has no FDE')
        return ordered[i]['start'], ordered[i]['end']
    return frame


def pattern_sites(data, lo, hi, pattern):
    base, code = text(data)
    window = code[lo - base:hi - base]
    return [lo + m.start() for m in re.finditer(re.escape(pattern), window)]


def bind(data, fdes):
    for va, expect in FIXED.items():
        if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
            raise ValueError(f'instruction at {va:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for vtable, (size, align) in VTABLE_SIZES.items():
        if struct.unpack('<QQ', read_va(data, vtable + 8, 16)) != (size, align):
            raise ValueError(f'vtable {vtable:#x} layout changed')
    for va, expect in STRINGS.items():
        if read_va(data, va, len(expect)) != expect:
            raise ValueError(f'string at {va:#x} changed')
    loc = LOCATION[0]
    if struct.unpack('<QII', read_va(data, loc + 8, 16)) != LOCATION[1:]:
        raise ValueError('Location changed')

    frame = frame_of(fdes)
    poll = frame(POLL_B)
    spawn_sites = callers(data, SPAWNER, SPAWNER_SLOT)
    census = {
        'spawner_callers': [[hex(v), hex(frame(v)[0])] for v in spawn_sites],
        'write_callers': [hex(v) for v in callers(data, WRITE)],
        'line_callers': [hex(v) for v in callers(data, LINE)],
        'record_callers': [hex(v) for v in callers(data, RECORD)],
        'liner_write_callers': len(callers(data, LINER_WRITE)),
        'poll_writer_reads': [hex(v) for v in
                              pattern_sites(data, *poll, b'\x48\x39\x43\x18')
                              + pattern_sites(data, *poll, b'\x48\x8d\x73\x18')],
    }
    if census['write_callers'] != ['0x5a88864'] or len(census['record_callers']) != 1:
        raise ValueError('call census changed')
    if [c[1] for c in census['spawner_callers']] != ['0x2af45f0', '0x2cc1120']:
        raise ValueError('spawner census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'spawner': {
            'fn': hex(SPAWNER), 'slot': hex(SPAWNER_SLOT), 'fde': [hex(v) for v in frame(SPAWNER)],
            'task_a': '0x60-byte box, vtable 0x64b9188 (drop 0x5a5c580, size 0x60, align 8, poll %s); '
                      'holds 0x20 bytes from the fourth argument and the Arc at struct +0xf0 (lock inc at 0x5a81f0d); '
                      'name %r when the flag is set' % (hex(POLL_A), STRINGS[0x93b963].decode()),
            'task_b': '0x2d80-byte box, vtable 0x64b91a8 (drop 0x5a5c610, size 0x2d80, align 8, poll %s); '
                      'struct (0x118 bytes) at +0x0, third argument at +0x118, fifth at +0x120, flag at +0x1a4, '
                      'state 0 at +0x1a5; name %r when the flag is set' % (hex(POLL_B), STRINGS[0x93b982].decode()),
            'name_len': 0x1f,
        },
        'spawn_wrapper': {
            'fn': hex(WRAPPER),
            'unnamed': 'call 0x15ca9e0 with Location %s:%d:%d, then lock cmpxchg 0xcc -> 0x84 on the result'
                       % (STRINGS[0x4326c1].decode(), LOCATION[2], LOCATION[3]),
            'named': 'call 0x15d6730 with edx = 1',
        },
        'poll_b': {'fde': [hex(v) for v in poll], 'state_byte': '+0x1a5 (0x5a826b5)',
                   'writer_none_check': '0x5a887cc cmp [rbx+0x18], 0x8000000000000000; je 0x5a88954',
                   'writer_passed': '0x5a887fc lea rsi, [rbx+0x18] -> call %s at 0x5a88864' % hex(WRITE)},
        'write': {
            'fn': hex(WRITE),
            'steps': ['wall clock slot 0x64e0990 -> 0x1629690',
                      'path rotation slot 0x64e0f80 -> 0x1546570',
                      'liner +0x48 None (0 - x overflows) -> drop path, no write',
                      'new path -> open slot 0x64e0020 -> 0x14c3b30; store date +0x98, hourly +0xa8, hour +0xa9',
                      'line write %s' % hex(LINE),
                      'store time at +0x9c',
                      'if +0xaa and byte [0x64ffe50] are set: 0x14c3950 -> 0x1533e80, error dropped by 0x14c4d00'],
        },
        'line': {
            'fn': hex(LINE),
            'shape': "'[' time ',' record ']' '\\n'",
            'record_offset': 'time argument +0x10 (0x50e67f0 add r12, 0x10)',
            'liner_write': '%s, which calls the flush gate slot 0x64e0008' % hex(LINER_WRITE),
        },
        'record': {
            'fn': hex(RECORD),
            'fields': [['tx_hash', 'record +0x10', hex(0x5a8028b)],
                       ['signed_actions', 'record +0x0', hex(0x5a802ad)]],
        },
        'census': census,
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
    c = result['census']
    print(f"spawner_callers={len(c['spawner_callers'])} poll_writer_reads={len(c['poll_writer_reads'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
