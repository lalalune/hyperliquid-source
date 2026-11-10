#!/usr/bin/env python3
"""Bind the node #115 'node save visor_abci_state' periodic task (stage 77b).

Continues #6002/#6004. Stage 34 found that 0x5a39630, reached only through the
relocation at 0x64b8b30, builds a `visor_abci_states` line writer and writes
`hyperliquid_data/visor_abci_state.json`. This tool binds:

1. the spawn: both pollers (0x2aed339 in 0x2aeaef0, 0x2cb8959 in 0x2cb6500)
   box one Arc pointer (8 bytes), and call slot 0x64e1750 -> 0x15d63c0 with
   the 26-byte name `node save visor_abci_state` and the closure vtable
   0x64b8b18 {drop 0x5a5a230, size 8, align 8, call 0x5a39630};
2. the loop body 0x5a39630: a daily writer `visor_abci_states` (17 bytes)
   converted to hourly; then forever: read wrapper 0x5648400 with the name
   `get_visor_state` (15 bytes), path builder 0x5942870 with
   `visor_abci_state`, value writer 0x50de010 (unwrap at node.rs:914:42),
   line writer 0x4e3fe00, then clock_nanosleep(CLOCK_MONOTONIC) for 5 s with
   an EINTR retry;
3. the line writer 0x4e3fe00 serialises its record through 0x50e50b0, whose
   value serializer 0x51addb0 emits the same six field names, in the same
   order and with the same lengths, as the pretty serializer 0x51adf60 used for
   visor_abci_state.json (#6002/#6004);
4. the read wrapper 0x5648400 uses the per-minute counter block at
   runner +0xb50..+0xb68 that #6037 bound in 0x5647720.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import fixed, read_va, relative_relocations, rip_target, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-visor-abci-states-log-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

LOOP = 0x5a39630
VTABLE = 0x64b8b18
READ = 0x5648400
LINE_WRITER = 0x4e3fe00
COMPACT = 0x51addb0
PRETTY = 0x51adf60
STRINGS = {
    0x93b0b6: b'node save visor_abci_state',
    0x93b0d0: b'visor_abci_states',
    0x93b0e1: b'get_visor_state',
    0x4564d0: b'visor_abci_state',
}
FIELDS = ((0x4504e0, 0x10), (0x91f96f, 0x0e), (0x91f97d, 0x06),
          (0x91f983, 0x17), (0x91f99a, 0x0e), (0x91f9a8, 0x0f))
FIELD_NAMES = ('hardfork_version', 'initial_height', 'height',
               'scheduled_freeze_height', 'consensus_time', 'wall_clock_time')
RELOCS = {
    0x64b8b18: 0x5a5a230,   # vtable drop
    0x64b8b30: LOOP,        # vtable call
    0x64e1750: 0x15d63c0,   # spawn slot
    0x64e0f98: 0x1546700,   # daily writer ctor (#5872)
    0x64e0fa0: 0x1546000,   # hourly conversion (#5872)
    0x64b7f70: 0x4564d0,    # &'visor_abci_state'
    0x64e0f88: 0x64ffe50,   # global flush byte (#5878)
}

FIXED = {
    # poller spawn site (0x2aeaef0): box one 8-byte Arc, name length 26
    0x2aed31b: 'bf08000000',            # mov edi, 8          (alloc size)
    0x2aed32f: '488918',                # mov [rax], rbx      (Arc ptr into box)
    0x2aed340: 'be1a000000',            # mov esi, 0x1a       (name length)
    0x2aed345: '4889c2',                # mov rdx, rax        (boxed closure)
    0x2cb8960: 'be1a000000',            # second poller: same name length
    # loop body 0x5a39630
    0x5a39641: '4c8b37',                # mov r14, [rdi]      (Arc ptr from box)
    0x5a39658: 'ba11000000',            # mov edx, 0x11       (len 'visor_abci_states')
    0x5a3967a: '498d4610',              # lea rax, [r14+0x10] (Arc payload)
    0x5a396b0: 'b90f000000',            # mov ecx, 0xf        (len 'get_visor_state')
    0x5a396f4: '4885c0',                # test rax, rax       (value writer Err)
    0x5a39720: '41be05000000',          # mov r14d, 5         (sleep seconds)
    0x5a3975d: 'bf01000000',            # mov edi, 1          (CLOCK_MONOTONIC)
    0x5a39762: '31f6',                  # xor esi, esi        (relative sleep)
    0x5a3976a: 'ffd5',                  # call rbp            (clock_nanosleep)
    0x5a39774: '83f804',                # cmp eax, 4          (EINTR -> retry)
    0x5a397c3: 'be2b000000',            # mov esi, 0x2b       (unwrap message length)
    # read wrapper 0x5648400 vs 0x5647720 (#6037): same counter block
    0x5648442: 'ba01000000',            # mov edx, 1          (blocking mode)
    0x564844c: '498d9d500b0000',        # lea rbx, [r13+0xb50]
    0x5648553: '498985600b0000',        # mov [r13+0xb60], rax (last minute)
    0x56488aa: '49898d680b0000',        # mov [r13+0xb68], rcx (count)
    0x564776c: '498d9d500b0000',        # 0x5647720: lea rbx, [r13+0xb50]
    # line writer 0x4e3fe00: extra flush gate (#5876 shape)
    0x4e3ff75: '4180beaa00000000',      # cmp byte [r14+0xaa], 0
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x2aed320, b'\xff\x15', 6, 0x64df480),
    (0x2aed332, b'\x48\x8d\x3d', 7, 0x93b0b6),
    (0x2aed339, b'\x48\x8d\x0d', 7, VTABLE),
    (0x2aed348, b'\xff\x15', 6, 0x64e1750),
    (0x2cb8952, b'\x48\x8d\x3d', 7, 0x93b0b6),
    (0x2cb8959, b'\x48\x8d\x0d', 7, VTABLE),
    (0x2cb8968, b'\xff\x15', 6, 0x64e1750),
    (0x5a39649, b'\x48\x8d\x35', 7, 0x93b0d0),
    (0x5a3965d, b'\xff\x15', 6, 0x64e0f98),
    (0x5a39670, b'\xff\x15', 6, 0x64e0fa0),
    (0x5a3969f, b'\x48\x8b\x2d', 7, 0x64e11e8),
    (0x5a396bd, b'\x48\x8d\x15', 7, 0x93b0e1),
    (0x5a396c4, b'\xe8', 5, READ),
    (0x5a396cc, b'\x48\x8d\x35', 7, 0x64b7f70),
    (0x5a396d3, b'\xe8', 5, 0x5942870),
    (0x5a396e8, b'\x48\x8d\x0d', 7, 0x64b8b38),
    (0x5a396ef, b'\xe8', 5, 0x50de010),
    (0x5a3971b, b'\xe8', 5, LINE_WRITER),
    (0x5a397a9, b'\x48\x8d\x3d', 7, 0x9382bc),
    (0x5648447, b'\xe8', 5, 0x4e47060),
    (0x564885e, b'\xe8', 5, 0x51eaff0),
    (0x5647767, b'\xe8', 5, 0x4e46b50),
    (0x4e3ff5c, b'\xe8', 5, 0x50e50b0),
    (0x4e3ff7f, b'\x48\x8b\x05', 7, 0x64e0f88),
    (0x50e5151, b'\xe8', 5, COMPACT),
)
LOCATION = (0x64b8b38, b'node/src/node.rs', 914, 42)
SLEEP_LOCATION = (0x64c3bc8, 581, 17)


def glob_dat_symbol(data, slot):
    from elf_index import sections
    secs = sections(data)
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynstr = next(s for s in secs if s['name'] == '.dynstr')
    for sec in secs:
        if sec['type'] != 4:
            continue
        for va, info, _ in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if va == slot and info & 0xffffffff == 6:
                name_off = struct.unpack_from('<I', data, dynsym['offset'] + (info >> 32) * 24)[0]
                end = data.index(b'\0', dynstr['offset'] + name_off)
                return data[dynstr['offset'] + name_off:end].decode()
    return None


def field_table(data, start, span=0x1b0):
    """(string va, length) pairs: lea rsi,[rip+x] then mov edx,len within 16 bytes."""
    code = read_va(data, start, span)
    out = []
    for m in re.finditer(rb'\x48\x8d\x35', code):
        i = m.start()
        target = start + i + 7 + struct.unpack_from('<i', code, i + 3)[0]
        window = code[i + 7:i + 23]
        k = window.find(b'\xba')
        if k >= 0 and k + 5 <= len(window):
            out.append((target, struct.unpack_from('<I', window, k + 1)[0]))
    return out


def census(data, calls, leas):
    """One pass over .text: direct calls to `calls` and RIP-relative lea to `leas`."""
    base, code = text(data)
    found = {t: [] for t in list(calls) + list(leas)}
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code):
            t = base + i + 5 + struct.unpack_from('<i', code, i + 1)[0]
            if t in calls:
                found[t].append(base + i)
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = m.start()
        if i + 7 <= len(code):
            t = base + i + 7 + struct.unpack_from('<i', code, i + 3)[0]
            if t in leas:
                found[t].append(base + i)
    return found


def location(data, va, rel):
    ptr = rel.get(va)
    length, line, col = struct.unpack('<QII', read_va(data, va + 8, 16))
    return read_va(data, ptr, length), line, col


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    vt = struct.unpack('<QQQ', read_va(data, VTABLE + 8, 24))
    if vt[:2] != (8, 8):
        raise ValueError('closure vtable size/align changed')
    for va, s in STRINGS.items():
        if read_va(data, va, len(s)) != s:
            raise ValueError(f'string at {va:#x} changed')
    if glob_dat_symbol(data, 0x64e11e8) != 'clock_nanosleep':
        raise ValueError('sleep slot symbol changed')
    loc = location(data, LOCATION[0], rel)
    if loc != LOCATION[1:]:
        raise ValueError('value writer Location changed')
    if location(data, SLEEP_LOCATION[0], rel)[1:] != SLEEP_LOCATION[1:]:
        raise ValueError('sleep Location changed')
    compact, pretty = field_table(data, COMPACT), field_table(data, PRETTY)
    if compact[:6] != list(FIELDS) or pretty[:6] != list(FIELDS):
        raise ValueError('visor state field table changed')
    names = [read_va(data, va, n).decode() for va, n in FIELDS]
    if names != list(FIELD_NAMES):
        raise ValueError('visor state field names changed')

    found = census(data, calls=(LOOP, READ, LINE_WRITER, COMPACT), leas=(VTABLE, 0x93b0b6))
    starts = {f['start']: f['end'] for f in fdes}
    for fn in (LOOP, READ, 0x5647720, LINE_WRITER, 0x50e50b0):
        if fn not in starts:
            raise ValueError(f'{fn:#x} has no FDE')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'spawn': {
            'vtable': hex(VTABLE),
            'vtable_entries': {'drop': hex(rel[VTABLE]), 'size': vt[0], 'align': vt[1], 'call': hex(rel[0x64b8b30])},
            'vtable_lea_sites': [hex(v) for v in found[VTABLE]],
            'name': STRINGS[0x93b0b6].decode(),
            'name_lea_sites': [hex(v) for v in found[0x93b0b6]],
            'spawner': 'slot 0x64e1750 -> %s (as #6011)' % hex(rel[0x64e1750]),
            'closure': 'one boxed 8-byte Arc pointer; body uses Arc payload +0x10',
        },
        'loop': {
            'fn': hex(LOOP),
            'fde_size': hex(starts[LOOP] - LOOP),
            'direct_calls_to_loop': len(found[LOOP]),
            'writer': '%s daily (slot 0x64e0f98) -> hourly (slot 0x64e0fa0)' % STRINGS[0x93b0d0].decode(),
            'per_tick': [
                'read %s(payload, %r)' % (hex(READ), STRINGS[0x93b0e1].decode()),
                'path 0x5942870(%r) -> value writer 0x50de010, unwrap at %s:%d:%d' % (
                    STRINGS[0x4564d0].decode(), loc[0].decode(), loc[1], loc[2]),
                'line writer %s(hourly writer, value)' % hex(LINE_WRITER),
                'clock_nanosleep(CLOCK_MONOTONIC, relative, 5 s); EINTR retries the remainder; '
                'other errors panic at std thread/unix.rs:%d:%d' % SLEEP_LOCATION[1:],
            ],
            'interval_seconds': 5,
        },
        'line_writer': {
            'fn': hex(LINE_WRITER),
            'record_serializer': '0x50e50b0 -> value serializer %s' % hex(COMPACT),
            'extra_flush': 'writer +0xaa and global byte 0x64ffe50 (as #5876)',
            'callers_of_line_writer': len(found[LINE_WRITER]),
            'callers_of_compact_serializer': len(found[COMPACT]),
        },
        'visor_state_fields': names,
        'fields_match_pretty_serializer': hex(PRETTY),
        'read_wrapper': {
            'fn': hex(READ),
            'direct_calls': len(found[READ]),
            'blocking_body': '0x4e47060 (edx = 1)',
            'counter_block': 'runner +0xb50 lock, +0xb60 last minute, +0xb68 count; '
                             'record via 0x51eaff0 (same block as 0x5647720, #6037)',
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
    print('vtable sites=%s interval=%ss' % (result['spawn']['vtable_lea_sites'], result['loop']['interval_seconds']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
