#!/usr/bin/env python3
"""Bind the node #115 info_server handler's sleep flag and its inner sleep future (25th stage).

Continues the info_server handler packet (24th stage). The handler 0x2e3ed10
polls an inner future at state+0x570 after the request timing, only when
bpl != 0 at 0x2e3fd51. This tool binds:

1. where bpl comes from: [rsp+0x10] <- state byte +0x520 <- r12b <- state
   byte +0x6b2 <- bpl <- state byte +0x6da (or 0 from `xor ebp, ebp`); the
   only direct store to +0x6da is a word store of 0 (0x2e3f7e2); the
   handler's state-dispatch jump tables send no entry into the flag-carrying
   spans;
2. the inner future 0x2d4f790 (resume panics at base/src/lu.rs:63:46): an
   f64 argument of 0.0 completes at once; any other value is polled through
   0x2d4f8b0;
3. 0x2d4f8b0 (resume panics at base/src/lu.rs:74:57): the f64 is converted to
   a Duration (negative, NaN or too large panics through the Location
   core/src/time.rs:962:23), slot 0x64e13a0 -> 0x5cf2150 builds a timer with
   the Location base/src/lu.rs:75:5, and slot 0x64e0858 -> 0x5cf2d30 polls it;
   0x5cf2d30 references tokio/src/time/sleep.rs:467:23;
4. the handler argument passed as rsi: r13 = rdx (third argument) at 0x2e3ed30,
   saved to [rsp+0x30].

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-info-user-ip-future-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

HANDLER = 0x2e3ed10
OUTER, INNER = 0x2d4f790, 0x2d4f8b0
TIMER_SLOT, TIMER = 0x64e13a0, 0x5cf2150
POLL_SLOT, POLL = 0x64e0858, 0x5cf2d30
PANIC_FMT_SLOT, PANIC_FMT = 0x64df6b8, 0x1680e80
LOC_OUTER, LOC_INNER, LOC_TIMER, LOC_TIME = 0x6451428, 0x6451470, 0x6451458, 0x644f678
LOC_STD_TIME, LOC_SLEEP = 0x64c4090, 0x64c6700
HANDLER_TABLES = {0x616438: 7, 0x616454: 4, 0x616464: 4, 0x616474: 4, 0x616488: 4, 0x616498: 4, 0x6164a8: 4}
OUTER_TABLE, INNER_TABLE = 0x6105f4, 0x610604
# spans that carry the flag in ebp, r12 or [rsp+0x10] (hand-checked: no write to that holder inside)
SPANS = ((0x2e3f805, 0x2e3f91e), (0x2e3f946, 0x2e3fa34), (0x2e3fa5f, 0x2e3fd51))
FLAG_BYTES = (0x6da, 0x6db, 0x6b2, 0x6b3, 0x520, 0x521)
SECONDS = 0x3f8cac083126e979

FIXED = {
    # handler: context argument
    0x2e3ed30: '4989d5',                # mov r13, rdx
    0x2e3ee5d: '4c896c2430',            # mov [rsp+0x30], r13
    # flag chain
    0x2e3f7e2: '66c783da0600000000',    # mov word [rbx+0x6da], 0
    0x2e3f7fe: 'c7042400000000',        # mov dword [rsp], 0
    0x2e3f805: '31ed',                  # xor ebp, ebp
    0x2e3ee64: '0fb6abda060000',        # movzx ebp, byte [rbx+0x6da]
    0x2e3ee72: '0fb683db060000',        # movzx eax, byte [rbx+0x6db]
    0x2e3ee79: '890424',                # mov [rsp], eax
    0x2e3ee7c: 'e986090000',            # jmp 0x2e3f807
    0x2e3f91e: '4088abb2060000',        # mov [rbx+0x6b2], bpl
    0x2e3f941: '4189ec',                # mov r12d, ebp
    0x2e3efc4: '440fb6a3b2060000',      # movzx r12d, byte [rbx+0x6b2]
    0x2e3efda: 'e967090000',            # jmp 0x2e3f946
    0x2e3fa34: '4489642410',            # mov [rsp+0x10], r12d
    0x2e3fa39: '4488a320050000',        # mov [rbx+0x520], r12b
    0x2e3f58b: '0fb68320050000',        # movzx eax, byte [rbx+0x520]
    0x2e3f592: '89442410',              # mov [rsp+0x10], eax
    0x2e3f59d: 'e9bd040000',            # jmp 0x2e3fa5f
    0x2e3fcc5: '8b6c2410',              # mov ebp, [rsp+0x10]
    0x2e3fd25: '8b6c2410',              # mov ebp, [rsp+0x10]
    0x2e3fd51: '4084ed',                # test bpl, bpl
    0x2e3fd54: '0f84b4010000',          # je 0x2e3ff0e (skip the inner future)
    0x2e3fd6f: '48b879e9263108ac8c3f',  # movabs rax, 0.014
    0x2e3fd79: '48898370050000',        # mov [rbx+0x570], rax
    0x2e3fd8a: '488b742430',            # mov rsi, [rsp+0x30]
    0x2e3fd8f: 'e8fcf9f0ff',            # call 0x2d4f790
    # outer future 0x2d4f790
    0x2d4f79a: '0fb68790000000',        # movzx eax, byte [rdi+0x90]   (state)
    0x2d4f7b1: 'f20f1003',              # movsd xmm0, [rbx]            (argument)
    0x2d4f7be: '660f2ec1',              # ucomisd xmm0, xmm1           (vs 0.0)
    0x2d4f7c2: '7507',                  # jne -> poll
    0x2d4f7c4: '7a05',                  # jp  -> poll
    0x2d4f7c6: '40b501',                # mov bpl, 1                   (returned)
    0x2d4f7cb: 'f20f114310',            # movsd [rbx+0x10], xmm0
    0x2d4f7de: 'e8cd000000',            # call 0x2d4f8b0
    # inner future 0x2d4f8b0
    0x2d4f8bd: '4989f6',                # mov r14, rsi
    0x2d4f8c3: '0fb64778',              # movzx eax, byte [rdi+0x78]   (state)
    0x2d4f8d7: 'f20f1003',              # movsd xmm0, [rbx]
    0x2d4f8e1: '660f2ec8',              # ucomisd xmm1, xmm0
    0x2d4f8e5: '0f875c020000',          # ja 0x2d4fb47                 (negative -> panic)
    0x2d4f992: '81fa00ca9a3b',          # cmp edx, 1000000000
    0x2d4fa11: '81fa00ca9a3b',          # cmp edx, 1000000000
    0x2d4fa22: '81ff3f040000',          # cmp edi, 0x43f
    0x2d4fa3b: '488d7c2420',            # lea rdi, [rsp+0x20]
    0x2d4facd: '4c89f6',                # mov rsi, r14                 (context)
    0x2d4fb45: 'b201',                  # mov dl, 1
    0x2d4fb47: '8854240f',              # mov [rsp+0xf], dl            (error kind)
}
REFERENCES = (
    (0x2d4f7a1, b'\x48\x8d\x0d', 7, OUTER_TABLE),
    (0x2d4f84e, b'\x48\x8d\x3d', 7, LOC_OUTER),
    (0x2d4f8c7, b'\x48\x8d\x0d', 7, INNER_TABLE),
    (0x2d4fa34, b'\x48\x8d\x0d', 7, LOC_TIMER),
    (0x2d4fa40, b'\xff\x15', 6, TIMER_SLOT),
    (0x2d4fad0, b'\xff\x15', 6, POLL_SLOT),
    (0x2d4fb2b, b'\x48\x8d\x3d', 7, LOC_INNER),
    (0x2d4fb38, b'\x48\x8d\x3d', 7, LOC_INNER),
    (0x2d4fb68, b'\x48\x8d\x15', 7, LOC_TIME),
    (0x2d4fb74, b'\xff\x15', 6, PANIC_FMT_SLOT),
)


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


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
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def location(data, rel, va):
    length, line, column = struct.unpack('<QII', read_va(data, va + 8, 16))
    return read_va(data, rel[va], length).decode(), line, column


def extent(fdes, va):
    for f in fdes:
        if f['start'] <= va < f['end']:
            return f['start'], f['end']
    raise ValueError(f'{va:#x} has no FDE')


def lea_refs(data, lo, hi, target):
    code = read_va(data, lo, hi - lo)
    out = []
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = m.start()
        if i + 7 <= len(code) and lo + i + 7 + struct.unpack_from('<i', code, i + 3)[0] == target:
            out.append(lo + i)
    return out


def jump_table(data, base, count):
    return [base + v for v in struct.unpack('<%di' % count, read_va(data, base, 4 * count))]


def flag_byte_census(data, lo, hi):
    """Every `[rbx+disp32]` operand (mod 10, rm 011) naming one of FLAG_BYTES, with the two bytes before ModRM."""
    code = read_va(data, lo, hi - lo)
    out = []
    for disp in FLAG_BYTES:
        for m in re.finditer(re.escape(struct.pack('<I', disp)), code):
            i = m.start() - 1
            if i >= 2 and (code[i] & 0xc7) == 0x83:
                out.append((lo + i, disp, code[i - 2:i].hex()))
    return sorted(out)


def rsp10_census(data, lo, hi):
    """Every `[rsp+0x10]` operand (mod 01, rm 100, SIB 0x24, disp8 0x10), with the two bytes before ModRM."""
    code = read_va(data, lo, hi - lo)
    out = []
    for m in re.finditer(rb'\x24\x10', code):
        i = m.start() - 1
        if i >= 2 and (code[i] & 0xc7) == 0x44:
            out.append((lo + i, code[i - 2:i].hex()))
    return out

STORE_OPCODES = ('66c7', '4088', '2488', '4488', '0088', '4889', '0089', '4489')
EXPECTED_FLAG_STORES = [('0x2e3f7e4', '0x6da', 'mov word [rbx+0x6da], 0'),
                        ('0x2e3f920', '0x6b2', 'mov [rbx+0x6b2], bpl'),
                        ('0x2e3f929', '0x6b3', 'mov [rbx+0x6b3], cl'),
                        ('0x2e3fa3b', '0x520', 'mov [rbx+0x520], r12b'),
                        ('0x2e3fa42', '0x521', 'mov [rbx+0x521], bpl')]


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in ((TIMER_SLOT, TIMER), (POLL_SLOT, POLL), (PANIC_FMT_SLOT, PANIC_FMT)):
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    seconds = struct.unpack('<d', read_va(data, 0x2e3fd71, 8))[0]
    if seconds != 0.014:
        raise ValueError('inner future argument changed')

    lo, hi = extent(fdes, HANDLER)
    stores = [(hex(va), hex(disp)) for va, disp, op in flag_byte_census(data, lo, hi) if op in STORE_OPCODES]
    if stores != [(a, b) for a, b, _ in EXPECTED_FLAG_STORES]:
        raise ValueError('flag byte store census changed')
    rsp10 = rsp10_census(data, lo, hi)
    span_writes = [hex(va) for va, op in rsp10 if op in STORE_OPCODES and any(s <= va < e for s, e in SPANS)]
    if span_writes:
        raise ValueError('a [rsp+0x10] store sits inside a flag span')
    tables = {hex(base): [hex(t) for t in jump_table(data, base, n)] for base, n in HANDLER_TABLES.items()}
    into_spans = [t for ts in tables.values() for t in ts if any(s <= int(t, 16) <= e for s, e in SPANS)]
    if into_spans:
        raise ValueError('a handler jump table entry lands inside a flag span')

    outer_lo, outer_hi = extent(fdes, OUTER)
    inner_lo, inner_hi = extent(fdes, INNER)
    timer_lo, timer_hi = extent(fdes, TIMER)
    poll_lo, poll_hi = extent(fdes, POLL)
    loc = {name: '%s:%d:%d' % location(data, rel, va) for name, va in
           (('outer', LOC_OUTER), ('inner', LOC_INNER), ('timer', LOC_TIMER), ('duration', LOC_TIME),
            ('std_time', LOC_STD_TIME), ('sleep', LOC_SLEEP))}
    if not loc['sleep'].endswith('tokio/src/time/sleep.rs:467:23'):
        raise ValueError('sleep Location changed')
    if (loc['outer'], loc['inner'], loc['timer']) != ('base/src/lu.rs:63:46', 'base/src/lu.rs:74:57',
                                                        'base/src/lu.rs:75:5'):
        raise ValueError('lu.rs Locations changed')
    if not loc['duration'].endswith('library/core/src/time.rs:962:23'):
        raise ValueError('Duration Location changed')
    refs = {
        'outer_in_outer': [hex(v) for v in lea_refs(data, outer_lo, outer_hi, LOC_OUTER)],
        'inner_in_inner': [hex(v) for v in lea_refs(data, inner_lo, inner_hi, LOC_INNER)],
        'std_time_in_timer': [hex(v) for v in lea_refs(data, timer_lo, timer_hi, LOC_STD_TIME)],
        'sleep_in_poll': [hex(v) for v in lea_refs(data, poll_lo, poll_hi, LOC_SLEEP)],
    }
    if not all(refs.values()):
        raise ValueError('Location reference census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'info-api',
        'flag': {
            'test': hex(0x2e3fd51) + ' test bpl, bpl; je 0x2e3ff0e skips the inner future',
            'chain': ['[rsp+0x10] -> ebp at 0x2e3fcc5 / 0x2e3fd25',
                      '[rsp+0x10] <- r12d at 0x2e3fa34 (and <- state +0x520 at 0x2e3f592 on resume)',
                      'state +0x520 <- r12b at 0x2e3fa39',
                      'r12d <- ebp at 0x2e3f941 (or <- state +0x6b2 at 0x2e3efc4 on resume)',
                      'state +0x6b2 <- bpl at 0x2e3f91e',
                      'ebp <- 0 at 0x2e3f805 (or <- state +0x6da at 0x2e3ee64 on resume)'],
            'flag_byte_stores': [s for _, _, s in EXPECTED_FLAG_STORES],
            'rsp10_operands': len(rsp10),
            'spans': [[hex(s), hex(e)] for s, e in SPANS],
            'jump_tables': tables,
        },
        'inner_future': {
            'argument': '%s f64 %r stored at state +0x570 (0x2e3fd79)' % (hex(SECONDS), seconds),
            'context': 'rsi = [rsp+0x30] = r13 = handler rdx (0x2e3ed30, saved 0x2e3ee5d)',
            'outer': {'fn': [hex(outer_lo), hex(outer_hi)], 'state': '+0x90',
                      'table': [hex(t) for t in jump_table(data, OUTER_TABLE, 4)],
                      'zero': 'argument == 0.0 -> state 1 (returned), ready',
                      'else': 'copy to +0x10, poll %s' % hex(INNER), 'location': loc['outer']},
            'inner': {'fn': [hex(inner_lo), hex(inner_hi)], 'state': '+0x78',
                      'table': [hex(t) for t in jump_table(data, INNER_TABLE, 4)],
                      'convert': 'f64 seconds -> (secs, nanos), nanos < 1e9; negative -> 0x2d4fb47, '
                                 'overflow or NaN -> 0x2d4fb45; panic via %s with %s'
                                 % (hex(PANIC_FMT), loc['duration']),
                      'timer': 'slot %s -> %s with Location %s; state +0x8..+0x78'
                               % (hex(TIMER_SLOT), hex(TIMER), loc['timer']),
                      'poll': 'slot %s -> %s (rdi = state+0x8, rsi = context)' % (hex(POLL_SLOT), hex(POLL)),
                      'location': loc['inner']},
            'timer_fn_location': loc['std_time'],
            'poll_fn_location': loc['sleep'],
            'location_refs': refs,
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
    print('flag_stores=%d sleep=%s' % (len(result['flag']['flag_byte_stores']),
                                       result['inner_future']['poll_fn_location']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
