#!/usr/bin/env python3
"""Bind the node #115 liner flush interval and flush gate (sixth stage).

Continues the observer packets for 0x1547530 (first to fifth stage). The fifth
stage found that every liner opened by 0x14c3b30 copies an f64 flush interval
from the lazily initialised global 0x64efce0 and that the gate 0x154ce40
flushes when a record's time passes a stored time plus that interval. This
tool binds:

1. the global 0x64efce0: a lazy cell whose value word holds the initializer
   0x14c4770 (R_X86_64_RELATIVE) and whose state dword is 3 at rest; its only
   reference is GOT slot 0x64e0030, loaded once (in the liner open); its
   only value store is the Once closure 0x14c3f80;
2. the initializer 0x14c4770: environment name `LINER_FLUSH_PERIOD`; an Err
   lookup gives 60.0; an Ok value is parsed as f64 and unwrapped (liner.rs
   17:74); the parsed value must be +-0, positive subnormal or positive
   normal, else an Option unwrap panics (liner.rs 17:84);
3. the gate 0x154ce40: an empty stored time flushes; otherwise the interval
   is converted by 0x15ed960, added to the stored time of day and date, and
   the line flushes only when the record time is strictly later than the
   result; a failed addition selects the far-future tuple 0x4679d0;
4. the observer's two writer states (+0x98, +0x148): the constructor
   0x1548bb0 stores both as None (first qword 0x8000000000000000), and the
   observer skips the path check and the write while a state is None.

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
PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-flush-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

OBSERVER = (0x1547530, 0x1548ba3)
CONSTRUCTOR = (0x1548bb0, 0x1548f3d)
OPEN = (0x14c3b30, 0x14c3c86)
INIT = (0x14c4770, 0x14c48cd)
ONCE_CLOSURE = (0x14c3f80, 0x14c3fb4)
GATE = (0x154ce40, 0x154cfe0)
SECONDS = (0x15ed960, 0x15edb81)
OPTION_PANIC = (0x1680c10, 0x1680c29)
PARSE_F64 = (0x16876b0, 0x1687c2a)
ENV_LOOKUP = (0x5c9a340, 0x5c9a529)
TIME_ADD = (0x162a9a0, 0x162ab02)
DATE_ADD = (0x16290d0, 0x16292fc)

GLOBAL = 0x64efce0
GLOBAL_SLOT = 0x64e0030
OPEN_SLOT = 0x64e0020
GATE_SLOT = 0x64e0008
ENV_SLOT = 0x64e0040
PARSE_SLOT = 0x64e0048
OPTION_PANIC_SLOT = 0x64df830
ONCE_CALL_SLOT = 0x64df9f0
ONCE_CALL = 0x5c87d50
SECONDS_SLOT = 0x64e0f70
TIME_ADD_SLOT = 0x64e0f78
DATE_ADD_SLOT = 0x64e0aa0
SINK_SLOT = 0x64e0f80
MEMCPY_SLOT = 0x64df508
ONCE_VTABLE = 0x63f8d30
ENV_NAME = (0x464990, b'LINER_FLUSH_PERIOD')
DEFAULT = 0x459718
RESULT_UNWRAP = (0x4649ca, b'called `Result::unwrap()` on an `Err` value')
OPTION_UNWRAP = (0x46e992, b'called `Option::unwrap()` on a `None` value')
LOC_PARSE = 0x63f8de0
LOC_CHECK = 0x63f8df8
LOC_ONCE = 0x63f8d58
FALLBACK = 0x4679d0
NONE = 0x8000000000000000
MODRM_RIP = re.compile(rb'[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')

FIXED = {
    # liner open: lazy read of the global, value copied to liner +0x38, stored date cleared
    0x14c3b74: '418b4508',              # mov eax, [r13+8]             (state dword)
    0x14c3b78: '85c0',                  # test eax, eax
    0x14c3b7a: '7574',                  # jne 0x14c3bf0                (not complete -> Once)
    0x14c3b7c: 'f2410f104500',          # movsd xmm0, [r13]            (value)
    0x14c3ba8: 'f2410f114738',          # movsd [r15+0x38], xmm0
    0x14c3bae: '41c7474000000000',      # mov dword [r15+0x40], 0
    0x14c3bff: '498d7d08',              # lea rdi, [r13+8]             (Once state)
    0x14c3c16: 'be01000000',            # mov esi, 1
    # Once closure: take the initializer, call it, store the f64 over it
    0x14c3f81: '488b07',                # mov rax, [rdi]
    0x14c3f84: '488b18',                # mov rbx, [rax]
    0x14c3f87: '48c70000000000',        # mov qword [rax], 0
    0x14c3f93: '807e0401',              # cmp byte [rsi+4], 1           (poisoned)
    0x14c3f99: 'ff13',                  # call [rbx]                    (initializer)
    0x14c3f9b: 'f20f1103',              # movsd [rbx], xmm0             (value store)
    # initializer
    0x14c4785: 'ba12000000',            # mov edx, 0x12                 (name length)
    0x14c4795: '807c242000',            # cmp byte [rsp+0x20], 0        (Ok tag)
    0x14c479a: '742e',                  # je 0x14c47ca                  (Ok -> parse)
    0x14c47e2: '807c241001',            # cmp byte [rsp+0x10], 1        (parse Err)
    0x14c47e7: '0f8492000000',          # je 0x14c487f                  (unwrap panic)
    0x14c47f8: '488d48ff',              # lea rcx, [rax-1]
    0x14c47fc: '48baffffffffffff0f00',  # movabs rdx, 0xfffffffffffff
    0x14c4809: '0f92c1',                # setb cl                       (positive subnormal)
    0x14c480c: '48baffffffffffffff7f',  # movabs rdx, 0x7fffffffffffffff
    0x14c4819: '400f94c6',              # sete sil                      (+-0)
    0x14c4820: '48b9000000000000f0ff',  # movabs rcx, 0xfff0000000000000
    0x14c482d: '48c1e935',              # shr rcx, 0x35
    0x14c4831: '81f9ff030000',          # cmp ecx, 0x3ff
    0x14c4837: '0f92c1',                # setb cl                       (normal)
    0x14c483a: '4885c0',                # test rax, rax
    0x14c483d: '0f99c0',                # setns al                      (sign clear)
    0x14c4845: '7429',                  # je 0x14c4870                  (reject -> panic)
    0x14c48a2: 'be2b000000',            # mov esi, 0x2b
    # gate
    0x154ce54: '8b6f08',                # mov ebp, [rdi+8]              (stored date)
    0x154ce57: '85ed',                  # test ebp, ebp
    0x154ce59: '0f845f010000',          # je 0x154cfbe                  (empty -> flush)
    0x154ce72: 'f20f1003',              # movsd xmm0, [rbx]             (interval)
    0x154ce90: 'b900ca9a3b',            # mov ecx, 1000000000
    0x154cea4: '48b8ffffffffffffff7f',  # movabs rax, i64::MAX          (saturate nanos)
    0x154ceb1: '480f43c8',              # cmovae rcx, rax
    0x154ceb8: '480f45c8',              # cmovne rcx, rax
    0x154cebc: '48bab394d626e80b2e11',  # movabs rdx, 0x112e0be826d694b3 (/1e9)
    0x154cecc: '48c1ea1a',              # shr rdx, 0x1a
    0x154cf08: '7674',                  # jbe 0x154cf7e                 (range -> fallback)
    0x154cf24: '7258',                  # jb 0x154cf7e                  (range -> fallback)
    0x154cf33: '48b9572951cea0c84518',  # movabs rcx, 0x1845c8a0ce512957 (/86400)
    0x154cf47: '48c1ea0d',              # shr rdx, 0xd
    0x154cf55: '85c0',                  # test eax, eax
    0x154cf57: '7425',                  # je 0x154cf7e                  (date add failed)
    0x154cf74: '45392f',                # cmp [r15], r13d               (deadline date vs record)
    0x154cf77: '0f9cc2',                # setl dl
    0x154cf7e: 'c744241800000000',      # mov dword [rsp+0x18], 0
    0x154cf9b: '45392f',                # cmp [r15], r13d
    0x154cfa7: '3911',                  # cmp [rcx], edx                (seconds)
    0x154cfa9: '0f92c2',                # setb dl
    0x154cfb2: '3908',                  # cmp [rax], ecx                (fraction)
    0x154cfb4: '7208',                  # jb 0x154cfbe                  (later -> flush)
    0x154cfb6: '31c0',                  # xor eax, eax                  (no flush)
    0x154cfbe: '4883c308',              # add rbx, 8
    0x154cfc6: '894308',                # mov [rbx+8], eax              (store record time)
    0x154cfcc: '488903',                # mov [rbx], rax
    0x154cfcf: 'b001',                  # mov al, 1                     (flush)
    # seconds conversion: x >= 0 (or NaN) takes the bit-decode path
    0x15ed964: '660f2ec8',              # ucomisd xmm1, xmm0
    0x15ed968: '0f86cb000000',          # jbe 0x15eda39
    0x15eda4d: '81f9e0030000',          # cmp ecx, 0x3e0
    0x15edae7: '81ff33040000',          # cmp edi, 0x433
    0x15edb6e: '81ff3f040000',          # cmp edi, 0x43f
    0x15edb74: '0f83f4fdffff',          # jae 0x15ed96e                 (>= 2^64 -> saturating path)
    # constructor: two writer states start as None
    0x1548bdd: '48b80000000000000080',  # movabs rax, 0x8000000000000000
    0x1548be7: '4889442428',            # mov [rsp+0x28], rax
    0x1548bec: '48898424d8000000',      # mov [rsp+0xd8], rax
    0x1548c96: 'bab0000000',            # mov edx, 0xb0
    0x1548da1: '498dbe98000000',        # lea rdi, [r14+0x98]
    0x1548da8: '488d742428',            # lea rsi, [rsp+0x28]
    0x1548dad: 'bab0000000',            # mov edx, 0xb0
    0x1548db2: '41ffd4',                # call r12                      (memcpy)
    0x1548db5: '498dbe48010000',        # lea rdi, [r14+0x148]
    0x1548dbc: '488db424d8000000',      # lea rsi, [rsp+0xd8]
    0x1548dc4: 'bab0000000',            # mov edx, 0xb0
    0x1548dc9: '41ffd4',                # call r12
    # observer: None state skips (0 - i64::MIN overflows)
    0x1547c02: '31c0',                  # xor eax, eax
    0x1547c04: '483b8348010000',        # cmp rax, [rbx+0x148]
    0x154887b: '31c0',                  # xor eax, eax
    0x154887d: '483b8398000000',        # cmp rax, [rbx+0x98]
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x14c3b6d, b'\x4c\x8b\x2d', 7, GLOBAL_SLOT),
    (0x14c3c03, b'\x48\x8d\x0d', 7, ONCE_VTABLE),
    (0x14c3c0a, b'\x4c\x8d\x05', 7, LOC_ONCE),
    (0x14c3c1b, b'\xff\x15', 6, ONCE_CALL_SLOT),
    (0x14c3c21, b'\xe9', 5, 0x14c3b7c),
    (0x14c4779, b'\x48\x8d\x35', 7, ENV_NAME[0]),
    (0x14c478a, b'\xff\x15', 6, ENV_SLOT),
    (0x14c479c, b'\xf3\x0f\x7e\x05', 8, DEFAULT),
    (0x14c47bd, b'\xf3\x0f\x7e\x05', 8, DEFAULT),
    (0x14c47dc, b'\xff\x15', 6, PARSE_SLOT),
    (0x14c4870, b'\x48\x8d\x3d', 7, LOC_CHECK),
    (0x14c4877, b'\xff\x15', 6, OPTION_PANIC_SLOT),
    (0x14c4888, b'\x48\x8d\x3d', 7, RESULT_UNWRAP[0]),
    (0x14c4896, b'\x4c\x8d\x05', 7, LOC_PARSE),
    (0x1680c17, b'\x48\x8d\x3d', 7, OPTION_UNWRAP[0]),
    (0x154ce88, b'\xff\x15', 6, SECONDS_SLOT),
    (0x154cee3, b'\xff\x15', 6, TIME_ADD_SLOT),
    (0x154cf4f, b'\xff\x15', 6, DATE_ADD_SLOT),
    (0x154cf86, b'\x4c\x8d\x3d', 7, FALLBACK),
    (0x15488a3, b'\xff\x15', 6, SINK_SLOT),
    (0x1547c37, b'\xff\x15', 6, SINK_SLOT),
    (0x1548884, b'\x0f\x80', 6, 0x1548657),
    (0x1547c15, b'\x0f\x80', 6, 0x1547f47),
    (0x1548c8f, b'\x4c\x8b\x25', 7, MEMCPY_SLOT),
)
SLOTS = {GLOBAL_SLOT: GLOBAL, GLOBAL: INIT[0], OPEN_SLOT: OPEN[0], GATE_SLOT: GATE[0],
         ENV_SLOT: ENV_LOOKUP[0], PARSE_SLOT: PARSE_F64[0], OPTION_PANIC_SLOT: OPTION_PANIC[0],
         ONCE_CALL_SLOT: ONCE_CALL, SECONDS_SLOT: SECONDS[0], TIME_ADD_SLOT: TIME_ADD[0],
         DATE_ADD_SLOT: DATE_ADD[0], ONCE_VTABLE + 0x18: ONCE_CLOSURE[0], 0x64e1020: CONSTRUCTOR[0]}
LOCATIONS = {LOC_PARSE: (b'base/src/liner.rs', 17, 74), LOC_CHECK: (b'base/src/liner.rs', 17, 84)}


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return off, data[off:off + size]


def rip_target(data, va, prefix, length):
    _, raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    width = length - len(prefix)
    disp = struct.unpack_from('<b' if width == 1 else '<i', raw, len(prefix))[0]
    return va + length + disp


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2)[1] != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def relocations(data):
    """R_X86_64_RELATIVE addends and GLOB_DAT symbol indexes by slot."""
    rel, glob = {}, {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
            elif info & 0xffffffff == 6:
                glob[va] = info >> 32
    return rel, glob


def dynamic_symbol_name(data, index):
    secs = sections(data)
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynstr = next(s for s in secs if s['name'] == '.dynstr')
    name_off = struct.unpack_from('<I', data, dynsym['offset'] + 24 * index)[0]
    start = dynstr['offset'] + name_off
    return data[start:data.index(b'\0', start)]


def frame(fdes, va):
    rows = [(f['start'], f['end']) for f in fdes if f['start'] <= va < f['end']]
    if len(rows) != 1:
        raise ValueError(f'expected one FDE at {va:#x}')
    return rows[0]


def text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec['address'], data[sec['offset']:sec['offset'] + sec['size']]


def rip_refs(data, lo, hi):
    """Instructions in .text with a mod=00 rm=101 (rip-relative) ModRM whose
    disp32 resolves into [lo, hi), for no immediate, imm8 or imm32 tails.
    Returns the ModRM addresses."""
    base, raw = text(data)
    out = set()
    unpack = struct.unpack_from
    for match in MODRM_RIP.finditer(raw):
        index = match.start() + 1
        if index + 4 > len(raw):
            continue
        end = base + index + 4 + unpack('<i', raw, index)[0]
        if lo <= end < hi or lo <= end + 1 < hi or lo <= end + 4 < hi:
            out.add(base + index - 1)
    return sorted(out)


def slot_calls(data, slot):
    """FF 15 rel32 calls in .text through a GOT slot."""
    base, raw = text(data)
    out, start = [], 0
    while True:
        index = raw.find(b'\xff\x15', start)
        if index < 0 or index + 6 > len(raw):
            return out
        start = index + 1
        if base + index + 6 + struct.unpack_from('<i', raw, index + 2)[0] == slot:
            out.append(base + index)


def state_copies(data):
    """lea rdi, [reg+0x98] (disp32, not rsp) followed within 24 bytes by
    mov edx, 0xb0: an 0xb0-byte copy into an object's +0x98."""
    base, raw = text(data)
    out = []
    for rex in (b'\x48', b'\x49'):
        start = 0
        while True:
            index = raw.find(rex + b'\x8d', start)
            if index < 0:
                break
            start = index + 1
            modrm = raw[index + 2] if index + 2 < len(raw) else 0
            if modrm & 0xf8 != 0xb8 or modrm & 7 == 4:
                continue
            if raw[index + 3:index + 7] != b'\x98\x00\x00\x00':
                continue
            if b'\xba\xb0\x00\x00\x00' in raw[index + 7:index + 31]:
                out.append(base + index)
    return sorted(out)


def location(data, va):
    _, raw = read_va(data, va, 24)
    rel, _ = relocations(data)
    if va not in rel:
        raise ValueError(f'Location {va:#x} has no file pointer')
    length, line, column = struct.unpack_from('<QII', raw, 8)
    return read_va(data, rel[va], length)[1], line, column


def accepted(value):
    """The initializer's check at 0x14c47f8..0x14c4845, as written."""
    bits = struct.unpack('<Q', struct.pack('<d', value))[0]
    subnormal = (bits - 1) % (1 << 64) < 0xfffffffffffff
    zero = bits & 0x7fffffffffffffff == 0
    normal = ((bits & 0x7fffffffffffffff) + 0xfff0000000000000) % (1 << 64) >> 0x35 < 0x3ff
    return bool((bits >> 63 == 0 and normal) or zero or subnormal)


def bind(data, fdes):
    rel, glob = relocations(data)
    for slot, target in SLOTS.items():
        if rel.get(slot) != target:
            raise ValueError(f'slot {slot:#x} changed')
    if MEMCPY_SLOT not in glob or dynamic_symbol_name(data, glob[MEMCPY_SLOT]) != b'memcpy':
        raise ValueError('memcpy slot changed')
    for span in (OBSERVER, CONSTRUCTOR, OPEN, INIT, ONCE_CLOSURE, GATE, SECONDS, OPTION_PANIC, PARSE_F64,
                 ENV_LOOKUP, TIME_ADD, DATE_ADD):
        if frame(fdes, span[0]) != span:
            raise ValueError(f'FDE at {span[0]:#x} changed')
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, expect in REFERENCES:
        if rip_target(data, va, prefix, length) != expect:
            raise ValueError(f'reference at {va:#x} changed')
    for va, text_ in (ENV_NAME, RESULT_UNWRAP, OPTION_UNWRAP):
        if read_va(data, va, len(text_))[1] != text_:
            raise ValueError(f'string at {va:#x} changed')
    if read_va(data, 0x14c4785, 5)[1][1] != len(ENV_NAME[1]) or read_va(data, 0x14c48a2, 5)[1][1] != len(RESULT_UNWRAP[1]):
        raise ValueError('string length changed')
    default = struct.unpack('<d', read_va(data, DEFAULT, 8)[1])[0]
    if default != 60.0:
        raise ValueError('default interval changed')
    for va, expect in LOCATIONS.items():
        if location(data, va) != expect:
            raise ValueError(f'Location {va:#x} changed')

    # The global: value word (initializer pointer until init) and state dword.
    _, cell = read_va(data, GLOBAL, 16)
    value_word, state, pad = struct.unpack('<QII', cell)
    if value_word != 0 or state != 3:
        raise ValueError('global at rest changed')
    cell_relocs = sorted(va for va, addend in rel.items() if GLOBAL <= addend < GLOBAL + 16)
    cell_text_refs = rip_refs(data, GLOBAL, GLOBAL + 16)
    slot_text_refs = rip_refs(data, GLOBAL_SLOT, GLOBAL_SLOT + 8)
    if cell_relocs != [GLOBAL_SLOT] or cell_text_refs or slot_text_refs != [0x14c3b6f]:
        raise ValueError('global reference census changed')
    vtable_refs = rip_refs(data, ONCE_VTABLE, ONCE_VTABLE + 0x28)
    if vtable_refs != [0x14c3c05]:
        raise ValueError('Once vtable reference census changed')

    # Magic divisors.
    if 0x112e0be826d694b3 != -(-(1 << 90) // 10**9) or 0x1845c8a0ce512957 != -(-(1 << 77) // 86400):
        raise ValueError('divisor constants changed')
    date, secs, frac = struct.unpack('<III', read_va(data, FALLBACK, 12)[1])
    if (secs, frac) != (86399, 999999999):
        raise ValueError('fallback tuple changed')

    open_calls = slot_calls(data, OPEN_SLOT)
    gate_calls = slot_calls(data, GATE_SLOT)
    copies = state_copies(data)
    if 0x14c383f not in gate_calls or 0x154891f not in open_calls or 0x1547cc7 not in open_calls:
        raise ValueError('call census changed')
    if copies != [0x1548da1]:
        raise ValueError('state copy census changed')
    constructor_calls = slot_calls(data, 0x64e1020)

    samples = {'0.0': 0.0, '-0.0': -0.0, '5e-324': 5e-324, '60.0': 60.0, '1e300': 1e300,
               '-1.0': -1.0, '-5e-324': -5e-324, 'inf': float('inf'), 'nan': float('nan')}
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'interval_global': {
            'cell': hex(GLOBAL),
            'value_word': '+0x0: R_X86_64_RELATIVE -> initializer %s until init, then the f64' % hex(INIT[0]),
            'state_dword_at_rest': '+0x8 = %d (open takes the Once path when not 0)' % state,
            'relocations_into_cell': [hex(v) for v in cell_relocs],
            'rip_relative_refs_to_cell': len(cell_text_refs),
            'slot_loads': [hex(v) for v in slot_text_refs],
            'reader': hex(0x14c3b7c) + ' movsd xmm0, [r13] in the liner open; stored at liner +0x38',
            'writer': hex(0x14c3f9b) + ' movsd [rbx], xmm0 in Once closure ' + hex(ONCE_CLOSURE[0])
                      + ' (vtable %s +0x18, built only at %s)' % (hex(ONCE_VTABLE), hex(0x14c3c03)),
            'open_slot_calls': len(open_calls),
        },
        'initializer': {
            'fde': [hex(v) for v in INIT],
            'env_name': ENV_NAME[1].decode(),
            'lookup': 'slot %s -> %s; Err (tag byte != 0) -> %s' % (hex(ENV_SLOT), hex(ENV_LOOKUP[0]), default),
            'parse': 'slot %s -> %s; Err -> Result::unwrap panic at %s:%d:%d'
                     % ((hex(PARSE_SLOT), hex(PARSE_F64[0])) + tuple(
                         [location(data, LOC_PARSE)[0].decode()] + list(location(data, LOC_PARSE)[1:]))),
            'check': 'accept +-0, positive subnormal, positive normal; else Option::unwrap panic at %s:%d:%d'
                     % ((location(data, LOC_CHECK)[0].decode(),) + location(data, LOC_CHECK)[1:]),
            'check_samples': {k: accepted(v) for k, v in samples.items()},
        },
        'gate': {
            'fde': [hex(v) for v in GATE],
            'calls': len(gate_calls),
            'state': 'liner +0x38: f64 interval; +0x40 stored date (0 = empty), +0x44 seconds, +0x48 fraction',
            'empty': 'stored date 0 -> flush',
            'interval': 'slot %s -> %s (secs, nanos); nanos = secs*1e9 + nanos saturated to i64::MAX; '
                        'split again by 1e9' % (hex(SECONDS_SLOT), hex(SECONDS[0])),
            'deadline': 'slot %s -> %s (stored time of day + interval, overflow seconds); two range checks; '
                        'days = overflow / 86400; slot %s -> %s (stored date + days, 0 = failed)'
                        % (hex(TIME_ADD_SLOT), hex(TIME_ADD[0]), hex(DATE_ADD_SLOT), hex(DATE_ADD[0])),
            'fallback': '%s = (%s, %d, %d) when a range check or the date addition fails'
                        % (hex(FALLBACK), hex(date), secs, frac),
            'flush_when': 'deadline < record time, comparing date (signed), then seconds, then fraction',
            'on_flush': 'store the record time at +0x40..+0x4c, return 1',
        },
        'seconds_conversion': {
            'fde': [hex(v) for v in SECONDS],
            'paths': 'x >= 0 or NaN: bit decode (exponent < 0x3e0 -> 0; < 0x3ff fraction only; < 0x433 '
                     'seconds and fraction; < 0x43f seconds only; else the saturating microsecond path); '
                     'x < 0: saturating microsecond path',
        },
        'observer_writer_states': {
            'constructor': hex(CONSTRUCTOR[0]),
            'constructor_slot_calls': len(constructor_calls),
            'initial': 'rsp+0x28 and rsp+0xd8 first qword %s (None), copied 0xb0 bytes to +0x98 and +0x148'
                       % hex(NONE),
            'skip': {'+0x98': hex(0x1548884) + ' jo 0x1548657', '+0x148': hex(0x1547c15) + ' jo 0x1547f47'},
            'object_0xb0_copies_into_plus_0x98': [hex(v) for v in copies],
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
    print(f"open_calls={result['interval_global']['open_slot_calls']} gate_calls={result['gate']['calls']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
