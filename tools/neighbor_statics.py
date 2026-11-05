#!/usr/bin/env python3
"""RE-005: what are the three statics immediately before the
dispatcher vtable table (node 115)?

PR #3000 (dispatcher table) pinned the four-entry one-method
vtable table at 0x64004d0..0x6400550 and recorded, as a boundary
only, the three `lea` references to the statics that sit
immediately before it: cells 0x6400488 and 0x64004a0, lea'd at
0x1533e56 / 0x1533e5f inside the body at 0x1533d60, and cell
0x64004b8, lea'd at 0x15d5c49 inside the body at 0x15d5b00.
This packet identifies all three cells from the binary alone.

1. Cell 0x6400488 is not a Location and not a vtable entry. It
is a 0x18-byte static error-message datum of the shape std's
io error machinery uses for a statically allocated message:
{message: &str at +0x00, kind dword at +0x10, zero dword at
+0x14}. The &str is "failed to write whole buffer" (28 bytes
at 0x469219, pointer written by the cell's only relocation, an
R_X86_64_RELATIVE at +0x00), and the kind dword is 23. A
binary-wide census of every static of this exact shape whose
string is a sentence maps each distinct message to exactly
one dword, and the values calibrate against the std ErrorKind
declaration order (20 = the InvalidInput messages, 21 = the
InvalidData messages, 23 = both write messages, 37 = "failed
to fill whole buffer", 38 = "failed to allocate read buffer"),
so 23 is ErrorKind::WriteZero in this binary's std. The only
reference in the whole binary is the lea at 0x1533e56 inside a
277-byte buffered-write body (0x1533d60): when the underlying
libc `write` (GLOB_DAT slot 0x64dffc0) returns 0, the body
loads this cell's ADDRESS into rax and returns it, as one of
three pointer-sized results -- 0 for success, (errno << 32)|2
for an OS error (tag built at 0x1533e17/0x1533e1b, errno from
__errno_location, slot 0x64dffc8), and this cell's address for
the write-zero error. The body never dereferences the cell;
the address itself is the error value (its low bits are 0,
the tag the error-drop body 0x15be1a0 treats as the
nothing-to-free static-message variant).

2. Cell 0x64004a0 is a core::panic::Location static:
{file ptr at +0x00 (RELATIVE), file length 73 at +0x08,
line 1881 at +0x10, column 36 at +0x14} naming
library/std/src/io/mod.rs of the pinned rustc
(59807616e1fa2540724bfbac14d7976d7e4a3860). The same write
body lea's it at 0x1533e5f into rcx, the fourth argument of
the slice range-check helper 0x16817e0 (called through GOT
slot 0x64df570), on the guard path where the byte count
returned by `write` exceeds the buffer length; the helper
panics with the pieces string "range start index .. out of
range for slice of length .." and this Location.

3. Cell 0x64004b8 is a core::panic::Location static of the
same layout: file length 83, line 131, column 29, naming
library/std/src/thread/functions.rs. The body at 0x15d5b00 --
a 430-byte body that invokes spawn sibling 0x15b7a80 (the
entry-3 spawn body of PR #3000) directly at 0x15d5b51 -- lea's
it at 0x15d5c49 into r8, the last argument of a panic call
through GOT slot 0x64df6a0 to the panic-message thunk
0x1680c30 (the body PR #3000 pinned as panic_msg_thunk; its
sha256 here matches PR #3000's record exactly). The call's
message is the 22-byte string "failed to spawn thread" at
0x46925d, its value argument is the failed spawn result, and
its fourth argument (rcx) is the error value's own one-method
vtable at 0x64005f0 ({drop = 0x15be1a0, size 8, align 8,
method = 0x5ca5610}) -- a different static, past the table.

Family verdict: none of the three belongs to the dispatcher
table's closure family. The table entries are 0x20-byte
{drop, size, align, method} records whose pointer cells name
code bodies and which the four spawn siblings each lea once
to form a fat pointer. These three are 0x18-byte statics,
lea'd by two bodies that are not spawn siblings, and consumed
in incompatible ways: two only as &Location arguments to
panic machinery (the same kind as the lifecycle.rs Locations
PR #3000 pinned at 0x6400550 / 0x6400568, immediately after
the table), and one never dereferenced at all, returned by
address as an error value. A full census finds no other
reference to any of the three: no load, store, compare or
branch use, no relocation addend naming any of them, no raw
pointer stored in any allocated data section, no movabs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = (ROOT / 'research/work-items/'
          'RE-005-node115-neighbor-statics')

CELLS = (0x6400488, 0x64004a0, 0x64004b8)
CELLS_LO, CELLS_HI = 0x6400488, 0x64004d0
TABLE_LO, TABLE_HI = 0x64004d0, 0x6400550
WINDOW_LO, WINDOW_HI = 0x6400480, 0x6400578
ERROR_VTABLE = 0x64005f0

BODIES = {
 'error_drop': 0x15be1a0,
 'panic_msg_thunk': 0x1680c30,
 'range_check': 0x16817e0,
 'spawn_supervisor': 0x15d5b00,
 'write_body': 0x1533d60,
}

# PR #3000's records.json pins this body's sha256; this packet
# re-derives it and requires equality (cross-check, not a copy).
PR3000_PANIC_MSG_THUNK_SHA256 = (
 '2d00fd36dc6102ab0738e08907482bb818bca6e76e32a5b941eabf431f20767a')

# GOT / data slots resolved through the dynamic relocation table.
SLOTS = {
 0x64df4a0: ('relative', 0x635de30),   # deallocation entry
 0x64df508: ('glob', 'memcpy'),
 0x64df570: ('relative', 0x16817e0),   # slice range-check helper
 0x64df6a0: ('relative', 0x1680c30),   # panic-message thunk
 0x64dffc0: ('glob', 'write'),
 0x64dffc8: ('glob', '__errno_location'),
 0x64e0010: ('relative', 0x1533d60),   # cell holding write_body
 0x6401300: ('relative', 0x15d5b00),   # cell holding spawn_supervisor
}

PINS = {
 'write_body': [
  (0x50, 'ff1552b7fa04',
   'call through GLOB_DAT slot 0x64df508 (memcpy)'),
  (0x70, '4c8b2de9c1fa04',
   'load write fn from GLOB_DAT slot 0x64dffc0'),
  (0x8d, '41ffd5', 'call *r13: the loaded write fn'),
  (0xb7, '48c1e020', 'shl rax, 32: OS-error tag construction'),
  (0xbb, '4883c802', 'or rax, 2: OS-error tag bits'),
  (0xd7, 'e864a30800',
   'direct call to error_drop 0x15be1a0 (EINTR branch)'),
  (0xe1, '31c0', 'xor eax, eax: the null (success) result'),
  (0xf6, '488d052bc6ec04',
   'lea rax, cell 0x6400488: write-returns-0 error result'),
  (0xff, '488d0d3ac6ec04',
   'lea rcx, cell 0x64004a0: Location for the range-check helper'),
 ],
 'spawn_supervisor': [
  (0x51, 'e82a1ffeff',
   'direct call to spawn sibling 0x15b7a80 (table entry 3)'),
  (0x13b, '488d3d1b36e9fe',
   'lea rdi, "failed to spawn thread" message at 0x46925d'),
  (0x142, '488d0da7a9e204',
   'lea rcx, error-value vtable 0x64005f0'),
  (0x149, '4c8d0568a8e204',
   'lea r8, cell 0x64004b8: Location for the panic call'),
  (0x153, 'be16000000', 'mov esi, 0x16: message length 22'),
  (0x158, 'ff15429af004',
   'call through slot 0x64df6a0 to panic_msg_thunk'),
  (0x15e, '0f0b', 'ud2 after the panic call'),
 ],
 'range_check': [
  (0x8, '4839d7', 'cmp rdi, rdx: start index against length'),
  (0x34, '488d3d7a65dcfe',
   'lea rdi, "range start index .." pieces at 0x447d95'),
  (0x42, 'ff1590dee504',
   'call through slot 0x64df6b8 (panic formatting)'),
 ],
 'error_drop': [
  (0x8, '488b07', 'load the tagged error word from (rdi)'),
  (0xd, '83e103', 'and ecx, 3: the variant tag'),
  (0x84, 'ff257612f204',
   'tail-jump through slot 0x64df4a0 (dealloc)'),
 ],
 'panic_msg_thunk': [
  (0x0, '554889e5', 'push rbp; mov rbp, rsp: frame head'),
 ],
}

PIN_STARTS = {role: [BODIES[role] + rel for rel, _, _ in pins]
              for role, pins in PINS.items()}

STRINGS = {
 'write_zero_message': (0x469219, 28, 'failed to write whole buffer'),
 'spawn_message': (0x46925d, 22, 'failed to spawn thread'),
}

# The nine window references PR #3000 recorded; this packet's
# census over the same window must reproduce them exactly.
WINDOW_REFS = [
 ('0x1533e56', '0x6400488', 'lea', '0x1533d60'),
 ('0x1533e5f', '0x64004a0', 'lea', '0x1533d60'),
 ('0x15b7028', '0x64004d0', 'lea', '0x15b6d10'),
 ('0x15b76d0', '0x64004f0', 'lea', '0x15b73c0'),
 ('0x15b7d51', '0x6400510', 'lea', '0x15b7a80'),
 ('0x15b8436', '0x6400530', 'lea', '0x15b80e0'),
 ('0x15b88fe', '0x6400550', 'lea', '0x15b8810'),
 ('0x15b8912', '0x6400568', 'lea', '0x15b8810'),
 ('0x15d5c49', '0x64004b8', 'lea', '0x15d5b00'),
]

CELL_REFS = [r for r in WINDOW_REFS if r[1] in
             ('0x6400488', '0x64004a0', '0x64004b8')]

# Every distinct sentence-shaped message static of the
# {&str, kind_dword, 0} family in .data.rel.ro, with the dword
# the census must find. The values calibrate the ErrorKind
# discriminant: 20/21 are adjacent (InvalidInput/InvalidData),
# 23 follows TimedOut, 37/38 are the last adjacent pair
# (UnexpectedEof/OutOfMemory).
MESSAGE_KINDS = {
 'could not resolve to any addresses': 20,
 'file name contained an unexpected NUL byte': 20,
 'invalid argument': 20,
 'invalid stack size': 20,
 'nul byte found in provided data': 20,
 'the source path is neither a regular file nor a symlink '
 'to a regular file': 20,
 'invalid timestamp': 21,
 'stream did not contain valid UTF-8': 21,
 'failed to write the buffered data': 23,
 'failed to write whole buffer': 23,
 'failed to fill whole buffer': 37,
 'failed to allocate read buffer': 38,
}

LIMITATIONS = (
 'The two referencing bodies are described behaviourally; no '
 'source-level type name for either is pinned by this packet. '
 'The ErrorKind name WriteZero rests on the in-binary '
 'message-to-discriminant calibration recorded here plus the '
 'std declaration order, not on any symbol. Which std routine '
 'the write body monomorphises is not pinned. The method cell '
 'of the error-value vtable at 0x64005f0 is recorded, but that '
 'static is context for the spawn supervisor\'s panic call, '
 'not part of the question. Out of scope, as in PR #3000: '
 'the 0x3d0/0x2c40 argument layouts, the sv[1] writer '
 '(PR #2952), the wrapper-B registration cell (PR #2972) and '
 'the kind-1 Once cache (PR #2999).')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(data, va, n):
    for s in sections(data):
        if (s['type'] != 8 and s['address'] <= va
                and va + n <= s['address'] + s['size']):
            return data[s['offset'] + va - s['address']:
                        s['offset'] + va - s['address'] + n]
    raise ValueError(f'unmapped read at {va:#x}')


def raw_section_headers(data):
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize, count = struct.unpack_from('<HH', data, 58)
    rows = []
    for i in range(count):
        vals = struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * entsize)
        rows.append({'type': vals[1], 'address': vals[3],
                     'offset': vals[4], 'size': vals[5],
                     'link': vals[6], 'entsize': vals[9]})
    return rows


def relocations(data):
    """One pass over every SHT_RELA section.

    Keeps the full relocation map (offset -> entry) plus kind
    counts; 61,001 entries in this artifact.
    """
    headers = raw_section_headers(data)
    relmap = {}
    counts = {'relative': 0, 'glob_dat': 0, 'jump_slot': 0, 'total': 0}
    for s in headers:
        if s['type'] != 4 or not s['entsize']:
            continue
        dynsym = headers[s['link']]
        strtab = headers[dynsym['link']]
        for j in range(s['size'] // s['entsize']):
            r_off, r_info, r_add = struct.unpack_from(
                '<QQq', data, s['offset'] + j * s['entsize'])
            rtype = r_info & 0xffffffff
            counts['total'] += 1
            if rtype == 8:
                counts['relative'] += 1
            elif rtype == 6:
                counts['glob_dat'] += 1
            elif rtype == 7:
                counts['jump_slot'] += 1
            symbol = None
            if rtype in (6, 7):
                sym = r_info >> 32
                st_name = struct.unpack_from(
                    '<I', data, dynsym['offset'] + sym * dynsym['entsize'])[0]
                end = data.index(b'\0', strtab['offset'] + st_name)
                symbol = data[strtab['offset'] + st_name:end].decode()
            relmap[r_off] = {'type': rtype,
                             'addend': r_add & 0xffffffffffffffff,
                             'symbol': symbol}
    return {'map': relmap, 'counts': counts}


def slot_records(data, rel):
    out = []
    for slot in sorted(SLOTS):
        kind, want = SLOTS[slot]
        entry = rel['map'].get(slot)
        require(entry is not None, f'no relocation for slot {slot:#x}')
        if kind == 'relative':
            require(entry['type'] == 8 and entry['addend'] == want,
                    f'slot {slot:#x} is not RELATIVE to {want:#x}')
            out.append({'slot': hex(slot), 'kind': 'relative',
                        'target': hex(want)})
        else:
            require(entry['type'] in (6, 7) and entry['symbol'] == want,
                    f'slot {slot:#x} does not name {want}')
            out.append({'slot': hex(slot), 'kind': 'glob_dat',
                        'symbol': want})
    return out


def body_map(data):
    _, rows, _ = fde_extents(data)
    return {f['start']: f for f in rows}


def bodies(data, fdes):
    out = []
    for role in sorted(BODIES):
        start = BODIES[role]
        fde = fdes.get(start)
        require(fde is not None, f'{role} is not an FDE start')
        end = fde['end']
        blob = read(data, start, end - start)
        out.append({'role': role, 'start': hex(start), 'end': hex(end),
                    'bytes': end - start,
                    'sha256': hashlib.sha256(blob).hexdigest()})
    return out


def run_pins(data, role):
    start = BODIES[role]
    for rel, want, _ in PINS.get(role, []):
        got = read(data, start + rel, len(bytes.fromhex(want)))
        require(got.hex() == want,
                f'{role} pin at {start + rel:#x} changed')


def all_pins(data):
    out = []
    for role in sorted(PINS):
        run_pins(data, role)
        for rel, want, label in PINS[role]:
            out.append({'body': role, 'site': hex(BODIES[role] + rel),
                        'bytes': want, 'label': label})
    return out


def string_records(data):
    out = []
    for role in sorted(STRINGS):
        va, length, text = STRINGS[role]
        got = read(data, va, length)
        require(got == text.encode(),
                f'string {role} at {va:#x} changed')
        out.append({'role': role, 'address': hex(va),
                    'length': length, 'text': text})
    return out


def decode_str_cell(data, rel, va):
    """Decode one 0x18-byte {&str, u32, u32} static."""
    entry = rel['map'].get(va)
    require(entry is not None and entry['type'] == 8,
            f'cell {va:#x} has no RELATIVE relocation at +0x00')
    inside = [o for o in rel['map'] if va < o < va + 0x18]
    require(inside == [],
            f'cell {va:#x} has a relocation inside its tail')
    ptr = entry['addend']
    length, dword_a, dword_b = struct.unpack(
        '<QII', read(data, va + 8, 16))
    text = read(data, ptr, length).decode()
    return {'cell': hex(va), 'size': 0x18,
            'file_value_at_0x00': 0,
            'relocation_at_0x00': 'R_X86_64_RELATIVE',
            'str_pointer': hex(ptr), 'str_length': length,
            'dword_at_0x10': dword_a, 'dword_at_0x14': dword_b,
            'text': text}


def cell_records(data, rel):
    out = []
    c1 = decode_str_cell(data, rel, CELLS[0])
    require(c1['text'] == 'failed to write whole buffer'
            and c1['str_length'] == 28
            and c1['dword_at_0x10'] == 23
            and c1['dword_at_0x14'] == 0,
            'cell 0x6400488 decode changed')
    c1['kind'] = 'io_error_message'
    c1['error_kind'] = 'WriteZero (dword 23, calibrated below)'
    out.append(c1)
    for va, suffix, length, line, col in (
            (CELLS[1], '/library/std/src/io/mod.rs', 73, 1881, 36),
            (CELLS[2], '/library/std/src/thread/functions.rs',
             83, 131, 29)):
        rec = decode_str_cell(data, rel, va)
        require(rec['text'].endswith(suffix)
                and rec['str_length'] == length
                and rec['dword_at_0x10'] == line
                and rec['dword_at_0x14'] == col,
                f'Location decode changed at {va:#x}')
        rec['kind'] = 'panic_location'
        rec['file'] = rec.pop('text')
        rec['line'] = line
        rec['column'] = col
        out.append(rec)
    return out


def message_census(data, rel):
    """Every {.data.rel.ro} static of the shape {&str, a, 0}
    whose string is a sentence (length >= 10, contains a space,
    no '/'), grouped by string. Each string must map to exactly
    one dword; the twelve known pairs must all be present."""
    secs = sections(data)
    dr = next(s for s in secs if s['name'] == '.data.rel.ro')
    ro = next(s for s in secs if s['name'] == '.rodata')
    found = {}
    for off, entry in rel['map'].items():
        if entry['type'] != 8:
            continue
        if not (dr['address'] <= off < dr['address'] + dr['size']):
            continue
        if off % 8:
            continue
        ptr = entry['addend']
        if not (ro['address'] <= ptr < ro['address'] + ro['size']):
            continue
        length = struct.unpack('<Q', read(data, off + 8, 8))[0]
        if not (10 <= length <= 120):
            continue
        raw = read(data, ptr, length)
        try:
            text = raw.decode()
        except UnicodeDecodeError:
            continue
        if (' ' not in text or '/' in text
                or not all(32 <= ord(c) < 127 for c in text)):
            continue
        dword_a, dword_b = struct.unpack(
            '<II', read(data, off + 0x10, 8))
        if dword_b != 0 or dword_a == 0:
            continue
        found.setdefault(text, set()).add(dword_a)
    out = []
    for text in sorted(found):
        values = found[text]
        require(len(values) == 1,
                f'message {text!r} maps to several dwords')
        out.append({'message': text, 'kind_dword': values.pop()})
    got = {r['message']: r['kind_dword'] for r in out}
    require(got == MESSAGE_KINDS,
            'message-static census changed')
    return out


def error_vtable_record(data, rel, fdes):
    drop_e = rel['map'].get(ERROR_VTABLE)
    require(drop_e is not None and drop_e['type'] == 8,
            'error-value vtable drop cell has no RELATIVE relocation')
    size, align = struct.unpack(
        '<QQ', read(data, ERROR_VTABLE + 8, 16))
    meth_e = rel['map'].get(ERROR_VTABLE + 0x18)
    require(meth_e is not None and meth_e['type'] == 8,
            'error-value vtable method cell has no RELATIVE relocation')
    require(drop_e['addend'] == BODIES['error_drop'],
            'error-value vtable drop is not the error_drop body')
    require(size == 8 and align == 8,
            'error-value vtable size/align changed')
    require(meth_e['addend'] in fdes,
            'error-value vtable method is not an FDE start')
    return {'base': hex(ERROR_VTABLE),
            'drop_cell': hex(ERROR_VTABLE),
            'drop_in_place': hex(drop_e['addend']),
            'size_cell': hex(ERROR_VTABLE + 8), 'size': size,
            'align_cell': hex(ERROR_VTABLE + 0x10), 'align': align,
            'method_cell': hex(ERROR_VTABLE + 0x18),
            'method': hex(meth_e['addend'])}


def relro_record(data):
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', data, 54)
    for i in range(phnum):
        p_type, _, _, p_va, _, _, p_memsz, _ = struct.unpack_from(
            '<IIQQQQQQ', data, phoff + i * phentsize)
        if p_type == 0x6474e552:  # PT_GNU_RELRO
            require(p_va <= CELLS_LO and TABLE_HI <= p_va + p_memsz,
                    'PT_GNU_RELRO does not cover the cells and table')
            return {'start': hex(p_va), 'end': hex(p_va + p_memsz),
                    'covers_cells_and_table': True}
    raise ValueError('no PT_GNU_RELRO segment')


RIP_KINDS = {0x8d: 'lea', 0x8b: 'load', 0x89: 'store', 0x63: 'movsxd',
             0x3b: 'cmp', 0x85: 'test', 0x39: 'cmp', 0x01: 'add',
             0x03: 'add', 0x2b: 'sub', 0x31: 'xor', 0x33: 'xor',
             0xff: 'incdec/call/jmp', 0x8a: 'load8', 0x88: 'store8',
             0xc7: 'movimm', 0x80: 'grp1-8', 0x83: 'grp1-imm8',
             0x81: 'grp1-imm32', 0x38: 'cmp8', 0x3a: 'cmp8',
             0x84: 'test8', 0x00: 'add8', 0x02: 'add', 0x28: 'sub8',
             0x2a: 'sub', 0xfe: 'incdec8', 0xf6: 'grp3-8',
             0xf7: 'grp3', 0xc6: 'movimm8', 0x69: 'imul',
             0x6b: 'imul'}

RIP_OPS = (rb'\x8d|\x8b|\x89|\x63|\x3b|\x85|\x39|\x01|\x03|\x2b|'
           rb'\x31|\x33|\xff|\x8a|\x88|\xc7|\x80|\x83|\x81|\x38|'
           rb'\x3a|\x84|\x00|\x02|\x28|\x2a|\xfe|\xf6|\xf7|\xc6|'
           rb'\x69|\x6b')
RIP_MODRM = rb'\x05|\x0d|\x15|\x1d|\x25|\x2d|\x35|\x3d'


def _rip_refs(raw, tb, lo, hi, fdes, starts):
    import bisect
    import re

    def in_body(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0:
            f = fdes[starts[i]]
            if f['start'] <= va < f['end']:
                return hex(f['start'])
        return None

    refs = []
    pat = re.compile(rb'(\x48|\x49|\x4c|\x4d)(' + RIP_OPS
                     + rb')(' + RIP_MODRM + rb')')
    for m in pat.finditer(raw):
        disp = struct.unpack_from('<i', raw, m.start() + 3)[0]
        target = tb + m.start() + 7 + disp
        if lo <= target < hi:
            refs.append({'site': hex(tb + m.start()),
                         'target': hex(target),
                         'kind': RIP_KINDS[raw[m.start() + 1]],
                         'in_body': in_body(tb + m.start())})
    pat2 = re.compile(rb'(' + RIP_OPS + rb')(' + RIP_MODRM + rb')')
    for m in pat2.finditer(raw):
        if m.start() > 0 and raw[m.start() - 1] in b'\x48\x49\x4c\x4d':
            continue
        disp = struct.unpack_from('<i', raw, m.start() + 2)[0]
        target = tb + m.start() + 6 + disp
        if lo <= target < hi:
            refs.append({'site': hex(tb + m.start()),
                         'target': hex(target),
                         'kind': RIP_KINDS[raw[m.start()]],
                         'in_body': in_body(tb + m.start()),
                         'form': 'no_rex'})
    refs.sort(key=lambda r: int(r['site'], 16))
    return refs


def text_census(data, fdes):
    import re
    text = next(s for s in sections(data) if s['name'] == '.text')
    tb, tl = text['address'], text['size']
    raw = data[text['offset']:text['offset'] + tl]
    starts = sorted(fdes)

    cell_refs = _rip_refs(raw, tb, CELLS_LO, CELLS_HI, fdes, starts)
    got = [(r['site'], r['target'], r['kind'], r['in_body'])
           for r in cell_refs]
    require(got == [tuple(x) for x in CELL_REFS],
            'cell reference census changed')
    require(all('form' not in r for r in cell_refs),
            'a no-REX reference reaches the cells')

    window_refs = _rip_refs(raw, tb, WINDOW_LO, WINDOW_HI,
                            fdes, starts)
    got_w = [(r['site'], r['target'], r['kind'], r['in_body'])
             for r in window_refs]
    require(got_w == [tuple(x) for x in WINDOW_REFS],
            'window census no longer matches PR #3000')

    movabs = []
    for cell in CELLS:
        needle = struct.pack('<Q', cell)
        pos = 0
        while True:
            j = raw.find(needle, pos)
            if j < 0:
                break
            movabs.append({'cell': hex(cell),
                           'site': hex(tb + j)})
            pos = j + 1
    require(movabs == [], 'a movabs immediate names a cell')

    direct = {}
    for role in ('write_body', 'spawn_supervisor'):
        target = BODIES[role]
        hits = []
        for m in re.finditer(rb'[\xe8\xe9]....', raw):
            disp = struct.unpack_from('<i', raw, m.start() + 1)[0]
            if tb + m.start() + 5 + disp == target:
                hits.append(hex(tb + m.start()))
        require(hits == [], f'a direct rel32 branch reaches {role}')
        direct[role] = hits

    return {'rip_refs_to_cells': cell_refs,
            'rip_refs_in_window': window_refs,
            'movabs_immediates_to_cells': movabs,
            'direct_rel32_callers': direct,
            'stores_into_cells': []}


def data_census(data, rel):
    """Static pointers TO the cells: relocation addends and raw
    qwords in allocated data sections (relocation sections
    excluded by name -- their r_offset fields name the cells
    by construction)."""
    addend_hits = []
    for off, entry in rel['map'].items():
        if entry['type'] != 8:
            continue
        for cell in CELLS:
            if cell <= entry['addend'] < cell + 0x18:
                addend_hits.append({'at': hex(off),
                                    'addend': hex(entry['addend'])})
    require(addend_hits == [],
            'a relocation addend names one of the cells')
    raw_hits = []
    for s in sections(data):
        if s['type'] == 8 or not (s['flags'] & 0x2):
            continue
        if s['name'] == '.text' or s['name'].startswith('.rela'):
            continue
        blob = data[s['offset']:s['offset'] + s['size']]
        for i in range(0, len(blob) - 7, 8):
            v = struct.unpack_from('<Q', blob, i)[0]
            if v in CELLS:
                raw_hits.append({'section': s['name'],
                                 'at': hex(s['address'] + i)})
    require(raw_hits == [], 'a raw data qword names one of the cells')
    landing = sorted(hex(o) for o in rel['map']
                     if CELLS_LO <= o < CELLS_HI)
    require(landing == [hex(c) for c in CELLS],
            'relocations landing in the three cells changed')
    return {'relocation_addends_into_cells': addend_hits,
            'raw_qwords_naming_cells': raw_hits,
            'relocations_landing_in_cells': landing,
            'relocation_counts': rel['counts']}


def analyze(data):
    rel = relocations(data)
    fdes = body_map(data)
    census = text_census(data, fdes)
    thunk = next(b for b in bodies(data, fdes)
                 if b['role'] == 'panic_msg_thunk')
    require(thunk['sha256'] == PR3000_PANIC_MSG_THUNK_SHA256,
            'panic_msg_thunk hash differs from PR #3000')
    return {
        'artifact': {'path': 'artifacts/node/115/hl-node',
                     'size': SIZE, 'sha256': SHA},
        'bodies': bodies(data, fdes),
        'pins': all_pins(data),
        'slots': slot_records(data, rel),
        'cells': cell_records(data, rel),
        'message_census': message_census(data, rel),
        'error_value_vtable': error_vtable_record(data, rel, fdes),
        'relro': relro_record(data),
        'census': census,
        'data_census': data_census(data, rel),
        'strings': string_records(data),
        'cross_checks': {
            'pr3000_panic_msg_thunk_sha256': PR3000_PANIC_MSG_THUNK_SHA256,
            'panic_msg_thunk_matches_pr3000': True,
            'window_census_matches_pr3000': True},
        'answers': {
            'cell_0x6400488': 'a static io error-message datum: '
                              '{message &str "failed to write whole '
                              'buffer", kind dword 23 = ErrorKind::'
                              'WriteZero by the in-binary calibration, '
                              'zero tail dword}; the write body '
                              '0x1533d60 returns its bare address as '
                              'the error result when write(2) returns '
                              '0; never dereferenced by its only '
                              'referencer',
            'cell_0x64004a0': 'a core::panic::Location static for '
                              'std/src/io/mod.rs:1881:36, lea\'d by '
                              'the same write body into rcx as the '
                              'Location argument of the slice '
                              'range-check helper 0x16817e0',
            'cell_0x64004b8': 'a core::panic::Location static for '
                              'std/src/thread/functions.rs:131:29, '
                              'lea\'d by body 0x15d5b00 into r8 as '
                              'the Location argument of the panic '
                              'call to panic_msg_thunk 0x1680c30 on '
                              'the "failed to spawn thread" path',
            'family': 'none of the three belongs to the dispatcher '
                      'vtable table family: they are 0x18-byte '
                      'statics (one error-message datum, two panic '
                      'Locations), lea\'d once each by two bodies '
                      'that are not spawn siblings, against the '
                      'table\'s 0x20-byte {drop, size, align, '
                      'method} entries lea\'d by the spawn siblings',
        },
        'limitations': LIMITATIONS,
    }


def decode_export(asm, start, end, blob):
    import re
    starts, total = set(), 0
    for line in asm.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\t([0-9a-f ]+?)\t', line)
        if m:
            starts.add(int(m.group(1), 16))
            total += len(m.group(2).split())
    require(total == len(blob), 'objdump byte total mismatch')
    return starts


def exports(data):
    out = {}
    fdes = body_map(data)
    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / 'hl-node'
        snapshot.write_bytes(data)
        for role in sorted(BODIES):
            start = BODIES[role]
            end = fdes[start]['end']
            asm = subprocess.check_output(
                ['objdump', '-d', '-M', 'intel', '--insn-width=16',
                 f'--start-address={start:#x}',
                 f'--stop-address={end:#x}', str(snapshot)], text=True)
            ins = decode_export(asm, start, end,
                                read(data, start, end - start))
            for va in PIN_STARTS.get(role, []):
                require(va in ins, f'{role} instruction start missing')
            out[role] = asm.replace(str(snapshot),
                                    '<authenticated-node115>')
    return out


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('pinned node115 distribution changed')
    payload = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / 'hl-node'
        snapshot.write_bytes(data)
        native = subprocess.check_output(
            ['readelf', '-wf', str(snapshot)], text=True)
        fdes = body_map(data)
        wanted = []
        for role in sorted(BODIES):
            start = BODIES[role]
            end = fdes[start]['end']
            needle = f'pc={start:016x}..{end:016x}'
            wanted += [ln for ln in native.splitlines() if needle in ln]
        require(len(wanted) == len(BODIES), 'body frame lines missing')
        (output / 'frames.txt').write_text('\n'.join(wanted) + '\n')
        exps = exports(data)
        for role, asm in exps.items():
            (output / f'{role}.objdump.txt').write_bytes(
                asm.encode('utf-8'))
    (output / 'records.json').write_text(
        json.dumps(payload, indent=1, sort_keys=True) + '\n')
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('output', nargs='?', default=str(PACKET))
    args = parser.parse_args()
    payload = generate(TARGET, Path(args.output))
    for body in payload['bodies']:
        print(body['role'], body['start'], body['end'],
              body['bytes'], body['sha256'])


if __name__ == '__main__':
    main()
