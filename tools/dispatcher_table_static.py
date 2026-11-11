#!/usr/bin/env python3
"""RE-005: who registers the wrapper-A adapter in its static table,
what the dispatcher walks, and who calls the dispatcher (node 115).

PR #2969 (RE-005 builder wrapper identities) pinned the 67-byte
adapter A (0x155fa10) for the base/src/lu.rs runner (wrapper A,
0x15d6fd0): the adapter has no direct callers and is called once,
through GOT slot 0x64e1190, by a 498-byte dispatcher (0x15b8fd0)
whose address is recorded in a static .data.rel.ro table cell
(0x6400548). That packet left three ends open. This packet closes
them, from the binary alone.

1. Who registers the adapter. Nobody does, at run time. The cell
0x6400548 is the method slot (+0x18) of one entry of a four-entry
static table of one-method trait-object vtables in .data.rel.ro
(bases 0x64004d0, 0x64004f0, 0x6400510, 0x6400530; each entry is
{drop_in_place, size, align = 8, method}). The whole table sits
inside PT_GNU_RELRO (0x63f2ba0..0x64ef000), so it is read-only
after relocation. Every pointer cell of the table is written by
exactly one R_X86_64_RELATIVE relocation at link time; the
relocation whose addend is the dispatcher (0x15b8fd0) targets
cell 0x6400548 and no other cell. A full .text census finds no
store into the table's range, no reference to the method cell
itself, and exactly one reference to each vtable base: a single
lea inside one of four sibling spawn bodies (0x15b6d10,
0x15b73c0, 0x15b7a80, 0x15b80e0). The .init_array holds 168
entries and none of them is any body pinned here. The registrar
is therefore the compiler/linker pair that emitted the vtable
when a spawn body coerced its closure to a fat pointer; there is
no run-time registration path to audit.

2. What the dispatcher walks. No list. Per call the dispatcher
(0x15b8fd0..0x15b91c2) invokes adapter_0 (0x155f9e0, through GOT
slot 0x64e1318 at 0x15b9054) on a copy of self+0x00..0x20, then
adapter A (through slot 0x64e1190 at 0x15b907d) on a copy of
self+0x28..0x58, then drains ONE shared packet cell: the pointer
at self+0x20. When the packet's state qword at +0x18 is nonzero
it enters the drain block at 0x15b9091 -- whose only in-body
branch sources are the fall-through of the state test at
0x15b908a and the unwind landing pad's jne at 0x15b91b7 -- loads
the single fat pointer stored in the packet ({data at +0x20,
vtable at +0x28}), calls the vtable's drop slot on the data when
non-null, deallocates the data with the vtable's size/align when
the size is nonzero, writes state 1 at +0x18, writes 0 to +0x20
(r14 was zeroed at 0x15b9083) and the caller-side r15 value to
+0x28, then decrements the packet strong count at +0x00 and
calls the weak-release glue (slot 0x64dfe60) when it reaches
zero. No packet field is ever followed as a next pointer: the
"list" the earlier packet described is this single-cell drain,
and the only list-shaped object in the neighbourhood is the
static four-entry vtable table itself, each entry used by
exactly one spawn body.

3. Who calls the dispatcher. No code does, directly: the census
of direct rel32 call/jump targets over the whole .text contains
zero hits for 0x15b8fd0, and the only pointer to it anywhere is
the table cell. The call path is the operating system's new
thread. Spawn body 0x15b80e0 -- the sibling whose vtable entry
carries the dispatcher -- reads the RUST_MIN_STACK name built
from immediates (lookup through slot 0x64e0a30 at 0x15b8179,
length 0xf), defaults the stack to 0x200000, allocates the
0x58-byte closure object (the vtable entry's size) and a
0x18-byte package {thread Arc at +0x00, closure data at +0x08,
vtable base 0x6400530 at +0x10, stored at 0x15b8461}, and hands
(stack size, package) to the thread-create body 0x5c87b50
through GOT slot 0x64e1580 (call at 0x15b8476). That body sets
up pthread attributes (pthread_attr_init / setstacksize through
GLOB_DAT slots) and calls pthread_create (GLOB_DAT slot
0x64ec838, call at 0x5c87c2b) with the start routine 0x5ca44a0
(loaded by the lea at 0x5c87c19). The start routine unpacks the
package -- closure data from +0x08 (0x5ca45a2), vtable from
+0x10 (0x5ca45a6) -- frees the package, and calls the vtable's
method slot: call *0x18(%r15) at 0x5ca45d7, which is the
dispatcher for this entry. The mirror body 0x15b8810 joins the
thread: pthread_join through slot 0x64e1590 (call at 0x15b8824),
then it reads the same packet's result fat pointer at +0x20 /
+0x28 under the flag byte at +0x18 (test at 0x15b8873, clear at
0x15b8877); its failure path carries the 41-byte message
"threads should not terminate unexpectedly" and Locations in
std/src/thread/lifecycle.rs (247:14 and 251:14, cells 0x6400550
and 0x6400568, immediately after the vtable table).
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
          'RE-005-node115-dispatcher-table')

DISPATCHER = 0x15b8fd0
ADAPTER_A = 0x155fa10
TABLE_BASES = (0x64004d0, 0x64004f0, 0x6400510, 0x6400530)
TABLE_LO, TABLE_HI = 0x64004d0, 0x6400550
WINDOW_LO, WINDOW_HI = 0x6400480, 0x6400578
DRAIN_BLOCK = 0x15b9091

BODIES = {
 'adapter_0': 0x155f9e0,
 'adapter_0_callee': 0x5c908b0,
 'adapter_a': ADAPTER_A,
 'dealloc': 0x635de30,
 'dispatcher': DISPATCHER,
 'join': 0x15b8810,
 'panic_msg_thunk': 0x1680c30,
 'spawn_e1': 0x15b6d10,
 'spawn_e2': 0x15b73c0,
 'spawn_e3': 0x15b7a80,
 'spawn_e4': 0x15b80e0,
 'thread_create': 0x5c87b50,
 'thread_start': 0x5ca44a0,
 'vtable_e1_drop': 0x15bb900,
 'vtable_e1_method': 0x15b8cd0,
 'vtable_e2_drop': 0x15bd430,
 'vtable_e2_method': 0x15b8e40,
 'vtable_e3_drop': 0x15bc390,
 'vtable_e3_method': 0x15b91d0,
 'vtable_e4_drop': 0x15bb300,
 'weak_release': 0x5bc2a80,
}

# GOT / data slots resolved through the dynamic relocation table.
SLOTS = {
 0x64df480: ('relative', 0x6355830),   # allocation entry
 0x64df4a0: ('relative', 0x635de30),   # deallocation entry
 0x64dfe60: ('relative', 0x5bc2a80),   # Arc weak-release glue
 0x64e0a30: ('relative', 0x167e030),   # environment lookup
 0x64e1188: ('relative', 0x5c908b0),   # adapter_0's callee
 0x64e1190: ('relative', ADAPTER_A),
 0x64e1318: ('relative', 0x155f9e0),   # adapter_0
 0x64e1580: ('relative', 0x5c87b50),   # thread create
 0x64e1590: ('glob', 'pthread_join'),
 0x64ebff0: ('glob', 'sysconf'),
 0x64ec828: ('glob', 'pthread_attr_init'),
 0x64ec830: ('glob', 'pthread_attr_setstacksize'),
 0x64ec838: ('glob', 'pthread_create'),
 0x64ec5a0: ('glob', 'pthread_attr_destroy'),
}

# .text call sites through each slot, as derived by the census.
SLOT_CALL_SITES = {
 '0x64e1188': ['0x155f9f7', '0x2c7bb57', '0x4d99177', '0x5bbed67',
               '0x5cd66d7', '0x5cdd027'],
 '0x64e1190': ['0x15b907d'],
 '0x64e1318': ['0x15b9054'],
 '0x64e1580': ['0x15b7068', '0x15b7710', '0x15b7d91', '0x15b8476',
               '0x2d46bb7', '0x2d47353', '0x2d47a68', '0x5613e33',
               '0x5614587', '0x5614d0f', '0x5615467', '0x5bc2fe5',
               '0x5cd97ab', '0x5cf71ec'],
 '0x64e1590': ['0x15b8824', '0x564680d', '0x5cf7564'],
}

# Every rip-relative reference into the window that contains the
# table, as derived by the census: the four vtable leas, the two
# lifecycle Location leas in the join body, and three leas to the
# preceding statics from two unrelated bodies (boundary).
WINDOW_REFS = [
 ('0x1533e56', '0x6400488', 'lea'),
 ('0x1533e5f', '0x64004a0', 'lea'),
 ('0x15b7028', '0x64004d0', 'lea'),
 ('0x15b76d0', '0x64004f0', 'lea'),
 ('0x15b7d51', '0x6400510', 'lea'),
 ('0x15b8436', '0x6400530', 'lea'),
 ('0x15b88fe', '0x6400550', 'lea'),
 ('0x15b8912', '0x6400568', 'lea'),
 ('0x15d5c49', '0x64004b8', 'lea'),
]

STRINGS = {
 'join_failed_prefix': (0x43d3e2, 23, 'failed to join thread: '),
 'join_panic_message': (0x469273, 41,
                        'threads should not terminate unexpectedly'),
 'lifecycle_file': (0x442f30, 83,
                    '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860'
                    '/library/std/src/thread/lifecycle.rs'),
}

LOCATIONS = {
 0x6400550: ('lifecycle.rs', 247, 14),
 0x6400568: ('lifecycle.rs', 251, 14),
}

# Byte pins: role -> [(relative offset, expected bytes hex, label)].
PINS = {
 'adapter_0': [
  (0x17, 'ff158b17f804', 'call through slot 0x64e1188 to 0x5c908b0'),
 ],
 'adapter_a': [
  (0x36, 'e885750700', 'direct call to wrapper A 0x15d6fd0'),
 ],
 'dispatcher': [
  (0x84, 'ff15be82f204', 'call through slot 0x64e1318 (adapter_0)'),
  (0xad, 'ff150d81f204', 'call through slot 0x64e1190 (adapter A)'),
  (0xb3, '4531f6', 'xor r14d, r14d (value stored to packet +0x20)'),
  (0xb6, '488b6b20', 'load packet pointer from self +0x20'),
  (0xba, '48837d1800', 'compare packet state qword at +0x18 with 0'),
  (0xbf, '7449', 'je +0x49 to 0x15b90da when state is zero'),
  (0xc1, '4c8b6520', 'drain block entry: load stored data at +0x20'),
  (0xce, '498b4500', 'load vtable drop slot at vtable +0x00'),
  (0xde, 'ffd0', 'call *%rax (the stored drop function)'),
  (0x104, 'ff15c663f204', 'call through slot 0x64df4a0 (dealloc)'),
  (0x10a, '48c7451801000000', 'store state 1 at packet +0x18'),
  (0x112, '4c897520', 'store r14 (zero) at packet +0x20'),
  (0x116, '4c897d28', 'store r15 at packet +0x28'),
  (0x11f, 'f048ff4d00', 'lock decq packet strong count at +0x00'),
  (0x12b, 'ff155f6df204', 'call through slot 0x64dfe60 (weak glue)'),
  (0x1de, '488b6b20', 'unwind pad reloads packet pointer'),
  (0x1e7, '0f85d4feffff', 'unwind pad jne back to the drain block'),
 ],
 'join': [
  (0x14, 'ff15668df204', 'call through slot 0x64e1590 (pthread_join)'),
  (0x63, 'f6401801', 'test result flag byte at packet +0x18'),
  (0x67, '48c7401800000000', 'clear packet state qword at +0x18'),
  (0xe7, '488d3d7509ebfe', 'lea of the 41-byte panic message'),
  (0xee, '488d154b7ce404', 'lea of Location cell 0x6400550'),
  (0x102, '488d3d4f7ce404', 'lea of Location cell 0x6400568'),
 ],
 'spawn_e1': [
  (0x2cf, 'bf30000000ff159684f204', 'allocate 0x30-byte closure object'),
  (0x318, '488d05a194e404', 'lea vtable base 0x64004d0'),
  (0x358, 'ff1512a5f204', 'call through slot 0x64e1580 (thread create)'),
 ],
 'spawn_e2': [
  (0x2bc, 'bf38000000ff15f97df204', 'allocate 0x38-byte closure object'),
  (0x310, '488d05198ee404', 'lea vtable base 0x64004f0'),
  (0x350, 'ff156a9ef204', 'call through slot 0x64e1580 (thread create)'),
 ],
 'spawn_e3': [
  (0x288, 'bf28000000ff156d77f204', 'allocate 0x28-byte closure object'),
  (0x2d1, '488d05b887e404', 'lea vtable base 0x6400510'),
  (0x311, 'ff15e997f204', 'call through slot 0x64e1580 (thread create)'),
 ],
 'spawn_e4': [
  (0x58, '48b8494e5f535441434b', 'movabs spelling IN_STACK (env name)'),
  (0x94, 'ba0f000000', 'env name length 0xf'),
  (0x99, 'ff15b188f204', 'call through slot 0x64e0a30 (env lookup)'),
  (0x2e9, 'bf58000000ff15ac70f204', 'allocate 0x58-byte closure object'),
  (0x356, '488d05f380e404', 'lea vtable base 0x6400530'),
  (0x365, 'bf18000000ff153070f204', 'allocate 0x18-byte thread package'),
  (0x381, '48894810', 'store vtable base at package +0x10'),
  (0x396, 'ff150491f204', 'call through slot 0x64e1580 (thread create)'),
 ],
 'thread_create': [
  (0x17, 'ff15bb4c8600', 'call through slot 0x64ec828 (attr_init)'),
  (0xc9, '488d1580c80100', 'lea start routine 0x5ca44a0'),
  (0xdb, 'ff15074c8600', 'call through slot 0x64ec838 (pthread_create)'),
 ],
 'thread_start': [
  (0x102, '4c8b7308', 'load closure data from package +0x08'),
  (0x106, '4c8b7b10', 'load closure vtable from package +0x10'),
  (0x137, '41ff5718', 'call *0x18(%r15): the vtable method slot'),
  (0x13b, '498b7708', 'load vtable size at vtable +0x08'),
 ],
}

PIN_STARTS = {
 role: [BODIES[role] + rel for rel, _, _ in pins]
 for role, pins in PINS.items()
}

LIMITATIONS = (
 'Static evidence only: nothing was executed. A vtable entry is '
 'identified by its layout ({drop, size, align, method}) and by '
 'the spawn body that loads its base; which source-level closure '
 'each sibling entry runs is not identified beyond the entry '
 'whose method is the dispatcher. The packet cell the dispatcher '
 'drains is described by the operations performed on it; the '
 'source type of the stored fat pointer and the value held in '
 'r15 when it is stored back to packet +0x28 are not established '
 'inside the dispatcher body. The 0x3d0/0x2c40 argument layouts, '
 'the sv[1] writer question, the wrapper-B registration cell and '
 'the kind-1 Once cache are other packets\' boundaries and are '
 'not revisited here.')


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


def va_to_offset(data, va):
    for s in sections(data):
        if s['type'] != 8 and s['address'] <= va < s['address'] + s['size']:
            return s['offset'] + va - s['address']
    raise ValueError(f'unmapped va {va:#x}')


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
    """One targeted pass over every SHT_RELA section.

    Collects only what this packet cites: the resolutions of the
    slots in SLOTS, every relocation landing in the table window
    or in .init_array, and every RELATIVE relocation whose addend
    is the dispatcher. Counts of the relocation kinds are kept
    for the census.
    """
    headers = raw_section_headers(data)
    secs = sections(data)
    init = next(s for s in secs if s['name'] == '.init_array')
    init_range = (init['address'], init['address'] + init['size'])
    slots, window, init_cells, dispatcher_hits = {}, {}, {}, []
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
            wanted = (r_off in SLOTS
                      or WINDOW_LO <= r_off < WINDOW_HI
                      or init_range[0] <= r_off < init_range[1]
                      or (rtype == 8 and r_add == DISPATCHER))
            if not wanted:
                continue
            symbol = None
            if rtype in (6, 7):
                sym = r_info >> 32
                st_name = struct.unpack_from(
                    '<I', data, dynsym['offset'] + sym * dynsym['entsize'])[0]
                end = data.index(b'\0', strtab['offset'] + st_name)
                symbol = data[strtab['offset'] + st_name:end].decode()
            entry = {'type': rtype, 'addend': r_add, 'symbol': symbol}
            if r_off in SLOTS:
                slots[r_off] = entry
            if WINDOW_LO <= r_off < WINDOW_HI:
                window[r_off] = entry
            if init_range[0] <= r_off < init_range[1]:
                init_cells[r_off] = entry
            if rtype == 8 and r_add == DISPATCHER:
                dispatcher_hits.append(r_off)
    return {'slots': slots, 'window': window, 'init': init_cells,
            'dispatcher_addend': sorted(dispatcher_hits),
            'counts': counts}


def slot_records(data, rel):
    out = []
    for slot in sorted(SLOTS):
        kind, want = SLOTS[slot]
        entry = rel['slots'].get(slot)
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


def qword(data, rel_window, va):
    entry = rel_window.get(va)
    if entry is not None:
        require(entry['type'] == 8, f'cell {va:#x} is not RELATIVE')
        return entry['addend'] & 0xffffffffffffffff
    return struct.unpack('<Q', read(data, va, 8))[0]


def table_records(data, rel, fdes):
    entries = []
    for base in TABLE_BASES:
        drop = qword(data, rel['window'], base)
        size = struct.unpack('<Q', read(data, base + 8, 8))[0]
        align = struct.unpack('<Q', read(data, base + 16, 8))[0]
        method = qword(data, rel['window'], base + 24)
        require(align == 8, f'vtable at {base:#x} align is not 8')
        require(drop in fdes, f'vtable drop {drop:#x} is not an FDE start')
        require(method in fdes,
                f'vtable method {method:#x} is not an FDE start')
        entries.append({'base': hex(base), 'drop_cell': hex(base),
                        'drop_in_place': hex(drop),
                        'size_cell': hex(base + 8), 'size': size,
                        'align_cell': hex(base + 16), 'align': align,
                        'method_cell': hex(base + 24),
                        'method': hex(method)})
    e4 = entries[3]
    require(e4['method_cell'] == '0x6400548'
            and e4['method'] == hex(DISPATCHER),
            'the fourth entry does not carry the dispatcher')
    require(rel['dispatcher_addend'] == [0x6400548],
            'dispatcher addend does not land exactly on 0x6400548')
    return entries


def relro_record(data):
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', data, 54)
    for i in range(phnum):
        p_type, _, _, p_va, _, _, p_memsz, _ = struct.unpack_from(
            '<IIQQQQQQ', data, phoff + i * phentsize)
        if p_type == 0x6474e552:  # PT_GNU_RELRO
            require(p_va <= TABLE_LO and TABLE_HI <= p_va + p_memsz,
                    'PT_GNU_RELRO does not cover the table')
            return {'start': hex(p_va), 'end': hex(p_va + p_memsz),
                    'covers_table': True}
    raise ValueError('no PT_GNU_RELRO segment')


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


def decode_location(data, rel, va):
    entry = rel['window'].get(va)
    require(entry is not None and entry['type'] == 8,
            f'Location file cell at {va:#x} has no RELATIVE relocation')
    file_ptr = entry['addend'] & 0xffffffffffffffff
    file_len, line, col = struct.unpack('<QII', read(data, va + 8, 16))
    text = read(data, file_ptr, file_len).decode()
    return {'cell': hex(va), 'file': text, 'file_length': file_len,
            'line': line, 'col': col}


def location_records(data, rel):
    out = []
    for va in sorted(LOCATIONS):
        rec = decode_location(data, rel, va)
        _, line, col = LOCATIONS[va]
        require(rec['line'] == line and rec['col'] == col
                and rec['file'].endswith('/std/src/thread/lifecycle.rs'),
                f'Location at {va:#x} changed')
        out.append(rec)
    return out


RIP_KINDS = {0x8d: 'lea', 0x8b: 'load', 0x89: 'store', 0x63: 'load',
             0x3b: 'cmp', 0x85: 'test', 0x39: 'cmp', 0x01: 'add',
             0x03: 'add', 0x2b: 'sub', 0x31: 'xor', 0x33: 'xor',
             0xff: 'incdec'}


def text_census(data, fdes):
    import re
    text = next(s for s in sections(data) if s['name'] == '.text')
    tb, tl = text['address'], text['size']
    raw = data[text['offset']:text['offset'] + tl]
    starts = sorted(fdes)

    def in_body(va):
        import bisect
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0:
            f = fdes[starts[i]]
            if f['start'] <= va < f['end']:
                return hex(f['start'])
        return None

    # Direct rel32 call/jump targets equal to the dispatcher.
    direct = []
    branch = re.compile(rb'[\xe8\xe9]....|'
                        rb'\x0f[\x80-\x8f]....', re.S)
    for m in branch.finditer(raw):
        n = 6 if raw[m.start()] == 0x0f else 5
        disp = struct.unpack_from('<i', raw, m.start() + n - 4)[0]
        if tb + m.start() + n + disp == DISPATCHER:
            direct.append(hex(tb + m.start()))
    require(direct == [], 'a direct rel32 branch reaches the dispatcher')

    # Rip-relative references into the window around the table.
    refs = []
    pat = re.compile(rb'(\x48|\x49|\x4c|\x4d)'
                     rb'(\x8d|\x8b|\x89|\x63|\x3b|\x85|\x39|'
                     rb'\x01|\x03|\x2b|\x31|\x33|\xff)'
                     rb'(\x05|\x0d|\x15|\x1d|\x25|\x2d|\x35|\x3d)')
    for m in pat.finditer(raw):
        disp = struct.unpack_from('<i', raw, m.start() + 3)[0]
        target = tb + m.start() + 7 + disp
        if WINDOW_LO <= target < WINDOW_HI:
            refs.append({'site': hex(tb + m.start()),
                         'target': hex(target),
                         'kind': RIP_KINDS[raw[m.start() + 1]],
                         'in_body': in_body(tb + m.start())})
    got = [(r['site'], r['target'], r['kind']) for r in refs]
    require(got == [tuple(x) for x in WINDOW_REFS],
            'window reference census changed')
    stores = [r for r in refs
              if r['kind'] == 'store'
              and TABLE_LO <= int(r['target'], 16) < TABLE_HI]
    require(stores == [], 'a store reaches the vtable table')

    # Call sites through the censused GOT slots.
    site_lists = {}
    wanted = {int(k, 16) for k in SLOT_CALL_SITES}
    pos = 0
    while True:
        j = raw.find(b'\xff\x15', pos)
        if j < 0:
            break
        disp = struct.unpack_from('<i', raw, j + 2)[0]
        target = tb + j + 6 + disp
        if target in wanted:
            site_lists.setdefault(target, []).append(tb + j)
        pos = j + 1
    slot_sites = {}
    for slot in sorted(wanted):
        sites = [hex(x) for x in site_lists.get(slot, [])]
        require(sites == SLOT_CALL_SITES[hex(slot)],
                f'call-site census changed for slot {slot:#x}')
        slot_sites[hex(slot)] = sites

    # Direct branches inside the dispatcher that target the drain
    # block: exactly the unwind pad's jne.
    body_start = DISPATCHER
    fde = fdes[body_start]
    blob = raw[body_start - tb:fde['end'] - tb]
    drain_sources = []
    for m in branch.finditer(blob):
        n = 6 if blob[m.start()] == 0x0f else 5
        disp = struct.unpack_from('<i', blob, m.start() + n - 4)[0]
        if body_start + m.start() + n + disp == DRAIN_BLOCK:
            drain_sources.append(hex(body_start + m.start()))
    for m in re.finditer(rb'[\x70-\x7f].', blob):
        disp = struct.unpack_from('<b', blob, m.start() + 1)[0]
        if body_start + m.start() + 2 + disp == DRAIN_BLOCK:
            drain_sources.append(hex(body_start + m.start()))
    for m in re.finditer(rb'\xeb.', blob):
        disp = struct.unpack_from('<b', blob, m.start() + 1)[0]
        if body_start + m.start() + 2 + disp == DRAIN_BLOCK:
            drain_sources.append(hex(body_start + m.start()))
    require(sorted(set(drain_sources)) == ['0x15b91b7'],
            'drain block branch sources changed')

    return {'direct_rel32_branches_to_dispatcher': direct,
            'rip_refs_in_window': refs,
            'stores_into_table': [],
            'slot_call_sites': slot_sites,
            'drain_block_branch_sources': ['0x15b91b7'],
            'relocation_counts': None}  # filled by analyze()


def init_array_record(data, rel, fdes):
    targets = sorted(
        (e['addend'] & 0xffffffffffffffff)
        for e in rel['init'].values() if e['type'] == 8)
    require(len(targets) == 168, '.init_array entry count changed')
    pinned = {hex(v) for v in BODIES.values()}
    hits = [hex(t) for t in targets if hex(t) in pinned]
    require(hits == [], 'an .init_array entry names a pinned body')
    return {'entries': len(targets),
            'targets_that_are_pinned_bodies': hits}


def analyze(data):
    rel = relocations(data)
    fdes = body_map(data)
    census = text_census(data, fdes)
    census['relocation_counts'] = rel['counts']
    return {
        'artifact': {'path': 'artifacts/node/115/hl-node',
                     'size': SIZE, 'sha256': SHA},
        'bodies': bodies(data, fdes),
        'pins': all_pins(data),
        'slots': slot_records(data, rel),
        'table': {'window': [hex(WINDOW_LO), hex(WINDOW_HI)],
                  'entries': table_records(data, rel, fdes),
                  'relro': relro_record(data)},
        'census': census,
        'init_array': init_array_record(data, rel, fdes),
        'strings': string_records(data),
        'locations': location_records(data, rel),
        'answers': {
            'registrar': 'link-time R_X86_64_RELATIVE relocation into '
                         'cell 0x6400548; no run-time registration '
                         'path exists (no stores, no init_array '
                         'entry, one lea per vtable base)',
            'walked': 'no list: one shared packet cell at self+0x20, '
                      'drained once per call when its state qword '
                      'at +0x18 is nonzero',
            'caller': 'no direct caller: the new OS thread started '
                      'by pthread_create (start routine 0x5ca44a0) '
                      'calls the package vtable method slot +0x18',
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
