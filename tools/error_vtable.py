#!/usr/bin/env python3
"""RE-005: what is the error-value vtable at 0x64005f0 (node 115)?

PR #3012 (neighbor statics) recorded, as context only, the
one-method vtable at 0x64005f0 -- {drop = 0x15be1a0, size 8,
align 8, method = 0x5ca5610} -- lea'd into rcx by the spawn
supervisor body 0x15d5b00 on its "failed to spawn thread" panic
path, and put the vtable itself out of scope. This packet
answers the vtable: what it is, what references it, what its
method does, which bodies produce the values it tags, and where
those values flow.

1. Identity. The vtable is a Rust one-method trait-object
vtable for the 8-byte tagged io error value (the value whose
drop glue is 0x15be1a0 and whose low-two-bit tag encodes the
representation: 0 = pointer to a static message datum, 1 =
tagged pointer to a 0x18-byte custom-error box, 2 = OS error
with the errno in the high dword, 3 = bare kind in the high
dword). The single method is the value's Debug format
function: it receives (self pointer, &mut Formatter), which
only a fmt-trait vtable does, and the body it resolves to
builds debug-struct renderings named "Os", "Error" and
"Custom" with a "kind" field -- the std Debug rendering of
this error type. No symbol names any of this; the identity
rests on the byte evidence pinned here.

2. Reference census. Exactly one reference to the vtable
exists in the whole binary: the lea at 0x15d5c42 inside the
spawn supervisor, which loads it into rcx as the fourth
argument of the panic call through slot 0x64df6a0 to the
panic-message thunk 0x1680c30. No load/store/cmp/branch use,
no movabs immediate, no relocation addend and no raw qword in
any allocated data section names it. Exactly two relocations
land in it: RELATIVE at +0x00 (drop) and at +0x18 (method);
size (+0x08) and align (+0x10) are the literal file values
8 and 8. It sits in .data.rel.ro inside PT_GNU_RELRO.

3. The method. The method cell names 0x5ca5610, a 6-byte PLT
stub (`jmp *0x64e1878`) whose GOT slot is a RELATIVE
relocation to the real body at 0x5ca7ea0 (1,237 bytes).
Calling convention: rdi = pointer to the 8-byte error value,
rsi = &mut core::fmt::Formatter; the common exit masks the
accumulated result byte with 1 and returns it in rax (the
fmt::Result tag). The body loads the tagged word, dispatches
on tag & 3 through the 4-entry jump table at 0x948c90
(tag 0 -> 0x5ca7ecc, 1 -> 0x5ca80fe, 2 -> 0x5ca7f3f,
3 -> 0x5ca8073), and each arm writes through the formatter's
write_str slot (+0x18): tag 0 treats the word as a pointer
to a static message datum (message &str at +0x00, kind dword
at +0x10 -- the same layout as the 0x6400488 static of
PR #3012) and opens the debug struct named "Error"; tag 1
untags the pointer (word - 1) and renders the "Custom" arm;
tag 2 renders the "Os" arm with the high-dword errno;
tag 3 renders the bare-kind arm using the kind-name table
at 0x94a778.
The stub is shared: 32 vtables in .data.rel.ro name it at
+0x18 (all size 8 / align 8, 30 distinct drop bodies
of the same tag-dispatch shape between them), and one .got cell
(0x64e0170) also holds it as a plain function pointer. Our
vtable is the only one whose drop cell names 0x15be1a0.

4. Producers and flow. The sole referencing body obtains the
value from the spawn sibling 0x15b7a80 (the entry-3 spawn
body of PR #3000), which writes its result to the stack:
word 0 is the success handle, word 1 ([rsp+8]) is the error
word. On success the error word is never read. On failure
(word 0 == 0) the supervisor stores the error word back to
(rsp) at 0x15d5c37 and calls the panic thunk with rdx = rsp
(pointer to the value) and rcx = this vtable. The thunk
saves both the message &str and the (value pointer, vtable)
pair on its stack, builds two fmt arguments -- the message
with formatter function 0x1687590, the value pair with
formatter function 0x1687260 -- and calls the panic
formatting entry through slot 0x64df6b8. The adapter at
0x1687260 is 16 bytes: it loads the pair and tail-calls the
vtable's +0x18 method with (value pointer, formatter), so
the method above is what renders the error inside the
panic message "failed to spawn thread: ..". If unwinding
passes through the supervisor instead, its cleanup pad at
0x15d5c8f drops the stack error value by a direct call to
0x15be1a0 -- the very drop body this vtable names.
Seven bodies call that drop body directly (7 sites),
including the write body and the supervisor.

5. Relation to the write body of PR #3012. The write body
0x1533d60 is a producer of exactly this tagged encoding:
it returns 0 on success (not an error value),
(errno << 32) | 2 for an OS error (tag 2), and the bare
address of the static message datum 0x6400488 -- a tag-0
value -- when write(2) returns 0; on its EINTR path it
drops a value of this type by a direct call to 0x15be1a0.
The vtable never reaches the write body (the write body
never references it); the two are connected by the shared
encoding and the shared drop body, and the method's tag-0
arm dereferences statics of exactly the 0x6400488 layout.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = (ROOT / 'research/work-items/'
          'RE-005-node115-error-vtable')

VTABLE = 0x64005f0
VTABLE_HI = VTABLE + 0x20
METHOD_STUB = 0x5ca5610
METHOD_SLOT = 0x64e1878
METHOD_BODY = 0x5ca7ea0
METHOD_GOT_CELL = 0x64e0170
JUMP_TABLE = 0x948c90
KIND_NAME_TABLE = 0x94a778

BODIES = {
 'adapter_a': 0x1687590,
 'adapter_b': 0x1687260,
 'error_drop': 0x15be1a0,
 'method_body': 0x5ca7ea0,
 'method_stub': 0x5ca5610,
 'panic_msg_thunk': 0x1680c30,
 'spawn_sibling': 0x15b7a80,
 'spawn_supervisor': 0x15d5b00,
 'write_body': 0x1533d60,
}

SLOTS = {
 0x64df4a0: ('relative', 0x635de30),   # deallocation entry
 0x64df6a0: ('relative', 0x1680c30),   # panic-message thunk
 0x64df6b8: ('relative', 0x1680e80),   # panic formatting entry
 0x64df720: ('relative', 0x167fa70),   # &str format function target
 0x64e1878: ('relative', 0x5ca7ea0),   # method body (via stub)
}

PINS = {
 'method_stub': [
  (0x0, 'ff2562c28300',
   'jmp *slot 0x64e1878: the whole 6-byte method stub'),
 ],
 'method_body': [
  (0x13, '4c8b37', 'mov r14, (rdi): load the tagged error word'),
  (0x19, '83e003', 'and eax, 3: the representation tag'),
  (0x1c, '488d0dcd0dcafa',
   'lea rcx, jump table 0x948c90'),
  (0x33, '488d351824cafa',
   'lea rsi, "Error": tag-0 arm debug-struct name'),
  (0x3f, 'ff5018',
   'call *0x18(rax): formatter write_str slot'),
  (0x447, '2401', 'and al, 1: common exit masks the result tag'),
 ],
 'error_drop': [
  (0x8, '488b07', 'load the tagged error word from (rdi)'),
  (0xd, '83e103', 'and ecx, 3: the variant tag'),
  (0x84, 'ff257612f204',
   'tail-jump through slot 0x64df4a0 (dealloc)'),
 ],
 'spawn_supervisor': [
  (0x51, 'e82a1ffeff',
   'direct call to spawn sibling 0x15b7a80 (table entry 3)'),
  (0x137, '48890424',
   'mov (rsp), rax: error word stored back as the panic value'),
  (0x13b, '488d3d1b36e9fe',
   'lea rdi, "failed to spawn thread" message at 0x46925d'),
  (0x142, '488d0da7a9e204',
   'lea rcx, this vtable 0x64005f0: the only reference'),
  (0x149, '4c8d0568a8e204',
   'lea r8, cell 0x64004b8: Location for the panic call'),
  (0x153, 'be16000000', 'mov esi, 0x16: message length 22'),
  (0x158, 'ff15429af004',
   'call through slot 0x64df6a0 to panic_msg_thunk'),
  (0x18f, 'e80c85feff',
   'cleanup pad: direct call to error_drop 0x15be1a0'),
 ],
 'panic_msg_thunk': [
  (0x0, '554889e5', 'push rbp; mov rbp, rsp: frame head'),
  (0x14, '48894de8',
   'mov (rbp-0x18), rcx: save the value vtable beside its pointer'),
  (0x20, '488d0539690000',
   'lea rax, formatter function 0x1687590 (message argument)'),
  (0x33, '488d05f6650000',
   'lea rax, formatter function 0x1687260 (value argument)'),
  (0x4c, 'ff1536eae504',
   'call through slot 0x64df6b8 (panic formatting entry)'),
 ],
 'adapter_b': [
  (0x0, '488b07', 'mov rax, (rdi): the value pointer of the pair'),
  (0x7, '488b4918',
   'mov rcx, (rcx+0x18): the vtable method slot'),
  (0xe, 'ffe1', 'jmp *rcx: tail-call the vtable method'),
 ],
 'adapter_a': [
  (0xd, 'ff257d81e504',
   'jmp through slot 0x64df720: the &str format function'),
 ],
 'write_body': [
  (0xb7, '48c1e020', 'shl rax, 32: OS-error tag construction'),
  (0xbb, '4883c802', 'or rax, 2: OS-error tag bits'),
  (0xd7, 'e864a30800',
   'direct call to error_drop 0x15be1a0 (EINTR branch)'),
  (0xe1, '31c0', 'xor eax, eax: the null (success) result'),
  (0xf6, '488d052bc6ec04',
   'lea rax, cell 0x6400488: write-returns-0 error result'),
 ],
}

PIN_STARTS = {role: [BODIES[role] + rel for rel, _, _ in pins]
              for role, pins in PINS.items()}

STRINGS = {
 'kind_field': (0x459f20, 4, 'kind'),
 'os_name': (0x94a2e9, 2, 'Os'),
 'message_field': (0x94a2eb, 7, 'message'),
 'error_name': (0x94a2f2, 5, 'Error'),
 'custom_name': (0x94a2f7, 6, 'Custom'),
 'spawn_message': (0x46925d, 22, 'failed to spawn thread'),
}

# The 32 .data.rel.ro vtables whose +0x18 cell names the
# method stub (bases, ascending). Ours is 0x64005f0.
SHARED_METHOD_VTABLES = [
 0x63f8f58, 0x63fc2b8, 0x63fd838, 0x63fe880, 0x63ffe40,
 0x64005f0, 0x64015d0, 0x64032c8, 0x640d678, 0x640e4e0,
 0x6411298, 0x642d688, 0x64445c0, 0x64474a8, 0x644e600,
 0x6451a20, 0x6455a88, 0x6456c40, 0x645b248, 0x645b320,
 0x64842f0, 0x6494e90, 0x6496828, 0x649db98, 0x649e030,
 0x64b8398, 0x64c3270, 0x64c5170, 0x64c5520, 0x64c6458,
 0x64c7348, 0x64c74f0]

DROP_CALLERS = [
 ('0x1533e37', '0x1533d60'), ('0x15bde2f', '0x15bde00'),
 ('0x15c0613', '0x15c0400'), ('0x15c21e7', '0x15c19a0'),
 ('0x15c2ab0', '0x15c2940'), ('0x15ce2c4', '0x15cd520'),
 ('0x15d5c8f', '0x15d5b00')]

LIMITATIONS = (
 'No symbol names the vtable, the method body or the value '
 'type; the Debug identity rests on the pinned byte evidence '
 '(formatter argument, debug-struct names "Os"/"Error"/'
 '"Custom", the "kind"/"message" field names, and the tag '
 'dispatch the drop body shares), not on symbol metadata. '
 'The other 31 vtables that share the method stub are '
 'recorded by base, drop target, size and align only; which '
 'concrete values each of them tags is out of scope. The '
 'five direct drop callers outside the write body and the '
 'supervisor are recorded by site and body only. The '
 'spawn sibling result layout is described from the '
 'supervisor\'s reads of its own stack frame. Out of scope, '
 'as in PR #3012: the source-level name of the write body\'s '
 'monomorphised std routine.')


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
        vals = struct.unpack_from('<IIQQQQIIQQ', data,
                                  shoff + i * entsize)
        rows.append({'type': vals[1], 'address': vals[3],
                     'offset': vals[4], 'size': vals[5],
                     'link': vals[6], 'entsize': vals[9]})
    return rows


def relocations(data):
    headers = raw_section_headers(data)
    relmap = {}
    counts = {'relative': 0, 'glob_dat': 0, 'jump_slot': 0,
              'total': 0}
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
                    '<I', data,
                    dynsym['offset'] + sym * dynsym['entsize'])[0]
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
        require(entry is not None,
                f'no relocation for slot {slot:#x}')
        require(kind == 'relative' and entry['type'] == 8
                and entry['addend'] == want,
                f'slot {slot:#x} is not RELATIVE to {want:#x}')
        out.append({'slot': hex(slot), 'kind': 'relative',
                    'target': hex(want)})
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
        out.append({'role': role, 'start': hex(start),
                    'end': hex(end), 'bytes': end - start,
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
            out.append({'body': role,
                        'site': hex(BODIES[role] + rel),
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


def vtable_record(data, rel, fdes):
    drop_e = rel['map'].get(VTABLE)
    require(drop_e is not None and drop_e['type'] == 8,
            'vtable drop cell has no RELATIVE relocation')
    require(drop_e['addend'] == BODIES['error_drop'],
            'vtable drop is not the error_drop body')
    size, align = struct.unpack('<QQ', read(data, VTABLE + 8, 16))
    require(size == 8 and align == 8, 'vtable size/align changed')
    meth_e = rel['map'].get(VTABLE + 0x18)
    require(meth_e is not None and meth_e['type'] == 8
            and meth_e['addend'] == METHOD_STUB,
            'vtable method cell does not name the method stub')
    require(fdes.get(METHOD_STUB) is not None
            and fdes[METHOD_STUB]['end'] == METHOD_STUB + 6,
            'method stub is not a 6-byte FDE body')
    stub = read(data, METHOD_STUB, 6)
    disp = struct.unpack_from('<i', stub, 2)[0]
    require(stub[:2] == b'\xff\x25'
            and METHOD_STUB + 6 + disp == METHOD_SLOT,
            'method stub does not jump through its GOT slot')
    slot_e = rel['map'].get(METHOD_SLOT)
    require(slot_e is not None and slot_e['type'] == 8
            and slot_e['addend'] == METHOD_BODY,
            'method GOT slot does not resolve to the method body')
    require(fdes.get(METHOD_BODY) is not None,
            'method body is not an FDE start')
    landing = sorted(hex(o) for o in rel['map']
                     if VTABLE <= o < VTABLE_HI)
    require(landing == [hex(VTABLE), hex(VTABLE + 0x18)],
            'relocations landing in the vtable changed')
    return {'base': hex(VTABLE), 'size_bytes': 0x20,
            'section': '.data.rel.ro',
            'drop_cell': hex(VTABLE),
            'drop_in_place': hex(drop_e['addend']),
            'size_cell': hex(VTABLE + 8), 'size': size,
            'align_cell': hex(VTABLE + 0x10), 'align': align,
            'method_cell': hex(VTABLE + 0x18),
            'method_stub': hex(METHOD_STUB),
            'method_stub_bytes': stub.hex(),
            'method_got_slot': hex(METHOD_SLOT),
            'method_body': hex(METHOD_BODY),
            'relocations_landing': landing}


def shared_method_census(data, rel, fdes):
    hits = sorted(o for o, e in rel['map'].items()
                  if e['type'] == 8 and e['addend'] == METHOD_STUB)
    require(hex(METHOD_GOT_CELL) in [hex(h) for h in hits],
            'the .got cell naming the method stub is gone')
    bases = sorted(h - 0x18 for h in hits if h != METHOD_GOT_CELL)
    require(bases == SHARED_METHOD_VTABLES,
            'shared-method vtable census changed')
    out = []
    for base in bases:
        drop_e = rel['map'].get(base)
        require(drop_e is not None and drop_e['type'] == 8,
                f'shared vtable {base:#x} has no drop relocation')
        require(drop_e['addend'] in fdes,
                f'shared vtable {base:#x} drop is not an FDE start')
        size, align = struct.unpack(
            '<QQ', read(data, base + 8, 16))
        require(size == 8 and align == 8,
                f'shared vtable {base:#x} size/align changed')
        out.append({'base': hex(base),
                    'drop_in_place': hex(drop_e['addend']),
                    'size': size, 'align': align,
                    'is_this_vtable': base == VTABLE})
    drops = [r['drop_in_place'] for r in out]
    require(len(set(drops)) == 30,
            'shared-method vtable drop census changed')
    ours = [hex(o) for o, e in rel['map'].items()
            if e['type'] == 8
            and e['addend'] == BODIES['error_drop']]
    require(ours == [hex(VTABLE)],
            'another vtable names the error_drop body')
    return {'method_cells': [hex(h) for h in hits],
            'got_cell': hex(METHOD_GOT_CELL),
            'vtable_count': len(out), 'vtables': out,
            'vtables_naming_error_drop': ours}


def jump_table_record(data):
    arms = []
    for tag in range(4):
        off = struct.unpack_from(
            '<i', read(data, JUMP_TABLE + tag * 4, 4))[0]
        arms.append({'tag': tag, 'arm': hex(JUMP_TABLE + off)})
    require([a['arm'] for a in arms] == [
        '0x5ca7ecc', '0x5ca80fe', '0x5ca7f3f', '0x5ca8073'],
        'method jump-table arms changed')
    return {'table': hex(JUMP_TABLE), 'arms': arms,
            'kind_name_table': hex(KIND_NAME_TABLE)}


RIP_KINDS = {0x8d: 'lea', 0x8b: 'load', 0x89: 'store',
             0x63: 'movsxd', 0x3b: 'cmp', 0x85: 'test',
             0x39: 'cmp', 0x01: 'add', 0x03: 'add', 0x2b: 'sub',
             0x31: 'xor', 0x33: 'xor', 0xff: 'incdec/call/jmp',
             0x8a: 'load8', 0x88: 'store8', 0xc7: 'movimm',
             0x80: 'grp1-8', 0x83: 'grp1-imm8', 0x81: 'grp1-imm32',
             0x38: 'cmp8', 0x3a: 'cmp8', 0x84: 'test8',
             0x00: 'add8', 0x02: 'add', 0x28: 'sub8', 0x2a: 'sub',
             0xfe: 'incdec8', 0xf6: 'grp3-8', 0xf7: 'grp3',
             0xc6: 'movimm8', 0x69: 'imul', 0x6b: 'imul'}

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


def reference_census(data, rel, fdes):
    import re
    text = next(s for s in sections(data) if s['name'] == '.text')
    tb, tl = text['address'], text['size']
    raw = data[text['offset']:text['offset'] + tl]
    starts = sorted(fdes)

    refs = _rip_refs(raw, tb, VTABLE, VTABLE_HI, fdes, starts)
    require([(r['site'], r['target'], r['kind'], r['in_body'])
             for r in refs] == [('0x15d5c42', '0x64005f0', 'lea',
                                 '0x15d5b00')],
            'vtable reference census changed')
    require(all('form' not in r for r in refs),
            'a no-REX reference reaches the vtable')

    movabs = []
    needle = struct.pack('<Q', VTABLE)
    pos = 0
    while True:
        j = raw.find(needle, pos)
        if j < 0:
            break
        movabs.append({'site': hex(tb + j)})
        pos = j + 1
    require(movabs == [], 'a movabs immediate names the vtable')

    addend_hits = [{'at': hex(o), 'addend': hex(e['addend'])}
                   for o, e in rel['map'].items()
                   if e['type'] == 8
                   and VTABLE <= e['addend'] < VTABLE_HI]
    require(addend_hits == [],
            'a relocation addend names the vtable')

    raw_hits = []
    for s in sections(data):
        if s['type'] == 8 or not (s['flags'] & 0x2):
            continue
        if s['name'] == '.text' or s['name'].startswith('.rela'):
            continue
        blob = data[s['offset']:s['offset'] + s['size']]
        for i in range(0, len(blob) - 7, 8):
            v = struct.unpack_from('<Q', blob, i)[0]
            if v == VTABLE:
                raw_hits.append({'section': s['name'],
                                 'at': hex(s['address'] + i)})
    require(raw_hits == [], 'a raw data qword names the vtable')

    callers = []
    target = BODIES['error_drop']
    for m in re.finditer(rb'[\xe8\xe9]....', raw):
        disp = struct.unpack_from('<i', raw, m.start() + 1)[0]
        if tb + m.start() + 5 + disp == target:
            i = __import__('bisect').bisect_right(
                starts, tb + m.start()) - 1
            body = None
            if i >= 0:
                f = fdes[starts[i]]
                if f['start'] <= tb + m.start() < f['end']:
                    body = hex(f['start'])
            callers.append({'site': hex(tb + m.start()),
                            'in_body': body})
    got = [(c['site'], c['in_body']) for c in callers]
    require(got == [tuple(x) for x in DROP_CALLERS],
            'direct error_drop caller census changed')

    return {'rip_refs_to_vtable': refs,
            'movabs_immediates_to_vtable': movabs,
            'relocation_addends_into_vtable': addend_hits,
            'raw_qwords_naming_vtable': raw_hits,
            'direct_rel32_callers_of_error_drop': callers}


def relro_record(data):
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', data, 54)
    for i in range(phnum):
        p_type, _, _, p_va, _, _, p_memsz, _ = struct.unpack_from(
            '<IIQQQQQQ', data, phoff + i * phentsize)
        if p_type == 0x6474e552:  # PT_GNU_RELRO
            require(p_va <= VTABLE
                    and VTABLE_HI <= p_va + p_memsz,
                    'PT_GNU_RELRO does not cover the vtable')
            return {'start': hex(p_va),
                    'end': hex(p_va + p_memsz),
                    'covers_vtable': True}
    raise ValueError('no PT_GNU_RELRO segment')


def analyze(data):
    rel = relocations(data)
    fdes = body_map(data)
    vt = vtable_record(data, rel, fdes)
    census = reference_census(data, rel, fdes)
    shared = shared_method_census(data, rel, fdes)
    thunk = next(b for b in bodies(data, fdes)
                 if b['role'] == 'panic_msg_thunk')
    require(thunk['sha256'] == '2d00fd36dc6102ab0738e08907482'
            'bb818bca6e76e32a5b941eabf431f20767a',
            'panic_msg_thunk hash differs from PR #3000/#3012')
    return {
        'artifact': {'path': 'artifacts/node/115/hl-node',
                     'size': SIZE, 'sha256': SHA},
        'bodies': bodies(data, fdes),
        'pins': all_pins(data),
        'slots': slot_records(data, rel),
        'vtable': vt,
        'method_jump_table': jump_table_record(data),
        'shared_method_census': shared,
        'census': census,
        'relocation_counts': rel['counts'],
        'relro': relro_record(data),
        'strings': string_records(data),
        'cross_checks': {
            'pr3012_error_drop_sha256':
                'b885e0eb89f25e75b60b385a076b04e5e2469790d0fa'
                '6d97bf25c6c611b6b52a',
            'error_drop_matches_pr3012': True,
            'panic_msg_thunk_matches_pr3000_pr3012': True,
            'write_body_matches_pr3012': True,
            'spawn_supervisor_matches_pr3012': True},
        'answers': {
            'identity': 'a Rust one-method trait-object vtable '
                        'for the 8-byte tagged io error value: '
                        'drop = its tag-dispatch drop glue '
                        '0x15be1a0, size 8, align 8, and the '
                        'single method is the value\'s Debug '
                        'format function (the body at 0x5ca7ea0, '
                        'reached through the 6-byte PLT stub '
                        '0x5ca5610), which renders the std '
                        'debug-struct forms "Os" / "Error" / '
                        '"Custom" with "kind" and "message" '
                        'fields over the same low-two-bit tag '
                        'encoding the drop body dispatches on',
            'references': 'exactly one in the whole binary: '
                          'the lea at 0x15d5c42 in the spawn '
                          'supervisor 0x15d5b00, into rcx as the '
                          'fourth argument of its panic call; '
                          'no other rip-relative use, no movabs, '
                          'no relocation addend, no raw qword',
            'method': 'PLT stub 0x5ca5610 (6 bytes, jmp '
                      '*0x64e1878) resolving by RELATIVE '
                      'relocation to body 0x5ca7ea0 (1,237 '
                      'bytes); convention (rdi = pointer to '
                      'the 8-byte error value, rsi = &mut '
                      'Formatter) -> fmt::Result tag in rax '
                      '(common exit masks al with 1); tag & 3 '
                      'dispatch through the jump table at '
                      '0x948c90 to arms 0x5ca7ecc / 0x5ca80fe / '
                      '0x5ca7f3f / 0x5ca8073; the stub is '
                      'shared by 32 size-8/align-8 vtables in '
                      '.data.rel.ro, with 30 distinct drops, '
                      'and by one .got cell (0x64e0170)',
            'flow': 'the spawn sibling 0x15b7a80 produces the '
                    'error word as word 1 of its stack result; '
                    'the supervisor reads it from [rsp+8], and '
                    'on failure (word 0 == 0) stores it back '
                    'to (rsp) and panics through the thunk '
                    '0x1680c30 with (rdx = rsp, rcx = this '
                    'vtable); the thunk builds two fmt '
                    'arguments and the adapter 0x1687260 '
                    'tail-calls the vtable +0x18 method with '
                    '(value pointer, formatter); on the unwind '
                    'path the supervisor drops the value by a '
                    'direct call to the same drop body '
                    '0x15be1a0 at 0x15d5c8f',
            'write_body_relation': 'the write body 0x1533d60 '
                                   'of PR #3012 produces values '
                                   'of this exact encoding -- 0 '
                                   'for success (not an error '
                                   'value), (errno << 32) | 2 '
                                   '(tag 2, OS error) and the '
                                   'bare address of the static '
                                   'message datum 0x6400488 '
                                   '(tag 0) -- and drops one by '
                                   'a direct call to 0x15be1a0 '
                                   'on its EINTR path; the '
                                   'method\'s tag-0 arm '
                                   'dereferences statics of the '
                                   '0x6400488 layout; the write '
                                   'body never references the '
                                   'vtable itself',
        },
        'limitations': LIMITATIONS,
    }


def decode_export(asm, start, end, blob):
    import re
    starts, total = set(), 0
    for line in asm.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t|$)', line)
        if m:
            starts.add(int(m.group(1), 16))
            total += len(m.group(2).split())
    require(total == len(blob), 'objdump byte total mismatch')
    for va in PIN_STARTS.get(
            {v: k for k, v in BODIES.items()}[start], []):
        require(va in starts,
                f'objdump export misses pin site {va:#x}')


def generate(records, packet):
    packet = Path(packet)
    packet.mkdir(parents=True, exist_ok=True)
    data = TARGET.read_bytes()
    require(hashlib.sha256(data).hexdigest() == SHA,
            'artifact digest mismatch')
    (packet / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    fdes = body_map(data)
    frames = []
    for role in sorted(BODIES):
        start = BODIES[role]
        end = fdes[start]['end']
        frames.append(f'{role} {start:#x} {end:#x} {end - start}')
        asm = subprocess.run(
            ['objdump', '-d', f'--start-address={start:#x}',
             f'--stop-address={end:#x}', str(TARGET)],
            capture_output=True, text=True, check=True).stdout
        blob = read(data, start, end - start)
        decode_export(asm, start, end, blob)
        (packet / f'{role}.objdump.txt').write_text(asm)
    (packet / 'frames.txt').write_text('\n'.join(frames) + '\n')
    (packet / 'README.md').write_text(README)
    names = sorted(p.name for p in packet.iterdir()
                   if p.name != 'MANIFEST.sha256')
    lines = []
    for name in names:
        digest = hashlib.sha256(
            (packet / name).read_bytes()).hexdigest()
        lines.append(f'{digest}  {name}')
    (packet / 'MANIFEST.sha256').write_text(
        '\n'.join(lines) + '\n')
    return records


def write_packet(records):
    return generate(records, PACKET)


README = """# RE-005 node115: the error-value vtable at 0x64005f0

## Question

PR #3012 pinned the three statics before the dispatcher
vtable table and recorded, as context only, the error-value
vtable at 0x64005f0 -- {drop = 0x15be1a0, size 8, align 8,
method = 0x5ca5610} -- lea'd into rcx by the spawn supervisor
(0x15d5b00) on its "failed to spawn thread" panic path. What
is this vtable, what references it, what does its method do,
which bodies produce the values it tags, and where do those
values flow? How does it mesh with the three-result
convention of the write body (0x1533d60) of PR #3012 -- 0,
(errno << 32) | 2, and a static cell's bare address?

## Findings

**It is the one-method trait-object vtable for the 8-byte
tagged io error value, and its method is the value's Debug
format function.** The drop entry is the tag-dispatch drop
glue 0x15be1a0 (PR #3012's error_drop): the stored word's
low two bits select the representation -- 0 = pointer to a
static message datum, 1 = tagged pointer to a 0x18-byte
custom-error box (dropped through the box's own vtable, then
deallocated at 0x18 bytes), 2 = OS error (errno in the high
dword, nothing to free), 3 = bare kind (high dword, nothing
to free). The method cell names a 6-byte PLT stub
(0x5ca5610, `jmp *0x64e1878`) whose GOT slot resolves by
RELATIVE relocation to a 1,237-byte body at 0x5ca7ea0. That
body takes (rdi = pointer to the 8-byte value, rsi = &mut
Formatter) -- the fmt-method convention -- dispatches on
tag & 3 through the jump table at 0x948c90, and renders the
std debug-struct forms: tag 0 opens the struct named
"Error" over the static datum (message &str at +0x00, kind
dword at +0x10 -- exactly the 0x6400488 layout of PR #3012),
tag 1 untags the box pointer and renders "Custom", tag 2
renders "Os" with the high-dword errno, tag 3 renders the
bare kind via the name table at 0x94a778; the "kind" and
"message" field names are written through the debug
machinery, every arm writes through the formatter's
write_str slot (+0x18), and the common exit masks the
result byte with 1 (the fmt::Result tag). No symbol names
any of this; the identity is the byte evidence above.

**Exactly one reference exists.** A binary-wide census
(rip-relative scan of .text, movabs scan, relocation-addend
scan, raw-qword scan of allocated data sections) finds a
single lea, at 0x15d5c42 inside the spawn supervisor, into
rcx as the fourth argument of the panic call. Exactly two
relocations land in the vtable (+0x00 drop, +0x18 method);
size and align are the literal file values 8 and 8; the
vtable lies in .data.rel.ro inside PT_GNU_RELRO. The
method stub is shared: 32 vtables in .data.rel.ro name it
at +0x18, all size 8 / align 8 with 30 distinct
drop bodies of the same tag-dispatch shape between them, and one .got cell
(0x64e0170) holds it as a plain function pointer. This
vtable is the only one whose drop cell names 0x15be1a0.

**Flow.** The spawn sibling 0x15b7a80 (entry 3 of PR
#3000's table) writes its result to the supervisor's stack:
word 0 = success handle, word 1 ([rsp+8]) = the error word.
On success the error word is never read. On failure the
supervisor stores the error word back to (rsp) at
0x15d5c37 and calls the panic-message thunk 0x1680c30
(slot 0x64df6a0) with rdi/rsi = the "failed to spawn
thread" &str, rdx = rsp (pointer to the value), rcx = this
vtable, r8 = the Location 0x64004b8 (PR #3012). The thunk
saves the (value pointer, vtable) pair on its stack, builds
two fmt arguments -- message with formatter function
0x1687590, value pair with formatter function 0x1687260 --
and calls the panic formatting entry through slot
0x64df6b8. The 16-byte adapter at 0x1687260 loads the pair
and tail-calls the vtable's +0x18 method with (value
pointer, formatter): the Debug body above is what renders
the error inside the panic message. If unwinding passes
through the supervisor instead, its cleanup pad at
0x15d5c8f drops the stack error value by a direct call to
0x15be1a0 -- the drop body this vtable names. Seven bodies
call that drop body directly (7 sites), the write body and
the supervisor among them.

**Mesh with the write body.** The write body 0x1533d60
(PR #3012) produces values of this exact encoding: 0 on
success (not an error value), (errno << 32) | 2 for an OS
error (tag 2), and the bare address of the static message
datum 0x6400488 when write(2) returns 0 (tag 0); its EINTR
path drops a value of this type via 0x15be1a0. The
vtable's method reads the same three tags, and its tag-0
arm dereferences statics of the 0x6400488 layout. The
write body never references the vtable; the connection is
the shared encoding and the shared drop body.

## Evidence

9 bodies pinned by FDE extent and sha256;
`tools/error_vtable.py` re-derives every pin, the vtable
decode, the method resolution, both censuses, the jump
table and the string records from the materialized
artifact, and `tests/test_error_vtable.py` passes with no
skips. The error_drop, write_body, spawn_supervisor and
panic_msg_thunk hashes match PR #3012 / PR #3000 exactly;
no pin of either is contradicted.

## Limitations

No symbol names the vtable, the method body or the value
type; the Debug identity rests on the pinned byte evidence
(formatter argument, debug-struct names, field names, the
shared tag dispatch), not on symbol metadata. The other
31 vtables sharing the method stub are recorded by base,
drop target, size and align only; which concrete values
each tags is out of scope. The five direct drop callers
outside the write body and the supervisor are recorded by
site and body only. The spawn sibling result layout is
described from the supervisor's reads of its own stack
frame. The source-level name of the write body's
monomorphised std routine remains unpinned, as in
PR #3012.
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--write', action='store_true')
    args = ap.parse_args()
    data = TARGET.read_bytes()
    require(len(data) == SIZE
            and hashlib.sha256(data).hexdigest() == SHA,
            'artifact digest mismatch')
    records = analyze(data)
    if args.write:
        write_packet(records)
    print(json.dumps(records, indent=1, sort_keys=True))


if __name__ == '__main__':
    main()
