#!/usr/bin/env python3
"""Node 115: the owner handle of the timeout cache object's [obj+0x148] count.

The timeout-cache object-fields packet (#2953,
RE-005 timeout-cache-object-fields) pinned the registry entry
object at 0x64fee08 (Arc counts +0x00/+0x08, nine vendored-tokio
Notify cells, claim word +0x130, event counter +0x138, handle
counts +0x140 and +0x148) and left one open edge: [obj+0x148]
is a second handle count with exactly one decrement site in
.text (the drop body 0x5cfc8f0) and no lock-inc site anywhere,
so which handle type owns it on the registration side -- and
which registration call creates it -- stayed open.  This
packet answers that edge.

Answers, all static and re-derived by analyze() below:

1. The owner is the registry entry record itself.  The
   per-signal Vec built at registry construction holds
   0x20-byte records, one per signal:
     +0x00  pointer to the entry object (the Arc pointee),
     +0x08  pending byte (atomically swapped out by the
            driver drain 0x5ce7380 before each delivery),
     +0x10  registration cell (16 bytes): the outcome of the
            lazy signal-hook-registry registration, stored as
            a tag dword at +0x10 and a registration-id dword
            at +0x14,
     +0x18  state word of an embedded std sync::Once (the
            record's drop glue validates it against the panic
            Location std/src/sys/sync/once/futex.rs:91, whose
            message is the "invalid Once state" unreachable).
   The constructor-grower 0x5cfe910 writes exactly three
   fields per record -- the object pointer, a zero pending
   byte and the Once state word 3 -- and initialises
   [obj+0x148] to 1 in the same pass.  The count's single
   unit is therefore minted together with the record, by the
   registry construction chain itself:
   once_globals 0x5cdf582 -> globals-init closure 0x5cdf4f0 ->
   registry constructor wrapper 0x5cfcec0 -> Vec builder
   0x5ce1320 -> constructor-grower 0x5cfe910.  There is no
   per-registration clone: an extended whole-.text census of
   every lock-prefixed read-modify-write form (inc/dec,
   add/sub/or imm8/imm32, xadd, cmpxchg, register add/sub)
   with displacement 0x148 finds exactly one site, the
   decrement in 0x5cfc8f0; register-source forms cannot hide
   either, because the raw displacement bytes 48 01 00 00
   occur inside every pinned body that can hold the object
   pointer only at the constructor's init store and at that
   decrement (the two further occurrences, inside the
   registry insert body, are rsp-relative stack slots).
   (Contrast
   +0x140, which the same census shows incremented by the
   getter 0x5cfcf90 -- panic Location tokio/src/signal/
   registry.rs:73 -- and decremented by the pair-drop
   0x5cee390 and the refresh 0x5cee650: that count belongs to
   the transient lookup pair the getter hands out, not to the
   registry's own record.)

2. The record is released only by the entry-Vec drop glue
   0x5cfc9c0.  The glue walks the Vec buffer forward in
   0x20-byte strides calling the count's drop body
   0x5cfc8f0 once per record (two call sites in the glue:
   the normal loop and its own unwind loop), then frees the
   buffer.  A whole-.text direct-branch census shows the
   glue's only callers are the two construction unwind
   cleanups -- the constructor-grower's landing pad
   (0x5cfeb2b) and the Vec builder's landing pad (0x5ce1398)
   -- and the drop body's only callers are the glue's two
   sites; no .rela.dyn addend names either body.  On a
   successful construction the Vec moves into the registry
   globals OnceCell (0x64fee20) and is never dropped, so in
   every reachable non-unwind execution the [obj+0x148]
   count stays at its construction value 1 and the drop
   body's zero-transition (set the sticky bit in
   [obj+0x138], run the eight-cell drain callback once, drop
   the strong count) is dead code outside construction
   failure.

3. The registration side never touches the count.  When the
   lookup 0x5cde710 finds a record whose Once state word is
   nonzero it runs the record's once shim 0x5cdf535, which
   invokes std's once slow-path helper (GOT slot 0x64df9f0,
   body 0x5c87d50) exactly once per record; the init body it
   runs -- the cluster holds a closure form 0x5cdf460 and a
   direct form 0x5cdf630 of the same body -- calls the
   vendored
   signal-hook-registry table insert 0x5cdbf20 and stores
   only the outcome tag/id pair into the record's +0x10
   registration cell.  The globals construction likewise
   exists in a closure form (0x5cdf4f0) and a direct form
   (0x5cdf6c0); both call the same constructor wrapper.  The insert's own allocation is a
   separate 0x20-byte Arc object (counts 1/1, the globals
   pointer at +0x10, a token dword at +0x18) -- not the entry
   object.  So the creation the parent packet located "in
   the signal-hook-registry half of the vendored code" is
   the registry-construction cluster itself: the count is
   owned by the registry's per-signal entry record, a
   non-cloneable ownership token minted once per signal when
   the registry globals are built, and discharged only if
   that construction unwinds.

Open gaps (not claimed): whether the vendored fork's lazy
registration can also write the record's +0x10 cell for
signals other than the ones the lookup serves (the cell
semantics are pinned only for the lookup path); the producer
of the global signal fd at 0x64fee24 (a separate open edge,
owned by another packet).
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import sys
from pathlib import Path

TARGET_SIZE = 105896032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# (name, start, end) -- FDE (.eh_frame) ranges.
BODIES = [
    ('globals_init_closure', 0x5cdf4f0, 0x5cdf535),
    ('globals_init_direct', 0x5cdf6c0, 0x5cdf705),
    ('entry_init_direct', 0x5cdf630, 0x5cdf6b2),
    ('record_once_shim', 0x5cdf535, 0x5cdf582),
    ('entry_init_closure', 0x5cdf460, 0x5cdf4e2),
    ('once_globals', 0x5cdf582, 0x5cdf5c7),
    ('once_slow_helper', 0x5c87d50, 0x5c87f6c),
    ('reg_register', 0x5cdbf20, 0x5cdcd94),
    ('registry_ctor_wrap', 0x5cfcec0, 0x5cfcf88),
    ('vec_build', 0x5ce1320, 0x5ce13ab),
    ('ctor_grower', 0x5cfe910, 0x5cfeb3e),
    ('vec_drop_glue', 0x5cfc9c0, 0x5cfca6c),
    ('handle_drop_148', 0x5cfc8f0, 0x5cfc9b1),
    ('getobj', 0x5cfcf90, 0x5cfd00f),
    ('lookup', 0x5cde710, 0x5cde8b0),
    ('drain', 0x5ce7380, 0x5ce75a6),
    ('draincb', 0x5cfcc50, 0x5cfcebf),
    ('cell_runner', 0x5ce57c0, 0x5ce5bfe),
    ('refresh', 0x5cee650, 0x5cee8f7),
    ('pair_drop_140', 0x5cee390, 0x5cee455),
    ('pair_second_drop', 0x5cee460, 0x5cee531),
    ('release_weak', 0x5ce8860, 0x5ce887e),
    ('reap', 0x5cee900, 0x5ceead1),
]

# GOT / data slots whose resolved values are pinned.
RELA_SLOTS = {
    '0x64df9f0': 'once slow-path helper got slot',
    '0x64ecba8': 'draincb got slot',
    '0x64ecc58': 'release_weak got slot',
    '0x64e01e8': 'cell_runner got slot',
    '0x64df480': 'alloc got slot',
    '0x64df4a0': 'dealloc got slot',
}

# Panic Location structs: va -> (file suffix, line, col).
LOCATIONS = {
    '0x64c6e80': ('tokio/src/signal/registry.rs', 73, 32),
    '0x64c6fd8': ('std/src/sys/sync/once/futex.rs', 91, 18),
    '0x64c6ff0': ('tokio/src/signal/unix.rs', 28, 20),
}

# The std Once unreachable message stored at this rodata va.
ONCE_MSG_VA = 0x94dc90
ONCE_MSG = 'internal error: entered unreachable code: invalid Once state'

# Byte pins: site va -> expected instruction bytes (hex).
BYTE_PINS = {
    # ctor_grower: per-record stores (object ptr / pending byte / once word 3)
    '0x5cfe9b0': '49892f',
    '0x5cfe9b3': '41c6470800',
    '0x5cfe9b8': '41c7471803000000',
    # ctor_grower: [obj+0x140] = 1 ; [obj+0x148] = 1
    '0x5cfea00': '48c7854001000001000000',
    '0x5cfea0b': '48c7854801000001000000',
    # ctor_grower: unwind pad calls the vec drop glue
    '0x5cfeb2b': 'e890deffff',
    # vec_build: call ctor_grower ; unwind pad calls the vec drop glue
    '0x5ce132d': 'e8ded50100',
    '0x5ce1398': 'e823b60100',
    # registry_ctor_wrap: call vec_build
    '0x5cfcef1': 'e82a44feff',
    # globals_init_closure: call registry_ctor_wrap
    '0x5cdf50c': 'e8afd90100',
    # vec_drop_glue: buffer/len loads, element stride, two drop-body calls,
    # dealloc tail jump
    '0x5cfc9ce': '488b5f08',
    '0x5cfc9d2': '4c8b6f10',
    '0x5cfc9e6': '4c8d6720',
    '0x5cfc9ed': 'e8fefeff ff'.replace(' ', ''),
    '0x5cfca3d': 'e8aefeff ff'.replace(' ', ''),
    '0x5cfca16': 'ff25842a7e00',
    # handle_drop_148: lock decq [obj+0x148] ; lock orq $1, [obj+0x138] ;
    # draincb call ; once-state load and range check ; unreachable call
    '0x5cfc8fa': 'f048ff8f48010000',
    '0x5cfc904': 'f048838f3801000001',
    '0x5cfc90d': '4883c710',
    '0x5cfc911': 'ff1591027f00',
    '0x5cfc929': '8b4318',
    '0x5cfc92c': '8d48fe',
    '0x5cfc953': 'ff155f2d7e00',
    # getobj: lock incq [obj+0x140]
    '0x5cfcfc2': 'f048ff8040010000',
    # pair_drop_140 / refresh: lock decq [obj+0x140]
    '0x5cee3a4': 'f049ff8f40010000',
    '0x5cee721': 'f049ff8d40010000',
    # lookup: vec_len bounds cmp ; record once-word read ; cell state read ;
    # once-shim call ; getobj call
    '0x5cde7bc': '483b056d068200',
    '0x5cde7d4': '8b440118',
    '0x5cde7dc': '418b4610',
    '0x5cde869': 'e8c70c0000',
    '0x5cde802': 'e889e70100',
    # record_once_shim: state test ; once slow-path helper call
    '0x5cdf535': '8b4708',
    '0x5cdf577': 'ff1573048000',
    # entry_init_closure: registry insert call ; cell tag/id stores
    '0x5cdf48c': 'e88fcaff ff'.replace(' ', ''),
    '0x5cdf4c6': '892b',
    '0x5cdf4c8': '44897304',
    # reg_register: its own 0x20-byte Arc object (strong=1, fields)
    '0x5cdbf83': '48c70001000000',
    '0x5cdbf92': '4c897810',
    '0x5cdbf96': '895818',
    # drain: pending byte atomic swap on the record
    '0x5ce7496': '418606',
    # entry_init_direct: registry insert call ; cell tag/id stores
    '0x5cdf65c': 'e8bfc8ff ff'.replace(' ', ''),
    '0x5cdf696': '892b',
    '0x5cdf698': '44897304',
    # globals_init_direct: call registry_ctor_wrap
    '0x5cdf6dc': 'e8dfd70100',
    # reg_register: the only other disp-0x148 byte patterns in the pinned
    # set are rsp-relative stack slots (SIB byte 0x24)
    '0x5cdc65c': '4889842448010000',
    '0x5cdc6cc': '488db42448010000',
}

GLOBALS = {
    'vec_ptr': 0x64fee28,
    'vec_len': 0x64fee30,
}

# Bodies whose direct callers/callees are pinned by census.
CALL_TARGETS = {
    'handle_drop_148': 0x5cfc8f0,
    'vec_drop_glue': 0x5cfc9c0,
    'ctor_grower': 0x5cfe910,
    'vec_build': 0x5ce1320,
    'registry_ctor_wrap': 0x5cfcec0,
    'getobj': 0x5cfcf90,
    'pair_drop_140': 0x5cee390,
    'entry_init_closure': 0x5cdf460,
    'entry_init_direct': 0x5cdf630,
    'globals_init_direct': 0x5cdf6c0,
    'record_once_shim': 0x5cdf535,
    'once_globals': 0x5cdf582,
    'reg_register': 0x5cdbf20,
}

TEXT_VA = 0x1419300
TEXT_SIZE = 0x4fd7700

COUNT_DISPS = (0x138, 0x140, 0x148)


def pt_loads(data):
    phoff = struct.unpack_from('<Q', data, 0x20)[0]
    phentsize = struct.unpack_from('<H', data, 0x36)[0]
    phnum = struct.unpack_from('<H', data, 0x38)[0]
    loads = []
    for i in range(phnum):
        off = phoff + i * phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        if p_type != 1:
            continue
        p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from(
            '<QQQQ', data, off + 8)
        loads.append((p_vaddr, p_offset, p_filesz))
    return loads


def va2off(loads, va):
    for v, o, s in loads:
        if v <= va < v + s:
            return o + (va - v)
    raise ValueError(hex(va))


def rela_map(data):
    """Return ({offset: addend} for RELATIVE, {offset: name} for GLOB_DAT)."""
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    shnum = struct.unpack_from('<H', data, 0x3c)[0]
    sections = []
    for i in range(shnum):
        off = shoff + i * shentsize
        sh_type = struct.unpack_from('<I', data, off + 4)[0]
        sh_offset, sh_size = struct.unpack_from('<QQ', data, off + 24)
        sh_link = struct.unpack_from('<I', data, off + 40)[0]
        sh_entsize = struct.unpack_from('<Q', data, off + 56)[0]
        sections.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))
    dynsym = None
    for sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        if sh_type == 11:  # SHT_DYNSYM
            dynsym = (sh_offset, sh_size, sh_link, sh_entsize)
    sym_names = {}
    if dynsym:
        s_off, s_size, s_link, s_entsize = dynsym
        str_off = sections[s_link][1]
        for j in range(s_size // s_entsize):
            st_name = struct.unpack_from(
                '<I', data, s_off + j * s_entsize)[0]
            end = data.index(b'\x00', str_off + st_name)
            sym_names[j] = data[str_off + st_name:end].decode(
                'utf8', 'replace')
    rel, glob = {}, {}
    for sh_type, sh_offset, sh_size, _link, sh_entsize in sections:
        if sh_type != 4:  # SHT_RELA
            continue
        for j in range(sh_size // sh_entsize):
            r_offset, r_info, r_addend = struct.unpack_from(
                '<QqQ', data, sh_offset + j * sh_entsize)
            r_type = r_info & 0xffffffff
            r_sym = r_info >> 32
            if r_type == 8:  # R_X86_64_RELATIVE
                rel[r_offset] = r_addend
            elif r_type == 6:  # R_X86_64_GLOB_DAT
                glob[r_offset] = sym_names.get(r_sym, '')
    return rel, glob


def analyze(data):
    result = {}
    result['artifact'] = {
        'bytes': len(data),
        'sha256': hashlib.sha256(data).hexdigest(),
    }
    loads = pt_loads(data)
    result['pt_loads'] = [
        {'va': hex(v), 'off': hex(o), 'size': hex(s)} for v, o, s in loads]

    def rd(va, n):
        o = va2off(loads, va)
        return data[o:o + n]

    def body_name(va):
        for name, s, e in BODIES:
            if s <= va < e:
                return name
        return None

    bodies = {}
    for name, s, e in BODIES:
        b = rd(s, e - s)
        bodies[name] = {
            'va': hex(s),
            'end': hex(e),
            'size': e - s,
            'sha256': hashlib.sha256(b).hexdigest(),
        }
    result['bodies'] = bodies

    rel, glob = rela_map(data)
    slots = {}
    for va_hex in RELA_SLOTS:
        va = int(va_hex, 16)
        if va in rel:
            slots[va_hex] = {'kind': 'relative', 'target': hex(rel[va])}
        elif va in glob:
            slots[va_hex] = {'kind': 'glob_dat', 'name': glob[va]}
        else:
            slots[va_hex] = {'kind': 'missing'}
    result['slots'] = slots

    def qword(va):
        if va in rel:
            return rel[va]
        return struct.unpack('<Q', rd(va, 8))[0]

    locs = {}
    for va_hex in LOCATIONS:
        va = int(va_hex, 16)
        fp, fl = qword(va), qword(va + 8)
        line, col = struct.unpack_from('<II', rd(va + 16, 8))
        path = rd(fp, fl).decode('utf8', 'replace')
        suffix = path.split('z_vendor/')[-1]
        suffix = suffix.split('/library/')[-1]
        locs[va_hex] = {'file': suffix, 'line': line, 'col': col}
    result['locations'] = locs

    result['once_state_message'] = rd(
        ONCE_MSG_VA, len(ONCE_MSG)).decode('utf8', 'replace')

    pins = {}
    for va_hex, want in BYTE_PINS.items():
        va = int(va_hex, 16)
        got = rd(va, len(bytes.fromhex(want))).hex()
        pins[va_hex] = got
    result['byte_pins'] = pins

    # text slice for the censuses
    text_off = va2off(loads, TEXT_VA)
    text = data[text_off:text_off + TEXT_SIZE]

    # (a) rip-relative references to the entry-Vec globals
    grefs = {}
    pats = [
        (re.compile(rb'[\x48\x49\x4c\x4d][\x8b\x8d\x89\x39\x3b]'
                    rb'[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]'), 7),
        (re.compile(rb'\xff[\x15\x25]'), 6),
        (re.compile(rb'\xf0\x0f\xb0[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]'), 7),
    ]
    targets = {v: k for k, v in GLOBALS.items()}
    for pat, ln in pats:
        for m in pat.finditer(text):
            i = m.start()
            disp = struct.unpack_from('<i', text, i + ln - 4)[0]
            tgt = TEXT_VA + i + ln + disp
            if tgt in targets:
                name = targets[tgt]
                b = body_name(TEXT_VA + i) or 'outside_pinned'
                grefs.setdefault(name, {}).setdefault(b, []).append(
                    hex(TEXT_VA + i))
    result['global_refs'] = {
        k: {b: sorted(sites) for b, sites in sorted(v.items())}
        for k, v in sorted(grefs.items())}

    # (b) direct call/jump census for the pinned control-flow targets
    want = {v: k for k, v in CALL_TARGETS.items()}
    call_sites = {k: [] for k in CALL_TARGETS}
    for m in re.finditer(rb'[\xe8\xe9]', text):
        i = m.start()
        rel32 = struct.unpack_from('<i', text, i + 1)[0]
        tgt = TEXT_VA + i + 5 + rel32
        if tgt in want:
            call_sites[want[tgt]].append({
                'site': hex(TEXT_VA + i),
                'kind': 'call' if text[i] == 0xe8 else 'jmp',
                'body': body_name(TEXT_VA + i) or 'outside_pinned',
            })
    result['call_sites'] = {
        k: sorted(v, key=lambda s: int(s['site'], 16))
        for k, v in sorted(call_sites.items())}

    # (c) extended lock-prefixed RMW census for the count displacements:
    #     inc/dec (FF /0,/1), imm groups (83/81 /0,/1,/4,/5,/7),
    #     register add/sub/xor/cmp (01/03/29/2B/31/3B), xadd (0F C1),
    #     cmpxchg (0F B1) -- all with mod=2 (disp32) addressing.
    rmw = []
    fam = [
        (re.compile(rb'\xf0[\x48\x49\x4c\x4d]\xff'), 3, 'incdec'),
        (re.compile(rb'\xf0[\x48\x49\x4c\x4d]\x83'), 3, 'imm8'),
        (re.compile(rb'\xf0[\x48\x49\x4c\x4d]\x81'), 3, 'imm32'),
        (re.compile(rb'\xf0[\x48\x49\x4c\x4d]\x0f\xc1'), 4, 'xadd'),
        (re.compile(rb'\xf0[\x48\x49\x4c\x4d]\x0f\xb1'), 4, 'cmpxchg'),
    ]
    for pat, moff, kind in fam:
        for m in pat.finditer(text):
            i = m.start()
            modrm = text[i + moff]
            if modrm >> 6 != 2:
                continue
            disp = struct.unpack_from('<i', text, i + moff + 1)[0]
            if disp in COUNT_DISPS:
                rmw.append({
                    'site': hex(TEXT_VA + i),
                    'body': body_name(TEXT_VA + i) or 'outside_pinned',
                    'kind': kind,
                    'reg': (modrm >> 3) & 7,
                    'disp': hex(disp),
                })
    result['lock_rmw_sites'] = sorted(
        rmw, key=lambda s: (int(s['disp'], 16), int(s['site'], 16)))

    # (d) raw disp-0x148 byte-pattern scan inside every pinned body:
    #     catches any addressing form (incl. register-source lock ops)
    #     in the bodies that can hold the entry-object pointer.
    pat148 = bytes.fromhex('48010000')
    hits148 = {}
    for name, s, e in BODIES:
        b = rd(s, e - s)
        found = []
        i = 0
        while True:
            k = b.find(pat148, i)
            if k < 0:
                break
            found.append(hex(s + k))
            i = k + 1
        if found:
            hits148[name] = found
    result['disp148_pattern_hits'] = hits148

    # (e) .rela.dyn addends naming the drop bodies / glue / shim
    watched = {0x5cfc8f0, 0x5cfc9c0, 0x5cdf535}
    rela_refs = sorted(
        hex(off) for off, add in rel.items() if add in watched)
    result['rela_refs_to_drop_bodies'] = rela_refs

    result['layout'] = {
        'entry_object': {
            'alloc_size': '0x150',
            'strong_count': 'obj+0x00',
            'weak_count': 'obj+0x08',
            'notify_cells': 'obj+0x10..+0x110 (8) + obj+0x110 (ninth)',
            'drain_claim_word': 'obj+0x130',
            'event_counter': 'obj+0x138',
            'lookup_handle_count': 'obj+0x140',
            'record_handle_count': 'obj+0x148',
            'count148_ctor_init': 1,
        },
        'entry_record': {
            'size': '0x20',
            'object_ptr': 'record+0x00',
            'pending_byte': 'record+0x08',
            'registration_cell': 'record+0x10 (tag dword +0x10, id dword +0x14)',
            'once_state_word': 'record+0x18',
            'once_state_ctor_init': 3,
        },
        'count148': {
            'owner': 'the registry entry record (entry-Vec element)',
            'created_by': 'ctor_grower inside registry construction '
                          '(once_globals -> globals_init_closure -> '
                          'registry_ctor_wrap -> vec_build -> ctor_grower)',
            'increment_sites': 0,
            'decrement_sites': ['handle_drop_148'],
            'release_path': 'vec_drop_glue, reachable only from the '
                            'ctor_grower and vec_build unwind pads',
        },
    }
    return result


def main():
    root = Path(__file__).resolve().parents[1]
    target = root / 'artifacts/node/115/hl-node'
    data = target.read_bytes()
    print(json.dumps(analyze(data), indent=1, sort_keys=True))


if __name__ == '__main__':
    sys.exit(main())
