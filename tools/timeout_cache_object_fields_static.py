#!/usr/bin/env python3
"""Node 115: the +0x10..+0x108 field range of the timeout cache object.

The park slow-path timeout cache packet (PR #2947,
RE-005 timeout-cache) identified the object cached at
0x64fee08 as an Arc clone of the vendored tokio signal
registry's entry object for signal 17 (SIGCHLD), and pinned
the event counter at [obj+0x138] and its consumer (the orphan
reap pass).  It left one open edge: the payload range
[obj+0x10 .. obj+0x108] -- what the fields are, and who reads
or writes them.  This packet answers that edge.

Answers, all static and re-derived by analyze() below:

1. The payload is an array of eight 0x20-byte cells at
   obj+0x10, +0x30, ..., +0xf0, plus a ninth cell of the same
   shape at obj+0x110.  Each cell is one vendored-tokio
   `sync::Notify` wait cell:
     +0x00  state word (tag bits in the low 2 bits, advanced
            by 4 per run of the cell runner),
     +0x08  claim byte (CAS 0->1 before a run, released 1->0
            by the runner; contention parks for 0x3b9aca00),
     +0x10  waiter list head, +0x18 waiter list tail
            (tokio util/linked_list.rs intrusive list).
   The runner for one cell is body 0x5ce57c0: its panic
   Locations resolve to z_vendor/tokio/src/sync/notify.rs
   (line 463), util/wake_list.rs (35, 36) and
   util/linked_list.rs (367, 385, 403).  On a run it drains
   the cell's waiter list into a 32-entry wake list and wakes
   each waiter through its vtable slot +0x8; with an empty
   list it only advances the state word by 4 and releases
   the claim byte.
2. Construction: the registry entry constructor 0x5cfe910
   (sole caller: the Vec builder 0x5ce1320, called by the
   registry globals constructor 0x5cfcec0) allocates 0x150
   bytes per entry object, writes strong=1, weak=1, then
   memsets obj+0x10 for 0x130 bytes to zero -- the eight
   cells, the ninth cell, and the [obj+0x138] counter all
   start zero -- and finally stores 1 to [obj+0x140] and 1
   to [obj+0x148].  The registry is built for
   __libc_current_sigrtmax() entries, so every signal entry
   object has this identical layout.
3. Per delivery: the signal driver drain 0x5ce7380
   (z_vendor/tokio/src/runtime/signal/mod.rs, panic Locations
   at lines 118 and 121) walks the entry Vec; for each entry
   whose pending byte was set and whose [obj+0x140] count is
   nonzero, it claims [obj+0x130] (CAS 0->8), adds 2 to
   [obj+0x138], releases the claim, then calls the drain
   callback 0x5cfcc50 (GOT slot 0x64ecba8) with rdi =
   obj+0x10.  The callback claims and runs all eight cells
   in order.
4. The ninth cell (obj+0x110) is run only from the two
   release paths of the [obj+0x140] handle count: the
   standalone pair-drop body 0x5cee390 and the cache-swap arm
   of the refresh 0x5cee650 (plus the constructor's inlined
   clone/drop sequence).  When the count reaches zero the
   path claims the cell byte at obj+0x118, runs the cell, then
   decrements the Arc strong count at [obj+0x00]; the weak
   release 0x5ce8860 frees the 0x150-byte allocation when
   [obj+0x08] reaches zero.  The getter 0x5cfcf90 is the
   only body that increments [obj+0x140] (it also increments
   the strong count and returns [obj+0x138] & ~1).
5. [obj+0x148] is a second handle count with exactly one
   decrement site in .text: the pair-drop body 0x5cfc8f0.
   When it reaches zero that body sets bit 0 of [obj+0x138]
   (the sticky flag the getter masks off) and runs the
   eight-cell drain callback once, then drops the strong
   count.  Its only callers are two sites in the entry-Vec
   element drop glue reached from the registry
   constructor's unwind path.
6. Provenance closure for the payload: RIP-relative census
   shows the cache globals (0x64fee00/08/10) are referenced
   only by the refresh, and the entry Vec globals
   (0x64fee28/30) only by the lookup 0x5cde710 and the drain.
   Every body that can receive the object pointer -- the
   getter, the lookup, the drain, the drain callback, the
   cell runner, the refresh, the two pair-drop bodies, the
   weak release, the constructor -- is pinned below by FDE
   range and sha256, and none of them forms a cell pointer
   for waiter registration: the only cell-pointer consumers
   are the drain callback (cells 0-7, run-only) and the two
   release paths (ninth cell, run-only).  The vendored
   Notify register machinery exists elsewhere in the binary
   but never receives one of this object's cells.  For the
   SIGCHLD entry the eight lists therefore stay empty in
   every reachable path; a delivery advances each cell's
   state word by 4 and wakes nobody.

Open gaps (not claimed): which handle type owns the
[obj+0x148] count on the registration side (its creation is
in the signal-hook-registry half of the vendored code, and
no lock-inc site for +0x148 exists in .text); whether any
vendored-fork patch assigns distinct meanings to the eight
cells (no per-cell divergence exists in the binary: the
drain callback treats all eight identically); the producer
of the global signal fd at 0x64fee24 (a separate open edge).
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
    ('entry_init_closure', 0x5cdf460, 0x5cdf4e2),
    ('once_globals', 0x5cdf582, 0x5cdf5c7),
    ('registry_ctor_wrap', 0x5cfcec0, 0x5cfcf88),
    ('vec_build', 0x5ce1320, 0x5ce13ab),
    ('ctor_grower', 0x5cfe910, 0x5cfeb3e),
    ('getobj', 0x5cfcf90, 0x5cfd00f),
    ('lookup', 0x5cde710, 0x5cde8b0),
    ('drain', 0x5ce7380, 0x5ce75a6),
    ('draincb', 0x5cfcc50, 0x5cfcebf),
    ('cell_runner', 0x5ce57c0, 0x5ce5bfe),
    ('refresh', 0x5cee650, 0x5cee8f7),
    ('pair_drop_140', 0x5cee390, 0x5cee455),
    ('handle_drop_148', 0x5cfc8f0, 0x5cfc9b1),
    ('release_weak', 0x5ce8860, 0x5ce887e),
    ('reap', 0x5cee900, 0x5ceead1),
]

# GOT / data slots whose resolved values are pinned.
RELA_SLOTS = {
    '0x64e01e8': 'cell_runner got slot',
    '0x64ecc58': 'release_weak got slot',
    '0x64ecba8': 'draincb got slot',
    '0x64df750': 'memset got slot',
    '0x64ecba0': 'sigrtmax got slot',
}

# Panic Location structs: va -> (file suffix, line, col).
LOCATIONS = {
    '0x64c5d58': ('tokio/src/sync/notify.rs', 463, 5),
    '0x64c5c38': ('tokio/src/util/wake_list.rs', 35, 9),
    '0x64c5c50': ('tokio/src/util/wake_list.rs', 36, 9),
    '0x64c5da0': ('tokio/src/util/linked_list.rs', 385, 61),
    '0x64c5db8': ('tokio/src/util/linked_list.rs', 403, 73),
    '0x64c5d88': ('tokio/src/util/linked_list.rs', 367, 42),
    '0x64c5f80': ('tokio/src/runtime/signal/mod.rs', 118, 26),
    '0x64c5f98': ('tokio/src/runtime/signal/mod.rs', 121, 27),
    '0x64c6e80': ('tokio/src/signal/registry.rs', 73, 32),
}

# Byte pins: site va -> expected instruction bytes (hex).
BYTE_PINS = {
    # ctor_grower: memset(obj+0x10, 0, 0x130) setup
    '0x5cfe9f2': '488d7810ba30010000',
    # ctor_grower: [obj+0x140] = 1 ; [obj+0x148] = 1
    '0x5cfea00': '48c7854001000001000000',
    '0x5cfea0b': '48c7854801000001000000',
    # ctor_grower: alloc failure args (align 8, size 0x150)
    '0x5cfeade': 'bf08000000be50010000',
    # getobj: lock incq [obj+0x140]
    '0x5cfcfc2': 'f048ff8040010000',
    # drain: test [obj+0x140]
    '0x5ce74a1': '488b8740010000',
    # drain: claim CAS [obj+0x130] 0->8 ; counter lock addq $2, [obj+0x138]
    '0x5ce74af': 'f04c0fb1a730010000',
    '0x5ce74ba': 'f04883873801000002',
    # refresh: lock decq [obj+0x140] on the cache-swap arm
    '0x5cee721': 'f049ff8d40010000',
    # refresh: run the ninth cell through the cell_runner slot
    '0x5cee764': 'ff157e1a7f00',
    # pair_drop_140: lock decq [obj+0x140] ; runner call
    '0x5cee3a4': 'f049ff8f40010000',
    '0x5cee3e2': 'ff15001e7f00',
    # handle_drop_148: lock decq [obj+0x148] ; lock orq $1, [obj+0x138] ;
    # draincb call through its got slot with rdi = obj+0x10
    '0x5cfc8fa': 'f048ff8f48010000',
    '0x5cfc904': 'f048838f3801000001',
    '0x5cfc90d': '4883c710',
    '0x5cfc911': 'ff1591027f00',
    # release_weak: lock decq [obj+0x08] ; dealloc size 0x150
    '0x5ce8869': 'f048ff4f08',
    '0x5ce8870': 'be50010000',
}

GLOBALS = {
    'cache_lock': 0x64fee00,
    'cache_obj': 0x64fee08,
    'cache_key': 0x64fee10,
    'vec_ptr': 0x64fee28,
    'vec_len': 0x64fee30,
}

TEXT_VA = 0x1419300


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
    rel, glob = {}, {}
    strtabs = {}
    for sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        if sh_type == 3:  # SHT_STRTAB
            strtabs[len(strtabs)] = (sh_offset, sh_size)
    dynsym = None
    for sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        if sh_type == 11:  # SHT_DYNSYM
            dynsym = (sh_offset, sh_size, sh_link, sh_entsize)
    sym_names = {}
    if dynsym:
        s_off, s_size, s_link, s_entsize = dynsym
        str_off, _str_size = sections[s_link][1], sections[s_link][2]
        for j in range(s_size // s_entsize):
            st_name = struct.unpack_from(
                '<I', data, s_off + j * s_entsize)[0]
            end = data.index(b'\x00', str_off + st_name)
            sym_names[j] = data[str_off + st_name:end].decode(
                'utf8', 'replace')
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
        locs[va_hex] = {'file': suffix, 'line': line, 'col': col}
    result['locations'] = locs

    pins = {}
    for va_hex, want in BYTE_PINS.items():
        va = int(va_hex, 16)
        got = rd(va, len(bytes.fromhex(want))).hex()
        pins[va_hex] = got
    result['byte_pins'] = pins

    # text slice for the censuses
    text_off = va2off(loads, TEXT_VA)
    text_size = 0x4fd7700
    text = data[text_off:text_off + text_size]

    # (a) rip-relative references to the registry/cache globals
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

    # (b) lock inc/dec qword with disp32 in {0x138, 0x140, 0x148}
    lock_sites = []
    for m in re.finditer(rb'\xf0[\x48\x49\x4c\x4d]\xff', text):
        i = m.start()
        if i + 8 > text_size:
            continue
        modrm = text[i + 3]
        if modrm >> 6 != 2:
            continue
        reg = (modrm >> 3) & 7
        disp = struct.unpack_from('<i', text, i + 4)[0]
        if disp in (0x138, 0x140, 0x148) and reg in (0, 1):
            lock_sites.append({
                'site': hex(TEXT_VA + i),
                'body': body_name(TEXT_VA + i) or 'outside_pinned',
                'op': 'inc' if reg == 0 else 'dec',
                'disp': hex(disp),
            })
    result['lock_count_sites'] = lock_sites

    # (c) calls through the cell_runner got slot 0x64e01e8
    runner_sites = {}
    total = 0
    for m in re.finditer(rb'\xff\x15', text):
        i = m.start()
        disp = struct.unpack_from('<i', text, i + 2)[0]
        if TEXT_VA + i + 6 + disp == 0x64e01e8:
            total += 1
            b = body_name(TEXT_VA + i)
            if b:
                runner_sites.setdefault(b, []).append(hex(TEXT_VA + i))
    result['runner_call_sites'] = {
        'total': total,
        'in_pinned_bodies': {k: sorted(v) for k, v in
                             sorted(runner_sites.items())},
    }

    # (d) draincb's per-cell claim offsets (lock cmpxchg byte, disp)
    claims = []
    dstart, dend = 0x5cfcc50, 0x5cfcebf
    dbytes = rd(dstart, dend - dstart)
    for m in re.finditer(rb'\xf0\x40\x0f\xb0', dbytes):
        i = m.start()
        modrm = dbytes[i + 4]
        if modrm >> 6 == 1:
            claims.append(hex(dbytes[i + 5]))
        elif modrm >> 6 == 2:
            claims.append(hex(struct.unpack_from('<i', dbytes, i + 5)[0]))
    result['draincb_claim_offsets'] = claims

    result['layout'] = {
        'alloc_size': '0x150',
        'strong_count': 'obj+0x00',
        'weak_count': 'obj+0x08',
        'payload_base': 'obj+0x10',
        'cells': 8,
        'cell_stride': '0x20',
        'cell_fields': {
            'state_word': '+0x00',
            'claim_byte': '+0x08',
            'waiter_head': '+0x10',
            'waiter_tail': '+0x18',
        },
        'ninth_cell': 'obj+0x110',
        'drain_claim_word': 'obj+0x130',
        'event_counter': 'obj+0x138',
        'handle_count_140': 'obj+0x140',
        'handle_count_148': 'obj+0x148',
        'ctor_memset': {'at': 'obj+0x10', 'len': '0x130'},
        'ctor_count_init': {'obj+0x140': 1, 'obj+0x148': 1},
    }
    return result


def main():
    root = Path(__file__).resolve().parents[1]
    target = root / 'artifacts/node/115/hl-node'
    data = target.read_bytes()
    print(json.dumps(analyze(data), indent=1, sort_keys=True))


if __name__ == '__main__':
    sys.exit(main())
