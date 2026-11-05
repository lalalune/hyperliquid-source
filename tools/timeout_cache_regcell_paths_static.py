#!/usr/bin/env python3
"""Node 115: who can write the timeout-cache registry record's
+0x10 registration cell -- is there a path other than the lookup's?

The timeout-cache packets (#2953,
RE-005-node115-timeout-cache-object-fields, and #2964,
RE-005-node115-timeout-cache-count148-owner) pinned the
vendored tokio signal registry whose globals live in the
OnceCell at 0x64fee20: a per-signal Vec of 0x20-byte entry
records (object pointer +0x00, pending byte +0x08,
registration cell +0x10 -- tag dword +0x10, registration-id
dword +0x14 -- and an embedded std sync::Once state word
+0x18).  #2964 pinned the cell's semantics for the lookup
path only and left the edge open: can the vendored fork's
lazy registration write a record's +0x10 cell on any path
other than the lookup's, and if so, by which call path?

Answer, re-derived by analyze() below: no.  The cell stores
exist only in the two entry-init bodies, those bodies are
reachable only through one std-once vtable, the vtable is
materialised only by the record's once shim, and the shim's
only caller in .text is the lookup.  In detail:

1. The cell stores.  The tag/id store pair
   (mov [rbx],ebp ; mov [rbx+4],r14d -- rbx = record+0x10)
   exists at exactly two instruction sites in the registry
   cluster, in entry_init_closure 0x5cdf460 (0x5cdf4c6) and
   entry_init_direct 0x5cdf630 (0x5cdf696).  A whole-.text
   scan for the pair's byte pattern finds one further site,
   0x5d08ac6, inside an unrelated UTF-8 string body
   (0x5d08910) that stores a four-dword result into its
   caller's out-struct and never touches the registry.

2. Reachability of the entry-init bodies.  Neither body has
   a direct branch caller anywhere in .text.  Their only
   data references in the whole ELF are two R_X86_64_RELATIVE
   addends -- the method slots +0x18 (direct form) and +0x20
   (closure form) of the closure vtable at 0x64c57a0 (the
   vtable's other words are 0, 8, 8).  A RIP-relative
   reference census finds exactly one materialisation of
   that vtable's address: the lea at 0x5cdf566 inside
   record_once_shim 0x5cdf535, which passes it to std's once
   slow-path helper (GOT slot 0x64df9f0, body 0x5c87d50)
   together with the caller Location std/src/sync/once.rs:219
   col 20 (the struct at 0x64c5788).  The helper invokes the
   closure through the vtable; there is no other consumer.

3. The shim's caller set.  A whole-.text direct-branch
   census finds exactly one call site to record_once_shim:
   lookup 0x5cde710 at 0x5cde869, which passes
   record+0x10 as the shim's base (the shim reads the Once
   word through +0x8 of that base, i.e. record+0x18).  The
   shim has no relocation, RIP-relative or raw references.

4. The value source.  The (tag, id) pair the entry-init
   bodies store comes from the vendored signal-hook-registry
   insert reg_register 0x5cdbf20, whose only direct callers
   in .text are the two entry-init bodies (0x5cdf48c,
   0x5cdf65c) and which has no data references at all -- so
   no other path can even obtain a fresh pair to store.
   reg_register never receives a record pointer: its
   disp-0x10/0x14 stores (store census) go to its own fresh
   Arc allocation (0x5cdbf92), its own table nodes/buffers
   and the stack.  After storing, each entry-init body drops
   the returned registration handle through the shared drop
   glue 0x5cdf710.

5. Record pointers are confined to the lookup path.  A
   record pointer can only be computed from the registry
   Vec globals (0x64fee28 ptr / 0x64fee30 len); the
   RIP-relative census for those globals finds only lookup
   and the driver drain 0x5ce7380.  A disp-0x10/0x14 store
   census over every body that can hold a record pointer
   (lookup, drain, driver_init 0x5ce71f0, ctor_grower
   0x5cfe910, vec_drop_glue 0x5cfc9c0, handle_drop_148
   0x5cfc8f0, record_once_shim, the two entry-init bodies,
   reg_register) finds no store to a record cell outside
   the entry-init pair: lookup's and drain's only hits are
   stack spills, the grower writes the record's +0x00/+0x08/
   +0x18 fields at construction (and a caller out-struct at
   0x5cfeaba) but never the cell, driver_init assembles its
   own out-struct, and the glue/drop bodies have no such
   stores at all.

6. The surrounding surface agrees.  The lookup's only
   direct caller is the park slow-path refresh 0x5cee650
   (#2947); once_globals 0x5cdf582 -- the globals OnceCell
   shim, twin of the record shim, passing the globals-init
   vtable 0x64c5760 to the same helper slot -- is called
   from lookup (twice), drain and driver_init, and only
   constructs the globals.  Neighbouring cluster bodies
   that drop registration handles (0x5cdfa50, 0x5cdfc90,
   0x5cdfe50) reference neither the Vec globals,
   reg_register, the shim nor the vtable.

Scope: the claim is about the registry whose OnceCell is
0x64fee20 (the #2953/#2964 registry) in the node 115
artifact.  The censuses cover direct branches, RIP-relative
materialisations, .rela.dyn addends and raw absolute qwords;
a code pointer copied out of the vtable at runtime would
leave no static trace, but the vtable itself is loaded only
by the shim, so any such copy would still originate on the
lookup path.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

TARGET_SIZE = 105896032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# (name, FDE start) -- body end is the next FDE start.
BODY_STARTS = [
    ('lookup', 0x5cde710),
    ('driver_init', 0x5ce71f0),
    ('drain', 0x5ce7380),
    ('refresh', 0x5cee650),
    ('getobj', 0x5cfcf90),
    ('reg_register', 0x5cdbf20),
    ('entry_init_closure', 0x5cdf460),
    ('globals_init_closure', 0x5cdf4f0),
    ('record_once_shim', 0x5cdf535),
    ('once_globals', 0x5cdf582),
    ('entry_init_direct', 0x5cdf630),
    ('globals_init_direct', 0x5cdf6c0),
    ('reg_handle_drop', 0x5cdf710),
    ('once_slow_helper', 0x5c87d50),
    ('registry_ctor_wrap', 0x5cfcec0),
    ('vec_build', 0x5ce1320),
    ('ctor_grower', 0x5cfe910),
    ('vec_drop_glue', 0x5cfc9c0),
    ('handle_drop_148', 0x5cfc8f0),
    ('utf8_result_body', 0x5d08910),
]

# GOT / data slots whose resolved values are pinned.
RELA_SLOTS = {
    '0x64df9f0': 'std once slow-path helper got slot',
}

# Panic / caller Location structs: va -> (file suffix, line, col).
LOCATIONS = {
    '0x64c5788': ('std/src/sync/once.rs', 219, 20),
    '0x64c57c8': ('std/src/sync/once.rs', 219, 49),
}

# Byte pins: site va -> expected instruction bytes (hex).
BYTE_PINS = {
    # lookup: vec_len bounds cmp ; record once-word load ;
    # getobj call ; cell tag load ; cell id load ; shim call
    '0x5cde7bc': '483b056d068200',
    '0x5cde7d4': '8b440118',
    '0x5cde802': 'e889e70100',
    '0x5cde7dc': '418b4610',
    '0x5cde82f': '418b4614',
    '0x5cde869': 'e8c70c0000',
    # record_once_shim: once-word load (via cell base +8) ;
    # entry-init vtable lea ; once helper call
    '0x5cdf535': '8b4708',
    '0x5cdf566': '488d0d33627e00',
    '0x5cdf577': 'ff1573048000',
    # once_globals: globals-init vtable lea ; once helper call
    '0x5cdf5ab': '488d0dae617e00',
    '0x5cdf5bc': 'ff152e048000',
    # entry_init_closure: insert call ; handle-drop call ;
    # cell tag store ; cell id store ; panic location lea
    '0x5cdf48c': 'e88fcaffff',
    '0x5cdf4ba': 'e851020000',
    '0x5cdf4c6': '892b',
    '0x5cdf4c8': '44897304',
    '0x5cdf4d5': '488d3dec627e00',
    # entry_init_direct: insert call ; handle-drop call ;
    # cell tag store ; cell id store
    '0x5cdf65c': 'e8bfc8ffff',
    '0x5cdf68a': 'e881000000',
    '0x5cdf696': '892b',
    '0x5cdf698': '44897304',
    # reg_register: its own 0x20-byte Arc object stores
    '0x5cdbf92': '4c897810',
    '0x5cdbf96': '895818',
    # reg_handle_drop: dealloc tail call
    '0x5cdf776': 'ff1524fd7f00',
    # drain: pending-byte atomic swap ; its only disp-0x10
    # store is a stack spill
    '0x5ce7496': '418606',
    '0x5ce7531': '4889442410',
    # ctor_grower: record field stores (object ptr / pending
    # byte / once word) ; globals out-struct store
    '0x5cfe9b0': '49892f',
    '0x5cfe9b3': '41c6470800',
    '0x5cfe9b8': '41c7471803000000',
    '0x5cfeaba': '4c897010',
    # driver_init: signal fd load ; once_globals call
    '0x5ce7211': '8b3d0d7c8100',
    '0x5ce732a': 'e85382ffff',
}

# Bodies whose direct callers are pinned by census.
CALL_TARGETS = {
    'reg_register': 0x5cdbf20,
    'entry_init_closure': 0x5cdf460,
    'entry_init_direct': 0x5cdf630,
    'globals_init_closure': 0x5cdf4f0,
    'globals_init_direct': 0x5cdf6c0,
    'record_once_shim': 0x5cdf535,
    'once_globals': 0x5cdf582,
    'lookup': 0x5cde710,
    'getobj': 0x5cfcf90,
    'reg_handle_drop': 0x5cdf710,
    'once_slow_helper': 0x5c87d50,
    'ctor_grower': 0x5cfe910,
    'vec_drop_glue': 0x5cfc9c0,
    'handle_drop_148': 0x5cfc8f0,
}

# Data targets of the RIP-relative reference census.
RIP_TARGETS = {
    'vtable_globals_init': 0x64c5760,
    'vtable_entry_init': 0x64c57a0,
    'loc_once_caller': 0x64c5788,
    'loc_entry_panic': 0x64c57c8,
    'g_oncecell': 0x64fee20,
    'g_fd': 0x64fee24,
    'g_vec_ptr': 0x64fee28,
    'g_vec_len': 0x64fee30,
    'g_init_flag': 0x64fee38,
    'entry_init_closure': 0x5cdf460,
    'entry_init_direct': 0x5cdf630,
    'reg_register': 0x5cdbf20,
    'record_once_shim': 0x5cdf535,
    'lookup': 0x5cde710,
}

VTABLES = {
    'vtable_globals_init': 0x64c5760,
    'vtable_entry_init': 0x64c57a0,
}

GLOBALS = {
    'oncecell': 0x64fee20,
    'fd': 0x64fee24,
    'vec_ptr': 0x64fee28,
    'vec_len': 0x64fee30,
    'init_flag': 0x64fee38,
}

# Bodies scanned by the disp-0x10/0x14 store census: every
# body that can hold a registry record pointer, plus the
# insert body that produces the stored values.
STORE_CENSUS_BODIES = [
    'lookup', 'drain', 'driver_init', 'ctor_grower',
    'vec_drop_glue', 'handle_drop_148', 'record_once_shim',
    'entry_init_closure', 'entry_init_direct', 'reg_register',
]

CELL_STORE_PATTERN = bytes.fromhex('892b44897304')

REG_NAMES = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
             'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']


def sections(data):
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    shnum = struct.unpack_from('<H', data, 0x3c)[0]
    raw = []
    for i in range(shnum):
        off = shoff + i * shentsize
        name_i, typ = struct.unpack_from('<II', data, off)
        addr, offset, size = struct.unpack_from('<QQQ', data, off + 16)
        link = struct.unpack_from('<I', data, off + 40)[0]
        entsize = struct.unpack_from('<Q', data, off + 56)[0]
        raw.append((name_i, typ, addr, offset, size, link, entsize))
    strtab = raw[struct.unpack_from('<H', data, 0x3e)[0]][3]
    out = {}
    for name_i, typ, addr, offset, size, link, entsize in raw:
        e = data.index(b'\x00', strtab + name_i)
        out[data[strtab + name_i:e].decode()] = (
            typ, addr, offset, size, link, entsize)
    return out


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
        p_offset, p_vaddr = struct.unpack_from('<QQ', data, off + 8)
        p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
        loads.append((p_vaddr, p_offset, p_filesz))
    return loads


def rela_map(data, secs):
    """Return ({offset: addend} RELATIVE, {offset: symidx} GLOB_DAT)."""
    rel, glob = {}, {}
    for _name, (typ, _a, offset, size, _l, entsize) in secs.items():
        if typ != 4:  # SHT_RELA
            continue
        for j in range(size // entsize):
            r_offset, r_info, r_addend = struct.unpack_from(
                '<QqQ', data, offset + j * entsize)
            r_type = r_info & 0xffffffff
            if r_type == 8:  # R_X86_64_RELATIVE
                rel[r_offset] = r_addend
            elif r_type == 6:  # R_X86_64_GLOB_DAT
                glob[r_offset] = r_info >> 32
    return rel, glob


def fde_starts(data, secs):
    _typ, addr, offset, _size, _l, _e = secs['.eh_frame_hdr']
    cnt = struct.unpack_from('<I', data, offset + 8)[0]
    return sorted(
        addr + struct.unpack_from('<i', data, offset + 12 + 8 * i)[0]
        for i in range(cnt))


def store_census(buf, base_va):
    """All stores with disp 0x10/0x14 in the given body bytes.

    Decodes the store families a compiler emits for dword /
    qword / vector stores (89, 88, 87, C7 /0, 0F 11) with
    mod=1/2 addressing, SIB included.  Byte-aligned scanning
    can re-read an instruction from its REX byte; a hit that
    starts one byte after a REX-carrying hit with the same
    disp/base is the same instruction and is dropped.
    """
    hits = []
    i = 0
    n = len(buf)
    while i < n:
        j = i
        rex = 0
        if 0x40 <= buf[j] <= 0x4f:
            rex = buf[j]
            j += 1
            if j >= n:
                break
        op = buf[j]
        kind = None
        oplen = 1
        if op in (0x88, 0x89, 0x87):
            kind = 'mov/xchg-store'
        elif op == 0xc7:
            kind = 'mov-imm-store'
        elif op == 0x0f and j + 1 < n and buf[j + 1] == 0x11:
            kind = 'movups-store'
            oplen = 2
        if kind is None:
            i += 1
            continue
        mpos = j + oplen
        if mpos >= n:
            break
        modrm = buf[mpos]
        mod = modrm >> 6
        reg = (modrm >> 3) & 7
        rm = modrm & 7
        if op == 0xc7 and reg != 0:
            i += 1
            continue
        if mod == 3 or mod == 0:
            i += 1
            continue
        pos = mpos + 1
        if rm == 4:  # SIB
            if pos >= n:
                break
            sib = buf[pos]
            pos += 1
            base = (sib & 7) | (8 if rex & 1 else 0)
        elif rm == 5:
            i += 1
            continue
        else:
            base = rm | (8 if rex & 1 else 0)
        if mod == 1:
            if pos >= n:
                break
            disp = struct.unpack_from('<b', buf, pos)[0]
        else:
            if pos + 4 > n:
                break
            disp = struct.unpack_from('<i', buf, pos)[0]
        if disp in (0x10, 0x14):
            hits.append({'site': hex(base_va + i), 'kind': kind,
                         'disp': hex(disp),
                         'base': REG_NAMES[base],
                         'rex': bool(rex)})
        i += 1
    out = []
    for h in hits:
        if (out and h['site'] == hex(int(out[-1]['site'], 16) + 1)
                and out[-1]['rex'] and not h['rex']
                and h['disp'] == out[-1]['disp']):
            continue
        out.append(h)
    for h in out:
        del h['rex']
    return out


def analyze(data):
    result = {}
    result['artifact'] = {
        'bytes': len(data),
        'sha256': hashlib.sha256(data).hexdigest(),
    }
    secs = sections(data)
    loads = pt_loads(data)
    result['pt_loads'] = [
        {'va': hex(v), 'off': hex(o), 'size': hex(s)} for v, o, s in loads]

    def va2off(va):
        for v, o, s in loads:
            if v <= va < v + s:
                return o + (va - v)
        raise ValueError(hex(va))

    def rd(va, n):
        o = va2off(va)
        return data[o:o + n]

    fdes = fde_starts(data, secs)

    def body_end(start):
        k = bisect.bisect_right(fdes, start)
        return fdes[k] if k < len(fdes) else start

    def body_name(va):
        for name, s in BODY_STARTS:
            if s == va:
                return name
        k = bisect.bisect_right(fdes, va) - 1
        for name, s in BODY_STARTS:
            if k >= 0 and s == fdes[k]:
                return name
        return hex(fdes[k]) if k >= 0 else 'outside_fde'

    bodies = {}
    ranges = {}
    for name, s in BODY_STARTS:
        e = body_end(s)
        ranges[name] = (s, e)
        b = rd(s, e - s)
        bodies[name] = {
            'va': hex(s),
            'end': hex(e),
            'size': e - s,
            'sha256': hashlib.sha256(b).hexdigest(),
        }
    result['bodies'] = bodies

    rel, glob = rela_map(data, secs)

    def qword(va):
        if va in rel:
            return rel[va]
        return struct.unpack('<Q', rd(va, 8))[0]

    slots = {}
    for va_hex in RELA_SLOTS:
        va = int(va_hex, 16)
        if va in rel:
            slots[va_hex] = {'kind': 'relative', 'target': hex(rel[va])}
        elif va in glob:
            slots[va_hex] = {'kind': 'glob_dat', 'sym': glob[va]}
        else:
            slots[va_hex] = {'kind': 'missing'}
    result['slots'] = slots

    locs = {}
    for va_hex in LOCATIONS:
        va = int(va_hex, 16)
        fp, fl = qword(va), qword(va + 8)
        line, col = struct.unpack_from('<II', rd(va + 16, 8))
        path = rd(fp, fl).decode('utf8', 'replace')
        suffix = path.split('/library/')[-1]
        locs[va_hex] = {'file': suffix, 'line': line, 'col': col}
    result['locations'] = locs

    pins = {}
    for va_hex, want in BYTE_PINS.items():
        va = int(va_hex, 16)
        pins[va_hex] = rd(va, len(bytes.fromhex(want))).hex()
    result['byte_pins'] = pins

    text_va, text_off, text_size = (
        secs['.text'][1], secs['.text'][2], secs['.text'][3])
    text = data[text_off:text_off + text_size]

    # (a) direct call/jump census for the pinned targets
    want = {v: k for k, v in CALL_TARGETS.items()}
    call_sites = {k: [] for k in CALL_TARGETS}
    for m in re.finditer(rb'[\xe8\xe9]', text):
        i = m.start()
        rel32 = struct.unpack_from('<i', text, i + 1)[0]
        tgt = text_va + i + 5 + rel32
        if tgt in want:
            call_sites[want[tgt]].append({
                'site': hex(text_va + i),
                'kind': 'call' if text[i] == 0xe8 else 'jmp',
                'body': body_name(text_va + i),
            })
    result['call_sites'] = {
        k: sorted(v, key=lambda s: int(s['site'], 16))
        for k, v in sorted(call_sites.items())}

    # (b) RIP-relative reference census (mod=0, rm=5 forms,
    #     with and without a REX prefix)
    targets = {v: k for k, v in RIP_TARGETS.items()}
    rip = {k: [] for k in RIP_TARGETS}
    pats = [
        (re.compile(rb'[\x40-\x4f][\x8d\x8b\x89\x39\x3b\x85\x2b\x03\x8a\x88]'
                    rb'[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]'), 7),
        (re.compile(rb'[\x8d\x8b\x89\x39\x3b\x85\x2b\x03\x8a\x88]'
                    rb'[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]'), 6),
    ]
    for pat, ln in pats:
        for m in pat.finditer(text):
            i = m.start()
            disp = struct.unpack_from('<i', text, i + ln - 4)[0]
            tgt = text_va + i + ln + disp
            if tgt in targets:
                rip[targets[tgt]].append({
                    'site': hex(text_va + i),
                    'body': body_name(text_va + i),
                    'op': hex(text[i + (1 if ln == 7 else 0)]),
                    '_rex': text[i] if ln == 7 else 0,
                })
    # Byte-aligned scanning re-reads most instructions from
    # the byte after a REX prefix, producing a ghost hit one
    # byte later with the same computed target.  Two hits one
    # byte apart cannot both be real (a REX byte is never a
    # standalone instruction in 64-bit code): if the first
    # carries a REX.W prefix it is the real instruction and
    # the second is its ghost; if the first's would-be REX
    # byte has no W bit it is itself a ghost (e.g. a short
    # branch displacement byte) and the second is real.
    for k in rip:
        ded = []
        for s in sorted(rip[k], key=lambda s: int(s['site'], 16)):
            if (ded and int(s['site'], 16)
                    == int(ded[-1]['site'], 16) + 1):
                prev = ded[-1]
                if prev['_rex'] and prev['_rex'] < 0x48:
                    ded[-1] = s
                continue
            ded.append(s)
        for s in ded:
            del s['_rex']
        rip[k] = ded
    result['rip_refs'] = rip

    # (c) .rela.dyn addends naming the watched code bodies
    rela_refs = {}
    for name, va in CALL_TARGETS.items():
        rela_refs[name] = sorted(
            hex(off) for off, add in rel.items() if add == va)
    for name, va in [('globals_init_closure', 0x5cdf4f0),
                     ('globals_init_direct', 0x5cdf6c0)]:
        rela_refs[name] = sorted(
            hex(off) for off, add in rel.items() if add == va)
    result['rela_refs'] = rela_refs

    # (d) raw absolute-qword scan outside .text
    raw = {}
    for name, va in CALL_TARGETS.items():
        patb = struct.pack('<Q', va)
        hits = []
        i = 0
        while True:
            k = data.find(patb, i)
            if k < 0:
                break
            if not (text_off <= k < text_off + text_size):
                hits.append(k)
            i = k + 1
        raw[name] = len(hits)
    result['raw_refs_outside_text'] = raw

    # (e) cell store-pair byte-pattern census over .text
    hits = []
    i = 0
    while True:
        k = text.find(CELL_STORE_PATTERN, i)
        if k < 0:
            break
        va = text_va + k
        hits.append({'site': hex(va), 'body': body_name(va)})
        i = k + 1
    result['cell_store_pattern'] = hits

    # (f) disp-0x10/0x14 store census over the bodies that
    #     can hold a record pointer (plus the insert body)
    sc = {}
    for name in STORE_CENSUS_BODIES:
        s, e = ranges[name]
        o = va2off(s)
        sc[name] = store_census(data[o:o + (e - s)], s)
    result['store_census'] = sc

    # (g) the two std-once closure vtables
    vt = {}
    for name, va in VTABLES.items():
        vt[name] = [hex(qword(va + 8 * k)) for k in range(5)]
    result['vtables'] = vt

    result['layout'] = {
        'entry_record': {
            'size': '0x20',
            'object_ptr': 'record+0x00',
            'pending_byte': 'record+0x08',
            'registration_cell': 'record+0x10 (tag dword +0x10, '
                                 'id dword +0x14)',
            'once_state_word': 'record+0x18',
            'once_state_ctor_init': 3,
        },
        'cell_write': {
            'stores': ['entry_init_closure 0x5cdf4c6/0x5cdf4c8',
                       'entry_init_direct 0x5cdf696/0x5cdf698'],
            'value_source': 'reg_register 0x5cdbf20, called only '
                            'from the two entry-init bodies',
            'invocation': 'lookup 0x5cde710 -> record_once_shim '
                          '0x5cdf535 -> std once helper (GOT '
                          '0x64df9f0) -> vtable 0x64c57a0 methods '
                          '(+0x18 direct, +0x20 closure)',
            'answer': 'no path other than the lookup writes the '
                      'cell',
        },
        'registry_globals': {
            'oncecell': '0x64fee20',
            'fd': '0x64fee24',
            'vec_ptr': '0x64fee28',
            'vec_len': '0x64fee30',
            'init_flag': '0x64fee38',
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
