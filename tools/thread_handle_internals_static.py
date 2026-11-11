#!/usr/bin/env python3
"""Node 115: what is inside the main-thread handle at ScopeData +0x10?

The packet-cell-context packet (RE-005-node115-packet-cell-context,
PR #3204) pinned the packet cells' context pointer as the std
scoped-thread state (ScopeData, library/std/src/thread/scoped.rs):
its field at A+0x10 is an Arc-style handle to the main thread, the
context release path (0x5bc24b0) decrements the strong count at
[A+0x10]+0x00 and at zero runs the shared thread field-drop glue
0x5c98b40 on the field (slot 0x64dfe58), and the payload drop's
unpark tail xchg's 1 into the word at [A+0x10]+0x28, waking the
thread through the futex syscall iff the old word was -1.  That
packet left the handle's own decomposition as an explicit
boundary ("thread_handle_internals"): beyond the parker state
word at handle +0x28 the allocation was not pinned; its drop glue
was seen to free a (pointer, length) buffer at handle +0x18/+0x20
before the weak-count release, consistent with a name buffer.
PR #3206 pinned that thread::scope itself is not instantiated,
but the handle type's layout question is separate and stayed
open.  This packet closes it from the handle's constructors and
its drop chain:

1.  Constructors.  The handle allocation is exactly 0x30 bytes,
    taken through the libc malloc GOT slot (0x64e1570) at every
    construction.  A binary-wide census of the
    `mov $0x30,%edi; call *malloc-slot` pattern finds exactly 16
    sites: one in each of the 14 spawn bodies PR #3204 pinned,
    one in the current-thread lazy initialiser (0x5c9d1f0, the
    body that also carries the thread/current.rs line 315
    Location and calls the field-drop glue on its own unwind
    path), and one in a sibling unnamed initialiser in the
    scoped-machinery neighborhood (0x5c82fd0).  After the call,
    all 16 sites execute the same store map on the fresh block:
    strong = 1 at +0x00, weak = 1 at +0x08, a thread id at +0x10,
    a (pointer, length) pair at +0x18/+0x20, and a zeroed 4-byte
    word at +0x28.  Nothing is stored at +0x2c: the +0x28 word
    is the last field and the remaining 4 bytes are tail padding
    of the 0x30 block.

2.  The id at +0x10.  Both fully-read constructors mint it
    inline from the same global counter (0x6500050) with a
    lock cmpxchg loop -- ThreadId::new inlined -- whose overflow
    arm calls the panic shim 0x5ca4480, which loads the message
    "failed to generate unique thread ID: bitspace exhausted"
    and the thread/id.rs Location (0x64c3dc0, line 38 col 13).
    The shim has exactly 22 direct callers, one per ThreadId
    minting site, the three constructors among them.

3.  The pair at +0x18/+0x20 is the thread's name.  The named
    variant (the 14 spawn bodies) passes the name string through
    the validator body 0x5ca5760 first (called through slot
    0x64e1568): it scans the (pointer, length) string for an
    interior NUL byte and panics at the thread/thread.rs
    Location (0x64c3e08, line 24 col 40, "thread name may not
    contain interior null bytes") if one is present, otherwise
    returns the pair unchanged, and the constructor stores it.
    The unnamed variant (the two initialisers) stores a zero
    pointer at +0x18 and never stores +0x20 at all -- the main
    thread has no name, and the length word is only ever read
    when the pointer is nonzero (point 4).

4.  Drop chain.  The field-drop glue 0x5c98b40 (108 call sites
    through its slot, 77 distinct owner bodies, every site
    FDE-owned) loads the handle from its argument slot; if the
    +0x18 pointer is nonzero it writes a zero byte at the
    buffer's first byte and, if the +0x20 length is nonzero,
    frees (pointer, length) through the dealloc slot 0x64df4a0;
    it then decrements the weak count at +0x08 and at zero
    tail-jumps to libc free (slot 0x64e20d8) on the whole 0x30
    block -- the free carries no size, which is why the total
    size had to come from the constructors.

Conclusion: the main-thread handle is a 0x30-byte Arc allocation
whose inner layout is {+0x10 thread id, +0x18 name buffer
pointer, +0x20 name buffer length, +0x28 parker state word},
with the Arc strong/weak header at +0x00/+0x08 and 4 bytes of
tail padding at +0x2c.  There are no fields beyond the parker
word PR #3204 pinned; its boundary is closed.
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
from bisect import bisect_right
from pathlib import Path

from artifacts import ROOT

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7'
                 'a8278fa39f249e98c3867b5301')
SNAPSHOT = '<authenticated-node115>'
WORK_ITEM = 'RE-005-node115-thread-handle-internals'
OUT = ROOT / 'research/work-items' / WORK_ITEM

RUSTC = '59807616e1fa2540724bfbac14d7976d7e4a3860'

MAIN_CTOR = 0x5c9d1f0
MAIN_CTOR_END = 0x5c9d323
SCOPED_CTOR = 0x5c82fd0
SCOPED_CTOR_END = 0x5c8312c
SPAWN_CTOR = 0x5613a70
SPAWN_CTOR_END = 0x56141ee
GLUE = 0x5c98b40
GLUE_END = 0x5c98b89
VALIDATOR = 0x5ca5760
VALIDATOR_END = 0x5ca58c3
ID_SHIM = 0x5ca4480
ID_SHIM_END = 0x5ca449d

GLUE_SLOT = 0x64dfe58
MALLOC_SLOT = 0x64e1570
FREE_SLOT = 0x64e20d8
DEALLOC_SLOT = 0x64df4a0
ALLOC_ERROR_SLOT = 0x64df490
VALIDATOR_SLOT = 0x64e1568
FUTEX_SLOT = 0x64e06b8
ID_COUNTER = 0x6500050

LOC_CURRENT = 0x64c3a70
LOC_ID = 0x64c3dc0
LOC_THREAD = 0x64c3e08
ID_MESSAGE = b'failed to generate unique thread ID: bitspace exhausted'
ID_MESSAGE_VA = 0x94a088
NAME_MESSAGE = b'thread name may not contain interior null bytes'
NAME_MESSAGE_VA = 0x94a1ad

OWNERS = {
    'main_thread_ctor': (MAIN_CTOR, MAIN_CTOR_END),
    'scoped_region_ctor': (SCOPED_CTOR, SCOPED_CTOR_END),
    'spawn_thread_ctor': (SPAWN_CTOR, SPAWN_CTOR_END),
    'thread_field_drop': (GLUE, GLUE_END),
    'name_validator': (VALIDATOR, VALIDATOR_END),
    'thread_id_panic_shim': (ID_SHIM, ID_SHIM_END),
}
EXPORTED = ('main_thread_ctor', 'scoped_region_ctor',
            'spawn_thread_ctor', 'thread_field_drop',
            'name_validator', 'thread_id_panic_shim')

# The 14 spawn bodies PR #3204 pinned, by FDE start.
SPAWN_STARTS = (
    0x15b6d10, 0x15b73c0, 0x15b7a80, 0x15b80e0,
    0x2d46820, 0x2d46f90, 0x2d47710,
    0x5613a70, 0x56141f0, 0x5614960, 0x56150d0,
    0x5bc2c90, 0x5cd9470, 0x5cf6e80,
)

PINS = {
    # main-thread initialiser: id cmpxchg on the counter global,
    # malloc(0x30), the full store block (note: no +0x20 store),
    # the alloc-error arm (align 8, size 0x30), the unwind-path
    # call through the field-drop slot
    'main_id_cmpxchg': (0x5c9d23a, 'f04c0fb13d0d2e8600'),
    'main_alloc_size': (0x5c9d249, 'bf30000000'),
    'main_alloc_call': (0x5c9d24e, 'ff151c438400'),
    'main_store_block': (
        0x5c9d260,
        '48c7000100000048c740080100000048c7401800000000'
        '4c897810c7402800000000'),
    'main_alloc_error': (
        0x5c9d2f8, 'bf08000000be30000000ff1588218400'),
    'main_unwind_drop_call': (0x5c9d315, 'ff153d2b8400'),
    # scoped-region initialiser: malloc(0x30) and its store block
    'scoped_alloc_size': (0x5c8303d, 'bf30000000'),
    'scoped_store_block': (
        0x5c83054,
        '48c7000100000048c740080100000048c7401800000000'
        '4c897010c7402800000000'),
    # spawn constructor: id cmpxchg, the name-validation call,
    # malloc(0x30), the full store block (name pair stored)
    'spawn_id_cmpxchg': (0x5613b9e, 'f04c0fb13da9c4ee00'),
    'spawn_name_validate_call': (0x5613bba, 'ff15a8d9ec00'),
    'spawn_alloc_size': (0x5613bc6, 'bf30000000'),
    'spawn_alloc_call': (0x5613bcb, 'ff159fd9ec00'),
    'spawn_store_block': (
        0x5613bdd,
        '48c7000100000048c74008010000004889581848896820'
        '4c897810c7402800000000'),
    # field-drop glue: name pointer/length loads, the
    # first-byte zeroing, the dealloc call, the weak decrement,
    # the tail jump to free
    'glue_load_name_ptr': (0x5c98b49, '488b7b18'),
    'glue_load_name_len': (0x5c98b52, '488b7320'),
    'glue_zero_first_byte': (0x5c98b56, 'c60700'),
    'glue_dealloc_call': (0x5c98b60, 'ff153a698400'),
    'glue_weak_decq': (0x5c98b6c, 'f048ff4b08'),
    'glue_free_jmp': (0x5c98b7c, 'ff2556958400'),
    # name validator: input pair loads, the panic message and
    # thread.rs Location lea's on the interior-NUL arm
    'validator_load_base': (0x5ca5769, '488b0f'),
    'validator_load_len': (0x5ca5770, '488b5710'),
    'validator_lea_message': (0x5ca587d, '488d3d2949cafa'),
    'validator_lea_location': (0x5ca588b, '4c8d0576e58100'),
    # ThreadId panic shim: the message and id.rs Location lea's
    'shim_lea_message': (0x5ca4484, '488d3dfd5bcafa'),
    'shim_lea_location': (0x5ca448b, '488d152ef98100'),
}

QUESTION = (
    'The packet-cell-context packet (PR #3204) pinned the packet '
    'cells\' context pointer as std\'s ScopeData and its field at '
    'A+0x10 as the main thread\'s handle, with the parker state '
    'word at handle +0x28 and a (pointer, length) buffer freed '
    'from handle +0x18/+0x20 by the drop glue, but left the '
    'handle\'s own decomposition beyond the parker word '
    'explicitly unpinned (its "thread_handle_internals" '
    'boundary).  What type is the handle allocation, how large '
    'is it, and what are its fields -- in particular, is there '
    'anything beyond the parker word?')

ANSWER = (
    'The handle is a single 0x30-byte heap allocation taken '
    'through the libc malloc slot at every one of its 16 '
    'construction sites (the 14 spawn bodies, the current-thread '
    'lazy initialiser 0x5c9d1f0, and a sibling unnamed '
    'initialiser 0x5c82fd0), laid out as an Arc header and four '
    'inner fields: strong count at +0x00 and weak count at '
    '+0x08 (both initialised to 1), the thread id at +0x10 '
    '(minted inline from the global counter 0x6500050, '
    'ThreadId::new inlined, overflow panicking at thread/id.rs '
    'line 38), the thread name as an owned (pointer, length) '
    'buffer at +0x18/+0x20 (validated for interior NUL bytes by '
    'body 0x5ca5760, panicking at thread/thread.rs line 24; '
    'zero pointer and an unstored length in the two unnamed '
    'constructions), and the parker state word at +0x28 '
    '(initialised to 0).  There is nothing beyond the parker '
    'word: +0x2c..+0x30 is tail padding of the 0x30 block, no '
    'constructor stores there and the drop glue reads nothing '
    'there.  The drop glue 0x5c98b40 frees the name buffer by '
    '(pointer, length) through the dealloc slot, decrements the '
    'weak count, and at zero tail-jumps to libc free on the '
    'whole block.')

BOUNDARIES = {
    'source_names': (
        'Names such as Thread, ThreadId and parker are the std '
        'source names for the mechanisms the artifact itself '
        'names through its thread/current.rs, thread/id.rs and '
        'thread/thread.rs path strings and panic messages; the '
        'binary carries no symbol naming the handle struct.  '
        'What is pinned is the byte layout and the code that '
        'writes and reads each field.  Whether std spells '
        '+0x18/+0x20 as a single Option<Box<str>> field is a '
        'source-level question the bytes do not answer; the code '
        'pins one owned (pointer, length) buffer, validated as '
        'a thread name and freed by size.'),
    'name_first_byte_zero': (
        'The drop glue writes a zero byte at the name buffer\'s '
        'first byte before freeing it.  The binary records no '
        'reason for this (no string, Location or comment names '
        'it); it is recorded as behaviour only.'),
    'empty_name_length': (
        'In the two unnamed constructions the length slot at '
        '+0x20 is never stored, so its word holds whatever the '
        'fresh malloc block contained.  This is safe in the '
        'artifact\'s own terms: the only consumer of +0x20 is '
        'the drop glue, which reads it only when the +0x18 '
        'pointer is nonzero, and every construction that stores '
        'a nonzero pointer also stores the length (census: 14 '
        'named, 2 unnamed, no third variant).'),
    'scoped_region_ctor': (
        'Body 0x5c82fd0 is a second lazy initialiser in the '
        'scoped-machinery neighborhood: it uses the same TLS '
        'slots and id counter as 0x5c9d1f0, constructs the same '
        'unnamed handle, and additionally assembles a 0x30 '
        'packet through the packet allocator slot.  Which entry '
        'points reach it is PR #3206\'s instantiation question '
        'and is not re-derived here; its store map is identical, '
        'so the layout does not depend on the answer.'),
    'park_side': (
        'The park (futex wait) side of the parker is not pinned '
        'by this packet.  The +0x28 word\'s identity as the '
        'parker state word rests on the constructors\' zero '
        'store, its position as the last field, and PR #3204\'s '
        'pinned unpark tail (an xchg of 1 at [A+0x10]+0x28, '
        'waking through futex syscall 202 iff the old word was '
        '-1).  The state names (0 empty, 1 notified, -1 parked) '
        'follow that pinned unpark behaviour.'),
    'other_malloc_site': (
        'One further call goes through the malloc slot (site '
        '0x5c8b956, body 0x5c8b8f0) without the 0x30 size '
        'pattern; it does not construct this layout and is '
        'recorded for census completeness only.'),
}

LIMITS = (
    'Static trace only; no captured code was executed.  The '
    'censuses cover the artifact\'s file bytes, its .rela.dyn '
    'relocations and rip-relative / direct-branch references '
    'in .text; a construction that obtained the 0x30 block '
    'through some other allocator entry would not be a '
    'construction of this handle type as pinned here, because '
    'the drop chain frees the block through libc free.')


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------- ELF

class Elf:
    def __init__(self, data):
        self.data = data
        d = data
        check(d[:4] == b'\x7fELF' and d[4] == 2, 'not an ELF64')
        phoff = struct.unpack_from('<Q', d, 0x20)[0]
        shoff = struct.unpack_from('<Q', d, 0x28)[0]
        phentsize, phnum = struct.unpack_from('<HH', d, 0x36)
        shentsize, shnum, shstrndx = struct.unpack_from(
            '<HHH', d, 0x3a)
        self.loads = []
        for i in range(phnum):
            p_type, _f, p_off, p_va, _pa, p_filesz, _ms, _al = \
                struct.unpack_from('<IIQQQQQQ', d,
                                   phoff + i * phentsize)
            if p_type == 1:
                self.loads.append((p_va, p_off, p_filesz))
        self.sections = {}
        sh = shoff + shstrndx * shentsize
        str_off = struct.unpack_from('<Q', d, sh + 0x18)[0]
        for i in range(shnum):
            sh = shoff + i * shentsize
            name_off, _t = struct.unpack_from('<II', d, sh)
            addr, off, size = struct.unpack_from('<QQQ', d,
                                                 sh + 0x10)
            end = d.index(b'\0', str_off + name_off)
            name = d[str_off + name_off:end].decode()
            self.sections[name] = (addr, off, size)

    def va2off(self, va):
        for p_va, p_off, p_filesz in self.loads:
            if p_va <= va < p_va + p_filesz:
                return p_off + (va - p_va)
        return None

    def off2va(self, off):
        for p_va, p_off, p_filesz in self.loads:
            if p_off <= off < p_off + p_filesz:
                return p_va + (off - p_off)
        return None

    def read(self, va, n):
        off = self.va2off(va)
        check(off is not None, f'unmapped va {va:#x}')
        return self.data[off:off + n]

    def u64(self, va):
        return struct.unpack('<Q', self.read(va, 8))[0]

    def u32(self, va):
        return struct.unpack('<I', self.read(va, 4))[0]

    def fdes(self):
        addr, off, size = self.sections['.eh_frame']
        d = self.data
        pos, end_all = off, off + size
        while pos < end_all:
            length = struct.unpack_from('<I', d, pos)[0]
            if length == 0:
                break
            if length == 0xffffffff:
                length = struct.unpack_from('<Q', d, pos + 4)[0]
                hdr = 16
            else:
                hdr = 4
            cie_ptr = struct.unpack_from('<i', d, pos + hdr)[0]
            entry_end = pos + hdr + length
            if cie_ptr != 0:
                field_va = addr + (pos + hdr + 4 - off)
                iloc_rel = struct.unpack_from(
                    '<i', d, pos + hdr + 4)[0]
                irange = struct.unpack_from(
                    '<I', d, pos + hdr + 8)[0]
                iloc = field_va + iloc_rel
                if iloc and irange:
                    yield (iloc, iloc + irange)
            pos = entry_end

    def relocations(self):
        """va -> (type, addend) for every .rela.dyn entry."""
        _addr, off, size = self.sections['.rela.dyn']
        out = {}
        for i in range(size // 24):
            r_off, r_info, r_add = struct.unpack_from(
                '<QQq', self.data, off + i * 24)
            out[r_off] = (r_info & 0xffffffff, r_add)
        return out

    def relocation_symbols(self):
        """va -> dynamic symbol name for symbol relocations."""
        d = self.data
        shoff = struct.unpack_from('<Q', d, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(
            '<HHH', d, 0x3a)

        def shdr(i):
            o = shoff + i * shentsize
            vals = struct.unpack_from('<IIQQQQIIQQ', d, o)
            return {'name': vals[0], 'off': vals[4],
                    'size': vals[5]}
        shstr = shdr(shstrndx)

        def secname(s):
            o = shstr['off'] + s['name']
            e = d.index(b'\0', o)
            return d[o:e].decode()
        secs = {secname(shdr(i)): shdr(i) for i in range(shnum)}
        dsym, dstr = secs['.dynsym'], secs['.dynstr']

        def sym_name(idx):
            o = dsym['off'] + idx * 24
            noff = struct.unpack_from('<I', d, o)[0]
            e = d.index(b'\0', dstr['off'] + noff)
            return d[dstr['off'] + noff:e].decode()
        out = {}
        for secn in ('.rela.dyn', '.rela.plt'):
            if secn not in secs:
                continue
            s = secs[secn]
            for o in range(s['off'], s['off'] + s['size'], 24):
                r_off, r_info, _add = struct.unpack_from(
                    '<QQq', d, o)
                if r_info >> 32:
                    out[r_off] = sym_name(r_info >> 32)
        return out


def find_all(data, pat):
    out, i = [], 0
    while True:
        j = data.find(pat, i)
        if j < 0:
            return out
        out.append(j)
        i = j + 1


# ------------------------------------------------------------ censuses

def owners(data, elf):
    fde = dict()
    for start, end in elf.fdes():
        fde[start] = end
    out = {}
    for role, (start, end) in OWNERS.items():
        check(fde.get(start) == end, f'{role}: FDE extent moved')
        off = elf.va2off(start)
        body = data[off:off + (end - start)]
        out[role] = {'start': hex(start), 'end': hex(end),
                     'offset': off, 'bytes': end - start,
                     'sha256': sha(body)}
    return out


def text_window(elf):
    _va, off, size = elf.sections['.text']
    return elf.sections['.text'][0], elf.data[off:off + size]


def fde_owner(fdes, starts, va):
    i = bisect_right(starts, va) - 1
    if i >= 0 and fdes[i][0] <= va < fdes[i][1]:
        return fdes[i]
    return None


def slot_calls(elf, slot):
    """All ff 15 (call *disp32(%rip)) sites in .text naming slot."""
    tva, text = text_window(elf)
    sites = []
    for o in find_all(text, b'\xff\x15'):
        if o + 6 <= len(text):
            disp = struct.unpack_from('<i', text, o + 2)[0]
            if tva + o + 6 + disp == slot:
                sites.append(tva + o)
    return sorted(sites)


def direct_xrefs(elf, target):
    """All E8/E9 (call/jmp rel32) sites in .text naming target."""
    tva, text = text_window(elf)
    sites = []
    for op in (b'\xe8', b'\xe9'):
        for o in find_all(text, op):
            if o + 5 <= len(text):
                rel = struct.unpack_from('<i', text, o + 1)[0]
                if tva + o + 5 + rel == target:
                    sites.append(tva + o)
    return sorted(sites)


def _disp8_store(window, disp):
    """True if window holds a REX 89 /r store with disp8 == disp
    to base register rax (the fresh allocation pointer)."""
    for i in range(len(window) - 3):
        if window[i] in (0x48, 0x4c) and window[i + 1] == 0x89 \
                and window[i + 2] & 0xc7 == 0x40 \
                and window[i + 3] == disp:
            return True
    return False


def construction_census(data, elf):
    fdes = sorted(elf.fdes())
    starts = [f[0] for f in fdes]
    tva, text = text_window(elf)
    pat = b'\xbf\x30\x00\x00\x00\xff\x15'
    sites = []
    for o in find_all(text, pat):
        disp = struct.unpack_from('<i', text, o + 7)[0]
        if tva + o + 11 + disp == MALLOC_SLOT:
            sites.append(tva + o)
    check(len(sites) == 16, 'malloc(0x30) site count moved')
    records = []
    want_owners = sorted(list(SPAWN_STARTS) + [MAIN_CTOR,
                                               SCOPED_CTOR])
    got_owners = []
    for site in sites:
        call = site + 5
        own = fde_owner(fdes, starts, site)
        check(own is not None, f'malloc site {site:#x} ownerless')
        got_owners.append(own[0])
        woff = elf.va2off(call + 6)
        window = data[woff:woff + 0x30]
        check(b'\x48\xc7\x00\x01\x00\x00\x00' in window,
              f'site {site:#x}: strong store missing')
        check(b'\x48\xc7\x40\x08\x01\x00\x00\x00' in window,
              f'site {site:#x}: weak store missing')
        check(b'\xc7\x40\x28\x00\x00\x00\x00' in window,
              f'site {site:#x}: parker store missing')
        check(_disp8_store(window, 0x10),
              f'site {site:#x}: id store missing')
        named = _disp8_store(window, 0x18) \
            and _disp8_store(window, 0x20)
        unnamed = b'\x48\xc7\x40\x18\x00\x00\x00\x00' in window \
            and not _disp8_store(window, 0x20)
        check(named != unnamed,
              f'site {site:#x}: variant not classifiable')
        records.append({'mov': hex(site), 'call': hex(call),
                        'owner': hex(own[0]),
                        'variant': 'named' if named else 'unnamed'})
    check([hex(s) for s in sorted(got_owners)]
          == [hex(s) for s in want_owners],
          'malloc(0x30) owners are not the expected 16 bodies')
    named = [r for r in records if r['variant'] == 'named']
    unnamed = [r for r in records if r['variant'] == 'unnamed']
    check(len(named) == 14 and len(unnamed) == 2,
          'named/unnamed split moved')
    check(sorted(r['owner'] for r in unnamed)
          == sorted([hex(MAIN_CTOR), hex(SCOPED_CTOR)]),
          'unnamed constructions are not the two initialisers')
    all_malloc = slot_calls(elf, MALLOC_SLOT)
    check(len(all_malloc) == 17, 'malloc slot call count moved')
    other = [s for s in all_malloc
             if s not in {int(r['call'], 16) for r in records}]
    check(len(other) == 1, 'unexpected extra malloc call sites')
    o_own = fde_owner(fdes, starts, other[0])
    return {
        'pattern': 'bf 30 00 00 00 ff 15 <malloc slot>',
        'malloc_slot_call_sites': len(all_malloc),
        'size_0x30_sites': records,
        'named_variant': len(named),
        'unnamed_variant': len(unnamed),
        'other_malloc_call': {
            'site': hex(other[0]),
            'owner': hex(o_own[0]) if o_own else None},
    }


def glue_census(data, elf):
    fdes = sorted(elf.fdes())
    starts = [f[0] for f in fdes]
    sites = slot_calls(elf, GLUE_SLOT)
    owner_set = set()
    for s in sites:
        own = fde_owner(fdes, starts, s)
        check(own is not None, f'glue site {s:#x} ownerless')
        owner_set.add(own[0])
    check(len(sites) == 108, 'glue call site count moved')
    check(len(owner_set) == 77, 'glue owner count moved')
    return {'slot': hex(GLUE_SLOT), 'target': hex(GLUE),
            'call_sites': len(sites),
            'distinct_owners': len(owner_set),
            'main_ctor_unwind_site': '0x5c9d315',
            'scoped_ctor_unwind_site': '0x5c8311e'}


def id_shim_census(data, elf):
    fdes = sorted(elf.fdes())
    starts = [f[0] for f in fdes]
    sites = direct_xrefs(elf, ID_SHIM)
    records = []
    for s in sites:
        own = fde_owner(fdes, starts, s)
        check(own is not None, f'id shim caller {s:#x} ownerless')
        records.append({'site': hex(s), 'owner': hex(own[0])})
    check(len(records) == 22, 'id shim caller count moved')
    owner_set = {r['owner'] for r in records}
    for want in (MAIN_CTOR, SCOPED_CTOR, SPAWN_CTOR):
        check(hex(want) in owner_set,
              f'constructor {want:#x} does not call the id shim')
    msg_hits = find_all(data, ID_MESSAGE)
    check(len(msg_hits) == 1
          and elf.off2va(msg_hits[0]) == ID_MESSAGE_VA,
          'ThreadId panic message moved')
    name_hits = find_all(data, NAME_MESSAGE)
    check(len(name_hits) == 1
          and elf.off2va(name_hits[0]) == NAME_MESSAGE_VA,
          'thread-name panic message moved')
    return {'target': hex(ID_SHIM), 'direct_callers': records,
            'count': len(records),
            'id_message': {'text': ID_MESSAGE.decode(),
                           'va': hex(ID_MESSAGE_VA)},
            'name_message': {'text': NAME_MESSAGE.decode(),
                             'va': hex(NAME_MESSAGE_VA),
                             'len': len(NAME_MESSAGE)}}


def locations(data, elf):
    relocs = elf.relocations()
    out = {}
    for name, loc, line, col in (
            ('current_rs', LOC_CURRENT, 315, 9),
            ('id_rs', LOC_ID, 38, 13),
            ('thread_rs', LOC_THREAD, 24, 40)):
        typ, add = relocs[loc]
        check(typ == 8, f'{name}: Location file ptr not relative')
        off = elf.va2off(add)
        end = data.index(b'\0', off)
        path = data[off:end].decode()
        rec = {'record': hex(loc), 'file': path,
               'len': elf.u64(loc + 8),
               'line': elf.u32(loc + 16),
               'col': elf.u32(loc + 20)}
        check(rec['line'] == line and rec['col'] == col,
              f'{name}: Location line/col moved')
        out[name] = rec
    return out


def slots(data, elf):
    relocs = elf.relocations()
    syms = elf.relocation_symbols()
    out = {}
    for name, slot in (('thread_field_drop', GLUE_SLOT),
                       ('malloc', MALLOC_SLOT),
                       ('free', FREE_SLOT),
                       ('dealloc', DEALLOC_SLOT),
                       ('alloc_error', ALLOC_ERROR_SLOT),
                       ('name_validator', VALIDATOR_SLOT),
                       ('futex_syscall', FUTEX_SLOT)):
        typ, add = relocs[slot]
        rec = {'slot': hex(slot), 'type': typ}
        if typ == 8:
            rec['target'] = hex(add)
        else:
            rec['symbol'] = syms.get(slot)
        out[name] = rec
    check(out['thread_field_drop']['target'] == hex(GLUE),
          'field-drop slot target moved')
    check(out['malloc']['symbol'] == 'malloc',
          'malloc slot symbol moved')
    check(out['free']['symbol'] == 'free',
          'free slot symbol moved')
    check(out['dealloc']['target'] == '0x635de30',
          'dealloc slot target moved')
    check(out['name_validator']['target'] == hex(VALIDATOR),
          'validator slot target moved')
    check(out['futex_syscall']['symbol'] == 'syscall',
          'futex slot symbol moved')
    return out


def check_pins(data, elf):
    out = {}
    for name, (va, want) in PINS.items():
        raw = elf.read(va, len(bytes.fromhex(want)))
        check(raw.hex() == want, f'pin {name} moved')
        out[name] = {'va': hex(va), 'bytes': want}
    # both inlined ThreadId cmpxchg loops resolve to the counter
    for name in ('main_id_cmpxchg', 'spawn_id_cmpxchg'):
        va = PINS[name][0]
        raw = elf.read(va, 9)
        disp = struct.unpack_from('<i', raw, 5)[0]
        check(va + 9 + disp == ID_COUNTER,
              f'{name} does not resolve to the id counter')
    return out


LAYOUT = {
    'allocation': {
        'size': '0x30', 'align': 8,
        'allocator': 'libc malloc via slot 0x64e1570',
        'release': 'libc free via slot 0x64e20d8 (no size '
                   'argument), reached from the field-drop glue '
                   'when the weak count reaches zero',
        'alloc_error': 'slot 0x64df490 with (align 8, size '
                       '0x30) in the main initialiser',
    },
    'fields': [
        {'offset': '0x00', 'size': 8, 'name': 'strong count',
         'evidence': 'both read constructors store 1; PR '
                     '#3204\'s context release decrements '
                     '[A+0x10]+0x00 and runs the field-drop '
                     'glue at zero'},
        {'offset': '0x08', 'size': 8, 'name': 'weak count',
         'evidence': 'both read constructors store 1; the '
                     'field-drop glue decrements it (lock decq '
                     'at glue +0x2c) and tail-jumps to free at '
                     'zero'},
        {'offset': '0x10', 'size': 8, 'name': 'thread id',
         'inner_offset': '0x00',
         'evidence': 'stored from the lock cmpxchg loop on '
                     'the global counter 0x6500050 (ThreadId::'
                     'new inlined) in all three read '
                     'constructors; overflow calls the panic '
                     'shim 0x5ca4480 (thread/id.rs line 38)'},
        {'offset': '0x18', 'size': 8,
         'name': 'name buffer pointer', 'inner_offset': '0x08',
         'evidence': 'the 14 spawn constructions store the '
                     'validated name string\'s pointer; the '
                     'two initialisers store 0; the field-drop '
                     'glue loads it and, when nonzero, zeroes '
                     'its first byte and frees it by the +0x20 '
                     'length'},
        {'offset': '0x20', 'size': 8,
         'name': 'name buffer length', 'inner_offset': '0x10',
         'evidence': 'stored by the 14 spawn constructions '
                     'from the validated name string\'s '
                     'length; never stored by the two '
                     'initialisers; consumed only by the '
                     'field-drop glue as the dealloc size, '
                     'only when the +0x18 pointer is nonzero'},
        {'offset': '0x28', 'size': 4,
         'name': 'parker state word', 'inner_offset': '0x18',
         'evidence': 'stored as 0 by every construction; PR '
                     '#3204 pinned the scope payload drop '
                     'xchg\'ing 1 into this word at '
                     '[A+0x10]+0x28 and waking through the '
                     'futex syscall iff the old word was -1'},
        {'offset': '0x2c', 'size': 4, 'name': 'tail padding',
         'evidence': 'no construction stores at +0x2c and '
                     'the drop glue reads nothing there; the '
                     '0x30 allocation ends at +0x30'},
    ],
}


def analyze(data):
    check(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,
          'artifact authentication failed')
    elf = Elf(data)
    return {
        'artifact': {'path': 'artifacts/node/115/hl-node',
                     'bytes': TARGET_SIZE, 'sha256': TARGET_SHA256,
                     'snapshot': SNAPSHOT},
        'packet': WORK_ITEM,
        'captured_code_executed': False,
        'question': QUESTION,
        'answer': ANSWER,
        'owners': owners(data, elf),
        'pins': check_pins(data, elf),
        'slots': slots(data, elf),
        'locations': locations(data, elf),
        'thread_id_counter': {'address': hex(ID_COUNTER)},
        'layout': LAYOUT,
        'construction_census': construction_census(data, elf),
        'glue_census': glue_census(data, elf),
        'id_shim_census': id_shim_census(data, elf),
        'boundaries': BOUNDARIES,
        'limits': LIMITS,
    }


# -------------------------------------------------------------- output

def objdump_range(start, end):
    text = subprocess.run(
        ['objdump', '-d', '--start-address', hex(start),
         '--stop-address', hex(end), str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    return text.replace(str(TARGET), SNAPSHOT, 1)


def exports(role):
    start, end = OWNERS[role]
    return objdump_range(start, end)


def frame_lines():
    text = subprocess.run(['readelf', '-wf', str(TARGET)],
                          check=True, capture_output=True,
                          text=True).stdout
    wanted = []
    for start, end in OWNERS.values():
        needle = f'pc={start:016x}..{end:016x}'
        wanted += [ln for ln in text.splitlines() if needle in ln]
    check(len(wanted) == len(OWNERS), 'owner frame lines missing')
    return [line + '\n' for line in wanted]


def manifest_lines():
    names = sorted(p.name for p in OUT.iterdir()
                   if p.is_file() and p.name != 'MANIFEST.sha256')
    lines = []
    for name in names:
        digest = sha((OUT / name).read_bytes())
        lines.append(f'{digest}  {name}\n')
    return lines


def generate(data):
    OUT.mkdir(parents=True, exist_ok=True)
    records = analyze(data)
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (OUT / 'frames.txt').write_text(''.join(frame_lines()))
    for role in EXPORTED:
        (OUT / f'{role}.objdump.txt').write_text(exports(role))
    check((OUT / 'README.md').is_file(),
          'README.md must exist before MANIFEST generation')
    (OUT / 'MANIFEST.sha256').write_text(''.join(manifest_lines()))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--generate', action='store_true')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    if args.generate:
        generate(data)
        return
    records = analyze(data)
    expected = json.loads((OUT / 'records.json').read_text())
    check(records == expected, 'records.json is stale')
    for role in EXPORTED:
        check((OUT / f'{role}.objdump.txt').read_text()
              == exports(role), f'{role}.objdump.txt is stale')
    check((OUT / 'frames.txt').read_text() == ''.join(frame_lines()),
          'frames.txt is stale')
    check((OUT / 'MANIFEST.sha256').read_text()
          == ''.join(manifest_lines()), 'MANIFEST.sha256 is stale')
    print(json.dumps({'packet': WORK_ITEM, 'matches': True},
                     sort_keys=True))


if __name__ == '__main__':
    main()
