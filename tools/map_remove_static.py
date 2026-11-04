#!/usr/bin/env python3
"""Pin the RE-015 map removal side and the grow reachability
variants in node 115.

Questions (carried by the map-grow packet
RE-015-node115-map-grow):

(1) The removal side of the same S-rooted hashbrown map
(map words at S+0x20: +0x00 ctrl base, +0x08 mask, +0x10
growth-left, +0x18 items): which body removes an entry --
does it clear the control byte to a 0x80 tombstone, or does
it do backward-shift deletion (moving subsequent records)?
What happens to items/growth-left and the removed value
(returned, dropped, freed)?

(2) Does anything ever reach the grow body 0x4742aa0 with
a fallibility byte of 0, or with an additional argument
other than 1? The grow slot 0x64eaf78 has exactly one .text
reference (the insert's call at 0x474ba06, args (map, 1,
map+0x20, 1)) per the grow packet -- so part (2) is answered
by censusing every other reference form to the grow body /
slot (direct E8/E9, rela addends, absolute words, lea and
the other rip-relative forms).

Findings pinned by this packet:

(1) NO single-entry erase body for the S-rooted map can be
isolated from static evidence, and the censuses below bound
that negative exactly. The map's traced operation set is
closed: build (insert helper 0x4741960 -> map insert
0x474b620), grow (0x4742aa0 through slot 0x64eaf78),
read-only lookup (0x4742130, no stores at all), replace on
insert hit (the displaced value is copied out and dropped
by the caller), and whole-table recursive teardown
(0x4742960). The candidate censuses:

  - the whole-.text FNV-1a basis-load census finds 20
    bodies; inside the S family cluster
    (0x4740000..0x4750000) the only FNV bodies are the
    insert helper, the lookup, the grow and the insert --
    no fifth body hashes this map's keys;
  - no body in the whole binary stores an immediate 0x80
    byte AND carries any tie to a 0x58-bucket map (imul
    0x58, the FNV basis, a bcmp slot call, or a call to
    the map's record drop 0x4742960): the tied candidate
    set is empty;
  - the only two bodies in the binary with the
    erase_no_drop shape census (tzcnt + bsr/lzcnt + a
    register byte store) are 0x143f000 and 0x63bb7e0,
    neither tied to this map (no imul 0x58, no FNV, no
    bcmp, no record-drop call, outside the cluster);
  - no body in the cluster materialises 0x80 into a byte
    register while using imul 0x58;
  - no body in the whole cluster range
    0x4740000..0x4750000 stores an immediate 0x80 byte at
    all (the immediate-0xff stores there are the grow
    family's in-place "source becomes empty" stores);
  - the only decrement of a qword at [reg+0x18] in the
    whole cluster range (sub / dec forms, whole-.text
    census) is the cleanup owner's own dec at 0x474263b;
    no other cluster body touches an item count downward.

  The only removal-flavoured body in the cluster is an
  owner of this packet: the marked-record cleanup
  0x47425c0 (182 bytes). It is NOT a consumer erase: its
  sole caller is a landing pad at 0x4743fdd inside the
  SIBLING grow 0x4743990 (the seeded-hash map family whose
  reserve goes through slot 0x64eaf88), and it takes a
  stack descriptor {map pointer at +0x00, record drop
  function pointer at +0x08, record stride at +0x10}. It
  scans the control bytes from index 0 upward for bytes
  equal to 0x80 -- the mark the sibling grow's in-place
  fixup leaves on live records -- and for each marked
  slot it stores 0xff at the slot and at its mirror
  ((index-0x10) wrapped by the mask, expressed in the
  body as ctrl + (rbp & mask) + 0x10), calls the
  descriptor's function pointer on the bucket record
  (ctrl - (index+1)*stride), and decrements the item
  count at map+0x18 by one per record. When the scan
  ends (or the mask is -1 / the drop pointer is null on
  entry) it recomputes growth-left = cap(mask+1) - items
  with the grow packet's capacity model and stores it at
  map+0x10. It removes only fixup-marked records, only
  on the unwind path, and it never moves a record:
  there is no backward-shift deletion here either.

  What does remove entries of the S map, in the only
  sense the binary instantiates, is the second owner:
  the whole-table recursive drop 0x4742960 (307 bytes,
  the body earlier packets pinned as the displaced-record
  drop). Called with a map pointer, it reads the mask at
  map+0x08 (returning at once when it is 0) and the item
  count at map+0x18, walks the control groups with
  pmovmskb (full bytes are the non-special lanes), and
  for each live bucket frees the key buffer through the
  dealloc slot 0x64df4a0 (size = the key record's first
  word, when nonzero), frees the child S mapped array
  (buffer at bucket+0x28, count at bucket+0x20, size =
  count*8, when nonzero), and recurses into the child
  S's embedded map at bucket+0x38. It then tail-jumps to
  the dealloc slot with the allocation base (ctrl -
  align16(buckets*0x58)) and the total size
  (align16(buckets*0x58) + buckets + 16, with the
  alignment flag folded into the third argument). It
  never rewrites a control byte and never stores the
  item count or growth-left: the table ceases to exist.
  Its whole-.text caller census is six sites, all drop /
  displaced-value contexts (0x47408db, 0x474205d in the
  insert helper, the self-recursion at 0x47429c1,
  0x474b419, and the two 45-byte value-drop tails at
  0x4740a58 / 0x474ac58) -- no erase consumer among them.

(2) The grow body is reachable through exactly one
reference in every censused form, scope = the whole
binary, all sections:

  - direct E8/E9 calls or jumps to 0x4742aa0: none;
  - rip-relative references (ff call/jmp group, lea,
    mov load/store, cmp/test and the other REX / non-REX
    rip-modrm forms, byte-pattern census corroborated by
    a full objdump disassembly grep): to the body, none;
    to slot 0x64eaf78, exactly the insert's call at
    0x474ba06;
  - .rela.dyn entries whose addend is 0x4742aa0: exactly
    one, the grow slot itself (0x64eaf78, type 8);
    .rela.plt: none;
  - absolute 64-bit words equal to 0x4742aa0 anywhere in
    the file: only that relocation entry's own addend
    field; the slot address 0x64eaf78 as an absolute word
    likewise occurs only as that entry's offset field.

  So nothing reaches the grow body with a fallibility
  byte of 0 or an additional other than 1: the sole
  call site passes (map, 1, map+0x20, 1), as the insert
  packet pinned at 0x474b9ee..0x474ba06, and there is no
  other referrer in any form. (The body's own FDE in
  .eh_frame / .eh_frame_hdr names its extent for unwind
  purposes; that is metadata the earlier packets already
  pin as frame records, not a call path.)

Static evidence only; no captured code is executed.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export, require

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'

OWNERS = {
    'marked_cleanup': (
        0x47425c0, 0x4742676,
        'a27501e59ce2fa4fc610ed13d3da63c01ea578963bec73d983d86b584a3e49e4'),
    'map_drop': (
        0x4742960, 0x4742a93,
        '1aae44edc7f846da821541c9455706506403ae72981926a7927dd0aa0a3069e1'),
}
BOUNDARIES = {
    'map_lookup': (
        0x4742130, 0x4742470,
        '930b9aa4933c3aab6513d5f1df4ffb9578225cbe084873a6063f65cc10201a2f'),
    'wrap_ctor': (
        0x4742470, 0x4742595,
        'fe91e95a97ff89e4df3823200e2973aeb23dd05dabf5737d48ce10a74798ef9c'),
    'pad_helper_next': (
        0x4742680, 0x47426d1,
        'da0038dfd88d2675f82db29375445a91dc3116e140ab87ae02e1c6eac7fb3401'),
    'map_grow': (
        0x4742aa0, 0x4743347,
        'dddec9130ff0171ebc861ae72351d0e4d846e76cbbd9811c5bed5d56d0ac4a67'),
    'sibling_grow': (
        0x4743990, 0x4743ff0,
        'eeac52dec8e29f0c1c3084ba80545a9b551b44c69b974a60f2220d564f961eef'),
    'map_insert': (
        0x474b620, 0x474ba5d,
        'f6d9ca4362a1a81c592c33e5e75d6522a738b71a143b4c6b9bcb0b1739cd6658'),
    'insert_helper': (
        0x4741960, 0x4742124,
        '19ab10dcba77aea7e558737bddc7bace985b7d49bc254b69d731e23bb805136d'),
}

CLEANUP_PINS = {
    'map_load': (0x47425cb, bytes.fromhex('488b1f')),
    'fnptr_load': (0x47425ce, bytes.fromhex('4c8b7708')),
    'mask_load': (0x47425d7, bytes.fromhex('4c8b7b08')),
    'stride_load': (0x47425e1, bytes.fromhex('4c8b6710')),
    'ctrl_cmp': (0x4742616, bytes.fromhex('3a4c2810')),
    'ctrl_jno': (0x474261a, bytes.fromhex('71e4')),
    'mask_reload': (0x474261c, bytes.fromhex('488b4b08')),
    'store_slot_ff': (0x4742623, bytes.fromhex('c6442810ff')),
    'store_mirror_ff': (0x474262b, bytes.fromhex('c6440810ff')),
    'drop_call': (0x4742636, bytes.fromhex('41ffd6')),
    'items_dec': (0x474263b, bytes.fromhex('48ff4b18')),
    'finish_mask_load': (0x4742641, bytes.fromhex('488b4308')),
    'growth_store': (0x4742663, bytes.fromhex('48894b10')),
}
DROP_PINS = {
    'mask_load': (0x474296e, bytes.fromhex('488b4708')),
    'items_load': (0x4742985, bytes.fromhex('4c8b6718')),
    'group_load': (0x474299a, bytes.fromhex('66410f6f4500')),
    'pmovmskb': (0x47429a4, bytes.fromhex('660fd7')),
    'tzcnt': (0x47429fc, bytes.fromhex('f30fbcc3')),
    'imul58': (0x4742a03, bytes.fromhex('486bc058')),
    'key_size_load': (0x4742a0b, bytes.fromhex('498b7405a8')),
    'array_count_load': (0x4742a21, bytes.fromhex('498b77c8')),
    'total_imul58': (0x4742a44, bytes.fromhex('486bc658')),
}
DROP_SLOT_CALLS = {
    'key_dealloc': (0x4742a1b, 0x64df4a0),
    'array_dealloc': (0x4742a34, 0x64df4a0),
    'table_dealloc_tail': (0x4742a7e, 0x64df4a0),
}
SIBLING_PAD_PINS = {
    'pad_lea_desc': (0x4743fd8, bytes.fromhex('488d7c2420')),
}

SLOT_BINDINGS_WANTED = {
    'dealloc': 0x64df4a0, 'grow_fn': 0x64eaf78,
    'sibling_grow_fn': 0x64eaf88,
}
EXPECTED_BINDINGS = {
    'dealloc': ('rela', '0x635de30'),
    'grow_fn': ('rela', '0x4742aa0'),
    'sibling_grow_fn': ('rela', '0x4743990'),
}

CLUSTER_LO = 0x4740000
CLUSTER_HI = 0x4750000
GROW_BODY = 0x4742aa0
GROW_SLOT = 0x64eaf78
FNV_BASIS = bytes.fromhex('25232284e49cf2cb')


def read(data, va, n):
    for s in sections(data):
        if s['type'] != 8 and s['address'] <= va < s['address'] + s['size']:
            off = s['offset'] + va - s['address']
            if off + n > s['offset'] + s['size']:
                break
            return off, data[off:off + n]
    raise ValueError(f'unmapped {va:#x}')


def _pin(data, site, expected, label):
    if read(data, site, len(expected))[1] != expected:
        raise ValueError(f'{label} changed')


def _pins(data, table, role):
    for label, (site, expected) in table.items():
        _pin(data, site, expected, f'{role} {label}')


def _slot_call(data, site, slot, label):
    raw = read(data, site, 6)[1]
    require(raw[:2] in (b'\xff\x15', b'\xff%'),
            f'{label} is not a slot call')
    disp = struct.unpack('<i', raw[2:])[0]
    require(site + 6 + disp == slot, f'{label} slot changed')


def _relocations(data, name):
    s = next(s for s in sections(data) if s['name'] == name)
    out = {}
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        offset, info, addend = struct.unpack_from('<QQq', data, off)
        out[offset] = {'type': info & 0xffffffff,
                       'symbol': info >> 32, 'addend': addend}
    return out


def _dynsym_names(data):
    secs = sections(data)
    sym = next(s for s in secs if s['name'] == '.dynsym')
    strs = next(s for s in secs if s['name'] == '.dynstr')
    names = {}
    for i, off in enumerate(range(sym['offset'],
                                  sym['offset'] + sym['size'], 24)):
        noff = struct.unpack_from('<I', data, off)[0]
        end = data.index(b'\x00', strs['offset'] + noff)
        names[i] = data[strs['offset'] + noff:end].decode()
    return names


def slot_bindings(data):
    rel = _relocations(data, '.rela.dyn')
    names = _dynsym_names(data)
    out = {}
    for name, slot in SLOT_BINDINGS_WANTED.items():
        entry = rel[slot]
        kind, want = EXPECTED_BINDINGS[name]
        if kind == 'rela':
            got = hex(entry['addend'])
            out[name] = {'slot': hex(slot), 'type': entry['type'],
                         'addend': got}
            if got != want:
                raise ValueError(f'slot binding {name} changed')
        else:
            got = names[entry['symbol']]
            out[name] = {'slot': hex(slot), 'type': entry['type'],
                         'symbol': entry['symbol'], 'name': got}
            if got != want:
                raise ValueError(f'slot binding {name} changed')
    return out


def _text(data):
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    return data[text['offset']:text['offset'] + text['size']], \
        text['address']


def _fde_bodies(data):
    _, fs, _ = fde_extents(data)
    starts = sorted(f['start'] for f in fs)
    by_start = {f['start']: f for f in fs}
    return fs, starts, by_start


def _body_of(starts, by_start, va):
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0:
        f = by_start[starts[i]]
        if f['start'] <= va < f['end']:
            return f
    return None


def direct_call_census(data, targets):
    """E8 and E9 sites per target, as [site, opcode] pairs."""
    raw, base = _text(data)
    found = {t: [] for t in targets}
    for op in (0xe8, 0xe9):
        for m in re.finditer(bytes([op]), raw):
            i = m.start()
            if i + 5 > len(raw):
                continue
            disp = struct.unpack_from('<i', raw, i + 1)[0]
            tgt = base + i + 5 + disp
            if tgt in found:
                found[tgt].append([hex(base + i), hex(op)])
    return {hex(k): v for k, v in found.items()}


def slot_call_census(data, slot):
    raw, base = _text(data)
    hits = []
    for m in re.finditer(rb'\xff[\x15\x25]', raw):
        i = m.start()
        if i + 6 > len(raw):
            continue
        disp = struct.unpack_from('<i', raw, i + 2)[0]
        if base + i + 6 + disp == slot:
            hits.append(base + i)
    return [hex(x) for x in hits]


RIP_MODRM = {0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d}


def riprel_census(data, targets):
    """Every rip-relative reference form to a target: the ff
    group, lea / mov / cmp forms with a REX.W prefix (7-byte
    form) and without (6-byte form). Byte-pattern census;
    corroborated for these two targets by a full objdump
    disassembly grep (see README)."""
    raw, base = _text(data)
    hits = {t: set() for t in targets}
    for m in re.finditer(
            rb'[\x48-\x4f][\x8d\x8b\x89\x3b\x39\x85\x63\x23\x2b\x03\x33]',
            raw):
        i = m.start()
        if i + 7 > len(raw) or raw[i + 2] not in RIP_MODRM:
            continue
        disp = struct.unpack_from('<i', raw, i + 3)[0]
        tgt = base + i + 7 + disp
        if tgt in hits:
            hits[tgt].add(base + i)
    for m in re.finditer(rb'[\x8d\x8b\x89\x3b\x39\x85]', raw):
        i = m.start()
        if i + 6 > len(raw) or raw[i + 1] not in RIP_MODRM:
            continue
        disp = struct.unpack_from('<i', raw, i + 2)[0]
        tgt = base + i + 6 + disp
        if tgt in hits:
            hits[tgt].add(base + i)
    for m in re.finditer(rb'\xff', raw):
        i = m.start()
        if i + 6 > len(raw) or raw[i + 1] not in RIP_MODRM:
            continue
        disp = struct.unpack_from('<i', raw, i + 2)[0]
        tgt = base + i + 6 + disp
        if tgt in hits:
            hits[tgt].add(base + i)
    return {hex(k): [hex(x) for x in sorted(v)]
            for k, v in hits.items()}


def fnv_bodies(data, starts, by_start):
    raw, base = _text(data)
    bodies = set()
    for m in re.finditer(
            rb'[\x48\x49][\xb8-\xbf]\x25\x23\x22\x84\xe4\x9c\xf2\xcb',
            raw):
        f = _body_of(starts, by_start, base + m.start())
        if f is not None:
            bodies.add(f['start'])
    return [hex(x) for x in sorted(bodies)]


def byte_imm_stores(raw, val):
    """Sites of `mov byte ptr [mem], imm8` (C6 /0, mod != 3)
    whose immediate equals val; returns body-relative offsets."""
    hits = []
    for m in re.finditer(rb'\xc6', raw):
        i = m.start()
        if i + 2 > len(raw):
            continue
        modrm = raw[i + 1]
        mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        if reg != 0 or mod == 3:
            continue
        j = i + 2
        if rm == 4:
            if j >= len(raw):
                continue
            sib = raw[j]
            j += 1
            if mod == 0 and (sib & 7) == 5:
                j += 4
        elif rm == 5 and mod == 0:
            j += 4
        if mod == 1:
            j += 1
        elif mod == 2:
            j += 4
        if j < len(raw) and raw[j] == val:
            hits.append(i)
    return hits


def _has_imul58(raw):
    return re.search(
        rb'[\x48\x49\x4c\x4d]\x6b[\x00-\xff]\x58', raw) is not None or \
        re.search(
            rb'[\x48\x49\x4c\x4d]\x69[\x00-\xff]\x58\x00\x00\x00',
            raw) is not None


def tied_erase_candidates(data, fs):
    """Bodies that store an immediate 0x80 byte AND carry a
    tie to a 0x58-bucket map: imul 0x58, the FNV basis, a
    bcmp slot call, or a call to the map drop 0x4742960."""
    out = []
    for f in fs:
        raw = read(data, f['start'], f['end'] - f['start'])[1]
        if not byte_imm_stores(raw, 0x80):
            continue
        # (slot / call ties are checked on this body only)
        body_slots = []
        for m in re.finditer(rb'\xff[\x15\x25]', raw):
            i = m.start()
            if i + 6 > len(raw):
                continue
            disp = struct.unpack_from('<i', raw, i + 2)[0]
            if f['start'] + i + 6 + disp == 0x64df9f8:
                body_slots.append(f['start'] + i)
        calls_drop = False
        for m in re.finditer(rb'\xe8', raw):
            i = m.start()
            if i + 5 > len(raw):
                continue
            disp = struct.unpack_from('<i', raw, i + 1)[0]
            if f['start'] + i + 5 + disp == 0x4742960:
                calls_drop = True
        if _has_imul58(raw) or FNV_BASIS in raw or body_slots \
                or calls_drop:
            out.append(hex(f['start']))
    return out


def tzcnt_bsr_bodies(data, fs):
    """Bodies with the erase_no_drop census shape: a REX
    tzcnt, a REX bsr/lzcnt, and a register byte store."""
    out = []
    for f in fs:
        raw = read(data, f['start'], f['end'] - f['start'])[1]
        if not re.search(rb'\xf3[\x48\x49\x4c\x4d]\x0f\xbc', raw):
            continue
        if not (re.search(rb'\xf3[\x48\x49\x4c\x4d]\x0f\xbd', raw)
                or re.search(rb'[\x48\x49\x4c\x4d]\x0f\xbd', raw)):
            continue
        if not re.search(
                rb'[\x88\x44\x88\x43\x88\x41\x88]\x04'
                rb'|[\x88\x44\x88\x43\x88\x41\x88]\x44'
                rb'|[\x88\x44\x88]\x84', raw):
            continue
        out.append(hex(f['start']))
    return out


def mov80_imul58_bodies(data, fs):
    """Bodies that materialise 0x80 into a byte register
    (mov r8b/al/..., 0x80 forms) while using imul 0x58."""
    out = []
    for f in fs:
        raw = read(data, f['start'], f['end'] - f['start'])[1]
        if re.search(rb'[\xb0-\xb7]\x80|[\x40\x41][\xb0-\xb7]\x80',
                     raw) and _has_imul58(raw):
            out.append(hex(f['start']))
    return out


def cluster_imm_stores(data, fs):
    """Immediate 0x80 / 0xff byte stores per body inside the
    S family cluster range."""
    out = {}
    for f in fs:
        if not (CLUSTER_LO <= f['start'] < CLUSTER_HI):
            continue
        raw = read(data, f['start'], f['end'] - f['start'])[1]
        s80 = [hex(f['start'] + i)
               for i in byte_imm_stores(raw, 0x80)]
        sff = [hex(f['start'] + i)
               for i in byte_imm_stores(raw, 0xff)]
        if s80 or sff:
            out[hex(f['start'])] = {'imm80': s80, 'immff': sff}
    return out


def rela_addend_census(data, target):
    out = {}
    for name in ('.rela.dyn', '.rela.plt'):
        rel = _relocations(data, name)
        out[name] = [{'slot': hex(slot), 'type': e['type']}
                     for slot, e in sorted(rel.items())
                     if e['addend'] == target]
    return out


def absolute_word_census(data, value):
    """File offsets of the 64-bit little-endian word `value`,
    classified by containing section."""
    pat = struct.pack('<Q', value)
    secs = sections(data)
    hits = []
    i = data.find(pat)
    while i != -1:
        name = None
        for s in secs:
            if s['type'] != 8 and s['offset'] <= i < \
                    s['offset'] + s['size']:
                name = s['name']
                break
        hits.append({'file_offset': hex(i), 'section': name})
        i = data.find(pat, i + 1)
    return hits


def analyze(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('wrong node115 capture')
    _pins(data, CLEANUP_PINS, 'marked_cleanup')
    _pins(data, DROP_PINS, 'map_drop')
    _pins(data, SIBLING_PAD_PINS, 'sibling_grow')
    for label, (site, slot) in DROP_SLOT_CALLS.items():
        _slot_call(data, site, slot, f'map_drop {label}')
    bindings = slot_bindings(data)
    fs, starts, by_start = _fde_bodies(data)

    fnv = fnv_bodies(data, starts, by_start)
    if len(fnv) != 20:
        raise ValueError('FNV body census changed')
    fnv_cluster = [b for b in fnv
                   if CLUSTER_LO <= int(b, 16) < CLUSTER_HI]
    if fnv_cluster != ['0x4741960', '0x4742130', '0x4742aa0',
                       '0x474b620']:
        raise ValueError('cluster FNV census changed')
    tied = tied_erase_candidates(data, fs)
    if tied != []:
        raise ValueError('tied erase candidate census changed')
    tzbs = tzcnt_bsr_bodies(data, fs)
    if tzbs != ['0x143f000', '0x63bb7e0']:
        raise ValueError('tzcnt/bsr body census changed')
    mov80 = mov80_imul58_bodies(data, fs)
    mov80_cluster = [b for b in mov80
                     if CLUSTER_LO <= int(b, 16) < CLUSTER_HI]
    if mov80_cluster != []:
        raise ValueError('mov80 cluster census changed')
    imm = cluster_imm_stores(data, fs)
    if any(v['imm80'] for v in imm.values()):
        raise ValueError('cluster imm80 census changed')
    if imm.get('0x4742aa0', {}).get('immff') != \
            ['0x474320c', '0x4743211']:
        raise ValueError('grow immff census changed')

    callers = direct_call_census(
        data, (0x47425c0, 0x4742960, 0x4742130, GROW_BODY))
    if callers['0x47425c0'] != [['0x4743fdd', '0xe8']]:
        raise ValueError('cleanup caller census changed')
    if callers['0x4742960'] != [
            ['0x47408db', '0xe8'], ['0x474205d', '0xe8'],
            ['0x47429c1', '0xe8'], ['0x474b419', '0xe8'],
            ['0x4740a58', '0xe9'], ['0x474ac58', '0xe9']]:
        raise ValueError('map drop caller census changed')
    if callers['0x4742130'] != [['0x4740368', '0xe8'],
                                ['0x4740745', '0xe8']]:
        raise ValueError('lookup caller census changed')
    if callers[hex(GROW_BODY)] != []:
        raise ValueError('grow direct-call census changed')
    slot_census = slot_call_census(data, GROW_SLOT)
    if slot_census != ['0x474ba06']:
        raise ValueError('grow slot census changed')
    riprel = riprel_census(data, (GROW_BODY, GROW_SLOT))
    if riprel[hex(GROW_BODY)] != [] or \
            riprel[hex(GROW_SLOT)] != ['0x474ba06']:
        raise ValueError('grow rip-relative census changed')
    rela = rela_addend_census(data, GROW_BODY)
    if rela['.rela.dyn'] != [{'slot': '0x64eaf78', 'type': 8}] \
            or rela['.rela.plt'] != []:
        raise ValueError('grow rela census changed')
    abs_body = absolute_word_census(data, GROW_BODY)
    abs_slot = absolute_word_census(data, GROW_SLOT)
    if len(abs_body) != 1 or abs_body[0]['section'] != '.rela.dyn' \
            or len(abs_slot) != 1 \
            or abs_slot[0]['section'] != '.rela.dyn':
        raise ValueError('grow absolute-word census changed')
    if int(abs_body[0]['file_offset'], 16) - \
            int(abs_slot[0]['file_offset'], 16) != 16:
        raise ValueError('grow rela entry layout changed')

    _, fs2, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs2}

    def frame_records(a, b, sha, role):
        if (a, b) not in fdes:
            raise ValueError(f'{role} scope FDE changed')
        offset, raw = read(data, a, b - a)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != sha:
            raise ValueError(f'{role} body changed')
        records = {}
        for kind in ['fde', 'cie']:
            va = fdes[(a, b)][kind]
            n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
            records[kind] = {'va': hex(va),
                             'bytes_hex': read(data, va, n)[1].hex()}
        return {'role': role, 'start': hex(a), 'end': hex(b),
                'file_offset': hex(offset), 'bytes': b - a,
                'sha256': digest, 'frames': records}

    owners = [frame_records(a, b, sha, role)
              for role, (a, b, sha) in OWNERS.items()]
    boundaries = [frame_records(a, b, sha, role)
                  for role, (a, b, sha) in BOUNDARIES.items()]
    return {
        'target_sha256': SHA,
        'owners': owners,
        'boundaries': boundaries,
        'slot_bindings': bindings,
        'caller_census': {
            'marked_cleanup': callers['0x47425c0'],
            'map_drop': callers['0x4742960'],
            'map_lookup': callers['0x4742130'],
        },
        'grow_reference_census': {
            'direct_e8_e9': callers[hex(GROW_BODY)],
            'slot_ff15_ff25': slot_census,
            'riprel_all_forms': riprel,
            'rela_addend': rela,
            'absolute_qword_body': abs_body,
            'absolute_qword_slot': abs_slot,
        },
        'erase_candidate_censuses': {
            'fnv_bodies': fnv,
            'fnv_bodies_cluster': fnv_cluster,
            'imm80_store_tied_bodies': tied,
            'tzcnt_bsr_bytestore_bodies': tzbs,
            'mov80_imul58_bodies_count': len(mov80),
            'mov80_imul58_bodies_cluster': mov80_cluster,
            'cluster_imm_stores': imm,
        },
        'cleanup_phases': [
            'entry: rbx = the map pointer loaded from the '
            'descriptor at [rdi+0x00]; r14 = the record drop '
            'function pointer at [rdi+0x08] (a null pointer '
            'skips the scan); r12 = the record stride at '
            '[rdi+0x10]; the mask is loaded from map+0x08 and '
            'a mask of -1 skips the scan',
            'scan: control bytes are visited from index 0 '
            'upward (the byte at ctrl + index is compared '
            'against 0, and the loop advances while the '
            'subtraction does not overflow -- only the byte '
            '0x80, the in-place fixup mark, stops the scan); '
            'the scan ends when the index arithmetic reaches '
            'the mask-derived bound',
            'per marked slot: the mask is reloaded, the slot '
            'index is wrapped (rbp & mask), 0xff is stored at '
            'ctrl + index (0x4742623) and at the mirror '
            'ctrl + (rbp & mask) + 0x10 (0x474262b), the '
            'record pointer (ctrl plus the accumulated '
            '-index*stride offset) is passed to the '
            'descriptor function pointer (call r14 at '
            '0x4742636), and the item count at map+0x18 is '
            'decremented by one (0x474263b)',
            'finish: growth-left = cap(mask + 1) - items, '
            'with the grow packet capacity model (cmovb '
            'small-table form included), is stored at '
            'map+0x10 (0x4742663); the control pointer and '
            'the mask are never stored',
        ],
        'drop_phases': [
            'entry: the mask at map+0x08 is the gate -- zero '
            'returns at once (the static empty block is not '
            'heap); the item count at map+0x18 bounds the '
            'walk',
            'walk: control groups are loaded in order with '
            'movdqa/pmovmskb; the inverted mask selects the '
            'full (non-special) lanes; each group step moves '
            'the bucket cursor by -0x580 (16 buckets of '
            '0x58) and an intra-group lane resolves with '
            'tzcnt and an imul by 0x58',
            'per live bucket: the key buffer at bucket+0x08 '
            'is freed through the dealloc slot when the key '
            'record first word at bucket+0x00 is nonzero '
            '(size = that word); the child S mapped array '
            'at bucket+0x28 is freed when the count at '
            'bucket+0x20 is nonzero (size = count*8); the '
            'body recurses into the child S embedded map '
            'at bucket+0x38 (self-call at 0x47429c1)',
            'finish: the body tail-jumps to the dealloc '
            'slot with base = ctrl - align16(buckets*0x58) '
            'and the total size align16(buckets*0x58) + '
            'buckets + 16; no control byte is rewritten and '
            'neither map+0x10 nor map+0x18 is stored',
        ],
        'verdicts': {
            'removal_side': (
                'No single-entry erase body for the S-rooted '
                'map can be isolated: the censused candidate '
                'sets are empty or untied, the map operation '
                'set traced across the RE-015 packets is '
                'build / grow / lookup / replace-on-hit / '
                'whole-table drop, and the only '
                'removal-flavoured body in the cluster '
                '(0x47425c0) is the sibling grow\'s '
                'unwind-path cleanup of fixup-marked records '
                '-- it blanks marked slots to 0xff (slot '
                'plus mirror), drops each marked record '
                'through a descriptor function pointer, '
                'decrements items once per record and '
                'recomputes growth-left at the end. No body '
                'clears a live entry of this map to a 0x80 '
                'tombstone as a consumer erase, and no body '
                'performs backward-shift deletion for it: '
                'entries leave the S map only when the whole '
                'table is dropped by 0x4742960 or when an '
                'insert hit displaces a value into the '
                'caller\'s hands.'),
            'grow_reachability': (
                'The grow body 0x4742aa0 is referred to '
                'exactly once in the whole binary across '
                'every censused form: the map insert\'s call '
                'through slot 0x64eaf78 at 0x474ba06, passing '
                '(map, 1, map+0x20, 1). Direct E8/E9 sites: '
                'none. Other rip-relative references to the '
                'body or the slot: none. .rela.dyn addend '
                'carriers: only the slot itself; .rela.plt: '
                'none. Absolute words naming the body or '
                'the slot: only that relocation entry\'s own '
                'fields. Nothing reaches the grow body with '
                'a fallibility byte of 0 or an additional '
                'other than 1.'),
        },
    }


def _objdump(path, start, end):
    return subprocess.check_output(
        ['objdump', '-d', '-M', 'intel', '--insn-width=16',
         f'--start-address={start:#x}', f'--stop-address={end:#x}',
         str(path)]).decode('utf-8')


WINDOWS = [
    ('marked_cleanup_objdump.txt', 0x47425c0, 0x4742676,
     [s for s, _ in CLEANUP_PINS.values()]),
    ('map_drop_objdump.txt', 0x4742960, 0x4742a93,
     [s for s, _ in DROP_PINS.values()]
     + [s for s, _ in DROP_SLOT_CALLS.values()]),
    ('sibling_grow_pad_objdump.txt', 0x4743fc3, 0x4743ff0,
     [s for s, _ in SIBLING_PAD_PINS.values()] + [0x4743fdd]),
    ('insert_grow_callsite_objdump.txt', 0x474b9ee, 0x474ba0c,
     [0x474b9ee, 0x474b9f7, 0x474ba01, 0x474ba06]),
]


def generate(binary, output):
    data = Path(binary).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('wrong node115 capture')
    report = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
            dir=output, suffix='.elf', delete=False) as handle:
        handle.write(data)
        snapshot = Path(handle.name)
    try:
        native = subprocess.check_output(
            ['readelf', '--debug-dump=frames-interp',
             str(snapshot)]).decode('utf-8')
        lines = []
        for role, (a, b, _) in list(OWNERS.items()) + \
                list(BOUNDARIES.items()):
            rows = [l for l in native.splitlines()
                    if f'pc={a:016x}..{b:016x}' in l]
            if len(rows) != 1:
                raise ValueError('native FDE disagreement')
            lines.extend(rows)
        for name, start, end, sites in WINDOWS:
            asm = _objdump(snapshot, start, end)
            ins = decode_export(asm, start, end,
                                read(data, start, end - start)[1])
            if not set(sites) <= set(ins):
                raise ValueError(f'{name} evidence site not a '
                                 'native instruction start')
            (output / name).write_bytes(
                asm.replace(str(snapshot),
                            '<authenticated-node115>').encode('utf-8'))
    finally:
        snapshot.unlink()
    (output / 'frames.txt').write_bytes(
        ('\n'.join(lines) + '\n').encode('utf-8'))
    (output / 'records.json').write_bytes(
        (json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--output', type=Path,
                   default=ROOT / 'work/map-remove115')
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['owners']),
                      'bytes': sum(x['bytes'] for x in report['owners']),
                      'executed': False}))
