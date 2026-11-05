#!/usr/bin/env python3
"""Pin who reads the seven stored pointers of the X5 caller bodies.

The X5 consumer-callers packet (RE-005-node115-x5-consumer-callers,
follow-on to PR #3235) pinned the 65 FDE bodies that call the 63
consumers of GOT slot 0x64e7718 directly, and recorded one level up
as counts only.  Seven of those caller bodies have no direct rel32
caller at all; each is reached only through exactly one .rela.dyn
entry whose addend is the body start -- a stored pointer in
.data.rel.ro.  That packet counted the seven stored pointers and
explicitly did not follow them.  This packet answers the question
it left open: who reads those stored pointers?

* for each of the seven bodies the single defining relocation is
  re-derived from the binary (R_X86_64_RELATIVE, addend == body
  start, slot in .data.rel.ro);
* every rip-relative reference to the slot itself is enumerated:
  exactly two slots are referenced directly, one `lea` each, so for
  those two the slot is its own vtable base;
* the other five slots are never referenced directly.  Each is
  the first -- and only -- code entry of a vtable whose
  three-qword header {drop, size, align} occupies the 0x18 bytes
  before the slot (the entry after each of the five points into
  .rodata), and the two slots of this form whose readers dispatch
  in the same body (below) confirm the anchor: they load the
  header address and call through [base + 0x18], which is the
  slot.  Every rip-relative reference to each such base is
  enumerated: exactly one `lea` per base;
* each of the seven reference sites is classified by what its body
  does with the materialised base, tracked forward from the `lea`:
  five readers store the base into a record they construct on the
  stack (the record is then copied into a fresh allocation), and
  two readers additionally dispatch through the stored pointer in
  the same body -- they store the base into an object field and
  immediately `call qword ptr [base + 0x18]`, i.e. they read the
  slot's stored pointer and call the body it names;
* the other reachability forms are excluded by independent passes
  for both the slots and the bases: no relocation addend names a
  slot or a base, no stored 8-byte copy of a slot or base exists
  outside the relocation sections' own serialised entries, no
  instruction materialises a slot or base as an immediate, and no
  .dynsym entry carries one as its value;
* one level up is recorded as counts only: each reader body's raw
  direct rel32 call/jump occurrence count in .text and its
  .rela.dyn addend count.

Once a constructed record carrying a vtable base leaves its
constructor, later reads of the method entry go through that
record's vtable field generically; those dispatch sites are not
attributable to one slot by static evidence and are outside this
packet's question, exactly as the callers' callers were outside
the previous packet's.
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

import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
WORK_ITEM = 'RE-005-node115-x5-stored-pointer-readers'
PACKET_DIR = ROOT / 'research/work-items' / WORK_ITEM

SOURCE_WORK_ITEM = 'RE-005-node115-x5-consumer-callers'
SOURCE_SLOT = 0x64e7718

# The seven caller bodies the source packet recorded with zero
# direct rel32 callers and exactly one .rela.dyn addend each
# (its one_level_up.zero_direct_caller_bodies list).
STORED_BODIES_PINNED = [
    0x159d600, 0x17457f0, 0x2a225c0, 0x2a2a0e0, 0x2a64e20,
    0x5a93b50, 0x5a940c0,
]

CALLER_SAVED = ('rax', 'rcx', 'rdx', 'rsi', 'rdi',
                'r8', 'r9', 'r10', 'r11')


def hx(value):
    return '0x%x' % value


def load_segments(data):
    phoff = struct.unpack_from('<Q', data, 0x20)[0]
    phentsize = struct.unpack_from('<H', data, 0x36)[0]
    phnum = struct.unpack_from('<H', data, 0x38)[0]
    segs = []
    for i in range(phnum):
        vals = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phentsize)
        if vals[0] == 1:
            segs.append((vals[3], vals[2], vals[5]))  # vaddr, offset, filesz
    return segs


def va_bytes(data, segs, va, size):
    for vaddr, offset, filesz in segs:
        if vaddr <= va and va + size <= vaddr + filesz:
            return data[offset + (va - vaddr): offset + (va - vaddr) + size]
    raise ValueError('unmapped va %#x' % va)


def va_offset(segs, va):
    for vaddr, offset, filesz in segs:
        if vaddr <= va < vaddr + filesz:
            return offset + (va - vaddr)
    raise ValueError('unmapped va %#x' % va)


def relocations(data, secs, name):
    sec = next(s for s in secs if s['name'] == name)
    out = []
    for p in range(sec['offset'], sec['offset'] + sec['size'], 24):
        r_off, r_info, r_add = struct.unpack_from('<QQq', data, p)
        out.append({'offset': r_off, 'type': r_info & 0xffffffff,
                    'addend': r_add & 0xffffffffffffffff})
    return out, sec


def fde_index(data, secs):
    _, fdes = eh_frame_records(data, secs)
    extents = sorted((f['start'], f['end']) for f in fdes)
    return extents, fdes


def body_of(extents, va):
    starts = [b for b, _ in extents]
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0 and extents[i][0] <= va < extents[i][1]:
        return extents[i]
    return None


def section_of(secs, va):
    for s in secs:
        if s['address'] <= va < s['address'] + s['size']:
            return s['name']
    return None


def disp_candidates(data, sec, target):
    """Positions in sec whose disp32 could end an instruction at
    target with 0..8 trailing bytes: va + 4 + k + disp == target."""
    base_va, off, size = sec['address'], sec['offset'], sec['size']
    blob = data[off:off + size]
    b = np.frombuffer(blob, dtype=np.uint8)
    n = len(b) - 3
    disp = (b[:n].astype(np.int64) | (b[1:n + 1].astype(np.int64) << 8) |
            (b[2:n + 2].astype(np.int64) << 16) |
            (b[3:n + 3].astype(np.int64) << 24))
    disp = np.where(disp >= 0x80000000, disp - 0x100000000, disp)
    dvals = disp + (base_va + np.arange(n, dtype=np.int64)) + 4
    cand = np.nonzero((dvals >= target - 8) & (dvals <= target))[0]
    return [(off + int(j), base_va + int(j), int(target - dvals[j]))
            for j in cand]


def verify_rip_refs(data, exec_secs, target, md):
    """Capstone-verified rip-relative references to target."""
    by_name = {s['name']: s for s in exec_secs.values()}
    hits = []
    cands = []
    for sec in exec_secs.values():
        cands.extend(disp_candidates(data, sec, target))
    for disp_off, disp_va, k in cands:
        end_va = disp_va + 4 + k
        sec = next(s for s in by_name.values()
                   if s['address'] <= disp_va < s['address'] + s['size'])
        end_off = sec['offset'] + (end_va - sec['address'])
        for start_off in range(max(sec['offset'], end_off - 15),
                               disp_off + 1):
            code = data[start_off:end_off]
            if len(code) < 2:
                continue
            got = list(md.disasm(code, sec['address'] +
                                 (start_off - sec['offset']), count=1))
            if not got:
                continue
            insn = got[0]
            if insn.address + insn.size != end_va:
                continue
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP \
                        and insn.address + insn.size + op.mem.disp == target:
                    hits.append({'site': insn.address,
                                 'mnemonic': insn.mnemonic,
                                 'form': 'ripmem'})
                    break
                if op.type == X86_OP_IMM and op.imm == target:
                    hits.append({'site': insn.address,
                                 'mnemonic': insn.mnemonic,
                                 'form': 'imm'})
                    break
            else:
                continue
            break
    return hits


def linear_stream(data, segs, body, md):
    begin, end = body
    off = va_offset(segs, begin)
    return list(md.disasm(data[off:off + (end - begin)], begin))


def reg_root(name):
    m = {'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
         'esi': 'rsi', 'edi': 'rdi', 'esp': 'rsp', 'ebp': 'rbp',
         'ax': 'rax', 'bx': 'rbx', 'cx': 'rcx', 'dx': 'rdx',
         'si': 'rsi', 'di': 'rdi', 'sp': 'rsp', 'bp': 'rbp',
         'al': 'rax', 'bl': 'rbx', 'cl': 'rcx', 'dl': 'rdx',
         'sil': 'rsi', 'dil': 'rdi', 'spl': 'rsp', 'bpl': 'rbp'}
    if name in m:
        return m[name]
    for suffix in ('d', 'w', 'b'):
        mm = re.match(r'(r\d+)%s$' % suffix, name)
        if mm:
            return mm.group(1)
    return name


def insn_text(insn):
    return ('%s %s' % (insn.mnemonic, insn.op_str)).strip()


def track_uses(stream, lea_idx, base, slot):
    """Forward-track the register the lea at lea_idx loads (it holds
    `base`) and record every use of the tracked value: stores of the
    value into memory, memory operands through the value (flagging
    those whose effective address is the slot itself), and address
    computations from it.  Tracking follows mov copies and lea/add/
    sub adjustments, and stops for a register when it is overwritten
    or clobbered by a call (caller-saved set)."""
    lea = stream[lea_idx]
    dest = reg_root(lea.reg_name(lea.operands[0].reg))
    known = {dest: base}
    uses = []
    for i in range(lea_idx + 1, len(stream)):
        insn = stream[i]
        ops = insn.operands
        text = insn_text(insn)
        # Uses through a tracked register as a memory base.
        for oi, op in enumerate(ops):
            if op.type == X86_OP_MEM and op.mem.base != 0 \
                    and op.mem.index == 0:
                rn = reg_root(insn.reg_name(op.mem.base))
                if rn in known:
                    eff = known[rn] + op.mem.disp
                    uses.append({
                        'site': hx(insn.address), 'kind': 'mem_through',
                        'insn': text, 'effective': hx(eff),
                        'reads_stored_pointer': eff == slot})
        # Store of the tracked value itself into memory.
        if insn.mnemonic == 'mov' and len(ops) == 2 \
                and ops[0].type == X86_OP_MEM \
                and ops[1].type == X86_OP_REG \
                and reg_root(insn.reg_name(ops[1].reg)) in known \
                and known[reg_root(insn.reg_name(ops[1].reg))] == base:
            uses.append({'site': hx(insn.address),
                         'kind': 'store_value', 'insn': text,
                         'effective': None,
                         'reads_stored_pointer': False})
        # Value propagation / kills.
        if insn.mnemonic == 'lea' and len(ops) == 2 \
                and ops[0].type == X86_OP_REG \
                and ops[1].type == X86_OP_MEM:
            dst = reg_root(insn.reg_name(ops[0].reg))
            if ops[1].mem.base == X86_REG_RIP:
                known.pop(dst, None)
            elif ops[1].mem.index == 0 and ops[1].mem.base != 0:
                src = reg_root(insn.reg_name(ops[1].mem.base))
                if src in known:
                    known[dst] = known[src] + ops[1].mem.disp
                else:
                    known.pop(dst, None)
            else:
                known.pop(dst, None)
            continue
        if insn.mnemonic == 'mov' and len(ops) == 2 \
                and ops[0].type == X86_OP_REG \
                and ops[1].type == X86_OP_REG:
            dst = reg_root(insn.reg_name(ops[0].reg))
            src = reg_root(insn.reg_name(ops[1].reg))
            if src in known:
                known[dst] = known[src]
            else:
                known.pop(dst, None)
            continue
        if insn.mnemonic in ('add', 'sub') and len(ops) == 2 \
                and ops[0].type == X86_OP_REG \
                and ops[1].type == X86_OP_IMM:
            dst = reg_root(insn.reg_name(ops[0].reg))
            if dst in known:
                known[dst] += ops[1].imm if insn.mnemonic == 'add' \
                    else -ops[1].imm
            continue
        if ops and ops[0].type == X86_OP_REG \
                and insn.mnemonic not in ('cmp', 'test', 'push'):
            known.pop(reg_root(insn.reg_name(ops[0].reg)), None)
        if insn.mnemonic == 'call':
            for r in CALLER_SAVED:
                known.pop(r, None)
    return uses


def record_geometry(stream, store_idx):
    """For a store of the base into [rsp + k]: find the constructor's
    copy pattern -- a later `lea rsi, [rsp + m]` with a `mov edx, N`
    before the following call -- and return the record's stack base
    offset, size, and the field offset k - m of the stored base."""
    store = stream[store_idx]
    dst = store.operands[0]
    if dst.mem.base == 0 or store.reg_name(dst.mem.base) != 'rsp':
        return None
    k = dst.mem.disp
    for j in range(store_idx + 1, len(stream)):
        insn = stream[j]
        if insn.mnemonic == 'lea' and len(insn.operands) == 2 \
                and insn.operands[0].type == X86_OP_REG \
                and insn.reg_name(insn.operands[0].reg) == 'rsi' \
                and insn.operands[1].type == X86_OP_MEM \
                and insn.operands[1].mem.base != 0 \
                and insn.reg_name(insn.operands[1].mem.base) == 'rsp':
            m = insn.operands[1].mem.disp
            for t in range(j + 1, min(j + 9, len(stream))):
                nxt = stream[t]
                if nxt.mnemonic == 'mov' and len(nxt.operands) == 2 \
                        and nxt.operands[0].type == X86_OP_REG \
                        and reg_root(nxt.reg_name(
                            nxt.operands[0].reg)) == 'rdx' \
                        and nxt.operands[1].type == X86_OP_IMM:
                    size = nxt.operands[1].imm
                    if m <= k < m + size:
                        return {'record_stack_base': hx(m),
                                'record_size': size,
                                'field_offset': hx(k - m)}
                    break
    return None


def raw_direct_counts(data, secs, wanted):
    """Raw census: e8/e9 byte occurrences in .text whose rel32 lands
    on a wanted start (counts only, unverified)."""
    text = next(s for s in secs if s['name'] == '.text')
    base, off, size = text['address'], text['offset'], text['size']
    counts = {w: 0 for w in wanted}
    for op in (0xE8, 0xE9):
        idx, limit = off, off + size - 5
        while idx < limit:
            j = data.find(bytes([op]), idx, limit + 1)
            if j < 0:
                break
            rel = struct.unpack_from('<i', data, j + 1)[0]
            tgt = base + (j - off) + 5 + rel
            if tgt in counts:
                counts[tgt] += 1
            idx = j + 1
    return counts


def stored_copies(data, rela_secs, targets):
    ranges = [(s['offset'], s['offset'] + s['size']) for s in rela_secs]
    out = []
    for target in targets:
        needle = struct.pack('<Q', target)
        idx = 0
        while True:
            j = data.find(needle, idx)
            if j < 0:
                break
            if not any(lo <= j < hi for lo, hi in ranges):
                out.append({'value': target, 'file_offset': j})
            idx = j + 1
    return out


def imm_materialisations(data, exec_secs, targets, md):
    out = []
    for target in targets:
        needle = struct.pack('<I', target)
        for sec in exec_secs:
            idx, limit = sec['offset'], sec['offset'] + sec['size'] - 4
            while idx < limit:
                j = data.find(needle, idx, limit + 1)
                if j < 0:
                    break
                for start in range(max(sec['offset'], j - 11), j + 1):
                    got = list(md.disasm(
                        data[start:j + 4],
                        sec['address'] + (start - sec['offset']), count=1))
                    if not got:
                        continue
                    insn = got[0]
                    if start + insn.size < j + 4:
                        continue
                    for op in insn.operands:
                        if op.type == X86_OP_IMM and op.imm == target:
                            out.append({'site': insn.address,
                                        'target': target})
                idx = j + 1
    return out


def analyze(data):
    if len(data) != TARGET_SIZE \
            or hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('artifact authentication failed')
    secs = sections(data)
    segs = load_segments(data)
    extents, _ = fde_index(data, secs)
    exec_secs = {s['name']: s for s in secs
                 if s['type'] != 8 and s.get('flags', 0) & 0x4
                 and s['size']}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    rels_dyn, rela_dyn_sec = relocations(data, secs, '.rela.dyn')
    rels_plt, rela_plt_sec = relocations(data, secs, '.rela.plt')
    fde_starts = {b for b, _ in extents}

    # The seven stored bodies, re-derived from the FDE index.
    stored_bodies = {}
    for start in STORED_BODIES_PINNED:
        b = body_of(extents, start)
        assert b is not None and b[0] == start, \
            'stored body %#x is not an FDE body start' % start
        raw = va_bytes(data, segs, b[0], b[1] - b[0])
        stored_bodies[start] = {
            'start': b[0], 'end': b[1],
            'sha256': hashlib.sha256(raw).hexdigest()}

    # The defining relocation of each stored body: exactly one
    # entry, in .rela.dyn, of type R_X86_64_RELATIVE (8).
    slot_of = {}
    for start in STORED_BODIES_PINNED:
        hits = [r for r in rels_dyn + rels_plt if r['addend'] == start]
        assert len(hits) == 1, \
            'body %#x has %d defining relocations' % (start, len(hits))
        hit = hits[0]
        assert hit in rels_dyn and hit['type'] == 8
        assert section_of(secs, hit['offset']) == '.data.rel.ro'
        slot_of[start] = hit['offset']

    entries = []
    all_targets = set()
    for start in STORED_BODIES_PINNED:
        slot = slot_of[start]
        all_targets.add(slot)
        slot_refs = [h for h in verify_rip_refs(
            data, exec_secs, slot, md) if h['form'] == 'ripmem']
        if slot_refs:
            form = 'slot_base'
            base = slot
            header = None
            triple = [struct.unpack_from(
                '<Q', data, va_offset(segs, slot - 0x18 + 8 * i))[0]
                for i in range(3)]
            base_refs = slot_refs
        else:
            form = 'header'
            base = slot - 0x18
            drop_entry = next(r for r in rels_dyn
                              if r['offset'] == base)
            drop = drop_entry['addend']
            assert drop in fde_starts, \
                'header drop %#x is not an FDE body start' % drop
            size = struct.unpack_from(
                '<Q', data, va_offset(segs, base + 8))[0]
            align = struct.unpack_from(
                '<Q', data, va_offset(segs, base + 0x10))[0]
            assert 0 < size and align in (1, 2, 4, 8, 16, 32, 64)
            header = {'drop': hx(drop), 'size': size, 'align': align}
            triple = None
            base_refs = [h for h in verify_rip_refs(
                data, exec_secs, base, md) if h['form'] == 'ripmem']
        all_targets.add(base)
        assert base_refs, 'no reference to base %#x' % base
        assert all(h['mnemonic'] == 'lea' for h in base_refs), \
            'non-lea reference to base %#x' % base

        # Method run: consecutive relocation entries from the slot
        # whose addends are FDE body starts.
        run = 0
        while True:
            ent = next((r for r in rels_dyn
                        if r['offset'] == slot + 8 * run), None)
            if ent is None or ent['addend'] not in fde_starts:
                break
            run += 1

        # The qword immediately after the slot, for the record.
        after_ent = next((r for r in rels_dyn
                          if r['offset'] == slot + 8), None)
        if after_ent is not None:
            entry_after = {
                'kind': 'relocation', 'addend': hx(after_ent['addend']),
                'addend_section': section_of(secs, after_ent['addend'])}
        else:
            entry_after = {
                'kind': 'raw',
                'value': hx(struct.unpack_from(
                    '<Q', data, va_offset(segs, slot + 8))[0]),
                'addend_section': None}

        readers = []
        for h in sorted(base_refs, key=lambda x: x['site']):
            rb = body_of(extents, h['site'])
            assert rb is not None, \
                'reference site %#x outside any FDE body' % h['site']
            stream = linear_stream(data, segs, rb, md)
            index = {insn.address: i for i, insn in enumerate(stream)}
            assert h['site'] in index, \
                'linear sweep of reader body misses site %#x' % h['site']
            li = index[h['site']]
            uses = track_uses(stream, li, base, slot)
            store_idx = next(
                (i for i in range(li + 1, len(stream))
                 if hx(stream[i].address) in
                 {u['site'] for u in uses if u['kind'] == 'store_value'}),
                None)
            geom = record_geometry(stream, store_idx) \
                if store_idx is not None else None
            dispatch = [u for u in uses
                        if u['kind'] == 'mem_through'
                        and u['reads_stored_pointer']
                        and stream[index[int(u['site'], 16)]].mnemonic
                        == 'call']
            if dispatch and any(u['kind'] == 'store_value'
                                for u in uses):
                classification = 'store_and_direct_dispatch'
            elif dispatch:
                classification = 'direct_dispatch'
            elif geom is not None:
                classification = 'materialise_into_constructed_record'
            elif uses:
                classification = 'other_use'
            else:
                classification = 'address_only'
            prev_insn = stream[li - 1] if li else None
            next_insn = stream[li + 1] if li + 1 < len(stream) else None
            rraw = va_bytes(data, segs, rb[0], rb[1] - rb[0])
            readers.append({
                'body': {'start': hx(rb[0]), 'end': hx(rb[1]),
                         'bytes': rb[1] - rb[0],
                         'sha256': hashlib.sha256(rraw).hexdigest()},
                'lea_site': hx(h['site']),
                'lea_insn': insn_text(stream[li]),
                'prev_insn': insn_text(prev_insn)
                if prev_insn is not None else None,
                'next_insn': insn_text(next_insn)
                if next_insn is not None else None,
                'uses': uses,
                'record': geom,
                'classification': classification,
            })
        body = stored_bodies[start]
        entries.append({
            'body': {'start': hx(body['start']), 'end': hx(body['end']),
                     'bytes': body['end'] - body['start'],
                     'sha256': body['sha256']},
            'slot': hx(slot),
            'slot_section': '.data.rel.ro',
            'relocation': {'offset': hx(slot), 'type': 8,
                           'addend': hx(start)},
            'form': form,
            'base': hx(base),
            'header': header,
            'preceding_triple': [hx(t) for t in triple]
            if triple is not None else None,
            'method_run': run,
            'entry_after_slot': entry_after,
            'readers': readers,
        })

    # Exclusion census for every slot and base.
    addend_hits = sum(1 for r in rels_dyn + rels_plt
                      if r['addend'] in all_targets)
    copies = stored_copies(data, [rela_dyn_sec, rela_plt_sec],
                           sorted(all_targets))
    imms = imm_materialisations(data, list(exec_secs.values()),
                                sorted(all_targets), md)
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynsym_hits = 0
    for i in range(dynsym['size'] // 24):
        val = struct.unpack_from('<Q', data,
                                 dynsym['offset'] + i * 24 + 8)[0]
        if val in all_targets:
            dynsym_hits += 1

    # One level up, counts only, for the reader bodies.
    reader_starts = sorted({int(r['body']['start'], 16)
                            for e in entries for r in e['readers']})
    up_counts = raw_direct_counts(data, secs, set(reader_starts))
    up_addends = {s: sum(1 for r in rels_dyn if r['addend'] == s)
                  for s in reader_starts}
    for e in entries:
        for r in e['readers']:
            s = int(r['body']['start'], 16)
            r['direct_callers'] = up_counts[s]
            r['relocation_addends'] = up_addends[s]

    census = {
        'executable_sections': sorted(exec_secs),
        'stored_bodies': len(entries),
        'defining_relocations_per_body': 1,
        'relocation_type': 8,
        'slot_section': '.data.rel.ro',
        'slot_base_forms': sum(1 for e in entries
                               if e['form'] == 'slot_base'),
        'header_forms': sum(1 for e in entries
                            if e['form'] == 'header'),
        'direct_references_to_slots': sum(
            len(e['readers']) for e in entries
            if e['form'] == 'slot_base'),
        'references_to_bases': sum(len(e['readers']) for e in entries),
        'reader_bodies': len(reader_starts),
        'all_references_are_lea': True,
        'direct_dispatch_readers': sum(
            1 for e in entries for r in e['readers']
            if r['classification'] == 'store_and_direct_dispatch'),
        'constructed_record_readers': sum(
            1 for e in entries for r in e['readers']
            if r['classification']
            == 'materialise_into_constructed_record'),
        'rela_dyn_entries': len(rels_dyn),
        'rela_plt_entries': len(rels_plt),
        'relocations_with_addend_eq_any_slot_or_base': addend_hits,
        'stored_qword_copies_of_slots_or_bases_outside_rela':
            len(copies),
        'imm_materialisations_of_slots_or_bases': len(imms),
        'dynsym_entries_with_slot_or_base_st_value': dynsym_hits,
    }

    records = {
        'artifact': {'path': 'artifacts/node/115/hl-node',
                     'sha256': TARGET_SHA256, 'size': TARGET_SIZE},
        'captured_code_executed': False,
        'question': (
            'Who reads the seven stored pointers that are the only '
            'static reachability of the seven X5-consumer caller '
            'bodies with no direct callers -- at which reference '
            'sites, in which bodies, and in what use form?'),
        'source': {
            'work_item': SOURCE_WORK_ITEM,
            'slot': hx(SOURCE_SLOT),
            'stored_body_count': len(STORED_BODIES_PINNED),
            'note': (
                'The seven bodies are the source packet\'s '
                'one-level-up zero-direct-caller set; each body\'s '
                'extent and hash, its defining relocation, and its '
                'slot are re-derived from the binary in analyze().'),
        },
        'census': census,
        'stored': entries,
        'answer': {
            'one_reader_each': (
                'Each of the seven stored pointers is read through '
                'exactly one materialisation of its vtable base: '
                'seven `lea` reference sites in seven distinct '
                'reader bodies, and no other rip-relative reference '
                'to any slot or base exists.'),
            'forms': (
                'Two slots (0x64b9b70, 0x64ba390) are their own '
                'vtable base: the reader loads the slot address '
                'itself, and the slot begins a run of seven '
                'consecutive code entries.  The other five slots '
                'are the first -- and only -- code entry of a '
                'vtable whose {drop, size, align} header sits in '
                'the 0x18 bytes before the slot (the entry after '
                'each of the five points into .rodata: 0x448bd0 '
                'for three of them, 0x4349eb for two), and the '
                'reader loads the header address.'),
            'uses': (
                'Five readers store the materialised base into a '
                'record they construct on the stack -- at field '
                'offset 0x10 of a 0x200-byte record for the two '
                'slot-base readers, and at field offset 0x30 of a '
                '0x128-byte record for the three header-form '
                'constructors -- and the record is then copied into '
                'a fresh allocation.  The remaining two readers '
                '(the header-form dispatchers) also store the base, '
                'into an object field at +0x70, and immediately read '
                'the stored pointer back with '
                '`call qword ptr [rax + 0x18]`: the effective '
                'address of that call is the slot itself, so these '
                'two bodies are direct readers of the stored '
                'pointer, calling exactly the body it names '
                '(0x2a225c0 and 0x2a2a0e0).'),
            'no_other_path': (
                'No relocation addend, no stored 8-byte copy '
                'outside the relocation sections, no immediate '
                'materialisation, and no dynamic symbol names any '
                'of the seven slots or five bases.'),
        },
        'boundaries': {
            'prior_packets': (
                'RE-011-evm-permit-routing-115 records two of the '
                'seven (reader body, base, stored body) triples as '
                'method-table rows -- future body 0x2d087e0 with '
                'inner vtable 0x6445868 and inner poll target '
                '0x2a2a0e0 (eth_call), and future body 0x2d062f0 '
                'with inner vtable 0x64455c8 and inner poll target '
                '0x2a225c0 (eth_estimateGas) -- without reference '
                'sites, use forms, or a completeness census. '
                'RE-011-eth-call-path-115, '
                'RE-001-node115-channel-repoll-terminal and '
                'RE-003-pr-integration-20261103 mention individual '
                'body or slot addresses incidentally.  The source '
                'packet (RE-005-node115-x5-consumer-callers) '
                'counted the seven stored pointers and left their '
                'readers as an explicit boundary; no earlier packet '
                'enumerates the readers of all seven, pins their '
                'reference sites and use forms, or excludes the '
                'other reference forms for the slots and bases.'),
            'one_level_up': (
                'For each reader body this packet records only two '
                'counts: raw direct rel32 call/jump byte '
                'occurrences in .text whose target is the body '
                'start, and .rela.dyn entries whose addend is the '
                'body start.  The reader bodies\' own callers are '
                'outside this packet\'s question.'),
            'generic_dispatch': (
                'Once a constructed record carrying a vtable base '
                'leaves its constructor, later reads of the method '
                'entry go through that record\'s vtable field '
                'generically (a load of the field at +0x18 for the '
                'header form, or at +0x0 for the slot-base form); '
                'those dispatch sites are shared by every vtable '
                'of the same shape and are not attributable to one '
                'slot by static evidence.'),
            'runtime_behaviour': (
                'Which runtime path reaches a given reader, what '
                'the per-slot statics name, and the concrete Rust '
                'types of the stored and reader bodies are not '
                'established by static evidence.'),
        },
    }
    return records


def frames_lines(data, records):
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    wanted = {int(e['body']['start'], 16) for e in records['stored']}
    wanted |= {int(r['body']['start'], 16)
               for e in records['stored'] for r in e['readers']}
    frame_sec = next(s for s in secs if s['name'] == '.eh_frame')
    lines = []
    for f in fdes:
        if f['start'] not in wanted:
            continue
        rec_off = frame_sec['offset'] + (f['fde'] - frame_sec['address'])
        length = struct.unpack_from('<I', data, rec_off)[0] + 4
        cie_field = struct.unpack_from('<I', data, rec_off + 4)[0]
        cie_off = frame_sec['offset'] + (f['cie'] - frame_sec['address'])
        lines.append('%08x %016x %08x FDE cie=%08x pc=%016x..%016x'
                     % (rec_off, length, cie_field, cie_off,
                        f['start'], f['end']))
    return lines


def readme_text(records):
    c = records['census']
    rows = []
    for e in records['stored']:
        r = e['readers'][0]
        if e['form'] == 'slot_base':
            form = ('slot is its own base; preceding triple %s'
                    % ', '.join(e['preceding_triple']))
        else:
            h = e['header']
            form = ('header base %s: drop %s, size %d, align %d'
                    % (e['base'], h['drop'], h['size'], h['align']))
        rows.append('- body `%s` (%d bytes), slot `%s` (%s); '
                    'method run %d; reader body `%s`, `lea` at `%s` '
                    '(%s)'
                    % (e['body']['start'], e['body']['bytes'],
                       e['slot'], form, e['method_run'],
                       r['body']['start'], r['lea_site'],
                       r['classification']))
    rows_text = '\n'.join(rows)
    return f"""# RE-005 node 115: who reads the X5 callers' stored pointers

## Question

The consumer-callers packet (`RE-005-node115-x5-consumer-callers`)
pinned the 65 FDE bodies that call the 63 consumers of GOT slot
`0x64e7718` directly, and recorded one level up as counts only.
Seven of those caller bodies have no direct rel32 caller at all;
each is reached only through exactly one `.rela.dyn` entry whose
addend is the body start -- a stored pointer in `.data.rel.ro`.
That packet counted the seven stored pointers and did not follow
them. Who reads them -- at which reference sites, in which bodies,
and in what use form?

## Method

Static analysis only, against the authenticated node 115 binary
(SHA-256 `{records['artifact']['sha256']}`). Each stored body's
defining relocation is re-derived from the binary (exactly one
entry, `R_X86_64_RELATIVE`, addend == body start, slot in
`.data.rel.ro`). Every rip-relative reference to each slot is
enumerated with a disp32 candidate scan over every executable
section ({', '.join(c['executable_sections'])}), each candidate
verified by decoding the instruction at the site, and each
verified site cross-checked against a linear disassembly sweep of
its containing FDE body. For slots with no direct reference, the
vtable header in the 0x18 bytes before the slot is validated
(a relocation at the header base whose addend is an FDE body
start -- the drop entry -- followed by the size and align qwords),
and every rip-relative reference to the header base is enumerated
the same way. Each reference site's use of the materialised base
is classified by forward register tracking inside its body.
Independent passes excluded the other forms for all seven slots
and five bases: relocation addends across all
{c['rela_dyn_entries']} `.rela.dyn` and {c['rela_plt_entries']}
`.rela.plt` entries, stored 8-byte copies outside the relocation
sections' own serialised entries, immediate materialisations, and
`.dynsym` values.

## Answer

Every stored pointer has exactly one reader, and the seven
readers are seven distinct bodies with one `lea` reference site
each:

{rows_text}

Two slots are their own vtable base -- the reader loads the slot
address itself (`0x64b9b70` read by body `0x5964ef0`, `0x64ba390`
by body `0x5965d90`), and each begins a run of seven consecutive
code entries. The other five slots are the first -- and only --
code entry of a vtable whose {{drop, size, align}} header
occupies the 0x18 bytes before the slot (the entry after each of
the five points into `.rodata`), and the reader loads the header
address.

The uses separate into two forms:

- **Materialise into a constructed record
  ({c['constructed_record_readers']} readers)** -- the base is
  stored into a record the reader builds on the stack: at field
  offset 0x10 of a 0x200-byte record for the two slot-base
  readers, and at field offset 0x30 of a 0x128-byte record for
  three header-form readers (bodies `0x15d0660`, `0x16d7df0`,
  `0x294f1a0`). The record is then copied into a fresh allocation.
- **Store and direct dispatch
  ({c['direct_dispatch_readers']} readers)** -- bodies
  `0x2d062f0` and `0x2d087e0` store the header base into an object
  field at +0x70 and immediately read the stored pointer back:
  `call qword ptr [rax + 0x18]`, whose effective address is the
  slot itself. These two bodies call exactly the stored bodies
  `0x2a225c0` and `0x2a2a0e0` through their slots.

No other path exists: no relocation addend, no stored 8-byte
copy, no immediate materialisation, and no dynamic symbol names
any of the seven slots or five bases (the exclusion census is
zero in every form).

One level up is recorded as counts only (`direct_callers` and
`relocation_addends` per reader body).

## Boundaries

{records['boundaries']['prior_packets']}

{records['boundaries']['one_level_up']}

{records['boundaries']['generic_dispatch']}

{records['boundaries']['runtime_behaviour']}
"""


def objdump_text():
    ranges = [('--start-address=0x5964f4c', '--stop-address=0x5964f7b'),
              ('--start-address=0x5965dec', '--stop-address=0x5965e1b'),
              ('--start-address=0x15d089d', '--stop-address=0x15d08da'),
              ('--start-address=0x16d8171', '--stop-address=0x16d81bd'),
              ('--start-address=0x294f3dd', '--stop-address=0x294f419'),
              ('--start-address=0x2d06804', '--stop-address=0x2d06822'),
              ('--start-address=0x2d090a2', '--stop-address=0x2d090c7')]
    out = []
    for start, stop in ranges:
        r = subprocess.run(['objdump', '-d', start, stop, str(TARGET)],
                           capture_output=True, text=True, check=True)
        out.append(r.stdout)
    return '\n'.join(out)


def render_files(records, data):
    files = {}
    files['records.json'] = json.dumps(records, indent=2,
                                       sort_keys=True) + '\n'
    files['frames.txt'] = '\n'.join(frames_lines(data, records)) + '\n'
    files['README.md'] = readme_text(records)
    files['reader_sites.objdump.txt'] = objdump_text()
    manifest = ''.join(
        '%s  %s\n' % (hashlib.sha256(v.encode()).hexdigest(), k)
        for k, v in sorted(files.items()))
    files['MANIFEST.sha256'] = manifest
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('command', choices=('generate', 'check'))
    args = ap.parse_args()
    data = TARGET.read_bytes()
    records = analyze(data)
    files = render_files(records, data)
    if args.command == 'generate':
        PACKET_DIR.mkdir(parents=True, exist_ok=True)
        for name, text in files.items():
            (PACKET_DIR / name).write_text(text)
        print('generated', len(files), 'files in', PACKET_DIR)
    else:
        bad = []
        for name, text in files.items():
            p = PACKET_DIR / name
            if not p.exists() or p.read_text() != text:
                bad.append(name)
        if bad:
            print('STALE:', ', '.join(sorted(bad)))
            return 1
        print('check ok:', len(files), 'files match regeneration')
    return 0


if __name__ == '__main__':
    sys.exit(main())
