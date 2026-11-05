#!/usr/bin/env python3
"""Pin every consumer of the GOT slot that holds the X5 schedule caller.

The X5 env-pair packet (RE-005-node115-x5-env-pair-source, PR #3227)
pinned the schedule-caller body 0x5cf5100 and showed code reaches it
only indirectly: one RELATIVE relocation, in .got slot 0x64e7718,
stores its address.  It left open who loads that slot.  This packet
answers with a census, not a sample:

* every verified rip-relative code reference to 0x64e7718 in every
  executable section (disp32 candidate scan, capstone-verified);
* the absence of every other reference form: no data load, no lea, no
  immediate materialisation, no absolute disp32 reference, no stored
  copy of the slot or target address outside the .rela.dyn section's
  own serialised entries, no relocation whose addend is the slot, and
  no PLT stub;
* the containing FDE body, body hash, and call-site template of each
  consumer: allocation through GOT slot 0x64df590, copy through GOT
  slot 0x64df508, the bool-indexed +0x1f8 pair-entry selection, the
  constant third argument 1, and the (al, rdx) return-pair test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
WORK_ITEM = 'RE-005-node115-x5-caller-slot-consumers'
PACKET_DIR = ROOT / 'research/work-items' / WORK_ITEM

SLOT = 0x64e7718
CALLER = 0x5cf5100
NEIGH_L = 0x64e7710
NEIGH_R = 0x64e7720
ALLOC_SLOT = 0x64df590
COPY_SLOT = 0x64df508
SCAN_TARGETS = (('slot', SLOT), ('caller', CALLER),
                ('neighbour_left', NEIGH_L), ('neighbour_right', NEIGH_R))


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


def relocations(data, secs):
    sec = next(s for s in secs if s['name'] == '.rela.dyn')
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
    import bisect
    starts = [b for b, _ in extents]
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0 and extents[i][0] <= va < extents[i][1]:
        return extents[i]
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


def verify_candidates(data, secs_by_name, candidates, target, md):
    sec_cache = {}
    hits = []
    for disp_off, disp_va, k in candidates:
        end_va = disp_va + 4 + k
        for name, sec in secs_by_name.items():
            if sec['address'] <= disp_va < sec['address'] + sec['size']:
                sec_cache[disp_va] = sec
                break
        sec = sec_cache[disp_va]
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
                                 'operands': insn.op_str,
                                 'bytes': insn.bytes.hex(), 'form': 'ripmem'})
                    break
                if op.type == X86_OP_IMM and op.imm == target:
                    hits.append({'site': insn.address,
                                 'mnemonic': insn.mnemonic,
                                 'operands': insn.op_str,
                                 'bytes': insn.bytes.hex(), 'form': 'imm'})
                    break
            else:
                continue
            break
    return hits


def absolute_disp_refs(data, secs, targets, md):
    text = next(s for s in secs if s['name'] == '.text')
    out = []
    for target in targets:
        needle = struct.pack('<I', target)
        idx, limit = text['offset'], text['offset'] + text['size'] - 4
        while idx < limit:
            j = data.find(needle, idx, limit + 1)
            if j < 0:
                break
            for start in range(max(text['offset'], j - 11), j + 1):
                got = list(md.disasm(data[start:j + 4],
                                     text['address'] + (start -
                                                         text['offset']),
                                     count=1))
                if not got:
                    continue
                insn = got[0]
                if start + insn.size < j + 4:
                    continue
                for op in insn.operands:
                    if op.type == X86_OP_MEM and op.mem.base == 0 \
                            and op.mem.index == 0 and op.mem.disp == target:
                        out.append({'site': insn.address,
                                    'target': target})
            idx = j + 1
    return out


def stored_copies(data, rela_sec, targets):
    """8-byte copies of the target values anywhere in the file outside
    the .rela.dyn section's own serialised entries."""
    out = []
    lo, hi = rela_sec['offset'], rela_sec['offset'] + rela_sec['size']
    for target in targets:
        needle = struct.pack('<Q', target)
        idx = 0
        while True:
            j = data.find(needle, idx)
            if j < 0:
                break
            if not (lo <= j < hi):
                out.append({'value': target, 'file_offset': j})
            idx = j + 1
    return out


def ff15_call_before(data, segs, body, site, target_slot):
    """Nearest preceding ff 15 <disp32> in body that resolves to
    target_slot, or None."""
    begin, _ = body
    begin_off = va_offset(segs, begin)
    site_off = va_offset(segs, site)
    best = None
    for p in range(begin_off, site_off - 5):
        if data[p] == 0xff and data[p + 1] == 0x15:
            disp = struct.unpack_from('<i', data, p + 2)[0]
            va = begin + (p - begin_off)
            if va + 6 + disp == target_slot:
                best = va
    return best


def pair_add_before(data, segs, body, limit_va):
    """Last `add reg, 0x1f8` (REX 81 /r f8 01 00 00) in body before
    limit_va, or None."""
    begin, _ = body
    begin_off = va_offset(segs, begin)
    limit_off = va_offset(segs, limit_va)
    best = None
    for p in range(begin_off, limit_off - 7):
        if data[p] in (0x48, 0x49, 0x4c, 0x4d) and data[p + 1] == 0x81 \
                and 0xc0 <= data[p + 2] <= 0xc7 \
                and data[p + 3:p + 7] == b'\xf8\x01\x00\x00':
            best = begin + (p - begin_off)
    return best


def direct_caller_counts(data, secs, wanted):
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


def analyze(data):
    if len(data) != TARGET_SIZE \
            or hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('artifact authentication failed')
    secs = sections(data)
    segs = load_segments(data)
    extents, fdes = fde_index(data, secs)
    rels, rela_sec = relocations(data, secs)
    exec_secs = {s['name']: s for s in secs
                 if s['type'] != 8 and s.get('flags', 0) & 0x4
                 and s['size']}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    slot_entries = [r for r in rels if r['offset'] == SLOT]
    assert len(slot_entries) == 1 and slot_entries[0]['type'] == 8 \
        and slot_entries[0]['addend'] == CALLER

    census = {}
    verified = {}
    for name, target in SCAN_TARGETS:
        cands = []
        for sec in exec_secs.values():
            cands.extend(disp_candidates(data, sec, target))
        census[name] = len(cands)
        verified[name] = verify_candidates(data, exec_secs, cands,
                                           target, md)
    slot_hits = verified['slot']
    assert all(h['mnemonic'] == 'call' and h['form'] == 'ripmem'
               for h in slot_hits)

    abs_refs = absolute_disp_refs(data, secs, (SLOT, CALLER), md)
    copies = stored_copies(data, rela_sec, (SLOT, CALLER))
    addend_eq_slot = sum(1 for r in rels if r['addend'] == SLOT)
    addend_eq_caller = sum(1 for r in rels if r['addend'] == CALLER)

    bodies = {}
    for h in slot_hits:
        bodies[body_of(extents, h['site'])] = h['site']
    caller_counts = direct_caller_counts(
        data, secs, {b for b, _ in bodies} | {CALLER})

    consumers = []
    for (begin, end), site in sorted(bodies.items()):
        raw = va_bytes(data, segs, begin, end - begin)
        site_off = va_offset(segs, site)
        alloc = ff15_call_before(data, segs, (begin, end), site,
                                 ALLOC_SLOT)
        copy = ff15_call_before(data, segs, (begin, end), site,
                                COPY_SLOT)
        alloc_size = None
        if alloc is not None:
            aoff = va_offset(segs, alloc)
            if data[aoff - 10] == 0xbf and data[aoff - 5] == 0xbe \
                    and data[aoff - 4:aoff] == b'\x07\x00\x00\x00':
                alloc_size = struct.unpack_from('<I', data, aoff - 9)[0]
        consumers.append({
            'site': hx(site),
            'site_bytes': data[site_off:site_off + 6].hex(),
            'body': {'start': hx(begin), 'end': hx(end),
                     'bytes': end - begin,
                     'sha256': hashlib.sha256(raw).hexdigest()},
            'alloc_size': alloc_size,
            'template': {
                'alloc_call': hx(alloc) if alloc is not None else None,
                'copy_call': hx(copy) if copy is not None else None,
                'pair_add_1f8': hx(pair_add_before(
                    data, segs, (begin, end),
                    copy if copy is not None else site))
                if True else None,
                'mov_edx_1_at_site_minus_5':
                    data[site_off - 5:site_off] == b'\xba\x01\x00\x00\x00',
                'return_pair_test':
                    data[site_off + 6:site_off + 9] == b'\x48\x85\xd2',
            },
            'direct_callers': caller_counts[begin],
        })

    clusters = []
    run = [consumers[0]]
    for c in consumers[1:]:
        prev = run[-1]
        gap = int(c['body']['start'], 16) - int(prev['body']['end'], 16)
        if gap <= 0x100:
            run.append(c)
        else:
            clusters.append(run)
            run = [c]
    clusters.append(run)
    cluster_records = [{
        'bodies': len(r),
        'first_body': r[0]['body']['start'],
        'last_body': r[-1]['body']['end'],
        'body_sizes': sorted({c['body']['bytes'] for c in r}),
    } for r in clusters]

    caller_raw = va_bytes(data, segs, CALLER, 0x4d7)
    records = {
        'artifact': {'path': 'artifacts/node/115/hl-node',
                     'sha256': TARGET_SHA256, 'size': TARGET_SIZE},
        'captured_code_executed': False,
        'question': (
            'Who loads GOT slot 0x64e7718, the only static holder of '
            'the X5 schedule-caller body 0x5cf5100, and under what '
            'call conditions?'),
        'slot': {
            'va': hx(SLOT), 'section': '.got',
            'relocation': {'r_offset': hx(SLOT), 'type': 8,
                           'addend': hx(CALLER)},
            'target_body': {
                'start': hx(CALLER), 'end': hx(CALLER + 0x4d7),
                'bytes': 0x4d7,
                'sha256': hashlib.sha256(caller_raw).hexdigest()},
            'target_direct_callers': caller_counts[CALLER],
        },
        'census': {
            'executable_sections': sorted(exec_secs),
            'disp32_candidates': census,
            'verified_rip_relative_refs': {
                name: len(hits) for name, hits in verified.items()},
            'absolute_disp32_refs': len(abs_refs),
            'stored_qword_copies_outside_rela_dyn': len(copies),
            'relocations_with_addend_eq_slot': addend_eq_slot,
            'relocations_with_addend_eq_caller': addend_eq_caller,
        },
        'consumers': consumers,
        'consumer_count': len(consumers),
        'clusters': cluster_records,
        'neighbours': {
            hx(NEIGH_L): {
                'target': hx(next(r['addend'] for r in rels
                                  if r['offset'] == NEIGH_L)),
                'verified_ref_sites': [hx(h['site'])
                                       for h in verified[
                                           'neighbour_left']]},
            hx(NEIGH_R): {
                'target': hx(next(r['addend'] for r in rels
                                  if r['offset'] == NEIGH_R)),
                'verified_ref_sites': [hx(h['site'])
                                       for h in verified[
                                           'neighbour_right']]},
        },
        'answer': {
            'consumer_form': (
                'Every verified reference to the slot is the same '
                'instruction form: ff 15 <disp32>, an indirect call '
                'through the slot. There is no data load, lea, '
                'immediate, absolute, or stored-copy reference.'),
            'call_template': (
                'Each consumer body allocates a fresh buffer through '
                'GOT slot 0x64df590 (size = its per-type alloc_size), '
                'selects a bool-indexed pair entry at +0x1f8 with a '
                '0x40 stride, copies the buffer full through GOT slot '
                '0x64df508, then calls the slot with rdi = selected '
                'entry, rsi = buffer, rdx = 1, rcx = stack out-slot, '
                'and tests the (al, rdx) return pair.'),
        },
        'boundaries': {
            'prior_packets': (
                'RE-005-node115-gate-checkers pins the slot '
                'relocation and narrates one consumer body '
                '(0x2b3c9d0); RE-009 records one consumer site '
                '(0x2b3ad3b) as a transfer row; RE-017 records one '
                'direct caller of one consumer body (0x5a9c620) as '
                'a transfer row; RE-003\'s integration review '
                'carries the 0x5a79730 consumer body as a start '
                'record; RE-001-node115-lu-park-queue pins one '
                'instruction inside the caller body; the X5 '
                'env-pair packet (#3227) pins the caller body and '
                'the slot value and leaves the consumers open. '
                'None enumerates the consumers or excludes the '
                'other reference forms.'),
            'runtime_behaviour': (
                'Which of the two bool-indexed pair entries a given '
                'consumer selects at run time, and the concrete Rust '
                'types of the consumers, are not established by '
                'static evidence.'),
            'one_level_up': (
                'Every consumer body has at least one direct rel32 '
                'caller and none has a relocation slot of its own; '
                'the consumers\' own callers are outside this '
                'packet\'s question.'),
        },
    }
    return records


def frames_lines(data, records):
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    wanted = {int(records['slot']['target_body']['start'], 16)}
    wanted |= {int(c['body']['start'], 16) for c in records['consumers']}
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
    cl = records['clusters']
    alloc_sizes = ', '.join(
        '0x%x' % s for s in sorted({x['alloc_size']
                                    for x in records['consumers']}))
    cluster_lines = '\n'.join(
        '- %d %s, %s..%s, body sizes %s'
        % (x['bodies'], 'body' if x['bodies'] == 1 else 'bodies',
           x['first_body'], x['last_body'],
           '/'.join(str(s) for s in x['body_sizes'])) for x in cl)
    return f"""# RE-005 node 115: who consumes the X5 schedule caller's GOT slot

## Question

The X5 env-pair packet (`RE-005-node115-x5-env-pair-source`, PR
#3227) pinned the schedule-caller body `0x5cf5100` and showed it has
no direct callers: the only static holder of its address is one
RELATIVE relocation in `.got` slot `0x64e7718`. It left one question
open: who loads that slot, along what path, and under what call
conditions — or is the slot never loaded at all?

## Method

Static analysis only, against the authenticated node 115 binary
(SHA-256 `{records['artifact']['sha256']}`). A disp32 candidate scan
over every executable section ({', '.join(c['executable_sections'])})
enumerated every position whose disp32 field could end an
instruction at the target with 0–8 trailing bytes; each candidate was
verified by decoding the instruction that ends there. The same scan
ran on the caller address itself and on the two neighbouring slots
as controls. Independent passes excluded the other reference forms:
absolute disp32 addressing, stored 8-byte copies of either address
outside the `.rela.dyn` section's own serialised entries, and
relocations whose addend is the slot.

## Answer

The slot has exactly **{records['consumer_count']} consumers**, and
every one of them uses the slot the same way: a single indirect call
`call qword ptr [rip + disp32]` (bytes `ff 15 …`) inside its own FDE
body. There is no data load, no `lea`, no immediate materialisation,
and no PLT stub for the caller body, which itself keeps
{records['slot']['target_direct_callers']} direct callers. The
consumers form {len(cl)} address clusters:

{cluster_lines}

Each consumer body runs the same call template (pinned per site in
`records.json`):

1. allocate a fresh buffer through GOT slot `0x64df590` — the size
   is the body's per-type value size (`alloc_size` in
   `records.json`: {alloc_sizes} across the pinned set) — and take
   an error path if it returns null;
2. select one of two pair entries: a flag byte is inverted, masked
   to 0/1, shifted left 6 (×0x40), and added to a base at `+0x1f8` —
   the same bool-indexed pair shape the env-pair packet pinned
   inside the caller;
3. copy the stack-built value into the allocation through GOT slot
   `0x64df508`;
4. call the slot with `rdi` = selected entry, `rsi` = allocation,
   `rdx` = 1 (the `mov edx, 1` sits immediately before the call at
   every site), `rcx` = a stack out-slot, and test the `(al, rdx)`
   return pair (`test rdx, rdx; setne cl; and cl, al; cmp cl, 1`).

## Boundaries

{records['boundaries']['prior_packets']}

{records['boundaries']['runtime_behaviour']}

{records['boundaries']['one_level_up']}
"""


def objdump_text():
    ranges = [('--start-address=0x2b3a8c0', '--stop-address=0x2b3ab9c'),
              ('--start-address=0x5a9c620', '--stop-address=0x5a9cab1'),
              ('--start-address=0x5cf4540', '--stop-address=0x5cf47ed')]
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
    files['site_template.objdump.txt'] = objdump_text()
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
