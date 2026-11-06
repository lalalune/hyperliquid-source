#!/usr/bin/env python3
"""Node 115: is the X4 packet cell's drain helper reachable?

The X4/X5 cell-layout packet (#3160) pinned the standalone drain
helper of each packet-cell family -- X4 0x5cd8580, X5 0x5ce7d70,
each taking the {state, data, vtable} triple at cell +0x18 and
dropping/deallocating the stored pair when the state word is
non-zero -- but left its reachability as a stated boundary:
the drains it pinned in the dispatcher, the payload drop and
the cell glue are inlined copies of the same idiom, and whether
the standalone body is ever entered, under what condition and
with what in the cell was not decided.  This packet decides it
for X4, with X5 carried as a control.

Answers, all static and re-derived by analyze() below:

1.  Sole reference.  An exhaustive census of the artifact
    (direct rel32 branches in executable sections, 64-bit
    pointer occurrences in every file-backed section, 32-bit
    immediate occurrences, R_X86_64 relocation addends,
    rip-relative lea / indirect-branch address computations,
    and fall-through from the preceding FDE) finds exactly one
    reference to 0x5cd8580: the direct call at 0x5cd87df.
    Fall-through is excluded separately: the preceding FDE
    (0x5cd8540..0x5cd857c) ends in a tail jump and an
    _Unwind_Resume call, followed by four int3 bytes.
2.  The call site is landing-pad code.  0x5cd87df lies in the
    block at 0x5cd87c1 inside the X4 cell drop glue
    (0x5cd86e0), and the glue's LSDA call-site table assigns
    exactly one call site to that pad: the payload-drop call
    at 0x5cd86f2 (entry [0x5cd86ef..0x5cd86f7) -> pad
    0x5cd87c1).  The pad redoes the context release the
    unwound payload drop skipped, then calls the drain helper
    on the triple at cell +0x18, then runs the shared
    weak-count/dealloc tail into _Unwind_Resume.  The glue's
    main path does not call the helper: it tests the state
    itself (0x5cd870e) and drains inline.
3.  The helper never sees a live pair.  The payload drop
    (0x5cda210) can leave its frame by unwinding only from
    the pair drop call at 0x5cda248 (its own LSDA assigns it
    the pad 0x5cda2db, action 5), from its pad's rethrow
    processing, or from the context-ledger panic tail jump
    at 0x5cda2d5.  On the first two paths the payload pad
    runs first -- innermost frame first -- and stores 0 into
    the state word (0x5cda30a) before the unwind resumes;
    on the third the normal-path store (0x5cda276) has
    already run.  So when the glue pad calls the helper, the
    helper's own guard (cmpq $0x0,(%rdi) at 0x5cd8585) reads
    a zero state word and it returns having dropped nothing.
    The only calls in the payload drop that have no LSDA
    call-site entry are the two dealloc calls (0x5cda270 on
    the normal path, 0x5cda304 in its pad): the unwind
    tables record the dealloc entry as non-unwinding, and a
    hypothetical unwind there is the only path that could
    enter the glue pad with the state word still 1 -- with
    the pair's allocation already being freed by that very
    call.  See boundaries.
4.  Conclusion.  The standalone X4 drain helper is reachable
    only as landing-pad cleanup for a panicking payload
    drop, and on every path the unwind tables describe it
    is entered with a zero state word: it never drops or
    deallocates a live pair.  The live drains of the X4
    cell are the three inlined copies -- the dispatcher's
    pre-store drain (state test at 0x5cd9b97, pinned by
    #3160), the payload drop's inline drain
    (0x5cda238..0x5cda270) and the cell glue's main-path
    inline drain (state test at 0x5cd870e).  The X5 control
    shows the identical geometry: sole call at 0x5ce8494
    inside cell_glue_x5's payload-drop pad 0x5ce8476, and
    payload_drop_x5's pad stores 0 into the state word at
    0x5cfc4da before any unwind can reach it.
"""
import bisect
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from elf_index import sections, unwind_index
from fde_extents import fde_extents, is_int3_fill

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7'
                 'a8278fa39f249e98c3867b5301')
SNAPSHOT = '<authenticated-node115>'
WORK_ITEM = 'RE-005-node115-x4-drain-reachability'
OUT = ROOT / 'research/work-items' / WORK_ITEM

OWNERS = {
    'drain_x4': (0x5cd8580, 0x5cd860f,
                 '27dde2348fd486d19480e86af2e108d87e5e217bad18'
                 '91359c47d5f57b6ae749'),
    'cell_glue_x4': (0x5cd86e0, 0x5cd880f,
                     'b00b49cda8cc6f4e875da8f3046d7bd18e270fbec6'
                     'a3235ccbba0e67b376f5ac'),
    'payload_drop_x4': (0x5cda210, 0x5cda37e,
                        '6cfdb2d06e84078fd1f654681ea6a1d4cc4fb711'
                        'a2fddf7883c66390f668b12e'),
    'preceding_body': (0x5cd8540, 0x5cd857c,
                       '989276ed8b69cb40d878fa3e9916ee9cf2917ad31'
                       'c9f4578e5aa6be4dfddedab'),
    'drain_x5': (0x5ce7d70, 0x5ce7dff,
                 '2b4e56becb7d10d717359c3955825e468fa096d0647'
                 '5bff135d583c72d9aac70'),
    'cell_glue_x5': (0x5ce8390, 0x5ce84c4,
                     '47595306d82fbac24e1c7ec4c42550d1177efaa13'
                     '0783bc81ba7c27b79dc8af9'),
    'payload_drop_x5': (0x5cfc3e0, 0x5cfc54e,
                        '7e67f86b57437f1c4a119a9872eb1786806413a7'
                        'ef944396711a70d8403d3561'),
}

EXPORTED = list(OWNERS)

PINS = {
    'drain_x4': [
        (0x5cd8585, '48833f00'),   # cmpq $0,(%rdi): the guard
        (0x5cd858b, '488b5f08'),   # mov 0x8(%rdi),%rbx: data
        (0x5cd8594, '4c8b7f10'),   # mov 0x10(%rdi),%r15: vtable
    ],
    'cell_glue_x4': [
        (0x5cd86f2, 'e8191b0000'),  # call payload_drop_x4
        (0x5cd870e, '48837b1800'),  # cmpq $0,0x18(%rbx): inline test
        (0x5cd87d5, 'ff158d438100'),  # pad: call *context slot
        (0x5cd87db, '488d7b18'),   # pad: lea 0x18(%rbx),%rdi
        (0x5cd87df, 'e89cfdffff'),  # pad: call drain_x4
    ],
    'payload_drop_x4': [
        (0x5cda245, '4c89f7'),     # mov %r14,%rdi (pair data)
        (0x5cda248, 'ffd0'),       # call *%rax: the pair drop fn
        (0x5cda270, 'ff152a528000'),  # call *dealloc slot
        (0x5cda276, '48c7430800000000'),  # movq $0,0x8(%rbx): state
        (0x5cda304, 'ff1596518000'),  # pad: call *dealloc slot
        (0x5cda30a, '48c7430800000000'),  # pad: movq $0,0x8(%rbx)
        (0x5cda315, 'ff156d5b8000'),  # pad: call *catch-pair slot
    ],
    'preceding_body': [
        (0x5cd855d, 'e9ae000000'),  # jmp 0x5cd8610: tail jump out
        (0x5cd8577, 'e8d4847100'),  # call _Unwind_Resume@plt
    ],
    'drain_x5': [
        (0x5ce7d75, '48833f00'),
        (0x5ce7d7b, '488b5f08'),
        (0x5ce7d84, '4c8b7f10'),
    ],
    'cell_glue_x5': [
        (0x5ce83a2, 'e839400100'),  # call payload_drop_x5
        (0x5ce8490, '488d7b18'),   # pad: lea 0x18(%rbx),%rdi
        (0x5ce8494, 'e8d7f8ffff'),  # pad: call drain_x5
    ],
    'payload_drop_x5': [
        (0x5cfc415, '4c89f7'),
        (0x5cfc418, 'ffd0'),
        (0x5cfc440, 'ff155a307e00'),  # call *dealloc slot
        (0x5cfc446, '48c7430800000000'),
        (0x5cfc4d4, 'ff15c62f7e00'),  # pad: call *dealloc slot
        (0x5cfc4da, '48c7430800000000'),  # pad: movq $0,0x8(%rbx)
    ],
}

SLOTS = {
    'dealloc': 0x64df4a0,
    'catch_pair': 0x64dfe88,
    'terminate_stub': 0x64df4c0,
    'x4_context_release': 0x64ecb68,
    'x5_context_release': 0x64ecc50,
    'x4_panic_raise': 0x64e06b8,
}

DRAIN_TARGETS = {'drain_x4': 0x5cd8580, 'drain_x5': 0x5ce7d70}

QUESTION = (
    'The X4/X5 cell-layout packet (#3160) pinned the packet '
    'cells\' standalone drain helpers (X4 0x5cd8580, X5 '
    '0x5ce7d70, each taking the {state, data, vtable} triple '
    'at cell +0x18) but left their reachability open: the '
    'drains it pinned in the dispatchers, the payload drops '
    'and the cell glues are inlined copies of the same idiom, '
    'and whether the standalone bodies are ever entered, '
    'under what condition and with what in the cell was '
    'stated as a run-time question only the paths and offsets '
    'being pinned.  Who references the X4 drain helper, '
    'under what condition does control reach it, and can it '
    'ever drain a live pair?  (The X5 helper is carried as '
    'a control.)')

ANSWER = {
    'sole_reference': (
        'Exactly one reference to the X4 drain helper '
        '0x5cd8580 exists in the artifact: the direct call '
        'at 0x5cd87df.  The census covers direct rel32 '
        'branches in executable sections, 64-bit pointer '
        'occurrences in every file-backed section, 32-bit '
        'immediate occurrences, relocation addends, and '
        'rip-relative lea / indirect-branch address '
        'computations; every channel but the direct branch '
        'is empty, and fall-through is excluded by the '
        'preceding FDE\'s tail jump and the int3 fill at '
        '0x5cd857c..0x5cd8580.'),
    'caller_context': (
        'The call sits in the landing pad at 0x5cd87c1 of '
        'the X4 cell drop glue 0x5cd86e0.  The glue\'s LSDA '
        'call-site table assigns that pad to exactly one '
        'call site, the payload-drop call at 0x5cd86f2 '
        '(entry [0x5cd86ef..0x5cd86f7)).  The pad redoes '
        'the context release the unwound payload drop '
        'skipped, calls the drain helper on the triple at '
        'cell +0x18, and joins the shared weak-count tail '
        'into _Unwind_Resume.  The glue\'s main path never '
        'calls the helper: it tests the state word itself '
        'at 0x5cd870e and drains inline, and assigns its '
        'own inline drain calls to a different pad '
        '(0x5cd8790).'),
    'state_on_entry': (
        'On every unwind path by which the payload drop '
        '0x5cda210 can leave its frame, the state word has '
        'already been stored 0 before the glue pad runs: '
        'the pair drop call at 0x5cda248 is assigned the '
        'payload pad 0x5cda2db (action 5), which deallocates '
        'the pair data and stores 0 into the state word at '
        '0x5cda30a before resuming the unwind; the context-'
        'ledger panic tail jump at 0x5cda2d5 is preceded by '
        'the normal-path store at 0x5cda276; unwinds out of '
        'the payload pad\'s rethrow processing start from '
        'code after 0x5cda30a.  The helper\'s guard '
        '(cmpq $0x0,(%rdi) at 0x5cd8585) therefore reads a '
        'zero state word on every described path and the '
        'helper returns having dropped nothing.'),
    'conclusion': (
        'The standalone X4 drain helper is reachable only '
        'as landing-pad cleanup for a panicking payload '
        'drop, and it never drops or deallocates a live '
        'pair on any path the unwind tables describe.  The '
        'live drains of the X4 cell are the three inlined '
        'copies: the dispatcher\'s pre-store drain (state '
        'test at 0x5cd9b97, #3160), the payload drop\'s '
        'inline drain (0x5cda238..0x5cda270) and the cell '
        'glue\'s main-path inline drain (state test at '
        '0x5cd870e).  The X5 control is geometrically '
        'identical: sole call at 0x5ce8494 in cell_glue_x5\'s '
        'payload-drop pad 0x5ce8476, payload_drop_x5\'s pad '
        'storing 0 into the state word at 0x5cfc4da.'),
}

BOUNDARIES = {
    'dealloc_unwind_caveat': (
        'The two dealloc calls of the payload drop '
        '(0x5cda270 normal path, 0x5cda304 in its pad) have '
        'no LSDA call-site entry: the unwind tables record '
        'the dealloc entry (GOT slot 0x64df4a0) as '
        'non-unwinding.  A hypothetical unwind out of '
        'either call is the only path that could enter the '
        'glue pad with the state word still 1, and it '
        'would do so while that call is freeing the pair\'s '
        'allocation.  The packet reports this as a '
        'boundary of the unwind-table evidence, not as a '
        'reachable path: nothing in the artifact contradicts '
        'the compiler\'s non-unwinding record, and the same '
        'absence holds for the cell glue\'s own dealloc '
        'calls.'),
    'payload_panic_possibility': (
        'Whether the payload drop can actually panic on '
        'its drop call -- a payload destructor panicking '
        'while the cell glue runs -- is a run-time property '
        'of the payload type and is not decided here.  The '
        'packet decides the static side completely: the '
        'helper has one caller, the caller is a landing '
        'pad, and the state word is zero on entry on every '
        'path the unwind tables describe, panic or not.'),
    'prior_packets': (
        'The cell layout, the producers and the inlined '
        'drain paths are #3160\'s pins and are not '
        're-derived; this packet cites the dispatcher '
        'pre-store test at 0x5cd9b97 from that packet.  '
        'The take/release semantics of the X5 join body '
        'remain open PR #3074\'s subject and are untouched: '
        'the X5 bodies here are a reachability control '
        'only.'),
}

LIMITS = (
    'Static analysis only; no captured code was executed. '
    'Body boundaries are FDE extents cross-checked by '
    'SHA-256.  The reachability closure rests on the '
    'reference census (channels enumerated in the records), '
    'the LSDA call-site tables of the drain, glue and '
    'payload-drop bodies of both families, and the byte '
    'pins, all re-derived from the authenticated artifact '
    'by analyze().  A mov that reads the helper\'s first '
    'bytes as data would not transfer control and is not a '
    'reference channel; control can reach a body start '
    'only by a direct branch, an indirect branch through a '
    'stored or computed pointer, or fall-through, and each '
    'is enumerated or excluded.')


def read(va, data, size=None):
    for section in sections(data):
        if section['type'] == 8:
            continue
        if (section['address'] <= va and
                va < section['address'] + section['size']):
            offset = section['offset'] + va - section['address']
            end = (section['offset'] + section['size'] if size is None
                   else offset + size)
            return offset, bytes(data[offset:end])
    raise ValueError(hex(va))


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def owners(data):
    check(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,
          'unexpected node artifact')
    _, fdes, _ = fde_extents(data)
    extents = {(f['start'], f['end']) for f in fdes}
    records = {}
    for role, (start, end, digest) in OWNERS.items():
        check((start, end) in extents, f'missing FDE {role}')
        offset, body = read(start, data, end - start)
        check(sha(body) == digest, f'body hash mismatch {role}')
        records[role] = {'start': hex(start), 'end': hex(end),
                         'file_offset': hex(offset),
                         'bytes': end - start, 'sha256': digest}
    return records


def check_pins(data):
    records = {}
    for role, rows in PINS.items():
        start, end, _ = OWNERS[role]
        _, body = read(start, data, end - start)
        for va, expected in rows:
            got = body[va - start:va - start +
                       len(bytes.fromhex(expected))]
            check(got.hex() == expected,
                  f'byte pin mismatch {role} at {va:#x}')
        records[role] = {hex(va): expected for va, expected in rows}
    return records


def rela_entries(data):
    secs = sections(data)
    dyn = next(s for s in secs if s['name'] == '.rela.dyn')
    out = {}
    for i in range(dyn['size'] // 24):
        off, info, add = struct.unpack_from(
            '<QQq', data, dyn['offset'] + i * 24)
        out.setdefault(off, []).append((info & 0xffffffff, add))
    return out


def slots(data):
    rela = rela_entries(data)
    records = {}
    for name, slot in SLOTS.items():
        rows = rela.get(slot)
        check(rows, f'slot {name} {slot:#x} has no relocation')
        typ, add = rows[0]
        records[name] = {'slot': hex(slot), 'type': typ,
                         'target': hex(add) if typ == 8 else None}
    return records


# ---------------- reference census ----------------

_BRANCH_BYTES = re.compile(rb'[\xe8\xe9]')
_LEA_BYTES = re.compile(rb'\x8d')
_FF_BYTES = re.compile(rb'\xff')


def _fde_lookup(fdes):
    starts = [f['start'] for f in fdes]

    def containing(va):
        i = bisect.bisect_right(starts, va) - 1
        if 0 <= i < len(fdes) and fdes[i]['start'] <= va < fdes[i]['end']:
            return fdes[i]
        return None
    return containing


def reference_census(data):
    """Every static reference channel to the two drain helpers.

    Returns per-target records and fails closed unless each
    target shows exactly one validated direct call and no
    other reference of any channel.
    """
    secs = sections(data)
    _, fdes, _ = fde_extents(data)
    containing = _fde_lookup(sorted(fdes, key=lambda f: f['start']))
    targets = set(DRAIN_TARGETS.values())
    found = {t: {'direct_branches': [], 'pointer_occurrences': [],
                 'immediate32_occurrences': [],
                 'relocation_addends': [], 'rip_relative': []}
             for t in targets}

    # (a) direct rel32 call/jmp in executable sections
    raw_branch_hits = []
    for s in secs:
        if s['type'] == 8 or not (s['flags'] & 4):
            continue
        seg = data[s['offset']:s['offset'] + s['size']]
        va0 = s['address']
        for m in _BRANCH_BYTES.finditer(seg):
            i = m.start()
            if i + 5 > len(seg):
                continue
            rel = struct.unpack_from('<i', seg, i + 1)[0]
            tgt = va0 + i + 5 + rel
            if tgt in targets:
                raw_branch_hits.append(
                    (va0 + i, 'call' if seg[i] == 0xE8 else 'jmp', tgt))
    # validate each hit against the objdump of its containing FDE
    for site, kind, tgt in raw_branch_hits:
        fde = containing(site)
        check(fde is not None, f'branch hit outside any FDE {site:#x}')
        text = objdump_range(data, fde['start'], fde['end'])
        pat = re.compile(
            rf'^\s+{site:x}:\t[0-9a-f ]+\t{kind}\s+{tgt:x}\b', re.M)
        check(pat.search(text),
              f'branch hit at {site:#x} is not an instruction boundary')
        role = next(r for r, (a, b, _) in OWNERS.items()
                    if a == fde['start'] and b == fde['end'])
        found[tgt]['direct_branches'].append(
            {'site': hex(site), 'kind': kind, 'containing_body': role})

    # (b) 64-bit pointer and (c) 32-bit immediate occurrences in
    # every file-backed section
    for t in targets:
        p64 = struct.pack('<Q', t)
        p32 = struct.pack('<I', t)
        for s in secs:
            if s['type'] == 8:
                continue
            seg = data[s['offset']:s['offset'] + s['size']]
            for pat, key in ((p64, 'pointer_occurrences'),
                             (p32, 'immediate32_occurrences')):
                start = 0
                while True:
                    j = seg.find(pat, start)
                    if j < 0:
                        break
                    if key == 'immediate32_occurrences':
                        # an 8-byte occurrence contains the 4-byte
                        # pattern at its low half; count it once,
                        # under pointers
                        if seg[j:j + 8] == p64:
                            start = j + 1
                            continue
                    found[t][key].append(hex(s['address'] + j))
                    start = j + 1

    # (d) relocation addends naming a target
    for off, rows in rela_entries(data).items():
        for typ, add in rows:
            if add in targets:
                found[add]['relocation_addends'].append(
                    {'offset': hex(off), 'type': typ})

    # (e) rip-relative address computations: lea (any REX) and
    # FF /2, /4 indirect branches through [rip+disp32]
    for s in secs:
        if s['type'] == 8 or not (s['flags'] & 4):
            continue
        seg = data[s['offset']:s['offset'] + s['size']]
        va0 = s['address']
        for m in _LEA_BYTES.finditer(seg):
            i = m.start()  # at the 0x8d opcode
            for pre in (1, 0):
                j = i - pre  # instruction start
                if j < 0:
                    continue
                if pre and not (0x40 <= seg[j] <= 0x4F):
                    continue
                if i + 1 >= len(seg):
                    continue
                modrm = seg[i + 1]
                if modrm & 0xC7 != 0x05:
                    continue
                disp = struct.unpack_from('<i', seg, i + 2)[0]
                tgt = va0 + i + 6 + disp
                if tgt in targets:
                    found[tgt]['rip_relative'].append(
                        {'site': hex(va0 + j), 'form': 'lea'})
        for m in _FF_BYTES.finditer(seg):
            i = m.start()
            for pre in (1, 0):
                j = i - pre
                if j < 0:
                    continue
                if pre and not (0x40 <= seg[j] <= 0x4F):
                    continue
                if i + 1 >= len(seg):
                    continue
                modrm = seg[i + 1]
                if modrm & 0xC7 != 0x05 or (modrm >> 3) & 7 not in (2, 4):
                    continue
                disp = struct.unpack_from('<i', seg, i + 2)[0]
                tgt = va0 + i + 6 + disp
                if tgt in targets:
                    found[tgt]['rip_relative'].append(
                        {'site': hex(va0 + j), 'form': 'indirect'})

    records = {}
    expected = {
        'drain_x4': {'site': '0x5cd87df', 'containing_body': 'cell_glue_x4'},
        'drain_x5': {'site': '0x5ce8494', 'containing_body': 'cell_glue_x5'},
    }
    for role, t in DRAIN_TARGETS.items():
        got = found[t]
        want = expected[role]
        check(len(got['direct_branches']) == 1,
              f'{role}: expected exactly one direct branch, '
              f"got {got['direct_branches']}")
        hit = got['direct_branches'][0]
        check(hit['site'] == want['site'] and
              hit['kind'] == 'call' and
              hit['containing_body'] == want['containing_body'],
              f'{role}: direct branch mismatch {hit}')
        for key in ('pointer_occurrences', 'immediate32_occurrences',
                    'relocation_addends', 'rip_relative'):
            check(got[key] == [], f'{role}: {key} not empty: {got[key]}')
        records[role] = {'target': hex(t), **got}

    # (f) fall-through into drain_x4: the preceding FDE must be
    # the pinned preceding body and the gap must be int3 fill
    ordered = sorted(fdes, key=lambda f: f['start'])
    idx = next(i for i, f in enumerate(ordered)
               if f['start'] == DRAIN_TARGETS['drain_x4'])
    prev = ordered[idx - 1]
    ps, pe, _ = OWNERS['preceding_body']
    check((prev['start'], prev['end']) == (ps, pe),
          'preceding FDE is not the pinned preceding body')
    text_sec = next(s for s in secs if s['name'] == '.text')
    check(is_int3_fill(data, text_sec, pe, DRAIN_TARGETS['drain_x4']),
          'gap before drain_x4 is not int3 fill')
    records['fallthrough'] = {
        'preceding_fde': {'start': hex(ps), 'end': hex(pe)},
        'int3_fill': {'start': hex(pe),
                      'end': hex(DRAIN_TARGETS['drain_x4'])},
        'excluded': True}
    return records


# ---------------- LSDA call-site tables ----------------

def _uleb(buf, p):
    r = 0
    s = 0
    while True:
        b = buf[p]
        p += 1
        r |= (b & 0x7F) << s
        s += 7
        if not (b & 0x80):
            return r, p


def _enc_read(buf, p, enc, base_va):
    """Read one DW_EH_PE value; base_va is the buffer's VA so a
    pcrel value resolves against its own field address."""
    start_p = p
    fmt = enc & 0x0F
    appl = enc & 0x70
    if fmt == 0x00:
        val = struct.unpack_from('<Q', buf, p)[0]
        p += 8
    elif fmt == 0x01:
        val, p = _uleb(buf, p)
    elif fmt == 0x02:
        val = struct.unpack_from('<H', buf, p)[0]
        p += 2
    elif fmt == 0x03:
        val = struct.unpack_from('<I', buf, p)[0]
        p += 4
    elif fmt == 0x04:
        val = struct.unpack_from('<Q', buf, p)[0]
        p += 8
    elif fmt == 0x0B:
        val = struct.unpack_from('<i', buf, p)[0]
        p += 4
    elif fmt == 0x0C:
        val = struct.unpack_from('<q', buf, p)[0]
        p += 8
    else:
        raise ValueError(f'unsupported LSDA encoding {enc:#x}')
    if appl == 0x10:
        val = base_va + start_p + val
    return val, p


def parse_lsda(data, lsda_va, func_start):
    """Parse one .gcc_except_table LSDA into call-site entries.

    Landing-pad values are absolute (lpbase defaults to the
    function start when the header omits it).
    """
    secs = sections(data)
    tab = next(s for s in secs if s['name'] == '.gcc_except_table')
    _, raw = read(tab['address'], data, tab['size'])
    base = tab['address']
    p = lsda_va - base
    lpbase_enc = raw[p]
    p += 1
    if lpbase_enc != 0xFF:
        field_va = base + p
        fmt = lpbase_enc & 0x0F
        if fmt == 0x03:
            val = struct.unpack_from('<I', raw, p)[0]
            p += 4
        elif fmt == 0x0B:
            val = struct.unpack_from('<i', raw, p)[0]
            p += 4
        elif fmt == 0x00:
            val = struct.unpack_from('<Q', raw, p)[0]
            p += 8
        elif fmt == 0x04:
            val = struct.unpack_from('<Q', raw, p)[0]
            p += 8
        else:
            raise ValueError(f'lpbase encoding {lpbase_enc:#x}')
        lpbase = field_va + val if (lpbase_enc & 0x70) == 0x10 else val
    else:
        lpbase = func_start
    ttype_enc = raw[p]
    p += 1
    if ttype_enc != 0xFF:
        _tt, p = _uleb(raw, p)
    cs_enc = raw[p]
    p += 1
    cs_len, p = _uleb(raw, p)
    cs_end = p + cs_len
    entries = []
    while p < cs_end:
        st, p = _enc_read(raw, p, cs_enc, 0)
        ln, p = _enc_read(raw, p, cs_enc, 0)
        lp, p = _enc_read(raw, p, cs_enc, 0)
        act, p = _uleb(raw, p)
        entries.append({'start': hex(func_start + st),
                        'end': hex(func_start + st + ln),
                        'landing_pad': hex(lpbase + lp) if lp else None,
                        'action': act})
    check(p == cs_end, 'LSDA call-site table length mismatch')
    return {'lsda': hex(lsda_va), 'lpbase': hex(lpbase),
            'entries': entries}


EXPECTED_LSDA = {
    'cell_glue_x4': [
        ('0x5cd86ef', '0x5cd86f7', '0x5cd87c1', 0),
        ('0x5cd872b', '0x5cd8730', '0x5cd8790', 0),
        ('0x5cd87df', '0x5cd87e4', '0x5cd8809', 1),
        ('0x5cd87e4', '0x5cd880f', None, 0)],
    'payload_drop_x4': [
        ('0x5cda245', '0x5cda24a', '0x5cda2db', 5),
        ('0x5cda33e', '0x5cda35c', '0x5cda362', 0),
        ('0x5cda365', '0x5cda370', '0x5cda378', 1),
        ('0x5cda370', '0x5cda37e', None, 0)],
    'drain_x4': [
        ('0x5cd85a0', '0x5cd85a5', '0x5cd85da', 0),
        ('0x5cd85a5', '0x5cd860f', None, 0)],
    'cell_glue_x5': [
        ('0x5ce839f', '0x5ce83a7', '0x5ce8476', 0),
        ('0x5ce83b5', '0x5ce83be', '0x5ce8471', 0),
        ('0x5ce83db', '0x5ce83e0', '0x5ce8440', 0),
        ('0x5ce8487', '0x5ce8499', '0x5ce84be', 1),
        ('0x5ce8499', '0x5ce84c4', None, 0)],
    'payload_drop_x5': [
        ('0x5cfc415', '0x5cfc41a', '0x5cfc4ab', 5),
        ('0x5cfc50e', '0x5cfc52c', '0x5cfc532', 0),
        ('0x5cfc535', '0x5cfc540', '0x5cfc548', 1),
        ('0x5cfc540', '0x5cfc54e', None, 0)],
}


def lsda_tables(data):
    _, fdes, _ = fde_extents(data)
    by_start = {f['start']: f for f in fdes}
    records = {}
    for role, want in EXPECTED_LSDA.items():
        start = OWNERS[role][0]
        fde = by_start[start]
        check(fde['lsda'] is not None, f'{role} has no LSDA')
        table = parse_lsda(data, fde['lsda'], start)
        got = [(e['start'], e['end'], e['landing_pad'], e['action'])
               for e in table['entries']]
        check(got == want, f'LSDA table mismatch {role}: {got}')
        records[role] = table
    return records


def covering(entries, site):
    for e in entries:
        if int(e['start'], 16) <= site < int(e['end'], 16):
            return e
    return None


# ---------------- objdump helpers ----------------

def objdump_range(data, start, end):
    text = subprocess.run(
        ['objdump', '-d', '--start-address', hex(start),
         '--stop-address', hex(end), str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    return text.replace(str(TARGET), SNAPSHOT, 1)


def exports(data, role):
    start, end, _ = OWNERS[role]
    return objdump_range(data, start, end)


_LINE = re.compile(r'^\s+([0-9a-f]+):\t[0-9a-f ]+\t(.*)$')
_BRANCH = re.compile(r'^(call|jmp)\s+(.*)$')


def body_branches(text):
    """(va, mnemonic, operand) for call/jmp instructions in a body."""
    out = []
    for line in text.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        mm = _BRANCH.match(m.group(2).strip())
        if mm:
            out.append((int(m.group(1), 16), mm.group(1), mm.group(2)))
    return out


# ---------------- unwind-path audit ----------------

FAMILIES = {
    'x4': {'glue': 'cell_glue_x4', 'payload': 'payload_drop_x4',
           'glue_payload_call': 0x5cd86f2, 'pad': 0x5cd87c1,
           'drain_call': 0x5cd87df,
           'state_store': 0x5cda276, 'pad_state_store': 0x5cda30a,
           'drop_call': 0x5cda248, 'dealloc_call': 0x5cda270,
           'payload_pad': 0x5cda2db, 'pad_dealloc_call': 0x5cda304,
           'panic_jmp': 0x5cda2d5},
    'x5': {'glue': 'cell_glue_x5', 'payload': 'payload_drop_x5',
           'glue_payload_call': 0x5ce83a2, 'pad': 0x5ce8476,
           'drain_call': 0x5ce8494,
           'state_store': 0x5cfc446, 'pad_state_store': 0x5cfc4da,
           'drop_call': 0x5cfc418, 'dealloc_call': 0x5cfc440,
           'payload_pad': 0x5cfc4ab, 'pad_dealloc_call': 0x5cfc4d4,
           'panic_jmp': 0x5cfc4a5},
}


def _direct_target(operand):
    try:
        return int(operand.split(' ')[0], 16)
    except (ValueError, IndexError):
        return None


def unwind_audit(data, census, lsda):
    records = {}
    for fam, p in FAMILIES.items():
        glue_start = OWNERS[p['glue']][0]
        payload_start, payload_end, _ = OWNERS[p['payload']]
        glue_branches = body_branches(exports(data, p['glue']))
        payload_branches = body_branches(exports(data, p['payload']))
        glue_entries = lsda[p['glue']]['entries']
        payload_entries = lsda[p['payload']]['entries']

        # the glue's direct call into the payload drop body
        direct = [va for va, kind, op in glue_branches
                  if kind == 'call' and
                  _direct_target(op) == payload_start]
        check(direct == [p['glue_payload_call']],
              f'{fam}: glue payload-drop call mismatch {direct}')
        entry = covering(glue_entries, p['glue_payload_call'])
        check(entry is not None and
              entry['landing_pad'] == hex(p['pad']),
              f'{fam}: payload-drop call not assigned the drain pad')
        # the drain call (sole reference, from the census) sits
        # inside that pad; the pad ends where the LSDA entry
        # covering the drain call ends (the shared tail)
        drain_entry = covering(glue_entries, p['drain_call'])
        check(drain_entry is not None, f'{fam}: drain call uncovered')
        pad_end = int(drain_entry['end'], 16)
        check(p['pad'] <= p['drain_call'] < pad_end,
              f'{fam}: drain call outside its pad')

        payload_calls = sorted(va for va, kind, _ in payload_branches
                               if kind == 'call')
        pre_store = [va for va in payload_calls
                     if va < p['state_store']]
        check(pre_store == [p['drop_call'], p['dealloc_call']],
              f'{fam}: pre-store calls mismatch {pre_store}')
        drop_entry = covering(payload_entries, p['drop_call'])
        check(drop_entry is not None and
              drop_entry['landing_pad'] == hex(p['payload_pad']) and
              drop_entry['action'] == 5,
              f'{fam}: drop call pad mismatch')
        check(covering(payload_entries, p['dealloc_call']) is None,
              f'{fam}: dealloc call unexpectedly has a landing pad')
        jmps = [va for va, kind, _ in payload_branches if kind == 'jmp']
        check(p['panic_jmp'] in jmps and
              p['panic_jmp'] > p['state_store'] and
              covering(payload_entries, p['panic_jmp']) is None,
              f'{fam}: panic tail jump mismatch')
        pad_calls = [va for va in payload_calls
                     if p['payload_pad'] <= va < p['pad_state_store']]
        check(pad_calls == [p['pad_dealloc_call']],
              f'{fam}: pad calls before the pad state store '
              f'mismatch {pad_calls}')
        check(covering(payload_entries, p['pad_dealloc_call']) is None,
              f'{fam}: pad dealloc unexpectedly has a landing pad')

        records[fam] = {
            'glue_payload_call': hex(p['glue_payload_call']),
            'glue_pad_for_payload_call': entry['landing_pad'],
            'drain_call_site': hex(p['drain_call']),
            'drain_call_within_pad': {'pad_start': hex(p['pad']),
                                      'pad_end': hex(pad_end)},
            'payload_pre_store_calls': {
                'drop_call': hex(p['drop_call']),
                'drop_call_pad': drop_entry['landing_pad'],
                'drop_call_action': drop_entry['action'],
                'dealloc_call': hex(p['dealloc_call']),
                'dealloc_call_pad': None},
            'payload_state_stores': {
                'normal_path': hex(p['state_store']),
                'in_payload_pad': hex(p['pad_state_store'])},
            'payload_panic_tail_jmp': {
                'site': hex(p['panic_jmp']),
                'after_state_store': True, 'pad': None},
            'payload_pad_calls_before_state_store': [
                hex(p['pad_dealloc_call'])],
            'state_word_on_glue_pad_entry': 0,
        }
    return records


def analyze(data):
    owner_records = owners(data)
    pin_records = check_pins(data)
    census = reference_census(data)
    lsda = lsda_tables(data)
    audit = unwind_audit(data, census, lsda)
    return {
        'artifact': {'path': 'artifacts/node/115/hl-node',
                     'bytes': TARGET_SIZE, 'sha256': TARGET_SHA256,
                     'snapshot': SNAPSHOT},
        'packet': WORK_ITEM,
        'captured_code_executed': False,
        'question': QUESTION,
        'answer': ANSWER,
        'owners': owner_records,
        'pins': pin_records,
        'slots': slots(data),
        'reference_census': census,
        'lsda_tables': lsda,
        'unwind_audit': audit,
        'boundaries': BOUNDARIES,
        'limits': LIMITS,
    }


def frame_lines(data):
    text = subprocess.run(['readelf', '-wf', str(TARGET)],
                          check=True, capture_output=True,
                          text=True).stdout
    wanted = []
    for start, end, _ in OWNERS.values():
        needle = (f'pc={start:016x}..{end:016x}')
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
    (OUT / 'frames.txt').write_text(''.join(frame_lines(data)))
    for role in EXPORTED:
        (OUT / f'{role}.objdump.txt').write_text(exports(data, role))
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
        check((OUT / f'{role}.objdump.txt').read_text() ==
              exports(data, role), f'{role}.objdump.txt is stale')
    check((OUT / 'frames.txt').read_text() ==
          ''.join(frame_lines(data)), 'frames.txt is stale')
    check((OUT / 'MANIFEST.sha256').read_text() ==
          ''.join(manifest_lines()), 'MANIFEST.sha256 is stale')
    print(json.dumps({'packet': WORK_ITEM, 'matches': True},
                     sort_keys=True))


if __name__ == '__main__':
    main()
