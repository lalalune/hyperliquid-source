#!/usr/bin/env python3
"""Node 115: the X4 and X5 packet cell layouts.

The packet-cell producers packet (#3050) pinned the type-A packet
cell (the 0x30-byte Arc allocation at closure +0x20: strong count
at +0x00, weak count at +0x08, context pointer at +0x10, state at
+0x18, data at +0x20, vtable at +0x28) and classified the two
remaining dispatcher families only far enough to exclude them:
"Families X4/X5 use different cell types (drop-glue slots
0x64ecb50 / 0x64ecc48) and are classified only far enough to
exclude them" -- their cell layouts were not pinned.  The
sibling-join packet (#3148) later pinned who owns the X4/X5
JoinHandles and which join bodies exist, without pinning the
cells either.  This packet pins both cells.

Answers, all static and re-derived by analyze() below:

1.  Layout: both cells are 0x30-byte, align-8 Arc allocations
    whose pointer sits at closure +0x20, with the same field
    offsets as the type-A cell: strong count at +0x00, weak
    count at +0x08, payload at +0x10 = {context pointer at
    +0x10, state at +0x18, data at +0x20, vtable at +0x28}.
    The allocation size is pinned three ways per family: the
    spawn body's alloc immediate (0x30), the 0x30-byte stack
    image the spawn body copies into the fresh allocation, and
    the dealloc immediate (0x30) in the family's own cell drop
    glue (X4 0x5cd86e0, X5 0x5ce8390).
2.  Producers per field.  Counts: written 1/1 by the spawn body
    (X4 0x5cd9470, X5 0x5cf6e80).  Context: stored by the spawn
    body from its r9 argument (the value saved at spawn entry
    and copied into the cell image at +0x10); the spawn body
    also increments the context object's own counter at A+0x18
    (lock incq 0x18(%rdi) with rdi = [cell+0x10]).  State:
    initialised to 0 by the spawn body (the pair slot is left
    uninitialised -- the spawn stack image's pair words are
    never written before the copy); set to 1 only by the
    dispatcher's finish block (two copies: fall-through and
    landing pad).  Data/vtable: written only by that finish
    block.  On the normal path data is 0 (r14 zeroed at
    dispatcher entry) in both families; the vtable half
    differs -- see 4.  On the catch path the pair is the panic
    payload's Box fat pointer from the shared catch-pair helper
    (GOT slot 0x64dfe88), exactly as for type-A.
3.  Consumers per field.  Both dispatchers test state at
    +0x18 and drain a live pair (drop fn at [vtable], size at
    [vtable+0x08], align at [vtable+0x10], dealloc through GOT
    slot 0x64df4a0) before their finish store, then decrement
    the strong count at +0x00 and release through the family's
    cell glue when it reaches zero.  The payload drop (X4
    0x5cda210, X5 0x5cfc3e0; called by the glue on the payload
    base at +0x10) reads state at payload +0x08, data at
    +0x10, vtable at +0x18, drains the pair the same way,
    zeroes the state word, and does the context bookkeeping:
    a flag byte at A+0x20 when it discards a live pair, a
    decrement of the counter at A+0x18, and an xchg on the
    word at [A+0x10]+0x28.  The cell glue then releases the
    context pointer itself (family slot: X4 0x64ecb68 ->
    0x5cd88d0, X5 0x64ecc50 -> 0x5ce8660), re-tests the state
    (live only on unwind paths, where the family's drain
    helper -- X4 0x5cd8580, X5 0x5ce7d70, taking the
    {state, data, vtable} triple at cell +0x18 -- does the
    drain), decrements the weak count at +0x08 and deallocates
    the 0x30 bytes.  X5 has one further consumer: the join
    body 0x5cf7550 takes the pair out (its take/release
    semantics are the subject of open PR #3074; this packet
    pins only the offsets it touches: CAS on the weak count
    at +0x08 (1 -> -1, restored to 1), strong-count check at
    +0x00, pair loaded from +0x20/+0x28, state bit 0 tested
    at +0x18 and the state word cleared).  X4 has no join
    body (#3148): no body ever reads the X4 pair out; it is
    only ever drained.
4.  What "different cell types" amounts to.  The field
    layout coincides with type-A offset for offset; the
    types differ as monomorphisations -- own cell drop glue,
    own payload drop, own context-release glue per family,
    over distinct context object types (the payload drops are
    instruction-identical except for call targets, GOT slots
    and the panic Location in their landing pads).  One
    producer-side difference is real: the vtable half the
    X4 finish block stores on the normal path is the X4
    entry base 0x64c5330, arriving in r15 from the thread
    start routine (package +0x10, pinned in #3050), while
    the X5 finish block stores the word at closure +0x30 --
    the vtable half of a fat-pointer field of the X5 closure
    environment (closure +0x28/+0x30), which the X5 spawn
    body copies from its caller's argument struct -- and the
    X5 dispatcher loads r15 from closure +0x30 at entry.
    The closure sizes also differ (X4 entry size 0x30, X5
    0x48), but the cell pointer sits at closure +0x20 in
    both.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from elf_index import sections, unwind_index
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7'
                 'a8278fa39f249e98c3867b5301')
SNAPSHOT = '<authenticated-node115>'
WORK_ITEM = 'RE-005-node115-x4-x5-cell-layouts'
OUT = ROOT / 'research/work-items' / WORK_ITEM

OWNERS = {
    'spawn_x4': (0x5cd9470, 0x5cd9b2f,
                 'a67df4f7707481778d223fca1d10a1dcb3360ea805ae'
                 '3215f317882fa163c6a2'),
    'dispatcher_x4': (0x5cd9b30, 0x5cd9cd7,
                      '939b0f395bedfc84d55c5f6a2de8b19f39bc64089'
                      'ce0cf3c25efe284478f51ae'),
    'cell_glue_x4': (0x5cd86e0, 0x5cd880f,
                     'b00b49cda8cc6f4e875da8f3046d7bd18e270fbec6'
                     'a3235ccbba0e67b376f5ac'),
    'payload_drop_x4': (0x5cda210, 0x5cda37e,
                        '6cfdb2d06e84078fd1f654681ea6a1d4cc4fb711'
                        'a2fddf7883c66390f668b12e'),
    'drain_x4': (0x5cd8580, 0x5cd860f,
                 '27dde2348fd486d19480e86af2e108d87e5e217bad18'
                 '91359c47d5f57b6ae749'),
    'context_release_x4': (0x5cd88d0, 0x5cd8908,
                           '6804f49815f9909b13e7c26c15ce5103f24c5b'
                           '79c52b4cb99bed9101fec66d0a'),
    'spawn_x5': (0x5cf6e80, 0x5cf7550,
                 '1de6a1382a5d5557a56bcc242cf2a8e7e543e089832'
                 'f43bcf8548b32a05c5a87'),
    'dispatcher_x5': (0x5cf7710, 0x5cf78e7,
                      '313eb6afb9fb15a3d11f14e20b1bd68e89d8be9ad'
                      '571026469e43fd35aa0bbd2'),
    'join_x5': (0x5cf7550, 0x5cf76ae,
                '12fbb6bdf25c91d5912271bcae41e6422635dd8ca655'
                'bb0233e985ad9b685c03'),
    'cell_glue_x5': (0x5ce8390, 0x5ce84c4,
                     '47595306d82fbac24e1c7ec4c42550d1177efaa13'
                     '0783bc81ba7c27b79dc8af9'),
    'payload_drop_x5': (0x5cfc3e0, 0x5cfc54e,
                        '7e67f86b57437f1c4a119a9872eb1786806413a7'
                        'ef944396711a70d8403d3561'),
    'drain_x5': (0x5ce7d70, 0x5ce7dff,
                 '2b4e56becb7d10d717359c3955825e468fa096d0647'
                 '5bff135d583c72d9aac70'),
    'context_release_x5': (0x5ce8660, 0x5ce86cf,
                           'fea36aaf5fa44c33bc5d56acb20324576efb31'
                           'b12739faa9281508a19a9395a7'),
    'thread_start': (0x5ca44a0, 0x5ca469d,
                     '65e3438cb7b950aa4b885b7c271b6a8bcbd4574519'
                     'dee0f3f336360fabb21276'),
}

EXPORTED = list(OWNERS)

# Static one-method vtable entries:
# (base, family, dispatcher role, expected closure size).
# Layout per entry: {drop, size, align = 8, method(call_once)}.
ENTRIES = [
    (0x64c5330, 'X4', 'dispatcher_x4', 0x30),
    (0x64c6ac0, 'X5', 'dispatcher_x5', 0x48),
]

SLOTS = {
    'x4_cell_drop': 0x64ecb50,
    'x5_cell_drop': 0x64ecc48,
    'x4_context_release': 0x64ecb68,
    'x5_context_release': 0x64ecc50,
    'x4_adapter_env0': 0x64ecb60,
    'x4_adapter_env1': 0x64ecb58,
    'x5_adapter_env0': 0x64ecb98,
    'x5_adapter_env1': 0x64ecb88,
    'catch_pair': 0x64dfe88,
    'dealloc': 0x64df4a0,
    'thread_create': 0x64e1580,
    'alloc': 0x64df480,
}

PINS = {
    'spawn_x4': [
        (0x5cd94a3, '4c898c2488000000'),
        (0x5cd963d, '48c784249000000001000000'),
        (0x5cd9649, '48c784249800000001000000'),
        (0x5cd9655, '488b842488000000'),
        (0x5cd9665, '48c78424a800000000000000'),
        (0x5cd9671, 'bf30000000'),
        (0x5cd96e3, 'f048ff4718'),
        (0x5cd976b, '488d05bebb7e00'),
    ],
    'dispatcher_x4': [
        (0x5cd9b90, '4531f6'),
        (0x5cd9b93, '488b6b20'),
        (0x5cd9b97, '48837d1800'),
        (0x5cd9be7, '48c7451801000000'),
        (0x5cd9bef, '4c897520'),
        (0x5cd9bf3, '4c897d28'),
        (0x5cd9bfc, 'f048ff4d00'),
        (0x5cd9c4b, '48c7451801000000'),
        (0x5cd9c53, '4c897520'),
        (0x5cd9c57, '4c897d28'),
    ],
    'cell_glue_x4': [
        (0x5cd86eb, '4c8d7b10'),
        (0x5cd86f2, 'e8191b0000'),
        (0x5cd870e, '48837b1800'),
        (0x5cd8762, 'f048ff4b08'),
        (0x5cd8769, 'be30000000'),
    ],
    'payload_drop_x4': [
        (0x5cda21f, '4c8b7f08'),
        (0x5cda223, '4c8b7710'),
        (0x5cda238, '4c8b6318'),
        (0x5cda276, '48c7430800000000'),
        (0x5cda28b, 'c6402001'),
        (0x5cda28f, 'f048ff4818'),
    ],
    'drain_x4': [
        (0x5cd8585, '48833f00'),
        (0x5cd858b, '488b5f08'),
        (0x5cd8594, '4c8b7f10'),
    ],
    'spawn_x5': [
        (0x5cf6ea6, '4c898c2498000000'),
        (0x5cf7035, '48c78424a000000001000000'),
        (0x5cf7041, '48c78424a800000001000000'),
        (0x5cf704d, '488b842498000000'),
        (0x5cf705d, '48c78424b800000000000000'),
        (0x5cf7069, 'bf30000000'),
        (0x5cf70ec, 'f048ff4718'),
        (0x5cf71ac, '488d050df97c00'),
    ],
    'dispatcher_x5': [
        (0x5cf7728, '4c8b7f30'),
        (0x5cf77a2, '4531f6'),
        (0x5cf77a5, '488b6b20'),
        (0x5cf77a9, '48837d1800'),
        (0x5cf77f9, '48c7451801000000'),
        (0x5cf7801, '4c897520'),
        (0x5cf7805, '4c897d28'),
        (0x5cf7860, '48c7451801000000'),
        (0x5cf7868, '4c897520'),
        (0x5cf786c, '4c897d28'),
    ],
    'join_x5': [
        (0x5cf7582, 'f0480fb15108'),
        (0x5cf7591, '48c7410801000000'),
        (0x5cf75ab, '4c8b7020'),
        (0x5cf75af, '4c8b7828'),
        (0x5cf75b3, 'f6401801'),
        (0x5cf75b7, '48c7401800000000'),
    ],
    'cell_glue_x5': [
        (0x5ce839b, '4c8d7b10'),
        (0x5ce83a2, 'e839400100'),
        (0x5ce83be, '48837b1800'),
        (0x5ce8412, 'f048ff4b08'),
        (0x5ce8419, 'be30000000'),
    ],
    'payload_drop_x5': [
        (0x5cfc3ef, '4c8b7f08'),
        (0x5cfc3f3, '4c8b7710'),
        (0x5cfc408, '4c8b6318'),
        (0x5cfc446, '48c7430800000000'),
        (0x5cfc45b, 'c6402001'),
        (0x5cfc45f, 'f048ff4818'),
    ],
    'drain_x5': [
        (0x5ce7d75, '48833f00'),
        (0x5ce7d7b, '488b5f08'),
        (0x5ce7d84, '4c8b7f10'),
    ],
}

QUESTION = (
    'The packet-cell producers packet (#3050) left the families '
    'X4/X5 classified only far enough to exclude them from the '
    'type-A cell: they use different cell types (own drop-glue '
    'slots 0x64ecb50 / 0x64ecc48), but their cell layouts were '
    'not pinned, and the sibling-join packet (#3148) pinned '
    'JoinHandle ownership without pinning the cells.  What is '
    'the layout of the packet cell the X4 dispatcher 0x5cd9b30 '
    'and the X5 dispatcher 0x5cf7710 drain -- allocation size, '
    'field offsets, and the producer and consumer of each '
    'field?')

ANSWER = {
    'allocation': (
        'Both cells are 0x30-byte, align-8 Arc allocations; the '
        'cell pointer sits at closure +0x20 in both families '
        '(closure sizes differ: X4 entry size 0x30, X5 0x48). '
        'Size pinned by the spawn alloc immediate (0x30), the '
        '0x30-byte stack image copied into the allocation, and '
        'the cell glue dealloc immediate (0x30).'),
    'fields': [
        {'offset': '0x00', 'name': 'strong_count',
         'producer': 'spawn body writes 1',
         'consumers': ('incremented for the closure/package '
                       'copies at spawn; decremented by the '
                       'dispatcher after its finish store, by '
                       'the join body (X5), by handle drops '
                       'and caller releases (#3148); the cell '
                       'glue runs when a decrement reaches '
                       'zero')},
        {'offset': '0x08', 'name': 'weak_count',
         'producer': 'spawn body writes 1',
         'consumers': ('CAS sentinel of the X5 join take '
                       '(1 -> -1, restored to 1; #3074 '
                       'semantics); decremented by the cell '
                       'glue before the 0x30-byte dealloc')},
        {'offset': '0x10', 'name': 'context_pointer',
         'producer': ('spawn body, from its r9 argument (saved '
                      'at spawn entry, copied into the cell '
                      'image); the spawn body increments the '
                      'counter at A+0x18'),
         'consumers': ('payload drop bookkeeping (flag byte '
                       'at A+0x20 on a discarded live pair, '
                       'decrement of the counter at A+0x18, '
                       'xchg on the word at [A+0x10]+0x28); '
                       'released by the cell glue through the '
                       'family context-release slot')},
        {'offset': '0x18', 'name': 'state',
         'producer': ('spawn body writes 0; only the '
                      'dispatcher finish block writes 1 '
                      '(fall-through and landing-pad copies)'),
         'consumers': ('dispatcher pre-store drain test; '
                       'payload drop (drains, then zeroes the '
                       'word); cell glue re-test (unwind '
                       'paths, via the family drain helper on '
                       'the triple at +0x18); X5 join (bit 0 '
                       'test, word cleared on take)')},
        {'offset': '0x20', 'name': 'data',
         'producer': ('dispatcher finish block only; the '
                      'spawn pair slot is uninitialised. '
                      'Normal path: 0 (r14 zeroed at '
                      'dispatcher entry). Catch path: the '
                      'panic Box data pointer from the '
                      'catch-pair helper (slot 0x64dfe88)'),
         'consumers': ('X5 join take (loaded out); drained '
                       '(dropped + deallocated through the '
                       'stored vtable) by the dispatcher, '
                       'the payload drop, the cell glue and '
                       'the drain helper. X4: drained only, '
                       'never taken')},
        {'offset': '0x28', 'name': 'vtable',
         'producer': ('dispatcher finish block only. '
                      'Normal path, X4: r15 = the entry base '
                      '0x64c5330, loaded by the thread start '
                      'routine from package +0x10 (#3050). '
                      'Normal path, X5: r15 = the word at '
                      'closure +0x30, the vtable half of the '
                      'closure environment fat-pointer field '
                      'at closure +0x28, copied by the spawn '
                      'body from its caller argument struct; '
                      'the dispatcher loads r15 from closure '
                      '+0x30 at entry. Catch path: the panic '
                      'Box vtable from the catch-pair helper'),
         'consumers': ('same readers as data; the drain '
                       'paths call [vtable] as the drop fn '
                       'and read size at [vtable+0x08] and '
                       'align at [vtable+0x10]')},
    ],
    'family_differences': (
        'Layout offsets are identical across type-A, X4 and '
        'X5.  The families differ as monomorphisations (own '
        'cell glue, payload drop and context-release glue per '
        'family, over distinct context object types) and in '
        'two uses: the X5 finish store takes its vtable half '
        'from closure +0x30 where X4 (and type-A) take the '
        'entry base in r15; and X5 has a join body that takes '
        'the pair out, while no body takes the X4 pair.'),
}

BOUNDARIES = {
    'context_identity': (
        'What the context object A at cell +0x10 is at source '
        'level is not pinned for either family (same limit as '
        '#3050 for type-A): the binary shows a refcounted '
        'object (counter at A+0x18 incremented by the spawn '
        'bodies, flag byte at A+0x20, a related object pointer '
        'at A+0x10 whose +0x28 word the payload drop xchgs) '
        'handed to each spawn body as argument r9; no string '
        'or Location names it on these paths.'),
    'x5_env_pair_identity': (
        'What the fat-pointer field at X5 closure +0x28/+0x30 '
        'is at source level is not pinned: the spawn body '
        'copies both words from its caller argument struct '
        'into the closure image, the dispatcher passes the '
        'pair to its second adapter and stores only the '
        '+0x30 word into a finished cell.  Its data word is '
        'discarded on the finish path (r14 is zeroed), so the '
        'cell never holds that pair itself.'),
    'join_x5_semantics': (
        'The take/release semantics of the X5 join body '
        '0x5cf7550 (CAS protocol, reference release order, '
        'diagnostics) are the subject of open PR #3074 '
        '(RE-012) and are not re-derived here; this packet '
        'pins only the cell offsets that body reads and '
        'writes, as one consumer of the layout.'),
    'drain_reachability': (
        'Whether the dispatchers\' pre-store drain (and the '
        'glue drain) ever sees a live pair is a run-time '
        'question: each dispatcher runs once per fresh cell '
        'whose state starts at 0, and static analysis does '
        'not decide how a second store into the same cell '
        'would arise.  Only the drain paths and the offsets '
        'they use are pinned.'),
    'adapter_semantics': (
        'What the two adapters per dispatcher do with their '
        'environment copies (X4 slots 0x64ecb60/0x64ecb58, '
        'X5 slots 0x64ecb98/0x64ecb88) is not revisited; '
        'neither adapter receives the cell pointer, and '
        'neither performs the completion store.'),
}

LIMITS = (
    'Static analysis only; no captured code was executed. '
    'Body boundaries are FDE extents cross-checked by '
    'SHA-256.  Producer/consumer closure rests on the '
    'byte-pinned bodies above plus the completion-store '
    'idiom census of #3050 (13 bodies: the 11 dispatchers '
    'and two stack constructions) and the take-idiom census '
    'of #3148 (exactly two join bodies), which bound the set '
    'of bodies that can store into or take out of any '
    'dispatcher packet cell.')


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


def relative_map(data):
    return {off: add for off, rows in rela_entries(data).items()
            for typ, add in rows if typ == 8}


def tables(data):
    rel = relative_map(data)
    records = []
    for base, family, role, want_size in ENTRIES:
        _, raw = read(base + 8, data, 16)
        size, align = struct.unpack('<QQ', raw)
        drop = rel.get(base)
        method = rel.get(base + 0x18)
        check(drop is not None and method is not None,
              f'table entry {base:#x} missing relocations')
        check(method == OWNERS[role][0],
              f'table method mismatch at {base:#x}')
        check(align == 8, f'table align mismatch at {base:#x}')
        check(size == want_size,
              f'table size mismatch at {base:#x}')
        records.append({'base': hex(base), 'family': family,
                        'dispatcher': role,
                        'drop': hex(drop), 'size': hex(size),
                        'align': hex(align), 'method': hex(method)})
    return records


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


def objdump_range(data, start, end):
    text = subprocess.run(
        ['objdump', '-d', '--start-address', hex(start),
         '--stop-address', hex(end), str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    return text.replace(str(TARGET), SNAPSHOT, 1)


def exports(data, role):
    start, end, _ = OWNERS[role]
    return objdump_range(data, start, end)


def frame_lines(data):
    # Read the frames from the target file itself (the bytes are
    # already authenticated by owners()); no scratch copy is made.
    text = subprocess.run(['readelf', '-wf', str(TARGET)],
                          check=True, capture_output=True,
                          text=True).stdout
    wanted = []
    for start, end, _ in OWNERS.values():
        needle = (f'pc={start:016x}..{end:016x}')
        wanted += [ln for ln in text.splitlines() if needle in ln]
    check(len(wanted) == len(OWNERS), 'owner frame lines missing')
    return [line + '\n' for line in wanted]


_LINE = re.compile(r'^\s+([0-9a-f]+):\t[0-9a-f ]+\t(.*)$')
_STORE_REG = re.compile(
    r'^mov\s+%(\w+),(0x18|0x20|0x28)\(%(\w+)\)$')
_STORE_IMM = re.compile(
    r'^movq\s+\$0x([0-9a-f]+),(0x18|0x20|0x28)\(%(\w+)\)$')
_SLOT_REF = re.compile(r'# ([0-9a-f]+) <')


def body_stores(text):
    """(va, kind, disp, base, src) for plain/imm stores in a body."""
    out = []
    for line in text.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        va, ins = int(m.group(1), 16), m.group(2).strip()
        mm = _STORE_REG.match(ins)
        if mm:
            out.append((va, 'reg', mm.group(2), mm.group(3),
                        mm.group(1)))
            continue
        mm = _STORE_IMM.match(ins)
        if mm:
            out.append((va, 'imm', mm.group(2), mm.group(3),
                        int(mm.group(1), 16)))
    return out


def body_slots(text):
    return sorted({int(x, 16) for x in _SLOT_REF.findall(text)})


def finish_store_audit(data):
    """The completion stores of both dispatchers, from objdump.

    Each dispatcher must show exactly two copies (fall-through
    and landing pad) of the finish block: state := 1 (imm) at
    +0x18, data from r14 at +0x20, vtable from r15 at +0x28,
    all with base rbp (the cell pointer).
    """
    records = {}
    for role in ('dispatcher_x4', 'dispatcher_x5'):
        start, end, _ = OWNERS[role]
        text = objdump_range(data, start, end)
        stores = [s for s in body_stores(text) if s[3] == 'rbp']
        want = [('imm', '0x18', 1), ('reg', '0x20', 'r14'),
                ('reg', '0x28', 'r15')]
        got = [(k, d, s) for _, k, d, _, s in stores]
        check(sorted(got) == sorted(want * 2),
              f'finish stores mismatch {role}: {got}')
        records[role] = {
            'stores': [{'site': hex(va), 'kind': k, 'disp': d,
                        'base': b, 'src': s}
                       for va, k, d, b, s in stores],
            'slots_referenced': [hex(s) for s in body_slots(text)],
        }
    return records


def analyze(data):
    owner_records = owners(data)
    pin_records = check_pins(data)
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
        'tables': tables(data),
        'slots': slots(data),
        'finish_store_audit': finish_store_audit(data),
        'boundaries': BOUNDARIES,
        'limits': LIMITS,
    }


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
