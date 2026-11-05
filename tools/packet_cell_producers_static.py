#!/usr/bin/env python3
"""Node 115: who produces the fat pointer in the dispatcher's packet cell.

The dispatcher-table packet (#3000) pinned the 498-byte dispatcher
0x15b8fd0 (the call_once shim in static-table entry 0x6400530): per
call it invokes two adapters, then drains one shared packet cell --
the Arc allocation whose pointer sits at closure +0x20 -- and, on
the finish path, stores a fat pointer back into the cell
(state := 1 at +0x18, data from r14 at +0x20, vtable from r15 at
+0x28).  That packet left two ends open: who else, if anyone,
stores a fat pointer into that cell (the producers), and where the
r15 value written to +0x28 comes from.

Answers, all static and re-derived by analyze() below:

1.  Producers: the only body that stores the pair into this cell
    instance is the dispatcher itself, on its single finish block
    (two copies: fall-through and landing pad).  The store idiom --
    movq $1,[base+0x18]; mov %r14,[base+0x20]; mov %r15,[base+0x28]
    -- occurs in exactly 13 bodies in .text.  Four are this
    dispatcher's own table family (entries 0x64004d0..0x6400530),
    five are sibling dispatchers whose cells share this cell's Arc
    drop glue (GOT slot 0x64dfe60 -> body 0x5bc2a80) but belong to
    other closures (entries 0x6451280, 0x64aa788, 0x64aa7a8,
    0x64aa7c8, 0x64bdc50), two are dispatchers of two further cell
    types (own drop-glue slots 0x64ecb50 / 0x64ecc48), and two are
    stack-value constructions (base rsp) that never touch a heap
    cell.  No other body performs the completion store; the cell's
    remaining writers are its own spawn body (initialisation: state
    0, pair slot uninitialised), the join body (take: pair loaded
    out, state := 0) and the two drop paths (drain-if-present).
2.  Payload shapes stored by the finish block: on the normal path
    r14 = 0 (xor at 0x15b9083), so the cell is left holding
    {data = NULL, vtable = r15}; on the catch path the pair is the
    panic payload's Box fat pointer, extracted by the helper behind
    GOT slot 0x64dfe88 (body 0x5bb19f0) from the caught Rust panic
    object (magic "MOZ\\0RUST" at +0x00, box data at +0x28, box
    vtable at +0x30, returned in rax:rdx -> r14:r15).
3.  The r15 origin, from the producer side: the dispatcher never
    writes r15 on its normal path (the single r15 write in the
    body is the catch-path mov %rdx,%r15 at 0x15b918e).  r15 at the
    finish store is the value the thread start routine 0x5ca44a0
    loaded from package +0x10 at 0x5ca45a6 and held across the
    call *0x18(%r15) at 0x5ca45d7 -- and package +0x10 is written
    by the spawn body 0x15b80e0, which stores the lea of its own
    static-table entry base 0x6400530 (lea at 0x15b8436) there.
    So the vtable half stored back on the normal path is the
    dispatcher's own entry vtable base: the cell is left holding a
    null-data trait object under the entry's own vtable, with
    state 1 marking completion for the join body, which tests
    state bit 0 and returns the pair in rax:rdx.
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
WORK_ITEM = 'RE-005-node115-packet-cell-producers'
OUT = ROOT / 'research/work-items' / WORK_ITEM

OWNERS = {
    'dispatcher_v1': (0x15b8cd0, 0x15b8e35,
                      '12e808c3517fa8aaa23b9caf9977b3cd269a45709c4a408'
                      '51b9fce75a87bc083'),
    'dispatcher_v2': (0x15b8e40, 0x15b8fc4,
                      'c5eb71b1574df93dbc20811992a518e4fe15892012e85725'
                      '51490b559c226efc'),
    'dispatcher_v3': (0x15b91d0, 0x15b932d,
                      '743621b0b7925a30bfbd46b9b3ed87266f5fda28f797f66'
                      'ebefa6af69ef00d3c'),
    'dispatcher_v4': (0x15b8fd0, 0x15b91c2,
                      '20cd3ac9bdc80df92482568c93f647e74cf4402f9b8b9c8'
                      'f917d8f7ba32dd0d9'),
    'dispatcher_x1': (0x2dd4f10, 0x2dd50cd,
                      '866f54c1d0f22e82fff69bdc2264eb03ce6d21ce135986d'
                      '5a6147011234c2bd5'),
    'dispatcher_x2a': (0x561f970, 0x561fb2d,
                       'c274b94bb48e9a5ab9163ba1a428c01dde1bba5594d27c'
                       'f403b0cdb3bb99cdad'),
    'dispatcher_x2b': (0x561fed0, 0x5620073,
                       '8967b83b554d76bb806ab31fe1961cbc16977a1916388a'
                       '525069a66c4bdbca02'),
    'dispatcher_x2c': (0x5620120, 0x56202dd,
                       '3aacd56cd0167d82a8b1dc920ceb5fb1965db54ac9da4294'
                       'f689fdcaf877db08'),
    'dispatcher_x3': (0x5bc3350, 0x5bc3607,
                      '59e6cda1aa5b9276b19ab3c8aa3abb6cef1a961cdd487f'
                      'a71ec971cb787852a6'),
    'dispatcher_x4': (0x5cd9b30, 0x5cd9cd7,
                      '939b0f395bedfc84d55c5f6a2de8b19f39bc64089ce0cf'
                      '3c25efe284478f51ae'),
    'dispatcher_x5': (0x5cf7710, 0x5cf78e7,
                      '313eb6afb9fb15a3d11f14e20b1bd68e89d8be9ad5710264'
                      '69e43fd35aa0bbd2'),
    'spawn_v4': (0x15b80e0, 0x15b8804,
                 '967d4b0bb72e2e86245bc092d3d850f2324631adaf5482ac'
                 '4df09804e3f152b8'),
    'join_v4': (0x15b8810, 0x15b896e,
                'f57a1ff86b1b2a431d2c168a23145ea2e603de76a51c662852d29'
                'c39853587aa'),
    'thread_start': (0x5ca44a0, 0x5ca469d,
                     '65e3438cb7b950aa4b885b7c271b6a8bcbd4574519dee0f3'
                     'f336360fabb21276'),
    'thread_create': (0x5c87b50, 0x5c87d4b,
                      '5a32afe678297cf1c46e730c440c2bc7158ccf7d949d5cc7'
                      '3c923e65644dd1e6'),
    'closure_drop_v4': (0x15bb300, 0x15bb387,
                        '60420815afb983f51ec356449a5d87c16ecf47d741c50983'
                        'f11c12befc156d73'),
    'cell_arc_drop': (0x5bc2a80, 0x5bc2bb4,
                      'fd3d9290228daf8af09b05b6c33b186878cb988f7e7eb2af'
                      '500c61c5e5957ca2'),
    'cell_payload_drop': (0x5bc3bf0, 0x5bc3d5e,
                          '34b27ee7a0f42fc39e8ec6eb5ff80aac859e4efa05834'
                          'dfc7cc2e39d8443c667'),
    'catch_pair': (0x5bb19f0, 0x5bb1a3f,
                   '2cef45eb77cd2fc8d8b607539e99a33167976c451803bc33'
                   '45f9416197c22d8e'),
    'begin_catch': (0x1680cab, 0x1680cbf,
                    '7604c0d4f26a7d70e59c5dcb8a39928bfd7207a5d4439d91d8f'
                    'b1e50be9846e7'),
    'dealloc_body': (0x635de30, 0x635ded5,
                     '714fc5cdd28a2587427c9dac8a25685ec09695a3a21bc9af'
                     '0eb09b29ae503f61'),
    'adapter_a_v4': (0x155fa10, 0x155fa53,
                     '61b4de43a06f936410b37a7d3c49857857e0fd892024a617d'
                     '7a522ac59692155'),
    'adapter_0_v4': (0x155f9e0, 0x155fa02,
                     '1c44ea5176f2e3f4a1ae286402e3f0253413d116e536fbb75'
                     'f86e3a9d4655772'),
}

EXPORTED = ('dispatcher_v4', 'dispatcher_v3', 'spawn_v4', 'join_v4',
            'thread_start', 'closure_drop_v4', 'cell_arc_drop',
            'cell_payload_drop', 'catch_pair', 'adapter_a_v4')

PINS = {
    'dispatcher_v4': [
        (0x15b9083, '4531f6'),            # xor %r14d,%r14d
        (0x15b9054, 'ff15be82f204'),      # call adapter_0 slot
        (0x15b907d, 'ff150d81f204'),      # call adapter_a slot
        (0x15b9086, '488b6b20'),          # mov 0x20(%rbx),%rbp (cell)
        (0x15b908a, '48837d1800'),        # cmpq $0,0x18(%rbp)
        (0x15b9091, '4c8b6520'),          # mov 0x20(%rbp),%r12 (data)
        (0x15b909a, '4c8b6d28'),          # mov 0x28(%rbp),%r13 (vtable)
        (0x15b90da, '48c7451801000000'),  # movq $1,0x18(%rbp)
        (0x15b90e2, '4c897520'),          # mov %r14,0x20(%rbp)
        (0x15b90e6, '4c897d28'),          # mov %r15,0x28(%rbp)
        (0x15b90ef, 'f048ff4d00'),        # lock decq 0x0(%rbp)
        (0x15b918e, '4989d7'),            # mov %rdx,%r15 (catch only)
    ],
    'spawn_v4': [
        (0x15b835a, 'f048ff4718'),        # lock incq 0x18(%rdi) ctx count
        (0x15b83c9, 'bf58000000'),        # mov $0x58,%edi closure alloc
        (0x15b8410, '0f115020'),          # movups %xmm2,0x20(%rax) cell
        (0x15b8436, '488d05f380e404'),    # lea 0x6400530,%rax entry base
        (0x15b8476, 'ff150491f204'),      # call thread-create slot
    ],
    'thread_start': [
        (0x5ca44af, '4c8b27'),            # mov (%rdi),%r12 package head
        (0x5ca45a6, '4c8b7b10'),          # mov 0x10(%rbx),%r15 vtable
        (0x5ca45d7, '41ff5718'),          # call *0x18(%r15) dispatcher
    ],
    'thread_create': [
        (0x5c87c19, '488d1580c80100'),    # lea thread_start,%rdx
    ],
    'join_v4': [
        (0x15b886b, '4c8b7020'),          # mov 0x20(%rax),%r14 take data
        (0x15b886f, '4c8b7828'),          # mov 0x28(%rax),%r15 take vt
        (0x15b8873, 'f6401801'),          # testb $1,0x18(%rax)
        (0x15b8877, '48c7401800000000'),  # movq $0,0x18(%rax)
    ],
    'closure_drop_v4': [
        (0x15bb339, '488b4320'),          # mov 0x20(%rbx),%rax cell
        (0x15bb351, 'ff25094bf204'),      # jmp *cell-glue slot
    ],
    'cell_arc_drop': [
        (0x5bc2aae, '48837b1800'),        # cmpq $0,0x18(%rbx) state
        (0x5bc2b09, 'be30000000'),        # mov $0x30,%esi alloc size
    ],
    'cell_payload_drop': [
        (0x5bc3c56, '48c7430800000000'),  # movq $0,0x8(%rbx) state := 0
        (0x5bc3c6f, 'f048ff4818'),        # lock decq 0x18(%rax) ctx
    ],
    'catch_pair': [
        (0x5bb19f7, '48b84d4f5a0052555354'),  # movabs "MOZ\0RUST"
        (0x5bb1a13, '488b5f28'),          # mov 0x28(%rdi),%rbx data
    ],
    'adapter_a_v4': [
        (0x155fa46, 'e885750700'),        # call wrapper_a 0x15d6fd0
    ],
}

# Static one-method vtable entries: (base, family, dispatcher role).
# Layout per entry: {drop, size, align = 8, method(call_once)}.
ENTRIES = [
    (0x64004d0, 'L', 'dispatcher_v1'),
    (0x64004f0, 'L', 'dispatcher_v2'),
    (0x6400510, 'L', 'dispatcher_v3'),
    (0x6400530, 'L', 'dispatcher_v4'),
    (0x6451280, 'X1', 'dispatcher_x1'),
    (0x64aa788, 'X2', 'dispatcher_x2a'),
    (0x64aa7a8, 'X2', 'dispatcher_x2b'),
    (0x64aa7c8, 'X2', 'dispatcher_x2c'),
    (0x64bdc50, 'X3', 'dispatcher_x3'),
    (0x64c5330, 'X4', 'dispatcher_x4'),
    (0x64c6ac0, 'X5', 'dispatcher_x5'),
]

SLOTS = {
    'cell_arc_drop': 0x64dfe60,
    'thread_arc_drop': 0x64dfe58,
    'catch_pair': 0x64dfe88,
    'catch_counter': 0x64dfe90,
    'dealloc': 0x64df4a0,
    'begin_catch': 0x64df4c0,
    'adapter_0_v4': 0x64e1318,
    'adapter_a_v4': 0x64e1190,
    'thread_create': 0x64e1580,
    'x4_cell_drop': 0x64ecb50,
    'x5_cell_drop': 0x64ecc48,
}

QUESTION = (
    'The dispatcher-table packet (#3000) left two ends open about '
    'the shared packet cell the dispatcher 0x15b8fd0 drains (the '
    'Arc allocation pointed to by closure +0x20; payload S at '
    'allocation +0x10 = {context at +0x10, state at +0x18, fat '
    'pointer data at +0x20, fat pointer vtable at +0x28}): '
    '(1) who stores a fat pointer into that cell -- the full census '
    'of bodies storing into it, and the payload shape each '
    'producer writes; (2) can the origin of the r15 value the '
    'dispatcher stores back to packet +0x28 be pinned from the '
    'producer side?')

ANSWER = {
    'producers': (
        'The only producer of this cell instance is the dispatcher '
        'itself. Its finish block (state := 1, data := r14, vtable '
        ':= r15, then a strong-count decrement on the cell) runs '
        'on every exit: the fall-through copy at 0x15b90da and the '
        'landing-pad copy at 0x15b9141. The completion-store idiom '
        'occurs in exactly 13 bodies in the whole .text (idiom '
        'census); none of the other 12 is a producer of this '
        'instance: four are the sibling dispatchers of the same '
        'table family, five are sibling dispatchers of other '
        'closures whose cells share this cell\'s Arc drop glue '
        '(slot 0x64dfe60), two are dispatchers of two different '
        'cell types (their own drop-glue slots), and two write '
        'the idiom onto their own stack frames only. The cell\'s '
        'other accesses are not productions: the spawn body '
        'initialises it, the join body takes the pair out '
        '(state := 0), and the Arc/payload drop paths drain it '
        'if a pair is still present.'),
    'payload_shapes': (
        'Normal path: r14 is zeroed at dispatcher entry '
        '(0x15b9083), so the stored pair is {data = NULL, vtable '
        '= r15} -- an empty trait object under a live vtable, '
        'with state 1 as the completion marker the join body '
        'tests (bit 0) before returning the pair in rax:rdx. '
        'Catch path: after the begin-catch body (slot 0x64df4c0 '
        '-> 0x1680cab), the helper behind slot 0x64dfe88 '
        '(0x5bb19f0) checks the panic object\'s "MOZ\\0RUST" '
        'magic and returns the enclosed Box fat pointer (data '
        'from object +0x28, vtable from object +0x30) in rax:rdx; '
        'the dispatcher moves it to r14:r15 (0x15b9170 / '
        '0x15b918e), drains any pair already in the cell, and the '
        'same finish block stores the panic payload pair.'),
    'r15_origin': (
        'Pinned from the producer side. The dispatcher contains '
        'exactly one r15-writing instruction, the catch-path mov '
        '%rdx,%r15 at 0x15b918e, so on the normal path the stored '
        'r15 is the caller\'s value, preserved across both adapter '
        'calls. The only caller is the thread start routine '
        '0x5ca44a0 (no direct call sites exist; the thread-create '
        'body 0x5c87b50 passes it to pthread_create as the start '
        'routine, lea at 0x5c87c19). The start routine loads r15 '
        'from package +0x10 at 0x5ca45a6 and does not write r15 '
        'before the call *0x18(%r15) at 0x5ca45d7. Package +0x10 '
        'is written by the spawn body 0x15b80e0: the package is a '
        'fresh 0x18-byte allocation {thread Arc at +0x00, closure '
        'data at +0x08, vtable base at +0x10}, and the vtable '
        'base stored at 0x15b8461.. is the lea 0x6400530 result '
        'of 0x15b8436 -- this dispatcher\'s own static-table '
        'entry. So on the normal path packet +0x28 receives the '
        'entry vtable base 0x6400530, produced by the spawn body; '
        'the lea census shows each of the 11 entries is loaded '
        'by exactly one lea, in its own spawn body.'),
    'cell_layout': (
        'Cell allocation is 0x30 bytes (dealloc size in the Arc '
        'drop glue 0x5bc2a80): strong count at +0x00, weak count '
        'at +0x08, payload S at +0x10: {context A at +0x10 (its '
        'own Arc count at A+0x00 and a second atomic counter at '
        'A+0x18, incremented by the spawn body at 0x15b835a and '
        'decremented by the payload drop 0x5bc3bf0, which also '
        'sets a flag byte at A+0x20 when it discards a live '
        'pair), state at +0x18, data at +0x20, vtable at +0x28}. '
        'The spawn body initialises state to 0 and leaves the '
        'pair slot uninitialised; the pair is only ever read '
        'when state is nonzero (dispatcher drain, Arc drop '
        'glue, payload drop) or taken by the join body after '
        'the thread has finished.'),
}

BOUNDARIES = {
    'context_a_identity': (
        'What the context object A at cell +0x10 is at source '
        'level is not pinned: the binary shows a refcounted '
        'object (Arc count at +0x00, second atomic counter at '
        '+0x18, flag byte at +0x20) handed to each spawn body '
        'as an argument (r9 for spawn_v4) and stored into the '
        'fresh cell; no string or Location names it on these '
        'paths.'),
    'sibling_instances': (
        'The sibling dispatchers (families X1/X2/X3) drain cells '
        'of the same Arc type but of their own closures; who '
        'owns those JoinHandles and whether their callers ever '
        'read the returned pair is not traced here. Families '
        'X4/X5 use different cell types (drop-glue slots '
        '0x64ecb50 / 0x64ecc48) and are classified only far '
        'enough to exclude them.'),
    'adapter_semantics': (
        'What the two adapters per dispatcher do with their '
        'environment copies (adapter_0 / adapter_a for v4, '
        'pinned in #2969) is not revisited; neither adapter '
        'receives the cell pointer in its argument struct '
        '(adapter_0 gets closure +0x00..+0x20, adapter_a gets '
        'closure +0x28..+0x58), and neither performs the '
        'completion store.'),
    'kind1_arm': (
        'Whether the kind-1 arm of wrapper A (0x15d6fd0, '
        '#2969) is selected at run time, and therefore how '
        'often any given dispatcher runs, is a run-time '
        'question static analysis does not decide.'),
}

LIMITS = (
    'Static analysis only; the captured binary was parsed and '
    'disassembled, never executed. The producer census is '
    'instruction-accurate for the completion-store idiom as '
    'compiled here (immediate state store + r14/r15 pair store, '
    'direct or disp32 addressing, verified per body against '
    'objdump); a hypothetical producer using SIB-based '
    'addressing, a computed state value, or a bulk copy to '
    'write the cell would not match the idiom and is excluded '
    'only in combination with the holder-flow evidence (the '
    'cell pointer is created by the spawn bodies and escapes '
    'only to the closure at +0x20, the JoinHandle at +0x08 and '
    'stack temporaries of the pinned bodies). FDE extents are '
    'unwind ranges, not proven function boundaries. GOT slot '
    'targets are the relocation addends of this static PIE; '
    'two slots used by the spawn/join bodies are dynamic '
    '(GLOB_DAT) and are identified by role, not by target.')



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
    for base, family, role in ENTRIES:
        _, raw = read(base + 8, data, 16)
        size, align = struct.unpack('<QQ', raw)
        drop = rel.get(base)
        method = rel.get(base + 0x18)
        check(drop is not None and method is not None,
              f'table entry {base:#x} missing relocations')
        check(method == OWNERS[role][0],
              f'table method mismatch at {base:#x}')
        check(align == 8, f'table align mismatch at {base:#x}')
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
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.bin',
                                     delete=False) as tmp:
        tmp.write(data)
        name = tmp.name
    try:
        text = subprocess.run(['readelf', '-wf', name],
                              check=True, capture_output=True,
                              text=True).stdout
    finally:
        Path(name).unlink()
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



_IMM1 = re.compile(
    rb'[\x48\x49]\xc7[\x40-\x47]\x18\x01\x00\x00\x00'
    rb'|[\x48\x49]\xc7[\x80-\x87]\x18\x00\x00\x00\x01\x00\x00\x00'
    rb'|[\x48\x49]\xc7\x44\x24\x18\x01\x00\x00\x00'
    rb'|[\x48\x49]\xc7\x84\x24\x18\x00\x00\x00\x01\x00\x00\x00')
_R14 = re.compile(
    rb'[\x4c\x4d]\x89[\x70-\x77]\x20'
    rb'|[\x4c\x4d]\x89[\xb0-\xb7]\x20\x00\x00\x00'
    rb'|\x4c\x89\x74\x24\x20'
    rb'|\x4c\x89\xb4\x24\x20\x00\x00\x00')
_R15 = re.compile(
    rb'[\x4c\x4d]\x89[\x78-\x7f]\x28'
    rb'|[\x4c\x4d]\x89[\xb8-\xbf]\x28\x00\x00\x00'
    rb'|\x4c\x89\x7c\x24\x28'
    rb'|\x4c\x89\xbc\x24\x28\x00\x00\x00')
_LEA = re.compile(rb'[\x48\x49\x4c\x4d]\x8d[\x05\x0d\x15\x1d'
                  rb'\x25\x2d\x35\x3d]')


def _text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec, data[sec['offset']:sec['offset'] + sec['size']]


def idiom_census(data):
    sec, tb = _text(data)
    base = sec['address']
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    import bisect

    def containing(va):
        i = bisect.bisect_right(starts, va) - 1
        check(i >= 0, f'no FDE for {va:#x}')
        return starts[i]

    cand = {}
    for name, pattern in (('imm1', _IMM1), ('r14', _R14),
                          ('r15', _R15)):
        for m in pattern.finditer(tb):
            body = containing(base + m.start())
            cand.setdefault(body, set()).add(name)
    bodies = sorted(b for b, kinds in cand.items()
                    if kinds == {'imm1', 'r14', 'r15'})
    role_by_start = {v[0]: k for k, v in OWNERS.items()}
    records = []
    for body in bodies:
        end = None
        for role, (s, e, _) in OWNERS.items():
            if s == body:
                end = e
        if end is None:
            i = bisect.bisect_right(starts, body)
            end = starts[i]
        text = objdump_range(data, body, end)
        stores = body_stores(text)
        triples = {}
        for va, kind, disp, breg, src in stores:
            if (kind == 'imm' and disp == '0x18' and src == 1):
                triples.setdefault(breg, {})['state'] = hex(va)
            if (kind == 'reg' and disp == '0x20' and src == 'r14'):
                triples.setdefault(breg, {})['data'] = hex(va)
            if (kind == 'reg' and disp == '0x28' and src == 'r15'):
                triples.setdefault(breg, {})['vtable'] = hex(va)
        full = {b: t for b, t in triples.items()
                if len(t) == 3}
        check(full, f'idiom candidate {body:#x} did not verify')
        breg, sites = next(iter(full.items()))
        fam = None
        for t in tables(data):
            if t['dispatcher'] == role_by_start.get(body):
                fam = t['family']
        records.append({
            'body': hex(body),
            'role': role_by_start.get(body),
            'family': fam,
            'base_register': breg,
            'class': ('stack_construction' if breg == 'rsp'
                      else 'dispatcher_finish'),
            'sites': sites,
            'slots_referenced': [hex(s) for s in body_slots(text)],
        })
    return {'bodies': records, 'count': len(records)}


def lea_census(data):
    sec, tb = _text(data)
    base = sec['address']
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    import bisect
    targets = {b for b, _, _ in ENTRIES}
    out = {}
    for m in _LEA.finditer(tb):
        va = base + m.start()
        disp = struct.unpack_from('<i', tb, m.end())[0]
        tgt = va + (m.end() - m.start()) + 4 + disp
        if tgt in targets:
            i = bisect.bisect_right(starts, va) - 1
            out.setdefault(hex(tgt), []).append(
                {'site': hex(va), 'body': hex(starts[i])})
    return out


def call_census(data):
    sec, tb = _text(data)
    base = sec['address']
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    import bisect
    targets = {'spawn_v4': OWNERS['spawn_v4'][0],
               'dispatcher_v4': OWNERS['dispatcher_v4'][0],
               'cell_payload_drop': OWNERS['cell_payload_drop'][0],
               'thread_start': OWNERS['thread_start'][0]}
    out = {k: [] for k in targets}
    for m in re.finditer(rb'\xe8', tb):
        va = base + m.start()
        disp = struct.unpack_from('<i', tb, m.start() + 1)[0]
        tgt = va + 5 + disp
        for name, t in targets.items():
            if tgt == t:
                i = bisect.bisect_right(starts, va) - 1
                out[name].append({'site': hex(va),
                                  'body': hex(starts[i])})
    return out


_R15_WRITE = re.compile(
    r'^(mov|xor|and|or|add|sub|lea|movq)\s+.*?,\s*%r15d?$')


def r15_audit(data):
    start, end, _ = OWNERS['dispatcher_v4']
    text = objdump_range(data, start, end)
    writes = []
    stores = []
    for line in text.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        va, ins = int(m.group(1), 16), m.group(2).strip()
        if _R15_WRITE.match(ins) and 'push' not in ins:
            writes.append({'site': hex(va), 'insn': ins})
        mm = _STORE_REG.match(ins)
        if mm and mm.group(1) == 'r15' and mm.group(2) == '0x28':
            stores.append(hex(va))
    return {'dispatcher_r15_writes': writes,
            'dispatcher_r15_stores_to_0x28': stores}


def dispatcher_audit(data):
    start, end, _ = OWNERS['dispatcher_v4']
    text = objdump_range(data, start, end)
    stores = body_stores(text)
    return {
        'stores': [{'site': hex(va), 'kind': k, 'disp': d,
                    'base': b, 'src': s if isinstance(s, str)
                    else s}
                   for va, k, d, b, s in stores],
        'slots_referenced': [hex(s) for s in body_slots(text)],
    }


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
        'idiom_census': idiom_census(data),
        'lea_census': lea_census(data),
        'call_census': call_census(data),
        'r15_audit': r15_audit(data),
        'dispatcher_audit': dispatcher_audit(data),
        'boundaries': BOUNDARIES,
        'limits': LIMITS,
    }


def generate(data):
    OUT.mkdir(parents=True, exist_ok=True)
    records = analyze(data)
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (OUT / 'frames.txt').write_text(''.join(frame_lines(data)))
    for role in EXPORTED:
        (OUT / f'{role}.objdump.txt').write_text(exports(data, role))


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
    print(json.dumps({'packet': WORK_ITEM, 'matches': True},
                     sort_keys=True))


if __name__ == '__main__':
    main()
