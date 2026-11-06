"""Static evidence for the RE-005 park contention
fallback packet.

Answers the open edge left by both the RE-005 TLS
value-object packet (PR #2935, which listed body
0x5ce30d0 as beyond its boundary) and the RE-005
park_timeout provenance packet (PR #2938, open edge:
"the contention fallback body 0x5ce30d0 that
registration_b calls when its byte claim fails"),
for the authenticated hl-node 115 artifact only:
what is the body, who can reach it and under what
conditions, what does it do inside, and can the
fallback actually fire?

SETTLED.  The body is the park core of the vendored
tokio multi-thread scheduler: its own panic Locations
name .../z_vendor/tokio/src/runtime/scheduler/
multi_thread/park.rs (lines 179, 211, 213).  It
operates on the same per-thread park cell Q that
registration_b 0x5cec8b0 drives -- Q is the field at
[r13+0x10] of the handle object registration_b takes
from its argument -- with the state word at [Q+8],
the guard byte at [Q+0x18] and the wait key at
[Q+0x10].  It never reads or writes [Q+0], the
pointer to the shared inner the byte claim protects.

Exactly one route in.  The whole-.text rel32 census
finds a single reference to the body in the whole
artifact: call 0x5cec9ec in registration_b.  There
is no tail jump, no raw pointer occurrence and no
.rela.dyn RELATIVE addend for the body start, so no
indirect route exists either.

Entry conditions, both inside registration_b with
rdi = Q and esi = 0 hardwired at the shared tail
0x5cec9e7:

- Sentinel arm: the caller's nanos word equals the
  0x3b9aca00 sentinel (cmp pin 0x5cec938), the
  consume CAS on the state word (3 -> 0, pin
  0x5cec948) has failed, and the byte claim on the
  shared inner at [S+0x50] (S = [Q+0]; CAS pin
  0x5cec95e) has failed, with the sentinel reloaded
  into r15d at 0x5cec964 before the branch to the
  tail.  The fallback is called with (0, sentinel).
- Finite arm: nanos is not the sentinel, the byte
  claim at 0x5cec9c8 has failed, and nanos is not
  zero -- the test/je pair at 0x5cec9e2/0x5cec9e5
  skips the call entirely for a zero nanos.

In both arms the byte is held by a sibling
registration_b execution on the same shared inner:
the claim holder keeps the byte across its whole
selector park (claims at 0x5cec95e / 0x5cec9c8,
release by the xchg at 0x5ceca09 on the shared
continuation), so the loser cannot simply wait for
the byte to clear.

Supply above registration_b: its only caller body
top_reg_b 0x5cecc60 supplies edx in {0, sentinel}
at all three call sites (xor-zeroed at 0x5cece57
and 0x5ced565, the sentinel constant at 0x5ced788;
the provenance packet's census), so the finite arm
of registration_b is never fed a finite nonzero
nanos and its zero case is gated off before the
call.  In this artifact the fallback is therefore
entered only with (secs = 0, nanos = sentinel):
only its indefinite-park arm can execute.  The
body's finite-duration arm -- deadline = clock now
plus the pair with the std checked-add overflow
panic (std/src/time.rs line 429), the
remaining-time recomputation through instant_sub
0x5c84210, and the timed wait loop -- is
structurally present but has no supplying caller.

Inside, on the reachable arm: claim the cell's own
guard byte [Q+0x18] (0 -> 1 CAS at 0x5ce30ee); if
it is already set, wait on it through the GOT slot
0x64e01f8 (byte_wait 0x5bb59d0) with (byte pointer,
0x3b9aca00) and continue regardless -- the same
guard idiom the RE-001 queue-table packets pinned
for their payloads.  Then CAS the state word [Q+8]
0 -> 1 (pin 0x5ce3100): an old value of 3 means a
notification raced in, and the body consumes it
(xchg to 0) and returns at once; an old value other
than 0 or 3 panics with "inconsistent park state;
actual = {}" (park.rs line 179).  Otherwise the
body waits in the loop at 0x5ce31b5, calling the
wait helper through GOT slot 0x64e73b8
(wait_helper 0x5bb4670) with (Q+0x10, Q+0x18,
sentinel) until its state CAS 3 -> 0 (pin
0x5ce31d3) succeeds.  Every exit releases the
guard byte (1 -> 0 CAS at 0x5ce331a); if that CAS
fails the exit tail-calls the notify helper
through GOT slot 0x64e0f38 (byte_notify
0x5bb5650) with (byte pointer, 0).  The body is
the only writer of state value 1 in this graph,
and 1 is exactly the "parked by this body" value
its own exit checks accept.

Difference from the normal path: the claim-success
arms drive the state word 0 -> 2 (wrapper_state
0x5ce2fd0 on the finite arm, registration_b's own
CAS at 0x5cec973 on the sentinel arm) and park
through the io/time selectors on the shared inner.
The fallback never touches the shared inner at
all: it parks the calling thread on its own cell
through the scheduler's wait table, cycles the
state word 0 -> 1 -> 0 instead of 0 -> 2 -> 0,
and registration_b discards its return value and
continues at the same shared continuation
(0x5ceca0d) as the claim-success arms, storing the
same pre-claim flag (bpl = 1 on both fallback
arms) into the returned object at +0x74 (pin
0x5cecac1).  The holder's byte is neither claimed
nor released by the loser.

Panic surface: the three park.rs assertions plus
the std duration-overflow panic.  On the reachable
arm only the entry state check (park.rs line 179)
sits on the path, and the pinned writer graph
produces only 0, or a raced 3, for this cell at
that point: it is a consistency assertion, not an
expected outcome.  The park.rs line 211 and 213
panics guard the finite arm's exit switch (jump
table at 0x94cb10: old state 0 -> panic line 211,
1 -> exit, 2 -> panic line 211, 3 -> exit; an old
state above 3 takes the line 213 panic at
0x5ce339d) and, with the overflow panic, are
unreachable from the pinned caller graph.

Method: two bodies are exported in full (the
fallback itself and its only caller,
registration_b); every other body is extent/digest
pinned.  Censuses: whole-.text rel32 call/jump
scans for the fallback, its caller and
wrapper_state, every hit boundary-verified against
its containing FDE body's own disassembly;
.rela.dyn RELATIVE addend census over all chain
bodies (the only hits are the three GOT slots that
resolve to the wait/notify helpers); a raw
whole-file scan for the fallback's address as a
stored pointer; instruction byte pins at every
load-bearing site.  Section mapping via the
section table (tools/elf_index).
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT  # noqa: E402
from elf_index import sections  # noqa: E402

TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7a8278'
                 'fa39f249e98c3867b5301')
WORK_ITEM = 'RE-005-node115-park-contention-fallback'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'
SENTINEL = 0x3B9ACA00

OWNERS = {
    'contention_fallback': (0x5CE30D0, 0x5CE3426),
    'registration_b': (0x5CEC8B0, 0x5CECC58),
}
EXPORTED = list(OWNERS)

PINNED_BODIES = {
    'wrapper_state': (0x5CE2FD0, 0x5CE30C7),
    'top_reg_b': (0x5CECC60, 0x5CEDD12),
    'wait_helper': (0x5BB4670, 0x5BB4CFD),
    'byte_wait': (0x5BB59D0, 0x5BB606D),
    'byte_notify': (0x5BB5650, 0x5BB59C5),
    'clock': (0x5C842E0, 0x5C843A9),
    'instant_sub': (0x5C84210, 0x5C842D6),
}

BODY_SHA256 = {
    'contention_fallback': '1727765a7756690cfec9d1c24f087b05'
                '362624a8154f7e40b5bc94ffe491f16f',
    'registration_b': 'e732e6851f0a42f5bbf4bcb63d5a44f8'
                'e1a030d7428404c514f5af8f92103a77',
    'wrapper_state': '17d62a55fe9d639eee5e5d26f3694a09'
                '0f7f07e629ca729d11bc66c31d3e0e37',
    'top_reg_b': '6daa4de9236c851758d6f62ee795cdd9'
                '5d9450cb932fe723046dd5218d53604d',
    'wait_helper': '65c70b3e926bbf20a45563b947502e17'
                'd87ead04556451512587b556e9f57f1d',
    'byte_wait': '1ba3a96e8d451e9299eb16b37f016d4c'
                '4f050d0ddad46f5f7b3d3e8ce2dc3e76',
    'byte_notify': '4eda0eff3310a0ba59b0a0fa1f208cf4'
                '8e2ec5499b3ad5e48c99b8b93df628de',
    'clock': '3efe331bdc612bff27ad3c487fbff92d'
                '57a2e097820c38f87506703794918f30',
    'instant_sub': 'f9d8d8a41505bf8c9552d4a34ac4e190'
                'a6d0665c245595be11f2848e1a333a4a',
}
ALL_BODIES = dict(OWNERS)
ALL_BODIES.update(PINNED_BODIES)

# Instruction byte pins at every load-bearing site.
PINS = {
    # contention_fallback entry: argument saves
    # (edx -> ebp nanos, rsi -> r12 secs, rdi -> r14
    # cell) and the guard-byte field address.
    0x5CE30DE: '89d5', 0x5CE30E0: '4989f4',
    0x5CE30E3: '4989fe', 0x5CE30E6: '488d5f18',
    # guard byte claim, state word CAS 0 -> 1,
    # sentinel compare on the nanos word.
    0x5CE30EE: 'f00fb04f18', 0x5CE3100: 'f0490fb14e08',
    0x5CE310C: '81fd00ca9a3b',
    # finite arm: the two clock calls and the
    # nanos add with carry into the deadline secs.
    0x5CE3122: 'e8b911faff', 0x5CE3148: '01ea',
    0x5CE316B: 'e87011faff',
    # sentinel wait loop: wait-helper pointer load,
    # the indirect call, the consume CAS 3 -> 0.
    0x5CE31B5: '4c8b3dfc418000', 0x5CE31CB: '41ffd7',
    0x5CE31D3: 'f04d0fb16608',
    # finite arm: second clock call, instant_sub
    # remaining recomputation, the timed wait call
    # through the GOT slot, the post-wait state CAS.
    0x5CE31F6: 'e8e510faff', 0x5CE3213: 'e8f80ffaff',
    0x5CE3286: 'ff152c418000', 0x5CE3297: 'f0490fb14e08',
    # exit: state xchg to 0, jump-table base load,
    # guard wait call, guard release CAS, notify
    # tail jump.
    0x5CE32AC: '49874608', 0x5CE32BA: '488d0d4f98c6fa',
    0x5CE32F1: 'ff1501cf7f00', 0x5CE331A: 'f00fb00b',
    0x5CE3342: 'ff25f0db7f00',
    # registration_b: the sentinel compare, the
    # state consume CAS (3 -> 0), the sentinel-arm
    # byte claim, the sentinel reload, the
    # park-state CAS (0 -> 2), the selector_park
    # call, the finite-arm byte claim, the
    # wrapper_state call, the zero-nanos gate on
    # the fallback, the shared fallback tail
    # (esi = 0, edx = r15d), the fallback call
    # itself and the jump to the shared
    # continuation, the byte release xchg and the
    # returned-object flag store.
    0x5CEC938: '4181ff00ca9a3b', 0x5CEC948: 'f0490fb14d18',
    0x5CEC95E: 'f0410fb04e50', 0x5CEC964: '41bf00ca9a3b',
    0x5CEC973: 'f0490fb14d18', 0x5CEC986: 'e8c53effff',
    0x5CEC9C8: 'f0410fb06e50', 0x5CEC9D9: 'e8f265ffff',
    0x5CEC9E2: '4585ff', 0x5CEC9E5: '7426',
    0x5CEC9E7: '31f6', 0x5CEC9E9: '4489fa',
    0x5CEC9EC: 'e8df66ffff', 0x5CEC9F1: 'eb1a',
    0x5CECA09: '41864650', 0x5CECAC1: '41886e74',
    # top_reg_b supplies into registration_b:
    # xor-zeroed nanos at two sites, the sentinel
    # constant at the third.
    0x5CECE57: '31d2', 0x5CED565: '31d2',
    0x5CED788: 'ba00ca9a3b',
}

# The finite arm's exit switch: a 4-entry jump
# table of i32 offsets relative to the table base.
JUMP_TABLE_BASE = 0x94CB10
JUMP_TABLE_EXPECT = ['0x5ce32ca', '0x5ce3316',
                     '0x5ce32ca', '0x5ce3316']

EXPECTED_RELA_HITS = [
    {'offset': '0x64e01f8', 'addend': '0x5bb59d0'},
    {'offset': '0x64e0f38', 'addend': '0x5bb5650'},
    {'offset': '0x64e73b8', 'addend': '0x5bb4670'},
]

CENSUS_EXPECT = {
    'contention_fallback': {'calls': ['0x5cec9ec'],
                            'jmps': []},
    'registration_b': {'calls': ['0x5cece59', '0x5ced567',
                                 '0x5ced78d'],
                       'jmps': []},
    'wrapper_state': {'calls': ['0x5cec9d9'], 'jmps': []},
}

PARK_RS = ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
           'src/runtime/scheduler/multi_thread/park.rs')
LOCATIONS = {
    'park_inconsistent': (0x64C5A20, 0x4407B7, 86, 179, 28),
    'park_timeout_inconsistent': (0x64C59F0, 0x4407B7, 86,
                                  211, 25),
    'park_timeout_invalid': (0x64C5A08, 0x4407B7, 86,
                             213, 32),
    'duration_overflow': (0x64C4090, 0x44182F, 71, 429, 33),
}
MESSAGES = {
    'park_inconsistent': (
        0x438163, 'inconsistent park state; actual = '),
    'park_timeout_inconsistent': (
        0x43701D, 'inconsistent park_timeout state, actual = '),
    'park_timeout_invalid': (
        0x44CECE, 'invalid park_timeout state, actual = '),
    'duration_overflow': (
        0x94A2C1, 'overflow when adding duration to instant'),
}

FINDINGS = {
    'question': (
        'Open edge of the RE-005 TLS value-object '
        'packet (PR #2935: body 0x5ce30d0 listed as '
        'beyond its boundary) and of the RE-005 '
        'park_timeout provenance packet (PR #2938: '
        '"the contention fallback body 0x5ce30d0 that '
        'registration_b calls when its byte claim '
        'fails"), answered against the same '
        'authenticated artifact: what is the body, '
        'which paths reach it and under what '
        'conditions, what does it produce, and can '
        'it actually fire?'),
    'identity': (
        'SETTLED. The body 0x5ce30d0..0x5ce3426 is '
        'the park core of the vendored tokio '
        'multi-thread scheduler: its three assertion '
        'panics carry Locations in .../z_vendor/'
        'tokio/src/runtime/scheduler/multi_thread/'
        'park.rs (lines 179, 211, 213, recovered '
        'from .rela.dyn RELATIVE addends). It '
        'operates on the per-thread park cell Q -- '
        'in registration_b, the field at [r13+0x10] '
        'of the handle object taken from the '
        "caller's argument -- using the state word "
        'at [Q+8], the guard byte at [Q+0x18] and '
        'the wait key at [Q+0x10]. It never reads '
        'or writes [Q+0], the shared-inner pointer '
        'whose byte claim gates entry.'),
    'sole_route': (
        'SETTLED. The whole-.text rel32 census '
        'finds exactly one reference to the body in '
        'the artifact: call 0x5cec9ec inside '
        'registration_b 0x5cec8b0. No tail jump '
        'targets it, no 8-byte stored pointer in '
        'the file equals its start, and no '
        '.rela.dyn RELATIVE addend names it, so no '
        'indirect route (function table, vtable, '
        'callback) reaches it either.'),
    'entry_conditions': (
        'SETTLED. Both entries share the tail at '
        '0x5cec9e7, which hardwires esi = 0 and '
        'edx = r15d (the nanos word) with '
        'rdi = Q unchanged since 0x5cec934. '
        'Sentinel arm: nanos == 0x3b9aca00 (cmp pin '
        '0x5cec938), the state-word consume CAS '
        '3 -> 0 at 0x5cec948 failed, and the byte '
        'claim on the shared inner at [S+0x50] '
        '(S = [Q+0]) at 0x5cec95e failed; the '
        'sentinel is reloaded into r15d at '
        '0x5cec964 on this arm, so the call passes '
        '(0, sentinel). Finite arm: nanos != '
        'sentinel, the byte claim at 0x5cec9c8 '
        'failed, and nanos != 0 -- the test at '
        '0x5cec9e2 with the je at 0x5cec9e5 skips '
        'the call for a zero nanos. In both arms '
        'the byte is held by a sibling '
        'registration_b execution on the same '
        'shared inner, and the holder keeps it '
        'across its entire selector park (claims '
        'at 0x5cec95e / 0x5cec9c8; release by the '
        'xchg at 0x5ceca09 after the selector call '
        'returns), so contention lasts for a whole '
        'park, not a spin window.'),
    'supply': (
        'SETTLED. registration_b is called only '
        'from top_reg_b 0x5cecc60, whose three '
        'call sites supply edx in {0, sentinel} '
        'only: xor-zeroed at 0x5cece57 and '
        '0x5ced565, the sentinel constant loaded '
        'at 0x5ced788 (the provenance packet '
        "records the same census). A zero nanos "
        'takes the finite arm of registration_b, '
        'whose fallback call is gated off, so in '
        'this artifact the fallback is entered '
        'only with (secs = 0, nanos = sentinel) '
        'and only its indefinite-park arm can '
        'execute. Its finite-duration arm -- '
        'deadline = clock 0x5c842e0 now plus the '
        'pair, with the std checked-add overflow '
        'panic (std/src/time.rs line 429), the '
        'remaining recomputed through instant_sub '
        '0x5c84210 at 0x5ce3213, and the timed '
        'wait at 0x5ce3286 -- is structurally '
        'present but no caller in the pinned graph '
        'supplies it a finite nonzero duration.'),
    'inside': (
        'SETTLED, for the reachable arm. The body '
        'first claims the cell\'s own guard byte '
        '[Q+0x18] (0 -> 1 CAS at 0x5ce30ee); if '
        'the byte is already set it waits through '
        'GOT slot 0x64e01f8 (byte_wait 0x5bb59d0) '
        'with (byte pointer, 0x3b9aca00) and '
        'continues to the state word regardless. '
        'It then CASes the state word [Q+8] '
        '0 -> 1 (0x5ce3100): an old value of 3 is '
        'a raced notification, consumed by the '
        'xchg to 0 at 0x5ce3312 with an immediate '
        'return; an old value other than 0 or 3 '
        'panics "inconsistent park state; actual '
        '= {}" (park.rs line 179, Location static '
        '0x64c5a20). Otherwise it waits in the '
        'loop at 0x5ce31b5: the wait helper is '
        'loaded from GOT slot 0x64e73b8 '
        '(wait_helper 0x5bb4670) and called with '
        '(Q+0x10, Q+0x18, sentinel) until the '
        'state CAS 3 -> 0 at 0x5ce31d3 succeeds. '
        'The exit at 0x5ce3316 releases the guard '
        'byte (1 -> 0 CAS at 0x5ce331a); if that '
        'CAS fails, the exit tail-calls the '
        'notify helper through GOT slot 0x64e0f38 '
        '(byte_notify 0x5bb5650) with (byte '
        'pointer, 0). The wait/notify call shapes '
        '(pointer + timeout / pointer + 0) are the '
        'same guard idiom the RE-001 queue-table '
        'packets pinned. The body is the only '
        'writer of state value 1 in this graph.'),
    'difference': (
        'SETTLED. The claim-success arms park '
        'through the shared inner: the state word '
        'is driven 0 -> 2 (wrapper_state at '
        '0x5cec9d9 on the finite arm, '
        "registration_b's own CAS at 0x5cec973 on "
        'the sentinel arm) and the thread sleeps '
        'in the io/time selectors. The fallback '
        'touches no shared state: the loser parks '
        'its own thread on its own cell through '
        'the scheduler wait table, cycling the '
        'state word 0 -> 1 -> 0 instead of '
        '0 -> 2 -> 0, and neither claims nor '
        'releases the holder\'s byte. '
        'registration_b discards the fallback\'s '
        'return value (the jump at 0x5cec9f1 goes '
        'straight to the shared continuation at '
        '0x5ceca0d) and stores the same pre-claim '
        'flag -- bpl is 1 on both fallback arms -- '
        'into the returned object at +0x74 (pin '
        '0x5cecac1), so the only observable trace '
        'of the fallback in the returned object '
        'is the intermediate state value.'),
    'panic_surface': (
        'SETTLED. Four panics are encoded in the '
        'body: park.rs line 179 "inconsistent park '
        'state; actual = {}", line 211 '
        '"inconsistent park_timeout state, actual '
        '= {}", line 213 "invalid park_timeout '
        'state, actual = {}", and the std '
        '"overflow when adding duration to '
        'instant" (std/src/time.rs line 429). On '
        'the reachable arm only the line 179 '
        'check sits on the path, and the pinned '
        'writer graph produces only 0, or a raced '
        '3, for this cell at that point: firing '
        'it needs a state the graph\'s writers do '
        'not produce, i.e. it is the source-level '
        'consistency assertion. The line 211/213 '
        'panics guard the finite arm\'s exit '
        'switch (jump table at 0x94cb10: old '
        'state 0 -> line 211 panic block '
        '0x5ce32ca, 1 -> exit 0x5ce3316, 2 -> '
        'line 211 panic block, 3 -> exit; an old '
        'state above 3 goes to the line 213 panic '
        'at 0x5ce339d) and are unreachable from '
        'the pinned caller graph, as is the '
        'overflow panic.'),
}

OPEN_EDGES = [
    'Who writes state value 3 to a cell (the '
    'notify/unpark side), and through which entry '
    'points a wake targets a specific cell, is not '
    'traced here; the fallback only consumes 3.',
    'The internals of the wait helper 0x5bb4670 '
    'and of the guard wait/notify helpers '
    '0x5bb59d0 / 0x5bb5650 are RE-001 territory; '
    'this packet pins only their GOT slots, '
    'extents, digests and the call shapes the '
    'fallback uses.',
    'Whether any body outside the exported/pinned '
    'set also claims the byte at [S+0x50] on the '
    'shared inner is not censused here; within '
    'the caller graph above registration_b the '
    'only claim and release sites are '
    'registration_b\'s own.',
    'Open edges 1, 2 and 4 of the TLS '
    'value-object packet, and the forwarder '
    'time-context writers edge of the provenance '
    'packet, remain open.',
]


def read(data, va, size):
    for section in sections(data):
        start = section['address']
        if start <= va < start + section['size']:
            off = section['offset'] + va - start
            return data[off:off + size]
    raise KeyError(hex(va))


def fde_extents():
    text = subprocess.run(
        ['readelf', '-wf', str(TARGET)], check=True,
        capture_output=True, text=True).stdout
    extents = []
    for line in text.splitlines():
        if 'pc=' not in line:
            continue
        needle = line.split('pc=')[1].split()[0]
        lo, hi = needle.split('..')
        if int(lo, 16):
            extents.append((int(lo, 16), int(hi, 16)))
    return extents


def body_record(data, extents, extent, expect):
    start, end = extent
    if (start, end) not in extents:
        raise AssertionError(
            f'no FDE extent for {start:#x}..{end:#x}')
    digest = hashlib.sha256(read(data, start, end - start)
                            ).hexdigest()
    if digest != expect:
        raise AssertionError(f'body digest drift at {start:#x}')
    return {'start': hex(start), 'end': hex(end),
            'bytes': end - start, 'sha256': digest}


def disasm_rows(data, start, end):
    text = subprocess.run(
        ['objdump', '-d', '--start-address', hex(start),
         '--stop-address', hex(end), str(TARGET)], check=True,
        capture_output=True, text=True).stdout
    rows = {}
    pattern = re.compile(
        r'^\s+([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t(.*)$')
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            va = int(match.group(1), 16)
            raw = bytes.fromhex(match.group(2))
            rows[va] = (raw, match.group(3).strip())
    return rows


def _verified_sites(data, extents, sites, kind_mask):
    """Re-derive each candidate site's containing body and
    confirm, from that body's own disassembly, that the
    site is exactly one instruction there (call/jump kind
    per kind_mask bit 0 = call, bit 1 = jmp)."""
    owners = {}
    for start, end in extents:
        for va in sites:
            if start <= va < end:
                owners.setdefault(va, (start, end))
    cache = {}
    out = set()
    for va in sites:
        extent = owners.get(va)
        if extent is None:
            continue
        if extent not in cache:
            cache[extent] = disasm_rows(data, *extent)
        row = cache[extent].get(va)
        if row is None:
            continue
        raw, text = row
        if raw[0] == 0xE8 and kind_mask & 1 and \
                text.startswith('call'):
            out.add(va)
        elif raw[0] == 0xE9 and kind_mask & 2 and \
                text.startswith('jmp'):
            out.add(va)
    return out


# rel32 census spans.  A raw scan of the whole .text is
# necessary because an incomplete candidate list would
# understate the graph; the boundary verification is
# what keeps the inflated raw hits honest.
def rel32_census(data, extents, target):
    found = {'call': set(), 'jmp': set()}
    for section in sections(data):
        if section['name'] != '.text':
            continue
        base = section['address']
        blob = data[section['offset']:section['offset']
                    + section['size']]
        for kind, opcode in (('call', 0xE8), ('jmp', 0xE9)):
            pos = 0
            while True:
                idx = blob.find(bytes([opcode]), pos)
                if idx < 0:
                    break
                pos = idx + 1
                if idx + 5 > len(blob):
                    continue
                disp = struct.unpack_from('<i', blob, idx + 1)[0]
                if base + idx + 5 + disp == target:
                    found[kind].add(base + idx)
    calls = _verified_sites(data, extents, found['call'], 1)
    jmps = _verified_sites(data, extents, found['jmp'], 2)
    return {'calls': [hex(v) for v in sorted(calls)],
            'jmps': [hex(v) for v in sorted(jmps)]}


def parse_rela(data):
    secs = {s['name']: s for s in sections(data)}
    entries = []
    for name in ('.rela.dyn', '.rela.plt'):
        sec = secs.get(name)
        if not sec:
            continue
        for off in range(sec['offset'], sec['offset']
                         + sec['size'], 24):
            r_off, r_info, r_add = struct.unpack_from(
                '<QQq', data, off)
            entries.append((r_off, r_info & 0xFFFFFFFF, r_add))
    return entries


def chain_rela_hits(data):
    starts = {start for start, _ in ALL_BODIES.values()}
    hits = []
    for off, typ, add in parse_rela(data):
        if typ == 8 and add in starts:
            hits.append({'offset': hex(off),
                         'addend': hex(add)})
    return sorted(hits, key=lambda h: int(h['offset'], 16))


def raw_pointer_hits(data, va):
    needle = struct.pack('<Q', va)
    out = []
    pos = 0
    while True:
        idx = data.find(needle, pos)
        if idx < 0:
            break
        out.append(idx)
        pos = idx + 1
    return out


def jump_table(data):
    out = []
    for i in range(4):
        rel = struct.unpack_from(
            '<i', read(data, JUMP_TABLE_BASE + 4 * i, 4))[0]
        out.append(hex(JUMP_TABLE_BASE + rel))
    if out != JUMP_TABLE_EXPECT:
        raise AssertionError(f'jump table drift: {out}')
    return {'base': hex(JUMP_TABLE_BASE), 'targets': out}


def location_record(data, static_va, path_addend, flen,
                    line, col):
    addends = [off for off, typ, add in parse_rela(data)
               if add == path_addend and typ == 8]
    if not addends:
        raise AssertionError('path addend missing')
    path = read(data, path_addend, flen).decode()
    raw = read(data, static_va, 24)
    fields = struct.unpack_from('<QII', raw, 8)
    if fields != (flen, line, col):
        raise AssertionError(
            f'Location drift at {static_va:#x}: {fields}')
    return {'location_static': hex(static_va), 'file': path,
            'file_len_via_rela_addend': flen, 'line': line,
            'col': col,
            'path_rela_offsets': [hex(o) for o in addends]}


def message_record(data, text_va, expect):
    blob = read(data, text_va, len(expect)).decode()
    if blob != expect:
        raise AssertionError(f'message drift at {text_va:#x}')
    return {'text_va': hex(text_va), 'len': len(expect),
            'text': expect}


def analyze(data):
    if len(data) != TARGET_SIZE:
        raise AssertionError('artifact size drift')
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise AssertionError('artifact sha256 drift')
    extents = fde_extents()
    owners = {role: body_record(data, extents, extent,
                                BODY_SHA256[role])
              for role, extent in OWNERS.items()}
    pinned = {role: body_record(data, extents, extent,
                                BODY_SHA256[role])
              for role, extent in PINNED_BODIES.items()}
    census = {}
    for role, target in CENSUS_EXPECT.items():
        got = rel32_census(data, extents,
                           ALL_BODIES[role][0])
        if got != target:
            raise AssertionError(
                f'census drift for {role}: {got}')
        census[role] = got
    locations = {role: location_record(data, *spec)
                 for role, spec in LOCATIONS.items()}
    messages = {role: message_record(data, *spec)
                for role, spec in MESSAGES.items()}
    hits = chain_rela_hits(data)
    if hits != EXPECTED_RELA_HITS:
        raise AssertionError(
            f'pointer census drift: {hits}')
    raw = raw_pointer_hits(data,
                           OWNERS['contention_fallback'][0])
    if raw:
        raise AssertionError(
            f'raw pointer hits for fallback: {raw}')
    table = jump_table(data)
    for va, expect_hex in PINS.items():
        rawb = read(data, va, len(bytes.fromhex(expect_hex)))
        if rawb.hex() != expect_hex:
            raise AssertionError(f'pin drift at {va:#x}')
    return {
        'artifact': {'snapshot': SNAPSHOT, 'size': len(data),
                     'sha256': TARGET_SHA256},
        'work_item': WORK_ITEM,
        'owners': owners,
        'pinned_bodies': pinned,
        'call_census': census,
        'rela_refs': {
            'chain_bodies': [hex(s) for s in sorted(
                start for start, _ in ALL_BODIES.values())],
            'relative_addend_hits': hits,
            'fallback_raw_pointer_hits': [],
        },
        'exit_switch': table,
        'locations': locations,
        'messages': messages,
        'pins': {hex(va): expect for va, expect in
                 sorted(PINS.items())},
        'findings': FINDINGS,
        'open_edges': OPEN_EDGES,
    }


def exports(data, start, end):
    return subprocess.run(
        ['objdump', '-d', '-M', 'intel',
         '--start-address', hex(start),
         '--stop-address', hex(end), str(TARGET)],
        check=True, capture_output=True, text=True).stdout


def frame_lines(spans):
    text = subprocess.run(
        ['readelf', '-wf', str(TARGET)], check=True,
        capture_output=True, text=True).stdout
    lines = []
    for line in text.splitlines():
        if 'pc=' not in line:
            continue
        needle = line.split('pc=')[1].split()[0]
        lo, hi = needle.split('..')
        if (int(lo, 16), int(hi, 16)) in spans:
            lines.append(line)
    return lines


def generate():
    data = TARGET.read_bytes()
    records = analyze(data)
    OUT.mkdir(parents=True, exist_ok=True)
    for role in EXPORTED:
        (OUT / f'{role}.objdump.txt').write_text(
            exports(data, *OWNERS[role]))
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=2) + '\n')
    spans = set(ALL_BODIES.values())
    (OUT / 'frames.txt').write_text(
        '\n'.join(frame_lines(spans)) + '\n')
    names = sorted(p.name for p in OUT.iterdir()
                   if p.name != 'MANIFEST.sha256')
    lines = []
    for name in names:
        digest = hashlib.sha256(
            (OUT / name).read_bytes()).hexdigest()
        lines.append(f'{digest}  {name}')
    (OUT / 'MANIFEST.sha256').write_text(
        '\n'.join(lines) + '\n')
    return records


def main():
    if '--generate' in sys.argv:
        generate()
        print('generated', OUT)
        return
    data = TARGET.read_bytes()
    records = analyze(data)
    on_disk = json.loads((OUT / 'records.json').read_text())
    print(json.dumps({'matches': records == on_disk},
                     indent=2))


if __name__ == '__main__':
    main()
