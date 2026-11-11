"""Static evidence for the RE-005 park unpark-writer
packet.

Answers the open edge the RE-005 park contention
fallback packet (PR #2941) left open -- "Who writes
state value 3 to a cell (the notify/unpark side), and
through which entry points a wake targets a specific
cell; the fallback only consumes 3" -- for the
authenticated hl-node 115 artifact only.

SETTLED.  The writer is the body 0x5ce3580..0x5ce3662,
the unpark half of the same vendored tokio
multi-thread scheduler park module whose park core
the fallback packet settled: its one panic carries
the Location static 0x64c5a38 in
.../z_vendor/tokio/src/runtime/scheduler/
multi_thread/park.rs line 288, with the message piece
"inconsistent state in unpark; actual = ".  It takes
the handle pointer its callers pass (the same handle
object registration_b takes, whose field at +0x10 is
the park cell Q of the earlier packets) and swaps 3
into the state word at [handle+0x18] (= [Q+8]) with a
single xchg (mov eax,3 pin at 0x5ce3585, xchg pin at
0x5ce358a).  A whole-.text scan for that exact store
pattern -- an immediate 3 loaded for an xchg into a
+0x18 word -- finds this one site in the whole
artifact, and the module census below shows every
body that references a multi_thread/park.rs panic
Location: wrapper_state, the contention fallback,
registration_b and this unpark body; the first three
only consume 3 (CAS 3 -> 0, pinned by the earlier
packets) and never store it.

What the swap does with the old value (jump table at
0x94cb20, four entries):

- old 0: nobody is parked on this cell; the 3 stays
  latched as a pending notification and the body
  returns.  The next park on the cell consumes it
  (the CAS 3 -> 0 sites the earlier packets pinned).
- old 1: the thread is parked in the contention
  fallback's own wait loop.  The body claims the
  cell's guard byte at [handle+0x28] (= [Q+0x18],
  CAS 0 -> 1 at 0x5ce35a8; on contention it waits on
  the byte through GOT slot 0x64e01f8, byte_wait
  0x5bb59d0, with the 0x3b9aca00 sentinel), releases
  it (CAS 1 -> 0 at 0x5ce35b3; on failure it calls
  the notify helper through GOT slot 0x64e0f38,
  byte_notify 0x5bb5650, with 0), then reads the
  wait key word at [handle+0x20] (= [Q+0x10]): if it
  is non-zero it tail-jumps through GOT slot
  0x64ec188 to the wake body 0x5bb42e0 with
  (&key, token snapshot); if zero it returns.
- old 2: the thread is parked through the io/time
  selectors on the shared inner (the claim-success
  arms of registration_b drive the state 0 -> 2).
  The body tail-jumps at 0x5ce35d5 to the driver
  signal body 0x5ce09a0..0x5ce0aa2 with rdi = its own
  second argument -- the pointer its callers form as
  ctx+0x150 (ctx+0x160 in the broadcast caller),
  i.e. the slot that holds the shared inner.  That
  body is an inline copy of the runtime-park unpark
  on the inner: it dereferences the slot, swaps 2
  into the inner parker's state word at [inner+0x10]
  (pins at 0x5ce09c2/0x5ce09c7), and on old 1 claims
  the inner byte at [inner+0x20], snapshots the
  token at [inner+0x18] and tail-jumps to the same
  wake body through the same GOT slot; its panic is
  the runtime/park.rs line 187 Location (static
  0x64c6f60) the TLS value-object packet pinned for
  the out-of-line unpark 0x5cfd600, whose protocol
  this is a copy of.
- old > 3: the line-288 panic, with the old value
  as the {} argument.  No writer in the pinned
  graph produces a value above 3, so this is the
  module's consistency assertion, not an expected
  outcome.

Entry points -- through which a wake targets a
specific cell.  The whole-.text rel32 census finds
exactly six references to the unpark body, all
direct, in six bodies; no .rela.dyn RELATIVE addend
names it and its start address occurs nowhere in
the file as a stored pointer, so no indirect route
exists.  Five of the callers share one idiom over a
scheduler context: claim the context guard byte at
[ctx+0xf8] (the fallback packet's caller graph uses
the same claim/release discipline), bounds-check an
index against the table length at [ctx+0x90], load
the per-worker handle from the 16-byte entry at
[ctx+0x88] + index*16 + 8, and pass
(second = ctx+0x150):

- signal_arg 0x5ce3fd0 (tail jump at 0x5ce4235):
  the index arrives in a register (bounds check
  against [ctx+0x90] after loading the table base
  [ctx+0x88]); argument-setup pins at
  0x5ce4218/0x5ce421f/0x5ce4224.
- signal_pop_call 0x5ce4430 (call at 0x5ce450e),
  signal_pop_jmp_a 0x5ce45b0 (tail jump at
  0x5ce468f), signal_pop_jmp_b 0x5ce4720 (tail jump
  at 0x5ce48cb), signal_pop_call_b 0x5ce4990 (call
  at 0x5ce4a88): the index is popped from the
  context's own stack -- length word at [ctx+0x110]
  decremented and stored back (pin 0x5ce44b1 in
  signal_pop_call), top element loaded from the
  buffer at [ctx+0x108] -- then the same claim,
  bounds check and handle load (setup pins at each
  site in records.json).
- signal_all 0x5cfadf0 (call at 0x5cfaec8, inside
  its loop): iterates every entry of its own table
  ([ctx+0x98] base, [ctx+0xa0] count, 16-byte
  stride, handle at +8) and unparks each one,
  passing second = ctx+0x160 -- the same ctx fields
  read through a +0x10 outer offset; setup pins at
  0x5cfaea7/0x5cfaec0/0x5cfaec5.

So a wake targets exactly one cell because the
caller resolves the worker's handle out of the
scheduler context's table first; the unpark body
itself is cell-agnostic.  The four pop variants are
extent- and digest-pinned separately; what differs
between them beyond index source and call-vs-jump
is not claimed here.

Method: two bodies are exported in full (the unpark
body and the driver signal body it tail-jumps to);
every other body is extent/digest pinned.  Censuses:
whole-.text rel32 call/jump scan for the unpark
body, every hit boundary-verified against its
containing FDE body's own disassembly; a lea census
for all six multi_thread/park.rs Location statics
with the same boundary verification; the xchg
store-pattern scan; the .rela.dyn RELATIVE addend
census and a raw whole-file pointer scan for the
unpark body start; the old-value jump table;
instruction byte pins at every load-bearing site.
Section mapping via the section table
(tools/elf_index).  Analysis is static only; the
artifact was not executed.
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
WORK_ITEM = 'RE-005-node115-park-unpark-writer'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'
SENTINEL = 0x3B9ACA00

OWNERS = {
    'unpark': (0x5CE3580, 0x5CE3662),
    'inner_unpark': (0x5CE09A0, 0x5CE0AA2),
}
EXPORTED = list(OWNERS)

PINNED_BODIES = {
    'contention_fallback': (0x5CE30D0, 0x5CE3426),
    'registration_b': (0x5CEC8B0, 0x5CECC58),
    'wrapper_state': (0x5CE2FD0, 0x5CE30C7),
    'handle_clone': (0x5CE3430, 0x5CE3578),
    'signal_arg': (0x5CE3FD0, 0x5CE42EC),
    'signal_pop_call': (0x5CE4430, 0x5CE45A9),
    'signal_pop_jmp_a': (0x5CE45B0, 0x5CE4720),
    'signal_pop_jmp_b': (0x5CE4720, 0x5CE498E),
    'signal_pop_call_b': (0x5CE4990, 0x5CE4B29),
    'signal_all': (0x5CFADF0, 0x5CFAEFF),
    'wait_helper': (0x5BB4670, 0x5BB4CFD),
    'wake_fn': (0x5BB42E0, 0x5BB4663),
    'byte_wait': (0x5BB59D0, 0x5BB606D),
    'byte_notify': (0x5BB5650, 0x5BB59C5),
}

BODY_SHA256 = {
    'unpark': '082ffba5ae38f1b412e4f1141a0162dd'
              '4ed49ff4e3c7e9029d7917e031f8f70c',
    'inner_unpark': 'c7efc9b1071af6d1e1a162ccdff36175'
                    'ffd1fe4a7dbfaa9628965f187d18b8e7',
    'contention_fallback': '1727765a7756690cfec9d1c24f087b05'
                           '362624a8154f7e40b5bc94ffe491f16f',
    'registration_b': 'e732e6851f0a42f5bbf4bcb63d5a44f8'
                      'e1a030d7428404c514f5af8f92103a77',
    'wrapper_state': '17d62a55fe9d639eee5e5d26f3694a09'
                     '0f7f07e629ca729d11bc66c31d3e0e37',
    'handle_clone': 'bfecd5e7ee8fe556954566e81d0a6d31388'
                    'b894ab1f86d5cd541f517ed3a3d90',
    'signal_arg': '7640e42c16234487d138b63218d37dbcf891'
                  '4aee3c6f35df63ff1addb826636e',
    'signal_pop_call': '5a41850c12e307f6a0d16dd278a60f17'
                       'e428c987861e7a98ff380faaf74d169c',
    'signal_pop_jmp_a': 'f019580d81830c0f3876c07ce7bdbe41'
                        '810262402979ee036503728eb2ac4295',
    'signal_pop_jmp_b': '5a97150d0b7f4485158125fda3e56043d2'
                        'e09c4c43a91cc88d6b79d0fe4cd88b',
    'signal_pop_call_b': '583b72ac967b94a05f00ce8506794e18b1'
                         'c0b53cd852aa6d450a992c42a89310',
    'signal_all': '5a1ee3a5f3c77c0ea6dc2680d063d02e9a45'
                  'b9710557587630bcb3c45c056f6f',
    'wait_helper': '65c70b3e926bbf20a45563b947502e17'
                   'd87ead04556451512587b556e9f57f1d',
    'wake_fn': '15a928dcf95723b20a24cf6f2e8fed1611'
               '8e2f4b0f3fbbe869dc6c6502d82c02',
    'byte_wait': '1ba3a96e8d451e9299eb16b37f016d4c'
                 '4f050d0ddad46f5f7b3d3e8ce2dc3e76',
    'byte_notify': '4eda0eff3310a0ba59b0a0fa1f208cf4'
                   '8e2ec5499b3ad5e48c99b8b93df628de',
}
ALL_BODIES = dict(OWNERS)
ALL_BODIES.update(PINNED_BODIES)

# Instruction byte pins at every load-bearing site.
PINS = {
    # unpark entry: the swap of 3 into the state word
    # at [handle+0x18], and the old-value bound check.
    0x5CE3585: 'b803000000', 0x5CE358A: '48874718',
    0x5CE358E: '4883f803',
    # old == 1 arm: guard byte claim and release at
    # [handle+0x28], wait-key load at [handle+0x20],
    # byte wait on contention, byte notify after a
    # failed release, wake tail jump.
    0x5CE35A8: 'f00fb04f28', 0x5CE35B3: 'f00fb04f28',
    0x5CE35BA: '488b7720',
    0x5CE361D: 'ff15d5cb7f00', 0x5CE363D: 'ff15f5d87f00',
    0x5CE365C: 'ff25268b8000',
    # old == 2 arm: second argument forwarded, tail
    # jump to the driver signal body.
    0x5CE35CD: '4889f7', 0x5CE35D5: 'e9c6d3ffff',
    # the line-288 panic: Location lea.
    0x5CE35FC: '488d1535247e00',
    # inner_unpark: swap of 2 into [inner+0x10], the
    # byte claim at [inner+0x20], the token load at
    # [inner+0x18], the wake tail jump.
    0x5CE09C2: 'b802000000', 0x5CE09C7: '48874310',
    0x5CE09F9: 'f00fb04b20', 0x5CE0A0B: '488b7318',
    0x5CE0A20: 'ff2562b78000',
    # signal_arg setup: ctx += 0x150, handle load,
    # second-argument move.
    0x5CE4218: '4881c350010000', 0x5CE421F: '4a8b7c3008',
    0x5CE4224: '4889de',
    # signal_pop_call: stack length store-back, top
    # load, then the shared setup.
    0x5CE44B1: '48898710010000', 0x5CE44BF: '4a8b5cf0f8',
    0x5CE4503: '488b441808', 0x5CE4508: '4889fe',
    0x5CE450B: '4889c7',
    # signal_pop_jmp_a / _b / signal_pop_call_b:
    # the same handle load and argument moves.
    0x5CE467F: '488b441808', 0x5CE4684: '4889fe',
    0x5CE4687: '4889c7',
    0x5CE48BB: '488b441808', 0x5CE48C0: '4889fe',
    0x5CE48C3: '4889c7',
    0x5CE4A7D: '488b441808', 0x5CE4A82: '4889fe',
    0x5CE4A85: '4889c7',
    # signal_all setup: ctx += 0x160, entry handle
    # load inside the loop, second-argument move.
    0x5CFAEA7: '4881c360010000', 0x5CFAEC0: '4b8b7c2708',
    0x5CFAEC5: '4889de',
}

CENSUS_EXPECT = {
    'calls': ['0x5ce450e', '0x5ce4a88', '0x5cfaec8'],
    'jmps': ['0x5ce4235', '0x5ce468f', '0x5ce48cb'],
}

# All six panic Location statics of the vendored
# multi_thread park.rs, with the lea sites that
# reference each (boundary-verified in analyze()).
PARK_RS_PATH = ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
                'src/runtime/scheduler/multi_thread/park.rs')
PARK_RS_LEN = 86
LOCATIONS = {
    'line271': (0x64C59C0, 271, 18, ['0x5ce3081', '0x5cec9ad']),
    'line258': (0x64C59D8, 258, 28, ['0x5ce30b5', '0x5cecb6c']),
    'line211': (0x64C59F0, 211, 25, ['0x5ce32d9']),
    'line213': (0x64C5A08, 213, 32, ['0x5ce33ac']),
    'line179': (0x64C5A20, 179, 28, ['0x5ce3357']),
    'line288': (0x64C5A38, 288, 23, ['0x5ce35fc']),
}

MESSAGES = {
    'unpark_inconsistent': (
        0x43B35A, 'inconsistent state in unpark; actual = '),
}

JUMP_TABLE_BASE = 0x94CB20
JUMP_TABLE_EXPECT = ['0x5ce35c7', '0x5ce35a4',
                     '0x5ce35cd', '0x5ce35c7']

XCHG3_EXPECT = ['0x5ce358a']

FINDINGS = {
    'writer': (
        'SETTLED. State value 3 is written by exactly '
        'one body: the unpark body 0x5ce3580..0x5ce3662 '
        'of the vendored tokio multi-thread scheduler '
        'park module. Its entry loads 3 (pin 0x5ce3585) '
        'and xchgs it into the state word at '
        '[handle+0x18] (pin 0x5ce358a) -- the word the '
        'contention fallback packet fixed as [Q+8] of '
        'the per-thread park cell, reached here through '
        'the handle object whose +0x10 field is Q. The '
        'body\'s one panic carries the multi_thread/'
        'park.rs line 288 Location (static 0x64c5a38) '
        'and the message piece "inconsistent state in '
        'unpark; actual = ". The whole-.text scan for '
        'the store pattern (immediate 3 loaded for an '
        'xchg into a +0x18 word) finds this site alone, '
        'and the module Location census names every '
        'body of the module -- wrapper_state '
        '0x5ce2fd0, the contention fallback 0x5ce30d0, '
        'registration_b 0x5cec8b0 and this unpark -- of '
        'which the first three only consume 3 with the '
        'CAS 3 -> 0 sites the earlier packets pinned.'),
    'old_value_arms': (
        'SETTLED. The swap\'s old value is switched '
        'through the jump table at 0x94cb20: 0 -> '
        '0x5ce35c7 (return; the 3 stays latched as a '
        'pending notification), 1 -> 0x5ce35a4 (claim '
        'the guard byte at [handle+0x28] = [Q+0x18] '
        'with CAS 0 -> 1, pin 0x5ce35a8, waiting on it '
        'through GOT 0x64e01f8 / byte_wait 0x5bb59d0 '
        'with the sentinel on contention; release with '
        'CAS 1 -> 0, pin 0x5ce35b3, calling byte_notify '
        'through GOT 0x64e0f38 when the release fails; '
        'then if the wait-key word at [handle+0x20] = '
        '[Q+0x10] is non-zero, tail-jump through GOT '
        '0x64ec188 to the wake body 0x5bb42e0 with '
        '(&key, token)), 2 -> 0x5ce35cd (forward the '
        'second argument and tail-jump to the driver '
        'signal body 0x5ce09a0), 3 -> 0x5ce35c7 '
        '(already notified; return). An old value '
        'above 3 takes the line-288 panic at '
        '0x5ce35da with the old value as the {} '
        'argument; no writer in the pinned graph '
        'produces a value above 3.'),
    'inner_arm': (
        'SETTLED. The driver signal body '
        '0x5ce09a0..0x5ce0aa2 is an inline copy of the '
        'runtime-park unpark protocol on the shared '
        'inner, reached only from the unpark body\'s '
        'old == 2 arm with rdi = the caller-supplied '
        'slot pointer (ctx+0x150, or ctx+0x160 in the '
        'broadcast caller). It dereferences the slot '
        'and swaps 2 into the inner parker state word '
        'at [inner+0x10] (pins 0x5ce09c2/0x5ce09c7): '
        'old 0 or 2 returns, old 1 claims the inner '
        'byte at [inner+0x20] (pin 0x5ce09f9), snapshots '
        'the token at [inner+0x18] (pin 0x5ce0a0b) and '
        'tail-jumps through GOT 0x64ec188 to the wake '
        'body (pin 0x5ce0a20), and any other old value '
        'panics through the runtime/park.rs line 187 '
        'Location (static 0x64c6f60) the TLS '
        'value-object packet pinned for the out-of-line '
        'unpark 0x5cfd600 -- the same protocol, inlined '
        'at the driver\'s call site.'),
    'entry_points': (
        'SETTLED. Exactly six direct references, no '
        'indirect route: no .rela.dyn RELATIVE addend '
        'names the body and its start occurs nowhere '
        'in the file as a stored pointer. Five callers '
        'resolve the target cell out of a scheduler '
        'context first -- claim the byte at [ctx+0xf8], '
        'bounds-check the index against [ctx+0x90], '
        'load the handle from the 16-byte table at '
        '[ctx+0x88] (entry +8), pass ctx+0x150 as the '
        'second argument: signal_arg 0x5ce3fd0 (tail '
        'jump 0x5ce4235, index from a register), '
        'signal_pop_call 0x5ce4430 (call 0x5ce450e), '
        'signal_pop_jmp_a 0x5ce45b0 (tail jump '
        '0x5ce468f), signal_pop_jmp_b 0x5ce4720 (tail '
        'jump 0x5ce48cb) and signal_pop_call_b '
        '0x5ce4990 (call 0x5ce4a88) -- the four pop '
        'variants take the index from the top of the '
        'context stack at [ctx+0x108]/[ctx+0x110]. The '
        'sixth, signal_all 0x5cfadf0 (call 0x5cfaec8 '
        'in its loop), unparks every entry of its own '
        'table ([ctx+0x98]/[ctx+0xa0], second argument '
        'ctx+0x160). A wake therefore targets exactly '
        'the cell whose handle the caller resolved; '
        'the unpark body itself is cell-agnostic.'),
    'handle_neighbour': (
        'CONTEXT. The body immediately above the '
        'unpark, handle_clone 0x5ce3430..0x5ce3578, '
        'builds a fresh handle-sized allocation pair '
        '(0x58-byte block copied from its argument, '
        '0x30-byte block holding the two 1-valued '
        'header words and the block pointer) through '
        'the allocator slot 0x64df480; it is pinned '
        'here as the unpark body\'s extent neighbour '
        'and the handle factory of the same cluster, '
        'and no claim about its callers is made.'),
}

OPEN_EDGES = [
    'What distinguishes the four pop-variant '
    'signal bodies (0x5ce4430, 0x5ce45b0, 0x5ce4720, '
    '0x5ce4990) from each other beyond index source '
    'and call-vs-tail-jump -- e.g. which scheduler '
    'event each one serves -- is not traced here.',
    'The writers of the scheduler context fields '
    'the signal bodies read (the worker table at '
    'ctx+0x88/+0x90, the index stack at '
    'ctx+0x108/+0x110, the guard byte at ctx+0xf8, '
    'the inner slot at ctx+0x150) are not censused '
    'here; the forwarder time-context writers edge '
    'of the park_timeout provenance packet is the '
    'same shape of question for the time context.',
    'Open edges 1 and 4 of the TLS value-object '
    'packet (the parking layer bit protocol and the '
    'missing type name) and the [S+0x50] byte-claim '
    'census edge of the contention fallback packet '
    'remain open.',
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


_LEA_MAP = None


def _lea_map(data):
    """One pass over .text: target VA -> set of
    rip-relative lea site VAs."""
    global _LEA_MAP
    if _LEA_MAP is not None:
        return _LEA_MAP
    out = {}
    for section in sections(data):
        if section['name'] != '.text':
            continue
        base = section['address']
        blob = data[section['offset']:section['offset']
                    + section['size']]
        pos = 0
        while True:
            idx = blob.find(b'\x8d', pos)
            if idx < 0:
                break
            pos = idx + 1
            if idx < 1 or idx + 6 > len(blob):
                continue
            if blob[idx - 1] not in (0x48, 0x4C):
                continue
            if (blob[idx + 1] & 0xC7) != 0x05:
                continue
            disp = struct.unpack_from('<i', blob, idx + 2)[0]
            site = base + idx - 1
            out.setdefault(site + 7 + disp, set()).add(site)
    _LEA_MAP = out
    return out


def lea_census(data, extents, static_va):
    """All rip-relative lea sites whose target is the
    given static, boundary-verified as lea instructions
    in their containing bodies."""
    found = set(_lea_map(data).get(static_va, set()))
    owners = {}
    for start, end in extents:
        for va in found:
            if start <= va < end:
                owners.setdefault(va, (start, end))
    cache = {}
    out = set()
    for va in found:
        extent = owners.get(va)
        if extent is None:
            continue
        if extent not in cache:
            cache[extent] = disasm_rows(data, *extent)
        row = cache[extent].get(va)
        if row is not None and row[1].startswith('lea'):
            out.add(va)
    return [hex(v) for v in sorted(out)]


def xchg3_census(data, extents):
    """Sites of the store pattern: mov eax,3 immediately
    before an xchg of rax into a +0x18 word."""
    found = set()
    for section in sections(data):
        if section['name'] != '.text':
            continue
        base = section['address']
        blob = data[section['offset']:section['offset']
                    + section['size']]
        pos = 0
        while True:
            idx = blob.find(b'\xb8\x03\x00\x00\x00', pos)
            if idx < 0:
                break
            pos = idx + 1
            if idx + 9 <= len(blob) and \
                    blob[idx + 5] in (0x48, 0x49) and \
                    blob[idx + 6] == 0x87 and \
                    (blob[idx + 7] & 0xC7) == 0x47 and \
                    blob[idx + 8] == 0x18:
                found.add(base + idx + 5)
    owners = {}
    for start, end in extents:
        for va in found:
            if start <= va < end:
                owners.setdefault(va, (start, end))
    cache = {}
    out = set()
    for va in found:
        extent = owners.get(va)
        if extent is None:
            continue
        if extent not in cache:
            cache[extent] = disasm_rows(data, *extent)
        row = cache[extent].get(va)
        if row is not None and 'xchg' in row[1]:
            out.add(va)
    return [hex(v) for v in sorted(out)]


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


def location_records(data, extents):
    entries = parse_rela(data)
    addends = sorted({off for off, typ, add in entries
                      if add == _path_va(data) and typ == 8})
    out = {}
    for role, (static_va, line, col, expect_refs) in \
            LOCATIONS.items():
        raw = read(data, static_va, 24)
        flen, ln, cl = struct.unpack_from('<QII', raw, 8)
        if (flen, ln, cl) != (PARK_RS_LEN, line, col):
            raise AssertionError(
                f'Location drift at {static_va:#x}')
        refs = lea_census(data, extents, static_va)
        if refs != expect_refs:
            raise AssertionError(
                f'lea census drift for {role}: {refs}')
        out[role] = {
            'location_static': hex(static_va),
            'file': PARK_RS_PATH,
            'file_len_via_rela_addend': PARK_RS_LEN,
            'line': line, 'col': col,
            'path_rela_offsets': [hex(o) for o in addends],
            'lea_refs': refs,
        }
    return out


def _path_va(data):
    idx = data.find(PARK_RS_PATH.encode())
    if idx < 0:
        raise AssertionError('park.rs path string missing')
    for section in sections(data):
        start = section['address']
        off = section['offset']
        if off <= idx < off + section['size']:
            return start + idx - off
    raise AssertionError('park.rs path outside sections')


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
    census = rel32_census(data, extents, OWNERS['unpark'][0])
    if census != CENSUS_EXPECT:
        raise AssertionError(f'unpark census drift: {census}')
    locations = location_records(data, extents)
    messages = {role: message_record(data, *spec)
                for role, spec in MESSAGES.items()}
    xchg3 = xchg3_census(data, extents)
    if xchg3 != XCHG3_EXPECT:
        raise AssertionError(f'xchg3 census drift: {xchg3}')
    rela_hits = [{'offset': hex(off), 'addend': hex(add)}
                 for off, typ, add in parse_rela(data)
                 if typ == 8 and add == OWNERS['unpark'][0]]
    if rela_hits:
        raise AssertionError(
            f'rela hits for unpark: {rela_hits}')
    raw = raw_pointer_hits(data, OWNERS['unpark'][0])
    if raw:
        raise AssertionError(
            f'raw pointer hits for unpark: {raw}')
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
        'call_census': {'unpark': census},
        'module_locations': locations,
        'messages': messages,
        'writer_pattern_census': {'xchg3_sites': xchg3},
        'rela_refs': {'unpark_relative_addend_hits': [],
                      'unpark_raw_pointer_hits': []},
        'old_value_switch': table,
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
