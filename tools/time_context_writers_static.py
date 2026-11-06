"""Static evidence for the RE-005 time-context
writers packet.

Answers open edge 2 of the RE-005 park_timeout
provenance packet (PR #2938) -- the same question
the park-unpark writer packet (PR #2945) left in
the same form -- for the authenticated hl-node 115
artifact only: the forwarder 0x5cfdd00 reads four
pieces of time state out of its context (the wheel
state at ctx+0x58, the stored budget at ctx+0x78,
the shutdown byte at ctx+0x80 and the base
timestamp pair at ctx+0x88/+0x90), and #2938 pinned
how it uses them without tracing who writes them.
Who writes each field, with what value, and what
is the body on the forwarder's exit path
(0x5ceaa20) that recomputes the period itself?

SETTLED.  The context is the time half of the
combined driver value built by driver_ctor
0x5ce01f0: ctx = value + 0x40, a nine-field match
under that shift (lock byte, wheel state, deadline
cache, shutdown byte, base pair), and every route
that reaches the state lands on the same shift --
the value sits at +0x180 in the current_thread
scheduler context (ctx = C + 0x1c0), at +0x120 in
the multi_thread shared object
(ctx = [[T]+0x10] + 0x160) and at +0x120/+0x200
past a timer entry's owner pointer
(ctx = owner + 0x160/+0x240).

Every field's writer is the constructor, once:
driver_ctor's fresh arm calls the clock
0x5c842e0 when the config's time flag is set and
stores the (secs, nanos) pair at value+0xc8/
+0xd0; when the flag is clear it stores the
sentinel nanos 0x3b9aca00 instead -- the
"timers disabled" encoding every consumer tests
before touching any other field.  The wheel
state (0x20 bytes at value+0x98) is built only
by wheel_ctor 0x5cf6480, whose only caller in
the artifact is driver_ctor: a fresh 6 x 0x410
levels buffer, elapsed 0, empty pending list.
The deadline cache at value+0xb8 and the
shutdown byte at value+0xc0 both start at 0.

At runtime exactly three bodies write the state
again, all under the byte lock at ctx+0x50: the
forwarder stores the resolved budget to
ctx+0x78; the unlock/process body 0x5ceaa20 on
its exit path re-resolves the wheel and stores
the next deadline to the same slot (and is the
only caller of wheel_process 0x5cf6510, which
is the only body that ever advances the wheel's
elapsed field); and shutdown_setter 0x5ce08e0
xchg's 1 into ctx+0x80 -- its only two callers
are the drop body 0x5ceb330 and the
current_thread signal body 0x5cfbfd0.  No body
in the closed method set reads the ctx+0x78
slot back: the deadline is always recomputed
from the wheel, so the slot is a write-only
cache in this artifact.

Method: seven bodies are exported in full (the
driver constructor, the wheel constructor, the
wheel resolver, the wheel process body, the
unlock body, the shutdown setter and the
forwarder); every other body is extent/digest
pinned.  Censuses: whole-.text rel32 call/jump
scans for all seven graph bodies plus the
constructor, every hit boundary-verified against
its containing FDE body's own disassembly; a
byte-pattern census of lock cmpxchg / xchg byte
operations at displacement 0x50 over the
vendored-runtime cluster, likewise verified;
.rela.dyn/.rela.plt addend census for pointer
references; instruction byte pins at every
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
WORK_ITEM = 'RE-005-node115-time-context-writers'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'
SENTINEL = 0x3B9ACA00

OWNERS = {
    'driver_ctor': (0x5CE01F0, 0x5CE084B),
    'wheel_ctor': (0x5CF6480, 0x5CF650B),
    'wheel_resolve': (0x5CF6390, 0x5CF647D),
    'wheel_process': (0x5CF6510, 0x5CF6876),
    'unlock': (0x5CEAA20, 0x5CEAD37),
    'shutdown_setter': (0x5CE08E0, 0x5CE0998),
    'forwarder': (0x5CFDD00, 0x5CFE0E9),
}
EXPORTED = list(OWNERS)

PINNED_BODIES = {
    'builder': (0x5CF9600, 0x5CFA8B1),
    'registration_a': (0x5CFB780, 0x5CFB919),
    'registration_b': (0x5CEC8B0, 0x5CECC58),
    'signal_body': (0x5CFBFD0, 0x5CFC29E),
    'drop_body': (0x5CEB330, 0x5CEB52A),
    'cancel_body': (0x5CEAFD0, 0x5CEB1A4),
    'insert_body': (0x5CEA7C0, 0x5CEAA17),
    'wheel_insert': (0x5CF6880, 0x5CF69BF),
    'levels_alloc': (0x5CE1050, 0x5CE12A0),
    'io_wake': (0x5CEF000, 0x5CEF186),
    'clock': (0x5C842E0, 0x5C843A9),
    'instant_sub': (0x5C84210, 0x5C842D6),
}

BODY_SHA256 = {
    'driver_ctor': '90919826d6842d84b3b1229420978c82d49b767f'
                '5c609650b17c3785a73e0cba',
    'wheel_ctor': 'c70344a0e9848791deee12da2191934ab49847af'
                '6f108441214b4486abd85e5c',
    'wheel_resolve': '7f576d12868e201a625c9ff780d4816c77d80f5'
                '0d55c1666485a8f5c957bd1ac',
    'wheel_process': 'b7480df660b1983837d9b7b52af3a5359c9d4b5'
                '1e6667f7f1d272eebafec7649',
    'unlock': '3e07106e25d72afaf2baf4307e7d4efefce68c56b04d'
                '2a8db9ee1ea67b38b8af',
    'shutdown_setter': '9fa7b5de24e9817753cf9f25131869c1a866d'
                '55bfda45a9ea3eeb5c1e22214ac',
    'forwarder': '2d8ea94341d17a31bd755de9d3226f6911a337d3a6'
                'c97134ed1721c6a097c647',
    'builder': '12813161d76cb5aa11039d12cbbf45d6f170b2aa53d'
                'a586df8e03b579e02d13b',
    'registration_a': '3be383ace482e644674d7916cca63e4a37988f'
                '50c0ce1478256c16df4dfb4139',
    'registration_b': 'e732e6851f0a42f5bbf4bcb63d5a44f8e1a03'
                '0d7428404c514f5af8f92103a77',
    'signal_body': '00b892b1338b7e9e86719ad234b0f62b3e7ae8490'
                'd707201dadcab3dcf2a612c',
    'drop_body': '40a140f7bfbdb9681add88cc8beb66765c6ca3d84'
                '820569d584c6a0a737f4ab2',
    'cancel_body': '5b1addcef08123e292e9e2110d74cdf9516ac71'
                '3d91a19fb6a988b9bee7c52a3',
    'insert_body': '5fbfddaf7831cf129e1dc6734e16b7aa37d5e51b'
                '3355c96a8da582d905f4d8e2',
    'wheel_insert': '9b9b96ad18568130435d9442cbc897deef1bd53'
                '1a6b2bab71e050997e87ef6ef',
    'levels_alloc': '0db11315cc19dc1fe327fcd785013bb8608b31b'
                '474125f8bc85119868f5557c1',
    'io_wake': '70ac193745162ac20876fb1e756a5d0d2c4f1d5af3'
                'df2de3763f9585f3fe48b9',
    'clock': '3efe331bdc612bff27ad3c487fbff92d57a2e097'
                '820c38f87506703794918f30',
    'instant_sub': 'f9d8d8a41505bf8c9552d4a34ac4e190a6d0665c'
                '245595be11f2848e1a333a4a',
}
ALL_BODIES = dict(OWNERS)
ALL_BODIES.update(PINNED_BODIES)

# Instruction byte pins at every load-bearing site.
PINS = {
    # driver_ctor: time-flag test supply (edi = 1), the
    # clock call, the wheel_ctor call, the disabled arm
    # (tag 2, sentinel nanos), the field stores.
    0x5CE03FE: 'bf01000000', 0x5CE0403: 'e8d83efaff',
    0x5CE0412: 'e869600100', 0x5CE0438: 'b802000000',
    0x5CE043D: 'bd00ca9a3b',
    0x5CE04E4: '4c89b388000000', 0x5CE04EB: 'c6839000000000',
    0x5CE0502: '0f118391000000', 0x5CE0518: '488983b0000000',
    0x5CE051F: '48c783b800000000000000',
    0x5CE052A: 'c683c000000000', 0x5CE0531: '4c89bbc8000000',
    0x5CE0538: '89abd0000000', 0x5CE06A4: '48c70303000000',
    # wheel_ctor: levels allocation call + the three
    # initialising stores (elapsed 0, levels ptr,
    # pending list zeroed).
    0x5CF648F: 'e8bcabfeff', 0x5CF649A: '48c7430800000000',
    0x5CF64A2: '488903', 0x5CF64A8: '0f114310',
    # wheel_process: the resolver call + the two
    # monotonic elapsed stores ([wheel+8] via r12).
    0x5CF657F: 'e80cfeffff', 0x5CF6607: '4d890424',
    0x5CF677D: '4d893424',
    # unlock: entry CAS on the state lock byte, the
    # wheel_process call, the resolver call, the
    # next-deadline store to [state+0x28] = ctx+0x78.
    0x5CEAA47: 'f00fb00f', 0x5CEAA76: 'e895ba0000',
    0x5CEABA7: 'e8e4b70000', 0x5CEABC4: '48894328',
    # shutdown_setter: sentinel cmp on [ctx+0x90],
    # shutdown byte read, &ctx+0x50 lea, the xchg
    # that sets the byte, the unlock call, the
    # timers-disabled Location lea (time/mod.rs:190).
    0x5CE091A: '81be9000000000ca9a3b', 0x5CE0926: '0fb68e80000000',
    0x5CE0934: '488d4650', 0x5CE093D: '868e80000000',
    0x5CE0950: 'e8cba00000', 0x5CE0986: '488d151b667e00',
    # forwarder (cross-pinned with the #2938 packet):
    # entry sentinel check, wheel lea, the budget
    # store to [ctx+0x78], the base-pair reads.
    0x5CFDD0E: '81be9000000000', 0x5CFDD4D: '498d7658',
    0x5CFDD7A: '49894678', 0x5CFDDAC: '498b8e88000000',
    0x5CFDDB3: '418bb690000000',
    # identity routes: signal_body's ctx = obj+0x1c0
    # add and its setter call; drop_body's +0x150 add
    # and its setter call; cancel_body's two owner
    # offsets, its sentinel cmp, its ctx lock CAS and
    # its levels-base load.
    0x5CFC200: '4981c6c0010000', 0x5CFC20D: 'e8ce46feff',
    0x5CEB470: '4881c350010000', 0x5CEB47E: 'e85d54ffff',
    0x5CEB468: 'f0410fb04f50',
    0x5CEAFDC: 'b960010000', 0x5CEAFE1: 'b840020000',
    0x5CEAFEA: '4181bc079000000000ca9a3b',
    0x5CEB00A: 'f0410fb04f50', 0x5CEB06A: '49037f58',
    # registration routes: registration_a's +0x1c0 add,
    # registration_b's 0x160 displacement supply.
    0x5CFB7E1: '4981c7c0010000', 0x5CEC92B: 'ba60010000',
    # builder: the two driver_ctor calls.
    0x5CF9669: 'e8826bfeff', 0x5CF96EB: 'e8006bfeff',
}

EXPECTED_RELA_HITS = [
    {'offset': '0x64dfe40', 'addend': '0x5ceafd0'},
    {'offset': '0x64e1760', 'addend': '0x5cf9600'},
]

CENSUS_EXPECT = {
    'driver_ctor': {'calls': ['0x5cf9669', '0x5cf96eb'],
                    'jmps': []},
    'wheel_ctor': {'calls': ['0x5ce0412'], 'jmps': []},
    'wheel_resolve': {'calls': ['0x5ceaba7', '0x5cf657f',
                                '0x5cfdd56'],
                      'jmps': []},
    'wheel_process': {'calls': ['0x5ceaa76'], 'jmps': []},
    'unlock': {'calls': ['0x5ce0950'], 'jmps': ['0x5cfe088']},
    'shutdown_setter': {'calls': ['0x5ceb47e', '0x5cfc20d'],
                        'jmps': []},
    'forwarder': {'calls': [], 'jmps': ['0x5ce019f',
                                        '0x5ce088d']},
}

# Verified byte-lock census over the vendored-runtime
# cluster [0x5ce0000, 0x5d05000): every lock cmpxchg /
# xchg on a byte at displacement 0x50 that is a real
# instruction start in its FDE body.  The ctx state
# lock accounts for the forwarder and cancel_body
# sites; drop_body's pair is the host-object lock it
# holds across its setter call; registration_b's
# sites belong to the parking-layer entry lock of
# the #2945 packet, included here so the census is
# complete rather than selective.
BYTE_LOCK_EXPECT = {
    'cmpxchg': ['0x5ceb00a', '0x5ceb468', '0x5cec95e',
                '0x5cec9c8', '0x5cfdd2e', '0x5cfdd80'],
    'xchg': ['0x5ceb485', '0x5ceb4fe', '0x5ceca09',
             '0x5cecbca'],
}

TIME_RS = ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
           'src/runtime/time/mod.rs')
ENTRY_RS = ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
            'src/runtime/time/entry.rs')
WHEEL_RS = ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
            'src/runtime/time/wheel/mod.rs')
WAKE_RS = ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
           'src/util/wake_list.rs')
LOCATIONS = {
    'forwarder_time': (0x64C6F78, 0x43E4FE, 67, 214, 32),
    'forwarder_shutdown': (0x64C6F90, 0x43E4FE, 67, 217, 9),
    'setter_timers_disabled': (0x64C6FA8, 0x43E4FE, 67,
                               190, 32),
    'cancel_timers_disabled': (0x64C6158, 0x44CEF5, 69,
                               549, 30),
    'entry_state_panic': (0x64C6188, 0x44CEF5, 69, 181, 13),
    'wheel_level_panic': (0x64C6A48, 0x446310, 73, 130, 17),
    'wheel_ctor_panic': (0x64C6A18, 0x446310, 73, 56, 39),
    'wake_list_first': (0x64C6100, 0x434DB3, 65, 35, 9),
    'wake_list_second': (0x64C6118, 0x434DB3, 65, 36, 9),
}
MESSAGES = {
    'timers_disabled': (
        0x94CA6B,
        'A Tokio 1.x context was found, but timers are '
        'disabled. Call `enable_time` on the runtime builder '
        'to enable timers.'),
    'is_shutdown': (0x94DC50,
                    'assertion failed: !handle.is_shutdown()'),
    'mark_pending': (
        0x94D3CB,
        'mark_pending called when the timer entry is in an '
        'invalid state'),
}

FINDINGS = {
    'question': (
        'Open edge 2 of '
        'research/work-items/RE-005-node115-park-timeout-'
        'provenance, restated there as: the writers of '
        'the time context fields the forwarder reads -- '
        'the wheel state at ctx+0x58, the base pair at '
        'ctx+0x88/+0x90, the shutdown byte at ctx+0x80, '
        'and the adjusted budget stored to ctx+0x78 -- '
        "and the forwarder exit path's call through "
        '0x5ceaa20, which recomputes the remaining '
        'period itself, are not traced.  The park-unpark '
        'writer packet (PR #2945) left the same fields '
        'in the same form.  This packet settles all '
        'five.'),
    'identity': (
        'SETTLED.  The forwarder\'s ctx is the time '
        'half of the combined driver value built by '
        'driver_ctor 0x5ce01f0: ctx = value + 0x40.  '
        'Under that shift the constructor\'s stores '
        'land exactly on the fields the consumers '
        'read -- value+0x90 is the byte lock at '
        'ctx+0x50 (stored 0 at pin 0x5ce04eb), the '
        '0x20-byte wheel state copied to '
        'value+0x91..0xb1 puts its levels pointer at '
        'value+0x98 = ctx+0x58, elapsed at ctx+0x60, '
        'pending-list links at ctx+0x68/+0x70, the '
        'deadline cache store at value+0xb8 = '
        'ctx+0x78, the shutdown byte at value+0xc0 = '
        'ctx+0x80 and the base pair at value+0xc8/'
        '+0xd0 = ctx+0x88/+0x90.  Every independent '
        'route confirms the same shift: '
        'registration_a and the signal body reach '
        'the state at scheduler-context + 0x1c0 '
        '(value at +0x180; add pin 0x5cfb7e1, signal '
        'add pin 0x5cfc200), registration_b at '
        '[[T]+0x10] + 0x160 (value at +0x120; '
        'displacement pin 0x5cec92b), and the timer '
        'entry cancel body at owner + 0x160 or '
        'owner + 0x240 (value at +0x120/+0x200; '
        'pins 0x5ceafdc/0x5ceafe1).  The same object '
        'also hosts the io state below +0x50: the '
        'io wake body 0x5cef000, tail-called by the '
        'shutdown setter, operates [ctx+8], '
        '[ctx+0x10] and the [ctx+0x44] token the '
        'selectors test.'),
    'base_pair': (
        'SETTLED, one writer.  driver_ctor\'s fresh '
        'arm tests the config time-flag byte: set '
        '(supply pin 0x5ce03fe, clock call pin '
        '0x5ce0403) it calls clock 0x5c842e0 once '
        'and stores secs to value+0xc8 (pin '
        '0x5ce0531) and nanos to value+0xd0 (pin '
        '0x5ce0538) -- the pair is the driver\'s '
        'construction instant.  Clear, the value '
        'tag is 2 (pin 0x5ce0438) and the nanos '
        'word is the sentinel 0x3b9aca00 (pin '
        '0x5ce043d): the "timers disabled" encoding.  '
        'Every consumer tests that word before '
        'touching any other field -- the forwarder '
        'at entry (pin 0x5cfdd0e, panic '
        'time/mod.rs:214), the shutdown setter '
        '(pin 0x5ce091a, panic time/mod.rs:190), '
        'the cancel body (pin 0x5ceafea, panic '
        'time/entry.rs:549) -- so in the disabled '
        'flavour the secs slot (which then holds '
        'the constructor\'s companion-Arc pointer) '
        'is never read.  The constructor\'s third '
        'arm (tag 3, store pin 0x5ce06a4) wraps an '
        'already-built context and does not rewrite '
        'the pair.'),
    'wheel_state': (
        'SETTLED.  The 0x20-byte wheel state '
        '{levels, elapsed, list head, list tail} is '
        'built only by wheel_ctor 0x5cf6480, whose '
        'only caller in the artifact is driver_ctor '
        '(call pin 0x5ce0412; census).  It stores a '
        'fresh levels buffer from levels_alloc '
        '0x5ce1050 (call pin 0x5cf648f; the buffer '
        'is 6 level records of 0x410 bytes, the '
        'stride wheel_resolve and wheel_process '
        'index by), elapsed = 0 (pin 0x5cf649a), '
        'the levels pointer (pin 0x5cf64a2) and a '
        'zeroed pending list (pin 0x5cf64a8); '
        'driver_ctor copies the result into the '
        'value (pins 0x5ce0502/0x5ce0518).  After '
        'construction the levels pointer is never '
        'rewritten.  The elapsed field is advanced '
        'only by wheel_process 0x5cf6510 (monotonic '
        'stores at pins 0x5cf6607/0x5cf677d), which '
        'is called only by the unlock body (call '
        'pin 0x5ceaa76; census); the pending-list '
        'links are mutated by wheel_process and '
        'the entry cancel/insert paths under the '
        'ctx lock.'),
    'shutdown_byte': (
        'SETTLED, one runtime writer.  The byte '
        'starts 0 (driver_ctor store pin 0x5ce052a).  '
        'shutdown_setter 0x5ce08e0 xchg\'s 1 into '
        '[ctx+0x80] (pin 0x5ce093d) after reading '
        'the byte and returning early when it is '
        'already set (pin 0x5ce0926), after the '
        'timers-enabled check on [ctx+0x90] (pin '
        '0x5ce091a; Location time/mod.rs line 190 '
        'col 32, static 0x64c6fa8).  It then calls '
        'the unlock body with an elapsed of -1 (pin '
        '0x5ce0950) and tail-calls the io wake body '
        '0x5cef000.  The setter has exactly two '
        'callers in the artifact (census): the drop '
        'body 0x5ceb330 (call pin 0x5ceb47e, ctx '
        'passed as its second argument + 0x150) '
        'and the current_thread signal body '
        '0x5cfbfd0 (call pin 0x5cfc20d, ctx = its '
        'object + 0x1c0).  No other body in the '
        'closed method set stores to the byte.'),
    'budget_cache': (
        'SETTLED, three writers, no reader.  '
        'driver_ctor initialises value+0xb8 = 0 '
        '(pin 0x5ce051f).  The forwarder stores '
        'the wheel_resolve budget it computed to '
        '[ctx+0x78] while holding the lock (pin '
        '0x5cfdd7a; the value\'s provenance is '
        '#2938\'s settled cap).  The unlock body '
        'stores its own re-resolved deadline to '
        '[state+0x28] = ctx+0x78 (pin 0x5ceabc4) '
        'on every exit.  Both runtime stores write '
        'the resolver\'s result word (+carry) for '
        'the same wheel state.  No body in the '
        'method set -- forwarder, unlock, wheel '
        'process/resolver, setter, cancel, insert '
        '-- ever loads the slot: the next deadline '
        'is always recomputed from the wheel, so '
        'in this artifact ctx+0x78 is a write-only '
        'cache.'),
    'exit_recompute': (
        'SETTLED.  The body on the forwarder\'s '
        'exit path, 0x5ceaa20, is the state\'s '
        'unlock/process body: its self pointer is '
        '&ctx+0x50 (the lock byte is its +0, the '
        'wheel its +8), it has exactly two '
        'references (census) -- the shutdown '
        'setter\'s call with elapsed = -1 and the '
        'forwarder\'s tail jump at 0x5cfe088 with '
        'elapsed = milliseconds since the base '
        'instant.  It takes the lock (pin '
        '0x5ceaa47), caps the elapsed argument at '
        'the wheel\'s current elapsed field, '
        'advances the wheel through wheel_process '
        '(pin 0x5ceaa76), drains expired entries '
        'into a WakeList (overflow panics at '
        'util/wake_list.rs lines 35/36), re-resolves '
        'the wheel (pin 0x5ceaba7) and stores the '
        'next deadline to ctx+0x78 (pin 0x5ceabc4), '
        'then releases the lock and fires the '
        'collected wakers.  This closes the second '
        'half of the #2938 open edge: the exit '
        'recompute is the same remaining-period '
        'computation, run under the lock on the '
        'way out.'),
    'forwarder_use': (
        'Connection to the settled cap (#2938): '
        'the base pair is the construction instant '
        'in the clock body\'s (secs, nanos) '
        'domain, and the wheel\'s millisecond '
        'values (elapsed, budgets, deadlines) live '
        'in the same domain starting from 0 at '
        'construction.  The forwarder\'s elapsed = '
        'instant_sub(clock now, base pair) is '
        'therefore the time since the driver was '
        'built, and remaining = budget - elapsed '
        'is the time left in the current wheel '
        'period measured from construction -- the '
        'writers above are what make the two '
        'sides of that subtraction commensurable.'),
}

OPEN_EDGES = [
    'The tag-3 arm of driver_ctor wraps an '
    'already-built context (its fields were '
    'written by an earlier fresh construction); '
    'which runtime build paths supply it, and '
    'whether a wrapped context\'s fields can ever '
    'be re-initialised afterwards, is not traced '
    'here.',
    'The drop body passes ctx as (its second '
    'argument) + 0x150.  The object that argument '
    'points into is not identified in this '
    'packet; the value passed satisfies the same '
    'field contract, but the +0x150 base relation '
    'to the +0x160/+0x1c0 forms is stated as '
    'observed, not derived.',
    'The insert path (insert_body 0x5cea7c0 via '
    'wheel_insert 0x5cf6880) writes wheel level '
    'slots and entry fields, and the pending-list '
    'links at ctx+0x68/+0x70 are mutated by the '
    'entry paths under the lock; a full field '
    'census of the insert path is not part of '
    'this packet.  Its stores do not land on any '
    'of the five fields settled here.',
    'Whether the disabled flavour\'s base secs '
    'slot can be observed by any path that skips '
    'the sentinel check is a whole-artifact '
    'negative this packet does not claim: every '
    'traced consumer checks the nanos word '
    'first, and the claim is limited to them.',
    'The io half of the same object (fields '
    'below ctx+0x50, including the [ctx+0x44] '
    'token) belongs to the io driver graph of '
    'the TLS value-object and timeout-pair '
    'packets and is not re-traced here.',
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


# Byte-lock census: raw byte-pattern candidates for
# lock cmpxchg / xchg on a byte at displacement 0x50,
# restricted to the vendored-runtime cluster, then
# verified the same way as the rel32 census -- a
# candidate counts only when its containing FDE body's
# own disassembly has an instruction starting there
# with the right mnemonic and a 0x50(%r..) operand.
# Mid-instruction phantom hits fail verification.
def byte_lock_census(data, extents):
    candidates = {'cmpxchg': set(), 'xchg': set()}
    for section in sections(data):
        if section['name'] != '.text':
            continue
        base = section['address']
        blob = data[section['offset']:section['offset']
                    + section['size']]
        for i in range(len(blob) - 6):
            va = base + i
            if not (0x5CE0000 <= va < 0x5D05000):
                continue
            b = blob[i:i + 6]
            if b[0] == 0xF0 and 0x40 <= b[1] <= 0x4F \
                    and b[2] == 0x0F and b[3] == 0xB0 \
                    and 0x40 <= b[4] <= 0x7F \
                    and (b[4] & 7) != 4 and b[5] == 0x50:
                candidates['cmpxchg'].add(va)
            elif b[0] == 0xF0 and b[1] == 0x0F \
                    and b[2] == 0xB0 and 0x40 <= b[3] <= 0x7F \
                    and (b[3] & 7) != 4 and b[4] == 0x50:
                candidates['cmpxchg'].add(va)
            if 0x40 <= b[0] <= 0x4F and b[1] == 0x86 \
                    and 0x40 <= b[2] <= 0x7F \
                    and (b[2] & 7) != 4 and b[3] == 0x50:
                candidates['xchg'].add(va)
            elif b[0] == 0x86 and 0x40 <= b[1] <= 0x7F \
                    and (b[1] & 7) != 4 and b[2] == 0x50:
                candidates['xchg'].add(va)
    owners = {}
    for start, end in extents:
        for sites in candidates.values():
            for va in sites:
                if start <= va < end:
                    owners.setdefault(va, (start, end))
    cache = {}
    out = {'cmpxchg': [], 'xchg': []}
    for kind, sites in candidates.items():
        for va in sorted(sites):
            extent = owners.get(va)
            if extent is None:
                continue
            if extent not in cache:
                cache[extent] = disasm_rows(data, *extent)
            row = cache[extent].get(va)
            if row is None:
                continue
            text = row[1]
            if '0x50(%r' not in text:
                continue
            if kind == 'cmpxchg' and 'lock cmpxchg' in text:
                out[kind].append(hex(va))
            elif kind == 'xchg' and text.startswith('xchg'):
                out[kind].append(hex(va))
    return out


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
    return hits


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
    locks = byte_lock_census(data, extents)
    if locks != BYTE_LOCK_EXPECT:
        raise AssertionError(f'byte-lock census drift: {locks}')
    locations = {role: location_record(data, *spec)
                 for role, spec in LOCATIONS.items()}
    messages = {role: message_record(data, *spec)
                for role, spec in MESSAGES.items()}
    hits = chain_rela_hits(data)
    if hits != EXPECTED_RELA_HITS:
        raise AssertionError(
            f'pointer census drift: {hits}')
    for va, expect_hex in PINS.items():
        raw = read(data, va, len(bytes.fromhex(expect_hex)))
        if raw.hex() != expect_hex:
            raise AssertionError(f'pin drift at {va:#x}')
    return {
        'artifact': {'snapshot': SNAPSHOT, 'size': len(data),
                     'sha256': TARGET_SHA256},
        'work_item': WORK_ITEM,
        'owners': owners,
        'pinned_bodies': pinned,
        'call_census': census,
        'byte_lock_census': locks,
        'rela_refs': {
            'chain_bodies': [hex(s) for s in sorted(
                start for start, _ in ALL_BODIES.values())],
            'relative_addend_hits': hits,
        },
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
