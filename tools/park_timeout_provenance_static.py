"""Static evidence for the RE-005 park_timeout
timeout-provenance packet.

Answers open edge 3 of the RE-005 TLS value-object
packet (PR #2935), for the authenticated hl-node 115
artifact only: park_timeout 0x5cfd9a0 has exactly
three call sites and one tail jump, and that packet
did not trace the timeout values they pass.  Where
does each timeout come from -- a constant, a
computed value, a pass-through -- and is it capped?

SETTLED.  Every layer between the top-level callers
and park_timeout passes the timeout as a (secs u64,
nanos u32) register pair (at park_timeout itself:
rsi -> r15 at 0x5cfd9be, edx -> ebp at 0x5cfd9bc;
a zero pair returns right after the consume CAS).
The nanos word doubles as the infinity sentinel:
nanos == 0x3b9aca00 (1_000_000_000, one more than
any valid Duration nanos) means "no timeout", every
consumer tests the nanos word alone (dispatch
0x5cf6a9a, wrapper_state 0x5ce3019, registration_a
0x5cfb7ee, registration_b 0x5cec938, forwarder
0x5cfde70), and the secs word is then a don't-care.

The four references to park_timeout, one by one:

- Tail jump 0x5ce0193 (selector_timeout 0x5ce0160,
  the arm where the pair word at [pair+0] is 1 with
  [pair+8] == 0): a pure pass-through -- the
  selector moves its own (rdx, rcx) to (rsi, rdx)
  at 0x5ce0187/0x5ce018a and tail-jumps with
  rdi = [pair+0x10] + 0x10.
- Call 0x5cfdfa5 (forwarder 0x5cfdd00, the arm
  where the resolver flag for the context's
  +0x58 wheel state is clear): a pure pass-through
  of the forwarder's own entry pair ([rsp] secs
  saved at 0x5cfdd49, ebp nanos saved at
  0x5cfdd1e) to the payload at [pair+8] + 0x10.
- Call 0x5cfdeab (forwarder, resolver flag set):
  the one genuinely computed value in the graph.
  The forwarder resolves the context's wheel state
  at +0x58 through wheel_resolve 0x5cf6390
  (present flag + a millisecond budget), computes
  the elapsed time since the base timestamp stored
  as a (secs, nanos) pair at ctx+0x88/+0x90 with
  instant_sub 0x5c84210 and the clock body
  0x5c842e0, converts to milliseconds with
  saturation, and takes remaining = budget -
  elapsed (saturating).  It calls park_timeout
  with min(remaining, caller pair) compared
  lexicographically on (secs, nanos) -- except
  that a caller nanos equal to the sentinel skips
  the min and passes the full remaining.  A zero
  remaining takes the consume-notification arm at
  0x5cfdeb5 instead of calling park_timeout.
- Call 0x5cf29c8 (loop_body 0x5cf27c0): the
  remaining time to the body's own deadline.  The
  body converts its entry pair to an absolute
  deadline at entry (clock call 0x5cf283f, checked
  add of the pair at 0x5cf2847) and, each time its
  poll helper reports the pending status, calls
  park_timeout with deadline - now recomputed by
  instant_sub (call 0x5cf298a), saturating at
  zero.

Supply census (who feeds the graph): the two
selectors are called only by wrapper_state
0x5ce2fd0 and registration_a 0x5cfb780;
wrapper_state is called only by registration_b
0x5cec8b0.  Both registration bodies hardwire
secs = 0 (registration_a at its selector calls,
registration_b at 0x5cec9d4) and forward a bare
nanos word.  All six registration call sites
supply nanos in {0, 0x3b9aca00} only: xor-zeroed
at 0x5cece57, 0x5ced565 (into registration_b) and
0x5cfb67d, 0x5cfba81 (into registration_a), the
sentinel constant at 0x5ced788 and 0x5cfbbed.
A sentinel nanos is diverted to selector_park by
both registration paths, so the values that
actually reach selector_timeout are (0, 0); the
forwarder's cap is the only route by which a
nonzero finite duration (the time left in the
context's current wheel period, against a
sentinel caller) reaches park_timeout.

The loop body's chain is finite in form but
unreached in fact: loop_body is called only by
dispatch 0x5cf6a90, dispatch only by park_wrap
0x5cf3fe0 (a register pass-through of its own
(rsi, rdx) pair), and park_wrap's only three
callers (0x15deec0, 0x2abbaf0, 0x5cf8640) each load
edx = 0x3b9aca00 immediately before the call
(0x15deec8, 0x2abbaf8, 0x5cf8648), so dispatch
always takes its park arm and the loop body never
runs.  The .rela.dyn/.rela.plt addend census over
all nineteen bodies finds exactly two pointer
references: the slots at 0x64e1790/0x64e1798,
inside a larger function-pointer table, hold
top_reg_a1 0x5cfb610 and top_reg_a2 0x5cfb920.
Both bodies hardwire their registration_a
supplies (xor-zeroed / sentinel) in their own
code no matter how they are invoked, and no body
that receives a duration has any pointer
reference, so no indirect route injects a
different value into the graph.

Identities, from the artifact's own panic
Locations: the selectors' panic arms reference
/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/
runtime/io/driver.rs (selector_timeout line 165
col 32, selector_park line 160 col 32, both with
the "IO is disabled" message), and the forwarder's
reference .../runtime/time/mod.rs (line 214 col 32
with the "timers are disabled" message, fired at
entry when the nanos word of the base pair at
[ctx+0x90] equals the sentinel; line 217 col 9
with "assertion failed: !handle.is_shutdown()",
fired when the byte at [ctx+0x80] is set).

Method: ten bodies are exported in full (the two
selectors, wrapper_state, dispatch, the forwarder,
the loop body, the two registration bodies and
the two arithmetic helpers); every other body is
extent/digest pinned.  Censuses: whole-.text rel32
call/jump scans for all ten graph bodies, every
hit boundary-verified against its containing FDE
body's own disassembly; .rela.dyn/.rela.plt addend
census for pointer references; instruction byte
pins at every load-bearing site.  Section mapping
via the section table (tools/elf_index).
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
WORK_ITEM = 'RE-005-node115-park-timeout-provenance'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'
SENTINEL = 0x3B9ACA00

OWNERS = {
    'selector_timeout': (0x5CE0160, 0x5CE01E9),
    'selector_park': (0x5CE0850, 0x5CE08DC),
    'wrapper_state': (0x5CE2FD0, 0x5CE30C7),
    'dispatch': (0x5CF6A90, 0x5CF6BAE),
    'forwarder': (0x5CFDD00, 0x5CFE0E9),
    'loop_body': (0x5CF27C0, 0x5CF2AAB),
    'registration_a': (0x5CFB780, 0x5CFB919),
    'registration_b': (0x5CEC8B0, 0x5CECC58),
    'wheel_resolve': (0x5CF6390, 0x5CF647D),
    'instant_sub': (0x5C84210, 0x5C842D6),
}
EXPORTED = list(OWNERS)

PINNED_BODIES = {
    'park_timeout': (0x5CFD9A0, 0x5CFDB8D),
    'park_wrap': (0x5CF3FE0, 0x5CF4536),
    'park_wrapper_a': (0x15DEEC0, 0x15DEFCC),
    'park_wrapper_b': (0x2ABBAF0, 0x2ABBBFC),
    'park_wrapper_c': (0x5CF8640, 0x5CF874C),
    'top_reg_a1': (0x5CFB610, 0x5CFB77A),
    'top_reg_a2': (0x5CFB920, 0x5CFBDDB),
    'top_reg_b': (0x5CECC60, 0x5CEDD12),
    'clock': (0x5C842E0, 0x5C843A9),
}

BODY_SHA256 = {
    'selector_timeout': 'f0eb5ff4372093ba8f617e6f52555f35e6f4e776'
                '59dc9928372825790444357b',
    'selector_park': 'b0882248d77cea8ba4ee9d4fae1b1f50c69bb5cb'
                'a4e7dcd01ddd777981a6caa9',
    'wrapper_state': '17d62a55fe9d639eee5e5d26f3694a090f7f07e6'
                '29ca729d11bc66c31d3e0e37',
    'dispatch': 'b9c059a5c99fa902f6da2f0fdb1d755a40aebc68'
                '9ea3d1b7b04f1fb31482f490',
    'forwarder': '2d8ea94341d17a31bd755de9d3226f6911a337d3'
                'a6c97134ed1721c6a097c647',
    'loop_body': 'f363c9d5c5ec098149dd574324e0d36bd46f131d'
                '752b940deee59b8094ce3de1',
    'registration_a': '3be383ace482e644674d7916cca63e4a37988f50'
                'c0ce1478256c16df4dfb4139',
    'registration_b': 'e732e6851f0a42f5bbf4bcb63d5a44f8e1a030d7'
                '428404c514f5af8f92103a77',
    'wheel_resolve': '7f576d12868e201a625c9ff780d4816c77d80f50'
                'd55c1666485a8f5c957bd1ac',
    'instant_sub': 'f9d8d8a41505bf8c9552d4a34ac4e190a6d0665c'
                '245595be11f2848e1a333a4a',
    'park_timeout': '411cc42aff700d68883fd2371a63226cf62e426c'
                '5530e188ed619f6fb98cbef5',
    'park_wrap': '187d899dd8e0dd2ffb90181036a90c1585f25a24'
                'f21f40fe56e402f9c65f1bb0',
    'park_wrapper_a': 'fbd4ce213b851d908b361a85c8102dbae27fc933'
                'a6a5eea0530205bac4835122',
    'park_wrapper_b': 'fa5894378be92837762c666e1c7404fcc59c689f'
                '0bb010e27f620ebf1bb958b5',
    'park_wrapper_c': 'd09d8a23c4fad4fc9a30e8b1fc5b89bfffedc6e4'
                '8153ad9f1eba5035bec9fbf5',
    'top_reg_a1': 'a8c6ab86806fc95db1800ecd0dbe1879ad987c51'
                'ff7361aadbcedc5f80cc8640',
    'top_reg_a2': 'c0182c69f7564a102b726d9fc4a38df8418bf923'
                'f073d16e92e0ecbede1b344c',
    'top_reg_b': '6daa4de9236c851758d6f62ee795cdd95d9450cb'
                '932fe723046dd5218d53604d',
    'clock': '3efe331bdc612bff27ad3c487fbff92d57a2e097'
                '820c38f87506703794918f30',
}
ALL_BODIES = dict(OWNERS)
ALL_BODIES.update(PINNED_BODIES)

# Instruction byte pins at every load-bearing site.
PINS = {
    # park_timeout entry: (rsi, edx) is the duration pair.
    0x5CFD9BC: '89d5', 0x5CFD9BE: '4989f7', 0x5CFD9C1: '4885f6',
    # selector_timeout: pass-through moves + the two tail jumps.
    0x5CE0187: '4889d6', 0x5CE018A: '89ca',
    0x5CE0193: 'e908d80100', 0x5CE019F: 'e95cdb0100',
    # selector_park: sentinel load + tail jumps.
    0x5CE0881: 'b900ca9a3b', 0x5CE088D: 'e96ed40100',
    0x5CE087C: 'e90fd30100',
    # forwarder: entry sentinel check on [ctx+0x90], saved pair,
    # wheel field, base-pair reads, sentinel compare, calls.
    0x5CFDD0E: '81be9000000000', 0x5CFDD1E: '89cd',
    0x5CFDD49: '48891424', 0x5CFDD4D: '498d7658',
    0x5CFDDAC: '498b8e88000000', 0x5CFDDB3: '418bb690000000',
    0x5CFDE70: '81fd00ca9a3b', 0x5CFDEAB: 'e8f0faffff',
    0x5CFDF8B: 'e800fcffff', 0x5CFDFA5: 'e8f6f9ffff',
    # loop body: entry pair saved, clock call, deadline add,
    # remaining recompute, the park_timeout call.
    0x5CF27D1: '4189cf', 0x5CF27D4: '4989d4',
    0x5CF283F: 'e89c1af9ff', 0x5CF2847: '4d01e6',
    0x5CF298A: 'e88118f9ff', 0x5CF29C8: 'e8d3af0000',
    # dispatch: the sentinel compare + the loop call.
    0x5CF6A9A: '81fa00ca9a3b', 0x5CF6B60: 'e85bbcffff',
    # wrapper_state: the three selector calls + sentinel cmp.
    0x5CE2FF3: 'e868d1ffff', 0x5CE3019: '4181f800ca9a3b',
    0x5CE3022: 'e829d8ffff', 0x5CE3045: 'e816d1ffff',
    # registration_a: sentinel cmp, selector calls, secs = 0.
    0x5CFB7EE: '81fd00ca9a3b', 0x5CFB7F6: 'e85550feff',
    0x5CFB7FD: '31d2', 0x5CFB7FF: '89e9',
    0x5CFB801: 'e85a49feff',
    # registration_b: sentinel cmp, selector_park call,
    # secs = 0 / nanos forward into wrapper_state.
    0x5CEC938: '4181ff00ca9a3b', 0x5CEC986: 'e8c53effff',
    0x5CEC9D4: '31c9', 0x5CEC9D6: '4589f8',
    0x5CEC9D9: 'e8f265ffff',
    # park_wrap: entry pair saved + the dispatch call.
    0x5CF3FF1: '89d5', 0x5CF3FF3: '4989f6',
    0x5CF414E: 'e83d290000',
    # top-level supplies: sentinel constants.
    0x15DEEC8: 'ba00ca9a3b', 0x2ABBAF8: 'ba00ca9a3b',
    0x5CF8648: 'ba00ca9a3b', 0x5CED788: 'ba00ca9a3b',
    0x5CFBBED: '41b800ca9a3b',
    # top-level supplies: xor-zeroed nanos.
    0x5CECE57: '31d2', 0x5CED565: '31d2',
    0x5CFB67D: '4531c0', 0x5CFBA81: '4531c0',
}

EXPECTED_RELA_HITS = [
    {'offset': '0x64e1790', 'addend': '0x5cfb610'},
    {'offset': '0x64e1798', 'addend': '0x5cfb920'},
]

CENSUS_EXPECT = {
    'park_timeout': {'calls': ['0x5cf29c8', '0x5cfdeab',
                               '0x5cfdfa5'],
                     'jmps': ['0x5ce0193']},
    'forwarder': {'calls': [], 'jmps': ['0x5ce019f', '0x5ce088d']},
    'selector_timeout': {'calls': ['0x5ce2ff3', '0x5ce3045',
                                   '0x5cfb801'],
                         'jmps': []},
    'selector_park': {'calls': ['0x5ce3022', '0x5cec986',
                                '0x5cfb7f6'],
                      'jmps': []},
    'wrapper_state': {'calls': ['0x5cec9d9'], 'jmps': []},
    'registration_a': {'calls': ['0x5cfb680', '0x5cfba84',
                                 '0x5cfbbf3'],
                       'jmps': []},
    'registration_b': {'calls': ['0x5cece59', '0x5ced567',
                                 '0x5ced78d'],
                       'jmps': []},
    'dispatch': {'calls': ['0x5cf414e'], 'jmps': []},
    'loop_body': {'calls': ['0x5cf6b60'], 'jmps': []},
    'park_wrap': {'calls': ['0x15deecd', '0x2abbafd', '0x5cf864d'],
                  'jmps': []},
}

IO_RS = ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
         'src/runtime/io/driver.rs')
TIME_RS = ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
           'src/runtime/time/mod.rs')
LOCATIONS = {
    'selector_timeout': (0x64C64B0, 0x44281E, 68, 165, 32),
    'selector_park': (0x64C64C8, 0x44281E, 68, 160, 32),
    'forwarder_time': (0x64C6F78, 0x43E4FE, 67, 214, 32),
    'forwarder_shutdown': (0x64C6F90, 0x43E4FE, 67, 217, 9),
}
MESSAGES = {
    'io_disabled': (
        0x94CA03,
        'A Tokio 1.x context was found, but IO is disabled. '
        'Call `enable_io` on the runtime builder to enable IO.'),
    'timers_disabled': (
        0x94CA6B,
        'A Tokio 1.x context was found, but timers are '
        'disabled. Call `enable_time` on the runtime builder '
        'to enable timers.'),
    'is_shutdown': (0x94DC50,
                    'assertion failed: !handle.is_shutdown()'),
}

FINDINGS = {
    'question': (
        'Open edge 3 of '
        'research/work-items/RE-005-node115-tls-value-object, '
        'answered against the same artifact: park_timeout '
        '0x5cfd9a0 (three calls, one tail jump, recorded '
        'there) left the timeout values untraced; this '
        'packet fixes the provenance of the duration '
        'argument at every reference, and the complete '
        'supply above it.'),
    'representation': (
        'SETTLED. Every layer passes the timeout as a '
        '(secs u64, nanos u32) register pair; at '
        'park_timeout the pair arrives as (rsi, rdx) and is '
        'saved at 0x5cfd9be (rsi -> r15) and 0x5cfd9bc '
        '(edx -> ebp), with a zero pair returning right '
        'after the entry consume CAS. The nanos word is '
        'the infinity sentinel: nanos == 0x3b9aca00 '
        '(1_000_000_000) means no timeout, and every '
        'consumer tests the nanos word alone -- dispatch '
        'cmp at 0x5cf6a9a, wrapper_state cmp at 0x5ce3019, '
        'registration_a cmp at 0x5cfb7ee, registration_b '
        'cmp at 0x5cec938, forwarder cmp at 0x5cfde70, '
        'forwarder entry check on the base pair nanos at '
        '0x5cfdd0e ([ctx+0x90]). The secs word is a '
        "don't-care whenever nanos is the sentinel."),
    'site_tail_jump': (
        'SETTLED, pass-through. 0x5ce0193 is the tail jump '
        'in selector_timeout 0x5ce0160 (panic Location '
        'io/driver.rs line 165 col 32): taken when the '
        'pair word at [pair+0] is 1 and [pair+8] is 0, it '
        'moves its own (rdx, rcx) to (rsi, rdx) at '
        '0x5ce0187/0x5ce018a and tail-jumps with '
        'rdi = [pair+0x10] + 0x10. Nothing is computed; '
        'the value is whatever the selector was given.'),
    'site_forwarder_passthrough': (
        'SETTLED, pass-through. Call 0x5cfdfa5 in '
        'forwarder 0x5cfdd00 is the arm where the flag '
        'returned by wheel_resolve 0x5cf6390 for the '
        "context's wheel state at +0x58 is clear: it "
        'forwards the entry pair unchanged (secs saved '
        'to [rsp] at 0x5cfdd49, nanos saved to ebp at '
        '0x5cfdd1e) to the payload at [pair+8] + 0x10.'),
    'site_forwarder_capped': (
        'SETTLED, computed and capped -- the only '
        'genuinely computed timeout in the graph. With '
        'the resolver flag set, the forwarder takes the '
        'millisecond budget from wheel_resolve (the '
        "wheel state read at ctx+0x58, lea pin "
        '0x5cfdd4d), computes elapsed = clock now '
        '(clock body 0x5c842e0) minus the base timestamp '
        'stored as a (secs, nanos) pair at ctx+0x88/'
        '+0x90 (reads pinned at 0x5cfddac/0x5cfddb3) via '
        'instant_sub 0x5c84210, converts to milliseconds '
        'with saturation, and forms remaining = budget - '
        'elapsed (saturating). The call at 0x5cfdeab '
        'passes min(remaining, caller pair) compared '
        'lexicographically on (secs, nanos), except a '
        'caller nanos equal to the sentinel (cmp pin '
        '0x5cfde70) skips the min and passes the full '
        'remaining. A zero remaining instead takes the '
        'consume-notification arm at 0x5cfdeb5. The '
        'adjusted budget is also stored back to '
        'ctx+0x78.'),
    'site_loop_body': (
        'SETTLED, computed but unreached. Call 0x5cf29c8 '
        'in loop_body 0x5cf27c0 passes the remaining '
        'time to the body\'s own deadline: the entry '
        'pair (rdx, rcx; saved at 0x5cf27d4/0x5cf27d1) '
        'becomes an absolute deadline at entry (clock '
        'call 0x5cf283f, checked add 0x5cf2847 with an '
        'overflow panic), and each pending poll '
        'recomputes deadline - now through instant_sub '
        '(call 0x5cf298a), saturating at zero. The chain '
        'above it can only supply the sentinel: loop_body '
        'is called only by dispatch 0x5cf6a90 (call pin '
        '0x5cf6b60; dispatch diverts on the sentinel cmp '
        '0x5cf6a9a and returns on a zero pair), dispatch '
        'only by park_wrap 0x5cf3fe0 (a register '
        'pass-through of its own (rsi, rdx), pins '
        '0x5cf3ff1/0x5cf3ff3/0x5cf414e), and '
        "park_wrap's only three callers each load "
        'edx = 0x3b9aca00 immediately before the call '
        '(pins 0x15deec8, 0x2abbaf8, 0x5cf8648). The '
        'finite arm of this chain therefore never '
        'executes in this artifact.'),
    'supply_census': (
        'SETTLED. Above the selectors: '
        'selector_timeout/selector_park are called only '
        'by wrapper_state 0x5ce2fd0 (0x5ce3022, '
        '0x5ce3045, zero-duration arm 0x5ce2ff3) and '
        'registration_a 0x5cfb780 (0x5cfb7f6, 0x5cfb801); '
        'wrapper_state is called only by registration_b '
        '0x5cec8b0 (0x5cec9d9). Both registration bodies '
        'hardwire secs = 0 (registration_a xor pin '
        '0x5cfb7fd; registration_b xor pin 0x5cec9d4 with '
        'the nanos forwarded at 0x5cec9d6) and forward a '
        'bare nanos word. All six registration call '
        'sites supply nanos in {0, 0x3b9aca00} only: '
        'xor-zeroed at 0x5cece57 and 0x5ced565 (into '
        'registration_b, from top_reg_b 0x5cecc60) and '
        'at 0x5cfb67d and 0x5cfba81 (into '
        'registration_a, from top_reg_a1/top_reg_a2), '
        'the sentinel constant at 0x5ced788 and '
        '0x5cfbbed. A sentinel nanos is diverted to '
        'selector_park on both paths, so the pair that '
        'actually reaches selector_timeout from this '
        'graph is (0, 0). The rela addend census over '
        'all nineteen bodies finds exactly two pointer '
        'references -- slots 0x64e1790/0x64e1798 of a '
        'larger function-pointer table hold top_reg_a1 '
        '0x5cfb610 and top_reg_a2 0x5cfb920 -- and both '
        'of those bodies hardwire the supplies above '
        'in their own code regardless of how they are '
        'invoked; no body that receives a duration has '
        'any pointer reference, so no indirect route '
        'injects a different value.'),
    'forwarder_identity': (
        'The selectors\' panic arms reference '
        'io/driver.rs -- selector_timeout line 165 col '
        '32, selector_park line 160 col 32, both with '
        'the io_disabled message -- and the '
        "forwarder's reference time/mod.rs: line 214 "
        'col 32 carries the timers_disabled message and '
        'fires at entry when the nanos word of the base '
        'pair at [ctx+0x90] equals the sentinel; line '
        '217 col 9 carries '
        '"assertion failed: !handle.is_shutdown()" and '
        'fires when the byte at [ctx+0x80] is set. The '
        'two files\' path strings are recovered from '
        '.rela.dyn RELATIVE addends (0x44281e and '
        '0x43e4fe), not from bytes at the Location '
        'statics.'),
}

OPEN_EDGES = [
    'What selects the direct arm: the pair word at '
    '[pair+0] takes values beyond 0 and 1 in this '
    'graph (the selectors test only == 0 / == 1 and '
    'fall to a slow path through 0x5ceed20, 0x5ce7380 '
    'and 0x5cee650 otherwise). Who writes the pair '
    'word and the payloads at [pair+8]/[pair+0x10] is '
    'not traced here; that is open edge 2 of the '
    'TLS value-object packet and stays open.',
    'The writers of the time context fields the '
    'forwarder reads -- the wheel state at ctx+0x58, '
    'the base pair at ctx+0x88/+0x90, the shutdown '
    'byte at ctx+0x80, and the adjusted budget stored '
    'to ctx+0x78 -- and the forwarder exit path\'s '
    'call through 0x5ceaa20, which recomputes the '
    'remaining period itself, are not traced. The '
    'cap rule is pinned; the state lifecycle is not.',
    'The contention fallback registration_b calls '
    'when its byte claim at [entry+8] fails (body '
    '0x5ce30d0, listed as beyond-boundary in the TLS '
    'value-object packet) is not traced here; by '
    'the censuses above it cannot reach park_timeout '
    'except through the same chains.',
    'Open edges 1 (the parking-layer consume '
    'bit/counter protocol), 2 (the pair onward '
    'fields) and 4 (the park_timeout owner type '
    'name) of the TLS value-object packet are '
    'untouched by this packet and remain open.',
    'Whether the loop-body chain\'s finite arm is '
    'dead in every build or only unreached from the '
    'three sentinel wrappers found here is a census '
    'statement about this artifact only; a future '
    'artifact could revive it without changing any '
    'body pinned here.',
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


def rela_refs(data, va):
    return [{'offset': hex(off), 'type': typ}
            for off, typ, add in parse_rela(data)
            if add == va]


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
