"""Static evidence for the RE-005 tag-3 supply
packet.

Answers open edge 1 of the RE-005 time-context
writers packet (PR #2948) -- left in the same
form by PR #2938 and PR #2945 -- for the
authenticated hl-node 115 artifact only: which
build / call path supplies the tag-3 arm of
driver_ctor 0x5ce01f0, the arm #2948 described
as wrapping an already-built context?

SETTLED, WITH A CORRECTION.  The tag-3 arm is
not a wrapper of anything.  The ctor tail at
0x5ce06a0 writes only [out] = 3 and
[out+8] = r15 and touches no driver field: it
is the constructor's failure encoding.  Only
the poll variant can reach it (variant byte 0
jumps straight to the shared install sequence
at 0x5ce0332; the boundary-verified branch
census into the tail is exactly one rel32 jo
and one rel8 je, plus one fall-through).  Two
routes are live, both OS failures while the
poll half is being built, and both carry
(errno << 32) | 2 in [out+8]: Poll::new
0x5ceeae0 failing (its word0 INT64_MIN is
caught by the neg / jo pair at the ctor entry;
all three of its error exits write
{INT64_MIN, (errno << 32) | 2} and close their
own partial fds), and the signal-attach body
0x5ce71f0 failing (it dups the lazily
initialised global signal fd with
fcntl(F_DUPFD_CLOEXEC) and registers it on
the poll's epoll with data 1; its two failure
exits write the same pair, and the ctor then
tears the partial poll state down -- dup fd
close, registry Vec drop, buffer free, eventfd
close -- and falls through to the tail).  The
third branch into the tail, the je at
0x5ce0670 in the post-registration block, is
value-unreachable: on the only path that
reaches it rcx is the movabs INT64_MIN of
0x5ce02c2 incremented once (no other rcx write
exists in the block), while rax is the attach
result's word0 reloaded through [rsp+0xc8] --
the capacity on success, the failure word
having been diverted at 0x5ce02d9 -- so the
equality capacity == INT64_MIN + 1 can never
hold, and the block's real exit loops back
into the install sequence at 0x5ce0382.

SUPPLY.  The ctor's only callers are the two
call sites of the runtime builder 0x5cf9600.
The builder has no direct callers and exactly
one pointer reference in the artifact: the
.rela.dyn type-8 addend at GOT slot
0x64e1760, which is also the only imm64
occurrence of the builder's start in the
file.  The slot is called at exactly three
sites in two wrapper bodies (FDE
0x15d6fd0..0x15d8447: 0x15d7026, 0x15d70c2;
FDE 0x2ae1690..0x2ae27b2: 0x2ae16f2).  Every
wrapper builds its builder config with
cfg_ctor 0x5cf93f0 -- whose only callers are
those same three wrapper sites -- which fixes
capacity 0x400 at [bcfg+0x60], [bcfg+0] = 0,
the flavour argument at [bcfg+0xe4] and zeroes
the dword at [bcfg+0xe5]; each wrapper then
overwrites the u16 at [bcfg+0xe5] with the
constant 0x0101: variant byte 1 (poll), tag
byte 1 (time enabled).  The builder copies
[bcfg+0x60] and that u16 into the ctor config
(cfg+0xa = 1 at site 1, 0 at site 2; cfg+0xb =
[bcfg+0xe7]); the ctor reads only cfg word0,
cfg+8 and cfg+9.  So every runtime build in
the artifact drives the poll variant with
time enabled, and the two failure routes above
are the whole supply of the tag-3 arm.

The builder converts a ctor tag-3 into its
own error {[+0] = 2, [+8] = the ctor's error
word} at both call sites, and both wrappers
compare the builder result's tag against 2
and divert to their own error paths.  A tag-3
outcome therefore surfaces as a runtime-build
failure: no caller ever receives a tag-3
context, nothing is installed from one, and
re-initialisation of a wrapped context cannot
arise.

Method: five bodies are exported in full (the
driver constructor, the signal-attach body,
the runtime builder, the builder-config
constructor and Poll::new); every other body
is extent/digest pinned.  Censuses:
whole-.text rel32 call/jump scans for all
five graph bodies, every hit
boundary-verified against its containing FDE
body's own disassembly; an FF 15 census of
indirect calls through the builder's GOT
slot, likewise verified; an all-encoding
branch census into the ctor tail (rel32
call/jump/jcc, rel8 jcc/jmp), raw candidates
recorded and boundary-verified, the single
phantom (a byte inside the close call's
displacement at 0x5ce069e) rejected;
.rela.dyn/.rela.plt addend census;
whole-file imm64 census for every graph body
start; a byte-pattern census of the tag-3
store inside the ctor; register-write scans
for the R3 compare's two operands; a census
of the ctor's reads through its config
pointer; instruction byte pins at every
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
WORK_ITEM = 'RE-005-node115-tag3-supply'
SNAPSHOT = 'node/115'

OWNERS = {
    'driver_ctor': (0x5CE01F0, 0x5CE084B),
    'signal_attach': (0x5CE71F0, 0x5CE7374),
    'builder': (0x5CF9600, 0x5CFA8B1),
    'cfg_ctor': (0x5CF93F0, 0x5CF959F),
    'poll_new': (0x5CEEAe0, 0x5CEED20),
}
PINNED_BODIES = {
    'wrapper_a': (0x15D6FD0, 0x15D8447),
    'wrapper_b': (0x2AE1690, 0x2AE27B2),
    'lazy_init': (0x5CDF582, 0x5CDF5C7),
    'builder_precall': (0x5CF5DB0, 0x5CF60AF),
}
ALL_BODIES = dict(OWNERS)
ALL_BODIES.update(PINNED_BODIES)
BODY_SHA256 = {
    'driver_ctor':
        '90919826d6842d84b3b1229420978c82d49b767f5c609650b'
        '17c3785a73e0cba',
    'signal_attach':
        '53d22092e6cf21707c22a3c004e2ef4ea4089a642db1c457'
        'f340b535b17853a9',
    'builder':
        '12813161d76cb5aa11039d12cbbf45d6f170b2aa53da586df'
        '8e03b579e02d13b',
    'cfg_ctor':
        '9736d15280792f960bb0b52a53ff015185c0ac78b5f3a7f4'
        'daaf0387ead23680',
    'poll_new':
        'fa4bb2a034f3b5d5d1ca3569b76fdb6e4d59bd32a3a9f2c7'
        '01bf9abd7bfa9a64',
    'wrapper_a':
        '0a33a4e33944ad1377a8544831780bcc081401ce3f7d5e86'
        'c33606c88ff44d8c',
    'wrapper_b':
        '6ca0595c13836bca0cb0173bd591a09d6da6791532e23a5a'
        '71c63715380727d9',
    'lazy_init':
        'eb1d96c653d04893807aa124709186466dce90119c8472d3'
        '7a896b9f12380a57',
    'builder_precall':
        '59b3791ae5ccc42304f0f0c45734387c46d1f782722f398c'
        'ef3bb146abb9d3f0',
}
EXPORTED = list(OWNERS)

BUILDER_GOT_SLOT = 0x64E1760
TAIL = 0x5CE06A0

CENSUS_EXPECT = {
    'driver_ctor': {'calls': ['0x5cf9669', '0x5cf96eb'],
                    'jmps': []},
    'signal_attach': {'calls': ['0x5ce02bd'], 'jmps': []},
    'poll_new': {'calls': ['0x5ce0218'], 'jmps': []},
    'cfg_ctor': {'calls': ['0x15d7007', '0x15d70a3',
                           '0x2ae16d1'],
                 'jmps': []},
    'builder': {'calls': [], 'jmps': []},
}
GOT_CALL_EXPECT = [
    {'site': '0x15d7026', 'body': 'wrapper_a'},
    {'site': '0x15d70c2', 'body': 'wrapper_a'},
    {'site': '0x2ae16f2', 'body': 'wrapper_b'},
]
TAIL_CENSUS_EXPECT = {
    'raw_candidates': ['0x5ce022c', '0x5ce0670', '0x5ce069e'],
    'verified': {'0x5ce022c': 'jo', '0x5ce0670': 'je'},
    'fallthrough': {'predecessor': '0x5ce069a',
                    'predecessor_text': 'call',
                    'lands_on': '0x5ce06a0'},
}
TAG3_STORE_EXPECT = ['0x5ce06a4']
CFG_READS_EXPECT = ['0x5ce0207', '0x5ce0211', '0x5ce03f6']
RCX_WRITES_SPAN_EXPECT = ['0x5ce02c2', '0x5ce0377',
                          '0x5ce0442', '0x5ce0482',
                          '0x5ce066a']
RCX_WRITES_BLOCK_EXPECT = []
RDX_WRITES_SPAN_EXPECT = []

PINS = {
    # driver_ctor: variant dispatch and Poll::new entry
    0x5CE0207: '807e0800',
    0x5CE020B: '0f8421010000',
    0x5CE0218: 'e8c3e80000',
    0x5CE0229: '48f7d9',
    0x5CE022C: '0f806e040000',
    # driver_ctor: signal-attach result check (R2/R3 split)
    0x5CE02BD: 'e82e6f0000',
    0x5CE02C2: '48b90000000000000080',
    0x5CE02CC: '488b542470',
    0x5CE02D1: '4c8b7c2478',
    0x5CE02D6: '4839ca',
    0x5CE02D9: '0f8564020000',
    # driver_ctor: R2 cleanup head and tail
    0x5CE02DF: '8b7c2440',
    0x5CE02F1: '0f8484030000',
    0x5CE067B: '488b742410',
    0x5CE0696: '8b7c2444',
    0x5CE069A: 'ff15d8f77f00',
    # driver_ctor: tag read and the shared install exit
    0x5CE03F6: '41807c240901',
    0x5CE053E: 'e968010000',
    # driver_ctor: post-registration block (R3)
    0x5CE05CA: '48899424c8000000',
    0x5CE05D2: '4c89bc24d0000000',
    0x5CE05E6: '488b4208',
    0x5CE0603: 'f0480fb17208',
    0x5CE060B: '488b8424c8000000',
    0x5CE0613: '4c8bbc24d0000000',
    0x5CE066A: '48ffc1',
    0x5CE066D: '4839c8',
    0x5CE0670: '742e',
    # driver_ctor: the tag-3 tail itself
    0x5CE06A0: '4c897b08',
    0x5CE06A4: '48c70303000000',
    # signal_attach: global signal state and dup/register
    0x5CE7203: '8b052f7c8100',
    0x5CE7211: '8b3d0d7c8100',
    0x5CE7217: 'be06040000',
    0x5CE721C: 'ba03000000',
    0x5CE7223: 'ff15ef178000',
    0x5CE7230: 'c744240c01200080',
    0x5CE7238: '48c7442410010000',
    0x5CE7241: '418b7f40',
    0x5CE7251: 'ff1569a07f00',
    0x5CE725F: 'bf10000000',
    0x5CE7285: '0f104b10',
    0x5CE728E: '410f1106',
    0x5CE7292: '49894620',
    0x5CE7296: '41896e28',
    0x5CE729A: 'eb46',
    # signal_attach: failure exit 1 (fcntl)
    0x5CE72A4: '48c1e020',
    0x5CE72A8: '4883c802',
    0x5CE72AC: '49894608',
    0x5CE72B0: '48b80000000000000080',
    0x5CE72BA: '498906',
    # signal_attach: failure exit 2 (epoll_ctl)
    0x5CE72F8: '48c1e020',
    0x5CE72FC: '4883c802',
    0x5CE7300: '49894608',
    0x5CE7304: '48b80000000000000080',
    0x5CE730E: '498906',
    # signal_attach: lazy-init of the global state
    0x5CE7323: '488d3df67a8100',
    0x5CE732A: 'e85382ffff',
    # poll_new: failure exit 1 (epoll_create1)
    0x5CEEB95: 'ff152d147f00',
    0x5CEEB9D: '48c1e020',
    0x5CEEBA1: '4883c802',
    0x5CEEBA5: '49894608',
    0x5CEEBA9: '48b80000000000000080',
    0x5CEEBB3: '498906',
    # poll_new: failure exit 2 (eventfd), shared encoder
    0x5CEEBD4: '49c1e720',
    0x5CEEBD8: '4983cf02',
    0x5CEEBDC: '4d897e08',
    0x5CEEBE0: '48b80000000000000080',
    0x5CEEBEA: '498906',
    # poll_new: failure exit 3 (epoll_ctl)
    0x5CEEC0F: '48c1e020',
    0x5CEEC13: '4883c802',
    0x5CEEC17: '49894608',
    0x5CEEC1B: '48b80000000000000080',
    0x5CEEC25: '498906',
    # builder: config selection and cfg assembly, site 1
    0x5CF961E: '80bee400000001',
    0x5CF9627: '41833e01',
    0x5CF9635: '410fb786e5000000',
    0x5CF9645: '498b5660',
    0x5CF9649: '6689442478',
    0x5CF964E: 'c644247a01',
    0x5CF9653: '884c247b',
    0x5CF9657: '48895424',
    0x5CF9669: 'e8826bfeff',
    0x5CF967E: '4983fc03',
    0x5CF9688: 'b802000000',
    0x5CF968D: 'b908',
    0x5CF9692: 'e92e0b0000',
    0x5CF9697: 'e814c7ffff',
    # builder: cfg assembly and conversion, site 2
    0x5CF96A9: '410fb78ee5000000',
    0x5CF96B9: '498b7660',
    0x5CF96BD: '66898c2438070000',
    0x5CF96C5: '8884243a07',
    0x5CF96CC: '8894243b07',
    0x5CF96D3: '4889b42430',
    0x5CF96EB: 'e8006bfeff',
    0x5CF9700: '4983fc03',
    0x5CF970A: '4c897b08',
    0x5CF970E: '48c70302000000',
    # builder: site 1 shared error stores
    0x5CFA1C5: '4c893c0b',
    0x5CFA1C9: '488903',
    # cfg_ctor: the fixed defaults
    0x5CF948E: '4088abe4000000',
    0x5CF949F: '48894320',
    0x5CF94A3: '48c7436000040000',
    0x5CF94AB: '48c70300000000',
    0x5CF9521: 'c783e500000000000000',
    # wrapper A, arm 1 (config flavour 1)
    0x15D7002: 'be01000000',
    0x15D7007: 'e8e4237204',
    0x15D700C: '66c78424f50500000101',
    0x15D7026: 'ff1534a7f004',
    0x15D7039: '83bc244001000002',
    0x15D7041: '0f84f2010000',
    # wrapper A, arm 2 (config flavour 0)
    0x15D70A1: '31f6',
    0x15D70A3: 'e848237204',
    0x15D70A8: '66c78424f50500000101',
    0x15D70C2: 'ff1598a6f004',
    0x15D70C8: '83bc244001000002',
    0x15D70D0: '0f8426010000',
    # wrapper B (config flavour 1)
    0x2AE16CC: 'be01000000',
    0x2AE16D1: 'e81a7d2103',
    0x2AE16D6: '66c78424150200000101',
    0x2AE16F2: 'ff156800a003',
    0x2AE16F8: '83bc24a85a000002',
    0x2AE1700: '0f84cd000000',
}

FINDINGS = {
    'question': (
        'Which build / call path supplies the '
        'tag-3 arm of driver_ctor 0x5ce01f0, left '
        'open as edge 1 of the time-context '
        'writers packet (#2948)?'),
    'answer': (
        'SETTLED, with the premise corrected.  '
        'The tag-3 arm is not a wrapper of an '
        'already-built context: the tail at '
        '0x5ce06a0 writes only [out] = 3 and '
        '[out+8] = r15 and touches no driver '
        'field -- it is the constructor\'s '
        'failure encoding.  Its whole supply is '
        'two OS-failure routes inside the poll '
        'variant, both carrying '
        '(errno << 32) | 2 in [out+8], reached '
        'from runtime builds that all drive the '
        'poll variant with time enabled.  The '
        'builder converts a ctor tag-3 into its '
        'own error {[+0] = 2, [+8] = error '
        'word}, and the wrappers divert on that '
        'tag, so a tag-3 outcome surfaces as a '
        'runtime-build failure: no caller ever '
        'receives a tag-3 context.'),
    'variant_gate': (
        'Only the poll variant reaches the '
        'tail.  cmpb $0, cfg+8 at 0x5ce0207 / '
        'je 0x5ce0332 at 0x5ce020b sends the '
        'variant-0 arm straight to the shared '
        'install sequence; the all-encoding '
        'branch census into 0x5ce06a0, '
        'boundary-verified against the ctor\'s '
        'own disassembly, is exactly jo '
        '0x5ce022c and je 0x5ce0670 plus the '
        'fall-through from the close call at '
        '0x5ce069a -- all in the poll path.  '
        'The raw candidate at 0x5ce069e is a '
        'byte inside that call\'s displacement '
        'and fails boundary verification.'),
    'route_r1_poll_new_failure': (
        'Poll::new 0x5ceeae0 fails (epoll_create1 '
        '/ eventfd / epoll_ctl): the ctor loads '
        'its word0, neg at 0x5ce0229 overflows '
        'exactly on INT64_MIN and jo 0x5ce022c '
        'jumps to the tail with r15 = word1.  '
        'All three Poll::new error exits write '
        '{INT64_MIN, (errno << 32) | 2} (encoder '
        'pins at 0x5ceeb9d..0x5ceebb3, shared '
        'encoder 0x5ceebd4..0x5ceebea, '
        '0x5ceec0f..0x5ceec25) and close their '
        'own partial fds, so [out+8] = '
        '(errno << 32) | 2.'),
    'route_r2_attach_failure': (
        'The signal-attach body 0x5ce71f0 '
        'lazily initialises a global signal '
        'state (flag dword 0x64fee38, fd dword '
        '0x64fee24, object 0x64fee20, via '
        'lazy_init 0x5cdf582), dups the global '
        'fd with fcntl(F_DUPFD_CLOEXEC = 0x406, '
        'min 3) through GOT slot 0x64e8a18 and '
        'registers the dup on the poll\'s epoll '
        'through slot 0x64e12c0 (event flags '
        '0x80002001, data 1), then wraps the '
        'registration in a fresh 0x10-byte Arc '
        'and copies the poll pair plus '
        '{+0x20 = Arc, +0x28 = dup fd} into its '
        'result.  Its two failure exits write '
        '{INT64_MIN, (errno << 32) | 2} '
        '(0x5ce72a4..0x5ce72ba for the fcntl '
        'failure, 0x5ce72f8..0x5ce730e for the '
        'epoll_ctl failure).  The ctor\'s cmp '
        'at 0x5ce02c2..0x5ce02d6 catches word0 '
        '== INT64_MIN, falls through to the '
        'cleanup (dup fd close at 0x5ce02df, '
        'registry Vec element drop loop, buffer '
        'free and eventfd close at '
        '0x5ce067b..0x5ce069a) and falls through '
        'to the tail with r15 = the same error '
        'word.'),
    'route_r3_value_unreachable': (
        'The je at 0x5ce0670 sits in the '
        'post-registration block entered only '
        'from the jne at 0x5ce02d9 (attach '
        'success).  The block stashes rdx / r15 '
        'at [rsp+0xc8] / [rsp+0xd0] '
        '(0x5ce05ca / 0x5ce05d2), increments '
        'the registration Arc\'s +8 word with a '
        'lock cmpxchg spin (0x5ce05e6..'
        '0x5ce0609), reloads rax = [rsp+0xc8] '
        'and r15 = [rsp+0xd0], then inc rcx '
        '(0x5ce066a) / cmp rax, rcx '
        '(0x5ce066d).  rcx on this path is the '
        'movabs INT64_MIN of 0x5ce02c2: the '
        'register-write scan finds no rcx write '
        'inside the block before the inc, and '
        'the only other rcx writes in the ctor '
        'span are inside the install sequence, '
        'which this path enters only after the '
        'compare (jmp 0x5ce0676 -> 0x5ce0382).  '
        'rax is the attach word0 -- on success '
        'the Poll::new capacity (0x400 under '
        'the artifact\'s own config), the '
        'failure word having been diverted at '
        '0x5ce02d9; and the rdx-write scan '
        'finds no rdx write between the load '
        'at 0x5ce02cc and the stash, so the '
        'stashed word is the attach word0 '
        'itself.  capacity == INT64_MIN + 1 '
        'can never hold, so the je never '
        'fires; it is a compiler-emitted '
        'counted compare whose exit the real '
        'flow leaves through 0x5ce0676.'),
    'supply_chain': (
        'driver_ctor\'s only callers are the '
        'builder\'s two call sites (0x5cf9669, '
        '0x5cf96eb).  The builder has no direct '
        'callers; its only pointer reference is '
        'the .rela.dyn type-8 addend at GOT '
        'slot 0x64e1760, and its start\'s only '
        'imm64 occurrence in the whole file is '
        'that addend field.  The slot is called '
        'at exactly three sites: 0x15d7026 and '
        '0x15d70c2 in the wrapper body under '
        'FDE 0x15d6fd0..0x15d8447, and '
        '0x2ae16f2 under FDE '
        '0x2ae1690..0x2ae27b2.'),
    'config_supply': (
        'cfg_ctor 0x5cf93f0\'s only callers '
        'are the same three wrapper sites.  It '
        'writes the flavour argument to '
        '[bcfg+0xe4] (0x5cf948e), '
        'INT64_MIN to [bcfg+0x20], '
        'capacity 0x400 to [bcfg+0x60] '
        '(0x5cf94a3), 0 to [bcfg+0] '
        '(0x5cf94ab) and 0 to the dword at '
        '[bcfg+0xe5] (0x5cf9521).  Each wrapper '
        'then stores the u16 constant 0x0101 '
        'at bcfg+0xe5 (0x15d700c, 0x15d70a8, '
        '0x2ae16d6): variant byte 1, tag byte '
        '1.  The builder assembles the ctor '
        'config from [bcfg+0x60] (word0) and '
        'the u16 at [bcfg+0xe5] (cfg+8), with '
        'cfg+0xa = 1 at site 1 (0x5cf964e) and '
        '0 at site 2 (0x5cf96c5) and cfg+0xb = '
        '[bcfg+0xe7]; path (b) to site 2 first '
        'calls builder_precall 0x5cf5db0 '
        '(0x5cf9697), selected because '
        '[bcfg+0] = 0 != 1 (cmp at 0x5cf9627).  '
        'The ctor\'s reads through its config '
        'pointer are exactly cfg+8 (variant, '
        '0x5ce0207), cfg word0 (0x5ce0211) and '
        'cfg+9 (tag, 0x5ce03f6).'),
    'conversion': (
        'At builder site 1 a ctor tag of 3 '
        '(cmp 0x5cf967e) loads eax = 2 and ecx '
        '= 8 (0x5cf9688 / 0x5cf968d) and jumps '
        'to the shared stores {[out+8] = r15, '
        '[out] = 2} at 0x5cfa1c5 / 0x5cfa1c9; '
        'at site 2 the stores are inline '
        '(0x5cf970a / 0x5cf970e).  Both '
        'wrappers compare the builder '
        'result\'s tag against 2 and jump to '
        'their own error paths (0x15d7039 / '
        '0x15d7041, 0x15d70c8 / 0x15d70d0, '
        '0x2ae16f8 / 0x2ae1700).  A tag-3 '
        'outcome surfaces as a runtime-build '
        'failure; no caller receives a tag-3 '
        'context, nothing is installed from '
        'one, and re-initialisation of a '
        'wrapped context cannot arise.'),
}

OPEN_EDGES = [
    'The two wrapper bodies\' source-level '
    'identity (which node subsystem\'s runtime '
    'build each is) is not pinned: no Location '
    'static for either was recovered in this '
    'packet.  The claim is limited to the call '
    'graph, their three builder call sites and '
    'the config bytes they write.',
    'cfg+0xa (1 at builder site 1, 0 at site 2) '
    'and cfg+0xb (= [bcfg+0xe7], 0 under the '
    'artifact\'s own config constructor) are '
    'assembled into the ctor config but never '
    'read by the ctor; their consumer, if any, '
    'is outside this question.',
    'The builder\'s [bcfg+0] == 1 arm '
    '(r13 = [bcfg+8], no builder_precall) is '
    'not supplied by the artifact\'s own '
    'config constructor, which writes 0 at '
    '[bcfg+0]; whether a config built outside '
    'the artifact could select it is outside '
    'the artifact and not claimed.',
    'The producer of the global signal state '
    '(what creates the fd published at '
    '0x64fee24 before lazy_init 0x5cdf582 '
    'runs) is not traced; this packet pins '
    'only the attach body\'s use of it.',
    'Why the compiler emits a counted compare '
    'against INT64_MIN + 1 in the '
    'post-registration block is stated at '
    'byte level only; the value-unreachability '
    'of route R3 does not depend on the '
    'source-level shape.',
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


def got_slot_census(data, extents):
    """Every FF 15 indirect call in .text whose resolved
    target is the builder's GOT slot, boundary-verified
    against its containing FDE body's disassembly."""
    raw_hits = set()
    for section in sections(data):
        if section['name'] != '.text':
            continue
        base = section['address']
        blob = data[section['offset']:section['offset']
                    + section['size']]
        pos = 0
        while True:
            idx = blob.find(b'\xff\x15', pos)
            if idx < 0:
                break
            pos = idx + 1
            if idx + 6 > len(blob):
                continue
            disp = struct.unpack_from('<i', blob, idx + 2)[0]
            if base + idx + 6 + disp == BUILDER_GOT_SLOT:
                raw_hits.add(base + idx)
    by_start = {start: (role, (start, end))
                for role, (start, end) in ALL_BODIES.items()}
    out = []
    cache = {}
    for va in sorted(raw_hits):
        extent = None
        for start, end in extents:
            if start <= va < end:
                extent = (start, end)
                break
        if extent is None:
            continue
        if extent not in cache:
            cache[extent] = disasm_rows(data, *extent)
        row = cache[extent].get(va)
        if row is None:
            continue
        raw, text = row
        if raw[:2] != b'\xff\x15' or \
                not text.startswith('call'):
            continue
        role = by_start.get(extent[0], (None, None))[0]
        out.append({'site': hex(va), 'body': role})
    return out


def tail_census(data):
    """All-encoding branch census into the ctor tail.
    Raw candidates come from a .text-wide scan of
    rel32 call/jmp/jcc and rel8 jcc/jmp encodings;
    a candidate counts only when the ctor's own
    disassembly has a branch instruction starting
    exactly there.  Mid-instruction phantoms are
    recorded raw and rejected here."""
    raw_hits = set()
    for section in sections(data):
        if section['name'] != '.text':
            continue
        base = section['address']
        blob = data[section['offset']:section['offset']
                    + section['size']]
        # rel32 forms: find-based scan of the whole .text.
        for opcode in (0xE8, 0xE9):
            pos = 0
            while True:
                idx = blob.find(bytes([opcode]), pos)
                if idx < 0:
                    break
                pos = idx + 1
                if idx + 5 > len(blob):
                    continue
                disp = struct.unpack_from('<i', blob, idx + 1)[0]
                if base + idx + 5 + disp == TAIL:
                    raw_hits.add(base + idx)
        pos = 0
        while True:
            idx = blob.find(b'\x0f', pos)
            if idx < 0:
                break
            pos = idx + 1
            if idx + 6 > len(blob) or \
                    not 0x80 <= blob[idx + 1] <= 0x8F:
                continue
            disp = struct.unpack_from('<i', blob, idx + 2)[0]
            if base + idx + 6 + disp == TAIL:
                raw_hits.add(base + idx)
        # rel8 forms reach at most 127 bytes, and the
        # tail sits inside the ctor with more than 127
        # bytes of ctor on both sides, so every rel8
        # origin lies inside the ctor body itself.
        cstart, cend = OWNERS['driver_ctor']
        cbase = cstart - base
        for i in range(cbase, cbase + (cend - cstart) - 1):
            b = blob[i]
            if 0x70 <= b <= 0x7F or b == 0xEB:
                disp = struct.unpack_from('<b', blob, i + 1)[0]
                if base + i + 2 + disp == TAIL:
                    raw_hits.add(base + i)
    rows = disasm_rows(data, *OWNERS['driver_ctor'])
    verified = {}
    for va in sorted(raw_hits):
        row = rows.get(va)
        if row is None:
            continue
        raw, text = row
        if raw[0] in (0xE8, 0xE9) or \
                (raw[0] == 0x0F and 0x80 <= raw[1] <= 0x8F) or \
                0x70 <= raw[0] <= 0x7F or raw[0] == 0xEB:
            verified[hex(va)] = text.split()[0]
    pred = rows.get(0x5CE069A)
    if pred is None:
        raise AssertionError('tail fall-through pred missing')
    praw, ptext = pred
    if not ptext.startswith('call') or \
            0x5CE069A + len(praw) != TAIL:
        raise AssertionError('tail fall-through shape drift')
    return {
        'raw_candidates': [hex(v) for v in sorted(raw_hits)],
        'verified': verified,
        'fallthrough': {
            'predecessor': '0x5ce069a',
            'predecessor_text': ptext.split()[0],
            'lands_on': hex(TAIL)},
    }


def tag3_store_census(data):
    start, end = OWNERS['driver_ctor']
    blob = read(data, start, end - start)
    pattern = bytes.fromhex('48c70303000000')
    hits = []
    pos = 0
    while True:
        idx = blob.find(pattern, pos)
        if idx < 0:
            break
        hits.append(hex(start + idx))
        pos = idx + 1
    rows = disasm_rows(data, start, end)
    return [h for h in hits if int(h, 16) in rows]


def _writes_reg(text, regs):
    t = text.strip()
    for prefix in ('lock ', 'rep ', 'repz ', 'repnz '):
        if t.startswith(prefix):
            t = t[len(prefix):]
    mnemonic = t.split(' ', 1)[0]
    if mnemonic in ('cmp', 'test', 'push', 'call', 'jmp',
                    'ret') or mnemonic.startswith('j'):
        return False
    if ',' in t:
        return t.rsplit(',', 1)[1].strip() in regs
    parts = t.split(' ', 1)
    return len(parts) == 2 and parts[1].strip() in regs


def reg_write_scan(data, lo, hi, regs):
    rows = disasm_rows(data, *OWNERS['driver_ctor'])
    return [hex(va) for va in sorted(rows)
            if lo <= va < hi and _writes_reg(rows[va][1], regs)]


def cfg_reads(data):
    rows = disasm_rows(data, *OWNERS['driver_ctor'])
    return [hex(va) for va in sorted(rows)
            if '(%r12)' in rows[va][1] or '0x8(%rsi)' in
            rows[va][1]]


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
            entries.append((r_off, r_info & 0xFFFFFFFF,
                            r_add, off + 16))
    return entries


def rela_hits(data):
    starts = {start for start, _ in ALL_BODIES.values()}
    hits = []
    for off, typ, add, add_file_off in parse_rela(data):
        if typ == 8 and add in starts:
            hits.append({'offset': hex(off),
                         'addend': hex(add),
                         'addend_file_offset':
                             hex(add_file_off)})
    return hits


def imm64_census(data):
    out = {}
    for role, (start, _end) in sorted(ALL_BODIES.items()):
        needle = struct.pack('<Q', start)
        hits = []
        pos = 0
        while True:
            idx = data.find(needle, pos)
            if idx < 0:
                break
            hits.append(hex(idx))
            pos = idx + 1
        out[role] = hits
    return out


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
    got_calls = got_slot_census(data, extents)
    if got_calls != GOT_CALL_EXPECT:
        raise AssertionError(
            f'GOT slot census drift: {got_calls}')
    tail = tail_census(data)
    if tail != TAIL_CENSUS_EXPECT:
        raise AssertionError(f'tail census drift: {tail}')
    stores = tag3_store_census(data)
    if stores != TAG3_STORE_EXPECT:
        raise AssertionError(
            f'tag-3 store census drift: {stores}')
    reads = cfg_reads(data)
    if reads != CFG_READS_EXPECT:
        raise AssertionError(f'cfg reads drift: {reads}')
    rcx_span = reg_write_scan(
        data, 0x5CE02C2, 0x5CE0672,
        {'%rcx', '%ecx', '%cl', '%ch'})
    if rcx_span != RCX_WRITES_SPAN_EXPECT:
        raise AssertionError(f'rcx span drift: {rcx_span}')
    rcx_block = reg_write_scan(
        data, 0x5CE0543, 0x5CE066A,
        {'%rcx', '%ecx', '%cl', '%ch'})
    if rcx_block != RCX_WRITES_BLOCK_EXPECT:
        raise AssertionError(f'rcx block drift: {rcx_block}')
    rdx_span = reg_write_scan(
        data, 0x5CE02CD, 0x5CE05CA,
        {'%rdx', '%edx', '%dl', '%dh'})
    if rdx_span != RDX_WRITES_SPAN_EXPECT:
        raise AssertionError(f'rdx span drift: {rdx_span}')
    hits = rela_hits(data)
    expect_hits = [{'offset': hex(BUILDER_GOT_SLOT),
                    'addend': hex(OWNERS['builder'][0]),
                    'addend_file_offset': hits[0][
                        'addend_file_offset']}] if hits else []
    if len(hits) != 1 or hits != expect_hits:
        raise AssertionError(f'rela census drift: {hits}')
    imm = imm64_census(data)
    for role, found in imm.items():
        if role == 'builder':
            if found != [hits[0]['addend_file_offset']]:
                raise AssertionError(
                    f'builder imm64 census drift: {found}')
        elif found:
            raise AssertionError(
                f'imm64 census drift for {role}: {found}')
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
        'builder_got_slot': {
            'slot': hex(BUILDER_GOT_SLOT),
            'indirect_calls': got_calls,
            'rela': hits,
            'imm64_occurrences': imm,
        },
        'tail_census': tail,
        'tag3_store_census': stores,
        'cfg_read_census': reads,
        'register_writes': {
            'rcx_ctor_span_0x5ce02c2_0x5ce0672': rcx_span,
            'rcx_block_0x5ce0543_0x5ce066a': rcx_block,
            'rdx_span_0x5ce02cd_0x5ce05ca': rdx_span,
        },
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


OUT = ROOT / 'research' / 'work-items' / WORK_ITEM


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
