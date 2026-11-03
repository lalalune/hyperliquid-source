#!/usr/bin/env python3
"""RE-005: digest-bound node115 reader-state construction trace.

Answers the next question of the open field1-5 caller-arguments
packet (PR #2433): who first writes the reader state's mode field
(+0x0) and limit field (+0x8) for the states the field1-5 decoders
consume, and how the registration helpers 0x232cd90 / 0x58251a0
invoke the twin decoders 0x26e5710 / 0x5aaa460.

State construction. Each of the four #2433 caller functions is
reached through exactly one chain of direct callers, and each chain
ends at a constructor that builds the 0x28-byte reader state on its
own stack and passes its address down:

- bulk copy a (0x2cd9710): 0x2ce1dc0 <- 0x2ceaf00 <- constructor
  0x26fe940, which stores mode = 1 (immediate), limit = its entry
  rcx, cursor = its entry rsi, remaining = its entry rdx,
  charged = 0 (immediate) at rsp+0x20 at three identical sites.
- twin a (0x26e5710): 0x2e466b0 <- constructor 0x26ff210, same five
  stores at rsp+0x70 (two sites) and rsp+0x98 (one site); mode = 1,
  charged = 0, limit = entry rcx (at the third site the limit
  register may first be reloaded from an earlier stage result's
  +0x28 field; the mode and charged stores are immediate on every
  path).
- bulk copy b (0x5968840): 0x4e05c10 <- 0x582b520 <- constructor
  0x5821aa0, which builds the state at rsp+0x18 from its own
  arguments (mode = arg rcx, limit = arg r8, cursor = arg rsi,
  remaining = arg rdx, charged = 0); its only caller 0x4e483d0
  passes mode = 1 (immediate at all three sites) and limit =
  [[view+0x10]] of its entry view argument.
- twin b (0x5aaa460): 0x5aac7c0 <- constructor 0x4e465a0, which
  stores mode = 1 (immediate), limit = [[view+0x10]], cursor =
  [view+0x0], remaining = [view+0x8], charged = 0 at rsp+0x58 at
  three sites.

The mode is therefore the constant 1 at all twelve construction
sites. The limit is never a constant: on the two copy-a spines it
is a qword loaded from the top dispatcher's context object
([rbx+0x220] / [rbx+0x180]); on the two copy-b spines it is the
value a view builder (0x5860cd0 / 0x58606f0) received in rcx and
forwarded by pointer through the view's +0x10 field (for twin b
that rcx is itself loaded from [rbx+0xa60] by the top caller
0x5a6a640). Who writes those context fields sits above the traced
window and is recorded as a boundary.

Twin registration. The helpers 0x232cd90 / 0x58251a0 are codegen
twins (578 bytes each; the bodies differ only in nine 4-byte
displacement fields). Each takes (rdi = out, rsi = state,
rdx = element decoder). It reads a count with the u64 reader
(copy a 0x2cd7ac0 / copy b 0x5821250) on the state; if the state
mode is nonzero it charges count * 0x18 against the state (stored
before the limit compare; refusal is a result with rawtag 2);
allocates min(count, 0xaaaa) * 0x18 bytes through the slot at
0x64df480; then per element refunds 0x18 from the charged count
(panicking through the slot at 0x64df848 if fewer than 0x18
remain) and calls the decoder through the saved rdx register
with (element result buffer, the same state). The 0x18-byte
element is copied out of the decoder result (+0x8) into the
vector; on a decoder error the error result is copied out and
the vector freed through the slot at 0x64df4a0. The twins are
therefore invoked only through these helpers, with exactly the
constructed states above: the wrappers 0x2dd2980 / 0x4de6210
load the twin address in rdx and forward their own entry state
unchanged, and the forwarders above them do the same.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-005-node115-state-construction'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
OWNERS = {
 'ctor_bulk_a': (0x26fe940, 0x26ff205,
            '3b4aa6a35db664697f92a85f65eb18896530076c50668b5457d28de0e48f71ce'),
 'ctor_twin_a': (0x26ff210, 0x26ff830,
            'b96ec36847823c98c649950413f331a366379f343daa14bfd7606d1c70591923'),
 'ctor_bulk_b': (0x5821aa0, 0x5821f27,
            '0cc3e394fb191b147639ea1cdf21d9250286f083c9d0358fc40adf85623d2813'),
 'ctor_bulk_b_mode': (0x4e483d0, 0x4e48752,
            '9593d1542d322337de47ae62409503eb0ed325fcad84bdcb3e49bf2902922959'),
 'ctor_twin_b': (0x4e465a0, 0x4e46b47,
            '875ebfbb9c3ce53df0bc6082737fbb05f2e90a87aadb7ed3114435708251620e'),
 'helper_a': (0x232cd90, 0x232cfd2,
            '4e7fa3b1af1e78b478b3f30191fa1aabb2f0a79610903797425e6f08d83606a0'),
 'helper_b': (0x58251a0, 0x58253e2,
            'f8e5d7170bcb8c8519bb4e6cb13469ef6b0891adb646e13fffc0e2a0e8f588f2'),
 'fwd_bulk_a_high': (0x2ceaf00, 0x2ceb298,
            '5288c828b35a6df2555f62523b6da30212001bfdbfdc6fe18968bc75718e1906'),
 'fwd_bulk_a_low': (0x2ce1dc0, 0x2ce2a32,
            'cd911f8ed1f3b4a35e300c9db6663f1ace78c7a8e85cf0340b36a22bf1345f89'),
 'fwd_twin_a': (0x2e466b0, 0x2e469a9,
            'e83dbe8a5a053e1c87c7d7ca300a681891cb1a58bf2ac5303c8acc01159ca8e1'),
 'fwd_bulk_b_high': (0x582b520, 0x582bce8,
            'a374513d243517dcbf4142c01cc9dbf74a05c50d9df0bad9348decc03aad0d57'),
 'fwd_bulk_b_low': (0x4e05c10, 0x4e05dd8,
            '4a4ab6e48d56b52cc42948beec94eecd1f2a2d459b1f95132ed22d9d57e73359'),
 'fwd_twin_b': (0x5aac7c0, 0x5aacc22,
            '3e0159ca16b60928de905e585f823776c42d39b592da8d78895ba5644a335668'),
 'wrap_twin_a': (0x2dd2980, 0x2dd2bd7,
            '048b0a68792000a2b9d24c069210e14d88dfd9a4556de276a873febbd69e0dae'),
 'wrap_twin_b': (0x4de6210, 0x4de6467,
            '4c4a67c315fcc1c353b0e5ab8d38d24bec66c6683efb5ed1808d499f8859687e'),
 'view_bulk_b': (0x5860cd0, 0x5860e04,
            '91500a83aa18f1645a93460d4b35f3bb4cfe67b9ea69dba3e9ce150aa688288c'),
 'view_twin_b': (0x58606f0, 0x586082d,
            'fb4d2da25247c044ca16c3e1a631120ae3955d878327ecd1ef80a87015494700')}
TWIN_A = 0x26e5710
TWIN_B = 0x5aaa460
BULK_A = 0x2cd9710
BULK_B = 0x5968840
U32_A = 0x2cd79c0
U32_B = 0x5821150
U64_A = 0x2cd7ac0
U64_B = 0x5821250
# GOT slots used by the twin helpers; each carries one
# R_X86_64_RELATIVE relocation whose addend is the target below.
SLOTS = {0x64df480: 0x6355830,   # allocation (size in rdi)
         0x64df498: 0x141e264,   # allocation-failure handler
         0x64df4a0: 0x635de30,   # deallocation (ptr, size, align)
         0x64df848: 0x1681e40,   # panic handler (then ud2)
         0x64e5008: 0x59621c0}   # vector growth (vec ptr in rdi)
PANIC_STRINGS = {'helper_a': 0x642e2a0,
                 'helper_b': 0x64b0ff0}
TOP_FDES = {'top_bulk_a': (0x2b67e50, 0x2b69279),
            'top_twin_a': (0x2b69d20, 0x2b6ae9f),
            'top_bulk_b': (0x5a64aa0, 0x5a69c05),
            'top_twin_b': (0x5a6a640, 0x5a6bfaa)}
LIMITS = (
 'Static trace only: no pinned bytes were executed and no live node, '
 'network, signer, or exchange state was used. The reader state is '
 'the five-field layout of the field1-5 reader packet (mode +0x0, '
 'limit +0x8, cursor +0x10, remaining +0x18, charged count +0x20). '
 'Mode and charged values are the immediate constants stored by the '
 'constructors on every traced path. The limit values are runtime '
 'qwords: on the copy-a spines a field of the top dispatcher\'s '
 'context object, on the copy-b spines a value forwarded by '
 'pointer through a view struct; who writes those fields is above '
 'the traced window and is a stated boundary, as is the writer of '
 'the +0x28 result field that the twin-a constructor\'s third site '
 'may reload its limit register from. Rawtag and result values are '
 'raw bytes; which Rust enum variants they name is not established. '
 'The slot targets are identified by argument shape only '
 '(allocation, deallocation, growth, panic, allocation failure); '
 'no symbol names are claimed for them. No Rust reconstruction is '
 'included or claimed.')


def read(data, va, n):
    matches = [s for s in sections(data) if s['type'] != 8
               and s['address'] <= va and va + n <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('expected one file-backed mapping')
    s = matches[0]
    o = s['offset'] + va - s['address']
    return o, bytes(data[o:o + n])


def require(condition, message):
    if not condition:
        raise ValueError(message)


def relocations(data):
    sec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    by_offset = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, off)
        by_offset.setdefault(r_offset, []).append(
         (r_info & 0xffffffff, r_info >> 32, r_addend))
    return by_offset


def pin(body, rel, expected, message):
    require(body[rel:rel + len(expected)] == expected,
            f'{message} changed')


def call_target(body, rel, base):
    return base + rel + 5 + struct.unpack_from('<i', body, rel + 1)[0]


def slot_at(body, rel, base):
    """Target slot of a call QWORD PTR [rip+disp32] at rel."""
    return base + rel + 6 + struct.unpack_from('<i', body, rel + 2)[0]


def body_of(data, role):
    a, b, _ = OWNERS[role]
    return a, read(data, a, b - a)[1]


def run_pins(data, role, pins):
    base, body = body_of(data, role)
    for rel, hexs, message in pins:
        pin(body, rel, bytes.fromhex(hexs), f'{role} {message}')
    return base, body


def ctor_bulk_a_semantics(data):
    role = 'ctor_bulk_a'
    pins = [
     (0x14, '4989ce', 'limit register r14 is the entry rcx'),
     (0x17, '4989d4', 'remaining register r12 is the entry rdx'),
     (0x1a, '4989f7', 'cursor register r15 is the entry rsi')]
    sites = []
    for rel, call_rel in ((0xc1, 0xef), (0x1e8, 0x216), (0x595, 0x5c3)):
        pins += [
         (rel, '4c897c2430', 'cursor store at state +0x10'),
         (rel + 0x5, '4c89642438', 'remaining store at state +0x18'),
         (rel + 0xa, '48c744242001000000', 'mode store at state +0x0 '
          'is the immediate 1'),
         (rel + 0x13, '4c89742428', 'limit store at state +0x8'),
         (rel + 0x18, '48c744244000000000', 'charged store at state '
          '+0x20 is the immediate 0'),
         (rel + 0x29, '488d742420', 'state argument is rsp+0x20')]
        sites.append(call_rel)
    base, body = run_pins(data, role, pins)
    for call_rel in sites:
        require(call_target(body, call_rel, base) ==
                OWNERS['fwd_bulk_a_high'][0],
                f'{role} downward call target changed')
    return {'state': 'rsp+0x20', 'call_sites': [hex(base + r)
                                                for r in sites],
            'downward_target': hex(OWNERS['fwd_bulk_a_high'][0]),
            'fields': {'mode': 'constant 1 (immediate store)',
                       'limit': 'r14 = entry rcx',
                       'cursor': 'r15 = entry rsi',
                       'remaining': 'r12 = entry rdx',
                       'charged': 'constant 0 (immediate store)'}}


def ctor_twin_a_semantics(data):
    role = 'ctor_twin_a'
    pins = [
     (0x14, '4989cd', 'limit register r13 is the entry rcx'),
     (0x17, '4989d4', 'remaining register r12 is the entry rdx'),
     (0x1a, '4989f6', 'cursor register r14 is the entry rsi'),
     (0x6a, '0f84ff000000', 'site-2 construction is entered only '
      'from this pre-call dispatch branch'),
     (0xfd, '4c8b742410', 'after a stage call the cursor register '
      'is reloaded from the result buffer'),
     (0x120, '4c8b6c2438', 'limit register reload from the stage '
      'result +0x28 field (arm a)'),
     (0x14f, '4c2ba42488000000', 'remaining register adjusted by '
      'the first state remaining after a stage'),
     (0x1ed, '4c8b6c2438', 'limit register reload from the stage '
      'result +0x28 field (arm b)')]
    for rel in (0xc4, 0x16f):
        pins += [
         (rel, '4c89b42480000000', 'cursor store at state +0x10'),
         (rel + 0x8, '4c89a42488000000', 'remaining store at '
          'state +0x18'),
         (rel + 0x10, '48c744247001000000', 'mode store at state '
          '+0x0 is the immediate 1'),
         (rel + 0x19, '4c896c2478', 'limit store at state +0x8'),
         (rel + 0x1e, '48c784249000000000000000', 'charged store '
          'at state +0x20 is the immediate 0'),
         (rel + 0x2f, '488d742470', 'state argument is rsp+0x70')]
    pins += [
     (0x3c9, '4c89b424a8000000', 'third-site cursor store at '
      'state +0x10'),
     (0x3d1, '4c89a424b0000000', 'third-site remaining store at '
      'state +0x18'),
     (0x3d9, '48c784249800000001000000', 'third-site mode store '
      'at state +0x0 is the immediate 1'),
     (0x3e5, '4c89ac24a0000000', 'third-site limit store at '
      'state +0x8'),
     (0x3ed, '48c78424b800000000000000', 'third-site charged '
      'store at state +0x20 is the immediate 0'),
     (0x3fe, '488db42498000000', 'third-site state argument is '
      'rsp+0x98')]
    base, body = run_pins(data, role, pins)
    require(base + 0x6a + 6 + 0xff == base + 0x16f,
            f'{role} site-2 dispatch branch target changed')
    for call_rel in (0xf8, 0x1a3, 0x406):
        require(call_target(body, call_rel, base) ==
                OWNERS['fwd_twin_a'][0],
                f'{role} downward call target changed')
    return {'states': ['rsp+0x70 (sites 1-2)', 'rsp+0x98 (site 3)'],
            'call_sites': [hex(base + r) for r in (0xf8, 0x1a3, 0x406)],
            'downward_target': hex(OWNERS['fwd_twin_a'][0]),
            'fields': {'mode': 'constant 1 (immediate store at '
                               'all three sites)',
                       'limit': 'r13: the entry rcx at sites 1-2 '
                                '(site 2 is entered only from the '
                                'pre-call dispatch branch); at '
                                'site 3, r13 as carried through '
                                'the earlier stages -- the entry '
                                'rcx, or the +0x28 field of an '
                                'earlier stage result where a '
                                'reload arm (0x26ff330 / 0x26ff3fd) '
                                'intervened',
                       'cursor': 'r14: the entry rsi at sites 1-2; '
                                 'at site 3, reloaded from the '
                                 'stage result buffer',
                       'remaining': 'r12: the entry rdx at sites '
                                    '1-2; at site 3, reduced by '
                                    'the first state\'s remaining '
                                    'after stage 1',
                       'charged': 'constant 0 (immediate store at '
                                  'all three sites)'}}


def ctor_bulk_b_semantics(data):
    role = 'ctor_bulk_b'
    base, body = run_pins(data, role, [
     (0x21, '4889742428', 'cursor store at state +0x10 is the '
      'entry rsi'),
     (0x26, '4889542430', 'remaining store at state +0x18 is the '
      'entry rdx'),
     (0x2b, '48894c2418', 'mode store at state +0x0 is the entry '
      'rcx argument'),
     (0x30, '4c89442420', 'limit store at state +0x8 is the entry '
      'r8 argument'),
     (0x35, '48c744243800000000', 'charged store at state +0x20 '
      'is the immediate 0'),
     (0x43, '488d742418', 'u32 reader state argument is rsp+0x18'),
     (0x300, '4c89642428', 'cursor slot rewritten with the '
      'advanced cursor before forwarding'),
     (0x305, '4c897c2430', 'remaining slot rewritten with the '
      'advanced remaining before forwarding'),
     (0x334, '488d742418', 'downward state argument is rsp+0x18')])
    require(call_target(body, 0x48, base) == U32_B,
            f'{role} u32 call target changed')
    require(call_target(body, 0x86, base) == U64_B,
            f'{role} first u64 call target changed')
    require(call_target(body, 0x339, base) ==
            OWNERS['fwd_bulk_b_high'][0],
            f'{role} downward call target changed')
    require(body.count(bytes.fromhex('48894c2418')) == 1,
            f'{role} mode slot stored more than once')
    require(body.count(bytes.fromhex('4c89442420')) == 1,
            f'{role} limit slot stored more than once')
    return {'state': 'rsp+0x18', 'call_site': hex(base + 0x339),
            'downward_target': hex(OWNERS['fwd_bulk_b_high'][0]),
            'fields': {'mode': 'the entry rcx argument (supplied '
                               'as the constant 1 by its only '
                               'caller, see ctor_bulk_b_mode)',
                       'limit': 'the entry r8 argument',
                       'cursor': 'the entry rsi argument, advanced '
                                 'by this constructor\'s own reads '
                                 'before forwarding',
                       'remaining': 'the entry rdx argument, '
                                    'advanced likewise',
                       'charged': 'constant 0 (immediate store)'}}


def ctor_bulk_b_mode_semantics(data):
    role = 'ctor_bulk_b_mode'
    pins = [
     (0x1c, '4c8b26', 'cursor register r12 is view +0x0'),
     (0x1f, '4c8b7e08', 'remaining register r15 is view +0x8'),
     (0x23, '4c8b6e10', 'limit pointer register r13 is '
      'view +0x10')]
    sites = []
    pins += [
     (0xb0, '488b06', 'site 1 cursor argument load is view +0x0'),
     (0xb3, '488b5608', 'site 1 remaining argument load is '
      'view +0x8'),
     (0xb7, '488b4e10', 'site 1 limit pointer load is view +0x10'),
     (0xbb, '4c8b01', 'site 1 limit argument is the dereferenced '
      'view +0x10 pointer'),
     (0xbe, '488d7c2420', 'site 1 result buffer is rsp+0x20'),
     (0xc9, 'b901000000', 'site 1 mode argument is the '
      'immediate 1'),
     (0xce, '4889c6', 'site 1 cursor argument register set')]
    sites.append(0xd1)
    pins += [
     (0x12c, '4d8b4500', 'site 2 limit argument is the '
      'dereferenced view +0x10 pointer (r13)'),
     (0x130, '488d7c2420', 'site 2 result buffer is rsp+0x20'),
     (0x13b, 'b901000000', 'site 2 mode argument is the '
      'immediate 1'),
     (0x140, '4c89e6', 'site 2 cursor argument is r12'),
     (0x143, '4c89fa', 'site 2 remaining argument is r15'),
     (0x225, '4d8b4500', 'site 3 limit argument is the '
      'dereferenced view +0x10 pointer (r13)'),
     (0x229, '488d7c2420', 'site 3 result buffer is rsp+0x20'),
     (0x22e, 'b901000000', 'site 3 mode argument is the '
      'immediate 1'),
     (0x233, '4c89e6', 'site 3 cursor argument is r12'),
     (0x236, '4c89fa', 'site 3 remaining argument is r15')]
    sites += [0x146, 0x239]
    base, body = run_pins(data, role, pins)
    for call_rel in sites:
        require(call_target(body, call_rel, base) ==
                OWNERS['ctor_bulk_b'][0],
                f'{role} constructor call target changed')
    return {'view': 'entry rsi (0x18-byte view)',
            'call_sites': [hex(base + r) for r in sites],
            'mode_argument': 'constant 1 (immediate at all '
                             'three sites)',
            'limit_argument': '[[view+0x10]] (dereferenced at '
                              'every site)',
            'cursor_argument': '[view+0x0]',
            'remaining_argument': '[view+0x8]'}


def ctor_twin_b_semantics(data):
    role = 'ctor_twin_b'
    pins = [
     (0x1c, '4c8b2e', 'cursor register r13 is view +0x0'),
     (0x1f, '4c8b7e08', 'remaining register r15 is view +0x8'),
     (0x23, '488b6e10', 'limit pointer register rbp is '
      'view +0x10'),
     (0xa7, '488b06', 'site 1 cursor load is view +0x0'),
     (0xaa, '4c8b7608', 'site 1 remaining load is view +0x8'),
     (0xae, '488b4e10', 'site 1 limit pointer load is view +0x10'),
     (0xb2, '488b09', 'site 1 limit is the dereferenced pointer'),
     (0x244, '4c2b7c2470', 'remaining register reduced by the '
      'state remaining after site 2')]
    sites = []
    for rel, call_rel, fresh in ((0xb5, 0xe3, True),
                                 (0x190, 0x1be, False),
                                 (0x33b, 0x369, False)):
        if fresh:
            pins += [
             (rel, '4889442468', 'cursor store at state +0x10'),
             (rel + 0x5, '4c89742470', 'remaining store at '
              'state +0x18')]
        else:
            pins += [
             (rel - 0x4, '488b4500', 'limit load is the '
              'dereferenced view +0x10 pointer (rbp)'),
             (rel, '4c896c2468', 'cursor store at state +0x10'),
             (rel + 0x5, '4c897c2470', 'remaining store at '
              'state +0x18')]
        pins += [
         (rel + 0xa, '48c744245801000000', 'mode store at state '
          '+0x0 is the immediate 1'),
         (rel + 0x13, '48894c2460' if fresh else '4889442460',
          'limit store at state +0x8'),
         (rel + 0x18, '48c744247800000000', 'charged store at '
          'state +0x20 is the immediate 0'),
         (call_rel - 0x5, '488d742458', 'state argument is '
          'rsp+0x58')]
        sites.append(call_rel)
    base, body = run_pins(data, role, pins)
    for call_rel in sites:
        require(call_target(body, call_rel, base) ==
                OWNERS['fwd_twin_b'][0],
                f'{role} downward call target changed')
    return {'state': 'rsp+0x58',
            'call_sites': [hex(base + r) for r in sites],
            'downward_target': hex(OWNERS['fwd_twin_b'][0]),
            'fields': {'mode': 'constant 1 (immediate store at '
                               'all three sites)',
                       'limit': '[[view+0x10]] (dereferenced at '
                                'every site)',
                       'cursor': '[view+0x0]',
                       'remaining': '[view+0x8], reduced by the '
                                    'state remaining after site 2 '
                                    'before site 3',
                       'charged': 'constant 0 (immediate store at '
                                  'all three sites)'}}


def helper_semantics(data, role, u64_target):
    base, body = run_pins(data, role, [
     (0x0e, '4989d6', 'decoder argument saved to r14'),
     (0x11, '4989f7', 'state argument saved to r15'),
     (0x14, '4889fb', 'result argument saved to rbx'),
     (0x17, '488d7c2420', 'count result buffer is rsp+0x20'),
     (0x21, '0fb6442420', 'count rawtag load'),
     (0x26, '3c12', 'count rawtag 0x12 test'),
     (0x28, '7533', 'count failure branches to the error copy'),
     (0x2a, '4c8b642428', 'count value at result +0x8'),
     (0x2f, '49833f00', 'bulk charge mode test at state +0x0'),
     (0x33, '744f', 'zero mode skips the bulk charge'),
     (0x35, 'b918000000', 'bulk charge element size 0x18'),
     (0x3a, '4c89e0', 'bulk charge count register'),
     (0x3d, '48f7e1', 'bulk charge count * 0x18'),
     (0x40, '7013', 'bulk charge overflow refusal'),
     (0x42, '49034720', 'bulk charge adds the charged count '
      'at state +0x20'),
     (0x46, '720d', 'bulk charge addition overflow refusal'),
     (0x48, '498b4f08', 'bulk charge limit load at state +0x8'),
     (0x4c, '49894720', 'bulk charge stored before the limit '
      'compare'),
     (0x50, '4839c8', 'bulk charge limit compare'),
     (0x53, '762f', 'bulk charge refusal above the limit'),
     (0x55, 'c60302', 'charge refusal result rawtag 2'),
     (0x5d, '8b4c2421', 'count error copy source'),
     (0x79, '8803', 'count error rawtag stored to the output'),
     (0x84, '48895c2418', 'output pointer saved for the vector '
      'build'),
     (0x89, '4981fcaa aa0000'.replace(' ', ''), 'capacity '
      'compare against 0xaaaa'),
     (0x90, 'bdaaaa0000', 'capacity cap 0xaaaa'),
     (0x95, '490f42ec', 'capacity is min(count, 0xaaaa)'),
     (0x99, '4d85e4', 'zero count skips the allocation'),
     (0xa2, '8d04ed00000000', 'allocation size is capacity * 8 '
      '(first factor)'),
     (0xa9, '4c8d2c40', 'allocation size is capacity * 0x18'),
     (0xad, '4c89ef', 'allocation size argument'),
     (0xb6, '4885c0', 'allocation null test'),
     (0xb9, '0f844a010000', 'allocation failure branch'),
     (0xbf, '48892c24', 'vector capacity stored'),
     (0xc3, '4889442408', 'vector pointer stored'),
     (0xc8, '48c744241000000000', 'vector length stored as 0'),
     (0xd1, '488d6c2428', 'element copy source base is the '
      'decoder result +0x8'),
     (0xd6, '4c8d6c2447', 'element staging base'),
     (0xe0, '488b442408', 'vector pointer load for the element '
      'copy'),
     (0xe5, '488d0c5b', 'element offset is index * 3 (first '
      'factor)'),
     (0xe9, '498b5510', 'element copy third qword load'),
     (0xed, '488954c810', 'element copy third qword store at '
      'index * 0x18 + 0x10'),
     (0xf2, '410f104500', 'element copy first 16 bytes load'),
     (0xf7, '0f1104c8', 'element copy first 16 bytes store at '
      'index * 0x18'),
     (0xfb, '48ffc3', 'element index increment'),
     (0xfe, '48895c2410', 'vector length store'),
     (0x103, '49ffcc', 'remaining count decrement'),
     (0x106, '7471', 'all elements decoded branches to success'),
     (0x108, '49833f00', 'element refund mode test at '
      'state +0x0'),
     (0x10e, '498b4720', 'element refund charged load at '
      'state +0x20'),
     (0x112, '4883f818', 'element refund bound 0x18'),
     (0x116, '0f82de000000', 'element refund shortfall panics'),
     (0x11c, '4883c0e8', 'element refund subtracts 0x18'),
     (0x120, '49894720', 'element refund store at state +0x20'),
     (0x124, '488d7c2420', 'element result buffer is rsp+0x20'),
     (0x129, '4c89fe', 'element state argument is r15'),
     (0x12c, '41ffd6', 'element decoder called through the '
      'saved rdx register'),
     (0x12f, '0fb6442420', 'element rawtag load'),
     (0x134, '3c12', 'element rawtag 0x12 test'),
     (0x136, '7565', 'element failure branches to the error '
      'copy-out'),
     (0x138, '488b4510', 'element staging third qword load'),
     (0x13c, '49894510', 'element staging third qword store'),
     (0x140, '0f104500', 'element staging first 16 bytes load'),
     (0x144, '410f114500', 'element staging first 16 bytes '
      'store'),
     (0x154, '4889e7', 'growth argument is the vector'),
     (0x183, '48894318', 'success count stored at output +0x18'),
     (0x18b, '48894308', 'success vector field stored at '
      'output +0x8'),
     (0x194, '48894310', 'success vector field stored at '
      'output +0x10'),
     (0x198, 'c60312', 'success rawtag 0x12 at output +0x0'),
     (0x1d3, '488b7c2408', 'error free pointer is the vector '
      'pointer'),
     (0x1d8, '48c1e003', 'error free size is length * 8 (first '
      'factor)'),
     (0x1dc, '488d3440', 'error free size is length * 0x18'),
     (0x1e0, '31d2', 'error free align argument is 0'),
     (0x207, '0f0b', 'panic path ends in ud2'),
     (0x209, 'bf08000000', 'allocation failure size argument 8')])
    require(call_target(body, 0x1c, base) == u64_target,
            f'{role} u64 count call target changed')
    for rel, slot in ((0xb0, 0x64df480), (0x157, 0x64e5008),
                      (0x1e2, 0x64df4a0), (0x201, 0x64df848),
                      (0x211, 0x64df498), (0x234, 0x64df4a0)):
        require(body[rel:rel + 2] == b'\xff\x15',
                f'{role} slot call opcode changed')
        require(slot_at(body, rel, base) == slot,
                f'{role} slot target changed')
    disp = struct.unpack_from('<i', body, 0x1fd)[0]
    require(base + 0x1fa + 7 + disp == PANIC_STRINGS[role],
            f'{role} panic string reference changed')
    return {'arguments': {'rdi': 'out result', 'rsi': 'reader '
                          'state (saved to r15)',
                          'rdx': 'element decoder address (saved '
                                 'to r14)'},
            'count_call': {'site': hex(base + 0x1c),
                           'target': hex(u64_target),
                           'state': 'entry rsi (r15)'},
            'element_size': '0x18',
            'bulk_charge': 'mode != 0: charged += count * 0x18, '
                           'stored before the compare; refusal '
                           '(rawtag 2) when the new charged count '
                           'exceeds the limit',
            'capacity_cap': '0xaaaa elements',
            'allocation_slot': '0x64df480',
            'element_call': {'site': hex(base + 0x12c),
                             'form': 'call r14 (the saved rdx)',
                             'state': 'r15 (the helper entry '
                                      'state, unchanged)',
                             'result': 'rsp+0x20'},
            'element_refund': 'mode != 0: 0x18 subtracted from '
                              'the charged count before each '
                              'element call; charged < 0x18 '
                              'panics through slot 0x64df848',
            'growth_slot': '0x64e5008',
            'free_slot': '0x64df4a0',
            'panic_slot': '0x64df848',
            'panic_string': hex(PANIC_STRINGS[role]),
            'alloc_failure_slot': '0x64df498'}


def forwarding_semantics(data):
    out = {}
    base, body = run_pins(data, 'fwd_bulk_a_high', [
     (0x11, '4989f4', 'state argument saved to r12'),
     (0x95, '4c89e6', 'downward state argument is r12')])
    require(call_target(body, 0x98, base) ==
            OWNERS['fwd_bulk_a_low'][0],
            'fwd_bulk_a_high downward call target changed')
    out['fwd_bulk_a_high'] = {
     'state': 'entry rsi saved to r12, forwarded unchanged',
     'call_site': hex(base + 0x98),
     'target': hex(OWNERS['fwd_bulk_a_low'][0])}
    base, body = run_pins(data, 'fwd_bulk_a_low', [
     (0x3e, '4989f6', 'state argument saved to r14'),
     (0x8a, '4c89f6', 'first downward state argument is r14'),
     (0x323, '4c89f6', 'second downward state argument is r14'),
     (0x548, '4c89f6', 'third downward state argument is r14')])
    sites = []
    for call_rel in (0x8d, 0x326, 0x54b):
        require(call_target(body, call_rel, base) == BULK_A,
                'fwd_bulk_a_low downward call target changed')
        sites.append(hex(base + call_rel))
    out['fwd_bulk_a_low'] = {
     'state': 'entry rsi saved to r14, forwarded unchanged',
     'call_sites': sites, 'target': hex(BULK_A)}
    base, body = run_pins(data, 'fwd_twin_a', [
     (0x7, '4989f6', 'state argument saved to r14'),
     (0x3f, '41833e01', 'inline charge mode == 1 test at '
      'state +0x0'),
     (0x45, '498b7e20', 'inline charge charged load at '
      'state +0x20'),
     (0x67, '4d8b4608', 'inline charge limit load at state +0x8'),
     (0x6f, '4d894e20', 'inline charge store at state +0x20'),
     (0x134, '4889e7', 'downward result argument is rsp'),
     (0x137, '4c89f6', 'downward state argument is r14')])
    require(call_target(body, 0x13a, base) ==
            OWNERS['wrap_twin_a'][0],
            'fwd_twin_a downward call target changed')
    out['fwd_twin_a'] = {
     'state': 'entry rsi saved to r14, forwarded unchanged; '
              'its own inline charge reads mode/limit and '
              'stores only the charged count',
     'call_site': hex(base + 0x13a),
     'target': hex(OWNERS['wrap_twin_a'][0])}
    base, body = run_pins(data, 'fwd_bulk_b_high', [
     (0x11, '4989f6', 'state argument saved to r14'),
     (0x53, '4c89f6', 'downward state argument is r14')])
    require(call_target(body, 0x56, base) ==
            OWNERS['fwd_bulk_b_low'][0],
            'fwd_bulk_b_high downward call target changed')
    out['fwd_bulk_b_high'] = {
     'state': 'entry rsi saved to r14, forwarded unchanged',
     'call_site': hex(base + 0x56),
     'target': hex(OWNERS['fwd_bulk_b_low'][0])}
    base, body = run_pins(data, 'fwd_bulk_b_low', [
     (0x3b, '4989f7', 'state argument saved to r15'),
     (0x3e, '4889fb', 'result argument saved to rbx'),
     (0x41, '488d7c2408', 'result buffer is rsp+0x8'),
     (0x8d, '4c89fe', 'second downward state argument is r15'),
     (0xd2, '4c89fe', 'third downward state argument is r15')])
    sites = []
    for call_rel in (0x46, 0x90, 0xd5):
        require(call_target(body, call_rel, base) == BULK_B,
                'fwd_bulk_b_low downward call target changed')
        sites.append(hex(base + call_rel))
    out['fwd_bulk_b_low'] = {
     'state': 'entry rsi (the register itself at site 1, the '
              'saved r15 at sites 2-3), forwarded unchanged',
     'call_sites': sites, 'target': hex(BULK_B)}
    base, body = run_pins(data, 'fwd_twin_b', [
     (0xc, '4989f6', 'state argument saved to r14'),
     (0x13b, '4889e7', 'downward result argument is rsp'),
     (0x13e, '4c89f6', 'downward state argument is r14')])
    require(call_target(body, 0x141, base) ==
            OWNERS['wrap_twin_b'][0],
            'fwd_twin_b downward call target changed')
    out['fwd_twin_b'] = {
     'state': 'entry rsi saved to r14, forwarded unchanged',
     'call_site': hex(base + 0x141),
     'target': hex(OWNERS['wrap_twin_b'][0])}
    return out


def wrap_semantics(data, role, twin, helper):
    base, body = run_pins(data, role, [
     (0x0, '4157', 'prologue push r15'),
     (0x2, '4156', 'prologue push r14'),
     (0x4, '4154', 'prologue push r12'),
     (0x6, '53', 'prologue push rbx'),
     (0x7, '4883ec58', 'prologue stack allocation'),
     (0xb, '4889fb', 'result argument saved to rbx'),
     (0x15, '488d7c2410', 'helper result buffer is rsp+0x10')])
    disp = struct.unpack_from('<i', body, 0x11)[0]
    require(base + 0xe + 7 + disp == twin,
            f'{role} twin lea target changed')
    require(call_target(body, 0x1a, base) == helper,
            f'{role} helper call target changed')
    return {'lea_site': hex(base + 0xe), 'decoder': hex(twin),
            'helper_call': hex(base + 0x1a),
            'helper': hex(helper),
            'state': 'entry rsi, not written between the entry '
                     'and the helper call (the pinned prologue '
                     'sequence contains no rsi write)',
            'result': 'rsp+0x10 (a stack buffer, forwarded to '
                      'the caller\'s own output handling)'}


def view_semantics(data):
    out = {}
    base, body = run_pins(data, 'view_twin_b', [
     (0x14, '4989d4', 'remaining source register r12 is the '
      'entry rdx'),
     (0x17, '4989f5', 'cursor source register r13 is the entry '
      'rsi'),
     (0x1d, '48894c2408', 'entry rcx saved to the stack slot '
      'the view points at'),
     (0x32, '4c896c2420', 'view +0x0 is the entry rsi'),
     (0x37, '4c89642428', 'view +0x8 is the entry rdx'),
     (0x3c, '488d442408', 'view +0x10 pointer is the rcx slot'),
     (0x41, '4889442430', 'view +0x10 store'),
     (0x4b, '488d742420', 'view argument is rsp+0x20')])
    require(call_target(body, 0x52, base) ==
            OWNERS['ctor_twin_b'][0],
            'view_twin_b constructor call target changed')
    out['view_twin_b'] = {
     'view': 'rsp+0x20: {+0x0: entry rsi, +0x8: entry rdx, '
             '+0x10: address of the stack slot holding the '
             'entry rcx}',
     'call_site': hex(base + 0x52),
     'target': hex(OWNERS['ctor_twin_b'][0]),
     'limit_consequence': 'the twin-b limit is this '
                          'function\'s entry rcx value, '
                          'forwarded by pointer'}
    base, body = run_pins(data, 'view_bulk_b', [
     (0x14, '4989d4', 'remaining source register r12 is the '
      'entry rdx'),
     (0x17, '4989f5', 'cursor source register r13 is the entry '
      'rsi'),
     (0x1d, '48890c24', 'entry rcx saved to the stack slot the '
      'view points at'),
     (0x31, '4c896c2428', 'view +0x0 is the entry rsi'),
     (0x36, '4c89642430', 'view +0x8 is the entry rdx'),
     (0x3b, '4889e0', 'view +0x10 pointer is the rcx slot'),
     (0x3e, '4889442438', 'view +0x10 store'),
     (0x4b, '488d742428', 'view argument is rsp+0x28')])
    require(call_target(body, 0x55, base) ==
            OWNERS['ctor_bulk_b_mode'][0],
            'view_bulk_b mode caller target changed')
    out['view_bulk_b'] = {
     'view': 'rsp+0x28: {+0x0: entry rsi, +0x8: entry rdx, '
             '+0x10: address of the stack slot holding the '
             'entry rcx}',
     'call_site': hex(base + 0x55),
     'target': hex(OWNERS['ctor_bulk_b_mode'][0]),
     'limit_consequence': 'the bulk-b limit is this '
                          'function\'s entry rcx value, '
                          'forwarded by pointer'}
    return out


def top_caller_semantics(data):
    def span(va, hexs, message):
        _, raw = read(data, va, len(bytes.fromhex(hexs)))
        require(raw == bytes.fromhex(hexs), f'{message} changed')

    def target(va, expected, message):
        _, raw = read(data, va, 5)
        got = va + 5 + struct.unpack_from('<i', raw, 1)[0]
        require(got == expected, f'{message} changed')

    span(0x2b68885, '488b8b20020000', 'top bulk-a limit load')
    span(0x2b688ae, '4c89ee', 'top bulk-a cursor argument')
    span(0x2b688b1, '4c89f2', 'top bulk-a remaining argument')
    target(0x2b688b4, OWNERS['ctor_bulk_a'][0],
           'top bulk-a constructor call target')
    span(0x2b6aa24, '488b8b80010000', 'top twin-a limit load')
    span(0x2b6aa4d, '4c89fe', 'top twin-a cursor argument')
    span(0x2b6aa50, '4c89ea', 'top twin-a remaining argument')
    target(0x2b6aa53, OWNERS['ctor_twin_a'][0],
           'top twin-a constructor call target')
    span(0x5a6b881, '488b8b600a0000', 'top twin-b limit load')
    span(0x5a6b8aa, '4889ee', 'top twin-b view cursor argument')
    span(0x5a6b8ad, '4c89f2', 'top twin-b view remaining argument')
    target(0x5a6b8b5, OWNERS['view_twin_b'][0],
           'top twin-b view call target')
    span(0x5a66d2f, '4c89fa', 'top bulk-b view remaining argument')
    target(0x5a66d32, OWNERS['view_bulk_b'][0],
           'top bulk-b view call target')
    return {
     'bulk_a': {'fde': '0x2b67e50..0x2b69279',
                'call_site': '0x2b688b4',
                'limit': '[rbx+0x220], loaded into rcx at '
                         '0x2b68885',
                'cursor': 'r13', 'remaining': 'r14'},
     'twin_a': {'fde': '0x2b69d20..0x2b6ae9f',
                'call_site': '0x2b6aa53',
                'limit': '[rbx+0x180], loaded into rcx at '
                         '0x2b6aa24',
                'cursor': 'r15', 'remaining': 'r13'},
     'twin_b': {'fde': '0x5a6a640..0x5a6bfaa',
                'call_site': '0x5a6b8b5',
                'limit': '[rbx+0xa60], loaded into rcx at '
                         '0x5a6b881 and passed to the view '
                         'builder',
                'view_cursor': 'rbp', 'view_remaining': 'r14'},
     'bulk_b': {'fde': '0x5a64aa0..0x5a69c05',
                'call_site': '0x5a66d32',
                'limit': 'its rcx argument at the view-builder '
                         'call (register state at that site; '
                         'its own load is not pinned)',
                'view_remaining': 'r15'}}


FRAMES = {'ctor_bulk_a': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                         'va': '0x103d604'},
                 'fde': {'bytes_hex': '500000000c540f002cbf5c01c508000004f7dd0fff410e10420e18420e20420e28420e30410e38470ef00483078c068d058e048f0386020397040e38410e30420e28420e20420e18420e10410e08410ef0040000',
                         'va': '0x1132a0c'}},
 'ctor_bulk_b': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                         'va': '0x103d604'},
                 'fde': {'bytes_hex': '500000009014340008304a048704000004232505ff410e10420e18420e20420e28420e30410e38470ef00283078c068d058e048f038602036b020e38410e30420e28420e20420e18420e10410e08410ef0020000',
                         'va': '0x137ea90'}},
 'ctor_bulk_b_mode': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                              'va': '0x103d604'},
                      'fde': {'bytes_hex': '50000000f8672c00d045b40382030000044f9d07ff410e10420e18420e20420e28420e30410e38470e800283078c068d058e048f03860203f8020e38410e30420e28420e20420e18420e10410e08410e80020000',
                              'va': '0x1303df8'}},
 'ctor_twin_a': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                         'va': '0x103d604'},
                 'fde': {'bytes_hex': '5000000060540f00a8c75c01200600000433de0fff410e10420e18420e20420e28420e30410e38470eb00283078c068d058e048f03860203d4020e38410e30420e28420e20420e18420e10410e08410eb0020000',
                         'va': '0x1132a60'}},
 'ctor_twin_b': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                         'va': '0x103d604'},
                 'fde': {'bytes_hex': '50000000e8642c00b02ab403a705000004c79c07ff410e10420e18420e20420e28420e30410e38470ea00283078c068d058e048f0386020387020e38410e30420e28420e20420e18420e10410e08410ea0020000',
                         'va': '0x1303ae8'}},
 'fwd_bulk_a_high': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                             'va': '0x103d604'},
                     'fde': {'bytes_hex': '5000000088b415007024b5019803000004cbf80dff410e10420e18420e20420e28420e30410e38470ee00183078c068d058e048f0386020325010e38410e30420e28420e20420e18420e10410e08410ee0010000',
                             'va': '0x1198a88'}},
 'fwd_bulk_a_low': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                            'va': '0x103d604'},
                    'fde': {'bytes_hex': '5c000000e4b11500d495b401720c0000047bf90dff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0ec06283078c068d058e048f038602030c010e38410e30420e28420e20420e18420e10410e08410ec0620000',
                            'va': '0x11987e4'}},
 'fwd_bulk_b_high': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                             'va': '0x103d604'},
                     'fde': {'bytes_hex': '50000000181e340000c14a04c8070000040b2005ff410e10420e18420e20420e28420e30410e38470ef00383078c068d058e048f038602029f0e38410e30420e28420e20420e18420e10410e08410ef003000000',
                             'va': '0x137f418'}},
 'fwd_bulk_b_low': {'cie': {'bytes_hex': '1400000000000000017a5200017810011b0c070890010000',
                            'va': '0xca6ed8'},
                    'fde': {'bytes_hex': '48000000d0e827006404ee03c801000000420e10420e18420e20410e28470ea8204f0ea8404f0ea8604f0eb07183058c048e038f0202e00e28410e20420e18420e10420e08410eb071000000',
                            'va': '0xf257a4'}},
 'fwd_twin_a': {'cie': {'bytes_hex': '1400000000000000017a5200017810011b0c070890010000',
                        'va': '0xca6ed8'},
                'fde': {'bytes_hex': '2800000078270f005cd00a02f902000000420e10410e18440e900183038e0203ee020e18410e10420e080000',
                        'va': '0xd9964c'}},
 'fwd_twin_b': {'cie': {'bytes_hex': '1400000000000000017a5200017810011b0c070890010000',
                        'va': '0xca6ed8'},
                'fde': {'bytes_hex': '40000000e8f13100fc66ae046204000000410e10420e18420e20420e28410e30440ea00183068c058e048f038602034d040e30410e28420e20420e18420e10410e080000',
                        'va': '0xfc60bc'}},
 'helper_a': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                      'va': '0x103d604'},
              'fde': {'bytes_hex': '5000000060bd0b00283a23014202000004ab7611ff410e10420e18420e20420e28420e30410e38440ea00183078c068d058e048f03860203e1010e38410e30420e28420e20420e18420e10410e08410ea0010000',
                      'va': '0x10f9360'}},
 'helper_b': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                      'va': '0x103d604'},
              'fde': {'bytes_hex': '500000001c1a34007c614a044202000004f72105ff410e10420e18420e20420e28420e30410e38440ea00183078c068d058e048f03860203e1010e38410e30420e28420e20420e18420e10410e08410ea0010000',
                      'va': '0x137f01c'}},
 'view_bulk_b': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                         'va': '0x103d604'},
                 'fde': {'bytes_hex': '50000000046b3400c4cb4d0434010000041f0105ff410e10420e18420e20420e28420e30410e38470eb00383078c068d058e048f03860202bf0e38410e30420e28420e20420e18420e10410e08410eb003000000',
                         'va': '0x1384104'}},
 'view_twin_b': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                         'va': '0x103d604'},
                 'fde': {'bytes_hex': '500000006069340088c74d043d01000004230205ff410e10420e18420e20420e28420e30410e38470ee00183078c068d058e048f03860202ce0e38410e30420e28420e20420e18420e10410e08410ee001000000',
                         'va': '0x1383f60'}},
 'wrap_twin_a': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                         'va': '0x103d604'},
                 'fde': {'bytes_hex': '40000000888d1600f0c5c2015702000004b3c50dff420e10420e18420e20410e28440e800183058c048e038f0202c90e28410e20420e18420e10420e08410e8001000000',
                         'va': '0x11a6388'}},
 'wrap_twin_b': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                         'va': '0x103d604'},
                 'fde': {'bytes_hex': '4000000050dd2b00b8aeae0357020000045be707ff420e10420e18420e20410e28440e800183058c048e038f0202c90e28410e20420e18420e10420e08410e8001000000',
                         'va': '0x12fb350'}}}

PIN_STARTS = {
 'ctor_bulk_a': [0x26fe954, 0x26fea0b, 0x26fea2f, 0x26feb32,
                 0x26feb56, 0x26feedf, 0x26fef03],
 'ctor_twin_a': [0x26ff224, 0x26ff27a, 0x26ff2e4, 0x26ff308,
                 0x26ff38f, 0x26ff3b3, 0x26ff5e9, 0x26ff616],
 'ctor_bulk_b': [0x5821acb, 0x5821ae8, 0x5821dd9],
 'ctor_bulk_b_mode': [0x4e483ec, 0x4e48499, 0x4e484a1, 0x4e4850b,
                      0x4e48516, 0x4e485fe, 0x4e48609],
 'ctor_twin_b': [0x4e465bc, 0x4e4665f, 0x4e46683, 0x4e4673a,
                 0x4e4675e, 0x4e468e5, 0x4e46909],
 'helper_a': [0x232cd9e, 0x232cdac, 0x232cddc, 0x232ce40,
              0x232cebc, 0x232cee7, 0x232cf72, 0x232cf91],
 'helper_b': [0x58251ae, 0x58251bc, 0x58251ec, 0x5825250,
              0x58252cc, 0x58252f7, 0x5825382, 0x58253a1],
 'fwd_bulk_a_high': [0x2ceaf11, 0x2ceaf98],
 'fwd_bulk_a_low': [0x2ce1dfe, 0x2ce1e4d, 0x2ce20e6, 0x2ce230b],
 'fwd_twin_a': [0x2e466b7, 0x2e466ef, 0x2e467ea],
 'fwd_bulk_b_high': [0x582b531, 0x582b576],
 'fwd_bulk_b_low': [0x4e05c4b, 0x4e05c56, 0x4e05ca0, 0x4e05ce5],
 'fwd_twin_b': [0x5aac7cc, 0x5aac901],
 'wrap_twin_a': [0x2dd298e, 0x2dd299a],
 'wrap_twin_b': [0x4de621e, 0x4de622a],
 'view_bulk_b': [0x5860ced, 0x5860d25],
 'view_twin_b': [0x586070d, 0x5860742]}

EXPECTED_CALLERS = {
 'ctor_bulk_a': [('0x2b688b4', '0x2b67e50..0x2b69279')],
 'ctor_twin_a': [('0x2b6aa53', '0x2b69d20..0x2b6ae9f')],
 'ctor_bulk_b': [('0x4e484a1', '0x4e483d0..0x4e48752'),
                 ('0x4e48516', '0x4e483d0..0x4e48752'),
                 ('0x4e48609', '0x4e483d0..0x4e48752')],
 'ctor_bulk_b_mode': [('0x5860d25', '0x5860cd0..0x5860e04')],
 'ctor_twin_b': [('0x5860742', '0x58606f0..0x586082d')],
 'helper_a': [('0x2dd299a', '0x2dd2980..0x2dd2bd7')],
 'helper_b': [('0x4de622a', '0x4de6210..0x4de6467')],
 'fwd_bulk_a_high': [('0x26fea2f', '0x26fe940..0x26ff205'),
                     ('0x26feb56', '0x26fe940..0x26ff205'),
                     ('0x26fef03', '0x26fe940..0x26ff205')],
 'fwd_bulk_a_low': [('0x2ceaf98', '0x2ceaf00..0x2ceb298')],
 'fwd_twin_a': [('0x26ff308', '0x26ff210..0x26ff830'),
                ('0x26ff3b3', '0x26ff210..0x26ff830'),
                ('0x26ff616', '0x26ff210..0x26ff830')],
 'fwd_bulk_b_high': [('0x5821dd9', '0x5821aa0..0x5821f27')],
 'fwd_bulk_b_low': [('0x582b576', '0x582b520..0x582bce8')],
 'fwd_twin_b': [('0x4e46683', '0x4e465a0..0x4e46b47'),
                ('0x4e4675e', '0x4e465a0..0x4e46b47'),
                ('0x4e46909', '0x4e465a0..0x4e46b47')],
 'wrap_twin_a': [('0x2e467ea', '0x2e466b0..0x2e469a9')],
 'wrap_twin_b': [('0x5aac901', '0x5aac7c0..0x5aacc22')],
 'view_bulk_b': [('0x5a66d32', '0x5a64aa0..0x5a69c05')],
 'view_twin_b': [('0x5a6b8b5', '0x5a6a640..0x5a6bfaa')],
 'twin_a': [], 'twin_b': [],
 'bulk_a': [('0x2ce1e4d', '0x2ce1dc0..0x2ce2a32'),
            ('0x2ce20e6', '0x2ce1dc0..0x2ce2a32'),
            ('0x2ce230b', '0x2ce1dc0..0x2ce2a32')],
 'bulk_b': [('0x4e05c56', '0x4e05c10..0x4e05dd8'),
            ('0x4e05ca0', '0x4e05c10..0x4e05dd8'),
            ('0x4e05ce5', '0x4e05c10..0x4e05dd8')]}
EXPECTED_LEA = {'twin_a': ['0x2dd298e'], 'twin_b': ['0x4de621e']}
READER_CALLS_INSIDE = {
 'u32_copy_a': {'fwd_bulk_a_high': ['0x2ceaf1a'],
                'fwd_bulk_a_low': ['0x2ce1e0c'],
                'fwd_twin_a': ['0x2e466c0', '0x2e46827']},
 'u32_copy_b': {'ctor_bulk_b': ['0x5821ae8'],
                'fwd_bulk_b_high': ['0x582b546'],
                'fwd_twin_b': ['0x5aac7d5', '0x5aac941',
                               '0x5aac9f2']},
 'u64_copy_a': {'fwd_bulk_a_high': ['0x2ceaf7c', '0x2ceb081',
                                    '0x2ceb09d', '0x2ceb0b9'],
                'helper_a': ['0x232cdac']},
 'u64_copy_b': {'ctor_bulk_b': ['0x5821b26', '0x5821b96',
                                '0x5821bba', '0x5821bda',
                                '0x5821db4'],
                'fwd_twin_b': ['0x5aacae2', '0x5aacb00',
                               '0x5aacb59', '0x5aacb73',
                               '0x5aacb97', '0x5aacbb1'],
                'helper_b': ['0x58251bc']}}
HELPER_DIFF_RUNS = [('0x1d', '0x20'), ('0xb2', '0xb5'),
                    ('0x159', '0x15c'), ('0x1e4', '0x1e7'),
                    ('0x1fd', '0x200'), ('0x203', '0x206'),
                    ('0x213', '0x216'), ('0x236', '0x239'),
                    ('0x23e', '0x241')]


def census(data):
    """Direct E8 callers and rip-relative lea references for every
    traced function and the four #2433 decoders, plus the reader
    calls that fall inside the traced functions."""
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, off, size = sec['address'], sec['offset'], sec['size']
    body = data[off:off + size]
    _, fs, _ = fde_extents(data)
    fdes = sorted((f['start'], f['end']) for f in fs)
    import bisect
    starts = [s for s, _ in fdes]

    def containing(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and fdes[i][0] <= va < fdes[i][1]:
            return fdes[i]
        return None

    targets = {}
    for role, (a, _, _) in OWNERS.items():
        targets[a] = role
    targets.update({TWIN_A: 'twin_a', TWIN_B: 'twin_b',
                    BULK_A: 'bulk_a', BULK_B: 'bulk_b',
                    U32_A: 'u32_copy_a', U32_B: 'u32_copy_b',
                    U64_A: 'u64_copy_a', U64_B: 'u64_copy_b'})
    calls = {name: [] for name in targets.values()}
    i = body.find(b'\xe8')
    while i != -1:
        va = base + i
        t = va + 5 + struct.unpack_from('<i', body, i + 1)[0]
        if t in targets:
            c = containing(va)
            calls[targets[t]].append(
             {'site': hex(va),
              'containing_fde': (f'{c[0]:#x}..{c[1]:#x}'
                                 if c else None)})
        i = body.find(b'\xe8', i + 1)
    lea_refs = {name: [] for name in targets.values()}
    for pat in (b'\x48\x8d', b'\x4c\x8d'):
        j = body.find(pat)
        while j != -1:
            if j + 7 <= size:
                tgt = base + j + 7 + struct.unpack_from(
                    '<i', body, j + 3)[0]
                if tgt in targets:
                    lea_refs[targets[tgt]].append(hex(base + j))
            j = body.find(pat, j + 1)
    lea_refs = {k: sorted(set(v)) for k, v in lea_refs.items()}
    return calls, lea_refs, containing


def exports(data):
    out = {}
    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / 'hl-node'
        snapshot.write_bytes(data)
        for role, (a, b, _) in OWNERS.items():
            asm = subprocess.check_output(
             ['objdump', '-d', '-M', 'intel', '--insn-width=16',
              f'--start-address={a:#x}', f'--stop-address={b:#x}',
              str(snapshot)], text=True)
            ins = decode_export(asm, a, b, read(data, a, b - a)[1])
            for va in PIN_STARTS[role]:
                require(va in ins,
                        f'{role} instruction start missing')
            out[role] = asm.replace(str(snapshot),
                                    '<authenticated-node115>')
    return out


def analyze(data):
    by_offset = relocations(data)
    reloc_records = {}
    for slot, target in SLOTS.items():
        entries = by_offset.get(slot, [])
        require(len(entries) == 1, f'slot {slot:#x} relocation '
                                   'changed')
        require(entries[0] == (8, 0, target),
                f'slot {slot:#x} relocation changed')
        reloc_records[hex(slot)] = {'type': 8, 'symbol_index': 0,
                                    'addend_target': hex(target)}
    ctor_a = ctor_bulk_a_semantics(data)
    ctor_ta = ctor_twin_a_semantics(data)
    ctor_b = ctor_bulk_b_semantics(data)
    mode_b = ctor_bulk_b_mode_semantics(data)
    ctor_tb = ctor_twin_b_semantics(data)
    helper_a = helper_semantics(data, 'helper_a', U64_A)
    helper_b = helper_semantics(data, 'helper_b', U64_B)
    fwd = forwarding_semantics(data)
    wrap_a = wrap_semantics(data, 'wrap_twin_a', TWIN_A,
                            OWNERS['helper_a'][0])
    wrap_b = wrap_semantics(data, 'wrap_twin_b', TWIN_B,
                            OWNERS['helper_b'][0])
    views = view_semantics(data)
    tops = top_caller_semantics(data)
    _, ha = read(data, OWNERS['helper_a'][0], 578)
    _, hb = read(data, OWNERS['helper_b'][0], 578)
    diff = [i for i in range(578) if ha[i] != hb[i]]
    runs = []
    for i in diff:
        if runs and i == runs[-1][1] + 1:
            runs[-1][1] = i
        else:
            runs.append([i, i])
    require([(hex(a), hex(b)) for a, b in runs] == HELPER_DIFF_RUNS,
            'helper bodies differ outside the displacement fields')
    calls, lea_refs, _ = census(data)
    for name, expected in EXPECTED_CALLERS.items():
        got = [(c['site'], c['containing_fde']) for c in calls[name]]
        require(got == expected, f'{name} direct caller census '
                                 'changed')
        want_lea = EXPECTED_LEA.get(name, [])
        require(lea_refs[name] == want_lea,
                f'{name} lea reference census changed')
    role_fdes = {f'{a:#x}..{b:#x}': role
                 for role, (a, b, _) in OWNERS.items()}
    inside = {}
    for reader in ('u32_copy_a', 'u32_copy_b', 'u64_copy_a',
                   'u64_copy_b'):
        per = {}
        for c in calls[reader]:
            role = role_fdes.get(c['containing_fde'])
            if role:
                per.setdefault(role, []).append(c['site'])
        inside[reader] = per
        require(per == READER_CALLS_INSIDE[reader],
                f'{reader} calls inside the traced functions '
                'changed')
    exps = exports(data)
    require(len(exps) == len(OWNERS), 'export count changed')
    _, fs, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs}
    owners = []
    for role, (a, b, sha) in OWNERS.items():
        require((a, b) in fdes, f'{role} FDE changed')
        offset, raw = read(data, a, b - a)
        require(hashlib.sha256(raw).hexdigest() == sha,
                f'{role} body changed')
        records = {}
        for kind in ('fde', 'cie'):
            va = fdes[(a, b)][kind]
            n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
            records[kind] = {'va': hex(va),
                             'bytes_hex': read(data, va, n)[1].hex()}
        require(records == FRAMES[role],
                f'{role} frame records changed')
        owners.append({'role': role, 'start': hex(a),
                       'end': hex(b), 'file_offset': hex(offset),
                       'bytes': b - a, 'sha256': sha,
                       'frames': records})
    census_records = {}
    for name in EXPECTED_CALLERS:
        census_records[name] = {
         'direct_calls': calls[name],
         'lea_references': lea_refs[name]}
    return {
     'target_sha256': SHA,
     'owners': owners,
     'state_layout': {
      'size': '0x28',
      'fields': {'mode': '+0x0', 'limit': '+0x8',
                 'cursor': '+0x10', 'remaining': '+0x18',
                 'charged': '+0x20'},
      'source': 'the reader-state layout of the u32 reader '
                'packet (#2412) and the field1-5 reader packet '
                '(#2422), re-validated here only where these '
                'bytes store the fields'},
     'construction': {
      'bulk_a': {'constructor': ctor_a,
                 'forwarding': [fwd['fwd_bulk_a_high'],
                                fwd['fwd_bulk_a_low']],
                 'top_caller': tops['bulk_a'],
                 'decoder': 'bulk copy a 0x2cd9710, a #2433 '
                            'owner (boundary)'},
      'twin_a': {'constructor': ctor_ta,
                 'forwarding': [fwd['fwd_twin_a'], wrap_a],
                 'top_caller': tops['twin_a'],
                 'decoder': 'twin a 0x26e5710, a #2433 owner '
                            '(boundary)'},
      'bulk_b': {'constructor': ctor_b,
                 'mode_supplier': mode_b,
                 'view_builder': views['view_bulk_b'],
                 'forwarding': [fwd['fwd_bulk_b_high'],
                                fwd['fwd_bulk_b_low']],
                 'top_caller': tops['bulk_b'],
                 'decoder': 'bulk copy b 0x5968840, a #2433 '
                            'owner (boundary)'},
      'twin_b': {'constructor': ctor_tb,
                 'view_builder': views['view_twin_b'],
                 'forwarding': [fwd['fwd_twin_b'], wrap_b],
                 'top_caller': tops['twin_b'],
                 'decoder': 'twin b 0x5aaa460, a #2433 owner '
                            '(boundary)'}},
     'mode_value': 'the constant 1 at every one of the twelve '
                   'construction sites: an immediate store in '
                   'ctor_bulk_a (3 sites), ctor_twin_a (3), '
                   'ctor_twin_b (3), and an immediate argument in '
                   'ctor_bulk_b_mode (3) stored by ctor_bulk_b',
     'limit_value': 'never a constant and never the buffer '
                    'length: bulk_a takes the top dispatcher '
                    'context field [rbx+0x220], twin_a takes '
                    '[rbx+0x180], twin_b takes [[view+0x10]] '
                    'whose pointee is the top caller\'s rcx '
                    '([rbx+0xa60] in 0x5a6a640), bulk_b takes '
                    '[[view+0x10]] whose pointee is the view '
                    'builder 0x5860cd0\'s entry rcx',
     'charged_value': 'the constant 0 at every construction '
                      'site',
     'twin_registration': {
      'helper_a': helper_a, 'helper_b': helper_b,
      'wrappers': {'wrap_twin_a': wrap_a, 'wrap_twin_b': wrap_b},
      'body_relation': 'the two helpers are 578-byte codegen '
                       'twins; all 36 differing bytes sit in '
                       'nine 4-byte displacement fields (the '
                       'u64 reader call and eight branch/lea '
                       'displacements)',
      'invocation': 'the twins have no direct callers and one '
                    'lea reference each; each wrapper passes '
                    'the twin address in rdx to its helper with '
                    'its own entry state unchanged, and the '
                    'helper calls the twin through that '
                    'register once per element with the same '
                    'state -- so the states the twins consume '
                    'are exactly the constructed states of the '
                    'twin_a / twin_b construction records'},
     'call_census': census_records,
     'reader_calls_inside': inside,
     'boundaries': {
      'limit_writers': 'who writes the context fields '
                       '[rbx+0x220], [rbx+0x180], [rbx+0xa60] '
                       'and the bulk-b top caller\'s rcx is '
                       'above the traced window; the top '
                       'dispatchers (0x2b67e50, 0x2b69d20, '
                       '0x5a64aa0, 0x5a6a640) each have many '
                       'callers and are recorded by span pins '
                       'only, not traced',
      'twin_a_site_3_limit': 'at the twin-a constructor\'s '
                             'third site the limit register '
                             'may hold the +0x28 field of an '
                             'earlier stage result instead of '
                             'the entry rcx; who writes that '
                             'result field is inside '
                             'fwd_twin_a\'s result construction '
                             'and is not traced',
      'decoder_bodies': 'the four #2433 caller functions and '
                        'the reader families (u32 #2412, '
                        'field1-5 #2422, u64 #2300) are cited '
                        'boundaries, not re-derived',
      'slot_identities': 'the five helper slots are '
                         'R_X86_64_RELATIVE relocations to '
                         'unnamed internal targets, identified '
                         'by argument shape only'},
     'relocations': reloc_records,
     'captured_code_executed': False,
     'limits': LIMITS}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('pinned node115 distribution changed')
    payload = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / 'hl-node'
        snapshot.write_bytes(data)
        native = subprocess.check_output(
         ['readelf', '-wf', str(snapshot)], text=True)
        wanted = []
        for a, b, _ in OWNERS.values():
            needle = f'pc={a:016x}..{b:016x}'
            wanted += [ln for ln in native.splitlines()
                       if needle in ln]
        require(len(wanted) == len(OWNERS),
                'owner frame lines missing')
        (output / 'frames.txt').write_text('\n'.join(wanted) + '\n')
        exps = exports(data)
        for role, asm in exps.items():
            (output / f'{role}.objdump.txt').write_bytes(
             asm.encode('utf-8'))
    (output / 'records.json').write_text(
     json.dumps(payload, indent=1, sort_keys=True) + '\n')
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('output', nargs='?', default=str(PACKET))
    args = parser.parse_args()
    payload = generate(TARGET, Path(args.output))
    for owner in payload['owners']:
        print(owner['role'], owner['start'], owner['end'],
              owner['bytes'], owner['sha256'])


if __name__ == '__main__':
    main()
