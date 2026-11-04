#!/usr/bin/env python3
"""RE-005: digest-bound node115 field1-5 varint reader caller trace.

Traces the six direct call sites of the bincode-fork scalar varint
reader family whose error results carry field1 5 (the family traced
by the open field1-5 reader packet, PR #2422: fast copies 0x2cd7bb0
and 0x5821340, slow reader 0x5822710). The sites live in four caller
functions, two twin pairs. The twins (0x26e5710 and 0x5aaa460,
byte-identical except three call displacements and two string
displacements) first call the u32 reader family of PR #2412 on the
same reader state, then -- only when that value is zero -- perform
an inline four-byte read with an inline mode-1 charge of 1, read
one flag byte, and call the field1-5 reader. The bulk pair
(0x2cd9710 and 0x5968840) each call the field1-5 reader twice and
then read one fixed 0x800-byte record, one inline and one through
the shared charge helper 0x58214b0. At every one of the six sites
the reader state argument is the caller function's own entry state
argument, forwarded unchanged; no traced caller writes the mode
field (state +0x0) or the limit field (state +0x8). The mode and
limit each read is charged against are established upstream of
these functions and only read here, by the inline charge blocks
(amounts 1 and 0x800) and by the helper.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-005-node115-field1-5-caller-args'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
OWNERS = {
 'twin_a': (0x26e5710, 0x26e58d8,
            '2e266f10c206f37fedfd9b7da720ef871409dbb56605d16fa6a9b76c7dbccb0e'),
 'twin_b': (0x5aaa460, 0x5aaa628,
            'acc58bb5d8410ed2ef670dba68b4351f3a860a0e9fad3cc891a1a9293aa7eba4'),
 'bulk_a': (0x2cd9710, 0x2cd9844,
            'e63eb1e52fa5eb5aa819e29e8347e84e0ae6674e44f700bea5f97fcc877c41c3'),
 'bulk_b': (0x5968840, 0x5968980,
            '0c2c5b75b9ab949f169bd4ba08335209461a5b7db6c06397ce9a85e7ab6cbc78')}
HELPER = (0x58214b0, 0x582153d, '6000169db178838a7a44122d479531046f4969600ae59171272f7af03f6ab575')
F15_A = 0x2cd7bb0
F15_B = 0x5821340
F15_SLOW = 0x5822710
U32_A = 0x2cd79c0
U32_B = 0x5821150
U64_A = 0x2cd7ac0
U64_B = 0x5821250
MEMCPY_SLOT = 0x64df508
TWIN_STRING = b'NodeIp'
TWIN_STRING_B = 0x4553c0
LIMITS = (
 'Static trace only: no pinned bytes were executed and no live node, '
 'network, signer, or exchange state was used. The reader state is '
 'the five-field layout of the field1-5 reader packet (mode +0x0, '
 'limit +0x8, cursor +0x10, remaining +0x18, charged count +0x20); '
 'field names are that packet record, re-validated here only where '
 'these bytes touch the fields. Who first writes the mode and limit '
 'fields is not established: every traced function forwards a state '
 'it received, and the two twins are reached only through a helper '
 'call whose forwarding is recorded as a boundary, not traced. '
 'Rawtag and result values are raw bytes; which Rust enum variants '
 'they name is not established. No Rust reconstruction is included '
 'or claimed.')


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


def dynsym_name(data, index):
    sym = next(s for s in sections(data) if s['name'] == '.dynsym')
    strs = next(s for s in sections(data) if s['name'] == '.dynstr')
    off = sym['offset'] + index * 24
    name_off = struct.unpack_from('<I', data, off)[0]
    start = strs['offset'] + name_off
    end = data.index(b'\0', start)
    return data[start:end].decode()


def pin(body, rel, expected, message):
    require(body[rel:rel + len(expected)] == expected,
            f'{message} changed')


def call_target(body, rel, base):
    return base + rel + 5 + struct.unpack_from('<i', body, rel + 1)[0]


def twin_semantics(data, role, base, u32_target, f15_target, string_va):
    """Validate the shared layout of one twin caller (0x26e5710 twin)."""
    _, body = read(data, base, OWNERS[role][1] - base)
    pins = [
     (0x00a, '4989f6', 'state argument saved to r14'),
     (0x00d, '4889fb', 'result argument saved to rbx'),
     (0x010, '488d7c2418', 'u32 result buffer is rsp+0x18'),
     (0x01a, '0fb6442418', 'u32 rawtag load'),
     (0x01f, '3c12', 'u32 rawtag 0x12 test'),
     (0x023, '8b44241c', 'u32 value dword at result +0x4'),
     (0x02f, 'b005', 'nonzero-value result tag 5'),
     (0x038, 'be06000000', 'named string length 6'),
     (0x0a6, '498b7618', 'inline read remaining load at state +0x18'),
     (0x0aa, '4883fe04', 'inline read width 4 test'),
     (0x0b0, 'b904000000', 'inline shortfall width 4'),
     (0x0b5, '4829f1', 'inline shortfall additional is 4 - remaining'),
     (0x0bc, '498b7e10', 'inline read cursor load at state +0x10'),
     (0x0c0, '488d4704', 'inline read cursor advance 4'),
     (0x0c4, '4c8d46fc', 'inline read remaining drop 4'),
     (0x0c8, '448b3f', 'inline read value dword load'),
     (0x0cb, '49894610', 'inline read cursor stored before the charge'),
     (0x0cf, '4d894618', 'inline read remaining stored before the charge'),
     (0x0d3, '41833e01', 'inline charge mode == 1 test at state +0x0'),
     (0x0d9, '4d8b4e20', 'inline charge charged load at state +0x20'),
     (0x0dd, 'b102', 'inline charge refusal tag 2'),
     (0x0e4, '4983f9ff', 'inline charge overflow bound charged == u64::MAX'),
     (0x0ee, '4d8b5608', 'inline charge limit load at state +0x8'),
     (0x0f2, '498d5101', 'inline charge increment 1'),
     (0x0f6, '49895620', 'inline charge stored before the limit compare'),
     (0x0fa, '4d39d1', 'inline charge compares the old charged count'),
     (0x0fd, '0f8390000000', 'inline charge refusal at old charged >= limit'),
     (0x10d, '0fb66f04', 'flag byte load past the inline read'),
     (0x111, '4883c705', 'flag path cursor advance 5 in total'),
     (0x115, '4883c6fb', 'flag path remaining drop 5 in total'),
     (0x119, '49897e10', 'flag path cursor store at state +0x10'),
     (0x11d, '49897618', 'flag path remaining store at state +0x18'),
     (0x121, '4080fd01', 'flag byte bound 1'),
     (0x127, '488d7c2418', 'field1-5 result buffer is rsp+0x18'),
     (0x12c, '4c89f6', 'field1-5 state argument is r14'),
     (0x134, '0fb64c2418', 'field1-5 rawtag load'),
     (0x139, '80f912', 'field1-5 rawtag 0x12 test'),
     (0x13e, '488b442420', 'field1-5 value qword at result +0x8'),
     (0x143, '4c897b08', 'inline value stored at output +0x8'),
     (0x147, '48894310', 'field1-5 value stored at output +0x10'),
     (0x14b, '40886b18', 'flag byte stored at output +0x18'),
     (0x14f, 'c60312', 'success rawtag 0x12 at output +0x0')]
    for rel, hexs, message in pins:
        pin(body, rel, bytes.fromhex(hexs), f'{role} {message}')
    require(call_target(body, 0x15, base) == u32_target,
            f'{role} u32 call target changed')
    require(call_target(body, 0x12f, base) == f15_target,
            f'{role} field1-5 call target changed')
    disp = struct.unpack_from('<i', body, 0x34)[0]
    require(base + 0x31 + 7 + disp == string_va,
            f'{role} named string reference changed')
    require(read(data, string_va, 6)[1] == TWIN_STRING,
            f'{role} named string bytes changed')
    disp = struct.unpack_from('<i', body, 0x40)[0]
    require(base + 0x3d + 7 + disp == TWIN_STRING_B,
            f'{role} shared string reference changed')
    return {'u32_call': {'site': hex(base + 0x15),
                         'target': hex(u32_target),
                         'state': 'entry rsi, not yet reloaded',
                         'result': 'rsp+0x18'},
            'field1_5_call': {'site': hex(base + 0x12f),
                              'target': hex(f15_target),
                              'state': 'r14 (the saved entry rsi)',
                              'result': 'rsp+0x18'},
            'named_string': {'va': hex(string_va), 'length': 6,
                             'bytes': TWIN_STRING.decode()},
            'shared_string': hex(TWIN_STRING_B)}


def bulk_a_semantics(data):
    base = OWNERS['bulk_a'][0]
    _, body = read(data, base, OWNERS['bulk_a'][1] - base)
    pins = [
     (0x00b, '4989f6', 'state argument saved to r14'),
     (0x00e, '4889fb', 'result argument saved to rbx'),
     (0x011, '488d7c2408', 'first result buffer is rsp+0x8'),
     (0x01b, '0fb6442408', 'first rawtag load'),
     (0x020, '3c12', 'first rawtag 0x12 test'),
     (0x024, '4c8b642410', 'first value qword at result +0x8'),
     (0x029, '488d7c2408', 'second result buffer is rsp+0x8'),
     (0x02e, '4c89f6', 'second state argument is r14'),
     (0x036, '0fb6442408', 'second rawtag load'),
     (0x03f, '4c8b7c2410', 'second value qword at result +0x8'),
     (0x044, '41833e01', 'inline charge mode == 1 test at state +0x0'),
     (0x04a, '498b4e20', 'inline charge charged load at state +0x20'),
     (0x04e, 'b002', 'inline charge refusal tag 2'),
     (0x050, '4881f9fff7ffff', 'inline charge overflow bound '
      'charged > u64::MAX - 0x800'),
     (0x057, '0f87d2000000', 'inline charge overflow refusal branch'),
     (0x05d, '498b5608', 'inline charge limit load at state +0x8'),
     (0x061, '4881c100080000', 'inline charge increment 0x800'),
     (0x068, '49894e20', 'inline charge stored before the limit compare'),
     (0x06c, '4839d1', 'inline charge compares the new charged count'),
     (0x06f, '7717', 'inline charge refusal at new charged > limit'),
     (0x071, '498b4618', 'record remaining load at state +0x18'),
     (0x075, '483dff070000', 'record width test remaining > 0x7ff'),
     (0x07b, '774f', 'record consume branch'),
     (0x07d, '41bf00080000', 'record shortfall width 0x800'),
     (0x083, '4929c7', 'record shortfall additional is 0x800 - remaining'),
     (0x086, '31c0', 'record shortfall tag 0'),
     (0x088, '884308', 'record result tag store at output +0x8'),
     (0x0ac, 'b801000000', 'failure wrapper tag 1'),
     (0x0b1, 'b910000000', 'plain exit value offset 0x10'),
     (0x0b6, '4c893c0b', 'second value store at output + offset'),
     (0x0ba, '488903', 'wrapper tag store at output +0x0'),
     (0x0cc, '498b4e10', 'record cursor load at state +0x10'),
     (0x0d0, '488d9100080000', 'record cursor advance 0x800'),
     (0x0d7, '480500f8ffff', 'record remaining drop 0x800'),
     (0x0e9, '49895610', 'record cursor store at state +0x10'),
     (0x0ed, '49894618', 'record remaining store at state +0x18'),
     (0x110, '488d7b1f', 'record payload destination is output +0x1f'),
     (0x114, 'bae9070000', 'record payload copy length 0x7e9'),
     (0x119, 'ff15d95c8003', 'record payload copy through the memcpy slot'),
     (0x11f, '4c89a308080000', 'first value stored at output +0x808'),
     (0x126, 'b910080000', 'bulk exit value offset 0x810')]
    for rel, hexs, message in pins:
        pin(body, rel, bytes.fromhex(hexs), f'bulk_a {message}')
    require(call_target(body, 0x16, base) == F15_A,
            'bulk_a first field1-5 call target changed')
    require(call_target(body, 0x31, base) == F15_A,
            'bulk_a second field1-5 call target changed')
    slot = base + 0x119 + 6 + struct.unpack_from('<i', body, 0x11b)[0]
    require(slot == MEMCPY_SLOT, 'bulk_a memcpy slot changed')
    return {'field1_5_calls': [
             {'site': hex(base + 0x16), 'target': hex(F15_A),
              'state': 'entry rsi, not yet reloaded', 'result': 'rsp+0x8'},
             {'site': hex(base + 0x31), 'target': hex(F15_A),
              'state': 'r14 (the saved entry rsi)', 'result': 'rsp+0x8'}],
            'memcpy_slot': hex(MEMCPY_SLOT),
            'payload_copy_length': '0x7e9',
            'record_header_bytes': '0x17 bytes copied field by field '
                                   'from the cursor before the payload '
                                   'copy (0x17 + 0x7e9 = 0x800)'}


def bulk_b_semantics(data):
    base = OWNERS['bulk_b'][0]
    _, body = read(data, base, OWNERS['bulk_b'][1] - base)
    pins = [
     (0x00a, '4881ec00100000', 'first stack probe step 0x1000'),
     (0x011, '48c7042400000000', 'first stack probe store'),
     (0x019, '4881ec00100000', 'second stack probe step 0x1000'),
     (0x020, '48c7042400000000', 'second stack probe store'),
     (0x029, '4989f6', 'state argument saved to r14'),
     (0x02c, '4889fb', 'result argument saved to rbx'),
     (0x02f, '4889e7', 'first result buffer is rsp'),
     (0x037, '0fb60424', 'first rawtag load'),
     (0x03b, '3c12', 'first rawtag 0x12 test'),
     (0x03f, '4c8b642408', 'first value qword at result +0x8'),
     (0x044, '4889e7', 'second result buffer is rsp'),
     (0x047, '4c89f6', 'second state argument is r14'),
     (0x04f, '0fb60424', 'second rawtag load'),
     (0x057, '4c8b6c2408', 'second value qword at result +0x8'),
     (0x05c, '4889e7', 'helper result buffer is rsp'),
     (0x05f, '4c89f6', 'helper state argument is r14'),
     (0x067, '803c2401', 'helper result byte 1 test'),
     (0x06d, '0f10442408', 'helper failure payload load at result +0x8'),
     (0x072, '0f104c2418', 'helper failure payload load at result +0x18'),
     (0x087, '0f114b18', 'helper failure payload store at output +0x18'),
     (0x08b, '0f114308', 'helper failure payload store at output +0x8'),
     (0x0b4, '48c70301000000', 'failure wrapper tag 1'),
     (0x0d0, '488d742401', 'bulk source is the helper payload at result +0x1'),
     (0x0dd, '488b2de46bb700', 'memcpy pointer load through the slot'),
     (0x0e4, 'ba00080000', 'bulk copy length 0x800'),
     (0x126, '4c89a308080000', 'first value stored at output +0x808'),
     (0x12d, '4c89ab10080000', 'second value stored at output +0x810'),
     (0x134, '48c70300000000', 'success wrapper tag 0')]
    for rel, hexs, message in pins:
        pin(body, rel, bytes.fromhex(hexs), f'bulk_b {message}')
    require(call_target(body, 0x32, base) == F15_B,
            'bulk_b first field1-5 call target changed')
    require(call_target(body, 0x4a, base) == F15_B,
            'bulk_b second field1-5 call target changed')
    require(call_target(body, 0x62, base) == HELPER[0],
            'bulk_b helper call target changed')
    slot = base + 0xdd + 7 + struct.unpack_from('<i', body, 0xe0)[0]
    require(slot == MEMCPY_SLOT, 'bulk_b memcpy slot load changed')
    for rel in (0xec, 0x101, 0x116, 0x124):
        pin(body, rel, bytes.fromhex('ffd5'),
            'bulk_b staged memcpy call through the loaded pointer')
    return {'field1_5_calls': [
             {'site': hex(base + 0x32), 'target': hex(F15_B),
              'state': 'entry rsi, not yet reloaded', 'result': 'rsp'},
             {'site': hex(base + 0x4a), 'target': hex(F15_B),
              'state': 'r14 (the saved entry rsi)', 'result': 'rsp'}],
            'helper_call': {'site': hex(base + 0x62),
                            'target': hex(HELPER[0]),
                            'state': 'r14 (the saved entry rsi)',
                            'result': 'rsp'},
            'memcpy_slot': hex(MEMCPY_SLOT),
            'bulk_copy_length': '0x800',
            'bulk_copies': 'four staged copies of 0x800 bytes: '
                           'result +0x1 to rsp+0x1808 to rsp+0x1008 '
                           'to rsp+0x808 to output +0x8'}


def helper_semantics(data):
    base, end, sha = HELPER
    _, body = read(data, base, end - base)
    pins = [
     (0x000, '4889f8', 'helper result argument saved to rax'),
     (0x003, '833e01', 'helper charge mode == 1 test at state +0x0'),
     (0x006, '752a', 'helper uncharged branch to the width test'),
     (0x008, '488b4e20', 'helper charge charged load at state +0x20'),
     (0x00c, '4881f9fff7ffff', 'helper charge overflow bound '
      'charged > u64::MAX - 0x800'),
     (0x013, '7714', 'helper charge overflow refusal branch'),
     (0x015, '488b5608', 'helper charge limit load at state +0x8'),
     (0x019, '4881c100080000', 'helper charge increment 0x800'),
     (0x020, '48894e20', 'helper charge stored before the limit compare'),
     (0x024, '4839d1', 'helper charge compares the new charged count'),
     (0x027, '7609', 'helper charge acceptance at new charged <= limit'),
     (0x029, 'c6400802', 'helper refusal tag 2 at result +0x8'),
     (0x02d, 'b101', 'helper failure wrapper tag 1'),
     (0x02f, '8808', 'helper failure tag store at result +0x0'),
     (0x032, '488b5618', 'helper remaining load at state +0x18'),
     (0x036, '4881faff070000', 'helper width test remaining > 0x7ff'),
     (0x03d, '7715', 'helper consume branch'),
     (0x03f, 'b900080000', 'helper shortfall width 0x800'),
     (0x044, '4829d1', 'helper shortfall additional is 0x800 - remaining'),
     (0x047, 'c6400800', 'helper shortfall tag 0 at result +0x8'),
     (0x04b, '48894810', 'helper shortfall additional store at '
      'result +0x10'),
     (0x054, '53', 'helper consume saves rbx'),
     (0x055, '488b4e10', 'helper cursor load at state +0x10'),
     (0x059, '488db900080000', 'helper cursor advance 0x800'),
     (0x060, '4881c200f8ffff', 'helper remaining drop 0x800'),
     (0x067, '48897e10', 'helper cursor store at state +0x10'),
     (0x06b, '48895618', 'helper remaining store at state +0x18'),
     (0x06f, '488d7801', 'helper payload destination is result +0x1'),
     (0x073, 'ba00080000', 'helper payload copy length 0x800'),
     (0x078, '4889ce', 'helper payload source is the old cursor'),
     (0x07e, 'ff15d4dfcb00', 'helper payload copy through the memcpy slot'),
     (0x087, '31c9', 'helper success wrapper tag 0'),
     (0x08a, '8808', 'helper success tag store at result +0x0')]
    for rel, hexs, message in pins:
        pin(body, rel, bytes.fromhex(hexs), message)
    slot = base + 0x7e + 6 + struct.unpack_from('<i', body, 0x80)[0]
    require(slot == MEMCPY_SLOT, 'helper memcpy slot changed')
    require(hashlib.sha256(body).hexdigest() == sha,
            'bulk helper body changed')
    return {'fde': f'{base:#x}..{end:#x}', 'bytes': end - base,
            'sha256': sha,
            'role': 'shared fixed-record charge helper: performs the '
                    'mode-1 charge of 0x800 and, when the charge and '
                    'the remaining width allow, copies 0x800 bytes '
                    'from the cursor into its result at +0x1. Its '
                    'result byte at +0x0 is 0 on success and 1 on '
                    'failure, with +0x8 holding 2 for a charge '
                    'refusal and 0 for a shortfall (the additional '
                    'count then at +0x10). Recorded as a called '
                    'boundary of bulk_b, not a traced owner.'}


FRAMES = {'bulk_a': {'cie': {'bytes_hex': '1400000000000000017a5200017810011b0c070890010000',
                    'va': '0xca6ed8'},
            'fde': {'bytes_hex': '38000000f84f0e003cd8f4013401000000420e10420e18420e20410e28440e5083058c048e038f0202b90e28410e20420e18420e10420e08410e5000',
                    'va': '0xd8becc'}},
 'bulk_b': {'cie': {'bytes_hex': '1400000000000000017a5200017810011b0c070890010000',
                    'va': '0xca6ed8'},
            'fde': {'bytes_hex': '54000000844c3100e0cc9a044001000000410e10420e18420e20420e28420e30410e38470eb8204f0eb840490ec04083078c068d058e048f038602029c0e38410e30420e28420e20420e18420e10410e08410ec040000000',
                    'va': '0xfbbb58'}},
 'bulk_helper': {'cie': {'bytes_hex': '1400000000000000017a5200017810011b0c070890010000',
                         'va': '0xca6ed8'},
                 'fde': {'bytes_hex': '18000000e4552f00f04f88048d0000000002550e108302750e08c300',
                         'va': '0xf9c4b8'}},
 'twin_a': {'cie': {'bytes_hex': '1400000000000000017a5200017810011b0c070890010000',
                    'va': '0xca6ed8'},
            'fde': {'bytes_hex': '3800000068ee0900ccf99901c801000000410e10420e18420e20410e28440e6083058e048f03860202950e28410e20420e18420e10410e08410e6000',
                    'va': '0xd45d3c'}},
 'twin_b': {'cie': {'bytes_hex': '1400000000000000017a5200017810011b0c070890010000',
                    'va': '0xca6ed8'},
            'fde': {'bytes_hex': '3800000008ee31007c47ae04c801000000410e10420e18420e20410e28440e6083058e048f03860202950e28410e20420e18420e10410e08410e6000',
                    'va': '0xfc5cdc'}}}
REQUIRED_STARTS = {
 'twin_a': [0x26e5710, 0x26e5711, 0x26e5713, 0x26e5715, 0x26e5716,
            0x26e571a, 0x26e571d, 0x26e5720, 0x26e5725, 0x26e572a,
            0x26e572f, 0x26e5731, 0x26e5733, 0x26e5737, 0x26e5739,
            0x26e573b, 0x26e573f, 0x26e5741, 0x26e5748, 0x26e574d,
            0x26e5754, 0x26e5756, 0x26e575b, 0x26e575f, 0x26e5764,
            0x26e5768, 0x26e576c, 0x26e5771, 0x26e5776, 0x26e577b,
            0x26e577f, 0x26e5782, 0x26e5788, 0x26e578c, 0x26e5792,
            0x26e5797, 0x26e5799, 0x26e579c, 0x26e57a0, 0x26e57a4,
            0x26e57a8, 0x26e57ab, 0x26e57af, 0x26e57b0, 0x26e57b2,
            0x26e57b4, 0x26e57b5, 0x26e57b6, 0x26e57ba, 0x26e57be,
            0x26e57c0, 0x26e57c5, 0x26e57c8, 0x26e57ca, 0x26e57cc,
            0x26e57d0, 0x26e57d4, 0x26e57d8, 0x26e57db, 0x26e57df,
            0x26e57e3, 0x26e57e7, 0x26e57e9, 0x26e57ed, 0x26e57ef,
            0x26e57f4, 0x26e57f8, 0x26e57fe, 0x26e5802, 0x26e5806,
            0x26e580a, 0x26e580d, 0x26e5813, 0x26e5818, 0x26e581b,
            0x26e581d, 0x26e5821, 0x26e5825, 0x26e5829, 0x26e582d,
            0x26e5831, 0x26e5835, 0x26e5837, 0x26e583c, 0x26e583f,
            0x26e5844, 0x26e5849, 0x26e584c, 0x26e584e, 0x26e5853,
            0x26e5857, 0x26e585b, 0x26e585f, 0x26e5862, 0x26e5867,
            0x26e5869, 0x26e586b, 0x26e586d, 0x26e586f, 0x26e5874,
            0x26e5878, 0x26e587c, 0x26e5881, 0x26e5886, 0x26e588b,
            0x26e5890, 0x26e5895, 0x26e5899, 0x26e589e, 0x26e58a3,
            0x26e58a7, 0x26e58ab, 0x26e58ae, 0x26e58b3, 0x26e58b7,
            0x26e58bb, 0x26e58c0, 0x26e58c4, 0x26e58c8, 0x26e58ca,
            0x26e58ce, 0x26e58d1, 0x26e58d6],
 'twin_b': [0x5aaa460, 0x5aaa461, 0x5aaa463, 0x5aaa465, 0x5aaa466,
            0x5aaa46a, 0x5aaa46d, 0x5aaa470, 0x5aaa475, 0x5aaa47a,
            0x5aaa47f, 0x5aaa481, 0x5aaa483, 0x5aaa487, 0x5aaa489,
            0x5aaa48b, 0x5aaa48f, 0x5aaa491, 0x5aaa498, 0x5aaa49d,
            0x5aaa4a4, 0x5aaa4a6, 0x5aaa4ab, 0x5aaa4af, 0x5aaa4b4,
            0x5aaa4b8, 0x5aaa4bc, 0x5aaa4c1, 0x5aaa4c6, 0x5aaa4cb,
            0x5aaa4cf, 0x5aaa4d2, 0x5aaa4d8, 0x5aaa4dc, 0x5aaa4e2,
            0x5aaa4e7, 0x5aaa4e9, 0x5aaa4ec, 0x5aaa4f0, 0x5aaa4f4,
            0x5aaa4f8, 0x5aaa4fb, 0x5aaa4ff, 0x5aaa500, 0x5aaa502,
            0x5aaa504, 0x5aaa505, 0x5aaa506, 0x5aaa50a, 0x5aaa50e,
            0x5aaa510, 0x5aaa515, 0x5aaa518, 0x5aaa51a, 0x5aaa51c,
            0x5aaa520, 0x5aaa524, 0x5aaa528, 0x5aaa52b, 0x5aaa52f,
            0x5aaa533, 0x5aaa537, 0x5aaa539, 0x5aaa53d, 0x5aaa53f,
            0x5aaa544, 0x5aaa548, 0x5aaa54e, 0x5aaa552, 0x5aaa556,
            0x5aaa55a, 0x5aaa55d, 0x5aaa563, 0x5aaa568, 0x5aaa56b,
            0x5aaa56d, 0x5aaa571, 0x5aaa575, 0x5aaa579, 0x5aaa57d,
            0x5aaa581, 0x5aaa585, 0x5aaa587, 0x5aaa58c, 0x5aaa58f,
            0x5aaa594, 0x5aaa599, 0x5aaa59c, 0x5aaa59e, 0x5aaa5a3,
            0x5aaa5a7, 0x5aaa5ab, 0x5aaa5af, 0x5aaa5b2, 0x5aaa5b7,
            0x5aaa5b9, 0x5aaa5bb, 0x5aaa5bd, 0x5aaa5bf, 0x5aaa5c4,
            0x5aaa5c8, 0x5aaa5cc, 0x5aaa5d1, 0x5aaa5d6, 0x5aaa5db,
            0x5aaa5e0, 0x5aaa5e5, 0x5aaa5e9, 0x5aaa5ee, 0x5aaa5f3,
            0x5aaa5f7, 0x5aaa5fb, 0x5aaa5fe, 0x5aaa603, 0x5aaa607,
            0x5aaa60b, 0x5aaa610, 0x5aaa614, 0x5aaa618, 0x5aaa61a,
            0x5aaa61e, 0x5aaa621, 0x5aaa626],
 'bulk_a': [0x2cd9710, 0x2cd9712, 0x2cd9714, 0x2cd9716, 0x2cd9717,
            0x2cd971b, 0x2cd971e, 0x2cd9721, 0x2cd9726, 0x2cd972b,
            0x2cd9730, 0x2cd9732, 0x2cd9734, 0x2cd9739, 0x2cd973e,
            0x2cd9741, 0x2cd9746, 0x2cd974b, 0x2cd974d, 0x2cd974f,
            0x2cd9754, 0x2cd9758, 0x2cd975a, 0x2cd975e, 0x2cd9760,
            0x2cd9767, 0x2cd976d, 0x2cd9771, 0x2cd9778, 0x2cd977c,
            0x2cd977f, 0x2cd9781, 0x2cd9785, 0x2cd978b, 0x2cd978d,
            0x2cd9793, 0x2cd9796, 0x2cd9798, 0x2cd979b, 0x2cd979d,
            0x2cd97a1, 0x2cd97a5, 0x2cd97a8, 0x2cd97ab, 0x2cd97b0,
            0x2cd97b5, 0x2cd97b9, 0x2cd97bc, 0x2cd97c1, 0x2cd97c6,
            0x2cd97ca, 0x2cd97cd, 0x2cd97d0, 0x2cd97d4, 0x2cd97d5,
            0x2cd97d7, 0x2cd97d9, 0x2cd97db, 0x2cd97dc, 0x2cd97e0,
            0x2cd97e7, 0x2cd97ed, 0x2cd97f1, 0x2cd97f5, 0x2cd97f9,
            0x2cd97fd, 0x2cd9801, 0x2cd9803, 0x2cd9806, 0x2cd9809,
            0x2cd980c, 0x2cd980f, 0x2cd9812, 0x2cd9815, 0x2cd9818,
            0x2cd981c, 0x2cd9820, 0x2cd9824, 0x2cd9829, 0x2cd982f,
            0x2cd9836, 0x2cd983b, 0x2cd983d, 0x2cd983f],
 'bulk_b': [0x5968840, 0x5968841, 0x5968843, 0x5968845, 0x5968847,
            0x5968849, 0x596884a, 0x5968851, 0x5968859, 0x5968860,
            0x5968868, 0x5968869, 0x596886c, 0x596886f, 0x5968872,
            0x5968877, 0x596887b, 0x596887d, 0x596887f, 0x5968884,
            0x5968887, 0x596888a, 0x596888f, 0x5968893, 0x5968895,
            0x5968897, 0x596889c, 0x596889f, 0x59688a2, 0x59688a7,
            0x59688ab, 0x59688ad, 0x59688b2, 0x59688b7, 0x59688bf,
            0x59688c7, 0x59688cb, 0x59688cf, 0x59688d1, 0x59688d5,
            0x59688d9, 0x59688dc, 0x59688df, 0x59688e4, 0x59688e9,
            0x59688ed, 0x59688f0, 0x59688f4, 0x59688fb, 0x59688fe,
            0x5968905, 0x5968906, 0x5968908, 0x596890a, 0x596890c,
            0x596890e, 0x596890f, 0x5968910, 0x5968915, 0x596891d,
            0x5968924, 0x5968929, 0x596892c, 0x596892e, 0x5968936,
            0x596893b, 0x596893e, 0x5968941, 0x5968943, 0x596894b,
            0x5968950, 0x5968953, 0x5968956, 0x5968958, 0x596895c,
            0x5968961, 0x5968964, 0x5968966, 0x596896d, 0x5968974,
            0x596897b],
 'bulk_helper': [0x58214b0, 0x58214b3, 0x58214b6, 0x58214b8, 0x58214bc,
            0x58214c3, 0x58214c5, 0x58214c9, 0x58214d0, 0x58214d4,
            0x58214d7, 0x58214d9, 0x58214dd, 0x58214df, 0x58214e1,
            0x58214e2, 0x58214e6, 0x58214ed, 0x58214ef, 0x58214f4,
            0x58214f7, 0x58214fb, 0x58214ff, 0x5821501, 0x5821503,
            0x5821504, 0x5821505, 0x5821509, 0x5821510, 0x5821517,
            0x582151b, 0x582151f, 0x5821523, 0x5821528, 0x582152b,
            0x582152e, 0x5821534, 0x5821537, 0x5821539, 0x582153a,
            0x582153c]
}
STATE_REG = {'twin_a': 'r14', 'twin_b': 'r14', 'bulk_a': 'r14',
             'bulk_b': 'r14', 'bulk_helper': 'rsi'}
EXPECTED_ACCESS = {
 'twin_a': {'reads': ['+0x0', '+0x8', '+0x10', '+0x18', '+0x20'],
            'stores': ['+0x10', '+0x18', '+0x20']},
 'twin_b': {'reads': ['+0x0', '+0x8', '+0x10', '+0x18', '+0x20'],
            'stores': ['+0x10', '+0x18', '+0x20']},
 'bulk_a': {'reads': ['+0x0', '+0x8', '+0x10', '+0x18', '+0x20'],
            'stores': ['+0x10', '+0x18', '+0x20']},
 'bulk_b': {'reads': [], 'stores': []},
 'bulk_helper': {'reads': ['+0x0', '+0x8', '+0x10', '+0x18', '+0x20'],
                 'stores': ['+0x10', '+0x18', '+0x20']}}


def exports(data):
    """objdump exports and instruction maps for the owners + helper."""
    ranges = dict(OWNERS)
    ranges['bulk_helper'] = HELPER
    out = {}
    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / 'hl-node'
        snapshot.write_bytes(data)
        for role, (a, b, _) in ranges.items():
            asm = subprocess.check_output(
             ['objdump', '-d', '-M', 'intel', '--insn-width=16',
              f'--start-address={a:#x}', f'--stop-address={b:#x}',
              str(snapshot)], text=True)
            ins = decode_export(asm, a, b, read(data, a, b - a)[1])
            for va in REQUIRED_STARTS[role]:
                require(va in ins, f'{role} instruction start missing')
            out[role] = (asm, ins)
    return out


def access_inventory(role, asm):
    """Sorted state-field offsets read / stored via the state register."""
    reg = STATE_REG[role]
    reads, stores = set(), set()
    for line in asm.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+(.*)$', line)
        if not m:
            continue
        text = m[2]
        hit = re.search(r'\[' + reg + r'(?:\+0x([0-9a-f]+))?\]', text)
        if not hit:
            continue
        off = '+0x' + (hit[1] or '0')
        mnemonic = text.split(None, 1)[0]
        operands = text.split(None, 1)[1] if ' ' in text else ''
        first = operands.split(',')[0]
        if mnemonic in ('mov', 'movups', 'movaps') and (
                '[' + reg in first):
            stores.add(off)
        else:
            reads.add(off)
    return {'reads': sorted(reads, key=lambda x: int(x, 16)),
            'stores': sorted(stores, key=lambda x: int(x, 16))}


def census(data):
    """Direct E8 call sites for the reader families and the owners,
    plus the rip-relative lea references to the twins."""
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

    targets = {F15_A: 'field1_5_copy_a', F15_B: 'field1_5_copy_b',
               F15_SLOW: 'field1_5_slow', U32_A: 'u32_copy_a',
               U32_B: 'u32_copy_b', U64_A: 'u64_copy_a',
               U64_B: 'u64_copy_b', HELPER[0]: 'bulk_helper'}
    for role, (a, _, _) in OWNERS.items():
        targets[a] = role
    calls = {name: [] for name in targets.values()}
    i = body.find(b'\xe8')
    while i != -1:
        va = base + i
        t = va + 5 + struct.unpack_from('<i', body, i + 1)[0]
        if t in targets:
            c = containing(va)
            calls[targets[t]].append(
             {'site': hex(va),
              'containing_fde': (f'{c[0]:#x}..{c[1]:#x}' if c else None)})
        i = body.find(b'\xe8', i + 1)
    lea_refs = {hex(OWNERS[r][0]): [] for r in ('twin_a', 'twin_b')}
    for pat in (b'\x48\x8d', b'\x4c\x8d'):
        j = body.find(pat)
        while j != -1:
            if j + 7 <= size:
                tgt = base + j + 7 + struct.unpack_from('<i', body, j + 3)[0]
                if hex(tgt) in lea_refs:
                    lea_refs[hex(tgt)].append(hex(base + j))
            j = body.find(pat, j + 1)
    return calls, {k: sorted(v) for k, v in lea_refs.items()}, containing


def analyze(data):
    by_offset = relocations(data)
    entries = [e for e in by_offset.get(MEMCPY_SLOT, []) if e[0] == 6]
    require(len(entries) == 1, 'memcpy slot relocation changed')
    require(dynsym_name(data, entries[0][1]) == 'memcpy',
            'memcpy slot symbol changed')
    require(entries[0][2] == 0, 'memcpy slot addend changed')
    twins = {'twin_a': twin_semantics(data, 'twin_a', OWNERS['twin_a'][0],
                                      U32_A, F15_A, 0x5f430e),
             'twin_b': twin_semantics(data, 'twin_b', OWNERS['twin_b'][0],
                                      U32_B, F15_B, 0x93a9f1)}
    bulk_a = bulk_a_semantics(data)
    bulk_b = bulk_b_semantics(data)
    helper = helper_semantics(data)
    _, ta = read(data, OWNERS['twin_a'][0], 456)
    _, tb = read(data, OWNERS['twin_b'][0], 456)
    diff = [i for i in range(456) if ta[i] != tb[i]]
    require(all(0x16 <= i < 0x1a or 0x34 <= i < 0x38 or 0x40 <= i < 0x44
                or 0x130 <= i < 0x134 for i in diff),
            'twin bodies differ outside the call/string displacements')
    exps = exports(data)
    access = {}
    for role in list(OWNERS) + ['bulk_helper']:
        access[role] = access_inventory(role, exps[role][0])
        require(access[role] == EXPECTED_ACCESS[role],
                f'{role} state-field access inventory changed')
        for off in access[role]['stores']:
            require(off not in ('+0x0', '+0x8'),
                    f'{role} writes the mode or limit field')
    calls, lea_refs, containing = census(data)
    require(calls['field1_5_copy_a'] == [
             {'site': '0x26e583f',
              'containing_fde': '0x26e5710..0x26e58d8'},
             {'site': '0x2cd9726',
              'containing_fde': '0x2cd9710..0x2cd9844'},
             {'site': '0x2cd9741',
              'containing_fde': '0x2cd9710..0x2cd9844'}],
            'field1-5 copy-a call census changed')
    require(calls['field1_5_copy_b'] == [
             {'site': '0x5968872',
              'containing_fde': '0x5968840..0x5968980'},
             {'site': '0x596888a',
              'containing_fde': '0x5968840..0x5968980'},
             {'site': '0x5aaa58f',
              'containing_fde': '0x5aaa460..0x5aaa628'}],
            'field1-5 copy-b call census changed')
    require(calls['field1_5_slow'] == [],
            'field1-5 slow reader direct caller appeared')
    owner_fdes = {f"{OWNERS[r][0]:#x}..{OWNERS[r][1]:#x}" for r in OWNERS}
    u32_in = [c for r in ('u32_copy_a', 'u32_copy_b') for c in calls[r]
              if c['containing_fde'] in owner_fdes]
    require(u32_in == [
             {'site': '0x26e5725',
              'containing_fde': '0x26e5710..0x26e58d8'},
             {'site': '0x5aaa475',
              'containing_fde': '0x5aaa460..0x5aaa628'}],
            'u32 calls inside the owners changed')
    u64_in = [c for r in ('u64_copy_a', 'u64_copy_b') for c in calls[r]
              if c['containing_fde'] in owner_fdes]
    require(u64_in == [], 'u64 call appeared inside an owner')
    require(calls['twin_a'] == [] and calls['twin_b'] == [],
            'a twin gained a direct call site')
    require([c['site'] for c in calls['bulk_a']] ==
            ['0x2ce1e4d', '0x2ce20e6', '0x2ce230b'],
            'bulk_a direct caller census changed')
    require([c['site'] for c in calls['bulk_b']] ==
            ['0x4e05c56', '0x4e05ca0', '0x4e05ce5'],
            'bulk_b direct caller census changed')
    require([c['site'] for c in calls['bulk_helper']] == ['0x59688a2'],
            'bulk helper caller census changed')
    require(lea_refs == {'0x26e5710': ['0x2dd298e'],
                         '0x5aaa460': ['0x4de621e']},
            'twin lea reference census changed')
    reg_a = containing(0x2dd298e)
    reg_b = containing(0x4de621e)
    _, fs, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs}
    owners = []
    frame_records = {}
    ranges = dict(OWNERS)
    ranges['bulk_helper'] = HELPER
    for role, (a, b, sha) in ranges.items():
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
        require(records == FRAMES[role], f'{role} frame records changed')
        frame_records[role] = records
        if role in OWNERS:
            owners.append({'role': role, 'start': hex(a), 'end': hex(b),
                           'file_offset': hex(offset), 'bytes': b - a,
                           'sha256': sha, 'frames': records})
    helper['frames'] = frame_records['bulk_helper']
    return {
     'target_sha256': SHA,
     'owners': owners,
     'reader_state': {
      'mode': 'state +0x0, dword; read by the twin and bulk_a inline '
              'charge blocks and by the helper (== 1 test); written by '
              'none of the traced functions',
      'limit': 'state +0x8, u64; read by the same charge blocks; '
               'written by none of the traced functions',
      'cursor': 'state +0x10, pointer; advanced by the readers, by '
                'the twin inline read and by the bulk record reads',
      'remaining': 'state +0x18, u64; decremented alongside the '
                   'cursor',
      'charged_count': 'state +0x20, u64; the mode-1 charge ledger '
                       'the inline blocks and the helper add to'},
     'call_sites': {
      'twin_a': twins['twin_a'], 'twin_b': twins['twin_b'],
      'bulk_a': bulk_a, 'bulk_b': bulk_b,
      'field1_5_census': {'copy_a': calls['field1_5_copy_a'],
                          'copy_b': calls['field1_5_copy_b'],
                          'slow': calls['field1_5_slow']}},
     'inline_charges': {
      'twin_inline': {
       'amount': 1, 'subject': 'the inline four-byte read',
       'committed_before_charge': 'the read itself: cursor +4 and '
        'remaining -4 are stored before the mode test, so a charge '
        'refusal still leaves the state advanced by four bytes; the '
        'flag byte that follows is charge-gated',
       'overflow': 'charged == u64::MAX refuses (tag 2)',
       'rule': 'charged + 1 is stored before the compare; refusal '
               'iff the OLD charged count >= limit, i.e. success iff '
               'charged + 1 <= limit'},
      'bulk_a_inline': {
       'amount': '0x800', 'subject': 'the fixed 0x800-byte record',
       'overflow': 'charged > u64::MAX - 0x800 refuses (tag 2)',
       'rule': 'charged + 0x800 is stored before the compare; '
               'refusal iff the NEW charged count > limit, i.e. '
               'success iff charged + 0x800 <= limit'},
      'bulk_helper': {
       'amount': '0x800', 'subject': 'the fixed 0x800-byte record',
       'overflow': 'charged > u64::MAX - 0x800 refuses (result +0x8 '
                   'tag 2)',
       'rule': 'same store-before-compare rule as the bulk_a inline '
               'block: refusal iff the new charged count > limit'},
      'uniform_bound': 'every charge traced here and in the reader '
       'packets (#2412 charge 4, #2422/#2300 charge 8) succeeds '
       'under the same bound: new charged count <= limit'},
     'state_field_access': access,
     'cross_family': {
      'u32_inside_owners': u32_in,
      'u64_inside_owners': u64_in,
      'finding': 'each twin calls the u32 reader first and the '
       'field1-5 reader later in the same invocation, both times '
       'with the identical state pointer (its entry argument) and '
       'the identical result buffer (rsp+0x18): one input stream '
       'through one state can therefore produce a field1 2 error '
       'from the first read and a field1 5 error from the second. '
       'No u64-family call occurs in any of the four owners, so '
       'the field1 2/3 results of that family are not produced on '
       'these states inside the traced functions. bulk_a is also '
       'called by a function (0x2ce1dc0) that first reads a u32 '
       'discriminant on the same state it passes on.'},
     'direct_callers': {
      'twin_a': {'direct_calls': calls['twin_a'],
                 'lea_references': lea_refs['0x26e5710'],
                 'lea_fde': f'{reg_a[0]:#x}..{reg_a[1]:#x}',
                 'note': 'the referencing function passes the twin '
                         'address in rdx, with a stack result buffer '
                         'in rdi, to a helper call at 0x2dd299a '
                         '(target 0x232cd90); the helper is a '
                         'boundary, its forwarding is not traced'},
      'twin_b': {'direct_calls': calls['twin_b'],
                 'lea_references': lea_refs['0x5aaa460'],
                 'lea_fde': f'{reg_b[0]:#x}..{reg_b[1]:#x}',
                 'note': 'same shape as twin_a: helper call at '
                         '0x4de622a (target 0x58251a0), a boundary'},
      'bulk_a': {'direct_calls': calls['bulk_a'],
                 'note': 'all three sites sit in FDE '
                         '0x2ce1dc0..0x2ce2a32 and pass that '
                         "function's own entry state argument (r14); "
                         'the same function first calls the u32 '
                         'copy-a reader at 0x2ce1e0c on that state'},
      'bulk_b': {'direct_calls': calls['bulk_b'],
                 'note': 'all three sites sit in FDE '
                         '0x4e05c10..0x4e05dd8 and pass that '
                         "function's own entry state argument (r15); "
                         'the function repeats the call, copying '
                         'each non-terminal result out, until a '
                         'result with first dword 1 arrives'}},
     'boundaries': {
      'bulk_helper': helper,
      'field1_5_readers': 'copies 0x2cd7bb0/0x5821340 and the slow '
       'reader 0x5822710 are the owners of the open field1-5 reader '
       'packet (#2422); recorded here only as call targets',
      'u32_readers': 'copies 0x2cd79c0/0x5821150 are the owners of '
       'the open u32 reader packet (#2412); recorded here only as '
       'call targets',
      'u64_readers': 'copies 0x2cd7ac0/0x5821250 are owned by the '
       'open u64 reader packet (#2300); no call to either occurs in '
       'the traced functions',
      'memcpy_slot': 'GOT slot 0x64df508, R_X86_64_GLOB_DAT against '
       'the dynamic symbol memcpy (glibc); bulk_a and the helper '
       'call through the slot, bulk_b loads the pointer from the '
       'slot and calls it four times',
      'twin_helpers': 'the helpers at 0x232cd90 and 0x58251a0 that '
       'receive the twin addresses are not traced; whether they '
       'forward a state unchanged is outside this packet'},
     'relocations': {hex(MEMCPY_SLOT): {'type': 6, 'symbol': 'memcpy',
                                        'addend': 0}},
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
        native = subprocess.check_output(['readelf', '-wf', str(snapshot)],
                                         text=True)
        ranges = dict(OWNERS)
        ranges['bulk_helper'] = HELPER
        wanted = []
        for a, b, _ in ranges.values():
            needle = f'pc={a:016x}..{b:016x}'
            wanted += [ln for ln in native.splitlines() if needle in ln]
        require(len(wanted) == len(ranges), 'owner frame lines missing')
        (output / 'frames.txt').write_text('\n'.join(wanted) + '\n')
        for role, (a, b, _) in ranges.items():
            asm = subprocess.check_output(
             ['objdump', '-d', '-M', 'intel', '--insn-width=16',
              f'--start-address={a:#x}', f'--stop-address={b:#x}',
              str(snapshot)], text=True)
            ins = decode_export(asm, a, b, read(data, a, b - a)[1])
            for va in REQUIRED_STARTS[role]:
                require(va in ins, f'{role} instruction start missing')
            (output / f'{role}.objdump.txt').write_bytes(
             asm.replace(str(snapshot), '<authenticated-node115>')
             .encode('utf-8'))
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
