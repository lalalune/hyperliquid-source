#!/usr/bin/env python3
"""Regenerate the RE-005 node 115 rmp-signable tag-source packet.

The chain-top packet (RE-005-node115-rmp-signable-chain-top) grounded
both dispatcher entries of the rmp_signable serializer chain and left
one question open: what the two tag source bytes denote -- the object
the top FDE's container field +0x10 points through to, and the field
at +0x11d of the record the grand_b_caller FDE receives -- and which
values they take. This tool traces both source bytes exactly one
level higher, to the writers the static bytes pin: the five direct
callers of the top_caller FDE and the adapter chain above one of
them (grand_a path), and the seven FDEs that hold the twelve
indirect call sites into the grand_b_caller FDE (grand_b path),
without executing the captured code.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-005-node115-rmp-signable-tag-source'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TOP_CALLER = (0x3ebdd10, 0x3ebdf64)
GRAND_B_CALLER = (0x38d9c60, 0x38d9edc)
GRAND_B_CALLER_SLOT = 0x64e6c60
RELA_RELATIVE = 8
GA_A1 = (0x35c57e0, 0x35c588f)
GA_A2 = (0x35c9c80, 0x35ca1c1)
GA_A3 = (0x3719a90, 0x3719c4b)
GA_A4 = (0x3b87c20, 0x3b880dc)
GA_A5 = (0x4301ce0, 0x4301e82)
GA_A5_THUNK = (0x3d9d160, 0x3d9d16c)
GA_A5_FEEDER = (0x3713530, 0x37136cb)
GB_B1 = (0x294af20, 0x294b127)
GB_B2 = (0x2ae41e0, 0x2ae6d66)
GB_B3 = (0x2cde430, 0x2ce0dd1)
GB_B4 = (0x2e098e0, 0x2e11140)
GB_B5 = (0x5a70c20, 0x5a70cb5)
GB_B6 = (0x5a70cc0, 0x5a70d55)
GB_B7 = (0x5a70d60, 0x5a70e1c)
OWNERS = {'ga_a1': GA_A1, 'ga_a2': GA_A2, 'ga_a3': GA_A3, 'ga_a4': GA_A4,
          'ga_a5': GA_A5, 'ga_a5_thunk': GA_A5_THUNK,
          'ga_a5_feeder': GA_A5_FEEDER,
          'gb_b1': GB_B1, 'gb_b2': GB_B2, 'gb_b3': GB_B3,
          'gb_b4': GB_B4, 'gb_b5': GB_B5, 'gb_b6': GB_B6, 'gb_b7': GB_B7}
# Owners larger than the export limit are retained as hash + pins with
# window exports around every pinned span.
WINDOWS = {
    'gb_b2': [(0x2ae41e0, 0x2ae4292), (0x2ae443c, 0x2ae44e3),
              (0x2ae4cce, 0x2ae4d6a), (0x2ae515e, 0x2ae51d6),
              (0x2ae5739, 0x2ae57a5)],
    'gb_b3': [(0x2cde430, 0x2cde4b0), (0x2cde546, 0x2cde57a),
              (0x2cdedc7, 0x2cdee55), (0x2cdf24b, 0x2cdf2bb),
              (0x2cdf83e, 0x2cdf89f)],
    'gb_b4': [(0x2e098e0, 0x2e09932), (0x2e09af0, 0x2e09c0f),
              (0x2e09f47, 0x2e0a095)],
}
# Relied-upon links from the earlier chain packets, re-verified here.
SERIALIZER_TAG_PINS = [
    (0x36aac32, '4080fd03', 'compare tag argument against 3'),
    (0x36aac39, 'b262', 'tag byte base 0x62'),
    (0x36aac3b, '28ca', 'tag byte subtraction'),
    (0x36aac3d, '8810', 'store of the tag byte'),
]
CHAIN_LINK_PINS = [
    (0x371336c, '0fb610', 'top FDE tag byte load (chain-top packet)'),
    (0x38d9c77, '0fb6ae1d010000', 'grand_b_caller tag byte capture (chain-top packet)'),
]
GA_PINS = {
    'ga_a1': [
        (0x35c580d, '488d7b28', 'container base is the record +0x28 sub-struct'),
        (0x35c5818, '488b4710', 'container field 2 load from record +0x38'),
        (0x35c581c, '4889442410', 'container field 2 stored to the frame copy'),
        (0x35c5821, '0f1007', 'container fields 0/1 load from record +0x28'),
        (0x35c5824, '0f290424', 'container fields 0/1 stored to the frame copy'),
        (0x35c5828, '4889e0', 'stack argument 8 is the frame container copy'),
        (0x35c582b, '0fb6d2', 'the caller byte argument is zero-extended'),
    ],
    'ga_a2': [
        (0x35c9e27, '410f104760', 'container fields 0/1 load from the record +0x60'),
        (0x35c9e2c, '0f298424c0000000', 'container fields 0/1 stored to the frame copy'),
        (0x35c9e1b, '498b4f70', 'container field 2 load from the record +0x70'),
        (0x35c9e1f, '48898c24d0000000', 'container field 2 stored to the frame copy'),
        (0x35c9e3e, '488d8424c0000000', 'stack argument 8 is the frame container copy'),
        (0x35c9e4e, 'ba01000000', 'the caller discriminator argument is the constant 1'),
        (0x35c9d84, '488d1505fd1400', 'ga_a3 address materialised for the registry'),
        (0x35ca001, '488db424c0000000', 'ga_a1 record argument is the frame container copy'),
    ],
    'ga_a3': [
        (0x3719acc, '488d7b28', 'container base is the record +0x28 sub-struct'),
        (0x3719ad7, '488b5710', 'container field 2 load from record +0x38'),
        (0x3719adb, '4889542450', 'container field 2 stored to the frame copy'),
        (0x3719ae0, '0f1007', 'container fields 0/1 load from record +0x28'),
        (0x3719ae3, '0f29442440', 'container fields 0/1 stored to the frame copy'),
        (0x3719ae8, '4c8d542440', 'stack argument 8 is the frame container copy'),
        (0x3719af2, 'ba01000000', 'the caller discriminator argument is the constant 1'),
    ],
    'ga_a4': [
        (0x3b87dab, '498b4d70', 'container field 2 load from the record +0x70'),
        (0x3b87daf, '48898c24c0000000', 'container field 2 stored to the frame copy'),
        (0x3b87db7, '410f104560', 'container fields 0/1 load from the record +0x60'),
        (0x3b87dbc, '0f298424b0000000', 'container fields 0/1 stored to the frame copy'),
        (0x3b87dce, '488d8424b0000000', 'stack argument 8 is the frame container copy'),
        (0x3b87dde, '31d2', 'the caller discriminator argument is the constant 0'),
        (0x3b87d1c, '4c8d256d1db9ff', 'ga_a3 address materialised for the registry'),
        (0x3b87d23, '4c892430', 'ga_a3 address stored into the registry slot'),
        (0x3b87d27, '488d5c2430', 'registry context is a frame record'),
        (0x3b87d2c, '48895c3008', 'registry context stored beside the ga_a3 address'),
        (0x3b87f95, '488db424b0000000', 'ga_a1 record argument is the frame container copy'),
    ],
    'ga_a5': [
        (0x4301d29, '0f1002', 'record fields 0/1 load from the third argument'),
        (0x4301d2c, '0f29442430', 'record fields 0/1 stored to the frame copy'),
        (0x4301d31, '488b4210', 'record field 2 load from the third argument +0x10'),
        (0x4301d35, '4889442440', 'record field 2 stored to the frame copy'),
        (0x4301d7b, '488d442440', 'container field 0 is the address of the field 2 copy'),
        (0x4301d80, '48890424', 'container field 0 stored'),
        (0x4301d84, '48896c2408', 'container field 1 is the computed element pointer'),
        (0x4301d89, '4c89742410', 'container field 2 is the second argument'),
        (0x4301d8e, '4889e0', 'stack argument 8 is the frame container'),
        (0x4301d9f, '31d2', 'the caller discriminator argument is the constant 0'),
    ],
    'ga_a5_thunk': [
        (0x3d9d160, '4889f2', 'the record argument is the caller second argument'),
        (0x3d9d163, '488b7608', 'the second argument is the record field +0x8'),
    ],
    'ga_a5_feeder': [
        (0x3713549, '488b1a', 'container range begin load from the third argument'),
        (0x371354c, '4c8b7a08', 'container range end load from the third argument +0x8'),
        (0x3713559, '4c8b6a10', 'tag cell pointer load from the third argument +0x10'),
        (0x3713590, '498b4500', 'tag byte pointer load through the tag cell'),
        (0x3713598, '0fb600', 'tag byte loaded through that pointer'),
        (0x371359b, '8844240f', 'tag byte stored to the frame byte at +0xf'),
        (0x371359f, '0f104118', 'record head load from the element record'),
        (0x37135be, '0f11442470', 'record head stored to the frame record at +0x70'),
        (0x37135c3, '488d44240f', 'record field +0x10 is the frame tag byte address'),
        (0x37135c8, '4889842480000000', 'record field +0x10 stored'),
        (0x37135d0, '488d7c2418', 'thunk first argument is a frame descriptor'),
        (0x37135d5, '488d742470', 'thunk record argument is the frame record at +0x70'),
    ],
}
FEEDER_CALL_SITE = 0x37135da
THUNK_JUMP_SITE = 0x3d9d167
GA_CALL_SITES = {'ga_a1': 0x35c5834, 'ga_a2': 0x35c9e56, 'ga_a3': 0x3719afa,
                 'ga_a4': 0x3b87de3, 'ga_a5': 0x4301da7}
GA_A1_CALL_SITES = {'ga_a2': 0x35ca00e, 'ga_a4': 0x3b87f9f}
# Store encodings that could write the container fields of each
# caller's input record, for the negative census: (prefixes, ModRM
# bytes for [base+disp8], displacements). The census is over exactly
# these encodings and no others.
GA_STORE_CENSUS = {
    'ga_a1': (['0f11', '4889', '89', 'c643'],
              [0x43, 0x4b, 0x53, 0x5b, 0x63, 0x6b, 0x73, 0x7b], [0x28, 0x30, 0x38]),
    'ga_a3': (['0f11', '4889', '89', 'c643'],
              [0x43, 0x4b, 0x53, 0x5b, 0x63, 0x6b, 0x73, 0x7b], [0x28, 0x30, 0x38]),
    'ga_a2': (['410f11', '4d89', '4989', '41c647'],
              [0x47, 0x4f, 0x57, 0x5f, 0x67, 0x6f, 0x77, 0x7f], [0x60, 0x68, 0x70]),
    'ga_a4': (['410f11', '4d89', '4989', '41c645'],
              [0x45, 0x4d, 0x55, 0x5d, 0x65, 0x6d, 0x75, 0x7d], [0x60, 0x68, 0x70]),
    'ga_a5': (['0f11', '4889', '89', 'c642'],
              [0x42, 0x4a, 0x52, 0x5a, 0x62, 0x6a, 0x72, 0x7a], [0x00, 0x08, 0x10]),
}
GB_PINS = {
    'gb_b1': [
        (0x294af56, '488b4f18', 'tag pointer field load from the first argument +0x18'),
        (0x294af5a, '48894c2438', 'tag pointer saved to the frame slot +0x38'),
        (0x294afb0, '488b442438', 'tag pointer reloaded at the loop head'),
        (0x294afb5, '440fb620', 'tag byte loaded through the tag pointer'),
        (0x294b03f, '48c744246001000000', 'record field +0x00 is the constant 1'),
        (0x294b048, '4889442468', 'record field +0x08 is the helper call result'),
        (0x294b04d, '48c7442470c2000000', 'record field +0x10 is the constant 0xc2'),
        (0x294b056, 'c644247802', 'record byte +0x18 is the constant 2'),
        (0x294b082, '4889842460010000', 'record field +0x100 is the first argument +0x10 field'),
        (0x294b08a, 'c684246801000000', 'record byte +0x108 is the constant 0'),
        (0x294b092, '4488a4247d010000', 'tag byte stored to record +0x11d'),
        (0x294b09d, '488d742460', 'record argument is the frame record at +0x60'),
    ],
    'gb_b2': [
        (0x2ae41f1, '4889fb', 'the context object is the first argument'),
        (0x2ae44c8, '8bbba0000000', 'tag field source is the dword at object +0xa0'),
        (0x2ae44ce, '4088bbe8010000', 'tag field of the object written from that dword low byte'),
        (0x2ae4cce, '0fb6abe8010000', 'site 1 tag byte loaded from object +0x1e8'),
        (0x2ae4cdc, '48c78424d000000001000000', 'site 1 record field +0x00 is the constant 1'),
        (0x2ae4cf0, '48c78424e000000097000000', 'site 1 record field +0x10 is the constant 0x97'),
        (0x2ae4d4c, '4088ac24ed010000', 'site 1 tag byte stored to record +0x11d'),
        (0x2ae4d5c, '488db424d0000000', 'site 1 record argument is the frame record at +0xd0'),
        (0x2ae515e, '0fb6abe8010000', 'site 2 tag byte loaded from object +0x1e8'),
        (0x2ae5184, '48c78424d000000000000000', 'site 2 record field +0x00 is the constant 0'),
        (0x2ae51b8, '4088ac24ed010000', 'site 2 tag byte stored to record +0x11d'),
        (0x2ae5739, '0fb683e8010000', 'site 3 tag byte loaded from object +0x1e8'),
        (0x2ae5754, '48c78424e000000087000000', 'site 3 record field +0x10 is the constant 0x87'),
        (0x2ae5788, '888424ed010000', 'site 3 tag byte stored to record +0x11d'),
    ],
    'gb_b3': [
        (0x2cde447, '4c8b7708', 'context holder load from the first argument +0x8'),
        (0x2cde495, '4d8b2e', 'the context object is the holder first qword'),
        (0x2cde498, '410fb6851a020000', 'dispatch byte load from object +0x21a'),
        (0x2cde564, '418bbda0000000', 'tag field source is the dword at object +0xa0'),
        (0x2cde56b, '4188bde8010000', 'tag field of the object written from that dword low byte'),
        (0x2cdedc7, '410fb6ade8010000', 'site 1 tag byte loaded from object +0x1e8'),
        (0x2cdedd6, '48c744246001000000', 'site 1 record field +0x00 is the constant 1'),
        (0x2cdede4, '48c744247097000000', 'site 1 record field +0x10 is the constant 0x97'),
        (0x2cdee3a, '4088ac247d010000', 'site 1 tag byte stored to record +0x11d'),
        (0x2cdf24b, '410fb6ade8010000', 'site 2 tag byte loaded from object +0x1e8'),
        (0x2cdf2a0, '4088ac247d010000', 'site 2 tag byte stored to record +0x11d'),
        (0x2cdf83e, '410fb685e8010000', 'site 3 tag byte loaded from object +0x1e8'),
        (0x2cdf885, '8884247d010000', 'site 3 tag byte stored to record +0x11d'),
    ],
    'gb_b4': [
        (0x2e098fc, '48893424', 'the second argument is saved to the frame'),
        (0x2e09927, '4c8b3c24', 'the record object is the saved second argument'),
        (0x2e09b01, '450fb6bfd50b0000', 'site 1 tag byte loaded from object +0xbd5'),
        (0x2e09b8e, '48c7842430070000dd000000', 'site 1 record blob head is the constant 0xdd'),
        (0x2e09bbb, '48c744245001000000', 'site 1 record field +0x00 is the constant 1'),
        (0x2e09bf1, '4488bc246d010000', 'site 1 tag byte stored to record +0x11d'),
        (0x2e09c01, '488d742450', 'site 1 record argument is the frame record at +0x50'),
        (0x2e09f87, '450fb6bfd50b0000', 'site 2 tag byte loaded from object +0xbd5'),
        (0x2e0a014, '48c7842430070000dc000000', 'site 2 record blob head is the constant 0xdc'),
        (0x2e0a041, '48c744245001000000', 'site 2 record field +0x00 is the constant 1'),
        (0x2e0a077, '4488bc246d010000', 'site 2 tag byte stored to record +0x11d'),
    ],
    'gb_b5': [
        (0x5a70c33, '89f5', 'the tag byte source is the second argument byte'),
        (0x5a70c4f, '48c744240801000000', 'record field +0x00 is the constant 1'),
        (0x5a70c5d, '48c7442418c4000000', 'record field +0x10 is the constant 0xc4'),
        (0x5a70c79, '40886c2450', 'record byte +0x48 is the same argument byte'),
        (0x5a70c86, 'c684241001000000', 'record byte +0x108 is the constant 0'),
        (0x5a70c8e, '4088ac2425010000', 'tag byte stored to record +0x11d'),
        (0x5a70c96, '488d742408', 'record argument is the frame record at +0x8'),
    ],
    'gb_b6': [
        (0x5a70cd3, '89f5', 'the tag byte source is the second argument byte'),
        (0x5a70cef, '48c744240801000000', 'record field +0x00 is the constant 1'),
        (0x5a70cfd, '48c7442418c3000000', 'record field +0x10 is the constant 0xc3'),
        (0x5a70d19, '40886c2450', 'record byte +0x48 is the same argument byte'),
        (0x5a70d2e, '4088ac2425010000', 'tag byte stored to record +0x11d'),
        (0x5a70d36, '488d742408', 'record argument is the frame record at +0x8'),
    ],
    'gb_b7': [
        (0x5a70d7d, '4189f5', 'the tag byte source is the second argument byte'),
        (0x5a70dbb, '48c7442418a8000000', 'record field +0x10 is the constant 0xa8'),
        (0x5a70dd7, '44886c2464', 'record byte +0x5c is the same argument byte'),
        (0x5a70ddc, '40886c2465', 'record byte +0x5d is the fifth argument byte'),
        (0x5a70df1, '4488ac2425010000', 'tag byte stored to record +0x11d'),
        (0x5a70df9, '488d742408', 'record argument is the frame record at +0x8'),
    ],
}
GB_CALL_SITES = {'gb_b1': [0x294b0a2],
                 'gb_b2': [0x2ae4d64, 0x2ae51d0, 0x2ae579f],
                 'gb_b3': [0x2cdee4f, 0x2cdf2b5, 0x2cdf899],
                 'gb_b4': [0x2e09c09, 0x2e0a08f],
                 'gb_b5': [0x5a70c9e], 'gb_b6': [0x5a70d3e], 'gb_b7': [0x5a70e01]}
GB_COUNTS = {'gb_b1': [('48894c2438', 1, 'frame tag pointer store')],
             'gb_b2': [('24ed010000', 3, 'record +0x11d stores'),
                       ('4088bbe8010000', 1, 'object +0x1e8 stores')],
             'gb_b3': [('247d010000', 3, 'record +0x11d stores'),
                       ('4188bde8010000', 1, 'object +0x1e8 stores')],
             'gb_b4': [('4488bc246d010000', 2, 'record +0x11d stores'),
                       ('450fb6bfd50b0000', 2, 'object +0xbd5 loads')]}


def read(data, va, n):
    for sec in sections(data):
        if sec['type'] != 8 and sec['address'] <= va and va + n <= sec['address'] + sec['size']:
            return data[sec['offset'] + va - sec['address']:sec['offset'] + va - sec['address'] + n]
    raise ValueError(f'unmapped read {va:#x}+{n}')


def section_of(data, va):
    for sec in sections(data):
        if sec['type'] != 8 and sec['address'] <= va < sec['address'] + sec['size']:
            return sec['name']
    return None


def va_of_offset(data, off):
    for sec in sections(data):
        if sec['type'] != 8 and sec['offset'] <= off < sec['offset'] + sec['size']:
            return sec['address'] + off - sec['offset']
    return None


def relocations(data):
    """All .rela.dyn entries as (slot, type, addend, addend file offset)."""
    sec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    out = []
    for i, (off, info, add) in enumerate(
            struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']])):
        out.append((off, info & 0xffffffff, add, sec['offset'] + 24 * i + 16))
    return out


def _pin(body, base, va, hexbytes, what):
    want = bytes.fromhex(hexbytes)
    if body[va - base:va - base + len(want)] != want:
        raise ValueError(f'byte pin failed for {what} at {va:#x}')


def _call_target(body, base, va, insn_len=5):
    disp = struct.unpack_from('<i', body, va - base + 1)[0]
    return va + insn_len + disp


def _branch_target(body, base, va, insn_len, disp_at):
    disp = struct.unpack_from('<i', body, va - base + disp_at)[0]
    return va + insn_len + disp


def tag_byte(tag):
    return 0x62 - (1 if tag == 3 else 0)


def call_census(data, targets):
    """Every direct call/jump site in .text for each target VA, with the
    containing FDE for each site. targets maps role -> VA."""
    text = next(s for s in sections(data) if s['name'] == '.text')
    blob = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    _summary, extents, _records = fde_extents(data)
    starts = sorted(e['start'] for e in extents)
    ends = {e['start']: e['end'] for e in extents}

    def owner(va):
        i = bisect.bisect_right(starts, va) - 1
        return starts[i] if i >= 0 and starts[i] <= va < ends[starts[i]] else None

    by_va = {va: role for role, va in targets.items()}
    found = {role: [] for role in targets}
    for opcode in (b'\xe8', b'\xe9'):
        idx = blob.find(opcode)
        while idx != -1:
            site = base + idx
            tgt = site + 5 + struct.unpack_from('<i', blob, idx + 1)[0]
            if tgt in by_va:
                own = owner(site)
                role = next((r for r, rng in OWNERS.items() if rng[0] == own), None)
                found[by_va[tgt]].append({'site': hex(site),
                                          'kind': 'call' if opcode == b'\xe8' else 'jump',
                                          'owner': role,
                                          'owner_start': hex(own) if own else None})
            idx = blob.find(opcode, idx + 1)
    return found


def rip_relative_refs(data, target):
    """Every RIP-relative reference to target in .text, over the three
    encodings this binary uses for slot and pointer access: call/jump
    qword ptr [rip+disp32] (ff 15 / ff 25) and REX.W mov/lea with a
    RIP-relative ModRM. Sites are raw byte-pattern hits; callers must
    validate kept sites as native instruction starts."""
    text = next(s for s in sections(data) if s['name'] == '.text')
    blob = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    found = []
    for opcode, kind in ((b'\xff\x15', 'call'), (b'\xff\x25', 'jump')):
        idx = blob.find(opcode)
        while idx != -1:
            site = base + idx
            if site + 6 + struct.unpack_from('<i', blob, idx + 2)[0] == target:
                found.append({'site': hex(site), 'kind': kind, 'encoding': opcode.hex()})
            idx = blob.find(opcode, idx + 1)
    for rex in (b'\x48', b'\x4c'):
        for op in (b'\x8b', b'\x8d'):
            for modrm in (0x05, 0x0d, 0x15, 0x1d, 0x2d, 0x35, 0x3d):
                pat = rex + op + bytes([modrm])
                idx = blob.find(pat)
                while idx != -1:
                    site = base + idx
                    if idx + 7 <= len(blob) and \
                            site + 7 + struct.unpack_from('<i', blob, idx + 3)[0] == target:
                        found.append({'site': hex(site),
                                      'kind': 'mov' if op == b'\x8b' else 'lea',
                                      'encoding': pat.hex()})
                    idx = blob.find(pat, idx + 1)
    return sorted(found, key=lambda r: int(r['site'], 16))


def raw_occurrences(data, va):
    """File offsets of the VA's 8-byte and 4-byte little-endian forms."""
    out = {}
    for width, fmt in ((8, '<Q'), (4, '<I')):
        needle = struct.pack(fmt, va)
        offs = []
        idx = data.find(needle)
        while idx != -1:
            offs.append(idx)
            idx = data.find(needle, idx + 1)
        out[width] = offs
    return out


def store_census_count(body, prefixes, modrms, disps):
    n = 0
    for prefix in prefixes:
        pb = bytes.fromhex(prefix)
        for modrm in modrms:
            for disp in disps:
                n += body.count(pb + bytes([modrm, disp]))
    return n


def analyze(data):
    if len(data) != TARGET_SIZE:
        raise ValueError('expected pinned node115')
    _summary, extents, _records = fde_extents(data)
    by_start = {e['start']: e for e in extents}
    text_sec = next(s for s in sections(data) if s['name'] == '.text')
    owners = {}
    bodies = {}
    for role, (start, end) in OWNERS.items():
        ext = by_start.get(start)
        if ext is None or ext['end'] != end:
            raise ValueError(f'FDE extent mismatch for {role}')
        body = read(data, start, end - start)
        bodies[role] = body
        owners[role] = {'role': role, 'start': hex(start), 'end': hex(end),
                        'file_offset': hex(text_sec['offset'] + start - text_sec['address']),
                        'bytes': end - start, 'sha256': hashlib.sha256(body).hexdigest(),
                        'frames': {}}
    # Relied-upon links from the earlier chain packets, re-verified:
    # the serializer tag rule, the top FDE tag byte load, and the
    # grand_b_caller tag capture (chain-top packet claims).
    ser = read(data, 0x36aa9a0, 0x36aade6 - 0x36aa9a0)
    for va, hexbytes, what in SERIALIZER_TAG_PINS:
        _pin(ser, 0x36aa9a0, va, hexbytes, what)
    top = read(data, 0x3713300, 0x3713523 - 0x3713300)
    _pin(top, 0x3713300, *CHAIN_LINK_PINS[0])
    gbc = read(data, GRAND_B_CALLER[0], GRAND_B_CALLER[1] - GRAND_B_CALLER[0])
    _pin(gbc, GRAND_B_CALLER[0], *CHAIN_LINK_PINS[1])
    # Direct call census: the five top_caller callers, the in-chain
    # calls into ga_a1, and the callers above ga_a2 / ga_a4 (boundary).
    census = call_census(data, {'top_caller': TOP_CALLER[0], 'ga_a1': GA_A1[0],
                                'ga_a2': GA_A2[0], 'ga_a3': GA_A3[0],
                                'ga_a4': GA_A4[0], 'ga_a5': GA_A5[0],
                                'ga_a5_thunk': GA_A5_THUNK[0],
                                'ga_a5_feeder': GA_A5_FEEDER[0],
                                'grand_b_caller': GRAND_B_CALLER[0]})
    expect_tc = [(hex(GA_CALL_SITES[r]), r) for r in
                 ('ga_a1', 'ga_a2', 'ga_a3', 'ga_a4', 'ga_a5')]
    got_tc = [(s['site'], s['owner']) for s in census['top_caller']]
    if got_tc != expect_tc or any(s['kind'] != 'call' for s in census['top_caller']):
        raise ValueError('top_caller call census mismatch')
    if [(s['site'], s['owner']) for s in census['ga_a1']] != \
            [('0x35ca00e', 'ga_a2'), ('0x3b87f9f', 'ga_a4')]:
        raise ValueError('ga_a1 call census mismatch')
    if [(s['site'], s['owner_start']) for s in census['ga_a2']] != \
            [('0x371d31f', '0x371d280'), ('0x371f41b', '0x371f380')]:
        raise ValueError('ga_a2 call census mismatch')
    if [(s['site'], s['owner_start']) for s in census['ga_a4']] != \
            [('0x3b91432', '0x3b913e0')]:
        raise ValueError('ga_a4 call census mismatch')
    if census['ga_a3'] != []:
        raise ValueError('ga_a3 unexpectedly has direct call or jump sites')
    if [(s['site'], s['kind'], s['owner']) for s in census['ga_a5']] != \
            [(hex(THUNK_JUMP_SITE), 'jump', 'ga_a5_thunk')]:
        raise ValueError('ga_a5 call census mismatch')
    if [(s['site'], s['kind'], s['owner']) for s in census['ga_a5_thunk']] != \
            [(hex(FEEDER_CALL_SITE), 'call', 'ga_a5_feeder')]:
        raise ValueError('ga_a5_thunk call census mismatch')
    if [(s['site'], s['owner_start']) for s in census['ga_a5_feeder']] != \
            [('0x3ec1c0c', '0x3ec1b80')]:
        raise ValueError('ga_a5_feeder call census mismatch')
    if census['grand_b_caller'] != []:
        raise ValueError('grand_b_caller unexpectedly has direct call or jump sites')
    # The grand_b_caller slot binding (chain-top packet), re-verified,
    # and its twelve indirect call sites mapped to this packet owners.
    rel = relocations(data)
    gbc_relocs = [(off, typ) for off, typ, add, aoff in rel if add == GRAND_B_CALLER[0]]
    if gbc_relocs != [(GRAND_B_CALLER_SLOT, RELA_RELATIVE)]:
        raise ValueError('grand_b_caller relocation reference mismatch')
    if section_of(data, GRAND_B_CALLER_SLOT) != '.got':
        raise ValueError('grand_b_caller slot is not in .got')
    slot_refs = rip_relative_refs(data, GRAND_B_CALLER_SLOT)
    if len(slot_refs) != 12 or any(r['kind'] != 'call' for r in slot_refs):
        raise ValueError('grand_b_caller slot reference census mismatch')
    slot_sites = {}
    for role, sites in GB_CALL_SITES.items():
        for site in sites:
            slot_sites[hex(site)] = role
    got_sites = {r['site']: r for r in slot_refs}
    if set(got_sites) != set(slot_sites):
        raise ValueError('grand_b_caller slot site set mismatch')
    for site, role in slot_sites.items():
        start, end = OWNERS[role]
        if not (start <= int(site, 16) < end):
            raise ValueError(f'slot site {site} is not inside {role}')
    # Raw VA occurrences: each wrapper start occurs exactly once in
    # the file, as a stored qword; ga_a3 and ga_a5 occur nowhere as
    # stored qwords.
    raw = {}
    for role in ('gb_b5', 'gb_b6', 'gb_b7'):
        occ = raw_occurrences(data, OWNERS[role][0])
        if len(occ[8]) != 1:
            raise ValueError(f'{role} raw occurrence census mismatch')
        fo = occ[8][0]
        raw[role] = {'eight_byte_file_offsets': [hex(fo)],
                     'eight_byte_vas': [hex(va_of_offset(data, fo))]}
    for role in ('ga_a3', 'ga_a5'):
        occ = raw_occurrences(data, OWNERS[role][0])
        if occ[8] != []:
            raise ValueError(f'{role} raw occurrence census mismatch')
        raw[role] = {'eight_byte_file_offsets': [], 'eight_byte_vas': []}
    # Grand_a path: pins, call targets, and the negative store census
    # over the container fields of each caller input record.
    for role, pins in GA_PINS.items():
        start = OWNERS[role][0]
        for va, hexbytes, what in pins:
            _pin(bodies[role], start, va, hexbytes, what)
    for role, site in GA_CALL_SITES.items():
        start = OWNERS[role][0]
        if _call_target(bodies[role], start, site) != TOP_CALLER[0]:
            raise ValueError(f'{role} call target mismatch')
    for role, site in GA_A1_CALL_SITES.items():
        start = OWNERS[role][0]
        if _call_target(bodies[role], start, site) != GA_A1[0]:
            raise ValueError(f'{role} ga_a1 call target mismatch')
    for role in ('ga_a2', 'ga_a4'):
        start = OWNERS[role][0]
        lea_va = 0x35c9d84 if role == 'ga_a2' else 0x3b87d1c
        if _branch_target(bodies[role], start, lea_va, 7, 3) != GA_A3[0]:
            raise ValueError(f'{role} ga_a3 address materialisation mismatch')
    if _call_target(bodies['ga_a5_feeder'], GA_A5_FEEDER[0],
                    FEEDER_CALL_SITE) != GA_A5_THUNK[0]:
        raise ValueError('ga_a5_feeder call target mismatch')
    if _call_target(bodies['ga_a5_thunk'], GA_A5_THUNK[0],
                    THUNK_JUMP_SITE) != GA_A5[0]:
        raise ValueError('ga_a5_thunk jump target mismatch')
    for role, (prefixes, modrms, disps) in GA_STORE_CENSUS.items():
        if store_census_count(bodies[role], prefixes, modrms, disps) != 0:
            raise ValueError(f'{role} unexpectedly stores to a container field')
    # Grand_b path: pins, slot targets, and store/load counts.
    for role, pins in GB_PINS.items():
        start = OWNERS[role][0]
        for va, hexbytes, what in pins:
            _pin(bodies[role], start, va, hexbytes, what)
    for role, sites in GB_CALL_SITES.items():
        start = OWNERS[role][0]
        for site in sites:
            if _branch_target(bodies[role], start, site, 6, 2) != GRAND_B_CALLER_SLOT:
                raise ValueError(f'{role} indirect call does not target the '
                                 'grand_b_caller slot')
    for role, counts in GB_COUNTS.items():
        for hexbytes, want, what in counts:
            if bodies[role].count(bytes.fromhex(hexbytes)) != want:
                raise ValueError(f'{role} {what} count mismatch')
    return {'target_sha256': TARGET_SHA256,
            'owners': [owners[r] for r in OWNERS],
            'serializer_tag_rule': {'argument': 'third argument (edx)', 'compared_against': 3,
                                    'byte_if_equal': hex(tag_byte(3)),
                                    'byte_otherwise': hex(tag_byte(4))},
            'chain_links_reverified': {
                'top_tag_load': 'the top FDE loads the tag byte at 0x371336c '
                                'through the container field +0x10 pointer '
                                '(chain-top packet pin, re-verified)',
                'grand_b_caller_capture': 'the grand_b_caller FDE captures '
                                          'the byte at [arg2+0x11d] at '
                                          '0x38d9c77 (chain-top packet pin, '
                                          're-verified)',
                'grand_b_caller_slot': {'slot': hex(GRAND_B_CALLER_SLOT),
                                        'type': RELA_RELATIVE,
                                        'type_name': 'R_X86_64_RELATIVE',
                                        'addend': hex(GRAND_B_CALLER[0]),
                                        'slot_section': '.got'}},
            'caller_census': {
                'top_caller': census['top_caller'],
                'ga_a1': census['ga_a1'],
                'ga_a2': census['ga_a2'],
                'ga_a4': census['ga_a4'],
                'ga_a3': census['ga_a3'],
                'ga_a5': census['ga_a5'],
                'ga_a5_thunk': census['ga_a5_thunk'],
                'ga_a5_feeder': census['ga_a5_feeder'],
                'grand_b_caller': census['grand_b_caller'],
                'grand_b_caller_slot_references': [
                    {'site': r['site'], 'kind': r['kind'], 'encoding': r['encoding'],
                     'owner': slot_sites[r['site']]} for r in slot_refs]},
            'grand_a_tag_provenance': {
                'ga_a1': {'call_site': hex(GA_CALL_SITES['ga_a1']),
                          'container': 'a frame copy of the three-qword '
                                       'sub-struct at the record (second '
                                       'argument) +0x28; its field 0, '
                                       'loaded from record +0x28, is the '
                                       'cell pointer of the chain-top '
                                       'trace: the top FDE loads the '
                                       'qword stored in that cell and '
                                       'takes the byte at that address, '
                                       'so the tag byte is the first '
                                       'byte of the object whose address '
                                       'is stored in the cell at '
                                       '[record +0x28]',
                          'discriminator_argument': 'the caller own byte '
                                                    'argument, zero-extended',
                          'writer': 'no instruction in this FDE stores '
                                    'to the record +0x28/+0x30/+0x38 '
                                    'fields (encoding-scoped store '
                                    'census); the writer is above'},
                'ga_a2': {'call_site': hex(GA_CALL_SITES['ga_a2']),
                          'container': 'a frame copy assembled from the '
                                       'record (second argument) fields '
                                       '+0x60/+0x68/+0x70; the +0x60 '
                                       'field is the cell pointer of '
                                       'the chain-top trace, so the tag '
                                       'byte is the first byte of the '
                                       'object whose address is stored '
                                       'in the cell at [record +0x60]',
                          'discriminator_argument': 'constant 1',
                          'writer': 'no instruction in this FDE stores '
                                    'to the record +0x60/+0x68/+0x70 '
                                    'fields (encoding-scoped store '
                                    'census); the writer is above'},
                'ga_a3': {'call_site': hex(GA_CALL_SITES['ga_a3']),
                          'container': 'a frame copy of the three-qword '
                                       'sub-struct at the record (first '
                                       'argument) +0x28; its field 0, '
                                       'loaded from record +0x28, is '
                                       'the cell pointer of the '
                                       'chain-top trace, so the tag '
                                       'byte is the first byte of the '
                                       'object whose address is stored '
                                       'in the cell at [record +0x28]',
                          'discriminator_argument': 'constant 1',
                          'reachability': 'no direct call or jump site '
                                          'and no stored qword in the '
                                          'file; the address is '
                                          'materialised by lea in ga_a2 '
                                          '(0x35c9d84) and ga_a4 '
                                          '(0x3b87d1c) and stored into a '
                                          'registry slot with a frame '
                                          'context record',
                          'writer': 'no instruction in this FDE stores '
                                    'to the record +0x28/+0x30/+0x38 '
                                    'fields (encoding-scoped store '
                                    'census); the writer is above'},
                'ga_a4': {'call_site': hex(GA_CALL_SITES['ga_a4']),
                          'container': 'a frame copy assembled from the '
                                       'record (second argument) fields '
                                       '+0x60/+0x68/+0x70; the +0x60 '
                                       'field is the cell pointer of '
                                       'the chain-top trace, so the tag '
                                       'byte is the first byte of the '
                                       'object whose address is stored '
                                       'in the cell at [record +0x60]',
                          'discriminator_argument': 'constant 0',
                          'writer': 'no instruction in this FDE stores '
                                    'to the record +0x60/+0x68/+0x70 '
                                    'fields (encoding-scoped store '
                                    'census); the writer is above'},
                'ga_a5': {'call_site': hex(GA_CALL_SITES['ga_a5']),
                          'container': 'assembled on the frame: field 0 '
                                       'is the address of the frame copy '
                                       'of the third argument field 2 '
                                       '(+0x10), field 1 is a computed '
                                       'element pointer, field 2 is the '
                                       'second argument; the cell '
                                       'pointer of the chain-top trace '
                                       'is therefore that frame slot, '
                                       'the qword it holds is the third '
                                       'argument +0x10 value, and the '
                                       'tag byte is the first byte of '
                                       'the object that value addresses',
                          'discriminator_argument': 'constant 0',
                          'reachability': 'no direct call site and no '
                                          'stored qword in the file; '
                                          'reached only through the '
                                          'ga_a5_thunk adapter (single '
                                          'jump site 0x3d9d167), which '
                                          'forwards its own second '
                                          'argument as the record and '
                                          'that record +0x8 field as '
                                          'the second argument',
                          'writer': 'inside ga_a5 the field is copied, '
                                    'never stored to (encoding-scoped '
                                    'store census over the third '
                                    'argument fields). One level '
                                    'higher the writer is pinned: the '
                                    'ga_a5_feeder FDE performs the '
                                    'same two-dereference load from '
                                    'its own third argument container '
                                    '(0x3713590, 0x3713598), stores '
                                    'the byte to a frame byte '
                                    '(0x371359b), and stores that '
                                    'frame byte address as the record '
                                    '+0x10 field (0x37135c8) of the '
                                    'record the thunk forwards to '
                                    'ga_a5 as its third argument; so '
                                    'on this path the tag byte value '
                                    'is the feeder own container byte, '
                                    'whose writer is above the '
                                    'feeder'}},
            'grand_b_tag_provenance': {
                'gb_b1': {'call_sites': [hex(s) for s in GB_CALL_SITES['gb_b1']],
                          'record': 'built on the frame at +0x60 once '
                                    'per loop iteration (fields +0x00=1, '
                                    '+0x10=0xc2, byte +0x18=2, +0x100 '
                                    'from the first argument +0x10 field)',
                          'tag_source': 'the first byte of the object '
                                        'pointed to by the first '
                                        'argument +0x18 field; the '
                                        'pointer is saved once at entry '
                                        '(0x294af5a, count-pinned unique) '
                                        'and the byte is reloaded '
                                        'through it at every loop head '
                                        '(0x294afb5)'},
                'gb_b2': {'call_sites': [hex(s) for s in GB_CALL_SITES['gb_b2']],
                          'record': 'built on the frame at +0xd0 per '
                                    'call site (field +0x10 is 0x97 at '
                                    'site 1, blob-copied at site 2, '
                                    '0x87 at site 3)',
                          'tag_source': 'the byte at object +0x1e8 of '
                                        'the context object (the first '
                                        'argument), freshly loaded '
                                        'before each call; the only '
                                        'store to that field in the FDE '
                                        '(0x2ae44ce, count-pinned unique) '
                                        'writes the low byte of the '
                                        'dword at object +0xa0, itself '
                                        'stored from a staged frame '
                                        'value in the same entry arm'},
                'gb_b3': {'call_sites': [hex(s) for s in GB_CALL_SITES['gb_b3']],
                          'record': 'built on the frame at +0x60 per '
                                    'call site (field +0x10 is 0x97 at '
                                    'site 1)',
                          'tag_source': 'the byte at object +0x1e8 of '
                                        'the context object (loaded as '
                                        '[[first argument +0x8]] at '
                                        '0x2cde495), freshly loaded '
                                        'before each call; the only '
                                        'store to that field in the FDE '
                                        '(0x2cde56b, count-pinned unique) '
                                        'writes the low byte of the '
                                        'dword at object +0xa0, itself '
                                        'written by a 0x98-byte copy '
                                        'into the object in the same '
                                        'entry arm'},
                'gb_b4': {'call_sites': [hex(s) for s in GB_CALL_SITES['gb_b4']],
                          'record': 'built on the frame at +0x50 per '
                                    'call site (field +0x00=1; the '
                                    '+0x10 blob is copied from a frame '
                                    'record whose head qword is 0xdd at '
                                    'site 1 and 0xdc at site 2)',
                          'tag_source': 'the byte at object +0xbd5 of '
                                        'the record object (the second '
                                        'argument), freshly loaded in '
                                        'each call block (0x2e09b01, '
                                        '0x2e09f87; count-pinned exactly '
                                        'two loads and two tag stores)'},
                'gb_b5': {'call_sites': [hex(s) for s in GB_CALL_SITES['gb_b5']],
                          'record': 'built on the frame at +0x8 '
                                    '(field +0x10 is the constant 0xc4)',
                          'tag_source': 'the wrapper own second '
                                        'argument byte, captured at '
                                        'entry (0x5a70c33) and stored '
                                        'both to record +0x48 and to '
                                        'record +0x11d',
                          'reachability': 'no direct call or jump '
                                          'site; the start address '
                                          'occurs exactly once in the '
                                          'file, as a stored qword (see '
                                          'boundary)'},
                'gb_b6': {'call_sites': [hex(s) for s in GB_CALL_SITES['gb_b6']],
                          'record': 'built on the frame at +0x8 '
                                    '(field +0x10 is the constant 0xc3)',
                          'tag_source': 'the wrapper own second '
                                        'argument byte, captured at '
                                        'entry (0x5a70cd3) and stored '
                                        'both to record +0x48 and to '
                                        'record +0x11d',
                          'reachability': 'no direct call or jump '
                                          'site; the start address '
                                          'occurs exactly once in the '
                                          'file, as a stored qword (see '
                                          'boundary)'},
                'gb_b7': {'call_sites': [hex(s) for s in GB_CALL_SITES['gb_b7']],
                          'record': 'built on the frame at +0x8 '
                                    '(field +0x10 is the constant 0xa8)',
                          'tag_source': 'the wrapper own second '
                                        'argument byte, captured at '
                                        'entry (0x5a70d7d) and stored '
                                        'both to record +0x5c and to '
                                        'record +0x11d; the neighbouring '
                                        'byte +0x5d is the fifth '
                                        'argument byte',
                          'reachability': 'no direct call or jump '
                                          'site; the start address '
                                          'occurs exactly once in the '
                                          'file, as a stored qword (see '
                                          'boundary)'}},
            'wrapper_table_entries': raw,
            'boundary': {
                'grand_a': 'on the ga_a1/ga_a2/ga_a3/ga_a4 paths the '
                           'cell pointer is forwarded, never written, '
                           'inside all traced callers, and the object '
                           'whose first byte is the tag is written '
                           'above them: one level higher the pointer '
                           'is still forwarded (the ga_a2 callers, '
                           'FDE 0x371d280 site 0x371d31f and FDE '
                           '0x371f380 site 0x371f41b, copy it from '
                           'their own first argument record +0x60 '
                           'field into the frame record they pass; '
                           'the ga_a4 caller, FDE 0x3b913e0 site '
                           '0x3b91432, passes a record returned by a '
                           'helper call). The ga_a5 path is closed '
                           'one level higher by the ga_a5_feeder '
                           'FDE, which materialises the byte from '
                           'its own container; the feeder has '
                           'exactly one direct caller (FDE '
                           '0x3ec1b80, site 0x3ec1c0c), not traced. '
                           'Who writes the tag byte objects on the '
                           'remaining paths, and which cell contents '
                           'occur per action family, remain open.',
                'grand_b_wrappers': 'gb_b5/gb_b6/gb_b7 have no direct '
                                    'call sites; each start address '
                                    'occurs exactly once in the file '
                                    'as a stored qword (gb_b5 at the '
                                    'VA in wrapper_table_entries, '
                                    'likewise gb_b6/gb_b7), i.e. they '
                                    'are reached through a pointer '
                                    'table whose consumer is not '
                                    'traced; which byte their callers '
                                    'pass as the second argument is '
                                    'above that table.',
                'grand_b_fields': 'the writers of the gb_b2/gb_b3 '
                                  'context object +0xa0 source '
                                  'buffer, of the gb_b4 object '
                                  '+0xbd5 byte, and of the object '
                                  'gb_b1 first argument +0x18 points '
                                  'to, are not in the traced FDEs '
                                  'and remain open; in gb_b2/gb_b3 '
                                  'the +0x1e8 field may also keep a '
                                  'value set before the traced entry '
                                  'arm ran, since exactly one store '
                                  'exists in each FDE and it is '
                                  'arm-local.'},
            'captured_code_executed': False,
            'limits': ('Static byte pins, FDE extent censuses, one .text '
                       'call census, one RIP-relative reference census '
                       'over the ff 15 / ff 25 / REX.W mov/lea encodings, '
                       'the .rela.dyn addend census, a raw VA occurrence '
                       'census, and encoding-scoped store censuses over '
                       'the container fields (the prefixes and ModRM '
                       'sets named in the checker) only. Runtime byte '
                       'values are not observed: which tag the node '
                       'emits for a given record depends on the source '
                       'bytes above, whose contents are data. The '
                       'packet does not name the record or object types '
                       'the pointers denote and does not follow the '
                       'forwarding chain above the boundary FDEs.')}


def executable(path, args, marker=None):
    out = subprocess.run([path, *args], check=True, stdout=subprocess.PIPE).stdout.decode()
    if 'LLVM' in out or (marker is not None and marker not in out):
        raise ValueError(f'unexpected {path} output')
    return out


def generate(binary, output):
    data = Path(binary).read_bytes()
    if len(data) != TARGET_SIZE or hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('expected pinned node115')
    result = analyze(data)
    readelf = executable('readelf', ['-wf', str(binary)], marker='FDE').splitlines()
    eh = next(s for s in sections(data) if s['name'] == '.eh_frame')

    def record(line):
        off, size = int(line.split()[0], 16), int(line.split()[1], 16)
        raw = data[eh['offset'] + off:eh['offset'] + off + size + 4]
        return {'va': hex(eh['address'] + off), 'bytes_hex': raw.hex()}

    exports = {}
    for owner in result['owners']:
        start, end = OWNERS[owner['role']]
        lines = [l for l in readelf if 'FDE' in l and f'pc={start:016x}..{end:016x}' in l]
        if len(lines) != 1:
            raise ValueError(f'expected one FDE line for {owner["role"]}')
        fde_line = lines[0]
        cie_ref = fde_line.split('cie=')[1].split()[0]
        cie_lines = [l for l in readelf if len(l.split()) > 3 and l.split()[0] == cie_ref and ' CIE' in l]
        if len(cie_lines) != 1:
            raise ValueError(f'expected one CIE line for {owner["role"]}')
        owner['frames'] = {'fde': record(fde_line), 'cie': record(cie_lines[0])}
        role = owner['role']
        if role in WINDOWS:
            parts = []
            for wstart, wend in WINDOWS[role]:
                parts.append(executable(
                    'objdump', ['-d', '-M', 'intel', '--insn-width=16',
                                f'--start-address={wstart:#x}',
                                f'--stop-address={wend:#x}', str(binary)],
                    marker='Disassembly of section'))
            exports[role] = parts
        else:
            exports[role] = executable(
                'objdump', ['-d', '-M', 'intel', '--insn-width=16',
                            f'--start-address={start:#x}',
                            f'--stop-address={end:#x}', str(binary)],
                marker='Disassembly of section')
    # Native validation: every pinned address and every call site
    # inside an owner must be an instruction start in that owner's
    # decoded extent (per window for the windowed owners).
    pin_vas = {role: set() for role in OWNERS}
    for role, pins in GA_PINS.items():
        pin_vas[role] |= {va for va, _h, _w in pins}
    for role, pins in GB_PINS.items():
        pin_vas[role] |= {va for va, _h, _w in pins}
    for role, site in GA_CALL_SITES.items():
        pin_vas[role].add(site)
    for role, site in GA_A1_CALL_SITES.items():
        pin_vas[role].add(site)
    pin_vas['ga_a5_feeder'].add(FEEDER_CALL_SITE)
    pin_vas['ga_a5_thunk'].add(THUNK_JUMP_SITE)
    for role, sites in GB_CALL_SITES.items():
        pin_vas[role] |= set(sites)
    for role, (start, end) in OWNERS.items():
        body = read(data, start, end - start)
        if role in WINDOWS:
            starts = set()
            for (wstart, wend), text in zip(WINDOWS[role], exports[role]):
                starts |= set(decode_export(text, wstart, wend,
                                            read(data, wstart, wend - wstart)))
        else:
            starts = set(decode_export(exports[role], start, end, body))
        missing = {hex(v) for v in pin_vas[role] if v not in starts}
        if missing:
            raise ValueError(f'pinned addresses are not instruction starts in {role}: {missing}')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    frames = []
    for owner in result['owners']:
        start, end = OWNERS[owner['role']]
        frames += [l for l in readelf if 'FDE' in l and f'pc={start:016x}..{end:016x}' in l]
    (output / 'frames.txt').write_text('\n'.join(frames) + '\n')
    for role in OWNERS:
        if role in WINDOWS:
            text = ''
            for (wstart, wend), part in zip(WINDOWS[role], exports[role]):
                text += f'# window {wstart:#x}..{wend:#x}\n'
                text += part.replace(str(binary), '<authenticated-node115>')
            (output / f'{role}.objdump.txt').write_text(text)
        else:
            (output / f'{role}.objdump.txt').write_text(
                exports[role].replace(str(binary), '<authenticated-node115>'))
    (output / 'records.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', default=str(TARGET))
    ap.add_argument('--output', default=str(PACKET))
    a = ap.parse_args()
    generate(a.binary, a.output)


if __name__ == '__main__':
    main()
