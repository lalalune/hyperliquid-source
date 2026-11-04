#!/usr/bin/env python3
"""Regenerate the RE-005 node 115 rmp-signable chain-top packet.

The rmp-signable caller-tag packet (RE-005-node115-rmp-signable-caller-tags)
established that the serializer's tag is the zero-extended low byte of
each dispatcher's own entry edx on every reaching path, and left open
who calls the two dispatchers and which third-argument values those
sites pass. This tool pins the top of that chain: grand_a's sole call
site, inside FDE 0x3713300, and grand_b's only reference in the whole
binary, a .got slot consumed by one indirect call inside FDE
0x38d9c60, together with the tag-argument provenance at both sites,
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
PACKET = ROOT / 'research/work-items/RE-005-node115-rmp-signable-chain-top'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SERIALIZER = (0x36aa9a0, 0x36aade6)
CALLER_A = (0x36aadf0, 0x36aaf0e)
CALLER_B = (0x36aaf10, 0x36aaff6)
GRAND_A = (0x36c2050, 0x36c2f99)
GRAND_B = (0x36c5350, 0x36c5676)
TOP = (0x3713300, 0x3713523)
TOP_CALLER = (0x3ebdd10, 0x3ebdf64)
GRAND_B_CALLER = (0x38d9c60, 0x38d9edc)
OWNERS = {'serializer': SERIALIZER, 'caller_a': CALLER_A, 'caller_b': CALLER_B,
          'grand_a': GRAND_A, 'grand_b': GRAND_B, 'top': TOP,
          'top_caller': TOP_CALLER, 'grand_b_caller': GRAND_B_CALLER}
TAG_EQUAL = 3
TAG_BYTE_BASE = 0x62
GRAND_B_SLOT = 0x64e8ed0
GRAND_B_CALLER_SLOT = 0x64e6c60
RELA_RELATIVE = 8
SERIALIZER_TAG_PINS = [
    (0x36aac32, '4080fd03', 'compare tag argument against 3'),
    (0x36aac39, 'b262', 'tag byte base 0x62'),
    (0x36aac3b, '28ca', 'tag byte subtraction'),
    (0x36aac3d, '8810', 'store of the tag byte'),
]
CALLER_PREFIX = {
    'caller_a': '41574156534881ecf00000004d89c64889fb4c8dbc24980000004c89ff',
    'caller_b': '41574156534881eca00000004c89c34989fe4c8d7c24484c89ff',
}
TOP_PINS = [
    (0x3713319, '488b1a', 'container begin load from the entry third argument'),
    (0x371331c, '4c8b7a08', 'container end load from the entry third argument'),
    (0x3713329, '488b4210', 'tag pointer load from container field +0x10'),
    (0x371332d, '4889442418', 'tag pointer saved to the frame slot +0x18'),
    (0x3713360, '488b442418', 'tag pointer reload at the loop head'),
    (0x3713365, '488b00', 'tag pointer dereference'),
    (0x3713368, '488d7310', 'dispatcher record argument is the element +0x10'),
    (0x371342e, '4881c368010000', 'element stride 0x168'),
]
# From the tag byte load (0x371336c) up to the call instruction at
# 0x37133b3: the record field copies and the remaining argument setup.
# No instruction in this span writes edx, so the loaded tag byte is the
# value the call receives; pinning the whole span makes that load-bearing.
TOP_TAG_SPAN = (0x371336c,
                '0fb610488b835d0100004889450d0f1083500100000f114500'
                '488b83480100000f100348898424a00000000f29842490000000'
                '4c8d8300010000488d7c2420488d8c2490000000')
TOP_EMPTY_EXIT = 0x3713323
TOP_LOOP_BACK = 0x371348d
TOP_CALL_SITE = 0x37133b3
GBC_PINS = [
    (0x38d9c77, '0fb6ae1d010000', 'tag byte captured from the entry second argument record +0x11d'),
    (0x38d9cc3, '84c040886c240f', 'tag byte stored to the frame slot +0xf before the path split'),
    (0x38d9db1, '488dac2498000000', 'dispatcher record pointer is the frame record at +0x98'),
]
GBC_CALL_SPAN = (0x38d9df0,
                 '0fb654240f488d7c2450488d4c24204889ee4c8b442418ff15c3f0c002')
GBC_SPLIT_JE = 0x38d9ccf
GBC_CONVERGE_JMP = 0x38d9da5
GBC_CALL_SITE = 0x38d9e07
TOP_CALLER_PINS = [
    (0x3ebdd80, '4c894c2468', 'container field 0 store'),
    (0x3ebdd85, '4889742470', 'container field 1 store'),
    (0x3ebdd8a, '4889442478', 'container field 2 store (the tag pointer field)'),
    (0x3ebdd8f, '488d7c2410', 'top out argument'),
    (0x3ebdd94, '488d742438', 'top second argument'),
    (0x3ebdd99, '488d542468', 'top container argument'),
]
TOP_CALLER_CALL_SITE = 0x3ebdd9e


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


def relocations(data):
    """All .rela.dyn entries as (slot, type, addend, addend file offset)."""
    sec = next((s for s in sections(data) if s['name'] == '.rela.dyn'), None)
    if sec is None:
        raise ValueError('missing.rela.dyn section')
    if sec['size'] % 24:
        raise ValueError('truncated.rela.dyn section')
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


def _branch_target8(body, base, va):
    disp = struct.unpack_from('<b', body, va - base + 1)[0]
    return va + 2 + disp


def tag_byte(tag):
    return TAG_BYTE_BASE - (1 if tag == TAG_EQUAL else 0)


def call_census(data, targets):
    """Every direct call/jump site in .text for each target VA, with the
    containing FDE start for each site. targets maps role -> VA."""
    text = next((s for s in sections(data) if s['name'] == '.text'), None)
    if text is None:
        raise ValueError('missing.text section')
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
    text = next((s for s in sections(data) if s['name'] == '.text'), None)
    if text is None:
        raise ValueError('missing.text section')
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


def analyze(data):
    if len(data) != TARGET_SIZE:
        raise ValueError('expected pinned node115')
    _summary, extents, _records = fde_extents(data)
    by_start = {e['start']: e for e in extents}
    text_sec = next((s for s in sections(data) if s['name'] == '.text'), None)
    if text_sec is None:
        raise ValueError('missing.text section')
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
    # The chain this packet extends, re-verified: the serializer's tag
    # rule, the two callers' forwarding prefixes, and the dispatcher
    # call census (the caller-tag packet's claims).
    for va, hexbytes, what in SERIALIZER_TAG_PINS:
        _pin(bodies['serializer'], SERIALIZER[0], va, hexbytes, what)
    for role in ('caller_a', 'caller_b'):
        start = OWNERS[role][0]
        _pin(bodies[role], start, start, CALLER_PREFIX[role], f'{role} forwarding prefix')
        site = start + len(bytes.fromhex(CALLER_PREFIX[role]))
        if _call_target(bodies[role], start, site) != SERIALIZER[0]:
            raise ValueError(f'{role} call target mismatch')
    census_targets = {'serializer': SERIALIZER[0], 'caller_a': CALLER_A[0],
                      'caller_b': CALLER_B[0], 'grand_a': GRAND_A[0], 'grand_b': GRAND_B[0],
                      'top': TOP[0], 'top_caller': TOP_CALLER[0],
                      'grand_b_caller': GRAND_B_CALLER[0]}
    census = call_census(data, census_targets)
    if [s['site'] for s in census['serializer']] != ['0x36aae0d', '0x36aaf2a']:
        raise ValueError('serializer call census mismatch')
    if [s['site'] for s in census['caller_a']] != ['0x36c208b'] or \
            census['caller_a'][0]['owner'] != 'grand_a':
        raise ValueError('caller_a call census mismatch')
    if [s['site'] for s in census['caller_b']] != ['0x36c5388'] or \
            census['caller_b'][0]['owner'] != 'grand_b':
        raise ValueError('caller_b call census mismatch')
    # Grand_a: exactly one direct call site in the whole .text, inside
    # the top FDE; no jump sites, no relocation or raw references.
    if [s['site'] for s in census['grand_a']] != [hex(TOP_CALL_SITE)] or \
            census['grand_a'][0]['kind'] != 'call' or census['grand_a'][0]['owner'] != 'top':
        raise ValueError('grand_a call census mismatch')
    # Grand_b: no direct call or jump sites anywhere.
    if census['grand_b'] != []:
        raise ValueError('grand_b unexpectedly has direct call or jump sites')
    # The top FDE is itself called directly exactly once, from the
    # top_caller FDE; the boundary FDEs' own censuses are recorded.
    if [s['site'] for s in census['top']] != [hex(TOP_CALLER_CALL_SITE)] or \
            census['top'][0]['owner'] != 'top_caller':
        raise ValueError('top call census mismatch')
    if census['grand_b_caller'] != []:
        raise ValueError('grand_b_caller unexpectedly has direct call or jump sites')
    rel = relocations(data)

    def addend_refs(va):
        return [(off, typ, aoff) for off, typ, add, aoff in rel if add == va]

    def interior_refs(start, end):
        return [(off, add) for off, typ, add, aoff in rel if start < add < end]

    for role in ('serializer', 'caller_a', 'caller_b', 'grand_a', 'top', 'top_caller'):
        if addend_refs(OWNERS[role][0]):
            raise ValueError(f'unexpected relocation reference to {role}')
    for role in ('grand_a', 'grand_b', 'top'):
        start, end = OWNERS[role]
        if interior_refs(start, end):
            raise ValueError(f'unexpected relocation reference into the {role} body')
    # Grand_b's one relocation: a R_X86_64_RELATIVE entry binding the
    # .got slot 0x64e8ed0 to grand_b. The slot's file content is zero;
    # it is filled by the dynamic linker before any code runs.
    gb_relocs = addend_refs(GRAND_B[0])
    if len(gb_relocs) != 1 or gb_relocs[0][0] != GRAND_B_SLOT or gb_relocs[0][1] != RELA_RELATIVE:
        raise ValueError('grand_b relocation reference mismatch')
    if section_of(data, GRAND_B_SLOT) != '.got':
        raise ValueError('grand_b slot is not in .got')
    if read(data, GRAND_B_SLOT, 8) != b'\x00' * 8:
        raise ValueError('grand_b slot file content is not zero')
    gbc_relocs = addend_refs(GRAND_B_CALLER[0])
    if len(gbc_relocs) != 1 or gbc_relocs[0][0] != GRAND_B_CALLER_SLOT or \
            gbc_relocs[0][1] != RELA_RELATIVE:
        raise ValueError('grand_b_caller relocation reference mismatch')
    # Raw VA occurrences: grand_b's VA occurs in the file exactly once,
    # as the addend field of that single relocation entry (in both its
    # 8-byte and 4-byte forms). Grand_a's and the top FDE's VAs occur
    # nowhere as raw data.
    raw = {}
    for role in ('grand_a', 'grand_b', 'top', 'top_caller', 'grand_b_caller'):
        raw[role] = raw_occurrences(data, OWNERS[role][0])
    if raw['grand_b'][8] != [gb_relocs[0][2]] or raw['grand_b'][4] != [gb_relocs[0][2]]:
        raise ValueError('grand_b raw occurrence census mismatch')
    for role in ('grand_a', 'top', 'top_caller'):
        if raw[role][8] != [] or raw[role][4] != []:
            raise ValueError(f'{role} raw occurrence census mismatch')
    if raw['grand_b_caller'][8] != [gbc_relocs[0][2]] or \
            raw['grand_b_caller'][4] != [gbc_relocs[0][2]]:
        raise ValueError('grand_b_caller raw occurrence census mismatch')
    # RIP-relative references: nothing anywhere references grand_b's VA
    # directly. Exactly one instruction references its .got slot: the
    # indirect call inside grand_b_caller. The grand_b_caller slot is
    # consumed by indirect calls only (boundary data, not followed).
    if rip_relative_refs(data, GRAND_B[0]) != []:
        raise ValueError('unexpected RIP-relative reference to grand_b')
    slot_refs = rip_relative_refs(data, GRAND_B_SLOT)
    if [r['site'] for r in slot_refs] != [hex(GBC_CALL_SITE)] or slot_refs[0]['kind'] != 'call':
        raise ValueError('grand_b slot reference census mismatch')
    gbc_slot_refs = rip_relative_refs(data, GRAND_B_CALLER_SLOT)
    if len(gbc_slot_refs) != 12 or any(r['kind'] != 'call' for r in gbc_slot_refs):
        raise ValueError('grand_b_caller slot reference census mismatch')
    # Top FDE: the tag-argument provenance at grand_a's call site.
    tbody = bodies['top']
    for va, hexbytes, what in TOP_PINS:
        _pin(tbody, TOP[0], va, hexbytes, what)
    _pin(tbody, TOP[0], TOP_TAG_SPAN[0], TOP_TAG_SPAN[1], 'tag byte load and call argument setup')
    _pin(tbody, TOP[0], TOP_EMPTY_EXIT, '0f846a010000', 'empty range exit branch')
    if _branch_target(tbody, TOP[0], TOP_EMPTY_EXIT, 6, 2) != 0x3713493:
        raise ValueError('top empty range exit does not reach the epilogue')
    if _call_target(tbody, TOP[0], TOP_CALL_SITE) != GRAND_A[0]:
        raise ValueError('top call target mismatch')
    _pin(tbody, TOP[0], TOP_LOOP_BACK, '0f85cdfeffff', 'element loop back branch')
    if _branch_target(tbody, TOP[0], TOP_LOOP_BACK, 6, 2) != 0x3713360:
        raise ValueError('top loop back branch does not reach the loop head')
    if tbody.count(bytes.fromhex('4889442418')) != 1 or \
            tbody.count(bytes.fromhex('488b442418')) != 1:
        raise ValueError('top tag pointer frame slot is written or read more than once')
    # Grand_b_caller FDE: the tag-argument provenance at the indirect
    # call, and the convergence of both entry paths above the call.
    gbody = bodies['grand_b_caller']
    for va, hexbytes, what in GBC_PINS:
        _pin(gbody, GRAND_B_CALLER[0], va, hexbytes, what)
    _pin(gbody, GRAND_B_CALLER[0], GBC_CALL_SPAN[0], GBC_CALL_SPAN[1],
         'tag byte load, argument setup and the indirect call')
    _pin(gbody, GRAND_B_CALLER[0], GBC_SPLIT_JE, '0f84d2000000', 'path split branch')
    if _branch_target(gbody, GRAND_B_CALLER[0], GBC_SPLIT_JE, 6, 2) != 0x38d9da7:
        raise ValueError('grand_b_caller path split does not reach the convergence')
    _pin(gbody, GRAND_B_CALLER[0], GBC_CONVERGE_JMP, 'eb03', 'path convergence jump')
    if _branch_target8(gbody, GRAND_B_CALLER[0], GBC_CONVERGE_JMP) != 0x38d9daa:
        raise ValueError('grand_b_caller convergence jump target mismatch')
    if _branch_target(gbody, GRAND_B_CALLER[0], GBC_CALL_SITE, 6, 2) != GRAND_B_SLOT:
        raise ValueError('grand_b_caller indirect call does not target the grand_b slot')
    for pat in ('0fb6ae1d010000', '40886c240f', '0fb654240f'):
        if gbody.count(bytes.fromhex(pat)) != 1:
            raise ValueError(f'grand_b_caller tag byte pattern {pat} is not unique')
    # Top_caller FDE (boundary): the container it passes to the top FDE
    # is assembled on its own stack immediately before the call. Its
    # own argument provenance is not traced.
    cbody = bodies['top_caller']
    for va, hexbytes, what in TOP_CALLER_PINS:
        _pin(cbody, TOP_CALLER[0], va, hexbytes, what)
    if _call_target(cbody, TOP_CALLER[0], TOP_CALLER_CALL_SITE) != TOP[0]:
        raise ValueError('top_caller call target mismatch')
    return {'target_sha256': TARGET_SHA256,
            'owners': [owners[r] for r in OWNERS],
            'serializer_tag_rule': {'argument': 'third argument (edx)', 'compared_against': TAG_EQUAL,
                                    'byte_if_equal': hex(tag_byte(TAG_EQUAL)),
                                    'byte_otherwise': hex(tag_byte(TAG_EQUAL + 1))},
            'caller_forwarding': {
                'caller_a': {'call_site': '0x36aae0d', 'tag': 'its own third argument (edx), '
                             'forwarded unchanged; only rdi is replaced'},
                'caller_b': {'call_site': '0x36aaf2a', 'tag': 'its own third argument (edx), '
                             'forwarded unchanged; only rdi is replaced'}},
            'dispatcher_call_sites': {'caller_a': census['caller_a'],
                                      'caller_b': census['caller_b']},
            'grand_a_call_sites': census['grand_a'],
            'grand_a_references': {'relocations': 0, 'raw_occurrences_8byte': 0,
                                   'raw_occurrences_4byte': 0},
            'top_call_sites': census['top'],
            'top_tag_provenance': {
                'call_site': hex(TOP_CALL_SITE), 'owner': 'top',
                'argument': 'third argument (edx)',
                'source': 'a byte loaded through two dereferences of the top '
                          'entry third argument: the qword at [arg3+0x10] is '
                          'loaded at entry (0x3713329) and saved to the frame '
                          '(0x371332d); at the loop head it is reloaded '
                          '(0x3713360), dereferenced (0x3713365), and its '
                          'first byte is loaded into edx (0x371336c)',
                'execution': 'the call runs once per element of the range '
                             '[arg3]..[arg3+0x8] with stride 0x168; an empty '
                             'range branches to the epilogue and never calls; '
                             'the byte load re-executes every iteration',
                'delivers': 'tag 3 (emitted byte 0x61) exactly when that '
                            'memory byte equals 3 at the call; any other '
                            'byte value delivers a non-3 tag (byte 0x62)'},
            'grand_b_references': {
                'direct_call_sites': [], 'direct_jump_sites': [],
                'rip_relative_references': [],
                'relocations': [{'slot': hex(GRAND_B_SLOT), 'type': RELA_RELATIVE,
                                 'type_name': 'R_X86_64_RELATIVE',
                                 'addend': hex(GRAND_B[0]),
                                 'slot_section': '.got',
                                 'slot_file_content': 'zero; filled by the dynamic '
                                                      'linker from the relocation'},
                                ],
                'slot_references': [{'site': hex(GBC_CALL_SITE), 'kind': 'call',
                                     'encoding': 'ff15',
                                     'owner': 'grand_b_caller',
                                     'owner_start': hex(GRAND_B_CALLER[0])}],
                'raw_occurrences': {'eight_byte_file_offsets': [hex(gb_relocs[0][2])],
                                    'four_byte_file_offsets': [hex(gb_relocs[0][2])],
                                    'identity': 'the addend field of the single '
                                                'relocation entry above; the VA '
                                                'occurs nowhere else in the file'}},
            'grand_b_tag_provenance': {
                'call_site': hex(GBC_CALL_SITE), 'owner': 'grand_b_caller',
                'slot': hex(GRAND_B_SLOT),
                'argument': 'third argument (edx)',
                'source': 'the byte at [arg2+0x11d] of the calling FDE '
                          'entry, captured into ebp at entry (0x38d9c77), '
                          'stored to the frame slot +0xf (0x38d9cc5) before '
                          'the entry path split (0x38d9ccf), and reloaded '
                          'into edx immediately before the indirect call '
                          '(0x38d9df0); both entry paths converge at '
                          '0x38d9daa above the call',
                'delivers': 'tag 3 (emitted byte 0x61) exactly when that '
                            'record byte equals 3; any other byte value '
                            'delivers a non-3 tag (byte 0x62)'},
            'boundary_callers': {
                'top_caller': {'direct_call_sites': census['top_caller'],
                               'container': 'the three-qword container the top '
                                            'FDE receives is assembled on this '
                                            'FDE stack at [rsp+0x68] immediately '
                                            'before the call (fields stored at '
                                            '0x3ebdd80, 0x3ebdd85, 0x3ebdd8a); '
                                            'its own arguments are not traced'},
                'grand_b_caller': {'direct_call_sites': census['grand_b_caller'],
                                   'relocation': {'slot': hex(GRAND_B_CALLER_SLOT),
                                                  'type': RELA_RELATIVE,
                                                  'addend': hex(GRAND_B_CALLER[0])},
                                   'slot_references': gbc_slot_refs}},
            'tag_provenance': ('the chain is now grounded at both dispatcher '
                               'entries. grand_a path: the tag is a byte loaded '
                               'from memory through the top FDE third argument '
                               'pointer chain. grand_b path: the tag is a byte '
                               'copied from offset +0x11d of the calling FDE '
                               'second argument record. Neither path '
                               'materialises a constant tag; on each path the '
                               'emitted byte is 0x61 exactly when the '
                               'respective source byte equals 3, and 0x62 '
                               'otherwise'),
            'captured_code_executed': False,
            'limits': ('Static byte pins, FDE extent censuses, one .text call '
                       'census, one RIP-relative reference census over the '
                       'ff 15 / ff 25 / REX.W mov/lea encodings, the .rela.dyn '
                       'addend census and a raw VA occurrence census only. '
                       'Runtime byte values are not observed: which of the '
                       'two tag bytes the node emits for a given record '
                       'depends on the source bytes above, whose contents '
                       'are data. The packet does not name the record or '
                       'object types the pointers denote, does not trace the '
                       'top_caller FDE own arguments (the origins of the '
                       'values it stores into the container), and does not '
                       'follow the grand_b_caller FDE twelve indirect '
                       'callers. The dispatcher-internal behaviour is the '
                       'caller-tag packet claim, re-anchored here only '
                       'through the caller census, the forwarding prefixes '
                       'and the body hashes.')}


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
        exports[owner['role']] = executable(
            'objdump', ['-d', '-M', 'intel', '--insn-width=16', f'--start-address={start:#x}',
                        f'--stop-address={end:#x}', str(binary)],
            marker='Disassembly of section')
    # Native validation: every pinned address and every census or slot
    # call site inside an owner must be an instruction start in that
    # owner's decoded extent.
    pin_vas = {role: set() for role in OWNERS}
    for va, _h, _w in SERIALIZER_TAG_PINS:
        pin_vas['serializer'].add(va)
    for role in ('caller_a', 'caller_b'):
        pin_vas[role].add(OWNERS[role][0])
    for va, _h, _w in TOP_PINS:
        pin_vas['top'].add(va)
    pin_vas['top'] |= {TOP_TAG_SPAN[0], TOP_EMPTY_EXIT, TOP_LOOP_BACK, TOP_CALL_SITE}
    for va, _h, _w in GBC_PINS:
        pin_vas['grand_b_caller'].add(va)
    pin_vas['grand_b_caller'] |= {GBC_CALL_SPAN[0], GBC_SPLIT_JE, GBC_CONVERGE_JMP, GBC_CALL_SITE}
    for va, _h, _w in TOP_CALLER_PINS:
        pin_vas['top_caller'].add(va)
    pin_vas['top_caller'].add(TOP_CALLER_CALL_SITE)
    for entry in result['dispatcher_call_sites']['caller_a'] + result['dispatcher_call_sites']['caller_b']:
        pin_vas[entry['owner']].add(int(entry['site'], 16))
    for entry in result['grand_a_call_sites'] + result['top_call_sites']:
        pin_vas[entry['owner']].add(int(entry['site'], 16))
    for role, (start, end) in OWNERS.items():
        starts = set(decode_export(exports[role], start, end, read(data, start, end - start)))
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
