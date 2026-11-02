#!/usr/bin/env python3
"""Collect digest-bound static evidence for a configuration-rooted data route.

Only local ELF bytes are read. No captured executable or external tool is run.
"""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = TOOLS.parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280

# Selected FDEs only. Previously owned callers and callees are boundaries.
FUNCTIONS = (
 ('parent_finalize',0x1d3aa70,0x1d3ad06,'c7b92da5a548c6a4ded44c9b8d463a98f443138a09ada378484185e1fc0300e5'),
 ('sample_timing',0x4525250,0x4525453,'9b3e2b3b05248492e951ed7e64bd96458d3fa6e1f3a37c5d8b564a00974fbcf8'),
 ('indirect_string_formatter',0x45b0200,0x45b0217,'f6d3153f32460e15c6a35ea944aac2d2c925e26466d0efe7fa3624dc0cb66076'),
 ('event_record_writer',0x45ba470,0x45ba67b,'2ba1202b106ae3c8fd97d85bef2c3f1ba33d8f8bf0780901981b989bdcc957b4'),
 ('replica_entry',0x474bd90,0x474bf96,'220a187f0abf97160d0e4dc0551367b97a40813d7f7585aeeffabe24c7e0ae01'),
 ('pending_record_drain',0x4760b00,0x4760cc9,'3d1bc3d2fbde4b44c8f0d40acb173182d817a6d68e24df1b35251e9b2cc31c17'),
 ('response_field_writer',0x4a80e80,0x4a8105a,'91891f8493c7a1845d9cef499b011d4f78d6f17a07e023366c13fda13d11c5ff'),
 ('block_field_writer',0x4a85160,0x4a852e0,'1a07a620f1edb466f88bff95cb809d9edd47b1713c1eb00da847e12c7e26a422'),
 ('liner_drop',0x4b20250,0x4b2030d,'b8883399aa46b2986eeec4392b6847a01806dbee23626dcf9b41c78437b5d8af'),
 ('path_and_liner_constructor',0x4b307c0,0x4b30c2b,'70bc5cd388369a64dc97e10cd4dba8b016706da9310177dfc41c32eb236b11c1'),
 ('string_formatter',0x4b6ef00,0x4b6ef14,'ac4c6b99f205060905007ed866f7aa44b30a4aef644b6bed703004bbd8e4efc6'),
 ('buffer_drain',0x4b71f10,0x4b72029,'b8d0b51898678323645b2984c200c538a7d1ce47e34f54a3e0329719a102dac6'),
)

# These fixed bytes are checked independently beneath the full-image hash gate.
CONTRACTS = (
 ('finalize_entry',0x1d3aa70,'4157415641554154534889fbff15b685a303'),
 ('finalize_field',0x1d3aaea,'4889dfe88ec20000488bb3400500004885f6740f488bbb4805000031d2ff150335a303488dbb58050000e887ee0000'),
 ('finalize_pending',0x1d3ab25,'488b83b80500004889c148f7d9706c'),
 ('finalize_unwind',0x1d3ac63,'4889dfe815c10000488dbb40050000e819f90000488dbb60020000e88dfe0000488dbbb8050000e821780100'),
 ('entry_modes',0x474bdaf,'85f60f84cf000000'),
 ('entry_fmt_gate',0x474be5e,'e8edf7c8fc84c00f858c000000'),
 ('entry_modes_tail',0x474be7e,'4080fd01760ceb1f4c893c244080fd0177154889e74c89f6e8053f3e008b05f7ec020185c07577'),
 ('entry_key_call',0x474bea5,'4531c94080fd02410f92c14d8b4628488d150af9fafb4889e6b90c0000004889dfe8f5483e00'),
 ('constructor_sentinel',0x4b307ec,'31c0483b060f81a4000000'),
 ('local_path_predicate',0x4b30816,'488d35b7716bfb488d7c2408488d942488000000ff1510d8c3004c8b6424104c8b6c24184c89e74c89eeff155ae1c30084c074384c89a424880000004c89ac2490000000488d35e5936efb488dbc2488000000ba0a00000031c9e8bb9189fc4885c07408488b084889c7ff11'),
 ('config_path',0x4b3089b,'4889742460488b1d81e0c3008b435085c00f85e50200004883c31848895c2408488d053ee603004889442410488d8424d80000004889442418488d05959213004889442420488d4424604889442428488d050ff9a7ff4889442430488d352abc6cfb488d7c2470488d542408ff1533d7c300'),
 ('time_validate',0x4b30a3d,'488d7c2408ff1558dec300488dbc2488000000488d74240831d2ff15ebdfc3008b84248800000085c00f8410010000'),
 ('materialize',0x4b30aa1,'488d353dfa6bfb488dbc2488000000488d542408ff1585d5c300488d7c2408488db42488000000ff15f2dfc3000f10442448410f1147580f104424080f104c24180f105424280f105c2438410f115f48410f115738410f114f28410f114718488b842480000000498947100f28442470410f11074d8977688b44245841884770'),
 ('time_fail',0x4b30b7c,'488d3d52916efb488d15269fb300be2b000000ff15d3d8c3000f0b'),
 ('take',0x4760b0c,'488b87b805000048b9000000000000008048898fb80500004889c148f7d90f80f0000000'),
 ('timing',0x4760b73,'c6442478024889fb488bb760060000488d5610440fb68ea04b00004881c6d8020000488d0d4ab3f9fb488d7c240841b80c000000e8a446dcff'),
 ('name_gate',0x4760bac,'f20f10442410f20f584424184c8b742408660f2e05f39eaafb4889df762d4c8b3d57dd0001418b475085c07554410fb6474883f81f7714b900603c800fa3c1730a8b05a59f010185c07577'),
 ('drain_boundary',0x4760bf7,'49ffc648c7c6ffffffff490f45f64881c740050000488d542420e84af63c00488d7c2420e8503bfdff'),
 ('writer_first',0x45ba484,'bf80000000ff15493b1b014885c00f849d01000048c7442410800000004889442418488d4c241048894c2440c6007b48c74424200100000066c704240001488d4424404889442408488d351fcf13fc4889e7ba0a0000004c89e1e87dac4c004989c74885c07546803c2401751d48c74424280a000000488d7c242831f631d2ff15774a1b014989c7eb234983c458488d35e3ce13fc4889e7ba050000004c89e1e857694c004989c74885c0742b'),
 ('writer_second',0x45ba55c,'f60424017527807c2401007420488b4424084c8b38498b77104939377474498b4708c604307d48ffc649897710488b7424104c8b7c24184889f048f7d870ad4c8b64242048897424284c897c24304c896424384c89e04c39e6745841c604070a49ffc44c89f74889de4c89fa4c89e1e8d06ce1fc'),
 ('writer_more',0x45ba5ee,'ba01000000b90100000041b8010000004c89ffe8ca4ff9ff498b7710e96bffffff488d7c2428ba01000000b90100000041b801000000e81736e3fc4c8b7c2430488b442438eb82'),
 ('block_punctuation',0x4a851a0,'c64701024d8b3e498b47104939070f8484000000498b4f08c604012248ffc049894710'),
 ('resps_null',0x4a80f26,'803b02752c498b1e488b03488b73104829f04883f8030f86f7000000488b4308c704306e756c6c4883c60448897310eb10'),
 ('drop_guard',0x4b20255,'31c0483b07705b4889fbff1543e8c40048b800000000000000804839431874294c8d7b184c89ffe88f1c0500'),
 ('drop_fields',0x4b20281,'498b374885f6740c488b7b2031d2ff157bddc4008b7b34ff156ae4c400488b334885f67411488b7b0831d25b415e415fff2559ddc4005b415e415fc3'),
 ('flush_guard',0x4b71f1c,'807f18000f85b00000004889fb48893c24488b57104885d20f849c000000'),
 ('flush_errno',0x4b71f50,'41ffd48b00c643180083f8047546488b53104c39f27636'),
 ('flush_loop',0x4b71f67,'c64318014889d04c29f07270488b73084c01f689ef4889c241ffd74883f8ff74c8c64318004885c074134901c6488b53104c39f277ca4d85f6750beb324d85f6742d488b5310'),
 ('flush_move',0x4b71fad,'4989d74d29f7724848c74310000000007417488b7b084901fe4c89f64c89faff150ec1bf004c897b10'),
 ('adapter_ref',0x45b0200,'4889f0488b0f488b7108488b51104889c7ff25e9dd1b01'),
 ('adapter_string',0x4b6ef00,'4889f0488b7708488b57104889c7ff25ecf0bf00'),
 ('sample_lock',0x4525279,'4d8da768050000498b876805000089c183e108c1e9034883f8f00f93c208ca74124c89e731f6b900ca9a3bff153ea32401eb0c488d4810f0490fb10c2475e2'),
 ('sample_unlock',0x4525302,'4d8bb79805000048c7c0f0fffffff0490fc187680500004883e0f24883f8120f84e3000000'),
 ('sample_option',0x4525363,'807c2430007417bf32000000660f7f642430ff157d952401660f6f642430'),
 ('sample_result',0x45253e0,'4c8933660f5e0dc5fecdfb660f58cb660fdfc1f30f7f4308'),
 ('counter_increment',0x4760bf7,'49ffc648c7c6ffffffff490f45f6'),
)

# Bounded handoff observations only; these are not selected FDE bodies.
BOUNDARIES = (
 ('caller_entry',0x226eddd,'0fb6b3ab5700000fb693aa570000488dbc24a0110100488d8c24884c0100ff15274d5003'),
 ('caller_parent',0x226f13d,'488dbc2460170000488db42460cc0000ba6002000041ffd5'),
 ('caller_pending_init',0x226f2b7,'48b8000000000000008048898424181d0000'),
 ('caller_copy_parent',0x226f2df,'488db42460170000ba980600004c89f741ffd5'),
 ('caller_move',0x226f15d,'488b84241012010048898424101d00000f108424001201000f118424001d00000f108424f01101000f118424f01c00000f108424e01101000f118424e01c00000f108424a01101000f108c24b01101000f109424c01101000f109c24d01101000f119c24d01c00000f119424c01c00000f118c24b01c00000f118424a01c0000'),
 ('handoff_write',0x4b306c5,'48b8000000000000008048390374254c8d7c24184c89ffff15bee1c3004889df4c89fe4889eae8809da8ff4889dfff15afe3c300'),
 ('handoff_drop',0x4b3068b,'ff152fe4c3004889dfe8b7fbfeff'),
)

# RELA bindings used by the selected path; 6 denotes a dynamic symbol.
BINDINGS = {
 0x5668488:(8,0x2180ff,''), 0x576e010:(8,0x54c8cb0,''), 0x576e040:(8,0x1344760,''),
 0x576e928:(8,0x577b288,''), 0x576e9a0:(8,0x144a070,''),
 0x576eaa8:(8,0x13d1880,''), 0x576eac0:(8,0x13d1720,''),
 0x576e8a0:(8,0x151cba0,''), 0x576ea48:(8,0x151cec0,''),
 0x576e8b8:(8,0x4ee3b20,''), 0x5773b28:(8,0x474bd90,''),
 0x5773038:(8,0x4760b00,''), 0x576e000:(8,0x1573450,''),
 0x576dfb8:(8,0x1346068,''), 0x576dfd8:(8,0x54c06b0,''),
 0x576e108:(8,0x157b7f0,''), 0x576e8f8:(8,0x13c9e20,''),
 0x576e968:(8,0x4edba50,''), 0x576ea30:(8,0x1570900,''),
 0x576ea60:(8,0x1454a00,''), 0x576f5e8:(8,0x4e0b770,''),
 0x576f5f8:(8,0x4e0be20,''),
 0x576e0e0:(6,0,'memmove'), 0x576e708:(6,0,'close'),
 0x576e8d8:(6,0,'__errno_location'), 0x576eb88:(6,0,'write'),
}


def verify_identity(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 94 size or SHA-256 mismatch')


class View:
    def __init__(self,data,secs=None):
        self.data=data
        self.sections=sections(data) if secs is None else secs

    def offset(self,va,size):
        if type(va) is not int or type(size) is not int or va < 0 or size <= 0 or va + size > 1 << 64:
            raise ValueError('invalid virtual range')
        hits=[s for s in self.sections if s['type'] != 8 and s['size'] and s['address'] <= va and va+size <= s['address']+s['size']]
        if len(hits)!=1:
            raise ValueError('virtual range lacks a unique file-backed section')
        off=hits[0]['offset']+va-hits[0]['address']
        if off < 0 or off+size > len(self.data):
            raise ValueError('file-backed range is truncated')
        return off

    def read(self,va,size):
        off=self.offset(va,size)
        return self.data[off:off+size]


def require(view,label,va,expected):
    expected=bytes.fromhex(expected)
    actual=bytes(view.read(va,len(expected)))
    if actual != expected:
        raise ValueError('byte contract changed: '+label)
    return {'label':label,'va':hex(va),'file_offset':hex(view.offset(va,len(actual))),
            'length':len(actual),'bytes':actual.hex()}


# The closed byte-pattern x86 length reader is adapted from the independent
# MIT configuration-path collectors in PRs 1588 and 1632. It does not use
# disassembler output and fails on an unrecognized opcode.
def _need(body, pos, count):
    if pos < 0 or count < 0 or pos + count > len(body):
        raise ValueError('truncated instruction')


def decode_one(body, off, base):
    """Decode one length and control-transfer form; no full mnemonic claim."""
    start = off
    prefix66 = False
    rex = 0
    while True:
        _need(body, off, 1)
        p = body[off]
        if p in (0x66, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65):
            prefix66 |= p == 0x66
            off += 1
        elif 0x40 <= p <= 0x4f:
            rex = p
            off += 1
        else:
            break
        if off - start > 8:
            raise ValueError('too many prefixes')
    op = body[off]
    off += 1
    kind = 'instruction'
    target = None
    rel_width = 0
    modrm_needed = False
    imm = 0
    op2 = None
    if op == 0x0f:
        _need(body, off, 1)
        op2 = body[off]
        off += 1
        if 0x80 <= op2 <= 0x8f:
            kind, rel_width = 'conditional', 4
        elif op2 == 0x0b:
            kind = 'trap'
        elif (op2 in (0x10, 0x11, 0x14, 0x15, 0x1f, 0x28, 0x29, 0x2a, 0x2e, 0x2f, 0x57, 0x58, 0x5c, 0x5e,
                      0x60, 0x62, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x72, 0x73, 0x74, 0x7e, 0x7f, 0xa3, 0xaf, 0xb6, 0xb7,
                      0xb0, 0xb1, 0xbc, 0xc1, 0xbe, 0xbf, 0xd6, 0xd7, 0xdb, 0xdf, 0xe6, 0xeb, 0xef)
              or 0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f):
            modrm_needed = True
        else:
            raise ValueError(f'unsupported 0f opcode {op2:02x} at {base + start:#x}')
    elif op in (0xe8, 0xe9):
        kind, rel_width = ('call' if op == 0xe8 else 'jump'), 4
    elif op == 0xeb or 0x70 <= op <= 0x7f:
        kind, rel_width = ('jump' if op == 0xeb else 'conditional'), 1
    elif op in (0xc3, 0xcb):
        kind = 'return'
    elif op == 0xc2:
        kind, imm = 'return', 2
    elif op in (0xcc, 0xf4):
        kind = 'trap'
    elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99, 0xc9):
        pass
    elif 0xb8 <= op <= 0xbf:
        imm = 8 if rex & 8 else (2 if prefix66 else 4)
    elif 0xb0 <= op <= 0xb7 or op in (0x6a, 0xa8, 0x04, 0x0c, 0x24, 0x2c, 0x34, 0x3c):
        imm = 1
    elif op in (0x68, 0xa9, 0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d):
        imm = 2 if prefix66 else 4
    elif op in (0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2a, 0x2b,
                0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3a, 0x3b,
                0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85,
                0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8d, 0x8f,
                0xc0, 0xc1, 0xc6, 0xc7, 0xd0, 0xd1, 0xd2, 0xd3,
                0xf6, 0xf7, 0xfe, 0xff):
        modrm_needed = True
    else:
        raise ValueError(f'unsupported opcode {op:02x} at {base + start:#x}')

    rip_disp_pos = None
    modrm = None
    if modrm_needed:
        _need(body, off, 1)
        modrm = body[off]
        off += 1
        mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        sib_base = None
        if mod != 3 and rm == 4:
            _need(body, off, 1)
            sib_base = body[off] & 7
            off += 1
        if mod == 0 and rm == 5:
            rip_disp_pos = off
            off += 4
        elif mod == 0 and sib_base == 5:
            off += 4
        elif mod == 1:
            off += 1
        elif mod == 2:
            off += 4
        if op == 0x0f and op2 in (0x70, 0x72, 0x73):
            imm = 1
        elif op in (0x80, 0x83, 0x6b, 0xc0, 0xc1, 0xc6):
            imm = 1
        elif op in (0x81, 0x69, 0xc7):
            imm = 2 if prefix66 else 4
        elif op == 0xf6 and reg in (0, 1):
            imm = 1
        elif op == 0xf7 and reg in (0, 1):
            imm = 2 if prefix66 else 4
        if op == 0xff and reg in (2, 4):
            kind = 'indirect_call' if reg == 2 else 'indirect_jump'
    if rel_width:
        _need(body, off, rel_width)
        delta = int.from_bytes(body[off:off + rel_width], 'little', signed=True)
        off += rel_width
        target = base + off + delta
    else:
        _need(body, off, imm)
        off += imm
        if rip_disp_pos is not None:
            _need(body, rip_disp_pos, 4)
            target = base + off + struct.unpack_from('<i', body, rip_disp_pos)[0]
    if off - start > 15:
        raise ValueError('instruction exceeds x86 maximum')
    _need(body, start, off - start)
    return {'va': base + start, 'end': base + off, 'kind': kind,
            'target': target, 'bytes': bytes(body[start:off]),
            'opcode': (op, op2), 'modrm': modrm,
            'rip_relative': rip_disp_pos is not None}


def decode_body(body, base):
    result = []
    offset = 0
    while offset < len(body):
        row = decode_one(body, offset, base)
        result.append(row)
        offset = row['end'] - base
    if offset != len(body):
        raise ValueError('function decoding exceeded extent')
    starts = {r['va'] for r in result}
    end = base + len(body)
    for row in result:
        if row['kind'] in ('jump', 'conditional') and base <= row['target'] < end:
            if row['target'] not in starts:
                raise ValueError(f'branch into an instruction at {row["va"]:#x}')
        if row['kind'] == 'conditional' and row['end'] < end and row['end'] not in starts:
            raise ValueError('fallthrough is not an instruction boundary')
    return result




def reachable(decoded, source, destination, forbidden=()):
    """Over-approximate normal flow: all conditions feasible and calls return."""
    by_va = {ins['va']: ins for ins in decoded}
    if source not in by_va or destination not in by_va:
        raise ValueError('CFG query is not at an instruction boundary')
    forbidden = set(forbidden)
    if any(va not in by_va for va in forbidden):
        raise ValueError('CFG forbidden VA is not an instruction boundary')
    pending, seen = [source], set()
    while pending:
        va = pending.pop()
        if va in forbidden or va in seen or va not in by_va:
            continue
        if va == destination:
            return True
        seen.add(va)
        ins = by_va[va]
        kind = ins['kind']
        if kind in ('return', 'trap', 'indirect_jump'):
            continue
        if kind == 'jump':
            pending.append(ins['target'])
        elif kind == 'conditional':
            pending.extend((ins['target'], ins['end']))
        else:
            pending.append(ins['end'])
    return False

def parse_lsda(view, start, end, lsda_va):
    """Read this target's ULEB call-site table; do not interpret actions/types."""
    containing = [s for s in view.sections if s['name'] == '.gcc_except_table'
                  and s['type'] != 8 and s['address'] <= lsda_va < s['address'] + s['size']]
    if len(containing) != 1:
        raise ValueError('LSDA outside file-backed exception table')
    sec = containing[0]
    pos = view.offset(lsda_va, 2)
    section_end = sec['offset'] + sec['size']
    data = view.data
    lp_encoding, type_encoding = data[pos], data[pos+1]
    pos += 2
    if lp_encoding != 0xff or type_encoding not in (0xff, 0x9b):
        raise ValueError('unsupported LSDA header encoding')
    type_base = None
    if type_encoding != 0xff:
        relative, pos = uleb(data, pos, section_end)
        type_base = pos + relative
        if type_base > section_end:
            raise ValueError('LSDA type table outside section')
    if pos >= section_end or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, section_end)
    stop = pos + size
    if stop > section_end or (type_base is not None and stop > type_base):
        raise ValueError('LSDA call-site table outside bounds')
    begin = pos
    rows = []
    previous_end = 0
    while pos < stop:
        entry_off = pos
        region, pos = uleb(data, pos, stop)
        length, pos = uleb(data, pos, stop)
        landing, pos = uleb(data, pos, stop)
        action, pos = uleb(data, pos, stop)
        if not length or region < previous_end or region + length > end - start:
            raise ValueError('LSDA protected range invalid')
        if landing and landing >= end - start:
            raise ValueError('LSDA landing pad outside selected FDE')
        previous_end = region + length
        rows.append({'function': hex(start), 'lsda_va': hex(lsda_va),
                     'entry_file_offset': hex(entry_off), 'start_va': hex(start + region),
                     'end_va': hex(start + region + length),
                     'landing_va': hex(start + landing) if landing else '', 'action_index': action})
    header = {'function': hex(start), 'lsda_va': hex(lsda_va),
              'header_file_offset': hex(view.offset(lsda_va, 2)),
              'lpstart_encoding': hex(lp_encoding), 'type_encoding': hex(type_encoding),
              'callsite_encoding': '0x1', 'callsite_file_offset': hex(begin),
              'callsite_size': size, 'entries': len(rows)}
    return header, rows



def parse_bindings(view, expected=BINDINGS):
    relas=[s for s in view.sections if s['name']=='.rela.dyn' and s['type']==4]
    syms=[s for s in view.sections if s['name']=='.dynsym' and s['type']==11]
    strings=[s for s in view.sections if s['name']=='.dynstr' and s['type']==3]
    if len(relas)!=1 or len(syms)!=1 or len(strings)!=1 or relas[0]['size']%24 or syms[0]['size']%24:
        raise ValueError('invalid relocation or dynamic-symbol section')
    rela, sym, string=relas[0],syms[0],strings[0]
    found={}
    for off in range(rela['offset'],rela['offset']+rela['size'],24):
        where,info,addend=struct.unpack_from('<QQq',view.data,off)
        if where not in expected:
            continue
        if where in found:
            raise ValueError('duplicate selected relocation')
        typ,idx=info & 0xffffffff,info >> 32
        symbol=''
        if idx:
            if idx*24+24>sym['size']:
                raise ValueError('dynamic symbol index out of bounds')
            nameoff=struct.unpack_from('<I',view.data,sym['offset']+idx*24)[0]
            if nameoff>=string['size']:
                raise ValueError('dynamic symbol name out of bounds')
            a=string['offset']+nameoff
            end=view.data.find(b'\0',a,string['offset']+string['size'])
            if end<0:
                raise ValueError('unterminated dynamic symbol')
            symbol=view.data[a:end].decode('ascii')
        if (typ,addend,symbol)!=expected[where] or (typ==8 and idx!=0):
            raise ValueError('selected relocation changed: '+hex(where))
        found[where]={'slot_va':hex(where),'record_offset':hex(off),'type':typ,
                      'symbol_index':idx,'symbol':symbol,'addend':hex(addend),
                      'record_bytes':view.data[off:off+24].hex()}
    if set(found)!=set(expected):
        raise ValueError('missing selected relocation')
    return [found[k] for k in sorted(found)]


def template(view,va,expected):
    expected=bytes.fromhex(expected)
    raw=bytes(view.read(va,len(expected)))
    if raw!=expected:
        raise ValueError('format template bytes changed')
    pos=0
    tokens=[]
    while pos<len(raw):
        tag=raw[pos]
        pos+=1
        if tag==0:
            if pos!=len(raw):
                raise ValueError('trailing format bytes')
            return {'va':hex(va),'file_offset':hex(view.offset(va,len(raw))),
                    'length':len(raw),'bytes':raw.hex(),'tokens':tokens}
        if tag==0xc0:
            tokens.append({'argument':True})
        elif 1<=tag<=0x7f:
            if pos+tag>len(raw):
                raise ValueError('truncated format literal')
            tokens.append({'literal_hex':raw[pos:pos+tag].hex()})
            pos+=tag
        else:
            raise ValueError('unsupported format token')
    raise ValueError('missing format terminator')


def render_template(record,arguments):
    out=bytearray()
    index=0
    for token in record['tokens']:
        if 'argument' in token:
            if index>=len(arguments):
                raise ValueError('missing format argument')
            out.extend(arguments[index])
            index+=1
        else:
            out.extend(bytes.fromhex(token['literal_hex']))
    if index!=len(arguments):
        raise ValueError('extra format argument')
    return bytes(out)


def immediate32(view,va,prefix):
    prefix=bytes.fromhex(prefix)
    raw=bytes(view.read(va,len(prefix)+4))
    if not raw.startswith(prefix):
        raise ValueError('immediate instruction changed')
    return struct.unpack_from('<I',raw,len(prefix))[0]


def selected_slice(view, label, target, length, expected):
    raw=bytes(view.read(target,length))
    if raw!=expected:
        raise ValueError('data slice changed: '+label)
    return {'label':label,'va':hex(target),'file_offset':hex(view.offset(target,length)),
            'length':length,'bytes':raw.hex()}


def rip(view,va):
    raw=bytes(view.read(va,7))
    if raw[0] not in (0x48,0x4c) or raw[1] not in (0x8b,0x8d) or raw[2]&0xc7!=5:
        raise ValueError('unsupported selected RIP-relative operand')
    return va+7+struct.unpack_from('<i',raw,3)[0]


def direct(view,va,opcode=0xe8):
    raw=bytes(view.read(va,5))
    if raw[0]!=opcode:
        raise ValueError('direct transfer opcode changed')
    return va+5+struct.unpack_from('<i',raw,1)[0]


def name_admitted(value,mask,upper):
    if type(value) is not int or not 0<=value<=255 or not 0<=mask<1<<32 or upper!=31:
        raise ValueError('invalid discriminant predicate')
    return value<=upper and bool(mask & (1<<value))


def counter_increment(value):
    # INC sets zero on wrap; CMOVNE otherwise keeps the incremented value.
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError('invalid unsigned counter')
    return min(value + 1, (1 << 64) - 1)


def duration_gate(value,threshold):
    # UCOMISD/JBE takes the bypass for less, equal, or unordered operands.
    if type(value) is not float or type(threshold) is not float:
        raise ValueError('invalid binary64 comparison')
    return value > threshold


def classify_drain(active,initial,results,retry_error=4):
    """Model the visible write loop with supplied return values, not node execution.

    Returns a remaining-byte vector, number of supplied writes consumed and a
    label. A -1 return uses its supplied errno. Inputs outside the normal write
    contract are rejected; an exhausted script leaves the next attempt pending.
    """
    remaining=bytes(initial)
    if active or not remaining:
        return remaining,0,'guard_return'
    consumed=0
    cursor=0
    for result,err in results:
        if result < -1 or result > len(remaining)-cursor:
            raise ValueError('impossible supplied write result')
        consumed+=1
        if result==-1:
            if err==retry_error:
                continue
            break
        if result==0:
            break
        cursor+=result
        if cursor>=len(remaining):
            return b'',consumed,'finished'
    else:
        return remaining[cursor:],consumed,'next_write_pending'
    return remaining[cursor:],consumed,'stopped'


def cfg_checks(decodes):
    # Conditional edges are treated as feasible and calls as normally returning.
    tests=(
      ('parent_start_reaches_pending',0x1d3aa70,0x1d3aa70,0x1d3aa7c,True),
      ('parent_after_pending_reaches_field',0x1d3aa70,0x1d3aa82,0x1d3aaf2,True),
      ('parent_unwind_reaches_field_cleanup',0x1d3aa70,0x1d3ac63,0x1d3ac72,True),
      ('entry_present_reaches_constructor',0x474bd90,0x474be6b,0x474bec6,True),
      ('entry_absent_reaches_constructor',0x474bd90,0x474be86,0x474bec6,True),
      ('entry_format_error_reaches_trap',0x474bd90,0x474bef7,0x474bf1a,True),
      ('entry_format_error_bypasses_constructor',0x474bd90,0x474bef7,0x474bec6,False),
      ('local_constructor_reaches_join',0x4b307c0,0x4b307f7,0x4b3090d,True),
      ('config_constructor_reaches_join',0x4b307c0,0x4b3089b,0x4b3090d,True),
      ('constructor_normal_reaches_liner',0x4b307c0,0x4b30a6c,0x4b30ac8,True),
      ('constructor_time_error_reaches_trap',0x4b307c0,0x4b30b7c,0x4b30b95,True),
      ('constructor_time_error_bypasses_liner',0x4b307c0,0x4b30b7c,0x4b30ac8,False),
      ('drain_live_record_reaches_handoff',0x4760b00,0x4760b30,0x4760c11,True),
      ('drain_absent_bypasses_handoff',0x4760b00,0x4760c20,0x4760c11,False),
      ('record_error_bypasses_write',0x45ba470,0x45ba531,0x45ba5cb,False),
      ('record_success_reaches_write',0x45ba470,0x45ba5b7,0x45ba5cb,True),
      ('null_field_reaches_literal',0x4a80e80,0x4a80f2b,0x4a80f46,True),
      ('null_field_bypasses_value_helper',0x4a80e80,0x4a80f2b,0x4a80f5d,False),
      ('nonnull_field_reaches_value_helper',0x4a80e80,0x4a80f57,0x4a80f5d,True),
      ('drop_present_reaches_buffer',0x4b20250,0x4b20275,0x4b2027c,True),
      ('drop_absent_bypasses_buffer',0x4b20250,0x4b202b7,0x4b2027c,False),
      ('write_loop_can_retry',0x4b71f10,0x4b71f5e,0x4b71f7f,True),
      ('write_partial_can_compact',0x4b71f10,0x4b71fa9,0x4b71fcc,True),
    )
    out=[]
    for label,fn,source,destination,want in tests:
        actual=reachable(decodes[fn],source,destination)
        if actual!=want:
            raise ValueError('control-flow proposition failed: '+label)
        out.append({'label':label,'function_va':hex(fn),'source_va':hex(source),
                    'destination_va':hex(destination),'reachable':int(actual)})
    return out


def tsv(path,rows,columns):
    with path.open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=columns,delimiter='\t',lineterminator='\n',extrasaction='raise')
        writer.writeheader()
        writer.writerows(rows)


def selected_unwind_index(index, starts):
    wanted=set(starts)
    result={}
    for row in index:
        start=row['start']
        if start not in wanted:
            continue
        if start in result:
            raise ValueError('duplicate selected unwind-index start')
        result[start]=row
    if set(result)!=wanted:
        raise ValueError('missing selected unwind-index start')
    return result


def collect(data,check_identity=True):
    if check_identity:
        verify_identity(data)
    view=View(data)
    secs,index=unwind_index(data)
    _,fdes=eh_frame_records(data,secs)
    index_by_start=selected_unwind_index(index,(start for _,start,_,_ in FUNCTIONS))
    fnrows=[]
    decodes={}
    lsda_headers=[]
    lsda_rows=[]
    for role,start,end,digest in FUNCTIONS:
        matches=[f for f in fdes if f['start']==start]
        if len(matches)!=1 or matches[0]['end']!=end:
            raise ValueError('selected FDE missing, duplicated or changed: '+role)
        f=matches[0]
        if start not in index_by_start or index_by_start[start]['fde']!=f['fde']:
            raise ValueError('FDE and unwind index differ: '+role)
        raw=bytes(view.read(start,end-start))
        if hashlib.sha256(raw).hexdigest()!=digest:
            raise ValueError('selected body digest changed: '+role)
        rows=decode_body(raw,start)
        decodes[start]=rows
        fnrows.append({'role':role,'start_va':hex(start),'end_va':hex(end),
                       'fde_va':hex(f['fde']),'cie_va':hex(f['cie']),
                       'lsda_va':hex(f['lsda']) if f['lsda'] is not None else '',
                       'file_offset':hex(view.offset(start,len(raw))),'size':len(raw),
                       'instructions':len(rows),'sha256':digest})
        if f['lsda'] is not None:
            h,sites=parse_lsda(view,start,end,f['lsda'])
            lsda_headers.append(h)
            lsda_rows.extend(sites)
    first_call=[x for x in decodes[0x1d3aa70] if x['va']==0x1d3aa7c]
    if (len(first_call)!=1 or first_call[0]['kind']!='indirect_call'
            or first_call[0]['target']!=0x5773038 or BINDINGS[0x5773038]!=(8,0x4760b00,'')):
        raise ValueError('parent finalizer call target changed')
    contracts=[require(view,*row) for row in CONTRACTS]
    boundaries=[require(view,*row) for row in BOUNDARIES]
    boundary_decodes={}
    for label,va,expected in BOUNDARIES:
        boundary_decodes[label]=decode_body(bytes(view.read(va,len(bytes.fromhex(expected)))),va)
    boundary_edges=[]
    for label,site,kind,operand,resolved in (
        ('caller_entry',0x226edfb,'indirect_call',0x5773b28,0x474bd90),
        ('handoff_drop',0x4b3068b,'indirect_call',0x576eac0,0x13d1720),
        ('handoff_drop',0x4b30694,'call',0x4b20250,0x4b20250),
        ('handoff_write',0x4b306dc,'indirect_call',0x576e8a0,0x151cba0),
        ('handoff_write',0x4b306eb,'call',0x45ba470,0x45ba470)):
        found=[x for x in boundary_decodes[label] if x['va']==site]
        if len(found)!=1 or found[0]['kind']!=kind or found[0]['target']!=operand:
            raise ValueError('boundary transfer changed: '+label)
        if kind=='indirect_call' and BINDINGS.get(operand)!=(8,resolved,''):
            raise ValueError('boundary relocation expectation changed')
        boundary_edges.append({'boundary':label,'site_va':hex(site),'kind':kind,
                               'operand_va':hex(operand),'resolved_va':hex(resolved)})
    starts={fn:{x['va'] for x in seq}|{seq[-1]['end']} for fn,seq in decodes.items()}
    for row in contracts:
        va=int(row['va'],16)
        end=va+row['length']
        owners=[fn for fn in starts if va in starts[fn] and end in starts[fn]]
        if len(owners)!=1:
            raise ValueError('contract not aligned to selected instructions: '+row['label'])
    for row in lsda_rows:
        fn=int(row['function'],16)
        for key in ('start_va','end_va','landing_va'):
            if row[key] and int(row[key],16) not in starts[fn]:
                raise ValueError('LSDA endpoint is not an instruction boundary')
    relocations=parse_bindings(view)
    source_base=struct.unpack('<I',view.read(0x226edef,4))[0]
    parent_base=struct.unpack('<I',view.read(0x226f141,4))[0]
    relative_field=struct.unpack('<I',view.read(0x4760c08,4))[0]
    next_parent_base=struct.unpack('<I',view.read(0x226f2e3,4))[0]
    copy_size=struct.unpack('<I',view.read(0x226f2e8,4))[0]
    pending_stack=struct.unpack('<I',view.read(0x226f2c5,4))[0]
    pending_read=struct.unpack('<I',view.read(0x4760b0f,4))[0]
    pending_store=struct.unpack('<I',view.read(0x4760b20,4))[0]
    init_sentinel=struct.unpack('<Q',view.read(0x226f2b9,8))[0]
    take_sentinel=struct.unpack('<Q',view.read(0x4760b15,8))[0]
    if (pending_stack-parent_base!=pending_read or pending_read!=pending_store
            or init_sentinel!=take_sentinel or init_sentinel!=1<<63):
        raise ValueError('pending state initialization mismatch')
    move_specs=((0x226f15d,0x226f165,8),(0x226f16d,0x226f175,16),
                (0x226f17d,0x226f185,16),(0x226f18d,0x226f195,16),
                (0x226f19d,0x226f1d5,16),(0x226f1a5,0x226f1cd,16),
                (0x226f1ad,0x226f1c5,16),(0x226f1b5,0x226f1bd,16))
    moves=[]
    for load,store,width in move_specs:
        source=struct.unpack('<I',view.read(load+4,4))[0]
        dest=struct.unpack('<I',view.read(store+4,4))[0]
        if source-source_base != dest-parent_base-relative_field:
            raise ValueError('staged output move mismatch')
        moves.append({'load_va':hex(load),'store_va':hex(store),'width':width,
                      'source_stack_offset':hex(source),'destination_stack_offset':hex(dest),
                      'object_relative_offset':hex(source-source_base)})
    if next_parent_base!=parent_base or copy_size<=relative_field+0x70:
        raise ValueError('parent handoff range changed')
    handoff={'source_stack_offset':hex(source_base),'parent_stack_offset':hex(parent_base),
             'object_field_offset':hex(relative_field),'subsequent_copy_bytes':copy_size,
             'pending_state_offset':hex(pending_read),'pending_sentinel':hex(init_sentinel),
             'moves':moves,'limitation':'Local offsets support the handoff; runtime instance identity and scheduling are not established.'}
    instructions=[]
    transfers=[]
    for fn in sorted(decodes):
        for item in decodes[fn]:
            size=item['end']-item['va']
            row={'function_va':hex(fn),'va':hex(item['va']),'file_offset':hex(view.offset(item['va'],size)),
                 'size':size,'bytes':item['bytes'].hex(),'kind':item['kind'],
                 'rip_relative':int(item['rip_relative']),
                 'target_va':hex(item['target']) if item['target'] is not None else ''}
            instructions.append(row)
            if item['kind']!='instruction':
                transfers.append(row)
    expected_rips={0x474beb4:0x6fb7c5,0x4b30816:0x1e79d4,0x4b308f6:0x1fc527,
                   0x4b30aa1:0x1f04e5,0x45ba4cc:0x6f73f2,0x45ba512:0x6f73fc,
                   0x4760b95:0x6fbee6,0x4b3085a:0x219c46,0x4b3094d:0x706af0,
                   0x474bef7:0x219b4d,0x4b30b7c:0x219cd5}
    rip_rows=[]
    for site,want in sorted(expected_rips.items()):
        got=rip(view,site)
        if got!=want:
            raise ValueError('selected data operand changed')
        rip_rows.append({'site_va':hex(site),'file_offset':hex(view.offset(site,7)),
                         'bytes':bytes(view.read(site,7)).hex(),'target_va':hex(got)})
    if (direct(view,0x474bec6)!=0x4b307c0 or direct(view,0x4760ba7)!=0x4525250
            or direct(view,0x4760c11)!=0x4b30260 or direct(view,0x45ba4de)!=0x4a85160
            or direct(view,0x45ba524)!=0x4a80e80 or direct(view,0x4b2027c)!=0x4b71f10):
        raise ValueError('selected call edge changed')
    if direct(view,0x4b306eb)!=0x45ba470 or direct(view,0x4b30694)!=0x4b20250:
        raise ValueError('previously indexed handoff target changed')
    templates={
      'local':template(view,0x1e79d4,'0b2f746d702f6c6f63616c5fc0065f6c696e657200'),
      'configured':template(view,0x1fc527,'c0062f646174612fc0012fc000'),
      'child':template(view,0x1f04e5,'c0012fc0012fc000'),
    }
    data_rows=[selected_slice(view,'replica_key',0x6fb7c5,immediate32(view,0x474bebe,'b9'),b'replica_cmds'),
               selected_slice(view,'timing_key',0x6fbee6,immediate32(view,0x4760ba1,'41b8'),b'crash_height'),
               selected_slice(view,'block_key',0x6f73f2,immediate32(view,0x45ba4d6,'ba'),b'abci_block'),
               selected_slice(view,'responses_key',0x6f73fc,immediate32(view,0x45ba51c,'ba'),b'resps'),
               selected_slice(view,'time_pattern',0x219d00,immediate32(view,0x474bdf6,'48c7842480000000'),b'%Y-%m-%dT%H:%M:%SZ'),
               selected_slice(view,'child_time_pattern',0x706af0,immediate32(view,0x4b30959,'48c7442430'),b'%Y-%m-%dT%H:%M:%S%.3fZ'),
               selected_slice(view,'local_operation',0x219c46,immediate32(view,0x4b30869,'ba'),b'remove_dir'),
               selected_slice(view,'entry_failure',0x219b4d,immediate32(view,0x474bf0f,'be'),b'a Display implementation returned an error unexpectedly'),
               selected_slice(view,'time_failure',0x219cd5,immediate32(view,0x4b30b8a,'be'),b'Local time out of range for `NaiveDateTime`')]
    default_length=struct.unpack('<Q',view.read(0x5668490,8))[0]
    default=selected_slice(view,'default_name',0x2180ff,default_length,b'NvTestnet')
    default['table_slot_va']=hex(0x5668488)
    default['table_index']=(0x5668488-0x5668288)//16
    if default['table_index']!=32 or (0x5668488-0x5668288)%16:
        raise ValueError('default name table boundary changed')
    data_rows.append({k:default[k] for k in ('label','va','file_offset','length','bytes')})
    mask=struct.unpack('<I',view.read(0x4760be4,4))[0]
    upper=view.read(0x4760be0,1)[0]
    if mask!=0x803c6000 or upper!=31:
        raise ValueError('name gate immediate changed')
    threshold=struct.unpack('<d',view.read(0x20aab8,8))[0]
    if threshold!=3.0:
        raise ValueError('duration threshold changed')
    tags=[{'byte':i,'admitted_by_mask':int(name_admitted(i,mask,upper))} for i in range(256)]
    counter_values=(0,1,(1<<64)-3,(1<<64)-2,(1<<64)-1)
    counter_cases=[{'input':hex(i),'result':hex(counter_increment(i))} for i in counter_values]
    duration_values=(('negative_infinity',float('-inf')),('below',float.fromhex('0x1.7ffffffffffffp+1')),
                     ('equal',threshold),('above',float.fromhex('0x1.8000000000001p+1')),
                     ('positive_infinity',float('inf')),('unordered',float('nan')))
    duration_cases=[{'sample':label,'name_gate_reached':int(duration_gate(value,threshold))}
                    for label,value in duration_values]
    mode_upper=view.read(0x474be81,1)[0]
    mode_upper_absent=view.read(0x474be8d,1)[0]
    mode_forward_limit=view.read(0x474beab,1)[0]
    response_null_tag=view.read(0x4a80f28,1)[0]
    if (mode_upper,mode_upper_absent,mode_forward_limit,response_null_tag)!=(1,1,2,2):
        raise ValueError('mode or response immediate changed')
    modes=[{'first_flag':flag,'mode_byte':mode,
            'initial_value':'time_format' if flag else 'sentinel',
            'mode_le_one':int(mode<=mode_upper if flag else mode<=mode_upper_absent),
            'forwarded_low_byte':int(mode<mode_forward_limit)}
           for flag in (0,1) for mode in range(256)]
    response_tags=[{'byte':i,'local_result':'literal_null' if i==response_null_tag else 'external_value_helper'} for i in range(256)]
    scripts=(('empty',0,b'',()),('already_active',1,b'abcdef',((6,0),)),
             ('complete',0,b'abcdef',((6,0),)),('short_then_complete',0,b'abcdef',((2,0),(4,0))),
             ('eintr_then_complete',0,b'abcdef',((-1,4),(6,0))),
             ('partial_zero',0,b'abcdef',((2,0),(0,0))),('partial_error',0,b'abcdef',((3,0),(-1,5))),
             ('first_error',0,b'abcdef',((-1,5),)),('eintr_waiting',0,b'abcdef',((-1,4),)))
    retry_code=view.read(0x4b71f5b,1)[0]
    if retry_code!=4:
        raise ValueError('write retry immediate changed')
    drain_cases=[]
    for label,active,initial,script in scripts:
        remaining,used,status=classify_drain(active,initial,script,retry_code)
        drain_cases.append({'case':label,'active':active,'input_hex':initial.hex(),
                            'supplied':','.join(str(a)+':'+str(e) for a,e in script),
                            'remaining_hex':remaining.hex(),'calls':used,'result':status})
    cfg=cfg_checks(decodes)
    examples={
      'local':render_template(templates['local'],[b'replica_cmds']).hex(),
      'configured':render_template(templates['configured'],[b'ROOT',b'replica_cmds',b'VALUE']).hex(),
      'child':render_template(templates['child'],[b'BASE',b'FIELD',b'TIME']).hex(),
    }
    summary={'schema':1,'target':'node94','sha256':DIGEST,
             'coordinate_system':'linked ELF virtual addresses and section-mapped file offsets',
             'selected_fdes':len(fnrows),'selected_fde_bytes':sum(x['size'] for x in fnrows),
             'decoded_instructions':len(instructions),'decoded_transfers':len(transfers),
             'transfer_classes':dict(sorted(Counter(x['kind'] for x in transfers).items())),
             'contracts':len(contracts),'boundary_excerpts':len(boundaries),
             'boundary_edges':len(boundary_edges),
             'relative_or_symbol_bindings':len(relocations),'lsda_tables':len(lsda_headers),
             'lsda_sites':len(lsda_rows),'cfg_propositions':len(cfg),'templates':len(templates),
             'data_slices':len(data_rows),'name_mask':hex(mask),'name_upper':upper,
             'name_admitted':[r['byte'] for r in tags if r['admitted_by_mask']],
             'duration_threshold_binary64':threshold,'default_name':default,
             'write_retry_code':retry_code,'mode_limit_inclusive':mode_upper,
             'mode_forward_exclusive':mode_forward_limit,'response_null_tag':response_null_tag,
             'mode_cases':len(modes),
             'name_byte_cases':len(tags),'response_byte_cases':len(response_tags),
             'buffer_cases':len(drain_cases),'counter_cases':len(counter_cases),
             'duration_cases':len(duration_cases),'rendered_examples_hex':examples,
             'limitations':['FDE extents are not a whole-function census',
                            'Selected boundary excerpts do not select or decode their containing FDEs',
                            'CFG assumes normally returning calls and does not prove path feasibility',
                            'Formatter, initializer, interposed route, shared writers and filesystem effects are boundaries',
                            'Synthetic models are not executions of the captured binary']}
    scope=locals()
    keys=('fnrows','instructions','transfers','contracts','boundaries','boundary_edges','rip_rows',
          'data_rows','relocations','lsda_headers','lsda_rows','cfg','tags','modes',
          'response_tags','drain_cases','counter_cases','duration_cases','summary','templates','handoff')
    return {key:scope[key] for key in keys}


def generate(data,out):
    r=collect(data)
    out.mkdir(parents=True,exist_ok=True)
    specs=(
      ('functions.tsv','fnrows',('role','start_va','end_va','fde_va','cie_va','lsda_va','file_offset','size','instructions','sha256')),
      ('instructions.tsv','instructions',('function_va','va','file_offset','size','bytes','kind','rip_relative','target_va')),
      ('transfers.tsv','transfers',('function_va','va','file_offset','size','bytes','kind','rip_relative','target_va')),
      ('contracts.tsv','contracts',('label','va','file_offset','length','bytes')),
      ('boundary-excerpts.tsv','boundaries',('label','va','file_offset','length','bytes')),
      ('boundary-edges.tsv','boundary_edges',('boundary','site_va','kind','operand_va','resolved_va')),
      ('data-refs.tsv','rip_rows',('site_va','file_offset','bytes','target_va')),
      ('data-slices.tsv','data_rows',('label','va','file_offset','length','bytes')),
      ('relocations.tsv','relocations',('slot_va','record_offset','type','symbol_index','symbol','addend','record_bytes')),
      ('lsda-headers.tsv','lsda_headers',('function','lsda_va','header_file_offset','lpstart_encoding','type_encoding','callsite_encoding','callsite_file_offset','callsite_size','entries')),
      ('lsda-sites.tsv','lsda_rows',('function','lsda_va','entry_file_offset','start_va','end_va','landing_va','action_index')),
      ('cfg.tsv','cfg',('label','function_va','source_va','destination_va','reachable')),
      ('name-cases.tsv','tags',('byte','admitted_by_mask')),
      ('mode-cases.tsv','modes',('first_flag','mode_byte','initial_value','mode_le_one','forwarded_low_byte')),
      ('response-cases.tsv','response_tags',('byte','local_result')),
      ('buffer-cases.tsv','drain_cases',('case','active','input_hex','supplied','remaining_hex','calls','result')),
      ('counter-cases.tsv','counter_cases',('input','result')),
      ('duration-cases.tsv','duration_cases',('sample','name_gate_reached')),
    )
    for filename,key,cols in specs:
        tsv(out/filename,r[key],cols)
    for key in ('summary','templates','handoff'):
        (out/(key+'.json')).write_text(json.dumps(r[key],indent=2,ensure_ascii=True)+'\n',encoding='utf-8',newline='\n')
    return r


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    data=TARGET.read_bytes()
    verify_identity(data)
    r=generate(data,args.out)
    print(json.dumps(r['summary'],sort_keys=True))
    return 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (ValueError,OSError,struct.error) as error:
        print('config_replica_route94:',error,file=sys.stderr)
        raise SystemExit(1)
