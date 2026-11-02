#!/usr/bin/env python3
"""Extract the node 94 configured status-file route from authenticated ELF bytes.

Addresses are unrelocated virtual addresses. This is a restricted instruction
length/control-transfer reader, not a general x86 disassembler or an emulator.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

TOOL_DIR = Path(__file__).resolve().parent
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = TOOL_DIR.parent
CAPTURE = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
SOURCE_COMMIT = '966865f1637a29ce75b019e1bf11d5529cc6f519'

# These are selected entry seeds, not a complete inventory of functions.
FUNCTIONS = (
    ('status_json_writer', 0x276cd60),
    ('status_binary_writer', 0x276cfa0),
    ('json_object_close', 0x27b1280),
    ('binary_optional_float', 0x27b25e0),
    ('status_file_route', 0x28eb6a0),
    ('json_optional_height', 0x295c660),
    ('json_time_field', 0x2965820),
    ('json_optional_float', 0x296c640),
)


def verify_identity(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 94 artifact size or SHA-256 mismatch')


class View:
    def __init__(self, data, secs=None):
        self.data = data
        self.sections = sections(data) if secs is None else secs

    def offset(self, va, size):
        if type(va) is not int or type(size) is not int or va < 0 or size <= 0 or va + size > 1 << 64:
            raise ValueError('invalid virtual address range')
        found = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2 and s['size']
                 and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(found) != 1:
            raise ValueError('virtual range is not uniquely allocated and file-backed')
        off = found[0]['offset'] + va - found[0]['address']
        if off < 0 or off + size > len(self.data):
            raise ValueError('truncated file-backed range')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def section(self, name):
        found = [s for s in self.sections if s['name'] == name and s['type'] != 8]
        if len(found) != 1:
            raise ValueError('missing or duplicate file-backed section')
        return found[0]


def check_bytes(view, name, va, expected_hex):
    expected = bytes.fromhex(expected_hex)
    actual = bytes(view.read(va, len(expected)))
    if actual != expected:
        raise ValueError('changed instruction/data contract: ' + name)
    return {'name': name, 'va': hex(va), 'file_offset': hex(view.offset(va, len(expected))),
            'length': len(expected), 'bytes': actual.hex()}

# Restricted x86 length/transfer reader adapted from the MIT heartbeat collector.
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
        elif 0xc8 <= op2 <= 0xcf:
            pass
        elif (op2 in (0x10, 0x11, 0x13, 0x14, 0x15, 0x1f, 0x28, 0x29, 0x2a, 0x2e, 0x2f, 0x57, 0x58, 0x5c, 0x5e,
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
        if row['kind'] == 'conditional' and not base <= row['target'] < end:
            raise ValueError(f'conditional branch outside selected extent at {row["va"]:#x}')
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



# Exact selected byte contracts pin the dataflow described in README. Each is
# read again from the input; these are selections, not invented target bytes.
CONTRACTS = (
    ('path_capture_arguments', 0x25ae06b, '4889d34989f6'),
    ('file_route_capture_arguments', 0x28eb6ae, '4889cb4989d64989f74989fc'),
    ('caller_status_object', 0x220c0eb, '4c897c24304c896424380f288424800000000f2944241048c744242000000000488d3d661b4903488d156f1b4903488d742410e83d1f3a00'),
    ('root_cell_boundary', 0x25ae0c9, '4c8b3d58081c03418b475085c00f85870000004983c718'),
    ('format_call', 0x25ae111, '488d35f141c4fd4889e7488d542418ff151aff1b034c8b7c2408488b5424104c89f74c89fe4889d9e862d53300'),
    ('null_path', 0x28eb6c4, '4883fa09751f48b82f6465762f6e756c493307410fb64f084883f16c4809c10f844c0100004c89ff4c89f6ff152b3fe80284c0746f'),
    ('binary_setup', 0x28eb6f9, '48c74424080000000048c74424100100000048c744241800000000488d4424084889442458c744246000040001c644246400488d7c2420488d5424584c89e6e86318e8ff4c8b64242048b800000000000000804883c8044939c40f85ed000000'),
    ('json_setup', 0x28eb768, 'bf80000000ff156528e8024885c00f843101000048c744240880000000488944241048c744241800000000488d4424084889442420488d054ca8b0fd488944242848c74424300200000048c744243800000000c644244000488d7424204c89e7e89315e8ff4989c44885c00f85ae0000004c8b6c24084c8b6424104c89e848f7d80f80af000000'),
    ('filesystem_sequence', 0x28eb7ef, '488b6c24184c89ff4c89f6ff156832e8024885c075154c89e74889ee4c89fa4c89f14989d8ff15563ee802'),
    ('serialize_errors', 0x28eb846, '488b5c24284c8b742430488b7424084885f6740d488b7c241031d2ff15a927e8024c8964242048895c24284c89742430488d7c2448488d742420e8eb000000ebb0488b7424084885f6740d488b7c241031d2ff157227e802488d7c24484c89e6e855000000eb8a'),
    ('json_start', 0x276cd6b, '488b46184883f8ff0f84190200004889fb4c8b3648ffc048894618c6462000498b46104939060f8497010000498b4e08c604017b48ffc04989461066c744240800014889742410488d4b20488d357e34c8fd488d7c2408ba0e000000'),
    ('json_height_tag', 0x295c680, '4d8b6608488b7b084c8b33498b1c24488b03488b73104829f04883f8010f86aa000000488b430866c704303a204883c60248897310498b1c2441f6c601743a'),
    ('json_height_null', 0x295c6f9, '488b03488b73104829f04883f8030f868f000000488b4308c704306e756c6c4883c60448897310'),
    ('binary_height_tag', 0x276d0af, '41833f01753b498b57084889e74c89f6e80cf0e3ff488b04244883f802744e488b54240848892b48894308488953104889d84883c4285b415c415d415e415f5dc34d8b264d8b2c24498b7424104939f50f84220100004939f50f847a010000498b442408c60430c049ff442410'),
    ('json_float_tag', 0x296c68d, '41803e007466498b1c24f3410f7e460866480f7ec048b9ffffffffffffff7f4821c148b8000000000000f07f4839c17d3f'),
    ('json_float_null', 0x296c6f9, '498b1c24488b03488b73104829f04883f8037661488b4308c704306e756c6c4883c60448897310'),
    ('binary_float_tag', 0x27b25fe, '807e0b0074204c89f74889d64889caf20f11442408e8d881dffff20f104424084883f802754441f6c70174144c89f7e80e80dfff4883f802753d4983c404eb3f4d8b364d8b3e498b76104939f7743f4939f70f849d000000498b4608c60430c049ff46104983c404eb15'),
    ('writer_output_tag', 0x276d1de, '4c8923e9f8feffff48892c2448894424084889542410488b44241048894310488b0424488903488b44240848894308'),
    ('close_json', 0x27b128b, '803f000f85cc000000807f01000f84c20000004c8b67084d8b6c24184d85ed0f8404010000498b1c2449ffcd4d896c2418'),
    ('buffer_mark', 0x27b134b, '4c3933741f488b430842c604307d49ffc64c897310'),
)

# Key pointer and length are decoded from each LEA and following immediate;
# offsets and transfer sites are checked against the selected instruction bytes.
FIELDS = (
    ('initial_height', 0x276cdb6, 0x276cdc2, 0x276cdc7, 0x276d01b, 0x276d022, 0x276d042, 0x20),
    ('height', 0x276cde4, 0x276cdf0, 0x276cdf5, 0x276d05c, 0x276d063, 0x276d07f, 0x28),
    ('scheduled_freeze_height', 0x276ce0e, 0x276ce1a, 0x276ce22, 0x276d095, 0x276d09c, 0x276d0bf, 0x00),
    ('consensus_time', 0x276ce3b, 0x276ce47, 0x276cea5, 0x276d123, 0x276d12a, 0x276d15f, 0x30),
    ('wall_clock_time', 0x276ceb8, 0x276cec4, 0x276cec9, 0x276d179, 0x276d180, 0x276d1ac, 0x3c),
    ('reference_lag', 0x276cede, 0x276ceea, 0x276cef2, 0x276d1c1, 0x276d1cb, 0x276d1d3, 0x10),
)

# One selected result branch immediately after each value-writer call.
JSON_RESULT_BRANCHES = (0x276cdcf, 0x276cdfd, 0x276ce2a, 0x276cead, 0x276ced1, 0x276cefa)
BINARY_RESULT_BRANCHES = (0x276d04f, 0x276d08c, 0x276d0cc, 0x276d16c, 0x276d1b5, 0x276d1dc)

# Exact operands connecting the input object to the field writers.
FIELD_OPERANDS = (
    ('json_initial_offset', 0x276cdb2, '488d4b20'),
    ('json_height_offset', 0x276cde0, '488d4b28'),
    ('json_freeze_base', 0x276ce1f, '4889d9'),
    ('json_consensus_offset', 0x276ce5c, '4c8d6330'),
    ('json_wall_offset', 0x276ceb4, '488d4b3c'),
    ('json_lag_offset', 0x276ceda, '4883c310'),
    ('binary_initial_offset', 0x276d010, '4d8b6720'),
    ('binary_height_offset', 0x276d051, '4d8b6728'),
    ('binary_freeze_base', 0x276d0af, '41833f01'),
    ('binary_consensus_offset', 0x276d141, '498d4730'),
    ('binary_wall_offset', 0x276d193, '498d473c'),
    ('binary_lag_offset', 0x276d1b7, '4d8b4710f2410f104718'),
)


def read_relocations(view, wanted):
    sec = view.section('.rela.dyn')
    if sec['size'] % 24:
        raise ValueError('invalid ELF64 relocation section size')
    found = {}
    for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
        location, info, addend = struct.unpack_from('<QQq', view.data, pos)
        if location in wanted:
            if location in found:
                raise ValueError('duplicate selected relocation')
            found[location] = {'slot': location, 'type': info & 0xffffffff,
                               'symbol': info >> 32, 'addend': addend, 'offset': pos}
    if wanted - found.keys():
        raise ValueError('selected relocation missing')
    return found


def relative_target(relocs, slot):
    row = relocs[slot]
    if row['type'] != 8 or row['symbol'] != 0 or row['addend'] < 0:
        raise ValueError('expected symbol-free R_X86_64_RELATIVE')
    return row['addend']


def read_template(view, va):
    """Recognize the selected placeholder/literal template, rejecting extras."""
    pos, tokens, raw = 0, [], bytearray()
    while pos < 128:
        tag = view.read(va + pos, 1)[0]
        pos += 1
        raw.append(tag)
        if tag == 0:
            return bytes(raw), tokens
        if tag == 0xc0:
            tokens.append({'kind': 'argument'})
        elif 1 <= tag <= 0x7f:
            literal = bytes(view.read(va + pos, tag))
            raw.extend(literal)
            pos += tag
            tokens.append({'kind': 'literal', 'hex': literal.hex(), 'ascii': literal.decode('ascii')})
        else:
            raise ValueError('unsupported format token')
    raise ValueError('unterminated or oversized template')


def json_optional_height(tag):
    if type(tag) is not int or not 0 <= tag < (1 << 64):
        raise ValueError('height tag must be a 64-bit word')
    return 'value' if tag & 1 else 'null'


def binary_optional_height(tag):
    if type(tag) is not int or not 0 <= tag < (1 << 64):
        raise ValueError('height tag must be a 64-bit word')
    return 'value' if tag & 0xffffffff == 1 else 'nil'


def json_optional_float(tag, bits):
    if type(tag) is not int or not 0 <= tag <= 255 or type(bits) is not int or not 0 <= bits < (1 << 64):
        raise ValueError('invalid float tag or bits')
    if tag == 0 or bits & 0x7fffffffffffffff >= 0x7ff0000000000000:
        return 'null'
    return 'delegate-finite'


def binary_optional_float(tag):
    if type(tag) is not int or not 0 <= tag <= 255:
        raise ValueError('invalid float tag')
    return 'delegate-value' if tag & 1 else 'nil'


def immediate32(ins):
    b = ins['bytes']
    if len(b) != 5 or b[0] not in (0xb9, 0xba):
        raise ValueError('field length is not an expected immediate move')
    return struct.unpack_from('<I', b, 1)[0]


def target_at(instructions, va, kind=None):
    ins = instructions.get(va)
    if ins is None or ins['target'] is None or (kind is not None and ins['kind'] != kind):
        raise ValueError('required target is not a selected instruction boundary')
    return ins['target']


def collect(data, check_digest=True):
    if check_digest:
        verify_identity(data)
    secs, index = unwind_index(data)
    view = View(data, secs)
    _, fdes = eh_frame_records(data, secs)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    indexed = {row['start']: row for row in index}
    functions, all_instructions, decoded = [], {}, {}
    for role, start in FUNCTIONS:
        if len(by_start.get(start, [])) != 1 or start not in indexed:
            raise ValueError('missing or duplicate selected FDE/index')
        fde = by_start[start][0]
        if indexed[start]['fde'] != fde['fde'] or fde['end'] <= start:
            raise ValueError('FDE/index disagreement or empty extent')
        size = fde['end'] - start
        body = bytes(view.read(start, size))
        executable = [s for s in secs if s['type'] != 8 and s['flags'] & 4
                      and s['address'] <= start and fde['end'] <= s['address'] + s['size']]
        if len(executable) != 1:
            raise ValueError('selected FDE is not uniquely executable and file-backed')
        rows = decode_body(body, start)
        for ins in rows:
            if ins['va'] in all_instructions:
                raise ValueError('overlapping selected instruction ranges')
            ins['role'] = role
            all_instructions[ins['va']] = ins
        decoded[role] = rows
        functions.append({'role': role, 'start_va': hex(start), 'end_va': hex(fde['end']),
                          'file_offset': hex(view.offset(start, size)), 'size': size,
                          'fde_va': hex(fde['fde']), 'cie_va': hex(fde['cie']),
                          'lsda_va': hex(fde['lsda']) if fde['lsda'] is not None else '',
                          'unwind_index': indexed[start]['index'], 'body_sha256': hashlib.sha256(body).hexdigest(),
                          'instruction_count': len(rows)})

    contracts = [check_bytes(view, *item) for item in CONTRACTS + FIELD_OPERANDS]
    # The two earlier-owned parent instructions are boundary context only.
    boundary = decode_one(bytes(view.read(0x220c11e, 5)), 0, 0x220c11e)
    descriptor_ref = decode_one(bytes(view.read(0x220c10b, 7)), 0, 0x220c10b)
    location_ref = decode_one(bytes(view.read(0x220c112, 7)), 0, 0x220c112)
    if boundary['kind'] != 'call' or boundary['target'] != 0x25ae060:
        raise ValueError('previous caller does not enter selected path')
    if not descriptor_ref['rip_relative'] or descriptor_ref['opcode'][0] != 0x8d or descriptor_ref['target'] != 0x569dc78:
        raise ValueError('previous caller does not pass the selected descriptor')
    if not location_ref['rip_relative'] or location_ref['opcode'][0] != 0x8d or location_ref['target'] != 0x569dc88:
        raise ValueError('previous caller does not pass the selected Location')
    root_ref = decode_one(bytes(view.read(0x25ae0c9, 7)), 0, 0x25ae0c9)
    if not root_ref['rip_relative'] or root_ref['target'] != 0x576e928:
        raise ValueError('selected entry does not load the configuration slot')

    slots = {ins['target'] for ins in all_instructions.values()
             if ins['kind'] in ('indirect_call', 'indirect_jump') and ins['rip_relative']}
    slots.update((0x576e928, 0x577b288, 0x569dc78, 0x569dc88))
    relocs = read_relocations(view, slots)
    root_cell = relative_target(relocs, 0x576e928)
    if root_cell != 0x577b288:
        raise ValueError('configuration relocation changed')
    root_initializer = relative_target(relocs, root_cell)
    if root_initializer != 0x164ff00:
        raise ValueError('configuration initializer relocation changed')
    desc_target = relative_target(relocs, 0x569dc78)
    desc_len = struct.unpack('<Q', view.read(0x569dc80, 8))[0]
    if desc_len != 16:
        raise ValueError('unexpected selected name descriptor length')
    name = bytes(view.read(desc_target, desc_len))
    if name != b'visor_abci_state':
        raise ValueError('unexpected caller name')
    location = location_ref['target']
    source_va = relative_target(relocs, location)
    source_len = struct.unpack('<Q', view.read(location + 8, 8))[0]
    if not 1 <= source_len <= 4096:
        raise ValueError('invalid Location path length')
    source_bytes = bytes(view.read(source_va, source_len))
    source_tail = b'l1/src/abci/engine.rs'
    if not source_bytes.endswith(source_tail):
        raise ValueError('unexpected Location source tail')
    source_line, source_column = struct.unpack('<II', view.read(location + 16, 8))

    sink_call = decode_one(bytes(view.read(0x25ae139, 5)), 0, 0x25ae139)
    if sink_call['kind'] != 'call' or sink_call['target'] != 0x28eb6a0:
        raise ValueError('boundary does not call the selected file route')
    template_ref = decode_one(bytes(view.read(0x25ae111, 7)), 0, 0x25ae111)
    if not template_ref['rip_relative'] or template_ref['opcode'][0] != 0x8d:
        raise ValueError('boundary does not refer to a format template')
    template_va = template_ref['target']
    template, tokens = read_template(view, template_va)
    if template != bytes.fromhex('c0122f68797065726c69717569645f646174612fc0012ec000'):
        raise ValueError('status path template changed')

    fields = []
    for ordinal, (expected, jptr, jlen, jcall, bptr, blen, bcall, obj_off) in enumerate(FIELDS):
        for site in (jptr, bptr):
            reference = all_instructions.get(site)
            if reference is None or not reference['rip_relative'] or reference['opcode'][0] != 0x8d:
                raise ValueError('field name reference is not a RIP-relative LEA')
        ja, ba = target_at(all_instructions, jptr), target_at(all_instructions, bptr)
        jl, bl = immediate32(all_instructions[jlen]), immediate32(all_instructions[blen])
        text = bytes(view.read(ja, jl))
        if ja != ba or jl != bl or text.decode('ascii') != expected:
            raise ValueError('field label, pointer, or length disagrees')
        jtarget, btarget = target_at(all_instructions, jcall, 'call'), target_at(all_instructions, bcall, 'call')
        jbranch = all_instructions[JSON_RESULT_BRANCHES[ordinal]]
        bbranch = all_instructions[BINARY_RESULT_BRANCHES[ordinal]]
        if jbranch['kind'] != 'conditional' or bbranch['kind'] != 'conditional' or jbranch['target'] != 0x276cf22:
            raise ValueError('unexpected field result branch')
        fields.append({'ordinal': ordinal, 'name': text.decode('ascii'), 'name_va': hex(ja),
                       'name_file_offset': hex(view.offset(ja, jl)),
                       'length': jl, 'input_offset': hex(obj_off), 'json_name_site': hex(jptr),
                       'json_call_site': hex(jcall), 'json_callee': hex(jtarget),
                       'binary_name_site': hex(bptr), 'binary_call_site': hex(bcall),
                       'binary_callee': hex(btarget),
                       'json_result_branch': hex(jbranch['va']), 'json_error_target': hex(jbranch['target']),
                       'binary_result_branch': hex(bbranch['va']),
                       'binary_taken_target': hex(bbranch['target']), 'binary_fallthrough': hex(bbranch['end'])})

    # The object-offset numbers above must agree with actual operand bytes.
    decoded_offsets = [view.read(0x276cdb5, 1)[0], view.read(0x276cde3, 1)[0], 0,
                       view.read(0x276ce5f, 1)[0], view.read(0x276ceb7, 1)[0],
                       view.read(0x276cedd, 1)[0]]
    if decoded_offsets != [x[-1] for x in FIELDS]:
        raise ValueError('object field offsets changed')

    headers, exceptions = [], []
    for (_, start), f in zip(FUNCTIONS, functions):
        fde = by_start[start][0]
        if fde['lsda'] is not None:
            header, entries = parse_lsda(view, start, fde['end'], fde['lsda'])
            bounds = {row['va'] for row in decoded[f['role']]} | {fde['end']}
            for entry in entries:
                for key in ('start_va', 'end_va', 'landing_va'):
                    if entry[key] and int(entry[key], 16) not in bounds:
                        raise ValueError('LSDA site is not on a selected instruction boundary')
            headers.append(header)
            exceptions.extend(entries)
    return {'view': view, 'functions': functions, 'decoded': decoded, 'instructions': all_instructions,
            'contracts': contracts, 'fields': fields, 'relocations': relocs,
            'lsda_headers': headers, 'exception_sites': exceptions,
            'path': {'root_slot': hex(0x576e928), 'root_cell': hex(root_cell),
                     'prior_initializer_va': hex(root_initializer),
                     'root_field_offset': hex(view.read(0x25ae0df, 1)[0]),
                     'root_once_offset': hex(view.read(0x25ae0d3, 1)[0]),
                     'parent_call_site': hex(boundary['va']), 'parent_call_target': hex(boundary['target']),
                     'parent_call_file_offset': hex(view.offset(boundary['va'], 5)),
                     'name_descriptor_ref_site': hex(descriptor_ref['va']),
                     'name_descriptor_ref_file_offset': hex(view.offset(descriptor_ref['va'], 7)),
                     'location_ref_site': hex(location_ref['va']), 'location_descriptor': hex(location),
                     'location_file_offset': hex(view.offset(location, 24)),
                     'location_source_va': hex(source_va), 'location_source_file_offset': hex(view.offset(source_va, source_len)),
                     'location_source_length': source_len, 'location_source_sha256': hashlib.sha256(source_bytes).hexdigest(),
                     'location_source_tail': source_tail.decode('ascii'), 'location_line': source_line,
                     'location_column': source_column,
                     'name_descriptor': hex(descriptor_ref['target']), 'name_descriptor_file_offset': hex(view.offset(0x569dc78, 16)),
                     'name_va': hex(desc_target), 'name_file_offset': hex(view.offset(desc_target, desc_len)),
                     'name_length': desc_len, 'name_hex': name.hex(), 'name': name.decode('ascii'),
                     'boundary_call_site': hex(sink_call['va']), 'boundary_call_target': hex(sink_call['target']),
                     'boundary_call_file_offset': hex(view.offset(sink_call['va'], 5)),
                     'root_ref_site': hex(root_ref['va']), 'template_ref_site': hex(template_ref['va']),
                     'template_va': hex(template_va), 'template_file_offset': hex(view.offset(template_va, len(template))),
                     'template_hex': template.hex(), 'template_tokens': tokens}}

BRANCH_ROLES = {
    0x28eb6c8: 'path length differs from special bypass',
    0x28eb6e3: 'path equals special bypass',
    0x28eb6f7: 'extension predicate selects JSON',
    0x28eb753: 'binary serializer does not return success tag',
    0x28eb776: 'JSON buffer allocation returned zero',
    0x28eb7d3: 'JSON serializer returned an error',
    0x28eb7e9: 'JSON buffer has signed-minimum sentinel',
    0x28eb803: 'first file step returned nonzero; skip second',
    0x276cd73: 'JSON nesting level cannot increment',
    0x276cdcf: 'first JSON field writer failed',
    0x276cfc5: 'binary writer chooses positional mode',
    0x276d0b3: 'freeze-height tag is not one',
    0x295c6bd: 'freeze-height low bit clear',
    0x296c691: 'reference-lag byte is zero',
    0x296c6bc: 'reference-lag float is nonfinite',
    0x27b2628: 'binary reference-lag low bit clear',
    0x27b12aa: 'JSON closing depth is zero',
}

# Reachability overapproximates normal flow: both branch outcomes are allowed,
# calls return, and no claim of runtime feasibility is made.
CFG_QUERIES = (
    ('file_route_binary_arm', 'status_file_route', 0x28eb6a0, 0x28eb738, True),
    ('file_route_json_arm', 'status_file_route', 0x28eb6a0, 0x28eb7c8, True),
    ('bypass_cannot_reach_json', 'status_file_route', 0x28eb835, 0x28eb7c8, False),
    ('bypass_cannot_reach_binary', 'status_file_route', 0x28eb835, 0x28eb738, False),
    ('binary_failure_cannot_reach_file_step', 'status_file_route', 0x28eb846, 0x28eb7fa, False),
    ('json_failure_cannot_reach_file_step', 'status_file_route', 0x28eb887, 0x28eb7fa, False),
    ('first_file_step_failure_skips_second', 'status_file_route', 0x28eb81a, 0x28eb814, False),
    ('json_writer_can_close', 'status_json_writer', 0x276cd60, 0x276cf01, True),
    ('json_error_cannot_close', 'status_json_writer', 0x276cf22, 0x276cf01, False),
    ('binary_height_can_write_nil', 'status_binary_writer', 0x276d0af, 0x276d113, True),
    ('binary_height_can_write_value', 'status_binary_writer', 0x276d0af, 0x276d0bf, True),
    ('json_float_can_write_null', 'json_optional_float', 0x296c68d, 0x296c711, True),
    ('json_float_can_delegate_finite', 'json_optional_float', 0x296c68d, 0x296c6c1, True),
    ('binary_float_can_write_nil', 'binary_optional_float', 0x27b2624, 0x27b265a, True),
    ('binary_float_can_delegate_value', 'binary_optional_float', 0x27b2624, 0x27b262d, True),
)


def hex_or_empty(value):
    return '' if value is None else hex(value)


def make_tables(result):
    ins = result['instructions']
    relocs = result['relocations']
    functions = result['functions']
    by_start = {int(f['start_va'], 16): f['role'] for f in functions}
    by_role = {f['role']: f for f in functions}
    instructions, branches, transfers = [], [], []
    for va in sorted(ins):
        row = ins[va]
        target = row['target']
        instructions.append({'function': row['role'], 'va': hex(va),
                             'file_offset': hex(result['view'].offset(va, len(row['bytes']))),
                             'length': len(row['bytes']), 'bytes': row['bytes'].hex(),
                             'kind': row['kind'], 'rip_relative': int(row['rip_relative']),
                             'target_va': hex_or_empty(target)})
        if row['kind'] == 'conditional':
            branches.append({'function': row['role'], 'va': hex(va), 'bytes': row['bytes'].hex(),
                             'taken_va': hex(target), 'fallthrough_va': hex(row['end']),
                             'selected_meaning': BRANCH_ROLES.get(va, '')})
        if row['kind'] in ('call', 'jump', 'indirect_call', 'indirect_jump'):
            resolved = None
            binding = ''
            if row['kind'] in ('indirect_call', 'indirect_jump') and row['rip_relative']:
                relocation = relocs[target]
                binding = 'relocation'
                if relocation['type'] == 8 and relocation['symbol'] == 0:
                    resolved = relocation['addend']
            elif row['kind'] in ('call', 'jump'):
                resolved = target
                binding = 'relative'
            transfers.append({'function': row['role'], 'va': hex(va), 'kind': row['kind'],
                              'bytes': row['bytes'].hex(), 'encoded_target_or_slot': hex_or_empty(target),
                              'binding': binding, 'resolved_va': hex_or_empty(resolved),
                              'selected_target_function': by_start.get(resolved, '')})
    missing = set(BRANCH_ROLES) - {int(row['va'], 16) for row in branches}
    if missing:
        raise ValueError('selected branch seed is not a decoded conditional')

    reloc_rows = []
    for slot, row in sorted(relocs.items()):
        reloc_rows.append({'slot_va': hex(slot), 'slot_file_offset': hex(result['view'].offset(slot, 8)),
                           'rela_file_offset': hex(row['offset']), 'type': row['type'],
                           'symbol': row['symbol'], 'addend': hex(row['addend']) if row['addend'] >= 0 else str(row['addend'])})
    queries = []
    for label, role, source, target, expected in CFG_QUERIES:
        if role not in by_role:
            raise ValueError('unknown CFG role')
        got = reachable(result['decoded'][role], source, target)
        if got != expected:
            raise ValueError('unexpected structural reachability: ' + label)
        queries.append({'query': label, 'function': role, 'source_va': hex(source),
                        'target_va': hex(target), 'reachable': int(got)})
    return instructions, branches, transfers, reloc_rows, queries


def tsv(out, name, rows, headings):
    with (out / name).open('w', encoding='utf-8', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=headings, delimiter='\t', lineterminator='\n', extrasaction='raise')
        writer.writeheader()
        writer.writerows(rows)


def json_file(out, name, value):
    (out / name).write_bytes((json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode('utf-8'))


def generate(data, out):
    result = collect(data)
    instructions, branches, transfers, relocs, queries = make_tables(result)
    out.mkdir(parents=True, exist_ok=True)
    tsv(out, 'functions.tsv', result['functions'],
        ('role', 'start_va', 'end_va', 'file_offset', 'size', 'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'body_sha256', 'instruction_count'))
    tsv(out, 'instructions.tsv', instructions,
        ('function', 'va', 'file_offset', 'length', 'bytes', 'kind', 'rip_relative', 'target_va'))
    tsv(out, 'branches.tsv', branches,
        ('function', 'va', 'bytes', 'taken_va', 'fallthrough_va', 'selected_meaning'))
    tsv(out, 'transfers.tsv', transfers,
        ('function', 'va', 'kind', 'bytes', 'encoded_target_or_slot', 'binding', 'resolved_va', 'selected_target_function'))
    tsv(out, 'fields.tsv', result['fields'],
        ('ordinal', 'name', 'name_va', 'name_file_offset', 'length', 'input_offset', 'json_name_site', 'json_call_site', 'json_callee',
         'binary_name_site', 'binary_call_site', 'binary_callee', 'json_result_branch', 'json_error_target',
         'binary_result_branch', 'binary_taken_target', 'binary_fallthrough'))
    tsv(out, 'relocations.tsv', relocs, ('slot_va', 'slot_file_offset', 'rela_file_offset', 'type', 'symbol', 'addend'))
    tsv(out, 'contracts.tsv', result['contracts'], ('name', 'va', 'file_offset', 'length', 'bytes'))
    tsv(out, 'cfg.tsv', queries, ('query', 'function', 'source_va', 'target_va', 'reachable'))
    tsv(out, 'lsda-headers.tsv', result['lsda_headers'],
        ('function', 'lsda_va', 'header_file_offset', 'lpstart_encoding', 'type_encoding', 'callsite_encoding', 'callsite_file_offset', 'callsite_size', 'entries'))
    tsv(out, 'exception-sites.tsv', result['exception_sites'],
        ('function', 'lsda_va', 'entry_file_offset', 'start_va', 'end_va', 'landing_va', 'action_index'))
    json_file(out, 'path.json', result['path'])
    v = result['view']
    tag_data = {'height_json_mask': v.read(0x295c6bc, 1)[0],
                'height_binary_compare': v.read(0x276d0b2, 1)[0],
                'lag_json_absent_byte': v.read(0x296c690, 1)[0],
                'lag_binary_mask': v.read(0x27b2627, 1)[0],
                'float_magnitude_mask': hex(struct.unpack('<Q', v.read(0x296c6a4, 8))[0]),
                'float_infinity_bits': hex(struct.unpack('<Q', v.read(0x296c6b1, 8))[0]),
                'json_null_ascii': bytes(v.read(0x295c714, 4)).decode('ascii'),
                'binary_nil_byte': hex(v.read(0x276d116, 1)[0]),
                'concrete_caller_lag_tag_qword': hex(struct.unpack('<I', v.read(0x220c107, 4))[0])}
    if tag_data != {'height_json_mask': 1, 'height_binary_compare': 1, 'lag_json_absent_byte': 0,
                    'lag_binary_mask': 1, 'float_magnitude_mask': '0x7fffffffffffffff',
                    'float_infinity_bits': '0x7ff0000000000000', 'json_null_ascii': 'null',
                    'binary_nil_byte': '0xc0', 'concrete_caller_lag_tag_qword': '0x0'}:
        raise ValueError('selected tag, nil, or float constant changed')
    json_file(out, 'tag-constants.json', tag_data)
    summary = {'target_sha256': DIGEST, 'target_size': len(data), 'source_commit': SOURCE_COMMIT,
               'selected_fdes': len(result['functions']),
               'selected_bytes': sum(f['size'] for f in result['functions']),
               'selected_instructions': len(instructions), 'conditional_branches': len(branches),
               'transfers': len(transfers), 'selected_relocations': len(relocs),
               'field_count': len(result['fields']), 'byte_contracts': len(result['contracts']),
               'cfg_queries': len(queries), 'lsda_headers': len(result['lsda_headers']),
               'lsda_call_sites': len(result['exception_sites']),
               'limits': 'Static selected extents only; calls, reachability feasibility, action encodings, I/O and binary equivalence are unresolved.'}
    json_file(out, 'summary.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    summary = generate(CAPTURE.read_bytes(), args.out)
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
