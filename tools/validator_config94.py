#!/usr/bin/env python3
"""Recover selected node 94 validator configuration paths from ELF bytes.

Reads the authenticated capture statically, without executing it or external
programs. Selected FDEs are unwind extents, not a complete function census.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections
from fde_extents import eh_frame_records, uleb

ROOT = TOOLS.parent
TARGET = ROOT / "artifacts/node/94/hl-node"
DIGEST = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
SIZE = 91774280

def verify_identity(data, expected=DIGEST):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('node 94 size or SHA-256 mismatch')


class View:
    def __init__(self, data, secs=None):
        self.data = data
        self.sections = sections(data) if secs is None else secs

    def offset(self, va, size):
        if type(va) is not int or type(size) is not int or va < 0 or size <= 0 or va + size > 1 << 64:
            raise ValueError('invalid virtual range')
        hits = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2 and s['size']
                and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(hits) != 1:
            raise ValueError('virtual range lacks a unique allocated, file-backed section')
        offset = hits[0]['offset'] + va - hits[0]['address']
        if offset < 0 or offset + size > len(self.data):
            raise ValueError('file-backed range is truncated')
        return offset

    def read(self, va, size):
        p = self.offset(va, size)
        return self.data[p:p + size]


def require_bytes(actual, expected, label):
    if actual != expected:
        raise ValueError('byte contract changed: ' + label)


# Restricted x86 byte-pattern reader adapted from the MIT replica-route collector.
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



# Site, branch role, taken meaning, fallthrough meaning. Each row must decode as
# a conditional instruction inside a selected body; targets come from rel bytes.
REQUIRED_RELOCS = {
    0x576e010: (8, 0x54c8cb0), 0x576e040: (8, 0x1344760),
    0x568a3b8: (8, 0x3b8af9),
    0x576e850: (8, 0x4f11400), 0x576e928: (8, 0x577b288),
    0x576e9e8: (8, 0x144a710), 0x576eca0: (8, 0x4ebf970),
    0x576f628: (8, 0x144a600), 0x576f640: (8, 0x4ed97e0),
    0x576f648: (8, 0x4ed9180), 0x57743a0: (8, 0x454ea10),
    0x577b288: (8, 0x164ff00),
}

def parse_relocations(view, wanted):
    names = ('.rela.dyn', '.dynsym', '.dynstr')
    if any(sum(s['name'] == name for s in view.sections) != 1 for name in names):
        raise ValueError('missing or duplicate relocation or symbol section')
    by_name = {s['name']: s for s in view.sections}
    rel, sym, strings = (by_name[n] for n in ('.rela.dyn', '.dynsym', '.dynstr'))
    if (rel['type'] != 4 or sym['type'] != 11 or strings['type'] == 8
            or rel['size'] % 24 or sym['size'] % 24):
        raise ValueError('invalid relocation or symbol section')
    out = {}
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', view.data, off)
        if where not in wanted:
            continue
        if where in out:
            raise ValueError('duplicate selected relocation')
        typ, idx = info & 0xffffffff, info >> 32
        symbol = ''
        if idx:
            if idx * 24 + 24 > sym['size']:
                raise ValueError('symbol index out of bounds')
            noff = struct.unpack_from('<I', view.data, sym['offset'] + idx * 24)[0]
            if noff >= strings['size']:
                raise ValueError('symbol name out of bounds')
            pos = strings['offset'] + noff
            end = view.data.find(b'\0', pos, strings['offset'] + strings['size'])
            if end < 0:
                raise ValueError('unterminated symbol')
            symbol = view.data[pos:end].decode('ascii')
        out[where] = {'slot_va': hex(where), 'record_file_offset': hex(off),
                      'type': typ, 'symbol_index': idx, 'symbol': symbol,
                      'addend': hex(addend), 'record_bytes': view.data[off:off + 24].hex()}
    for address, (typ, addend) in REQUIRED_RELOCS.items():
        r = out.get(address)
        if r is None or r['type'] != typ or int(r['addend'], 16) != addend or r['symbol_index'] != 0:
            raise ValueError('required relocation changed: ' + hex(address))
    return out


def parse_template(raw):
    """Parse only literal-length and default-argument tokens in this template."""
    pos, result, arg = 0, [], 0
    while pos < len(raw):
        tag = raw[pos]
        pos += 1
        if tag == 0:
            if pos != len(raw):
                raise ValueError('trailing template bytes')
            return result
        if tag == 0xc0:
            result.append({'kind': 'argument', 'index': arg})
            arg += 1
        elif 1 <= tag <= 0x7f:
            if pos + tag > len(raw):
                raise ValueError('truncated template literal')
            result.append({'kind': 'literal', 'size': tag, 'hex': raw[pos:pos + tag].hex()})
            pos += tag
        else:
            raise ValueError('unsupported template token')
    raise ValueError('unterminated template')


def immediate(view, address, prefix, size):
    raw = bytes(view.read(address, len(prefix) + size))
    require_bytes(raw[:len(prefix)], prefix, 'immediate opcode')
    return int.from_bytes(raw[len(prefix):], 'little')

def table(path, rows, names):
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=names, delimiter='\t', lineterminator='\n', extrasaction='raise')
        writer.writeheader()
        writer.writerows(rows)



# Selected functions have no selected-start matches in the earlier corpus.
# The filename constructor is prior-owned context and is not in this list.
FUNCTIONS = (
    ("binary_validator", 0x185ba10, 0x185d780),
    ("json_document", 0x1b2cfd0, 0x1b2d11e),
    ("json_first_item", 0x1b66500, 0x1b666a8),
    ("json_ip_item", 0x1b9b9d0, 0x1b9bb48),
    ("json_ip_array", 0x1be6b30, 0x1be6d24),
    ("json_ip_value", 0x1be97a0, 0x1be98db),
    ("json_validator", 0x1cfdbf0, 0x1cfe924),
    ("json_sentry_limit", 0x21c28b0, 0x21c2932),
    ("binary_sentry_limit", 0x21c2940, 0x21c29e1),
    ("json_ip_array_loop", 0x24cec60, 0x24ced77),
    ("configuration_loader", 0x28ea420, 0x28eaae4),
)

# The hashes authenticate the exact byte windows used for the specific
# propositions, including two explicitly labelled prior-caller excerpts.
SPANS = (
    ('path_global_binding', 0x222db47, 0x222db5a, 'cb108fb08fbc1f0cbc7d1db8502e9d6426f2657fe31413aaaa64bc15b98bab13'),
    ('path_format', 0x222db5a, 0x222db86, '683a4c39697ca11ba7e83e141c13afdb38257abeb98d2713cde0efe724f3a5b3'),
    ('path_to_loader', 0x222dbdb, 0x222dbf8, 'c48748330fd6f1360f2c6351a9b198d5007f1a3ad9516b6cd62b52a4cfbaf6e2'),
    ('rmp_entry', 0x185ba27, 0x185ba49, '1161c9639dfd3b7e2517535d180ccea249168d62f346770a93ff09f5bad91072'),
    ('rmp_fresh_marker', 0x185bbcf, 0x185bbf9, 'a48c8f0c6c84fbf89895e01fdd0b9d1e0f0780be172554037e4ea71c86a6e11d'),
    ('rmp_marker_range_a', 0x185bd94, 0x185bdac, '05a5ce8284264df230e492ee30e4b33af75b90379e98f90f2bfaa2d4fd7c902a'),
    ('rmp_marker_range_b', 0x185bebd, 0x185bef8, 'b29a9986c3e8b45194864d4fdc9166aad3835f078f84324501fb1046ad6efbe9'),
    ('rmp_first_value', 0x185bf17, 0x185bf5a, 'bba05994431971a3124d1f95616145c71a76b66779325264f5324720b6470b17'),
    ('rmp_item_count', 0x185c01c, 0x185c02f, 'c1c16269eec84fd3c9ddc86b7d3060df5728d5c9467d918f698ec94c922d7a04'),
    ('rmp_sentry_value', 0x185c207, 0x185c221, 'bf18f851cdeea4095183c1c6a276472bcfe3929d8be275795453ffaaa2739c0e'),
    ('rmp_extra_item', 0x185c392, 0x185c3c8, '486f20f698d75355e2674aa59661830e117aba9b78b000c26701f0ce1c9d8ba7'),
    ('rmp_missing_item', 0x185c491, 0x185c4ae, 'd5edbafb4c8e09ef35529285d97b95f4c051b41e843e6135e3f7b13c269cfef3'),
    ('rmp_sentry_limit', 0x21c294f, 0x21c299c, '2c2ede14968579ea25fbada0ec8593f5703200218a14751a468438efed751d1b'),
    ('rmp_sentry_error', 0x21c29a7, 0x21c29e1, 'cd8c4eabc363cdbf89355f3202a893dee06221732775094ccea149206845f242'),
    ('load_transform_exists', 0x28ea43b, 0x28ea472, 'b0dc1249a1ce87bc4481a3c19bb0874d94d0ab6133401a4c1faa5da95a490dd5'),
    ('component_tag', 0x28ea4ec, 0x28ea51e, '2019eafbd903f57d17c2b29c485ca559b88ed11a1bff3fb3918e40b184b11cb7'),
    ('dot_selection', 0x28ea530, 0x28ea561, '2453929892d1170f59611917efc8a366aaa96b23f6d53e999a2ae6709411a6af'),
    ('rmp_ascii', 0x28ea561, 0x28ea5bf, 'ea9184851875e13e2892910a09ab916a758e0c1acd73453d58db75d7719727bc'),
    ('read_binary', 0x28ea5cf, 0x28ea5da, '9688faeb41f52704ed73a81c23e6b7dfeba6c7d048aabda8064bc25aeadef1ba'),
    ('read_text', 0x28ea6cb, 0x28ea6d6, '89cfd79eda8e2c37470ef85c3befb31c4b2f44b68aa4cfc1857c8dd3dfdda812'),
    ('json_parse', 0x28ea812, 0x28ea827, '6ac7f639a2a5ddc4b91f7d6fd0bf900d2ef180e4a42c77dc122ecf00ad8aed00'),
    ('binary_parse', 0x28ea8fa, 0x28ea911, '95ca894152b0d7ecdf913d61001f0d5251d85ac2def28236407ca30a0e4e80ea'),
    ('publish', 0x28ea9bb, 0x28ea9e1, '6dcdd80cac4dd1b63ac3a63320b3aa6785fbe1add81dcb271c3e53a34fc9752d'),
    ('document_call', 0x1b2d012, 0x1b2d02a, 'a93f6f6c1ccc24bd1016b30622318faf5e4e935e7f20cb5de4c08ea0d04080d8'),
    ('document_trailing', 0x1b2d047, 0x1b2d086, '7579d2b32f5e5c5bdabf70e89fc7fab19775b7cfe2feb44dd6ee3b4f054cdbe0'),
    ('trailing_error', 0x1b2d0ab, 0x1b2d0c8, '3b02421e1977880670984f48cc94b3876e730f0babd6b6991ee0e6256eaf0542'),
    ('object_entry', 0x1cfdc80, 0x1cfdcab, 'c1179e1cfdd8d08d72836d8a2e41ef0f2c041bb6626640ed5ef50bf6e489aa06'),
    ('field_key', 0x1cfddb6, 0x1cfde00, '008eebe311f95cadea2d8b205a11f0ff8ae334d81f700103ae139c01d993aff4'),
    ('field_sentry', 0x1cfde57, 0x1cfde7a, 'e6e354d093279f7e91afcdd94d770c95b8216a9e5acdd5c56ac7cb25e24c62f3'),
    ('unknown_value', 0x1cfded6, 0x1cfdeee, 'f54a876a0bfba1a3cc83e4849f9ea96edcadf5fffdcd84f1d842783cca64aba1'),
    ('sentry_duplicate_test', 0x1cfdf1c, 0x1cfdf2f, 'ee58dae42fbd50388cb64e555a648bc42525364aea8df4baee9c4446679f405e'),
    ('key_value_call', 0x1cfdfac, 0x1cfdfd3, '48c4465702368891ccfc268a8781b3217d732c9ea301dc8bd4ec9c5325013e95'),
    ('sentry_value_call', 0x1cfe028, 0x1cfe05a, '11f31c14053ae2c0e86c5bdd7195df241574094e1f8a88ef40abcdf7bef7cef5'),
    ('first_sequence_call', 0x1cfe070, 0x1cfe0c9, 'a29678e61afea1666f0d513041b079eb77315175676763b53f7cfbda6e0eac82'),
    ('object_required_key', 0x1cfe2ab, 0x1cfe2bd, 'ed444cbfa4c30947b38ab36033a6f209a0b76d2178a7181cb4f4e8981ce62bf8'),
    ('default_vector', 0x1cfe2f4, 0x1cfe320, '03f6a80ff672999a0e383440e66f54da8ee886b478424d1f1fc129c4aaf01fd6'),
    ('sequence_sentry_cap', 0x1cfe3e7, 0x1cfe400, 'bc6d7f6f3a5dc46b0734ac90b2733ab8181c97f13e209346552c6df2de67abc3'),
    ('missing_key', 0x1cfe4ae, 0x1cfe4e5, 'f918e26ca8adcfdf8e48cd8c2a0a85e686c4695d77b7a7cd1b1ee32b98c1ed31'),
    ('too_many', 0x1cfe546, 0x1cfe56e, 'f64e56bd041192321f026ac6247b578f4d9038853a202288d463176db31a6149'),
    ('duplicate_key', 0x1cfe678, 0x1cfe6b4, '24f4eae16cf8d36d10472b87bb01f2eabd6ccd020179a6fbead6511b3e50a8b3'),
    ('duplicate_sentry', 0x1cfe6b9, 0x1cfe6f5, '142b6f4be91c66f4ec1f4dcd66c476c4c899c824b435a9edc7d889d1f1b59852'),
    ('object_publish', 0x1cfe78f, 0x1cfe7c9, '7a1967779b78b7919b744e7c28e09aa8a275cf9ba22dfc2792ac87f5a70845e4'),
    ('vector_limit', 0x21c28ba, 0x21c2907, '2f521337a387f4c8aa336fafaa9ed31992d58b7f144026d22a72a756e77dda98'),
    ('vector_limit_error', 0x21c2907, 0x21c2932, 'b3b080839ccda10f9fc69d75ec1e646e12c6d2f2726481a540574ebbd73d6d3d'),
    ('vector_nested', 0x1be6bae, 0x1be6c2e, '39efaeb065a496f8b017abdf2e9191df19e762ee8a1a03c91f6a6031d0eef874'),
    ('items_loop', 0x24ceca6, 0x24cecf1, '78510494d7743ae8ca57fd358c7be0aff79e4ed1739102e616f6ed9c2a6886a2'),
    ('item_error_cleanup', 0x24cecf1, 0x24ced29, 'd962852ebc48a091ad554117dc96a5eecbed17af4e69255d2bed56e349bf50fb'),
    ('item_success', 0x24ced29, 0x24ced3f, '3e31a5ed19e0e904580101e77a33794ed1c86f425f6e739161cd3fc09137a109'),
    ('item_addr_type', 0x1b9bad8, 0x1b9bb1f, '0cbfce39a48ee092c792e010dc74fdb077c16375e3de615e13d53173dc9d3a96'),
    ('ip_len_parse', 0x1be985a, 0x1be989b, '79460e7fe426799a34a46af3b96f8d3834b241dddb45c18edffb4dbb44c7a982'),
    ('ip_bad', 0x1be989b, 0x1be98ce, '07fdd8df92e6cf247d8b95a66bc39d6db69af6fd9df31346307525e06529e4a8'),
    ('first_item_key', 0x1b665fb, 0x1b6663c, '3a34f3edd2cd3cbeeca4375f068b997bbc5d5427e6cb869fba19a3f483bb4ec0'),
)

# Conditional transfers: label, source VA, required target, taken interpretation.
BRANCHES = (
    ('binary_read_marker_signed', 0x185bbf3, 0x185bd94, 'fresh marker has its high bit set'),
    ('binary_marker_above_df', 0x185bd99, 0x185ba49, 'fresh marker is above 0xdf'),
    ('binary_marker_at_least_90', 0x185bda1, 0x185bebd, 'fresh marker is at least 0x90'),
    ('binary_marker_at_least_a0', 0x185bebf, 0x185c4db, 'fresh marker is at least 0xa0'),
    ('binary_empty_sequence', 0x185bef2, 0x185c491, 'sequence has no first value'),
    ('binary_key_error', 0x185bf54, 0x185c02f, 'first value result tag is not 9'),
    ('binary_second_value', 0x185c01f, 0x185c1fc, 'sequence count differs from 1'),
    ('binary_sentry_error', 0x185c21b, 0x185c44b, 'sentry result tag is not 9'),
    ('binary_no_extra_value', 0x185c394, 0x185c3c8, 'remaining sequence count is zero after the selected or default route'),
    ('binary_vector_reader_error', 0x21c295b, 0x21c298b, 'vector result tag is not 9'),
    ('binary_sentry_too_many', 0x21c2970, 0x21c29a7, 'parsed element count is at least 3'),
    ('missing_file', 0x28ea462, 0x28ea472, 'existence predicate returned zero'),
    ('component_not_normal', 0x28ea502, 0x28ea6bb, 'component result tag differs from 9'),
    ('parent_component', 0x28ea518, 0x28ea6bb, 'component is exactly two dots'),
    ('no_dot', 0x28ea537, 0x28ea6bb, 'backward scan exhausted'),
    ('leading_dot', 0x28ea54e, 0x28ea6bb, 'last dot has no prefix'),
    ('extension_length', 0x28ea55b, 0x28ea6bb, 'suffix is not three bytes'),
    ('extension_first', 0x28ea57c, 0x28ea6bb, 'folded first suffix byte differs'),
    ('extension_second', 0x28ea59d, 0x28ea6bb, 'folded second suffix byte differs'),
    ('extension_third', 0x28ea5b9, 0x28ea6bb, 'folded third suffix byte differs'),
    ('binary_read_success', 0x28ea5ef, 0x28ea8c6, 'binary reader result is not the minimum sentinel'),
    ('text_read_success', 0x28ea6eb, 0x28ea7e7, 'text reader result is not the minimum sentinel'),
    ('json_success', 0x28ea821, 0x28ea9bb, 'JSON result is not the minimum sentinel'),
    ('binary_success', 0x28ea90b, 0x28ea9bb, 'binary result is not the minimum sentinel'),
    ('document_visitor_error', 0x1b2d028, 0x1b2d086, 'visitor returned the minimum sentinel'),
    ('document_eof', 0x1b2d037, 0x1b2d086, 'cursor is at or beyond input end'),
    ('trailing_above_space', 0x1b2d069, 0x1b2d0ab, 'trailing byte exceeds space'),
    ('trailing_not_space', 0x1b2d06f, 0x1b2d0ab, 'trailing byte is not in the whitespace mask'),
    ('sequence_entry', 0x1cfdc83, 0x1cfe070, 'first significant byte is an open bracket'),
    ('invalid_entry', 0x1cfdc8c, 0x1cfe5ba, 'first significant byte is not an open brace'),
    ('sequence_first_result', 0x1cfe0bd, 0x1cfe13d, 'first-item reader result tag is not 1'),
    ('sequence_first_missing', 0x1cfe177, 0x1cfe5db, 'first-item presence bit is clear'),
    ('sequence_array_success', 0x1cfe375, 0x1cfe3e7, 'sentry array reader returned a non-sentinel result'),
    ('sequence_sentry_too_many', 0x1cfe3f0, 0x1cfe546, 'parsed sequence element count is at least 3'),
    ('sentry_length', 0x1cfddbf, 0x1cfde57, 'field length is 10'),
    ('not_key_length', 0x1cfddcc, 0x1cfde7a, 'remaining field length is not 3'),
    ('not_key_bytes', 0x1cfddef, 0x1cfde7a, 'three-byte field is not key'),
    ('duplicate_key', 0x1cfddfa, 0x1cfe678, 'key was already parsed'),
    ('sentry_bytes', 0x1cfde74, 0x1cfdf1c, 'ten-byte field equals sentry_ips'),
    ('duplicate_sentry', 0x1cfdf29, 0x1cfe6b9, 'sentry result is no longer unset'),
    ('key_value_error', 0x1cfdfcd, 0x1cfe5d3, 'key value reader returned an error'),
    ('sentry_value_error', 0x1cfe054, 0x1cfe705, 'sentry value reader returned an error'),
    ('key_required', 0x1cfe2b7, 0x1cfe4ae, 'closing object has no key value'),
    ('sentry_reader_success', 0x21c28db, 0x21c28e6, 'array reader returned a non-sentinel length'),
    ('sentry_too_many', 0x21c28ef, 0x21c2907, 'parsed element count is at least 3'),
    ('element_error', 0x24cecd0, 0x24cecf1, 'element iterator returned an error'),
    ('elements_done', 0x24cecd7, 0x24ced29, 'element iterator returned end'),
    ('capacity_available', 0x24cece7, 0x24cecb0, 'length differs from capacity'),
    ('address_too_long', 0x1be9863, 0x1be989b, 'decoded string length exceeds 15'),
    ('address_trailing_bytes', 0x1be987f, 0x1be989b, 'address parser did not consume the slice'),
    ('address_parse_failure', 0x1be9883, 0x1be989b, 'address parser low success bit is clear'),
)

# Intra-FDE graph checks only. Calls are assumed to return, conditional edges
# are both feasible and register-indirect jumps are deliberately not followed.
# A False value means no path in that restricted graph, not an execution proof.
CFG_QUERIES = (
    ('loader_missing', 0x28ea420, 0x28ea420, 0x28ea472, (), True),
    ('loader_text_parse', 0x28ea420, 0x28ea420, 0x28ea817, (), True),
    ('loader_binary_parse', 0x28ea420, 0x28ea420, 0x28ea901, (), True),
    ('text_without_reader', 0x28ea420, 0x28ea420, 0x28ea817, (0x28ea6d0,), False),
    ('binary_without_reader', 0x28ea420, 0x28ea420, 0x28ea901, (0x28ea5d4,), False),
    ('document_visitor', 0x1b2cfd0, 0x1b2cfd0, 0x1b2d01a, (), True),
    ('document_trailing_error', 0x1b2cfd0, 0x1b2d02a, 0x1b2d0ab, (), True),
    ('trailing_without_checks', 0x1b2cfd0, 0x1b2d02a, 0x1b2d0ab, (0x1b2d069, 0x1b2d06f), False),
    ('object_duplicate_key', 0x1cfdbf0, 0x1cfdbf0, 0x1cfe678, (), True),
    ('object_duplicate_sentry', 0x1cfdbf0, 0x1cfdbf0, 0x1cfe6b9, (), True),
    ('object_missing_key', 0x1cfdbf0, 0x1cfdbf0, 0x1cfe4ae, (), True),
    ('object_sentry_call', 0x1cfdbf0, 0x1cfdbf0, 0x1cfe038, (), True),
    ('sequence_sentry_call', 0x1cfdbf0, 0x1cfdbf0, 0x1cfe359, (), True),
    ('sequence_sentry_error', 0x1cfdbf0, 0x1cfe359, 0x1cfe546, (), True),
    ('sequence_error_without_cap', 0x1cfdbf0, 0x1cfe359, 0x1cfe546, (0x1cfe3f0,), False),
    ('json_object_sentry_error', 0x21c28b0, 0x21c28b0, 0x21c2907, (), True),
    ('binary_sentry_error', 0x21c2940, 0x21c2940, 0x21c29a7, (), True),
    ('fresh_binary_sentry', 0x185ba10, 0x185bbcf, 0x185c20f, (), True),
    ('fresh_binary_missing', 0x185ba10, 0x185bbcf, 0x185c491, (), True),
    ('fresh_binary_extra', 0x185ba10, 0x185bbcf, 0x185c3a1, (), True),
    ('fresh_binary_without_key', 0x185ba10, 0x185bbcf, 0x185c20f, (0x185bf48,), False),
    ('array_iteration', 0x1be6b30, 0x1be6b30, 0x1be6bea, (), True),
    ('array_item', 0x24cec60, 0x24cec60, 0x24cecc6, (), True),
    ('address_parse', 0x1be97a0, 0x1be97a0, 0x1be9874, (), True),
)


def checked_cfg(grouped):
    rows = []
    for label, function, source, destination, forbidden, expected in CFG_QUERIES:
        if function not in grouped:
            raise ValueError('CFG function is not selected: ' + hex(function))
        actual = reachable(grouped[function], source, destination, forbidden)
        if actual != expected:
            raise ValueError('restricted CFG result changed: ' + label)
        rows.append({'label': label, 'function_va': hex(function), 'source_va': hex(source),
                     'destination_va': hex(destination),
                     'forbidden_va': ','.join(hex(x) for x in forbidden),
                     'reachable': int(actual)})
    return rows


def locate_instruction(decoded, address, opcode=None, target=None):
    row = decoded.get(address)
    if row is None:
        raise ValueError('missing instruction boundary: ' + hex(address))
    if opcode is not None and not row['bytes'].startswith(bytes.fromhex(opcode)):
        raise ValueError('unexpected instruction encoding: ' + hex(address))
    if target is not None and row['target'] != target:
        raise ValueError('unexpected instruction target: ' + hex(address))
    return row


def checked_spans(view, decoded):
    records = []
    for label, begin, end, digest in SPANS:
        if begin >= end:
            raise ValueError('invalid witness extent')
        if not label.startswith('path_'):
            if begin not in decoded or not any(r['end'] == end for r in decoded.values()):
                raise ValueError('witness does not end at instruction boundaries: ' + label)
        raw = bytes(view.read(begin, end - begin))
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('witness bytes changed: ' + label)
        records.append({'label': label, 'va': hex(begin), 'end_va': hex(end),
                        'file_offset': hex(view.offset(begin, len(raw))),
                        'bytes': raw.hex(), 'sha256': digest,
                        'scope': 'prior caller excerpt' if label.startswith('path_') else 'selected body'})
    return records


def field_spec(view, decoded):
    """Extract the two exact post-unescape field comparisons and limits."""
    def imm8(address, prefix):
        raw = bytes(view.read(address, len(prefix) + 1))
        if raw[:len(prefix)] != prefix:
            raise ValueError('unexpected immediate encoding')
        return raw[-1]
    key_len = imm8(0x1cfddc5, b'\x48\x83\xf8')
    sentry_len = imm8(0x1cfddbb, b'\x48\x83\xf8')
    key_parts = ((0x1cfddd7, '663305', 2), (0x1cfdde3, '320d', 1))
    sentry_parts = ((0x1cfde5b, '483305', 8), (0x1cfde67, '66330d', 2))
    def joined(parts):
        chunks = []
        for address, opcode, size in parts:
            ins = locate_instruction(decoded, address, opcode)
            if not ins['rip_relative'] or ins['target'] is None:
                raise ValueError('field comparison has no RIP target')
            chunks.append(bytes(view.read(ins['target'], size)))
        return b''.join(chunks)
    key, sentry = joined(key_parts), joined(sentry_parts)
    cap = imm8(0x21c28eb, b'\x48\x83\xf8')
    sequence_cap = imm8(0x1cfe3ec, b'\x48\x83\xfa')
    ip_max = imm8(0x1be985f, b'\x48\x83\xf9')
    binary_cap = imm8(0x21c296c, b'\x48\x83\xfa')
    mask_ins = locate_instruction(decoded, 0x1b2d052, '48be')
    mask = int.from_bytes(mask_ins['bytes'][2:], 'little')
    if key != b'key' or sentry != b'sentry_ips' or (key_len, sentry_len) != (len(key), len(sentry)):
        raise ValueError('field comparison differs from retained interpretation')
    if cap != 3 or sequence_cap != cap or binary_cap != cap or ip_max != 15 or mask != 0x100002600:
        raise ValueError('comparison limit differs from retained interpretation')
    return {'key': key, 'sentry': sentry, 'cap': cap, 'sequence_cap': sequence_cap,
            'binary_cap': binary_cap, 'ip_max': ip_max, 'whitespace_mask': mask}


def classify_field(value, spec):
    if value == spec['key']:
        return 'key'
    if value == spec['sentry']:
        return 'sentry_ips'
    return 'unknown'


def model_field_events(fields, spec):
    """Conditional model of duplicate and missing-field routing, not JSON execution."""
    seen = set()
    for value in fields:
        which = classify_field(value, spec)
        if which == 'unknown':
            continue
        if which in seen:
            return 'duplicate_' + which
        seen.add(which)
    return 'missing_key' if 'key' not in seen else 'selected'


def model_sentry_count(count, spec):
    if type(count) is not int or count < 0:
        raise ValueError('count must be a nonnegative integer')
    return 'accepted_by_count_gate' if count < spec['cap'] else 'too_many'


def model_binary_array_marker(marker, loader):
    """Route fresh markers, assuming normal nested returns and sufficient input."""
    if type(marker) is not int or not 0 <= marker <= 255:
        raise ValueError('marker must be a byte')
    if not loader['binary_array_lower'] <= marker < loader['binary_array_upper']:
        return 'other_marker'
    count = marker & loader['binary_array_mask']
    if count == 0:
        return 'missing_first'
    if count == 1:
        return 'default_sentry'
    if count == 2:
        return 'read_sentry'
    return 'extra_sequence_values'


def model_extension(component, tag, extension):
    """Conditional model after the external component reader has returned."""
    if not isinstance(component, bytes) or type(tag) is not int or not 0 <= tag <= 255:
        raise ValueError('component must be bytes and tag a byte')
    if tag != 9 or component == b'..':
        return 'text'
    dot = component.rfind(b'.')
    if dot <= 0 or len(component) - dot != len(extension) + 1:
        return 'text'
    suffix = bytes(c + 32 if 65 <= c <= 90 else c for c in component[dot + 1:])
    return 'binary' if suffix == extension else 'text'


def load_spec(view, decoded):
    # These targets are independently recomputed from their instruction bytes.
    locate_instruction(decoded, 0x28ea43e, 'ff15', 0x576f628)
    locate_instruction(decoded, 0x28ea45a, 'ff15', 0x576e9e8)
    locate_instruction(decoded, 0x28ea4ec, 'ff15', 0x576e850)
    locate_instruction(decoded, 0x28ea5d4, 'ff15', 0x576f640)
    locate_instruction(decoded, 0x28ea6d0, 'ff15', 0x576f648)
    locate_instruction(decoded, 0x28ea817, 'e8', 0x1b2cfd0)
    locate_instruction(decoded, 0x1b2d01a, 'e8', 0x1cfdbf0)
    locate_instruction(decoded, 0x1cfe038, 'e8', 0x21c28b0)
    locate_instruction(decoded, 0x21c28c7, 'e8', 0x1be6b30)
    locate_instruction(decoded, 0x1be6bea, 'e8', 0x24cec60)
    locate_instruction(decoded, 0x24cecc6, 'e8', 0x1b9b9d0)
    locate_instruction(decoded, 0x1b9bae9, 'e8', 0x1be97a0)
    locate_instruction(decoded, 0x1cfe0b3, 'e8', 0x1b66500)
    locate_instruction(decoded, 0x1cfe359, 'e8', 0x1be6b30)
    locate_instruction(decoded, 0x28ea901, 'e8', 0x185ba10)
    locate_instruction(decoded, 0x185bf48, 'e8', 0x190f5b0)
    locate_instruction(decoded, 0x185c20f, 'e8', 0x21c2940)
    locate_instruction(decoded, 0x21c2951, 'e8', 0x19ffc40)
    for address, opcode, target in (
        (0x28ea483, '488d35', 0x1f751c), (0x28ea615, '488d05', 0x1f644e),
        (0x28ea711, '488d05', 0x1de93b), (0x28ea847, '488d05', 0x1fd0ce),
        (0x28ea93c, '488d05', 0x1f3c9c), (0x1cfe4d4, '488d3d', 0x1df8f3),
        (0x1cfe6a3, '488d3d', 0x1e0fd5), (0x1cfe6e4, '488d3d', 0x1e0fd5),
        (0x1cfe5db, '488d35', 0x568a3b8),
        (0x21c2918, '488d3d', 0x70693e), (0x1cfe55d, '488d3d', 0x70693e),
        (0x21c29a7, '488d35', 0x70693e),
    ):
        locate_instruction(decoded, address, opcode, target)
    table_base = locate_instruction(decoded, 0x185ba38, '488d0d', 0x307bd4)['target']
    slot = bytes(view.read(table_base + 4, 4))
    if table_base + int.from_bytes(slot, 'little', signed=True) != 0x185bbcf:
        raise ValueError('fresh-marker dispatch slot changed')
    locate_instruction(decoded, 0x185bd9f, '3c')
    locate_instruction(decoded, 0x185bebd, '3c')
    lower = immediate(view, 0x185bd9f, b'\x3c', 1)
    upper = immediate(view, 0x185bebd, b'\x3c', 1)
    mask = immediate(view, 0x185bec5, b'\x24', 1)
    if (lower, upper, mask) != (0x90, 0xa0, 0x0f):
        raise ValueError('fixed-array marker bounds changed')
    # Extension bytes are read from each comparison immediate.
    ext = bytes((view.read(0x28ea578, 4)[3], view.read(0x28ea599, 4)[3],
                 view.read(0x28ea5b6, 3)[2]))
    if ext != b'rmp':
        raise ValueError('extension comparisons changed')
    # A complete compact format template, including token and terminator.
    prefix = bytes(view.read(0x1f1371, 2))
    if prefix[0] != 0xc0:
        raise ValueError('unsupported configuration template')
    raw = bytes(view.read(0x1f1371, prefix[1] + 3))
    parts = parse_template(raw)
    expected_suffix = bytes.fromhex(
        '2f68797065726c69717569645f646174612f6e6f64655f636f6e6669672e6a736f6e')
    if parts != [{'kind': 'argument', 'index': 0},
                 {'kind': 'literal', 'size': len(expected_suffix),
                  'hex': expected_suffix.hex()}]:
        raise ValueError('configuration template changed')
    # Decode the older caller's two instruction starts without selecting its FDE.
    global_load = decode_one(view.read(0x222db47, 7), 0, 0x222db47)
    path_lea = decode_one(view.read(0x222db6f, 7), 0, 0x222db6f)
    prior_call = decode_one(view.read(0x222dbf3, 5), 0, 0x222dbf3)
    if (global_load['target'] != 0x576e928 or path_lea['target'] != 0x1f1371
            or prior_call['target'] != 0x28ea420):
        raise ValueError('caller handoff changed')
    return {'extension': ext, 'template': raw, 'template_parts': parts,
            'binary_array_lower': lower, 'binary_array_upper': upper, 'binary_array_mask': mask,
            'fresh_marker_table_base': table_base, 'fresh_marker_slot': slot}


def data_records(view, spec, loader):
    entries = (
        ('node_config_template', 0x1f1371, loader['template']),
        ('key_compare', 0x3d2871, spec['key']),
        ('sentry_compare', 0x3d2874, spec['sentry']),
        ('key_diagnostic', 0x3b8aec, spec['key']),
        ('sentry_diagnostic', 0x3b8aef, spec['sentry']),
        ('validator_type', 0x3b8af9, b'struct ValidatorConfig with 2 elements'),
        ('validator_type_descriptor', 0x568a3b8, b'\x00' * 8 + struct.pack('<Q', 38)),
        ('sentry_limit_message', 0x70693e, b'SentryIps can only have at most 2 IPs'),
        ('address_expectation', 0x3f6ac6, b'IPv4 address'),
        ('fresh_marker_slot', 0x307bd8, loader['fresh_marker_slot']),
        ('missing_file_template', 0x1f751c, b'\x0emissing file: \xc0\x00'),
        ('binary_read_template', 0x1f644e, b'\x06read: \xc0\x00'),
        ('text_read_template', 0x1de93b, b'\x10read_to_string: \xc0\x00'),
        ('json_parse_template', 0x1fd0ce, b'\x16serde_json::from_str: \xc0\x00'),
        ('binary_parse_template', 0x1f3c9c, b'\x17rmp_serde::from_slice: \xc0\x00'),
        ('missing_field_template', 0x1df8f3, b'\x0fmissing field `\xc0\x01`\x00'),
        ('duplicate_field_template', 0x1e0fd5, b'\x11duplicate field `\xc0\x01`\x00'),
    )
    rows = []
    for label, va, expected in entries:
        raw = bytes(view.read(va, len(expected)))
        if raw != expected:
            raise ValueError('data anchor changed: ' + label)
        rows.append({'label': label, 'va': hex(va), 'file_offset': hex(view.offset(va, len(raw))),
                     'length': len(raw), 'bytes': raw.hex(),
                     'text': raw.decode('ascii') if all(32 <= b < 127 for b in raw) else ''})
    return rows


def collect(data):
    verify_identity(data)
    view = View(data)
    _, fdes = eh_frame_records(data, view.sections)
    by_start = {}
    for fde in fdes:
        if fde['start'] in by_start:
            raise ValueError('duplicate FDE start')
        by_start[fde['start']] = fde
    decoded, grouped, functions = {}, {}, []
    headers, lsda_rows = [], []
    for role, begin, end in FUNCTIONS:
        fde = by_start.get(begin)
        if fde is None or fde['end'] != end:
            raise ValueError('selected FDE extent changed: ' + role)
        body = bytes(view.read(begin, end - begin))
        parts = decode_body(body, begin)
        grouped[begin] = parts
        for row in parts:
            if row['va'] in decoded:
                raise ValueError('overlapping selected instruction')
            row['role'] = role
            decoded[row['va']] = row
        functions.append({'role': role, 'start_va': hex(begin), 'end_va': hex(end),
                          'file_offset': hex(view.offset(begin, end - begin)),
                          'bytes': end - begin, 'fde_va': hex(fde['fde']),
                          'cie_va': hex(fde['cie']),
                          'lsda_va': hex(fde['lsda']) if fde['lsda'] else '',
                          'instruction_count': len(parts),
                          'sha256': hashlib.sha256(body).hexdigest()})
        if fde['lsda'] is not None:
            head, rows = parse_lsda(view, begin, end, fde['lsda'])
            headers.append(head)
            lsda_rows.extend(rows)
    spans = checked_spans(view, decoded)
    cfg = checked_cfg(grouped)
    spec = field_spec(view, decoded)
    loader = load_spec(view, decoded)
    data_rows = data_records(view, spec, loader)

    branches = []
    for label, site, expected, taken in BRANCHES:
        ins = locate_instruction(decoded, site, target=expected)
        if ins['kind'] != 'conditional':
            raise ValueError('selected transfer is not conditional: ' + label)
        branches.append({'label': label, 'site_va': hex(site),
                         'file_offset': hex(view.offset(site, len(ins['bytes']))),
                         'bytes': ins['bytes'].hex(), 'taken_va': hex(ins['target']),
                         'fallthrough_va': hex(ins['end']), 'taken_condition': taken})
    needed = set(REQUIRED_RELOCS)
    needed.update(r['target'] for r in decoded.values()
                  if r['rip_relative'] and r['kind'] in ('indirect_call', 'indirect_jump')
                  and r['target'] is not None)
    relocations = parse_relocations(view, needed)
    selected = {a for _, a, _ in FUNCTIONS}
    instructions, transfers = [], []
    for addr in sorted(decoded):
        row = decoded[addr]
        inst = {'function': row['role'], 'va': hex(addr),
                'file_offset': hex(view.offset(addr, len(row['bytes']))),
                'size': len(row['bytes']), 'bytes': row['bytes'].hex(),
                'kind': row['kind'], 'target_va': hex(row['target']) if row['target'] is not None else ''}
        instructions.append(inst)
        if row['kind'] in ('call', 'jump', 'conditional', 'indirect_call', 'indirect_jump'):
            target = row['target']
            binding = 'dynamic-register' if target is None else ('selected' if target in selected else 'boundary')
            if row['rip_relative'] and target in relocations:
                binding = 'relocated-slot'
            transfers.append({**inst, 'binding': binding})

    fields = [
        {'field': spec['key'].decode('ascii'), 'length': len(spec['key']),
         'comparison_bytes': spec['key'].hex(), 'length_site': hex(0x1cfddc5),
         'first_data_va': hex(decoded[0x1cfddd7]['target']), 'second_data_va': hex(decoded[0x1cfdde3]['target']),
         'duplicate_branch': hex(0x1cfddfa), 'absence': 'missing-field path'},
        {'field': spec['sentry'].decode('ascii'), 'length': len(spec['sentry']),
         'comparison_bytes': spec['sentry'].hex(), 'length_site': hex(0x1cfddbb),
         'first_data_va': hex(decoded[0x1cfde5b]['target']), 'second_data_va': hex(decoded[0x1cfde67]['target']),
         'duplicate_branch': hex(0x1cfdf29), 'absence': 'empty vector triple'},
    ]
    field_cases = []
    for label, value in (('key', spec['key']), ('sentry_ips', spec['sentry'])):
        field_cases.append({'base': label, 'position': 'exact', 'bit': '', 'input_hex': value.hex(),
                            'classification': classify_field(value, spec)})
        for i in range(len(value)):
            for bit in range(8):
                changed = bytearray(value)
                changed[i] ^= 1 << bit
                field_cases.append({'base': label, 'position': i, 'bit': bit,
                                    'input_hex': changed.hex(),
                                    'classification': classify_field(bytes(changed), spec)})
    # All examples are explicitly model inputs, derived from the extracted suffix.
    ext = loader['extension']
    examples = ((b'x.' + ext, 9), (b'x.' + ext.upper(), 9), (b'.' + ext, 9),
                (b'x.' + ext + b'x', 9), (b'x.' + ext[:-1], 9),
                (b'x.y.' + ext, 9), (b'..', 9), (b'x.' + ext, 8))
    extension_cases = [{'component_hex': component.hex(), 'tag': tag,
                        'route': model_extension(component, tag, ext)}
                       for component, tag in examples]
    count_cases = [{'count': n, 'route': model_sentry_count(n, spec)}
                   for n in range(spec['cap'] + 3)]
    marker_cases = [{'marker': hex(n), 'route': model_binary_array_marker(n, loader)}
                    for n in range(loader['binary_array_lower'] - 1, loader['binary_array_upper'] + 1)]
    whitespaces = [n for n in range(33) if (spec['whitespace_mask'] >> n) & 1]
    summary = {
        'artifact': 'artifacts/node/94/hl-node',
        'artifact_sha256': DIGEST,
        'coordinate_system': 'linked ELF virtual address; file offsets are separate',
        'selected_fde_count': len(functions),
        'selected_fde_bytes': sum(x['bytes'] for x in functions),
        'selected_instruction_count': len(instructions),
        'selected_transfer_count': len(transfers),
        'selected_branch_witness_count': len(branches),
        'restricted_cfg_query_count': len(cfg),
        'byte_contract_count': len(spans),
        'selected_relocation_count': len(relocations),
        'lsda_headers': len(headers), 'lsda_callsite_rows': len(lsda_rows),
        'field_count': len(fields), 'field_mutation_probes': len(field_cases) - len(fields),
        'extracted_rmp_extension_hex': loader['extension'].hex(),
        'post_parse_sentry_count_reject_at': spec['cap'],
        'sequence_post_parse_sentry_count_reject_at': spec['sequence_cap'],
        'binary_post_parse_sentry_count_reject_at': spec['binary_cap'],
        'binary_array_marker_bounds': [hex(loader['binary_array_lower']), hex(loader['binary_array_upper'])],
        'address_text_maximum_bytes': spec['ip_max'],
        'trailing_whitespace_bytes': whitespaces,
        'limitations': 'Selected static extents and conditional models; external helpers, exact runtime input, '
                       'all MessagePack arms and captured execution are not established.',
    }
    return {'functions.tsv': functions, 'instructions.tsv': instructions,
            'transfers.tsv': transfers, 'contracts.tsv': spans, 'branches.tsv': branches, 'cfg.tsv': cfg,
            'relocations.tsv': [relocations[k] for k in sorted(relocations)],
            'lsda-headers.tsv': headers, 'lsda-sites.tsv': lsda_rows,
            'fields.tsv': fields, 'field-cases.tsv': field_cases,
            'extension-cases.tsv': extension_cases, 'count-cases.tsv': count_cases,
            'binary-marker-cases.tsv': marker_cases,
            'data.tsv': data_rows, 'summary.json': summary}


HEADERS = {
    'functions.tsv': ('role', 'start_va', 'end_va', 'file_offset', 'bytes', 'fde_va', 'cie_va', 'lsda_va', 'instruction_count', 'sha256'),
    'instructions.tsv': ('function', 'va', 'file_offset', 'size', 'bytes', 'kind', 'target_va'),
    'transfers.tsv': ('function', 'va', 'file_offset', 'size', 'bytes', 'kind', 'target_va', 'binding'),
    'contracts.tsv': ('label', 'va', 'end_va', 'file_offset', 'bytes', 'sha256', 'scope'),
    'branches.tsv': ('label', 'site_va', 'file_offset', 'bytes', 'taken_va', 'fallthrough_va', 'taken_condition'),
    'cfg.tsv': ('label', 'function_va', 'source_va', 'destination_va', 'forbidden_va', 'reachable'),
    'relocations.tsv': ('slot_va', 'record_file_offset', 'type', 'symbol_index', 'symbol', 'addend', 'record_bytes'),
    'lsda-headers.tsv': ('function', 'lsda_va', 'header_file_offset', 'lpstart_encoding', 'type_encoding', 'callsite_encoding', 'callsite_file_offset', 'callsite_size', 'entries'),
    'lsda-sites.tsv': ('function', 'lsda_va', 'entry_file_offset', 'start_va', 'end_va', 'landing_va', 'action_index'),
    'fields.tsv': ('field', 'length', 'comparison_bytes', 'length_site', 'first_data_va', 'second_data_va', 'duplicate_branch', 'absence'),
    'field-cases.tsv': ('base', 'position', 'bit', 'input_hex', 'classification'),
    'extension-cases.tsv': ('component_hex', 'tag', 'route'),
    'count-cases.tsv': ('count', 'route'),
    'binary-marker-cases.tsv': ('marker', 'route'),
    'data.tsv': ('label', 'va', 'file_offset', 'length', 'bytes', 'text'),
}


def generate(data, out):
    records = collect(data)
    out.mkdir(parents=True, exist_ok=True)
    for name, rows in records.items():
        path = out / name
        if name.endswith('.json'):
            path.write_text(json.dumps(rows, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        else:
            table(path, rows, HEADERS[name])
    return records['summary.json']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = generate(TARGET.read_bytes(), args.out)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as error:
        print('validator_config94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
