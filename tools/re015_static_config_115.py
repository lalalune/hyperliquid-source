#!/usr/bin/env python3
"""Collect bounded static configuration evidence from the authenticated node 115 ELF.

Only fixed, analyst-selected instruction forms are decoded. This is not a general
x86 decoder, a program emulator, or a complete control-flow or xref census.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents

TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/115/hl-node'

# Names describe local evidence roles, not verified source function names.
FUNCTIONS = {
    'aws_path': 0x1772fa0,
    'value_reader': 0x1773070,
    'missing_name_reader': 0x1773fd0,
    'serde_name_classifier': 0x1774100,
    'name_formatter': 0x1774e60,
    'plain_name_classifier': 0x1775500,
    'document_end_check': 0x1775dd0,
    'quoted_name_reader': 0x1777080,
    'document_reader': 0x17771b0,
    'directory_selector': 0x17780c0,
    'create_error': 0x1778270,
    'home_string': 0x17782e0,
    'static_reader': 0x17783e0,
    'config_initializer': 0x17785f0,
    'error_drop': 0x1778770,
    'name_trim': 0x1778840,
    'publication_callback_a': 0x5944f60,
    'publication_callback_b': 0x5940470,
    'file_read_helper': 0x5ca4940,
    'open_helper': 0x5c97060,
    'read_helper': 0x5c75580,
    'home_env_or_account': 0x5c9abb0,
    'env_lookup': 0x5c81950,
}

# Selection was made from independently inspected instruction starts. Every
# transfer below is re-decoded from the binary; indirect slots use RELATIVE
# relocations rather than their zero-filled pre-relocation file contents.
EDGES = [
    ('config_initializer','home_string',0x1778608,0x17782e0),
    ('config_initializer','directory_selector',0x1778621,0x17780c0),
    ('config_initializer','metadata_boundary',0x1778636,0x5c9c810),
    ('config_initializer','formatter_boundary',0x177867d,0x141e3a0),
    ('config_initializer','static_reader',0x1778698,0x17783e0),
    ('config_initializer','error_drop',0x17786eb,0x1778770),
    ('config_initializer','panic_boundary',0x1778714,None),
    ('directory_selector','formatter_boundary',0x1778102,0x141e3a0),
    ('directory_selector','metadata_boundary',0x1778122,0x5c9c810),
    ('directory_selector','error_drop',0x1778134,0x1778770),
    ('directory_selector','formatter_boundary',0x1778173,0x141e3a0),
    ('directory_selector','metadata_boundary',0x177819c,0x5c9c810),
    ('directory_selector','error_drop',0x17781ae,0x1778770),
    ('directory_selector','create_boundary',0x17781dd,0x5c8f4c0),
    ('directory_selector','create_error',0x1778227,0x1778270),
    ('create_error','panic_boundary',0x17782b4,None),
    ('static_reader','formatter_boundary',0x177841f,0x141e3a0),
    ('static_reader','file_read_boundary',0x177843c,0x5ca4940),
    ('static_reader','error_drop',0x1778457,0x1778770),
    ('static_reader','document_end_check',0x17784ae,0x1775dd0),
    ('document_end_check','document_reader',0x1775e19,0x17771b0),
    ('document_end_check','error_boundary',0x1775ead,None),
    ('document_reader','string_decode_boundary',0x1777341,None),
    ('document_reader','value_reader',0x1777927,0x1773070),
    ('document_reader','missing_name_reader_array',0x1777a21,0x1773fd0),
    ('document_reader','missing_name_reader_object',0x1777a3b,0x1773fd0),
    ('value_reader','quoted_name_reader',0x17730ef,0x1777080),
    ('quoted_name_reader','string_decode_boundary',0x1777124,None),
    ('quoted_name_reader','serde_name_classifier',0x1777149,0x1774100),
    ('missing_name_reader','aws_path',0x1773fde,0x1772fa0),
    ('missing_name_reader','file_read_boundary',0x1773ff6,0x5ca4940),
    ('missing_name_reader','name_trim',0x177402b,0x1778840),
    ('missing_name_reader','plain_name_classifier',0x1774036,0x1775500),
    ('missing_name_reader','read_failure_panic',0x177408a,None),
    ('missing_name_reader','name_failure_panic',0x17740b1,None),
    ('aws_path','home_string',0x1772faf,0x17782e0),
    ('aws_path','directory_selector',0x1772fca,0x17780c0),
    ('aws_path','formatter_boundary',0x1772ff0,0x141e3a0),
    ('publication_callback_a','missing_initializer_boundary',0x5944fba,None),
    ('publication_callback_a','poison_boundary',0x5944fc0,None),
    ('publication_callback_b','missing_initializer_boundary',0x59404ca,None),
    ('publication_callback_b','poison_boundary',0x59404d0,None),
    ('file_read_helper','open_helper',0x5ca4a9b,0x5c97060),
    ('file_read_helper','read_helper',0x5ca4c08,0x5c75580),
    ('file_read_helper','utf8_boundary',0x5ca4c25,0x16815e0),
    ('home_string','home_env_or_account',0x17782f4,0x5c9abb0),
    ('home_string','utf8_boundary',0x1778321,0x16815e0),
    ('home_env_or_account','env_lookup',0x5c9abed,0x5c81950),
    ('document_reader','duplicate_field_error',0x1777ea1,0x1778bd0),
    ('document_reader','invalid_container_error',0x1777d49,0x1776910),
    ('document_reader','finalize_error',0x1777c33,0x1778060),
    ('serde_name_classifier','unknown_name_error',0x177495f,0x1777fd0),
]

# These are selected decision sites, not an exhaustive list of the functions'
# branches. Each opcode, signed displacement and destination is read from ELF.
BRANCHES = [
    ('first_metadata_tag_ne_2',0x177812d,'jne'),
    ('first_mode_not_directory',0x1778149,'jne'),
    ('second_metadata_tag_ne_2',0x17781a7,'jne'),
    ('second_mode_is_directory',0x17781c3,'je'),
    ('create_return_nonzero',0x17781e6,'jne'),
    ('initializer_metadata_tag_2',0x1778641,'je'),
    ('initializer_mode_not_directory',0x1778655,'jne'),
    ('static_read_no_neg_overflow',0x1778452,'jno'),
    ('parser_tag_not_one',0x17784c2,'jne'),
    ('parser_reported_error',0x1775e21,'jne'),
    ('document_consumed',0x1775e30,'jae'),
    ('trailing_byte_over_32',0x1775e59,'ja'),
    ('trailing_byte_not_whitespace',0x1775e5f,'jae'),
    ('document_begins_array',0x177722f,'je'),
    ('document_not_object',0x1777238,'jne'),
    ('object_end',0x17772b3,'je'),
    ('aws_name_key_match',0x177736d,'je'),
    ('aws_name_duplicate',0x17778bd,'jne'),
    ('array_not_empty',0x1777a1d,'jne'),
    ('object_name_present',0x1777a39,'jne'),
    ('quoted_name_not_error_marker',0x17730fb,'jne'),
    ('missing_name_read_error',0x177401c,'jo'),
    ('missing_name_unknown',0x177403e,'je'),
    ('name_length_outside_2_to_13',0x177550a,'ja'),
    ('plain_nvtestnet_match',0x17755f5,'je'),
    ('plain_nvtestnet2_match',0x17758ae,'je'),
    ('serde_nvtestnet_match',0x1774203,'je'),
    ('publication_a_null_pointer',0x5944f75,'je'),
    ('publication_a_state_one',0x5944f7b,'je'),
    ('publication_b_null_pointer',0x5940485,'je'),
    ('publication_b_state_one',0x594048b,'je'),
    ('read_path_contains_nul',0x5ca4a8a,'jne'),
    ('open_helper_reported_error',0x5ca4aa4,'je'),
    ('fstat_minus_one',0x5ca4b78,'je'),
    ('utf8_check_zero',0x5ca4c33,'je'),
    ('file_read_success',0x5ca4c55,'je'),
    ('open_not_minus_one',0x5c97149,'jne'),
    ('open_errno_not_four',0x5c9717a,'jne'),
    ('open_retry_minus_one',0x5c9719a,'je'),
    ('read_not_minus_one',0x5c756d3,'jne'),
    ('read_errno_four_retry',0x5c756e2,'je'),
    ('read_zero',0x5c756fe,'je'),
    ('home_result_not_error',0x1778304,'jno'),
    ('home_utf8_tag_not_one',0x177832b,'jne'),
    ('home_env_not_first_sentinel',0x5c9abfd,'jne'),
    ('home_env_not_second_sentinel',0x5c9ac0d,'jne'),
    ('home_account_lookup_result_present',0x5c9ac8d,'je'),
    ('home_empty_env_fallback',0x5c9ad56,'je'),
    ('getenv_null',0x5c81996,'je'),
    ('name_value_reader_error',0x1777931,'je'),
    ('object_result_error',0x1777d1b,'jne'),
    ('serde_name_length_outside_2_to_13',0x177410b,'ja'),
]

LITERALS = [
    ('cham',0x44ab69,0x17780f3,b'/cham'),
    ('hl',0x43de29,0x1778164,b'/hl'),
    ('code',0x43de2f,0x177866c,b'/code'),
    ('static_config',0x4401ef,0x177840e,b'/static_config'),
    ('aws_name',0x44205d,0x1772fe1,b'/aws_name'),
]

# Short contiguous contexts make the preceding compares and stores reviewable.
# They are hex bytes only: no disassembler output is part of generated evidence.
WINDOWS = [
    ('selector_first_path_and_mode',0x17780de,0x177815b),
    ('selector_second_path_and_create',0x177815b,0x17781f9),
    ('selector_create_failure',0x17781dd,0x177822e),
    ('initializer_calls_and_directory_gate',0x1778600,0x177865b),
    ('initializer_code_path_and_store',0x177865b,0x17786d2),
    ('initializer_failure_and_unwind',0x17786e6,0x177876f),
    ('static_read_and_fallback',0x17783ee,0x1778483),
    ('static_parse_and_tag',0x1778483,0x177853d),
    ('document_end_and_whitespace',0x1775e19,0x1775eb8),
    ('document_container_start',0x17771c4,0x177727c),
    ('document_key_and_duplicate',0x1777341,0x1777373),
    ('document_name_value_call',0x17778b8,0x1777942),
    ('document_array_and_object_missing_name',0x17779f5,0x1777a4c),
    ('quoted_name_read',0x1777101,0x1777160),
    ('value_reader_dispatch',0x17730e6,0x1773112),
    ('missing_name_read_and_lookup',0x1773fd0,0x1774061),
    ('missing_name_panics',0x1774061,0x17740b9),
    ('aws_name_path',0x1772fa0,0x1772ff6),
    ('plain_name_dispatch',0x1775500,0x1775520),
    ('plain_nvtestnet_comparison',0x17755dd,0x17755fb),
    ('plain_nvtestnet2_comparison',0x1775893,0x17758b4),
    ('serde_nvtestnet_comparison',0x17741eb,0x1774209),
    ('serde_nvtestnet_leaf',0x1774a04,0x1774a0d),
    ('name_format_dispatch',0x1774e60,0x1774e76),
    ('publication_callback_a',0x5944f60,0x5944fc6),
    ('publication_callback_b',0x5940470,0x59404d6),
    ('open_result_error_sentinel',0x5ca4a87,0x5ca4ada),
    ('file_read_validate_and_close',0x5ca4b98,0x5ca4c97),
    ('open_call_and_errno_retry',0x5c97127,0x5c971a6),
    ('read_call_and_errno_retry',0x5c756c0,0x5c75704),
    ('home_string_and_utf8',0x17782ee,0x1778342),
    ('home_environment_dispatch',0x5c9abd1,0x5c9ac13),
    ('home_account_fallback',0x5c9ac13,0x5c9aca0),
    ('home_empty_environment',0x5c9ad08,0x5c9ad6c),
    ('getenv_result',0x5c81983,0x5c819ee),
    ('document_duplicate_field_error',0x1777e6a,0x1777eab),
    ('document_success_return',0x1777d18,0x1777d3a),
    ('document_failure_return',0x1777c2d,0x1777c43),
    ('value_dispatch_entry',0x1773175,0x1773190),
    ('value_dispatch_success',0x1773f26,0x1773f43),
    ('serde_unknown_name',0x1774946,0x1774974),
]

IMPORT_SITES = [
    ('open_helper',0x5c97140,0x64ec8c8,'open64'),
    ('read_helper',0x5c756c9,0x64e2310,'read'),
    ('file_read_helper',0x5ca4b6f,0x64eafe8,'fstat64'),
    ('file_read_helper',0x5ca4c91,0x64dfe78,'close'),
    ('read_helper',0x5c756d5,0x64dffc8,'__errno_location'),
    ('open_helper',0x5c9714f,0x64dffc8,'__errno_location'),
    ('env_lookup',0x5c8198d,0x64ec6c8,'getenv'),
    ('home_env_or_account',0x5c9ac18,0x64ebff0,'sysconf'),
    ('home_env_or_account',0x5c9ac5d,0x64ec918,'getuid'),
    ('home_env_or_account',0x5c9ac76,0x64ec920,'getpwuid_r'),
]


def authenticate(data, expected=TARGET_SHA256):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('artifact SHA-256 mismatch')


def span(data, secs, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid virtual-address span')
    found = [s for s in secs if s['type'] != 8 and s['size'] and
             s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('virtual-address span is not uniquely file-backed')
    sec = found[0]
    offset = sec['offset'] + va - sec['address']
    if offset + size > len(data):
        raise ValueError('span exceeds file')
    return offset, data[offset:offset + size], sec['name']


def relative_relocations(data, secs):
    rs = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(rs) != 1 or rs[0]['size'] % 24:
        raise ValueError('unexpected dynamic relocation section')
    sec = rs[0]
    result = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if info == 8:
            if slot in result:
                raise ValueError('duplicate RELATIVE relocation')
            result[slot] = (addend, off)
    return result


def imported_relocations(data, secs, wanted):
    """Resolve selected symbol relocations using the shared ELF section map."""
    dyn = [s for s in secs if s['name'] == '.dynsym' and s['type'] == 11]
    strings = [s for s in secs if s['name'] == '.dynstr' and s['type'] == 3]
    if len(dyn) != 1 or len(strings) != 1 or dyn[0]['size'] % 24:
        raise ValueError('unexpected dynamic symbol sections')
    dyn, strings = dyn[0], strings[0]
    wanted = set(wanted)
    found = {}
    for section in secs:
        if section['name'] not in ('.rela.dyn','.rela.plt'):
            continue
        if section['type'] != 4 or section['size'] % 24:
            raise ValueError('unexpected relocation section')
        for offset in range(section['offset'],section['offset'] + section['size'],24):
            slot,info,addend = struct.unpack_from('<QQq',data,offset)
            if slot not in wanted:
                continue
            if slot in found or info & 0xffffffff != 6 or addend != 0:
                raise ValueError('unexpected selected import relocation')
            index=info >> 32
            symbol_offset=dyn['offset']+index*24
            if index == 0 or symbol_offset+24 > dyn['offset']+dyn['size']:
                raise ValueError('import symbol index out of range')
            name_offset=struct.unpack_from('<I',data,symbol_offset)[0]
            if name_offset >= strings['size']:
                raise ValueError('import symbol name out of range')
            begin=strings['offset']+name_offset
            end=data.find(b'\0',begin,strings['offset']+strings['size'])
            if end < 0:
                raise ValueError('unterminated import symbol')
            try:
                name=data[begin:end].decode('ascii')
            except UnicodeDecodeError as exc:
                raise ValueError('non-ASCII import symbol') from exc
            found[slot]=(name,index,offset)
    if set(found) != wanted:
        raise ValueError('selected import relocation missing')
    return found


def parse_template(raw):
    if len(raw) < 3 or raw[0] != 0xc0:
        raise ValueError('not a selected format template')
    length = raw[1]
    if len(raw) != length + 3 or raw[-1] != 0:
        raise ValueError('format template length or terminator mismatch')
    return raw[2:-1]


def decode_lea(site, raw):
    if len(raw) != 7 or raw[:3] != b'\x48\x8d\x35':
        raise ValueError('unexpected selected RIP-relative lea')
    return site + 7 + struct.unpack_from('<i', raw, 3)[0]


def decode_rip_lea(site, raw):
    if len(raw) != 7 or raw[0] not in (0x48,0x4c) or raw[1] != 0x8d or raw[2] & 0xc7 != 0x05:
        raise ValueError('unsupported RIP-relative lea')
    return site + 7 + struct.unpack_from('<i',raw,3)[0]


def decode_transfer(site, raw):
    if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
        return ('direct_call' if raw[0] == 0xe8 else 'direct_jump',
                site + 5 + struct.unpack_from('<i', raw, 1)[0])
    if len(raw) == 6 and raw[:2] in (b'\xff\x15', b'\xff\x25'):
        return ('indirect_call' if raw[1] == 0x15 else 'indirect_jump',
                site + 6 + struct.unpack_from('<i', raw, 2)[0])
    raise ValueError('unsupported selected transfer')


CC = {0x70:'jo', 0x71:'jno', 0x73:'jae', 0x74:'je',
      0x75:'jne', 0x77:'ja'}

def decode_branch(site, raw):
    if len(raw) >= 2 and raw[0] in CC:
        op, length, disp = raw[0], 2, struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f and raw[1] - 0x10 in CC:
        op, length, disp = raw[1] - 0x10, 6, struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported selected conditional branch')
    return CC[op], site + length, site + length + disp, raw[:length]


def arm_data(site, raw):
    """Read one fixed leaf: lea string, length, move context, indirect jump."""
    if len(raw) != 21 or raw[:3] != b'\x48\x8d\x35' or raw[7] != 0xba or raw[12:17] != b'\x48\x89\xc7\xff\x25':
        raise ValueError('unexpected formatter arm')
    literal = site + 7 + struct.unpack_from('<i', raw, 3)[0]
    size = struct.unpack_from('<I', raw, 8)[0]
    jump_slot = site + 21 + struct.unpack_from('<i', raw, 17)[0]
    return literal, size, jump_slot


def copy_store(raw):
    """Decode the five selected 16-byte stack-to-object store forms."""
    if len(raw) == 3 and raw == bytes.fromhex('0f1103'):
        return 0, 16
    if len(raw) == 4 and raw[:2] == bytes.fromhex('0f11') and raw[2] in (0x43,0x4b,0x53,0x5b):
        return raw[3], 16
    raise ValueError('unsupported publication store')


def pair(data, secs, relocs, address):
    offset, raw, _ = span(data, secs, address, 16)
    if raw[:8] != b'\x00' * 8 or address not in relocs:
        raise ValueError('string pointer is not an on-disk zero with RELATIVE relocation')
    pointer, rel_off = relocs[address]
    length = struct.unpack_from('<Q', raw, 8)[0]
    if not 1 <= length <= 64:
        raise ValueError('invalid selected string length')
    text_off, contents, section = span(data, secs, pointer, length)
    try:
        text = contents.decode('ascii')
    except UnicodeDecodeError as exc:
        raise ValueError('selected name is not ASCII') from exc
    if not text.isalnum():
        raise ValueError('selected name is not alphanumeric')
    return {'slot': address, 'file_offset': offset, 'relocation_offset': rel_off,
            'text_va': pointer, 'text_offset': text_off, 'text_section': section,
            'length': length, 'text': text}


def marker_count(data, secs, relocs):
    address = 0x63f8ca8
    off, raw, _ = span(data, secs, address, 16)
    del off
    if address not in relocs or raw[:8] != b'\x00' * 8:
        raise ValueError('variant bound descriptor is not relative')
    ptr = relocs[address][0]
    length = struct.unpack_from('<Q', raw, 8)[0]
    _, content, _ = span(data, secs, ptr, length)
    prefix = b'variant index 0 <= i < '
    if not content.startswith(prefix) or not content[len(prefix):].isdigit():
        raise ValueError('unexpected bound diagnostic')
    return int(content[len(prefix):]), ptr, content.decode('ascii')


def name_rows(data, secs, relocs):
    count, marker_va, diagnostic = marker_count(data, secs, relocs)
    if count != 79:
        raise ValueError('unexpected name bound')
    base1, base2, jump_base = 0x63f8788, 0x6410ce8, 0x481bd0
    rows = []
    for index in range(count):
        a = pair(data, secs, relocs, base1 + index * 16)
        b = pair(data, secs, relocs, base2 + index * 16)
        jo, raw, _ = span(data, secs, jump_base + index * 4, 4)
        target = jump_base + struct.unpack('<i', raw)[0]
        if not 0x1774e60 <= target < 0x17754f1:
            raise ValueError('formatter jump outside its FDE')
        arm_off, arm, _ = span(data, secs, target, 21)
        text_va, length, slot = arm_data(target, arm)
        if slot not in relocs or relocs[slot][0] != 0x167fa70:
            raise ValueError('unexpected formatter dispatch target')
        text_off, txt, _ = span(data, secs, text_va, length)
        if txt != a['text'].encode() or txt != b['text'].encode():
            raise ValueError('name tables and formatter arms disagree')
        rows.append([index, hex(jump_base + index * 4), hex(jo), raw.hex(),
                     hex(target), hex(arm_off), arm.hex(), hex(text_va), hex(text_off),
                     length, txt.decode('ascii'), hex(a['slot']), hex(a['relocation_offset']),
                     hex(a['text_va']), hex(b['slot']), hex(b['relocation_offset']),
                     hex(b['text_va']), hex(slot), hex(relocs[slot][0])])
    if len({row[10] for row in rows}) != count:
        raise ValueError('duplicate selected name')
    return rows, marker_va, diagnostic


def value_dispatch_leaf(site, raw):
    if len(raw) != 9 or raw[:3] != bytes.fromhex('c64301') or raw[4] != 0xe9:
        raise ValueError('unexpected value-dispatch leaf')
    return raw[3], site+9+struct.unpack_from('<i',raw,5)[0]


def value_dispatch_rows(data, secs, names):
    base=0x481928
    rows=[]
    for index,name_row in enumerate(names):
        slot=base+index*4
        slot_off,raw,_=span(data,secs,slot,4)
        target=base+struct.unpack('<i',raw)[0]
        if not 0x1773070 <= target < 0x1773fc4:
            raise ValueError('value-dispatch leaf outside selected FDE')
        leaf_off,leaf,_=span(data,secs,target,9)
        value,destination=value_dispatch_leaf(target,leaf)
        if value != index or destination != 0x1773f2d:
            raise ValueError('value-dispatch output or success destination changed')
        rows.append([index,name_row[10],hex(slot),hex(slot_off),raw.hex(),
                     hex(target),hex(leaf_off),leaf.hex(),value,hex(destination)])
    return rows


def nv_rule(data, secs, kind):
    """Lift exactly one known compare/branch/leaf form, not the full classifier."""
    if kind == 'plain9':
        start, length, prefix, imm, tail, expected = 0x17755dd, 30, bytes.fromhex('48330f0fb65708'), bytes.fromhex('4883f2'), bytes.fromhex('4809ca'), 9
    elif kind == 'plain10':
        start, length, prefix, imm, tail, expected = 0x1775893, 33, bytes.fromhex('48330f0fb75708'), bytes.fromhex('4881f2'), bytes.fromhex('4809ca'), 10
    elif kind == 'serde9':
        start, length, prefix, imm, tail, expected = 0x17741eb, 30, bytes.fromhex('48330e0fb67e08'), bytes.fromhex('4883f7'), bytes.fromhex('4809cf'), 9
    else:
        raise ValueError('unsupported comparison')
    off, raw, _ = span(data, secs, start, length)
    if raw[:2] != b'\x48\xb9' or raw[10:17] != prefix or raw[17:20] != imm:
        raise ValueError('unsupported name comparison form')
    imm_len = 4 if expected == 10 else 1
    tail_at = 20 + imm_len
    if raw[tail_at:tail_at + 3] != tail:
        raise ValueError('unexpected name comparison reduction')
    cc, fall, target, branch = decode_branch(start + tail_at + 3, raw[tail_at + 3:])
    if cc != 'je':
        raise ValueError('name comparison is not equality branch')
    leaf_off, leaf, _ = span(data, secs, target, 9 if kind == 'serde9' else 3)
    if kind == 'serde9':
        if leaf[:3] != b'\xc6\x40\x01' or leaf[4:] != b'\x31\xc9\x88\x08\xc3':
            raise ValueError('unsupported serde result leaf')
        value = leaf[3]
    else:
        if leaf[0] != 0xb0 or leaf[2] != 0xc3:
            raise ValueError('unsupported plain result leaf')
        value = leaf[1]
    suffix = int.from_bytes(raw[20:20 + imm_len], 'little').to_bytes(imm_len, 'little')
    if imm_len == 4:
        if suffix[2:] != b'\0\0':
            raise ValueError('unexpected upper suffix immediate')
        suffix = suffix[:2]
    target_bytes = raw[2:10] + suffix
    if len(target_bytes) != expected:
        raise ValueError('unexpected compared name length')
    return {'kind':kind, 'site':start, 'file_offset':off, 'window':raw,
            'bytes':target_bytes, 'branch_site':start + tail_at + 3,
            'fallthrough':fall, 'target':target, 'branch':branch,
            'leaf_offset':leaf_off, 'leaf':leaf, 'value':value}


def rule_match(rule, value):
    """Evaluate only the extracted equality predicate with its length precondition."""
    if len(value) != len(rule['bytes']):
        return False
    first = int.from_bytes(value[:8], 'little') ^ int.from_bytes(rule['bytes'][:8], 'little')
    last = int.from_bytes(value[8:], 'little') ^ int.from_bytes(rule['bytes'][8:], 'little')
    return (first | last) == 0


def directory_constants(data, secs):
    """Extract the selected tag and directory-mode predicates from both sites."""
    first = span(data,secs,0x177813b,14)[1]
    second = span(data,secs,0x17781b5,14)[1]
    if first[:1] != b'\xb8' or first[5:10] != bytes.fromhex('234424603d') or second != first:
        raise ValueError('directory mode predicate form changed')
    mask=struct.unpack_from('<I',first,1)[0]
    expected=struct.unpack_from('<I',first,10)[0]
    tag1=span(data,secs,0x1778128,5)[1]
    tag2=span(data,secs,0x17781a2,5)[1]
    if tag1 != tag2 or tag1[:4] != bytes.fromhex('837c2428'):
        raise ValueError('directory metadata tag form changed')
    return {'error_tag':tag1[4],'mask':mask,'directory':expected}


def directory_model(constants, first_tag, first_mode, second_tag, second_mode, create_result):
    """Model the selected tag/mode/creation branch, with external results supplied."""
    def accepted(tag,mode):
        return tag != constants['error_tag'] and mode & constants['mask'] == constants['directory']
    if accepted(first_tag,first_mode):
        return 'first'
    if accepted(second_tag,second_mode):
        return 'second'
    return 'second_created' if create_result == 0 else 'creation_error'


def static_result_model(fallback, read_error, parser_tag, parser_value):
    """Model only the normal-returning sentinel/tag selection in the static reader."""
    if read_error or parser_tag != 0:
        return fallback
    if not 0 <= parser_value <= 255:
        raise ValueError('parser value does not fit its observed byte')
    return parser_value


def missing_name_model(marker, read_error, name_result):
    """Model the selected separate-name-file error and classifier-result tests."""
    if read_error:
        return 'read_error_unwrap'
    if not 0 <= name_result <= 255:
        raise ValueError('classifier result does not fit its observed byte')
    return 'unknown_name_unwrap' if name_result == marker else 'normal_return'


def require(data, secs, va, expected):
    _, raw, _ = span(data, secs, va, len(expected))
    if raw != expected:
        raise ValueError('selected instruction context changed')
    return raw


def check_contexts(data, secs, count):
    # Context checks bind the meanings assigned to selected branch and store rows.
    checks = {
        0x1778128:'837c242802', 0x177813b:'b800f00000234424603d00400000',
        0x17781a2:'837c242802', 0x17781b5:'b800f00000234424603d00400000',
        0x17781e3:'4885c0', 0x177863c:'837c244002',
        0x1778647:'b800f00000234424783d00400000',
        0x177844c:'4c89e048f7d8', 0x177845c:'40b521',
        0x17784b3:'440fb66c24080fb66c2409', 0x17784be:'4180fd01',
        0x1778525:'400fb6c54584edbd210000000f44e8',
        0x17786ce:'41884648', 0x1775e1e:'803b00',
        0x1775e2d:'4839c1', 0x1775e3d:'48be0026000001000000',
        0x1775e55:'4883ff20', 0x1775e5b:'480fa3fe',
        0x177722c:'83ff5b', 0x1777235:'83ff7b',
        0x1777277:'c64424074f', 0x17772b0:'83ff7d',
        0x1777357:'48837c241808', 0x177735f:'48b86177735f6e616d65',
        0x1777369:'49390424', 0x17778b8:'807c24074f',
        0x1777a1a:'83f95d', 0x1777a30:'0fb644240731ed3c4f',
        0x17730f4:'0fb6042483f84f', 0x1774016:'4889d848f7d8',
        0x177403c:'3c4f', 0x1775500:'b04f4883c6fe4883fe0b',
        0x1774e60:'4889f00fb60f',
        0x5944f65:'488b07488b1848c700000000004885db',
        0x5940475:'488b07488b1848c700000000004885db',
        0x5944f80:'ff13', 0x5940490:'ff13',
        0x5ca4a87:'4c39f2', 0x5ca4aa0:'837dc001',
        0x5ca4ac8:'48b80000000000000080488903',
        0x5ca4c2b:'4883bd20feffff00',
        0x5ca4c51:'41f6c401', 0x5ca4c5f:'48b80000000000000080488903',
        0x5c97146:'83f8ff', 0x5c97177:'83f904', 0x5c97197:'83f8ff',
        0x5c756cf:'4883f8ff', 0x5c756de:'4883f904', 0x5c756fb:'4885c0',
        0x17782fe:'4c89f048f7d8', 0x1778327:'833c2401',
        0x5c9abd1:'c78538feffff484f4d45c6853cfeffff00',
        0x5c9abf6:'498d46014939c4', 0x5c9ac0a:'4d39f4',
        0x5c9ac81:'488b45b84885c00f94c208ca',
        0x5c9ad53:'4d85e4', 0x5c81993:'4885c0',
        0x177792c:'807c242801', 0x1777d18:'4084ed',
        0x1777e6a:'488d054711cefe', 0x1777e95:'488d3d7eb6cbfe',
        0x1777c38:'48894308b001', 0x1777d21:'88430131c08803',
        0x1773175:'89c0488d0daae7d0fe486304814801c8ffe0',
        0x1773f2d:'31c08803',
        0x1774103:'488d4afe4883f90b',
        0x177494e:'b94f000000', 0x177496e:'b1015b8808c3',
    }
    for va, encoded in checks.items():
        require(data, secs, va, bytes.fromhex(encoded))
    marker = span(data, secs, 0x177727b, 1)[1][0]
    if marker != count:
        raise ValueError('missing-name sentinel differs from name count')
    fallback = span(data, secs, 0x177845e, 1)[1][0]
    if fallback != struct.unpack('<I', span(data, secs, 0x177852d, 4)[1])[0]:
        raise ValueError('fallback immediates disagree')
    return fallback, marker, len(checks)


def globals_and_stores(data, secs, relocs):
    links = [
        ('consumer_slot',0x64e0918,0x64f06c0),
        ('initial_initializer',0x64f06c0,0x17785f0),
        ('callback_a_vtable_slot',0x64b6710,0x5944f60),
        ('callback_b_vtable_slot',0x64b6718,0x5940470),
    ]
    rows = []
    for label,slot,expected in links:
        off,raw,sec=span(data,secs,slot,8)
        if raw != b'\0'*8 or slot not in relocs or relocs[slot][0] != expected:
            raise ValueError('publication relocation changed')
        rows.append([label,hex(slot),hex(off),sec,raw.hex(),hex(relocs[slot][1]),hex(relocs[slot][0])])
    for label,va,expected in (('vtable_drop_slot',0x64b66f8,0),
                              ('vtable_size',0x64b6700,8),
                              ('vtable_alignment',0x64b6708,8)):
        off,raw,sec=span(data,secs,va,8)
        if int.from_bytes(raw,'little') != expected or va in relocs:
            raise ValueError('publication vtable header changed')
        rows.append([label,hex(va),hex(off),sec,raw.hex(),'',str(expected)])
    guard_va=0x64f0710
    off,guard,sec=span(data,secs,guard_va,4)
    if guard != bytes.fromhex('03000000'):
        raise ValueError('publication guard initial bytes changed')
    rows.append(['guard_initial_file_bytes',hex(guard_va),hex(off),sec,guard.hex(),'',str(int.from_bytes(guard,'little'))])

    specs = [
      ('publication_callback_a',0x5944f87,4),('publication_callback_a',0x5944f9e,4),
      ('publication_callback_a',0x5944fa2,4),('publication_callback_a',0x5944fa6,4),
      ('publication_callback_a',0x5944faa,3),
      ('publication_callback_b',0x5940497,4),('publication_callback_b',0x59404ae,4),
      ('publication_callback_b',0x59404b2,4),('publication_callback_b',0x59404b6,4),
      ('publication_callback_b',0x59404ba,3),
    ]
    stores=[]
    for name,site,size in specs:
        off,raw,_=span(data,secs,site,size)
        displacement,width=copy_store(raw)
        stores.append([name,hex(site),hex(off),raw.hex(),displacement,width])
    for name in ('publication_callback_a','publication_callback_b'):
        intervals=sorted((row[4],row[4]+row[5]) for row in stores if row[0]==name)
        if intervals != [(n,n+16) for n in range(0,80,16)]:
            raise ValueError('publication stores do not cover the selected 80-byte region')
    return rows,stores


def diagnostic_rows(data, secs):
    specs = [
        ('duplicate_field',0x43351a,0x1777e95,b'\x11duplicate field `\xc0\x01`\x00'),
        ('aws_name_key',0x458fb8,0x1777e6a,b'aws_name'),
        ('unwrap_error',0x481f8a,0x177406b,b'called `Result::unwrap()` on an `Err` value'),
        ('not_directory',0x445b89,0x1778701,b'\x19cham_dir does not exist: \xc0\x00'),
        ('create_error',0x44f4ad,0x17782a1,b'\x11could not create \xc0\x02: \xc0\x00'),
    ]
    rows=[]
    for label,va,site,expected in specs:
        off,raw,section=span(data,secs,va,len(expected))
        ins_off,ins,_=span(data,secs,site,7)
        if raw != expected or ins[:2] != b'\x48\x8d' or ins[2] not in (0x05,0x3d):
            raise ValueError('diagnostic byte or reference form changed')
        if site+7+struct.unpack_from('<i',ins,3)[0] != va:
            raise ValueError('diagnostic reference target changed')
        rows.append([label,hex(va),hex(off),section,len(raw),raw.hex(),hex(site),hex(ins_off),ins.hex()])
    return rows


def compare_94(data, names):
    """Optionally authenticate the retired capture and compare its recorded table.

    This is an independent historical comparison, never an input requirement for
    the node-115 packet or its generated evidence files.
    """
    authenticate(data,HISTORICAL_SHA256)
    secs=sections(data)
    relocs=relative_relocations(data,secs)
    marker_slot=0x5668778
    if marker_slot not in relocs:
        raise ValueError('historical bound relocation missing')
    _,descriptor,_=span(data,secs,marker_slot,16)
    if descriptor[:8] != b'\0'*8:
        raise ValueError('historical bound pointer is not zero on disk')
    marker_va=relocs[marker_slot][0]
    length=struct.unpack_from('<Q',descriptor,8)[0]
    _,marker,_=span(data,secs,marker_va,length)
    prefix=b'variant index 0 <= i < '
    if not marker.startswith(prefix) or not marker[len(prefix):].isdigit():
        raise ValueError('historical bound diagnostic changed')
    count=int(marker[len(prefix):])
    old=[pair(data,secs,relocs,0x5668288+i*16)['text'] for i in range(count)]
    if len(set(old)) != count:
        raise ValueError('historical table contains duplicate names')
    new=[row[10] for row in names]
    _,default_raw,_=span(data,secs,0x164fc56,3)
    if default_raw[:2] != b'\x40\xb5':
        raise ValueError('historical default instruction changed')
    default=default_raw[2]
    if default >= len(old):
        raise ValueError('historical default out of range')
    historical_templates=[]
    for target,site,text in ((0x1fc0ec,0x164f840,b'/cham'),(0x1ef5f5,0x164fbae,b'/static_config')):
        _,raw,_=span(data,secs,target,len(text)+3)
        _,lea,_=span(data,secs,site,7)
        if parse_template(raw) != text or decode_lea(site,lea) != target:
            raise ValueError('historical template reference changed')
        historical_templates.append({'text':text.decode('ascii'),'entry_va':hex(target),'site_va':hex(site),'template_bytes':raw.hex(),'lea_bytes':lea.hex()})
    return {
        'historical_sha256':HISTORICAL_SHA256,
        'historical_table_va':hex(0x5668288),'historical_marker_va':hex(marker_va),
        'historical_count':len(old),'target_count':len(new),
        'shared_names':len(set(old)&set(new)),
        'shifted_shared_names':sum(old.index(name)!=i for i,name in enumerate(new) if name in old),
        'added':[{'index':i,'name':name} for i,name in enumerate(new) if name not in old],
        'removed':[{'index':i,'name':name} for i,name in enumerate(old) if name not in new],
        'historical_default':{'site_va':hex(0x164fc56),'bytes':default_raw.hex(),'index':default,'name':old[default]},
        'target_default':{'index':new.index(old[default]),'name':old[default]},
        'historical_templates':historical_templates,
    }


def tsv(header, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def collect(data):
    authenticate(data)
    secs = sections(data)
    relocs = relative_relocations(data, secs)
    imports = imported_relocations(data,secs,[row[2] for row in IMPORT_SITES])
    _, fdes, _ = fde_extents(data)
    by_start = {f['start']: f for f in fdes}
    if len(by_start) != len(fdes):
        raise ValueError('ambiguous FDE start')
    selected = {}
    funcs = []
    for name, start in FUNCTIONS.items():
        if start not in by_start:
            raise ValueError('selected FDE missing')
        f = by_start[start]
        offset, body, section = span(data, secs, start, f['end'] - start)
        if section != f['section']:
            raise ValueError('FDE file mapping disagrees')
        selected[name] = f
        funcs.append([name,hex(start),hex(f['end']),len(body),hex(offset),section,
                      hex(f['fde']),hex(f['cie']),'' if f['lsda'] is None else hex(f['lsda']),
                      hashlib.sha256(body).hexdigest()])

    names, marker_va, diagnostic = name_rows(data, secs, relocs)
    count = len(names)
    fallback, sentinel, context_count = check_contexts(data, secs, count)
    directory = directory_constants(data,secs)
    globals_,stores = globals_and_stores(data,secs,relocs)
    diagnostics = diagnostic_rows(data,secs)
    if names[fallback][10] != 'NvTestnet':
        raise ValueError('fallback and formatter name disagree')
    rules = [nv_rule(data, secs, n) for n in ('plain9','plain10','serde9')]
    for rule in rules:
        if rule['value'] >= count or names[rule['value']][10].encode() != rule['bytes']:
            raise ValueError('classifier and formatter names disagree')
    value_rows = value_dispatch_rows(data,secs,names)

    plain_bound = span(data,secs,0x1775509,1)[1][0]
    serde_bound = span(data,secs,0x177410a,1)[1][0]
    if plain_bound != serde_bound or plain_bound > 63:
        raise ValueError('selected length-dispatch bounds disagree')
    length_count = plain_bound + 1
    table_refs=[]
    for label,site,target,entries in [
        ('quoted_value',0x1773177,0x481928,count),
        ('serde_length',0x1774111,0x481ba0,length_count),
        ('serde_unknown_array',0x1774947,0x6410ce8,count),
        ('formatter',0x1774e66,0x481bd0,count),
        ('plain_length',0x1775510,0x481d0c,length_count),
    ]:
        off,raw,_=span(data,secs,site,7)
        resolved=decode_rip_lea(site,raw)
        if resolved != target:
            raise ValueError('table reference target changed')
        table_refs.append([label,hex(site),hex(off),raw.hex(),hex(resolved),entries])

    literals = []
    for label, target, site, text in LITERALS:
        offset, raw, section = span(data, secs, target, len(text) + 3)
        if parse_template(raw) != text:
            raise ValueError('selected template does not carry expected bytes')
        site_offset, ins, _ = span(data, secs, site, 7)
        if decode_lea(site, ins) != target:
            raise ValueError('template lea does not resolve to entry')
        literals.append([label,hex(target),hex(offset),section,raw.hex(),hex(target+2),
                         len(text),text.decode('ascii'),hex(site),hex(site_offset),ins.hex()])

    edges = []
    for caller, role, site, expected in EDGES:
        if not selected[caller]['start'] <= site < selected[caller]['end']:
            raise ValueError('selected transfer outside caller FDE')
        site_off, first, _ = span(data, secs, site, 2)
        size = 5 if first[0] in (0xe8,0xe9) else 6
        _, raw, _ = span(data, secs, site, size)
        kind, target_or_slot = decode_transfer(site, raw)
        if kind.startswith('indirect'):
            if target_or_slot not in relocs:
                raise ValueError('indirect transfer has no relative relocation')
            dst, roff = relocs[target_or_slot]
            slot = hex(target_or_slot)
            relocation = hex(roff)
        else:
            dst, slot, relocation = target_or_slot, '', ''
        if expected is not None and dst != expected:
            raise ValueError('selected transfer target changed')
        edges.append([caller,role,hex(site),hex(site_off),raw.hex(),kind,slot,relocation,hex(dst)])

    import_rows=[]
    for caller,site,slot,expected_name in IMPORT_SITES:
        if not selected[caller]['start'] <= site < selected[caller]['end']:
            raise ValueError('selected import call outside its FDE')
        off,raw,_=span(data,secs,site,6)
        kind,actual_slot=decode_transfer(site,raw)
        if kind != 'indirect_call' or actual_slot != slot or imports[slot][0] != expected_name:
            raise ValueError('selected imported call changed')
        name,index,rel_offset=imports[slot]
        import_rows.append([caller,hex(site),hex(off),raw.hex(),hex(slot),hex(rel_offset),index,name])

    branches = []
    for name, site, expected in BRANCHES:
        site_off, raw, _ = span(data, secs, site, 6)
        cc, fall, target, raw = decode_branch(site, raw)
        if cc != expected:
            raise ValueError('selected branch condition changed')
        owners = [n for n,f in selected.items() if f['start'] <= site < f['end']]
        if len(owners) != 1:
            raise ValueError('selected branch has no unique selected FDE')
        branches.append([name,owners[0],hex(site),hex(site_off),raw.hex(),cc,hex(fall),hex(target)])

    windows = []
    for name,start,end in WINDOWS:
        off,raw,sec = span(data,secs,start,end-start)
        owners = [n for n,f in selected.items() if f['start'] <= start < end <= f['end']]
        if len(owners) != 1:
            raise ValueError('selected window outside selected FDE')
        windows.append([name,owners[0],hex(start),hex(end),hex(off),sec,raw.hex(),hashlib.sha256(raw).hexdigest()])

    dispatches = []
    for label,base,first in [('plain',0x481d0c,0x1775500),('serde',0x481ba0,0x1774100)]:
        for length in range(2,2+length_count):
            va=base+4*(length-2)
            off,raw,_=span(data,secs,va,4)
            dst=base+struct.unpack('<i',raw)[0]
            f=by_start[first]
            if not f['start'] <= dst < f['end']:
                raise ValueError('length dispatch target outside selected FDE')
            dispatches.append([label,length,hex(va),hex(off),raw.hex(),hex(dst)])

    rule_rows = []
    probes = []
    for rule in rules:
        rule_rows.append([rule['kind'],hex(rule['site']),hex(rule['file_offset']),
                          rule['window'].hex(),rule['bytes'].decode('ascii'),
                          hex(rule['branch_site']),rule['branch'].hex(),hex(rule['fallthrough']),
                          hex(rule['target']),hex(rule['leaf_offset']),rule['leaf'].hex(),rule['value']])
        text = rule['bytes']
        probes.append([rule['kind'],'exact',text.hex(),len(text),1,rule['value']])
        for i in range(len(text)):
            bad=bytearray(text);bad[i]^=1
            probes.append([rule['kind'],'flip_byte_'+str(i),bytes(bad).hex(),len(bad),int(rule_match(rule,bad)), ''])
        for label,bad in [('truncated',text[:-1]),('extended',text+b'2')]:
            probes.append([rule['kind'],label,bad.hex(),len(bad),int(rule_match(rule,bad)), ''])
    for row in probes:
        if row[1] != 'exact' and row[4] != 0:
            raise ValueError('negative comparison probe matched')

    err,mask,dir_mode=directory['error_tag'],directory['mask'],directory['directory']
    dir_cases = [
      ('first_exact',0,dir_mode,0,0,1),
      ('first_with_low_bits',0,dir_mode|0x1ff,err,0,1),
      ('first_wrong_mode_second_exact',0,0,0,dir_mode,1),
      ('first_error_tag_even_with_mode',err,dir_mode,0,dir_mode,1),
      ('second_error_tag_even_with_mode',err,0,err,dir_mode,0),
      ('both_fail_creation_succeeds',err,0,err,0,0),
      ('both_fail_creation_fails',err,0,err,0,1),
      ('both_wrong_mode_creation_fails',0,mask,0,mask,0xffffffff),
      ('non_error_tag_directory',err+1,dir_mode,err,0,1),
    ]
    dir_rows=[]
    for label,first_tag,first_mode,second_tag,second_mode,result in dir_cases:
        out=directory_model(directory,first_tag,first_mode,second_tag,second_mode,result)
        dir_rows.append([label,first_tag,hex(first_mode),second_tag,hex(second_mode),hex(result),out])
    reader_rows=[]
    for label,read_error,tag,value in [
        ('read_error',1,0,0),('parse_error',0,1,0),('success_first',0,0,0),
        ('success_old_default_index',0,0,32),('success_target_default_index',0,0,fallback),
        ('success_last_name',0,0,count-1),('success_marker_hypothetical',0,0,sentinel),
    ]:
        reader_rows.append([label,'static_reader',read_error,tag,value,static_result_model(fallback,read_error,tag,value)])
    for label,read_error,value in [('name_read_error',1,0),('name_unknown',0,sentinel),
                                    ('name_valid_first',0,0),('name_valid_default',0,fallback),
                                    ('name_valid_last',0,count-1)]:
        reader_rows.append([label,'missing_name_reader',read_error,'',value,missing_name_model(sentinel,read_error,value)])

    summary = {
        'binary_sha256':TARGET_SHA256,
        'address_space':'linked ELF virtual addresses; file offsets are section-derived',
        'function_count':len(funcs), 'selected_transfer_count':len(edges),
        'selected_branch_count':len(branches), 'selected_window_count':len(windows),
        'template_count':len(literals), 'name_count':count,
        'name_bound_diagnostic_va':hex(marker_va), 'name_bound_diagnostic':diagnostic,
        'fallback_discriminant':fallback, 'missing_name_sentinel':sentinel,
        'comparison_rule_count':len(rules), 'comparison_probe_count':len(probes),
        'context_check_count':context_count,
        'publication_relocation_count':sum(bool(row[5]) for row in globals_),
        'publication_store_count':len(stores),
        'selected_import_call_count':len(import_rows),
        'diagnostic_count':len(diagnostics),
        'directory_model_case_count':len(dir_rows),
        'reader_model_case_count':len(reader_rows),
        'value_dispatch_count':len(value_rows),
        'selected_table_reference_count':len(table_refs),
        'limitations':'Selected instruction patterns and selected FDEs only; not a whole-program function or xref census, full parser model, target execution, or equivalence claim.'
    }
    files = {
      'functions.tsv':tsv(['role','start_va','end_va','size','file_offset','section','fde_va','cie_va','lsda_va','sha256'],funcs),
      'calls.tsv':tsv(['caller','role','site_va','file_offset','bytes','kind','relocation_slot_va','relocation_file_offset','target_va'],edges),
      'branches.tsv':tsv(['decision','fde_role','site_va','file_offset','bytes','condition','fallthrough_va','taken_va'],branches),
      'windows.tsv':tsv(['label','fde_role','start_va','end_va','file_offset','section','bytes','sha256'],windows),
      'literals.tsv':tsv(['label','entry_va','entry_offset','section','template_bytes','text_va','length','text','site_va','site_offset','lea_bytes'],literals),
      'names-115.tsv':tsv(['index','jump_slot_va','jump_slot_offset','jump_bytes','arm_va','arm_offset','arm_bytes','render_text_va','render_text_offset','length','name','table_a_slot_va','table_a_rela_offset','table_a_text_va','table_b_slot_va','table_b_rela_offset','table_b_text_va','tail_slot_va','tail_target_va'],names),
      'length-dispatch.tsv':tsv(['classifier','length','slot_va','slot_offset','bytes','target_va'],dispatches),
      'name-rules.tsv':tsv(['classifier','start_va','file_offset','window_bytes','matched_text','branch_va','branch_bytes','fallthrough_va','taken_va','leaf_offset','leaf_bytes','result'],rule_rows),
      'name-probes.tsv':tsv(['classifier','case','input_hex','length','selected_predicate_match','result_if_matched'],probes),
      'globals.tsv':tsv(['role','slot_va','file_offset','section','file_bytes','relocation_offset','relative_addend_or_initial_value'],globals_),
      'publication-stores.tsv':tsv(['callback','site_va','file_offset','bytes','destination_offset','width'],stores),
      'imports.tsv':tsv(['caller','site_va','file_offset','bytes','slot_va','relocation_offset','dynsym_index','symbol'],import_rows),
      'diagnostics.tsv':tsv(['label','data_va','file_offset','section','length','bytes','lea_va','lea_offset','lea_bytes'],diagnostics),
      'directory-cases.tsv':tsv(['case','first_tag','first_mode','second_tag','second_mode','creation_result','selected_outcome'],dir_rows),
      'reader-cases.tsv':tsv(['case','scope','read_error','parser_tag','value','selected_outcome'],reader_rows),
      'value-dispatch.tsv':tsv(['index','name','jump_slot_va','jump_slot_offset','jump_bytes','leaf_va','leaf_offset','leaf_bytes','output_byte','success_va'],value_rows),
      'table-refs.tsv':tsv(['role','lea_va','file_offset','bytes','target_va','selected_entries'],table_refs),
      'summary.json':(json.dumps(summary,indent=2,sort_keys=True)+'\n').encode('utf-8'),
    }
    return files, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--compare-94',type=Path,help='optionally compare an authenticated historical capture')
    args = parser.parse_args()
    data = BINARY.read_bytes()
    files, summary = collect(data)
    args.out.mkdir(parents=True,exist_ok=True)
    for name,contents in files.items():
        (args.out / name).write_bytes(contents)
    print('Collected %d functions, %d selected transfers and %d names.' %
          (summary['function_count'],summary['selected_transfer_count'],summary['name_count']))
    if args.compare_94 is not None:
        secs=sections(data)
        names,_,_=name_rows(data,secs,relative_relocations(data,secs))
        print(json.dumps(compare_94(args.compare_94.read_bytes(),names),indent=2,sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError,ValueError,struct.error) as exc:
        print('re015_static_config_115: '+str(exc),file=sys.stderr)
        raise SystemExit(1)
