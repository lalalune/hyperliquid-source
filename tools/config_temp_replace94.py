#!/usr/bin/env python3
"""Recover the node 94 configuration-rooted temporary replacement path from ELF bytes.

The image is data, never an executable input. All addresses are linked ELF VAs.
The instruction reader accepts only the x86-64 forms required by selected FDEs
and fails on unknown/truncated forms. It uses no external programs.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280

FUNCTIONS = {
    0x13464d0: 'owned_nul_checked_buffer',
    0x144a070: 'directory_predicate',
    0x144a2f0: 'metadata_exists_predicate',
    0x144a4e0: 'directory_error_adapter',
    0x144d0d0: 'configured_temporary_path',
    0x37eaa70: 'replacement_entry',
    0x4edfb40: 'metadata_adapter',
    0x4ee0000: 'link_adapter',
    0x4ee0300: 'long_source_link_callback',
    0x4ee04b0: 'long_destination_link_callback',
    0x4ee60a0: 'long_input_adapter',
    0x4ee9b80: 'backward_component_classifier',
    0x4ee9cb0: 'component_slice_view',
}

# Offsets are analysis coordinates; each expected opcode, target and following
# byte is checked before its annotated meaning may be emitted.
BRANCH_CONTRACTS = {
    'config_once_slow': (0x144d11c, '0f85', 0x144d3e1),
    'primary_component_tag_other': (0x144d1d8, '73', 0x144d209),
    'primary_component_no_slice': (0x144d1e8, '74', 0x144d209),
    'primary_component_utf8_failure': (0x144d1fd, '74', 0x144d209),
    'primary_parent_exists': (0x144d221, '0f85', 0x144d37e),
    'primary_create_ok': (0x144d248, '0f84', 0x144d37e),
    'fallback_component_tag_other': (0x144d2db, '73', 0x144d306),
    'fallback_component_no_slice': (0x144d2eb, '74', 0x144d306),
    'fallback_component_utf8_success': (0x144d300, '0f85', 0x144d3d2),
    'fallback_parent_exists': (0x144d324, '75', 0x144d3a4),
    'fallback_create_ok': (0x144d347, '74', 0x144d3a4),
    'source_stat_failure': (0x37eaab2, '74', 0x37eaaeb),
    'destination_stat_failure': (0x37eaad4, '74', 0x37eaaeb),
    'metadata_word0_differs': (0x37eaadb, '75', 0x37eaafd),
    'metadata_word1_differs': (0x37eaae2, '75', 0x37eaafd),
    'link_result_zero': (0x37eaba0, '74', 0x37eabac),
    'destination_parent_error': (0x37eabbb, '75', 0x37eabd6),
    'stat_initial_failure': (0x144a08d, '74', 0x144a0c5),
    'stat_repeat_success': (0x144a0a5, '75', 0x144a0c9),
    'metadata_short_length': (0x4edfb5d, '0f87', 0x4edfd44),
    'metadata_early_nul': (0x4edfc5d, '0f85', 0x4edfcf8),
    'metadata_other_adapter': (0x4edfc84, '0f85', 0x4edfd1b),
    'link_source_long': (0x4ee0027, '0f87', 0x4ee02cf),
    'link_source_early_nul': (0x4ee014d, '0f85', 0x4ee02a6),
    'link_destination_long': (0x4ee0162, '0f87', 0x4ee02e7),
    'link_destination_early_nul': (0x4ee027a, '75', 0x4ee02a6),
    'linkat_failure': (0x4ee02a0, '74', 0x4ee02bd),
    'callback_destination_long': (0x4ee0329, '0f87', 0x4ee0489),
    'callback_destination_early_nul': (0x4ee043a, '75', 0x4ee0462),
    'callback_linkat_failure': (0x4ee045c, '74', 0x4ee046b),
    'both_long_linkat_success': (0x4ee04d4, '75', 0x4ee04e6),
    'long_converter_non_sentinel': (0x4ee60cf, '71', 0x4ee60f8),
    'converter_empty_input': (0x134652a, '0f84', 0x13465f0),
    'converter_first_loop_nul': (0x1346546, '0f84', 0x134661b),
    'converter_alignment_loop_nul': (0x13465c6, '74', 0x134661b),
    'converter_tail_loop_nul': (0x13465e6, '74', 0x1346618),
    'tail_empty': (0x4ee9c1b, '74', 0x4ee9c62),
    'tail_one_byte': (0x4ee9c21, '74', 0x4ee9c5a),
    'tail_not_two_bytes': (0x4ee9c27, '75', 0x4ee9c5f),
    'tail_two_not_dot_first': (0x4ee9c2c, '75', 0x4ee9c5f),
    'tail_two_dot_match': (0x4ee9c35, '74', 0x4ee9c62),
    'tail_one_dot_match': (0x4ee9c5d, '74', 0x4ee9c62),
    'slice_back_first_not_skip': (0x4ee9df2, '75', 0x4ee9e5f),
    'slice_back_second_not_skip': (0x4ee9e42, '75', 0x4ee9e5f),
    'slice_back_third_not_skip': (0x4ee9efb, '0f85', 0x4ee9e5f),
}

# Each assertion binds a small semantic window, with no masked operands.
WITNESSES = {
    'global_config_and_state': (0x144d10f, '4c8b3512183204418b465085c0'),
    'config_path_field': (0x144d122, '4983c6184c89742408'),
    'input_string_pair': (0x144d0e4, '4889b424a800000048899424b0000000'),
    'first_format_argument': (0x144d122, '4983c6184c897424084c8d257e9500004c89642410'),
    'third_format_argument': (0x144d150, '488d8c24a800000048894c24284889442430'),
    'tmp_text_length': (0x144d0f4, '488d0571cbdcfe48898424b800000048c78424c000000003000000'),
    'component_tag_primary': (0x144d1cf, '0fb644247004f93c03732f'),
    'component_tag_fallback': (0x144d2d2, '0fb644247004f93c037329'),
    'primary_mode_and_recursive': (0x144d227, 'c7442470ff010000c644247401'),
    'fallback_mode_and_recursive': (0x144d326, 'c7442470ff010000c644247401'),
    'directory_file_type': (0x144a0c9, 'b800f00000234424483d00400000400f94c5'),
    'exists_result': (0x144a37f, '4183ff020f95c0'),
    'metadata_words_loaded': (0x37eaab4, '488b5c2468488b6c2470'),
    'same_metadata_words': (0x37eaad6, '483b5c24687520483b6c2470751931c0'),
    'source_metadata_tag': (0x37eaaa3, '837c244802'),
    'destination_metadata_tag': (0x37eaacf, '837c244802'),
    'link_result_test': (0x37eab9d, '4885c0'),
    'link_input_arguments': (0x37eab7f, '4c89e7488b7424084c89ea4889e9'),
    'destination_parent_test': (0x37eabb8, '4885c0'),
    'fallback_error_callback': (0x144d351, 'e88ad1ffff488b084889c7ff11'),
    'primary_error_callback': (0x144d376, '498b064c89f7ff10'),
    'temporary_string_cleanup': (0x37eabd6, '488b7424484885f67411'),
    'metadata_length_limit': (0x4edfb56, '4881fa7f010000'),
    'source_length_limit': (0x4ee0020, '4981ff7f010000'),
    'destination_length_limit': (0x4ee015b, '4881fb7f010000'),
    'return_primary': (0x144d37e, '488b442460488943100f284424500f1103'),
    'return_fallback': (0x144d3a4, '4c89234c897b084c897310'),
    'linkat_arguments': (0x4ee028a, 'bf9cffffffba9cffffff4531c0'),
    'linkat_result': (0x4ee029d, '83f8ff741b31c0'),
    'linkat_errno_encoding': (0x4ee02bd, 'ff1515e688008b0048c1e0204883c802'),
    'long_source_errno_encoding': (0x4ee046b, 'ff1567e488008b0048c1e0204883c802'),
    'long_destination_errno_encoding': (0x4ee04d6, 'ff15fce388008b1848c1e3204883cb02'),
    'stat64_success_tag': (0x4edfcef, '48c70300000000'),
    'stat64_failure_tag': (0x4edfd03, '48c70302000000'),
    'stat64_errno_encoding': (0x4edfd32, 'ff15a0eb88008b0048c1e0204883c802'),
    'stat64_result_copy': (0x4edfcd9, '488d7b20488db530ffffffba90000000ff15f1e2880048c70300000000'),
    'metadata_adapter_selector': (0x4edfc7d, '83bd30ffffff030f8591000000'),
    'long_callback_destination_limit': (0x4ee0322, '4981fe7f010000'),
    'long_input_callback_save': (0x4ee60af, '4889cb'),
    'long_input_niche_test': (0x4ee60c5, '488b75c04889f048f7d87127'),
    'long_input_callback_dispatch': (0x4ee60e2, 'ffd3'),
    'long_input_callback_arguments': (0x4ee60d1, '4c8b7dc84c8b75d04c89e74c89fe4c89f2ffd3'),
    'long_input_after_callback_zero': (0x4ee60e7, '41c60700'),
    'converter_empty_and_short_length': (0x1346521, '4983ff0f77324d85ff'),
    'converter_nul_index_store': (0x134661b, '48894b18'),
    'converter_success_sentinel': (0x134660c, '49be0000000000000080'),
    'converter_finalizer_call': (0x13465fc, '488d7dc0ff15227a42044989c44989d7'),
    'converter_zero_high_mask': (0x134656c, '48ba8080808080808080'),
    'converter_zero_subtract_mask': (0x1346576, '48be0001010101010101'),
    'converter_zero_word_check': (0x134659c, '4921d14921f94939d17544'),
    'long_source_linkat_arguments': (0x4ee043c, '488d8d58feffffbf9cffffff4889deba9cffffff4531c0'),
    'long_destination_linkat_arguments': (0x4ee04b6, '4889f1488b3731dbbf9cffffffba9cffffff4531c0'),
    'tail_backward_separator': (0x4ee9bef, '41807c11ff2f'),
    'tail_empty_tag_and_length': (0x4ee9c15, '41b00a4829c27445'),
    'tail_length_tests': (0x4ee9c1d, '4883fa0174374883fa027536'),
    'tail_two_dot_test': (0x4ee9c29, '80392e753141b0088079012e742b'),
    'tail_one_dot_and_regular': (0x4ee9c5a, '80392e740341b009'),
    'tail_output_fields': (0x4ee9c65, '4889374488470848894f1048895718'),
    'slice_front_separator_test': (0x4ee9d60, '41803c362f7419'),
    'slice_front_dot_test': (0x4ee9d8a, '4883fe01751c41803e2e7516'),
    'slice_back_first_tag': (0x4ee9deb, '80bd68ffffff0a756b'),
    'slice_back_second_tag': (0x4ee9e3b, '80bd68ffffff0a751b'),
    'slice_back_third_tag': (0x4ee9ef4, '80bd68ffffff0a0f855effffff'),
    'slice_return_pair': (0x4ee9e5f, '4c89f04889da'),
}

# Expected relocation edges are checked independently of the selected body
# hashes. This includes external boundaries, not ownership of their bodies.
RELOCATIONS = {
    0x576e928: ('config_global_pointer', 8, 0x577b288, ''),
    0x577b288: ('config_initializer_pointer', 8, 0x164ff00, ''),
    0x576e040: ('format_boundary', 8, 0x1344760, ''),
    0x576e028: ('owned_buffer_finalizer_boundary', 8, 0x1344670, ''),
    0x576e0f8: ('owned_buffer_converter', 8, 0x13464d0, ''),
    0x576e850: ('component_reader_boundary', 8, 0x4f11400, ''),
    0x576ef20: ('component_slice_view', 8, 0x4ee9cb0, ''),
    0x576e3f8: ('utf8_reader_boundary', 8, 0x157a200, ''),
    0x576e8b8: ('once_boundary', 8, 0x4ee3b20, ''),
    0x576e9a0: ('directory_predicate', 8, 0x144a070, ''),
    0x576f610: ('exists_predicate', 8, 0x144a2f0, ''),
    0x576f618: ('metadata_adapter', 8, 0x4edfb40, ''),
    0x576e9e0: ('token_source_boundary', 8, 0x144ada0, ''),
    0x576ebe0: ('configured_temporary_path', 8, 0x144d0d0, ''),
    0x576ef28: ('recursive_directory_boundary', 8, 0x4ed84c0, ''),
    0x576ea68: ('destination_parent_boundary', 8, 0x144c180, ''),
    0x5775ec0: ('link_adapter', 8, 0x4ee0000, ''),
    0x576f498: ('move_boundary', 8, 0x144cf90, ''),
    0x57772d8: ('stat64_import', 6, 0, 'stat64'),
    0x57772e8: ('linkat_import', 6, 0, 'linkat'),
    0x576e8d8: ('errno_import', 6, 0, '__errno_location'),
}

# Each item names an actual RIP-relative LEA site and an expected complete
# Rust-format byte template. The three-byte item is a length-delimited str.
TEMPLATES = {
    'three_argument_path': (0x144d162, bytes.fromhex('c0012fc0012fc000')),
    'fallback_prefix': (0x144d26d, bytes.fromhex('052f746d702fc000')),
    'replacement_token_path': (0x37eab17, bytes.fromhex('1c7574696c735f686172645f6c696e6b5f616e645f7265706c6163652fc000')),
    'directory_error': (0x144a514, bytes.fromhex('0c656e737572655f6469727320c0023a20c000')),
}

CALL_CONTRACTS = {
    'source_metadata': (0x37eaa9d, 0x576f618),
    'destination_metadata': (0x37eaac9, 0x576f618),
    'token_source': (0x37eab00, 0x576e9e0),
    'path_builder': (0x37eab5c, 0x576ebe0),
    'create_link': (0x37eab8d, 0x5775ec0),
    'destination_parent': (0x37eabb2, 0x576ea68),
    'move_to_destination': (0x37eabd0, 0x576f498),
    'primary_parent_predicate': (0x144d219, 0x576e9a0),
    'primary_parent_create': (0x144d23f, 0x576ef28),
    'primary_component_reader': (0x144d1c9, 0x576e850),
    'primary_slice_reader': (0x144d1df, 0x576ef20),
    'primary_utf8_reader': (0x144d1f2, 0x576e3f8),
    'fallback_component_reader': (0x144d2cc, 0x576e850),
    'fallback_slice_reader': (0x144d2e2, 0x576ef20),
    'fallback_utf8_reader': (0x144d2f5, 0x576e3f8),
    'fallback_parent_predicate': (0x144d31c, 0x576e9a0),
    'fallback_parent_create': (0x144d33e, 0x576ef28),
    'first_exists_stat': (0x144a085, 0x576f610),
    'second_directory_stat': (0x144a09a, 0x576f618),
    'exists_metadata': (0x144a309, 0x576f618),
    'stat64': (0x4edfcce, 0x57772d8),
    'linkat': (0x4ee0297, 0x57772e8),
    'long_source_callback_linkat': (0x4ee0453, 0x57772e8),
    'long_destination_callback_linkat': (0x4ee04cb, 0x57772e8),
    'long_owned_buffer_converter': (0x4ee60bf, 0x576e0f8),
    'converter_buffer_finalizer': (0x1346600, 0x576e028),
}

# Fixed RIP-relative callback addresses and direct edges which the long-input
# adapter passes through a register rather than a statically named call.
CALLBACK_CONTRACTS = {
    'source_long_callback': (0x4ee02cf, 0x4ee0300),
    'destination_long_callback': (0x4ee02e7, 0x4ee04b0),
    'both_long_second_callback': (0x4ee0489, 0x4ee04b0),
}
DIRECT_CALL_CONTRACTS = {
    'first_long_input_adapter': (0x4ee02e0, 0x4ee60a0),
    'second_long_input_adapter': (0x4ee049a, 0x4ee60a0),
    'slice_back_first_classifier': (0x4ee9de6, 0x4ee9b80),
    'slice_back_second_classifier': (0x4ee9e36, 0x4ee9b80),
    'slice_back_third_classifier': (0x4ee9eef, 0x4ee9b80),
}


def check_digest(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 94 artifact size or SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.loaded = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2]

    def offset(self, va, size=1, executable=False):
        if va < 0 or size <= 0:
            raise ValueError('negative VA or nonpositive size')
        hits = [s for s in self.loaded if s['address'] <= va and va + size <= s['address'] + s['size']
                and (not executable or s['flags'] & 4)]
        if len(hits) != 1:
            raise ValueError(f'address {va:#x} length {size} is not uniquely file-backed')
        sec = hits[0]
        off = sec['offset'] + va - sec['address']
        if off + size > len(self.data):
            raise ValueError('file-backed section is truncated')
        return off

    def read(self, va, size, executable=False):
        off = self.offset(va, size, executable)
        return self.data[off:off + size]

    def section(self, name):
        found = [s for s in self.sections if s['name'] == name and s['type'] != 8]
        if len(found) != 1:
            raise ValueError(f'missing or ambiguous file-backed section {name}')
        return found[0]

    def relocations(self, slots=None):
        sec = self.section('.rela.dyn')
        if sec['type'] != 4 or sec['size'] % 24:
            raise ValueError('unsupported dynamic relocation table')
        sym = self.section('.dynsym')
        names = self.section('.dynstr')
        slots = set(RELOCATIONS) | (set(slots) if slots is not None else set())
        result = {}
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.data, off)
            if slot not in slots:
                continue
            if slot in result:
                raise ValueError('duplicate selected relocation')
            typ, index = info & 0xffffffff, info >> 32
            if index * 24 + 24 > sym['size']:
                raise ValueError('symbol index out of range')
            noff = struct.unpack_from('<I', self.data, sym['offset'] + index * 24)[0]
            if noff >= names['size']:
                raise ValueError('symbol name outside dynamic string table')
            nstart = names['offset'] + noff
            nend = self.data.find(b'\0', nstart, names['offset'] + names['size'])
            if nend < 0:
                raise ValueError('unterminated dynamic symbol')
            name = self.data[nstart:nend].decode('ascii')
            if typ not in (6, 8) or (typ == 8 and index != 0):
                raise ValueError('unsupported selected relocation')
            self.offset(slot, 8)
            label = 'relative' if typ == 8 else 'dynamic_import'
            if slot in RELOCATIONS:
                label, wanted_type, wanted_addend, wanted_name = RELOCATIONS[slot]
                if (typ, addend, name) != (wanted_type, wanted_addend, wanted_name):
                    raise ValueError(f'relocation contract mismatch for {label}')
            result[slot] = {'label': label, 'type': typ, 'symbol_index': index,
                            'symbol': name, 'addend': addend, 'file_offset': off}
        if set(result) != slots:
            raise ValueError('missing selected dynamic relocation')
        return result


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
        elif (op2 in (0x10, 0x11, 0x1f, 0x28, 0x29, 0x2e, 0x2f, 0x57,
                      0x6f, 0x74, 0x7e, 0x7f, 0xa3, 0xaf, 0xb6, 0xb7,
                      0xbc, 0xbe, 0xbf, 0xd6, 0xdb, 0xdf, 0xeb, 0xef)
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
        if op in (0x80, 0x83, 0x6b, 0xc0, 0xc1, 0xc6):
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


def parse_template(data):
    pos, pieces = 0, []
    while pos < len(data):
        op = data[pos]
        pos += 1
        if op == 0:
            if pos != len(data):
                raise ValueError('bytes follow template terminator')
            return pieces
        if op == 0xc0:
            pieces.append(('argument', ''))
        elif 1 <= op <= 0x7f:
            if pos + op > len(data):
                raise ValueError('truncated literal')
            pieces.append(('literal', data[pos:pos + op].hex()))
            pos += op
        else:
            raise ValueError('unsupported format control')
    raise ValueError('unterminated template')


def component_tag_gate(add_bytes, compare_bytes, tag):
    """Compute the byte gates from the encoded AL add and unsigned compare."""
    if (len(add_bytes) != 2 or add_bytes[0] != 0x04 or
            len(compare_bytes) != 2 or compare_bytes[0] != 0x3c or not 0 <= tag <= 255):
        raise ValueError('invalid component tag gate')
    return ((tag + add_bytes[1]) & 0xff) < compare_bytes[1]


def adapter_length_gate(compare_bytes, length):
    """The selected cmp encodes an unsigned 32-bit short-buffer limit."""
    if (len(compare_bytes) != 7 or compare_bytes[:2] not in (b'\x48\x81', b'\x49\x81')
            or compare_bytes[2] not in (0xfa, 0xff, 0xfb, 0xfe) or not 0 <= length < 1 << 64):
        raise ValueError('invalid adapter length gate')
    limit = struct.unpack_from('<I', compare_bytes, 3)[0]
    return length <= limit


def classify_tail(segment, dot, slash, skip_tag, parent_tag, ordinary_tag):
    """Model the selected final component after separator-delimited slicing."""
    if (not isinstance(segment, bytes) or any(not 0 <= v <= 255 for v in
            (dot, slash, skip_tag, parent_tag, ordinary_tag)) or dot == slash or slash in segment):
        raise ValueError('invalid separator-delimited component')
    if not segment or segment == bytes([dot]):
        return skip_tag
    if segment == bytes([dot, dot]):
        return parent_tag
    return ordinary_tag


def tsv(headers, rows):
    result = io.StringIO(newline='')
    out = csv.writer(result, delimiter='\t', lineterminator='\n')
    out.writerow(headers)
    out.writerows(rows)
    return result.getvalue()


def hx(value):
    return '' if value is None else hex(value)


def validate_contracts(img, instruction_at, relocs):
    """Check the branch and operand contracts after independently decoding bytes."""
    for label, (site, opcode_hex, target) in BRANCH_CONTRACTS.items():
        r = instruction_at.get(site)
        if (r is None or r['kind'] != 'conditional' or
                not r['bytes'].startswith(bytes.fromhex(opcode_hex)) or r['target'] != target):
            raise ValueError(f'branch contract mismatch for {label}')
    for label, (site, target) in CALL_CONTRACTS.items():
        r = instruction_at.get(site)
        if (r is None or r['kind'] != 'indirect_call' or not r['rip_relative'] or
                r['target'] != target or target not in relocs):
            raise ValueError(f'call contract mismatch for {label}')
    for label, (site, target) in CALLBACK_CONTRACTS.items():
        r = instruction_at.get(site)
        if (r is None or r['opcode'][0] != 0x8d or not r['rip_relative'] or r['target'] != target):
            raise ValueError(f'callback address mismatch for {label}')
    for label, (site, target) in DIRECT_CALL_CONTRACTS.items():
        r = instruction_at.get(site)
        if r is None or r['kind'] != 'call' or r['target'] != target:
            raise ValueError(f'direct call mismatch for {label}')
    for label, (site, expected) in WITNESSES.items():
        raw = bytes.fromhex(expected)
        if img.read(site, len(raw), executable=True) != raw or site not in instruction_at:
            raise ValueError(f'instruction contract mismatch for {label}')


def reachable(rows, start, goal, blocked=()):
    """Local normal-return control-flow reachability, without exception edges."""
    by_va = {r['va']: r for r in rows}
    if start not in by_va or goal not in by_va:
        raise ValueError('CFG endpoint is not a decoded instruction')
    blocked, seen, stack = set(blocked), set(), [start]
    while stack:
        va = stack.pop()
        if va in seen or va in blocked or va not in by_va:
            continue
        if va == goal:
            return True
        seen.add(va)
        r = by_va[va]
        if r['kind'] == 'conditional':
            stack.extend((r['target'], r['end']))
        elif r['kind'] == 'jump':
            stack.append(r['target'])
        elif r['kind'] not in ('indirect_jump', 'return', 'trap'):
            stack.append(r['end'])
    return False


def verify_cfg(decodes):
    # Reachability assumes that calls return normally. A false result means no
    # path in this local normal-return graph, not that external code is closed.
    checks = [
        ('same_words_returns', 0x37eaa70, 0x37eaae4, 0x37eac02, (), True),
        ('same_words_bypasses_link', 0x37eaa70, 0x37eaae4, 0x37eab8d, (), False),
        ('metadata_error_reaches_token', 0x37eaa70, 0x37eaaeb, 0x37eab00, (), True),
        ('link_requires_path_builder', 0x37eaa70, 0x37eaa70, 0x37eab8d, (0x37eab5c,), False),
        ('move_requires_link', 0x37eaa70, 0x37eaa70, 0x37eabd0, (0x37eab8d,), False),
        ('move_requires_parent_check', 0x37eaa70, 0x37eaa70, 0x37eabd0, (0x37eabb2,), False),
        ('link_error_bypasses_parent', 0x37eaa70, 0x37eaba2, 0x37eabb2, (), False),
        ('link_error_bypasses_move', 0x37eaa70, 0x37eaba2, 0x37eabd0, (), False),
        ('parent_error_bypasses_move', 0x37eaa70, 0x37eabd6, 0x37eabd0, (), False),
        ('link_success_reaches_parent', 0x37eaa70, 0x37eabac, 0x37eabb2, (), True),
        ('parent_success_reaches_move', 0x37eaa70, 0x37eabbd, 0x37eabd0, (), True),
        ('both_create_errors_return_primary', 0x144d0d0, 0x144d349, 0x144d37e, (), True),
        ('both_create_errors_bypass_fallback_return', 0x144d0d0, 0x144d349, 0x144d3a4, (), False),
        ('primary_return_bypasses_fallback_return', 0x144d0d0, 0x144d37e, 0x144d3a4, (), False),
        ('fallback_return_bypasses_primary_return', 0x144d0d0, 0x144d3a4, 0x144d37e, (), False),
        ('fallback_requires_primary_create', 0x144d0d0, 0x144d0d0, 0x144d26d, (0x144d23f,), False),
        ('primary_create_requires_predicate', 0x144d0d0, 0x144d0d0, 0x144d23f, (0x144d219,), False),
        ('repeat_stat_requires_exists_call', 0x144a070, 0x144a070, 0x144a09a, (0x144a085,), False),
        ('repeat_stat_is_reachable', 0x144a070, 0x144a070, 0x144a09a, (), True),
        ('source_long_bypasses_direct_linkat', 0x4ee0000, 0x4ee02cf, 0x4ee0297, (), False),
        ('destination_long_bypasses_direct_linkat', 0x4ee0000, 0x4ee02e7, 0x4ee0297, (), False),
        ('source_nul_bypasses_direct_linkat', 0x4ee0000, 0x4ee02a6, 0x4ee0297, (), False),
        ('metadata_nul_bypasses_direct_stat64', 0x4edfb40, 0x4edfcf8, 0x4edfcce, (), False),
        ('metadata_non3_bypasses_stat64', 0x4edfb40, 0x4edfd1b, 0x4edfcce, (), False),
        ('metadata_tag3_reaches_stat64', 0x4edfb40, 0x4edfc8a, 0x4edfcce, (), True),
        ('nonsentinel_bypasses_callback', 0x4ee60a0, 0x4ee60f8, 0x4ee60e2, (), False),
        ('sentinel_reaches_callback', 0x4ee60a0, 0x4ee60d1, 0x4ee60e2, (), True),
        ('callback_short_reaches_linkat', 0x4ee0300, 0x4ee043c, 0x4ee0453, (), True),
        ('callback_long_bypasses_direct_linkat', 0x4ee0300, 0x4ee0489, 0x4ee0453, (), False),
        ('callback_nul_bypasses_linkat', 0x4ee0300, 0x4ee0462, 0x4ee0453, (), False),
        ('converter_no_nul_reaches_sentinel', 0x13464d0, 0x13465f0, 0x134660c, (), True),
        ('converter_nul_bypasses_sentinel_store', 0x13464d0, 0x134661b, 0x134660c, (), False),
        ('tail_store_bypasses_ordinary_tag', 0x4ee9b80, 0x4ee9c62, 0x4ee9c5f, (), False),
        ('tail_ordinary_reaches_store', 0x4ee9b80, 0x4ee9c5f, 0x4ee9c65, (), True),
        ('slice_non_skip_bypasses_shrink', 0x4ee9cb0, 0x4ee9e5f, 0x4ee9df7, (), False),
        ('slice_non_skip_returns_pair', 0x4ee9cb0, 0x4ee9e5f, 0x4ee9e74, (), True),
        ('slice_skip_reaches_shrink', 0x4ee9cb0, 0x4ee9df4, 0x4ee9df7, (), True),
    ]
    out = []
    for label, owner, start, goal, blocked, expected in checks:
        actual = reachable(decodes[owner], start, goal, blocked)
        if actual != expected:
            raise ValueError(f'CFG contract mismatch for {label}')
        out.append([label, hx(owner), hx(start), hx(goal), ','.join(map(hx, blocked)),
                    str(expected).lower(), str(actual).lower()])
    return out


def collect(data):
    check_digest(data)
    img = Image(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    found = {f['start']: f for f in fdes if f['start'] in FUNCTIONS}
    if set(found) != set(FUNCTIONS):
        raise ValueError('selected FDE not found')
    index_by_start = {r['start']: r for r in index if r['start'] in FUNCTIONS}
    if set(index_by_start) != set(FUNCTIONS):
        raise ValueError('selected unwind index entry not found')
    decodes, instruction_at = {}, {}
    for start in sorted(FUNCTIONS):
        f = found[start]
        if f['fde'] != index_by_start[start]['fde'] or f['end'] <= start:
            raise ValueError('FDE and unwind index differ')
        raw = img.read(start, f['end'] - start, executable=True)
        decodes[start] = decode_body(raw, start)
        for r in decodes[start]:
            if r['va'] in instruction_at:
                raise ValueError('overlapping selected instruction starts')
            instruction_at[r['va']] = r
    call_slots = {r['target'] for rows in decodes.values() for r in rows
                  if r['kind'] in ('indirect_call', 'indirect_jump') and r['rip_relative']}
    relocs = img.relocations(call_slots)

    validate_contracts(img, instruction_at, relocs)
    cfg_checks = verify_cfg(decodes)

    functions, instructions, transfers, bindings = [], [], [], []
    for start in sorted(FUNCTIONS):
        f, rows = found[start], decodes[start]
        raw = img.read(start, f['end'] - start, executable=True)
        functions.append([FUNCTIONS[start], hx(start), hx(f['end']), hx(f['fde']), hx(f['cie']),
                          hx(f['lsda']), hx(img.offset(start, len(raw), True)), len(raw), len(rows),
                          hashlib.sha256(raw).hexdigest()])
        for row in rows:
            instructions.append([FUNCTIONS[start], hx(row['va']), hx(img.offset(row['va'], len(row['bytes']), True)),
                                 len(row['bytes']), row['bytes'].hex(), row['kind'], hx(row['target'])])
            if row['kind'] in ('conditional', 'jump', 'call', 'indirect_call', 'indirect_jump', 'return', 'trap'):
                target = row['target']
                resolution = relocs.get(target) if row['rip_relative'] else None
                transfers.append([FUNCTIONS[start], hx(row['va']), row['bytes'].hex(), row['kind'],
                                  hx(target), hx(row['end']) if row['kind'] in ('conditional', 'call', 'indirect_call') else '',
                                  resolution['label'] if resolution else '',
                                  hx(resolution['addend']) if resolution and resolution['type'] == 8 else '',
                                  resolution['symbol'] if resolution else ''])
    for slot in sorted(relocs):
        r = relocs[slot]
        bindings.append([r['label'], hx(slot), hx(r['file_offset']), r['type'], r['symbol_index'], r['symbol'], hx(r['addend'])])
    templates = []
    for label, (site, expected) in TEMPLATES.items():
        r = instruction_at.get(site)
        if r is None or r['opcode'][0] != 0x8d or not r['rip_relative']:
            raise ValueError(f'template reference is not a RIP-relative lea: {label}')
        raw = img.read(r['target'], len(expected))
        if raw != expected:
            raise ValueError(f'template bytes mismatch: {label}')
        pieces = parse_template(raw)
        templates.append([label, hx(site), r['bytes'].hex(), hx(r['target']), hx(img.offset(r['target'], len(raw))),
                          raw.hex(), '|'.join(k if not v else k + ':' + v for k, v in pieces)])
    r = instruction_at.get(0x144d0f4)
    if r is None or img.read(r['target'], 3) != bytes.fromhex('746d70'):
        raise ValueError('temporary component slice mismatch')
    templates.append(['temporary_component', hx(r['va']), r['bytes'].hex(), hx(r['target']),
                      hx(img.offset(r['target'], 3)), img.read(r['target'], 3).hex(), 'literal:746d70'])
    witnesses = [[label, hx(site), hx(img.offset(site, len(bytes.fromhex(raw)), True)),
                  img.read(site, len(bytes.fromhex(raw)), True).hex()]
                 for label, (site, raw) in WITNESSES.items()]
    branches = [[label, hx(site), instruction_at[site]['bytes'].hex(), hx(instruction_at[site]['end']),
                 hx(instruction_at[site]['target'])] for label, (site, _, _) in BRANCH_CONTRACTS.items()]
    tags = []
    for label, addsite, cmpsite in (('primary', 0x144d1d4, 0x144d1d6),
                                    ('fallback', 0x144d2d7, 0x144d2d9)):
        add, compare = img.read(addsite, 2, True), img.read(cmpsite, 2, True)
        for tag in range(256):
            candidate = component_tag_gate(add, compare, tag)
            tags.append([label, hx(addsite), add.hex(), hx(cmpsite), compare.hex(), tag,
                         'inspect_slice' if candidate else 'keep_input_slice'])
    lengths = []
    for label, site in (('metadata', 0x4edfb56), ('link_source', 0x4ee0020),
                        ('link_destination', 0x4ee015b), ('long_callback_destination', 0x4ee0322)):
        compare = img.read(site, 7, True)
        limit = struct.unpack_from('<I', compare, 3)[0]
        for length in sorted({0, 1, limit - 1, limit, limit + 1, limit + 2}):
            is_short = adapter_length_gate(compare, length)
            lengths.append([label, hx(site), compare.hex(), limit, length,
                            'short_buffer' if is_short else 'long_helper'])
    callbacks = []
    for label, (site, _) in CALLBACK_CONTRACTS.items():
        r = instruction_at[site]
        callbacks.append([label, hx(site), r['bytes'].hex(), hx(r['target'])])
    for label, (site, _) in DIRECT_CALL_CONTRACTS.items():
        r = instruction_at[site]
        callbacks.append([label, hx(site), r['bytes'].hex(), hx(r['target'])])
    link_cases = build_link_cases(img)
    tail_rows = build_tail_cases(img)
    cases = build_cases()
    summary = {
        'artifact_sha256': DIGEST,
        'artifact_size': len(data),
        'coordinates': 'linked ELF virtual addresses; file offsets are separate',
        'selected_fde_count': len(functions),
        'selected_bytes': sum(f['end'] - f['start'] for f in found.values()),
        'decoded_instructions': len(instructions),
        'transfers': len(transfers),
        'conditional_branches': sum(r['kind'] == 'conditional' for v in decodes.values() for r in v),
        'named_branch_contracts': len(branches),
        'named_call_contracts': len(CALL_CONTRACTS),
        'callback_and_direct_contracts': len(callbacks),
        'cfg_contracts': len(cfg_checks),
        'resolved_relocations': len(bindings),
        'named_relocation_contracts': len(RELOCATIONS),
        'format_templates_and_slice': len(templates),
        'component_gate_rows': len(tags),
        'length_boundary_rows': len(lengths),
        'long_link_cases': len(link_cases),
        'tail_component_cases': len(tail_rows),
        'static_cases': len(cases),
        'limitations': 'FDE extents are unwind ranges; external helpers, exceptions, live filesystem state, dynamic dispatch and target execution are outside the model.',
    }
    return {
        'functions.tsv': tsv(['role','start_va','end_va','fde_va','cie_va','lsda_va','file_offset','bytes','instructions','sha256'], functions),
        'instructions.tsv': tsv(['function','site_va','file_offset','length','bytes','kind','target_va'], instructions),
        'transfers.tsv': tsv(['function','site_va','bytes','kind','target_or_slot','fallthrough_va','binding','relative_addend','symbol'], transfers),
        'relocations.tsv': tsv(['binding','slot_va','rela_file_offset','type','symbol_index','symbol','addend'], bindings),
        'templates.tsv': tsv(['label','site_va','instruction','target_va','file_offset','bytes','pieces'], templates),
        'witnesses.tsv': tsv(['label','site_va','file_offset','bytes'], witnesses),
        'branches.tsv': tsv(['label','site_va','bytes','fallthrough_va','target_va'], branches),
        'component-tags.tsv': tsv(['path','add_site_va','add_bytes','compare_site_va','compare_bytes','tag_byte','route'], tags),
        'adapter-lengths.tsv': tsv(['adapter','compare_site_va','compare_bytes','short_maximum','length','route'], lengths),
        'callback-edges.tsv': tsv(['label','site_va','bytes','target_va'], callbacks),
        'long-link-cases.tsv': tsv(['source_length','destination_length','source_converter','destination_converter','route','linkat_site'], link_cases),
        'tail-components.tsv': tsv(['component_hex','length','dot_byte','separator_byte','skip_tag','parent_tag','ordinary_tag','predicted_tag'], tail_rows),
        'cfg.tsv': tsv(['label','function_start','start_va','goal_va','blocked_va','expected_reachable','observed_reachable'], cfg_checks),
        'cases.tsv': tsv(['scenario','source_stat','destination_stat','word0_equal','word1_equal','primary_candidate','fallback_candidate','link','destination_parent','move','predicted_trace','result_boundary'], cases),
        'summary.json': json.dumps(summary, indent=2, sort_keys=True) + '\n',
    }


def predict_route(src, dst, word0, word1, primary, fallback, link, parent, move):
    """Conditional transfer model. External calls and callbacks must return normally."""
    domains = ((src, {'ok', 'error'}), (dst, {'ok', 'error', '-'}),
               (word0, {'yes', 'no', '-'}), (word1, {'yes', 'no', '-'}),
               (primary, {'present', 'created', 'failed', '-'}),
               (fallback, {'present', 'created', 'failed', '-'}),
               (link, {'ok', 'error', '-'}), (parent, {'ok', 'error', '-'}),
               (move, {'ok', 'error', '-'}))
    if any(value not in domain for value, domain in domains):
        raise ValueError('invalid abstract status')
    trace = ['stat_source']
    if src == 'error':
        if (dst, word0, word1) != ('-', '-', '-'):
            raise ValueError('source failure bypasses destination and comparisons')
        trace.append('metadata_error_callback')
    else:
        if dst == '-':
            raise ValueError('source success requires destination status')
        trace.append('stat_destination')
        if dst == 'error':
            if (word0, word1) != ('-', '-'):
                raise ValueError('destination failure bypasses comparisons')
            trace.append('metadata_error_callback')
        elif word0 == 'no':
            if word1 != '-':
                raise ValueError('different first word bypasses second comparison')
        elif word0 == 'yes':
            if word1 == 'yes':
                if (primary, fallback, link, parent, move) != ('-', '-', '-', '-', '-'):
                    raise ValueError('equal metadata bypasses path construction')
                return '>'.join(trace + ['return_zero']), 'zero'
            if word1 != 'no':
                raise ValueError('second metadata word must be compared')
        else:
            raise ValueError('two successful metadata results require comparison')
    if primary == '-':
        raise ValueError('replacement requires primary candidate status')
    trace.append('primary_candidate_' + primary)
    if primary == 'failed':
        if fallback == '-':
            raise ValueError('primary create failure requires fallback candidate')
        trace.append('fallback_candidate_' + fallback)
        selected = 'primary' if fallback == 'failed' else 'fallback'
        if fallback == 'failed':
            trace.append('two_error_callbacks')
    else:
        if fallback != '-':
            raise ValueError('successful primary bypasses fallback')
        selected = 'primary'
    trace.append('select_' + selected)
    if link == 'error':
        if (parent, move) != ('-', '-'):
            raise ValueError('link error bypasses parent and move')
        return '>'.join(trace + ['link_error']), 'link_error_boundary'
    if link != 'ok':
        raise ValueError('replacement requires link result')
    trace.append('link_ok')
    if parent == 'error':
        if move != '-':
            raise ValueError('parent error bypasses move')
        return '>'.join(trace + ['destination_parent_error']), 'parent_error_boundary'
    if parent != 'ok' or move not in ('ok', 'error'):
        raise ValueError('successful link requires parent and move result')
    return '>'.join(trace + ['destination_parent_ok', 'move_' + move]), 'move_result'


def build_cases():
    # These cases are abstract branch predictions, not execution of node code.
    # Candidate outcomes: 'present', 'created' or 'failed'. A dash is bypassed.
    cases = []
    def add(name, src='ok', dst='ok', w0='yes', w1='yes', primary='-', fallback='-',
            link='-', parent='-', move='-'):
        trace, result = predict_route(src, dst, w0, w1, primary, fallback, link, parent, move)
        cases.append([name, src, dst, w0, w1, primary, fallback, link, parent, move, trace, result])
    add('same_words')
    # A failed first metadata read bypasses the second. On either metadata error
    # or differing words the local entry proceeds to token/path construction.
    entries = [('source_error','error','-', '-', '-'),
               ('destination_error','ok','error','-', '-'),
               ('first_word_diff','ok','ok','no','-'),
               ('second_word_diff','ok','ok','yes','no')]
    for name, src, dst, w0, w1 in entries:
        add(name, src, dst, w0, w1, 'present', '-', 'ok', 'ok', 'ok')
    for primary in ('present','created','failed'):
        for fallback in (('present','created','failed') if primary == 'failed' else ('-',)):
            for link in ('error','ok'):
                if link == 'error':
                    add(f'{primary}_{fallback}_link_error','ok','ok','no','-',primary,fallback,link,'-','-')
                else:
                    for parent in ('error','ok'):
                        if parent == 'error':
                            add(f'{primary}_{fallback}_parent_error','ok','ok','no','-',primary,fallback,link,parent,'-')
                        else:
                            for move in ('error','ok'):
                                add(f'{primary}_{fallback}_move_{move}','ok','ok','no','-',primary,fallback,link,parent,move)
    return cases


def predict_link_route(source_length, destination_length, source_result, destination_result, limit):
    """Select local linkat site under the two converter-result assumptions."""
    if not (0 <= source_length < 1 << 64 and 0 <= destination_length < 1 << 64 and 0 <= limit < 1 << 31):
        raise ValueError('invalid length domain')
    valid = {'-', 'sentinel', 'non_sentinel'}
    if source_result not in valid or destination_result not in valid:
        raise ValueError('invalid converter result')
    source_long = source_length > limit
    destination_long = destination_length > limit
    if not source_long and source_result != '-':
        raise ValueError('short source bypasses its converter')
    if source_long and source_result == '-':
        raise ValueError('long source requires converter result')
    if source_long and source_result == 'non_sentinel':
        if destination_result != '-':
            raise ValueError('source converter failure bypasses destination')
        return 'source_conversion_boundary', ''
    if not destination_long and destination_result != '-':
        raise ValueError('short destination bypasses its converter')
    if destination_long and destination_result == '-':
        raise ValueError('long destination requires converter result')
    if destination_long and destination_result == 'non_sentinel':
        return 'destination_conversion_boundary', ''
    if destination_long:
        return 'long_destination_callback', hx(CALL_CONTRACTS['long_destination_callback_linkat'][0])
    if source_long:
        return 'long_source_callback', hx(CALL_CONTRACTS['long_source_callback_linkat'][0])
    return 'direct_short', hx(CALL_CONTRACTS['linkat'][0])


def build_link_cases(img):
    compares = [img.read(site, 7, True) for site in (0x4ee0020, 0x4ee015b, 0x4ee0322)]
    limits = [struct.unpack_from('<I', data, 3)[0] for data in compares]
    if len(set(limits)) != 1:
        raise ValueError('link adapter length limits differ')
    limit = limits[0]
    out = []
    for source_length in (0, limit, limit + 1):
        for destination_length in (0, limit, limit + 1):
            source_states = ('sentinel', 'non_sentinel') if source_length > limit else ('-',)
            for source_result in source_states:
                if source_result == 'non_sentinel':
                    destination_states = ('-',)
                else:
                    destination_states = ('sentinel', 'non_sentinel') if destination_length > limit else ('-',)
                for destination_result in destination_states:
                    route, site = predict_link_route(source_length, destination_length,
                                                     source_result, destination_result, limit)
                    out.append([source_length, destination_length, source_result, destination_result, route, site])
    return out


def build_tail_cases(img):
    dot = img.read(0x4ee9c2b, 1, True)[0]
    if img.read(0x4ee9c34, 1, True)[0] != dot or img.read(0x4ee9c5c, 1, True)[0] != dot:
        raise ValueError('dot comparisons disagree')
    slash = img.read(0x4ee9bf4, 1, True)[0]
    skip_tag = img.read(0x4ee9c17, 1, True)[0]
    parent_tag = img.read(0x4ee9c30, 1, True)[0]
    ordinary_tag = img.read(0x4ee9c61, 1, True)[0]
    if len({skip_tag, parent_tag, ordinary_tag}) != 3:
        raise ValueError('component outcome tags are not distinct')
    examples = (b'', bytes([dot]), bytes([dot, dot]), bytes([dot]) * 3,
                b'a', bytes([dot]) + b'a', b'a' + bytes([dot]), b'\0', b'\xff')
    rows = []
    for segment in examples:
        result = classify_tail(segment, dot, slash, skip_tag, parent_tag, ordinary_tag)
        rows.append([segment.hex(), len(segment), hx(dot), hx(slash), skip_tag,
                     parent_tag, ordinary_tag, result])
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    outputs = collect(ARTIFACT.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(outputs):
        (args.out / name).write_text(outputs[name], encoding='utf-8', newline='\n')
    print(f'wrote {len(outputs)} evidence files')


if __name__ == '__main__':
    main()
