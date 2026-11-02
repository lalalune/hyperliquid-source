#!/usr/bin/env python3
"""Extract a bounded node-115 private-provider and scaled-precompile route.

This is static analysis only. It reads the authenticated ELF as data, uses the
repository's ELF/FDE readers, and does not launch a disassembler or the node.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import struct
from pathlib import Path

from elf_index import sections
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ADDR09 = bytes(19) + b'\x09'
U64_MAX = (1 << 64) - 1

# These are selected FDE starts, not a census or validated source boundaries.
FUNCTIONS = {
    0x2962aa0: 'context and frame driver',
    0x29837a0: 'alternate call frame',
    0x2a07040: 'upstream context assembly and driver call',
    0x2a6ab20: 'alternate precompile routing',
    0x38be030: 'private-key dispatcher',
    0x38be800: 'provider constructor',
    0x4200a50: 'address enumeration switch',
    0x433dc40: 'activation flag construction',
    0x46a0eb0: 'scaled-callback selector',
}

# Fixed opcode windows selected after manual instruction inspection. The table
# is deliberately bounded: it does not purport to decode the entire FDEs.
WINDOWS = [
 ('upstream_argument_capture',0x2a07060,'4989d64989f748897c2418'),
 ('upstream_state_and_constructor_call',0x2a0713c,'4981c6781c000040b501488dbc24200b0000488d9424e0000000be010000004c89f1ff15acfcad03'),
 ('upstream_flag_first_copy',0x2a07164,'488b8424200d00004889842430010000'),
 ('upstream_flag_second_copy',0x2a071d6,'488b8c243001000048898c2450090000'),
 ('upstream_driver_argument',0x2a07b22,'488db424f8080000488d9424680900004c89f14d89e8e863aff5ff'),
 ('entry_arguments',0x2962ac0,'4c894424304989cd4989d64889f3'),
 ('incoming_revision_copy',0x2962ad6,'0f1081400100000f298424800f0000'),
 ('revision_from_fourth_argument',0x2962b45,'440fb6a424880f0000'),
 ('save_second_argument',0x2962b5c,'48895c2458'),
 ('restore_second_argument_case_a',0x2962f2a,'4c8b7c2458'),
 ('restore_second_argument_case_b',0x2962f79,'4c8b7c2458'),
 ('save_revision',0x2962d50,'4488642420'),
 ('provider_input_and_constructor',0x2963184,'4983c708410fb6f4488dbc24600700004c89faff15433bb803'),
 ('context_base_initial_copy',0x2963233,'488dbc24f00f0000488db424400b0000bae0030000ff15bac2b703'),
 ('provider_flag_copy',0x296331a,'0f108424e00700000f29842450140000'),
 ('first_frame_context_argument',0x2964585,'488db424f00f0000488d9424900f0000e806f20100'),
 ('second_frame_context_argument',0x2964fe6,'488db424f00f0000488d942460180000e8a5e70100'),
 ('provider_input_mode_and_table',0x38be80a,'4889d389f54989fe400fb6c5488d0d672feefc0fb6040888442420488d0440c1e005'),
 ('provider_once_slot_index',0x38be825,'488d0440c1e005488d0d3df8c3024c8d3c018b44085885c00f8560030000'),
 ('provider_initial_set_and_reserve',0x38be843,'498d7728488d7c2420e83f5a600048837c243800b815000000be0b000000480f44f0483b7424300f8745030000'),
 ('provider_reserve_choice',0x38be851,'48837c243800b815000000be0b000000480f44f0483b7424300f8745030000'),
 ('provider_publish_set',0x38beb3a,'488b442440498946300f104424200f104c2430410f114e20410f1146104d893e41886e08'),
 ('provider_copy_configuration',0x38beb57,'4d893e41886e080f10030f104b100f1053200f105b30410f114638410f114e48410f115658410f115e680f104340410f114678488b435049898688000000'),
 ('provider_once_call',0x38beba3,'488d7424204c89ffe868f73202e98efcffff'),
 ('provider_grow_call',0x38bebb5,'488d542440488d7c2420b901000000ff151ea9c202e9a1fcffff'),
 ('frame_transition_state_subobject',0x2983dae,'488db370020000'),
 ('frame_variant',0x2983ded,'4883fa01746f4883fa020f85601d0000'),
 ('frame_depth_guard',0x2983eab,'4981fe010400008844242748894c24380f8293000000'),
 ('frame_checkpoint',0x2983f54,'488b5424184c8baa80020000488b8298020000488b8ab00200004c89ac2438020000488984244002000048898c2448020000488b82880300004883f8ff0f845d1d00004989f748ffc048898288030000'),
 ('frame_value_variant',0x2983fa4,'837d0001747a'),
 ('frame_value_inputs',0x2983faa,'0f1045080f104d180f298c24c00400000f298424b00400008b85c8000000898424600200000f1085b80000000f298424500200008b85b4000000898424a00000000f1085a40000000f29842490000000488db42450020000488d942490000000488d8c24b00400004c89ffe836c7feff89c33c030f85f0040000'),
 ('frame_provider_context',0x29842b6,'4c89f3488b542418488db2e0030000'),
 ('frame_precompile_call_arguments',0x2984351,'0fb685cc00000088442410488b85800000004889442408488dbc24900000004889e9e8a8670e00'),
 ('frame_output_special_tag',0x2984398,'80f938753b'),
 ('frame_output_miss',0x2984434,'84c90f8465040000'),
 ('frame_result_disposition',0x29844df,'807c2420050f8340050000488b4c2418488b81880300004883f801'),
 ('frame_value_failure_and_status',0x2984514,'488db424380200004c89ffe8bccbfeffc0e303b812302f0089d9d3e889442420'),
 ('frame_result_revert_call',0x2984a97,'488db424380200004c89ffe839c6feff'),
 ('lookup_key_copy',0x2a6ab3f,'4c8da9900000008b81a0000000898424b0010000f30f6f8190000000660f7f8424a0010000'),
 ('scaled_feature_and_selector',0x2a6ab64,'80be880000000074304c89efff15c2c5a7034885c07422'),
 ('scaled_callback_and_divisor',0x2a6ab7b,'4989c04989d44d8b6e50498b4e604d85ed0f844c010000498b765831ede9b6040000'),
 ('private_iterator_slot',0x2a6abcc,'488b1d6dc5a703'),
 ('private_iterator_limit',0x2a6abe0,'4883fe1e74684c8d66014c89ffffd3'),
 ('full_address_comparison',0x2a6abef,'f30f6f442440660f6e4c2450660f6e942410010000660f74d1660f74842400010000660fdbc2660fd7c04c89e63dffff000075bd'),
 ('private_index_filter',0x2a6ac23,'4180c4f94180fc157321'),
 ('generic_lookup_and_miss',0x2a6ac4e,'488b7d004c89eee8061700004885c0488b5c24307423'),
 ('scaled_input_slice_checks',0x2a6acde,'488b442408488b80b8030000488b501048beffffffffffffff7f4839f20f83b1090000498b76584c8d7810488d7a01488978104889cf4829f70f8229030000483b48280f871f0300004803702031ed4889f9e91e030000'),
 ('scaled_invalid_slice_restores_counter',0x2a6b046,'498917be0100000040b50131c9'),
 ('generic_indirect_callback',0x2a6ad99,'498b8e800000004d8b8688000000488d7c2440ff5018'),
 ('gas_division_and_scaled_callback',0x2a6b053,'498b86800000004889c24c09e248c1ea20740731d249f7f4eb0531d241f7f4488d7c24404889ca4889c141ffd0'),
 ('scaled_output_tag',0x2a6b080,'488b4c24400f104424480f29842400010000488b44245848898424100100004885c9747f'),
 ('scaled_output_multiply',0x2a6b0a4,'4c89e048f7642460'),
 ('scaled_output_overflow',0x2a6b0cc,'0f8014060000'),
 ('scaled_borrowed_counter_release',0x2a6b143,'4d85ed0f95c24008ea758f49ff0f'),
 ('private_dispatch_slot',0x2a6b1e8,'488b7424284d8b8e80000000488d7c2440488d9424a0010000ff1541bfa703'),
 ('result_converter_slot',0x2a6b697,'ff15b3baa703'),
 ('overflow_saturates',0x2a6b6e6,'48c7c0ffffffff4d85ed0f95c24008ea0f85e1f9ffff'),
 ('scaled_callback_unwind_cleanup',0x2a6b73f,'4889c34d85ed0f95c04008e8754249ff0f4889dfe8f8529803'),
 ('private_tree_input',0x38be393,'4889742420488b46384c8b384d85ff0f84ad0000004c8b6008'),
 ('private_tree_search',0x38be3e0,'4885db743b488d6e14ba140000004c89d741ffd54c8b54241848984885c00f98c10f9fc028c849ffc64883c3ec4889ee3c0174cc0fb6c085c0'),
 ('private_existing_key_result',0x38be438,'488b5c241048c743080000000048b8010000000000008048894310eb25'),
 ('private_callback_call',0x38be455,'488b5c2410488d7b08488b742420488b542428488b4c24304c8b442438488b442408ff5018b80100'),
 ('address_iterator_prologue',0x4200a50,'4889f8400fb6ce488d15ea6a5cfc48630c8a4801d1ffe1'),
 ('address_iterator_write',0x4200d79,'8b4c24f88948100f284424e80f1100c3'),
 ('activation_argument',0x433dc51,'4989ce897424444c8b0a'),
 ('activation_save_state',0x433dd1f,'4c89742438'),
 ('activation_counter_and_overflow',0x433de23,'488b442438488b98601d00004883fbff0f84dd080000'),
 ('activation_counter_increment',0x433de93,'48ffc3'),
 ('activation_save_counter',0x433df24,'48896c24204c8974244848895c2450'),
 ('activation_restore_state_and_counter',0x433e173,'488b5c24584c8b7c24384c8b642450488b742448'),
 ('activation_restore_state_and_counter_alt_a',0x433e29b,'488b5c24584c8b7c24384c8b04244c8b642450'),
 ('activation_restore_state_and_counter_alt_b',0x433e2d6,'488b5c24584c8b7c24384c8b04244c8b642450'),
 ('activation_tag_threshold',0x433e5e7,'4183bfb81e000001752531c04d3ba7c01e0000b9000000004819c9b9000000004819c94819c00f93c089442410eb08c744241000000000'),
 ('activation_output_byte',0x433e6f7,'8b442410888300020000'),
 ('activation_overflow_failure',0x433e716,'488d3df30d1502ff15fd0d1a020f0b'),
]

# (label, instruction VA, expected instruction kind, expected relative target).
# Only direct branches/calls selected for this question are listed.
EDGES = [
 ('upstream_driver_call',0x2a07b38,'call',0x2962aa0),
 ('activation_counter_overflow',0x433de33,'jcc',0x433e716),
 ('activation_tag_not_one',0x433e5ef,'jcc',0x433e616),
 ('activation_flag_join',0x433e614,'jmp',0x433e61e),
 ('first_frame',0x2964595,'call',0x29837a0),('second_frame',0x2964ff6,'call',0x29837a0),
 ('frame_kind_one',0x2983df1,'jcc',0x2983e62),('frame_other_kind',0x2983df7,'jcc',0x2985b5d),
 ('frame_depth_allowed',0x2983ebb,'jcc',0x2983f54),('frame_depth_overflow',0x2983f91,'jcc',0x2985cf4),
 ('frame_skip_value_transition',0x2983fa8,'jcc',0x2984024),('frame_value_transition',0x2984015,'call',0x2970750),
 ('frame_value_failure',0x298401e,'jcc',0x2984514),('frame_direct_input',0x2984079,'jcc',0x29842b0),
 ('frame_input_join',0x29840ad,'jmp',0x29842b6),('frame_dispatch',0x2984373,'call',0x2a6ab20),
 ('frame_special_tag',0x298439b,'jcc',0x29843d8),('frame_dispatch_miss',0x2984436,'jcc',0x29848a1),
 ('frame_status_revert',0x29844e4,'jcc',0x2984a2a),('frame_value_revert',0x298451f,'call',0x29710e0),
 ('frame_result_revert',0x2984aa2,'call',0x29710e0),
 ('frame_inspection_boundary',0x29837da,'call',0x22d8eb0),('frame_inspection_early_result',0x29837fd,'jcc',0x298387a),
 ('frame_inspection_early_callback',0x29838ab,'call',0x22d94a0),('frame_inspection_input_drop',0x29838ce,'call',0x29f0690),
 ('scaled_flag_clear',0x2a6ab6b,'jcc',0x2a6ab9d),('scaled_selector_miss',0x2a6ab79,'jcc',0x2a6ab9d),
 ('scaled_input_borrowed',0x2a6ab8c,'jcc',0x2a6acde),('scaled_input_direct',0x2a6ab98,'jmp',0x2a6b053),
 ('enumeration_complete',0x2a6abe4,'jcc',0x2a6ac4e),('enumeration_next',0x2a6ac21,'jcc',0x2a6abe0),
 ('enumeration_not_private',0x2a6ac2b,'jcc',0x2a6ac4e),('private_borrowed_input',0x2a6ac3d,'jcc',0x2a6ad35),
 ('private_direct_input',0x2a6ac49,'jmp',0x2a6b1e8),('generic_registry_lookup',0x2a6ac55,'call',0x2a6c360),
 ('generic_lookup_miss',0x2a6ac62,'jcc',0x2a6ac87),('scaled_divide_32',0x2a6b064,'jcc',0x2a6b06d),
 ('scaled_input_counter_limit',0x2a6acfb,'jcc',0x2a6b6b2),('scaled_input_range_underflow',0x2a6ad17,'jcc',0x2a6b046),
 ('scaled_input_range_overrun',0x2a6ad21,'jcc',0x2a6b046),('scaled_input_range_valid',0x2a6ad30,'jmp',0x2a6b053),
 ('scaled_divide_join',0x2a6b06b,'jmp',0x2a6b072),('scaled_callback_error',0x2a6b0a2,'jcc',0x2a6b123),
 ('scaled_multiply_overflow',0x2a6b0cc,'jcc',0x2a6b6e6),
 ('scaled_unwind_skips_counter',0x2a6b74b,'jcc',0x2a6b78f),('scaled_unwind_resume',0x2a6b753,'call',0x63f0a50),
 ('provider_once_needed',0x38be83d,'jcc',0x38beba3),('provider_once_boundary',0x38bebab,'call',0x5bee318),
 ('provider_initial_set_boundary',0x38be84c,'call',0x3ec4290),('provider_grow_needed',0x38be86a,'jcc',0x38bebb5),
 ('provider_grow_rejoin',0x38bebca,'jmp',0x38be870),
 ('private_tree_empty',0x38be3a2,'jcc',0x38be455),('private_tree_end',0x38be3e3,'jcc',0x38be420),
 ('private_tree_next_key',0x38be412,'jcc',0x38be3e0),('private_tree_next_child',0x38be419,'jcc',0x38be425),
 ('private_tree_equal',0x38be41b,'jmp',0x38be438),('private_tree_no_child',0x38be429,'jcc',0x38be455),
 ('private_tree_descend',0x38be433,'jmp',0x38be3b3),('private_existing_result',0x38be453,'jmp',0x38be47a),
]

# RIP-relative instructions and their relocation slots. The target code at a
# relocated slot remains an endpoint unless also listed in FUNCTIONS.
RIP = [
 ('upstream_activation_constructor',0x2a0715e,'ff15',0x64e6e10),
 ('context_provider_constructor',0x2963197,'ff15',0x64e6ce0),
 ('provider_revision_table',0x38be816,'488d0d',0x7a1784),
 ('provider_once_slots',0x38be82c,'488d0d',0x64fe070),
 ('scaled_selector_slot',0x2a6ab70,'ff15',0x64e7138),
 ('private_iterator_slot',0x2a6abcc,'488b1d',0x64e7140),
 ('private_dispatch_slot',0x2a6b201,'ff15',0x64e7148),
 ('result_converter_slot',0x2a6b697,'ff15',0x64e7150),
 ('address_switch_table',0x4200a57,'488d15',0x7c7548),
 ('unwind_resume_plt_slot',0x63f0a50,'ff25',0x64ee178),
]
RELA_SLOTS = [0x64e6e10,0x64e6ce0,0x64e7138,0x64e7140,0x64e7148,0x64e7150]


def authenticate(data: bytes) -> None:
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('node 115 SHA-256 mismatch')


def read_va(data: bytes, sec: list[dict], va: int, size: int) -> tuple[bytes, int, str]:
    if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
        raise ValueError('invalid virtual range')
    matches = [s for s in sec if s['type'] != 8 and s['size'] and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('virtual range is not uniquely file-backed')
    s = matches[0]
    off = s['offset'] + va - s['address']
    if off < 0 or off + size > len(data):
        raise ValueError('virtual range extends past file')
    return data[off:off + size], off, s['name']


def need(actual: bytes, expected: bytes, label: str) -> None:
    if actual != expected:
        raise ValueError('changed byte predicate: ' + label)


def relative_target(va: int, insn: bytes, kind: str) -> int:
    if len(insn) == 5 and insn[0] in (0xe8, 0xe9):
        actual = 'call' if insn[0] == 0xe8 else 'jmp'
        delta = struct.unpack_from('<i', insn, 1)[0]
    elif len(insn) == 2 and (insn[0] == 0xeb or 0x70 <= insn[0] <= 0x7f):
        actual = 'jmp' if insn[0] == 0xeb else 'jcc'
        delta = struct.unpack_from('<b', insn, 1)[0]
    elif len(insn) == 6 and insn[0] == 0x0f and 0x80 <= insn[1] <= 0x8f:
        actual = 'jcc'
        delta = struct.unpack_from('<i', insn, 2)[0]
    else:
        raise ValueError('unsupported relative instruction')
    if kind != actual:
        raise ValueError('relative instruction kind mismatch')
    return va + len(insn) + delta


def read_edge(data, sec, va, kind):
    prefix = read_va(data, sec, va, 1)[0][0]
    n = 6 if prefix == 0x0f else (5 if prefix in (0xe8, 0xe9) else 2)
    raw, off, name = read_va(data, sec, va, n)
    return relative_target(va, raw, kind), raw, off, name


def rip_target(va: int, raw: bytes, prefix: bytes) -> int:
    if len(raw) != len(prefix) + 4 or not raw.startswith(prefix):
        raise ValueError('changed RIP-relative instruction')
    return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]


def relative_relocations(data: bytes, sec: list[dict], slots: set[int]) -> dict[int, dict]:
    result = {}
    for s in sec:
        if s['type'] != 4:
            continue
        if s['size'] % 24 or s['offset'] + s['size'] > len(data):
            raise ValueError('malformed RELA section')
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            if slot not in slots:
                continue
            if slot in result:
                raise ValueError('duplicate relocation')
            if info != 8 or addend < 0:
                raise ValueError('expected symbol-free R_X86_64_RELATIVE')
            result[slot] = {'slot_va': hex(slot), 'section': s['name'], 'file_offset': hex(off),
                            'type': 8, 'symbol': 0, 'addend_va': hex(addend),
                            'raw_hex': data[off:off + 24].hex()}
    if set(result) != slots:
        raise ValueError('missing relative relocation')
    return result


def dynamic_symbol_relocation(data, sec, slot, expected_name, expected_type=6):
    """Resolve one symbol-bearing ELF64 RELA entry using shared section metadata."""
    tables = [s for s in sec if s['name'] == '.dynsym' and s['type'] == 11]
    strings = [s for s in sec if s['name'] == '.dynstr' and s['type'] == 3]
    if len(tables) != 1 or len(strings) != 1:
        raise ValueError('dynamic symbol or string table missing/ambiguous')
    table, string_table = tables[0], strings[0]
    if table['size'] % 24 or table['offset'] + table['size'] > len(data):
        raise ValueError('malformed dynamic symbol table')
    if string_table['offset'] + string_table['size'] > len(data):
        raise ValueError('malformed dynamic string table')
    matches = []
    for s in sec:
        if s['type'] != 4:
            continue
        if s['size'] % 24 or s['offset'] + s['size'] > len(data):
            raise ValueError('malformed RELA section')
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, off)
            if where == slot:
                matches.append((off, info, addend, s['name']))
    if len(matches) != 1:
        raise ValueError('symbol relocation missing/duplicate')
    off, info, addend, rela_name = matches[0]
    symbol_index, relocation_type = info >> 32, info & 0xffffffff
    if expected_type not in (6, 7) or relocation_type != expected_type or symbol_index == 0 or symbol_index * 24 + 24 > table['size']:
        raise ValueError('invalid symbol relocation')
    sym_off = table['offset'] + symbol_index * 24
    name_off, st_info, st_other, shndx, value, size = struct.unpack_from('<IBBHQQ', data, sym_off)
    if name_off >= string_table['size']:
        raise ValueError('dynamic symbol name outside string table')
    name_start = string_table['offset'] + name_off
    name_end = data.find(b'\0', name_start, string_table['offset'] + string_table['size'])
    if name_end < 0:
        raise ValueError('unterminated dynamic symbol name')
    name = data[name_start:name_end].decode('ascii')
    if name != expected_name:
        raise ValueError('dynamic symbol name changed')
    return {'slot_va': hex(slot), 'relocation_section': rela_name, 'relocation_file_offset': hex(off),
            'relocation_hex': data[off:off + 24].hex(), 'relocation_type': relocation_type,
            'symbol_index': symbol_index, 'addend': addend, 'symbol_name': name,
            'symbol_file_offset': hex(sym_off), 'symbol_hex': data[sym_off:sym_off + 24].hex(),
            'symbol_info': st_info, 'symbol_other': st_other, 'symbol_section_index': shndx,
            'symbol_value': hex(value), 'symbol_size': size,
            'name_file_offset': hex(name_start), 'name_hex': data[name_start:name_end + 1].hex()}


def frame_record(data, sec, va):
    length_raw = read_va(data, sec, va, 4)[0]
    length = struct.unpack('<I', length_raw)[0]
    if length == 0 or length == 0xffffffff:
        raise ValueError('unsupported unwind record')
    return read_va(data, sec, va, length + 4)[0].hex()


def selected_fdes(data, sec):
    _, fdes = eh_frame_records(data, sec)
    found = {}
    for row in fdes:
        start = row['start']
        if start not in FUNCTIONS:
            continue
        if start in found or row['end'] <= start:
            raise ValueError('missing, duplicate or empty selected FDE')
        raw, off, name = read_va(data, sec, start, row['end'] - start)
        if name != '.text':
            raise ValueError('selected FDE is outside file-backed text')
        found[start] = {
            'role_inferred': FUNCTIONS[start], 'start_va': hex(start), 'end_va': hex(row['end']),
            'file_offset': hex(off), 'byte_count': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'raw_hex': raw.hex(), 'fde_va': hex(row['fde']), 'cie_va': hex(row['cie']),
            'lsda_va': None if row['lsda'] is None else hex(row['lsda']),
            'fde_raw_hex': frame_record(data, sec, row['fde']),
            'cie_raw_hex': frame_record(data, sec, row['cie']),
        }
    if set(found) != set(FUNCTIONS):
        raise ValueError('selected FDE start missing')
    return [found[k] for k in sorted(found)]


def check_windows(data, sec):
    rows = []
    for label, va, expected in WINDOWS:
        raw, off, name = read_va(data, sec, va, len(bytes.fromhex(expected)))
        need(raw, bytes.fromhex(expected), label)
        rows.append({'label': label, 'va': hex(va), 'file_offset': hex(off), 'section': name, 'raw_hex': raw.hex()})
    return rows


def check_edges(data, sec):
    rows = []
    for label, va, kind, expected in EDGES:
        target, raw, off, name = read_edge(data, sec, va, kind)
        if target != expected:
            raise ValueError('changed relative target: ' + label)
        rows.append({'label': label, 'kind': kind, 'va': hex(va), 'file_offset': hex(off),
                     'section': name, 'raw_hex': raw.hex(), 'target_va': hex(target)})
    return rows


def check_rip(data, sec):
    rows = []
    for label, va, prefix_hex, expected in RIP:
        prefix = bytes.fromhex(prefix_hex)
        raw, off, name = read_va(data, sec, va, len(prefix) + 4)
        target = rip_target(va, raw, prefix)
        if target != expected:
            raise ValueError('changed RIP target: ' + label)
        rows.append({'label': label, 'va': hex(va), 'file_offset': hex(off), 'section': name,
                     'raw_hex': raw.hex(), 'target_va': hex(target)})
    return rows


def scaled_selector(data, sec, reloc):
    """Decode seven complete equality tests and their callback records."""
    out = []
    for i in range(scaled_count(data, sec)):
        va = 0x46a0eb0 + i * 18
        raw, off, _ = read_va(data, sec, va, 18)
        if raw[:5] != bytes.fromhex('8b47104835') or raw[9:17] != bytes.fromhex('480b07480b470874'):
            raise ValueError('changed scaled selector predicate')
        key = bytes(16) + raw[5:9]
        target = relative_target(va + 16, raw[16:18], 'jcc')
        body = read_va(data, sec, target, 16)[0]
        if body[:3] != bytes.fromhex('488d0d') or body[7:] != bytes.fromhex('488b4118488b5120c3'):
            raise ValueError('changed scaled selector result')
        rec = rip_target(target, body[:7], bytes.fromhex('488d0d'))
        record, rec_off, section = read_va(data, sec, rec, 40)
        if record[:20] != key:
            raise ValueError('selector key differs from record')
        scale = struct.unpack_from('<Q', record, 32)[0]
        if not scale:
            raise ValueError('zero scaled-callback divisor')
        callback = reloc[rec + 24]['addend_va']
        out.append({'test_va': hex(va), 'test_file_offset': hex(off), 'test_hex': raw.hex(),
                    'key_hex': key.hex(), 'branch_target_va': hex(target), 'target_hex': body.hex(),
                    'record_va': hex(rec), 'record_file_offset': hex(rec_off), 'record_section': section,
                    'record_hex': record.hex(), 'callback_slot_va': hex(rec + 24),
                    'callback_addend_va': callback, 'divisor': scale})
    if len({r['key_hex'] for r in out}) != len(out):
        raise ValueError('duplicate scaled selector key')
    row09 = next((r for r in out if r['key_hex'] == ADDR09.hex()), None)
    if row09 is None or row09['callback_addend_va'] != '0x5c16650' or row09['divisor'] != 10:
        raise ValueError('address 09 scaled binding changed')
    return out


def routing_limits(data, sec):
    loop = read_va(data, sec, 0x2a6abe0, 4)[0]
    filt = read_va(data, sec, 0x2a6ac23, 8)[0]
    need(loop[:3], bytes.fromhex('4883fe'), 'iterator bound')
    need(filt[:3], bytes.fromhex('4180c4'), 'iterator adjustment')
    need(filt[4:7], bytes.fromhex('4180fc'), 'private bound')
    if not 0 < filt[7] <= loop[3] <= 64:
        raise ValueError('unsupported address enumeration domain')
    return loop[3], filt[3], filt[7]


def scaled_count(data, sec):
    # Each complete test has the same 18-byte shape. Its first non-test is
    # explicitly required to be the no-match xor/ret, not guessed as an end.
    for i in range(33):
        va = 0x46a0eb0 + 18 * i
        lead = read_va(data, sec, va, 3)[0]
        if lead == bytes.fromhex('31c0c3'):
            if not i:
                raise ValueError('empty scaled selector')
            return i
        if lead != bytes.fromhex('8b4710'):
            raise ValueError('unsupported scaled selector terminator')
    raise ValueError('scaled selector exceeds bounded domain')


def iterator_cases(data, sec):
    table = 0x7c7548
    join = 0x4200d79
    out = []
    iterator_count, adjustment, private_count = routing_limits(data, sec)
    for i in range(iterator_count):
        raw_table, off, _ = read_va(data, sec, table + 4 * i, 4)
        target = table + struct.unpack('<i', raw_table)[0]
        lead = read_va(data, sec, target, 8)[0]
        literal_va = None
        if lead[:4] in (bytes.fromhex('f30f6f05'), bytes.fromhex('660f6f05')):
            literal_va = rip_target(target, lead, lead[:4])
            first = read_va(data, sec, literal_va, 16)[0]
            p = target + 8
        elif lead[:4] == bytes.fromhex('660f76c0'):
            first = bytes([255]) * 16
            p = target + 4
        else:
            raise ValueError('unsupported iterator case')
        need(read_va(data, sec, p, 6)[0], bytes.fromhex('660f7f4424e8'), 'iterator store16')
        p += 6
        tail = read_va(data, sec, p, 8)[0]
        need(tail[:4], bytes.fromhex('c74424f8'), 'iterator store4')
        key = first + tail[4:]
        p += 8
        if p != join:
            dest, _, _, _ = read_edge(data, sec, p, 'jmp')
            if dest != join:
                raise ValueError('iterator case does not join')
        out.append({'index': i, 'table_entry_va': hex(table + 4 * i), 'table_file_offset': hex(off),
                    'table_entry_hex': raw_table.hex(), 'case_va': hex(target),
                    'first_16_va': None if literal_va is None else hex(literal_va),
                    'case_bytes_hex': read_va(data, sec, target, p - target)[0].hex(),
                    'key_hex': key.hex(), 'private_index_accepted': ((i + 1 + adjustment) & 255) < private_count})
    if len({r['key_hex'] for r in out}) != iterator_count:
        raise ValueError('duplicate enumeration key')
    return out


def private_cases(data, sec, reloc):
    """Decode selector comparisons and record targets, including the first special shape."""
    out = []
    _, _, private_count = routing_limits(data, sec)
    for i in range(private_count):
        intervening = b''
        if i == 0:
            va = 0x38be041
            raw = read_va(data, sec, va, 16)[0]
            if raw[:5] != bytes.fromhex('8b42104835') or raw[9:] != bytes.fromhex('480b02480b4208'):
                raise ValueError('changed first private key predicate')
            intervening = read_va(data, sec, 0x38be051, 25)[0]
            need(intervening, bytes.fromhex('488954241848897c24104c894c24384c8944243048894c2428'),
                 'private first comparison flag-preserving stores')
            suffix = raw[5:9]
            branch = 0x38be06a
        else:
            va = 0x38be070 + (i - 1) * 23
            raw = read_va(data, sec, va, 17)[0]
            if raw[:6] != bytes.fromhex('418b42104835') or raw[10:] != bytes.fromhex('490b02490b4208'):
                raise ValueError('changed private key predicate')
            suffix = raw[6:10]
            branch = va + 17
        key = bytes(16) + suffix
        dst, insn, off, _ = read_edge(data, sec, branch, 'jcc')
        if not insn.startswith(bytes.fromhex('0f84')):
            raise ValueError('private comparison is not equality branch')
        lea = read_va(data, sec, dst, 7)[0]
        rec = rip_target(dst, lea, bytes.fromhex('488d05'))
        record, rec_off, section = read_va(data, sec, rec, 32)
        if record[:20] != key:
            raise ValueError('private selector key differs from record')
        out.append({'index': i, 'test_va': hex(va), 'test_hex': raw.hex(),
                    'intervening_flag_preserving_hex': intervening.hex(), 'branch_va': hex(branch),
                    'branch_file_offset': hex(off), 'branch_hex': insn.hex(), 'branch_target_va': hex(dst),
                    'record_lea_hex': lea.hex(), 'key_hex': key.hex(), 'record_va': hex(rec),
                    'record_file_offset': hex(rec_off), 'record_section': section, 'record_hex': record.hex(),
                    'callback_slot_va': hex(rec + 24), 'callback_addend_va': reloc[rec + 24]['addend_va']})
    if len({r['key_hex'] for r in out}) != private_count:
        raise ValueError('duplicate private selector key')
    return out


def constructor_private_copies(data, sec):
    out = []
    _, _, private_count = routing_limits(data, sec)
    for i in range(private_count):
        va = 0x38be870 + i * 34
        raw, off, _ = read_va(data, sec, va, 34)
        if (raw[:2] != bytes.fromhex('8b05') or raw[6:10] != bytes.fromhex('89442410') or
            raw[10:13] != bytes.fromhex('0f1005') or raw[17:29] != bytes.fromhex('0f290424488d7c24204889e6')):
            raise ValueError('changed private constructor copy')
        final4 = rip_target(va, raw[:6], bytes.fromhex('8b05'))
        first16 = rip_target(va + 10, raw[10:17], bytes.fromhex('0f1005'))
        if final4 != first16 + 16:
            raise ValueError('private key copy does not assemble 20 bytes')
        call = relative_target(va + 29, raw[29:34], 'call')
        if call != 0x3ed7620:
            raise ValueError('changed private key insertion boundary')
        key = read_va(data, sec, first16, 20)[0]
        out.append({'index': i, 'copy_va': hex(va), 'copy_file_offset': hex(off), 'copy_hex': raw.hex(),
                    'first_16_va': hex(first16), 'last_4_va': hex(final4), 'key_hex': key.hex(),
                    'insert_helper_va': hex(call)})
    return out


def activation_lineage(data, sec):
    """Recover selected field offsets and cross-check their copy arithmetic."""
    raw = lambda va, n: read_va(data, sec, va, n)[0]
    state_base = struct.unpack_from('<I', raw(0x2a0713c, 7), 3)[0]
    counter = struct.unpack_from('<I', raw(0x433de23, 12), 8)[0]
    tag_code = raw(0x433e5e7, 8)
    tag_offset = struct.unpack_from('<I', tag_code, 3)[0]
    tag_value = tag_code[7]
    threshold = struct.unpack_from('<I', raw(0x433e5f3, 7), 3)[0]
    constructor_output = struct.unpack_from('<I', raw(0x433e6fb, 6), 2)[0]
    upstream_output_stack = struct.unpack_from('<I', raw(0x2a07146, 8), 4)[0]
    upstream_output_read = struct.unpack_from('<I', raw(0x2a07164, 8), 4)[0]
    upstream_config_stack = struct.unpack_from('<I', raw(0x2a07b22, 8), 4)[0]
    upstream_flag_store = struct.unpack_from('<I', raw(0x2a071de, 8), 4)[0]
    constructor_arg_add = raw(0x2963184, 4)[3]
    provider_input_off = raw(0x38beb8a, 4)[3]
    provider_output_off = struct.unpack_from('<I', raw(0x38beb8e, 7), 3)[0]
    frame_context_off = struct.unpack_from('<I', raw(0x29842be, 7), 3)[0]
    provider_flag_test_off = struct.unpack_from('<I', raw(0x2a6ab64, 7), 2)[0]
    config_flag_off = constructor_arg_add + provider_input_off
    if (upstream_output_read - upstream_output_stack != constructor_output or
        upstream_flag_store - upstream_config_stack != config_flag_off or
        provider_output_off != provider_flag_test_off or
        frame_context_off + provider_output_off != 0x468):
        raise ValueError('activation flag copy lineage does not match')
    return {
        'upstream_state_subobject_offset': hex(state_base),
        'counter_offset_in_state_subobject': hex(counter),
        'counter_offset_from_upstream_argument': hex(state_base + counter),
        'option_tag_offset_in_state_subobject': hex(tag_offset), 'option_tag_required': tag_value,
        'option_tag_offset_from_upstream_argument': hex(state_base + tag_offset),
        'threshold_offset_in_state_subobject': hex(threshold),
        'threshold_offset_from_upstream_argument': hex(state_base + threshold),
        'activation_output_byte_offset': hex(constructor_output),
        'upstream_output_stack_offset': hex(upstream_output_stack),
        'upstream_output_read_stack_offset': hex(upstream_output_read),
        'upstream_configuration_stack_offset': hex(upstream_config_stack),
        'upstream_flag_store_stack_offset': hex(upstream_flag_store),
        'driver_second_argument_flag_offset': hex(config_flag_off),
        'provider_input_pointer_adjustment': hex(constructor_arg_add),
        'provider_flag_input_offset': hex(provider_input_off),
        'provider_flag_output_offset': hex(provider_output_off),
        'frame_provider_context_offset': hex(frame_context_off),
        'frame_flag_context_offset': hex(frame_context_off + provider_output_off),
        'scope': 'Conditional normal-return dataflow; effects of intervening external helpers and aliases are not established.'}


def parse_lsda(data, sec, fde):
    """Decode the selected ULEB call-site table, without interpreting actions."""
    va = int(fde['lsda_va'], 16)
    start, end = int(fde['start_va'], 16), int(fde['end_va'], 16)
    _, base, name = read_va(data, sec, va, 1)
    if name != '.gcc_except_table':
        raise ValueError('LSDA outside exception section')
    matches = [s for s in sec if s['name'] == name and s['type'] != 8]
    if len(matches) != 1:
        raise ValueError('exception section missing/ambiguous')
    section = matches[0]
    limit = section['offset'] + section['size']
    if limit > len(data) or base + 2 > limit:
        raise ValueError('truncated LSDA header')
    pos = base
    lp_encoding, type_encoding = data[pos], data[pos + 1]
    pos += 2
    if lp_encoding != 0xff or type_encoding not in (0xff, 0x9b):
        raise ValueError('unsupported LSDA pointer encoding')
    type_table_va = None
    type_table_off = None
    if type_encoding == 0x9b:
        type_delta, pos = uleb(data, pos, limit)
        type_table_off = pos + type_delta
        if type_table_off > limit:
            raise ValueError('LSDA type table outside section')
        type_table_va = va + type_table_off - base
    if pos >= limit or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    pos += 1
    table_size, pos = uleb(data, pos, limit)
    table_start, table_end = pos, pos + table_size
    if table_end > limit or (type_table_off is not None and table_end > type_table_off):
        raise ValueError('LSDA call-site table outside bounded region')
    rows = []
    while pos < table_end:
        entry = pos
        offset, pos = uleb(data, pos, table_end)
        length, pos = uleb(data, pos, table_end)
        landing, pos = uleb(data, pos, table_end)
        action, pos = uleb(data, pos, table_end)
        region_start, region_end = start + offset, start + offset + length
        landing_va = None if landing == 0 else start + landing
        if not start <= region_start <= region_end <= end:
            raise ValueError('LSDA call-site range outside FDE')
        if landing_va is not None and not start <= landing_va < end:
            raise ValueError('LSDA landing pad outside FDE')
        rows.append({'function_va': hex(start), 'lsda_va': hex(va),
                     'entry_file_offset': hex(entry), 'raw_hex': data[entry:pos].hex(),
                     'start_va': hex(region_start), 'end_va': hex(region_end),
                     'landing_pad_va': '' if landing_va is None else hex(landing_va),
                     'action_index': action})
    header = {'function_va': hex(start), 'lsda_va': hex(va), 'file_offset': hex(base),
              'section': name, 'header_hex': data[base:table_start].hex(),
              'lpstart_encoding': lp_encoding, 'type_encoding': type_encoding,
              'type_table_va': None if type_table_va is None else hex(type_table_va),
              'callsite_encoding': 1, 'callsite_bytes': table_size,
              'callsite_count': len(rows)}
    return header, rows


def select_route(key: bytes, enabled: bool, scaled: list[dict], iterator: list[dict]) -> str:
    if not isinstance(key, bytes) or len(key) != 20 or type(enabled) is not bool:
        raise ValueError('key must contain exactly 20 bytes')
    if enabled and any(bytes.fromhex(r['key_hex']) == key for r in scaled):
        return 'scaled'
    if any(r['private_index_accepted'] and bytes.fromhex(r['key_hex']) == key for r in iterator):
        return 'private'
    return 'registry'


def model_scaled_09(gas: int, payload: bytes, divisor: int):
    """Synthetic arithmetic model; it never executes a captured instruction."""
    if type(gas) is not int or not 0 <= gas <= U64_MAX or type(divisor) is not int or not 1 <= divisor <= U64_MAX:
        raise ValueError('invalid synthetic gas or divisor')
    if len(payload) != 213:
        return 'length', None
    rounds = int.from_bytes(payload[:4], 'big')
    if gas // divisor < rounds:
        return 'gas', None
    if payload[212] >= 2:
        return 'flag', None
    return 'success', saturating_scale(rounds, divisor)


def saturating_scale(cost: int, divisor: int) -> int:
    if (type(cost) is not int or not 0 <= cost <= U64_MAX or
        type(divisor) is not int or not 1 <= divisor <= U64_MAX):
        raise ValueError('invalid synthetic scaling operands')
    return min(cost * divisor, U64_MAX)


def model_activation(tag: int, counter: int, threshold: int) -> bool:
    """Synthetic unsigned model for the observed option/threshold gate."""
    if (type(tag) is not int or not 0 <= tag < (1 << 32) or
        type(counter) is not int or not 0 <= counter <= U64_MAX or
        type(threshold) is not int or not 0 <= threshold <= U64_MAX):
        raise ValueError('invalid synthetic activation input')
    if counter == U64_MAX:
        raise OverflowError('counter increment takes the failure boundary')
    return tag == 1 and counter + 1 >= threshold


def collect(data: bytes) -> dict[str, object]:
    authenticate(data)
    sec = sections(data)
    fdes = selected_fdes(data, sec)
    windows = check_windows(data, sec)
    edges = check_edges(data, sec)
    rip = check_rip(data, sec)
    _, _, private_count = routing_limits(data, sec)
    scaled_slots = {0x6492f30 + 40 * i + 24 for i in range(scaled_count(data, sec))}
    private_slots = {0x646e4e0 + 32 * i + 24 for i in range(private_count)}
    reloc = relative_relocations(data, sec, set(RELA_SLOTS) | scaled_slots | private_slots)
    expected_bindings = {0x64e6e10:0x433dc40,0x64e6ce0:0x38be800,0x64e7138:0x46a0eb0,0x64e7140:0x4200a50,
                         0x64e7148:0x38be030,0x64e7150:0x5be6a80}
    for slot, target in expected_bindings.items():
        if int(reloc[slot]['addend_va'], 16) != target:
            raise ValueError('relocation binding changed')
    scaled = scaled_selector(data, sec, reloc)
    iterator = iterator_cases(data, sec)
    private = private_cases(data, sec, reloc)
    copies = constructor_private_copies(data, sec)
    symbols = [dynamic_symbol_relocation(data, sec, 0x64df508, 'memcpy'),
               dynamic_symbol_relocation(data, sec, 0x64dfb50, 'memcmp'),
               dynamic_symbol_relocation(data, sec, 0x64ee178, '_Unwind_Resume', 7)]
    exception_headers, exception_rows = [], []
    for fde in fdes:
        if fde['lsda_va'] is not None:
            header, rows = parse_lsda(data, sec, fde)
            exception_headers.append(header)
            exception_rows.extend(rows)
    private_keys = [r['key_hex'] for r in private]
    if private_keys != [r['key_hex'] for r in copies]:
        raise ValueError('constructor and private dispatcher disagree')
    if private_keys != [r['key_hex'] for r in iterator if r['private_index_accepted']]:
        raise ValueError('iterator and private dispatcher disagree')
    if ADDR09.hex() in {r['key_hex'] for r in iterator}:
        raise ValueError('address 09 unexpectedly appears in private enumeration')
    modes, modes_off, mode_section = read_va(data, sec, 0x7a1784, 15)
    mode_rows = [{'input': i, 'mode': value, 'byte_va': hex(0x7a1784 + i),
                  'file_offset': hex(modes_off + i), 'raw_hex': f'{value:02x}'} for i,value in enumerate(modes)]
    summary = {'target_sha256': TARGET_SHA256, 'selected_fde_intervals': len(fdes),
               'selected_fde_bytes': sum(r['byte_count'] for r in fdes), 'selected_byte_windows': len(windows),
               'selected_direct_edges': len(edges), 'selected_rip_references': len(rip),
               'selected_relative_relocations': len(reloc), 'scaled_selector_records': len(scaled),
               'symbol_relocations': len(symbols),
               'lsda_headers': len(exception_headers), 'exception_call_sites': len(exception_rows),
               'iterator_cases': len(iterator), 'accepted_private_cases': len(private),
               'constructor_private_copies': len(copies), 'inspected_mode_bytes': len(mode_rows),
               'limitations': 'Selected FDEs, fixed byte windows and synthetic models are not a complete CFG, runtime observation or component coverage.'}
    return {'functions.json':fdes, 'windows.tsv':windows, 'edges.tsv':edges, 'rip-references.tsv':rip,
            'relocations.json':[reloc[k] for k in sorted(reloc)], 'dynamic-symbols.json':symbols, 'scaled-records.json':scaled,
            'iterator-cases.json':iterator, 'private-records.json':private,
            'constructor-copies.json':copies,
            'exception-headers.json':exception_headers, 'exception-sites.tsv':exception_rows,
            'modes.json':{'table_va':'0x7a1784','section':mode_section,'inspected_bytes':mode_rows,
                          'scope':'Only the first 15 inputs are inspected; valid runtime input domain is not established.'},
            'activation-lineage.json':activation_lineage(data, sec),
            'summary.json':summary}


def render(name, item):
    if name.endswith('.json'):
        return (json.dumps(item, indent=2, ensure_ascii=True) + '\n').encode('ascii')
    if not name.endswith('.tsv') or not item:
        raise ValueError('unknown output format')
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=list(item[0]), delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(item)
    return output.getvalue().encode('ascii')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    evidence = collect(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, value in evidence.items():
        (args.out / name).write_bytes(render(name, value))


if __name__ == '__main__':
    main()
