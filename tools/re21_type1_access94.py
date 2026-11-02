#!/usr/bin/env python3
"""Extract node-94 type-1 transaction and access-list static evidence (MIT).

No captured instruction is executed. Only Python and the shared ELF/FDE
readers are needed; outputs depend on file bytes and explicit study seeds.
The restricted x86 length decoder is adapted from this repository's
MIT-licensed tools/evm_kvs_inventory.py. It is not a general disassembler.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
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
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

class EvidenceError(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise EvidenceError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def authenticate(data):
    require(digest(data) == DIGEST, 'node #94 digest mismatch')

def decode_instruction(code, offset=0, base=0):
    """Restricted legacy x86-64 length decoder, not a general disassembler.

    Decode sequentially from FDE entry; never resynchronize after an unknown
    opcode. ModRM/SIB/displacements and immediates are consumed, so opcode-like
    bytes inside operands cannot become anchors. Only enumerated forms pass.
    Operand semantics used for claims get a second exact decoder below.
    """
    require(0 <= offset < len(code), 'instruction offset outside input')
    start = offset
    def take(n):
        nonlocal offset
        require(offset + n <= len(code), 'truncated instruction')
        value = code[offset:offset+n]
        offset += n
        require(offset - start <= 15, 'overlong instruction')
        return value
    def byte():
        return take(1)[0]
    prefixes = []
    while offset < len(code) and code[offset] in (0x66, 0xf2, 0xf3, 0xf0, 0x2e, 0x64):
        p = byte()
        require(p not in prefixes or p == 0x66, 'duplicate legacy prefix')
        prefixes.append(p)
    require(not (0xf2 in prefixes and 0xf3 in prefixes), 'conflicting repeat prefixes')
    rex = 0
    if offset < len(code) and 0x40 <= code[offset] <= 0x4f:
        rex = byte()
    op = byte()
    operand = 2 if 0x66 in prefixes and not rex & 8 else 4
    kind, imm, modrm, group = 'other', 0, False, None
    if op in (0xe8, 0xe9, 0xeb) or 0x70 <= op <= 0x7f:
        require(not prefixes and not rex, 'unsupported branch prefixes')
        kind = 'call_rel32' if op == 0xe8 else 'jmp_rel32' if op == 0xe9 else 'branch'
        imm = 4 if op in (0xe8, 0xe9) else 1
    elif 0xb8 <= op <= 0xbf:
        imm = 8 if rex & 8 else operand
        kind = 'mov_imm'
    elif 0xb0 <= op <= 0xb7:
        imm = 1
    elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99, 0xc3, 0xcc, 0xc9, 0xfc):
        pass
    elif op in (0x68, 0x6a, 0xa8, 0xa9, 0xc2):
        imm = 2 if op == 0xc2 else 1 if op in (0x6a, 0xa8) else operand
    elif op in tuple(x + y for x in range(0, 0x40, 8) for y in range(4)) + (
            0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8d, 0x8f, 0xc0, 0xc1, 0xc6, 0xc7,
            0xd0, 0xd1, 0xd2, 0xd3, 0xf6, 0xf7, 0xfe, 0xff):
        modrm = True
        if op in (0x69, 0x81, 0xc7): imm = operand
        if op in (0x6b, 0x80, 0x83, 0xc0, 0xc1, 0xc6): imm = 1
        if op in (0x8f, 0xc6, 0xc7): group = {0}
        if op == 0xfe: group = {0, 1}
        if op == 0xff: group = {0, 1, 2, 4, 6}  # excludes far forms and reserved /7
        if op in (0xf6, 0xf7): group = {0, 2, 3, 4, 5, 6, 7}
        if op == 0x8d: kind = 'lea'
        if op == 0xc7: kind = 'mov_imm'
    elif op < 0x40 and op % 8 in (4, 5):
        imm = 1 if op % 8 == 4 else operand
    elif op == 0x0f:
        op2 = byte()
        if 0x80 <= op2 <= 0x8f:
            require(not prefixes and not rex, 'unsupported conditional branch prefixes')
            imm, kind = 4, 'branch'
        elif op2 == 0x0b:
            kind = 'ud2'
        elif 0xc8 <= op2 <= 0xcf:
            require(not prefixes, 'unsupported BSWAP prefixes')
        elif op2 in (0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x1f, 0x28, 0x29,
                     0x2a, 0x2c, 0x2d, 0x2e, 0x2f, 0x50, 0x51, 0x54, 0x55,
                     0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
                     0x5f, 0x60, 0x61, 0x62, 0x66, 0x6c, 0x6d, 0x6e, 0x6f,
                     0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x7e, 0x7f,
                     0xa3, 0xab, 0xaf, 0xb0, 0xb1, 0xb3, 0xb6, 0xb7, 0xba,
                     0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc6,
                     0xd4, 0xd6, 0xd7, 0xdb, 0xdf, 0xe6, 0xeb, 0xef, 0xf3,
                     0xf4, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe) or 0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f:
            modrm = True
            if op2 in (0x70, 0x71, 0x72, 0x73, 0xba, 0xc2, 0xc6): imm = 1
            if op2 == 0x1f: group = {0}
            if op2 in (0x71, 0x72): group = {2, 4, 6}
            if op2 == 0x73: group = {2, 3, 6, 7}
            if op2 == 0xba: group = {4, 5, 6, 7}
        else:
            raise EvidenceError(f'unsupported 0f opcode {op2:02x}')
    else:
        raise EvidenceError(f'unsupported opcode {op:02x}')
    if modrm:
        m = byte()
        mod, reg, rm = m >> 6, (m >> 3) & 7, m & 7
        require(group is None or reg in group, 'unsupported ModRM group')
        require(op != 0x8d or mod != 3, 'register-source LEA is invalid')
        if op in (0xf6, 0xf7) and reg == 0: imm = 1 if op == 0xf6 else operand
        if mod != 3:
            if rm == 4:
                sib = byte()
                if mod == 0 and sib & 7 == 5: take(4)
            elif mod == 0 and rm == 5:
                take(4)
            if mod == 1: take(1)
            if mod == 2: take(4)
        if 0xf0 in prefixes:
            require(mod != 3 and (op in (0x01, 0x09, 0x21, 0x29, 0x31, 0x80, 0x81, 0x83, 0xff)
                    or op == 0x0f and op2 in (0xb0, 0xb1, 0xc0, 0xc1)), 'unsupported LOCK form')
    else:
        require(0xf0 not in prefixes, 'LOCK without memory operand')
    if 0xf0 in prefixes and op in (0x80, 0x81, 0x83):
        require(reg != 7, 'LOCK CMP is invalid')
    if 0xf0 in prefixes and op == 0xff:
        require(reg in (0, 1), 'unsupported LOCK FF group')
    if prefixes.count(0x66) > 1 or 0x2e in prefixes:
        require(op == 0x0f and op2 == 0x1f and all(p in (0x66, 0x2e) for p in prefixes),
                'redundant prefixes only supported on NOP')
    if 0x64 in prefixes:
        require(prefixes == [0x64] and modrm and mod != 3 and op in (0x8b, 0x89, 0x80, 0x83, 0x88, 0xc6, 0x0f, 0xff, 0x22),
                'unsupported FS form')
    take(imm)
    return {'site': base + start, 'raw': bytes(code[start:offset]), 'kind': kind}


# Selected FDE starts are research seeds, not an inventory of all code.
ROLES = {
    0x134f840: 'type-1 unsigned fields and access-list handoff',
    0x1350970: 'byte-string payload decoder',
    0x1350bc0: 'nested row and vector cleanup',
    0x1350c40: 'bounded unsigned integer decoder',
    0x1350e50: 'nested access-list parser',
    0x1353a40: 'release initialized row payloads',
    0x1353a90: 'grow 48-byte row vector',
    0x1353af0: 'checked 48-byte allocation',
    0x135b590: 'grow 32-byte key vector',
    0x135b5f0: 'checked 32-byte allocation',
    0x4e52960: 'append cloned rows',
    0x4e53b90: 'signed-list cleanup',
    0x4e54230: 'type-1 signed envelope decoder',
    0x4e54fe0: 'replace and extend cloned rows',
}

# Fixed, reviewed instruction windows. Their expected bytes are retained here
# so a changed instruction fails even when testing a deliberately altered image
# without using the whole-file authentication entry point.
PINS = (
    (0x4e5424e, 'outer_input_length', '4c8b6608b9020000004d85e4'),
    (0x4e54267, 'outer_prefix_class', '4584f6780c'),
    (0x4e54395, 'unsigned_decoder_call', 'ff15859e9100'),
    (0x4e544c7, 'signature_decoder_call', 'e8e4180000'),
    (0x4e54590, 'outer_checked_add', '4c01e90f820b0100004c39e1'),
    (0x4e545b9, 'unsigned_copy_size', 'baa00000004c89f741ffd70f28842400020000'),
    (0x4e54618, 'success_copy_size', 'bae00000004889df4c89f641ffd7'),
    (0x4e54632, 'outer_mismatch_result', '4929c4727c48c703080000004c896b084c896310'),
    (0x134f85a, 'first_integer_call', 'e8e1130000'),
    (0x134f87b, 'second_integer_call', 'e8c0130000'),
    (0x134f8fc, 'gas_integer_call', 'e83f130000'),
    (0x134f925, 'recipient_decode_call', 'ff15dde84104'),
    (0x134fb79, 'payload_decode_call', 'e8f20d0000'),
    (0x134fbbe, 'access_list_decode_call', 'e88d120000'),
    (0x134fbe0, 'list_result_tag', '83f801488b4c24380f85ef010000'),
    (0x134fdf0, 'access_list_output', '488b842490000000488943780f28842480000000'),
    (0x134fe08, 'tagged_recipient_load', '0f288424b00000000f118380000000488b8424bd0000004889838d0000000f10442440'),
    (0x134fe26, 'payload_output_words', '0f104424400f104c24500f1143200f114b30'),
    (0x1350e64, 'list_input_length', '4c8b6608b9020000004d85e4'),
    (0x1350e7e, 'list_input_error', 'b90600000048894b08'),
    (0x1350f98, 'short_list_length', '4180c740410fb6d74889c54939d4'),
    (0x1350fac, 'outer_cursor_advance', '4929d4488d042a4889064c896608'),
    (0x1350fd5, 'empty_list_fast_path', '4885d20f84fd040000'),
    (0x1350ff4, 'item_prefix_check', '440fb67d004584ff0f8975070000'),
    (0x135110c, 'address_width_check', '4180ff140f8505050000'),
    (0x1351119, 'address_load_first', '418b0e418b5603'),
    (0x1351324, 'slot_width_check', '4180ff200f85cc020000'),
    (0x135132e, 'slot_load_first', '418b4500418b4d03894c247389442470'),
    (0x1351289, 'slot_push_first', '4d01fd488b4424208b4c24708b542473428954200342890c20488b4c24104a894c2007'),
    (0x13512da, 'slot_stride', '4983c420'),
    (0x1351376, 'slot_grow_call', 'ff15e4cd4104'),
    (0x13513d8, 'item_length_consumed', '4c2b742438488bac2480000000'),
    (0x13513fa, 'item_length_check', '488b4424784939c60f85f8030000'),
    (0x135145a, 'row_grow_call', 'ff15f8cc4104'),
    (0x1351479, 'row_stride', '4b8d0c7648c1e104'),
    (0x1351486, 'row_vector_words', '488914084c896c0808488b5424084889540810488b5424304889540818'),
    (0x1351499, 'row_address_first', '488b54243048895408188b5424608b742463'),
    (0x13514c2, 'row_count_update', '49ffc64c89742450'),
    (0x13514db, 'list_success', '488b44245048894318488b44244048894308488b4424484889431048c70300000000'),
    (0x1351604, 'inner_cleanup', '4989fe488b7c242048c1e60531d2ff15f8c941044c89f7'),
    (0x135161b, 'list_error_return', '4531ff31c0488944240849c1e72848b8ffffffffff00000048234424084c09f848897b0848894310488b4424304889431848c70301000000'),
    (0x1351658, 'rows_cleanup_call', 'e8e3230000'),
    (0x13518b3, 'unwind_rows_cleanup', 'e808f3ffff'),
    (0x1350bc9, 'rows_destructor_input', '4989fe488b5f084c8b7f104d85ff'),
    (0x1350bf0, 'rows_destructor_stride', '4983c43049ffcf7419'),
    (0x1350c03, 'rows_destructor_slots', '498b3c2448c1e60531d241ffd5'),
    (0x1353a9d, 'row_growth_policy', '488d04364883f80541be040000004c0f43f0488b5708'),
    (0x1353ab9, 'row_growth_helper_call', 'e832000000'),
    (0x1353afe, 'row_capacity_bound', '48b8aaaaaaaaaaaaaa024839c1'),
    (0x1353b17, 'row_allocation_size', '48c1e1044c8d3449'),
    (0x135b59d, 'slot_growth_policy', '488d04364883f80541be040000004c0f43f0488b5708'),
    (0x135b5b9, 'slot_growth_helper_call', 'e832000000'),
    (0x135b5fb, 'slot_allocation_size_guard', '49c1e60548c1e93b0f95c04d85f60f98c108c1'),
    (0x4e54ff7, 'destination_length_compare', '4c8b7a104c39fe'),
    (0x4e55013, 'destination_length_publish', '488b4d084c89751048894c2410'),
    (0x4e55043, 'source_slot_length', '4a8b5c22f84989dd49c1e505'),
    (0x4e55059, 'slot_size_overflow', '4d85ed0f98c108c1'),
    (0x4e55088, 'clone_allocate', 'ff154a8f91004885c0'),
    (0x4e550b2, 'slot_copy', '4889ef4c89eaff15228f91004c8b6c2410'),
    (0x4e550c3, 'destination_old_slot_capacity', '4b8b7425004885f64c8b442408'),
    (0x4e550d2, 'free_old_slot_vector', '4b8b7c250848c1e60531d2ff152d8f9100'),
    (0x4e550f5, 'install_cloned_vector', '4b894c25004b896c25084b895c2510'),
    (0x4e55104, 'copy_row_address', '0f1000430f114425188b40104389442528'),
    (0x4e55115, 'clone_next_row', '4983c43049ffc8'),
    (0x4e5515b, 'clone_tail_append', 'e900d8ffff'),
    (0x4e55190, 'truncate_old_rows', '488b73f84885f674e7488b3b'),
    (0x4e52974, 'append_row_count', '4889d04829f048c1e80449bcabaaaaaaaaaaaaaa4c0fafe0'),
    (0x4e529a8, 'append_first_slot_count', '498b5f1031ff4889d848c1e83b'),
    (0x4e529ef, 'append_allocate_or_empty', '4b8b342f4885ed74384c897424104989f6'),
    (0x4e52a3e, 'append_slot_copy', '4889da48c1e2054889c74889c5ff158fb59100'),
    (0x4e52a56, 'append_row_fields', '488b4424184a894429e84a896c29f04a895c29f8430f10442f10420f110429438b442f20'),
    (0x4e52ab0, 'append_row_count_advance', '49ffc6'),
    (0x4e52ad5, 'append_length_publish', '4d897510'),
    (0x4e53b95, 'signed_list_cleanup_start', '488b5f104885db74324c8b7708'),
    (0x1351150, 'address_middle_load', '488b450848898424b0000000'),
    (0x135115c, 'address_tail_load', '8b451048898424a0000000'),
    (0x1351167, 'address_last_load', '0fb65514418d442408'),
    (0x135133e, 'slot_tail_load', '498b46084889442410498b461048898424c0000000498b46184889442430450fb67620'),
    (0x13512a2, 'slot_middle_store', '488b4c24104a894c2007488b8c24c00000004a894c200f488b4c2430'),
    (0x13513aa, 'address_stage_first', '8b4424688b4c246b89842490000000898c2493000000'),
    (0x13513c0, 'address_stage_middle', '488b8424b00000004889842497000000'),
    (0x1351411, 'address_first_qword_stage', '488b8424900000004889442430'),
    (0x135141e, 'address_middle_stage', '8b018b490389442458894c245b'),
    (0x1351460, 'address_tail_combine', '488bbc24a800000048c1e7204803bc24a0000000488b442448'),
    (0x135149e, 'address_first_qword_store', '4889540818'),
    (0x13514a3, 'address_middle_store', '8b5424608b7424638954082089740823'),
    (0x13514b3, 'address_tail_store', '4889fa48c1ea208854082b897c0827'),
    (0x1350e68, 'outer_empty_error_code', 'b902000000'),
    (0x1350ece, 'outer_noncanonical_error_code', 'b903000000'),
    (0x1350f51, 'long_length_error_code', 'b904000000'),
    (0x13510c5, 'address_width_error_code', 'bf05000000'),
    (0x13512ee, 'key_width_error_code', 'bf05000000'),
    (0x1351777, 'nested_list_error_code', 'bf06000000'),
    (0x1351825, 'row_length_error_code', 'bf08000000'),
    (0x4e54637, 'envelope_length_error_code', '48c70308000000'),
    (0x13510ee, 'address_payload_base', '4c8d7501'),
    (0x1351439, 'address_restaging', '8b4424588b4c245b894c246389442460'),
    (0x13512be, 'slot_tail_store', '4a894c2017468874201f'),
    (0x1351120, 'address_initial_stage', '8954246b894c2468'),
    (0x1351172, 'address_last_stage', '48899424a8000000'),
    (0x13513e5, 'address_staging_base', '488d8c2498000000'),
    (0x1351309, 'key_payload_base', '4d8d6e01'),
    (0x134fdf8, 'access_list_count_store', '48894378'),
    (0x134fe04, 'access_list_vector_store', '0f114368'),
    (0x1351502, 'zero_leading_length_error_code', 'b901000000'),
    (0x4e5507e, 'existing_row_empty_key_branch', '7425'),
    (0x4e550a5, 'existing_row_empty_key_sentinel', 'bd0100000048c7042400000000'),
    (0x4e529f6, 'appended_row_empty_key_branch', '7438'),
    (0x4e52a30, 'appended_row_empty_key_sentinel', 'b80100000048c744241800000000'),
    (0x1350fba, 'empty_outer_vector_initialization', '48c74424400000000048c74424480800000048c744245000000000'),
    (0x135120f, 'empty_inner_vector_initialization', '48c74424180000000048c74424200100000048c744242800000000'),
    (0x1351254, 'short_inner_vector_initialization', '48c74424180000000048c74424200100000048c744242800000000'),
)

class Image:
    def __init__(self, data, sec=None):
        self.data = data
        self.sections = sections(data) if sec is None else sec

    def mapping(self, va, size, executable=False):
        require(type(va) is int and type(size) is int and va >= 0 and size > 0,
                'invalid address range')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and (not executable or s['flags'] & 4)
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'range has no unique file-backed section')
        sec = matches[0]
        off = sec['offset'] + va - sec['address']
        require(off >= 0 and off + size <= len(self.data), 'range crosses file end')
        return sec, off

    def read(self, va, size, executable=False):
        _, off = self.mapping(va, size, executable)
        return bytes(self.data[off:off + size])

    def evidence(self, va, size, executable=False):
        sec, off = self.mapping(va, size, executable)
        return {'va': hex(va), 'file_offset': hex(off), 'section': sec['name'],
                'bytes': bytes(self.data[off:off + size]).hex()}


def selected_fdes(data, secs):
    index_secs, index = unwind_index(data)
    require(index_secs == secs, 'inconsistent section parsing')
    _, records = eh_frame_records(data, secs)
    out = {}
    for start in sorted(ROLES):
        candidates = [f for f in records if f['start'] == start]
        entries = [e for e in index if e['start'] == start]
        require(len(candidates) == len(entries) == 1, 'missing or duplicate FDE')
        fde, ent = candidates[0], entries[0]
        require(fde['fde'] == ent['fde'] and fde['end'] > start,
                'unwind header does not bind FDE extent')
        out[start] = dict(fde, index=ent['index'])
    return out


def frame_record(image, va):
    raw_size = struct.unpack('<I', image.read(va, 4))[0]
    require(4 <= raw_size < 0xffffffff, 'unsupported frame record size')
    return image.evidence(va, 4 + raw_size)


def decode_body(image, fde):
    start, end = fde['start'], fde['end']
    code = image.read(start, end - start, executable=True)
    pos, ins = 0, []
    while pos < len(code):
        try:
            item = decode_instruction(code, pos, start)
        except EvidenceError as error:
            raise EvidenceError(f'unsupported instruction at {start + pos:#x}: {error}') from error
        ins.append(item)
        pos += len(item['raw'])
    require(pos == len(code), 'instruction walk does not end at FDE end')
    validate_local_branches(ins, start, end)
    return ins


def relative_target(ins):
    raw, site = ins['raw'], ins['site']
    if ins['kind'] in ('call_rel32', 'jmp_rel32'):
        require(len(raw) == 5 and raw[0] in (0xe8, 0xe9), 'bad rel32 transfer')
        return site + len(raw) + int.from_bytes(raw[1:], 'little', signed=True)
    if ins['kind'] == 'branch':
        prefix = 2 if raw[0] == 0x0f else 1
        require(len(raw) in (2, 6, 5), 'bad relative branch length')
        return site + len(raw) + int.from_bytes(raw[prefix:], 'little', signed=True)
    return None


def validate_local_branches(instructions, start, end):
    boundaries = {item['site'] for item in instructions}
    require(len(boundaries) == len(instructions), 'duplicate instruction start')
    for item in instructions:
        target = relative_target(item)
        if target is not None and start <= target < end:
            require(target in boundaries, 'local branch enters an instruction')


def verify_pins(image, boundaries=None):
    rows = []
    for va, name, expected in PINS:
        expected = bytes.fromhex(expected)
        if boundaries is not None:
            require(va in boundaries and va + len(expected) in boundaries,
                    f'pin is not bounded by instruction starts: {name}')
        actual = image.read(va, len(expected), executable=True)
        require(actual == expected, f'byte pin mismatch: {name}')
        rows.append((name, hex(va), hex(image.mapping(va, len(expected), True)[1]),
                     len(actual), actual.hex()))
    return rows


def relocations(image):
    found = {}
    for s in image.sections:
        if s['type'] != 4:
            continue
        require(s['type'] != 8 and s['size'] % 24 == 0, 'bad RELA section')
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            require(off + 24 <= len(image.data), 'truncated RELA')
            slot, info, addend = struct.unpack_from('<QQq', image.data, off)
            found.setdefault(slot, []).append({
                'slot': slot, 'section': s['name'], 'entry_va': s['address'] + off - s['offset'],
                'file_offset': off, 'type': info & 0xffffffff, 'symbol': info >> 32,
                'addend': addend, 'bytes': bytes(image.data[off:off + 24]).hex()})
    return found


def rip_reference(item):
    raw, va = item['raw'], item['site']
    if len(raw) == 6 and raw[:2] in (b'\xff\x15', b'\xff\x25'):
        return ('indirect_call' if raw[1] == 0x15 else 'indirect_jump',
                va + 6 + struct.unpack_from('<i', raw, 2)[0])
    if len(raw) == 7 and raw[0] in range(0x48, 0x50) and raw[1] in (0x8b, 0x8d) and raw[2] & 0xc7 == 5:
        return ('rip_load' if raw[1] == 0x8b else 'rip_lea',
                va + 7 + struct.unpack_from('<i', raw, 3)[0])
    return None


def validate_relative_entry(records, slot):
    matches = records.get(slot, [])
    require(len(matches) == 1, 'missing or duplicate relocation')
    row = matches[0]
    require(row['type'] == 8 and row['symbol'] == 0 and row['addend'] >= 0,
            'expected a symbol-free R_X86_64_RELATIVE relocation')
    return row


def validate_binding(records, slot, expected_target):
    row = validate_relative_entry(records, slot)
    require(row['addend'] == expected_target, 'selected call-slot addend mismatch')
    return row


def exception_records(image, fde):
    if fde['lsda'] is None:
        return [], None
    candidates = [s for s in image.sections if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(candidates) == 1, 'missing exception section')
    section = candidates[0]
    _, off = image.mapping(fde['lsda'], 1)
    endsec = section['offset'] + section['size']
    require(section['offset'] <= off < endsec, 'LSDA outside exception section')
    data, pos = image.data, off
    require(data[pos] == 0xff, 'unsupported LPStart encoding')
    pos += 1
    require(pos < endsec, 'truncated LSDA')
    encoding = data[pos]
    pos += 1
    type_base = None
    if encoding != 0xff:
        require(encoding == 0x9b, 'unsupported type encoding')
        delta, pos = uleb(data, pos, endsec)
        type_base = pos + delta
        require(type_base <= endsec, 'type table outside section')
    require(pos < endsec and data[pos] == 1, 'unsupported call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, endsec)
    end = pos + size
    require(end <= endsec and (type_base is None or end <= type_base), 'invalid call-site extent')
    out, previous = [], 0
    while pos < end:
        row_start = pos
        begin, pos = uleb(data, pos, end)
        length, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        require(begin >= previous and fde['start'] + begin + length <= fde['end'],
                'invalid exception interval')
        require(not landing or fde['start'] + landing < fde['end'], 'invalid landing')
        previous = begin + length
        out.append((hex(fde['start']), hex(fde['lsda']), hex(row_start),
                    hex(fde['start'] + begin), length, hex(fde['start'] + begin + length),
                    hex(fde['start'] + landing) if landing else '', action,
                    bytes(data[row_start:pos]).hex()))
    return out, {'owner': hex(fde['start']), 'lsda_va': hex(fde['lsda']),
                 'file_offset': hex(off), 'type_encoding': hex(encoding),
                 'raw_through_callsite_table': bytes(data[off:end]).hex(),
                 'limit': 'Action chains and type tables are not decoded.'}


def to_tsv(headers, rows):
    buf = io.StringIO(newline='')
    writer = csv.writer(buf, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return buf.getvalue().encode('ascii')


def to_json(obj):
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


DECISIONS = (
    (0x1350e70, 'outer input is empty', 'return an error'),
    (0x1350e7c, 'outer prefix has high bit set', 'decode prefix; fallthrough returns an error'),
    (0x1350f5a, 'long-form payload length is below short-form threshold', 'return an error'),
    (0x1350f6b, 'outer payload length exceeds remaining bytes', 'return an error'),
    (0x1350fd8, 'outer list payload is empty', 'return an empty vector'),
    (0x1350ffc, 'row prefix has high bit clear', 'leave loop through an error'),
    (0x1351110, 'address payload length differs from selected width', 'release partial allocations and return an error'),
    (0x1351328, 'key payload length differs from selected width', 'release partial allocations and return an error'),
    (0x13513f4, 'row-consumption subtraction borrows', 'enter diagnostic failure call'),
    (0x1351402, 'row consumed length differs from declared length', 'release key vector and return an error'),
    (0x1351453, 'row count differs from capacity', 'skip growth; equality takes growth call'),
    (0x13514d5, 'outer payload bytes remain', 'continue with next row'),
    (0x4e54593, 'outer consumed-length addition carries', 'enter diagnostic failure call'),
    (0x4e5459c, 'outer consumed length differs from declared length', 'write an error and clean temporary values'),
    (0x4e54ffe, 'source length is no greater than old destination length', 'publish shortened or equal destination length'),
    (0x4e55020, 'source length is below old destination length', 'release removed rows before replacement loop'),
    (0x4e55061, 'selected key-vector allocation size overflows', 'enter allocation failure boundary'),
    (0x4e5507e, 'existing-row key allocation size is zero', 'use an empty-vector sentinel and bypass allocation'),
    (0x4e55091, 'allocation returns zero', 'enter allocation failure boundary'),
    (0x4e5512e, 'overlapping row copies remain', 'advance to next row'),
    (0x4e529f6, 'appended-row key allocation size is zero', 'use an empty-vector sentinel and bypass allocation'),
    (0x4e52a0c, 'appended row key allocation returns zero', 'enter allocation failure boundary'),
    (0x1353b0b, 'row capacity is within multiplication bound', 'compute row allocation size'),
    (0x135b614, 'key allocation size passes both checks', 'continue to allocate or reallocate'),
)


ERROR_SITES = (
    ('empty_input', 0x1350e68),
    ('zero_leading_length', 0x1351502),
    ('noncanonical_single_byte', 0x1350ece),
    ('noncanonical_long_length', 0x1350f51),
    ('address_width', 0x13510c5),
    ('key_width', 0x13512ee),
    ('row_not_list', 0x1351777),
    ('row_length_mismatch', 0x1351825),
    ('envelope_length_mismatch', 0x4e54637),
)


def immediate_error(raw):
    if len(raw) == 5 and 0xb8 <= raw[0] <= 0xbf:
        return struct.unpack('<I', raw[1:])[0]
    if len(raw) == 7 and raw[:3] == b'\x48\xc7\x03':
        return struct.unpack('<I', raw[3:])[0]
    raise EvidenceError('unsupported selected error-store instruction')


def indexed_qword_store(raw):
    require(len(raw) in (4, 5) and raw[0] & 0xf8 == 0x48 and raw[1] == 0x89,
            'unsupported indexed store')
    modrm = raw[2]
    require(modrm & 7 == 4 and raw[3] == 0x08, 'unexpected indexed address')
    mod = modrm >> 6
    require((mod == 0 and len(raw) == 4) or (mod == 1 and len(raw) == 5),
            'unsupported indexed displacement')
    return 0 if mod == 0 else raw[4], 8 if raw[0] & 8 else 4


def project_lanes(by_site, address_width, key_width, row_stride):
    """Project selected straight-line moves symbolically, without running code.

    Fixed byte pins cover these shapes; offsets below are decoded from their
    instruction bytes. The model assumes the selected success edges and no
    intervening alias or helper mutation. It tracks labels, not machine code.
    """
    def raw(site):
        return by_site[site][1]['raw']
    def d8(site):
        return raw(site)[-1]
    def d32(site):
        return int.from_bytes(raw(site)[-4:], 'little')
    def move(dst, dst_start, src, src_start, size):
        require(0 <= src_start <= len(src) - size and 0 <= dst_start <= len(dst) - size,
                'symbolic copy outside selected range')
        values = src[src_start:src_start + size]
        require(all(value is not None for value in values), 'symbolic copy uses undefined byte')
        for index, value in enumerate(values, dst_start):
            require(dst[index] is None or dst[index] == value, 'conflicting overlapping stores')
            dst[index] = value

    source = list(range(address_width))
    stack, row = [None] * 256, [None] * row_stride
    prefix = d8(0x13510ee)
    move(stack, d8(0x1351120), source, d8(0x135111c), 4)
    move(stack, d8(0x1351124), source, 0, 4)
    move(stack, d32(0x1351154), source, d8(0x1351150) - prefix, 8)
    move(stack, d32(0x135115f), source, d8(0x135115c) - prefix, 4)
    move(stack, d32(0x1351172), source, d8(0x1351167) - prefix, 1)
    move(stack, d32(0x13513b2), stack, d8(0x13513aa), 4)
    move(stack, d32(0x13513b9), stack, d8(0x13513ae), 4)
    move(stack, d32(0x13513c8), stack, d32(0x13513c0), 8)
    move(stack, d8(0x1351419), stack, d32(0x1351411), 8)
    stage = d32(0x13513e5)
    move(stack, d8(0x1351423), stack, stage, 4)
    move(stack, d8(0x1351427), stack, stage + d8(0x1351420), 4)
    move(stack, d8(0x1351441), stack, d8(0x135143d), 4)
    move(stack, d8(0x1351445), stack, d8(0x1351439), 4)
    move(row, d8(0x135149e), stack, d8(0x1351419), 8)
    move(row, d8(0x13514ab), stack, d8(0x13514a3), 4)
    move(row, d8(0x13514af), stack, d8(0x13514a7), 4)
    move(row, d8(0x13514be), stack, d32(0x135146c), 4)
    move(row, d8(0x13514ba), stack, d32(0x1351460), 1)
    row_base, _ = indexed_qword_store(raw(0x135149e))
    address = row[row_base:row_base + address_width]
    require(address == source, 'address lane projection is not identity')

    source = list(range(key_width))
    stack, key = [None] * 256, [None] * key_width
    prefix = d8(0x1351309)
    move(stack, d8(0x1351336), source, d8(0x1351332), 4)
    move(stack, d8(0x135133a), source, d8(0x135132e), 4)
    move(stack, d8(0x1351342), source, d8(0x135133e) - prefix, 8)
    move(stack, d32(0x135134b), source, d8(0x1351347) - prefix, 8)
    move(stack, d8(0x1351357), source, d8(0x1351353) - prefix, 8)
    last = source[d8(0x135135c) - prefix]
    move(key, d8(0x1351299), stack, d8(0x1351295), 4)
    move(key, 0, stack, d8(0x1351291), 4)
    move(key, d8(0x13512a7), stack, d8(0x13512a2), 8)
    move(key, d8(0x13512b4), stack, d32(0x13512ac), 8)
    move(key, d8(0x13512be), stack, d8(0x13512b9), 8)
    move(key, d8(0x13512c3), [last], 0, 1)
    require(key == source, 'key lane projection is not identity')
    return [('address', i, row_base + i, source_lane) for i, source_lane in enumerate(address)] + [
        ('key', i, i, source_lane) for i, source_lane in enumerate(key)]


def collect(data):
    authenticate(data)  # Never interpret an unauthenticated artifact.
    secs = sections(data)
    image = Image(data, secs)
    fdes = selected_fdes(data, secs)
    relas = relocations(image)
    bodies, unwind, functions, instructions, flows, riprows = [], [], [], [], [], []
    exception_rows, exception_headers = [], []
    decoded = {}
    boundaries = set()
    for start, fde in fdes.items():
        seq = decode_body(image, fde)
        decoded[start] = seq
        boundaries.update(i['site'] for i in seq)
        boundaries.add(fde['end'])
    pins = verify_pins(image, boundaries)
    used_slots = set()
    by_site = {item['site']: (start, item)
               for start, seq in decoded.items() for item in seq}
    decisions = []
    for site, condition, outcome in DECISIONS:
        owner, item = by_site[site]
        require(item['kind'] == 'branch', 'decision is not a branch')
        target = relative_target(item)
        decisions.append((hex(owner), hex(site), item['raw'].hex(), hex(target), condition, outcome))
    errors = []
    for name, site in ERROR_SITES:
        owner, item = by_site[site]
        code = immediate_error(item['raw'])
        errors.append((name, hex(owner), hex(site), item['raw'].hex(), code))
    for start, fde in fdes.items():
        seq = decoded[start]
        end = fde['end']
        code = image.read(start, end - start, True)
        _, off = image.mapping(start, len(code), True)
        codehash = digest(code)
        functions.append((hex(start), hex(end), len(code), hex(off), hex(fde['fde']),
                          hex(fde['cie']), '' if fde['lsda'] is None else hex(fde['lsda']),
                          fde['index'], codehash, ROLES[start]))
        bodies.append({'start': hex(start), 'end_exclusive': hex(end),
                       'file_offset': hex(off), 'sha256': codehash, 'bytes': code.hex()})
        hdr = next(s for s in secs if s['name'] == '.eh_frame_hdr')
        index_va = hdr['address'] + 12 + 8 * fde['index']
        unwind.append({'start': hex(start), 'end_exclusive': hex(end),
                       'index_entry': image.evidence(index_va, 8),
                       'fde_record': frame_record(image, fde['fde']),
                       'cie_record': frame_record(image, fde['cie']),
                       'lsda': '' if fde['lsda'] is None else hex(fde['lsda'])})
        ex, head = exception_records(image, fde)
        local_boundaries = {item['site'] for item in seq}
        for row in ex:
            if row[6]:
                require(int(row[6], 16) in local_boundaries, 'landing is not an instruction boundary')
        exception_rows.extend(ex)
        if head:
            exception_headers.append(head)
        for item in seq:
            raw, va = item['raw'], item['site']
            _, offset = image.mapping(va, len(raw), True)
            instructions.append((hex(start), hex(va), hex(offset), len(raw), raw.hex(), item['kind']))
            target = relative_target(item)
            if target is not None:
                if item['kind'] == 'call_rel32':
                    kind = 'direct_call'
                elif item['kind'] == 'jmp_rel32' or raw[0] == 0xeb:
                    kind = 'direct_jump'
                else:
                    kind = 'conditional'
                owner = ('local' if start <= target < end else
                         'selected_fde' if target in fdes else 'external_or_unresolved')
                flows.append((hex(start), hex(va), hex(offset), kind, raw.hex(), hex(target), owner))
            else:
                op = 1 if raw[0] in range(0x40, 0x50) else 0
                if len(raw) > op + 1 and raw[op] == 0xff and ((raw[op + 1] >> 3) & 7) in (2, 4):
                    kind = 'indirect_call' if ((raw[op + 1] >> 3) & 7) == 2 else 'indirect_jump'
                    flows.append((hex(start), hex(va), hex(offset), kind, raw.hex(), '', 'dynamic'))
                elif raw in (b'\xc3', b'\x0f\x0b', b'\xcc'):
                    flows.append((hex(start), hex(va), hex(offset),
                                  {b'\xc3':'return', b'\x0f\x0b':'ud2', b'\xcc':'int3'}[raw],
                                  raw.hex(), '', 'terminal'))
            ref = rip_reference(item)
            if ref:
                kind, addr = ref
                entries = relas.get(addr, [])
                require(len(entries) <= 1, 'duplicate relocation at selected reference')
                if entries:
                    used_slots.add(addr)
                    entry = entries[0]
                    link = hex(entry['addend']) if entry['type'] == 8 and entry['symbol'] == 0 else ''
                else:
                    link = ''
                riprows.append((hex(start), hex(va), hex(offset), kind, raw.hex(), hex(addr), link))
    # Check the exact indirect bindings which connect the selected bodies.
    for slot, target in ((0x576e220, 0x134f840), (0x576e158, 0x1353a90),
                         (0x576e160, 0x135b590)):
        validate_binding(relas, slot, target)
        require(slot in used_slots, 'selected call slot is not referenced')
    relrows = []
    for slot in sorted(used_slots):
        entry = relas[slot][0]
        relrows.append((hex(slot), entry['section'], hex(entry['entry_va']),
                        hex(entry['file_offset']), entry['type'], entry['symbol'],
                        hex(entry['addend']) if entry['addend'] >= 0 else str(entry['addend']), entry['bytes']))
    # Constants/offsets below are extracted from fixed x86 byte shapes. These
    # are field/stride observations, not source-level type assertions.
    address_width = image.read(0x135110c, 4, True)[3]
    key_width = image.read(0x1351324, 4, True)[3]
    row_shift = image.read(0x135147d, 4, True)[3]
    row_stride = 3 << row_shift
    slot_stride = image.read(0x13512da, 4, True)[3]
    require((address_width, key_width, row_stride, slot_stride) == (20, 32, 48, 32),
            'unexpected selected field widths or strides')
    recipient_disp = struct.unpack('<I', image.read(0x134fe10, 7, True)[3:7])[0]
    require(recipient_disp == 0x80, 'unexpected tagged recipient offset')
    vector_store = by_site[0x134fe04][1]['raw']
    count_store = by_site[0x134fdf8][1]['raw']
    require(vector_store[:3] == b'\x0f\x11\x43' and count_store[:3] == b'\x48\x89\x43',
            'unexpected unsigned list result stores')
    vector_offset, count_offset = vector_store[-1], count_store[-1]
    require(count_offset == vector_offset + 16, 'noncontiguous unsigned list result')
    unsigned_size_raw = by_site[0x4e545b9][1]['raw']
    signed_size_raw = by_site[0x4e54618][1]['raw']
    require(unsigned_size_raw[0] == signed_size_raw[0] == 0xba, 'unexpected copy-size instruction')
    unsigned_copy_size = struct.unpack('<I', unsigned_size_raw[1:])[0]
    signed_copy_size = struct.unpack('<I', signed_size_raw[1:])[0]
    outer_empty = by_site[0x1350fc3][1]['raw']
    inner_empty = by_site[0x1351218][1]['raw']
    require(outer_empty[:4] == inner_empty[:4] == b'\x48\xc7\x44\x24',
            'unexpected empty-vector pointer stores')
    outer_empty_pointer = struct.unpack('<I', outer_empty[-4:])[0]
    inner_empty_pointer = struct.unpack('<I', inner_empty[-4:])[0]
    field_sites = (0x1351486, 0x135148a, 0x1351494, 0x135149e)
    field_offsets = [indexed_qword_store(by_site[site][1]['raw']) for site in field_sites]
    require([offset for offset, width in field_offsets] == [0, 8, 16, 24]
            and all(width == 8 for offset, width in field_offsets), 'unexpected row stores')
    lane_rows = project_lanes(by_site, address_width, key_width, row_stride)
    row_bound_raw = by_site[0x1353afe][1]['raw']
    require(len(row_bound_raw) == 10 and row_bound_raw[:2] == b'\x48\xb8',
            'unexpected row capacity bound')
    row_bound = struct.unpack('<Q', row_bound_raw[2:])[0]
    key_shift = by_site[0x135b5fb][1]['raw'][-1]
    key_high_shift = by_site[0x135b5ff][1]['raw'][-1]
    minimum_compare = by_site[0x1353aa1][1]['raw'][-1]
    minimum_capacity_raw = by_site[0x1353aa5][1]['raw']
    require(minimum_capacity_raw[:2] == b'\x41\xbe', 'unexpected minimum capacity')
    minimum_capacity = struct.unpack('<I', minimum_capacity_raw[2:])[0]
    require(by_site[0x1353a9d][1]['raw'] == by_site[0x135b59d][1]['raw'],
            'row and key growth multiplier shapes differ')
    growth = {'row_size': row_stride, 'key_size': 1 << key_shift,
              'row_count_bound': row_bound, 'key_count_high_shift': key_high_shift,
              'key_byte_shift': key_shift, 'minimum_capacity': minimum_capacity,
              'double_capacity_compare': minimum_compare,
              'limits': 'The guard is followed by allocator boundaries; malformed vector invariants and allocator behavior are not established.'}
    layout = {'coordinates': 'linked ELF virtual addresses before load bias',
              'input_identity': DIGEST,
              'list_parser': hex(0x1350e50),
              'address_width': address_width, 'key_width': key_width,
              'row_stride': row_stride, 'key_stride': slot_stride,
              'unsigned_recipient_offset': recipient_disp,
              'unsigned_list_vector_offset': vector_offset,
              'unsigned_list_count_offset': count_offset,
              'unsigned_copy_size': unsigned_copy_size,
              'signed_copy_size': signed_copy_size,
              'empty_outer_pointer': outer_empty_pointer,
              'empty_key_pointer': inner_empty_pointer,
              'row_layout': [
                  {'offset': field_offsets[0][0], 'width': field_offsets[0][1], 'role_inferred': 'key vector capacity'},
                  {'offset': field_offsets[1][0], 'width': field_offsets[1][1], 'role_inferred': 'key vector pointer'},
                  {'offset': field_offsets[2][0], 'width': field_offsets[2][1], 'role_inferred': 'key vector length'},
                  {'offset': field_offsets[3][0], 'width': address_width, 'role_inferred': 'address bytes'}],
              'basis': ['row_vector_words', 'row_address_first', 'row_stride',
                        'slot_width_check', 'slot_stride', 'tagged_recipient_load'],
              'limitations': 'Layout labels and source type names are inferences; padding and caller aliasing remain unresolved.'}
    summary = {'binary_sha256': digest(data), 'selected_fde_count': len(fdes),
               'selected_bytes': sum(f['end'] - f['start'] for f in fdes.values()),
               'decoded_instructions': len(instructions), 'control_flow_records': len(flows),
               'conditional_transfers': sum(r[3] == 'conditional' for r in flows),
               'annotated_decisions': len(decisions),
               'error_store_records': len(errors), 'projected_byte_lanes': len(lane_rows),
               'indirect_call_records': sum(r[3] == 'indirect_call' for r in flows),
               'pinned_windows': len(pins), 'rip_relative_references': len(riprows),
               'relocation_records': len(relrows), 'exception_tables': len(exception_headers),
               'exception_call_sites': len(exception_rows),
               'exception_landing_rows': sum(bool(r[6]) for r in exception_rows),
               'limits': 'Selected unwind intervals and linear instruction records are not a complete function or reachability census.'}
    return {
        'functions.tsv': to_tsv(('start_va','end_va','bytes','file_offset','fde_va','cie_va','lsda_va','index','sha256','role_inferred'), functions),
        'instructions.tsv': to_tsv(('owner_va','site_va','file_offset','size','bytes','kind'), instructions),
        'control-flow.tsv': to_tsv(('owner_va','site_va','file_offset','kind','bytes','target_va','scope'), flows),
        'decisions.tsv': to_tsv(('owner_va','site_va','branch_bytes','target_va','condition','taken_edge_inferred'), decisions),
        'error-stores.tsv': to_tsv(('case','owner_va','site_va','instruction_bytes','immediate'), errors),
        'lanes.tsv': to_tsv(('field','output_lane','output_offset','input_lane'), lane_rows),
        'windows.tsv': to_tsv(('name','site_va','file_offset','size','bytes'), pins),
        'rip-references.tsv': to_tsv(('owner_va','site_va','file_offset','kind','bytes','target_va','relative_addend'), riprows),
        'relocations.tsv': to_tsv(('slot_va','section','entry_va','file_offset','type','symbol','addend','bytes'), relrows),
        'exception-sites.tsv': to_tsv(('owner_va','lsda_va','entry_file_offset','start_va','size','end_va','landing_va','action','bytes'), exception_rows),
        'exception-headers.json': to_json(exception_headers),
        'unwind.json': to_json(unwind),
        'bodies.json': to_json(bodies),
        'layout.json': to_json(layout),
        'growth.json': to_json(growth),
        'summary.json': to_json(summary),
    }


def write_evidence(out, files):
    out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (out / name).write_bytes(files[name])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    files = collect(TARGET.read_bytes())
    write_evidence(args.out, files)
    print(files['summary.json'].decode('ascii'), end='')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print(f're21_type1_access94: {error}', file=sys.stderr)
        raise SystemExit(1)
