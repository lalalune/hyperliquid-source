#!/usr/bin/env python3
"""Extract node-94 type-3/4 transaction input static evidence (MIT).

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


# These FDE starts are bounded study seeds, not an ELF-wide census.
ROLES = {
    0x1346db0: 'type-3 unsigned transaction fields',
    0x1348310: 'type-3 row-vector cleanup',
    0x1348390: 'type-3 bounded integer decoder',
    0x13485a0: 'type-3 wider integer decoder',
    0x13487c0: 'type-3 value decoder',
    0x1348a80: 'type-3 address and key rows',
    0x1349140: 'type-3 vector of 32-byte elements',
    0x1349530: 'type-4 unsigned transaction fields',
    0x134a770: 'type-4 byte-string decoder',
    0x134a9c0: 'type-4 row-vector cleanup',
    0x134aa40: 'type-4 bounded integer decoder',
    0x134ac50: 'type-4 wider integer decoder',
    0x134ae70: 'type-4 value decoder',
    0x134b130: 'type-4 address and key rows',
    0x134bbd0: 'type-4 vector of fixed-size rows',
    0x1354d30: 'type-4 row integer decoder',
    0x1355110: 'type-4 signed authorization row',
    0x4e51a50: 'type-3 signed envelope',
    0x4e51e50: 'type-3 temporary payload cleanup',
    0x4e559d0: 'type-4 signed envelope',
    0x4e56190: 'type-4 temporary payload cleanup',
}
PINS = (
    (0x4e51a6e, 'outer_input', '4c8b6e08bf020000004d85ed0f841c020000'), # end 0x4e51a80 owner 0x4e51a50
    (0x4e559ee, 'outer_input_4', '4c8b6e08bf020000004d85ed0f841c020000'), # end 0x4e55a00 owner 0x4e559d0
    (0x4e51a83, 'outer_wrong_kind', '0fb61984db780c48c70006000000e911020000'), # end 0x4e51a96 owner 0x4e51a50
    (0x4e55a03, 'outer_wrong_kind_4', '0fb61984db780c48c70006000000e911020000'), # end 0x4e55a16 owner 0x4e559d0
    (0x4e51b49, 'outer_min_long_length', 'bf040000004883fd380f8244010000'), # end 0x4e51b58 owner 0x4e51a50
    (0x4e55ac9, 'outer_min_long_length_4', 'bf040000004883fd380f8244010000'), # end 0x4e55ad8 owner 0x4e559d0
    (0x4e51baa, 'unsigned_call', 'ff1570c59100'), # end 0x4e51bb0 owner 0x4e51a50
    (0x4e55b2a, 'unsigned_call_4', 'ff1538869100'), # end 0x4e55b30 owner 0x4e559d0
    (0x4e51bb0, 'unsigned_sentinel', '4c8bbc24f00000004d39e7752a488b4c2460'), # end 0x4e51bc2 owner 0x4e51a50
    (0x4e55b30, 'unsigned_sentinel_4', '4c8bbc24e00000004d39e7752a488b4c2460'), # end 0x4e55b42 owner 0x4e559d0
    (0x4e51c51, 'signature_call', '488d7c24504c89f6e852410000'), # end 0x4e51c5e owner 0x4e51a50
    (0x4e55bd1, 'signature_call_4', '488d7c24504c89f6e8d2010000'), # end 0x4e55bde owner 0x4e559d0
    (0x4e51c5e, 'signature_error', '440fb6bc24900000004180ff02488b0424754f'), # end 0x4e51c71 owner 0x4e51a50
    (0x4e55bde, 'signature_error_4', '440fb6bc24900000004180ff02488b0424754f'), # end 0x4e55bf1 owner 0x4e559d0
    (0x4e51d11, 'length_compare', '498b4e084889ca4801ea0f82c60000004c39ea0f858c000000'), # end 0x4e51d2a owner 0x4e51a50
    (0x4e55c91, 'length_compare_4', '498b4e084889ca4801ea0f82c60000004c39ea0f858c000000'), # end 0x4e55caa owner 0x4e559d0
    (0x4e51d2a, 'success_body_copy', '4c8d742450488db42400020000bad00000004c89f7488b1d9ac29100ffd30f284424100f284c2420'), # end 0x4e51d52 owner 0x4e51a50
    (0x4e55caa, 'success_body_copy_4', '4c8d742450488db424e0010000bac00000004c89f7488b1d1a839100ffd30f284424100f284c2420'), # end 0x4e55cd2 owner 0x4e559d0
    (0x4e51d98, 'success_publish', 'ba10010000488b3c244c89f6ffd3488b0424'), # end 0x4e51daa owner 0x4e51a50
    (0x4e55d18, 'success_publish_4', 'ba00010000488b3c244c89f6ffd3488b0424'), # end 0x4e55d2a owner 0x4e559d0
    (0x4e51db6, 'length_error', '4929cd723b48c70008000000488968084c8968104c89a0a0000000'), # end 0x4e51dd1 owner 0x4e51a50
    (0x4e55d36, 'length_error_4', '4929cd723b48c70008000000488968084c8968104c89a090000000'), # end 0x4e55d51 owner 0x4e559d0
    (0x4e51dd1, 'body_cleanup', '488dbc2400020000e872000000488b0424'), # end 0x4e51de2 owner 0x4e51a50
    (0x4e55d51, 'body_cleanup_4', '488dbc24e0010000e832040000488b0424'), # end 0x4e55d62 owner 0x4e559d0
    (0x4e51e05, 'unwind_cleanup', '4889c3488dbc2400020000e83b0000004889dfe8f3e28000'), # end 0x4e51e1d owner 0x4e51a50
    (0x4e55d85, 'unwind_cleanup_4', '4889c3488dbc24e0010000e8fb0300004889dfe873a38000'), # end 0x4e55d9d owner 0x4e559d0
    (0x1346dca, 'first_uint', 'e8c1150000488b04244c8b6424084883f80a7559'), # end 0x1346dde owner 0x1346db0
    (0x1346de4, 'second_uint', 'e8a7150000488b04244c8b6c24084883f80a754d'), # end 0x1346df8 owner 0x1346db0
    (0x1346dfe, 'fee_uints', 'e89d170000833c2401741b488b6c24104c8b7c24184889e74c89f6e882170000833c2401'), # end 0x1346e22 owner 0x1346db0
    (0x1346ea6, 'gas_uint', 'e8e5140000488b0424488b5424084883f80a7553'), # end 0x1346eba owner 0x1346db0
    (0x1346ec2, 'recipient_length', '498b6e08b8020000004885ed7420498b36'), # end 0x1346ed3 owner 0x1346db0
    (0x1346fff, 'recipient_cursor', '4829fd0f82e8feffff4889f84c01c049890649896e08b805000000'), # end 0x134701a owner 0x1346db0
    (0x134701a, 'recipient_width', '4080ff140f85ccfeffff'), # end 0x1347024 owner 0x1346db0
    (0x134702c, 'recipient_front_loads', '418b00418b4803894c244b89442448'), # end 0x134703b owner 0x1346db0
    (0x134703b, 'recipient_tail_loads', '488b460848898424c00000008b461048898424b80000000fb66e144989e74c89ff'), # end 0x134705c owner 0x1346db0
    (0x1347059, 'value_call', '4c89ff4c89f6e85c170000'), # end 0x1347064 owner 0x1346db0
    (0x13470dd, 'payload_call', '4889e74c89f6e8d80f0000'), # end 0x13470e8 owner 0x1346db0
    (0x1347124, 'access_call', '4889e74c89f6e851190000'), # end 0x134712f owner 0x1346db0
    (0x134719e, 'blob_fee_call', '4889e74c89f6e8f7130000'), # end 0x13471a9 owner 0x1346db0
    (0x13471d4, 'extra_vector_call', '4889e74c89f6e8611f0000'), # end 0x13471df owner 0x1346db0
    (0x1347279, 'recipient_front_output', '8b4424488b4c244b8983b8000000898bbb000000'), # end 0x134728d owner 0x1346db0
    (0x1347355, 'recipient_tail_output', '488b8424c0000000488983bf0000004889e848c1e8208883cb00000089abc7000000e9eafaffff'), # end 0x134737c owner 0x1346db0
    (0x13492a9, 'list32_empty', '48c74424080000000048c74424100100000048c7442418000000004d85e40f84f900000041bf010000004531edeb59'), # end 0x13492d8 owner 0x1349140
    (0x1349361, 'list32_item_width', '4929ec0f822f0100004080fd200f8547010000'), # end 0x1349374 owner 0x1349140
    (0x1349378, 'list32_data_loads', '418b0e418b560389542423894c2420498b480848894c2440498b481048894c2438498b481848894c2428410fb64820884c2407483b442408'), # end 0x13493b0 owner 0x1349140
    (0x13492db, 'list32_data_stores', '488b4424108b4c24208b542423428954280342890c28488b4c24404a894c2807488b4c24384a894c280f488b4c24284a894c28170fb64c240742884c281f4c897c241849ffc7'), # end 0x1349321 owner 0x1349140
    (0x13493ab, 'list32_grow', '483b4424080f8522ffffff488d7c2408ff159f4d4204e912ffffff'), # end 0x13493c6 owner 0x1349140
    (0x13493c6, 'list32_success', '488b44241848894318488b44240848894308488b4424104889431048c70300000000e996fdffffb901000000'), # end 0x13493f2 owner 0x1349140
    (0x13494bb, 'list32_fail_cleanup', '4889430848c7431000000000488b4424284889431848c70301000000488b7424084885f60f849efcffff488b7c241048c1e60531d2ff151a4b4204e988fcffff'), # end 0x13494fb owner 0x1349140
    (0x134bd3a, 'auth_list_empty', '4c89642420488954242848c74424080000000048c74424100800000048c7442418000000004885d20f848d0000004c8d642420'), # end 0x134bd6d owner 0x134bbd0
    (0x134bdbb, 'auth_row_call', '488d7c24304c89e6ffd5837c243001745a'), # end 0x134bdcc owner 0x134bbd0
    (0x134bd90, 'auth_stride', '4c89f848c1e0074a8d3cf848037c2410ba88000000'), # end 0x134bda5 owner 0x134bbd0
    (0x134bdab, 'auth_count', '49ffc74c897c241848837c242800743a'), # end 0x134bdbb owner 0x134bbd0
    (0x134be42, 'auth_error_cleanup', '488943180f11430848c70301000000488b4424084885c00f84b7fdffff488b7c24104889c148c1e107488d34c131d2ff1599214204'), # end 0x134be77 owner 0x134bbd0
    (0x1355263, 'auth_item_chain', '4c8d7424204c89f74889742410e8bbfaffff'), # end 0x1355275 owner 0x1355110
    (0x135541d, 'auth_item_address_width', '80f9140f85b9feffff'), # end 0x1355426 owner 0x1355110
    (0x1355426, 'auth_item_address_load', '418b4d00418b550389542453894c2450'), # end 0x1355436 owner 0x1355110
    (0x135548b, 'auth_item_nonce_short', '48c744242000000000ba0100000084c90f84d50400004c89f74829d74883c708'), # end 0x13554ab owner 0x1355110
    (0x13554fc, 'auth_item_parity', '0fb6064885c00f849a0200004983ff010f87890300004531ed4983ff014c0f44e8488d7c2420'), # end 0x1355522 owner 0x1355110
    (0x135551d, 'auth_item_second_uint', '488d7c2420488b742410e804f8ffff'), # end 0x135552c owner 0x1355110
    (0x13558b2, 'auth_item_third_uint', '488d7c2420488b742410e86ff4ffff'), # end 0x13558c1 owner 0x1355110
    (0x135599d, 'auth_item_length_check', '488b442410482b58080f82fe0000004c39e30f85d3000000'), # end 0x13559b5 owner 0x1355110
    (0x13559fc, 'auth_item_address_output', '448b44244844894030448b44244b448940334c8b4424784c8940374d89c849c1e820448840434489483f'), # end 0x1355a26 owner 0x1355110
    (0x1355a4c, 'auth_item_parity_output', '488988800000004c89a88800000031c9e9bdf8ffff'), # end 0x1355a61 owner 0x1355110
    (0x1355a88, 'auth_item_length_error', '488b44240848c74008080000004c89601048895818e977f8ffff4531f6'), # end 0x1355aa5 owner 0x1355110
    (0x4e51e5c, 'cleanup3_row', '4c8bb7900000004c8bbf980000004d85ff74334d8d66084c8b2d96c19100'), # end 0x4e51e7a owner 0x4e51e50
    (0x4e51e80, 'cleanup3_key_stride', '4983c43049ffcf7419498b7424f84885f674ed498b3c2448c1e60531d2'), # end 0x4e51e9d owner 0x4e51e50
    (0x4e51ec1, 'cleanup3_extra', '488bb3a00000004885f67413488bbba800000048c1e60531d2ff1530c19100488b4320'), # end 0x4e51ee4 owner 0x4e51e50
    (0x4e5619c, 'cleanup4_row', '4c8bb7800000004c8bbf880000004d85ff74334d8d66084c8b2d567e9100'), # end 0x4e561ba owner 0x4e56190
    (0x4e561fe, 'cleanup4_extra', '488b83900000004885c0741a488bbb980000004889c148c1e107488d34c131d2ff15ec7d9100'), # end 0x4e56224 owner 0x4e56190
    (0x134954a, 'type4_first_uint', 'e8f1140000488b04244c8b6424084883f80a7559'), # end 0x134955e owner 0x1349530
    (0x1349564, 'type4_second_uint', 'e8d7140000488b04244c8b6c24084883f80a754d'), # end 0x1349578 owner 0x1349530
    (0x134957e, 'type4_fees', 'e8cd160000833c2401741b488b6c24104c8b7c24184889e74c89f6e8b2160000833c2401'), # end 0x13495a2 owner 0x1349530
    (0x1349626, 'type4_gas_uint', 'e815140000488b0424488b5424084883f80a7553'), # end 0x134963a owner 0x1349530
    (0x1349642, 'type4_recipient_length', '498b6e08b8020000004885ed7420498b36'), # end 0x1349653 owner 0x1349530
    (0x134977f, 'type4_recipient_cursor', '4829fd0f82e8feffff4889f84c01c049890649896e08b805000000'), # end 0x134979a owner 0x1349530
    (0x134979a, 'type4_recipient_width', '4080ff140f85ccfeffff'), # end 0x13497a4 owner 0x1349530
    (0x13497ac, 'type4_recipient_front_loads', '418b00418b4803894c244b89442448'), # end 0x13497bb owner 0x1349530
    (0x13497bb, 'type4_recipient_tail_loads', '488b460848898424b00000008b461048898424a80000000fb66e144989e74c89ff'), # end 0x13497dc owner 0x1349530
    (0x13497d9, 'type4_value_call', '4c89ff4c89f6e88c160000'), # end 0x13497e4 owner 0x1349530
    (0x134985d, 'type4_payload_call', '4889e74c89f6e8080f0000'), # end 0x1349868 owner 0x1349530
    (0x13498a4, 'type4_access_call', '4889e74c89f6e881180000'), # end 0x13498af owner 0x1349530
    (0x134991e, 'type4_extra_vector_call', '4889e74c89f6e8a7220000'), # end 0x1349929 owner 0x1349530
    (0x13499c3, 'type4_recipient_front_output', '8b4424488b4c244b8983a8000000898bab000000'), # end 0x13499d7 owner 0x1349530
    (0x1349a89, 'type4_recipient_tail_output', '488b8424b0000000488983af0000004889e848c1e8208883bb00000089abb7000000e936fbffff'), # end 0x1349ab0 owner 0x1349530
    (0x1348daa, 'type3_access_width', '4180fe140f85cf020000'), # end 0x1348db4 owner 0x1348a80
    (0x134b3e0, 'type4_access_width', '4180fe140f85f0040000'), # end 0x134b3ea owner 0x134b130
    (0x134b61f, 'type4_access_key_width', '4180fc200f85d3020000'), # end 0x134b629 owner 0x134b130
    (0x134b5d3, 'type4_access_key_stride', '4983c6204c89ed4d85ff'), # end 0x134b5dd owner 0x134b130
    (0x1349321, 'type3_keycount', '4983c5204d89f04d85e4'), # end 0x134932b owner 0x1349140
    (0x134725b, 'type3_unsigned_vector', '488b8424a0000000488983b00000000f288424900000000f1183a0000000'), # end 0x1347279 owner 0x1346db0
    (0x13499a5, 'type4_unsigned_vector', '488b8424a0000000488983a00000000f288424900000000f118390000000'), # end 0x13499c3 owner 0x1349530
    (0x1354d7a, 'row_uint_width', '803e0074584983ff20765f'), # end 0x1354d85 owner 0x1354d30
    (0x1354dd7, 'row_uint_leading_zero', '48c7470801000000e9af010000'), # end 0x1354de4 owner 0x1354d30
    (0x1354f4f, 'row_uint_zero', '4584ff0f8522feffff31c031c931f631d2ebc4'), # end 0x1354f62 owner 0x1354d30
    (0x134bd6d, 'auth_row_allocator_slot', '488b2d14244204'), # end 0x134bd74 owner 0x134bbd0
    (0x134bde1, 'auth_row_vec_grow', '4c3b7c240875a8488d7c2408ff159d234204eb9b'), # end 0x134bdf5 owner 0x134bbd0
    (0x4e51be7, 'type3_unsigned_stage', '488dbc2460010000488d742450488b1de5c39100baa0000000ffd30f108424f80000000f108c24080100000f118424a80200000f118c24b8020000488b84241801000048898424c8020000488dbc2400020000'),
    (0x4e51c32, 'type3_stage_last', '488dbc2400020000baa0000000488db42460010000ffd34c89bc24a0020000'),
    (0x4e55b67, 'type4_unsigned_stage', '488dbc2450010000488d742450488b1d65849100ba90000000ffd30f108424e80000000f108c24f80000000f118424780200000f118c2488020000488b8424080100004889842498020000488dbc24e0010000'),
    (0x4e55bb2, 'type4_stage_last', '488dbc24e0010000ba90000000488db42450010000ffd34c89bc2470020000'),
    (0x1348de2, 'type3_keylist_call', 'e859030000'),
    (0x1346f27, 'type3_recipient_header_advance', '4c8d4601'),
    (0x13496a7, 'type4_recipient_header_advance', '4c8d4601'),
    (0x1349350, 'key32_header_advance', '4d8d7001'),
    (0x1355341, 'authorization_address_header_advance', '4c8d6e01'),
    (0x134bdd1, 'authorization_row_copy', '4c89ef488d74243841ffd6'),
    (0x1348549, 'uint8_width', '80fa08760431c0eb1f'),
    (0x134855b, 'uint8_zero', '84d27435440fb6364584f60f8577feffffb801000000488907'),
    (0x134872c, 'uint16_width', '80fa10763731c0eb50'),
    (0x134876f, 'uint16_zero', '84d2743a440fb6364584f60f8571feffffb80100000048894708'),
    (0x13489ba, 'uint32_order', '84d27475803b0074184883fa207677b801000000b90800000031d24889140f'),
    (0x134abf9, 'uint8_width4', '80fa08760431c0eb1f'),
    (0x134ac0b, 'uint8_zero4', '84d27435440fb6364584f60f8577feffffb801000000488907'),
    (0x134addc, 'uint16_width4', '80fa10763731c0eb50'),
    (0x134ae1f, 'uint16_zero4', '84d2743a440fb6364584f60f8571feffffb80100000048894708'),
    (0x134b06a, 'uint32_order4', '84d27475803b0074184883fa207677b801000000b90800000031d24889140f'),
    (0x1354d7a, 'row32_order', '803e0074584983ff20765fb801000000b90800000031d24889140f'),
    (0x134a77e, 'payload_entry', '4c8b6608b8020000004d85e40f84e2010000'),
    (0x134a846, 'payload_header', '418d4d0880f9c80f83fa0000004180fdf80f93c149ffcc49ffc64c89364c896608c0e10680c9b7'),
    (0x134a891, 'payload_length_leading_zero', '41803e000f84f9000000'),
    (0x134a8b4, 'payload_length_decode', '4c8b3c24490fcfb8040000004983ff380f82a8000000'),
    (0x134a8da, 'payload_bounds', '4180fdf70f878e0000004d29fc0f8285000000498d042f4889014c8961084d85ff'),
    (0x134a7b0, 'payload_alloc', '4c89ffff151f3842044885c00f84d90100004989c4'),
    (0x134a7c2, 'payload_copy', '4989c44889c74c89f64c89faff150c38420441f6c401'),
    (0x134a82b, 'payload_output', '4c89e14883c9014889034c8963084c897b1048894b18e93f010000418d4d08'),
    (0x134a99b, 'payload_allocation_fail', 'bf010000004c89feff150f364204'),
    (0x13470e8, 'payload_word_stage3', '4c8b3c240f104424080f29442470488b44241848898424800000004d85ff747d488b84248000000048894424400f284424700f11442430'),
    (0x1349868, 'payload_word_stage4', '4c8b3c240f104424080f29442470488b44241848898424800000004d85ff747d488b84248000000048894424400f284424700f11442430'),
    (0x13472c5, 'payload_unsigned3', '0f104424280f104c24380f298424300100000f298c24400100000f294b300f294320'),
    (0x1349a0c, 'payload_unsigned4', '0f104424280f104c24380f298424200100000f298c24300100000f294b300f294320'),
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
    return (json.dumps(obj, indent=2, sort_keys=True) + '\n').encode('ascii')


# Prior-owned dispatch/converter instructions are only interface anchors.
# The corresponding FDEs are not selected or re-exported as new coverage.
BOUNDARY_PINS = (
    (0x4e4ea61, 'type3_dispatch_source16', '0f108c24d8010000'),
    (0x4e4ea69, 'type3_dispatch_source_tail', '0f109424e8010000'),
    (0x4e4ea7d, 'type3_dispatch_stage16', '0f294c2410'),
    (0x4e4ea82, 'type3_dispatch_stage_tail', '0f29542420'),
    (0x4e4eac5, 'type3_dispatch_reload16', '0f284c2410'),
    (0x4e4ead1, 'type3_dispatch_store16', '0f118bc8000000'),
    (0x4e4ead8, 'type3_dispatch_reload_tail', '488b442420'),
    (0x4e4eadd, 'type3_dispatch_store_tail', '488983d8000000'),
    (0x4e4f2e9, 'type3_environment_tag', 'c6833c01000001'),
    (0x4e4f2f0, 'type3_environment_source16', '410f1086c8000000'),
    (0x4e4f2f8, 'type3_environment_store16', '0f11833d010000'),
    (0x4e4f2ff, 'type3_environment_source_tail', '418b8ed8000000'),
    (0x4e4f306, 'type3_environment_store_tail', '898b4d010000'),
    (0x4e4e68c, 'type4_auth_dispatch_source', '0f108424b8010000'),
    (0x4e4e6ac, 'type4_auth_dispatch_stage', '0f290424'),
    (0x4e4e6f4, 'type4_auth_dispatch_reload', '0f280424'),
    (0x4e4e6fd, 'type4_auth_dispatch_store', '0f1183a8000000'),
    (0x4e4f141, 'type4_auth_converter_count_stride', '4d8ba6b00000004c89e048c1e0074e8d3ce0'),
    (0x4e4f6d0, 'type4_auth_converter_pointer_allocate', '4d8baea80000004c89ffff15f8e89100'),
    (0x4e4f700, 'type4_auth_converter_copy_loop', '4939ef74214c89ee4801ee498d3c2eba88000000ff15c6e891004881c58800000049ffcc75da'),
    (0x4e4f785, 'type4_auth_converter_publish', '48c74370000000004c8963784c89b3800000004c89a388000000'),
    (0x4e4e694, 'type4_dispatch_source16', '0f108c24c8010000'),
    (0x4e4e69c, 'type4_dispatch_source_tail', '0f109424d8010000'),
    (0x4e4e6b0, 'type4_dispatch_stage16', '0f294c2410'),
    (0x4e4e6b5, 'type4_dispatch_stage_tail', '0f29542420'),
    (0x4e4e6f8, 'type4_dispatch_reload16', '0f284c2410'),
    (0x4e4e704, 'type4_dispatch_store16', '0f118bb8000000'),
    (0x4e4e70b, 'type4_dispatch_reload_tail', '488b442420'),
    (0x4e4e710, 'type4_dispatch_store_tail', '488983c8000000'),
    (0x4e4f06d, 'type4_environment_tag', 'c6833c01000001'),
    (0x4e4f074, 'type4_environment_source16', '410f1086b8000000'),
    (0x4e4f07c, 'type4_environment_store16', '0f11833d010000'),
    (0x4e4f083, 'type4_environment_source_tail', '418b8ec8000000'),
    (0x4e4f08a, 'type4_environment_store_tail', '898b4d010000'),
    (0x4e4ea37, 'payload_dispatch3_first', '4c8dbc2480000000488db424200100004c8b2d92f59100baa00000004c89ff41ffd5'),
    (0x4e4eab3, 'payload_dispatch3_second', 'baa00000004c89f74c89fe41ffd5'),
    (0x4e4e7d3, 'payload_dispatch3_base', '4c8d7310'),
    (0x4e4f321, 'payload_converter3_call', '498d7648498b4630498b5638498b4e40488d7c2408ff104c8dbbc0000000'),
    (0x4e4f35e, 'payload_converter3_publish', '0f104424080f104c2418410f114f10410f1107'),
    (0x4e4e66a, 'payload_dispatch4_first', '4c8dbc2480000000488db424200100004c8b2d5ff99100ba900000004c89ff41ffd5'),
    (0x4e4e6e6, 'payload_dispatch4_second', 'ba900000004c89f74c89fe41ffd5'),
    (0x4e4e65a, 'payload_dispatch4_base', '4c8d7310'),
    (0x4e4f0a5, 'payload_converter4_call', '498d7648498b4630498b5638498b4e40488d7c2408ff104c8dbbc0000000'),
    (0x4e4f0e2, 'payload_converter4_publish', '0f104424080f104c2418410f114f10410f1107'),
)


def verify_boundary_pins(image):
    rows = []
    for site, name, expected in BOUNDARY_PINS:
        raw = bytes.fromhex(expected)
        actual = image.read(site, len(raw), True)
        require(actual == raw, f'prior interface anchor changed: {name}')
        rows.append((name, hex(site), hex(image.mapping(site, len(raw), True)[1]), len(raw), actual.hex()))
    return rows


# Descriptions are interpretations of specific branch sites, whose bytes and
# destinations are decoded below. They are not a complete reachable CFG.
DECISIONS = (
    (0x4e51a7a, 'outer input length zero', 'outer error word 2'),
    (0x4e51ac6, 'one-byte short-string payload has high bit clear', 'outer error word 3'),
    (0x4e51b1d, 'long-form length begins with zero', 'outer error word 1'),
    (0x4e51b52, 'long-form length below 56', 'outer error word 4'),
    (0x4e51bbb, 'unsigned sentinel differs from signed-minimum', 'continue to signature'),
    (0x4e51c6f, 'signature result byte differs from 2', 'continue to length check'),
    (0x4e51d1b, 'remaining plus declared length carries', 'external failure boundary'),
    (0x4e51d24, 'consumed length differs from declared length', 'error word 8 and cleanup'),
    (0x4e559fa, 'outer input length zero', 'outer error word 2'),
    (0x4e55a46, 'one-byte short-string payload has high bit clear', 'outer error word 3'),
    (0x4e55a9d, 'long-form length begins with zero', 'outer error word 1'),
    (0x4e55ad2, 'long-form length below 56', 'outer error word 4'),
    (0x4e55b3b, 'unsigned sentinel differs from signed-minimum', 'continue to signature'),
    (0x4e55bef, 'signature result byte differs from 2', 'continue to length check'),
    (0x4e55c9b, 'remaining plus declared length carries', 'external failure boundary'),
    (0x4e55ca4, 'consumed length differs from declared length', 'error word 8 and cleanup'),
    (0x1346ece, 'recipient input length zero', 'error word 2'),
    (0x1347002, 'short recipient payload exceeds remaining bytes', 'error word 2'),
    (0x134701e, 'short recipient byte-string width differs from 20', 'error word 5'),
    (0x134964e, 'recipient input length zero', 'error word 2'),
    (0x1349782, 'short recipient payload exceeds remaining bytes', 'error word 2'),
    (0x134979e, 'short recipient byte-string width differs from 20', 'error word 5'),
    (0x134a78a, 'type-4 input string has no header', 'error word 2'),
    (0x134a7bc, 'type-4 input allocation returns zero', 'external allocation-failure boundary'),
    (0x134a7d8, 'type-4 nonempty input allocation pointer has low bit set', 'select alternate clone table'),
    (0x134a80a, 'type-4 one-byte short input lacks its payload', 'error word 2'),
    (0x134a819, 'type-4 one-byte short input has high bit clear', 'error word 3'),
    (0x134a878, 'type-4 long-form length bytes are truncated', 'error word 2'),
    (0x134a895, 'type-4 long-form length begins with zero', 'error word 1'),
    (0x134a8c4, 'type-4 long-form length below 56', 'error word 4'),
    (0x134a8de, 'type-4 long header denotes a list', 'error word 2 or 7 according to remaining length'),
    (0x134a8e7, 'type-4 long input payload exceeds remaining bytes', 'error word 2'),
    (0x134a91f, 'type-4 short input payload is nonempty', 'allocate and copy'),
    (0x1348dae, 'type-3 access row address width differs from 20', 'row error word 5'),
    (0x134b3e4, 'type-4 access row address width differs from 20', 'row error and outer cleanup'),
    (0x134b623, 'type-4 access key width differs from 32', 'key-vector cleanup and row error'),
    (0x134854c, 'type-3 8-byte integer payload width is at most 8', 'continue to leading-zero test'),
    (0x134872f, 'type-3 16-byte integer payload width is at most 16', 'continue to leading-zero test'),
    (0x134abfc, 'type-4 8-byte integer payload width is at most 8', 'continue to leading-zero test'),
    (0x134addf, 'type-4 16-byte integer payload width is at most 16', 'continue to leading-zero test'),
    (0x13489c1, 'type-3 32-byte integer payload begins with zero', 'error word 1'),
    (0x13489c7, 'type-3 32-byte nonzero integer payload width is at most 32', 'continue value conversion'),
    (0x134b071, 'type-4 32-byte integer payload begins with zero', 'error word 1'),
    (0x134b077, 'type-4 32-byte nonzero integer payload width is at most 32', 'continue value conversion'),
    (0x1354d7d, 'type-4 row integer payload begins with zero', 'error word 1'),
    (0x1354d83, 'type-4 row nonzero integer payload width is at most 32', 'continue value conversion'),
    (0x13492c7, '32-byte-element outer list has zero payload', 'return empty vector'),
    (0x1349364, '32-byte element exceeds remaining list bytes', 'error word 2 and free vector'),
    (0x134936e, '32-byte element width differs from 32', 'error word 5 and free vector'),
    (0x13493b0, 'initialized count differs from capacity', 'append without reserve'),
    (0x134bd62, 'type-4 row-list has zero payload', 'return empty vector'),
    (0x134bdca, 'row decoder returns tag 1', 'copy error and free vector'),
    (0x134bde6, 'initialized count differs from capacity', 'append without reserve'),
    (0x1355420, 'row address width differs from 20', 'row error word 5'),
    (0x1355502, 'encoded parity payload begins with zero', 'row error word 1'),
    (0x135550c, 'encoded parity payload exceeds one byte', 'row error word 0'),
    (0x13559a6, 'row length subtraction borrows', 'external failure boundary'),
    (0x13559af, 'row consumed length differs from declared length', 'row error word 8'),
    (0x4e51e6d, 'type-3 row count zero', 'skip row-element loop'),
    (0x4e51ecb, 'type-3 extra-vector capacity zero', 'skip its deallocation'),
    (0x4e561ad, 'type-4 row count zero', 'skip row-element loop'),
    (0x4e56208, 'type-4 extra-vector capacity zero', 'skip its deallocation'),
)


def short_fixed(data, width):
    """Model only the inspected short-string address/hash branches.

    Return (raw error or None, consumed, value). Wider RLP prefixes are not
    modeled here; the static instruction ledger retains their branches.
    """
    require(type(data) is bytes and width in (20, 32), 'invalid fixed-width model input')
    if not data:
        return 2, 0, None
    first = data[0]
    require(first <= 0xb7, 'long strings and lists are outside this model')
    if first < 0x80:
        return 5, 1, None
    n = first - 0x80
    if n == 1:
        if len(data) < 2:
            return 2, 1, None
        if data[1] < 0x80:
            return 3, 1, None
    if len(data) - 1 < n:
        return 2, 1, None
    if n != width:
        return 5, 1 + n, None
    return None, 1 + n, data[1:1 + n]


def uint_payload(payload, width):
    """Model only the selected short-string integer payload predicates."""
    require(type(payload) is bytes and width in (8, 16, 32) and len(payload) <= 55,
            'integer payload outside bounded model')
    if width != 32 and len(payload) > width:
        return 0, None
    if payload and payload[0] == 0:
        return 1, None
    if len(payload) > width:
        return 0, None
    return None, int.from_bytes(payload, 'big')


def long_one_byte_string(data):
    """Model only a long byte string with a one-byte length-of-length."""
    require(type(data) is bytes and data and data[0] == 0xb8, 'expected one-byte long string header')
    if len(data) < 2:
        return 2, 1, None
    length = data[1]
    if length == 0:
        return 1, 2, None
    if length < 56:
        return 4, 2, None
    if len(data) - 2 < length:
        return 2, 2, None
    return None, length + 2, data[2:2 + length]


def parity_payload(payload):
    """Projection after the row's byte-string header has been decoded."""
    require(type(payload) is bytes, 'parity payload must be bytes')
    if not payload:
        return None, 0
    if payload[0] == 0:
        return 1, None
    if len(payload) > 1:
        return 0, None
    return None, payload[0]


def list32_short(data):
    """Model a short list holding zero or one 32-byte short string."""
    require(type(data) is bytes and data, 'short list input required')
    first = data[0]
    require(0xc0 <= first <= 0xf7, 'list header outside bounded model')
    n = first - 0xc0
    if len(data) - 1 < n:
        return 2, None
    payload = data[1:1 + n]
    out = []
    while payload:
        error, used, value = short_fixed(payload, 32)
        if error is not None:
            return error, None
        out.append(value)
        payload = payload[used:]
    return None, out


def collect(data):
    authenticate(data)
    secs = sections(data)
    image = Image(data, secs)
    fdes = selected_fdes(data, secs)
    relas = relocations(image)
    decoded = {start: decode_body(image, fde) for start, fde in fdes.items()}
    boundaries = {ins['site'] for seq in decoded.values() for ins in seq}
    boundaries.update(fde['end'] for fde in fdes.values())
    pins = verify_pins(image, boundaries)
    boundary_pins = verify_boundary_pins(image)
    by_site = {i['site']: (start, i) for start, seq in decoded.items() for i in seq}
    body_records, unwind, function_rows, instruction_rows = [], [], [], []
    transfer_rows, rip_rows, used_slots, ex_rows, ex_headers = [], [], set(), [], []
    for start, fde in fdes.items():
        end, seq = fde['end'], decoded[start]
        code = image.read(start, end - start, True)
        _, off = image.mapping(start, len(code), True)
        function_rows.append((hex(start), hex(end), len(code), hex(off), hex(fde['fde']),
                              hex(fde['cie']), '' if fde['lsda'] is None else hex(fde['lsda']),
                              fde['index'], digest(code), len(seq), ROLES[start]))
        body_records.append({'start': hex(start), 'end_exclusive': hex(end),
                             'file_offset': hex(off), 'sha256': digest(code), 'bytes': code.hex()})
        hdr = next(s for s in secs if s['name'] == '.eh_frame_hdr')
        index_va = hdr['address'] + 12 + 8 * fde['index']
        unwind.append({'start': hex(start), 'end_exclusive': hex(end),
                       'index_entry': image.evidence(index_va, 8),
                       'fde_record': frame_record(image, fde['fde']),
                       'cie_record': frame_record(image, fde['cie']),
                       'lsda': '' if fde['lsda'] is None else hex(fde['lsda'])})
        rows, header = exception_records(image, fde)
        starts = {item['site'] for item in seq}
        for row in rows:
            if row[6]:
                require(int(row[6], 16) in starts, 'exception landing is not an instruction boundary')
        ex_rows.extend(rows)
        if header:
            ex_headers.append(header)
        for item in seq:
            raw, va = item['raw'], item['site']
            _, pos = image.mapping(va, len(raw), True)
            instruction_rows.append((hex(start), hex(va), hex(pos), len(raw), raw.hex(), item['kind']))
            target = relative_target(item)
            if target is not None:
                if item['kind'] == 'call_rel32':
                    kind = 'direct_call'
                elif item['kind'] == 'jmp_rel32' or raw[0] == 0xeb:
                    kind = 'direct_jump'
                else:
                    kind = 'conditional'
                scope = 'local' if start <= target < end else 'selected' if target in fdes else 'external'
                transfer_rows.append((hex(start), hex(va), hex(pos), kind, raw.hex(), hex(target), scope))
            else:
                op = 1 if raw[0] in range(0x40, 0x50) else 0
                if len(raw) > op + 1 and raw[op] == 0xff and ((raw[op + 1] >> 3) & 7) in (2, 4):
                    kind = 'indirect_call' if ((raw[op + 1] >> 3) & 7) == 2 else 'indirect_jump'
                    transfer_rows.append((hex(start), hex(va), hex(pos), kind, raw.hex(), '', 'dynamic'))
                elif raw in (b'\xc3', b'\x0f\x0b', b'\xcc'):
                    transfer_rows.append((hex(start), hex(va), hex(pos),
                        {b'\xc3':'return', b'\x0f\x0b':'ud2', b'\xcc':'int3'}[raw], raw.hex(), '', 'terminal'))
            ref = rip_reference(item)
            if ref:
                kind, addr = ref
                entries = relas.get(addr, [])
                require(len(entries) <= 1, 'duplicate relocation at selected reference')
                target = ''
                if entries:
                    used_slots.add(addr)
                    entry = entries[0]
                    if entry['type'] == 8 and entry['symbol'] == 0 and entry['addend'] >= 0:
                        target = hex(entry['addend'])
                rip_rows.append((hex(start), hex(va), hex(pos), kind, raw.hex(), hex(addr), target))
    for slot, target in ((0x576e120, 0x1346db0), (0x576e168, 0x1349530), (0x576e188, 0x1355110)):
        validate_binding(relas, slot, target)
        require(slot in used_slots, 'selected slot is not referenced by selected code')
    # The nonempty input selects one of the previously studied clone tables.
    for slot, target in ((0x576e140, 0x5670ae8), (0x576e148, 0x5670ac0),
                         (0x5670ae8, 0x1510c60), (0x5670ac0, 0x1510c10)):
        validate_binding(relas, slot, target)
        used_slots.add(slot)
    relocation_rows = []
    for slot in sorted(used_slots):
        row = relas[slot][0]
        relocation_rows.append((hex(slot), row['section'], hex(row['entry_va']), hex(row['file_offset']),
                                row['type'], row['symbol'], hex(row['addend']) if row['addend'] >= 0 else str(row['addend']), row['bytes']))
    # The numeric order follows the direct call sites in each unsigned
    # decoder; source-level field names remain an inference from that order.
    step_seeds = (
        (3, 'chain_word', 0x1346dca), (3, 'nonce', 0x1346de4),
        (3, 'priority_fee', 0x1346dfe), (3, 'fee_limit', 0x1346e19),
        (3, 'gas_limit', 0x1346ea6), (3, 'value', 0x134705f),
        (3, 'input_bytes', 0x13470e3), (3, 'access_list', 0x134712a),
        (3, 'blob_fee', 0x13471a4), (3, 'hash_vector', 0x13471da),
        (4, 'chain_word', 0x134954a), (4, 'nonce', 0x1349564),
        (4, 'priority_fee', 0x134957e), (4, 'fee_limit', 0x1349599),
        (4, 'gas_limit', 0x1349626), (4, 'value', 0x13497df),
        (4, 'input_bytes', 0x1349863), (4, 'access_list', 0x13498aa),
        (4, 'authorization_list', 0x1349924),
    )
    step_rows, last_site = [], {}
    for typ, name, site in step_seeds:
        owner, item = by_site[site]
        require(item['kind'] == 'call_rel32' and site > last_site.get(typ, 0), 'step order or opcode changed')
        target = relative_target(item)
        last_site[typ] = site
        step_rows.append((typ, name, hex(owner), hex(site), item['raw'].hex(), hex(target),
                          'selected' if target in fdes else 'external'))
    decisions = []
    for site, condition, action in DECISIONS:
        owner, item = by_site[site]
        require(item['kind'] == 'branch' and item['raw'][0] != 0xeb, 'decision must be a conditional transfer')
        target = relative_target(item)
        decisions.append((hex(owner), hex(site), item['raw'].hex(), hex(target),
                          hex(site + len(item['raw'])), condition, action))
    lane_rows, layouts = [], []
    for typ, sites in ((3, (0x1347281, 0x1347287, 0x134735d, 0x1347371, 0x134736b)),
                       (4, (0x13499cb, 0x13499d1, 0x1349a91, 0x1349aa5, 0x1349a9f))):
        stores = [by_site[site][1]['raw'] for site in sites]
        offsets = [struct.unpack('<I', raw[-4:])[0] for raw in stores]
        def store_width(raw):
            if raw[:2] in (b'\x89\x83', b'\x89\x8b', b'\x89\xab'):
                return 4
            if raw[:3] == b'\x48\x89\x83':
                return 8
            if raw[:2] == b'\x88\x83':
                return 1
            raise EvidenceError('unsupported recipient output store')
        widths = tuple(store_width(raw) for raw in stores)
        load_sites = ((0x134702c, 0x134702f, 0x134703b, 0x1347047, 0x1347052)
                      if typ == 3 else (0x13497ac, 0x13497af, 0x13497bb, 0x13497c7, 0x13497d2))
        load = [by_site[site][1]['raw'] for site in load_sites]
        require(load[0] == bytes.fromhex('418b00') and load[1][:3] == bytes.fromhex('418b48')
                and load[2][:3] == bytes.fromhex('488b46') and load[3][:2] == bytes.fromhex('8b46')
                and load[4][:3] == bytes.fromhex('0fb66e'), 'unsupported recipient input load')
        prefix_site = 0x1346f27 if typ == 3 else 0x13496a7
        prefix_ins = by_site[prefix_site][1]['raw']
        require(prefix_ins[:3] == bytes.fromhex('4c8d46'), 'unexpected input prefix adjustment')
        advance = prefix_ins[-1]
        input_starts = (0, load[1][-1], load[2][-1] - advance,
                        load[3][-1] - advance, load[4][-1] - advance)
        load_widths = (4, 4, 8 if load[2][0] & 8 else 4, 4, 1)
        require(widths == load_widths, 'recipient load and store widths disagree')
        base = offsets[0]
        require([o - base for o in offsets] == list(input_starts), 'recipient store lanes changed')
        width_site = 0x134701a if typ == 3 else 0x134979a
        width = by_site[width_site][1]['raw'][-1]
        require(width == 20, 'unexpected recipient width')
        for lane in range(width):
            writers = [j for j, (begin, n) in enumerate(zip(input_starts, widths)) if begin <= lane < begin + n]
            require(writers and all(offsets[j] + lane - input_starts[j] == base + lane for j in writers),
                    'recipient lane mismatch')
            lane_rows.append((typ, lane, hex(base + lane), len(writers)))
        copy_site = 0x4e51d37 if typ == 3 else 0x4e55cb7
        pub_site = 0x4e51d98 if typ == 3 else 0x4e55d18
        copy_ins, pub_ins = by_site[copy_site][1]['raw'], by_site[pub_site][1]['raw']
        require(copy_ins[0] == pub_ins[0] == 0xba, 'unexpected copy size instruction')
        body_size = struct.unpack('<I', copy_ins[1:])[0]
        final_size = struct.unpack('<I', pub_ins[1:])[0]
        require(body_size >= base + width and final_size >= body_size, 'recipient lies outside copy')
        layouts.append({'type': typ, 'unsigned_recipient_offset': base, 'recipient_width': width,
                        'copied_unsigned_prefix_bytes': body_size, 'signed_publish_copy_bytes': final_size,
                        'input_to_unsigned_stores': [{'instruction': hex(s), 'offset': o, 'width': n}
                            for s, o, n in zip(sites, offsets, widths)]})
    key_width = by_site[0x134936a][1]['raw'][-1]
    key_stride = by_site[0x1349321][1]['raw'][-1]
    key_loads = [by_site[x][1]['raw'] for x in (0x1349378, 0x134937b, 0x1349387,
                                                  0x1349390, 0x1349399, 0x13493a2)]
    key_stores = [by_site[x][1]['raw'] for x in (0x13492ed, 0x13492e8, 0x13492f6,
                                                   0x1349300, 0x134930a, 0x1349314)]
    require(key_loads[0] == bytes.fromhex('418b0e') and key_loads[1][:3] == bytes.fromhex('418b56')
            and all(raw[:3] == bytes.fromhex('498b48') for raw in key_loads[2:5])
            and key_loads[5][:4] == bytes.fromhex('410fb648'), 'unsupported key input loads')
    require(key_stores[0] == bytes.fromhex('42890c28') and key_stores[1][:4] == bytes.fromhex('42895428')
            and all(raw[:4] == bytes.fromhex('4a894c28') for raw in key_stores[2:5])
            and key_stores[5][:4] == bytes.fromhex('42884c28'), 'unsupported key output stores')
    advance = by_site[0x1349350][1]['raw'][-1]
    key_input = (0, key_loads[1][-1], *(raw[-1] - advance for raw in key_loads[2:]))
    key_output = (0, *(raw[-1] for raw in key_stores[1:]))
    def rex_store_width(raw):
        require(0x40 <= raw[0] <= 0x4f and raw[1] in (0x88, 0x89), 'unsupported REX store')
        return 1 if raw[1] == 0x88 else 8 if raw[0] & 8 else 4
    key_widths = tuple(rex_store_width(raw) for raw in key_stores)
    require(key_input == key_output, 'key byte lane changed')
    key_lanes = []
    for lane in range(key_width):
        writers = [i for i, (begin, n) in enumerate(zip(key_input, key_widths)) if begin <= lane < begin + n]
        require(writers and all(key_output[i] + lane - key_input[i] == lane for i in writers), 'key lane mismatch')
        key_lanes.append((lane, lane, len(writers)))
    auth_loads = [by_site[x][1]['raw'] for x in (0x1355426, 0x135542a, 0x135543f, 0x1355448, 0x1355450)]
    auth_stores = [by_site[x][1]['raw'] for x in (0x1355a01, 0x1355a0a, 0x1355a13, 0x1355a22, 0x1355a1e)]
    require(auth_loads[0][:3] == bytes.fromhex('418b4d') and auth_loads[1][:3] == bytes.fromhex('418b55')
            and auth_loads[2][:3] == bytes.fromhex('488b46') and auth_loads[3][:2] == bytes.fromhex('8b46')
            and auth_loads[4][:3] == bytes.fromhex('0fb646'), 'unsupported authorization address loads')
    require([raw[:3].hex() for raw in auth_stores] == ['448940', '448940', '4c8940', '448948', '448840'],
            'unsupported authorization address stores')
    advance = by_site[0x1355341][1]['raw'][-1]
    auth_input = (auth_loads[0][-1], auth_loads[1][-1], *(raw[-1] - advance for raw in auth_loads[2:]))
    auth_output = tuple(raw[-1] for raw in auth_stores)
    auth_widths = tuple(rex_store_width(raw) for raw in auth_stores)
    require(tuple(o - auth_output[0] for o in auth_output) == auth_input, 'authorization address lane changed')
    row_source = by_site[0x134bdd4][1]['raw'][-1]
    row_result = by_site[0x134bdbb][1]['raw'][-1]
    result_tag_size = row_source - row_result
    require(result_tag_size > 0 and auth_output[0] >= result_tag_size, 'invalid row result layout')
    auth_lanes = []
    for lane in range(20):
        writers = [i for i, (begin, n) in enumerate(zip(auth_input, auth_widths)) if begin <= lane < begin + n]
        require(writers and all(auth_output[i] + lane - auth_input[i] == auth_output[0] + lane for i in writers),
                'authorization address lane mismatch')
        auth_lanes.append((lane, hex(auth_output[0] + lane), hex(auth_output[0] - result_tag_size + lane), len(writers)))
    auth_shift = by_site[0x134bd93][1]['raw'][-1]
    auth_lea = by_site[0x134bd97][1]['raw']
    require(auth_lea == bytes.fromhex('4a8d3cf8'), 'unexpected row-stride addressing')
    auth_stride = (1 << auth_shift) + 8
    copy_raw = by_site[0x134bda0][1]['raw']
    require(copy_raw[0] == 0xba, 'unexpected row copy-size instruction')
    auth_copy_size = struct.unpack('<I', copy_raw[1:])[0]
    require((key_width, key_stride, auth_stride, auth_copy_size) == (32, 32, 136, 136), 'layout check failed')
    integer_widths = [by_site[site][1]['raw'][-1] for site in (0x1348549, 0x134872c, 0x13489c3)]
    other_widths = [by_site[site][1]['raw'][-1] for site in (0x134abf9, 0x134addc, 0x134b073)]
    require(integer_widths == other_widths == [8, 16, 32], 'integer widths changed')
    layout = {'binary_sha256': digest(data), 'recipient_layouts': layouts,
              'integer_payload_widths': integer_widths,
              'type3_key_width': key_width, 'type3_key_stride': key_stride,
              'type4_authorization_row_stride': auth_stride, 'type4_authorization_copy_bytes': auth_copy_size,
              'type4_authorization_address_offset_in_row': auth_output[0] - result_tag_size,
              'limitations': 'Only selected copies and widths are covered; source-level names, padding and aliasing remain inferred or unresolved.'}
    # Decode only the old dispatch's two call instructions and table entries as
    # integration anchors. Those instructions belong to a pending prior packet;
    # no old FDE is selected in this study.
    table = 0x7c1660
    anchors = []
    for typ, expected_call, expected_entry in ((3, 0x4e51a50, 0x4e4e7c6),
                                                (4, 0x4e559d0, 0x4e4e64d)):
        entry_va = table + typ * 4
        raw = image.read(entry_va, 4)
        arm = table + struct.unpack('<i', raw)[0]
        require(expected_entry == arm + 11, 'dispatch call is not in its selected table arm')
        arm_prefix = image.read(arm, 11, True)
        require(arm_prefix == bytes.fromhex('488dbc24200100004889d6'), 'dispatch arm prefix changed')
        call = image.read(expected_entry, 5, True)
        require(call[0] == 0xe8, 'dispatch boundary is not rel32 call')
        target = expected_entry + 5 + struct.unpack('<i', call[1:])[0]
        require(target == expected_call, 'dispatch target differs from selected signed decoder')
        anchors.append({'selector': typ, 'table_entry': image.evidence(entry_va, 4),
                        'arm_va': hex(arm), 'arm_prefix': image.evidence(arm, 11, True),
                        'prior_call': image.evidence(expected_entry, 5, True),
                        'target_va': hex(target), 'scope': 'prior dispatch boundary, not a selected FDE'})
    # The short boundary anchors are in previously studied code. Compose the
    # byte lanes only under normal memcpy/helper returns and no destructive alias.
    boundary_bytes = {name: image.read(site, len(bytes.fromhex(raw)), True)
                      for site, name, raw in BOUNDARY_PINS}
    handoff = []
    for entry, own in zip(anchors, layouts):
        typ = entry['selector']
        def disp(name):
            return struct.unpack('<I', boundary_bytes[f'type{typ}_' + name][-4:])[0]
        prior_prefix = bytes.fromhex(entry['arm_prefix']['bytes'])
        stack_base = struct.unpack_from('<I', prior_prefix, 4)[0]
        signed_offset = disp('dispatch_source16') - stack_base
        signed_tail = disp('dispatch_source_tail') - stack_base
        tagged_offset = disp('dispatch_store16')
        tagged_tail = disp('dispatch_store_tail')
        context_offset = disp('environment_store16')
        context_tail = disp('environment_store_tail')
        require(signed_offset == own['unsigned_recipient_offset'] and signed_tail == signed_offset + 16,
                'signed-to-dispatch lane mismatch')
        require(disp('environment_source16') == tagged_offset and disp('environment_source_tail') == tagged_tail
                and tagged_tail == tagged_offset + 16 and context_tail == context_offset + 16,
                'dispatch-to-environment lane mismatch')
        tag = boundary_bytes[f'type{typ}_environment_tag']
        require(tag[:2] == bytes.fromhex('c683') and tag[-1] == 1, 'unexpected environment tag')
        tag_offset = struct.unpack('<I', tag[2:6])[0]
        require(tag_offset + 1 == context_offset, 'environment tag and address are not adjacent')
        for lane in range(own['recipient_width']):
            handoff.append((typ, lane, hex(signed_offset + lane), hex(tagged_offset + lane),
                            hex(tag_offset), hex(context_offset + lane)))
        own['prior_dispatch_recipient_offset'] = tagged_offset
        own['prior_converter_tag_offset'] = tag_offset
        own['prior_converter_address_offset'] = context_offset
    # A second interface composition traces type-4 authorization rows to
    # the prior converter's owned vector, without selecting that old FDE.
    own_vec_store = by_site[0x13499bc][1]['raw']
    own_count_store = by_site[0x13499ad][1]['raw']
    require(own_vec_store[:3] == bytes.fromhex('0f1183')
            and own_count_store[:3] == bytes.fromhex('488983'), 'unknown unsigned vector stores')
    vec_base = struct.unpack('<I', own_vec_store[-4:])[0]
    own_count = struct.unpack('<I', own_count_store[-4:])[0]
    require(own_count == vec_base + 16, 'unsigned vector count offset changed')
    stack_base = struct.unpack_from('<I', bytes.fromhex(anchors[1]['arm_prefix']['bytes']), 4)[0]
    load_ptr_count = boundary_bytes['type4_auth_dispatch_source']
    output_ptr_count = boundary_bytes['type4_auth_dispatch_store']
    signed_ptr = struct.unpack('<I', load_ptr_count[-4:])[0] - stack_base
    tagged_ptr = struct.unpack('<I', output_ptr_count[-4:])[0]
    require(signed_ptr == vec_base + 8, 'dispatcher does not load unsigned pointer')
    count_stride = boundary_bytes['type4_auth_converter_count_stride']
    ptr_allocate = boundary_bytes['type4_auth_converter_pointer_allocate']
    copy_loop = boundary_bytes['type4_auth_converter_copy_loop']
    publish = boundary_bytes['type4_auth_converter_publish']
    tagged_count = struct.unpack('<I', count_stride[3:7])[0]
    prior_stride = (1 << count_stride[13]) + 8
    require(tagged_count == tagged_ptr + 8
            and struct.unpack('<I', ptr_allocate[3:7])[0] == tagged_ptr,
            'dispatcher and converter authorization inputs disagree')
    require(copy_loop[15] == 0xba and copy_loop[26:29] == bytes.fromhex('4881c5'),
            'unknown authorization row copy loop')
    copy_bytes = struct.unpack('<I', copy_loop[16:20])[0]
    increment = struct.unpack('<I', copy_loop[29:33])[0]
    require(prior_stride == copy_bytes == increment == auth_stride, 'authorization row size changed')
    require(publish[:3] == bytes.fromhex('48c743') and publish[4:8] == bytes(4)
            and publish[8:11] == bytes.fromhex('4c8963')
            and publish[12:15] == bytes.fromhex('4c89b3')
            and publish[19:22] == bytes.fromhex('4c89a3'), 'unknown authorization vector publication')
    env_tag, env_capacity = publish[3], publish[11]
    env_ptr = struct.unpack('<I', publish[15:19])[0]
    env_count = struct.unpack('<I', publish[22:26])[0]
    require((env_capacity, env_ptr, env_count) == (env_tag + 8, env_tag + 16, env_tag + 24),
            'prior authorization vector output is not contiguous')
    layout['type4_authorization_handoff'] = {
        'unsigned_capacity_offset': vec_base, 'unsigned_pointer_offset': signed_ptr,
        'unsigned_count_offset': own_count, 'prior_tagged_pointer_offset': tagged_ptr,
        'prior_tagged_count_offset': tagged_count, 'prior_converter_tag_offset': env_tag,
        'prior_converter_tag_value': 0, 'prior_converter_capacity_offset': env_capacity,
        'prior_converter_pointer_offset': env_ptr, 'prior_converter_count_offset': env_count,
        'prior_converter_copy_bytes_per_row': copy_bytes,
        'limit': 'Conditional on prior dispatch/converter inputs, successful allocation and ordinary copy semantics; later state eligibility remains separate.'}
    payload_words = []
    producer_sites = (0x134a832, 0x134a835, 0x134a839, 0x134a83d)
    producer_raw = [by_site[site][1]['raw'] for site in producer_sites]
    require(producer_raw[0] == bytes.fromhex('488903')
            and [raw[:3].hex() for raw in producer_raw[1:]] == ['4c8963', '4c897b', '48894b'],
            'unexpected payload result stores')
    selected_producer_offsets = (0, *(raw[-1] for raw in producer_raw[1:]))
    roles = ('method_table', 'data_pointer', 'byte_length', 'owner_word')
    for typ, own_store in ((3, 0x13472e3), (4, 0x1349a2a)):
        stage_start = 0x13470e8 if typ == 3 else 0x1349868
        first = by_site[stage_start][1]['raw']
        pair = by_site[stage_start + 4][1]['raw']
        last = by_site[stage_start + 14][1]['raw']
        require(first == bytes.fromhex('4c8b3c24') and pair[:4] == bytes.fromhex('0f104424')
                and last[:4] == bytes.fromhex('488b4424'), 'unexpected payload result stage')
        producer_offsets = (0, pair[-1], pair[-1] + 8, last[-1])
        require(producer_offsets == selected_producer_offsets, 'payload result word layout changed')
        own_raw = by_site[own_store][1]['raw']
        require(own_raw[:3] == bytes.fromhex('0f2943'), 'unexpected unsigned payload store')
        unsigned_base = own_raw[-1]
        arm_base = boundary_bytes[f'payload_dispatch{typ}_base']
        require(arm_base[:3] == bytes.fromhex('4c8d73'), 'unexpected dispatcher payload base')
        tagged_base = unsigned_base + arm_base[-1]
        call = boundary_bytes[f'payload_converter{typ}_call']
        require(call[:3] == bytes.fromhex('498d76') and call[4:7] == bytes.fromhex('498b46')
                and call[8:11] == bytes.fromhex('498b56') and call[12:15] == bytes.fromhex('498b4e')
                and call[21:23] == bytes.fromhex('ff10') and call[23:26] == bytes.fromhex('4c8dbb'),
                'unexpected payload clone call shape')
        observed = (call[7], call[11], call[15], call[3])
        require(observed == tuple(tagged_base + x for x in producer_offsets), 'payload input words shifted')
        env_base = struct.unpack('<I', call[26:30])[0]
        for role, src in zip(roles, producer_offsets):
            payload_words.append((typ, role, hex(src), hex(unsigned_base + src),
                                  hex(tagged_base + src), hex(env_base + src)))
    layout['payload_words_limit'] = ('The type-3 producer is an external boundary. The environment stores the returned clone; identity of its pointer and length '
                                     'depends on the selected prior method table and normal helper returns.')
    layout['integration_limit'] = ('These offsets are conditional on the prior dispatch/converter bodies, '
                                   'normal helper returns, unmodified source bytes and no destructive aliasing.')
    identity = image.read(0x574f0c0, 20)
    require(identity == b'\x00' * 19 + b'\x09', 'prior address-09 key changed')
    recipient_cases = []
    for name, payload in (('empty_input', b''), ('literal_zero', b'\x00'), ('empty_string', b'\x80'),
                          ('short_19', b'\x93' + identity[:19]), ('truncated_20', b'\x94' + identity[:19]),
                          ('address_09', b'\x94' + identity), ('trailing_byte', b'\x94' + identity + b'\xff')):
        error, consumed, value = short_fixed(payload, len(identity))
        recipient_cases.append({'case': name, 'input_hex': payload.hex(), 'error_word': error,
                                'consumed': consumed, 'value_hex': None if value is None else value.hex()})
    parity_cases = []
    for payload in (b'', b'\x00', b'\x01', b'\x01\x00'):
        error, value = parity_payload(payload)
        parity_cases.append({'payload_hex': payload.hex(), 'error_word': error, 'value': value})
    synthetic_key = bytes(range(key_width))
    vector_cases = []
    for name, payload in (('empty', b'\xc0'), ('one', b'\xe1\xa0' + synthetic_key),
                          ('wrong_width', b'\xe0\x9f' + synthetic_key[:31]),
                          ('truncated', b'\xe1\xa0' + synthetic_key[:31])):
        error, values = list32_short(payload)
        vector_cases.append({'case': name, 'input_hex': payload.hex(), 'error_word': error,
                             'values_hex': None if values is None else [v.hex() for v in values]})
    payload_cases = []
    for name, value in (('missing_length', b'\xb8'), ('zero_length', b'\xb8\x00'),
                        ('noncanonical_55', b'\xb8\x37' + bytes(55)),
                        ('truncated_213', b'\xb8\xd5' + bytes(212)),
                        ('length_213', b'\xb8\xd5' + bytes(213))):
        error, consumed, decoded_payload = long_one_byte_string(value)
        payload_cases.append({'case': name, 'error_word': error, 'consumed': consumed,
                              'value_length': None if decoded_payload is None else len(decoded_payload)})
    integer_cases = []
    for width in integer_widths:
        for name, payload in (('empty', b''), ('zero', b'\x00'), ('one', b'\x01'),
                              ('max_width', b'\xff' * width), ('wide_nonzero', b'\x01' + b'\x00' * width),
                              ('wide_zero', b'\x00' * (width + 1))):
            error, value = uint_payload(payload, width)
            integer_cases.append({'width': width, 'case': name, 'payload_hex': payload.hex(),
                                  'error_word': error, 'value_hex': None if value is None else hex(value)})
    examples = {'address_09': image.evidence(0x574f0c0, len(identity)),
                'recipient_short_cases': recipient_cases, 'parity_payload_cases': parity_cases,
                'integer_payload_cases': integer_cases, 'long_payload_cases': payload_cases,
                'list32_short_cases': vector_cases,
                'limits': 'Instruction-derived synthetic projections only; no captured execution or signature validation.'}
    summary = {'binary_sha256': digest(data), 'selected_fde_count': len(fdes),
               'selected_bytes': sum(f['end'] - f['start'] for f in fdes.values()),
               'decoded_instructions': len(instruction_rows), 'transfer_records': len(transfer_rows),
               'conditional_transfers': sum(r[3] == 'conditional' for r in transfer_rows),
               'annotated_decisions': len(decisions), 'ordered_field_calls': len(step_rows), 'pinned_windows': len(pins),
               'prior_interface_anchors': len(boundary_pins), 'projected_handoff_lanes': len(handoff),
               'payload_word_rows': len(payload_words),
               'projected_recipient_lanes': len(lane_rows), 'projected_key_lanes': len(key_lanes),
               'projected_authorization_address_lanes': len(auth_lanes), 'rip_relative_references': len(rip_rows),
               'relocation_records': len(relocation_rows), 'exception_tables': len(ex_headers),
               'exception_call_sites': len(ex_rows), 'exception_landings': sum(bool(r[6]) for r in ex_rows),
               'limits': 'Selected unwind ranges and linear decoding do not establish complete function coverage, reachability or target behavior.'}
    return {
        'functions.tsv': to_tsv(('start_va','end_va','bytes','file_offset','fde_va','cie_va','lsda_va','index','sha256','instructions','role_inferred'), function_rows),
        'instructions.tsv': to_tsv(('owner_va','site_va','file_offset','size','bytes','shape'), instruction_rows),
        'transfers.tsv': to_tsv(('owner_va','site_va','file_offset','kind','bytes','target_va','scope'), transfer_rows),
        'decisions.tsv': to_tsv(('owner_va','site_va','bytes','taken_va','fallthrough_va','condition_inferred','taken_effect_inferred'), decisions),
        'field-calls.tsv': to_tsv(('type','field_inferred','owner_va','site_va','bytes','target_va','scope'), step_rows),
        'payload-words.tsv': to_tsv(('type','word_inferred','producer_offset','unsigned_offset','prior_tagged_offset','prior_env_clone_offset'), payload_words),
        'windows.tsv': to_tsv(('name','site_va','file_offset','size','bytes'), pins),
        'prior-interface-windows.tsv': to_tsv(('name','site_va','file_offset','size','bytes'), boundary_pins),
        'handoff-lanes.tsv': to_tsv(('type','lane','signed_offset','prior_tagged_offset','prior_env_tag_offset','prior_env_address_offset'), handoff),
        'rip-references.tsv': to_tsv(('owner_va','site_va','file_offset','kind','bytes','target_va','relative_addend'), rip_rows),
        'relocations.tsv': to_tsv(('slot_va','section','entry_va','file_offset','type','symbol','addend','bytes'), relocation_rows),
        'exception-sites.tsv': to_tsv(('owner_va','lsda_va','entry_file_offset','start_va','size','end_va','landing_va','action','bytes'), ex_rows),
        'recipient-lanes.tsv': to_tsv(('type','input_lane','unsigned_and_signed_offset','writer_count'), lane_rows),
        'key32-lanes.tsv': to_tsv(('input_lane','vector_element_offset','writer_count'), key_lanes),
        'authorization-lanes.tsv': to_tsv(('input_lane','decoder_result_offset','vector_row_offset','writer_count'), auth_lanes),
        'dispatch-boundaries.json': to_json(anchors),
        'exception-headers.json': to_json(ex_headers),
        'unwind.json': to_json(unwind),
        'bodies.json': to_json(body_records),
        'layout.json': to_json(layout),
        'synthetic-cases.json': to_json(examples),
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
    except (EvidenceError, ValueError, OSError, struct.error) as error:
        print(f'error: {error}', file=sys.stderr)
        raise SystemExit(1)
