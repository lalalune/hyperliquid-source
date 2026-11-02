#!/usr/bin/env python3
"""Recover one node94 typed-transaction recipient-to-environment slice, statically.

Only the authenticated ELF is input. No captured code or external command runs.
All addresses are linked virtual addresses, before load bias. FDE extents are
unwind records, not a complete function census or a proof of source boundaries.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import struct
from pathlib import Path

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Selected bodies only. The existing registry, frame constructor and compressor
# are dependency boundaries; no byte window of those functions is selected.
FUNCTIONS = {
    0x135b670: 'recipient option decoder',
    0x134d5c0: 'type-2 unsigned fields decoder',
    0x134e410: 'payload bytes decoder and allocation',
    0x1510360: 'shared payload clone',
    0x1510520: 'payload ownership promotion',
    0x1510c10: 'first payload clone adapter',
    0x1510c60: 'second payload clone adapter',
    0x46c2d30: 'raw envelope and signature gate',
    0x4e4e600: 'typed envelope dispatch',
    0x4e4eee0: 'transaction to environment conversion',
    0x4e50020: 'transaction digest adapter',
    0x4e52fb0: 'type-2 list and signature decoder',
    0x4e55db0: 'signature component decoder',
    0x4e56860: 'signature scalar decoder',
    0x4e58840: 'signature recovery adapter',
}

# Each window is a reviewed fixed byte shape, not disassembler text. Longer
# code bodies are emitted separately and no general x86 decoder is claimed.
PINS = (
 ('raw_entry',0x46c2d49,'4885d274470fb60684c0785848ffca48ffc64889342448895424080fb6f0488d7c24304889e2ff157b050b01'),
 ('raw_tag_gate',0x46c2d75,'4c8b7424304c8b7c24384c89f04883f0054c09f80f8589010000c6431001eb04'),
 ('raw_address_copy',0x46c2f73,'488db42498000000488dbc24c8020000bae8000000ff1552b00a01'),
 ('raw_hash_edge',0x46c2fa6,'488d7c2430488db42460020000ff153f030b01'),
 ('raw_high_limb_bound',0x46c2fb9,'48b9ffffffffffffff7f'),
 ('raw_sig_bound',0x46c2fc3,'488b8424780300004839c875394883bc2470030000ff7537488b84246803000048b91d50a457736e575d4839c87517488b84246003000048b9a0201b68462fe9df4839c87409'),
 ('raw_recover_gate',0x46c3009,'4839c80f87d1000000488db42440030000488dbc24a0010000488d542430ff15d3020b0180bc24a0010000000f84a8000000'),
 ('raw_publish_copies',0x46c3066,'4c8b3d73af0a01ba500100004c89f741ffd7488dbc24b0030000ba700100004c89f641ffd7'),
 ('raw_publish_output',0x46c30be,'4c8d742440488db424b0030000ba700100004889dfff1507af0a01'),
 ('dispatch_table',0x4e4e610,'4889fb4080fe040f873a020000400fb6c6488d0d383097fb486304814801c8ffe0'),
 ('dispatch_type2',0x4e4e76e,'488dbc24200100004889d6e832480000'),
 ('dispatch_result_bias',0x4e4e77e,'488b842498010000488d4b104889c248f7da'),
 ('dispatch_lane_loads',0x4e4e903,'0f288424b00100000f294424100f288424c00100000f29442420'),
 ('dispatch_lane_stores',0x4e4e9bd,'0f2804240f284c24100f285424200f298ba00000000f2993b00000000f298390000000'),
 ('dispatch_payload_loads',0x4e4e8b7,'0f288424200100000f288c24300100000f289424400100000f289c24500100000f299c24b00000000f299424a00000000f298c24900000000f29842480000000'),
 ('dispatch_payload_stores',0x4e4e98e,'0f288424800000000f288c24900000000f289424a00000000f289c24b00000000f2959300f2951200f2949100f2901'),
 ('dispatch_type2_tag',0x4e4ea1c,'48c743080000000048c70302000000'),
 ('type2_header',0x4e52fce,'4c8b6608bf020000004d85e40f84d0020000488b0e0fb61984db780c48c70006000000e9c502000080fbb8733349ffcc48ffc148890e4c89660883e3'),
 ('type2_long_header',0x4e5302e,'8d530880fac80f83b100000080fbf80f93c249ffcc48ffc148890e4c896608c0e20680cab74189d84128d0410fb6d04929d40f824a020000488d3c1148893e4c89660848c7842490000000000000008039000f8425020000488dbc24900000004829d74883c7084989c64989f54889ceff153caf91004c89ee4c89f04c8bac2490000000490fcdbf040000004983fd380f82ec010000bf020000004d39ec0f82de01000080fbf70f860fffffffeb2b4939dc0f8304ffffffe9c501000049ffcc48ffc148890e4c89660880c340440fb6eb4d39ec0f82a8010000'),
 ('type2_fields_call',0x4e53108,'4889c3488dbc24900000004989f6ff15e4b09100488b842408010000'),
 ('type2_lane_stage',0x4e531d1,'0f288424200100000f298424500200000f288424300100000f29842460020000'),
 ('type2_payload_loads',0x4e5318d,'0f288424900000000f288c24a00000000f289424b00000000f289c24c00000000f295c24400f295424300f294c24200f29442410'),
 ('type2_payload_stores',0x4e53228,'0f284424100f284c24200f285424300f285c24400f299c24f00100000f299424e00100000f298c24d00100000f298424c0010000'),
 ('type2_signature_call',0x4e53264,'488dbc24900000004c89f6e83c2b00000fb6ac24d00000004080fd024889d875'),
 ('type2_length_guard',0x4e53331,'498b4e084889ca4c01ea0f82c90000004c39e20f8593000000'),
 ('type2_inner_copy',0x4e5334a,'4c8db42490000000488db424c00100004c8b3d7fac9100bab00000004c89f741ffd7'),
 ('type2_output_copy',0x4e533c0,'baf00000004889df4c89f641ffd74889d84088abf0000000'),
 ('field_predecessors',0x134d5d1,'4989f64889fb4889e7e801110000488b04244c8b6424084883f80a75594889e74c89f6e8e7100000488b04244c8b6c24084883f80a754d4889e74c89f6'),
 ('field_recipient_call',0x134d6a2,'4889e74c89f6e833100000488b0424488b5424084883f80a753648899424880000004889e74c89f6ff15380b4204803c2401752d'),
 ('field_address_stage',0x134d703,'488b44240e48898424ad0000000f104424010f298424a0000000'),
 ('field_address_output',0x134d858,'0f288424a00000000f118390000000488b8424ad0000004889839d000000'),
 ('field_payload_handoff',0x134d776,'e8950c0000488b0c240f104424080f29442450488b44241848894424604885c90f848e000000488b44246048894424480f284424500f1144243848894c242848894c2430'),
 ('field_payload_output',0x134d896,'0f105424300f105c24400f299424000100000f299c24100100000f295b300f295320'),
 ('payload_input',0x134e41b,'4889fb4c8b6608b8020000004d85e40f84e20100004c8b36450fb62e4584ed784749ffcc498d46014889064c89660841bf01000000'),
 ('payload_allocate_copy',0x134e450,'4c89ffff157ffb41044885c00f84d90100004989c44889c74c89f64c89faff156cfb410441f6c401754a488b05bffc4104'),
 ('payload_owner_store',0x134e4c4,'488b057dfc41044c89e14883c9014889034c8963084c897b1048894b18'),
 ('payload_long_length',0x134e54b,'ff158ffa41044c89f94c8b3c24490fcfb8040000004983ff380f82a800000031c04d39fc0f93c0488d04804883c0024180fdf70f878e0000004d29fc0f8285000000498d042f4889014c8961084d85ff0f89a8000000'),
 ('payload_long_to_copy',0x134e649,'4989eee9fffdffff'),
 ('payload_clone_odd_pointer',0x1510c10,'534989c94989d0488b0ef6c1017522f048ff41107e2b4c8947084c894f1048894f18488d05cffd15044889074889f85bc34889fb4889cae8d4f8ffff4889d85bc3'),
 ('payload_clone_even_pointer',0x1510c60,'534989c94989d0488b16f6c2017522f048ff42107e2f4c8947084c894f1048895718488d057ffd15044889074889f85bc34889d14883e1fe4889fbe880f8ffff4889d85bc3'),
 ('payload_promote_allocation',0x151052e,'488954240848897424104c89c54829cd4c01cd0f82bd0000004d89cf4d89c44989cd4989febf18000000ff157ada2504'),
 ('payload_promote_publish',0x1510567,'4889c34c89284889680848c7401002000000488b442408488b4c2410f0480fb11975254d8966084d897e1049895e18488d056b041604'),
 ('payload_promote_lost_race',0x15105af,'f048ff40107e464d8966084d897e1049894618488d053f041604498906be180000004889df31'),
 ('payload_shared_clone',0x1510360,'488b06f048ff40107e1a4889570848894f1048894718488d058b0616044889074889f8c350ff158dfe2504'),
 ('addr_entry',0x135b680,'488b5e084885db7425488b0e440fb6314981fe80000000751f48ffcb48ffc148890e48895e08c640010031c9eb4448c7400802000000eb38'),
 ('addr_short_header',0x135b702,'4180feb8733248ffcb4c8d79014c893e48895e084183e67f4983fe010f85d20000004885db0f844a010000bf0300000041803f00799f'),
 ('addr_fixed_size_copy',0x135b7f6,'bf020000004c29f30f82d3feffff4c89f24c01fa48891648895e08bf050000004180fe140f85b7feffff418b17418b7703897005895002488b51088b71100fb64914c64001014889500988481589701131c9e9a5feffff'),
 ('signature_two_scalars',0x4e55e06,'4989c4488d5c24204889df4989f6e8470a0000837c242001742a0f1043080f104b180f294424600f294c2470488d7c24204c89f6e8210a0000837c242001'),
 ('signature_parity_header',0x4e55dc3,'488b5e08bf020000004885db0f846c010000488b0e440fb639410fb6d784d20f888b00000048ffcb48ffc148890e48895e0885d20f843f01000083fa010f852d020000'),
 ('signature_parity_zero',0x4e55f83,'4929d172b94901d04c89064c894e0831c9bf0000000084d275a64531ffe961feffff'),
 ('scalar_guards',0x4e568aa,'803e0074584983ff20765fb801000000b908000000'),
 ('scalar_empty_value',0x4e56a6f,'4d29fe72434a8d043e4889034c8973084584ff0f8522feffff31c031c931f631d2ebc4'),
 ('hash_switch',0x4e5002c,'4889fb488b064883c610488d0d9b1697fb486304814801c8ffe0'),
 ('recover_output',0x4e5892f,'0fb6464088442460488d7c2408488d742420e84af3ffff807c240800740431c0eb148b442419894311f30f6f442409f30f7f4301b0018803'),
 ('env_entry',0x4e4eee0,'554157415641554154534881ecc80000004889f34989fe8b42108986380100000f10020f118628010000488b07488d0d882797fb486304814801c8ffe0'),
 ('env_type2_recipient',0x4e4f1cb,'410f1086a00000000f11833c010000498b8ead00000048898b49010000'),
 ('env_type2_payload',0x4e4f1fd,'498d7648498b4630498b5638498b4e40488d7c2408ff104c8dbbc0000000488b83c0000000488bb3c8000000488dbbd8000000488b93d0000000ff50200f104424080f104c2418410f114f10410f1107'),
 ('env_payload_unwind',0x4e4f7e6,'eb000f104424080f104c2418410f114f10410f11074889c7e80d098100'),
)

# Explicitly selected transfers only, not a whole-CFG census. For an indirect
# RIP-relative call, the target is the RELA addend of the resolved slot.
CALLS = (
 ('raw_to_dispatch',0x46c2d6f,0x4e4e600),
 ('raw_digest',0x46c2fb3,0x4e50020),
 ('raw_recover',0x46c3027,0x4e58840),
 ('type2_dispatch',0x4e4e779,0x4e52fb0),
 ('type2_fields',0x4e53116,0x134d5c0),
 ('type2_signature',0x4e5326f,0x4e55db0),
 ('chain_word',0x134d5da,0x134e6e0),
 ('nonce_word',0x134d5f4,0x134e6e0),
 ('fee_first',0x134d60e,0x134e8f0),
 ('fee_second',0x134d629,0x134e8f0),
 ('gas_word',0x134d6a8,0x134e6e0),
 ('recipient',0x134d6ca,0x135b670),
 ('value_word',0x134d723,0x134eb10),
 ('payload',0x134d776,0x134e410),
 ('payload_allocate',0x134e453,0x54c06b0),
 ('payload_copy',0x134e46e,'memcpy'),
 ('payload_length_copy',0x134e54b,'memcpy'),
 ('promotion_allocate',0x1510558,0x54c06b0),
 ('clone_even_promote',0x1510c9b,0x1510520),
 ('clone_odd_promote',0x1510c47,0x1510520),
 ('raw_repack',0x46c2f88,'memcpy'),
 ('raw_publish',0x46c30d3,'memcpy'),
 ('access_list',0x134d7c0,0x134edd0),
 ('signature_first_word',0x4e55e14,0x4e56860),
 ('signature_second_word',0x4e55e3a,0x4e56860),
 ('type2_signing_encoder',0x4e501cf,0x4e52b40),
 ('recover_external',0x4e58941,0x4e57c90),
)

# Site and meaning are hand-reviewed; destination is decoded from the ELF.
BRANCHES = (
 ('raw_empty',0x46c2d4c), ('raw_legacy',0x46c2d53),
 ('raw_dispatch_status',0x46c2d89), ('raw_large_s',0x46c300c),
 ('raw_failed_recovery',0x46c3035), ('raw_output_sentinel',0x46c30bc),
 ('dispatch_type_range',0x4e4e617), ('type2_empty_list',0x4e52fda),
 ('type2_header_class',0x4e52ff9), ('type2_inner_status',0x4e53127),
 ('type2_signature_status',0x4e53283), ('type2_length_overflow',0x4e5333b),
 ('type2_length_mismatch',0x4e53344), ('field_recipient_success',0x134d6d4),
 ('addr_empty',0x135b687), ('addr_nonempty_option',0x135b697),
 ('addr_header_class',0x135b706), ('addr_non_single_length',0x135b71e),
 ('addr_single_truncated',0x135b727), ('addr_short_overrun',0x135b7fe),
 ('addr_short_wrong_width',0x135b81a), ('addr_leading_zero_length',0x135b790),
 ('addr_long_noncanonical',0x135b7c5), ('signature_scalar_failure',0x4e55e1e),
 ('signature_parity_short_or_literal',0x4e55de2), ('signature_parity_literal_zero',0x4e55df7),
 ('signature_parity_literal_not_one',0x4e55e00), ('signature_empty_parity',0x4e55f9b),
 ('signature_second_scalar_failure',0x4e55e44),
 ('scalar_empty',0x4e56879), ('scalar_leading_zero',0x4e568ad),
 ('scalar_width',0x4e568b3), ('recovery_status',0x4e5894b),
 ('payload_empty',0x134e42a), ('payload_long_class',0x134e487),
 ('payload_alloc_null',0x134e45c), ('payload_long_leading_zero',0x134e535),
 ('payload_long_noncanonical',0x134e564), ('payload_long_truncated',0x134e587),
 ('payload_decode_failure',0x134d796), ('clone_even_owner_tag',0x1510c6d),
 ('clone_odd_owner_tag',0x1510c1d), ('clone_even_refcount_failure',0x1510c74),
 ('promote_size_overflow',0x1510541), ('promote_allocation_null',0x1510561),
 ('promote_publish_race',0x1510588), ('promote_refcount_failure',0x15105b4),
 ('shared_clone_refcount_failure',0x1510368),
)

RELATIVE = {
 0x576e200: 0x134d5c0,
 0x576e208: 0x135b670,
 0x576dfd8: 0x54c06b0,
 0x576e140: 0x5670ae8,
 0x576e148: 0x5670ac0,
 0x5670ae8: 0x1510c60,
 0x5670ac0: 0x1510c10,
 0x5670a08: 0x1510360,
 0x57732c8: 0x4e4eee0,
 0x57732f0: 0x4e4e600,
 0x57732f8: 0x4e50020,
 0x5773300: 0x4e58840,
}

# RIP-relative loads and LEAs anchoring the dynamic clone and shared table.
RIP_REFS = (
 ('payload_even_table_slot',0x134e47a,'488b05',0x576e140),
 ('payload_odd_table_slot',0x134e4c4,'488b05',0x576e148),
 ('promoted_shared_table',0x1510596,'488d05',0x5670a08),
 ('race_shared_table',0x15105c2,'488d05',0x5670a08),
 ('shared_clone_table',0x1510376,'488d05',0x5670a08),
 ('odd_clone_table',0x1510c32,'488d05',0x5670a08),
 ('even_clone_table',0x1510c82,'488d05',0x5670a08),
)

# Byte prefixes, displacement widths and expected operands of selected moves.
# Displacements are read again from the ELF, not taken from disassembler text.
LAYOUT_OPERANDS = (
 ('decoder_table',0x134e4d2,'488903',0,0),
 ('decoder_pointer',0x134e4d5,'4c8963',1,8),
 ('decoder_length',0x134e4d9,'4c897b',1,16),
 ('decoder_owner',0x134e4dd,'48894b',1,24),
 ('field_first_pair',0x134d8b4,'0f2953',1,0x20),
 ('field_second_pair',0x134d8b0,'0f295b',1,0x30),
 ('dispatch_result_bias',0x4e4e786,'488d4b',1,0x10),
 ('dispatch_first_pair',0x4e4e9b2,'0f2951',1,0x20),
 ('dispatch_second_pair',0x4e4e9ae,'0f2959',1,0x30),
 ('converter_owner',0x4e4f1fd,'498d76',1,0x48),
 ('converter_table',0x4e4f201,'498b46',1,0x30),
 ('converter_pointer',0x4e4f205,'498b56',1,0x38),
 ('converter_length',0x4e4f209,'498b4e',1,0x40),
 ('environment_payload',0x4e4f214,'4c8dbb',4,0xc0),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


# Adapted from the repository MIT tool tools/evm_kvs_inventory.py; two
# observed SSE opcode forms were added. Unknown encodings fail closed.
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
                     0x5f, 0x60, 0x61, 0x62, 0x66, 0x67, 0x68, 0x6c, 0x6d, 0x6e, 0x6f,
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
            raise ValueError(f'unsupported 0f opcode {op2:02x}')
    else:
        raise ValueError(f'unsupported opcode {op:02x}')
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


def authenticate(data, expected=SHA256):
    require(hashlib.sha256(data).hexdigest() == expected, 'node94 SHA-256 mismatch')


def map_va(sec, address, length):
    """Map only one allocated, file-backed section and reject crossing/ambiguity."""
    require(type(address) is int and type(length) is int and address >= 0 and length > 0,
            'invalid address or size')
    end = address + length
    require(end <= 1 << 64, 'address overflow')
    found = [s for s in sec if s['type'] != 8 and s['flags'] & 2
             and s['address'] <= address and end <= s['address'] + s['size']]
    require(len(found) == 1, 'address is missing, ambiguous, NOBITS or crosses a section')
    s = found[0]
    return s['offset'] + address - s['address']


def at(data, sec, address, length):
    off = map_va(sec, address, length)
    require(off + length <= len(data), 'file range outside artifact')
    return data[off:off + length]


def exact(data, sec, address, expected):
    expected = bytes.fromhex(expected) if isinstance(expected, str) else expected
    observed = at(data, sec, address, len(expected))
    require(observed == expected, 'instruction window mismatch at ' + hex(address))
    return observed


def read_relatives(data, sec):
    wanted = set(RELATIVE) | {0x576dfe0}
    records = {}
    for section in sec:
        if section['type'] != 4:
            continue
        require(section['size'] % 24 == 0, 'misaligned RELA section')
        for off in range(section['offset'], section['offset'] + section['size'], 24):
            loc, info, addend = struct.unpack_from('<QQq', data, off)
            if loc in wanted:
                require(loc not in records, 'duplicate target relocation')
                records[loc] = {'section': section['name'], 'file_offset': off,
                                'info': info, 'addend': addend,
                                'raw': data[off:off + 24].hex()}
    require(set(records) == wanted, 'missing selected relocation')
    for slot, target in RELATIVE.items():
        row = records[slot]
        require(row['info'] == 8 and row['addend'] == target, 'relative relocation mismatch')
    # R_X86_64_GLOB_DAT, read the dynamic symbol name rather than assume libc.
    row = records[0x576dfe0]
    require(row['info'] & 0xffffffff == 6 and row['addend'] == 0, 'copy relocation type')
    symbol_index = row['info'] >> 32
    sym = next(s for s in sec if s['name'] == '.dynsym')
    strings = next(s for s in sec if s['name'] == '.dynstr')
    require(symbol_index > 0 and symbol_index * 24 + 24 <= sym['size'], 'bad dynamic symbol')
    name_off = struct.unpack_from('<I', data, sym['offset'] + symbol_index * 24)[0]
    require(name_off < strings['size'], 'dynamic name offset')
    begin = strings['offset'] + name_off
    end = data.find(b'\0', begin, strings['offset'] + strings['size'])
    require(end >= 0 and data[begin:end] == b'memcpy', 'copy symbol mismatch')
    row['symbol'] = 'memcpy'
    return records


def selected_fdes(data, sec):
    _, index = unwind_index(data)
    selected_index = [r for r in index if r['start'] in FUNCTIONS]
    by_start = {r['start']: r for r in selected_index}
    require(len(by_start) == len(selected_index), 'duplicate selected unwind-index start')
    require(set(by_start) == set(FUNCTIONS), 'selected unwind-index start missing')
    cies, fdes = eh_frame_records(data, sec)
    found = {}
    for f in fdes:
        if f['start'] in FUNCTIONS:
            require(f['start'] not in found, 'duplicate selected FDE')
            require(f['fde'] == by_start[f['start']]['fde'], 'FDE/index disagreement')
            require(f['end'] > f['start'], 'empty FDE')
            off = map_va(sec, f['start'], f['end'] - f['start'])
            text_section = next(s for s in sec if s['name'] == '.text')
            require(text_section['offset'] <= off and off + f['end'] - f['start'] <= text_section['offset'] + text_section['size'], 'FDE not file-backed text')
            f = dict(f)
            f['offset'] = off
            found[f['start']] = f
    require(set(found) == set(FUNCTIONS), 'selected FDE missing')
    return found, cies


def record_bytes(data, sec, va):
    length = struct.unpack('<I', at(data, sec, va, 4))[0]
    require(0 < length < 0xffffffff, 'unsupported frame record')
    return at(data, sec, va, length + 4).hex()


def owner_of(fdes, site, length=1):
    found = [start for start, row in fdes.items() if start <= site and site + length <= row['end']]
    require(len(found) == 1, 'selected instruction outside its FDE')
    return found[0]


def direct_target(insn):
    raw, site, kind = insn['raw'], insn['site'], insn['kind']
    if kind in ('call_rel32', 'jmp_rel32'):
        return site + len(raw) + struct.unpack_from('<i', raw, 1)[0]
    if kind == 'branch':
        disp = raw[2:] if raw[0] == 0x0f else raw[1:]
        return site + len(raw) + int.from_bytes(disp, 'little', signed=True)
    return None


def decode_stream(code, start):
    """Decode a selected FDE sequentially; reject unknown forms or bad local edges."""
    result, cursor = [], 0
    while cursor < len(code):
        item = decode_instruction(code, cursor, start)
        result.append(item)
        cursor += len(item['raw'])
    require(cursor == len(code), 'instruction stream crosses FDE')
    starts = {item['site'] for item in result}
    for item in result:
        target = direct_target(item)
        if target is not None and start <= target < start + len(code):
            require(target in starts, 'direct edge lands inside an instruction')
    return result


def control_kind(raw):
    """Classify only fixed control-transfer opcode shapes in decoded bytes."""
    if raw[0] == 0xe8:
        return 'direct_call'
    if raw[0] in (0xe9, 0xeb):
        return 'direct_jump'
    if 0x70 <= raw[0] <= 0x7f or raw[:1] == b'\x0f' and 0x80 <= raw[1] <= 0x8f:
        return 'conditional'
    if raw[0] in (0xc2, 0xc3):
        return 'return'
    if raw[:2] == b'\x0f\x0b' or raw[0] == 0xcc:
        return 'trap'
    i = 0
    while i < len(raw) and raw[i] in (0x66, 0xf2, 0xf3, 0xf0, 0x2e, 0x64):
        i += 1
    if i < len(raw) and 0x40 <= raw[i] <= 0x4f:
        i += 1
    if i + 1 < len(raw) and raw[i] == 0xff:
        group = (raw[i+1] >> 3) & 7
        if group == 2:
            return 'indirect_call'
        if group == 4:
            return 'indirect_jump'
    return ''


def decoded_corpus(data, sec, fdes):
    rows, controls, boundaries = [], [], {}
    for owner in sorted(fdes):
        fde = fdes[owner]
        body = at(data, sec, owner, fde['end'] - owner)
        items = decode_stream(body, owner)
        boundaries[owner] = {item['site'] for item in items}
        for item in items:
            site, raw = item['site'], item['raw']
            flow = control_kind(raw)
            rows.append([hex(owner), hex(site), hex(map_va(sec, site, len(raw))),
                         len(raw), raw.hex(), flow or 'other'])
            if not flow:
                continue
            dest = direct_target(item)
            # External destinations are not selected bodies and are deliberately
            # left out of this all-instruction transfer census.
            dest_text = (hex(dest) if dest is not None and
                         (owner <= dest < fde['end'] or dest in FUNCTIONS) else '')
            fallthrough = hex(site + len(raw)) if flow == 'conditional' else ''
            controls.append([hex(owner), hex(site), raw.hex(), flow, dest_text, fallthrough])
    for _, site, *_ in (*PINS, *CALLS, *BRANCHES, *RIP_REFS, *LAYOUT_OPERANDS):
        owner = owner_of(fdes, site)
        require(site in boundaries[owner], 'selected site is not an instruction boundary')
    return rows, controls, boundaries


def payload_layout(data, sec):
    operands = []
    values = {}
    for label, site, prefix_hex, width, expected in LAYOUT_OPERANDS:
        prefix = bytes.fromhex(prefix_hex)
        raw = at(data, sec, site, len(prefix) + width)
        require(raw.startswith(prefix), 'payload layout opcode mismatch')
        value = int.from_bytes(raw[len(prefix):], 'little') if width else 0
        require(value == expected, 'payload layout displacement mismatch')
        values[label] = value
        operands.append({'name': label, 'site_va': hex(site), 'bytes': raw.hex(),
                         'displacement': hex(value)})
    decoder = [values['decoder_'+name] for name in ('table','pointer','length','owner')]
    fields = [values['field_first_pair'], values['field_first_pair']+8,
              values['field_second_pair'], values['field_second_pair']+8]
    bias = values['dispatch_result_bias']
    dispatched = [values['dispatch_first_pair']+bias, values['dispatch_first_pair']+bias+8,
                  values['dispatch_second_pair']+bias, values['dispatch_second_pair']+bias+8]
    converter = [values['converter_'+name] for name in ('table','pointer','length','owner')]
    require(decoder == [0,8,16,24] and dispatched == converter, 'payload word layout mismatch')
    require(dispatched == [v+bias for v in fields], 'payload dispatch layout mismatch')
    env = [values['environment_payload'] + v for v in decoder]
    return {'selected_instruction_operands': operands,
            'word_order_inferred': ['table','data_pointer','length','owner'],
            'decoder_result_offsets': [hex(x) for x in decoder],
            'unsigned_field_result_offsets': [hex(x) for x in fields],
            'typed_converter_input_offsets': [hex(x) for x in converter],
            'environment_output_offsets': [hex(x) for x in env],
            'limits': 'Selected nonempty success path, normal callbacks, no unproved aliasing.'}


def decode_call(data, sec, fdes, rel, label, site, expected):
    prefix = at(data, sec, site, 2)
    if prefix[0] == 0xe8:
        raw = at(data, sec, site, 5)
        address = site + 5 + struct.unpack_from('<i', raw, 1)[0]
        slot = None
        actual = address
        kind = 'rel32'
    else:
        require(prefix == b'\xff\x15', 'unsupported selected call')
        raw = at(data, sec, site, 6)
        slot = site + 6 + struct.unpack_from('<i', raw, 2)[0]
        require(slot in rel, 'unbound indirect call')
        if rel[slot]['info'] == 8:
            actual = rel[slot]['addend']
        else:
            require(rel[slot].get('symbol') == 'memcpy', 'unbound imported call')
            actual = rel[slot]['symbol']
        kind = 'rip_relative_slot'
    require(actual == expected, 'selected call target mismatch')
    return [label, hex(owner_of(fdes, site, len(raw))), hex(site), hex(map_va(sec, site, len(raw))),
            kind, raw.hex(), '' if slot is None else hex(slot), hex(actual) if isinstance(actual, int) else actual,
            'selected' if actual in FUNCTIONS else 'external']


def decode_rip_ref(data, sec, fdes, label, site, prefix, expected):
    raw = at(data, sec, site, 7)
    require(raw[:3] == bytes.fromhex(prefix), 'RIP-reference opcode mismatch')
    target = site + len(raw) + struct.unpack_from('<i', raw, 3)[0]
    require(target == expected, 'RIP-reference target mismatch')
    return [label, hex(owner_of(fdes, site, len(raw))), hex(site), raw.hex(), hex(target)]


def decode_branch(data, sec, fdes, label, site):
    first = at(data, sec, site, 2)
    if 0x70 <= first[0] <= 0x7f:
        raw = first
        cc = first[0] & 15
        disp = struct.unpack_from('<b', raw, 1)[0]
    else:
        require(first[0] == 0x0f and 0x80 <= first[1] <= 0x8f, 'unsupported branch')
        raw = at(data, sec, site, 6)
        cc = first[1] & 15
        disp = struct.unpack_from('<i', raw, 2)[0]
    start = owner_of(fdes, site, len(raw))
    target = site + len(raw) + disp
    require(fdes[start]['start'] <= target < fdes[start]['end'], 'branch leaves selected FDE')
    return [label, hex(start), hex(site), raw.hex(), cc, hex(target), hex(site + len(raw))]


def switch_entries(data, sec, fdes):
    # Table targets are relative to the table base, not each table cell.
    rows = []
    tables = (('envelope_type',0x7c1660,0x4e4e600,0x4e4e76e),
              ('transaction_environment',0x7c169c,0x4e4eee0,0x4e4ef79),
              ('signing_encoder',0x7c16d8,0x4e50020,0x4e501ca))
    for label, va, owner, expected_type2 in tables:
        for index in range(5):
            entry = va + 4 * index
            raw = at(data, sec, entry, 4)
            target = va + struct.unpack('<i', raw)[0]
            require(fdes[owner]['start'] <= target < fdes[owner]['end'], 'table target outside selected FDE')
            if index == 2:
                require(target == expected_type2, 'type-2 switch mismatch')
            rows.append([label, hex(va), index, hex(entry), hex(map_va(sec, entry, 4)), raw.hex(), hex(target)])
    return rows


def exceptions(data, sec, fde):
    if fde['lsda'] is None:
        return [], None
    table = next(s for s in sec if s['name'] == '.gcc_except_table')
    off = map_va(sec, fde['lsda'], 1)
    limit = table['offset'] + table['size']
    require(table['offset'] <= off < limit, 'exception pointer outside section')
    pos = off
    require(data[pos] == 0xff, 'unsupported LSDA landing base')
    pos += 1
    require(pos < limit, 'short LSDA')
    encoding = data[pos]
    pos += 1
    type_base = None
    if encoding != 0xff:
        require(encoding == 0x9b, 'unsupported LSDA type encoding')
        delta, pos = uleb(data, pos, limit)
        type_base = pos + delta
        require(type_base <= limit, 'type table outside section')
    require(pos < limit and data[pos] == 1, 'unsupported LSDA call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, limit)
    end = pos + size
    require(end <= limit and (type_base is None or end <= type_base), 'bad LSDA table extent')
    rows = []
    previous = 0
    while pos < end:
        record = pos
        start, pos = uleb(data, pos, end)
        length, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        require(start >= previous and fde['start'] + start + length <= fde['end'], 'bad exception interval')
        require(not landing or fde['start'] + landing < fde['end'], 'bad exception landing')
        previous = start + length
        rows.append([hex(fde['start']), hex(fde['lsda']), hex(record),
                     hex(fde['start'] + start), length, hex(fde['start'] + start + length),
                     hex(fde['start'] + landing) if landing else '', action, data[record:pos].hex()])
    return rows, {'owner': hex(fde['start']), 'lsda_va': hex(fde['lsda']),
                  'file_offset': hex(off), 'type_encoding': hex(encoding),
                  'raw_through_callsite_table': data[off:end].hex(),
                  'limit': 'Action chains and exception types are not decoded.'}


def address_field(data):
    """Synthetic projection of the reviewed address-option byte tests.

    Return (kind, error_code, consumed, address); this is not target execution.
    Only output bytes defined by the selected success arm are returned.
    """
    if not data:
        return ('error', 2, 0, b'')
    p = data[0]
    if p == 0x80:
        return ('none', None, 1, b'')
    if p < 0x80:
        return ('error', 5, 1, b'')
    if p < 0xb8:
        n = p - 0x80
        if n == 1:
            if len(data) < 2:
                return ('error', 2, 1, b'')
            if data[1] < 0x80:
                return ('error', 3, 1, b'')
        if len(data) - 1 < n:
            return ('error', 2, 1, b'')
        if n != 20:
            return ('error', 5, 1 + n, b'')
        return ('address', None, 21, data[1:21])
    if 0xc0 <= p < 0xf8:
        n = p - 0xc0
        return ('error', 7 if len(data) - 1 >= n else 2, 1, b'')
    list_kind = p >= 0xf8
    count = p - (0xf7 if list_kind else 0xb7)
    if len(data) - 1 < count:
        return ('error', 2, 1, b'')
    pos = 1 + count
    if data[1] == 0:
        return ('error', 1, pos, b'')
    n = int.from_bytes(data[1:pos], 'big')
    if n < 56:
        return ('error', 4, pos, b'')
    if len(data) - pos < n:
        return ('error', 2, pos, b'')
    if list_kind:
        return ('error', 7, pos, b'')
    return ('error', 5, pos + n, b'')


def payload_field(data):
    """Project selected RLP byte-field decisions; allocation is not modeled."""
    if not data:
        return ('error', 2, 0, b'')
    p = data[0]
    if p < 0x80:
        return ('bytes', None, 1, data[:1])
    if p < 0xb8:
        n = p - 0x80
        if n == 1:
            if len(data) < 2:
                return ('error', 2, 1, b'')
            if data[1] < 0x80:
                return ('error', 3, 1, b'')
        if len(data) - 1 < n:
            return ('error', 2, 1, b'')
        return ('bytes', None, 1 + n, data[1:1+n])
    if 0xc0 <= p < 0xf8:
        n = p - 0xc0
        return ('error', 7 if len(data) - 1 >= n else 2, 1, b'')
    list_kind = p >= 0xf8
    count = p - (0xf7 if list_kind else 0xb7)
    if len(data) - 1 < count:
        return ('error', 2, 1, b'')
    pos = 1 + count
    if data[1] == 0:
        return ('error', 1, pos, b'')
    n = int.from_bytes(data[1:pos], 'big')
    if n < 56:
        return ('error', 4, pos, b'')
    if len(data) - pos < n:
        return ('error', 2, pos, b'')
    if list_kind:
        return ('error', 7, pos, b'')
    return ('bytes', None, pos + n, data[pos:pos+n])


def scalar_field(data):
    """Synthetic projection of the selected unsigned scalar RLP guards."""
    kind, code, consumed, value = payload_field(data)
    if kind == 'error':
        return (kind, code, consumed, None)
    if value and value[0] == 0:
        return ('error', 1, consumed, None)
    if len(value) > 32:
        return ('error', 8, consumed, None)
    return ('value', None, consumed, int.from_bytes(value, 'big'))


def parity_field(data):
    """Synthetic projection of selected parity field's success/error arms."""
    kind, code, consumed, value = payload_field(data)
    if kind == 'error':
        return (kind, code, consumed, None)
    if not value:
        return ('value', None, consumed, 0)
    if len(value) > 1:
        return ('error', 0, consumed, None)
    if value[0] == 0:
        return ('error', 1, consumed, None)
    if value[0] == 1:
        return ('value', None, consumed, 1)
    return ('error', 9, consumed, None)


def signature_bound(data, sec):
    """Extract the compared limbs from the four selected instruction operands."""
    high = struct.unpack('<Q', at(data, sec, 0x46c2fbb, 8))[0]
    signed_second = struct.unpack('<b', at(data, sec, 0x46c2fd8, 1))[0]
    second = signed_second % (1 << 64)
    third = struct.unpack('<Q', at(data, sec, 0x46c2fe5, 8))[0]
    low = struct.unpack('<Q', at(data, sec, 0x46c2ffc, 8))[0]
    require(second == (1 << 64) - 1, 'unexpected sign-extended comparison')
    return (high, second, third, low)


def bound_exceeded(words, bound):
    """Project the selected unsigned four-limb comparison, high limb first."""
    require(len(words) == len(bound) == 4, 'four limbs required')
    require(all(type(x) is int and 0 <= x < (1 << 64) for x in (*words,*bound)), 'invalid limb')
    require(bound[1] == (1 << 64) - 1, 'unsupported second comparison')
    if words[0] != bound[0]:
        return words[0] > bound[0]
    if words[1] != bound[1]:
        return False
    if words[2] != bound[2]:
        return words[2] > bound[2]
    return words[3] > bound[3]


def rlp_bytes(value):
    if len(value) == 1 and value[0] < 0x80:
        return value
    if len(value) < 56:
        return bytes([0x80 + len(value)]) + value
    n = len(value).to_bytes((len(value).bit_length() + 7) // 8, 'big')
    return bytes([0xb7 + len(n)]) + n + value


def synthetic_transaction(key):
    """Build a non-executed example; the two zero signature scalars are unchecked."""
    payload = bytes(213)
    fields = [b'\x01', b'\x80', b'\x01', b'\x01', b'\x83\x01\x86\xa0',
              rlp_bytes(key), b'\x80', rlp_bytes(payload), b'\xc0',
              b'\x80', b'\x80', b'\x80']
    body = b''.join(fields)
    n = len(body).to_bytes((len(body).bit_length() + 7) // 8, 'big')
    prefix = b'\x02' + bytes([0xf7 + len(n)]) + n
    raw = prefix + body
    recipient_start = len(prefix) + sum(map(len, fields[:5]))
    payload_start = len(prefix) + sum(map(len, fields[:7]))
    require(address_field(raw[recipient_start:]) == ('address', None, 21, key), 'synthetic recipient')
    require(payload_field(raw[payload_start:]) == ('bytes', None, 215, payload), 'synthetic input')
    return {'kind': 'synthetic serialization, not executed or signature-validated',
            'raw_hex': raw.hex(), 'recipient_field_offset': recipient_start,
            'recipient_field_hex': fields[5].hex(), 'input_field_offset': payload_start,
            'input_rlp_prefix_hex': fields[7][:2].hex(), 'input_length': len(payload),
            'input_sha256': hashlib.sha256(payload).hexdigest(), 'raw_length': len(raw)}


def lane_projection(key):
    """Project only the 21 defined lanes through reviewed nonaliasing copies.

    Other bytes are placeholders, not an emulation of the transaction or target.
    Signature success, helper nonmutation of the saved lanes, and nonaliasing
    are assumptions of this path projection.
    """
    require(len(key) == 20, 'recipient must be 20 bytes')
    # Option decoder: two overlapping 4-byte stores, then 8, 4 and 1 bytes.
    helper = bytearray(22)
    helper[1] = 1
    for src, dst, n in ((0, 2, 4), (3, 5, 4), (7, 9, 8), (15, 17, 4), (19, 21, 1)):
        helper[dst:dst+n] = key[src:src+n]
    # Staged 16 + 8 moves overlap by three bytes, as in field_address_stage
    # and field_address_output. Only the defined recipient lanes are modeled.
    fields_stack = bytearray(0x120)
    fields_stack[0xad:0xb5] = helper[14:22]
    fields_stack[0xa0:0xb0] = helper[1:17]
    fields = bytearray(0xb0)
    fields[0x90:0xa0] = fields_stack[0xa0:0xb0]
    fields[0x9d:0xa5] = fields_stack[0xad:0xb5]
    inner = bytes(fields[0x90:0xa5])
    # Selected type-2 stack moves followed by the 0xb0-byte and 0xf0-byte
    # success copies. Other lanes are intentionally left unspecified here.
    ts = bytearray(0x280)
    ts[0x90:0x140] = fields
    ts[0x250:0x260] = ts[0x120:0x130]
    ts[0x260:0x270] = ts[0x130:0x140]
    ts[0x90:0x140] = ts[0x1c0:0x270]
    type2_obj = bytes(ts[0x90:0x180])
    type2 = type2_obj[0x90:0xa5]
    # Dispatch's 16-byte moves shift the child by a 0x10-byte tag region.
    ds = bytearray(0x220)
    ds[0x120:0x210] = type2_obj
    ds[0x10:0x20] = ds[0x1b0:0x1c0]
    ds[0x20:0x30] = ds[0x1c0:0x1d0]
    envelope_obj = bytearray(0x170)
    envelope_obj[0xa0:0xb0] = ds[0x10:0x20]
    envelope_obj[0xb0:0xc0] = ds[0x20:0x30]
    envelope = bytes(envelope_obj[0xa0:0xb5])
    # The raw-entry success arm copies the relevant range into the verified
    # object. This does not assert that digest or signature recovery succeeds.
    rs = bytearray(0x530)
    rs[0x30:0x1a0] = envelope_obj
    rs[0x2c8:0x3b0] = rs[0x98:0x180]
    rs[0x30:0x180] = rs[0x260:0x3b0]
    rs[0x3b0:0x520] = rs[0x30:0x1a0]
    verified = bytes(rs[0x3b0:0x520])
    verified_envelope = verified[0xa0:0xb5]
    env = bytearray(0x160)
    env[0x13c:0x14c] = verified[0xa0:0xb0]
    env[0x149:0x151] = verified[0xad:0xb5]
    tx_env = bytes(env[0x13c:0x151])
    return {'helper': bytes(helper), 'inner': inner, 'type2': type2,
            'envelope': envelope, 'verified_envelope': verified_envelope,
            'tx_env': tx_env}


def render_tsv(headers, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode()


def generate(data):
    authenticate(data)
    sec = sections(data)
    fdes, cies = selected_fdes(data, sec)
    rel = read_relatives(data, sec)
    instruction_rows, control_rows, boundaries = decoded_corpus(data, sec, fdes)
    flow_rows = []
    flow_names = ('conditional', 'direct_call', 'indirect_call', 'direct_jump',
                  'indirect_jump', 'return', 'trap')
    for owner in sorted(fdes):
        label = hex(owner)
        owned = [row for row in control_rows if row[0] == label]
        flow_rows.append([label, sum(row[0] == label for row in instruction_rows)] +
                         [sum(row[3] == kind for row in owned) for kind in flow_names])
    pin_rows = []
    for label, va, pattern in PINS:
        raw = exact(data, sec, va, pattern)
        pin_rows.append([label, hex(owner_of(fdes, va, len(raw))), hex(va),
                         hex(map_va(sec, va, len(raw))), len(raw), raw.hex()])
    call_rows = [decode_call(data, sec, fdes, rel, *row) for row in CALLS]
    rip_rows = [decode_rip_ref(data, sec, fdes, *row) for row in RIP_REFS]
    branch_rows = [decode_branch(data, sec, fdes, *row) for row in BRANCHES]
    fn_rows, bodies, frames, ex_rows, ex_headers = [], [], [], [], []
    for start in sorted(fdes):
        f = fdes[start]
        body = at(data, sec, start, f['end'] - start)
        fn_rows.append([hex(start), hex(f['end']), len(body), hex(f['offset']),
                        hex(f['fde']), hex(f['cie']), '' if f['lsda'] is None else hex(f['lsda']),
                        hashlib.sha256(body).hexdigest(), FUNCTIONS[start]])
        bodies.append({'start': hex(start), 'end': hex(f['end']), 'bytes': body.hex()})
        require(f['cie'] in cies, 'CIE missing')
        frames.append({'start': hex(start), 'end': hex(f['end']), 'fde': hex(f['fde']),
                       'fde_bytes': record_bytes(data, sec, f['fde']),
                       'cie': hex(f['cie']), 'cie_bytes': record_bytes(data, sec, f['cie']),
                       'lsda': None if f['lsda'] is None else hex(f['lsda'])})
        rows, header = exceptions(data, sec, f)
        ex_rows.extend(rows)
        if header is not None:
            ex_headers.append(header)
    reloc_rows = []
    for va in sorted(rel):
        x = rel[va]
        reloc_rows.append([hex(va), x['section'], hex(x['file_offset']), hex(x['info']),
                           hex(x['addend']), x.get('symbol', ''), x['raw']])
    table_rows = switch_entries(data, sec, fdes)
    switch_owners = {'envelope_type': 0x4e4e600, 'transaction_environment': 0x4e4eee0,
                     'signing_encoder': 0x4e50020}
    for row in table_rows:
        require(int(row[-1], 16) in boundaries[switch_owners[row[0]]], 'switch lands inside an instruction')
    # Derive target object bytes and all copy offsets from fixed instruction shapes.
    key = at(data, sec, 0x574f0c0, 20)
    require(key == bytes(19) + b'\x09', 'previous object key mismatch')
    child_offset = struct.unpack('<I', at(data, sec, 0x134d863, 4))[0]
    dispatch_offset = struct.unpack('<I', at(data, sec, 0x4e4e9ce, 4))[0]
    source_offset = struct.unpack('<I', at(data, sec, 0x4e4f1cf, 4))[0]
    env_offset = struct.unpack('<I', at(data, sec, 0x4e4f1d6, 4))[0]
    require((child_offset, dispatch_offset, source_offset, env_offset) == (0x90,0xa0,0xa0,0x13c), 'field displacement mismatch')
    projected = lane_projection(key)
    expected = b'\x01' + key
    require(all(projected[n] == expected for n in ('inner','type2','envelope','verified_envelope','tx_env')), 'recipient projection mismatch')
    lane_rows = []
    for i, value in enumerate(expected):
        lane_rows.append([i, 'tag' if i == 0 else 'address', i + 1,
                          hex(child_offset + i), hex(child_offset + i),
                          hex(dispatch_offset + i), hex(source_offset + i),
                          hex(env_offset + i), hex(value)])
    cases = [
      ('empty',b''), ('create',b'\x80'), ('address09',b'\x94'+key),
      ('short19',b'\x93'+key[:19]), ('long21',b'\x95'+key+b'\x00'),
      ('truncated20',b'\x94'+key[:19]), ('single_noncanonical',b'\x81\x00'),
      ('single_valid_wrong_width',b'\x81\x80'), ('list_empty',b'\xc0'),
      ('long_short_length',b'\xb8\x14'+key), ('long_leading_zero',b'\xb8\x00'),
      ('long_missing_length',b'\xb8'), ('long56_truncated',b'\xb8\x38'),
      ('list56_truncated',b'\xf8\x38'),
    ]
    case_rows = []
    for label, raw in cases:
        kind, code, consumed, value = address_field(raw)
        case_rows.append([label, raw.hex(), kind, '' if code is None else code, consumed, value.hex()])
    payload_cases = [
      ('empty_input',b''), ('empty_bytes',b'\x80'), ('literal_single',b'\x01'),
      ('short_one_noncanonical',b'\x81\x01'), ('short_one_valid',b'\x81\x80'),
      ('short55',b'\xb7'+bytes(55)), ('long56',b'\xb8\x38'+bytes(56)),
      ('long213',b'\xb8\xd5'+bytes(213)), ('long213_truncated',b'\xb8\xd5'+bytes(212)),
      ('long_short_length',b'\xb8\x37'+bytes(55)), ('long_leading_zero',b'\xb8\x00'),
      ('long_missing_length',b'\xb8'), ('short_list',b'\xc0'),
      ('long_list',b'\xf8\x38'+bytes(56)), ('long_list_truncated',b'\xf8\x38'),
    ]
    payload_rows = []
    for label, raw in payload_cases:
        kind, code, consumed, value = payload_field(raw)
        payload_rows.append([label, raw.hex(), kind, '' if code is None else code, consumed,
                             len(value), hashlib.sha256(value).hexdigest() if kind == 'bytes' else ''])
    sig_cases = [
      ('parity', 'zero', b'\x80'), ('parity', 'one', b'\x01'),
      ('parity', 'literal_zero', b'\x00'), ('parity', 'literal_two', b'\x02'),
      ('parity', 'noncanonical_one', b'\x81\x01'), ('parity', 'two_byte_value', b'\x82\x01\x02'),
      ('scalar', 'empty_value', b'\x80'), ('scalar', 'literal_zero', b'\x00'),
      ('scalar', 'one', b'\x01'), ('scalar', 'width32', b'\xa0'+bytes([0x80])*32),
      ('scalar', 'width33', b'\xa1'+bytes([0x80])*33),
      ('scalar', 'leading_zero', b'\x82\x00\x01'), ('scalar', 'truncated', b'\xa0'+bytes(31)),
    ]
    sig_rows = []
    for field, label, raw in sig_cases:
        kind, code, consumed, value = (parity_field if field == 'parity' else scalar_field)(raw)
        sig_rows.append([field, label, raw.hex(), kind, '' if code is None else code,
                         consumed, '' if value is None else hex(value)])
    bound = signature_bound(data, sec)
    bound_value = sum(word << (64 * (3-i)) for i, word in enumerate(bound))
    bound_record = {
      'description': 'Unsigned comparison of four selected limbs; identification as signature s is inferred.',
      'immediate_va_high_to_low': ['0x46c2fbb','0x46c2fd8','0x46c2fe5','0x46c2ffc'],
      'second_operand': 'one-byte immediate sign-extended to 64 bits',
      'limbs_high_to_low': [hex(x) for x in bound],
      'value_hex': format(bound_value, '064x'),
      'above_bound_taken_va': next(row[5] for row in branch_rows if row[0] == 'raw_large_s'),
      'equal_bound_is_rejected_by_this_comparison': bound_exceeded(bound, bound),
    }
    summary = {
      'artifact_sha256': SHA256,
      'selected_fde_count': len(fn_rows), 'selected_fde_bytes': sum(f['end'] - f['start'] for f in fdes.values()),
      'selected_window_count': len(pin_rows), 'selected_direct_or_slot_calls': len(call_rows),
      'selected_conditional_branches': len(branch_rows), 'switch_entries': len(table_rows),
      'decoded_instructions': len(instruction_rows), 'decoded_control_transfers': len(control_rows),
      'decoded_conditional_branches': sum(row[3] == 'conditional' for row in control_rows),
      'selected_rip_references': len(rip_rows),
      'selected_relocations': len(reloc_rows), 'exception_tables': len(ex_headers),
      'exception_call_sites': len(ex_rows), 'exception_landings': sum(bool(row[6]) for row in ex_rows),
      'synthetic_recipient_cases': len(case_rows), 'tracked_tag_and_recipient_lanes': len(lane_rows),
      'synthetic_payload_cases': len(payload_rows),
      'synthetic_signature_cases': len(sig_rows),
      'object_address_va': hex(0x574f0c0),
      'object_address_file_offset': hex(map_va(sec, 0x574f0c0, len(key))),
      'object_address_bytes': key.hex(),
      'observations': 'Selected bytes, FDEs, RELA, bounded switches and branch targets only.',
      'inference': 'The copied tagged field is the type-2 call recipient. Its composition with earlier frame and registry work is conditional.',
      'unresolved': 'No target execution, complete caller ownership, runtime table selection, allocator semantics, signature proof or component equivalence.',
    }
    return {
      'functions.tsv': render_tsv(('start_va','end_va','bytes','file_offset','fde_va','cie_va','lsda_va','sha256','role_inferred'),fn_rows),
      'bodies.json': json_bytes(bodies), 'unwind.json': json_bytes(frames),
      'windows.tsv': render_tsv(('name','fde_start','site_va','file_offset','length','bytes'),pin_rows),
      'instructions.tsv': render_tsv(('fde_start','site_va','file_offset','length','bytes','flow_class'),instruction_rows),
      'control-flow.tsv': render_tsv(('fde_start','site_va','bytes','flow_class','selected_or_local_target_va','conditional_fallthrough_va'),control_rows),
      'flow-summary.tsv': render_tsv(('fde_start','instructions') + flow_names,flow_rows),
      'calls.tsv': render_tsv(('name','fde_start','site_va','file_offset','kind','bytes','slot_va','target_va','scope'),call_rows),
      'rip-references.tsv': render_tsv(('name','fde_start','site_va','bytes','target_va'),rip_rows),
      'branches.tsv': render_tsv(('name','fde_start','site_va','bytes','x86_condition_code','taken_va','fallthrough_va'),branch_rows),
      'switches.tsv': render_tsv(('table','base_va','index','entry_va','file_offset','bytes','target_va'),table_rows),
      'relocations.tsv': render_tsv(('slot_va','section','file_offset','info','addend','symbol','bytes'),reloc_rows),
      'lanes.tsv': render_tsv(('lane','meaning','option_result_offset','field_result_offset','type2_result_offset','envelope_offset','converter_input_offset','tx_environment_offset','example_byte'),lane_rows),
      'recipient-cases.tsv': render_tsv(('synthetic_case','input_hex','kind','raw_error_code','consumed_bytes','address_hex'),case_rows),
      'payload-cases.tsv': render_tsv(('synthetic_case','input_hex','kind','raw_error_code','consumed_bytes','payload_length','payload_sha256'),payload_rows),
      'payload-layout.json': json_bytes(payload_layout(data, sec)),
      'signature-cases.tsv': render_tsv(('field','synthetic_case','input_hex','kind','raw_error_code','consumed_bytes','value'),sig_rows),
      'synthetic-transaction.json': json_bytes(synthetic_transaction(key)),
      'signature-bound.json': json_bytes(bound_record),
      'exception-sites.tsv': render_tsv(('owner','lsda_va','record_file_offset','start_va','size','end_va','landing_va','action','bytes'),ex_rows),
      'exception-headers.json': json_bytes(ex_headers), 'summary.json': json_bytes(summary),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    files = generate(ARTIFACT.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (args.out / name).write_bytes(files[name])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
