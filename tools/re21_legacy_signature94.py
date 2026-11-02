#!/usr/bin/env python3
"""Export selected legacy-transaction serialization evidence from node #94.

Static byte extraction only.  The selected code is never executed.  The small
RLP projections are independent synthetic examples, not target-run fixtures.
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

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET_ADDRESS = 0x574f0c0

# Addresses are deliberately selected seeds.  Ends come from actual FDE records.
FUNCTIONS = (
    (0x13518c0, 'six-field reader'),
    (0x13520c0, 'six-field writer'),
    (0x1352430, 'signed-list writer'),
    (0x1352710, 'signed-list reader'),
    (0x1352b40, 'six-field length'),
    (0x1352ca0, 'signed-list length'),
    (0x1352e30, 'signing-preimage writer'),
    (0x1352f90, 'unsigned-word reader'),
    (0x13531a0, 'signature-v and scalar reader'),
    (0x1353560, 'signature-scalar reader'),
    (0x135ad20, 'four-limb integer writer'),
    (0x4e555a0, 'signing-preimage allocation wrapper'),
)

# Fixed, manually selected byte shapes.  These are not a general x86 decoder.
WINDOWS = (
    ('fields-nonce-reader', 0x13518d1, '4989f64889fb4989e74c89ffe8ae160000488b04244c8b6c24084883f80a'),
    ('fields-recipient-call', 0x1351970, '4889e74c89f6ff158cc84104803c24010f8535010000'),
    ('fields-recipient-stage', 0x1351abb, '488b44240e488944246d0f104424010f29442460'),
    ('fields-recipient-output', 0x1351e19, '488b7c246d48897b7d0f284424600f114370'),
    ('fields-payload-allocate', 0x1351d9a, '41bf010000004c89ffff152fc241044885c00f84f1020000'),
    ('fields-payload-copy', 0x1351dc8, '4c89d64c89faff150cc241044c89bc24900000004889e7488db42480000000ff1553c44104'),
    ('fields-success-output', 0x1351e2b, '488b7c244048897b40488b7c243848897b48488b7c243048897b50488b7c242848897b5848c70300000000488973104889431848894b20488953284c894b304c8943384c896b6048896b68'),
    ('fields-price-width', 0x1351b41, '80fa10767231c0'),
    ('fields-value-width', 0x1351b13, '803e000f84c00100004983fc200f86d900000031c0'),
    ('fields-empty-payload', 0x1352037, 'bf010000004531ffe974fdffff'),
    ('outer-nonempty', 0x1352722, '4c8b7e08bf020000004d85ff0f844c020000'),
    ('outer-kind', 0x1352734, '488b0e0fb61984db780d'),
    ('outer-list-short', 0x1352837, '49ffcf48ffc148890e4c897e0880c340440fb6e34d39e70f822c010000'),
    ('outer-list-long', 0x1352783, '8d530880fac80f83a800000080fbf80f93c249ffcf48ffc148890e4c897e08c0e20680cab74189d8'),
    ('outer-fields-call', 0x1352854, '4889c3488d7c24504989f6ff15d3b94104488b442450'),
    ('outer-field-result-pointer', 0x1352857, '488d7c2450'),
    ('outer-lanes-second-chunk', 0x13528a5, '0f288424d00000000f298424a0010000'),
    ('outer-lanes-first-chunk', 0x13528b5, '0f288424c00000000f29842490010000'),
    ('outer-signature-stage-pointer', 0x1352939, '488d942420010000'),
    ('outer-signature-call', 0x1352934, '488d7c2450488d9424200100004c89f6e857080000'),
    ('outer-signature-status', 0x1352949, '0fb6ac24900000004080fd024889d87549'),
    ('outer-count-check', 0x13529fa, '498b4e084889ca4c01e20f82e00000004c39fa0f8590000000'),
    ('outer-stage-source', 0x1352a13, '4c8d742450488db42420010000'),
    ('outer-stage-copy', 0x1352a20, '4c8b3db9b54104ba900000004c89f741ffd7'),
    ('outer-final-copy', 0x1352a86, 'bad00000004889df4c89f641ffd74889d84088abd0000000'),
    ('outer-count-error', 0x1352aa3, '4929cf725148c74008080000004c8960104c89781848c70002000000'),
    ('outer-unwind-drop', 0x1352b08, '4889c3488b842430010000488bb42438010000488dbc2448010000488b942440010000ff50204889df'),
    ('v-unprotected-zero', 0x1353225, '4889e04989f84983f01b4909c80f84e1000000'),
    ('v-unprotected-one', 0x1353238, '4989f84983f01c4909c80f855001000041b401e9cc000000'),
    ('v-protected-bound', 0x1353398, '41b8020000004531e441b9220000004939f941b9000000004919c973154883c7dd4883d1ff4883f9010f8612010000'),
    ('v-protected-conversion', 0x13534d9, '480fa4f93f4080e70148c7042401000000488d4424404189fc4989c84c8900'),
    ('v-two-scalars', 0x135333c, '4989e64c89f74989f7e816020000833c24017429410f104608410f104e180f294424600f294c24704889e74c89fee8f1010000'),
    ('v-chain-option-store', 0x1353330, '488b4c244048890248894a08'),
    ('v-success-tag', 0x13534bb, '0f295c24100f2914240f114b300f1143200f115b100f111344886340'),
    ('v-width', 0x1353405, '80f9100f8737010000'),
    ('uint64-width', 0x135311e, '80fa08762e31c0'),
    ('scalar-canonical-width', 0x13535aa, '803e0074584983ff20765fb801000000b908000000'),
    ('scalar-overwidth-result', 0x13535b5, 'b801000000b90800000031d24889140fe9fe010000'),
    ('scalar-zero', 0x1353788, '31c031c931f631d2ebc4'),
    ('writer-nonce', 0x13520ce, '4889f34989fe488b77604c8b6a38488b6a48'),
    ('writer-price', 0x1352137, '498b7630498b46384889f14809c1'),
    ('writer-gas', 0x1352166, '498b76684885f674784881fe80000000'),
    ('writer-recipient-tag', 0x1352181, '41807e70017470'),
    ('writer-recipient-bytes', 0x13521f8, '4d8d7e714889dfbe94000000ffd5ba140000004889df4c89fe41ffd5'),
    ('writer-value', 0x135226c, '498d464049837e580075a8'),
    ('writer-payload', 0x13523a5, '4d8b7e184d8b76204983fe010f8430ffffff4983fe38730f'),
    ('length-recipient', 0x1352bce, '807f7000ba15000000480f44d6'),
    ('signed-base-fields', 0x1352611, '4c89ef4889de4c89e2ff1528bc4104'),
    ('signed-protected-v', 0x1352620, '410fb6464041807d00000f848d000000498b4d080fb6c0488d044848c1e93f4883c0234883d100'),
    ('signed-unprotected-v', 0x13526bd, '4d8b642438041b0fb6f04889dfffd5'),
    ('signed-two-scalars', 0x13526cc, '4c89f74889de4c89e24889e9e8438600004c89ff4889de4c89e24889e9e832860000'),
    ('preimage-chain-flag', 0x1352e44, '4989feff150bb4410441833e017528498b4e08'),
    ('preimage-list-boundary', 0x1352e8e, '4883f938730d80c9c00fb6f1'),
    ('preimage-fields', 0x1352ee7, '4c89f74889de4c89faff1552b3410441833e017574'),
    ('preimage-empty-tail', 0x1352f5c, '4889dfbe80000000ffd54889dfbe80000000ffd5'),
    ('scalar-zero-write', 0x135ad77, '483d00010000750a4889dfbe80000000eb0c3df90000007212'),
    ('wrapper-length', 0x4e555af, '4889f7ff15a08c910041833e017528498b4e08'),
    ('wrapper-checked-size', 0x4e555e8, '4801c10f8286000000480fbdc183f038c1e803ba090000004829c24883f93841bf010000004c0f43fa4901cf726e'),
    ('wrapper-output', 0x4e55644, '488d1575548f00488d7424084c89f7ff15178c9100488b442418488943100f104424080f1103'),
    ('wrapper-unwind-free', 0x4e5569f, '4889c3488b7424084885f6740d488b7c241031d2ff1557899100'),
)

# Each selected control transfer has a fixed opcode and an expected destination;
# the emitted target and displacement are decoded from authenticated ELF bytes.
# This is a selected decision ledger, not a complete instruction census.
BRANCHES = (
    ('fields-nonce-error', 0x13518ef, '0f85', 0x13519a7),
    ('fields-gas-price-empty', 0x1351901, '0f84', 0x1351bd8),
    ('fields-gas-price-zero-byte', 0x1351933, '0f84', 0x1351bd3),
    ('fields-gas-limit-error', 0x135196a, '0f85', 0x1351a00),
    ('fields-recipient-success', 0x1351980, '0f85', 0x1351abb),
    ('fields-price-width', 0x1351b44, '76', 0x1351bb8),
    ('fields-value-zero-byte', 0x1351b16, '0f84', 0x1351cdc),
    ('fields-value-width', 0x1351b20, '0f86', 0x1351bff),
    ('fields-value-loop-underflow', 0x1351d08, '0f82', 0x1352089),
    ('fields-value-loop-carry', 0x1351d27, '0f82', 0x1352096),
    ('fields-payload-alloc-null', 0x1351dac, '0f84', 0x13520a3),
    ('fields-payload-owner-status', 0x1351e03, '0f84', 0x135201f),
    ('fields-payload-truncated', 0x1351fca, '72', 0x135201d),
    ('fields-payload-empty', 0x1351fee, '74', 0x1352037),
    ('fields-payload-size-sign', 0x135207c, '79', 0x13520b1),
    ('fields-nonce-call', 0x13518dd, 'e8', 0x1352f90),
    ('fields-gas-limit-call', 0x1351958, 'e8', 0x1352f90),
    ('outer-empty', 0x135272e, '0f84', 0x1352980),
    ('outer-short-kind', 0x135273c, '78', 0x135274b),
    ('outer-short-length', 0x1352764, '0f85', 0x1352829),
    ('outer-missing-single-byte', 0x135276d, '0f84', 0x1352980),
    ('outer-noncanonical-single', 0x135277b, '0f89', 0x1352980),
    ('outer-missing-length-of-length', 0x13527b5, '0f82', 0x1352980),
    ('outer-leading-zero-length', 0x13527d2, '0f84', 0x135297b),
    ('outer-short-long-length', 0x135280a, '0f82', 0x1352980),
    ('outer-truncated-long-content', 0x1352818, '0f82', 0x1352980),
    ('outer-long-string-kind', 0x1352821, '0f86', 0x135273e),
    ('outer-short-string-kind', 0x135282c, '0f83', 0x135273e),
    ('outer-short-list-truncated', 0x135284e, '0f82', 0x1352980),
    ('outer-fields-success', 0x1352882, '75', 0x13528a5),
    ('outer-signature-reader', 0x1352944, 'e8', 0x13531a0),
    ('outer-signature-success', 0x1352958, '75', 0x13529a3),
    ('outer-count-overflow', 0x1352a04, '0f82', 0x1352aea),
    ('outer-count-mismatch', 0x1352a0d, '0f85', 0x1352aa3),
    ('outer-count-underflow', 0x1352aa6, '72', 0x1352af9),
    ('outer-unwind-resume-boundary', 0x1352b31, 'e8', 0x5660110),
    ('v-input-empty', 0x13531bf, '0f84', 0x1353456),
    ('v-prefix-kind', 0x13531cf, '78', 0x1353250),
    ('v-zero-invalid', 0x13531ee, '0f84', 0x135342a),
    ('v-27', 0x1353232, '0f84', 0x1353319),
    ('v-not-28', 0x1353242, '0f85', 0x1353398),
    ('v-noncanonical-single', 0x1353284, '0f88', 0x13531d1),
    ('v-invalid-option', 0x135332a, '0f84', 0x13533db),
    ('v-first-scalar-call', 0x1353345, 'e8', 0x1353560),
    ('v-first-scalar-error', 0x135334e, '74', 0x1353379),
    ('v-second-scalar-call', 0x135336a, 'e8', 0x1353560),
    ('v-second-scalar-success', 0x1353373, '0f85', 0x1353493),
    ('v-small-reject', 0x13533b3, '73', 0x13533ca),
    ('v-protected-high-bound', 0x13533c1, '0f86', 0x13534d9),
    ('v-width-error', 0x1353408, '0f87', 0x1353545),
    ('scalar-leading-zero', 0x13535ad, '74', 0x1353607),
    ('scalar-width-ok', 0x13535b3, '76', 0x1353614),
    ('scalar-missing-payload', 0x13535ee, '0f84', 0x13537b7),
    ('scalar-short-overlong', 0x13535ff, '0f89', 0x13537b7),
    ('scalar-long-canonical', 0x13536b7, '0f82', 0x13537b7),
    ('scalar-list-kind', 0x13536d1, '0f87', 0x13537b7),
    ('uint-width-ok', 0x1353121, '76', 0x1353151),
    ('writer-nonce-zero', 0x13520e3, '74', 0x13520f3),
    ('writer-nonce-long', 0x13520ec, '73', 0x13520ff),
    ('writer-price-zero', 0x1352145, '74', 0x135215c),
    ('writer-gas-zero', 0x135216d, '74', 0x13521e7),
    ('writer-gas-long', 0x1352176, '0f83', 0x1352223),
    ('writer-recipient-present', 0x1352186, '74', 0x13521f8),
    ('writer-recipient-absent', 0x13521f6, '75', 0x1352262),
    ('writer-payload-single', 0x13523b1, '0f84', 0x13522e7),
    ('writer-payload-long', 0x13523bb, '73', 0x13523cc),
    ('signed-short-list', 0x135259d, '73', 0x13525ab),
    ('signed-unprotected', 0x135262a, '0f84', 0x13526bd),
    ('signed-first-scalar', 0x13526d8, 'e8', 0x135ad20),
    ('signed-second-scalar', 0x13526e9, 'e8', 0x135ad20),
    ('preimage-no-chain', 0x1352e51, '75', 0x1352e7b),
    ('preimage-size-overflow', 0x1352e80, '0f82', 0x1352f7f),
    ('preimage-long-list', 0x1352e92, '73', 0x1352ea1),
    ('preimage-no-tail', 0x1352efa, '75', 0x1352f70),
    ('preimage-chain-zero', 0x1352f03, '74', 0x1352f13),
    ('preimage-chain-long', 0x1352f0c, '73', 0x1352f1f),
    ('wrapper-no-chain', 0x4e555bc, '75', 0x4e555e6),
    ('wrapper-body-size-overflow', 0x4e555eb, '0f82', 0x4e55677),
    ('wrapper-header-size-overflow', 0x4e55614, '72', 0x4e55684),
    ('wrapper-allocation-size', 0x4e55616, '79', 0x4e55623),
    ('wrapper-allocation-null', 0x4e5562f, '74', 0x4e55691),
    ('wrapper-unwind-resume-boundary', 0x4e556bc, 'e8', 0x5660110),
)

# Selected RELA entries, including the external field-reader boundary.
# Type 6 uses its dynamic symbol index; symbol-free type 8 uses its addend.
RELOCATION_SPECS = (
    (0x576dfb8, 8, 0, 0x1346068),
    (0x576dfd8, 8, 0, 0x54c06b0),
    (0x576dfe0, 6, 6, 0),
    (0x576e010, 8, 0, 0x54c8cb0),
    (0x576e118, 8, 0, 0x157b480),
    (0x576e128, 8, 0, 0x157b63b),
    (0x576e150, 8, 0, 0x157b520),
    (0x576e208, 8, 0, 0x135b670),
    (0x576e238, 8, 0, 0x13518c0),
    (0x576e240, 8, 0, 0x1511380),
    (0x576e248, 8, 0, 0x13520c0),
    (0x576e250, 8, 0, 0x1352430),
    (0x576e258, 8, 0, 0x1352b40),
    (0x576e260, 8, 0, 0x1352ca0),
    (0x576e268, 8, 0, 0x1352710),
    (0x576e270, 8, 0, 0x1352e30),
)

RIP_CALLS = (
    ('fields-recipient-reader-boundary', 0x1351976, 0x576e208),
    ('fields-payload-allocator', 0x1351da3, 0x576dfd8),
    ('fields-payload-copy', 0x1351dce, 0x576dfe0),
    ('fields-payload-owner-boundary', 0x1351de7, 0x576e240),
    ('outer-field-reader-boundary', 0x135285f, 0x576e238),
    ('signed-field-length', 0x135244a, 0x576e258),
    ('signed-field-writer', 0x135261a, 0x576e248),
    ('signed-length-field-length', 0x1352caa, 0x576e258),
    ('preimage-field-length', 0x1352e47, 0x576e258),
    ('preimage-field-writer', 0x1352ef0, 0x576e248),
    ('wrapper-field-length', 0x4e555b2, 0x576e258),
    ('wrapper-allocator', 0x4e55626, 0x576dfd8),
    ('wrapper-preimage-writer', 0x4e55653, 0x576e270),
    ('wrapper-release', 0x4e556b3, 0x576e010),
)


# The instruction-shape routine is adapted from tools/evm_kvs_inventory.py.
# Copyright (c) 2026 Hyperliquid Source contributors.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


def require(condition, message):
    if not condition:
        raise ValueError(message)


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
        if op == 0xc3: kind = 'return'
        if op == 0xcc: kind = 'trap'
    elif op in (0x68, 0x6a, 0xa8, 0xa9, 0xc2):
        imm = 2 if op == 0xc2 else 1 if op in (0x6a, 0xa8) else operand
        if op == 0xc2: kind = 'return'
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
                     0xa3, 0xa4, 0xa5, 0xab, 0xac, 0xad, 0xaf, 0xb0, 0xb1, 0xb3, 0xb6, 0xb7, 0xba,
                     0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc6,
                     0xd4, 0xd6, 0xd7, 0xdb, 0xdf, 0xe6, 0xeb, 0xef, 0xf3,
                     0xf4, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe) or 0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f:
            modrm = True
            if op2 in (0x70, 0x71, 0x72, 0x73, 0xa4, 0xac, 0xba, 0xc2, 0xc6): imm = 1
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
        if op == 0xff and reg in (2, 4):
            kind = 'indirect_call' if reg == 2 else 'indirect_jump'
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



class View:
    """Resolve file-backed linked VAs; never map NOBITS or crossing ranges."""
    def __init__(self, data, sects=None):
        self.data = data
        self.sections = sections(data) if sects is None else sects

    def offset(self, va, size=1, executable=False):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
            raise ValueError('invalid VA range')
        found = [s for s in self.sections if s['type'] != 8 and
                 (not executable or s['flags'] & 4) and
                 s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(found) != 1:
            raise ValueError('VA range is not uniquely file-backed')
        s = found[0]
        off = s['offset'] + va - s['address']
        if off < 0 or off + size > len(self.data):
            raise ValueError('VA range lies outside file')
        return off

    def read(self, va, size, executable=False):
        off = self.offset(va, size, executable)
        return self.data[off:off + size]


def authenticate(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != TARGET_SHA256:
        raise ValueError('node 94 SHA-256 mismatch')
    return digest


def check_windows(view):
    rows = []
    for name, va, want_hex in WINDOWS:
        want = bytes.fromhex(want_hex)
        got = view.read(va, len(want), executable=True)
        if got != want:
            raise ValueError('fixed instruction window mismatch: ' + name)
        rows.append({'name': name, 'va': hex(va), 'file_offset': hex(view.offset(va, len(want), True)),
                     'bytes': got.hex()})
    return rows


def relative_edge(view, name, va, prefix_hex, expected):
    prefix = bytes.fromhex(prefix_hex)
    first = view.read(va, len(prefix), executable=True)
    if first != prefix:
        raise ValueError('branch opcode mismatch: ' + name)
    if prefix[0] in (0xe8, 0xe9):
        size, disp_at, fmt = 5, 1, '<i'
    elif 0x70 <= prefix[0] <= 0x7f or prefix[0] == 0xeb:
        size, disp_at, fmt = 2, 1, '<b'
    elif len(prefix) == 2 and prefix[0] == 0x0f and 0x80 <= prefix[1] <= 0x8f:
        size, disp_at, fmt = 6, 2, '<i'
    else:
        raise ValueError('unsupported branch shape')
    raw = view.read(va, size, executable=True)
    disp = struct.unpack_from(fmt, raw, disp_at)[0]
    target = va + size + disp
    if target != expected:
        raise ValueError('branch destination mismatch: ' + name)
    return {'name': name, 'site_va': hex(va), 'file_offset': hex(view.offset(va, size, True)),
            'bytes': raw.hex(), 'kind': 'direct_call' if prefix[0] == 0xe8 else 'branch',
            'displacement': disp, 'target_va': hex(target)}


def rip_edge(view, name, va, expected_slot):
    raw = view.read(va, 6, executable=True)
    if raw[:2] != b'\xff\x15':
        raise ValueError('indirect call opcode mismatch: ' + name)
    disp = struct.unpack_from('<i', raw, 2)[0]
    slot = va + 6 + disp
    if slot != expected_slot:
        raise ValueError('indirect call slot mismatch: ' + name)
    return {'name': name, 'site_va': hex(va), 'file_offset': hex(view.offset(va, 6, True)),
            'bytes': raw.hex(), 'kind': 'indirect_slot_call', 'displacement': disp,
            'target_va': hex(slot)}


def selected_fdes(data, view):
    _, indexed = unwind_index(data)
    _, fdes = eh_frame_records(data, view.sections)
    selected = dict(FUNCTIONS)
    by_start = {}
    for fde in fdes:
        if fde['start'] in selected:
            by_start.setdefault(fde['start'], []).append(fde)
    table = {}
    for entry in indexed:
        if entry['start'] in selected:
            table.setdefault(entry['start'], []).append(entry)
    out = []
    for start, role in FUNCTIONS:
        if len(by_start.get(start, ())) != 1 or len(table.get(start, ())) != 1:
            raise ValueError('selected FDE/index is missing or ambiguous')
        fde = by_start[start][0]
        entry = table[start][0]
        if entry['fde'] != fde['fde'] or fde['end'] <= start:
            raise ValueError('selected FDE/index mismatch')
        raw = view.read(start, fde['end'] - start, executable=True)
        for rec in ('fde', 'cie'):
            record_size = struct.unpack('<I', view.read(fde[rec], 4))[0] + 4
            record = view.read(fde[rec], record_size)
            fde[rec + '_bytes'] = record.hex()
        out.append({'start_va': hex(start), 'end_va': hex(fde['end']), 'size': len(raw),
                    'file_offset': hex(view.offset(start, len(raw), True)), 'role': role,
                    'fde_va': hex(fde['fde']), 'cie_va': hex(fde['cie']),
                    'lsda_va': hex(fde['lsda']) if fde['lsda'] is not None else '',
                    'index': entry['index'], 'sha256': hashlib.sha256(raw).hexdigest(),
                    'bytes': raw.hex(), 'fde_bytes': fde['fde_bytes'],
                    'cie_bytes': fde['cie_bytes']})
    return out


def walk_selected(view, fdes):
    """Walk only the selected FDE extents using fixed opcode-shape patterns."""
    insns, transfers, owners, starts = [], [], {}, set()
    for f in fdes:
        start, end = int(f['start_va'], 16), int(f['end_va'], 16)
        raw = view.read(start, end - start, executable=True)
        cursor = 0
        while cursor < len(raw):
            try:
                ins = decode_instruction(raw, cursor, start)
            except ValueError as exc:
                raise ValueError(f'unsupported instruction shape at {start + cursor:#x}: {exc}') from exc
            size = len(ins['raw'])
            if size <= 0:
                raise ValueError('empty instruction')
            owners[ins['site']] = (start, end)
            starts.add(ins['site'])
            insns.append(ins)
            cursor += size
        if cursor != len(raw):
            raise ValueError('instruction walk crossed selected FDE end')
    ends = {int(f['end_va'], 16) for f in fdes}
    for ins in insns:
        site, raw, kind = ins['site'], ins['raw'], ins['kind']
        target = None
        if raw[0] in (0xe8, 0xe9):
            target = site + len(raw) + struct.unpack_from('<i', raw, 1)[0]
            kind = 'direct_call' if raw[0] == 0xe8 else 'direct_jump'
        elif raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f:
            target = site + len(raw) + struct.unpack_from('<b', raw, 1)[0]
            kind = 'direct_jump' if raw[0] == 0xeb else 'conditional'
        elif len(raw) >= 2 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
            target = site + len(raw) + struct.unpack_from('<i', raw, 2)[0]
            kind = 'conditional'
        if target is not None:
            for f in fdes:
                start, end = int(f['start_va'], 16), int(f['end_va'], 16)
                if start <= target < end and target not in starts:
                    raise ValueError('direct transfer lands inside an instruction')
        if kind in ('direct_call', 'direct_jump', 'conditional', 'indirect_call',
                    'indirect_jump', 'return', 'trap', 'ud2'):
            transfers.append({'fde_start': hex(owners[site][0]), 'site_va': hex(site),
                              'file_offset': hex(view.offset(site, len(raw), True)),
                              'bytes': raw.hex(), 'kind': kind,
                              'target_va': hex(target) if target is not None else ''})
        ins['fde_start'] = owners[site][0]
    for name, va, expected in WINDOWS:
        if va not in starts or va + len(bytes.fromhex(expected)) not in starts | ends:
            raise ValueError('fixed window is not bounded by instruction starts: ' + name)
    for name, va, _, _ in BRANCHES:
        if va not in starts:
            raise ValueError('selected branch is not at an instruction start: ' + name)
    for name, va, _ in RIP_CALLS:
        if va not in starts:
            raise ValueError('selected indirect call is not at an instruction start: ' + name)
    return insns, transfers, starts


def selected_relocations(data, view):
    candidates = [s for s in view.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(candidates) != 1:
        raise ValueError('missing or ambiguous dynamic relocation section')
    sec = candidates[0]
    if sec['size'] % 24:
        raise ValueError('bad relocation section size')
    wanted = {x[0]: x[1:] for x in RELOCATION_SPECS}
    found = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in wanted:
            continue
        typ, sym = info & 0xffffffff, info >> 32
        if slot in found or (typ, sym, addend) != wanted[slot]:
            raise ValueError('selected relocation differs or is duplicated')
        view.offset(slot, 8)
        found[slot] = {'slot_va': hex(slot), 'entry_file_offset': hex(off),
                       'type': typ, 'symbol_index': sym, 'addend_va': hex(addend),
                       'entry_bytes': data[off:off + 24].hex()}
    if set(found) != set(wanted):
        raise ValueError('selected relocation is absent')
    return [found[x] for x in sorted(found)]


def memcpy_symbol(data, view, relocs):
    """Bind the selected type-6 relocation to its ELF dynamic symbol bytes."""
    symbols = [s for s in view.sections if s['name'] == '.dynsym' and s['type'] != 8]
    strings = [s for s in view.sections if s['name'] == '.dynstr' and s['type'] != 8]
    if len(symbols) != 1 or len(strings) != 1:
        raise ValueError('missing or ambiguous dynamic symbol/string section')
    sym, names = symbols[0], strings[0]
    if sym['size'] % 24:
        raise ValueError('invalid dynamic symbol table size')
    row = next(r for r in relocs if r['slot_va'] == hex(0x576dfe0))
    index = row['symbol_index']
    offset = sym['offset'] + index * 24
    if index >= sym['size'] // 24:
        raise ValueError('dynamic symbol outside table')
    name_offset = struct.unpack_from('<I', data, offset)[0]
    if name_offset >= names['size']:
        raise ValueError('dynamic symbol name outside string table')
    begin = names['offset'] + name_offset
    end = data.find(b'\x00', begin, names['offset'] + names['size'])
    if end < 0 or data[begin:end] != b'memcpy':
        raise ValueError('dynamic copy symbol mismatch')
    return {'slot_va': row['slot_va'], 'symbol_index': index,
            'symbol_file_offset': hex(offset), 'symbol_bytes': data[offset:offset + 24].hex(),
            'name_file_offset': hex(begin), 'name': data[begin:end].decode('ascii')}


def lsda_rows(view, fdes):
    """Read selected LSDA call-site tables; action/type tables stay opaque."""
    headers, rows = [], []
    exception_secs = [s for s in view.sections if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(exception_secs) != 1:
        raise ValueError('missing exception table')
    sec = exception_secs[0]
    sec_end = sec['offset'] + sec['size']
    for f in fdes:
        if not f['lsda_va']:
            continue
        lsda = int(f['lsda_va'], 16)
        if not sec['address'] <= lsda < sec['address'] + sec['size']:
            raise ValueError('LSDA outside exception section')
        base = view.offset(lsda)
        pos = base
        data = view.data
        if pos + 2 > sec_end or data[pos] != 0xff:
            raise ValueError('unsupported LSDA LPStart encoding')
        pos += 1
        type_encoding = data[pos]
        pos += 1
        if type_encoding != 0xff:
            if type_encoding != 0x9b:
                raise ValueError('unsupported LSDA type encoding')
            _, pos = uleb(data, pos, sec_end)
        if pos >= sec_end or data[pos] != 1:
            raise ValueError('unsupported LSDA call-site encoding')
        pos += 1
        length, pos = uleb(data, pos, sec_end)
        limit = pos + length
        if limit > sec_end:
            raise ValueError('truncated LSDA call-site table')
        header_end = pos
        start = int(f['start_va'], 16)
        end = int(f['end_va'], 16)
        while pos < limit:
            row_off = pos
            rel, pos = uleb(data, pos, limit)
            size, pos = uleb(data, pos, limit)
            landing, pos = uleb(data, pos, limit)
            action, pos = uleb(data, pos, limit)
            if start + rel > end or start + rel + size > end or (landing and not start <= start + landing < end):
                raise ValueError('LSDA call site outside selected FDE')
            rows.append({'fde_start': hex(start), 'lsda_va': hex(lsda),
                         'file_offset': hex(row_off), 'start_va': hex(start + rel),
                         'length': size, 'end_va': hex(start + rel + size),
                         'landing_va': hex(start + landing) if landing else '',
                         'action': action, 'bytes': data[row_off:pos].hex()})
        if pos != limit:
            raise ValueError('LSDA table length mismatch')
        headers.append({'fde_start': hex(start), 'lsda_va': hex(lsda),
                        'type_encoding': hex(type_encoding),
                        'header_bytes': data[base:header_end].hex(),
                        'call_site_bytes': data[header_end:limit].hex()})
    return headers, rows


def constants(view):
    """Read immediate operands only after the fixed windows were authenticated."""
    check_windows(view)
    result = {
        'unprotected_v0': view.read(0x135322b, 4, True)[3],
        'unprotected_v1': view.read(0x135323b, 4, True)[3],
        'largest_rejected_small_v': struct.unpack('<I', view.read(0x13533a1, 6, True)[2:])[0],
        'protected_v_base': view.read(0x135263f, 4, True)[3],
        'adjusted_high_limit': view.read(0x13533bd, 4, True)[3],
        'parity_mask': view.read(0x13534de, 4, True)[3],
        'v_width': view.read(0x1353405, 3, True)[2],
        'scalar_width': view.read(0x13535af, 4, True)[3],
        'u64_width': view.read(0x135311e, 3, True)[2],
        'price_width': view.read(0x1351b41, 3, True)[2],
        'value_width': view.read(0x1351b1c, 4, True)[3],
        'recipient_tag_offset': view.read(0x1352181, 5, True)[3],
        'recipient_present_tag': view.read(0x1352181, 5, True)[4],
        'recipient_data_offset': view.read(0x13521f8, 4, True)[3],
        'recipient_rlp_prefix': struct.unpack('<I', view.read(0x13521ff, 5, True)[1:])[0],
        'recipient_size': struct.unpack('<I', view.read(0x1352206, 5, True)[1:])[0],
        'nonce_offset': view.read(0x13520d4, 4, True)[3],
        'price_low_offset': view.read(0x1352137, 4, True)[3],
        'price_high_offset': view.read(0x135213b, 4, True)[3],
        'gas_limit_offset': view.read(0x1352166, 4, True)[3],
        'value_offset': view.read(0x135226c, 4, True)[3],
        'payload_pointer_offset': view.read(0x13523a5, 4, True)[3],
        'payload_length_offset': view.read(0x13523a9, 4, True)[3],
        'short_list_limit': view.read(0x1352e8e, 4, True)[3],
        'empty_rlp': struct.unpack('<I', view.read(0x1352f5f, 5, True)[1:])[0],
        'staged_field_copy': struct.unpack('<I', view.read(0x1352a27, 5, True)[1:])[0],
        'success_copy': struct.unpack('<I', view.read(0x1352a86, 5, True)[1:])[0],
    }
    if (result['unprotected_v0'], result['unprotected_v1'], result['protected_v_base'],
        result['largest_rejected_small_v'], result['adjusted_high_limit'],
        result['recipient_rlp_prefix'], result['recipient_size']) != (27, 28, 35, 34, 1, 0x94, 20):
        raise ValueError('selected operand relationships differ')
    return result


def recipient_lanes(view, c):
    """Project selected option, field-result, stack-stage and output copies."""
    check_windows(view)
    # The stores overlap.  Apply the target's instruction order to byte labels;
    # the common overlapping bytes must agree, not merely be assumed identical.
    memory = {1 + i: i for i in range(c['recipient_size'] + 1)}

    def copy_labels(src, dest, size):
        labels = [memory[src + i] for i in range(size)]
        for i, label in enumerate(labels):
            memory[dest + i] = label

    option_stage = view.read(0x1351abb, 20, True)
    copy_labels(option_stage[4], option_stage[9], 8)
    copy_labels(option_stage[14], option_stage[19], 16)
    field_out = view.read(0x1351e19, 18, True)
    labels = [memory[field_out[4] + i] for i in range(8)]
    field = {field_out[8] + i: value for i, value in enumerate(labels)}
    labels = [memory[field_out[13] + i] for i in range(16)]
    field.update({field_out[17] + i: value for i, value in enumerate(labels)})
    field_base = view.read(0x1352857, 5, True)[4]
    stage_base = struct.unpack('<I', view.read(0x1352939, 8, True)[4:])[0]
    chunks = []
    for site in (0x13528b5, 0x13528a5):
        raw = view.read(site, 16, True)
        source = struct.unpack_from('<I', raw, 4)[0]
        dest = struct.unpack_from('<I', raw, 12)[0]
        chunks.append((source, dest, 16, site))
    rows = []
    for lane in range(c['recipient_size'] + 1):
        source_offset = c['recipient_tag_offset'] + lane
        if field.get(source_offset) != lane:
            raise ValueError('recipient option-to-field copy differs')
        source_stack = field_base + source_offset
        matching = [(src, dst, size, site) for src, dst, size, site in chunks
                    if src <= source_stack < src + size]
        if len(matching) != 1:
            raise ValueError('recipient lane is not copied once')
        src, dst, _, site = matching[0]
        stage_offset = dst + source_stack - src - stage_base
        if stage_offset != source_offset or stage_offset >= c['staged_field_copy']:
            raise ValueError('recipient lane does not survive selected copy')
        rows.append({'lane': lane, 'kind': 'tag' if lane == 0 else 'address',
                     'option_result_offset': hex(lane + 1),
                     'field_result_offset': hex(source_offset),
                     'stage_offset': hex(stage_offset), 'output_offset': hex(stage_offset),
                     'instruction_va': hex(site)})
    return rows


def classify_v(value, c):
    if not isinstance(value, int) or not 0 <= value < (1 << (8 * c['v_width'])):
        raise ValueError('v outside selected unsigned width')
    if value == c['unprotected_v0']:
        return {'kind': 'unprotected', 'parity': 0, 'chain_id': None}
    if value == c['unprotected_v1']:
        return {'kind': 'unprotected', 'parity': 1, 'chain_id': None}
    if value <= c['largest_rejected_small_v']:
        return {'kind': 'invalid', 'parity': None, 'chain_id': None}
    adjusted = value - c['protected_v_base']
    if (adjusted >> 64) > c['adjusted_high_limit']:
        return {'kind': 'invalid', 'parity': None, 'chain_id': None}
    return {'kind': 'protected', 'parity': adjusted & c['parity_mask'], 'chain_id': adjusted >> 1}


def encode_bytes(value, c):
    value = bytes(value)
    n = len(value)
    limit = c['short_list_limit']
    empty = c['empty_rlp']
    if n == 1 and value[0] < empty:
        return value
    if n < limit:
        return bytes((empty + n,)) + value
    size = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes((empty + limit - 1 + len(size),)) + size + value


def encode_uint(value, c, width=32):
    if not isinstance(value, int) or not 0 <= value < (1 << (8 * width)):
        raise ValueError('integer outside selected width')
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return encode_bytes(raw, c)


def encode_list(items, c):
    payload = b''.join(items)
    n = len(payload)
    limit = c['short_list_limit']
    list_base = c['empty_rlp'] + 64
    if n < limit:
        return bytes((list_base + n,)) + payload
    raw_len = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes((list_base + limit - 1 + len(raw_len),)) + raw_len + payload


def tx_fields(nonce, gas_price, gas_limit, recipient, value, payload, c):
    if recipient is not None and len(recipient) != c['recipient_size']:
        raise ValueError('recipient must be absent or 20 bytes')
    return [encode_uint(nonce, c, 8), encode_uint(gas_price, c, 16),
            encode_uint(gas_limit, c, 8), encode_bytes(b'' if recipient is None else recipient, c),
            encode_uint(value, c, 32), encode_bytes(payload, c)]


def signing_and_signed(fields, chain_id, parity, r, s, c):
    if parity not in (0, 1):
        raise ValueError('parity must be zero or one')
    if chain_id is None:
        preimage = encode_list(fields, c)
        v = c['unprotected_v0'] + parity
    else:
        if not isinstance(chain_id, int) or not 0 <= chain_id < 1 << 64:
            raise ValueError('chain id outside selected width')
        preimage = encode_list(fields + [encode_uint(chain_id, c, 8),
                                        bytes((c['empty_rlp'],)), bytes((c['empty_rlp'],))], c)
        v = 2 * chain_id + c['protected_v_base'] + parity
    signed = encode_list(fields + [encode_uint(v, c, c['v_width']),
                                   encode_uint(r, c, 32), encode_uint(s, c, 32)], c)
    return preimage, signed, v


def outer_header(buf, c):
    """Project selected outer-list header branches, returning cursor and tag."""
    buf = bytes(buf)
    if not buf:
        return {'result': 'error', 'detail': 2, 'consumed': 0}
    p = buf[0]
    if p < 0x80:
        return {'result': 'error', 'detail': 6, 'consumed': 0}
    if p < 0xb8:
        n = p - 0x80
        if n == 1 and len(buf) == 1:
            return {'result': 'error', 'detail': 2, 'consumed': 1}
        if n == 1 and buf[1] < 0x80:
            return {'result': 'error', 'detail': 3, 'consumed': 1}
        return {'result': 'error', 'detail': 6 if len(buf) - 1 >= n else 2, 'consumed': 1}
    is_list = p >= 0xc0
    if 0xc0 <= p < 0xf8:
        n = p - 0xc0
        if len(buf) - 1 < n:
            return {'result': 'error', 'detail': 2, 'consumed': 1}
        return {'result': 'list', 'length': n, 'consumed': 1}
    nlen = p - (0xf7 if is_list else 0xb7)
    if len(buf) - 1 < nlen:
        return {'result': 'error', 'detail': 2, 'consumed': 1}
    cursor = 1 + nlen
    if buf[1] == 0:
        return {'result': 'error', 'detail': 1, 'consumed': cursor}
    n = int.from_bytes(buf[1:cursor], 'big')
    if n < c['short_list_limit']:
        return {'result': 'error', 'detail': 4, 'consumed': cursor}
    if len(buf) - cursor < n:
        return {'result': 'error', 'detail': 2, 'consumed': cursor}
    if not is_list:
        return {'result': 'error', 'detail': 6, 'consumed': cursor}
    return {'result': 'list', 'length': n, 'consumed': cursor}


def body_length_decision(initial_remaining, declared_length, final_remaining):
    """Project the selected checked add, comparison, then checked subtraction."""
    limit = (1 << 64) - 1
    values = (initial_remaining, declared_length, final_remaining)
    if any(not isinstance(v, int) or not 0 <= v <= limit for v in values):
        raise ValueError('counter outside selected unsigned width')
    combined = final_remaining + declared_length
    if combined > limit:
        return {'result': 'add_overflow'}
    if combined == initial_remaining:
        return {'result': 'equal'}
    if final_remaining > initial_remaining:
        return {'result': 'subtract_underflow'}
    return {'result': 'length_mismatch', 'declared': declared_length,
            'consumed': initial_remaining - final_remaining}


def decode_bounded_uint(buf, width, c, *, field=False):
    """Project selected integer readers, including their different error order."""
    if width not in (c['u64_width'], c['price_width'], c['scalar_width']) or (
            width == c['price_width'] and not field):
        raise ValueError('unsupported selected integer width')
    buf = bytes(buf)

    def error(detail, consumed):
        return {'result': 'error', 'detail': detail, 'consumed': consumed}

    if not buf:
        return error(2, 0)
    p = buf[0]
    if p < 0x80:
        return error(1, 1) if p == 0 else {'result': 'value', 'value': p, 'consumed': 1}
    if p < 0xb8:
        n, pos = p - 0x80, 1
        if n == 1 and len(buf) == 1:
            return error(2, pos)
        if n == 1 and buf[pos] < 0x80:
            return error(3, pos)
        if len(buf) - pos < n:
            return error(2, pos)
    elif p < 0xc0 or p >= 0xf8:
        is_list = p >= 0xf8
        nlen = p - (0xf7 if is_list else 0xb7)
        if len(buf) - 1 < nlen:
            return error(2, 1)
        pos = 1 + nlen
        if buf[1] == 0:
            return error(1, pos)
        n = int.from_bytes(buf[1:pos], 'big')
        if n < c['short_list_limit']:
            return error(4, pos)
        if len(buf) - pos < n:
            return error(2, pos)
        if is_list:
            return error(7, pos)
    else:
        n, pos = p - 0xc0, 1
        return error(7 if len(buf) - pos >= n else 2, pos)

    end = pos + n
    if n == 0:
        return {'result': 'value', 'value': 0, 'consumed': end}
    if width in (c['u64_width'], c['price_width']) and n > width:
        return error(0, end)
    if buf[pos] == 0:
        return error(1, end)
    if n > width:
        return error(0, end)
    return {'result': 'value', 'value': int.from_bytes(buf[pos:end], 'big'), 'consumed': end}


def decode_payload(buf, c):
    """Project the selected byte-string prefix and cursor, before allocation."""
    buf = bytes(buf)

    def error(detail, consumed):
        return {'result': 'error', 'detail': detail, 'consumed': consumed}

    if not buf:
        return error(2, 0)
    p = buf[0]
    if p < 0x80:
        return {'result': 'value', 'hex': buf[:1].hex(), 'length': 1, 'consumed': 1}
    if p < 0xb8:
        n, pos = p - 0x80, 1
        if n == 1 and len(buf) == 1:
            return error(2, pos)
        if n == 1 and buf[pos] < 0x80:
            return error(3, pos)
        if len(buf) - pos < n:
            return error(2, pos)
    elif p < 0xc0 or p >= 0xf8:
        is_list = p >= 0xf8
        nlen = p - (0xf7 if is_list else 0xb7)
        if len(buf) - 1 < nlen:
            return error(2, 1)
        pos = 1 + nlen
        if buf[1] == 0:
            return error(1, pos)
        n = int.from_bytes(buf[1:pos], 'big')
        if n < c['short_list_limit']:
            return error(4, pos)
        if len(buf) - pos < n:
            return error(2, pos)
        if is_list:
            return error(7, pos)
    else:
        n, pos = p - 0xc0, 1
        return error(7 if len(buf) - pos >= n else 2, pos)
    return {'result': 'value', 'hex': buf[pos:pos + n].hex(), 'length': n, 'consumed': pos + n}


def synthetic_examples(view, c):
    address = view.read(TARGET_ADDRESS, c['recipient_size'])
    if address != bytes(19) + b'\x09':
        raise ValueError('prior address-09 data boundary differs')
    cases = []
    for chain, parity in ((None, 0), (None, 1), (0, 0), (1, 1), ((1 << 64) - 1, 0)):
        payload = bytes(213)
        fields = tx_fields(9, 20_000_000_000, 21_000, address, 0, payload, c)
        preimage, signed, v = signing_and_signed(fields, chain, parity, 1, 1, c)
        cases.append({'chain_id': chain, 'parity': parity, 'v': v,
                      'recipient_hex': address.hex(), 'payload_length': len(payload),
                      'signing_length': len(preimage), 'signing_hex': preimage.hex(),
                      'signed_length': len(signed), 'signed_hex': signed.hex(),
                      'qualification': 'synthetic fields and unchecked signature; not target execution'})
    return cases


def tsv(rows, columns):
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=columns, delimiter='\t', lineterminator='\n', extrasaction='ignore')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode('ascii')


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def collect(data):
    digest = authenticate(data)
    view = View(data)
    windows = check_windows(view)
    fdes = selected_fdes(data, view)
    instructions, full_transfers, instruction_starts = walk_selected(view, fdes)
    relocs = selected_relocations(data, view)
    dynamic_symbol = memcpy_symbol(data, view, relocs)
    edges = [relative_edge(view, *item) for item in BRANCHES]
    edges += [rip_edge(view, *item) for item in RIP_CALLS]
    exceptions, exception_rows = lsda_rows(view, fdes)
    for row in exception_rows:
        if row['landing_va'] and int(row['landing_va'], 16) not in instruction_starts:
            raise ValueError('LSDA landing does not begin an instruction')
    c = constants(view)
    lanes = recipient_lanes(view, c)
    max_v = c['protected_v_base'] + ((c['adjusted_high_limit'] + 1) << 64) - 1
    v_inputs = [0, 1, 26, 27, 28, 29, 34, 35, 36, 37, 38,
                (1 << 64) - 1, 1 << 64, max_v - 1, max_v, max_v + 1,
                (1 << (8 * c['v_width'])) - 1]
    v_cases = []
    for value in v_inputs:
        outcome = classify_v(value, c)
        v_cases.append({'v_decimal': value, 'v_hex': hex(value),
                        'kind': outcome['kind'],
                        'chain_id': '' if outcome['chain_id'] is None else outcome['chain_id'],
                        'parity': '' if outcome['parity'] is None else outcome['parity']})
    cases = [b'', b'\x00', b'\x80', b'\x81', b'\x81\x00', b'\x81\x80',
             b'\xc0', b'\xc1', b'\xc1\x80', b'\xf8', b'\xf8\x00',
             b'\xf8\x37' + bytes(55), b'\xf8\x38' + bytes(55),
             b'\xf8\x38' + bytes(56), b'\xb8\x38' + bytes(56)]
    header_cases = [{'input_hex': x.hex(), **outer_header(x, c)} for x in cases]
    integer_inputs = [b'', b'\x00', b'\x01', b'\x7f', b'\x80', b'\x81',
                      b'\x81\x00', b'\x81\x7f', b'\x81\x80',
                      b'\x88' + b'\xff' * 8, b'\x89' + b'\x00' * 9,
                      b'\x89' + b'\x01' * 9, b'\xa0' + b'\xff' * 32,
                      b'\xa1' + b'\x00' * 33, b'\xa1' + b'\x01' * 33,
                      b'\xb8\x37' + bytes(55), b'\xc0', b'\xc1', b'\xc1\x80']
    integer_cases = [{'width': width, 'context': 'field' if field else 'scalar',
                      'input_hex': x.hex(), **decode_bounded_uint(x, width, c, field=field)}
                     for width, field in ((c['u64_width'], True), (c['price_width'], True),
                                          (c['value_width'], True), (c['scalar_width'], False))
                     for x in integer_inputs]
    payload_inputs = [b'', b'\x00', b'\x7f', b'\x80', b'\x81', b'\x81\x00',
                      b'\x81\x80', b'\xb8\xd5' + bytes(212),
                      b'\xb8\xd5' + bytes(213), b'\xb8\x37' + bytes(55),
                      b'\xc0', b'\xc1', b'\xc1\x80']
    payload_cases = [{'input_hex': x.hex(), **decode_payload(x, c)} for x in payload_inputs]
    max_word = (1 << 64) - 1
    length_inputs = [(0, 0, 0), (8, 5, 3), (8, 4, 3), (8, 6, 3),
                     (8, 0, 9), (max_word, 1, max_word), (max_word, 0, max_word)]
    length_cases = [{'initial_remaining': initial, 'declared_length': declared,
                     'final_remaining': final, **body_length_decision(initial, declared, final)}
                    for initial, declared, final in length_inputs]
    txs = synthetic_examples(view, c)
    summary = {'target_sha256': digest, 'selected_fde_count': len(fdes),
               'selected_code_bytes': sum(x['size'] for x in fdes),
               'linear_instruction_shape_count': len(instructions),
               'all_syntactic_transfer_count': len(full_transfers),
               'conditional_transfer_count': sum(x['kind'] == 'conditional' for x in full_transfers),
               'indirect_transfer_count': sum(x['kind'] in ('indirect_call', 'indirect_jump') for x in full_transfers),
               'fixed_window_count': len(windows), 'selected_transfer_count': len(edges),
               'selected_relative_branches_and_calls': len(BRANCHES),
               'selected_rip_slot_calls': len(RIP_CALLS), 'selected_relocation_count': len(relocs),
               'lsda_table_count': len(exceptions), 'lsda_call_site_count': len(exception_rows),
               'lsda_nonzero_landing_count': sum(bool(x['landing_va']) for x in exception_rows),
               'synthetic_v_case_count': len(v_cases), 'synthetic_header_case_count': len(header_cases),
               'recipient_lane_count': len(lanes), 'synthetic_integer_case_count': len(integer_cases),
               'synthetic_payload_case_count': len(payload_cases),
               'synthetic_length_case_count': len(length_cases),
               'synthetic_transaction_case_count': len(txs),
               'limits': 'Selected static evidence only; synthetic cases are not captured execution or component coverage.'}
    files = {
        'functions.tsv': tsv(fdes, ('start_va', 'end_va', 'size', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'index', 'sha256', 'role')),
        'bodies.json': json_bytes(fdes),
        'instructions.tsv': tsv([{'fde_start': hex(i['fde_start']), 'site_va': hex(i['site']),
                                  'file_offset': hex(view.offset(i['site'], len(i['raw']), True)),
                                  'size': len(i['raw']), 'bytes': i['raw'].hex(), 'kind': i['kind']}
                                 for i in instructions],
                                ('fde_start', 'site_va', 'file_offset', 'size', 'bytes', 'kind')),
        'transfers.tsv': tsv(full_transfers, ('fde_start', 'site_va', 'file_offset', 'bytes', 'kind', 'target_va')),
        'windows.tsv': tsv(windows, ('name', 'va', 'file_offset', 'bytes')),
        'edges.tsv': tsv(edges, ('name', 'site_va', 'file_offset', 'bytes', 'kind', 'displacement', 'target_va')),
        'relocations.tsv': tsv(relocs, ('slot_va', 'entry_file_offset', 'type', 'symbol_index', 'addend_va', 'entry_bytes')),
        'dynamic-symbol.json': json_bytes(dynamic_symbol),
        'exception-headers.json': json_bytes(exceptions),
        'exception-sites.tsv': tsv(exception_rows, ('fde_start', 'lsda_va', 'file_offset', 'start_va', 'length', 'end_va', 'landing_va', 'action', 'bytes')),
        'layout.json': json_bytes(c),
        'recipient-lanes.tsv': tsv(lanes, ('lane', 'kind', 'option_result_offset', 'field_result_offset', 'stage_offset', 'output_offset', 'instruction_va')),
        'v-cases.tsv': tsv(v_cases, ('v_decimal', 'v_hex', 'kind', 'chain_id', 'parity')),
        'header-cases.json': json_bytes(header_cases),
        'integer-cases.json': json_bytes(integer_cases),
        'payload-cases.json': json_bytes(payload_cases),
        'length-cases.json': json_bytes(length_cases),
        'synthetic-transactions.json': json_bytes(txs),
        'summary.json': json_bytes(summary),
    }
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    files = collect(ARTIFACT.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (args.out / name).write_bytes(files[name])
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as exc:
        print('re21 legacy evidence:', exc, file=sys.stderr)
        raise SystemExit(1)
