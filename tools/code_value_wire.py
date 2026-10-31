#!/usr/bin/env python3
"""Pin the stored wire form of the HyperEVM code value in node #94.

Every number comes from ELF bytes read with struct: section headers through
tools/elf_index.py, FDE extents through tools/fde_extents.py, jump tables from
.rodata. Instruction facts are fixed byte pins. No external program runs and
the binary is never executed.
"""
import argparse
import bisect
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
JSON_NAME = 'code-value-wire.json'
TSV_NAME = 'code-value-fields.tsv'
SHT_NOBITS = 8

WRITER = 0x3bf8bb0
WRITER_TABLE = 0x5b7404
DECODER = 0x2a6afe0
MAP_PATH = 0x3bfaa20
BARE_PATH = 0x3bfa8a0
MAP_TABLE = 0x5b76b0
BARE_TABLE = 0x5b76a0
FIELD_TABLE = 0x4cc514
ENUM_NAME = (0x20a1b8, 8)
NEWTYPE_NAME = (0x5b88dd, 9)
EXT_NAME = '_ExtStruct'
ORDER_VALUE = (0x580f9a, 19)
ORDER_COMPARE = (0x5b44b2, 19)
MISSING_ORDER = (0x57643c, 5)
PANIC_TEXT = (0x1f9011, 29)
MAP_HEADER = 0x35981d0
ARRAY_HEADER = 0x3598e20
U64_WRITER = 0x359b320
BYTES_FIELD = 0x3a08b40
ADDRESS_WRITER = 0x3584470
JUMP_TABLE_WRITER = 0x323f840
DOMAIN = 0x3814330
EMPTY_BUILDER = 0x38143f0
TAIL_BUILDER = 0x38142d0
WHOLE_BUILDER = 0x3814540
HEAD_FULL_BUILDER = 0x3814250
HEAD_SINGLE_BUILDER = 0x38144e0
HEAD_SPAN_BUILDER = 0x3814410
DOMAIN_SWEEP = 65536

# (tag, name va, name length, writer arm, payload callee,
#  map decoder call, map decoder, bare decoder call, bare decoder)
VARIANTS = [
    (0, 0x5b88bc, 9, 0x3bf8bd9, 0x3246260, 0x3bfaa68, 0x2be5e50, 0x3bfa92a, 0x2aec8a0),
    (1, 0x5b88c5, 14, 0x3bf8c9e, 0x39057c0, 0x3bfab3e, 0x2bf3510, 0x3bfa9bb, 0x2aec9a0),
    (2, 0x5b88d3, 3, 0x3bf8c07, 0x3904d60, 0x3bfaad3, 0x3444830, 0x3bfa954, 0x2aec830),
    (3, 0x5b88d6, 7, 0x3bf8c5a, 0x3904490, 0x3bfaafd, 0x2d0ab90, 0x3bfa97c, 0x2aecfa0),
]
# (owner, position, lea va, name va, length, length va, length bytes, source offset, value form, call va, callee)
FIELDS = [
    ('LegacyAnalyzed', 0, 0x3905830, 0x20a5b0, 8, 0x390583a, 'b908000000', 0x00, 'bin', 0x3905845, BYTES_FIELD),
    ('LegacyAnalyzed', 1, 0x3905863, 0x5a66db, 12, 0x390586a, 'ba0c000000', 0x28, 'uint', 0x3905886, U64_WRITER),
    ('LegacyAnalyzed', 2, 0x390589c, 0x5a66e7, 10, 0x39058a3, 'ba0a000000', 0x20, 'bit vector map', 0x39058cf, JUMP_TABLE_WRITER),
    ('Eip7702', 0, 0x3904507, 0x5a6607, 17, 0x390450e, 'ba11000000', 0x20, 'bin8 of 20 bytes', 0x390452b, ADDRESS_WRITER),
    ('Eip7702', 1, 0x3904546, 0x5a6618, 7, 0x390454d, 'ba07000000', 0x34, 'uint', 0x3904569, U64_WRITER),
    ('Eip7702', 2, 0x3904578, 0x5a661f, 3, 0x3904582, 'b903000000', 0x00, 'bin', 0x390458d, BYTES_FIELD),
    ('Eof', 0, 0x3904ddd, 0x5a663d, 6, 0x3904de4, 'ba06000000', 0x00, 'map of 6', 0x3904e0f, MAP_HEADER),
    ('Eof', 1, 0x3904fdc, 0x209d98, 4, 0x3904fe3, 'ba04000000', 0x48, 'map of 5', 0x3905014, 0x3239060),
    ('Eof', 2, 0x390517e, 0x5a661f, 3, 0x390518a, 'b903000000', 0xb8, 'bin', 0x3905195, BYTES_FIELD),
    ('Eof.header', 0, 0x3904e51, 0x5a668e, 10, 0x3904e58, 'ba0a000000', 0x40, 'uint', 0x3904e7a, U64_WRITER),
    ('Eof.header', 1, 0x3904e95, 0x5a6698, 10, 0x3904e9c, 'ba0a000000', 0x00, 'list', 0x3904ebe, 0x32166c0),
    ('Eof.header', 2, 0x3904edc, 0x5a66a2, 15, 0x3904ee3, 'ba0f000000', 0x18, 'list', 0x3904f06, 0x32166c0),
    ('Eof.header', 3, 0x3904f25, 0x5a66b1, 9, 0x3904f2c, 'ba09000000', 0x42, 'uint', 0x3904f4e, U64_WRITER),
    ('Eof.header', 4, 0x3904f6d, 0x5a66ba, 14, 0x3904f74, 'ba0e000000', 0x30, 'uint', 0x3904f96, U64_WRITER),
    ('Eof.header', 5, 0x3904fae, 0x5a66c8, 19, 0x3904fba, 'b913000000', 0x38, 'uint', 0x3904fc2, 0x3a0bd80),
    ('Eof.body', 0, 0x3905034, 0x5a664a, 13, 0x390503b, 'ba0d000000', 0x48, 'list', 0x390505e, 0x3212200),
    ('Eof.body', 1, 0x3905079, 0x5a6657, 12, 0x3905080, 'ba0c000000', 0x60, 'list', 0x39050a3, 0x3217910),
    ('Eof.body', 2, 0x39050be, 0x5a6663, 17, 0x39050c5, 'ba11000000', 0x78, 'list', 0x39050e8, 0x3217910),
    ('Eof.body', 3, 0x3905102, 0x5a6674, 12, 0x390510e, 'b90c000000', 0x90, 'bin', 0x3905116, BYTES_FIELD),
    ('Eof.body', 4, 0x390513d, 0x5a6680, 14, 0x3905144, 'ba0e000000', 0xb0, 'bool', 0x3905168, 0x3238a00),
    ('Eof.types_section row', 0, 0x39047cb, 0x5a6622, 6, 0x39047d2, 'ba06000000', 0x02, 'uint', 0x39047f2, U64_WRITER),
    ('Eof.types_section row', 1, 0x3904811, 0x5a6628, 7, 0x3904818, 'ba07000000', 0x03, 'uint', 0x3904834, U64_WRITER),
    ('Eof.types_section row', 2, 0x390484e, 0x5a662f, 14, 0x3904855, 'ba0e000000', 0x00, 'uint', 0x3904871, U64_WRITER),
    ('JumpTable', 0, 0x323f8f0, 0x580fad, 5, 0x323f8f7, 'ba05000000', None, 'fixstr', 0x323f91d, 0x3599a40),
    ('JumpTable', 1, 0x323f933, 0x209eec, 4, 0x323f93a, 'ba04000000', None, 'map of 2', 0x323f965, MAP_HEADER),
    ('JumpTable', 2, 0x323fa58, 0x209e60, 4, 0x323fa5f, 'ba04000000', None, 'uint', 0x323fa85, U64_WRITER),
    ('JumpTable', 3, 0x323faaf, 0x20a08c, 4, 0x323fab6, 'ba04000000', None, 'array of uint', 0x323fb4e, ARRAY_HEADER),
    ('JumpTable.head', 0, 0x323f9cb, 0x21d508, 5, 0x323f9d2, 'ba05000000', None, 'uint 8', 0x323f9f6, U64_WRITER),
    ('JumpTable.head', 1, 0x323fa11, 0x21d50d, 5, 0x323fa18, 'ba05000000', None, 'uint', 0x323fa3d, U64_WRITER),
]
# (name, start)
FUNCTIONS = [
    ('writer', WRITER), ('newtype variant', 0x3246260), ('Eip7702 writer', 0x3904490),
    ('LegacyAnalyzed writer', 0x39057c0), ('Eof writer', 0x3904d60), ('types row writer', 0x3904750),
    ('jump table writer', JUMP_TABLE_WRITER), ('bit domain selector', DOMAIN), ('decoder', DECODER),
    ('map path', MAP_PATH), ('bare path', BARE_PATH), ('LegacyAnalyzed reader', 0x2bf3510),
    ('jump table reader', 0x34449a0), ('bit vector reader', 0x2ca6440), ('order reader', 0x2df3fd0),
    ('bit vector assembly', 0x2aeae30),
]
# (start, end, sha256 of the bytes, meaning)
RANGE_PINS = [
    (0x3814330, 0x38143e9, '3d9a2e1256c696dadba2e75099f4e08d041ee2686b46b1190d34bda3ea06c1b9', 'bit domain selector'),
    (0x38143f0, 0x381440a, 'a426d21ff63f890d45e3d8138086489363c52345360e91d3547e049aa661968c', 'empty region builder'),
    (0x38142d0, 0x3814314, '1ca06a77b0255cb22e25c9c67b7a48916ab2c2de37bc0c3537e4b80f5954d141', 'whole bytes with a masked tail builder'),
    (0x3814540, 0x381455b, '10117607928331a49e451a22d25bdb78352ddf0e9bb9078f34d34ba5d8c11f0c', 'whole bytes builder'),
]
RIP_PINS = [
    (0x37d2303, 'e8', 0x358c870, 'code write calls the encoder'),
    (0x358c8d3, 'e8', 0x3bf8bb0, 'Ec encoder calls the Bytecode writer in map mode'),
    (0x37d1502, 'e8', 0x2a6afe0, 'Ec getter calls the Bytecode decoder'),
    (0x3bf8bc9, '488d0d', 0x5b7404, 'writer: tag jump table'),
    (0x3bf8bd9, '488d15', 0x20a1b8, 'enum name for the newtype variant'),
    (0x3bf8be0, '4c8d0d', 0x5b88bc, 'name of tag 0'),
    (0x3bf8bf9, 'e8', 0x3246260, 'tag 0 payload helper'),
    (0x3bf8c12, 'e8', 0x35981d0, 'tag 2 map header'),
    (0x3bf8c25, '488d35', 0x5b88d3, 'name of tag 2'),
    (0x3bf8c34, 'e8', 0x3599a40, 'tag 2 name writer'),
    (0x3bf8c50, 'e8', 0x3904d60, 'tag 2 payload writer'),
    (0x3bf8c65, 'e8', 0x35981d0, 'tag 3 map header'),
    (0x3bf8c74, '488d35', 0x5b88d6, 'name of tag 3'),
    (0x3bf8c83, 'e8', 0x3599a40, 'tag 3 name writer'),
    (0x3bf8c97, 'e8', 0x3904490, 'tag 3 payload writer'),
    (0x3bf8ca9, 'e8', 0x35981d0, 'tag 1 map header'),
    (0x3bf8cb8, '488d35', 0x5b88c5, 'name of tag 1'),
    (0x3bf8cc7, 'e8', 0x3599a40, 'tag 1 name writer'),
    (0x3bf8cdb, 'e8', 0x39057c0, 'tag 1 payload writer'),
    (0x324627c, 'e8', 0x35981d0, 'tag 0 map header'),
    (0x3246297, 'e8', 0x3599a40, 'tag 0 name writer'),
    (0x3246353, 'e8', 0x35995d0, 'tag 0 bytes writer'),
    (0x39044c2, 'e8', 0x35981d0, 'Eip7702 map header'),
    (0x3904507, '488d35', 0x5a6607, 'field name delegated_address'),
    (0x3904516, 'e8', 0x3599a40, 'its writer'),
    (0x390452b, 'e8', 0x3584470, 'address writer'),
    (0x3904546, '488d35', 0x5a6618, 'field name version'),
    (0x3904555, 'e8', 0x3599a40, 'its writer'),
    (0x3904569, 'e8', 0x359b320, 'version uses the u64 writer'),
    (0x3904578, '488d15', 0x5a661f, 'field name raw'),
    (0x390458d, 'e8', 0x3a08b40, 'bytes field writer'),
    (0x3584710, 'e8', 0x35995d0, 'address uses the bytes writer'),
    (0x3a08b63, 'e8', 0x3599a40, 'bytes field: name writer'),
    (0x3a08bd1, 'e8', 0x35995d0, 'bytes field: bytes writer'),
    (0x39057f2, 'e8', 0x35981d0, 'LegacyAnalyzed map header'),
    (0x3905830, '488d15', 0x20a5b0, 'field name bytecode'),
    (0x3905845, 'e8', 0x3a08b40, 'bytes field writer'),
    (0x3905863, '488d35', 0x5a66db, 'field name original_len'),
    (0x3905872, 'e8', 0x3599a40, 'its writer'),
    (0x3905886, 'e8', 0x359b320, 'original_len uses the u64 writer'),
    (0x390589c, '488d35', 0x5a66e7, 'field name jump_table'),
    (0x39058ab, 'e8', 0x3599a40, 'its writer'),
    (0x39058ba, '488d15', 0x5b88dd, 'newtype name JumpTable'),
    (0x39058cf, 'e8', 0x323f840, 'jump table writer'),
    (0x323f89d, 'e8', 0x35981d0, 'outer map header'),
    (0x323f8f0, '488d35', 0x580fad, 'field name order'),
    (0x323f8ff, 'e8', 0x3599a40, 'its writer'),
    (0x323f90e, '488d35', 0x580f9a, 'order value'),
    (0x323f91d, 'e8', 0x3599a40, 'its writer'),
    (0x323f933, '488d35', 0x209eec, 'field name head'),
    (0x323f942, 'e8', 0x3599a40, 'its writer'),
    (0x323f965, 'e8', 0x35981d0, 'head map header'),
    (0x323f9cb, '488d35', 0x21d508, 'field name width'),
    (0x323f9da, 'e8', 0x3599a40, 'its writer'),
    (0x323f9f6, 'e8', 0x359b320, 'width writer'),
    (0x323fa11, '488d35', 0x21d50d, 'field name index'),
    (0x323fa20, 'e8', 0x3599a40, 'its writer'),
    (0x323fa3d, 'e8', 0x359b320, 'index writer'),
    (0x323fa58, '488d35', 0x209e60, 'field name bits'),
    (0x323fa67, 'e8', 0x3599a40, 'its writer'),
    (0x323fa85, 'e8', 0x359b320, 'bits writer'),
    (0x323faa3, 'e8', 0x3814330, 'domain selector'),
    (0x323faaf, '488d35', 0x20a08c, 'field name data'),
    (0x323fabe, 'e8', 0x3599a40, 'its writer'),
    (0x323fb4e, 'e8', 0x3598e20, 'data array header'),
    (0x323fc4b, 'e8', 0x359b320, 'first element uses the u64 writer'),
    (0x323fca1, 'e8', 0x359b320, 'next elements use the u64 writer'),
    (0x2a6b0b0, 'e8', 0x3bfaa20, 'decoder: map path'),
    (0x2a6b107, 'e8', 0x3bfa8a0, 'decoder: bare path'),
    (0x3bfaa35, 'e8', 0x2b36910, 'map path: identifier reader'),
    (0x3bfaa4d, '488d0d', 0x5b76b0, 'map path: arm table'),
    (0x3bfaa68, 'e8', 0x2be5e50, 'map arm 0 bytes reader'),
    (0x3bfaad3, 'e8', 0x3444830, 'map arm 2 Eof reader'),
    (0x3bfaafd, 'e8', 0x2d0ab90, 'map arm 3 Eip7702 reader'),
    (0x3bfab3e, 'e8', 0x2bf3510, 'map arm 1 LegacyAnalyzed reader'),
    (0x3bfa8b5, 'e8', 0x2b36910, 'bare path: identifier reader'),
    (0x3bfa914, '488d0d', 0x5b76a0, 'bare path: arm table'),
    (0x3bfa92a, 'e8', 0x2aec8a0, 'bare arm 0'),
    (0x3bfa954, 'e8', 0x2aec830, 'bare arm 2'),
    (0x3bfa97c, 'e8', 0x2aecfa0, 'bare arm 3'),
    (0x3bfa9bb, 'e8', 0x2aec9a0, 'bare arm 1'),
    (0x2b36a2f, 'e8', 0x3bfabb0, 'str identifier match'),
    (0x2bf3a0e, 'e8', 0x2be5e50, 'LegacyAnalyzed seq: first element reader'),
    (0x2bf3adf, 'e8', 0x2a65d30, 'LegacyAnalyzed seq: second element reader'),
    (0x2bf3ba9, 'e8', 0x34449a0, 'LegacyAnalyzed seq: third element reader'),
    (0x34449dc, 'e8', 0x2ca6440, 'jump table: bitvec reader'),
    (0x2ca6a01, '488d0d', 0x4cc514, 'bitvec map: field arm table'),
    (0x2ca6a1e, 'e8', 0x2df3fd0, 'field 0 reader'),
    (0x2ca6a4d, 'e8', 0x2a65ca0, 'field 2 reader'),
    (0x2ca6a7d, 'e8', 0x2b377d0, 'field 3 reader'),
    (0x2ca6ac9, 'e8', 0x2aeb250, 'field 1 reader'),
    (0x2ca6b6d, 'e8', 0x2aeae30, 'bitvec map: assembly'),
    (0x2df4238, 'f30f6f05', 0x5b44b2, 'order value: window at 0'),
    (0x2df424d, 'f30f6f15', 0x5b44b5, 'order value: window at 3'),
    (0x2aeaf30, '488d05', 0x57643c, 'missing order name'),
    (0x2aeaf89, '488d05', 0x209eec, 'missing head name'),
    (0x2aeafec, '488d05', 0x209e60, 'missing bits name'),
    (0x2aeb05a, '488d05', 0x20a08c, 'missing data name'),
    (0x2aeb13d, '488d3d', 0x1f9010, 'capacity panic template'),
    (0x2aeb150, 'ff15', 0x576e098, 'capacity panic call'),
]
BYTE_PINS = [
    (0x358c88a, '4080c6e9', 'encoder gate: code plus 0xe9'),
    (0x358c88e, '4080fe04', 'encoder gate: below 4'),
    (0x358c8b6, 'c744242000040001', 'encoder gate: stores the map mode flag'),
    (0x3bf8bc2, '488b06', 'writer: tag from value+0'),
    (0x3bf8bc5, '4983c708', 'writer: payload at value+8'),
    (0x3bf8be7, 'b908000000', 'enum name length'),
    (0x3bf8bf2, '4531c0', 'variant index argument 0'),
    (0x3bf8bf7, '6a09', 'tag 0 name length'),
    (0x3bf8c0d, 'ba01000000', 'tag 2 map of one entry'),
    (0x3bf8c2c, 'ba03000000', 'tag 2 name length'),
    (0x3bf8c43, '498b37', 'tag 2 loads the Arc pointer'),
    (0x3bf8c46, '4883c610', 'tag 2 skips the two Arc counters'),
    (0x3bf8c60, 'ba01000000', 'tag 3 map of one entry'),
    (0x3bf8c7b, 'ba07000000', 'tag 3 name length'),
    (0x3bf8ca4, 'ba01000000', 'tag 1 map of one entry'),
    (0x3bf8cbf, 'ba0e000000', 'tag 1 name length'),
    (0x3246277, 'ba01000000', 'tag 0 map of one entry'),
    (0x324628c, '488b542440', 'tag 0 name length from the stack'),
    (0x32462ab, '41807e0a00', 'tag 0 human-readable test'),
    (0x3246348, '488b7008', 'tag 0 byte pointer from Bytes+8'),
    (0x324634c, '488b5010', 'tag 0 byte length from Bytes+0x10'),
    (0x39044b1, '807a0b00', 'Eip7702 header choice'),
    (0x39044bd, 'ba03000000', 'Eip7702 three fields'),
    (0x390450e, 'ba11000000', 'its length'),
    (0x3904521, '498d7620', 'delegated address at +0x20'),
    (0x390453a, '450fb66634', 'version byte at +0x34'),
    (0x390454d, 'ba07000000', 'its length'),
    (0x3904582, 'b903000000', 'its length'),
    (0x390458a, '4d89f0', 'raw is at +0'),
    (0x358448b, '807a0a00', 'address human-readable test'),
    (0x3584708, 'ba14000000', 'address length 20'),
    (0x3a08b54, '807e0b00', 'bytes field: name gate'),
    (0x3a08b6e, '41807f0a00', 'bytes field: human-readable test'),
    (0x3a08bc6, '498b7608', 'bytes field: pointer from Bytes+8'),
    (0x3a08bca, '498b5610', 'bytes field: length from Bytes+0x10'),
    (0x39057e1, '807a0b00', 'LegacyAnalyzed header choice'),
    (0x39057ed, 'ba03000000', 'LegacyAnalyzed three fields'),
    (0x390583a, 'b908000000', 'its length'),
    (0x3905842, '4d89f0', 'bytecode is at +0'),
    (0x3905858, '4d8b6628', 'original_len at +0x28'),
    (0x390586a, 'ba0c000000', 'its length'),
    (0x39058a3, 'ba0a000000', 'its length'),
    (0x39058b6, '4983c620', 'jump table at +0x20'),
    (0x39058c4, 'b909000000', 'its length'),
    (0x323f857, '4883f90a', 'newtype name length test'),
    (0x323f85d, '48b85f45787453747275', 'extension name head'),
    (0x323f86e, '4881f163740000', 'extension name tail'),
    (0x323f878, '0f84fc000000', 'extension branch'),
    (0x323f87e, '498b00', 'Arc pointer of the jump table'),
    (0x323f881, '4c8b7810', 'BitVec pointer at Arc+0x10'),
    (0x323f885, '4c8b6018', 'BitVec encoded length at Arc+0x18'),
    (0x323f889, '41807e0b00', 'map or array choice'),
    (0x323f898, 'ba04000000', 'four fields'),
    (0x323f8f7, 'ba05000000', 'its length'),
    (0x3904e45, '450fb76640', 'header types_size at +0x40'),
    (0x3904efa, '498d5618', 'header container_sizes at +0x18'),
    (0x3904f19, '450fb76642', 'header data_size at +0x42'),
    (0x3904f62, '4d8b6630', 'header sum_code_sizes at +0x30'),
    (0x3904faa, '4d8b4638', 'header sum_container_sizes at +0x38'),
    (0x3905052, '498d5648', 'body types_section at +0x48'),
    (0x3905097, '498d5660', 'body code_section at +0x60'),
    (0x39050dc, '498d5678', 'body container_section at +0x78'),
    (0x39050fb, '4d8d8690000000', 'body data_section at +0x90'),
    (0x3905129, '410fb686b0000000', 'body is_data_filled at +0xb0'),
    (0x3905177, '4981c6b8000000', 'raw at +0xb8'),
    (0x39047bf, '450fb66702', 'types row inputs at +2'),
    (0x3904805, '450fb66703', 'types row outputs at +3'),
    (0x3904843, '450fb73f', 'types row max_stack_size at +0'),
    (0x3904e0a, 'ba06000000', 'header holds six fields'),
    (0x3905006, 'b907000000', 'body name length'),
    (0x390500b, '41b805000000', 'body holds five fields'),
    (0x323f915, 'ba13000000', 'its length'),
    (0x323f93a, 'ba04000000', 'its length'),
    (0x323f960, 'ba02000000', 'head holds two fields'),
    (0x323f9d2, 'ba05000000', 'its length'),
    (0x323f9ee, 'ba08000000', 'width value 8'),
    (0x323fa18, 'ba05000000', 'its length'),
    (0x323fa2f, '4489e2', 'index from the encoded length'),
    (0x323fa32, '83e207', 'index = low three bits'),
    (0x323fa5f, 'ba04000000', 'its length'),
    (0x323fa76, '4c89e2', 'bits from the encoded length'),
    (0x323fa79, '48c1ea03', 'bits = length >> 3'),
    (0x323fa9d, '4c89fe', 'domain base pointer'),
    (0x323faa0, '4c89e2', 'domain encoded length'),
    (0x323fab6, 'ba04000000', 'its length'),
    (0x323fb41, 'ba01000000', 'single element count'),
    (0x323fb5e, '49bd0000000000000080', 'no buffer marker'),
    (0x323fb68, '4c896c2458', 'buffer slot is the None marker'),
    (0x323fc8f, '4c396c2458', 'buffer test in the element loop'),
    (0x2a6b01c, '80f9df', 'decoder: map32 marker test'),
    (0x2a6b028, '81f9de000000', 'decoder: map16 marker test'),
    (0x2a6b030, '81f980000000', 'decoder: fixmap marker test'),
    (0x2a6b03b, '83f801', 'decoder: fixmap length must be 1'),
    (0x2a6b0a4, '83f801', 'decoder: map16 length must be 1'),
    (0x2a6b122, '83f801', 'decoder: map32 length must be 1'),
    (0x2a6b127, 'c6430804', 'decoder: length mismatch error tag'),
    (0x3bfaa30, 'ba01000000', 'map path: identifier flag'),
    (0x3bfaa83, '48c1e002', 'map arm 0 result tag from the status'),
    (0x3bfaaeb, 'b802000000', 'map arm 2 result tag 2'),
    (0x3bfab2f, 'b803000000', 'map arm 3 result tag 3'),
    (0x3bfab67, 'b801000000', 'map arm 1 result tag 1'),
    (0x2aec8a8, 'c64424380d', 'bare arm 0 unexpected kind 13'),
    (0x2aec838, 'c64424380d', 'bare arm 2 unexpected kind 13'),
    (0x2aecfa8, 'c64424380d', 'bare arm 3 unexpected kind 13'),
    (0x2aec9a8, 'c64424380d', 'bare arm 1 unexpected kind 13'),
    (0x3bfabba, '488d4afd', 'identifier length minus 3'),
    (0x3bfabbe, '4883f90b', 'identifier length range'),
    (0x3bfabf5, '66c7000902', 'name match Eof = index 2'),
    (0x3bfac5b, '66c7000900', 'name match LegacyRaw = index 0'),
    (0x3bfacc7, '66c7000901', 'name match LegacyAnalyzed = index 1'),
    (0x3bfacfd, '66c7000903', 'name match Eip7702 = index 3'),
    (0x3444a27, 'bf28000000', 'jump table: Arc allocation size'),
    (0x3444a3e, '48c70001000000', 'jump table: strong count 1'),
    (0x3444a45, '48c7400801000000', 'jump table: weak count 1'),
    (0x2ca6a2e, 'c644244d01', 'field 0 presence flag'),
    (0x2ca6ae4, 'c644244c01', 'field 1 presence flag'),
    (0x2df4219, '837c245001', 'order value: utf-8 result test'),
    (0x2df422e, '4883f913', 'order value: length 19'),
    (0x2df4232, '0f8550040000', 'order value: length mismatch branch'),
    (0x2df4248, 'f30f6f4003', 'order value: second window starts at 3'),
    (0x2df4261, '81faffff0000', 'order value: all bytes equal'),
    (0x2df4267, '0f851b040000', 'order value: byte mismatch branch'),
    (0x2aeae4a, '807e2a01', 'assembly: order presence at state+0x2a'),
    (0x2aeae54, '807b2800', 'assembly: head presence at state+0x28'),
    (0x2aeae5e, '803b00', 'assembly: bits presence at state+0'),
    (0x2aeae67, '0fb65329', 'assembly: head index from state+0x29'),
    (0x2aeae6b, '488b4b08', 'assembly: bits from state+8'),
    (0x2aeae6f, '4c8b7310', 'assembly: data capacity from state+0x10'),
    (0x2aeae73, '4c8b7b18', 'assembly: data pointer from state+0x18'),
    (0x2aeae77, '4c8b6b20', 'assembly: data length from state+0x20'),
    (0x2aeae7f, '4d39e6', 'assembly: data presence test'),
    (0x2aeaeda, '83e207', 'assembly: head masked to three bits'),
    (0x2aeaeee, '4a8d04f500000000', 'assembly: capacity in bits'),
    (0x2aeaef8, '4829d0', 'assembly: minus the head'),
    (0x2aeaefb, '480f43f0', 'assembly: saturates at zero'),
    (0x2aeaf03, '4839f1', 'assembly: bits against capacity'),
    (0x2aeaf06, '0f870e020000', 'assembly: over capacity branch'),
    (0x2aeaf0c, '488d04ca', 'assembly: encoded length = head + bits * 8'),
]


class View:
    """Read-only VA view over file-backed sections."""

    def __init__(self, data):
        self.data = data
        self.sections = elf_index.sections(data)
        self.loaded = [s for s in self.sections
                       if s['type'] != SHT_NOBITS and s['address'] and s['size']]

    def mem(self, va, size):
        for sec in self.loaded:
            if sec['address'] <= va and va + size <= sec['address'] + sec['size']:
                start = sec['offset'] + va - sec['address']
                return self.data[start:start + size]
        raise ValueError(f'{va:#x}+{size} is outside file-backed sections')

    def i32(self, va):
        return struct.unpack('<i', self.mem(va, 4))[0]

    def text(self, va, size):
        return self.mem(va, size).decode('ascii')


def rip_target(view, va, prefix):
    """Resolve prefix + rel32 at va, failing closed on different bytes."""
    if view.mem(va, len(prefix)) != prefix:
        raise ValueError(f'instruction bytes differ at {va:#x}')
    return va + len(prefix) + 4 + view.i32(va + len(prefix))


def check_rip_pin(view, pin):
    va, prefix, expected, meaning = pin
    target = rip_target(view, va, bytes.fromhex(prefix))
    if target != expected:
        raise ValueError(f'{va:#x} targets {target:#x}, not {expected:#x}')
    return {'va': hex(va), 'bytes_prefix': prefix, 'target': hex(target), 'meaning': meaning}


def check_byte_pin(view, pin):
    va, raw, meaning = pin
    if view.mem(va, len(bytes.fromhex(raw))).hex() != raw:
        raise ValueError(f'bytes differ at {va:#x}')
    return {'va': hex(va), 'bytes': raw, 'meaning': meaning}


def check_range_pin(view, pin):
    start, end, digest, meaning = pin
    if hashlib.sha256(view.mem(start, end - start)).hexdigest() != digest:
        raise ValueError(f'range {start:#x} differs')
    return {'start': hex(start), 'end': hex(end), 'sha256': digest, 'meaning': meaning}


def lea_target(view, va):
    raw = view.mem(va, 3)
    if raw[0] not in (0x48, 0x4c) or raw[1] != 0x8d or raw[2] & 0xc7 != 5:
        raise ValueError(f'no rip lea at {va:#x}')
    return rip_target(view, va, raw)


def expect_call(view, va, target):
    if rip_target(view, va, b'\xe8') != target:
        raise ValueError(f'call at {va:#x} does not reach {target:#x}')


def table_entry(view, table, index):
    return table + view.i32(table + 4 * index)


def fde_row(starts, ordered, start):
    index = bisect.bisect_right(starts, start) - 1
    row = ordered[index]
    if row['start'] != start:
        raise ValueError(f'{start:#x} is not an FDE start')
    return row


def check_variant(view, row):
    tag, name_va, size, arm, payload, map_call, map_fn, bare_call, bare_fn = row
    if table_entry(view, WRITER_TABLE, tag) != arm:
        raise ValueError(f'writer arm of tag {tag} differs')
    for table, call in ((MAP_TABLE, map_call), (BARE_TABLE, bare_call)):
        offset = call - table_entry(view, table, tag)
        if not 0 < offset < 16:
            raise ValueError(f'decoder call of tag {tag} is outside its arm')
    expect_call(view, map_call, map_fn)
    expect_call(view, bare_call, bare_fn)
    return {'tag': tag, 'name': view.text(name_va, size), 'writer_arm': hex(arm), 'payload_writer': hex(payload),
            'map_reader': hex(map_fn), 'bare_reader': hex(bare_fn)}


def check_field(view, row):
    owner, position, lea_va, name_va, size, size_va, size_raw, offset, form, call_va, callee = row
    if lea_target(view, lea_va) != name_va:
        raise ValueError(f'{owner} field {position} name differs')
    if view.mem(size_va, 5).hex() != size_raw:
        raise ValueError(f'{owner} field {position} name length differs')
    if struct.unpack('<I', bytes.fromhex(size_raw)[1:])[0] != size:
        raise ValueError(f'{owner} field {position} table length differs')
    expect_call(view, call_va, callee)
    return {'owner': owner, 'position': position, 'name': view.text(name_va, size),
            'offset': None if offset is None else hex(offset), 'form': form, 'callee': hex(callee)}


def bit_domain(head, bits):
    """Model selector 0x3814330: pick a builder for an encoded bit span."""
    encoded = bits << 3 | head
    tail = head
    if encoded >= 8:
        room = 8 - head
        if bits <= room:
            tail = (bits + head) & 0xff
        else:
            low = (bits - room) & 7
            tail = (8 if low == 0 else 0) | low
    total = head + bits + 7
    count = total >> 3
    if total < 8:
        return EMPTY_BUILDER, count, tail
    if head == 0:
        return (WHOLE_BUILDER if tail == 8 else TAIL_BUILDER), count, tail
    if tail == 8:
        return HEAD_FULL_BUILDER, count, tail
    return (HEAD_SINGLE_BUILDER if count == 1 else HEAD_SPAN_BUILDER), count, tail


def tail_mask(tail):
    """Model builder 0x38142d0: keep the low `tail` bits of the last byte."""
    if not 0 <= tail <= 8:
        raise ValueError('tail is 0..=8')
    return 0xff if tail == 8 else ~(0xff << tail) & 0xff


def data_elements(bits, raw):
    """The integers in the `data` array of a bit vector with head 0."""
    builder, count, tail = bit_domain(0, bits)
    if len(raw) != count:
        raise ValueError('raw length differs from the element count')
    if builder == EMPTY_BUILDER:
        return []
    if builder == WHOLE_BUILDER:
        return list(raw)
    if builder != TAIL_BUILDER:
        raise ValueError('head 0 reached another builder')
    return list(raw[:-1]) + [raw[-1] & tail_mask(tail)]


def capacity_accepts(bits, head, capacity):
    """Model the panic test at 0x2aeaf03: compare against capacity in bits."""
    return bits <= max(capacity * 8 - (head & 7), 0)


def uint_value(value):
    if value < 0x80:
        return bytes((value,))
    if value < 0x100:
        return bytes((0xcc, value))
    if value < 0x10000:
        return b'\xcd' + struct.pack('>H', value)
    if value < 0x100000000:
        return b'\xce' + struct.pack('>I', value)
    return b'\xcf' + struct.pack('>Q', value)


def fixstr(text):
    if len(text) >= 32:
        raise ValueError('model covers fixstr only')
    return bytes((0xa0 | len(text),)) + text.encode('ascii')


def bin_value(raw):
    if len(raw) < 0x100:
        return bytes((0xc4, len(raw))) + raw
    if len(raw) < 0x10000:
        return b'\xc5' + struct.pack('>H', len(raw)) + raw
    return b'\xc6' + struct.pack('>I', len(raw)) + raw


def array_header(count):
    if count < 0x10:
        return bytes((0x90 | count,))
    if count < 0x10000:
        return b'\xdc' + struct.pack('>H', count)
    return b'\xdd' + struct.pack('>I', count)


def jump_table_value(order, bits, raw):
    elements = data_elements(bits, raw)
    return (b'\x84' + fixstr('order') + fixstr(order)
            + fixstr('head') + b'\x82' + fixstr('width') + uint_value(8) + fixstr('index') + uint_value(0)
            + fixstr('bits') + uint_value(bits)
            + fixstr('data') + array_header(len(elements)) + b''.join(uint_value(e) for e in elements))


def legacy_raw_value(code):
    return b'\x81' + fixstr('LegacyRaw') + bin_value(code)


def legacy_analyzed_value(order, code, original_len, bits, raw):
    return (b'\x81' + fixstr('LegacyAnalyzed') + b'\x83' + fixstr('bytecode') + bin_value(code)
            + fixstr('original_len') + uint_value(original_len)
            + fixstr('jump_table') + jump_table_value(order, bits, raw))


def eip7702_value(address, version, raw):
    if len(address) != 20:
        raise ValueError('delegated address is 20 bytes')
    return (b'\x81' + fixstr('Eip7702') + b'\x83' + fixstr('delegated_address') + bin_value(address)
            + fixstr('version') + uint_value(version) + fixstr('raw') + bin_value(raw))


def domain_census():
    """Sweep the head 0 selector model against the plain element count."""
    counts = {}
    for bits in range(DOMAIN_SWEEP + 1):
        builder, count, _ = bit_domain(0, bits)
        if count != (bits + 7) >> 3:
            raise ValueError(f'element count differs at {bits}')
        counts[hex(builder)] = counts.get(hex(builder), 0) + 1
    return counts


def build(data):
    view = View(data)
    _, ordered, _ = fde_extents.fde_extents(data)
    starts = [row['start'] for row in ordered]
    rip_pins = [check_rip_pin(view, pin) for pin in RIP_PINS]
    byte_pins = [check_byte_pin(view, pin) for pin in BYTE_PINS]
    range_pins = [check_range_pin(view, pin) for pin in RANGE_PINS]
    variants = [check_variant(view, row) for row in VARIANTS]
    fields = [check_field(view, row) for row in FIELDS]
    functions = [{'name': name, 'start': hex(start), 'end': hex(fde_row(starts, ordered, start)['end'])}
                 for name, start in FUNCTIONS]
    order = view.text(*ORDER_VALUE)
    if view.text(*ORDER_COMPARE) != order:
        raise ValueError('order value and compare constant differ')
    if view.text(*MISSING_ORDER) != 'order':
        raise ValueError('missing field name differs')
    field_arms = [hex(table_entry(view, FIELD_TABLE, index)) for index in range(5)]
    address = bytes(range(0xa0, 0xb4))
    code = bytes.fromhex('6001600155')
    examples = {
        'legacy_raw': legacy_raw_value(code).hex(),
        'legacy_analyzed_bits_0': legacy_analyzed_value(order, b'', 0, 0, b'').hex(),
        'legacy_analyzed_bits_12': legacy_analyzed_value(order, code, 5, 12, b'\xff\xff').hex(),
        'eip7702': eip7702_value(address, 0, bytes.fromhex('ef0100') + address).hex(),
    }
    report = {
        'schema': 'code-value-wire/v1',
        'binary_sha256': hashlib.sha256(data).hexdigest(),
        'coordinate_system': 'ELF virtual addresses; FDE end exclusive',
        'enum_name': view.text(*ENUM_NAME),
        'newtype_name': view.text(*NEWTYPE_NAME),
        'order_value': order,
        'panic_text': view.text(*PANIC_TEXT),
        'variants': variants,
        'fields': fields,
        'functions': functions,
        'bit_vector_field_arms': field_arms,
        'bit_domain_sweep': {'head': 0, 'bits_max': DOMAIN_SWEEP, 'builder_counts': domain_census()},
        'capacity_samples': [
            {'bits': bits, 'head': head, 'capacity': capacity, 'accepted': capacity_accepts(bits, head, capacity)}
            for bits, head, capacity in ((8, 0, 1), (9, 0, 1), (5, 3, 1), (6, 3, 1), (0, 7, 0), (1, 7, 0))],
        'examples': examples,
        'rip_pins': rip_pins,
        'byte_pins': byte_pins,
        'range_pins': range_pins,
    }
    return report


def tsv_text(report):
    lines = ['owner\tposition\tname\toffset\tform\tcallee']
    for row in report['fields']:
        lines.append(f"{row['owner']}\t{row['position']}\t{row['name']}\t{row['offset'] or '-'}\t{row['form']}\t{row['callee']}")
    return '\n'.join(lines) + '\n'


def write_outputs(report, out):
    out.mkdir(parents=True, exist_ok=True)
    (out / JSON_NAME).write_text(json.dumps(report, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    (out / TSV_NAME).write_text(tsv_text(report), encoding='utf-8')


def load_binary(path=BINARY, expected=SHA256):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('binary sha256 mismatch')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = build(load_binary())
    write_outputs(report, args.out)
    print(json.dumps({'fields': len(report['fields']), 'variants': len(report['variants'])}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
