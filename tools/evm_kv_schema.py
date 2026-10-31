#!/usr/bin/env python3
"""Pin the HyperEVM RocksDB key and value encoding of node #94.

Every number comes from ELF bytes read with struct: section headers through
tools/elf_index.py, FDE extents through tools/fde_extents.py, and RELATIVE
relocations from .rela.dyn. Instruction facts are fixed byte pins or a small
evaluator over fixed SSE encodings. No external program runs and the binary is
never executed.
"""
import argparse
import bisect
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
JSON_NAME = 'evm-kv-schema.json'
TSV_NAME = 'key-concat-sites.tsv'
R_X86_64_RELATIVE = 8
SHT_NOBITS = 8

CONCAT = 0x3bc5ae0
CONCAT_BLOCK = 0x254dab0
RAW_GET = 0x3c98220
RAW_GET_BLOCK = 0x255a8e0
LABEL_TABLE = 0x56f1920
LABEL_COUNT = 28
KEY_ACCOUNT = 0x37d0e60
KEY_STORAGE = 0x37d0b40
KEY_CODE = 0x37d0d20
KEY_HEIGHT = 0x2811750
DEC_ACCOUNT = 0x2c641d0
DEC_STORAGE = 0x2ba6ab0
DEC_CODE = 0x2a6afe0
BYTES_WRITER = 0x35995d0
BIN_HEADER = 0x35990f0
MAP_HEADER = 0x35981d0
ARRAY_HEADER = 0x3598e20
STR_WRITER = 0x3599a40
U64_WRITER = 0x359b320
U256_WRITER = 0x3804a40
U256_TO_BE = 0x38036b0
B256_WRITER = 0x3583ba0
ACCOUNT_WRITER = 0x326cfc0
BYTECODE_WRITER = 0x3bf8bb0
HOST = 0x3269ae0
BATCH_PUT_SLOT = 0x57738e8
RAW_GET_SLOT = 0x5774600
EMPTY_HEAD = 0x206160
EMPTY_TAIL = 0x204be0
BYTECODE_NAME = 0x20a1b8
BYTECODE_VARIANTS = 0x5714a50
RMP_DECODE = b'rmp-serde-1.3.0/src/decode.rs'
RMP_ENCODE = b'rmp-serde-1.3.0/src/encode.rs'
READER_INIT = bytes.fromhex('c644242400c64424200166c74424220004')
NAMED_STORE = bytes.fromhex('c744242000040001')
ERROR_DROP = re.compile(rb'\x83\xf8\x02\x72.\x83\xf8\x05\x74.\x83\xf8\x06', re.S)

# (va, instruction prefix, expected rel32 target, meaning)
RIP_PINS = [
    (0x37d0f0f, 'e8', CONCAT, 'account key: concat of label and body'),
    (0x37d0c83, 'e8', CONCAT, 'storage key: concat of label and body'),
    (0x37d0dcd, 'e8', CONCAT, 'code key: concat of label and body'),
    (0x28117d6, 'e8', CONCAT_BLOCK, 'height key: copy of the prefix'),
    (0x281183c, 'e8', CONCAT_BLOCK, 'height key: concat of prefix and height'),
    (0x358cf80, '488d05', LABEL_TABLE, 'wrapper reads the label table'),
    (0x37d0fca, 'e8', KEY_ACCOUNT, 'account get builds the key'),
    (0x37d11e5, 'e8', KEY_STORAGE, 'storage get builds the key'),
    (0x37d13da, 'e8', KEY_CODE, 'code get builds the key'),
    (0x2810fd2, 'e8', KEY_HEIGHT, 'block get builds the key'),
    (0x37d182f, 'e8', KEY_ACCOUNT, 'account write builds the key'),
    (0x37d1d50, 'e8', KEY_STORAGE, 'storage write builds the key'),
    (0x37d2253, 'e8', KEY_CODE, 'code write builds the key'),
    (0x37d18da, 'e8', 0x358ca80, 'account write encodes the value'),
    (0x37d1e0f, 'e8', 0x358cc90, 'storage write encodes the value'),
    (0x37d2303, 'e8', 0x358c870, 'code write encodes the value'),
    (0x37d18f7, 'ff15', BATCH_PUT_SLOT, 'account write puts into the batch'),
    (0x37d1e2c, 'ff15', BATCH_PUT_SLOT, 'storage write puts into the batch'),
    (0x37d2320, 'ff15', BATCH_PUT_SLOT, 'code write puts into the batch'),
    (0x37d19eb, 'e8', 0x3c985f0, 'account write commits the batch'),
    (0x37d1f19, 'e8', 0x3c985f0, 'storage write commits the batch'),
    (0x37d2416, 'e8', 0x3c985f0, 'code write commits the batch'),
    (0x326d054, 'e8', MAP_HEADER, 'account value: map header'),
    (0x326d07e, 'e8', ARRAY_HEADER, 'account value: array header'),
    (0x326d023, '660f740d', EMPTY_TAIL, 'code hash tail compare'),
    (0x326d02b, '660f7405', EMPTY_HEAD, 'code hash head compare'),
    (0x326d0c1, '488d35', 0x583fe7, 'field name of offset 0'),
    (0x326d107, '488d35', 0x583fe8, 'field name of offset 0x40'),
    (0x326d1b2, '488d35', 0x583fd8, 'field name of offset 0x20'),
    (0x326d0d0, 'e8', STR_WRITER, 'field name 1 writer'),
    (0x326d116, 'e8', STR_WRITER, 'field name 2 writer'),
    (0x326d1c1, 'e8', STR_WRITER, 'field name 3 writer'),
    (0x326d0e8, 'e8', U256_WRITER, 'offset 0 uses the U256 writer'),
    (0x326d12e, 'e8', U64_WRITER, 'offset 0x40 uses the u64 writer'),
    (0x326d1d5, 'e8', B256_WRITER, 'offset 0x20 uses the 32-byte writer'),
    (0x3804a7a, 'e8', U256_TO_BE, 'U256 value is turned into 32 bytes'),
    (0x3804a8f, 'e8', BYTES_WRITER, 'U256 value is written as bytes'),
    (0x3583c5f, 'e8', BYTES_WRITER, '32-byte field is written as bytes'),
    (0x35995ee, 'e8', BIN_HEADER, 'bytes writer emits the header first'),
    (0x37d14e1, '488d15', BYTECODE_NAME, 'code value enum name'),
    (0x37d14e8, '4c8d05', BYTECODE_VARIANTS, 'code value variant table'),
    (0x3c98288, 'ff15', RAW_GET_SLOT, 'state raw get enters the C call'),
    (0x255a931, 'ff15', RAW_GET_SLOT, 'block raw get enters the C call'),
]
# (va, exact bytes, meaning)
BYTE_PINS = [
    (0x37d0e6d, '488b5e10', 'account key: prefix length from self+0x10'),
    (0x37d0e87, '4c8b6e08', 'account key: prefix pointer from self+0x8'),
    (0x37d0eb9, 'bf14000000', 'account key: 20-byte body allocation'),
    (0x37d0ecc, '418b442410', 'account key: reads address bytes 16..20'),
    (0x37d0ed1, '41894510', 'account key: stores them unchanged'),
    (0x37d0ed5, '410f100424', 'account key: reads address bytes 0..16'),
    (0x37d0eda, '410f114500', 'account key: stores them unchanged'),
    (0x37d0f07, 'ba02000000', 'account key: two parts'),
    (0x37d0b4d, '488b5e10', 'storage key: prefix length from self+0x10'),
    (0x37d0b67, '4c8b6608', 'storage key: prefix pointer from self+0x8'),
    (0x37d0b99, '410f104500', 'storage key: slot low half'),
    (0x37d0b9e, '0f29442440', 'storage key: slot low half on the stack'),
    (0x37d0ba3, '410f104510', 'storage key: slot high half'),
    (0x37d0ba8, '0f29442430', 'storage key: slot high half on the stack'),
    (0x37d0bad, 'bf34000000', 'storage key: 52-byte body allocation'),
    (0x37d0bc4, '418b4530', 'storage key: address bytes 16..20 from arg+0x30'),
    (0x37d0bc8, '4189442410', 'storage key: stored at body+0x10'),
    (0x37d0bcd, 'f3410f6f4520', 'storage key: address bytes 0..16 from arg+0x20'),
    (0x37d0bd3, 'f3410f7f0424', 'storage key: stored at body+0'),
    (0x37d0c7b, 'ba02000000', 'storage key: two parts'),
    (0x37d0d2d, '488b5e10', 'code key: prefix length from self+0x10'),
    (0x37d0d47, '4c8b6608', 'code key: prefix pointer from self+0x8'),
    (0x37d0d79, 'bf20000000', 'code key: 32-byte body allocation'),
    (0x37d0d8c, '410f104500', 'code key: reads hash bytes 0..16'),
    (0x37d0d91, '410f104d10', 'code key: reads hash bytes 16..32'),
    (0x37d0d96, '0f114810', 'code key: stores them unchanged'),
    (0x37d0d9a, '0f1100', 'code key: stores them unchanged'),
    (0x37d0dc5, 'ba02000000', 'code key: two parts'),
    (0x28117ee, 'bf08000000', 'height key: 8-byte body allocation'),
    (0x2811801, '490fce', 'height key: bswap r14'),
    (0x2811804, '4c8930', 'height key: stores the swapped value'),
    (0x2811834, 'ba02000000', 'height key: two parts'),
    (0x2810fc5, '488b7608', 'block get: prefix pointer from self+0x8'),
    (0x2810fc9, '498b5610', 'block get: prefix length from self+0x10'),
    (0x358cf87, '4e8b2ce0', 'wrapper: label row by code'),
    (0x358cf8b, 'bf02000000', 'wrapper: 2-byte label allocation'),
    (0x358cfa2, '410fb74500', 'wrapper: reads the two label bytes'),
    (0x358cfa7, '6641890424', 'wrapper: stores the two label bytes'),
    (0x358d048, '48c744241002000000', 'wrapper: capacity 2 at local+0x10'),
    (0x358d051, '4c89642418', 'wrapper: label pointer at local+0x18'),
    (0x358d056, '48c744242002000000', 'wrapper: length 2 at local+0x20'),
    (0x358d064, '4488742430', 'wrapper: code byte at local+0x30'),
    (0x358d15f, '0f10442410', 'wrapper: local+0x10 reloaded'),
    (0x358d169, '0f114320', 'wrapper: stored at out+0x20'),
    (0x358d171, '488b442430', 'wrapper: local+0x30 reloaded'),
    (0x358d176, '48894340', 'wrapper: stored at out+0x40'),
    (0x37d18ce, '418b7640', 'account write: code byte from wrapper+0x40'),
    (0x37d1e03, '418b7640', 'storage write: code byte from wrapper+0x40'),
    (0x37d22f7, '418b7640', 'code write: code byte from wrapper+0x40'),
    (0x37d166e, '498d5e20', 'account write: self = wrapper+0x20'),
    (0x37d1824, '4889de', 'account write: self passed to the key builder'),
    (0x3269cb3, '4c89fe', 'account wrapper+0x20 passed on'),
    (0x3269ece, '4c89fe', 'code wrapper+0x20 passed on'),
    (0x326a0da, '4c89fe', 'storage wrapper+0x20 passed on'),
    (0x37d15f1, '488b4738', 'account write: home from wrapper+0x38'),
    (0x37d1013, '498b7618', 'account get: home from self+0x18'),
    (0x37d1017, '31c0', 'account get: zero'),
    (0x37d1019, '483b4610', 'account get: compares zero with home+0x10'),
    (0x37d101d, '7122', 'account get: i64::MIN length means no database'),
    (0x37d101f, '48c70300000000', 'account get: returns None tag'),
    (0x326d00e, '4c8b6640', 'account value: offset 0x40 loaded'),
    (0x326d047, '41807e0b00', 'account value: header picked by serializer+0xb'),
    (0x326d0ba, '41807e0b01', 'account value: name 1 only when serializer+0xb is 1'),
    (0x326d100, '41807e0b01', 'account value: name 2 only when serializer+0xb is 1'),
    (0x326d1ab, '41807e0b01', 'account value: name 3 only when serializer+0xb is 1'),
    (0x326d0c8, 'ba01000000', 'field name 1 has length 1'),
    (0x326d10e, 'ba01000000', 'field name 2 has length 1'),
    (0x326d1b9, 'ba01000000', 'field name 3 has length 1'),
    (0x326d045, '01ca', 'account value: field count in edx'),
    (0x326d169, '4983c720', 'account value: third field at offset 0x20'),
    (0x326d16d, '66480f6ec1', 'code hash head low half is rcx'),
    (0x326d172, '66480f6ec8', 'code hash head high half is rax'),
    (0x326d18a, '66480f6ed6', 'code hash tail low half is rsi'),
    (0x326d18f, '66480f6eda', 'code hash tail high half is rdx'),
    (0x3804a54, '807a0a00', 'U256 value: human-readable test at serializer+0xa'),
    (0x3583bbb, '807a0a00', '32-byte field: human-readable test at serializer+0xa'),
    (0x3583c57, 'ba20000000', '32-byte field: length 32'),
    (0x35981ef, 'bd80000000', 'map header: fixmap base'),
    (0x35981e7, '34df', 'map header: map32 or map16 marker'),
    (0x3598e3f, 'bd90000000', 'array header: fixarray base'),
    (0x3598e37, '34dd', 'array header: array32 or array16 marker'),
    (0x3599115, 'bdc4000000', 'bytes header: bin8 marker'),
    (0x3599a5b, '40b5a0', 'string header: fixstr base'),
    (0x3c9826d, '488b7d30', 'state raw get: first argument from handle+0x30'),
    (0x3c98282, '4c89f2', 'state raw get: key pointer in rdx'),
    (0x3c98285, '4889d9', 'state raw get: key length in rcx'),
    (0x3c9827a, '4c8d442420', 'state raw get: error slot in r8, the last argument'),
    (0x255a90e, '498b7d30', 'block raw get: first argument from handle+0x30'),
    (0x255a928, '4889ea', 'block raw get: key pointer in rdx'),
    (0x255a92b, '4889d9', 'block raw get: key length in rcx'),
    (0x255a91b, '4c8d442418', 'block raw get: error slot in r8, the last argument'),
    (0x37d14f7, 'b908000000', 'code value enum name length'),
    (0x37d14fc, '41b904000000', 'code value variant count'),
]
# (code, wrapper-out lea, bytes, code imm va, wrapper call va, wrapper,
#  self lea, bytes, iterator call va, iterator, decoder call va, decoder)
BINDINGS = [
    (0x18, 0x3269c4c, '488dbc2480250000', 0x3269c54, 0x3269c5c, 0x358cea0,
     0x3269c86, '4c8dbc24a0250000', 0x3269cbe, 0x37d3070, 0x37d334c, DEC_ACCOUNT),
    (0x19, 0x3269e67, '488dbc2498370000', 0x3269e6f, 0x3269e77, 0x358d720,
     0x3269ea1, '4c8dbc24b8370000', 0x3269ed9, 0x37d3bd0, 0x37d3ec5, DEC_CODE),
    (0x1a, 0x326a079, '488d7c2458', 0x326a07e, 0x326a086, 0x358d2e0,
     0x326a0b0, '4c8d7c2478', 0x326a0e5, 0x37d2550, 0x37d281a, DEC_STORAGE),
]
# (name, start, raw get, raw call va, reader init va, decoder call va, decoder)
GETTERS = [
    ('account', 0x37d0fb0, RAW_GET, 0x37d1063, 0x37d10c6, 0x37d10e1, DEC_ACCOUNT),
    ('storage', 0x37d11d0, RAW_GET, 0x37d1278, 0x37d12da, 0x37d12f8, DEC_STORAGE),
    ('code', 0x37d13c0, RAW_GET, 0x37d146d, 0x37d14d0, 0x37d1502, DEC_CODE),
    ('block_by_height', 0x2810fb0, RAW_GET_BLOCK, 0x2811021, 0x2811084, 0x281109f, 0x17edf80),
    ('value_by_hash_a', 0x2811160, RAW_GET_BLOCK, 0x28112d9, 0x281133b, 0x2811356, 0x17457c0),
    ('value_by_hash_b', 0x2811460, RAW_GET_BLOCK, 0x28115d4, 0x281163e, 0x2811657, 0x16844a0),
]
# (start, named-mode callee, table)
ENCODERS = [(0x358ca80, ACCOUNT_WRITER, 'account'), (0x358cc90, U256_WRITER, 'storage'),
            (0x358c870, BYTECODE_WRITER, 'code')]
HEIGHT_BODY = 8
ROLES = {
    0x37d0e60: 'key builder account', 0x37d0b40: 'key builder storage',
    0x37d0d20: 'key builder code', 0x2811750: 'key builder height',
    0x37d0fb0: 'flatten account key', 0x37d11d0: 'flatten storage key',
    0x37d13c0: 'flatten code key', 0x37d15e0: 'flatten account key',
    0x37d1b20: 'flatten storage key', 0x37d2000: 'flatten code key',
    0x37d47c0: 'flatten storage key', 0x37d4d20: 'flatten account key',
    0x33be120: 'flatten account key', 0x33bdb20: 'flatten storage key',
    0x33bce70: 'flatten code key', 0x326b090: 'flatten storage key',
    0x2810890: 'flatten height key or prefix copy', 0x2811160: 'hash key',
    0x2811460: 'hash key',
    0x3284ad0: 'unresolved 32 bytes plus tail', 0x3284c70: 'unresolved 52 bytes plus U256',
    0x3284d90: 'unresolved 20 bytes plus 72 bytes', 0x3330900: 'unresolved u32 u64 u64 big endian',
    0x3362fd0: 'unresolved 1 byte plus rmp body',
}


class View:
    """Read-only VA view over file-backed sections, with .rela.dyn addends."""

    def __init__(self, data):
        self.data = data
        self.sections = elf_index.sections(data)
        self.loaded = [s for s in self.sections
                       if s['type'] != SHT_NOBITS and s['address'] and s['size']]
        self.addends = {}
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        for slot, info, addend in struct.iter_unpack(
                '<QQq', data[rela['offset']:rela['offset'] + rela['size']]):
            if info & 0xffffffff == R_X86_64_RELATIVE:
                self.addends[slot] = addend

    def mem(self, va, size):
        for sec in self.loaded:
            if sec['address'] <= va and va + size <= sec['address'] + sec['size']:
                start = sec['offset'] + va - sec['address']
                return self.data[start:start + size]
        raise ValueError(f'{va:#x}+{size} is outside file-backed sections')

    def text(self):
        sec = next(s for s in self.sections if s['name'] == '.text')
        return sec['address'], self.data[sec['offset']:sec['offset'] + sec['size']]

    def relative(self, slot):
        if slot not in self.addends:
            raise ValueError(f'no RELATIVE relocation at {slot:#x}')
        return self.addends[slot]

    def u64(self, va):
        return struct.unpack('<Q', self.mem(va, 8))[0]


def rip_target(view, va, prefix):
    """Resolve prefix + rel32 at va, failing closed on different bytes."""
    if view.mem(va, len(prefix)) != prefix:
        raise ValueError(f'instruction bytes differ at {va:#x}')
    end = va + len(prefix) + 4
    return end + struct.unpack('<i', view.mem(va + len(prefix), 4))[0]


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


def expect(view, va, raw):
    if view.mem(va, len(bytes.fromhex(raw))).hex() != raw:
        raise ValueError(f'bytes differ at {va:#x}')


def expect_call(view, va, target):
    if rip_target(view, va, b'\xe8') != target:
        raise ValueError(f'call at {va:#x} does not reach {target:#x}')


def shuffle(raw, imm, width, first, last):
    """Apply one x86 shuffle selector to lanes first..last of a 16-byte value."""
    lanes = [raw[i:i + width] for i in range(0, 16, width)]
    picked = [lanes[first + ((imm >> (2 * i)) & 3)] for i in range(last - first)]
    return b''.join(lanes[:first] + picked + lanes[last:])


def unpack(dst, src, offset):
    return b''.join(bytes((dst[offset + i], src[offset + i])) for i in range(8))


def pack_words(dst, src):
    out = bytearray()
    for raw in (dst, src):
        for i in range(0, 16, 2):
            word = struct.unpack_from('<H', raw, i)[0]
            out.append(min(word, 255))
    return bytes(out)


def run_sse(view, start, end, regs, stack):
    """Evaluate a fixed SSE byte sequence; any other encoding fails closed."""
    regs, stores, pc = dict(regs), {}, start
    while pc < end:
        raw = view.mem(pc, 7)
        two = raw[:2]
        if raw[0] == 0x66 and raw[1] == 0x0f and raw[2] in (0x60, 0x67, 0x68, 0x6f, 0xef) and raw[3] >= 0xc0:
            dst, src = (raw[3] >> 3) & 7, raw[3] & 7
            if raw[2] == 0x6f:
                regs[dst] = regs[src]
            elif raw[2] == 0xef:
                regs[dst] = bytes(16) if dst == src else bytes(a ^ b for a, b in zip(regs[dst], regs[src]))
            elif raw[2] == 0x60:
                regs[dst] = unpack(regs[dst], regs[src], 0)
            elif raw[2] == 0x68:
                regs[dst] = unpack(regs[dst], regs[src], 8)
            else:
                regs[dst] = pack_words(regs[dst], regs[src])
            pc += 4
        elif raw[:3] == b'\x66\x0f\x6f' and (raw[3] & 0xc7) == 0x44 and raw[4] == 0x24:
            regs[(raw[3] >> 3) & 7] = stack[raw[5]]
            pc += 6
        elif two in (b'\x66\x0f', b'\xf2\x0f', b'\xf3\x0f') and raw[2] == 0x70 and raw[3] >= 0xc0:
            dst, src, imm = (raw[3] >> 3) & 7, raw[3] & 7, raw[4]
            if raw[0] == 0x66:
                regs[dst] = shuffle(regs[src], imm, 4, 0, 4)
            elif raw[0] == 0xf2:
                regs[dst] = shuffle(regs[src], imm, 2, 0, 4)
            else:
                regs[dst] = shuffle(regs[src], imm, 2, 4, 8)
            pc += 5
        elif raw[:4] == b'\xf3\x41\x0f\x7f' and (raw[4] & 0xc7) == 0x44 and raw[5] == 0x24:
            stores[raw[6]] = regs[(raw[4] >> 3) & 7]
            pc += 7
        elif raw[:3] == b'\xf3\x0f\x7f' and (raw[3] & 0xc7) == 0x00:
            stores[0] = regs[(raw[3] >> 3) & 7]
            pc += 4
        elif raw[:3] == b'\xf3\x0f\x7f' and (raw[3] & 0xc7) == 0x40:
            stores[raw[4]] = regs[(raw[3] >> 3) & 7]
            pc += 5
        else:
            raise ValueError(f'unsupported SSE bytes at {pc:#x}')
    if pc != end:
        raise ValueError('SSE sequence overran its end')
    return stores


def storage_slot_bytes(view, slot):
    """Run the key builder's reversal on a 32-byte little-endian slot."""
    stack = {0x40: slot[:16], 0x30: slot[16:]}
    stores = run_sse(view, 0x37d0bdd, 0x37d0c53, {0: bytes(16)}, stack)
    if sorted(stores) != [0x14, 0x24]:
        raise ValueError('storage key stores differ')
    return stores[0x14] + stores[0x24]


def u256_value_bytes(view, value):
    """Run the value path's reversal on a 32-byte little-endian U256."""
    stores = run_sse(view, 0x38036e2, 0x380374b, {0: value[:16], 1: value[16:]}, {})
    if sorted(stores) != [0, 0x10]:
        raise ValueError('U256 value stores differ')
    return stores[0] + stores[0x10]


def labels(view):
    return [view.mem(view.relative(LABEL_TABLE + 8 * i), 2).decode('ascii') for i in range(LABEL_COUNT)]


def named_mode(code):
    """Model `add sil, 0xe9; cmp sil, 4; jae`, the encoders' code gate."""
    return (code + 0xe9) & 0xff < 4


def check_encoder(view, start, callee):
    expect(view, start + 0x1a, '4080c6e9')
    expect(view, start + 0x1e, '4080fe04')
    expect(view, start + 0x22, '7346')
    expect(view, start + 0x46, NAMED_STORE.hex())
    expect(view, start + 0x8c, 'c744242000040000')
    expect_call(view, start + 0x63, callee)
    expect_call(view, start + 0xa9, callee)


def field_name(view, va):
    return view.mem(va, 1).decode('ascii')


def empty_code_hash(view):
    """Rebuild the code hash constant from both compare forms; they must agree."""
    table = view.mem(EMPTY_HEAD, 16) + view.mem(EMPTY_TAIL, 16)
    words = {}
    for reg, va, opcode in (('rax', 0x326d141, '48b8'), ('rcx', 0x326d14b, '48b9'),
                            ('rdx', 0x326d155, '48ba'), ('rsi', 0x326d15f, '48be')):
        expect(view, va, opcode)
        words[reg] = view.mem(va + 2, 8)
    moved = words['rcx'] + words['rax'] + words['rsi'] + words['rdx']
    if moved != table:
        raise ValueError('code hash constants differ')
    return table.hex()


def bin_field(raw):
    return bytes((0xc4, len(raw))) + raw


def uint_value(value):
    """rmp unsigned integer, smallest form."""
    if value < 0x80:
        return bytes((value,))
    if value < 0x100:
        return bytes((0xcc, value))
    if value < 0x10000:
        return b'\xcd' + struct.pack('>H', value)
    if value < 0x100000000:
        return b'\xce' + struct.pack('>I', value)
    return b'\xcf' + struct.pack('>Q', value)


def encode_account(view, balance, nonce, code_hash, empty_hash, names, named=True):
    """Model the writer: omit defaults, then write fields in binary order."""
    fields = []
    if any(balance):
        fields.append((names['balance'], bin_field(u256_value_bytes(view, balance))))
    if nonce:
        fields.append((names['nonce'], uint_value(nonce)))
    if code_hash.hex() != empty_hash:
        fields.append((names['code_hash'], bin_field(code_hash)))
    if len(fields) > 15:
        raise ValueError('model covers fixed headers only')
    out = bytearray(((0x80 if named else 0x90) | len(fields),))
    for name, value in fields:
        if named:
            out += bytes((0xa0 | len(name),)) + name.encode('ascii')
        out += value
    return bytes(out)


def account_key(label, address):
    if len(address) != 20:
        raise ValueError('account key body is 20 bytes')
    return label.encode('ascii') + address


def storage_key(view, label, address, slot):
    if len(address) != 20 or len(slot) != 32:
        raise ValueError('storage key parts have fixed lengths')
    return label.encode('ascii') + address + storage_slot_bytes(view, slot)


def code_key(label, code_hash):
    if len(code_hash) != 32:
        raise ValueError('code key body is 32 bytes')
    return label.encode('ascii') + code_hash


def height_key(prefix, height):
    if not 0 <= height < 1 << 64:
        raise ValueError('height is a u64')
    return prefix + struct.pack('>Q', height)


def relative_calls(view, target):
    base, text = view.text()
    found = []
    for match in re.finditer(rb'\xe8', text):
        index = match.start()
        if index + 5 > len(text):
            break
        if base + index + 5 + struct.unpack_from('<i', text, index + 1)[0] == target:
            found.append(base + index)
    return found


def fde_for(starts, ordered, va):
    index = bisect.bisect_right(starts, va) - 1
    row = ordered[index]
    if not row['start'] <= va < row['end']:
        raise ValueError(f'{va:#x} is outside every FDE')
    return row


def parts_before(view, site):
    """Find the edx immediate of a concat call in the 24 bytes before it."""
    window = view.mem(site - 24, 24)
    found = [m.group(1)[0] for m in re.finditer(rb'\xba([\x01-\x08])\x00\x00\x00', window)]
    return found[-1] if found else None


def concat_rows(view, starts, ordered):
    rows = []
    for target in (CONCAT, CONCAT_BLOCK):
        for site in relative_calls(view, target):
            row = fde_for(starts, ordered, site)
            if row['start'] not in ROLES:
                raise ValueError(f"unclassified concat owner {row['start']:#x}")
            rows.append({'site': site, 'concat': target, 'fde_start': row['start'], 'fde_end': row['end'],
                         'parts': parts_before(view, site), 'role': ROLES[row['start']]})
    return rows


def pattern_sites(view, pattern):
    base, text = view.text()
    return [base + m.start() for m in re.finditer(re.escape(pattern), text)]


def getter_row(view, starts, ordered, row):
    name, start, raw_get, raw_site, init_site, dec_site, decoder = row
    extent = fde_for(starts, ordered, start)
    if extent['start'] != start:
        raise ValueError(f'{start:#x} is not an FDE start')
    expect_call(view, raw_site, raw_get)
    expect_call(view, dec_site, decoder)
    expect(view, init_site, READER_INIT.hex())
    body = view.mem(start, extent['end'] - start)
    if len(ERROR_DROP.findall(body)) != 1:
        raise ValueError(f'{start:#x} error drop differs')
    if body.count(READER_INIT) != 1:
        raise ValueError(f'{start:#x} reader init differs')
    return {'name': name, 'start': hex(start), 'end': hex(extent['end']), 'raw_get': hex(raw_get),
            'reader_init': hex(init_site), 'decoder': hex(decoder), 'error_tags_dropped': [2, 5, 6]}


def binding_row(view, names, row):
    code, out_va, out_raw, imm_va, call_va, wrapper, self_va, self_raw, iter_va, iterator, dec_va, decoder = row
    expect(view, out_va, out_raw)
    expect(view, self_va, self_raw)
    expect(view, imm_va, 'be' + struct.pack('<I', code).hex())
    expect_call(view, call_va, wrapper)
    expect_call(view, iter_va, iterator)
    expect_call(view, dec_va, decoder)
    return {'code': code, 'label': names[code], 'wrapper_fn': hex(wrapper), 'iterator': hex(iterator),
            'decoder': hex(decoder)}


def strings_once(view, needle):
    sec = next(s for s in view.sections if s['name'] == '.rodata')
    found = view.data[sec['offset']:sec['offset'] + sec['size']].count(needle)
    if found != 1:
        raise ValueError(f'{needle!r} count is {found}')
    return found


def bytecode_variants(view):
    names = []
    for i in range(view.mem(0x37d14fc + 2, 1)[0]):
        slot = BYTECODE_VARIANTS + 16 * i
        names.append(view.mem(view.relative(slot), view.u64(slot + 8)).decode('ascii'))
    return names


def build(data):
    view = View(data)
    _, ordered, _ = fde_extents.fde_extents(data)
    starts = [row['start'] for row in ordered]
    rip_pins = [check_rip_pin(view, pin) for pin in RIP_PINS]
    byte_pins = [check_byte_pin(view, pin) for pin in BYTE_PINS]
    names = labels(view)
    for start, callee, _ in ENCODERS:
        check_encoder(view, start, callee)
    fields = {'balance': field_name(view, 0x583fe7), 'nonce': field_name(view, 0x583fe8),
              'code_hash': field_name(view, 0x583fd8)}
    empty = empty_code_hash(view)
    getters = [getter_row(view, starts, ordered, row) for row in GETTERS]
    bindings = [binding_row(view, names, row) for row in BINDINGS]
    sample_slot = bytes(range(32))
    sample_value = bytes(range(0x40, 0x60))
    if storage_slot_bytes(view, sample_slot) != sample_slot[::-1]:
        raise ValueError('storage slot reversal differs')
    if u256_value_bytes(view, sample_value) != sample_value[::-1]:
        raise ValueError('U256 value reversal differs')
    rows = concat_rows(view, starts, ordered)
    address = bytes(range(0xa0, 0xb4))
    code_hash = bytes(range(0x20, 0x40))
    examples = {
        'account_key': account_key(names[24], address).hex(),
        'storage_key': storage_key(view, names[26], address, sample_slot).hex(),
        'code_key': code_key(names[25], code_hash).hex(),
        'account_value_all_default': encode_account(view, bytes(32), 0, bytes.fromhex(empty), empty, fields).hex(),
        'account_value_nonce_5': encode_account(view, bytes(32), 5, bytes.fromhex(empty), empty, fields).hex(),
    }
    return {
        'schema': 'evm-kv-schema/v1',
        'binary_sha256': hashlib.sha256(data).hexdigest(),
        'coordinate_system': 'ELF virtual addresses; FDE end exclusive',
        'labels': {str(code): names[code] for code in range(LABEL_COUNT)},
        'named_mode_codes': [code for code in range(LABEL_COUNT) if named_mode(code)],
        'key_layouts': [
            {'table': 'account', 'code': 24, 'label': names[24], 'builder': hex(KEY_ACCOUNT),
             'body_bytes': 20, 'total_bytes': 22, 'body': 'address, copied'},
            {'table': 'storage', 'code': 26, 'label': names[26], 'builder': hex(KEY_STORAGE),
             'body_bytes': 52, 'total_bytes': 54, 'body': 'address, then slot reversed to big endian'},
            {'table': 'code', 'code': 25, 'label': names[25], 'builder': hex(KEY_CODE),
             'body_bytes': 32, 'total_bytes': 34, 'body': '32-byte hash, copied'},
            {'table': 'block_by_height', 'code': None, 'label': None, 'builder': hex(KEY_HEIGHT),
             'body_bytes': HEIGHT_BODY, 'total_bytes': None, 'body': 'u64 after bswap'},
        ],
        'wrapper_layout': {'prefix_capacity': '0x20', 'prefix_pointer': '0x28', 'prefix_length': '0x30',
                           'home': '0x38', 'code': '0x40', 'key_self': '0x20'},
        'account_value': {'fields_in_write_order': [
            {'name': fields['balance'], 'offset': '0x0', 'omitted_when': 'all 32 bytes zero', 'writer': hex(U256_WRITER)},
            {'name': fields['nonce'], 'offset': '0x40', 'omitted_when': 'zero', 'writer': hex(U64_WRITER)},
            {'name': fields['code_hash'], 'offset': '0x20', 'omitted_when': 'equals empty_code_hash', 'writer': hex(B256_WRITER)},
        ], 'empty_code_hash': empty},
        'bytecode_enum': {'name': view.mem(BYTECODE_NAME, 8).decode('ascii'), 'variants': bytecode_variants(view)},
        'rmp_locations': {'decode': strings_once(view, RMP_DECODE), 'encode': strings_once(view, RMP_ENCODE)},
        'reader_init_sites': [hex(va) for va in pattern_sites(view, READER_INIT)],
        'named_store_sites': [hex(va) for va in pattern_sites(view, NAMED_STORE)],
        'encoders': [{'table': table, 'start': hex(start), 'callee': hex(callee)} for start, callee, table in ENCODERS],
        'getters': getters,
        'raw_get_slot': {'slot': hex(RAW_GET_SLOT), 'target': hex(view.relative(RAW_GET_SLOT)),
                         'register_arguments': 5},
        'bindings': bindings,
        'concat_counts': {hex(target): sum(row['concat'] == target for row in rows) for target in (CONCAT, CONCAT_BLOCK)},
        'examples': examples,
        'rip_pins': rip_pins,
        'byte_pins': byte_pins,
    }, rows


def tsv_text(rows):
    lines = ['site\tconcat\tfde_start\tfde_end\tparts\trole']
    for row in rows:
        lines.append(f"{row['site']:#x}\t{row['concat']:#x}\t{row['fde_start']:#x}\t{row['fde_end']:#x}\t"
                     f"{row['parts'] if row['parts'] is not None else '-'}\t{row['role']}")
    return '\n'.join(lines) + '\n'


def write_outputs(report, rows, out):
    out.mkdir(parents=True, exist_ok=True)
    (out / JSON_NAME).write_text(json.dumps(report, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    (out / TSV_NAME).write_text(tsv_text(rows), encoding='utf-8')


def load_binary(path=BINARY, expected=SHA256):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('binary sha256 mismatch')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report, rows = build(load_binary())
    write_outputs(report, rows, args.out)
    print(json.dumps({'keys': report['key_layouts'][0]['total_bytes'], 'sites': len(rows)}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
