#!/usr/bin/env python3
"""Export byte-backed node 94 precompile-registry ownership and cleanup evidence.

Only selected instruction byte shapes are recognized. The target is never run.
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

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK64 = (1 << 64) - 1

# These are questions/coordinates, not boundaries inferred from index spacing.
# Ends are checked against independently decoded FDE records.
FUNCTIONS = {
    0x4e94d80: (0x4e94e7a, 'partially initialized map entries cleanup'),
    0x4e952d0: (0x4e9530b, 'address-set storage cleanup'),
    0x4e95310: (0x4e954b9, 'map entries and storage cleanup'),
    0x4e98b60: (0x4e98bcd, 'map-set aggregate cleanup'),
    0x4e98bd0: (0x4e98c2e, 'record-vector cleanup wrapper'),
    0x4e9bb90: (0x4e9bc3b, 'single tagged-value cleanup on insertion failure'),
    0x4e9cd50: (0x4e9cdfb, 'single record cleanup for iterator unwind'),
    0x4e9d0d0: (0x4e9d240, 'remaining iterator records and storage cleanup'),
    0x4e9d6c0: (0x4e9d76b, 'single record cleanup for vector unwind'),
    0x4e9d810: (0x4e9d914, 'initialized record-vector elements cleanup'),
    0x4e9e410: (0x4e9e461, 'secondary counter release during unwind'),
    0x4e9e470: (0x4e9e508, 'last-primary-reference payload and counter cleanup'),
    0x4e9e550: (0x4e9e654, 'partially initialized source-record range cleanup'),
    0x4e9fb80: (0x4e9fc2b, 'single record cleanup for source-range unwind'),
}

# Reviewed windows are a bounded interpretation layer. Whole FDE bytes, all
# walked instruction shapes and all syntactic transfers are emitted separately.
WINDOWS = [
    (0x4e98b64, 0x4e98b75, 'aggregate calls map cleanup before set cleanup'),
    (0x4e98b75, 0x4e98bcd, 'set release and aggregate unwind landing'),
    (0x4e9531e, 0x4e95342, 'empty storage and item-count tests'),
    (0x4e95342, 0x4e953c3, 'occupied control scan and value-tag split'),
    (0x4e953c3, 0x4e953d9, 'atomic primary count decrement and final-release call'),
    (0x4e953e0, 0x4e9542d, 'virtual payload drop and conditional deallocation'),
    (0x4e9542d, 0x4e95475, 'map allocation base and length reconstruction'),
    (0x4e95484, 0x4e954b9, 'virtual payload exceptional cleanup and unwind'),
    (0x4e952d0, 0x4e9530b, 'set allocation base and length reconstruction'),
    (0x4e94d8b, 0x4e94dc3, 'partial clone scan by control byte and count'),
    (0x4e9bb95, 0x4e9bbc2, 'single value tag and primary-count branches'),
    (0x4e9bbc2, 0x4e9bc06, 'single value virtual drop and optional free'),
    (0x4e9bc06, 0x4e9bc3b, 'single value exceptional free and unwind'),
    (0x4e9d0db, 0x4e9d129, 'iterator span converted to record count'),
    (0x4e9d1cd, 0x4e9d23a, 'iterator unwind drops remaining records and storage'),
    (0x4e98bd4, 0x4e98c2e, 'vector elements and buffer cleanup including unwind'),
    (0x4e9d81b, 0x4e9d849, 'initialized vector count and record stride'),
    (0x4e9d8bd, 0x4e9d914, 'vector unwind drops remaining records'),
    (0x4e9e470, 0x4e9e49a, 'last primary reference calls optional payload destructor'),
    (0x4e9e49a, 0x4e9e4f2, 'secondary counter and allocation release'),
    (0x4e9e4f2, 0x4e9e508, 'payload destructor unwind releases secondary reference'),
    (0x4e9e410, 0x4e9e461, 'secondary reference unwind helper'),
    (0x4e9e55b, 0x4e9e599, 'source range count and record stride'),
    (0x4e9e5fe, 0x4e9e654, 'source-range unwind drops remaining records'),
]

# Exact byte predicates lock the operand/branch facts used in the prose.
# Fixed byte patterns, never disassembler text, establish instruction identities.
PINS = [
    (0x4e9531e, '488b4708', 'map reads mask'),
    (0x4e95335, '4c8b6718', 'map reads occupied count'),
    (0x4e95350, '660fd7c0', 'control high-bit mask'),
    (0x4e95354, 'f7d0', 'invert control high-bit mask'),
    (0x4e95367, '49ffcc', 'decrement remaining occupied count'),
    (0x4e95370, '6685c0', 'test current sixteen-control mask'),
    (0x4e95389, '4981c500fdffff', 'advance a control group by sixteen records'),
    (0x4e953a0, 'f3410fbcc6', 'select the next occupied control bit'),
    (0x4e953b0, '498b443de8', 'tag in bucket value'),
    (0x4e953b5, '4883f802', 'compare full tag with two'),
    (0x4e953be, '83f802', 'compare low tag word with two'),
    (0x4e953c7, 'f048ff08', 'atomic primary reference decrement'),
    (0x4e953e8, '488b03', 'load virtual destructor pointer'),
    (0x4e953f5, '488b7308', 'load dynamic payload size'),
    (0x4e95402, '488b4310', 'load dynamic payload alignment'),
    (0x4e95435, '48c1e004', 'map bucket stride shift'),
    (0x4e95439, '488d0440', 'map bucket stride multiply by three'),
    (0x4e95440, '4883c641', 'map allocation size bias'),
    (0x4e95451, '4883c7d0', 'map base adjustment'),
    (0x4e952d9, '488d04b6', 'set stride multiply by five'),
    (0x4e952dd, '488d048523000000', 'set aligned storage size expression'),
    (0x4e952e5, '4883e0f0', 'set storage alignment mask'),
    (0x4e952ec, '4883c611', 'set allocation size bias'),
    (0x4e98b67, 'e8a4c7ffff', 'aggregate invokes map cleanup'),
    (0x4e98bb9, '4883c328', 'unwind advances to set header'),
    (0x4e98bc0, 'e80bc7ffff', 'unwind invokes set cleanup'),
    (0x4e9bb95, '488b07', 'single-value tag load'),
    (0x4e9bb98, '4883f802', 'single-value full tag comparison'),
    (0x4e9bba4, '83f802', 'single-value low-word tag comparison'),
    (0x4e9bbad, 'f048ff08', 'single-value atomic decrement'),
    (0x4e9bbca, '498b07', 'single-value virtual callback load'),
    (0x4e9bbd7, '498b7708', 'single-value allocation size'),
    (0x4e9bbe0, '498b4710', 'single-value allocation alignment'),
    (0x4e9d0ec, '48baabaaaaaaaaaaaaaa', 'iterator division reciprocal'),
    (0x4e9d105, '49c1ef05', 'iterator division shift'),
    (0x4e9d109, '4983c630', 'iterator record stride'),
    (0x4e9d20c, 'e83ffbffff', 'iterator unwind cleanup call'),
    (0x4e9d81b, '4c8b6710', 'initialized vector length'),
    (0x4e9d82c, '4883c330', 'initialized vector record stride'),
    (0x4e9d8fc, 'e8bffdffff', 'vector unwind cleanup call'),
    (0x4e9e47c, '498b06', 'primary release virtual callback load'),
    (0x4e9e47f, '4d8b7e10', 'primary release alignment load'),
    (0x4e9e488, '498d4fff', 'dynamic payload alignment adjustment'),
    (0x4e9e48c, '4883e1f0', 'dynamic payload alignment mask'),
    (0x4e9e494, '4883c710', 'two-counter payload header'),
    (0x4e9e4a0, 'f048ff4b08', 'atomic secondary reference decrement'),
    (0x4e9e4ab, '4983ff09', 'minimum shared allocation alignment threshold'),
    (0x4e9e4af, 'b808000000', 'minimum shared allocation alignment'),
    (0x4e9e4bb, '4883c10f', 'shared allocation alignment bias'),
    (0x4e9e4fb, 'e810ffffff', 'unwind secondary-release helper call'),
    (0x4e9e416, 'f048ff4f08', 'unwind atomic secondary decrement'),
    (0x4e9e572, '488d0476', 'source-range address scale'),
    (0x4e9e576, '48c1e004', 'source-range record stride shift'),
    (0x4e9e63c, 'e83f150000', 'source-range unwind cleanup call'),
]

# Operand positions are within the exact checked instruction bytes above.
OPERANDS = [
    (0x4e9531e, 3, 1, False, 'map mask field offset'),
    (0x4e95335, 3, 1, False, 'map occupied count field offset'),
    (0x4e95389, 3, 4, True, 'map next-group bucket-base displacement'),
    (0x4e953b0, 4, 1, True, 'map value tag displacement'),
    (0x4e953b5, 3, 1, False, 'full-width tag threshold'),
    (0x4e953be, 2, 1, False, 'low-word tag equality'),
    (0x4e953f5, 3, 1, False, 'descriptor size offset'),
    (0x4e95402, 3, 1, False, 'descriptor alignment offset'),
    (0x4e95435, 3, 1, False, 'map storage stride shift'),
    (0x4e95440, 3, 1, False, 'map allocation size bias'),
    (0x4e95451, 3, 1, True, 'map allocation base adjustment'),
    (0x4e952dd, 4, 4, False, 'set alignment expression bias'),
    (0x4e952e5, 3, 1, True, 'set alignment mask'),
    (0x4e952ec, 3, 1, False, 'set allocation size bias'),
    (0x4e98bb9, 3, 1, False, 'aggregate set header offset'),
    (0x4e9bb98, 3, 1, False, 'single-value full tag threshold'),
    (0x4e9bba4, 2, 1, False, 'single-value low-word tag equality'),
    (0x4e9bbe0, 3, 1, False, 'single-value descriptor alignment offset'),
    (0x4e9d0ec, 2, 8, False, 'iterator reciprocal multiplier'),
    (0x4e9d105, 3, 1, False, 'iterator count shift'),
    (0x4e9d109, 3, 1, False, 'iterator record stride'),
    (0x4e9d81b, 3, 1, False, 'vector initialized count offset'),
    (0x4e9d82c, 3, 1, False, 'vector record stride'),
    (0x4e9e47f, 3, 1, False, 'shared descriptor alignment offset'),
    (0x4e9e488, 3, 1, True, 'shared payload alignment preadjustment'),
    (0x4e9e48c, 3, 1, True, 'shared payload alignment mask'),
    (0x4e9e494, 3, 1, False, 'shared payload header size'),
    (0x4e9e4a0, 4, 1, False, 'secondary counter offset'),
    (0x4e9e4ab, 3, 1, False, 'shared minimum alignment threshold'),
    (0x4e9e4af, 1, 4, False, 'shared minimum allocation alignment'),
    (0x4e9e4bb, 3, 1, False, 'shared allocation alignment bias'),
    (0x4e9e416, 4, 1, False, 'unwind secondary counter offset'),
    (0x4e9e576, 3, 1, False, 'source record stride shift'),
]

# Each row names a reviewed conditional instruction. The target and fallthrough
# are calculated from its bytes; labels are interpretations under valid layouts.
DECISIONS = [
    (0x4e94d8e, 4, 'zero partial-scan count returns', 'scan control bytes'),
    (0x4e94dc1, 8, 'negative control is skipped', 'inspect value tag'),
    (0x4e94dcc, 2, 'tag below two is skipped', 'inspect low tag word'),
    (0x4e94dd1, 5, 'other low word uses virtual path', 'decrement primary count'),
    (0x4e94ddc, 5, 'primary count remains nonzero', 'call last-primary helper'),
    (0x4e94dfb, 4, 'null virtual callback is skipped', 'call virtual callback'),
    (0x4e94e09, 4, 'zero-sized payload is not freed', 'free dynamic payload'),
    (0x4e952d7, 4, 'zero set mask returns', 'compute backing layout'),
    (0x4e952f0, 4, 'zero computed set size returns', 'call free boundary'),
    (0x4e95325, 4, 'zero map mask returns', 'inspect occupied count'),
    (0x4e9533c, 4, 'zero occupied count skips scan', 'scan occupied controls'),
    (0x4e9536a, 4, 'last occupied item completed', 'scan next occupied item'),
    (0x4e953b9, 2, 'tag below two needs no value cleanup', 'inspect low tag word'),
    (0x4e953c1, 5, 'other low word uses virtual path', 'decrement primary count'),
    (0x4e953cb, 5, 'primary count remains nonzero', 'call last-primary helper'),
    (0x4e953ee, 4, 'null virtual callback is skipped', 'call virtual callback'),
    (0x4e953fc, 4, 'zero-sized payload is not freed', 'free dynamic payload'),
    (0x4e95449, 4, 'zero computed map size returns', 'free map allocation'),
    (0x4e9548e, 4, 'exceptional zero-sized payload skips free', 'exceptional payload free'),
    (0x4e98b73, 4, 'zero set mask returns', 'compute set backing layout'),
    (0x4e98b8c, 4, 'zero computed set size returns', 'free set backing'),
    (0x4e9bb9c, 3, 'tag at least two enters cleanup', 'tag below two returns'),
    (0x4e9bba7, 5, 'other low word uses virtual path', 'decrement primary count'),
    (0x4e9bbb1, 5, 'primary count remains nonzero', 'tail-call last-primary helper'),
    (0x4e9bbd0, 4, 'null virtual callback is skipped', 'call virtual callback'),
    (0x4e9bbde, 4, 'zero-sized payload is not freed', 'free dynamic payload'),
    (0x4e9bc10, 4, 'exceptional zero-sized payload skips free', 'exceptional payload free'),
    (0x4e9d0fc, 4, 'iterator range is empty', 'iterate remaining records'),
    (0x4e9d131, 2, 'tag below two is skipped', 'inspect low tag word'),
    (0x4e9d136, 5, 'other low word uses virtual path', 'decrement primary count'),
    (0x4e9d140, 5, 'primary count remains nonzero', 'call last-primary helper'),
    (0x4e9d15f, 4, 'null virtual callback is skipped', 'call virtual callback'),
    (0x4e9d16d, 4, 'zero-sized payload is not freed', 'free dynamic payload'),
    (0x4e9d19b, 4, 'zero iterator buffer capacity skips free', 'free iterator buffer'),
    (0x4e9d203, 4, 'no remaining record after unwind', 'drop another record'),
    (0x4e9e414, 4, 'sentinel secondary pointer skips decrement', 'decrement secondary count'),
    (0x4e9e41b, 5, 'secondary count remains nonzero', 'compute allocation layout'),
    (0x4e9e442, 4, 'zero computed allocation size skips free', 'free shared allocation'),
    (0x4e9e486, 4, 'null virtual callback is skipped', 'call payload destructor'),
    (0x4e9e49e, 4, 'sentinel secondary pointer skips decrement', 'decrement secondary count'),
    (0x4e9e4a5, 5, 'secondary count remains nonzero', 'compute allocation layout'),
    (0x4e9e4c8, 4, 'zero computed allocation size skips free', 'free shared allocation'),
    (0x4e9e561, 5, 'source range is nonempty', 'empty source range returns'),
    (0x4e9e5a1, 2, 'tag below two is skipped', 'inspect low tag word'),
    (0x4e9e5a6, 5, 'other low word uses virtual path', 'decrement primary count'),
    (0x4e9e5b0, 5, 'primary count remains nonzero', 'call last-primary helper'),
    (0x4e9e5ce, 4, 'null virtual callback is skipped', 'call virtual callback'),
    (0x4e9e5dc, 4, 'zero-sized payload is not freed', 'free dynamic payload'),
    (0x4e9e633, 4, 'no remaining source record after unwind', 'drop another source record'),
]

# Calls in earlier-owned code are small connection anchors only; their
# enclosing FDEs are not selected or counted by this packet.
BOUNDARY_CALLS = [
    (0x4e99997, 0x4e95310, 'address-nine constructor publication-loser map cleanup'),
    (0x4e99a51, 0x4e9d0d0, 'address-nine constructor remaining iterator cleanup'),
    (0x4e99aac, 0x4e98bd0, 'address-nine constructor initialized vector cleanup'),
    (0x4e99ab6, 0x4e98b60, 'address-nine constructor aggregate cleanup'),
    (0x4e99ad4, 0x4e98b60, 'address-nine constructor aggregate cleanup alternate landing'),
    (0x4e952ab, 0x4e94d80, 'earlier map-clone partial cleanup'),
    (0x4e9be9e, 0x4e9bb90, 'earlier insertion exceptional value cleanup'),
    (0x4e9dd41, 0x4e9e550, 'earlier source-array partial cleanup'),
]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_digest(data):
    require(digest(data) == TARGET_SHA256, 'node 94 SHA-256 mismatch')


def file_offset(secs, va, size, *, executable=False):
    require(type(va) is int and type(size) is int and va >= 0 and size > 0,
            'invalid VA range')
    candidates = [s for s in secs if s['type'] != 8 and s['flags'] & 2
                  and (not executable or s['flags'] & 4)
                  and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(candidates) == 1, 'VA range is not uniquely file backed')
    return candidates[0]['offset'] + va - candidates[0]['address']


def read_va(data, secs, va, size, *, executable=False):
    off = file_offset(secs, va, size, executable=executable)
    require(off + size <= len(data), 'VA range extends beyond file')
    return data[off:off + size]


def checked_pin(data, secs, va, expected):
    require(isinstance(expected, bytes) and expected, 'empty byte predicate')
    actual = read_va(data, secs, va, len(expected), executable=True)
    require(actual == expected, 'fixed opcode predicate changed at ' + hex(va))
    return actual


def rel32_call_target(raw, va):
    require(len(raw) == 5 and raw[0] == 0xe8, 'unexpected direct-call shape')
    return va + len(raw) + struct.unpack_from('<i', raw, 1)[0]


def operand_value(raw, offset, width, signed):
    require(type(offset) is int and type(width) is int and offset >= 0 and width > 0 and
            offset + width <= len(raw) and type(signed) is bool, 'operand outside instruction')
    return int.from_bytes(raw[offset:offset + width], 'little', signed=signed)


def same_register_lea_factor(raw):
    require(len(raw) == 4 and raw[:3] == bytes.fromhex('488d04'), 'unexpected LEA shape')
    sib = raw[3]
    base, index, scale = sib & 7, (sib >> 3) & 7, 1 << (sib >> 6)
    require(base == index and base != 5, 'LEA base and index are not the same register')
    return 1 + scale


def named_section(secs, name):
    rows = [s for s in secs if s['name'] == name and s['type'] != 8]
    require(len(rows) == 1, 'missing or ambiguous section ' + name)
    return rows[0]


def relocations(data, secs):
    found = {}
    for section_name in ('.rela.dyn', '.rela.plt'):
        sec = named_section(secs, section_name)
        require(sec['size'] % 24 == 0, 'malformed RELA size')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            require(slot not in found, 'duplicate relocation slot')
            found[slot] = {'slot': slot, 'info': info, 'addend': addend,
                           'file_offset': off, 'section': section_name,
                           'raw': data[off:off + 24].hex()}
    return found


def relative_relocation(rels, slot, expected):
    row = rels.get(slot)
    require(row is not None and row['info'] == 8 and row['addend'] == expected,
            'missing or altered symbol-free relative relocation')
    return row


def plt_slot(raw, va):
    require(len(raw) == 6 and raw[:2] == b'\xff\x25', 'unexpected PLT entry shape')
    return va + len(raw) + struct.unpack_from('<i', raw, 2)[0]


def unwind_import(data, secs, rels):
    """Bind the selected PLT boundary to the on-disk dynamic symbol record."""
    va = 0x5660110
    code = read_va(data, secs, va, 6, executable=True)
    slot = plt_slot(code, va)
    entry = rels.get(slot)
    require(entry is not None and entry['section'] == '.rela.plt' and
            entry['info'] & 0xffffffff == 7 and entry['info'] >> 32 > 0,
            'unexpected PLT relocation')
    symbol_index = entry['info'] >> 32
    symbols = named_section(secs, '.dynsym')
    strings = named_section(secs, '.dynstr')
    require(symbols['size'] % 24 == 0 and symbol_index < symbols['size'] // 24,
            'dynamic symbol index outside section')
    symoff = symbols['offset'] + symbol_index * 24
    symraw = data[symoff:symoff + 24]
    nameoff = struct.unpack_from('<I', symraw, 0)[0]
    require(nameoff < strings['size'], 'dynamic symbol name outside string table')
    namepos = strings['offset'] + nameoff
    end = data.find(b'\0', namepos, strings['offset'] + strings['size'])
    require(end >= 0, 'unterminated dynamic symbol')
    rawname = data[namepos:end]
    require(rawname == b'_Unwind_Resume', 'unexpected unwind import')
    return {'plt_va': hex(va), 'plt_raw': code.hex(), 'slot_va': hex(slot),
            'relocation_file_offset': hex(entry['file_offset']),
            'relocation_raw': entry['raw'], 'relocation_info': hex(entry['info']),
            'symbol_index': symbol_index, 'symbol_file_offset': hex(symoff),
            'symbol_raw': symraw.hex(), 'name_file_offset': hex(namepos),
            'symbol_name': rawname.decode('ascii')}


def decode_one(buf, start):
    """Decode only instruction lengths and transfers for the pinned bodies."""
    i = start
    prefixes = []
    try:
        while buf[i] in (0x66, 0xf0, 0xf2, 0xf3, 0x2e, 0x64, 0x65) or 0x40 <= buf[i] <= 0x4f:
            prefixes.append(buf[i])
            i += 1
            require(i - start < 15, 'oversized prefix')
        rex = next((v for v in reversed(prefixes) if 0x40 <= v <= 0x4f), 0)
        op = buf[i]
        i += 1
        immediate = 0
        modrm_needed = False
        kind = 'plain'
        relpos = None
        rippos = None
        op2 = None
        if op in (0xe8, 0xe9):
            kind = 'call' if op == 0xe8 else 'jump'
            relpos, immediate = i, 4
        elif op == 0xeb or 0x70 <= op <= 0x7f:
            kind = 'jump' if op == 0xeb else 'jcc'
            relpos, immediate = i, 1
        elif op == 0xc3:
            kind = 'return'
        elif op == 0xcc:
            kind = 'int3'
        elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99):
            pass
        elif 0xb0 <= op <= 0xb7:
            immediate = 1
        elif 0xb8 <= op <= 0xbf:
            immediate = 8 if rex & 8 else (2 if 0x66 in prefixes else 4)
        elif op in (0x04, 0x0c, 0x24, 0x2c, 0x34, 0x3c, 0xa8, 0x6a):
            immediate = 1
        elif op in (0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d, 0x68, 0xa9):
            immediate = 2 if 0x66 in prefixes else 4
        elif op == 0x0f:
            op2 = buf[i]
            i += 1
            if 0x80 <= op2 <= 0x8f:
                kind, relpos, immediate = 'jcc', i, 4
            elif op2 == 0x0b:
                kind = 'trap'
            elif op2 in (0x10, 0x11, 0x1f, 0x28, 0x29, 0x6e, 0x6f, 0x74,
                         0x76, 0x7f, 0xaf, 0xb0, 0xb1, 0xb6, 0xb7, 0xbc,
                         0xbd, 0xc1, 0xd7, 0xdb, 0xeb, 0xef) or 0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f:
                modrm_needed = True
            elif op2 in (0x70, 0x71, 0x72, 0x73, 0xba, 0xc2, 0xc4, 0xc5, 0xc6):
                modrm_needed, immediate = True, 1
            else:
                raise ValueError('unsupported two-byte opcode')
        elif op in (0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                    0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b,
                    0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2a, 0x2b,
                    0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3a, 0x3b,
                    0x63, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a,
                    0x8b, 0x8d, 0x8f, 0xd0, 0xd1, 0xd2, 0xd3, 0xfe, 0xff):
            modrm_needed = True
        elif op in (0x80, 0x82, 0x83, 0xc0, 0xc1, 0xc6, 0x6b):
            modrm_needed, immediate = True, 1
        elif op in (0x81, 0xc7, 0x69):
            modrm_needed, immediate = True, 2 if 0x66 in prefixes else 4
        elif op in (0xf6, 0xf7):
            modrm_needed = True
        else:
            raise ValueError('unsupported opcode')
        if modrm_needed:
            modrm = buf[i]
            i += 1
            mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
            if op == 0xff and reg in (2, 4):
                kind = 'indirect-call' if reg == 2 else 'indirect-jump'
            if op in (0xf6, 0xf7) and reg == 0:
                immediate = 1 if op == 0xf6 else (2 if 0x66 in prefixes else 4)
            if mod != 3 and rm == 4:
                sib = buf[i]
                i += 1
                if mod == 0 and sib & 7 == 5:
                    i += 4
            elif mod == 0 and rm == 5:
                rippos = i
                i += 4
            if mod == 1:
                i += 1
            elif mod == 2:
                i += 4
        end = i + immediate
        require(end <= len(buf) and end - start <= 15, 'truncated instruction')
        result = {'size': end - start, 'kind': kind}
        if relpos is not None:
            result['target'] = end + int.from_bytes(buf[relpos:end], 'little', signed=True)
        if rippos is not None:
            result['rip'] = end + struct.unpack_from('<i', buf, rippos)[0]
        if kind == 'jcc':
            result['condition'] = (op2 if op == 0x0f else op) & 15
        return result
    except (IndexError, struct.error) as error:
        raise ValueError('truncated instruction') from error


def walk(buf):
    rows = []
    pos = 0
    while pos < len(buf):
        item = decode_one(buf, pos)
        rows.append((pos, item))
        pos += item['size']
    boundaries = {offset for offset, _ in rows}
    for _, item in rows:
        target = item.get('target')
        if target is not None and 0 <= target < len(buf):
            require(target in boundaries, 'local transfer enters instruction interior')
    return rows


def normalize_drop(buf, start):
    """Compare only known duplicated cleanup bodies, masking PC displacements.

    Each masked operand is resolved and checked first. No target/build
    equivalence follows from comparing these four captured bodies.
    """
    result = bytearray(buf)
    masks = []
    expected = {
        0x2c: ('RIP-relative slot', 0x57733e0),
        0x70: ('RIP-relative slot', 0x576e010),
        0x9d: ('RIP-relative slot', 0x576e010),
        0xa6: ('relative call target', 0x5660110),
    }
    seen = set()
    for off, item in walk(buf):
        resolved = None
        operand = None
        if 'rip' in item:
            resolved = start + item['rip']
            require(item['kind'] in ('indirect-call', 'indirect-jump'),
                    'unexpected RIP target in cleanup body')
            operand = 'RIP-relative slot'
        elif item['kind'] == 'call' and 'target' in item:
            resolved = start + item['target']
            operand = 'relative call target'
        if operand:
            require(expected.get(off) == (operand, resolved),
                    'unexpected RIP target or relative call in cleanup body')
            seen.add(off)
            displacement = off + item['size'] - 4
            original = buf[displacement:displacement + 4]
            masks.append([hex(start), hex(start + off), hex(start + displacement),
                          original.hex(), operand, hex(resolved)])
            result[displacement:displacement + 4] = bytes(4)
    require(seen == set(expected), 'unexpected masked displacement fields')
    return bytes(result), masks


def lsda_records(data, secs, fde):
    if fde['lsda'] is None:
        return None
    sec = named_section(secs, '.gcc_except_table')
    begin = file_offset(secs, fde['lsda'], 1)
    limit = sec['offset'] + sec['size']
    require(sec['offset'] <= begin < limit and begin + 2 <= limit, 'LSDA outside section')
    require(data[begin] == 0xff, 'unsupported LPStart encoding')
    encoding, pos = data[begin + 1], begin + 2
    types = None
    if encoding == 0x9b:
        delta, pos = uleb(data, pos, limit)
        types = pos + delta
        require(types <= limit, 'LSDA type table outside section')
    else:
        require(encoding == 0xff, 'unsupported LSDA type encoding')
    require(pos < limit and data[pos] == 1, 'unsupported call-site encoding')
    size, pos = uleb(data, pos + 1, limit)
    stop = pos + size
    require(stop <= limit and (types is None or stop <= types), 'invalid LSDA call-site extent')
    header_end, last, entries = pos, 0, []
    while pos < stop:
        old = pos
        offset, pos = uleb(data, pos, stop)
        length, pos = uleb(data, pos, stop)
        landing, pos = uleb(data, pos, stop)
        action, pos = uleb(data, pos, stop)
        require(offset >= last and offset + length <= fde['end'] - fde['start'],
                'LSDA call-site range outside function or unordered')
        require(landing == 0 or landing < fde['end'] - fde['start'], 'landing outside FDE')
        last = offset + length
        entries.append({'start_va': hex(fde['start'] + offset), 'length': length,
                        'landing_va': hex(fde['start'] + landing) if landing else None,
                        'action': action, 'raw': data[old:pos].hex()})
    return {'function_va': hex(fde['start']), 'lsda_va': hex(fde['lsda']),
            'file_offset': hex(begin), 'header': data[begin:header_end].hex(),
            'table': data[header_end:stop].hex(), 'entries': entries}


def model_tag(tag):
    """Projection of the two observed comparisons, not a target execution."""
    require(type(tag) is int and 0 <= tag <= MASK64, 'tag outside u64')
    if tag < 2:
        return 'no_value_cleanup'
    if tag & 0xffffffff == 2:
        return 'atomic_primary_decrement'
    return 'virtual_payload_cleanup'


def model_counter(value):
    require(type(value) is int and 0 <= value <= MASK64, 'counter outside u64')
    next_value = (value - 1) & MASK64
    return next_value, next_value == 0


def model_control_scan(controls, count):
    """Synthetic projection of the count-limited 16-byte occupied scan."""
    require(isinstance(controls, bytes) and len(controls) % 16 == 0 and
            type(count) is int and 0 <= count <= MASK64, 'invalid modeled controls')
    selected = []
    group = 0
    while count:
        require(group + 16 <= len(controls), 'modeled control scan exhausted')
        bits = sum((byte < 0x80) << index for index, byte in enumerate(controls[group:group + 16]))
        while bits and count:
            bit = (bits & -bits).bit_length() - 1
            selected.append(group + bit)
            bits &= bits - 1
            count -= 1
        group += 16
    return selected


def model_backing(mask, stride):
    """Allocation geometry for valid, nonempty mask shapes only."""
    require(type(mask) is int and mask > 0 and mask < (1 << 56) and
            (mask + 1) & mask == 0, 'invalid bucket mask')
    require(stride in (20, 48), 'unexpected entry stride')
    buckets = mask + 1
    offset = (stride * buckets + 15) & ~15
    total = offset + buckets + 16
    require(total <= MASK64, 'layout overflow')
    return offset, total


def model_secondary_layout(size, alignment):
    require(type(size) is int and type(alignment) is int and
            0 <= size < (1 << 60) and 0 < alignment < (1 << 60) and
            alignment & (alignment - 1) == 0, 'invalid modeled layout')
    a = max(8, alignment)
    return (size + a + 15) & -a


def model_payload_offset(alignment):
    require(type(alignment) is int and 0 < alignment < (1 << 60) and
            alignment & (alignment - 1) == 0, 'invalid modeled alignment')
    return ((alignment - 1) & ~15) + 16


def json_bytes(obj):
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def tsv_bytes(headers, rows):
    buf = io.StringIO(newline='')
    writer = csv.writer(buf, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return buf.getvalue().encode('ascii')


def select_fdes(fdes, index, queries):
    """Join selected FDEs with the unwind header without guessing extents."""
    selected = {start: [] for start in queries}
    for row in fdes:
        if row['start'] in selected:
            selected[row['start']].append(row)
    indexed = {}
    for row in index:
        start = row['start']
        if start in queries:
            require(start not in indexed, 'duplicate selected unwind start')
            indexed[start] = row
    result = {}
    for start, (end, _) in queries.items():
        require(len(selected[start]) == 1, 'selected FDE is missing or duplicated')
        fde = selected[start][0]
        require(fde['end'] == end, 'selected FDE extent differs')
        require(start in indexed and indexed[start]['fde'] == fde['fde'], 'FDE/index mismatch')
        result[start] = fde
    return result


def extract(data):
    verify_digest(data)
    secs = sections(data)
    _, header_index = unwind_index(data)
    cies, fdes = eh_frame_records(data, secs)
    chosen = select_fdes(fdes, header_index, FUNCTIONS)
    rels = relocations(data, secs)
    relative_relocation(rels, 0x57733e0, 0x4e9e470)
    relative_relocation(rels, 0x576e010, 0x54c8cb0)
    unwind = unwind_import(data, secs, rels)
    frows, brows, irows, transfers, riprows, decoded, exceptions = [], [], [], [], [], {}, []
    for start in sorted(FUNCTIONS):
        end, role = FUNCTIONS[start]
        fde = chosen[start]
        body = read_va(data, secs, start, end - start, executable=True)
        shapes = walk(body)
        decoded[start] = {start + off: item for off, item in shapes}
        frows.append([hex(start), hex(end), len(body), hex(file_offset(secs, start, len(body), executable=True)),
                      hex(fde['fde']), hex(fde['cie']), hex(fde['lsda']) if fde['lsda'] else '',
                      digest(body), role])
        def raw_record(va):
            head = read_va(data, secs, va, 4)
            length = struct.unpack('<I', head)[0]
            require(4 <= length < 0xffffffff, 'unsupported frame record length')
            return read_va(data, secs, va, length + 4).hex()
        brows.append({'start_va': hex(start), 'end_va': hex(end), 'body': body.hex(),
                      'fde_va': hex(fde['fde']), 'fde_raw': raw_record(fde['fde']),
                      'cie_va': hex(fde['cie']), 'cie_raw': raw_record(fde['cie']),
                      'cie_augmentation': cies[fde['cie']]['augmentation']})
        exc = lsda_records(data, secs, fde)
        if exc:
            exceptions.append(exc)
        for off, item in shapes:
            va = start + off
            raw = body[off:off + item['size']]
            target = start + item['target'] if 'target' in item else None
            slot = start + item['rip'] if 'rip' in item else None
            ins = [hex(start), hex(va), raw.hex(), item['kind'],
                   hex(target) if target is not None else '',
                   hex(slot) if slot is not None else '']
            irows.append(ins)
            if item['kind'] != 'plain':
                resolved = rels.get(slot) if slot is not None else None
                via_rela = resolved['addend'] if resolved and resolved['info'] == 8 else None
                transfers.append(ins + [str(item.get('condition', '')),
                    hex(via_rela) if via_rela is not None else '',
                    'within_selected_FDE' if target is not None and start <= target < end else
                    'selected_entry' if target in FUNCTIONS or via_rela in FUNCTIONS else
                    'outside_or_dynamic'])
            if slot is not None:
                rel = rels.get(slot)
                riprows.append([hex(start), hex(va), raw.hex(), hex(slot),
                                hex(rel['info']) if rel else '', hex(rel['addend']) if rel else ''])
    pinrows = []
    pin_values = {}
    for va, expected, label in PINS:
        raw = bytes.fromhex(expected)
        actual = checked_pin(data, secs, va, raw)
        owners = [s for s, (end, _) in FUNCTIONS.items() if s <= va and va + len(raw) <= end]
        require(len(owners) == 1 and va in decoded[owners[0]], 'pin is not a selected instruction start')
        pinrows.append([hex(owners[0]), hex(va), hex(file_offset(secs, va, len(raw), executable=True)),
                        actual.hex(), label])
        require(va not in pin_values, 'duplicate byte predicate address')
        pin_values[va] = actual
    operands = []
    for site, offset, width, signed, label in OPERANDS:
        require(site in pin_values, 'operand lacks a fixed byte predicate')
        raw = pin_values[site]
        operands.append([hex(site), raw.hex(), offset, width, str(signed).lower(),
                         operand_value(raw, offset, width, signed), label])
    for site, label in ((0x4e95439, 'map LEA multiplier'),
                        (0x4e952d9, 'set LEA multiplier')):
        require(site in pin_values, 'LEA lacks a fixed byte predicate')
        raw = pin_values[site]
        operands.append([hex(site), raw.hex(), 3, 1, 'false',
                         same_register_lea_factor(raw), label])
    windowrows = []
    for begin, end, meaning in WINDOWS:
        owner = next((s for s, (stop, _) in FUNCTIONS.items() if s <= begin < end <= stop), None)
        require(owner is not None and begin in decoded[owner] and
                (end == FUNCTIONS[owner][0] or end in decoded[owner]), 'window is not instruction bounded')
        windowrows.append([hex(owner), hex(begin), hex(end), hex(file_offset(secs, begin, end-begin, executable=True)),
                           read_va(data, secs, begin, end-begin, executable=True).hex(), meaning])
    decisions = []
    for site, condition, taken, fallthrough in DECISIONS:
        owner = next((s for s, (end, _) in FUNCTIONS.items() if s <= site < end), None)
        require(owner is not None and site in decoded[owner], 'decision instruction missing')
        ins = decoded[owner][site]
        require(ins['kind'] == 'jcc' and ins.get('condition') == condition,
                'decision condition changed')
        next_va = site + ins['size']
        target = owner + ins['target']
        require(target in decoded[owner] and next_va in decoded[owner], 'decision edge not instruction aligned')
        raw = read_va(data, secs, site, ins['size'], executable=True)
        decisions.append([hex(owner), hex(site), raw.hex(), condition, hex(target),
                          hex(next_va), taken, fallthrough])
    exceptional, exception_calls = [], []
    for exc in exceptions:
        owner = int(exc['function_va'], 16)
        boundaries = set(decoded[owner]) | {FUNCTIONS[owner][0]}
        for row in exc['entries']:
            lo = int(row['start_va'], 16)
            hi = lo + row['length']
            landing = int(row['landing_va'], 16) if row['landing_va'] else None
            require(lo in boundaries and hi in boundaries and
                    (landing is None or landing in boundaries), 'LSDA range is not instruction aligned')
            calls = [(site, ins) for site, ins in decoded[owner].items()
                     if lo <= site < hi and ins['kind'] in ('call', 'indirect-call')]
            if landing is not None:
                require(len(calls) == 1, 'landing range does not contain exactly one call')
            for site, ins in calls:
                target = owner + ins['target'] if 'target' in ins else None
                slot = owner + ins['rip'] if 'rip' in ins else None
                rel = rels.get(slot) if slot is not None else None
                details = [hex(owner), hex(lo), hex(hi), hex(site),
                           read_va(data, secs, site, ins['size'], executable=True).hex(),
                           hex(target) if target is not None else '',
                           hex(slot) if slot is not None else '',
                           hex(rel['addend']) if rel and rel['info'] == 8 else '',
                           hex(landing) if landing is not None else '', row['action'], row['raw']]
                exception_calls.append(details)
                if landing is not None:
                    exceptional.append(details)
    normalized = None
    masks, comparisons = [], []
    for start in (0x4e9bb90, 0x4e9cd50, 0x4e9d6c0, 0x4e9fb80):
        end = FUNCTIONS[start][0]
        body = read_va(data, secs, start, end - start, executable=True)
        current, fields = normalize_drop(body, start)
        if normalized is None:
            normalized = current
        require(current == normalized, 'cleanup body differs beyond checked displacements')
        masks.extend(fields)
        comparisons.append([hex(start), digest(body), digest(current), len(body), len(fields)])
    boundary_rows = []
    for site, expected, purpose in BOUNDARY_CALLS:
        raw = read_va(data, secs, site, 5, executable=True)
        target = rel32_call_target(raw, site)
        require(target == expected and target in FUNCTIONS, 'boundary call target changed')
        boundary_rows.append([hex(site), hex(file_offset(secs, site, 5, executable=True)),
                              raw.hex(), hex(target), purpose])
    # Static data anchor only; the existing compression and registry bodies are not selected.
    record = 0x574f0a8
    tag_bytes = read_va(data, secs, record, 8)
    address = read_va(data, secs, record + 24, 20)
    require(struct.unpack('<Q', tag_bytes)[0] == 0 and address == bytes(19) + b'\x09',
            'prior address-09 data anchor changed')
    anchor = {'record_va': hex(record), 'tag_va': hex(record), 'tag_raw': tag_bytes.hex(),
              'tag': struct.unpack('<Q', tag_bytes)[0], 'address_va': hex(record + 24),
              'address_raw': address.hex(), 'note': 'Data anchor from prior work; no prior function body is selected.'}
    used_slots = sorted({int(row[3], 16) for row in riprows if row[4]})
    relrows = []
    for slot in used_slots:
        row = rels[slot]
        relrows.append([hex(slot), row['section'], hex(row['file_offset']), hex(row['info']),
                        hex(row['addend']), row['raw']])
    summary = {'target_sha256': digest(data), 'coordinate_system': 'linked ELF VA before load bias',
               'selected_fde_count': len(frows), 'selected_code_bytes': sum(int(r[2]) for r in frows),
               'instruction_shapes': len(irows), 'syntactic_transfer_records': len(transfers),
               'rip_reference_records': len(riprows), 'fixed_byte_predicates': len(pinrows),
               'decoded_operand_projections': len(operands),
               'selected_windows': len(windowrows), 'reviewed_decisions': len(decisions),
               'lsda_tables': len(exceptions), 'exceptional_call_edges': len(exceptional),
               'calls_with_lsda_rows': len(exception_calls),
               'lsda_call_site_rows': sum(len(e['entries']) for e in exceptions),
               'target_body_comparisons': len(comparisons), 'masked_displacement_fields': len(masks),
               'prior_caller_boundary_calls': len(boundary_rows),
               'relocation_records': len(relrows), 'captured_execution': False,
               'independent_rust_implementation': 'not yet implemented',
               'claim': 'selected static bytes and inferred cleanup semantics only',
               'limits': ['FDE extents are not a complete function census.',
                          'Dynamic virtual callbacks and allocator internals are external.',
                          'Exception action chains, target behavior and live concurrency are unresolved.']}
    return {
        'functions.tsv': tsv_bytes(['start_va', 'end_va_exclusive', 'size', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'sha256', 'inferred_role'], frows),
        'bodies.json': json_bytes(brows),
        'instructions.tsv': tsv_bytes(['function_va', 'site_va', 'raw', 'shape', 'relative_target_va', 'rip_target_va'], irows),
        'transfers.tsv': tsv_bytes(['function_va', 'site_va', 'raw', 'shape', 'relative_target_va', 'rip_target_va', 'condition', 'relative_relocation_addend', 'scope'], transfers),
        'rip-references.tsv': tsv_bytes(['function_va', 'site_va', 'raw', 'target_va', 'relocation_info', 'relocation_addend'], riprows),
        'relocations.tsv': tsv_bytes(['slot_va', 'section', 'file_offset', 'info', 'addend', 'raw'], relrows),
        'exceptions.json': json_bytes(exceptions),
        'byte-predicates.tsv': tsv_bytes(['function_va', 'site_va', 'file_offset', 'raw', 'interpretation'], pinrows),
        'operands.tsv': tsv_bytes(['site_va', 'instruction_raw', 'operand_offset', 'operand_width', 'signed', 'decoded_value', 'interpretation'], operands),
        'semantic-windows.tsv': tsv_bytes(['function_va', 'start_va', 'end_va_exclusive', 'file_offset', 'raw', 'interpretation'], windowrows),
        'decisions.tsv': tsv_bytes(['function_va', 'branch_va', 'raw', 'condition', 'taken_va', 'fallthrough_va', 'taken_interpretation', 'fallthrough_interpretation'], decisions),
        'exception-edges.tsv': tsv_bytes(['function_va', 'protected_start', 'protected_end', 'call_va', 'call_raw', 'direct_target', 'rip_slot', 'relocation_addend', 'landing_va', 'action', 'lsda_raw'], exceptional),
        'exception-calls.tsv': tsv_bytes(['function_va', 'protected_start', 'protected_end', 'call_va', 'call_raw', 'direct_target', 'rip_slot', 'relocation_addend', 'landing_va', 'action', 'lsda_raw'], exception_calls),
        'cleanup-comparison.tsv': tsv_bytes(['start_va', 'raw_sha256', 'masked_sha256', 'size', 'masked_fields'], comparisons),
        'comparison-masks.tsv': tsv_bytes(['function_va', 'instruction_va', 'masked_va', 'original_bytes', 'operand_kind', 'resolved_target'], masks),
        'prior-boundary-calls.tsv': tsv_bytes(['call_va', 'file_offset', 'raw', 'target_va', 'dependency_interpretation'], boundary_rows),
        'unwind-import.json': json_bytes(unwind),
        'address-anchor.json': json_bytes(anchor),
        'summary.json': json_bytes(summary),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    files = extract(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, contents in sorted(files.items()):
        (args.out / name).write_bytes(contents)
    print('wrote ' + str(len(files)) + ' deterministic evidence files')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as error:
        print('re21_registry_drop94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
