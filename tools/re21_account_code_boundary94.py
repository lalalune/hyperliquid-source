#!/usr/bin/env python3
"""Export static account/code preparation evidence for the node 94 precompile path.

The input is authenticated before interpretation.  The byte walker recognizes
only the x86-64 encodings in the selected FDEs and fails closed on other shapes.
No captured instruction or external program is executed.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK64 = (1 << 64) - 1

# Analyst-selected starts and independently checked FDE ends.  Labels are
# interpretations; raw bytes and control transfers are emitted separately.
FUNCTIONS = {
    0x4e6c8b0: (0x4e6caa5, 'one-byte default code object'),
    0x4e6cab0: (0x4e6cc61, 'code representation conversion'),
    0x4e6cc70: (0x4e6cd7c, 'fallback execution input assembly'),
    0x4e6ec80: (0x4e6ecfa, 'partially built account cleanup'),
    0x4e6ed00: (0x4e6edb5, 'tagged code payload cleanup'),
    0x4e6f360: (0x4e6f68c, 'standard account access and journal entry'),
    0x4e6fd50: (0x4e6fee2, 'account code preparation'),
    0x4e73680: (0x4e737a0, 'clone code representation by tag'),
    0x4e7c4e0: (0x4e7c544, '88-byte journal vector growth'),
    0x4e7c550: (0x4e7c5b4, '24-byte journal frame vector growth'),
    0x4e7c5c0: (0x4e7c6aa, 'checked vector allocation and reallocation'),
    0x4e7c6b0: (0x4e7c73e, 'byte vector growth'),
    0x4e7d270: (0x4e7d2ce, 'bit-range iterator construction'),
    0x4e88a90: (0x4e88b4e, 'fallback interpreter ownership handoff'),
    0x4e8cd70: (0x4e8ce97, 'account lookup used by reverse journal'),
    0x4e8fa30: (0x4e8fca1, 'fallback interpreter initialization'),
}

# Windows are analyst annotations. The generator verifies both endpoints are
# decoded boundaries and records every byte from the authenticated input.
WINDOWS = [
    (0x4e6f360, 0x4e6f3aa, 'copy key and call account entry probe'),
    (0x4e6f3aa, 0x4e6f3dc, 'vacancy branch and default-account constructor'),
    (0x4e6f3dc, 0x4e6f432, 'per-table seed and process initialization guard'),
    (0x4e6f432, 0x4e6f4a3, 'construct account value and test address set'),
    (0x4e6f4a3, 0x4e6f4df, 'find available account bucket'),
    (0x4e6f4df, 0x4e6f551, 'publish mirrored controls, key, value and count'),
    (0x4e6f551, 0x4e6f5b5, 'set membership, journal presence, reserve and append'),
    (0x4e6f5b5, 0x4e6f5d6, 'hit flag test and normal tagged return'),
    (0x4e6f5e8, 0x4e6f608, 'clear flag or take missing-frame failure boundary'),
    (0x4e6f608, 0x4e6f652, 'probe advance and seed initialization boundary'),
    (0x4e6f652, 0x4e6f68c, 'account initialization unwind cleanup'),
    (0x4e6fd50, 0x4e6fd83, 'load account and test result and code tags'),
    (0x4e6fd83, 0x4e6fdb2, 'compare both halves of the empty-code hash'),
    (0x4e6fdb2, 0x4e6fe04, 'unequal hash materialization and publication'),
    (0x4e6fe04, 0x4e6fe39, 'non-five result copy branch'),
    (0x4e6fe39, 0x4e6fe73, 'equal hash materialization and publication'),
    (0x4e6fe73, 0x4e6fe87, 'return tag, pointer and journal byte'),
    (0x4e6fe87, 0x4e6fee2, 'restore selected values during unwind'),
    (0x4e6c8b0, 0x4e6c918, 'allocate one byte and build a one-bit iterator'),
    (0x4e6c918, 0x4e6c9ec, 'construct backing bytes through bounded iterator'),
    (0x4e6c9ec, 0x4e6ca65, 'allocate shared object and publish code fields'),
    (0x4e6ca65, 0x4e6caa5, 'allocation failures and unwind release'),
    (0x4e6cab0, 0x4e6caf4, 'nonzero code tag copies the existing representation'),
    (0x4e6caf4, 0x4e6cb2d, 'zero code tag checks padded length'),
    (0x4e6cb2d, 0x4e6cb6c, 'allocate, copy input and append thirty-three zero bytes'),
    (0x4e6cb6c, 0x4e6cbe3, 'select buffer methods and publish converted value'),
    (0x4e6cbe3, 0x4e6cc61, 'old value cleanup, failures and unwind'),
    (0x4e6cc70, 0x4e6cc97, 'assemble fallback input after code conversion'),
    (0x4e6cc97, 0x4e6cd55, 'copy fallback input fields to the output'),
    (0x4e6cd55, 0x4e6cd7c, 'fallback input cleanup on unwind'),
    (0x4e6ed00, 0x4e6ed17, 'indexed code-value cleanup dispatch'),
    (0x4e6ed17, 0x4e6ed34, 'tag zero and three virtual cleanup'),
    (0x4e6ed34, 0x4e6ed6b, 'tag one virtual cleanup and reference decrement'),
    (0x4e6ed6b, 0x4e6ed8d, 'tag two reference decrement'),
    (0x4e6ed8d, 0x4e6edb5, 'tag one unwind reference cleanup'),
    (0x4e73680, 0x4e7369e, 'code clone tag dispatch'),
    (0x4e7369e, 0x4e736c4, 'tag zero invokes virtual clone'),
    (0x4e736c4, 0x4e736e6, 'tag two increments a shared counter'),
    (0x4e736e6, 0x4e73744, 'tag three clones payload and copies auxiliary fields'),
    (0x4e73744, 0x4e73795, 'tag one clones payload and increments a counter'),
    (0x4e73795, 0x4e737a0, 'clone return and counter failure trap'),
    (0x4e7c4e0, 0x4e7c520, 'journal entry capacity and allocation result'),
    (0x4e7c520, 0x4e7c544, 'journal vector publication and allocation failure'),
    (0x4e7c550, 0x4e7c590, 'journal frame capacity and allocation result'),
    (0x4e7c590, 0x4e7c5b4, 'journal frame publication and allocation failure'),
    (0x4e7c5c0, 0x4e7c614, 'checked alignment, multiplication and size bound'),
    (0x4e7c614, 0x4e7c64a, 'nonempty allocation selects a reallocation slot'),
    (0x4e7c64a, 0x4e7c688, 'empty allocation selects an allocation slot'),
    (0x4e7c688, 0x4e7c6aa, 'allocation result encoding'),
    (0x4e7c6b0, 0x4e7c714, 'checked byte-vector growth and capacity selection'),
    (0x4e7c714, 0x4e7c73e, 'byte-vector publication and failure'),
    (0x4e7d270, 0x4e7d2b4, 'iterator bounds, masks and state construction'),
    (0x4e7d2b4, 0x4e7d2ce, 'iterator invalid-input failure boundaries'),
    (0x4e88a90, 0x4e88ad8, 'copy fallback interpreter and caller context to temporary storage'),
    (0x4e88ad8, 0x4e88b21, 'allocate and publish the fallback result'),
    (0x4e88b21, 0x4e88b4e, 'fallback allocation failure and unwind cleanup'),
    (0x4e8cd70, 0x4e8cdf5, 'account lookup seed and fingerprint setup'),
    (0x4e8cdf5, 0x4e8ce60, 'group probe and full twenty-byte comparison'),
    (0x4e8ce60, 0x4e8ce97, 'empty control, group advance and hit or miss'),
    (0x4e8fa30, 0x4e8fa61, 'fallback input code tag dispatch'),
    (0x4e8fa61, 0x4e8fa7d, 'code-tag arms select virtual input'),
    (0x4e8fa7d, 0x4e8face, 'clone input and copy execution fields'),
    (0x4e8face, 0x4e8fb18, 'allocate execution stack and publish gas fields'),
    (0x4e8fb18, 0x4e8fbfd, 'initialize execution buffers, flags and result fields'),
    (0x4e8fbfe, 0x4e8fc61, 'unsupported form and allocation failure boundaries'),
    (0x4e8fc61, 0x4e8fca1, 'fallback initialization unwind cleanup'),
]

# These byte patterns lock the exact machine operands behind key claims.
# The returned values are read from the instruction bytes, not from labels.
PINS = [
    (0x4e6f37a, '4883c630', 3, 1, 'context account-table offset'),
    (0x4e6f3a5, 'e856cd0100', None, 0, 'account entry probe call'),
    (0x4e6f3af, '4d85ed', None, 0, 'account entry present or vacant test'),
    (0x4e6f3d6, 'ff158c3e9000', None, 0, 'default account through relocation'),
    (0x4e6f43f, 'ba88000000', 1, 4, 'first account-copy length'),
    (0x4e6f478, '498dbf80000000', 3, 4, 'context address-set offset'),
    (0x4e6f482, 'e899cf0100', None, 0, 'address-set membership call'),
    (0x4e6f498, 'bab8000000', 1, 4, 'second account-copy length'),
    (0x4e6f500, '4869ead0000000', 3, 4, 'account-bucket stride'),
    (0x4e6f538, 'babc000000', 1, 4, 'inserted account value length'),
    (0x4e6f551, '807c240700', 4, 1, 'address set result zero test'),
    (0x4e6f558, '498b4f28', 3, 1, 'journal frame count offset'),
    (0x4e6f571, '4c8b6cc8f8', 4, 1, 'last journal frame length displacement'),
    (0x4e6f58f, '496bcd58', 3, 1, 'journal entry stride'),
    (0x4e6f593, 'c6040800', 3, 1, 'journal tag value'),
    (0x4e6f5c5, 'f6c110', 2, 1, 'account flag test'),
    (0x4e6f5e8, '80e1ef', 2, 1, 'account flag clear mask'),
    (0x4e6f5eb, '8848f8', 2, 1, 'store cleared account flag'),
    (0x4e6f5d3, 'c60305', 2, 1, 'account normal result tag'),
    (0x4e6fd5e, 'e8fdf5ffff', None, 0, 'code preparation calls account access'),
    (0x4e6fd67, '3c05', 1, 1, 'account result tag test'),
    (0x4e6fd79, '41833e04', 3, 1, 'missing-code tag test'),
    (0x4e6fda7, '3dffff0000', 1, 4, 'hash equality lane mask'),
    (0x4e6fdb7, 'e8f4caffff', None, 0, 'unequal hash default construction'),
    (0x4e6fe3c, 'e86fcaffff', None, 0, 'equal hash default construction'),
    (0x4e6fe4f, '49c70601000000', 3, 4, 'published code tag'),
    (0x4e6fe7b, 'c60305', 2, 1, 'prepared-account return tag'),
    (0x4e6c8c3, 'c644240700', 4, 1, 'default input byte'),
    (0x4e6c8c8, 'bf01000000', 1, 4, 'default initial allocation request'),
    (0x4e6c903, 'ba01000000', 1, 4, 'default iterator byte length'),
    (0x4e6c90d, '41b801000000', 2, 4, 'default iterator bit bound'),
    (0x4e6c9f1, 'bf28000000', 1, 4, 'shared-object allocation size'),
    (0x4e6ca14, '48c7401808000000', 4, 4, 'shared bit capacity'),
    (0x4e6ca2f, '488d0d659837fb', None, 0, 'default code literal address'),
    (0x4e6ca3a, '48c7421001000000', 4, 4, 'default code literal length'),
    (0x4e6cb17, '4983c621', 3, 1, 'fallback code padding length'),
    (0x4e6cb0a, '4983ffde', 3, 1, 'fallback unsigned length limit operand'),
    (0x4e6cb66, '43c6443c2000', 5, 1, 'last padding byte value'),
    (0x4e736c8, 'f048ff00', None, 0, 'tag two counter increment'),
    (0x4e7376a, 'f048ff02', None, 0, 'tag one counter increment'),
    (0x4e7c4fb, '4c0f43f0', None, 0, 'journal capacity conditional maximum'),
    (0x4e7c50c, '41b958000000', 2, 4, 'journal entry element size'),
    (0x4e7c57c, '41b918000000', 2, 4, 'journal frame element size'),
    (0x4e7c5ea, '48b90000000000000080', 2, 8, 'allocation signed-size boundary'),
    (0x4e7d278, '4180f808', 3, 1, 'iterator bit bound'),
    (0x4e88ad8, 'bf18020000', 1, 4, 'fallback wrapper allocation size'),
    (0x4e88b0a, '48c70303000000', 3, 4, 'fallback wrapper result tag'),
    (0x4e8ce1d, '4d69dbd0000000', 3, 4, 'reverse journal account-bucket stride'),
    (0x4e8ce4a, '81fbffff0000', 2, 4, 'account full-key equality lane mask'),
    (0x4e8face, 'bf00800000', 1, 4, 'fallback interpreter stack allocation size'),
    (0x4e8fb85, '49c7861801000000040000', 7, 4, 'fallback interpreter element capacity'),
]

# Earlier-owned code is represented only by these interface instruction
# bytes; its enclosing functions are not selected or counted in this packet.
ANCHORS = [
    (0x4e6ff01, '4989d6', 'retain the original call-input pointer'),
    (0x4e6ff0b, '4881bea800000000040000', 'call-depth comparison before account access'),
    (0x4e6ff16, '7647', 'call-depth accepted branch'),
    (0x4e6ff62, '418b4670', 'pre-lookup address last four bytes'),
    (0x4e6ff66, '89442430', 'copy address last four bytes to stack'),
    (0x4e6ff6a, 'f3410f6f4660', 'pre-lookup address first sixteen bytes'),
    (0x4e6ff70, '660f7f442420', 'copy address first sixteen bytes to stack'),
    (0x4e6ff7e, '488d542420', 'pass the copied address to account preparation'),
    (0x4e6ff83, 'e8c8fdffff', 'pre-lookup account-code preparation'),
    (0x4e6ffd0, 'e88bf3ffff', 'optional second account access'),
    (0x4e7001a, 'ff15084e9000', 'journal frame growth slot'),
    (0x4e70049, '498d4501', 'compute the next journal frame count'),
    (0x4e7004d, '48894528', 'publish the next journal frame count'),
    (0x4e70051, '41803e00', 'call-input transfer-variant test'),
    (0x4e70055, '0f843a010000', 'transfer-variant bypass branch'),
    (0x4e7005b, '498d7660', 'use the original address as registry lookup key'),
    (0x4e70067, '4180fc06', 'call scheme test'),
    (0x4e7006b, '0f8419070000', 'call scheme bypass branch'),
    (0x4e7007e, '4883bde000000000', 'context owned or borrowed registry test'),
    (0x4e70096, 'e835cf0100', 'owned precompile lookup'),
    (0x4e707b9, 'e892f5ffff', 'registry-miss account-code preparation'),
    (0x4e70927, 'ff1503459000', 'borrowed registry hit dispatch slot'),
    (0x4e70fb6, 'e8c5260000', 'registry-miss code-value clone'),
    (0x4e711c0, 'e8abbaffff', 'registry-miss fallback input assembly'),
    (0x4e711ea, 'ff15503c9000', 'fallback interpreter initialization slot'),
    (0x4e7120e, 'ff15343c9000', 'fallback interpreter ownership slot'),
    (0x4e79c64, 'e807310100', 'reverse journal account lookup'),
    (0x4e79c79, '8088b000000010', 'reverse journal flag restoration'),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, 'target SHA-256 mismatch')


def offset_for(secs, va, size, executable=False):
    require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
            'invalid virtual address or size')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'range is not uniquely file-backed')
    s = matches[0]
    return s['offset'] + va - s['address']


def read_va(data, secs, va, size, executable=False):
    off = offset_for(secs, va, size, executable)
    require(off + size <= len(data), 'file-backed range exceeds input')
    return data[off:off + size]


def checked_pin(data, secs, va, expected, executable=True):
    got = read_va(data, secs, va, len(expected), executable)
    require(got == expected, f'byte predicate mismatch at {va:#x}')
    return got


def named_section(secs, name):
    found = [s for s in secs if s['name'] == name and s['type'] != 8]
    require(len(found) == 1, f'missing or duplicate section {name}')
    return found[0]


def decode_one(buf, start):
    """Read instruction length and PC-relative fields for bounded x86 shapes."""
    p = start
    prefixes = []
    try:
        while buf[p] in (0x66, 0xf0, 0xf2, 0xf3, 0x2e, 0x64, 0x65) or 0x40 <= buf[p] <= 0x4f:
            prefixes.append(buf[p])
            p += 1
            require(p - start < 15, 'instruction prefix too long')
        rex = next((x for x in reversed(prefixes) if 0x40 <= x <= 0x4f), 0)
        op = buf[p]
        p += 1
        op2 = None
        immediate = 0
        modrm = False
        relative_pos = None
        rip_pos = None
        kind = 'plain'
        if op in (0xe8, 0xe9):
            kind, relative_pos, immediate = ('call' if op == 0xe8 else 'jump'), p, 4
        elif op == 0xeb or 0x70 <= op <= 0x7f:
            kind, relative_pos, immediate = ('jump' if op == 0xeb else 'jcc'), p, 1
        elif op in (0xc3, 0xcc):
            kind = 'return' if op == 0xc3 else 'int3'
        elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99):
            pass
        elif 0xb0 <= op <= 0xb7:
            immediate = 1
        elif 0xb8 <= op <= 0xbf:
            immediate = 8 if rex & 8 else (2 if 0x66 in prefixes else 4)
        elif op in (0x04, 0x0c, 0x24, 0x2c, 0x34, 0x3c, 0x6a, 0xa8):
            immediate = 1
        elif op in (0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d, 0x68, 0xa9):
            immediate = 2 if 0x66 in prefixes else 4
        elif op == 0x0f:
            op2 = buf[p]
            p += 1
            if 0x80 <= op2 <= 0x8f:
                kind, relative_pos, immediate = 'jcc', p, 4
            elif op2 == 0x0b:
                kind = 'trap'
            elif op2 in (0x10, 0x11, 0x1f, 0x28, 0x29, 0x57, 0x60, 0x6e, 0x6f,
                         0x74, 0x76, 0x7f, 0xaf, 0xb0, 0xb1, 0xb6, 0xb7, 0xbc,
                         0xbd, 0xc1, 0xd7, 0xdb, 0xeb, 0xef) or 0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f:
                modrm = True
            elif op2 in (0x70, 0x71, 0x72, 0x73, 0xba, 0xc2, 0xc4, 0xc5, 0xc6):
                modrm, immediate = True, 1
            else:
                raise ValueError(f'unsupported 0f opcode {op2:#x}')
        elif op in (0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11,
                    0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b, 0x20, 0x21, 0x22, 0x23,
                    0x28, 0x29, 0x2a, 0x2b, 0x30, 0x31, 0x32, 0x33, 0x38, 0x39,
                    0x3a, 0x3b, 0x63, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a,
                    0x8b, 0x8d, 0x8f, 0xd0, 0xd1, 0xd2, 0xd3, 0xfe, 0xff):
            modrm = True
        elif op in (0x80, 0x82, 0x83, 0xc0, 0xc1, 0xc6, 0x6b):
            modrm, immediate = True, 1
        elif op in (0x81, 0xc7, 0x69):
            modrm, immediate = True, 2 if 0x66 in prefixes else 4
        elif op in (0xf6, 0xf7):
            modrm = True
        else:
            raise ValueError(f'unsupported opcode {op:#x}')
        if modrm:
            modrm_byte = buf[p]
            p += 1
            mod, reg, rm = modrm_byte >> 6, (modrm_byte >> 3) & 7, modrm_byte & 7
            if op == 0xff and reg in (2, 4):
                kind = 'indirect-call' if reg == 2 else 'indirect-jump'
            if op in (0xf6, 0xf7) and reg == 0:
                immediate = 1 if op == 0xf6 else (2 if 0x66 in prefixes else 4)
            if mod != 3 and rm == 4:
                sib = buf[p]
                p += 1
                if mod == 0 and sib & 7 == 5:
                    p += 4
            elif mod == 0 and rm == 5:
                rip_pos = p
                p += 4
            if mod == 1:
                p += 1
            elif mod == 2:
                p += 4
        end = p + immediate
        require(end <= len(buf) and end - start <= 15, 'truncated or oversized instruction')
        row = {'size': end - start, 'kind': kind}
        if relative_pos is not None:
            row['relative'] = end + int.from_bytes(buf[relative_pos:end], 'little', signed=True)
            row['rel_field'] = (relative_pos - start, immediate)
        if rip_pos is not None:
            row['rip'] = end + struct.unpack_from('<i', buf, rip_pos)[0]
            row['rip_field'] = (rip_pos - start, 4)
        if kind == 'jcc':
            row['condition'] = (op2 if op == 0x0f else op) & 15
        return row
    except (IndexError, struct.error) as exc:
        raise ValueError('truncated instruction') from exc


def walk(raw):
    rows, pos = [], 0
    while pos < len(raw):
        try:
            item = decode_one(raw, pos)
        except ValueError as exc:
            raise ValueError(f'instruction at offset {pos:#x}: {exc}') from exc
        rows.append((pos, item))
        pos += item['size']
    bounds = {p for p, _ in rows}
    for _, item in rows:
        dest = item.get('relative')
        if dest is not None and 0 <= dest < len(raw):
            require(dest in bounds, 'local branch enters the middle of an instruction')
    return rows


def prove_tagged_returns(raw, base, store_offset, tail):
    """Check normal local returns must pass a byte-pinned tag-store epilogue.

    Direct calls are assumed to return normally, conditional edges take both
    alternatives, and traps terminate. Exception edges are reported separately.
    This is not a CPU emulator or a proof of external callees.
    """
    require(raw[store_offset:store_offset + len(tail)] == tail, 'tagged return epilogue changed')
    instructions = dict(walk(raw))
    todo, visited, returns = [(0, False)], set(), set()
    while todo:
        pos, tagged = todo.pop()
        if (pos, tagged) in visited:
            continue
        visited.add((pos, tagged))
        require(pos in instructions, 'control flow escapes or enters an instruction')
        item = instructions[pos]
        if pos == store_offset:
            tagged = True
        kind = item['kind']
        if kind == 'return':
            require(tagged, 'normal return bypasses tag store')
            returns.add(base + pos)
            continue
        if kind in ('trap', 'int3'):
            continue
        require(kind != 'indirect-jump', 'unresolved indirect jump in return proof')
        if kind in ('jump', 'jcc'):
            require('relative' in item, 'branch lacks a direct target')
            todo.append((item['relative'], tagged))
        if kind != 'jump':
            todo.append((pos + item['size'], tagged))
    require(returns, 'no normal return reachable')
    return {'entry_va': hx(base), 'store_va': hx(base + store_offset),
            'return_vas': [hx(x) for x in sorted(returns)],
            'visited_state_count': len(visited),
            'assumption': 'direct and indirect calls return normally; unwind and callee effects are not modeled'}


def selected_fdes(fdes, index, starts):
    by_start = {}
    for f in fdes:
        if f['start'] in starts:
            require(f['start'] not in by_start, 'duplicate selected FDE')
            by_start[f['start']] = f
    for start, end in starts.items():
        require(start in by_start and by_start[start]['end'] == end, 'missing or unexpected FDE')
        matches = [r for r in index if r['start'] == start]
        require(len(matches) == 1 and matches[0]['fde'] == by_start[start]['fde'],
                'unwind index does not uniquely reference selected FDE')
    return by_start


def record_bytes(data, secs, va):
    length = struct.unpack('<I', read_va(data, secs, va, 4))[0]
    require(0 < length < 0xffffffff, 'unsupported unwind record length')
    return read_va(data, secs, va, length + 4)


def parse_lsda(data, secs, fde):
    if fde['lsda'] is None:
        return None
    sec = named_section(secs, '.gcc_except_table')
    va = fde['lsda']
    off = offset_for(secs, va, 1)
    end = sec['offset'] + sec['size']
    require(sec['offset'] <= off < end and off + 2 <= end, 'LSDA outside section')
    require(data[off] == 0xff, 'unsupported LPStart encoding')
    typ, pos = data[off + 1], off + 2
    type_table = None
    if typ == 0x9b:
        delta, pos = uleb(data, pos, end)
        type_table = pos + delta
        require(type_table <= end, 'LSDA type table outside section')
    else:
        require(typ == 0xff, 'unsupported LSDA type encoding')
    require(pos < end and data[pos] == 1, 'unsupported LSDA call-site encoding')
    size, pos = uleb(data, pos + 1, end)
    stop = pos + size
    require(stop <= end and (type_table is None or stop <= type_table), 'invalid LSDA table size')
    head_end, previous, entries = pos, 0, []
    while pos < stop:
        first = pos
        start, pos = uleb(data, pos, stop)
        length, pos = uleb(data, pos, stop)
        landing, pos = uleb(data, pos, stop)
        action, pos = uleb(data, pos, stop)
        require(start >= previous and start + length <= fde['end'] - fde['start'], 'invalid LSDA call-site range')
        require(landing == 0 or landing < fde['end'] - fde['start'], 'invalid LSDA landing')
        previous = start + length
        entries.append({'start': fde['start'] + start, 'end': fde['start'] + start + length,
                        'landing': fde['start'] + landing if landing else None,
                        'action': action, 'raw': data[first:pos].hex()})
    return {'va': va, 'file_offset': off, 'header': data[off:head_end].hex(),
            'table': data[head_end:stop].hex(), 'entries': entries}


def get_relocations(data, secs):
    result = {}
    for name in ('.rela.dyn', '.rela.plt'):
        sec = named_section(secs, name)
        require(sec['size'] % 24 == 0, 'invalid RELA section length')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            require(slot not in result, 'duplicate relocation slot')
            result[slot] = {'slot': slot, 'info': info, 'addend': addend,
                            'entry_offset': off, 'raw': data[off:off + 24].hex()}
    return result


def symbol_name(data, secs, index):
    if index == 0:
        return ''
    sym = named_section(secs, '.dynsym')
    strings = named_section(secs, '.dynstr')
    require(index * 24 + 24 <= sym['size'], 'dynamic symbol outside table')
    name = struct.unpack_from('<I', data, sym['offset'] + index * 24)[0]
    require(name < strings['size'], 'dynamic symbol name outside table')
    begin = strings['offset'] + name
    end = data.find(b'\0', begin, strings['offset'] + strings['size'])
    require(end >= begin, 'unterminated dynamic symbol name')
    return data[begin:end].decode('ascii')


def relative_relocation(relocs, slot, addend):
    row = relocs.get(slot)
    require(row is not None and row['info'] == 8 and row['addend'] == addend,
            f'incorrect relative relocation at {slot:#x}')
    return row


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii')


def tsv_bytes(header, rows):
    buffer = io.StringIO(newline='')
    writer = csv.writer(buffer, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return buffer.getvalue().encode('ascii')


def hx(value):
    return '' if value is None else hex(value)


def relative_table(data, secs, bounds, table_base, expected):
    """Decode reviewed signed table entries and reject altered destinations."""
    rows = []
    for i, expected_dest in enumerate(expected):
        raw = read_va(data, secs, table_base + i * 4, 4)
        dest = table_base + struct.unpack('<i', raw)[0]
        require(dest in bounds and dest == expected_dest, 'relative table destination changed')
        rows.append([i, hx(table_base + i * 4), raw.hex(), hx(dest)])
    return rows


def cleanup_table(data, secs, bounds):
    return relative_table(data, secs, bounds, 0x7c353c,
                          (0x4e6ed17, 0x4e6ed34, 0x4e6ed6b, 0x4e6ed17))

# Branch annotations describe the selected edge; the complete transfer ledger
# is independently decoded from every selected FDE byte.
BRANCH_NOTES = {
    0x4e6f3b2: 'account entry is already present',
    0x4e6f42c: 'process words require initialization',
    0x4e6f4bd: 'no available control in current group',
    0x4e6f4d9: 'candidate control is occupied',
    0x4e6f556: 'address-set hit skips journal append',
    0x4e6f55f: 'journal frame absent reaches failure',
    0x4e6f57b: 'journal vector has spare capacity',
    0x4e6f5c8: 'account flag bit requires clearing and journal',
    0x4e6f5f5: 'journal frame present after flag clear',
    0x4e6fd69: 'non-five account result is copied out',
    0x4e6fd7d: 'code tag is already different from four',
    0x4e6fdac: 'both hash halves match the constants',
    0x4e6fdc9: 'old code tag still equals four',
    0x4e6fe45: 'old code tag still equals four',
    0x4e6c8d6: 'one-byte allocation returned null',
    0x4e6c94c: 'byte buffer is full before append',
    0x4e6c95d: 'iterator state uses alternate form',
    0x4e6c970: 'iterator has a pending endpoint',
    0x4e6c97a: 'iterator full-byte remainder is empty',
    0x4e6c9ad: 'iterator is exhausted',
    0x4e6c9ff: 'shared-object allocation returned null',
    0x4e6ca8d: 'temporary allocation has zero capacity',
    0x4e6cac5: 'code representation tag is zero',
    0x4e6cb0e: 'input length plus padding overflows unsigned width',
    0x4e6cb1b: 'padded allocation length is nonnegative as signed',
    0x4e6cb3e: 'padded-buffer allocation returned null',
    0x4e6cbe7: 'old code representation tag is zero',
    0x4e6ed55: 'tag-one reference count remains nonzero',
    0x4e6ed76: 'tag-two reference count remains nonzero',
    0x4e6ed98: 'unwind reference count remains nonzero',
    0x4e736cc: 'tag-two increment sets the signed less-or-equal condition',
    0x4e7376e: 'tag-one increment sets the signed less-or-equal condition',
    0x4e7c51e: 'journal-entry growth helper returned an error tag',
    0x4e7c58e: 'journal-frame growth helper returned an error tag',
    0x4e7c605: 'allocation arithmetic is within its size bound',
    0x4e7c617: 'old vector capacity is zero',
    0x4e7c67b: 'allocation or reallocation returned nonnull',
    0x4e7c6ca: 'requested byte length addition carried',
    0x4e7c718: 'byte-vector allocation helper returned an error tag',
    0x4e7d274: 'iterator byte length is zero',
    0x4e7d27c: 'iterator bit count equals eight',
    0x4e7d27e: 'iterator bit count is greater than eight',
    0x4e88ae6: 'fallback wrapper allocation returned null',
    0x4e8cd75: 'account table has no occupied entries',
    0x4e8ce50: 'account fingerprint candidate matches all key bytes',
    0x4e8ce6c: 'an empty control terminates the account lookup',
    0x4e8fa73: 'tag-two fallback input has no required field',
    0x4e8fadc: 'fallback interpreter allocation returned null',
}


def code_decision(result_tag, code_tag, value, expected):
    """Instruction-derived branch model; inputs are synthetic, not guest memory."""
    require(0 <= result_tag <= 0xff and 0 <= code_tag <= 0xffffffff, 'invalid tag width')
    require(len(value) == len(expected) == 32, 'code hashes must be 32 bytes')
    if result_tag != 5:
        return 'forward-result'
    if code_tag != 4:
        return 'retain-code'
    return 'default-equal-hash' if value == expected else 'default-other-hash'


def account_decision(present, flag, set_hit, frame_count, journal_length, journal_capacity):
    """Project selected state-change ordering for explicit synthetic inputs."""
    require(isinstance(present, bool) and isinstance(set_hit, bool), 'invalid boolean')
    require(0 <= flag <= 0xff, 'invalid account flag')
    require(all(0 <= x <= MASK64 for x in (frame_count, journal_length, journal_capacity)), 'invalid count')
    actions = []
    if present:
        if not flag & 0x10:
            return ['return-tag5-byte0']
        actions.append('clear-flag-0x10')
    else:
        actions.append('insert-account')
        if set_hit:
            return actions + ['return-tag5-byte0']
    if frame_count == 0:
        return actions + ['missing-frame-boundary']
    if journal_length == journal_capacity:
        actions.append('reserve-journal')
    return actions + ['append-tag0-and-key', 'increment-journal-length', 'return-tag5-byte1']


def vector_growth(capacity):
    """Model the unsigned machine operation for the two selected vector helpers."""
    require(0 <= capacity <= MASK64, 'invalid capacity')
    doubled = (capacity * 2) & MASK64
    return max(4, doubled)


def checked_allocation(count, stride, alignment):
    """Model the checked multiply in the selected allocator for valid alignments."""
    require(0 <= count <= MASK64 and 0 < stride <= MASK64, 'invalid allocation input')
    require(0 < alignment <= MASK64 and alignment & (alignment - 1) == 0, 'alignment is not a power of two')
    require(stride + alignment - 1 <= MASK64, 'alignment addition is outside modeled input domain')
    padded = (stride + alignment - 1) & -alignment
    product = padded * count
    if product > MASK64 or product > (1 << 63) - alignment:
        return None
    return product


def fallback_padding(length):
    """Return the padded size or the observed guard class for a synthetic length."""
    require(0 <= length <= MASK64, 'invalid input length')
    if length > MASK64 - 33:
        return 'unsigned-overflow'
    size = length + 33
    if size >= 1 << 63:
        return 'signed-size-failure'
    return size


def increment_jle(value):
    """Project x86 INC flags followed immediately by JLE for a synthetic u64."""
    require(0 <= value <= MASK64, 'invalid counter')
    after = (value + 1) & MASK64
    zero = after == 0
    sign = bool(after & (1 << 63))
    overflow = value == (1 << 63) - 1
    return after, zero or sign != overflow


def collect(data):
    verify_digest(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    queries = {start: end for start, (end, _) in FUNCTIONS.items()}
    selected = selected_fdes(fdes, index, queries)
    relocs = get_relocations(data, secs)
    functions, bodies, instruction_rows, edges, references = [], [], [], [], []
    decoded = {}
    all_instructions = {}
    used_relocs = set()
    frames = []
    exception_rows = []
    for start in sorted(FUNCTIONS):
        end, role = FUNCTIONS[start]
        fde = selected[start]
        raw = read_va(data, secs, start, end - start, True)
        decoded[start] = walk(raw)
        offsets = {off for off, _ in decoded[start]}
        for off, item in decoded[start]:
            va = start + off
            all_instructions[va] = item
            ins = raw[off:off + item['size']]
            direct = start + item['relative'] if 'relative' in item else None
            rip = start + item['rip'] if 'rip' in item else None
            cond = item.get('condition')
            instruction_rows.append([hx(start), hx(va), len(ins), ins.hex(), item['kind'], hx(direct), hx(rip), hx(cond)])
            if item['kind'] != 'plain':
                edges.append([hx(start), hx(va), item['kind'], hx(cond), hx(va + len(ins)),
                              hx(direct), hx(rip), ins.hex()])
            if rip is not None:
                rel = relocs.get(rip)
                if rel:
                    used_relocs.add(rip)
                references.append([hx(start), hx(va), ins.hex(), hx(rip),
                                   hx(rel['info']) if rel else '', hx(rel['addend']) if rel else '',
                                   symbol_name(data, secs, rel['info'] >> 32) if rel else ''])
        lsda = parse_lsda(data, secs, fde)
        if lsda:
            for ent in lsda['entries']:
                if ent['landing'] is not None:
                    require(ent['landing'] - start in offsets, 'LSDA landing is not an instruction boundary')
                exception_rows.append([hx(start), hx(ent['start']), hx(ent['end']),
                                       hx(ent['landing']), ent['action'], ent['raw']])
        frames.append({'start': hx(start), 'fde_va': hx(fde['fde']), 'cie_va': hx(fde['cie']),
                       'fde_record': record_bytes(data, secs, fde['fde']).hex(),
                       'cie_record': record_bytes(data, secs, fde['cie']).hex(),
                       'lsda': None if lsda is None else {
                           'va': hx(lsda['va']), 'file_offset': hx(lsda['file_offset']),
                           'header': lsda['header'], 'table': lsda['table']}})
        digest = hashlib.sha256(raw).hexdigest()
        functions.append([hx(start), hx(end), len(raw), hx(offset_for(secs, start, len(raw), True)),
                          hx(fde['fde']), hx(fde['cie']), hx(fde['lsda']), digest, len(decoded[start]), role])
        bodies.append({'start': hx(start), 'end': hx(end), 'sha256': digest, 'bytes': raw.hex()})
    boundaries = set(all_instructions)
    for start in FUNCTIONS:
        boundaries.add(FUNCTIONS[start][0])
    window_rows = []
    for start, end, label in WINDOWS:
        require(start in boundaries and end in boundaries and start < end, 'window endpoint is not an instruction boundary')
        require(any(f <= start < end <= FUNCTIONS[f][0] for f in FUNCTIONS), 'window crosses selected FDE')
        window_rows.append([hx(start), hx(end), read_va(data, secs, start, end - start, True).hex(), label])
    pin_rows = []
    values = {}
    for va, encoded, pos, width, label in PINS:
        expected = bytes.fromhex(encoded)
        raw = checked_pin(data, secs, va, expected)
        require(va in all_instructions and all_instructions[va]['size'] == len(raw), 'pin is not a complete instruction')
        value = int.from_bytes(raw[pos:pos + width], 'little') if pos is not None else None
        if pos is not None:
            require(pos + width <= len(raw), 'pin operand outside instruction')
            values[label] = value
        pin_rows.append([hx(va), raw.hex(), '' if pos is None else pos, width, hx(value), label])
    branch_rows = []
    for va, label in sorted(BRANCH_NOTES.items()):
        require(va in all_instructions and all_instructions[va]['kind'] == 'jcc', 'annotated branch missing')
        item = all_instructions[va]
        size = item['size']
        owner = next(start for start in FUNCTIONS if start <= va < FUNCTIONS[start][0])
        branch_rows.append([hx(va), read_va(data, secs, va, size, True).hex(),
                            hx(item['condition']), hx(owner + item['relative']), hx(va + size), label])
    anchors = []
    anchor_targets = {0x4e6ff83: 0x4e6fd50, 0x4e6ffd0: 0x4e6f360,
                      0x4e70096: 0x4e8cfd0, 0x4e707b9: 0x4e6fd50,
                      0x4e70fb6: 0x4e73680, 0x4e711c0: 0x4e6cc70,
                      0x4e79c64: 0x4e8cd70}
    for va, encoded, label in ANCHORS:
        raw = checked_pin(data, secs, va, bytes.fromhex(encoded))
        item = decode_one(raw, 0)
        require(item['size'] == len(raw), 'prior boundary is not a complete instruction')
        target = va + item['relative'] if 'relative' in item else None
        rip = va + item['rip'] if 'rip' in item else None
        if va in anchor_targets:
            require(target == anchor_targets[va], 'prior direct call target changed')
        if rip in relocs:
            used_relocs.add(rip)
        anchors.append([hx(va), raw.hex(), item['kind'], hx(target), hx(rip), label])
    relative_relocation(relocs, 0x5774e28, 0x4e7c550)
    relative_relocation(relocs, 0x5774e30, 0x4ea2df0)
    relative_relocation(relocs, 0x5773270, 0x4e7c4e0)
    relative_relocation(relocs, 0x5773268, 0x4ea53c0)
    relative_relocation(relocs, 0x574fbc0, 0x202e90)
    relative_relocation(relocs, 0x5774e40, 0x4e8fa30)
    relative_relocation(relocs, 0x5774e48, 0x4e88a90)
    relative_relocation(relocs, 0x574f0b0, 0x4e9d2a0)
    used_relocs.update((0x5774e28, 0x5773270, 0x5773268, 0x574f0b0))
    relocation_rows = []
    for slot in sorted(used_relocs):
        rel = relocs[slot]
        relocation_rows.append([hx(slot), hx(rel['info']), hx(rel['addend']), hx(rel['entry_offset']),
                                rel['raw'], symbol_name(data, secs, rel['info'] >> 32)])
    require(all_instructions[0x4e6ed15]['kind'] == 'indirect-jump', 'code cleanup dispatch changed')
    table_rows = cleanup_table(data, secs, boundaries)
    require(all_instructions[0x4e7369c]['kind'] == 'indirect-jump', 'code clone dispatch changed')
    clone_rows = relative_table(data, secs, boundaries, 0x7c358c,
                                (0x4e7369e, 0x4e73744, 0x4e736c4, 0x4e736e6))
    require(all_instructions[0x4e8fa5f]['kind'] == 'indirect-jump', 'fallback input dispatch changed')
    fallback_rows = relative_table(data, secs, boundaries, 0x7c47c8,
                                   (0x4e8fbfe, 0x4e8fa61, 0x4e8fa67, 0x4e8fa61))
    first_half = read_va(data, secs, 0x206160, 16)
    second_half = read_va(data, secs, 0x204be0, 16)
    require(first_half.hex() == 'c5d2460186f7233c927e7db2dcc703c0', 'first code-hash constant changed')
    require(second_half.hex() == 'e500b653ca82273b7bfad8045d85a470', 'second code-hash constant changed')
    default_byte = read_va(data, secs, 0x1e629b, 1)
    empty_controls = read_va(data, secs, 0x202e90, 16)
    require(default_byte == b'\0' and empty_controls == b'\xff' * 16, 'default code or table data changed')
    raw_record = read_va(data, secs, 0x574f0a8, 48)
    require(raw_record[24:44] == bytes(19) + b'\x09', 'prior address record changed')
    prior_object = {'record_va': hx(0x574f0a8), 'record_file_offset': hx(offset_for(secs, 0x574f0a8, 48)),
                    'record_bytes': raw_record.hex(), 'key_offset': 24, 'key_bytes': raw_record[24:44].hex(),
                    'callback_slot': hx(0x574f0b0), 'relocation_addend': hx(relocs[0x574f0b0]['addend']),
                    'linkage': 'earlier-owned data anchor; source record is not a newly selected FDE'}
    account_body = read_va(data, secs, 0x4e6f360, FUNCTIONS[0x4e6f360][0] - 0x4e6f360, True)
    return_proof = prove_tagged_returns(account_body, 0x4e6f360, 0x273,
                                       bytes.fromhex('c603054881c4980100005b415c415d415e415f5dc3'))
    summary = {
        'target': 'node94', 'sha256': SHA256, 'coordinate_system': 'linked ELF virtual addresses before load bias',
        'selected_fde_count': len(functions), 'selected_body_bytes': sum(row[2] for row in functions),
        'instruction_count': len(instruction_rows), 'control_transfer_count': len(edges),
        'annotated_branch_count': len(branch_rows), 'semantic_window_count': len(window_rows),
        'selected_pin_count': len(pin_rows), 'rip_reference_count': len(references),
        'relocation_count': len(relocation_rows), 'lsda_call_site_count': len(exception_rows),
        'cleanup_table_count': len(table_rows), 'prior_boundary_count': len(anchors),
        'clone_table_count': len(clone_rows), 'fallback_table_count': len(fallback_rows),
        'empty_code_hash': (first_half + second_half).hex(),
        'empty_code_hash_first_va': hx(0x206160), 'empty_code_hash_second_va': hx(0x204be0),
        'default_code_byte_va': hx(0x1e629b), 'default_code_byte': default_byte.hex(),
        'empty_controls_va': hx(0x202e90), 'empty_controls_bytes': empty_controls.hex(),
        'evidence_only': True, 'captured_execution': False, 'component_gate_requested': False,
        'notes': ['FDE ranges are unwind-described extents, not whole-node coverage.',
                  'Semantic labels, code identity and prior-packet composition are inferred.',
                  'Dynamic callbacks, seed initialization, allocator internals, LSDA actions and runtime state remain open.'],
    }
    files = {
        'functions.tsv': tsv_bytes(['start_va', 'end_va', 'bytes', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'sha256', 'instructions', 'inferred_role'], functions),
        'function-bytes.json': json_bytes(bodies),
        'instructions.tsv': tsv_bytes(['function_va', 'site_va', 'length', 'bytes', 'kind', 'target_va', 'rip_va', 'condition'], instruction_rows),
        'transfers.tsv': tsv_bytes(['function_va', 'site_va', 'kind', 'condition', 'next_va', 'target_va', 'rip_slot_va', 'bytes'], edges),
        'rip-references.tsv': tsv_bytes(['function_va', 'site_va', 'bytes', 'target_va', 'relocation_info', 'addend', 'symbol'], references),
        'relocations.tsv': tsv_bytes(['slot_va', 'info', 'addend', 'entry_file_offset', 'raw', 'dynamic_symbol'], relocation_rows),
        'semantic-windows.tsv': tsv_bytes(['start_va', 'end_va', 'bytes', 'interpretation'], window_rows),
        'byte-predicates.tsv': tsv_bytes(['site_va', 'bytes', 'operand_offset', 'operand_width', 'operand_value', 'interpretation'], pin_rows),
        'branch-decisions.tsv': tsv_bytes(['site_va', 'bytes', 'condition', 'taken_va', 'fallthrough_va', 'interpretation'], branch_rows),
        'prior-boundaries.tsv': tsv_bytes(['site_va', 'bytes', 'kind', 'direct_target_va', 'rip_va', 'prior_boundary'], anchors),
        'exception-sites.tsv': tsv_bytes(['function_va', 'start_va', 'end_va', 'landing_va', 'action', 'raw'], exception_rows),
        'unwind.json': json_bytes(frames),
        'cleanup-table.tsv': tsv_bytes(['tag', 'entry_va', 'raw', 'target_va'], table_rows),
        'clone-table.tsv': tsv_bytes(['tag', 'entry_va', 'raw', 'target_va'], clone_rows),
        'fallback-table.tsv': tsv_bytes(['tag', 'entry_va', 'raw', 'target_va'], fallback_rows),
        'prior-object.json': json_bytes(prior_object),
        'normal-return-proof.json': json_bytes(return_proof),
        'summary.json': json_bytes(summary),
    }
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    data = TARGET.read_bytes()
    files = collect(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (args.out / name).write_bytes(files[name])


if __name__ == '__main__':
    main()
