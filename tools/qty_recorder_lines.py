#!/usr/bin/env python3
"""RE-004: what each overflow recorder Location of l1/src/qtys does in node #94 (static).

Ten Rust Location lines sit in l1/src/qtys/mod.rs (827..=831) and impl_ntl.rs (6, 16, 26, 62,
664), and every record of them has column 1.  The code passes one of them to the overflow
recorder, which returns, and goes on with a saturated value.

The tool binds each lea of those records to the recorder calls it feeds with a forward walk,
because the compiler hoists the lea out of loops and rebuilds it after a call.  Then it reads
every conditional edge into each call.  Registers and memory start as free values, so no operand
is sampled and a proof holds for all operand pairs.  Flags stay as the operation and operands
that set them, and a condition met once on a path settles a later cmov on the same operands.

A guard passes when its overflow edge reaches the bound recorder call and some location holds
the wrapped result L on the other edge and a saturated value on the overflow edge, compared at a
common address, or at the end of the overflow path when the two edges share none:

    unsigned add   u64::MAX       unsigned sub   0
    signed         (L >>s 63) ^ i64::MIN, or i64::MAX + (L >= 0), or a one-sided constant

`saturation_lemma` shows the two computed signed forms are the saturated result whenever the
signed operation overflowed.  Functions named by other work items are left out and listed, and
guards the walk cannot settle are listed with the reason.  The line table, the co-occurrence
counts and the record neighbours come from relocations and lea bytes only.

    python3 tools/qty_recorder_lines.py --out <dir>

writes evidence.json, line-table.tsv, sites.tsv, cooccurrence.tsv, record-neighbours.tsv,
excluded-functions.tsv, unresolved.tsv and mutation-controls.tsv.  Only the Python standard
library is used; objdump is not.  Nothing from the binary runs.
"""

import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import elf_index  # noqa: E402
import fde_extents  # noqa: E402

BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64 = (1 << 64) - 1
I64_MIN = 1 << 63
I64_MAX = I64_MIN - 1

PATH_PART = b'/l1/src/qtys/'
LINES = (('impl_ntl.rs', 6), ('impl_ntl.rs', 16), ('impl_ntl.rs', 26), ('impl_ntl.rs', 62), ('impl_ntl.rs', 664),
         ('mod.rs', 827), ('mod.rs', 828), ('mod.rs', 829), ('mod.rs', 830), ('mod.rs', 831))
# Already pinned by other work items: lines used here only as named partners in the counts.
PARTNERS = (('impl_sz.rs', 9), ('impl_sz.rs', 35), ('impl_wei.rs', 6), ('impl_ntl.rs', 665))
RECORDER_SLOT, RECORDER = 0x5773190, 0x358dcd0

# Functions named by other work items, open pull requests or pending packets.
EXCLUDED_FUNCTIONS = {
    0x232e5a0: 'RE-004-sz-saturating-sites-94',
    0x232e6e0: 'RE-004-sz-saturating-sites-94',
    0x2355f40: 'RE-004-adl-shortfall-budget-94',
    0x24bbee0: 'fees-open-order-cap-94',
    0x24bda40: 'dex-registry-inventory-94',
    0x26b2180: 'fees-schedule-cancel-gate-94',
    0x26b5f30: 'RE-012-info-request-path',
    0x26b93b0: 'dex-registry-inventory-94',
    0x26d2560: 'RE-004-wei-saturating-ops-94',
    0x26e81c0: 'RE-001-cumulative-minute-94',
    0x26ebdc0: 'RE-004-px-tick-ladder-94',
    0x26f7ef0: 'dex-registry-inventory-94',
    0x26f9b70: 'dex-registry-inventory-94',
    0x26fbab0: 'fees-schedule-cancel-gate-94',
    0x26fe810: 'dex-registry-inventory-94',
    0x26ff460: 'RE-001-cumulative-minute-94',
    0x2700390: 'RE-001-cumulative-minute-94',
    0x2702330: 'RE-004-adl-shortfall-budget-94',
    0x27078a0: 'RE-004-wei-saturating-ops-94',
    0x270f6f0: 'RE-004-ntl-ten-thousand-add-94',
    0x2711440: 'RE-004-ntl-ten-thousand-add-94',
    0x27123d0: 'RE-004-ntl-ten-thousand-add-94',
    0x2715320: 'RE-004-spot-wei-scale-family-94',
    0x2716f90: 'RE-004-ntl-ten-thousand-add-94',
    0x271a1d0: 'RE-004-wei-saturating-ops-94',
    0x271b220: 'dex-registry-inventory-94',
    0x271bb40: 'fees-open-order-cap-94',
    0x271dfe0: 'pending packet',
    0x2721260: 'RE-010-exchange-handlers',
    0x2725150: 'RE-010-exchange-handlers',
    0x2727f30: 'dex-registry-inventory-94',
    0x272d000: 'RE-004-wei-saturating-ops-94',
    0x272fb00: 'RE-004-wei-saturating-ops-94',
    0x2735040: 'RE-004-ntl-ten-thousand-add-94',
    0x27371f0: 'RE-004-px-tick-ladder-94',
    0x2739d70: 'RE-004-wei-saturating-ops-94',
    0x27462e0: 'dex-registry-inventory-94',
    0x2748310: 'RE-004-decimal-scaled-u64-94',
    0x2752880: 'RE-004-wei-saturating-ops-94',
    0x2753010: 'RE-004-wei-saturating-ops-94',
    0x2754690: 'RE-004-wei-saturating-ops-94',
    0x2758800: 'RE-010-exchange-handlers',
    0x275f500: 'fees-schedule-cancel-gate-94',
    0x2760a70: 'RE-001-bucket-guard-94',
    0x2761b20: 'l1-evm-inventory-94',
    0x2768170: 'pending packet',
    0x2773bb0: 'fees-schedule-cancel-gate-94',
    0x28d4700: 'RE-004-wei-saturating-ops-94',
    0x28d56c0: 'RE-004-wei-saturating-ops-94',
    0x28d6ee0: 'RE-004-wei-saturating-ops-94',
    0x2a22bc0: 'clearinghouse-oracle-inventory-94',
    0x3333670: 'RE-007-margin-path-94',
    0x3333800: 'RE-007-margin-path-94',
    0x3335590: 'RE-007-margin-path-94',
    0x33709f0: 'RE-004-wei-saturating-ops-94',
    0x36e2d90: 'pending packet',
    0x36f5d40: 'clearinghouse-oracle-inventory-94',
    0x36f61e0: 'RE-004-sz-saturating-sites-94',
    0x36f7350: 'RE-004-sz-saturating-sites-94',
    0x36f7c40: 'RE-004-adl-shortfall-budget-94',
    0x36fe830: 'clearinghouse-oracle-inventory-94',
    0x36ff4f0: 'vault-guard-94',
    0x36fff10: 'RE-004-adl-shortfall-budget-94',
    0x37067b0: 'pending packet',
    0x3707c20: 'RE-004-sz-saturating-sites-94',
    0x3708bf0: 'RE-004-sz-saturating-sites-94',
    0x3709560: 'RE-010-exchange-handlers',
    0x370afd0: 'RE-004-sz-saturating-sites-94',
    0x370e2a0: 'RE-004-sz-saturating-sites-94',
    0x370ea50: 'RE-004-sz-saturating-sites-94',
    0x370ee20: 'RE-004-sz-saturating-sites-94',
    0x3710a70: 'RE-004-sz-saturating-sites-94',
    0x3711d00: 'RE-004-sz-saturating-sites-94',
    0x37128e0: 'RE-004-sz-saturating-sites-94',
    0x37130b0: 'RE-006-match-resting-order-94',
    0x37153f0: 'fees-compute-94',
    0x3717480: 'RE-007-margin-path-94',
    0x37179d0: 'RE-004-sz-saturating-sites-94',
    0x37198a0: 'RE-004-wei-saturating-ops-94',
    0x371a970: 'RE-004-wei-saturating-ops-94',
    0x371d120: 'RE-004-wei-saturating-ops-94',
    0x3720200: 'RE-004-wei-saturating-ops-94',
    0x3721780: 'RE-004-wei-saturating-ops-94',
    0x372b9d0: 'RE-004-wei-saturating-ops-94',
    0x372e0a0: 'RE-004-wei-saturating-ops-94',
    0x372faa0: 'fees-spot-volume-94',
    0x3736bd0: 'RE-004-adl-shortfall-budget-94',
    0x3742070: 'pending packet',
    0x3742460: 'pending packet',
    0x3743020: 'pending packet',
    0x3744eb0: 'RE-010-exchange-handlers',
    0x3745a60: 'RE-004-wei-saturating-ops-94',
    0x3757150: 'RE-004-wei-saturating-ops-94',
    0x3757610: 'clearinghouse-oracle-inventory-94',
    0x37615c0: 'clearinghouse-oracle-inventory-94',
    0x37d7360: 'RE-007-margin-path-94',
    0x37d77e0: 'RE-004-adl-shortfall-budget-94',
    0x37d79e0: 'RE-007-margin-path-94',
    0x37d7f10: 'clearinghouse-oracle-inventory-94',
    0x3955e80: 'vault-guard-94',
    0x39590f0: 'RE-004-decimal-scaled-u64-94',
    0x395a2c0: 'vault-guard-94',
    0x395b3a0: 'vault-guard-94',
    0x3bd1220: 'clearinghouse-oracle-inventory-94',
    0x3be5630: 'RE-004-wei-saturating-ops-94',
    0x3bfcdc0: 'RE-006-match-resting-order-94',
    0x3c0e8b0: 'RE-004-wei-saturating-ops-94',
    0x3c0f6e0: 'RE-004-wei-saturating-ops-94',
    0x42e85c0: 'RE-006-price-level-lifecycle-94',
    0x42ed300: 'dex-registry-inventory-94',
    0x42edcf0: 'dex-registry-inventory-94',
    0x42fc790: 'RE-006-top-order-clone-94',
    0x42fd530: 'RE-006-top-order-clone-94',
    0x42ff010: 'RE-004-px-tick-ladder-94',
    0x4300950: 'RE-004-px-tick-ladder-94',
    0x430d610: 'RE-001-cumulative-minute-94',
    0x4311140: 'RE-004-px-tick-ladder-94',
    0x4314da0: 'RE-004-px-tick-ladder-94',
    0x4318a00: 'RE-001-cumulative-minute-94',
    0x4447960: 'dex-registry-inventory-94',
    0x44495c0: 'dex-registry-inventory-94',
    0x444a3b0: 'fees-open-order-cap-94',
    0x444abf0: 'fees-open-order-cap-94',
    0x445d4a0: 'RE-004-wei-saturating-ops-94',
    0x445f870: 'RE-004-wei-saturating-ops-94',
    0x44612d0: 'RE-004-wei-saturating-ops-94',
    0x44709c0: 'RE-001-cumulative-minute-94',
    0x46e8290: 'RE-004-ntl-ten-thousand-add-94',
    0x46e89a0: 'RE-004-ntl-ten-thousand-add-94',
    0x46e93e0: 'dex-registry-inventory-94',
    0x46ea0b0: 'RE-004-wei-saturating-ops-94',
    0x46eaa10: 'RE-004-wei-saturating-ops-94',
    0x46f7560: 'RE-004-wei-saturating-ops-94',
    0x46f8400: 'RE-004-wei-saturating-ops-94',
    0x48ce500: 'RE-004-wei-saturating-ops-94',
    0x49e4de0: 'RE-004-sz-saturating-sites-94',
    0x49e4f20: 'RE-004-sz-saturating-sites-94',
    0x4caa870: 'RE-004-adl-shortfall-budget-94',
    0x4cb3200: 'RE-004-adl-shortfall-budget-94',
    0x4cdd580: 'RE-006-order-relation-transitions-94',
    0x4cde380: 'RE-006-order-relation-transitions-94',
    0x4ce19c0: 'fees-schedule-cancel-gate-94',
    0x4ce3360: 'fees-schedule-cancel-gate-94',
    0x4ce76a0: 'dex-registry-inventory-94',
    0x4ce7b90: 'dex-registry-inventory-94',
    0x4ce8b40: 'RE-001-cumulative-minute-94',
    0x4ce9670: 'RE-001-cumulative-minute-94',
    0x4cea760: 'RE-001-cumulative-minute-94',
    0x4cec260: 'RE-001-cumulative-minute-94',
    0x4ceea90: 'RE-004-adl-shortfall-budget-94',
    0x4ceeb80: 'RE-004-adl-shortfall-budget-94',
    0x4cf37f0: 'RE-006-user-book-cancel-94',
    0x4cf94a0: 'RE-006-user-book-cancel-94',
    0x4d03060: 'RE-004-ntl-ten-thousand-add-94',
    0x4d036a0: 'RE-004-ntl-ten-thousand-add-94',
    0x4d04f80: 'RE-004-ntl-ten-thousand-add-94',
    0x4d055f0: 'RE-004-ntl-ten-thousand-add-94',
    0x4d0a6d0: 'RE-004-spot-wei-scale-family-94',
    0x4d0bfa0: 'RE-004-spot-wei-scale-family-94',
    0x4d0dff0: 'RE-004-ntl-ten-thousand-add-94',
    0x4d0e820: 'RE-004-ntl-ten-thousand-add-94',
    0x4d19d40: 'dex-registry-inventory-94',
    0x4d1a670: 'dex-registry-inventory-94',
    0x4d1afa0: 'fees-open-order-cap-94',
    0x4d1b8b0: 'fees-open-order-cap-94',
    0x4d1fe20: 'pending packet',
    0x4d20570: 'pending packet',
    0x4d260c0: 'fees-schedule-cancel-gate-94',
    0x4d266c0: 'fees-schedule-cancel-gate-94',
    0x4d2b3c0: 'RE-006-user-book-cancel-94',
    0x4d2cd20: 'RE-006-user-book-cancel-94',
    0x4d2ff60: 'dex-registry-inventory-94',
    0x4d308e0: 'dex-registry-inventory-94',
    0x4d41320: 'RE-004-ntl-ten-thousand-add-94',
    0x4d45300: 'RE-004-ntl-ten-thousand-add-94',
    0x4d8bf70: 'fees-schedule-cancel-gate-94',
    0x4d8c0f0: 'fees-schedule-cancel-gate-94',
    0x4d8c610: 'RE-004-wei-saturating-ops-94',
    0x4d8d060: 'RE-004-wei-saturating-ops-94',
    0x4d8fce0: 'l1-evm-inventory-94',
    0x4d92a10: 'l1-evm-inventory-94',
    0x4d9c230: 'pending packet',
    0x4d9ce10: 'pending packet',}

STEP_LIMIT = 70
BIND_LIMIT = 6000
FORK_LIMIT = 24
BACK_LIMIT = 60
RSP, RAX, RCX, RDX, RSI, RDI = 4, 0, 1, 2, 6, 7
CALLER_SAVED = (0, 1, 2, 6, 7, 8, 9, 10, 11)
REG_NAMES = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
             'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')


class EvidenceError(Exception):
    pass


class Unsupported(Exception):
    """The instruction is outside the modelled subset, so the path ends here."""


def fail(message):
    raise EvidenceError(message)


# --- ELF image, from the shared repository parsers ------------------------------------------

class Image:
    def __init__(self, data, fdes=None, relocs=None):
        self.data = bytearray(data)
        table = elf_index.sections(data)
        self.sections = [s for s in table if s['type'] != 8 and s['address']]
        self.text = next(s for s in self.sections if s['name'] == '.text')
        if fdes is None:
            _, records = fde_extents.eh_frame_records(data, table)
            fdes = sorted((r['start'], r['end']) for r in records)
        self.fdes = fdes
        self.starts = [row[0] for row in fdes]
        self.relocs = relocs if relocs is not None else self.relative_relocations()

    def relative_relocations(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        relocs = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', self.data, pos)
            if info & 0xffffffff == 8:
                relocs[where] = addend
        return relocs

    def apply(self, edits):
        """Replace bytes in place and return the old bytes, for the negative controls."""
        saved = []
        for va, raw in edits:
            off = self.file_offset(va)
            saved.append((va, bytes(self.data[off:off + len(raw)])))
            self.data[off:off + len(raw)] = raw
        return saved

    def file_offset(self, va):
        for s in self.sections:
            if s['address'] <= va < s['address'] + s['size']:
                return va - s['address'] + s['offset']
        fail(f'address {va:#x} is outside every section with file bytes')

    def fde_of(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        if i < 0 or not self.fdes[i][0] <= va < self.fdes[i][1]:
            fail(f'{va:#x} is outside every FDE')
        return self.fdes[i]


def location_records(image):
    """Every Location record under l1/src/qtys: {record va: (file, line, column)}."""
    records = {}
    for where, target in image.relocs.items():
        try:
            off = image.file_offset(where)
            length, line, column = struct.unpack_from('<QII', image.data, off + 8)
            if not 0 < length < 300:
                continue
            start = image.file_offset(target)
            path = bytes(image.data[start:start + length])
        except (EvidenceError, struct.error):
            continue
        if PATH_PART in path:
            records[where] = (path.split(PATH_PART)[1].decode('ascii', 'replace'), line, column)
    return records


def lea_references(image, wanted):
    """Every REX.W lea r64,[rip+disp32] in .text that resolves to a wanted record."""
    base, off, size = image.text['address'], image.text['offset'], image.text['size']
    text = image.data[off:off + size]
    hits = {}
    for match in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text):
        pos = match.start()
        target = base + pos + 7 + struct.unpack_from('<i', text, pos + 3)[0]
        if target in wanted:
            hits[base + pos] = target
    return hits


# --- x86-64 length decoder ------------------------------------------------------------------

def modrm_length(data, p):
    modrm = data[p]
    mod, rm = modrm >> 6, modrm & 7
    length = 1
    if mod == 3:
        return length
    if rm == 4:
        length += 1
        if mod == 0 and data[p + 1] & 7 == 5:
            length += 4
    if mod == 0 and rm == 5:
        length += 4
    elif mod == 1:
        length += 1
    elif mod == 2:
        length += 4
    return length


MODRM_ONE = (set(range(0x00, 0x04)) | set(range(0x08, 0x0c)) | set(range(0x10, 0x14)) | set(range(0x18, 0x1c))
             | set(range(0x20, 0x24)) | set(range(0x28, 0x2c)) | set(range(0x30, 0x34)) | set(range(0x38, 0x3c))
             | set(range(0x84, 0x90)) | set(range(0xd8, 0xe0)) | {0x63, 0xd0, 0xd1, 0xd2, 0xd3, 0xfe, 0xff})
PLAIN_ONE = (set(range(0x50, 0x60)) | set(range(0x90, 0xa0))
             | {0xa4, 0xa5, 0xa6, 0xa7, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xc3, 0xc9, 0xcb, 0xcc, 0xcf,
                0xf4, 0xf5, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd})
PLAIN_TWO = {0x05, 0x06, 0x08, 0x09, 0x0b, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x77, 0xa0, 0xa1, 0xa2, 0xa8,
             0xa9, 0xaa} | set(range(0xc8, 0xd0))
PREFIXES = {0x66, 0x67, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0xf0}


class Insn:
    """One decoded instruction: position, opcode key, REX byte and ModRM offset."""

    __slots__ = ('va', 'off', 'size', 'key', 'rex', 'modrm', 'target', 'body')

    def __init__(self, va, off, size, key, rex, modrm, target, body):
        self.va, self.off, self.size, self.key = va, off, size, key
        self.rex, self.modrm, self.target, self.body = rex, modrm, target, body


def decode(data, off, va):
    """Decode the length of one 64-bit instruction, or raise on an unknown form."""
    p = off
    wide16 = False
    while data[p] in PREFIXES:
        wide16 = wide16 or data[p] == 0x66
        p += 1
    rex = 0
    if 0x40 <= data[p] <= 0x4f:
        rex = data[p]
        p += 1
    body = p
    op = data[p]
    p += 1
    iz = 2 if wide16 else 4

    def done(end, key, modrm=None, rel=None):
        size = end - off
        target = None if rel is None else va + size + rel
        return Insn(va, off, size, key, rex, modrm, target, body)

    if op in (0xc4, 0xc5, 0x62):
        if op == 0xc5:
            space = 1
            p += 1
        elif op == 0xc4:
            space = data[p] & 0x1f
            p += 2
        else:
            space = data[p] & 7
            p += 3
        code = data[p]
        p += 1
        if space == 1 and code == 0x77:
            return done(p, ('vex', code))
        p += modrm_length(data, p)
        if space == 3 or (space == 1 and code in (0x70, 0x71, 0x72, 0x73, 0xc2, 0xc4, 0xc5, 0xc6)):
            p += 1
        return done(p, ('vex', code))
    if op == 0x0f:
        two = data[p]
        p += 1
        if two in (0x38, 0x3a):
            three = data[p]
            p += 1
            modrm = p
            p += modrm_length(data, p) + (1 if two == 0x3a else 0)
            return done(p, (0x0f, two, three), modrm)
        if 0x80 <= two <= 0x8f:
            return done(p + 4, (0x0f, two), rel=struct.unpack_from('<i', data, p)[0])
        if two in PLAIN_TWO:
            return done(p, (0x0f, two))
        modrm = p
        p += modrm_length(data, p)
        if two in (0x70, 0x71, 0x72, 0x73, 0xa4, 0xac, 0xba, 0xc2, 0xc4, 0xc5, 0xc6):
            p += 1
        return done(p, (0x0f, two), modrm)
    if op in MODRM_ONE:
        modrm = p
        return done(p + modrm_length(data, p), op, modrm)
    if op in (0x69, 0x81, 0xc7):
        modrm = p
        return done(p + modrm_length(data, p) + iz, op, modrm)
    if op in (0x6b, 0x80, 0x83, 0xc0, 0xc1, 0xc6):
        modrm = p
        return done(p + modrm_length(data, p) + 1, op, modrm)
    if op in (0xf6, 0xf7):
        modrm = p
        imm = 0
        if (data[p] >> 3) & 7 in (0, 1):
            imm = 1 if op == 0xf6 else iz
        return done(p + modrm_length(data, p) + imm, op, modrm)
    if (op < 0x40 and op & 7 == 4) or op in (0xa8, 0x6a, 0xcd) or 0xb0 <= op <= 0xb7:
        return done(p + 1, op)
    if (op < 0x40 and op & 7 == 5) or op in (0xa9, 0x68):
        return done(p + iz, op)
    if op in PLAIN_ONE:
        return done(p, op)
    if 0xb8 <= op <= 0xbf:
        return done(p + (8 if rex & 8 else iz), op)
    if 0x70 <= op <= 0x7f or op in (0xeb, 0xe0, 0xe1, 0xe2, 0xe3):
        return done(p + 1, op, rel=struct.unpack_from('<b', data, p)[0])
    if op in (0xe8, 0xe9):
        return done(p + 4, op, rel=struct.unpack_from('<i', data, p)[0])
    if op == 0xc2:
        return done(p + 2, op)
    if op in (0xa0, 0xa1, 0xa2, 0xa3):
        return done(p + 8, op)
    fail(f'unknown opcode {op:#x} at {va:#x}')


def sweep(image, start, end):
    """Linear sweep of one FDE range; it must stop exactly on the FDE end."""
    rows = []
    va = start
    delta = image.text['offset'] - image.text['address']
    while va < end:
        insn = decode(image.data, va + delta, va)
        rows.append(insn)
        va += insn.size
    if va != end:
        fail(f'sweep of {start:#x} ended at {va:#x}, FDE ends at {end:#x}')
    return rows


# --- symbolic values ------------------------------------------------------------------------
#
# A value is (terms, constant): a sum of (atom, coefficient) pairs plus a constant, mod 2^64.
# Atoms are tuples compared structurally, so one pure function of equal inputs is one atom.

def konst(value):
    return ((), value & U64)


def atom(*parts):
    return (((parts, 1),), 0)


def is_const(value):
    return not value[0]


def order(pair):
    return repr(pair[0])


def linear(left, right, sign):
    terms = dict(left[0])
    for key, coefficient in right[0]:
        total = (terms.get(key, 0) + sign * coefficient) & U64
        if total:
            terms[key] = total
        else:
            terms.pop(key, None)
    return tuple(sorted(terms.items(), key=order)), (left[1] + sign * right[1]) & U64


def add(left, right):
    return linear(left, right, 1)


def sub(left, right):
    return linear(left, right, -1)


def scaled(value, factor):
    return tuple(sorted(((k, (c * factor) & U64) for k, c in value[0] if (c * factor) & U64), key=order)), (value[1] * factor) & U64


def pure(name, *args):
    return atom('f', name, *args)


def ordered(left, right):
    return (left, right) if repr(left) <= repr(right) else (right, left)


def xor(left, right):
    if left == right:
        return konst(0)
    if is_const(left) and is_const(right):
        return konst(left[1] ^ right[1])
    return pure('xor', *ordered(left, right))


def low(value, bits):
    if bits == 64:
        return value
    if is_const(value):
        return konst(value[1] & ((1 << bits) - 1))
    head = value[0][0][0]
    if len(value[0]) == 1 and value[1] == 0 and value[0][0][1] == 1:
        if head[:2] == ('f', 'setlow') and bits == 8:
            return head[3]
        if head[:2] == ('f', f'low{bits}') or head[0] == 'ns':
            return value
    return pure(f'low{bits}', value)


def is_value(item):
    return isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], tuple) and isinstance(item[1], int)


def show(item):
    if is_value(item):
        return render(item)
    if isinstance(item, tuple):
        return '(' + ','.join(show(x) for x in item) + ')'
    return str(item)


def render(value):
    def name(key):
        if key[0] == 'r':
            return REG_NAMES[key[1]]
        if key[0] == 'm':
            return f'[{render(key[1])}]'
        if key[0] == 'h':
            return f'clobbered:{REG_NAMES[key[1]]}'
        if key[0] == 'ns':
            return f'ns({render(key[1])})'
        return key[1] + '(' + ','.join(show(x) for x in key[2:]) + ')'
    parts = []
    for key, coefficient in value[0]:
        if coefficient == 1:
            parts.append('+' + name(key))
        elif coefficient == U64:
            parts.append('-' + name(key))
        else:
            parts.append(f'+{coefficient:#x}*{name(key)}')
    if value[1] or not parts:
        parts.append(f'+{value[1]:#x}')
    return ''.join(parts).lstrip('+')


# --- the two saturated forms ----------------------------------------------------------------

def saturated_signed(value):
    """Return L when value is one of the compiled forms of a signed saturated result, or None."""
    terms, constant = value
    if len(terms) != 1 or terms[0][1] != 1:
        return None
    key = terms[0][0]
    if constant == I64_MAX and key[0] == 'ns':
        return key[1]
    if constant == 0 and key[:2] == ('f', 'xor'):
        for one, other in ((key[2], key[3]), (key[3], key[2])):
            if other == konst(I64_MIN) and len(one[0]) == 1 and one[1] == 0:
                head = one[0][0][0]
                if head[:2] == ('f', 'sar') and head[3] == 63:
                    return head[2]
    return None


ONE_SIDED = (konst(I64_MAX), konst(I64_MIN))


def compiled_form(value):
    """Name the compiled form of a saturated value."""
    if value in ONE_SIDED:
        return 'one-sided-max' if value[1] == I64_MAX else 'one-sided-min'
    if is_const(value):
        return 'constant'
    return 'setns-add' if value[1] == I64_MAX else 'sar-xor'


def saturation_lemma(width=8):
    """Both signed forms give the saturated result whenever the signed operation overflowed.

    The check runs over all pairs at a small width, and on the edges at 64 bits.  The forms only
    read the sign of the wrapped value, so the argument is the same at every width: a true result
    above MAX wraps negative and one below MIN wraps non-negative.
    """
    def check(bits, a, b):
        mask = (1 << bits) - 1
        top = 1 << (bits - 1)
        low_bound, high_bound = -top, top - 1
        checked = 0
        for total in (a + b, a - b):
            if low_bound <= total <= high_bound:
                continue
            wrapped = total & mask
            sar = mask if wrapped & top else 0
            first = sar ^ top
            second = (high_bound + (0 if wrapped & top else 1)) & mask
            wanted = (high_bound if total > high_bound else low_bound) & mask
            if first != wanted or second != wanted:
                return None
            checked += 1
        return checked

    pairs = cases = 0
    top = 1 << (width - 1)
    for a in range(-top, top):
        for b in range(-top, top):
            result = check(width, a, b)
            if result is None:
                return {'proved': False, 'at': [a, b]}
            pairs += 1
            cases += result
    edges = (-I64_MIN, -I64_MIN + 1, -1, 0, 1, I64_MAX - 1, I64_MAX)
    for a in edges:
        for b in edges:
            result = check(64, a, b)
            if result is None:
                return {'proved': False, 'at': [a, b]}
            cases += result
    return {'proved': True, 'width': width, 'pairs': pairs, 'edge_pairs': len(edges) ** 2, 'overflow_cases': cases}


# --- symbolic machine -----------------------------------------------------------------------

class State:
    def __init__(self):
        self.regs = [atom('r', n) for n in range(16)]
        self.xmm = {}
        self.mem = {}
        self.flags = None
        self.assume = {}
        self.pc = 0
        self.records = 0
        self.clobbers = 0
        self.saturated_at_call = False

    def clone(self):
        other = State.__new__(State)
        other.regs = list(self.regs)
        other.xmm = dict(self.xmm)
        other.mem = dict(self.mem)
        other.flags = self.flags
        other.assume = dict(self.assume)
        other.pc = self.pc
        other.records = self.records
        other.clobbers = self.clobbers
        other.saturated_at_call = self.saturated_at_call
        return other

    def load(self, key, size):
        slot = self.mem.get(key)
        if slot is None:
            return atom('m', key, size)
        if slot[0] == size:
            return slot[1]
        return pure('part', slot[1], size)

    def peek(self, key):
        slot = self.mem.get(key)
        return slot[1] if slot else atom('m', key, 8)


def carry_key(op, left, right):
    if op == 'add':
        return ('CF', 'add', *ordered(left, right))
    if right[0]:
        terms = dict(left[0])
        if all(terms.get(k) == c for k, c in right[0]):
            # left < right exactly when (left - right) + right overflows, for all 64-bit values.
            return carry_key('add', sub(left, right), right)
    return ('CF', 'sub', left, right)


def predicate(flags, cc):
    """Return (key, polarity): the condition holds exactly when key has that truth value."""
    if flags is None:
        raise Unsupported('condition on unknown flags')
    base, negated = cc >> 1, bool(cc & 1)
    polarity = not negated
    if flags[0] == 'a':
        op, left, right = flags[1:]
        result = add(left, right) if op == 'add' else sub(left, right)
        if base == 0:
            pair = ordered(left, right) if op == 'add' else (left, right)
            return ('OF', op, *pair), polarity
        if base == 1:
            return carry_key(op, left, right), polarity
        if base == 2:
            return ('Z', result), polarity
        if base == 3 and op == 'sub':
            return carry_key('sub', right, left), negated
        if base == 4:
            return ('S', result), polarity
    elif flags[0] == 'l':
        value = flags[1]
        if base in (0, 1):
            return ('FALSE',), polarity
        if base in (2, 3):
            return ('Z', value), polarity
        if base == 4:
            return ('S', value), polarity
    return ('cc', base, flags), polarity


def settled(state, key):
    """Truth of a key when it is known on this path, else None."""
    if key in state.assume:
        return state.assume[key]
    if key[0] == 'FALSE':
        return False
    if key[0] == 'Z' and is_const(key[1]):
        return key[1][1] == 0
    if key[0] == 'S' and is_const(key[1]):
        return bool(key[1][1] >> 63)
    return None


def operand(data, p, rex):
    """Decode ModRM at p: ('r', n), ('rip', disp) or ('m', base, index, scale, disp)."""
    modrm = data[p]
    p += 1
    mod, reg, rm = modrm >> 6, ((modrm >> 3) & 7) | ((rex & 4) << 1), modrm & 7
    if mod == 3:
        return ('r', rm | ((rex & 1) << 3)), reg
    base, index, scale = None, None, 1
    if rm == 4:
        sib = data[p]
        p += 1
        scale = 1 << (sib >> 6)
        code = ((sib >> 3) & 7) | ((rex & 2) << 2)
        index = None if code == 4 else code
        if sib & 7 == 5 and mod == 0:
            return ('m', None, index, scale, struct.unpack_from('<i', data, p)[0]), reg
        base = (sib & 7) | ((rex & 1) << 3)
    elif mod == 0 and rm == 5:
        return ('rip', struct.unpack_from('<i', data, p)[0]), reg
    else:
        base = rm | ((rex & 1) << 3)
    disp = 0
    if mod == 1:
        disp = struct.unpack_from('<b', data, p)[0]
    elif mod == 2:
        disp = struct.unpack_from('<i', data, p)[0]
    return ('m', base, index, scale, disp), reg


class Walker:
    """Steps one instruction at a time on the symbolic state of one guard."""

    def __init__(self, image, record, expected=None, bound=()):
        self.image, self.record, self.expected = image, record, expected
        self.bound = bound

    def address(self, state, insn, op):
        if op[0] == 'rip':
            return konst(insn.va + insn.size + op[1])
        _, base, index, scale, disp = op
        value = konst(disp)
        if base is not None:
            value = add(value, state.regs[base])
        if index is not None:
            value = add(value, scaled(state.regs[index], scale))
        return value

    def get(self, state, insn, op, bits):
        if op[0] == 'r':
            if bits == 8 and not insn.rex and 4 <= op[1] < 8:
                raise Unsupported('high byte register')
            return low(state.regs[op[1]], bits)
        return state.load(self.address(state, insn, op), bits // 8)

    def put_reg(self, state, n, bits, value):
        if bits == 64:
            state.regs[n] = value
        elif bits == 32:
            state.regs[n] = low(value, 32)
        else:
            state.regs[n] = pure('partial', state.regs[n], bits, value)

    def put(self, state, insn, op, bits, value):
        if op[0] == 'r':
            if bits == 8 and not insn.rex and 4 <= op[1] < 8:
                raise Unsupported('high byte register')
            self.put_reg(state, op[1], bits, value)
        else:
            state.mem[self.address(state, insn, op)] = (bits // 8, value)

    def alu(self, state, kind, left, right, bits):
        """Run one ALU operation; return the result, or None for a compare."""
        if bits == 64 and kind in (0, 5, 7):
            name = 'add' if kind == 0 else 'sub'
            state.flags = ('a', name, left, right)
            if kind == 7:
                return None
            return add(left, right) if kind == 0 else sub(left, right)
        if kind in (0, 5, 7):
            state.flags = ('o', kind, bits, left, right)
            if kind == 7:
                return None
            result = add(left, right) if kind == 0 else sub(left, right)
            return low(result, bits) if is_const(result) else pure('alu', kind, bits, left, right)
        if kind == 6:
            result = xor(left, right)
        elif kind in (1, 4):
            if is_const(left) and is_const(right):
                result = konst(left[1] | right[1] if kind == 1 else left[1] & right[1])
            else:
                result = pure('or' if kind == 1 else 'and', *ordered(left, right))
        else:
            raise Unsupported('adc or sbb')
        state.flags = ('l', result) if bits == 64 else ('o', 'logic', bits, result)
        return result

    def call_recorder(self, state):
        if state.pc not in self.bound and (not is_const(state.regs[RSI]) or state.regs[RSI][1] != self.record):
            raise Unsupported('the recorder of another site')
        if low(state.regs[RDI], 8) != konst(0):
            fail(f'recorder byte argument {render(state.regs[RDI])} at {state.pc:#x}')
        if self.expected and held_anywhere(state, self.expected):
            state.saturated_at_call = True
        state.records += 1
        state.clobbers += 1
        for n in CALLER_SAVED:
            state.regs[n] = atom('h', n, state.clobbers)
        state.xmm = {}
        state.flags = None

    def step(self, state, insn):
        """Execute one instruction.  Return None, or (cc, target) for a conditional branch."""
        data = self.image.data
        prefixes = data[insn.off:insn.body - (1 if insn.rex else 0)]
        if any(b in (0x64, 0x65, 0xf0, 0x67) for b in prefixes):
            raise Unsupported('segment, lock or address-size prefix')
        wide = 0x66 in prefixes
        rep = 0xf3 in prefixes
        repne = 0xf2 in prefixes
        rex = insn.rex
        bits = 64 if rex & 8 else 16 if wide else 32
        key = insn.key
        following = insn.va + insn.size
        end = insn.off + insn.size
        state.pc = following

        def signed_imm(size):
            return struct.unpack_from({1: '<b', 2: '<h', 4: '<i'}[size], data, end - size)[0]

        if key == 0x90 or key == (0x0f, 0x1f):
            return None
        if key == (0x0f, 0x1e) and rep:
            return None
        if isinstance(key, int) and key < 0x40 and key & 7 < 4:
            kind = key >> 3
            op, reg = operand(data, insn.modrm, rex)
            width = 8 if not key & 1 else bits
            if width == 8 and not rex and reg >= 4 and reg < 8:
                raise Unsupported('high byte register')
            regop = ('r', reg)
            if key & 2:
                left, right, dest = self.get(state, insn, regop, width), self.get(state, insn, op, width), regop
            else:
                left, right, dest = self.get(state, insn, op, width), self.get(state, insn, regop, width), op
            if kind == 6 and op == regop:
                self.put(state, insn, dest, width, konst(0))
                state.flags = ('l', konst(0))
                return None
            result = self.alu(state, kind, left, right, width)
            if result is not None:
                self.put(state, insn, dest, width, result)
            return None
        if isinstance(key, int) and key < 0x40 and key & 7 == 5:
            size = 2 if wide else 4
            left = low(state.regs[RAX], bits)
            right = konst(signed_imm(size) & ((1 << bits) - 1))
            result = self.alu(state, key >> 3, left, right, bits)
            if result is not None:
                self.put_reg(state, RAX, bits, result)
            return None
        if key in (0x80, 0x81, 0x83):
            op, reg = operand(data, insn.modrm, rex)
            width = 8 if key == 0x80 else bits
            size = 1 if key != 0x81 else (2 if wide else 4)
            right = konst(signed_imm(size) & ((1 << width) - 1))
            result = self.alu(state, reg & 7, self.get(state, insn, op, width), right, width)
            if result is not None:
                self.put(state, insn, op, width, result)
            return None
        if key in (0x84, 0x85):
            op, reg = operand(data, insn.modrm, rex)
            width = 8 if key == 0x84 else bits
            if op == ('r', reg):
                value = self.get(state, insn, op, width)
            else:
                value = pure('and', *ordered(self.get(state, insn, op, width), self.get(state, insn, ('r', reg), width)))
            state.flags = ('l', value) if width == 64 else ('o', 'test', width, value)
            return None
        if key in (0x88, 0x89):
            op, reg = operand(data, insn.modrm, rex)
            width = 8 if key == 0x88 else bits
            self.put(state, insn, op, width, self.get(state, insn, ('r', reg), width))
            return None
        if key in (0x8a, 0x8b):
            op, reg = operand(data, insn.modrm, rex)
            width = 8 if key == 0x8a else bits
            self.put(state, insn, ('r', reg), width, self.get(state, insn, op, width))
            return None
        if key == 0x8d:
            op, reg = operand(data, insn.modrm, rex)
            self.put_reg(state, reg, bits, self.address(state, insn, op))
            return None
        if key == 0x63:
            op, reg = operand(data, insn.modrm, rex)
            self.put_reg(state, reg, bits, pure('sx', self.get(state, insn, op, 32)))
            return None
        if key in (0xc6, 0xc7):
            op, reg = operand(data, insn.modrm, rex)
            if reg & 7:
                raise Unsupported('group 11')
            width = 8 if key == 0xc6 else bits
            size = 1 if key == 0xc6 else (2 if wide else 4)
            self.put(state, insn, op, width, konst(signed_imm(size) & ((1 << width) - 1)))
            return None
        if isinstance(key, int) and 0xb8 <= key <= 0xbf:
            n = (key & 7) | ((rex & 1) << 3)
            if rex & 8:
                state.regs[n] = konst(struct.unpack_from('<Q', data, end - 8)[0])
            elif not wide:
                state.regs[n] = konst(struct.unpack_from('<I', data, end - 4)[0])
            else:
                raise Unsupported('16-bit immediate move')
            return None
        if isinstance(key, int) and 0x50 <= key <= 0x57:
            state.regs[RSP] = add(state.regs[RSP], konst(-8))
            state.mem[state.regs[RSP]] = (8, state.regs[(key & 7) | ((rex & 1) << 3)])
            return None
        if isinstance(key, int) and 0x58 <= key <= 0x5f:
            state.regs[(key & 7) | ((rex & 1) << 3)] = state.load(state.regs[RSP], 8)
            state.regs[RSP] = add(state.regs[RSP], konst(8))
            return None
        if key in (0xc1, 0xd1):
            op, reg = operand(data, insn.modrm, rex)
            count = data[end - 1] & 63 if key == 0xc1 else 1
            name = {4: 'shl', 5: 'shr', 7: 'sar'}.get(reg & 7)
            if name is None:
                raise Unsupported('rotate')
            value = self.get(state, insn, op, bits)
            state.flags = ('o', name, bits, value, count)
            self.put(state, insn, op, bits, pure(name, value, count))
            return None
        if key == 0xff:
            op, reg = operand(data, insn.modrm, rex)
            action = reg & 7
            if action in (0, 1):
                value = self.get(state, insn, op, bits)
                state.flags = ('o', 'incdec', action, bits, value)
                self.put(state, insn, op, bits, add(value, konst(1 if action == 0 else -1)))
                return None
            if action == 2 and ((op[0] == 'rip' and following + op[1] == RECORDER_SLOT) or insn.va in self.bound):
                state.pc = insn.va
                self.call_recorder(state)
                state.pc = following
                return None
            raise Unsupported('call or jump through a register or slot')
        if key == 0xf7:
            op, reg = operand(data, insn.modrm, rex)
            action = reg & 7
            value = self.get(state, insn, op, bits)
            if action == 0:
                size = 2 if wide else 4
                state.flags = ('o', 'testi', bits, value, signed_imm(size))
                return None
            if action == 2:
                self.put(state, insn, op, bits, pure('not', value))
                return None
            if action == 3 and bits == 64:
                state.flags = ('a', 'sub', konst(0), value)
                self.put(state, insn, op, bits, sub(konst(0), value))
                return None
            raise Unsupported('group 3')
        if key == 0xf6:
            op, reg = operand(data, insn.modrm, rex)
            if reg & 7:
                raise Unsupported('group 3 byte')
            state.flags = ('o', 'testb', self.get(state, insn, op, 8), signed_imm(1))
            return None
        if isinstance(key, int) and 0x70 <= key <= 0x7f:
            return key & 15, insn.target
        if key in (0xe9, 0xeb):
            state.pc = insn.target
            return None
        if isinstance(key, tuple) and key[0] == 0x0f:
            two = key[1]
            if 0x80 <= two <= 0x8f:
                return two & 15, insn.target
            if 0x40 <= two <= 0x4f:
                op, reg = operand(data, insn.modrm, rex)
                test, polarity = predicate(state.flags, two & 15)
                truth = settled(state, test)
                source = self.get(state, insn, op, bits)
                if truth is None:
                    self.put_reg(state, reg, bits, pure('ite', test, polarity, source, state.regs[reg]))
                elif truth == polarity:
                    self.put_reg(state, reg, bits, source)
                else:
                    self.put_reg(state, reg, bits, state.regs[reg])
                return None
            if 0x90 <= two <= 0x9f:
                op, reg = operand(data, insn.modrm, rex)
                test, polarity = predicate(state.flags, two & 15)
                truth = settled(state, test)
                if truth is not None:
                    value = konst(int(truth == polarity))
                elif test[0] == 'S' and not polarity:
                    value = atom('ns', test[1])
                else:
                    value = pure('set', test, polarity)
                if op[0] == 'r':
                    n = op[1]
                    if not rex and 4 <= n < 8:
                        raise Unsupported('high byte register')
                    old = state.regs[n]
                    state.regs[n] = value if old == konst(0) else pure('setlow', old, value)
                else:
                    state.mem[self.address(state, insn, op)] = (1, value)
                return None
            if two in (0xb6, 0xb7, 0xbe, 0xbf):
                op, reg = operand(data, insn.modrm, rex)
                source = self.get(state, insn, op, 8 if two & 1 == 0 else 16)
                value = source if two < 0xb8 else pure('sx', source)
                self.put_reg(state, reg, bits, value)
                return None
            if two == 0xaf:
                op, reg = operand(data, insn.modrm, rex)
                left, right = self.get(state, insn, ('r', reg), bits), self.get(state, insn, op, bits)
                state.flags = ('o', 'imul', bits, left, right)
                self.put_reg(state, reg, bits, pure('imul', *ordered(left, right)))
                return None
            if two in (0x28, 0x29, 0x10, 0x11, 0x6f, 0x7f) and (two in (0x28, 0x29) or not repne or two < 0x20):
                if two in (0x6f, 0x7f) and not (wide or rep):
                    raise Unsupported('mmx move')
                op, reg = operand(data, insn.modrm, rex)
                size = 8 if repne else 4 if rep and two < 0x20 else 16
                if two in (0x28, 0x10, 0x6f):
                    if op[0] == 'r':
                        state.xmm[reg] = state.xmm.get(op[1], pure('xmm', op[1]))
                    else:
                        state.xmm[reg] = state.load(self.address(state, insn, op), size)
                else:
                    value = state.xmm.get(reg, pure('xmm', reg))
                    if op[0] == 'r':
                        state.xmm[op[1]] = value
                    else:
                        state.mem[self.address(state, insn, op)] = (size, value)
                return None
            if two in (0x57, 0xef):
                op, reg = operand(data, insn.modrm, rex)
                if op == ('r', reg):
                    state.xmm[reg] = konst(0)
                    return None
        raise Unsupported(f'opcode {key}')


class Binder(Walker):
    """Forward walk from one lea: which recorder calls run with that Location in rsi.

    Instructions outside the model only lose what they write, and other calls clobber the
    caller-saved registers, so a register still holding the record really holds it.
    """

    def __init__(self, image, record, loaders):
        super().__init__(image, record)
        self.calls = set()
        self.loaders = loaders

    def recorder_call(self, state, insn):
        if insn.key != 0xff or insn.modrm is None:
            return False
        op, reg = operand(self.image.data, insn.modrm, insn.rex)
        if reg & 7 != 2:
            return False
        if op[0] == 'rip':
            return insn.va + insn.size + op[1] == RECORDER_SLOT
        return op[0] == 'r' and op[1] in self.loaders

    def advance(self, state, insn):
        """Step once; return successor pcs after any conditional branch, or None to stop."""
        if self.recorder_call(state, insn):
            if state.regs[RSI] == konst(self.record):
                self.calls.add(insn.va)
                return None
        if insn.key in (0xe8, 0xff) and insn.modrm is None or insn.key == 0xe8:
            state.pc = insn.va + insn.size
            state.clobbers += 1
            for n in CALLER_SAVED:
                state.regs[n] = atom('h', n, state.clobbers)
            state.flags = None
            return [state.pc]
        if insn.key == 0xff:
            op, reg = operand(self.image.data, insn.modrm, insn.rex)
            if reg & 7 == 2:
                state.pc = insn.va + insn.size
                state.clobbers += 1
                for n in CALLER_SAVED:
                    state.regs[n] = atom('h', n, state.clobbers)
                state.flags = None
                return [state.pc]
            if reg & 7 == 4:
                return None
        if insn.key in (0xc3, 0xcc, (0x0f, 0x0b)):
            return None
        try:
            outcome = self.step(state, insn)
        except Unsupported:
            state.pc = insn.va + insn.size
            state.clobbers += 1
            try:
                name = destination(self.image, insn)
            except (IndexError, KeyError, struct.error, TypeError):
                return None
            if name in REG_NAMES:
                state.regs[REG_NAMES.index(name)] = atom('h', REG_NAMES.index(name), state.clobbers)
            state.flags = None
            return [state.pc]
        if outcome is None:
            return [state.pc]
        return [outcome[1], insn.va + insn.size]


def recorder_loaders(image, rows):
    """Registers that a `mov` in this function loads from the recorder slot."""
    loaders = set()
    for insn in rows:
        if insn.key == 0x8b:
            op, reg = operand(image.data, insn.modrm, insn.rex)
            if op[0] == 'rip' and insn.va + insn.size + op[1] == RECORDER_SLOT:
                loaders.add(reg)
    return loaders


def bind_lea(image, rows, index, lea, record):
    """Return the recorder calls reached from this lea with the record in rsi."""
    binder = Binder(image, record, recorder_loaders(image, rows))
    state = State()
    state.pc = lea
    pending = [state]
    seen = set()
    steps = 0
    while pending and steps < BIND_LIMIT:
        current = pending.pop()
        while True:
            position = index.get(current.pc)
            if position is None:
                break
            holders = tuple(n for n in range(16) if current.regs[n] == konst(record))
            spilled = tuple(sorted(repr(k) for k, v in current.mem.items() if v[1] == konst(record)))
            mark = (current.pc, holders, spilled)
            if mark in seen or (not holders and not spilled and current.pc != lea):
                break
            seen.add(mark)
            steps += 1
            successors = binder.advance(current, rows[position])
            if not successors:
                break
            if len(successors) == 2:
                other = current.clone()
                other.pc = successors[0]
                pending.append(other)
                current.pc = successors[1]
    return binder.calls


def held_anywhere(state, expected):
    if any(expected(value) for value in state.regs):
        return True
    return any(expected(slot[1]) for slot in state.mem.values())


def explore(image, rows, index, state, walker, keep_after_record):
    """Follow every feasible edge from state.  Return a list of paths, each a list of snapshots."""
    paths = []
    pending = [(state, [])]
    forks = 0
    while pending:
        current, log = pending.pop()
        while len(log) < STEP_LIMIT:
            position = index.get(current.pc)
            if position is None:
                break
            if current.records == (1 if keep_after_record else 0):
                log.append(current.clone())
            elif current.records > 1 or not keep_after_record:
                break
            try:
                outcome = walker.step(current, rows[position])
            except Unsupported:
                break
            if outcome is None:
                continue
            cc, target = outcome
            try:
                test, polarity = predicate(current.flags, cc)
            except Unsupported:
                test, polarity = ('opaque', repr(current.flags), cc & 14), not cc & 1
            truth = settled(current, test)
            if truth is not None:
                if truth == polarity:
                    current.pc = target
                continue
            forks += 1
            if forks > FORK_LIMIT:
                break
            other = current.clone()
            other.pc = target
            other.assume[test] = polarity
            pending.append((other, list(log)))
            current.assume[test] = not polarity
        paths.append(log)
    return paths


def compatible(first, second, root):
    for key, value in first.assume.items():
        if key != root and second.assume.get(key, value) != value:
            return False
    return True


def result_locations(over, normal, wanted, result):
    """Locations holding the saturated value on one path and the wrapped result on the other."""
    found = {}
    for n in range(16):
        if wanted(over.regs[n]) and normal.regs[n] == result:
            found[REG_NAMES[n]] = over.regs[n]
    for key in sorted(set(over.mem) | set(normal.mem), key=repr):
        if wanted(over.peek(key)) and normal.peek(key) == result:
            found[f'[{render(key)}]'] = over.peek(key)
    return found


# --- sites and guards ------------------------------------------------------------------------

def branch_targets(rows):
    targets = {}
    for k, insn in enumerate(rows):
        if insn.target is not None and insn.key != 0xe8:
            targets.setdefault(insn.target, []).append(k)
    return targets


def is_conditional(insn):
    key = insn.key
    return (isinstance(key, int) and 0x70 <= key <= 0x7f) or (isinstance(key, tuple) and key[:1] == (0x0f,) and 0x80 <= key[1] <= 0x8f)


def is_jump(insn):
    return insn.key in (0xe9, 0xeb)


def ends_block(insn):
    return is_conditional(insn) or is_jump(insn) or insn.key in (0xc3, 0xe8, 0xff, 0xcc, (0x0f, 0x0b))


def condition_code(insn):
    return insn.key & 15 if isinstance(insn.key, int) else insn.key[1] & 15


def block_start(rows, targets, position):
    """First row of the straight block that holds position."""
    k = position
    while k > 0 and rows[k].va not in targets and not ends_block(rows[k - 1]):
        k -= 1
    return k


def find_guards(rows, targets, lea):
    """Return [(branch row, edge taken into the site)] for every conditional edge into the site."""
    entry = block_start(rows, targets, lea)
    guards = []
    for source in targets.get(rows[entry].va, ()):
        if is_jump(rows[source]):
            if not is_conditional(rows[source - 1]):
                fail(f'jmp at {rows[source].va:#x} follows no conditional branch')
            guards.append((source - 1, False))
        else:
            guards.append((source, True))
    if entry and is_conditional(rows[entry - 1]):
        guards.append((entry - 1, False))
    return sorted(set(guards))


NO_WRITE = {0x38, 0x39, 0x3a, 0x3b, 0x84, 0x85, (0x0f, 0xa3), (0x0f, 0xba)}
WRITES_RM = {0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19, 0x20, 0x21, 0x28, 0x29, 0x30, 0x31, 0x88, 0x89,
             0xc0, 0xc1, 0xd0, 0xd1, 0xd2, 0xd3, 0xc6, 0xc7, 0x80, 0x81, 0x83, 0xf6, 0xf7, 0xfe, 0xff}
SSE_ONLY = (set(range(0x10, 0x18)) | set(range(0x28, 0x30)) | set(range(0x51, 0x7e)) | {0x7f, 0xc2, 0xc6}
            | set(range(0xd0, 0xd7)) | set(range(0xd8, 0x100))) - {0x2c, 0x2d}


def touched(image, insn):
    """Registers an instruction may write, leaning towards too many."""
    key, rex = insn.key, insn.rex
    if isinstance(key, int) and 0x50 <= key <= 0x57:
        return set()
    if isinstance(key, int) and (0x58 <= key <= 0x5f or 0xb8 <= key <= 0xbf):
        return {(key & 7) | ((rex & 1) << 3)}
    if isinstance(key, int) and 0x91 <= key <= 0x97:
        return {RAX, (key & 7) | ((rex & 1) << 3)}
    if insn.modrm is None:
        return set() if key in (0x90, (0x0f, 0x05)) else {RAX, RCX, RDX, RSI, RDI}
    if key in NO_WRITE or (isinstance(key, tuple) and key[0] == 0x0f and len(key) == 2 and key[1] in SSE_ONLY):
        return set()
    modrm = image.data[insn.modrm]
    reg = ((modrm >> 3) & 7) | ((rex & 4) << 1)
    rm = {(modrm & 7) | ((rex & 1) << 3)} if modrm >> 6 == 3 else set()
    if key in WRITES_RM or (isinstance(key, tuple) and 0x90 <= key[1] <= 0x9f):
        return rm | {RAX, RDX}
    if key in (0x86, 0x87) or (isinstance(key, tuple) and key[1:2] and key[1] in (0xa4, 0xa5, 0xac, 0xad, 0xb0, 0xb1, 0xc0, 0xc1, 0xc7, 0x7e)):
        return rm | {reg, RAX, RDX}
    return {reg, RAX, RDX}


def reaching_constants(image, rows, index):
    """Forward dataflow from the function entry: {address: {register: saturation constant}}.

    A register keeps a constant only while every path from the entry holds that constant; any
    instruction that may touch it drops it.  Functions with an indirect jump get nothing.
    """
    if any(insn.key == 0xff and (image.data[insn.modrm] >> 3) & 7 in (4, 5) for insn in rows):
        return {}
    reached = {rows[0].va: {}}
    pending = [rows[0].va]
    while pending:
        pc = pending.pop()
        insn = rows[index[pc]]
        state = dict(reached[pc])
        key = insn.key
        call = key == 0xe8 or (key == 0xff and (image.data[insn.modrm] >> 3) & 7 == 2)
        immediate = None
        if isinstance(key, int) and 0xb8 <= key <= 0xbf and insn.rex & 8:
            immediate = struct.unpack_from('<Q', image.data, insn.off + insn.size - 8)[0]
        elif key == 0xc7 and insn.rex & 8 and image.data[insn.modrm] >> 6 == 3:
            immediate = struct.unpack_from('<i', image.data, insn.off + insn.size - 4)[0] & U64
        if call:
            for n in CALLER_SAVED:
                state.pop(n, None)
        elif not is_conditional(insn) and not is_jump(insn):
            written = touched(image, insn)
            for n in written:
                state.pop(n, None)
            if immediate in (U64, I64_MAX, I64_MIN) and len(written) >= 1:
                n = (key & 7) | ((insn.rex & 1) << 3) if key != 0xc7 else (image.data[insn.modrm] & 7) | ((insn.rex & 1) << 3)
                state[n] = immediate
        following = []
        if is_conditional(insn):
            following = [insn.target, insn.va + insn.size]
        elif is_jump(insn):
            following = [insn.target]
        elif key not in (0xc3, 0xcc, (0x0f, 0x0b), 0xf4):
            following = [insn.va + insn.size]
        for target in following:
            if target not in index:
                continue
            old = reached.get(target)
            merged = state if old is None else {n: v for n, v in old.items() if state.get(n) == v}
            if old is None or merged != old:
                reached[target] = merged
                pending.append(target)
    return reached


def guard_state(image, rows, targets, guard, walker, held):
    """Run the block that ends in the guard from free values, restarting past opaque rows."""
    start = block_start(rows, targets, guard)
    start = max(start, guard - BACK_LIMIT)
    state = State()
    for k in range(start, guard):
        insn = rows[k]
        if is_conditional(insn):
            continue
        try:
            walker.step(state, insn)
        except Unsupported:
            state = State()
    start_va = rows[start].va
    for n, value in held.get(start_va, {}).items():
        if state.regs[n] == atom('r', n):
            state.regs[n] = konst(value)
    return state


def analyse_guard(image, rows, index, targets, call, record, held, branch, taken_in):
    walker = Walker(image, record, bound={call})
    kind = None
    state = guard_state(image, rows, targets, branch, walker, held)
    insn = rows[branch]
    cc = condition_code(insn)
    if state.flags is None:
        fail(f'no flags are set in the block of the guard at {insn.va:#x}')
    test, polarity = predicate(state.flags, cc)
    if test[0] == 'S' and kind is None:
        # The sign bit of x is the carry out of x + x, so this is a doubling.
        op, left, right = 'add', test[1], test[1]
        kind = 'unsigned'
    elif test[0] in ('CF', 'OF'):
        op, left, right = test[1:]
        kind = 'signed' if test[0] == 'OF' else 'unsigned'
    else:
        fail(f'guard at {insn.va:#x} does not test an overflow: {test[0]}')
    overflow_edge = polarity if taken_in else not polarity
    if overflow_edge is not True:
        fail(f'call {call:#x} is entered when the guard at {insn.va:#x} did not overflow')
    result = add(left, right) if op == 'add' else sub(left, right)
    if kind == 'signed':
        def wanted(value):
            return saturated_signed(value) == result or value in ONE_SIDED
    else:
        saturated = konst(U64 if op == 'add' else 0)

        def wanted(value):
            return value == saturated
    walker.expected = wanted
    target, following = insn.target, insn.va + insn.size
    over, normal = state, state.clone()
    over.pc, normal.pc = (target, following) if taken_in else (following, target)
    over.assume[test] = True
    normal.assume[test] = False
    over_paths = explore(image, rows, index, over, walker, True)
    normal_paths = explore(image, rows, index, normal, walker, False)
    seen_lea = any(snapshot.records for path in over_paths for snapshot in path)
    if not seen_lea:
        fail(f'the overflow edge of {insn.va:#x} never reaches the call {call:#x}')
    joins, places, forms, cold_first = set(), set(), set(), False
    for path in over_paths:
        if not path:
            continue
        hit = meet(path, normal_paths, test, wanted, result, True) or meet(path[-1:], normal_paths, test, wanted, result, False)
        if hit is None:
            fail(f'overflow path of {insn.va:#x} for call {call:#x} meets no location with the saturated result')
        pc, found, first = hit
        joins.add(pc)
        places.update(found)
        forms.update(compiled_form(value) for value in found.values())
        cold_first = cold_first or first.saturated_at_call
    return {'call': call, 'guard': insn.va, 'guard_op': f'{data_hex(image, insn)}', 'edge': 'taken' if taken_in else 'fall',
            'operation': f'{op}-{kind}', 'left': render(left), 'right': render(right), 'result': render(result),
            'joins': sorted(joins), 'locations': sorted(places), 'saturated_before_call': cold_first,
            'forms': sorted(forms), 'paths': len(over_paths) + len(normal_paths)}


def meet(path, normal_paths, test, wanted, result, same_address):
    """First snapshot pair of the two edges with a common result location, or None."""
    for first in path:
        for other in normal_paths:
            for second in other:
                if same_address and first.pc != second.pc:
                    continue
                if compatible(first, second, test):
                    found = result_locations(first, second, wanted, result)
                    if found:
                        return (first.pc if same_address else 0), found, first
    return None


def data_hex(image, insn):
    return image.data[insn.off:insn.off + insn.size].hex()


def analyse_call(image, rows, call, record):
    index = {insn.va: k for k, insn in enumerate(rows)}
    targets = branch_targets(rows)
    guards = find_guards(rows, targets, index[call])
    if not guards:
        fail(f'no conditional edge enters the call {call:#x}')
    return [(branch, taken) for branch, taken in guards]


def bind_function(image, rows, leas, references):
    """Return {recorder call: set of records} for the leas of one function."""
    index = {insn.va: k for k, insn in enumerate(rows)}
    calls = {}
    unbound = []
    for lea in leas:
        reached = bind_lea(image, rows, index, lea, references[lea])
        if not reached:
            unbound.append(lea)
        for call in reached:
            calls.setdefault(call, set()).add(references[lea])
    return calls, unbound


# --- negative controls -----------------------------------------------------------------------

def flipped_condition(image, insn):
    raw = bytearray(image.data[insn.off:insn.off + insn.size])
    p = insn.body - insn.off
    if raw[p] == 0x0f:
        raw[p + 1] ^= 1
    else:
        raw[p] ^= 1
    return bytes(raw)


def destination(image, insn):
    """Name of the register an instruction writes, '[memory]' for a store, or None."""
    data, rex = image.data, insn.rex
    key = insn.key
    if isinstance(key, int) and 0xb8 <= key <= 0xbf:
        return REG_NAMES[(key & 7) | ((rex & 1) << 3)]
    if insn.modrm is None:
        return None
    op, reg = operand(data, insn.modrm, rex)
    into_rm = key in (0x01, 0x29, 0x31, 0xc1, 0xc7) or (isinstance(key, tuple) and 0x90 <= key[1] <= 0x9f)
    if not into_rm:
        return REG_NAMES[reg]
    return REG_NAMES[op[1]] if op[0] == 'r' else '[memory]'


def cold_mutations(image, rows, index, start, stop_at):
    """Yield (name, row, bytes) for the value-making rows of the cold run from `start`."""
    position = index[start]
    followed = 0
    for _ in range(40):
        insn = rows[position]
        if insn.va in stop_at or insn.key == 0xc3:
            return
        raw = bytearray(image.data[insn.off:insn.off + insn.size])
        p = insn.body - insn.off
        key = insn.key
        if key in (0x31, 0x33):
            modrm = raw[p + 1]
            if modrm >> 6 == 3 and (modrm >> 3) & 7 == modrm & 7 and insn.rex & 5 in (0, 5) and not (modrm & 7 == 7 and not insn.rex & 1):
                raw[p] = 0x09 if key == 0x31 else 0x0b
                yield 'xor-to-or', insn, bytes(raw)
        elif key == 0xc7 or (isinstance(key, int) and 0xb8 <= key <= 0xbf):
            raw[-1] ^= 1
            yield 'immediate', insn, bytes(raw)
        elif isinstance(key, tuple) and key[0] == 0x0f and (0x40 <= key[1] <= 0x4f or 0x90 <= key[1] <= 0x9f):
            raw[p + 1] ^= 1
            yield 'condition', insn, bytes(raw)
        elif key == 0xc1:
            raw[-1] ^= 1
            yield 'shift-count', insn, bytes(raw)
        elif key in (0x01, 0x03, 0x29, 0x2b):
            raw[p] ^= 0x28
            yield 'add-sub-swap', insn, bytes(raw)
        if is_jump(insn):
            followed += 1
            if followed > 1 or insn.target not in index:
                return
            position = index[insn.target]
            continue
        if is_conditional(insn) or key == 0xc3:
            return
        position += 1
        if position >= len(rows):
            return


def check_guard(image, fn, leas, references, call, record, branch_va):
    """Rebind and reread one guard; raise EvidenceError when the bytes no longer prove it."""
    rows = sweep(image, *fn)
    calls, _ = bind_function(image, rows, leas, references)
    if calls.get(call) != {record}:
        fail(f'call {call:#x} is no longer bound to its record')
    index = {insn.va: k for k, insn in enumerate(rows)}
    targets = branch_targets(rows)
    guards = analyse_call(image, rows, call, record)
    if branch_va is not None:
        guards = [item for item in guards if rows[item[0]].va == branch_va] or guards
    held = reaching_constants(image, rows, index)
    return [analyse_guard(image, rows, index, targets, call, record, held, branch, taken) for branch, taken in guards]


def guard_rows(items):
    return sorted((item['guard'], item['operation'], tuple(item['locations']), tuple(item['joins'])) for item in items)


def fails(image, fn, leas, references, call, record, branch_va, edits, facts):
    """'stopped' when the damaged bytes no longer prove the guards, 'changed' when they prove
    other rows, 'same' when the rows survive."""
    saved = image.apply(edits)
    try:
        found = check_guard(image, fn, leas, references, call, record, branch_va)
    except EvidenceError:
        return 'stopped'
    finally:
        image.apply(saved)
    same = guard_rows(found) == guard_rows(item for item in facts if branch_va in (None, item['guard']))
    return 'same' if same else 'changed'


def site_controls(image, rows, fn, leas, references, call, record, facts):
    """Damage one call: drop the recorder, flip each guard, change the cold value-making rows."""
    index = {insn.va: k for k, insn in enumerate(rows)}
    position = index[call]
    controls = []
    nop = bytes.fromhex('660f1f440000')[:rows[position].size].ljust(rows[position].size, b'\x90')
    controls.append(('drop-recorder', call, None, fails(image, fn, leas, references, call, record, None, [(call, nop)], facts)))
    for item in facts:
        insn = rows[index[item['guard']]]
        outcome = fails(image, fn, leas, references, call, record, insn.va, [(insn.va, flipped_condition(image, insn))], facts)
        controls.append(('flip-guard', insn.va, None, outcome))
    entry = rows[block_start(rows, branch_targets(rows), position)].va
    stops = set()
    for item in facts:
        stops.update(item['joins'])
    seen = set()
    places = {place for item in facts for place in item['locations']}
    in_memory = any(place.startswith('[') for place in places)
    for name, insn, raw in cold_mutations(image, rows, index, entry, stops):
        if insn.va in seen:
            continue
        seen.add(insn.va)
        written = destination(image, insn)
        hits = written in places or (written == '[memory]' and in_memory)
        outcome = fails(image, fn, leas, references, call, record, None, [(insn.va, raw)], facts)
        if hits and outcome == 'same':
            fail(f'damage at {insn.va:#x} changes a result location of call {call:#x} and was not caught')
        controls.append((name, insn.va, written, outcome))
    return controls


# --- whole packet -----------------------------------------------------------------------------

def name_of(record_row):
    return f'{record_row[0]}:{record_row[1]}'


def line_counts(image, records, references):
    """Counts from relocations and lea bytes only, over every function."""
    functions = {}
    for lea, record in references.items():
        functions.setdefault(name_of(records[record]), set()).add(image.fde_of(lea)[0])
    partners = [f'{file}:{line}' for file, line in PARTNERS] + [f'{file}:{line}' for file, line in LINES]
    rows = []
    for file, line in LINES:
        name = f'{file}:{line}'
        mine = functions.get(name, set())
        rows.append((name, len(mine), [len(mine & functions.get(other, set())) if other != name else 0 for other in partners]))
    return partners, rows


def neighbours(records):
    """Which qtys Location sits at +0x18 of each record of the chosen lines."""
    chosen = {name_of((file, line)) for file, line in LINES}
    rows = {}
    for va, row in records.items():
        name = name_of(row)
        if name not in chosen:
            continue
        for delta, side in ((0x18, 'next'), (-0x18, 'previous')):
            other = records.get(va + delta)
            if other is not None:
                key = (name, side, name_of(other))
                rows[key] = rows.get(key, 0) + 1
    return rows


def analyse(image, controls_wanted=True):
    records = location_records(image)
    chosen_records = {va: row for va, row in records.items() if (row[0], row[1]) in LINES}
    if sorted({(row[0], row[1]) for row in chosen_records.values()}) != sorted(LINES):
        fail('a chosen Location line has no record')
    if {row[2] for row in chosen_records.values()} != {1}:
        fail('a chosen Location record has a column other than 1')
    every = lea_references(image, records)
    references = {lea: record for lea, record in every.items() if record in chosen_records}
    if image.relocs.get(RECORDER_SLOT) != RECORDER:
        fail(f'recorder slot holds {image.relocs.get(RECORDER_SLOT)}')
    by_function = {}
    for lea in sorted(references):
        by_function.setdefault(image.fde_of(lea), []).append(lea)
    facts, controls, excluded, unresolved = [], [], [], []
    bound_calls = 0
    for fn, leas in sorted(by_function.items()):
        if fn[0] in EXCLUDED_FUNCTIONS:
            excluded.append({'function': fn[0], 'end': fn[1], 'leas': len(leas), 'named_by': EXCLUDED_FUNCTIONS[fn[0]]})
            continue
        rows = sweep(image, *fn)
        starts = {insn.va for insn in rows}
        if not starts.issuperset(leas):
            fail(f'a lea in {fn[0]:#x} is not an instruction start')
        calls, unbound = bind_function(image, rows, leas, references)
        if unbound:
            fail(f'leas {unbound} reach no recorder call')
        index = {insn.va: k for k, insn in enumerate(rows)}
        targets = branch_targets(rows)
        held = reaching_constants(image, rows, index)
        for call, bound in sorted(calls.items()):
            if len(bound) != 1:
                fail(f'call {call:#x} is reached by two records')
            record = next(iter(bound))
            bound_calls += 1
            found = []
            for branch, taken in analyse_call(image, rows, call, record):
                base = {'function': fn[0], 'function_end': fn[1], 'record': record, 'line': name_of(records[record]), 'call': call}
                try:
                    item = analyse_guard(image, rows, index, targets, call, record, held, branch, taken)
                except EvidenceError as error:
                    unresolved.append({**base, 'guard': rows[branch].va, 'reason': re.sub(r' (of|at) 0x[0-9a-f]+', '', str(error))})
                    continue
                item.update(base)
                found.append(item)
            facts.extend(found)
            if found and controls_wanted:
                for name, va, written, outcome in site_controls(image, rows, fn, leas, references, call, record, found):
                    controls.append({'call': call, 'control': name, 'va': va, 'writes': written or '', 'outcome': outcome})
    table = {}
    for file, line in LINES:
        name = f'{file}:{line}'
        table[name] = {'records': sum(1 for row in chosen_records.values() if (row[0], row[1]) == (file, line)),
                       'leas': sum(1 for record in references.values() if name_of(records[record]) == name),
                       'leas_read': 0, 'guards': 0, 'operations': {}, 'forms': {}, 'unresolved': 0}
    excluded_starts = {item['function'] for item in excluded}
    for lea, record in references.items():
        if image.fde_of(lea)[0] not in excluded_starts:
            table[name_of(records[record])]['leas_read'] += 1
    for item in facts:
        row = table[item['line']]
        row['guards'] += 1
        row['operations'][item['operation']] = row['operations'].get(item['operation'], 0) + 1
        for form in item['forms']:
            row['forms'][form] = row['forms'].get(form, 0) + 1
    for item in unresolved:
        table[item['line']]['unresolved'] += 1
    tally = {}
    for item in controls:
        row = tally.setdefault(item['control'], {'stopped': 0, 'changed': 0, 'same': 0})
        row[item['outcome']] += 1
    lemma = saturation_lemma()
    if not lemma['proved']:
        fail('saturation lemma failed')
    recorder_fde = image.fde_of(RECORDER)
    if recorder_fde[0] != RECORDER or not any(insn.key == 0xc3 for insn in sweep(image, *recorder_fde)):
        fail('the recorder is not a returning function at its FDE start')
    partners, counts = line_counts(image, records, every)
    joined = sum(1 for item in facts if 0 not in item['joins'])
    evidence = {
        'target_sha256': SHA256,
        'path_part': 'l1/src/qtys/',
        'recorder': {'slot': f'{RECORDER_SLOT:#x}', 'target': f'{RECORDER:#x}', 'fde_end': f'{recorder_fde[1]:#x}'},
        'location_records': {f'{va:#x}': {'file': row[0], 'line': row[1], 'column': row[2]}
                             for va, row in sorted(chosen_records.items())},
        'lea_sites': len(references),
        'functions_holding_sites': len(by_function),
        'excluded_functions': len(excluded),
        'excluded_leas': sum(item['leas'] for item in excluded),
        'read_functions': len(by_function) - len(excluded),
        'read_leas': sum(row['leas_read'] for row in table.values()),
        'bound_recorder_calls': bound_calls,
        'guards': len(facts),
        'guards_with_a_common_address': joined,
        'guards_saturated_before_call': sum(1 for item in facts if item['saturated_before_call']),
        'unresolved_guards': len(unresolved),
        'line_table': table,
        'saturation_lemma': lemma,
        'controls': dict(sorted(tally.items())),
        'survivors_writing_a_result_location': 0,
    }
    return evidence, facts, controls, excluded, unresolved, (partners, counts), neighbours(records)


def write_outputs(out, evidence, facts, controls, excluded, unresolved, matrix, adjacent):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
    lines = ['line\trecords\tleas\tleas_read\tguards\toperations\tforms\tunresolved']
    for name, row in evidence['line_table'].items():
        lines.append('\t'.join((name, str(row['records']), str(row['leas']), str(row['leas_read']), str(row['guards']),
                                ';'.join(f'{k}={v}' for k, v in sorted(row['operations'].items())),
                                ';'.join(f'{k}={v}' for k, v in sorted(row['forms'].items())), str(row['unresolved']))))
    (out / 'line-table.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['function\tfunction_end\tline\tcall\tguard\tguard_bytes\tedge\toperation\tleft\tright\tresult\tjoins\tlocations\tcompiled_form\tsaturated_before_call']
    for item in sorted(facts, key=lambda row: (row['call'], row['guard'])):
        lines.append('\t'.join((f'{item["function"]:#x}', f'{item["function_end"]:#x}', item['line'], f'{item["call"]:#x}',
                                f'{item["guard"]:#x}', item['guard_op'], item['edge'], item['operation'], item['left'],
                                item['right'], item['result'], ','.join(f'{j:#x}' if j else 'none' for j in item['joins']),
                                ';'.join(item['locations']), ';'.join(item['forms']),
                                str(item['saturated_before_call']).lower())))
    (out / 'sites.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['call\tcontrol\tva\twrites\toutcome']
    for item in controls:
        lines.append(f'{item["call"]:#x}\t{item["control"]}\t{item["va"]:#x}\t{item["writes"]}\t{item["outcome"]}')
    (out / 'mutation-controls.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['function\tend\tleas\tnamed_by']
    for item in excluded:
        lines.append(f'{item["function"]:#x}\t{item["end"]:#x}\t{item["leas"]}\t{item["named_by"]}')
    (out / 'excluded-functions.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['function\tline\tcall\tguard\treason']
    for item in unresolved:
        lines.append(f'{item["function"]:#x}\t{item["line"]}\t{item["call"]:#x}\t{item["guard"]:#x}\t{item["reason"]}')
    (out / 'unresolved.tsv').write_text('\n'.join(lines) + '\n')
    partners, rows = matrix
    lines = ['line\tfunctions\t' + '\t'.join(partners)]
    for name, count, cells in rows:
        lines.append('\t'.join([name, str(count)] + [str(cell) for cell in cells]))
    (out / 'cooccurrence.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['line\tside\tneighbour\tcount']
    for key, count in sorted(adjacent.items()):
        lines.append('\t'.join(key) + f'\t{count}')
    (out / 'record-neighbours.tsv').write_text('\n'.join(lines) + '\n')


def load_target(path):
    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        fail(f'binary digest {digest} is not node #94')
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--out', required=True)
    parser.add_argument('--binary', default=str(ROOT / BINARY))
    args = parser.parse_args(argv)
    write_outputs(args.out, *analyse(Image(load_target(args.binary))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
