#!/usr/bin/env python3
"""RE-004: integer-admission sign guards of five quantity newtypes in node #94.

Static, no execution.  For each rodata diagnostic piece

    invalid value .. for NtlPriv    when visiting i64   (u64 newtype, i64 input)
    invalid value .. for BigNtlPriv when visiting i64   (u128 newtype, i64 input)
    invalid value .. for SzPriv     when visiting i64   (u64 newtype, i64 input)
    invalid value .. for SziPriv    when visiting u64   (i64 newtype, u64 input)
    invalid value .. for NtliPriv   when visiting u64   (i64 newtype, u64 input)

the tool finds every RIP-relative LEA that loads it, the FDE-bounded functions
holding those LEAs (error constructors), every direct call to them, and for
each call the `test r64,r64` + `js`/`jns` guard whose error block issues that
call.  The guard is modelled on the 64-bit register value and compared with
the admission predicate implied by the message (i64 input: value >= 0;
u64 input: value <= i64::MAX).

    python3 tools/qty_newtype_sign_guards.py --out <dir>

writes evidence.json, call-sites.tsv and guard-bytes.txt.  Only the Python
standard library is used; the binary is read, never executed.
"""

import argparse
import bisect
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
# (newtype, raw width, visited integer type) -- one rodata piece each.  The raw
# width is a label taken from the reference tree; only the name and the visited
# type are read from the binary.
TYPES = [('NtlPriv', 'u64', 'i64'), ('BigNtlPriv', 'u128', 'i64'), ('SzPriv', 'u64', 'i64'),
         ('SziPriv', 'i64', 'u64'), ('NtliPriv', 'i64', 'u64')]
PREFIX = b'invalid value '
# Error block must reach its call within this many bytes of its first byte.
MAX_ERROR_BLOCK = 0x20
REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']


class EvidenceError(Exception):
    pass


def check_digest(data, expected=SHA256):
    got = hashlib.sha256(data).hexdigest()
    if got != expected:
        raise EvidenceError(f'sha256 mismatch: {got} != {expected}')
    return got


def sections(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise EvidenceError('not an ELF64 little-endian file')
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    raw = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    stroff = raw[shstrndx][4]
    out = {}
    for name, _typ, _flags, addr, off, size, *_ in raw:
        end = data.index(b'\0', stroff + name)
        out[data[stroff + name:end].decode()] = (addr, off, size)
    return out


class Image:
    def __init__(self, data):
        self.data = data
        self.sec = sections(data)

    def off(self, va, size=1):
        for addr, off, sz in self.sec.values():
            if addr and addr <= va and va + size <= addr + sz:
                return off + va - addr
        raise EvidenceError(f'VA {va:#x} is outside every allocated section')

    def read(self, va, size):
        o = self.off(va, size)
        return self.data[o:o + size]

    def text(self):
        addr, off, size = self.sec['.text']
        return addr, self.data[off:off + size]


def uleb(buf, i):
    val = shift = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7f) << shift
        shift += 7
        if b < 0x80:
            return val, i


def read_enc(img, va, enc):
    fmt = enc & 0x0f
    size, code = {0x03: (4, '<I'), 0x0b: (4, '<i'), 0x04: (8, '<Q'), 0x0c: (8, '<q')}[fmt]
    val = struct.unpack(code, img.read(va, size))[0]
    if enc & 0x70 == 0x10:
        val += va
    elif enc & 0x70 not in (0x00,):
        raise EvidenceError(f'unsupported pointer encoding {enc:#x}')
    return val & 0xffffffffffffffff, size


class Fdes:
    """Binary-search table from .eh_frame_hdr; ranges from each FDE body."""

    def __init__(self, img):
        self.img = img
        hdr = img.sec['.eh_frame_hdr'][0]
        version, ptr_enc, cnt_enc, tbl_enc = img.read(hdr, 4)
        if (version, cnt_enc, tbl_enc) != (1, 0x03, 0x3b):
            raise EvidenceError('unexpected .eh_frame_hdr encodings')
        _, n = read_enc(img, hdr + 4, ptr_enc)
        count = struct.unpack('<I', img.read(hdr + 4 + n, 4))[0]
        table = img.read(hdr + 8 + n, count * 8)
        self.starts, self.fde = [], []
        for i in range(count):
            loc, fde = struct.unpack_from('<ii', table, i * 8)
            self.starts.append(hdr + loc)
            self.fde.append(hdr + fde)
        self.count = count

    def cie_r_encoding(self, cie):
        img = self.img
        body = img.read(cie + 4, 64)
        if struct.unpack_from('<I', body, 0)[0] != 0:
            raise EvidenceError('CIE id is not zero')
        version = body[4]
        try:
            end = body.index(b'\0', 5)
        except ValueError:
            raise EvidenceError('Unterminated CIE augmentation') from None
        try:
            aug = body[5:end].decode()
        except UnicodeDecodeError:
            raise EvidenceError('Non-ASCII CIE augmentation') from None
        i = end + 1
        _, i = uleb(body, i)
        _, i = uleb(body, i)  # data alignment (value unused, length only)
        if version == 1:
            i += 1
        else:
            _, i = uleb(body, i)
        if not aug.startswith('z'):
            raise EvidenceError('CIE without z augmentation')
        aug_length, i = uleb(body, i)
        aug_end = i + aug_length
        if aug_end > len(body):
            raise EvidenceError('CIE augmentation data outside record')
        for ch in aug[1:]:
            if ch == 'R':
                if i >= aug_end:
                    raise EvidenceError('Truncated CIE augmentation data')
                return body[i]
            if ch == 'L':
                if i >= aug_end:
                    raise EvidenceError('Truncated CIE augmentation data')
                i += 1
            elif ch == 'P':
                if i >= aug_end:
                    raise EvidenceError('Truncated CIE augmentation data')
                penc = body[i]
                step = {0x03: 4, 0x0b: 4, 0x04: 8, 0x0c: 8}.get(penc & 0x0f)
                if step is None:
                    raise EvidenceError(f'Unsupported personality encoding {penc:#x}')
                if i + 1 + step > aug_end:
                    raise EvidenceError('Truncated CIE augmentation data')
                i += 1 + step
            else:
                raise EvidenceError(f'unsupported augmentation {aug!r}')
        raise EvidenceError('CIE has no R augmentation')

    def range_of(self, va):
        k = bisect.bisect_right(self.starts, va) - 1
        if k < 0:
            raise EvidenceError(f'{va:#x} precedes every FDE')
        fde = self.fde[k]
        cie_ptr = struct.unpack('<I', self.img.read(fde + 4, 4))[0]
        enc = self.cie_r_encoding(fde + 4 - cie_ptr)
        begin, n = read_enc(self.img, fde + 8, enc)
        length, _ = read_enc(self.img, fde + 8 + n, enc & 0x0f)
        if begin != self.starts[k]:
            raise EvidenceError(f'FDE {fde:#x} pc_begin disagrees with .eh_frame_hdr')
        if not begin <= va < begin + length:
            raise EvidenceError(f'{va:#x} is outside FDE [{begin:#x},{begin + length:#x})')
        return {'start': begin, 'end': begin + length, 'fde': fde, 'hdr_index': k}


def needle(name, visited):
    return f' for {name} when visiting {visited}\x00'.encode()


def find_piece(img, name, visited):
    addr, off, size = img.sec['.rodata']
    ro = img.data[off:off + size]
    nd = needle(name, visited)
    hits = []
    i = ro.find(nd)
    while i != -1:
        hits.append(i)
        i = ro.find(nd, i + 1)
    if len(hits) != 1:
        raise EvidenceError(f'expected one {name} {visited} piece, found {len(hits)}')
    tail = hits[0]
    # Layout before the needle: <len byte> "invalid value " <0xc0> <arg byte>.
    start = tail - 2 - len(PREFIX)
    if ro[start:start + len(PREFIX)] != PREFIX or ro[start - 1] != len(PREFIX) or ro[tail - 2] != 0xc0:
        raise EvidenceError(f'{name} piece prefix does not match the expected layout')
    end = tail + len(nd)
    # The piece begins at its length byte; the literal text follows it.
    return {'va': addr + start - 1, 'end': addr + end, 'text_va': addr + start,
            'bytes_hex': ro[start - 1:end].hex()}


def lea_rip_refs(text_va, text, lo, hi):
    """(insn VA, target) for REX.W 8D /r with ModRM mod=00 rm=101 into [lo,hi)."""
    out = []
    i = text.find(b'\x8d')
    while i != -1:
        if i >= 1 and text[i - 1] in (0x48, 0x4c) and i + 5 < len(text) and text[i + 1] & 0xc7 == 0x05:
            disp = struct.unpack_from('<i', text, i + 2)[0]
            tgt = text_va + i + 6 + disp
            if lo <= tgt < hi:
                out.append((text_va + i - 1, tgt))
        i = text.find(b'\x8d', i + 1)
    return out


def direct_calls(text_va, text, targets):
    out = []
    i = text.find(b'\xe8')
    while i != -1:
        if i + 5 <= len(text):
            tgt = text_va + i + 5 + struct.unpack_from('<i', text, i + 1)[0]
            if tgt in targets:
                out.append((text_va + i, tgt))
        i = text.find(b'\xe8', i + 1)
    return out


def decode_test(buf, i):
    """`test r64,r64` (REX.W 85 /r, mod=11, reg==rm) at buf[i] -> register."""
    if i < 0 or i + 3 > len(buf):
        return None
    rex, op, modrm = buf[i], buf[i + 1], buf[i + 2]
    if op != 0x85 or rex & 0xf8 != 0x48 or modrm >> 6 != 3:
        return None
    reg = ((rex >> 2) & 1) << 3 | (modrm >> 3) & 7
    rm = (rex & 1) << 3 | modrm & 7
    return REG64[reg] if reg == rm else None


def decode_spill(buf, i):
    """`mov [rsp+disp8], r64` (REX.W 89 /r, mod=01 rm=100 SIB=24) -> (reg, disp)."""
    if i < 0 or i + 5 > len(buf):
        return None
    rex, op, modrm, sib, disp = buf[i:i + 5]
    if op != 0x89 or rex & 0xfa != 0x48 or modrm & 0xc7 != 0x44 or sib != 0x24:
        return None
    return REG64[((rex >> 2) & 1) << 3 | (modrm >> 3) & 7], disp


def decode_store_rdi8(buf, i):
    """`mov [rdi+8], r64` (REX.W 89 /r, mod=01 rm=111 disp8=8) -> reg."""
    if i < 0 or i + 4 > len(buf):
        return None
    rex, op, modrm, disp = buf[i:i + 4]
    if op != 0x89 or rex & 0xfb != 0x48 or modrm & 0xc7 != 0x47 or disp != 8:
        return None
    return REG64[((rex >> 2) & 1) << 3 | (modrm >> 3) & 7]


def decode_sign_jcc(buf, i):
    """js/jns rel8 or rel32 at buf[i] -> (mnemonic, length, displacement)."""
    if i + 2 <= len(buf) and buf[i] in (0x78, 0x79):
        return ('js' if buf[i] == 0x78 else 'jns', 2, struct.unpack_from('<b', buf, i + 1)[0])
    if i + 6 <= len(buf) and buf[i] == 0x0f and buf[i + 1] in (0x88, 0x89):
        return ('js' if buf[i + 1] == 0x88 else 'jns', 6, struct.unpack_from('<i', buf, i + 2)[0])
    return None


def stack_arg_lea(buf, i):
    """`lea r64, [rsp+disp8]` -> disp."""
    if i + 5 <= len(buf) and buf[i] & 0xfb == 0x48 and buf[i + 1] == 0x8d and buf[i + 2] & 0xc7 == 0x44 and buf[i + 3] == 0x24:
        return buf[i + 4]
    return None


def guards_for_call(fn_va, fn, call_va):
    """All test+js/jns pairs in fn whose error block reaches call_va."""
    out = []
    for i in range(len(fn) - 4):
        reg = decode_test(fn, i)
        if reg is None:
            continue
        jcc = decode_sign_jcc(fn, i + 3)
        if jcc is None:
            continue
        name, n, disp = jcc
        after = fn_va + i + 3 + n
        target = after + disp
        error_entry, ok_entry = (target, after) if name == 'js' else (after, target)
        dist = call_va - error_entry
        if not 0 <= dist <= MAX_ERROR_BLOCK:
            continue
        spill = decode_spill(fn, i - 5)
        block = fn[error_entry - fn_va:call_va - fn_va]
        arg_disps = sorted({d for k in range(len(block)) if (d := stack_arg_lea(block, k)) is not None})
        ok_off = ok_entry - fn_va
        ok_store = decode_store_rdi8(fn, ok_off) if 0 <= ok_off < len(fn) else None
        out.append({
            'test_va': hex(fn_va + i), 'register': reg, 'jcc': name,
            'jcc_bytes': fn[i + 3:i + 3 + n].hex(),
            'error_entry': hex(error_entry), 'error_to_call_bytes': dist,
            'error_block_hex': block.hex(), 'ok_entry': hex(ok_entry),
            'ok_entry_hex': fn[ok_off:ok_off + 8].hex() if 0 <= ok_off < len(fn) else None,
            'spill': None if spill is None else {'register': spill[0], 'rsp_disp': spill[1]},
            'error_block_rsp_args': arg_disps,
            'spilled_value_is_tested_value': spill is not None and spill[0] == reg,
            'spill_slot_passed_to_error': spill is not None and spill[1] in arg_disps,
            'ok_first_store_rdi8': ok_store,
            'ok_stores_tested_value_unchanged': ok_store == reg,
        })
    return out


def sign_reads(fn_va, fn):
    """Widths that feed the guarded value: movsx r64, byte [..] and bswap r64."""
    sx, bs = [], []
    for i in range(len(fn) - 2):
        if fn[i] & 0xf8 == 0x48 and fn[i + 1] == 0x0f and fn[i + 2] == 0xbe:
            sx.append(hex(fn_va + i))
        if fn[i] & 0xfa == 0x48 and fn[i + 1] == 0x0f and 0xc8 <= fn[i + 2] <= 0xcf:
            bs.append(hex(fn_va + i))
    return sx, bs


def admitted(value_bits, jcc):
    """Model of the guard for a 64-bit register value: SF = bit 63 after test."""
    sf = (value_bits >> 63) & 1
    takes_branch = sf == 1 if jcc == 'js' else sf == 0
    return not takes_branch if jcc == 'js' else takes_branch


# Boundary values of the 64-bit register; with 2**k neighbours both SF classes are hit.
SAMPLES = sorted({0, 1, (1 << 63) - 1, 1 << 63, (1 << 64) - 1}
                 | {1 << k for k in range(64)} | {(1 << k) - 1 for k in range(1, 65)}
                 | {(1 << 64) - (1 << k) for k in range(64)})


def branches_to(fn_va, fn, target):
    """Every jmp/jcc (rel8 or rel32) in fn whose destination is target -> [(va, len, kind)]."""
    out = []
    for i in range(len(fn) - 1):
        b = fn[i]
        if b == 0xeb or 0x70 <= b <= 0x7f:
            if fn_va + i + 2 + struct.unpack_from('<b', fn, i + 1)[0] == target:
                out.append((fn_va + i, 2, 'jmp' if b == 0xeb else 'jcc'))
        if b == 0xe9 and i + 5 <= len(fn) and fn_va + i + 5 + struct.unpack_from('<i', fn, i + 1)[0] == target:
            out.append((fn_va + i, 5, 'jmp'))
        if b == 0x0f and i + 6 <= len(fn) and 0x80 <= fn[i + 1] <= 0x8f \
                and fn_va + i + 6 + struct.unpack_from('<i', fn, i + 2)[0] == target:
            out.append((fn_va + i, 6, 'jcc'))
    return out


def decode_narrow_test(buf, end):
    """`test r,r` of width 8/16/32 ending at buf offset end -> (width, reg index, start)."""
    # 16-bit: 66 85 /r ; 8-bit: [REX] 84 /r ; 32-bit: [REX without W] 85 /r
    cands = []
    if end >= 3 and buf[end - 3] == 0x66 and buf[end - 2] == 0x85:
        cands.append((16, end - 3, 0, buf[end - 1]))
    if end >= 2 and buf[end - 2] == 0x84:
        rex = buf[end - 3] if end >= 3 and 0x40 <= buf[end - 3] <= 0x47 else 0
        cands.append((8, end - 2 - (1 if rex else 0), rex, buf[end - 1]))
    if end >= 2 and buf[end - 2] == 0x85 and not (end >= 3 and buf[end - 3] in (0x66,) or
                                                    end >= 3 and 0x48 <= buf[end - 3] <= 0x4f):
        rex = buf[end - 3] if end >= 3 and 0x40 <= buf[end - 3] <= 0x47 else 0
        cands.append((32, end - 2 - (1 if rex else 0), rex, buf[end - 1]))
    for width, start, rex, modrm in cands:
        if modrm >> 6 != 3:
            continue
        reg = ((rex >> 2) & 1) << 3 | (modrm >> 3) & 7
        rm = (rex & 1) << 3 | modrm & 7
        if reg == rm:
            return width, reg, start
    return None


SIGN_EXTEND = {8: b'\x0f\xbe', 16: b'\x0f\xbf', 32: b'\x63'}


def narrow_entries(fn_va, fn, error_entry, ok_entry, guard_test_va):
    """Other branches into the error block: each must be `test rN,rN; jns ok; jmp error`."""
    out = []
    for va, n, kind in branches_to(fn_va, fn, error_entry):
        p = va - fn_va
        row = {'va': hex(va), 'kind': kind, 'bytes_hex': fn[p:p + n].hex(), 'width': None,
               'jns_to_ok': False, 'sign_extended_load': False}
        if kind == 'jcc':
            row['is_main_guard'] = va == guard_test_va + 3
            out.append(row)
            continue
        jns = None
        if p >= 6 and fn[p - 6] == 0x0f and fn[p - 5] == 0x89:
            jns = (p - 6, fn_va + p + struct.unpack_from('<i', fn, p - 4)[0])
        elif p >= 2 and fn[p - 2] == 0x79:
            jns = (p - 2, fn_va + p + struct.unpack_from('<b', fn, p - 1)[0])
        if jns is not None:
            row['jns_to_ok'] = jns[1] == ok_entry
            t = decode_narrow_test(fn, jns[0])
            if t is not None:
                width, reg, start = t
                row['width'] = width
                row['test_va'] = hex(fn_va + start)
                # REX.W movsx/movsxd into the tested register within 16 bytes before the test.
                window = fn[max(0, start - 16):start]
                row['sign_extended_load'] = any(
                    window[k] & 0xf8 == 0x48 and window[k + 1:k + 1 + len(SIGN_EXTEND[width])] == SIGN_EXTEND[width]
                    and k + 1 + len(SIGN_EXTEND[width]) < len(window)
                    and ((window[k] >> 2) & 1) << 3 | (window[k + 1 + len(SIGN_EXTEND[width])] >> 3) & 7 == reg
                    for k in range(len(window) - 2))
        row['is_main_guard'] = False
        out.append(row)
    return out


def narrow_admitted(value, width):
    """`test rW,rW` + jns: SF = top bit of the W-bit value."""
    return not (value >> (width - 1)) & 1


def narrow_mismatch(width, visited):
    """Compare the narrow guard with the message predicate on the sign-extended 64-bit value."""
    vals = range(1 << width) if width <= 16 else sorted(
        {0, 1, (1 << 31) - 1, 1 << 31, (1 << 32) - 1} | {1 << k for k in range(32)} | {(1 << 32) - (1 << k) for k in range(32)})
    bad = 0
    for v in vals:
        sext = v | (((1 << 64) - (1 << width)) if v >> (width - 1) else 0)
        if narrow_admitted(v, width) != message_predicate(sext, visited):
            bad += 1
    return bad, len(vals)


def message_predicate(value_bits, visited):
    """Admission implied by the message for a 64-bit input pattern."""
    if visited == 'i64':
        signed = value_bits - (1 << 64) if value_bits >> 63 else value_bits
        return signed >= 0                      # unsigned newtype: negative i64 rejected
    if visited == 'u64':
        return value_bits <= (1 << 63) - 1      # signed newtype: u64 above i64::MAX rejected
    raise EvidenceError(f'unknown visited type {visited!r}')


def analyse_type(img, fdes, text_va, text, name, width, visited, callers):
    piece = find_piece(img, name, visited)
    leas = lea_rip_refs(text_va, text, piece['va'], piece['end'])
    ctors = {}
    for va, tgt in leas:
        r = fdes.range_of(va)
        ctors.setdefault(r['start'], {'range': r, 'leas': []})['leas'].append(hex(va))
    calls = direct_calls(text_va, text, set(ctors))
    sites = []
    for call_va, tgt in calls:
        r = fdes.range_of(call_va)
        fn = img.read(r['start'], r['end'] - r['start'])
        callers[r['start']] = (r, fn)
        guards = guards_for_call(r['start'], fn, call_va)
        sx, bs = sign_reads(r['start'], fn)
        site = {'call_va': hex(call_va), 'constructor': hex(tgt),
                'caller_start': hex(r['start']), 'caller_end': hex(r['end']),
                'caller_fde': hex(r['fde']), 'caller_size': r['end'] - r['start'],
                'guards': guards, 'movsx_r64_m8': sx, 'bswap_r64': bs}
        if len(guards) == 1:
            g = guards[0]
            site['mismatch_vs_message_predicate'] = sum(
                1 for v in SAMPLES if admitted(v, g['jcc']) != message_predicate(v, visited))
            entries = narrow_entries(r['start'], fn, int(g['error_entry'], 16), int(g['ok_entry'], 16),
                                     int(g['test_va'], 16))
            for e in entries:
                if e['width']:
                    e['mismatch_vs_message_predicate'], e['values_checked'] = narrow_mismatch(e['width'], visited)
            site['error_entries'] = entries
            site['narrow_guards'] = sorted(e['width'] for e in entries if e['width'])
            site['unexplained_error_entries'] = sum(
                1 for e in entries if not e['is_main_guard']
                and not (e['width'] and e['jns_to_ok'] and e['sign_extended_load']))
        sites.append(site)
    matched = [s for s in sites if len(s['guards']) == 1]
    tied = sum(1 for s in matched if s['guards'][0]['spilled_value_is_tested_value']
               and s['guards'][0]['spill_slot_passed_to_error'])
    return {
        'newtype': name, 'raw_width_reference_label': width, 'visited': visited,
        'piece': {k: (hex(v) if isinstance(v, int) else v) for k, v in piece.items()},
        'lea_refs': [{'insn': hex(v), 'target': hex(t)} for v, t in leas],
        'constructors': [{'start': hex(k), 'end': hex(v['range']['end']), 'fde': hex(v['range']['fde']),
                          'size': v['range']['end'] - k, 'leas': v['leas']} for k, v in sorted(ctors.items())],
        'call_sites': sites,
        'summary': {'lea_refs': len(leas), 'constructors': len(ctors), 'call_sites': len(sites),
                    'call_sites_with_exactly_one_sign_guard': len(matched),
                    'guard_value_is_formatted_value': tied,
                    'js_guards': sum(1 for s in matched if s['guards'][0]['jcc'] == 'js'),
                    'jns_guards': sum(1 for s in matched if s['guards'][0]['jcc'] == 'jns'),
                    'mismatch_vs_message_predicate': sum(s['mismatch_vs_message_predicate'] for s in matched),
                    'narrow_guards': sum(len(s['narrow_guards']) for s in matched),
                    'narrow_mismatch_vs_message_predicate': sum(
                        e.get('mismatch_vs_message_predicate', 0) for s in matched for e in s['error_entries']),
                    'unexplained_error_entries': sum(s['unexplained_error_entries'] for s in matched),
                    'ok_path_stores_unchanged': sum(1 for s in matched
                                                    if s['guards'][0]['ok_stores_tested_value_unchanged'])},
    }


def analyse(data):
    digest = check_digest(data)
    img = Image(data)
    fdes = Fdes(img)
    text_va, text = img.text()
    callers = {}
    types = [analyse_type(img, fdes, text_va, text, n, w, v, callers) for n, w, v in TYPES]
    sums = [t['summary'] for t in types]
    total = {k: sum(s[k] for s in sums) for k in sums[0]}
    shared = sorted({s['caller_start'] for t in types for s in t['call_sites']})
    total['caller_functions'] = len(shared)
    total['all_sites_one_tied_guard'] = (total['call_sites'] == total['call_sites_with_exactly_one_sign_guard']
                                         == total['guard_value_is_formatted_value'])
    return {
        'task': 'RE-004', 'question': 'integer admission sign guards of Ntl/BigNtl/Sz/Szi/Ntli newtypes',
        'binary': BINARY, 'sha256': digest, 'coordinates': 'virtual addresses (ELF VA)',
        'text': {'va': hex(text_va), 'size': len(text)},
        'fde_table_entries': fdes.count,
        'guard_model': {
            'rule': 'test r,r sets SF = bit 63; js enters the error block when SF=1, jns leaves it when SF=0',
            'admitted': 'bit 63 clear (both jcc forms)',
            'samples': len(SAMPLES),
            'sf_classes_in_samples': sorted({v >> 63 for v in SAMPLES}),
        },
        'types': types,
        'summary': total,
    }, callers


def write(out, result, callers):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    rows = ['newtype\tvisited\tcall_va\tconstructor\tcaller_start\tcaller_end\ttest_va\tregister\tjcc\t'
            'error_entry\terror_to_call_bytes\tvalue_tied_to_message\tok_store_unchanged\tmismatch']
    for t in result['types']:
        for s in t['call_sites']:
            head = [t['newtype'], t['visited'], s['call_va'], s['constructor'], s['caller_start'], s['caller_end']]
            for g in s['guards'] or [None]:
                if g is None:
                    rows.append('\t'.join(head + ['-'] * 8))
                    continue
                rows.append('\t'.join(head + [
                    g['test_va'], g['register'], g['jcc'], g['error_entry'], str(g['error_to_call_bytes']),
                    str(g['spilled_value_is_tested_value'] and g['spill_slot_passed_to_error']).lower(),
                    str(g['ok_stores_tested_value_unchanged']).lower(),
                    str(s.get('mismatch_vs_message_predicate', '-'))]))
    (out / 'call-sites.tsv').write_text('\n'.join(rows) + '\n')
    # Bytes from each guard's test through the constructor call (the decided window).
    lines = []
    for t in result['types']:
        for s in t['call_sites']:
            start = int(s['caller_start'], 16)
            r, fn = callers[start]
            call = int(s['call_va'], 16)
            for g in s['guards']:
                lo = min(int(g['test_va'], 16), int(g['error_entry'], 16))
                hi = max(int(g['test_va'], 16) + 3 + len(g['jcc_bytes']) // 2, call + 5)
                lines.append(f"# {t['newtype']} {t['visited']} call {s['call_va']} in "
                             f"{s['caller_start']}..{s['caller_end']} FDE {s['caller_fde']}")
                for k in range(lo, hi, 16):
                    lines.append(f'{k:x}: {fn[k - start:min(k + 16, hi) - start].hex(" ")}')
                for e in s.get('error_entries', []):
                    if e['width']:
                        a, b = int(e['test_va'], 16), int(e['va'], 16) + len(e['bytes_hex']) // 2
                        lines.append(f"{a:x}: {fn[a - start:b - start].hex(' ')}  ; i{e['width']} test, jns ok, jmp error")
                lines.append('')
    (out / 'guard-bytes.txt').write_text('\n'.join(lines))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--binary', type=Path, default=ROOT / BINARY)
    args = ap.parse_args(argv)
    try:
        result, callers = analyse(args.binary.read_bytes())
    except EvidenceError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    write(args.out, result, callers)
    print(json.dumps(result['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
