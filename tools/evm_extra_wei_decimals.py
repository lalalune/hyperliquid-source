#!/usr/bin/env python3
"""RE-004: evm_extra_wei_decimals admission range in node #94 (static, no execution).

Finds the rodata message "EVM extra wei decimals must be between -2 and 18",
every RIP-relative LEA that loads it, the FDE-bounded function holding each
LEA, and the 8-bit range guard that immediately precedes each LEA:

    <add/sub/lea k into r8>  <cmp r8, c>  <ja|jae ok>  lea <msg>  mov <len>
    mov word [rdi], tag  ...

For every guard the tool evaluates the decoded byte arithmetic on all 256
input byte values and reports the admitted set as signed i8 values.  It also
pins the error payload (length immediate, enum tag, [rdi+8]/[rdi+0x10]
stores) and the "evm contract already set" check that gates the guard.

    python3 tools/evm_extra_wei_decimals.py --out <dir>

writes evidence.json, guards.tsv and guard-bytes.txt.  Only the Python
standard library is used; the binary is read, never executed.
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
BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MESSAGE = b'EVM extra wei decimals must be between -2 and 18'
ALREADY_SET = b'evm contract already set'
# Bytes scanned before the message LEA for the guard, and before the guard
# for the jump that skips the "already set" error.
GUARD_WINDOW = 16
GATE_WINDOW = 0x40
OK_WINDOW = 0x20
# Offset from the self pointer (rsi) used by both the insert and the re-check path.
FIELD_DISP = 0x468
REG8 = ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
        'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']
REG32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
         'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']
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
    for name, typ, _flags, addr, off, size, *_ in raw:
        if typ == 8:  # SHT_NOBITS occupies no file bytes; mapping its VAs would
            continue  # return unrelated file bytes as if they lived there.
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
        body = self.img.read(cie + 4, 64)
        if struct.unpack_from('<I', body, 0)[0] != 0:
            raise EvidenceError('CIE id is not zero')
        version = body[4]
        end = body.index(b'\0', 5)
        aug = body[5:end].decode()
        i = end + 1
        _, i = uleb(body, i)
        _, i = uleb(body, i)
        if version == 1:
            i += 1
        else:
            _, i = uleb(body, i)
        if not aug.startswith('z'):
            raise EvidenceError('CIE without z augmentation')
        _, i = uleb(body, i)
        for ch in aug[1:]:
            if ch == 'R':
                return body[i]
            if ch == 'L':
                i += 1
            elif ch == 'P':
                penc = body[i]
                i += 1 + {0x03: 4, 0x0b: 4, 0x04: 8, 0x0c: 8}[penc & 0x0f]
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


def find_unique(img, needle):
    addr, off, size = img.sec['.rodata']
    ro = img.data[off:off + size]
    first = ro.find(needle)
    if first == -1 or ro.find(needle, first + 1) != -1:
        raise EvidenceError(f'expected exactly one {needle!r} in .rodata')
    return addr + first


def lea_rip_refs(text_va, text, target):
    """(insn VA, dest reg) for REX.W 8D /r, mod=00 rm=101, loading exactly target."""
    out = []
    i = text.find(b'\x8d')
    while i != -1:
        if i >= 1 and text[i - 1] in (0x48, 0x4c) and i + 5 < len(text) and text[i + 1] & 0xc7 == 0x05:
            disp = struct.unpack_from('<i', text, i + 2)[0]
            if text_va + i + 6 + disp == target:
                reg = ((text[i - 1] >> 2) & 1) << 3 | (text[i + 1] >> 3) & 7
                out.append((text_va + i - 1, REG64[reg]))
        i = text.find(b'\x8d', i + 1)
    return out


def split_rex(buf, i):
    if 0x40 <= buf[i] <= 0x4f:
        return buf[i], i + 1
    return 0, i


def dec_adjust(buf, i):
    """Step 1: add/sub r8,imm8 or lea r32,[r+disp8] -> (k, dest reg idx, src reg idx, len, text)."""
    rex, j = split_rex(buf, i)
    if rex & 0x08:
        return None
    if j + 3 <= len(buf) and buf[j] == 0x80 and buf[j + 1] >> 6 == 3 and (buf[j + 1] >> 3) & 7 in (0, 5):
        r = (rex & 1) << 3 | buf[j + 1] & 7
        if not rex and r >= 4:
            return None
        imm = buf[j + 2]
        op = 'add' if (buf[j + 1] >> 3) & 7 == 0 else 'sub'
        k = imm if op == 'add' else (-imm) & 0xff
        return k, r, r, j + 3 - i, f'{op} {REG8[r]},{imm:#x}'
    if j + 3 <= len(buf) and buf[j] == 0x8d and buf[j + 1] >> 6 == 1 and buf[j + 1] & 7 != 4:
        dst = ((rex >> 2) & 1) << 3 | (buf[j + 1] >> 3) & 7
        src = (rex & 1) << 3 | buf[j + 1] & 7
        disp = struct.unpack_from('<b', buf, j + 2)[0]
        return disp & 0xff, dst, src, j + 3 - i, f'lea {REG32[dst]},[{REG64[src]}{disp:+#x}]'
    return None


def dec_cmp(buf, i):
    """Step 2: cmp al,imm8 (3C ib) or cmp r8,imm8 (80 /7 ib, mod=11) -> (c, reg idx, len)."""
    if i + 2 <= len(buf) and buf[i] == 0x3c:
        return buf[i + 1], 0, 2
    rex, j = split_rex(buf, i)
    if rex & 0x08 or j + 3 > len(buf):
        return None
    if buf[j] == 0x80 and buf[j + 1] >> 6 == 3 and (buf[j + 1] >> 3) & 7 == 7:
        r = (rex & 1) << 3 | buf[j + 1] & 7
        if not rex and r >= 4:
            return None
        return buf[j + 2], r, j + 3 - i
    return None


def dec_ujcc(buf, i):
    """Step 3: ja/jae rel8 or rel32 -> (mnemonic, len, disp)."""
    if i + 2 <= len(buf) and buf[i] in (0x77, 0x73):
        return ('ja' if buf[i] == 0x77 else 'jae'), 2, struct.unpack_from('<b', buf, i + 1)[0]
    if i + 6 <= len(buf) and buf[i] == 0x0f and buf[i + 1] in (0x87, 0x83):
        return ('ja' if buf[i + 1] == 0x87 else 'jae'), 6, struct.unpack_from('<i', buf, i + 2)[0]
    return None


def decode_guard(buf, base_va, end):
    """Find adjust+cmp+jcc whose last byte ends exactly at buf offset `end`."""
    found = []
    for s in range(max(0, end - GUARD_WINDOW), end):
        a = dec_adjust(buf, s)
        if a is None:
            continue
        k, dst, src, alen, atext = a
        c = dec_cmp(buf, s + alen)
        if c is None:
            continue
        cval, creg, clen = c
        j = dec_ujcc(buf, s + alen + clen)
        if j is None:
            continue
        jname, jlen, jdisp = j
        if s + alen + clen + jlen != end or creg != dst:
            continue
        found.append({'start_va': base_va + s, 'adjust': atext, 'k': k, 'input_reg': REG64[src],
                      'cmp_reg': REG8[creg], 'c': cval, 'jcc': jname,
                      'ok_target_va': base_va + end + jdisp,
                      'bytes_hex': buf[s:end].hex()})
    # `41 8d 40 ed` also decodes from its second byte as `8d 40 ed` (no REX);
    # keep only the prefixed instruction that starts one byte earlier.
    starts = {g['start_va'] for g in found}
    return [g for g in found
            if not (g['start_va'] - 1 in starts and 0x40 <= buf[g['start_va'] - 1 - base_va] <= 0x4f)]


def admitted(x, k, c, jcc):
    """Taken branch (skip the error) for input byte x under the decoded guard."""
    res = (x + k) & 0xff
    return res > c if jcc == 'ja' else res >= c


def admitted_signed(k, c, jcc):
    return sorted(x - 256 if x >= 128 else x for x in range(256) if admitted(x, k, c, jcc))


def ok_byte_store(buf, base_va, ok_va, reg):
    """First `mov byte [rsp+disp8], r8` (REX 88 /r, mod=01 rm=100 SIB=24) within
    OK_WINDOW bytes of the ok target -> (reg8, disp, va), or None."""
    lo = ok_va - base_va
    for i in range(lo, min(lo + OK_WINDOW, len(buf) - 5)):
        if 0x40 <= buf[i] <= 0x47 and buf[i + 1] == 0x88 and buf[i + 2] & 0xc7 == 0x44 and buf[i + 3] == 0x24:
            r = ((buf[i] >> 2) & 1) << 3 | (buf[i + 2] >> 3) & 7
            return {'reg': REG8[r], 'rsp_disp': buf[i + 4], 'va': hex(base_va + i),
                    'is_input_byte': REG8[r] == REG8[REG64.index(reg)]}
    return None


def input_movzx(buf, base_va, guard_off, reg):
    """Last `movzx r32, byte [base+disp8]` (REX 0F B6 /r, mod=01) into reg before the guard."""
    want = REG64.index(reg)
    for i in range(guard_off - 5, -1, -1):
        rex = buf[i]
        if 0x40 <= rex <= 0x4f and not rex & 0x08 and buf[i + 1:i + 3] == b'\x0f\xb6' and buf[i + 3] >> 6 == 1 \
                and buf[i + 3] & 7 != 4 and ((rex >> 2) & 1) << 3 | (buf[i + 3] >> 3) & 7 == want:
            base = (rex & 1) << 3 | buf[i + 3] & 7
            return {'va': hex(base_va + i), 'bytes_hex': buf[i:i + 5].hex(), 'base': REG64[base],
                    'disp': buf[i + 4], 'distance_to_guard': guard_off - i}
    return None


def field_refs(buf, base_va, disp=FIELD_DISP):
    """Instructions whose disp32 equals `disp` with rsi as base (ModRM mod=10 rm=110) or `add rsi,imm32`."""
    out = []
    pat = struct.pack('<I', disp)
    i = buf.find(pat)
    while i != -1:
        if i >= 3 and buf[i - 1] & 0xc7 == 0x86 and buf[i - 3] in (0x48, 0x4c):
            out.append({'va': hex(base_va + i - 3), 'bytes_hex': buf[i - 3:i + 4].hex(), 'kind': 'mem[rsi+disp32]'})
        elif i >= 3 and buf[i - 3:i] == b'\x48\x81\xc6':
            out.append({'va': hex(base_va + i - 3), 'bytes_hex': buf[i - 3:i + 4].hex(), 'kind': 'add rsi,imm32'})
        i = buf.find(pat, i + 1)
    return out


def message_bounds(msg):
    m = re.fullmatch(rb'.*between (-?\d+) and (-?\d+)', msg)
    if not m:
        raise EvidenceError('message has no "between A and B" bounds')
    return int(m.group(1)), int(m.group(2))


def dec_mov_imm32(buf, i):
    rex, j = split_rex(buf, i)
    if j + 5 <= len(buf) and 0xb8 <= buf[j] <= 0xbf and not rex & 0x08:
        return REG64[(rex & 1) << 3 | buf[j] - 0xb8], struct.unpack_from('<I', buf, j + 1)[0], j + 5 - i
    return None


def dec_store_rdi(buf, i):
    """mov [rdi+disp8], r64 (REX.W 89 /r, mod=01 rm=111) -> (reg, disp)."""
    if i + 4 <= len(buf) and buf[i] & 0xfb == 0x48 and buf[i + 1] == 0x89 and buf[i + 2] & 0xc7 == 0x47:
        return REG64[((buf[i] >> 2) & 1) << 3 | (buf[i + 2] >> 3) & 7], buf[i + 3]
    return None


def error_payload(buf, base_va, lea_off, lea_reg):
    """lea msg; mov len; mov word [rdi],tag; mov [rdi+8],ptr; mov [rdi+0x10],len."""
    i = lea_off + 7
    mv = dec_mov_imm32(buf, i)
    if mv is None:
        return None
    len_reg, length, n = mv
    i += n
    if buf[i:i + 3] != b'\x66\xc7\x07':
        return None
    tag = struct.unpack_from('<H', buf, i + 3)[0]
    i += 5
    s1, s2 = dec_store_rdi(buf, i), dec_store_rdi(buf, i + 4)
    return {'length_reg': len_reg, 'length': length, 'tag_store_va': hex(base_va + i - 5), 'tag': tag,
            'ptr_store': s1, 'len_store': s2,
            'stores_ptr_and_len': s1 == (lea_reg, 8) and s2 == (len_reg, 0x10)}


def gate_jump(buf, base_va, guard_off, already_va):
    """je rel8/rel32 to the guard start whose fall-through loads the already-set message."""
    out = []
    for s in range(max(0, guard_off - GATE_WINDOW), guard_off):
        if buf[s] == 0x74:
            n, disp = 2, struct.unpack_from('<b', buf, s + 1)[0]
        elif buf[s] == 0x0f and s + 1 < len(buf) and buf[s + 1] == 0x84:
            n, disp = 6, struct.unpack_from('<i', buf, s + 2)[0]
        else:
            continue
        if s + n + disp != guard_off:
            continue
        nxt = s + n
        if buf[nxt] in (0x48, 0x4c) and buf[nxt + 1] == 0x8d and buf[nxt + 2] & 0xc7 == 0x05:
            tgt = base_va + nxt + 7 + struct.unpack_from('<i', buf, nxt + 3)[0]
            if tgt == already_va:
                cmpb = buf[max(0, s - 9):s]
                out.append({'je_va': hex(base_va + s), 'fallthrough_lea_va': hex(base_va + nxt),
                            'flag_cmp_hex': cmpb.hex()})
    return out


def analyse(data):
    digest = check_digest(data)
    img = Image(data)
    fdes = Fdes(img)
    msg_va = find_unique(img, MESSAGE)
    already_va = find_unique(img, ALREADY_SET)
    lo, hi = message_bounds(MESSAGE)
    expected = list(range(lo, hi + 1))
    text_va, text = img.text()
    leas = lea_rip_refs(text_va, text, msg_va)
    sites, funcs = [], {}
    for lea_va, lea_reg in leas:
        r = fdes.range_of(lea_va)
        fn = img.read(r['start'], r['end'] - r['start'])
        funcs[r['start']] = (r, fn)
        lea_off = lea_va - r['start']
        guards = decode_guard(fn, r['start'], lea_off)
        site = {'lea_va': hex(lea_va), 'lea_reg': lea_reg, 'fn_start': hex(r['start']),
                'fn_end': hex(r['end']), 'fn_fde': hex(r['fde']), 'fn_size': r['end'] - r['start'],
                'field_refs': field_refs(fn, r['start']), 'guards': [], 'payload': error_payload(fn, r['start'], lea_off, lea_reg), 'gate': []}
        for g in guards:
            adm = admitted_signed(g['k'], g['c'], g['jcc'])
            site['guards'].append({
                **{k: (hex(v) if k.endswith('_va') else v) for k, v in g.items()},
                'ok_target_outside_error_block': g['ok_target_va'] > lea_va + 7,
                'ok_target_in_function': r['start'] <= g['ok_target_va'] < r['end'],
                'admitted_count': len(adm), 'admitted_min': min(adm) if adm else None,
                'admitted_max': max(adm) if adm else None,
                'admitted_equals_message_range': adm == expected,
                'ok_byte_store': ok_byte_store(fn, r['start'], g['ok_target_va'], g['input_reg']),
                'input_movzx': input_movzx(fn, r['start'], g['start_va'] - r['start'], g['input_reg']),
            })
            site['gate'] = gate_jump(fn, r['start'], g['start_va'] - r['start'], already_va)
        sites.append(site)
    ok = [s for s in sites if len(s['guards']) == 1 and s['guards'][0]['admitted_equals_message_range']
          and s['guards'][0]['ok_target_outside_error_block'] and s['guards'][0]['ok_target_in_function']
          and s['payload'] and s['payload']['length'] == len(MESSAGE) and s['payload']['stores_ptr_and_len']]
    forms = sorted({(s['guards'][0]['adjust'].split()[0], s['guards'][0]['k'], s['guards'][0]['c'],
                     s['guards'][0]['jcc']) for s in sites if len(s['guards']) == 1})
    tags = sorted({s['payload']['tag'] for s in sites if s['payload']})
    table = [{'byte': x, 'i8': x - 256 if x >= 128 else x,
              'admitted': {f'{f[0]}/{f[1]:#x}/{f[2]:#x}/{f[3]}': admitted(x, f[1], f[2], f[3]) for f in forms}}
             for x in range(256)]
    result = {
        'task': 'RE-004', 'question': 'evm_extra_wei_decimals admission range',
        'binary': BINARY, 'sha256': digest, 'coordinates': 'virtual addresses (ELF VA)',
        'text': {'va': hex(text_va), 'size': len(text)}, 'fde_table_entries': fdes.count,
        'message': {'va': hex(msg_va), 'text': MESSAGE.decode(), 'length': len(MESSAGE),
                    'bounds': [lo, hi]},
        'already_set_message': {'va': hex(already_va), 'text': ALREADY_SET.decode(), 'length': len(ALREADY_SET)},
        'sites': sites,
        'guard_forms': [{'op': f[0], 'k': f[1], 'c': f[2], 'jcc': f[3],
                         'admitted_i8': admitted_signed(f[1], f[2], f[3])} for f in forms],
        'summary': {
            'lea_refs': len(leas), 'functions': len(funcs),
            'sites_with_exactly_one_guard': sum(1 for s in sites if len(s['guards']) == 1),
            'sites_fully_verified': len(ok), 'guard_forms': len(forms),
            'admitted_i8_min': lo, 'admitted_i8_max': hi, 'admitted_count': len(expected),
            'error_tags': tags,
            'sites_gated_by_already_set': sum(1 for s in sites if len(s['gate']) == 1),
            'sites_ok_path_stores_input_byte': sum(
                1 for s in sites if len(s['guards']) == 1 and s['guards'][0]['ok_byte_store']
                and s['guards'][0]['ok_byte_store']['is_input_byte']),
        },
    }
    return result, funcs, table


def write(out, result, funcs, table):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    rows = ['lea_va\tfn_start\tfn_end\tguard_va\tadjust\tk\tcmp_reg\tc\tjcc\tok_target\t'
            'admitted_min\tadmitted_max\tadmitted_count\tlen_imm\ttag\tgate_je']
    for s in result['sites']:
        for g in s['guards'] or [None]:
            p = s['payload'] or {}
            if g is None:
                rows.append('\t'.join([s['lea_va'], s['fn_start'], s['fn_end']] + ['-'] * 13))
                continue
            rows.append('\t'.join([s['lea_va'], s['fn_start'], s['fn_end'], g['start_va'], g['adjust'],
                                   hex(g['k']), g['cmp_reg'], hex(g['c']), g['jcc'], g['ok_target_va'],
                                   str(g['admitted_min']), str(g['admitted_max']), str(g['admitted_count']),
                                   str(p.get('length', '-')), hex(p['tag']) if p else '-',
                                   s['gate'][0]['je_va'] if len(s['gate']) == 1 else '-']))
    rows.append('')
    rows.append('byte\ti8\t' + '\t'.join(table[0]['admitted']))
    for t in table:
        rows.append(f"{t['byte']:#04x}\t{t['i8']}\t" + '\t'.join(str(v).lower() for v in t['admitted'].values()))
    (out / 'guards.tsv').write_text('\n'.join(rows) + '\n')
    lines = []
    for s in result['sites']:
        start = int(s['fn_start'], 16)
        r, fn = funcs[start]
        lo = int(s['guards'][0]['start_va'], 16) if s['guards'] else int(s['lea_va'], 16)
        if s['gate']:
            lo = min(lo, int(s['gate'][0]['je_va'], 16) - 9)
        hi = int(s['lea_va'], 16) + 7 + 5 + 5 + 8
        lines.append(f"# site {s['lea_va']} in {s['fn_start']}..{s['fn_end']} FDE {s['fn_fde']}")
        for k in range(lo, hi, 16):
            lines.append(f'{k:x}: {fn[k - start:min(k + 16, hi) - start].hex(" ")}')
        lines.append('')
    (out / 'guard-bytes.txt').write_text('\n'.join(lines))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--binary', type=Path, default=ROOT / BINARY)
    args = ap.parse_args(argv)
    try:
        result, funcs, table = analyse(args.binary.read_bytes())
    except EvidenceError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    write(args.out, result, funcs, table)
    print(json.dumps(result['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
