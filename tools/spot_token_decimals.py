#!/usr/bin/env python3
"""RE-004: spot token szDecimals/weiDecimals admission guards in node #94 (static, no execution).

Finds three unique `.rodata` messages and every RIP-relative LEA that loads
them, bounds each holding function with its FDE, and decodes the byte guard
that decides whether the error is built:

  family "deploy" (one site): `szDecimals too large` and
      `weiDecimals must be at least szDecimals + 5`
          movzx eax, byte [rsp+S]; cmp al, C; jbe ok1; <error 1>; jmp join
     ok1: add al, K; cmp byte [rsp+W], al; jae ok2; <error 2>; jmp join

  family "range" (every site): `must have szDecimals <= weiDecimals <= 10`
          cmp A8, B8; seta al; cmp B8, N; setae cl; or cl, al; je ok
          mov r16, tag; lea <msg>; mov r32, <len>

For each decoded guard the tool evaluates the decoded byte arithmetic on all
65536 (szDecimals, weiDecimals) byte pairs and compares the admitted set with
the predicate stated by the message text.

    python3 tools/spot_token_decimals.py --out <dir>

writes evidence.json, admission.tsv and guard-bytes.txt.  Only the Python
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
SZ_TOO_LARGE = b'szDecimals too large'
WEI_MIN = b'weiDecimals must be at least szDecimals + 5'
RANGE = b'must have szDecimals <= weiDecimals <= 10'
TAG = 0xdf
# Bytes scanned before a range-message LEA for the guard start, and before a
# guard for the movzx loads that feed its two registers.
GUARD_WINDOW = 0x20
LOAD_WINDOW = 0x100
GRID = 16
REG8 = ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
        'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']
REG16 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
         'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']
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
    for name, _typ, _flags, addr, off, size, *_ in raw:
        end = data.index(b'\0', stroff + name)
        try:
            decoded = data[stroff + name:end].decode()
        except UnicodeDecodeError:
            raise EvidenceError('section name is not valid UTF-8')
        out[decoded] = (addr, off, size)
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
    elif enc & 0x70 != 0x00:
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


def rip_target(buf, base_va, i):
    """Target of the 7-byte `lea r64,[rip+disp32]` at buf offset i."""
    return base_va + i + 7 + struct.unpack_from('<i', buf, i + 3)[0]


# ---------------------------------------------------------------- deploy family

DEPLOY_RE = re.compile(
    rb'\x0f\xb6\x44\x24(?P<s>.)'            # movzx eax, byte [rsp+S]
    rb'\x3c(?P<c>.)'                         # cmp al, C
    rb'\x76(?P<j1>.)'                        # jbe ok1
    rb'\x66\xc7\x03\xdf\x00'                 # mov word [rbx], 0xdf
    rb'(?P<lea1>\x48\x8d\x05....)'           # lea rax, [rip+msg1]
    rb'\x48\x89\x43\x08'                     # mov [rbx+8], rax
    rb'\x48\xc7\x43\x10(?P<len1>....)'       # mov qword [rbx+0x10], len1
    rb'\xe9(?P<jmp1>....)'                   # jmp join
    rb'\x04(?P<k>.)'                         # ok1: add al, K
    rb'\x38\x44\x24(?P<w>.)'                 # cmp byte [rsp+W], al
    rb'\x73(?P<j2>.)'                        # jae ok2
    rb'\x66\xc7\x03\xdf\x00'
    rb'(?P<lea2>\x48\x8d\x05....)'
    rb'\x48\x89\x43\x08'
    rb'\x48\xc7\x43\x10(?P<len2>....)'
    rb'\xe9(?P<jmp2>....)', re.S)
# mov rcx, [r14+disp32]; test rcx, rcx; je rel8 -- immediately before the guard.
DEPLOY_GATE_RE = re.compile(rb'\x49\x8b\x8e(?P<disp>....)\x48\x85\xc9\x74(?P<rel>.)', re.S)


def deploy_admitted(sz, wei, c, k):
    """Both errors skipped for the byte pair under the decoded deploy guard."""
    if not sz <= c:                       # jbe ok1 (unsigned)
        return False
    return wei >= (sz + k) & 0xff         # add al,K (wraps); cmp [W],al; jae ok2


def decode_deploy(buf, base_va, lea1_off):
    """Decode the deploy guard whose first message LEA is at buf offset lea1_off."""
    found = []
    for m in DEPLOY_RE.finditer(buf, max(0, lea1_off - 0x20), lea1_off + 0x80):
        if m.start('lea1') != lea1_off:
            continue
        g = m.groupdict()
        s0 = m.start()
        ok1 = m.end('j1') + struct.unpack('<b', g['j1'])[0]
        ok2 = m.end('j2') + struct.unpack('<b', g['j2'])[0]
        join1 = m.end('jmp1') + struct.unpack('<i', g['jmp1'])[0]
        join2 = m.end('jmp2') + struct.unpack('<i', g['jmp2'])[0]
        gate = None
        gm = DEPLOY_GATE_RE.search(buf, max(0, s0 - 12), s0)
        if gm and gm.end() == s0:
            gate = {'va': hex(base_va + gm.start()), 'r14_disp': struct.unpack('<I', gm.group('disp'))[0],
                    'je_target_va': hex(base_va + gm.end() + struct.unpack('<b', gm.group('rel'))[0]),
                    'je_target_is_ok2': gm.end() + struct.unpack('<b', gm.group('rel'))[0] == ok2,
                    'bytes_hex': buf[gm.start():gm.end()].hex()}
        found.append({
            'start_va': hex(base_va + s0), 'end_va': hex(base_va + m.end()),
            'sz_rsp_disp': g['s'][0], 'wei_rsp_disp': g['w'][0], 'c': g['c'][0], 'k': g['k'][0],
            'jcc1': 'jbe', 'jcc2': 'jae',
            'msg1_va': hex(rip_target(buf, base_va, m.start('lea1'))),
            'msg2_va': hex(rip_target(buf, base_va, m.start('lea2'))),
            'lea2_va': hex(base_va + m.start('lea2')),
            'len1': struct.unpack('<I', g['len1'])[0], 'len2': struct.unpack('<I', g['len2'])[0],
            'ok1_va': hex(base_va + ok1), 'ok1_is_add': ok1 == m.start('k') - 1,
            'ok2_va': hex(base_va + ok2), 'ok2_follows_error2': ok2 == m.end(),
            'join_va': hex(base_va + join1), 'errors_share_join': join1 == join2,
            'gate': gate, 'bytes_hex': buf[s0:m.end()].hex(),
        })
    return found


# ----------------------------------------------------------------- range family

def split_rex(buf, i):
    if 0 <= i < len(buf) and 0x40 <= buf[i] <= 0x4f:
        return buf[i], i + 1
    return 0, i


def reg8_ok(rex, r):
    return bool(rex) or r < 4


def dec_cmp_rr8(buf, i):
    """cmp r/m8, r8 (38 /r, mod=11) -> (rm reg, reg reg, len)."""
    rex, j = split_rex(buf, i)
    if rex & 0x08 or j + 2 > len(buf) or buf[j] != 0x38 or buf[j + 1] >> 6 != 3:
        return None
    rm = (rex & 1) << 3 | buf[j + 1] & 7
    reg = ((rex >> 2) & 1) << 3 | (buf[j + 1] >> 3) & 7
    if not (reg8_ok(rex, rm) and reg8_ok(rex, reg)):
        return None
    return rm, reg, j + 2 - i


def dec_cmp_ri8(buf, i):
    """cmp r8, imm8 (80 /7 ib, mod=11) -> (reg, imm, len)."""
    rex, j = split_rex(buf, i)
    if rex & 0x08 or j + 3 > len(buf) or buf[j] != 0x80 or buf[j + 1] >> 6 != 3 or (buf[j + 1] >> 3) & 7 != 7:
        return None
    r = (rex & 1) << 3 | buf[j + 1] & 7
    if not reg8_ok(rex, r):
        return None
    return r, buf[j + 2], j + 3 - i


def decode_range(buf, base_va, lea_off):
    """Find the range guard whose `mov r16,tag` ends exactly at buf offset lea_off."""
    found = []
    tail = 6 + 4                               # je rel32 + mov r16, imm16
    if lea_off < tail or buf[lea_off - 4] != 0x66 or not 0xb8 <= buf[lea_off - 3] <= 0xbf \
            or buf[lea_off - 6 - 4:lea_off - 4 - 4] != b'\x0f\x84':
        return found
    je_off = lea_off - tail
    for s in range(max(0, je_off - GUARD_WINDOW), je_off):
        a = dec_cmp_rr8(buf, s)
        if a is None:
            continue
        rm, reg, n1 = a
        i = s + n1
        if buf[i:i + 3] != b'\x0f\x97\xc0':          # seta al
            continue
        i += 3
        b = dec_cmp_ri8(buf, i)
        if b is None:
            continue
        breg, imm, n2 = b
        i += n2
        if buf[i:i + 5] != b'\x0f\x93\xc1\x08\xc1':  # setae cl; or cl, al
            continue
        i += 5
        if i != je_off or breg != reg:
            continue
        rel = struct.unpack_from('<i', buf, je_off + 2)[0]
        ok = je_off + 6 + rel
        found.append({'start_va': hex(base_va + s), 'a_reg': REG8[rm], 'b_reg': REG8[reg], 'n': imm,
                      'a_idx': rm, 'b_idx': reg,
                      'je_va': hex(base_va + je_off), 'ok_target_va': hex(base_va + ok),
                      'ok_target_after_lea': ok > lea_off + 7,
                      'tag_reg': REG16[buf[lea_off - 3] - 0xb8],
                      'tag': struct.unpack_from('<H', buf, lea_off - 2)[0],
                      'bytes_hex': buf[s:lea_off].hex()})
    return found


def range_admitted(a, b, n):
    """Branch to ok for byte pair (a, b): not (a > b) and not (b >= n), unsigned."""
    return not (a > b) and not (b >= n)


def range_len(buf, lea_off):
    """mov r32, imm32 right after the LEA -> (reg, imm)."""
    rex, j = split_rex(buf, lea_off + 7)
    if rex & 0x08 or j + 5 > len(buf) or not 0xb8 <= buf[j] <= 0xbf:
        return None
    return REG32[(rex & 1) << 3 | buf[j] - 0xb8], struct.unpack_from('<I', buf, j + 1)[0]


def movzx_load(buf, base_va, before, reg_idx):
    """Last `movzx r32, byte [base+disp8]` (optional REX, 0F B6 /r, mod=01) into reg_idx
    within LOAD_WINDOW bytes before `before` -> dict or None."""
    for i in range(before - 4, max(-1, before - LOAD_WINDOW - 1), -1):
        rex, j = split_rex(buf, i)
        if rex & 0x08 or j + 4 > len(buf) or buf[j:j + 2] != b'\x0f\xb6':
            continue
        modrm = buf[j + 2]
        if modrm >> 6 != 1 or modrm & 7 == 4:
            continue
        if (((rex >> 2) & 1) << 3 | (modrm >> 3) & 7) != reg_idx:
            continue
        if rex == 0 and i >= 1 and 0x40 <= buf[i - 1] <= 0x4f:
            continue                       # this is the tail of a REX-prefixed insn
        base = (rex & 1) << 3 | modrm & 7
        return {'va': hex(base_va + i), 'bytes_hex': buf[i:j + 4].hex(), 'dst': REG32[reg_idx],
                'base': REG64[base], 'disp': buf[j + 3], 'distance_to_guard': before - i}
    return None


# --------------------------------------------------------------------- analysis

def parse_range_message(msg):
    m = re.fullmatch(rb'must have szDecimals <= weiDecimals <= (\d+)', msg)
    if not m:
        raise EvidenceError('range message is not "szDecimals <= weiDecimals <= N"')
    return int(m.group(1))


def parse_deploy_messages(sz_msg, wei_msg):
    if sz_msg != b'szDecimals too large':
        raise EvidenceError('unexpected szDecimals message')
    m = re.fullmatch(rb'weiDecimals must be at least szDecimals \+ (\d+)', wei_msg)
    if not m:
        raise EvidenceError('wei message is not "at least szDecimals + K"')
    return int(m.group(1))


def count_pairs(pred):
    return sum(1 for a in range(256) for b in range(256) if pred(a, b))


def analyse(data):
    digest = check_digest(data)
    img = Image(data)
    fdes = Fdes(img)
    text_va, text = img.text()
    va = {name: find_unique(img, msg) for name, msg in
          (('sz_too_large', SZ_TOO_LARGE), ('wei_min', WEI_MIN), ('range', RANGE))}
    msg_k = parse_deploy_messages(SZ_TOO_LARGE, WEI_MIN)
    msg_n = parse_range_message(RANGE)
    funcs = {}

    # deploy family
    deploy_leas = lea_rip_refs(text_va, text, va['sz_too_large'])
    wei_leas = lea_rip_refs(text_va, text, va['wei_min'])
    deploy_sites = []
    for lea_va, lea_reg in deploy_leas:
        r = fdes.range_of(lea_va)
        fn = img.read(r['start'], r['end'] - r['start'])
        funcs[r['start']] = (r, fn)
        for g in decode_deploy(fn, r['start'], lea_va - r['start']):
            g.update({'lea_va': hex(lea_va), 'fn_start': hex(r['start']), 'fn_end': hex(r['end']),
                      'fn_fde': hex(r['fde']), 'fn_size': r['end'] - r['start']})
            g['messages_match'] = (g['msg1_va'] == hex(va['sz_too_large']) and g['msg2_va'] == hex(va['wei_min'])
                                   and g['len1'] == len(SZ_TOO_LARGE) and g['len2'] == len(WEI_MIN))
            c, k = g['c'], g['k']
            got = lambda a, b, c=c, k=k: deploy_admitted(a, b, c, k)  # noqa: E731
            spec = lambda a, b: a <= c and b >= a + msg_k             # noqa: E731
            g['admitted_pairs'] = count_pairs(got)
            g['mismatch_vs_message_predicate'] = count_pairs(lambda a, b: got(a, b) != spec(a, b))
            g['sz_admitted'] = [a for a in range(256) if a <= c]
            g['add_can_wrap_for_admitted_sz'] = any(a + k > 0xff for a in g['sz_admitted'])
            g['wei_min_for_sz'] = {str(a): (a + k) & 0xff for a in g['sz_admitted']}
            deploy_sites.append(g)

    # range family
    range_leas = lea_rip_refs(text_va, text, va['range'])
    range_sites = []
    for lea_va, lea_reg in range_leas:
        r = fdes.range_of(lea_va)
        fn = img.read(r['start'], r['end'] - r['start'])
        funcs[r['start']] = (r, fn)
        lea_off = lea_va - r['start']
        guards = decode_range(fn, r['start'], lea_off)
        ln = range_len(fn, lea_off)
        site = {'lea_va': hex(lea_va), 'lea_reg': lea_reg, 'fn_start': hex(r['start']),
                'fn_end': hex(r['end']), 'fn_fde': hex(r['fde']), 'fn_size': r['end'] - r['start'],
                'length': {'reg': ln[0], 'value': ln[1]} if ln else None, 'guards': []}
        for g in guards:
            n = g['n']
            got = lambda a, b, n=n: range_admitted(a, b, n)            # noqa: E731
            spec = lambda a, b: a <= b <= msg_n                        # noqa: E731
            g['admitted_pairs'] = count_pairs(got)
            g['mismatch_vs_message_predicate'] = count_pairs(lambda a, b: got(a, b) != spec(a, b))
            g['ok_target_in_function'] = r['start'] <= int(g['ok_target_va'], 16) < r['end']
            before = int(g['start_va'], 16) - r['start']
            g['a_load'] = movzx_load(fn, r['start'], before, g.pop('a_idx'))
            g['b_load'] = movzx_load(fn, r['start'], before, g.pop('b_idx'))
            site['guards'].append(g)
        range_sites.append(site)

    def range_ok(s):
        if len(s['guards']) != 1 or not s['length'] or s['length']['value'] != len(RANGE):
            return False
        g = s['guards'][0]
        return (g['mismatch_vs_message_predicate'] == 0 and g['ok_target_after_lea']
                and g['ok_target_in_function'] and g['tag'] == TAG)

    def deploy_ok(g):
        return (g['messages_match'] and g['mismatch_vs_message_predicate'] == 0 and g['ok1_is_add']
                and g['ok2_follows_error2'] and g['errors_share_join'])

    load_disps = sorted({(g['a_load']['disp'] if g['a_load'] else None, g['b_load']['disp'] if g['b_load'] else None)
                         for s in range_sites for g in s['guards']}, key=str)
    forms = sorted({g['bytes_hex'] for s in range_sites for g in s['guards']})
    # Intersection of both decoded predicates (only meaningful if both run on one request).
    joint = []
    if deploy_sites and range_sites and all(len(s['guards']) == 1 for s in range_sites):
        d, rg = deploy_sites[0], range_sites[0]['guards'][0]
        joint = [(a, b) for a in range(256) for b in range(256)
                 if deploy_admitted(a, b, d['c'], d['k']) and range_admitted(a, b, rg['n'])]
    grid = []
    for a in range(GRID):
        for b in range(GRID):
            grid.append({'sz': a, 'wei': b,
                         'deploy': [deploy_admitted(a, b, g['c'], g['k']) for g in deploy_sites],
                         'range': [range_admitted(a, b, g['n']) for s in range_sites for g in s['guards']]})
    result = {
        'task': 'RE-004', 'question': 'spot token szDecimals/weiDecimals admission guards',
        'binary': BINARY, 'sha256': digest, 'coordinates': 'virtual addresses (ELF VA)',
        'text': {'va': hex(text_va), 'size': len(text)}, 'fde_table_entries': fdes.count,
        'messages': {name: {'va': hex(va[name]), 'text': msg.decode(), 'length': len(msg)}
                     for name, msg in (('sz_too_large', SZ_TOO_LARGE), ('wei_min', WEI_MIN), ('range', RANGE))},
        'message_parameters': {'wei_min_offset': msg_k, 'range_max': msg_n},
        'deploy_sites': deploy_sites, 'range_sites': range_sites,
        'joint_admitted': {'count': len(joint), 'pairs': [list(p) for p in joint]},
        'summary': {
            'deploy_lea_refs': len(deploy_leas), 'wei_min_lea_refs': len(wei_leas),
            'deploy_sites_decoded': len(deploy_sites),
            'deploy_sites_fully_verified': sum(1 for g in deploy_sites if deploy_ok(g)),
            'deploy_sz_max': max(deploy_sites[0]['sz_admitted']) if deploy_sites else None,
            'deploy_wei_offset': deploy_sites[0]['k'] if deploy_sites else None,
            'deploy_admitted_pairs': deploy_sites[0]['admitted_pairs'] if deploy_sites else None,
            'deploy_add_can_wrap': any(g['add_can_wrap_for_admitted_sz'] for g in deploy_sites),
            'deploy_gated': sum(1 for g in deploy_sites if g['gate'] and g['gate']['je_target_is_ok2']),
            'range_lea_refs': len(range_leas),
            'range_functions': len({s['fn_start'] for s in range_sites}),
            'range_sites_with_exactly_one_guard': sum(1 for s in range_sites if len(s['guards']) == 1),
            'range_sites_fully_verified': sum(1 for s in range_sites if range_ok(s)),
            'range_byte_forms': len(forms),
            'range_admitted_pairs': sorted({g['admitted_pairs'] for s in range_sites for g in s['guards']}),
            'range_load_disps': [list(p) for p in load_disps],
            'joint_admitted_pairs': len(joint),
            'error_tags': sorted({g['tag'] for s in range_sites for g in s['guards']} | ({TAG} if deploy_sites else set())),
        },
    }
    return result, funcs, grid


def write(out, result, funcs, grid):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    rows = ['family\tlea_va\tfn_start\tfn_end\tguard_va\tdecoded\tadmitted_pairs\tmismatch\tsz_load\twei_load']
    for g in result['deploy_sites']:
        rows.append('\t'.join(['deploy', g['lea_va'], g['fn_start'], g['fn_end'], g['start_va'],
                               f"sz<={g['c']} (jbe); wei>=(sz+{g['k']})&0xff (jae)",
                               str(g['admitted_pairs']), str(g['mismatch_vs_message_predicate']),
                               f"[rsp+{g['sz_rsp_disp']:#x}]", f"[rsp+{g['wei_rsp_disp']:#x}]"]))
    for s in result['range_sites']:
        for g in s['guards'] or [None]:
            if g is None:
                rows.append('\t'.join(['range', s['lea_va'], s['fn_start'], s['fn_end']] + ['-'] * 6))
                continue
            ld = [f"[{x['base']}+{x['disp']:#x}]" if x else '-' for x in (g['a_load'], g['b_load'])]
            rows.append('\t'.join(['range', s['lea_va'], s['fn_start'], s['fn_end'], g['start_va'],
                                   f"err if {g['a_reg']}>{g['b_reg']} (seta) or {g['b_reg']}>={g['n']} (setae)",
                                   str(g['admitted_pairs']), str(g['mismatch_vs_message_predicate'])] + ld))
    rows.append('')
    rows.append(f'# admission grid sz,wei in 0..{GRID - 1} (1 = error not built); columns: deploy sites, range sites')
    rows.append('sz\twei\tdeploy\trange')
    for c in grid:
        rows.append(f"{c['sz']}\t{c['wei']}\t" + ','.join(str(int(v)) for v in c['deploy'])
                    + '\t' + ','.join(str(int(v)) for v in c['range']))
    (out / 'admission.tsv').write_text('\n'.join(rows) + '\n')
    lines = []
    spans = [(g['fn_start'], g['fn_fde'], int(g['gate']['va'], 16) if g['gate'] else int(g['start_va'], 16),
              int(g['end_va'], 16), g['lea_va']) for g in result['deploy_sites']]
    for s in result['range_sites']:
        lo = min([int(s['lea_va'], 16)] + [int(g['start_va'], 16) for g in s['guards']])
        spans.append((s['fn_start'], s['fn_fde'], lo, int(s['lea_va'], 16) + 7 + 6, s['lea_va']))
    for fn_start, fde, lo, hi, lea in spans:
        start = int(fn_start, 16)
        r, fn = funcs[start]
        lines.append(f'# site {lea} in {fn_start}..{hex(r["end"])} FDE {fde}')
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
        result, funcs, grid = analyse(args.binary.read_bytes())
    except EvidenceError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    write(args.out, result, funcs, grid)
    print(json.dumps(result['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
