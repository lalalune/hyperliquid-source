#!/usr/bin/env python3
"""RE-004: WeiPriv integer-admission sign guard in node #94 (static, no execution).

Finds the rodata diagnostic piece "invalid value .. for WeiPriv when visiting
i64", every RIP-relative LEA that loads it, the FDE-bounded functions holding
those LEAs (error constructors), every direct call to them, and for each call
the `test r64,r64` + `js`/`jns` guard whose error block issues that call.

    python3 tools/weipriv_sign_guard.py --out <dir>

writes evidence.json, call-sites.tsv and caller-bytes.txt.  Only the Python
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
NEEDLE = b' for WeiPriv when visiting i64\x00'
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
        end = body.index(b'\0', 5)
        aug = body[5:end].decode()
        i = end + 1
        _, i = uleb(body, i)
        _, i = uleb(body, i)  # data alignment (value unused, length only)
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


def find_piece(img):
    addr, off, size = img.sec['.rodata']
    ro = img.data[off:off + size]
    hits = []
    i = ro.find(NEEDLE)
    while i != -1:
        hits.append(i)
        i = ro.find(NEEDLE, i + 1)
    if len(hits) != 1:
        raise EvidenceError(f'expected one WeiPriv i64 piece, found {len(hits)}')
    tail = hits[0]
    # Layout before the needle: <len byte> "invalid value " <0xc0> <arg byte>.
    start = tail - 2 - len(PREFIX)
    if ro[start:start + len(PREFIX)] != PREFIX or ro[start - 1] != len(PREFIX) or ro[tail - 2] != 0xc0:
        raise EvidenceError('WeiPriv piece prefix does not match the expected layout')
    end = tail + len(NEEDLE)
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


BOUNDARIES = [0, 1, (1 << 63) - 1, 1 << 63, (1 << 64) - 1]


def analyse(data):
    digest = check_digest(data)
    img = Image(data)
    fdes = Fdes(img)
    piece = find_piece(img)
    text_va, text = img.text()
    leas = lea_rip_refs(text_va, text, piece['va'], piece['end'])
    ctors = {}
    for va, tgt in leas:
        r = fdes.range_of(va)
        ctors.setdefault(r['start'], {'range': r, 'leas': []})['leas'].append(hex(va))
    calls = direct_calls(text_va, text, set(ctors))
    sites = []
    callers = {}
    for call_va, tgt in calls:
        r = fdes.range_of(call_va)
        fn = img.read(r['start'], r['end'] - r['start'])
        callers[r['start']] = (r, fn)
        guards = guards_for_call(r['start'], fn, call_va)
        sx, bs = sign_reads(r['start'], fn)
        sites.append({'call_va': hex(call_va), 'constructor': hex(tgt),
                      'caller_start': hex(r['start']), 'caller_end': hex(r['end']),
                      'caller_fde': hex(r['fde']), 'caller_size': r['end'] - r['start'],
                      'guards': guards, 'movsx_r64_m8': sx, 'bswap_r64': bs})
    matched = [s for s in sites if len(s['guards']) == 1]
    all_tied = all(g['spilled_value_is_tested_value'] and g['spill_slot_passed_to_error']
                   for s in matched for g in s['guards'])
    model = []
    for s in matched:
        g = s['guards'][0]
        model.append({'call_va': s['call_va'], 'jcc': g['jcc'],
                      'admitted': {hex(v): admitted(v, g['jcc']) for v in BOUNDARIES}})
    return {
        'task': 'RE-004', 'question': 'WeiPriv integer admission sign guard',
        'binary': BINARY, 'sha256': digest, 'coordinates': 'virtual addresses (ELF VA)',
        'text': {'va': hex(text_va), 'size': len(text)},
        'fde_table_entries': fdes.count,
        'piece': {k: (hex(v) if isinstance(v, int) else v) for k, v in piece.items()},
        'lea_refs': [{'insn': hex(v), 'target': hex(t)} for v, t in leas],
        'constructors': [{'start': hex(k), 'end': hex(v['range']['end']), 'fde': hex(v['range']['fde']),
                          'leas': v['leas']} for k, v in sorted(ctors.items())],
        'call_sites': sites,
        'summary': {'lea_refs': len(leas), 'constructors': len(ctors), 'call_sites': len(sites),
                    'call_sites_with_exactly_one_sign_guard': len(matched),
                    'guard_value_is_formatted_value': all_tied,
                    'ok_path_stores_unchanged': sum(1 for s in matched
                                                    if s['guards'][0]['ok_stores_tested_value_unchanged'])},
        'guard_model': model,
    }, callers


def write(out, result, callers):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    rows = ['call_va\tconstructor\tcaller_start\tcaller_end\ttest_va\tregister\tjcc\terror_entry\t'
            'error_to_call_bytes\tvalue_tied_to_message\tok_store_unchanged']
    for s in result['call_sites']:
        for g in s['guards'] or [None]:
            if g is None:
                rows.append('\t'.join([s['call_va'], s['constructor'], s['caller_start'], s['caller_end']] + ['-'] * 7))
                continue
            rows.append('\t'.join([s['call_va'], s['constructor'], s['caller_start'], s['caller_end'],
                                   g['test_va'], g['register'], g['jcc'], g['error_entry'],
                                   str(g['error_to_call_bytes']),
                                   str(g['spilled_value_is_tested_value'] and g['spill_slot_passed_to_error']).lower(),
                                   str(g['ok_stores_tested_value_unchanged']).lower()]))
    (out / 'call-sites.tsv').write_text('\n'.join(rows) + '\n', encoding='utf-8', newline='\n')
    lines = []
    for start in sorted(callers):
        r, fn = callers[start]
        lines.append(f'# caller {start:#x}..{r["end"]:#x} FDE {r["fde"]:#x} ({len(fn)} bytes)')
        for k in range(0, len(fn), 16):
            lines.append(f'{start + k:x}: {fn[k:k + 16].hex(" ")}')
        lines.append('')
    (out / 'caller-bytes.txt').write_text('\n'.join(lines), encoding='utf-8', newline='\n')


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
