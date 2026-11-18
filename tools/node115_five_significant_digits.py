#!/usr/bin/env python3
"""Statically bind the #115 five-significant-digit truncation leaf.

The captured ELF is never executed. The leaf's bytes are decoded by a strict
table and evaluated by an exact interpreter for exactly that instruction subset.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-five-significant-digits'
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x269d520, 0x269d69d
TEXT_START, TEXT_END, TEXT_OFFSET = 0x1419300, 0x63f0a00, 0x1418300
FDE, CIE = 0xd3f984, 0xca6ed8
BODY_HASH = '52ab6e2c5340311df8f90595108139623145a8bd04204779f2abdea5506d622f'
MASK = (1 << 64) - 1
CALL_SITES = (0x2dd3ea1, 0x2dd4e64)
# (call site, enclosing FDE start, end, FDE record VA, CIE VA)
CALLERS = ((0x2dd3ea1, 0x2dd34f0, 0x2dd3fa6, 0x11a63cc, 0x103d604),
           (0x2dd4e64, 0x2dd4530, 0x2dd4f02, 0xd95210, 0xca6ed8))
# Bytes immediately around each call: `mov rdi,r15` before, `mov r15,rax` after.
CALL_BEFORE, CALL_AFTER = bytes.fromhex('4c89ff'), bytes.fromhex('4989c7')

# Every encoding in the body. Longer prefixes are tried first. Fields:
# name, destination, source, immediate size, immediate kind.
ENCODINGS = {
    '4889f8': ('mov', 'rax', 'rdi', 0, None),
    '4889c2': ('mov', 'rdx', 'rax', 0, None),
    'b9': ('mov', 'rcx', 'imm', 4, 'zx32'),
    '48c7c0': ('mov', 'rax', 'imm', 4, 'sx32'),
    '48ba': ('mov', 'rdx', 'imm', 8, 'u64'),
    '48b9': ('mov', 'rcx', 'imm', 8, 'u64'),
    '48be': ('mov', 'rsi', 'imm', 8, 'u64'),
    '4881ff': ('cmp', 'rdi', 'imm', 4, 'sx32'),
    '483d': ('cmp', 'rax', 'imm', 4, 'sx32'),
    '4881fa': ('cmp', 'rdx', 'imm', 4, 'sx32'),
    '4839d0': ('cmp', 'rax', 'rdx', 0, None),
    '4839c8': ('cmp', 'rax', 'rcx', 0, None),
    '4839f0': ('cmp', 'rax', 'rsi', 0, None),
    '48c1ea': ('shr', 'rdx', 'imm', 1, 'u8'),
    '480f42ca': ('cmovb', 'rcx', 'rdx', 0, None),
    '48ffc1': ('inc', 'rcx', None, 0, None),
    '4809ca': ('or', 'rdx', 'rcx', 0, None),
    '31d2': ('xor32', 'rdx', 'rdx', 0, None),
    '48f7f1': ('div', 'rcx', None, 0, None),
    'f7f1': ('div32', 'rcx', None, 0, None),
    '48f7e1': ('mul', 'rcx', None, 0, None),
    '0f82': ('jb', None, None, 4, 'rel32'),
    '0f86': ('jbe', None, None, 4, 'rel32'),
    '72': ('jb', None, None, 1, 'rel8'),
    '76': ('jbe', None, None, 1, 'rel8'),
    '74': ('je', None, None, 1, 'rel8'),
    '70': ('jo', None, None, 1, 'rel8'),
    '71': ('jno', None, None, 1, 'rel8'),
    'eb': ('jmp', None, None, 1, 'rel8'),
    'c3': ('ret', None, None, 0, None),
}
PREFIXES = sorted(ENCODINGS, key=len, reverse=True)


def immediate(raw, kind):
    if kind == 'zx32' or kind == 'u8' or kind == 'u64':
        return int.from_bytes(raw, 'little')
    if kind == 'sx32':
        return int.from_bytes(raw, 'little', signed=True) & MASK
    return int.from_bytes(raw, 'little', signed=True)


def decode(body, base=START):
    rows, pos = [], 0
    while pos < len(body):
        for prefix in PREFIXES:
            p = bytes.fromhex(prefix)
            if body[pos:pos + len(p)] == p:
                break
        else:
            raise ValueError(f'unrecognized instruction at {base + pos:#x}')
        name, dst, src, size, kind = ENCODINGS[prefix]
        end = pos + len(p) + size
        if end > len(body):
            raise ValueError('truncated instruction')
        row = {'va': base + pos, 'bytes': body[pos:end].hex(), 'op': name}
        if dst:
            row['dst'] = dst
        if src:
            row['src'] = src
        if size:
            value = immediate(body[pos + len(p):end], kind)
            if kind.startswith('rel'):
                row['target'] = base + end + value
            else:
                row['immediate'] = value
        rows.append(row)
        pos = end
    if rows[-1]['op'] != 'ret':
        raise ValueError('body does not end in ret')
    for row in rows:
        if 'target' in row and not START <= row['target'] < END:
            raise ValueError('branch leaves the leaf')
    if {r['va'] for r in rows if 'target' in r} and not {r['target'] for r in rows if 'target' in r} <= {r['va'] for r in rows}:
        raise ValueError('branch target is not an instruction boundary')
    return rows


def run(rows, x):
    """Evaluate the decoded leaf for RDI=x.

    Registers carry a value and a tag: ('x', k) when the value is x >> k, else
    None. Returns (rax, path, compares, rcx, rcx tag). Each executed compare is
    recorded as (va, c, k): the unsigned compare of x >> k with constant c, so
    the following jb tests x < c << k and jbe tests x < (c + 1) << k.
    """
    at = {r['va']: i for i, r in enumerate(rows)}
    val = {'rax': 0, 'rcx': 0, 'rdx': 0, 'rsi': 0, 'rdi': x}
    tag = {'rax': None, 'rcx': None, 'rdx': None, 'rsi': None, 'rdi': ('x', 0)}
    cf = zf = of = False
    path, compares, i, steps = [], [], 0, 0
    while True:
        steps += 1
        if steps > 1000:
            raise ValueError('step limit')
        r = rows[i]
        op, nxt = r['op'], i + 1
        if op == 'mov':
            if r['src'] == 'imm':
                val[r['dst']], tag[r['dst']] = r['immediate'], None
            else:
                val[r['dst']], tag[r['dst']] = val[r['src']], tag[r['src']]
        elif op == 'cmp':
            a = val[r['dst']]
            b = r['immediate'] if r['src'] == 'imm' else val[r['src']]
            btag = None if r['src'] == 'imm' else tag[r['src']]
            if tag[r['dst']] is None or tag[r['dst']][0] != 'x' or btag is not None:
                raise ValueError('compare is not x>>k against a constant')
            cf, zf, of = a < b, a == b, False
            compares.append((r['va'], b, tag[r['dst']][1]))
        elif op == 'shr':
            k = r['immediate']
            val['rdx'] >>= k
            t = tag['rdx']
            tag['rdx'] = ('x', t[1] + k) if t and t[0] == 'x' else ('opaque', None)
            zf = val['rdx'] == 0
        elif op == 'cmovb':
            if cf:
                val['rcx'], tag['rcx'] = val['rdx'], tag['rdx']
        elif op == 'inc':
            val['rcx'] = (val['rcx'] + 1) & MASK
            zf = val['rcx'] == 0
        elif op == 'or':
            val['rdx'] |= val['rcx']
            tag['rdx'] = ('opaque', None)
            zf, cf, of = val['rdx'] == 0, False, False
        elif op == 'xor32':
            val['rdx'], tag['rdx'] = 0, None
            zf, cf, of = True, False, False
        elif op == 'div':
            if val['rdx'] >= val['rcx']:
                raise ValueError('divide fault')
            n = (val['rdx'] << 64) | val['rax']
            val['rax'], val['rdx'] = n // val['rcx'], n % val['rcx']
            tag['rax'] = tag['rdx'] = ('opaque', None)
        elif op == 'div32':
            d = val['rcx'] & 0xffffffff
            if (val['rdx'] & 0xffffffff) >= d:
                raise ValueError('divide fault')
            n = ((val['rdx'] & 0xffffffff) << 32) | (val['rax'] & 0xffffffff)
            val['rax'], val['rdx'] = n // d, n % d
            tag['rax'] = tag['rdx'] = ('opaque', None)
        elif op == 'mul':
            p = val['rax'] * val['rcx']
            val['rax'], val['rdx'] = p & MASK, p >> 64
            cf = of = val['rdx'] != 0
            tag['rax'] = tag['rdx'] = ('opaque', None)
        elif op == 'ret':
            return val['rax'], tuple(path), compares, val['rcx'], tag['rcx']
        else:
            taken = {'jb': cf, 'jbe': cf or zf, 'je': zf, 'jo': of,
                     'jno': not of, 'jmp': True}[op]
            if op != 'jmp':
                path.append((r['va'], taken))
            if taken:
                nxt = at[r['target']]
        i = nxt


def significant5(x):
    s = 10 ** max(0, len(str(x)) - 5)
    return s, x // s * s


def certificate(rows):
    """Prove `rax == x // s * s` with `s = 10**max(0, digits(x) - 5)` for all x.

    Each executed compare tests `x < t` for a constant t, so it is monotone in x.
    Refining the partition by every threshold seen, plus 2**32 (the tail's
    32-bit fast path) and every power of ten (digit classes), reaches a fixed
    point where both ends of every cell take the same path. On one path every
    branch predicate is constant, rcx is a constant scale, and the tail returns
    floor(x / rcx) * rcx; `jo` is never taken because that product is at most x.
    """
    cuts = {0, 1 << 32, 1 << 64} | {10 ** k for k in range(20)}
    seen = {}
    while True:
        edges = sorted(cuts)
        new = set()
        for lo, hi in zip(edges, edges[1:]):
            for x in (lo, hi - 1):
                _, _, compares, _, _ = run(rows, x)
                for va, c, k in compares:
                    if seen.setdefault(va, (c, k)) != (c, k):
                        raise ValueError('compare operand is not constant')
                    for t in (c << k, (c + 1) << k):
                        if 0 < t < 1 << 64 and t not in cuts:
                            new.add(t)
        if not new:
            break
        cuts |= new
    if {r['va'] for r in rows if r['op'] == 'cmp'} != set(seen):
        raise ValueError('a compare was never reached')
    edges = sorted(cuts)
    cells = []
    for lo, hi in zip(edges, edges[1:]):
        a, b = run(rows, lo), run(rows, hi - 1)
        if a[1] != b[1] or a[3] != b[3] or a[4] is not None:
            raise ValueError('cell is not on one constant-scale path')
        if len(str(lo)) != len(str(hi - 1)):
            raise ValueError('cell straddles a digit class')
        for x, res in ((lo, a), (hi - 1, b)):
            s, want = significant5(x)
            if res[0] != want or res[3] != s or any(v == 0x269d689 and t for v, t in res[1]):
                raise ValueError('closed form mismatch')
        cells.append({'start': lo, 'end': hi, 'scale': a[3]})
    return {'compares': [{'va': va, 'constant': c, 'shift': k} for va, (c, k) in sorted(seen.items())],
            'cells': cells}


def frame(fde, cie):
    if cie != bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'):
        raise ValueError('unexpected CIE')
    if len(fde) != 20:
        raise ValueError('bad FDE length')
    length, delta, rel, size = struct.unpack_from('<IIiI', fde)
    if (length, FDE + 4 - delta, FDE + 8 + rel, size, fde[16:]) != (16, CIE, START, END - START, b'\0' * 4):
        raise ValueError('unexpected FDE')
    return {'fde_va': FDE, 'fde_file_offset': FDE, 'fde_bytes': fde.hex(),
            'cie_va': CIE, 'cie_file_offset': CIE, 'cie_bytes': cie.hex(),
            'cie_augmentation': 'zR', 'lsda': None}


def direct_target(site, data):
    if len(data) != 5 or data[0] not in (0xe8, 0xe9):
        raise ValueError('not a rel32 direct call or jump')
    return site + 5 + struct.unpack_from('<i', data, 1)[0]


def check_reference(site, data):
    if direct_target(site, data) != START:
        raise ValueError('unexpected direct-reference target')


def scan(data):
    # Every byte, not just presumed instruction boundaries.
    hits = []
    lo, hi = TEXT_OFFSET, TEXT_OFFSET + TEXT_END - TEXT_START
    for op in (b'\xe8', b'\xe9'):
        pos = lo
        while True:
            pos = data.find(op, pos, hi - 4)
            if pos < 0:
                break
            site = TEXT_START + pos - TEXT_OFFSET
            raw = bytes(data[pos:pos + 5])
            if direct_target(site, raw) == START:
                check_reference(site, raw)
                hits.append({'site': site, 'opcode': op.hex(), 'bytes': raw.hex(), 'target': START})
            pos += 1
    hits.sort(key=lambda h: h['site'])
    if [(h['site'], h['opcode']) for h in hits] != [(s, 'e8') for s in CALL_SITES]:
        raise ValueError('unexpected direct-reference census')
    return hits


def caller_context(data):
    out = []
    for site, lo, hi, fde_va, cie_va in CALLERS:
        raw = bytes(data[fde_va:fde_va + 16])
        length, delta, rel, size = struct.unpack_from('<IIiI', raw)
        if (fde_va + 4 - delta, fde_va + 8 + rel, size) != (cie_va, lo, hi - lo):
            raise ValueError('invalid caller FDE geometry')
        off = site - 0x1000
        if bytes(data[off - 3:off]) != CALL_BEFORE or bytes(data[off + 5:off + 8]) != CALL_AFTER:
            raise ValueError('unexpected caller context')
        out.append({'site': site, 'fde_start': lo, 'fde_end': hi, 'fde_va': fde_va,
                    'cie_va': cie_va, 'before_hex': CALL_BEFORE.hex(), 'after_hex': CALL_AFTER.hex()})
    return out


def checked_records(data):
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node #115 size or digest mismatch')
    if bytes(data[:16]) != bytes.fromhex('7f454c46020101000000000000000000'):
        raise ValueError('unsupported ELF')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize, count, names_index = struct.unpack_from('<HHH', data, 58)
    if entsize != 64 or names_index >= count or shoff + count * entsize > len(data):
        raise ValueError('invalid section table')
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * entsize) for i in range(count)]
    names = headers[names_index]
    strings = bytes(data[names[4]:names[4] + names[5]])
    found = {}
    for h in headers:
        end = strings.find(b'\0', h[0])
        if h[0] >= len(strings) or end < 0:
            raise ValueError('bad section name')
        name = strings[h[0]:end]
        if name in (b'.text', b'.eh_frame'):
            if name in found:
                raise ValueError('duplicate section')
            found[name] = h
    text, eh = found[b'.text'], found[b'.eh_frame']
    if (text[2], text[3], text[4], text[5]) != (6, TEXT_START, TEXT_OFFSET, TEXT_END - TEXT_START):
        raise ValueError('unexpected text geometry')
    if (eh[3], eh[4], eh[5]) != (CIE, CIE, 0x77137c):
        raise ValueError('unexpected frame geometry')
    raw = bytes(data[START - 0x1000:END - 0x1000])
    if hashlib.sha256(raw).hexdigest() != BODY_HASH:
        raise ValueError('body mismatch')
    rows = decode(raw)
    cert = certificate(rows)
    pad = bytes(data[END - 0x1000:END - 0x1000 + 3])
    if pad != b'\xcc' * 3:
        raise ValueError('unexpected trailing padding')
    return {'target': {'sha256': DIGEST, 'size': len(data)},
            'function': {'start': START, 'end': END, 'size': len(raw), 'file_offset': START - 0x1000,
                         'body_sha256': BODY_HASH, 'body_hex': raw.hex(), 'padding_hex': pad.hex(),
                         'instructions': rows, 'frame': frame(bytes(data[FDE:FDE + 20]), bytes(data[CIE:CIE + 24])),
                         'callees': [], 'memory_accesses': []},
            'closed_form': {'statement': 'rax = (x // s) * s, s = 10**max(0, digits(x) - 5), x = rdi as u64',
                            'method': 'monotone-threshold partition; both ends of every cell evaluated',
                            **cert},
            'direct_references': scan(data),
            'direct_reference_scan': {'start': TEXT_START, 'end': TEXT_END, 'method': 'every-byte e8/e9 rel32'},
            'caller_context': {'sites': caller_context(data),
                               'qualification': 'call-adjacent bytes only; enclosing function behavior unbound'}}


def generate(binary, out):
    with binary.open('rb') as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record = checked_records(data)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    for name in ('README.md', 'verify.py'):
        (out / name).write_bytes((PACKET / name).read_bytes())
    names = ('README.md', 'records.json', 'verify.py')
    (out / 'MANIFEST.sha256').write_text(''.join(hashlib.sha256((out / n).read_bytes()).hexdigest() + '  ' + n + '\n' for n in names), encoding='ascii')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(args.binary, args.out)


if __name__ == '__main__':
    main()
