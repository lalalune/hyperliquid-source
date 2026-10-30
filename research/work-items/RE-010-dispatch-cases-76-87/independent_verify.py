#!/usr/bin/env python3
"""Independent check of dispatch-tail.json. Imports nothing from tools/.

Re-derives from artifacts/node/94/hl-node with its own ELF/relocation reader:
the jump-table arms for cases 76..87, the serde variant-name tables, each
case's first-call and continuation bytes, the shared-tail bytes hash and the
branch-source counts into the tail. Prints exactly one verdict line:
PASS, FAIL (a recomputed value disagrees) or INCONCLUSIVE (inputs missing).
Exit codes: 0 PASS, 1 FAIL, 2 INCONCLUSIVE. No assert; valid under -O.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / 'artifacts/node/94/hl-node'
BIN_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TABLE, N = 0x3EDE28, 88
LO, HI = 0x2759240, 0x275A376   # dispatcher range [start, end)
TAIL = (0x275A136, 0x275A180, 0x275A182, 0x275A186)
TAIL_RANGE = (0x275A136, 0x275A230)


class Bad(Exception):
    pass


def verdict(word, msg, code):
    print(f'RE-010 independent verify: {word}: {msg}')
    raise SystemExit(code)


class Img:
    def __init__(self, d):
        self.d = d
        phoff, = struct.unpack_from('<Q', d, 0x20)
        phent, phnum = struct.unpack_from('<HH', d, 0x36)
        self.loads = []
        for i in range(phnum):
            p = phoff + i * phent
            typ, = struct.unpack_from('<I', d, p)
            off, va, _pa, fsz = struct.unpack_from('<QQQQ', d, p + 8)
            if typ == 1:
                self.loads.append((va, off, fsz))
        shoff, = struct.unpack_from('<Q', d, 0x28)
        shent, shnum, shstr = struct.unpack_from('<HHH', d, 0x3A)
        hdr = [struct.unpack_from('<IIQQQQ', d, shoff + i * shent) for i in range(shnum)]
        so = hdr[shstr][4]
        self.sec = {}
        for name, typ, _f, va, off, size in hdr:
            nm = d[so + name:d.index(b'\0', so + name)].decode()
            self.sec[nm] = (typ, va, off, size)

    def off(self, va):
        for v, o, s in self.loads:
            if v <= va < v + s:
                return o + va - v
        raise Bad(f'unmapped {va:#x}')

    def rd(self, va, n):
        o = self.off(va)
        return self.d[o:o + n]

    def relative(self):
        out = {}
        for nm, (typ, _va, off, size) in self.sec.items():
            if typ != 4:  # SHT_RELA
                continue
            for k in range(off, off + size, 24):
                r_off, info, add = struct.unpack_from('<QQq', self.d, k)
                if info & 0xFFFFFFFF == 8:
                    out[r_off] = add
        return out


def i32(b, k):
    return struct.unpack_from('<i', b, k)[0]


def h(x):
    return int(x, 16) if isinstance(x, str) else x


def check(img, js):
    disp = js['dispatcher']
    if (h(disp['start']), h(disp['end'])) != (LO, HI):
        raise Bad('dispatcher range')
    rel = img.relative()
    tb = img.rd(TABLE, 4 * N)
    arms = [TABLE + i32(tb, 4 * i) for i in range(N)]
    names = None
    ro = img.sec['.rodata']
    rs, re_ = ro[2], ro[2] + ro[3]
    tables = []
    for m in re.finditer(rb'variant index 0 <= i < 88', img.d[rs:re_]):
        msg_va = ro[1] + m.start()
        for slot, add in rel.items():
            if add != msg_va:
                continue
            base = slot - 16 * N
            got = []
            for k in range(N):
                s = base + 16 * k
                if s not in rel:
                    break
                ln, = struct.unpack_from('<Q', img.rd(s + 8, 8))
                got.append(img.rd(rel[s], ln).decode())
            if len(got) == N:
                tables.append(base)
                if names is None:
                    names = got
                elif got != names:
                    raise Bad('variant tables disagree')
    tables.sort()
    if [h(t['va']) for t in js['variant_tables']] != tables:
        raise Bad(f'variant tables {[hex(t) for t in tables]}')
    if js['variant_names'] != names:
        raise Bad('variant names differ')
    cases = js['unclaimed_cases']
    if [c['index'] for c in cases] != list(range(76, 88)):
        raise Bad('case indices')
    joins = {}
    for c in cases:
        i = c['index']
        if h(c['arm']) != arms[i] or c['serde_name'] != names[i] or c['discriminant'] != 0x74 + i:
            raise Bad(f'case {i} arm/name/discriminant')
        site, tgt = h(c['first_call']['site']), h(c['first_call']['target'])
        b = img.rd(site, 5)
        if b[0] != 0xE8 or site + 5 + i32(b, 1) != tgt or not arms[i] <= site < arms[i] + 0x40:
            raise Bad(f'case {i} first call')
        cont = c['continuation']
        j = img.rd(h(cont['jmp_site']), 5)
        if j[0] != 0xE9 or h(cont['jmp_site']) + 5 + i32(j, 1) != h(cont['to']):
            raise Bad(f'case {i} continuation jmp')
        end = h(cont['to'])
        if 'trampoline' in cont:
            t = img.rd(end, 7)
            if t[0] != 0xB0 or t[2] != 0xE9 or end + 7 + i32(t, 3) != h(cont['trampoline']['to']):
                raise Bad(f'case {i} trampoline')
            end = h(cont['trampoline']['to'])
        if end not in TAIL:
            raise Bad(f'case {i} does not reach the tail')
        joins[end] = joins.get(end, 0) + 1
    if {h(k): v for k, v in js['unclaimed_join_counts'].items()} != joins:
        raise Bad(f'join counts {joins}')
    code = img.rd(LO, HI - LO)
    counts = dict.fromkeys(TAIL, 0)
    for k in range(len(code)):
        b, t = code[k], None
        if b == 0xE9 and k + 5 <= len(code):
            t = LO + k + 5 + i32(code, k + 1)
        elif (b == 0xEB or 0x70 <= b <= 0x7F) and k + 2 <= len(code):
            t = LO + k + 2 + struct.unpack_from('<b', code, k + 1)[0]
        elif b == 0x0F and k + 6 <= len(code) and 0x80 <= code[k + 1] <= 0x8F:
            t = LO + k + 6 + i32(code, k + 2)
        if t in counts:
            counts[t] += 1
    if {h(k): v for k, v in js['tail_branch_source_counts'].items()} != counts:
        raise Bad(f'tail branch counts {counts}')
    tail = img.rd(TAIL_RANGE[0], TAIL_RANGE[1] - TAIL_RANGE[0])
    if hashlib.sha256(tail).hexdigest() != js['tail']['bytes_sha256']:
        raise Bad('tail bytes hash')
    if tail[0x4A:0x4C] != b'\xb0\x0e' or tail[0x50:0x56] != b'\x81\xfd\x00\xca\x9a\x3b':
        raise Bad('tail idioms (mov al,0xe / cmp ebp,1e9)')
    return counts, joins


def main():
    pj = HERE / 'dispatch-tail.json'
    if not BIN.is_file() or not pj.is_file():
        verdict('INCONCLUSIVE', f'missing {BIN if not BIN.is_file() else pj}', 2)
    d = BIN.read_bytes()
    if hashlib.sha256(d).hexdigest() != BIN_SHA:
        verdict('INCONCLUSIVE', 'binary is not the pinned node #94 hl-node', 2)
    try:
        js = json.loads(pj.read_text())
        if js.get('binary_sha256') != BIN_SHA:
            raise Bad('json binary_sha256')
        counts, joins = check(Img(d), js)
    except (Bad, KeyError, ValueError, struct.error) as e:
        verdict('FAIL', str(e), 1)
    verdict('PASS', f'12 cases, tail sources {[counts[t] for t in TAIL]}, joins {sorted(joins.values())}', 0)


if __name__ == '__main__':
    main()
