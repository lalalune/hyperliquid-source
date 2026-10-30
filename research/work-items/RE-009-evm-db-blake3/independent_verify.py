#!/usr/bin/env python3
"""Independent RE-009 blake3 check. Own ELF parse; imports nothing from tools/.

Verdict: PASS (every check holds), FAIL (a check contradicts the claim),
INCONCLUSIVE (binary or JSON missing / wrong binary). Evidence lines are printed.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / 'artifacts/node/94/hl-node'
JSON_PATH = Path(__file__).resolve().parent / 'evm-db-blake3.json'
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FN = 0x3269ae0
CALLERS = [0x326e4bb, 0x32fc41f]


def verdict(v, ev):
    for line in ev:
        print(line)
    print(v)
    return {'PASS': 0, 'FAIL': 1, 'INCONCLUSIVE': 2}[v]


def main():
    ev = []
    if not BIN.exists() or not JSON_PATH.exists():
        return verdict('INCONCLUSIVE', [f'missing: {BIN if not BIN.exists() else JSON_PATH}'])
    b = BIN.read_bytes()
    h = hashlib.sha256(b).hexdigest()
    ev.append(f'binary sha256 {h}')
    if h != SHA:
        return verdict('INCONCLUSIVE', ev + ['not node #94'])
    shoff, = struct.unpack_from('<Q', b, 0x28)
    n, = struct.unpack_from('<H', b, 0x3c)
    shstr, = struct.unpack_from('<H', b, 0x3e)
    secs = [struct.unpack_from('<IIQQQQ', b, shoff + 64 * i) for i in range(n)]
    stro = secs[shstr][4]
    segs, text = [], None
    for nm, t, _, a, o, s in secs:
        name = b[stro + nm:b.index(b'\0', stro + nm)]
        if a and t != 8:
            segs.append((a, o, s))
        if name == b'.text':
            text = (a, o, s)

    def rd(va, k):
        for a, o, s in segs:
            if a <= va < a + s:
                return b[o + va - a:o + va - a + k]
        return b''

    def tgt(va):
        x = rd(va, 6)
        if x[:1] == b'\xe8':
            return va + 5 + struct.unpack_from('<i', x, 1)[0]
        if x[:2] == b'\xff\x15':
            return ('slot', va + 6 + struct.unpack_from('<i', x, 2)[0])
        return None

    bad = []
    calls = [(0x3269cd1, ('slot', 0x57700c0)), (0x3269eec, ('slot', 0x57700c0)), (0x326a0f8, ('slot', 0x57700c0)),
             (0x3269d96, ('slot', 0x57700c8)), (0x3269fb1, ('slot', 0x57700c8)), (0x326a1bd, ('slot', 0x57700c8)),
             (0x3269dac, ('slot', 0x57700d0)), (0x3269fc7, ('slot', 0x57700d0)), (0x326a1d3, ('slot', 0x57700d0)),
             (0x3269c5c, 0x358cea0), (0x3269e77, 0x358d720), (0x326a086, 0x358d2e0),
             (0x326a2e0, 0x32699c0)]
    for va, want in calls:
        got = tgt(va)
        ev.append(f'call {va:#x} -> {got}')
        if got != want:
            bad.append(f'{va:#x}')
    for va in (0x3269d91, 0x3269fac, 0x326a1b8):
        ok = rd(va, 5) == b'\xba\x00\x08\x00\x00'
        ev.append(f'{va:#x} mov edx,0x800 {ok}')
        if not ok:
            bad.append(f'{va:#x}')
    # digest-slot first writes: mov [rsp+slot],r14 = 4c 89 b4 24 <disp32>
    for va, slot in ((0x3269dcb, 0x2e90), (0x3269fe0, 0x2580), (0x326a1ec, 0x150)):
        ok = rd(va, 8) == b'\x4c\x89\xb4\x24' + struct.pack('<I', slot)
        ev.append(f'{va:#x} mov [rsp+{slot:#x}],r14 {ok}')
        if not ok:
            bad.append(f'{va:#x}')
    a, o, s = text
    tb = b[o:o + s]
    callers, i = [], tb.find(b'\xe8')
    while i != -1 and i + 5 <= len(tb):
        if a + i + 5 + struct.unpack_from('<i', tb, i + 1)[0] == FN:
            callers.append(a + i)
        i = tb.find(b'\xe8', i + 1)
    ev.append(f'rel32 callers of {FN:#x}: {[hex(c) for c in callers]}')
    if callers != CALLERS:
        bad.append('callers')
    j = json.loads(JSON_PATH.read_text())
    jc = (j['function']['rel32_callers'], [r['update_args']['rdx'] for r in j['rounds']],
          [r['finalize_out'] for r in j['rounds']], j['target']['sha256'])
    ev.append(f'json {jc}')
    if jc != ([hex(c) for c in CALLERS], [0x800] * 3, ['rsp+0x2e90', 'rsp+0x2580', 'rsp+0x150'], SHA):
        bad.append('json')
    return verdict('FAIL' if bad else 'PASS', ev + ([f'mismatch: {bad}'] if bad else []))


if __name__ == '__main__':
    sys.exit(main())
