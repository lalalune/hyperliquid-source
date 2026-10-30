#!/usr/bin/env python3
"""Independent RE-009-B check. Own ELF parse; imports nothing from tools/.

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
JSON_PATH = Path(__file__).resolve().parent / 'lt-hashes-format.json'
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
WRITER = 0x32699c0
SAVE = 0x3c16810
WRITER_CALLERS = [0x326a2e0, 0x326aff3, 0x32fc267]
KEYS = [(0x59b249, b'accounts_hash'), (0x59b256, b'contracts_hash'), (0x59b264, b'storage_hash')]


def verdict(v, ev):
    for line in ev:
        print(line)
    print(v)
    return {'PASS': 0, 'FAIL': 1, 'INCONCLUSIVE': 2}[v]


def main(json_path=None):
    json_path = Path(json_path) if json_path else JSON_PATH
    ev = []
    if not BIN.exists() or not json_path.exists():
        return verdict('INCONCLUSIVE', [f'missing: {BIN if not BIN.exists() else json_path}'])
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

    def rip(va, ln, disp_at):
        return va + ln + struct.unpack_from('<i', rd(va, ln), disp_at)[0]

    checks = []
    # 1. every rel32 call to the writer and to the save helper in .text
    a, o, s = text
    tb = b[o:o + s]
    hits = {WRITER: [], SAVE: []}
    i = tb.find(b'\xe8')
    while i != -1 and i + 5 <= len(tb):
        t = a + i + 5 + struct.unpack_from('<i', tb, i + 1)[0]
        if t in hits:
            hits[t].append(a + i)
        i = tb.find(b'\xe8', i + 1)
    checks.append(('writer callers ' + str([hex(x) for x in hits[WRITER]]), hits[WRITER] == WRITER_CALLERS))
    checks.append(('save helper callers ' + str([hex(x) for x in hits[SAVE]]), hits[SAVE] == [0x3269a7b]))
    # 2. path literal
    checks.append(('path template at lea 0x32699fe', rip(0x32699fe, 7, 3) == 0x201e63
                   and rd(0x201e63, 17) == b'\xc0\x0f/lt_hashes.json'))
    # 3. three 0x810 copies from rec+0xf8/+0xa00/+0x1308
    srcs = [struct.unpack_from('<i', rd(0x3269a15, 7), 3)[0] if rd(0x3269a15, 3) == b'\x48\x8d\xb3' else None,
            struct.unpack_from('<i', rd(0x3269a33, 7), 3)[0] if rd(0x3269a33, 3) == b'\x48\x8d\xb3' else None,
            struct.unpack_from('<i', rd(0x3269a4a, 7), 3)[0]
            if rd(0x3269a4a, 3) == b'\x48\x81\xc3' and rd(0x3269a5e, 3) == b'\x48\x89\xde' else None]
    checks.append((f'copy sources {[hex(x) if x is not None else None for x in srcs]}', srcs == [0xf8, 0xa00, 0x1308]))
    checks.append(('mov edx,0x810 at 0x3269a28/42/59 and 3 in writer',
                   all(rd(va, 5) == b'\xba\x10\x08\x00\x00' for va in (0x3269a28, 0x3269a42, 0x3269a59))
                   and b.count(b'\xba\x10\x08\x00\x00', o + 0x32699c0 - a, o + 0x3269ad1 - a) == 3))
    # 4. /dev/null short circuit
    checks.append(('/dev/null literal', rd(0x3c1683a, 10) == b'\x48\xb8/dev/nul'))
    # 5. keys referenced by both encoders
    for enc, leas in ((0x37e2510, (0x37e2581, 0x37e25a8, 0x37e25cc)), (0x37e21c0, (0x37e2215, 0x37e227d, 0x37e22e9))):
        got = [(rip(va, 7, 3), rd(rip(va, 7, 3), len(k))) for va, (_, k) in zip(leas, KEYS)]
        checks.append((f'{enc:#x} keys {[g[1].decode() for g in got]}', got == KEYS))
    # 5b. every pinned key VA holds exactly its key bytes in the binary
    for va, k in KEYS:
        checks.append((f'key bytes at {va:#x} == {k.decode()}', rd(va, len(k)) == k))
    # 6. JSON markers and MessagePack header bytes
    checks.append(('json "{" store 0x37e21fe', rd(0x37e21fe, 4)[-1:] == b'{'))
    checks.append(('json ": " store 0x37e2256', b'\x3a\x20' in rd(0x37e2256, 8)))
    checks.append(('indent "  " at 0x5b876a', rip(0x3c1690d, 7, 3) == 0x5b876a and rd(0x5b876a, 2) == b'  '))
    checks.append(('map header 0x80/0xdf', rd(0x35981e7, 2) == b'\x34\xdf' and rd(0x35981ef, 5) == b'\xbd\x80\x00\x00\x00'))
    checks.append(('array header 0x90/0xdd', rd(0x3598e37, 2) == b'\x34\xdd' and rd(0x3598e3f, 5) == b'\xbd\x90\x00\x00\x00'))
    checks.append(('msgpack config 0x1000400', rd(0x3c1688e, 8) == bytes.fromhex('c744246000040001')))
    # 7. JSON packet agrees
    j = json.loads(json_path.read_text())
    checks.append(('json fields', [f['name'] for f in j['fields']] == [k.decode() for _, k in KEYS]))
    # every JSON key VA is read back from the binary and must match name, length and the pinned VA
    for f, (va, k) in zip(j['fields'], KEYS):
        jva, jlen = int(f['key_va'], 16), f['key_len']
        checks.append((f"json key_va {f['key_va']} len {jlen} -> {rd(jva, jlen)!r}",
                       jva == va and jlen == len(k) and rd(jva, jlen) == f['name'].encode() == k))
    pool_va = int(j['key_pool']['va'], 16)
    pool = j['key_pool']['text'].encode()
    checks.append((f"json key_pool {j['key_pool']['va']}", pool_va == KEYS[0][0] and rd(pool_va, len(pool)) == pool))
    checks.append(('json callers', j['rel32_callers']['0x32699c0'] == [hex(x) for x in WRITER_CALLERS]))
    for name, ok in checks:
        ev.append(('ok   ' if ok else 'FAIL ') + name)
    return verdict('PASS' if all(ok for _, ok in checks) else 'FAIL', ev)


if __name__ == '__main__':
    sys.exit(main())
