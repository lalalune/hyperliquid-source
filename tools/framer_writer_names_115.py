#!/usr/bin/env python3
"""Tie the node #115 line framers in 0x25ebdb0..0x25f7350 to writers (stage 80).

Continues the line framer census (stage 79, RE-008-line-framer-census-115), which counted the direct
callers of the line writer 0x14c37f0 and found a block of framers between
0x25ebdb0 and 0x25f7350 that write a quoted time first. This tool binds:

1. the census of that block: every function whose FDE starts in
   [0x25ebdb0, 0x25f7350) and that calls 0x14c37f0 directly (30), split by
   whether it calls the time writer 0x2506050 (28) or not (2), with the
   record serializer it calls, its caller ("wrapper") and the wrapper's
   callers;
2. two bare framers as byte twins of the abci log framers: 0x25f19b0 of the
   abci_hashes framer 0x50e5fc0 (#6034) and 0x25f4be0 of the
   abci_digest_quorum framer 0x50e6fe0 (#6033); every differing byte lies in
   a rel32 or RIP displacement whose targets are equal or a listed twin;
3. their record serializers 0x28b5780 / 0x28b5950 as twins of 0x537d5e0 /
   0x537d7b0, loading the same field names (height, abci_digest,
   exchange_abci_hash; height, d) from a second copy of the strings;
4. the callers: 0x25f19b0 is reached through 0x2d4ca40 (twin of 0x4e3a7a0)
   from the catch-up digest step 0x2bb37c0 (#6058), whose call window is a
   twin of the layout-A digest step window in 0x548dad0; 0x25f4be0 is called
   from the catch-up wrapper 0x2d23610 (#6058).

The other 28 framers are reached from functions in the block-and-transaction
handler and peer code. Their writers are not traced here. The captured
binary is not executed. objdump and readelf are not started.
"""
import argparse
import bisect
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import SHA256, read_va, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-framer-writer-names-115'

LINE_WRITER = 0x14c37f0
TIME_WRITER = 0x2506050
BLOCK = (0x25ebdb0, 0x25f7350)
HELPERS = {TIME_WRITER, 0x25bf330, LINE_WRITER, 0x14cac50, 0x231e050}

# (catch-up copy, reference copy, length) — reference copies come from #6033/#6034/#6058.
TWINS = (
    (0x25f19b0, 0x50e5fc0, 0x184),   # abci_hashes framer
    (0x25f4be0, 0x50e6fe0, 0x184),   # abci_digest_quorum framer
    (0x28b5780, 0x537d5e0, 0x143),   # abci_hashes record serializer
    (0x28b5950, 0x537d7b0, 0x119),   # abci_digest_quorum record serializer
    (0x2d4ca40, 0x4e3a7a0, 0x1dd),   # abci_hashes line wrapper
    (0x2bb38a6, 0x548dbb6, 0x48),    # digest step call window (catch-up 0x2bb37c0, A 0x548dad0)
)
FIELDS = {
    0x28b5780: [(0x5ff124, b'height'), (0x5ff768, b'abci_digest'), (0x5ff773, b'exchange_abci_hash')],
    0x28b5950: [(0x5ff124, b'height'), (0x5fec4d, b'd')],
}
FIELD_LENGTHS = {va: len(name) for fields in FIELDS.values() for va, name in fields}
NAMES = {0x25f19b0: 'abci_hashes', 0x25f4be0: 'abci_digest_quorum'}
CALLER_EDGES = {0x25f19b0: (0x2d4ca40, 0x2bb38e9, 0x2bb37c0), 0x25f4be0: (0x2d23610, 0x2d24b1a, 0x2d23610)}


def call_index(data):
    """Every E8 call in .text as target -> [call sites]."""
    base, code = text(data)
    index = {}
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code):
            index.setdefault(base + i + 5 + struct.unpack_from('<i', code, i + 1)[0], []).append(base + i)
    return index


def frames(fdes):
    ordered = sorted((f['start'], f['end']) for f in fdes)
    starts = [s for s, _ in ordered]

    def frame(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not ordered[i][0] <= va < ordered[i][1]:
            raise ValueError(f'{va:#x} has no FDE')
        return ordered[i]
    return frame


def callees(data, frame, start):
    lo, hi = frame(start)
    code = read_va(data, lo, hi - lo)
    out = []
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code):
            t = lo + i + 5 + struct.unpack_from('<i', code, i + 1)[0]
            try:
                if frame(t)[0] == t:
                    out.append(t)
            except ValueError:
                pass
    return out


def field_at(raw, i):
    """Start of the rel32 / RIP disp32 field covering byte i, or None."""
    for k in range(max(0, i - 3), i + 1):
        if k >= 1 and raw[k - 1] == 0xe8:
            return k, 'call'
        if k >= 2 and raw[k - 2:k] == b'\xff\x15':
            return k, 'slot'
        if k >= 3 and raw[k - 3] in (0x48, 0x4c) and raw[k - 2] in (0x8b, 0x8d) and raw[k - 1] & 0xc7 == 0x05:
            return k, 'rip'
    return None


def twin(data, frame, a, b, n):
    """Compare two copies; every differing byte must sit in a displacement field.

    A differing call field must reach two function starts with equal FDE lengths.
    """
    ra, rb = read_va(data, a, n), read_va(data, b, n)
    fields = {}
    for i in range(n):
        if ra[i] != rb[i]:
            hit = field_at(ra, i)
            if hit is None or field_at(rb, i) != hit:
                raise ValueError(f'twin byte {a + i:#x} outside a displacement field')
            fields[hit[0]] = hit[1]
    pairs = []
    for k, kind in sorted(fields.items()):
        ta = a + k + 4 + struct.unpack_from('<i', ra, k)[0]
        tb = b + k + 4 + struct.unpack_from('<i', rb, k)[0]
        if kind == 'slot' and ta != tb:
            raise ValueError(f'slot field at {a + k:#x} differs')
        size = FIELD_LENGTHS.get(ta, 6)
        if kind == 'rip' and read_va(data, ta, size) != read_va(data, tb, size):
            raise ValueError(f'rip field at {a + k:#x} reaches different bytes')
        if kind == 'call' and ta != tb:
            fa, fb = frame(ta), frame(tb)
            if fa[0] != ta or fb[0] != tb or fa[1] - fa[0] != fb[1] - fb[0]:
                raise ValueError(f'call field at {a + k:#x} reaches {ta:#x} / {tb:#x}, not equal-length functions')
        pairs.append([hex(a + k), kind, hex(ta), hex(tb)])
    return {'copy': hex(a), 'reference': hex(b), 'length': hex(n),
            'differing_fields': len(fields), 'fields': pairs}


def printable(data, va, limit=24):
    raw = read_va(data, va, limit)
    out = bytearray()
    for b in raw:
        if not 32 <= b < 127:
            break
        out.append(b)
    return out.decode()


def first_string(data, frame, start, minimum=8):
    """First RIP-relative lea in the function that reaches >= minimum printable bytes."""
    lo, hi = frame(start)
    code = read_va(data, lo, hi - lo)
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = m.start()
        t = lo + i + 7 + struct.unpack_from('<i', code, i + 3)[0]
        try:
            s = printable(data, t)
        except ValueError:
            continue
        if len(s) >= minimum:
            return [hex(lo + i), hex(t), s]
    return None


def bind(data, fdes):
    frame = frames(fdes)
    index = call_index(data)
    framers = sorted({frame(c)[0] for c in index.get(LINE_WRITER, []) if BLOCK[0] <= frame(c)[0] < BLOCK[1]})
    if len(framers) != 30:
        raise ValueError('framer census changed')
    rows, callers = [], {}
    for x in framers:
        out = callees(data, frame, x)
        serializer = next((t for t in out if t not in HELPERS), None)
        wrappers = sorted({frame(c)[0] for c in index.get(x, [])})
        wcallers = sorted({frame(c)[0] for w in wrappers for c in index.get(w, [])})
        for w in wcallers:
            callers.setdefault(w, set()).add(x)
        rows.append({'framer': hex(x), 'time_writer': TIME_WRITER in out,
                     'serializer': hex(serializer) if serializer else None,
                     'wrappers': [hex(w) for w in wrappers],
                     'wrapper_callers': [hex(w) for w in wcallers],
                     'writer': NAMES.get(x, 'untied')})
    timed = sum(r['time_writer'] for r in rows)
    if timed != 28:
        raise ValueError('time framer count changed')

    twins = [twin(data, frame, a, b, n) for a, b, n in TWINS]
    for ser, fields in FIELDS.items():
        for va, name in fields:
            if read_va(data, va, len(name)) != name:
                raise ValueError(f'field name at {va:#x} changed')
    edges = {}
    for x, (wrapper, call, owner) in CALLER_EDGES.items():
        if call not in index.get(wrapper if wrapper != owner else x, []) and call not in index.get(x, []):
            raise ValueError(f'caller edge {call:#x} changed')
        if frame(call)[0] != owner:
            raise ValueError(f'caller {call:#x} not in {owner:#x}')
        edges[hex(x)] = {'wrapper': hex(wrapper), 'call': hex(call), 'in': hex(owner)}

    clusters = {hex(w): {'framers': sorted(hex(f) for f in fs), 'first_string': first_string(data, frame, w)}
                for w, fs in sorted(callers.items())}
    return {
        'target': RELATIVE, 'sha256': SHA256, 'task': 'RE-008', 'component': 'abci',
        'block': [hex(v) for v in BLOCK],
        'framers': rows,
        'counts': {'framers': len(rows), 'time_writer': timed, 'bare': len(rows) - timed,
                   'tied': sum(r['writer'] != 'untied' for r in rows)},
        'twins': twins,
        'record_fields': {hex(s): [[hex(v), n.decode()] for v, n in fs] for s, fs in FIELDS.items()},
        'tied_edges': edges,
        'wrapper_caller_clusters': clusters,
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    c = result['counts']
    print('framers=%d time=%d bare=%d tied=%d' % (c['framers'], c['time_writer'], c['bare'], c['tied']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
