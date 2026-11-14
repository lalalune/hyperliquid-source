#!/usr/bin/env python3
"""Census the node #115 callers of the line writer 0x14c37f0 by framing (stage 79).

Continues the hourly line framing packet (stage 78, open PR #6077), which
split the 96 functions that call the line writer 0x14c37f0 into 21 that call
the time writer 0x4fcd860, 39 that store '[' (c6 00 5b) without it, and 36
that do neither. This tool binds what the 39 bracket framers call first after
their '[' store:

1. 29 call 0x2506050 and 4 call 0x4779470. Both are quoted time writers with
   the same shape as 0x4fcd860: '"', core::fmt::write (slot 0x64df6f0) with a
   Display function, '"'. Their Display functions 0x26a1370 and 0x4783120
   call the date slot 0x64e1158, write 'T' (mov esi, 0x54) and tail-jump to
   the time slot 0x64e1160, the same three steps as 0x57a6f10 from stage 78;
2. the other 6 start with a non-time value: 0x4e2d7f0 (x2, stores "0x" as
   0x7830, hex), 0x3d3f240 and 0x3d40850 (hex digit table 0x455d40),
   0x50fc010 (decimal u64, #6036) and 0x50a3510 (string escaper, #6036);
3. writer names: only 0x50e50b0 reaches a static writer name
   (visor_abci_states) within two call levels in this census.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import bisect
import json
import re
import struct
from collections import Counter
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
from freeze_snapshot_115 import fixed, read_va, rip_target, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-line-framer-census-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

LINE_WRITER = 0x14c37f0
TIME_WRITER = 0x4fcd860
TWIN_A = 0x2506050
TWIN_B = 0x4779470
DISPLAY_78 = 0x57a6f10
DISPLAY_A = 0x26a1370
DISPLAY_B = 0x4783120
FMT_SLOT = 0x64df6f0
DATE_SLOT = 0x64e1158
TIME_SLOT = 0x64e1160
HEX_TABLE = 0x455d40
VISOR_FRAMER = 0x50e50b0
HASHES_FRAMER = 0x50e5fc0
QUORUM_FRAMER = 0x50e6fe0
FIRST_VALUE = {
    TWIN_A: 'quoted time (twin of 0x4fcd860, Display 0x26a1370)',
    TWIN_B: 'quoted time (twin of 0x4fcd860, Display 0x4783120)',
    0x4e2d7f0: 'hex with "0x" prefix (mov word 0x7830)',
    0x3d3f240: 'hex (digit table 0x455d40)',
    0x3d40850: 'hex (digit table 0x455d40)',
    0x50fc010: 'decimal u64 (#6036)',
    0x50a3510: 'escaped string (#6036)',
}

FIXED = {
    # twin A 0x2506050: quote, fmt::write(Display 0x26a1370), quote
    0x2506079: 'c6043022',
    0x25060dc: 'c6043022',
    # twin B 0x4779470
    0x47794ad: 'c6043022',
    # Display A / B: 'T' between date and time
    0x26a1394: 'be54000000',
    0x4783144: 'be54000000',
    # hex writers
    0x4e2d811: '66c744240630 78'.replace(' ', ''),
}
REFERENCES = (
    # (va, prefix, length, target)
    (0x25060a0, b'\x48\x8d\x05', 7, DISPLAY_A),
    (0x25060c2, b'\xff\x15', 6, FMT_SLOT),
    (0x47794d4, b'\x48\x8d\x05', 7, DISPLAY_B),
    (0x47794f6, b'\xff\x15', 6, FMT_SLOT),
    (0x26a1383, b'\xff\x15', 6, DATE_SLOT),
    (0x26a13bb, b'\xff\x25', 6, TIME_SLOT),
    (0x4783133, b'\xff\x15', 6, DATE_SLOT),
    (0x478316b, b'\xff\x25', 6, TIME_SLOT),
    (0x57a6f23, b'\xff\x15', 6, DATE_SLOT),
    (0x57a6f5b, b'\xff\x25', 6, TIME_SLOT),
    (0x3d3f283, b'\x48\x8d\x0d', 7, HEX_TABLE),
    (0x3d4089d, b'\x48\x8d\x05', 7, HEX_TABLE),
)
WRITER_NAMES = (
    'mempool_txs', 'tcp_traffic', 'tcp_lz4_stats', 'evm_block_and_receipts',
    'dex_user_clearinghouse_states', 'visor_abci_states', 'abci_digest_quorum',
    'abci_hashes', 'validator_latency_ema', 'node_trades', 'node_fills',
    'node_order_statuses', 'system_and_core_writer_actions', 'misc_events',
)


def index_calls(base, code):
    calls = {}
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code):
            calls.setdefault(base + i + 5 + struct.unpack_from('<i', code, i + 1)[0], []).append(base + i)
    return calls


def index_leas(base, code):
    leas = {}
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = m.start()
        if i + 7 <= len(code):
            leas.setdefault(base + i + 7 + struct.unpack_from('<i', code, i + 3)[0], []).append(base + i)
    return leas


def frame_finder(fdes):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]

    def find(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
            return None
        return ordered[i]['start'], ordered[i]['end']
    return find


def calls_in(base, code, lo, hi):
    body = code[lo - base:hi - base]
    out = []
    for m in re.finditer(rb'\xe8', body):
        k = m.start()
        if k + 5 <= len(body):
            out.append((lo + k, lo + k + 5 + struct.unpack_from('<i', body, k + 1)[0]))
    return out


def display_steps(data, va):
    """Date slot call, 'T', time slot tail-jump: the 0x57a6f10 shape."""
    raw = read_va(data, va, 0x60)
    if raw[0x13:0x15] != b'\xff\x15' or raw[0x24:0x29] != b'\xbe\x54\x00\x00\x00' or raw[0x4b:0x4d] != b'\xff\x25':
        raise ValueError(f'display {va:#x} changed')
    date = rip_target(data, va + 0x13, b'\xff\x15', 6)
    time = rip_target(data, va + 0x4b, b'\xff\x25', 6)
    return date, time


def name_functions(data, leas, find):
    ro = next(s for s in sections(data) if s['name'] == '.rodata')
    blob = data[ro['offset']:ro['offset'] + ro['size']]
    out = {}
    for name in WRITER_NAMES:
        for m in re.finditer(re.escape(name.encode()), blob):
            for site in leas.get(ro['address'] + m.start(), []):
                f = find(site)
                if f:
                    out.setdefault(name, set()).add(f[0])
    return out


def ancestors(start, calls, find, depth):
    seen, frontier = {start}, {start}
    for _ in range(depth):
        nxt = set()
        for g in frontier:
            for c in calls.get(g, []):
                f = find(c)
                if f and f[0] not in seen:
                    seen.add(f[0])
                    nxt.add(f[0])
        frontier = nxt
    return seen


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    displays = {hex(va): display_steps(data, va) for va in (DISPLAY_78, DISPLAY_A, DISPLAY_B)}
    if len(set(displays.values())) != 1 or displays[hex(DISPLAY_78)] != (DATE_SLOT, TIME_SLOT):
        raise ValueError('display shapes differ')

    base, code = text(data)
    find = frame_finder(fdes)
    calls = index_calls(base, code)
    leas = index_leas(base, code)
    sites = calls.get(LINE_WRITER, [])
    fns = sorted({find(v) for v in sites if find(v)})

    rows, classes, first = [], Counter(), Counter()
    for lo, hi in fns:
        body = code[lo - base:hi - base]
        inner = calls_in(base, code, lo, hi)
        timed = any(t == TIME_WRITER for _, t in inner)
        b = body.find(b'\xc6\x00\x5b')
        row = {'fn': hex(lo)}
        if timed:
            row['framing'] = '[time,value] via 0x4fcd860'
            classes['time_writer'] += 1
        elif b >= 0:
            after = [t for a, t in inner if a > lo + b]
            head = after[0] if after else None
            if head not in FIRST_VALUE:
                raise ValueError(f'unexpected first value writer in {lo:#x}')
            row['first_after_bracket'] = hex(head)
            row['framing'] = '[%s,value]' % FIRST_VALUE[head]
            first[hex(head)] += 1
            classes['twin_time' if head in (TWIN_A, TWIN_B) else 'bracket_other'] += 1
        else:
            row['framing'] = 'bare'
            classes['bare'] += 1
        rows.append(row)

    names = name_functions(data, leas, find)
    tied = {}
    for row in rows:
        f = int(row['fn'], 16)
        hits = sorted(n for n, fs in names.items() if fs & ancestors(f, calls, find, 2))
        row['writer'] = ','.join(hits) if hits else 'untied'
        if hits:
            tied[row['fn']] = hits
    for va, label in ((HASHES_FRAMER, 'abci_hashes (#6034, by call path)'),
                      (QUORUM_FRAMER, 'abci_digest_quorum (#6033, by call path)')):
        row = next(r for r in rows if r['fn'] == hex(va))
        if row['framing'] != 'bare':
            raise ValueError('bare framer changed')
        row['writer'] = label

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'line_writer': hex(LINE_WRITER),
        'call_sites': len(sites),
        'functions': len(fns),
        'classes': dict(sorted(classes.items())),
        'bracket_first_value_writers': dict(sorted(first.items())),
        'twin_time_writers': {
            hex(TWIN_A): "'\"' (0x2506079), core::fmt::write slot 0x64df6f0 (0x25060c2) with Display 0x26a1370, '\"' (0x25060dc)",
            hex(TWIN_B): "'\"' (0x47794ad), core::fmt::write slot 0x64df6f0 (0x47794f6) with Display 0x4783120",
        },
        'displays': {k: {'date_slot': hex(v[0]), 'T': 'mov esi, 0x54', 'time_slot': hex(v[1])}
                     for k, v in displays.items()},
        'name_ties_within_two_call_levels': tied,
        'rows': rows,
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
    print('classes=%s first=%s' % (result['classes'], result['bracket_first_value_writers']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
