#!/usr/bin/env python3
"""Bind the line framing of the node #115 hourly visor_abci_states log (stage 78).

Stage 77b found that the 'node save visor_abci_state' thread appends one line
to the hourly visor_abci_states log through 0x4e3fe00 -> 0x50e50b0 -> the
compact serializer 0x51addb0. This tool binds:

1. the framer 0x50e50b0: it writes '[', the time through 0x4fcd860, ',', the
   value through 0x51addb0, ']' and a newline, then calls the line writer
   0x14c37f0;
2. the time writer 0x4fcd860: a quoted string. It writes '"', calls
   core::fmt::write (slot 0x64df6f0) with the pieces table 0x649ffd0 and the
   Display function 0x57a6f10, then '"';
3. 0x57a6f10: the date part through slot 0x64e1158 (0x1628bc0, which writes
   '-' separators), the character 'T', then a tail jump through slot
   0x64e1160 (0x162a760, which writes ':' separators and compares the
   nanoseconds with 1000000000) on the value at +4;
4. the two other hourly writers keep a bare object line: the abci_hashes
   framer 0x50e5fc0 (#6034) and the abci_digest_quorum framer 0x50e6fe0
   (#6033) call their serializer and append only a newline;
5. a byte-shape census of the 96 functions that call 0x14c37f0, by whether
   they call 0x4fcd860 and whether they store '[' at a fresh buffer.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check, manifest_item  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from freeze_snapshot_115 import frame, read_va, relative_relocations, text  # noqa: E402

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-hourly-line-framing-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

FRAMER = 0x50e50b0
TIME_WRITER = 0x4fcd860
DISPLAY = 0x57a6f10
LINE_WRITER = 0x14c37f0
COMPACT = 0x51addb0
HASHES_FRAMER = 0x50e5fc0
QUORUM_FRAMER = 0x50e6fe0

FIXED = {
    # framer 0x50e50b0
    0x50e50ed: 'c6005b',            # mov byte [rax], '['
    0x50e5112: 'e84987eeff',        # call 0x4fcd860 (time)
    0x50e513d: 'c604302c',          # mov byte [rax+rsi], ','
    0x50e5151: 'e85a8c0c00',        # call 0x51addb0 (compact value)
    0x50e51d4: 'c604305d',          # mov byte [rax+rsi], ']'
    0x50e521b: '41c604060a',        # mov byte [r14+rax], '\n'
    0x50e5231: 'e8bae53dfc',        # call 0x14c37f0 (line writer)
    # time writer 0x4fcd860
    0x4fcd889: 'c6043022',          # '"'
    0x4fcd8b0: '488d0559967d00',    # lea rax, 0x57a6f10 (Display)
    0x4fcd8bc: '488d350d274d01',    # lea rsi, 0x649ffd0 (pieces)
    0x4fcd8d2: 'ff15181e5101',      # call [0x64df6f0] (core::fmt::write)
    0x4fcd8ec: 'c6043022',          # '"'
    # Display 0x57a6f10
    0x57a6f23: 'ff152fa2d300',      # call [0x64e1158] (date)
    0x57a6f34: 'be54000000',        # mov esi, 'T'
    0x57a6f4a: '4983c604',          # add r14, 4 (time part)
    0x57a6f5b: 'ff25ffa1d300',      # jmp [0x64e1160] (time)
    0x1628d09: 'be2d000000',        # date: mov esi, '-'
    0x162a81f: 'be3a000000',        # time: mov esi, ':'
    0x162a789: '81f900ca9a3b',      # time: cmp ecx, 1000000000
    # bare framers
    0x50e600e: 'e8cd752900',        # 0x50e5fc0: call 0x537d5e0 (abci_hashes record)
    0x50e60bb: 'c604030a',          # 0x50e5fc0: '\n'
    0x50e702e: 'e87d672900',        # 0x50e6fe0: call 0x537d7b0 (abci_digest_quorum record)
    0x50e70db: 'c604030a',          # 0x50e6fe0: '\n'
    # writers -> framers
    0x4e3ff5c: 'e84f512a00',        # visor_abci_states: call 0x50e50b0
    0x4e3a8dc: 'e8dfb62a00',        # abci_hashes (#6034): call 0x50e5fc0
    0x4e3a15c: 'e87fce2a00',        # abci_digest_quorum (#6033): call 0x50e6fe0
}
RELOCATIONS = {0x64df6f0: 0x1680500, 0x64e1158: 0x1628bc0, 0x64e1160: 0x162a760}


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def direct_call_sites(code, base, target):
    out = []
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code) and base + i + 5 + struct.unpack_from('<i', code, i + 1)[0] == target:
            out.append(base + i)
    return out


def callees(code, base, lo, hi):
    body = code[lo - base:hi - base]
    out = set()
    for m in re.finditer(rb'\xe8', body):
        k = m.start()
        if k + 5 <= len(body):
            out.add(lo + k + 5 + struct.unpack_from('<i', body, k + 1)[0])
    return out


def extents(fdes):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]

    def find(va):
        import bisect
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
            raise ValueError(f'{va:#x} has no FDE')
        return ordered[i]['start'], ordered[i]['end']
    return find


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    find = extents(fdes)
    if frame(fdes, 0x50e5112) != FRAMER or frame(fdes, 0x4fcd8d2) != TIME_WRITER:
        raise ValueError('framer extents changed')
    base, code = text(data)

    # census of line-writer callers
    sites = direct_call_sites(code, base, LINE_WRITER)
    fns = sorted({find(v) for v in sites})
    classes = Counter()
    by_fn = {}
    for lo, hi in fns:
        body = code[lo - base:hi - base]
        timed = TIME_WRITER in callees(code, base, lo, hi)
        bracket = b'\xc6\x00\x5b' in body
        cls = 'time_framed' if timed else ('bracket_no_time' if bracket else 'other')
        classes[cls] += 1
        by_fn[lo] = cls
    if by_fn.get(FRAMER) != 'time_framed':
        raise ValueError('visor framer not time-framed')
    for bare in (HASHES_FRAMER, QUORUM_FRAMER):
        if by_fn.get(bare) != 'other' or TIME_WRITER in callees(code, base, *find(bare)):
            raise ValueError('bare framer changed')
    time_calls = direct_call_sites(code, base, TIME_WRITER)

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'visor_abci_states_line': {
            'writer_call': hex(0x4e3ff5c) + ' -> framer ' + hex(FRAMER),
            'framing': "'[' (0x50e50ed), time via %s, ',' (0x50e513d), value via %s, ']' (0x50e51d4), "
                       "'\\n' (0x50e521b), line writer %s (0x50e5231)" % (hex(TIME_WRITER), hex(COMPACT), hex(LINE_WRITER)),
            'shape': '[<"time">,<compact visor_abci_state object>]\\n',
        },
        'time_writer': {
            'fn': hex(TIME_WRITER),
            'quotes': [hex(0x4fcd889), hex(0x4fcd8ec)],
            'format': 'core::fmt::write via slot 0x64df6f0 -> 0x1680500, pieces 0x649ffd0, Display ' + hex(DISPLAY),
            'display': "date via slot 0x64e1158 -> 0x1628bc0 ('-' at 0x1628d09), 'T' (0x57a6f34), "
                       "time at +4 via slot 0x64e1160 -> 0x162a760 (':' at 0x162a81f, nanos vs 1e9 at 0x162a789)",
            'direct_calls': len(time_calls),
        },
        'other_hourly_writers': {
            'abci_hashes (#6034)': hex(0x4e3a8dc) + ' -> ' + hex(HASHES_FRAMER) + ': record 0x537d5e0, then \\n (0x50e60bb); no time, no [ ]',
            'abci_digest_quorum (#6033)': hex(0x4e3a15c) + ' -> ' + hex(QUORUM_FRAMER) + ': record 0x537d7b0, then \\n (0x50e70db); no time, no [ ]',
        },
        'line_writer_census': {
            'call_sites': len(sites),
            'functions': len(fns),
            'classes': dict(sorted(classes.items())),
            'rule': "time_framed = calls 0x4fcd860; bracket_no_time = stores '[' at [rax] (c6 00 5b) without it; other = neither",
        },
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
    c = result['line_writer_census']
    print(f"line_writer_fns={c['functions']} classes={c['classes']} time_calls={result['time_writer']['direct_calls']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
