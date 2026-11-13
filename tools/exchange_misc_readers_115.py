#!/usr/bin/env python3
"""Bind the node #115 readers of the ExchangeMisc scalar fields (stage 93).

Continues #6099 (ExchangeMisc field offsets, box +0x3908 in layout A and
+0x4478 in layout B) and #6023 (abci digest cadence). This tool binds:

1. a census of [reg+disp32] operands (no SIB) at the scalar fields aci (+0xc0),
   mtpt (+0xc8), pmc (+0xe8), tde (+0xf4) and tce (+0xf5) of ExchangeMisc, in
   both box layouts, with the function (FDE) holding each one;
2. aci: every reader divides the block height by it (`div`) and branches on a
   zero remainder, beside the freeze-height checks; the two step functions
   use it for the abci digest cadence of #6023; the dispatchers store it;
3. tce and tde: four handlers return error tag 0xdd when tce is clear and
   0xdc when tde is clear; when tce is set a u64 argument must lie in
   5..=10080 or the handler returns 0xd1;
4. pmc: a 12-byte date-time whose date dword 0xf6401a decodes as chrono
   NaiveDate 1970-01-01 (unset); begin_block A resets it to that value and,
   when it is set, adds 600.0 s through the #5861 time helpers.

The captured binary is not executed. objdump is not started.
"""
import argparse
import bisect
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
from freeze_snapshot_115 import read_va

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-exchange-misc-readers-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

MISC_A, MISC_B = 0x3908, 0x4478
FIELDS = {'aci': 0xc0, 'mtpt': 0xc8, 'pmc': 0xe8, 'tde': 0xf4, 'tce': 0xf5}
EPOCH_DATE = 0xf6401a
F600 = (0x459568, 600.0)

FIXED = {
    # aci: height % aci in both steps (#6023 digest cadence)
    0x5a07f85: '488b8ec8390000',      # mov rcx, [rsi+0x39c8]   (A step 0x5a07ec0)
    0x5a07f9d: '48f7f1',              # div rcx
    0x5a087e5: '488b8e38450000',      # mov rcx, [rsi+0x4538]   (B step 0x5a08720)
    0x5a087fd: '48f7f1',              # div rcx
    0x59ec6a2: '488bb1c8390000',      # slow step wrapper 0x59ec200
    0x59ecf6b: '488bb0c8390000',
    0x5443d92: '488bb1c8390000',      # visor_abci_state writer 0x5443930
    0x5a6c918: '4c8b80c8390000',      # 0x5a6c8f0
    0x2d257bc: '488b8ec8390000',      # catch-up step 0x2d25620
    # aci / mtpt stores in the action dispatchers
    0x539337c: '49898dc8390000',      # A 0x538cd30
    0x539e19c: '49898d38450000',      # B 0x5397b50
    0x5392468: '498b4710',            # mov rax, [r15+0x10]
    0x539247f: '498985d0390000',      # A mtpt store
    0x539d29f: '49898540450000',      # B mtpt store
    # mtpt readers
    0x5aedd60: '498b87d0390000',
    0x5af2044: '498b8ed0390000',
    # tce / tde gates (handler 0x57c9f60)
    0x57c9f71: '80b9fd39000000',      # cmp byte [rcx+0x39fd], 0
    0x57c9f7e: '4c8d809fd8ffff',      # lea r8, [rax-0x2761]
    0x57c9f85: '4981f8a4d8ffff',      # cmp r8, -0x275c
    0x57c9f8e: '66c707d100',          # error 0xd1
    0x57c9f9c: '66c707dd00',          # error 0xdd
    0x57ca27c: '80b8fc39000000',      # cmp byte [rax+0x39fc], 0
    0x57ca419: '66c707dc00',          # error 0xdc
    # pmc in begin_block A 0x54b66b0
    0x54bfe3c: '41c787f839000000000000',
    0x54bfe47: '49c787f03900001a40f600',
    0x54c018d: '8b99f0390000',
    0x54c01a1: '81f21a40f600',
    0x54c01c6: 'f20f10059a93f9fa',
}
GATE_HANDLERS = (0x57c9f60, 0x57ca550, 0x57caa40, 0x57caf30)


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec['address'], data[sec['offset']:sec['offset'] + sec['size']]


def census(data, disp):
    """[reg+disp32] operands (mod=10, rm!=4) carrying disp; returns operand-start addresses."""
    base, code = text(data)
    hits = []
    for m in re.finditer(re.escape(struct.pack('<i', disp)), code):
        i = m.start()
        modrm = code[i - 1]
        if modrm >> 6 != 2 or modrm & 7 == 4:
            continue
        op = code[i - 2]
        if op in (0x8b, 0x89, 0x80, 0xc6, 0x88, 0x8a, 0xc7, 0x83, 0x81, 0x39, 0x3b, 0xb6):
            hits.append(base + i - 1)
    return hits


def frame_of(fdes):
    o = sorted(fdes, key=lambda f: f['start'])
    st = [f['start'] for f in o]

    def f(va):
        i = bisect.bisect_right(st, va) - 1
        if i < 0 or not o[i]['start'] <= va < o[i]['end']:
            return None
        return o[i]['start']
    return f


def naive_date(v):
    return v >> 13, (v >> 4) & 0x1ff


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    if struct.unpack('<d', read_va(data, F600[0], 8))[0] != F600[1]:
        raise ValueError('600.0 constant changed')
    if naive_date(EPOCH_DATE) != (1970, 1):
        raise ValueError('epoch date encoding changed')
    frame = frame_of(fdes)
    table = {}
    for name, off in FIELDS.items():
        row = {}
        for layout, base in (('A', MISC_A), ('B', MISC_B)):
            sites = census(data, base + off)
            row[layout] = {'offset': hex(base + off),
                           'sites': [hex(s) for s in sites],
                           'functions': sorted({hex(frame(s)) for s in sites if frame(s) is not None})}
        table[name] = row
    for h in GATE_HANDLERS:
        if hex(h) not in table['tce']['A']['functions'] + table['tce']['B']['functions']:
            raise ValueError('gate handler census changed')
    return {
        'target': RELATIVE, 'sha256': SHA256, 'task': 'RE-008', 'component': 'abci',
        'exchange_misc': {'A': hex(MISC_A), 'B': hex(MISC_B)},
        'census': table,
        'aci': 'height % aci at A step 0x5a07f85/0x5a07f9d and B step 0x5a087e5/0x5a087fd (digest cadence, #6023); '
               'also read by 0x59ec200, 0x5443930, 0x5a6c8f0, 0x2d25620 next to freeze-height checks; '
               'stored by dispatchers A 0x539337c / B 0x539e19c',
        'mtpt': 'stored by dispatchers A 0x539247f / B 0x539d29f after a < 0x0ccccccccccccccc check (0x5392468); '
                'read at 0x5aedd60 / 0x5af2044 and passed on; no compare against 1000 found',
        'tce_tde': {'handlers': [hex(h) for h in GATE_HANDLERS],
                    'tce_clear': 'error 0xdd (0x57c9f9c)', 'tde_clear': 'error 0xdc (0x57ca419)',
                    'range': 'u64 arg +0x48 must lie in 5..=10080 (lea -0x2761 / cmp -0x275c), else 0xd1'},
        'pmc': {'epoch_date': hex(EPOCH_DATE), 'decoded': '1970-01-01 (year<<13 | ordinal<<4 | flags)',
                'reset': '0x54bfe3c/0x54bfe47 in begin_block A', 'set_check': '0x54c01a1 xor 0xf6401a',
                'deadline': 'adds f64 %s s from %s' % (F600[1], hex(F600[0]))},
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
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, default=PACKET)
    p.add_argument('--check', action='store_true')
    a = p.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if a.check else None
    r = generate(output=a.out)
    if a.check and (a.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print(' '.join(f"{k}={len(v['A']['sites'])}+{len(v['B']['sites'])}" for k, v in r['census'].items()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
