#!/usr/bin/env python3
"""Bind where node #115 advances the abci box height (+0x28) (stage 85).

#6086 found that each step wrapper reads box +0x28 before its step, bumps the
shared counter and asserts counter == height, and that neither wrapper nor
step stores to box +0x28. This tool binds the store:

1. the begin functions 0x5483850 (layout A) and 0x5483f50 (layout B, same
   code with box offsets shifted) load box +0x28, add 1 saturating at
   u64::MAX (inc / cmovne), and store it back; they also zero box +0x0, store
   the round argument (rcx) at +0x30 and two more fields, and update the
   consensus time at +0x60 (old value to +0x6c) when the new time is later;
2. each is called once, from its step wrapper (A at 0x5a04fe9, B at
   0x5a067ad), before the wrapper's apply call and its height read;
3. after the store, if a stop flag is set (A +0x39b0, B +0x4520) and the new
   height equals a stored height (A +0x39a8, B +0x4518) and box byte
   (A +0xb9a, B +0x170a) is not 3, the code takes an 'explicit panic' at
   l1/src/simulate_panic.rs:10:13;
4. each then calls its begin_block function (A 0x54b66b0, B 0x54a9c70; both
   reference l1/src/exchange/begin_block.rs Locations);
5. the inc/cmovne/store byte run occurs exactly twice in .text.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, fixed, frame, read_va, relative_relocations, rip_target, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-height-advance-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

BEGIN = {'A': 0x5483850, 'B': 0x5483f50}
WRAPPER_CALL = {'A': 0x5a04fe9, 'B': 0x5a067ad}
WRAPPER = {'A': 0x5a04e40, 'B': 0x5a06600}
HEIGHT_READ = {'A': 0x5a055e6, 'B': 0x5a06e1e}
BEGIN_BLOCK = {'A': (0x5483a78, 0x54b66b0), 'B': (0x5484194, 0x54a9c70)}
PANIC = {'A': 0x5483edf, 'B': 0x54845ff}
ADVANCE_RUN = '498b752848ffc648c7c2ffffffff480f45d649895528'

FIXED = {
    # layout A begin 0x5483850
    0x54838d3: '498b7528',              # mov rsi, [r13+0x28]         (height)
    0x54838d7: '48ffc6',                # inc rsi
    0x54838da: '48c7c2ffffffff',        # mov rdx, -1
    0x54838e1: '480f45d6',              # cmovne rdx, rsi             (saturating +1)
    0x54838e5: '49895528',              # mov [r13+0x28], rdx         (store height)
    0x54838e9: '49c7450000000000',      # mov qword [r13+0x0], 0
    0x54838f1: '49894d30',              # mov [r13+0x30], rcx         (round)
    0x5483903: '41f685b039000001',      # test byte [r13+0x39b0], 1   (stop flag)
    0x548390d: '493b95a8390000',        # cmp rdx, [r13+0x39a8]       (stop height)
    0x5483916: '4180bd9a0b000003',      # cmp byte [r13+0xb9a], 3
    0x548391e: '0f85bb050000',          # jne 0x5483edf               (explicit panic)
    0x5483eed: 'be0e000000',            # mov esi, 14                 (len 'explicit panic')
    # layout B begin 0x5483f50
    0x5483fd3: '498b7528',
    0x5483fd7: '48ffc6',
    0x5483fda: '48c7c2ffffffff',
    0x5483fe1: '480f45d6',
    0x5483fe5: '49895528',
    0x5483fe9: '49c7450000000000',
    0x5483ff1: '49894d30',
    0x5484003: '41f6852045000001',      # test byte [r13+0x4520], 1
    0x548400d: '493b9518450000',        # cmp rdx, [r13+0x4518]
    0x5484016: '4180bd0a17000003',      # cmp byte [r13+0x170a], 3
    0x548401e: '0f85db050000',          # jne 0x54845ff
    0x548460d: 'be0e000000',
    # wrapper height reads (#6086)
    0x5a055e6: '488b4028',              # mov rax, [rax+0x28]
    0x5a06e1e: '488b4728',              # mov rax, [rdi+0x28]
}
REFERENCES = (
    # (va, prefix, length, target)
    (0x5483edf, b'\x48\x8d\x3d', 7, 0x7db393),     # 'explicit panic'
    (0x5483ee6, b'\x48\x8d\x15', 7, 0x6492ef0),    # Location simulate_panic.rs
    (0x54845ff, b'\x48\x8d\x3d', 7, 0x7db393),
    (0x5484606, b'\x48\x8d\x15', 7, 0x6492ef0),
    (0x5483a78, b'\xe8', 5, 0x54b66b0),            # begin_block A
    (0x5484194, b'\xe8', 5, 0x54a9c70),            # begin_block B
    (0x5a04fe9, b'\xe8', 5, 0x5483850),
    (0x5a067ad, b'\xe8', 5, 0x5483f50),
    (0x5a055b0, b'\xe8', 5, 0x54897e0),            # A apply (#6046)
)
PANIC_MSG = (0x7db393, b'explicit panic')
LOC = (0x6492ef0, 0x431bf2, b'l1/src/simulate_panic.rs', 10, 13)
BB_PATH = (0x449e4b, b'l1/src/exchange/begin_block.rs')


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    if read_va(data, PANIC_MSG[0], len(PANIC_MSG[1])) != PANIC_MSG[1]:
        raise ValueError('panic message changed')
    rel = relative_relocations(data)
    if rel.get(LOC[0]) != LOC[1] or read_va(data, LOC[1], len(LOC[2])) != LOC[2]:
        raise ValueError('simulate_panic Location changed')
    ln, col = struct.unpack('<II', read_va(data, LOC[0] + 16, 8))
    if (ln, col) != (LOC[3], LOC[4]):
        raise ValueError('simulate_panic Location line changed')
    if read_va(data, BB_PATH[0], len(BB_PATH[1])) != BB_PATH[1]:
        raise ValueError('begin_block path changed')

    base, code = text(data)
    runs = [hex(base + m.start()) for m in re.finditer(re.escape(bytes.fromhex(ADVANCE_RUN)), code)]
    if runs != ['0x54838d3', '0x5483fd3']:
        raise ValueError('height advance run census changed')
    layouts = {}
    for k in ('A', 'B'):
        calls = direct_calls(data, BEGIN[k])
        if calls != [WRAPPER_CALL[k]]:
            raise ValueError(f'begin {k} callers changed')
        if frame(fdes, WRAPPER_CALL[k]) != WRAPPER[k] or frame(fdes, HEIGHT_READ[k]) != WRAPPER[k]:
            raise ValueError(f'wrapper {k} frame changed')
        if not WRAPPER_CALL[k] < HEIGHT_READ[k]:
            raise ValueError('order changed')
        bb_site, bb = BEGIN_BLOCK[k]
        if frame(fdes, bb_site) != BEGIN[k] or direct_calls(data, bb) != [bb_site]:
            raise ValueError(f'begin_block {k} census changed')
        adv = int(runs[0 if k == 'A' else 1], 16)
        layouts[k] = {
            'begin_fn': hex(BEGIN[k]),
            'called_once_from': '%s in wrapper %s' % (hex(WRAPPER_CALL[k]), hex(WRAPPER[k])),
            'height_store': hex(adv + 0x12) + ' mov [r13+0x28], rdx after inc/cmovne (saturating +1)',
            'wrapper_height_read_after': hex(HEIGHT_READ[k]),
            'stop_check': {'A': '+0x39b0 flag, +0x39a8 height, byte +0xb9a != 3',
                           'B': '+0x4520 flag, +0x4518 height, byte +0x170a != 3'}[k]
                          + ' -> explicit panic at ' + hex(PANIC[k]),
            'begin_block_call': '%s -> %s' % (hex(bb_site), hex(bb)),
        }
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'height_advance_runs': runs,
        'layouts': layouts,
        'panic': {'message': PANIC_MSG[1].decode(), 'location': '%s:%d:%d' % (LOC[2].decode(), LOC[3], LOC[4])},
        'invariant': 'begin adds 1 to box +0x28 once per wrapper call before the wrapper reads it; '
                     'counter (starts at h0, +1 per tag-2 check) == height holds while each wrapper call '
                     'runs begin exactly once',
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
    print('height advance runs=%s' % result['height_advance_runs'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
