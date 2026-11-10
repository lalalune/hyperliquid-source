#!/usr/bin/env python3
"""Bind the node #115 shared height counter's start value and its compare order (stage 84).

Continues #6081, #6083 and #6085. The fast engine's shared counter starts at
the new box's height, and each tag-2 step wrapper increments it, then compares
it with the box height it reads before calling the step. This tool binds:

1. the start value: 0x5a6c0b2 loads [box+0x28] of the box returned by
   0x548ce30, and 0x5a6c0dc stores that value into the new counter Arc
   (+0x10), so counter_0 == box height at build time;
2. the order in both wrappers: the box height load (A 0x5a055e6,
   B 0x5a06e1e) and the counter increment and compare come before the step
   call (A 0x5a05fc9 -> 0x5a07ec0, B 0x5a077e1 -> 0x5a08720);
3. a store census: no 8-byte store to [reg+0x28] with a non-stack base in the
   wrappers before the compare, and none in either step.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import RELATIVE, SHA256, TARGET, direct_calls, fixed, frame, read_va, text

PACKET = ROOT / 'research/work-items/RE-008-counter-height-invariant-115'

BUILD = 0x5a6bfb0
BOX_CLONE = 0x548ce30
WRAPPER_A, WRAPPER_B = 0x5a04e40, 0x5a06600
STEP_A, STEP_B = 0x5a07ec0, 0x5a08720
ASSERT_SLOT = 0x64e1e68

FIXED = {
    # build: counter_0 = new box height
    0x5a6c0aa: 'e8810da2ff',          # call 0x548ce30 (box clone)
    0x5a6c0af: '4989c6',              # mov r14, rax (box)
    0x5a6c0b2: '4c8b7828',            # mov r15, [rax+0x28] (box height)
    0x5a6c0b6: 'bf18000000',          # mov edi, 0x18 (Arc alloc size)
    0x5a6c0cd: '48c70001000000',      # strong = 1
    0x5a6c0d4: '48c7400801000000',    # weak = 1
    0x5a6c0dc: '4c897810',            # mov [rax+0x10], r15 (counter_0)
    # wrapper B: height read, tag test, increment, compare, step
    0x5a06e1e: '488b4728',            # mov rax, [rdi+0x28] (box height)
    0x5a06e2a: '41833f02',            # cmp dword [r15], 2
    0x5a06e2e: '754e',                # jne (skip check)
    0x5a06e37: 'f048ff4110',          # lock inc [rcx+0x10]
    0x5a06e43: '488b4910',            # mov rcx, [rcx+0x10]
    0x5a06e4f: '4839c8',              # cmp rax, rcx
    0x5a06e52: '0f8481090000',        # je 0x5a077d9 (step path)
    0x5a077e1: 'e83a0f0000',          # call 0x5a08720 (step B)
    # wrapper A: same order
    0x5a055e6: '488b4028',            # mov rax, [rax+0x28] (box height)
    0x5a05601: 'f048ff4110',          # lock inc [rcx+0x10]
    0x5a0560e: '488b4910',            # mov rcx, [rcx+0x10]
    0x5a0561a: '4839c8',              # cmp rax, rcx
    0x5a05fc9: 'e8f21e0000',          # call 0x5a07ec0 (step A)
}
CALLS = {0x5a6c0aa: BOX_CLONE, 0x5a077e1: STEP_B, 0x5a05fc9: STEP_A}
ASSERT_CALL_B = 0x5a06e73  # call [rip+...] -> 0x64e1e68


def height_stores(data, lo, hi):
    """8-byte `mov [base+0x28], reg` (REX.W 89 /r, mod=01, disp8 0x28) with a non-stack base."""
    base, code = text(data)
    out = []
    for m in re.finditer(rb'[\x48\x49\x4c\x4d]\x89([\x40-\x7f])\x28', code):
        va = base + m.start()
        if not lo <= va < hi:
            continue
        rex, modrm = code[m.start()], code[m.start() + 2]
        rm = (modrm & 7) | ((rex & 1) << 3)
        if modrm & 7 == 4 or rm == 5:  # SIB (rsp-based) or rbp frame slot
            continue
        out.append(va)
    return out


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in CALLS.items():
        raw = read_va(data, va, 5)
        if raw[0] != 0xe8 or va + 5 + struct.unpack_from('<i', raw, 1)[0] != target:
            raise ValueError(f'call at {va:#x} changed')
    raw = read_va(data, ASSERT_CALL_B, 6)
    if raw[:2] != b'\xff\x15' or ASSERT_CALL_B + 6 + struct.unpack_from('<i', raw, 2)[0] != ASSERT_SLOT:
        raise ValueError('assert call changed')
    for va, owner in ((0x5a6c0b2, BUILD), (0x5a06e1e, WRAPPER_B), (0x5a077e1, WRAPPER_B),
                      (0x5a055e6, WRAPPER_A), (0x5a05fc9, WRAPPER_A)):
        if frame(fdes, va) != owner:
            raise ValueError(f'{va:#x} left its function')
    ends = {f['start']: f['end'] for f in fdes}
    census = {
        'wrapper_A_before_compare': height_stores(data, WRAPPER_A, 0x5a055e6),
        'wrapper_B_before_compare': height_stores(data, WRAPPER_B, 0x5a06e1e),
        'step_A': height_stores(data, STEP_A, ends[STEP_A]),
        'step_B': height_stores(data, STEP_B, ends[STEP_B]),
    }
    if any(census.values()):
        raise ValueError('a [reg+0x28] store appeared before the compare or in a step')
    # positive control: the scanner finds a known non-stack [rax+0x28] store
    if height_stores(data, 0x5489130, 0x5489140) != [0x5489135]:
        raise ValueError('height store scanner lost its control hit')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'counter_start': {
            'box': '0x548ce30 result (r14)',
            'load': '0x5a6c0b2 mov r15, [rax+0x28]',
            'store': '0x5a6c0dc mov [Arc+0x10], r15',
            'value': 'counter_0 == box height at build',
        },
        'wrapper_order': {
            'B': {'height_load': '0x5a06e1e', 'tag_test': '0x5a06e2a', 'increment': '0x5a06e37',
                  'compare': '0x5a06e4f', 'step_call': '0x5a077e1 -> 0x5a08720',
                  'assert_call': '0x5a06e73 -> slot 0x64e1e68'},
            'A': {'height_load': '0x5a055e6', 'increment': '0x5a05601', 'compare': '0x5a0561a',
                  'step_call': '0x5a05fc9 -> 0x5a07ec0'},
            'height_read_precedes_step': True,
        },
        'height_store_census': {k: [hex(v) for v in vs] for k, vs in census.items()},
        'height_store_control': '0x5489135 mov [rax+0x28], rcx (found)',
        'step_direct_callers': {'step_A': [hex(v) for v in direct_calls(data, STEP_A)],
                                'step_B': [hex(v) for v in direct_calls(data, STEP_B)]},
        'invariant': ('counter after increment == box height read at wrapper entry; with counter_0 == '
                      'build-time height h0, the n-th tag-2 check passes only if the box height is h0 + n'),
        'inference': ('the box height is advanced outside both wrappers and both steps, before the next '
                      'wrapper call; the writer is not bound here'),
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
    print('step callers', result['step_direct_callers'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
