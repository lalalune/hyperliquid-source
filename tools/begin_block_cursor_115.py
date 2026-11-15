#!/usr/bin/env python3
"""Bind the node #115 begin_block A cursor loop (stage 95).

Continues #6164. Inside begin_block A (0x54b66b0) this tool binds:

1. the entry guard: Exchange `pmn` (box +0x4270) and Locus `blp` word +0x710
   must both be non-zero, else `pmc` is reset (0xf6401a, 0);
2. the cursor: Exchange `pmi` (box +0x42b0 tag, +0x42b1 20-byte key). When the
   tag is 1 the key is copied out, otherwise a zero key is used;
3. two range iterators over the map at box +0x6f8 (inside Locus `blp`): one
   built by 0x4dcdfc0 with bounds (tag 1 + key, tag 2), one by 0x4dce210
   with the key, chained by the loop (first one, then the second);
4. the loop limit: the counter starts at `pmn` and is decremented once per
   step (0x54c0013); the loop stops at 0 or when both iterators end;
5. each step: the 20-byte key of the yielded entry becomes the new `pmi`
   (tag set to 1 at 0x54c008f), the key is looked up by 0x4ef4480 (a miss
   uses the lazy default cell behind slot 0x64e71a8); the key is collected
   into a Vec of 20-byte entries only when record byte +0x3c == 4, Locus
   `blp` byte +0x7b8 bit 0 is clear, and slot 0x64e7190 (0x3693030) returns
   true for the entry value;
6. after the loop: when `pmi` is set and memcmp(new key, entry key, 20) <= 0
   (the walk wrapped), `pmc` takes the block date-time; then every collected
   key is passed to 0x5582180 with (ecx 0, r8d 1).

Field names come from #6095 (Exchange) and #6097 (Locus). The captured binary
is not executed; objdump and readelf are not started.
"""
import argparse
import json
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (SHA256, direct_calls, fixed, read_va,
                                 relative_relocations, rip_target)

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-begin-block-cursor-115'

BEGIN_BLOCK_A = 0x54b66b0
RANGE_AFTER = 0x4dcdfc0
RANGE_REST = 0x4dce210
NEXT = 0x4e18aa0
LOOKUP = 0x4ef4480
PREDICATE_SLOT, PREDICATE = 0x64e7190, 0x3693030
DEFAULT_SLOT, DEFAULT_CELL = 0x64e71a8, 0x64fd9b0
MEMCMP_SLOT = 0x64dfb50
PER_KEY = 0x5582180

FIXED = {
    # entry guard: pmn and blp +0x710 non-zero, else reset pmc
    0x54bfdf5: '4983bf7042000000',      # cmp qword [r15+0x4270], 0   (Exchange pmn)
    0x54bfdfd: '743d',                  # je reset
    0x54bfdff: '4983bf1007000000',      # cmp qword [r15+0x710], 0    (Locus blp +0x90)
    0x54bfe07: '7433',                  # je reset
    0x54bfe3c: '41c787f839000000000000',  # mov dword [r15+0x39f8], 0
    0x54bfe47: '49c787f03900001a40f600',  # mov qword [r15+0x39f0], 0xf6401a (pmc unset)
    # cursor pmi: tag +0x42b0, key +0x42b1
    0x54bfe09: '498d9ff8060000',        # lea rbx, [r15+0x6f8]        (map in Locus blp)
    0x54bfe10: '4d8db7b1420000',        # lea r14, [r15+0x42b1]       (pmi key)
    0x54bfe17: '4180bfb042000001',      # cmp byte [r15+0x42b0], 1    (pmi tag)
    0x54bfe1f: '7536',                  # jne zero key
    0x54bfe21: '418b4610',              # mov eax, [r14+0x10]         (key bytes 16..20)
    0x54bfe2c: '66410f1006',            # movupd xmm0, [r14]          (key bytes 0..16)
    # range iterators over the map
    0x54bfe87: 'c644246001',            # bound tag 1 (with key)
    0x54bfe8c: 'c644247502',            # bound tag 2
    0x54bfe9e: '4889de',                # mov rsi, rbx (map)
    0x54bfecb: '4889de',                # mov rsi, rbx (map)
    # loop limit = pmn
    0x54bff42: '488b8070420000',        # mov rax, [rax+0x4270]
    0x54bffb0: '4885c0',                # test rax, rax
    0x54bffd0: 'eb41',                  # jmp 0x54c0013 (enter loop with rax = pmn)
    0x54c0002: '488b8424d0000000',      # mov rax, [rsp+0xd0] (remaining steps)
    0x54c000a: '4885c0',                # test rax, rax
    0x54c0013: '48ffc8',                # dec rax
    0x54c0016: '48898424d0000000',      # mov [rsp+0xd0], rax
    # chain: first iterator until exhausted (tag 3), then the second
    0x54c001e: '48837c246003',          # cmp qword [rsp+0x60], 3
    0x54c0035: '48c744246003000000',    # mark first iterator done
    0x54c003e: '83bc249800000003',      # cmp dword [rsp+0x98], 3
    # yielded key -> new pmi
    0x54c0060: '8b4810',                # mov ecx, [rax+0x10]
    0x54c008f: 'c680b042000001',        # mov byte [rax+0x42b0], 1
    0x54c009d: '41894610',       # mov [r14+0x10], eax
    0x54c00a9: '410f1106',              # movups [r14], xmm0
    # per-entry filter
    0x54c00dd: '4989c5',                # mov r13, rax (lookup result)
    0x54c00ec: '4989ed',                # miss -> default cell
    0x54c00ef: '41807d3c04',            # cmp byte [r13+0x3c], 4
    0x54c00ff: 'f680b807000001',        # test byte [rax+0x7b8], 1 (Locus blp +0x148)
    0x54c0115: '84c0',                  # predicate result
    # collected Vec of 20-byte keys
    0x54bffda: '488d0c9b',              # lea rcx, [rbx+rbx*4]
    0x54bffe5: '89548810',              # mov [rax+rcx*4+0x10], edx
    0x54bfff2: '660f110488',  # movupd [rax+rcx*4], xmm0
    # wrap check and pmc
    0x54c0279: 'f680b042000001',        # test byte [rax+0x42b0], 1
    0x54c028a: 'ba14000000',            # mov edx, 20
    0x54c0298: '85c0',                  # test eax, eax
    0x54c029a: '7f20',                  # jg skip (new key > entry key)
    0x54c02a1: '4805f0390000',          # add rax, 0x39f0 (pmc)
    # per collected key
    0x54c0332: '41b801000000',          # mov r8d, 1
    0x54c0343: '31c9',                  # xor ecx, ecx
}
CALLS = {
    0x54bfea1: RANGE_AFTER,
    0x54bfece: RANGE_REST,
    0x54c002b: NEXT,
    0x54c004f: NEXT,
    0x54c00d8: LOOKUP,
    0x54c0345: PER_KEY,
}
REFERENCES = (
    (0x54bffc9, b'\x48\x8b\x2d', 7, DEFAULT_SLOT),
    (0x54c010f, b'\xff\x15', 6, PREDICATE_SLOT),
    (0x54c0292, b'\xff\x15', 6, MEMCMP_SLOT),
)
FIELDS = {
    'pmn': 'Exchange index 55, box +0x4270 (u64 loop limit)',
    'pmi': 'Exchange index 54, box +0x42b0 tag / +0x42b1 20-byte key',
    'blp': 'Locus field, box +0x670..+0x7c0: map at +0x6f8, word +0x710, byte +0x7b8',
    'pmc': 'ExchangeMisc +0xe8, box +0x39f0 (#6103)',
}


def call_target(data, va):
    raw = read_va(data, va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'call at {va:#x} changed')
    return va + 5 + int.from_bytes(raw[1:], 'little', signed=True)


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in CALLS.items():
        if call_target(data, va) != target:
            raise ValueError(f'call at {va:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    if rel.get(PREDICATE_SLOT) != PREDICATE or rel.get(DEFAULT_SLOT) != DEFAULT_CELL:
        raise ValueError('slot relocations changed')
    starts = sorted(f['start'] for f in fdes if f['start'] <= 0x54bffb9 < f['end'])
    if starts != [BEGIN_BLOCK_A]:
        raise ValueError('loop is not inside begin_block A')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'function': hex(BEGIN_BLOCK_A),
        'loop': [hex(0x54bffb9), hex(0x54c0188)],
        'fields': FIELDS,
        'entry_guard': 'pmn != 0 and box +0x710 != 0, else pmc := (0xf6401a, 0)',
        'cursor': 'pmi Some -> copied 20-byte key, None -> zero key',
        'iterators': {
            'first': '%s(map box +0x6f8, bounds (tag 1, key) .. (tag 2))' % hex(RANGE_AFTER),
            'second': '%s(map box +0x6f8, key)' % hex(RANGE_REST),
            'next': hex(NEXT),
            'order': 'first until it reports done (tag 3), then second',
        },
        'limit': 'counter starts at pmn (0x54bff42, jmp 0x54bffd0 -> dec 0x54c0013); one decrement per step',
        'step': {
            'new_cursor': 'yielded 20-byte key -> pmi key, pmi tag := 1 (0x54c008f)',
            'lookup': '%s(key); miss -> lazy default cell %s via slot %s' % (hex(LOOKUP), hex(DEFAULT_CELL), hex(DEFAULT_SLOT)),
            'collect_if': 'record byte +0x3c == 4 and box +0x7b8 bit0 clear and slot %s (%s)(value) true'
                          % (hex(PREDICATE_SLOT), hex(PREDICATE)),
            'collected': 'Vec of 20-byte keys at rsp+0x280',
        },
        'after_loop': {
            'pmc': 'if pmi set and memcmp(new key, entry key, 20) <= 0 -> pmc := block date-time',
            'per_key': '%s(out, box, &key, ecx 0, r8d 1) for each collected key' % hex(PER_KEY),
        },
        'call_census': {hex(t): len(direct_calls(data, t)) for t in (RANGE_AFTER, RANGE_REST, PER_KEY)},
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
    print('loop %s..%s census %s' % (result['loop'][0], result['loop'][1], result['call_census']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
