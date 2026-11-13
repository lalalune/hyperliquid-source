#!/usr/bin/env python3
"""Bind how node #115 resolves the digest quorum store's per-height votes (63rd stage).

Continues the digest quorum store packets (open PRs #6048, #6049). #6049 found
that the entry builder 0x53779c0 reads a per-height value in store +0x18
(0x50-byte elements: inner map, byte +0x20, 32-byte key +0x21) and returns
None while byte +0x20 is non-zero. This tool binds who clears that byte:

1. 0x5374b70 is called once, by the store insert 0x5afa5d0 (0x5afa5f4). It
   walks store +0x18, skips values whose byte +0x20 is 0, and for each
   remaining value walks the inner map (0x60-byte entries: 32-byte key at
   +0x0, a collection of 0x68-byte items at +0x20);
2. per inner entry it collects the items (0x53485b0) and calls 0x36c7f70
   with the insert's third argument, that argument's +0x58 value, and the
   collected set; a false result moves on to the next inner entry;
3. 0x36c7f70 looks its second argument up in the map at its first argument;
   when absent it emits error tag 0x9b and returns false; otherwise it
   returns 0x422e0f0(..., vtable 0x6468cb0);
4. 0x422e0f0 sums u64 +0x20 over 0x28-byte items into r12, takes (tag, S)
   from 0x4351520 (which adds looked-up u64 weights, returning tag 1 or 0
   on overflow), and returns tag == 1 && 2*r12 < 3*S as a 128-bit compare;
5. a second gate: when f64 store +0x38 is not 0 the value must satisfy
   count > len * store+0x38 (both u64 converted to f64); store +0x38 == 0
   passes;
6. on both gates the walker writes byte +0x20 = 0 and copies the inner
   entry's 32-byte key to value +0x21..+0x41.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import bisect
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import SHA256, fixed, render, rip_target, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-digest-quorum-votes-115'

INSERT, WALKER, STAKE_CHECK, PREDICATE, VOTER_SUM = 0x5afa5d0, 0x5374b70, 0x36c7f70, 0x422e0f0, 0x4351520
PREDICATE_VTABLE = 0x6468cb0

FIXED = {
    # insert -> walker
    0x5afa5f4: 'e877a587ff',            # call 0x5374b70
    # walker: store +0x18 map, +0x58 key, f64 store +0x38
    0x5374bb0: '488b4618',              # mov rax, [rsi+0x18]
    0x5374c9c: '498b4758',              # mov rax, [r15+0x58]
    0x5374ca8: 'f20f104638',            # movsd xmm0, [rsi+0x38]
    0x5374d59: '807a2000',              # cmp byte [rdx+0x20], 0  (pending flag)
    0x5374d5d: '74e1',                  # je next value (resolved)
    0x5374dcc: '4c8d0476',              # lea r8, [rsi+rsi*2]     (0x60 stride, *3<<5)
    0x5374eba: '488d4560',              # lea rax, [rbp+0x60]     (next inner entry)
    0x5374ec6: '488d4520',              # lea rax, [rbp+0x20]     (inner item collection)
    0x5374f71: '486bf968',              # imul rdi, rcx, 0x68     (item stride)
    0x5374fca: '4c89ff',                # mov rdi, r15
    0x5374fd5: '4c89ea',                # mov rdx, r13            (collected set)
    0x5374fe8: '4584f6',                # test r14b, r14b
    0x5374feb: '0f846ffeffff',          # je next inner entry
    # second gate
    0x53750ef: '660f57c9',              # xorpd xmm1, xmm1
    0x53750f3: '660f2ec1',              # ucomisd xmm0, xmm1     (store +0x38 == 0?)
    0x53750f7: 'b301',                  # mov bl, 1
    0x53754f3: 'f20f599424c0000000',    # mulsd xmm2, [rsp+0xc0]
    0x53754fc: '660f2eca',              # ucomisd xmm1, xmm2
    0x5375500: '0f97c3',                # seta bl
    0x5375558: '84db',                  # test bl, bl
    0x537555f: '0f84fbf8ffff',          # je next inner entry
    # resolution
    0x5375588: 'c6402000',              # mov byte [rax+0x20], 0
    0x5375596: '0f114021',              # movups [rax+0x21], xmm0
    0x537559a: '0f114831',              # movups [rax+0x31], xmm1
    # stake check
    0x36c80a3: '66c74424209b00',        # mov word [rsp+0x20], 0x9b
    0x36c80b4: '31c0',                  # xor eax, eax
    # predicate
    0x422e160: '4c036120',              # add r12, [rcx+0x20]
    0x422e221: '4c0322',                # add r12, [rdx]
    0x422e23d: '4983fe01',              # cmp r14, 1
    0x422e241: '7520',                  # jne -> false
    0x422e243: '4c89e1',                # mov rcx, r12
    0x422e246: '48c1e93f',              # shr rcx, 63
    0x422e24a: '4d01e4',                # add r12, r12            (2 * sum)
    0x422e24d: 'ba03000000',            # mov edx, 3
    0x422e252: '4889d8',                # mov rax, rbx
    0x422e255: '48f7e2',                # mul rdx                 (3 * S, 128-bit)
    0x422e258: '4939c4',                # cmp r12, rax
    0x422e25b: '4819d1',                # sbb rcx, rdx
    0x422e25e: '0f92c0',                # setb al
    # voter sum
    0x4351564: '4d033c24',              # add r15, [r12]
    0x435156d: '0f823b010000',          # jb -> overflow (tag 0)
    0x43516a7: 'b801000000',            # mov eax, 1
    0x43516ae: '31c0',                  # xor eax, eax
    0x43516b0: '4c89fa',                # mov rdx, r15
}
CALLS = (
    (0x5374d48, 0x4e18e60),             # next store value
    (0x5374fc5, 0x53485b0),             # collect items
    (0x5374fd8, STAKE_CHECK),
    (0x36c80af, 0x36dae30),             # error 0x9b
    (0x36c82e4, PREDICATE),
    (0x422e100, VOTER_SUM),
)
REFERENCES = ((0x36c82d0, b'\x48\x8d\x15', 7, PREDICATE_VTABLE),)


def call_sites(data, wanted):
    """One pass over .text: every E8 rel32 call whose target is in `wanted`."""
    base, code = text(data)
    out = {t: [] for t in wanted}
    pos = code.find(b'\xe8')
    lo, hi = min(wanted), max(wanted)
    while pos != -1 and pos + 5 <= len(code):
        target = base + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
        if lo <= target <= hi and target in out:
            out[target].append(base + pos)
        pos = code.find(b'\xe8', pos + 1)
    return out


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in CALLS:
        if rip_target(data, va, b'\xe8', 5) != target:
            raise ValueError(f'call at {va:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')

    targets = {'walker': WALKER, 'stake_check': STAKE_CHECK, 'predicate': PREDICATE, 'voter_sum': VOTER_SUM}
    found = call_sites(data, set(targets.values()))
    starts = sorted(f['start'] for f in fdes)
    ends = {f['start']: f['end'] for f in fdes}

    def frame_of(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not starts[i] <= va < ends[starts[i]]:
            raise ValueError(f'{va:#x} has no FDE')
        return starts[i]

    census = {}
    for name, target in targets.items():
        sites = found[target]
        census[name] = {'fn': hex(target), 'direct_calls': [hex(v) for v in sites],
                        'callers': sorted({hex(frame_of(v)) for v in sites})}
    if census['walker']['direct_calls'] != ['0x5afa5f4'] or census['predicate']['direct_calls'] != ['0x36c82e4'] \
            or census['voter_sum']['direct_calls'] != ['0x422e100']:
        raise ValueError('call census changed')
    extents = {hex(f): hex(ends[frame_of(f)]) for f in (WALKER, STAKE_CHECK, PREDICATE, VOTER_SUM)}

    def predicate(total_items, voter_sum, tag=1):
        return tag == 1 and 2 * total_items < 3 * voter_sum

    samples = {'sum=3,S=2': predicate(3, 2), 'sum=3,S=3': predicate(3, 3),
               'sum=300,S=201': predicate(300, 201), 'sum=300,S=200': predicate(300, 200),
               'tag=0': predicate(1, 10, tag=0), 'sum=2**63,S=2**63': predicate(2 ** 63, 2 ** 63)}

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'census': census,
        'fde_ends': extents,
        'walker': {
            'store_map': 'store +0x18 (0x50-byte values), walked via 0x4e18e60',
            'skip': hex(0x5374d59) + ' cmp byte [value+0x20], 0; je next value',
            'inner_entry': '0x60 bytes: 32-byte key +0x0, item collection +0x20 (0x68-byte items)',
            'check_args': 'rdi = insert arg 3 (r15), rsi = [r15+0x58], rdx = collected set',
            'resolve': hex(0x5375588) + ' value +0x20 = 0; ' + hex(0x5375596) + '/' + hex(0x537559a)
                       + ' value +0x21..+0x41 = inner key',
        },
        'stake_check': {
            'absent': 'error tag 0x9b via 0x36dae30, returns 0',
            'present': 'returns 0x422e0f0(..., vtable %s)' % hex(PREDICATE_VTABLE),
        },
        'predicate': {
            'formula': 'tag == 1 and 2*sum(item+0x20 over 0x28-byte items) < 3*S, 128-bit unsigned',
            'S': '0x4351520 second return (u64 sum of looked-up weights; tag 0 on overflow)',
            'samples': samples,
        },
        'second_gate': 'store +0x38 f64; 0 passes; else count > len * store+0x38 (u64 -> f64) at '
                       + hex(0x53754fc),
        'gates_changed': False,
    }


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
    print('stake_check callers=%d' % len(result['census']['stake_check']['direct_calls']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
