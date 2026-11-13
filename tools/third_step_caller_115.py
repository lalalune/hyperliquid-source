#!/usr/bin/env python3
"""Bind the node #115 third abci step 0x2d25620 (sixty-eighth stage).

#6040 found four callers of the l1-hash helper 0x452aab0 besides the two
engine steps; three load node/src/gossip_config.rs and are left alone. The
fourth, 0x2d25620, loads the freeze assertion and both snapshot labels.
This tool binds:

1. its opening: the same instruction bytes as the layout-A step 0x5a07ec0
   (engine value +0x450 box, height +0x28, the % 10000 test, freeze height
   at box +0x10e8/+0x10f0), so it uses layout A (#6006);
2. how it is reached: two direct calls, from 0x2d23610 (a wrapper that
   loads 'new abci digests reached quorum' and the #6023 digest panic) and
   from 0x2d275d0; both of those are reached only from the task poll
   0x2b1df60, whose only reference is relocation 0x6449fb0 and which loads
   'non-validator abci state not caught up yet', 'using initial abci state
   from non-validator' and 'client block recver ended before valid block';
3. its own digest step 0x2bb37c0 (one call, rdx = engine value +0x330,
   rcx = +0x20), byte-equal to the A digest step 0x548dad0 except for call
   targets, same-target RIP displacements and a duplicated
   l1/src/abci/abci_hash.rs:28:37 Location;
4. its snapshot label ('freeze' 6 / 'periodic' 8 on sil, gated by bl), its
   linked-abci-state twin call 0x22ed1f0, its l1-hash call (edx = 1) and its
   periodic folder path (hour >= 2, '{}/data/{}' with the periodic slice);
5. a call census: all 45 direct calls to 0x2666c80 sit in this step, and it
   makes no direct call to 0x548dad0, 0x5a046f0 or 0x5942b40.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, read_va, relative_relocations, rip_target

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-third-step-caller-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

STEP, A_STEP = 0x2d25620, 0x5a07ec0
WRAPPER, SHIM, OUTER, POLL = 0x2d23610, 0x2d275d0, 0x2774590, 0x2b1df60
POLL_RELOC = 0x6449fb0
DIGEST, A_DIGEST, DIGEST_SIZE = 0x2bb37c0, 0x548dad0, 0x203
LINKED, L1_HELPER, SLOT_BUILDER = 0x22ed1f0, 0x452aab0, 0x2666c80
OPENING = (0x2d25637, 0x5a07ed7, 0x3c)

FIXED = {
    0x2d256ff: '498d9530030000',        # lea rdx, [r13+0x330]        (abci_hashes writer)
    0x2d25706: '498d4d20',              # lea rcx, [r13+0x20]         (observer)
    0x2d262ac: '84db',                  # test bl, bl                 (snapshot gate)
    0x2d262c2: '488d0c4506000000',      # lea rcx, [rax*2+6]          (label length 6 / 8)
    0x2d262d8: '4084f6',                # test sil, sil               (freeze?)
    0x2d262db: '480f45d0',              # cmovne rdx, rax
    0x2d2638c: 'ba01000000',            # mov edx, 1                  (blocking helper mode)
    0x2d263a8: '3c02',                  # cmp al, 2                   (hour >= 2)
}
CALLS = {                               # e8 site -> target
    0x2d25712: DIGEST,
    0x2d262ea: LINKED,
    0x2d26391: L1_HELPER,
    0x2d24ed9: STEP,                    # in WRAPPER
    0x2d2766f: STEP,                    # in SHIM
    0x27745e0: WRAPPER,                 # in OUTER
    0x2b1e3ee: OUTER,                   # in POLL
    0x2b1e1f8: SHIM,                    # in POLL
}
REFERENCES = (                          # (va, prefix, length, target)
    (0x2d262ca, b'\x48\x8d\x05', 7, 0x616bb1),   # 'freeze'
    (0x2d262d1, b'\x48\x8d\x15', 7, 0x458f30),   # 'periodic'
    (0x2d263a2, b'\xff\x15', 6, 0x64e0f58),      # hour of day
    (0x2d263d7, b'\x48\x8d\x05', 7, 0x646e9f0),  # periodic slice (#5970)
    (0x2d263ef, b'\x48\x8d\x35', 7, 0x448b77),   # '{}/data/{}'
    (0x2d26226, b'\x48\x8d\x3d', 7, 0x5eadd9),   # freeze assertion
    (0x2d2471e, b'\x48\x8d\x05', 7, 0x616be3),       # wrapper: quorum message
    (0x2d2511b, b'\x48\x8d\x3d', 7, 0x44c993),       # wrapper: digest panic (#6023)
    (0x2b1e879, b'\x48\x8d\x05', 7, 0x606039),
    (0x2b1eb71, b'\x48\x8d\x05', 7, 0x606063),
    (0x2b1efbf, b'\x48\x8d\x3d', 7, 0x60608e),
)
STRINGS = {
    0x616bb1: b'freeze',
    0x458f30: b'periodic',
    0x5eadd9: b'assertion failed: freeze_height >= self.locus.co',
    0x616be3: b'new abci digests reached quorum',
    0x606039: b'non-validator abci state not caught up yet',
    0x606063: b'using initial abci state from non-validator',
    0x60608e: b'client block recver ended before valid block',
}
NOT_CALLED = (A_DIGEST, 0x5a046f0, 0x5942b40)


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def call_target(data, va):
    raw = read_va(data, va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'no direct call at {va:#x}')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def extent(fdes, va):
    hits = [f for f in fdes if f['start'] <= va < f['end']]
    if len(hits) != 1:
        raise ValueError(f'{va:#x} is not in exactly one FDE')
    return hits[0]['start'], hits[0]['end']


def location(data, rel, va):
    ptr = rel.get(va)
    if ptr is None:
        return None
    length, line, col = struct.unpack('<QII', read_va(data, va + 8, 16))
    return read_va(data, ptr, length), line, col


def twin_diff(data, rel, a, b, size):
    """Classify every differing byte of two same-size bodies."""
    x, y = read_va(data, a, size), read_va(data, b, size)
    covered = set()
    for k in range(size - 4):
        if x[k] == 0xe8 and y[k] == 0xe8:
            covered.update(range(k + 1, k + 5))
    rest = [i for i in range(size) if x[i] != y[i] and i not in covered]
    windows, same_target, same_location = [], 0, 0
    for i in rest:
        if windows and i <= windows[-1] + 3:
            continue
        windows.append(i)
    for s in windows:
        ta = a + s + 4 + struct.unpack_from('<i', x, s)[0]
        tb = b + s + 4 + struct.unpack_from('<i', y, s)[0]
        if ta == tb:
            same_target += 1
        elif location(data, rel, ta) is not None and location(data, rel, ta) == location(data, rel, tb):
            same_location += 1
        else:
            raise ValueError(f'twin byte {s:#x} differs beyond call/RIP/Location')
    return {'differing_bytes': sum(x[i] != y[i] for i in range(size)),
            'call_rel32_bytes': sum(1 for i in range(size) if x[i] != y[i] and i in covered),
            'rip_same_target_windows': same_target, 'same_location_windows': same_location}


def bind(data, fdes):
    rel = relative_relocations(data)
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for site, target in CALLS.items():
        if call_target(data, site) != target:
            raise ValueError(f'call at {site:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, text_ in STRINGS.items():
        if read_va(data, va, len(text_)) != text_:
            raise ValueError(f'string at {va:#x} changed')
    a, b, n = OPENING
    if read_va(data, a, n) != read_va(data, b, n):
        raise ValueError('opening no longer matches the layout-A step')

    step = extent(fdes, STEP)
    if step[0] != STEP:
        raise ValueError('step FDE changed')
    callers = {
        'step': direct_calls(data, STEP),
        'wrapper': direct_calls(data, WRAPPER),
        'shim': direct_calls(data, SHIM),
        'outer': direct_calls(data, OUTER),
        'poll': direct_calls(data, POLL),
    }
    expect = {'step': [0x2d24ed9, 0x2d2766f], 'wrapper': [0x27745e0], 'shim': [0x2b1e1f8],
              'outer': [0x2b1e3ee], 'poll': []}
    if callers != expect:
        raise ValueError('caller census changed')
    for site, owner in ((0x2d24ed9, WRAPPER), (0x2d2766f, SHIM), (0x27745e0, OUTER),
                        (0x2b1e3ee, POLL), (0x2b1e1f8, POLL)):
        if extent(fdes, site)[0] != owner:
            raise ValueError(f'site {site:#x} moved')
    poll_relocs = sorted(k for k, v in rel.items() if v == POLL)
    if poll_relocs != [POLL_RELOC]:
        raise ValueError('poll references changed')

    builder_calls = direct_calls(data, SLOT_BUILDER)
    if len(builder_calls) != 45 or not all(step[0] <= v < step[1] for v in builder_calls):
        raise ValueError('slot builder census changed')
    for target in NOT_CALLED:
        if any(step[0] <= v < step[1] for v in direct_calls(data, target)):
            raise ValueError(f'step now calls {target:#x}')
    if direct_calls(data, DIGEST) != [0x2d25712]:
        raise ValueError('digest twin callers changed')
    d_ext, a_ext = extent(fdes, DIGEST), extent(fdes, A_DIGEST)
    if d_ext[1] - d_ext[0] != DIGEST_SIZE or a_ext[1] - a_ext[0] != DIGEST_SIZE:
        raise ValueError('digest step sizes changed')
    twin = twin_diff(data, rel, DIGEST, A_DIGEST, DIGEST_SIZE)
    linked_callers = direct_calls(data, LINKED)
    if len(linked_callers) != 3:
        raise ValueError('linked twin callers changed')
    loc = location(data, rel, 0x644d5c0)

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'step': {'fde': [hex(v) for v in step],
                 'opening_equal_to_layout_A_step': '%s..+%#x == %s..+%#x' % (hex(a), n, hex(b), n),
                 'box': 'engine value +0x450; height +0x28; freeze height +0x10e8/+0x10f0 (layout A)'},
        'reached_from': {
            'direct_callers': [hex(v) for v in callers['step']],
            'wrapper': hex(WRAPPER) + " (loads 'new abci digests reached quorum' and the #6023 digest panic)",
            'shim': hex(SHIM),
            'wrapper_caller': hex(OUTER) + ' <- ' + hex(0x2b1e3ee),
            'poll': hex(POLL) + ' (only reference: relocation %s)' % hex(POLL_RELOC),
            'poll_strings': [STRINGS[v].decode() for v in (0x606039, 0x606063, 0x60608e)],
        },
        'digest_step_twin': {'fn': hex(DIGEST), 'call': hex(0x2d25712),
                             'args': 'rdx = engine value +0x330, rcx = engine value +0x20',
                             'equal_to': hex(A_DIGEST), 'size': hex(DIGEST_SIZE), **twin,
                             'location': '%s:%d:%d' % (loc[0].decode(), loc[1], loc[2])},
        'snapshot': {'gate': hex(0x2d262ac) + ' test bl, bl',
                     'label': "'freeze' (6) when sil != 0, else 'periodic' (8)",
                     'linked_abci_state_twin': hex(LINKED) + ' (%d direct calls)' % len(linked_callers),
                     'l1_hash_call': hex(0x2d26391) + ' -> ' + hex(L1_HELPER) + ' with edx = 1',
                     'periodic_path': "hour >= 2 (slot 0x64e0f58), '{}/data/{}' with slice 0x646e9f0"},
        'census': {'slot_builder_0x2666c80_calls_in_step': len(builder_calls),
                   'no_direct_calls_to': [hex(v) for v in NOT_CALLED]},
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
    print(f"callers={len(result['reached_from']['direct_callers'])} "
          f"builder_calls={result['census']['slot_builder_0x2666c80_calls_in_step']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
