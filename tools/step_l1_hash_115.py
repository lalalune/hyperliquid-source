#!/usr/bin/env python3
"""Bind the node #115 l1 hash inside the two abci steps (58th stage).

Stage 57 (#6039) found l1 = BLAKE3(BLAKE3(bytes) || digest32) in 0x457cf60,
reached only through 0x452aab0, with seven call sites. This tool binds the
two step sites (layout A 0x5a07ec0, layout B 0x5a08720, #6006):

1. condition: the digest step runs when bpl is set or height % box +0x39c8
   (A) is 0; the l1 hash runs only when bpl is set (je at 0x5a07fed / B
   0x5a0884d skips it);
2. bytes: 0x5485a60 (A) / 0x5485f80 (B, #5999) is called with the label
   'freeze' (6 bytes, 0x93a687) when r13b is set, else 'periodic' (8 bytes,
   0x458f30). 0x5485a60 builds the hyperliquid_data/abci_state path
   (0x5942870, name 0x929ae3), runs the blocking serialiser 0x4e49960
   (edx = 1) -> 0x4e35e90 -> closure 0x4e4af80 -> 0x5480950 with config
   0x01000400, and returns that 0x38-byte result unchanged; the step passes
   result +0x8 / +0x10 (Vec ptr, len) as the l1 bytes. The B closure
   0x4e4b3f0 calls 0x5481900 with the same config;
3. record: {ptr, len, &digest (rsp+0x80, copied from the digest step's
   output at rsp+0x130), &height (rsp+0x40 = r15)}, edx = 1;
4. after: both steps call 0x5a046f0(engine value +0x3e0, height, &l1).
   0x5a046f0 has the same entry shape as the digest-map insert 0x5a03fa0
   (#6023): it trims once the map holds 0x33 entries. 0x5a046f0 and
   0x5a03fa0 each have exactly two direct calls.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, fixed, frame, read_va, relative_relocations, rip_target

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-step-l1-hash-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

HELPER = 0x452aab0
STEP_A, STEP_B = 0x5a07ec0, 0x5a08720
STATE_A, STATE_B = 0x5485a60, 0x5485f80
L1_MAP_INSERT, DIGEST_MAP_INSERT = 0x5a046f0, 0x5a03fa0
SERIALISE_A, SERIALISE_B = 0x5480950, 0x5481900
LABELS = {0x93a687: b'freeze', 0x458f30: b'periodic', 0x929ae3: b'abci_state'}
GOSSIP_LOCATION = (0x449029, b'node/src/gossip_config.rs')
FREEZE_ASSERT = (0x5eadd9, b'assertion failed: freeze_height >= ')

FIXED = {
    # A step: digest condition, l1 gate, label, record
    0x5a07f80: '4084ed',                # test bpl, bpl
    0x5a07f83: '7536',                  # jne -> digest step
    0x5a07f85: '488b8ec8390000',        # mov rcx, [rsi+0x39c8]   (divisor)
    0x5a07fea: '4084ed',                # test bpl, bpl
    0x5a07fed: '0f845e030000',          # je 0x5a08351            (skip l1)
    0x5a07ffb: '488d0c4506000000',      # lea rcx, [rax*2+6]      (label len 6|8)
    0x5a08011: '4584ed',                # test r13b, r13b
    0x5a08014: '480f45d0',              # cmovne rdx, rax         (freeze)
    0x5a08018: '4889e7',                # mov rdi, rsp
    0x5a08077: '4c897c2440',            # mov [rsp+0x40], r15     (height)
    0x5a08081: '48890424',              # record +0x0 = ret+0x8   (ptr)
    0x5a0808d: '4889542408',            # record +0x8 = ret+0x10  (len)
    0x5a08092: '488dac2480000000',      # lea rbp, [rsp+0x80]     (digest copy)
    0x5a0809a: '48896c2410',            # record +0x10 = &digest
    0x5a0809f: '488d442440',            # lea rax, [rsp+0x40]
    0x5a080a4: '4889442418',            # record +0x18 = &height
    0x5a080a9: '488dbc2480010000',      # lea rdi, [rsp+0x180]    (l1 out)
    0x5a080b1: '4889e6',                # mov rsi, rsp
    0x5a080b4: 'ba01000000',            # mov edx, 1
    0x5a08255: '498dbee0030000',        # lea rdi, [r14+0x3e0]    (l1 map)
    0x5a0825c: '488d942480010000',      # lea rdx, [rsp+0x180]
    0x5a08264: '4c89fe',                # mov rsi, r15
    # B step: same gate and destination
    0x5a0884a: '4084ed',
    0x5a0884d: '0f845e030000',
    0x5a08874: '480f45d0',
    0x5a08909: '488dbc2480010000',
    0x5a08911: '4889e6',
    0x5a08914: 'ba01000000',
    0x5a08ab5: '498dbee0030000',
    0x5a08abc: '488d942480010000',
    0x5a08ac4: '4c89fe',
    # 0x5485a60: blocking serialise with edx = 1, result +0x8 returned
    0x5485b26: 'ba01000000',
    0x5485d82: '488b442448',            # mov rax, [rsp+0x48]
    0x5485d87: '49894708',              # mov [r15+0x8], rax
    # serialise closures: same config
    0x4e4aff1: 'c744241800040001',      # mov dword [rsp+0x18], 0x01000400
    0x4e4b461: 'c744241800040001',
    # l1 map insert trims at 0x33 like the digest map insert
    0x5a04711: '4883fa33',
    0x5a03fc1: '4883fa33',
}
REFERENCES = (
    (0x5a07fce, b'\xe8', 5, 0x548dad0),            # A digest step
    (0x5a07fe5, b'\xe8', 5, DIGEST_MAP_INSERT),
    (0x5a08003, b'\x48\x8d\x05', 7, 0x93a687),     # 'freeze'
    (0x5a0800a, b'\x48\x8d\x15', 7, 0x458f30),     # 'periodic'
    (0x5a0801e, b'\xe8', 5, STATE_A),
    (0x5a080b9, b'\xe8', 5, HELPER),
    (0x5a08267, b'\xe8', 5, L1_MAP_INSERT),
    (0x5a0882e, b'\xe8', 5, 0x548d8c0),            # B digest step
    (0x5a08845, b'\xe8', 5, DIGEST_MAP_INSERT),
    (0x5a08863, b'\x48\x8d\x05', 7, 0x93a687),
    (0x5a0886a, b'\x48\x8d\x15', 7, 0x458f30),
    (0x5a0887e, b'\xe8', 5, STATE_B),
    (0x5a08919, b'\xe8', 5, HELPER),
    (0x5a08ac7, b'\xe8', 5, L1_MAP_INSERT),
    (0x5485ace, b'\x48\x8d\x35', 7, 0x64aa220),    # &str 'abci_state'
    (0x5485ae0, b'\xe8', 5, 0x5942870),            # hyperliquid_data path
    (0x5485b2b, b'\xe8', 5, 0x4e49960),            # blocking serialise
    (0x4e499f9, b'\xe8', 5, 0x4e35e90),
    (0x4e35f6d, b'\xe8', 5, 0x4e4af80),
    (0x4e4b010, b'\xe8', 5, SERIALISE_A),
    (0x4e4b480, b'\xe8', 5, SERIALISE_B),
)
OTHER_SITES = {
    # site: (enclosing FDE start, evidence loaded nearby)
    0x2ad8dc1: (0x2ad7140, 'gossip'),
    0x2cae5c8: (0x2cad9b0, 'gossip'),
    0x2d26391: (0x2d25620, 'freeze'),
    0x5a6812a: (0x5a64aa0, 'gossip'),
}


def rip_loads(data, fdes, start, target):
    """RIP-relative lea/mov loads of target inside the FDE that starts at start."""
    from freeze_snapshot_115 import text
    import re
    import struct
    base, code = text(data)
    hits = []
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = m.start()
        va = base + i
        if i + 7 <= len(code) and va + 7 + struct.unpack_from('<i', code, i + 3)[0] == target:
            try:
                if frame(fdes, va) == start:
                    hits.append(va)
            except ValueError:
                pass
    return hits


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, text_ in LABELS.items():
        if read_va(data, va, len(text_)) != text_:
            raise ValueError(f'string at {va:#x} changed')
    if relative_relocations(data).get(0x64aa220) != 0x929ae3:
        raise ValueError('abci_state name relocation changed')
    for va, text_ in (GOSSIP_LOCATION, FREEZE_ASSERT):
        if read_va(data, va, len(text_)) != text_:
            raise ValueError(f'string at {va:#x} changed')
    for va, start in ((0x5a080b9, STEP_A), (0x5a08919, STEP_B), (0x5485b2b, STATE_A)):
        if frame(fdes, va) != start:
            raise ValueError(f'enclosing function of {va:#x} changed')
    inserts = {hex(f): [hex(v) for v in direct_calls(data, f)] for f in (L1_MAP_INSERT, DIGEST_MAP_INSERT)}
    if inserts != {hex(L1_MAP_INSERT): ['0x5a08267', '0x5a08ac7'],
                   hex(DIGEST_MAP_INSERT): ['0x5a07fe5', '0x5a08845']}:
        raise ValueError('map insert census changed')
    if [hex(v) for v in direct_calls(data, STATE_A)] != ['0x5a0801e']:
        raise ValueError('0x5485a60 call census changed')
    others = []
    for site, (start, kind) in OTHER_SITES.items():
        if frame(fdes, site) != start:
            raise ValueError(f'enclosing function of {site:#x} changed')
        target = GOSSIP_LOCATION[0] if kind == 'gossip' else FREEZE_ASSERT[0]
        loads = rip_loads(data, fdes, start, target)
        if not loads:
            raise ValueError(f'{kind} evidence missing in {start:#x}')
        others.append({'site': hex(site), 'function': hex(start), 'evidence': kind,
                       'loads': [hex(v) for v in loads],
                       'stopped': 'networking boundary' if kind == 'gossip' else 'not traced'})
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'condition': {
            'digest': 'bpl set, or height % box +0x39c8 == 0 (A); B uses box +0x4538 (#6023)',
            'l1': 'only when bpl is set (A je 0x5a07fed, B je 0x5a0884d)',
            'label': "'freeze' (6 bytes) when r13b set, else 'periodic' (8 bytes)",
        },
        'bytes': {
            'A': '%s -> 0x4e49960 (edx=1) -> 0x4e35e90 -> 0x4e4af80 -> %s, config 0x01000400'
                 % (hex(STATE_A), hex(SERIALISE_A)),
            'B': '%s -> ... -> 0x4e4b3f0 -> %s, config 0x01000400' % (hex(STATE_B), hex(SERIALISE_B)),
            'passed': 'returned 0x38-byte result +0x8 (ptr) and +0x10 (len)',
            'path': "0x5942870 with 'abci_state' (slot 0x64aa220 -> 0x929ae3)",
        },
        'record': '{ptr, len, &digest (rsp+0x80, from digest step output rsp+0x130), &height (rsp+0x40)}, edx = 1',
        'after': {
            'l1_map_insert': hex(L1_MAP_INSERT) + '(engine value +0x3e0, height, &l1); trims at 0x33',
            'digest_map_insert': hex(DIGEST_MAP_INSERT) + '(engine value +0x400, height, &digest); trims at 0x33',
            'direct_calls': inserts,
        },
        'other_sites': others,
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
    print(f"other_sites={len(result['other_sites'])} l1_inserts={len(result['after']['direct_calls'][hex(L1_MAP_INSERT)])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
