#!/usr/bin/env python3
"""Bind the node #115 ExchangeMisc field `i` as Option<(u64, bool)> (stage 92).

Continues #6099. Field `i` (msc+0xa0 u64, msc+0xa8 byte; box +0x39a8/+0x39b0)
is decoded by 0x47922c0. This tool binds:

1. msgpack nil (0xc0) writes byte 2 (0x47923c3): None;
2. a fixarray value is a 2-tuple: element 0 through slot 0x64e2580, element 1
   through 0x586a170, which reads a marker and calls slot 0x64e2590
   (0x3482410). That decoder's table 0x78cfd8 sends 0xc2 to `xor eax,eax`
   (false = 0) and 0xc3 to `mov al,1` (true = 1), then stores the byte with
   Ok tag 9. The tuple path keeps `byte & 1` (0x47929d6) and treats 2 as a
   missing element (0x47929ce);
3. other markers go through slot 0x64e2598 (0x3493900), whose type errors
   expect "a tuple of size 2" (0x38db600 -> 0x7a0390, length 0x11);
4. so the six simulate-panic sites from #6091/#6099 test the bool: begin A/B
   and 0x2bdf270 arm on Some((h, true)); the quorum-entry builders A/B and
   0x2c71eb0 arm on Some((h, false)); None (2) arms neither.

The tuple has no field names, so the bool has no name in the binary.
The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import RELATIVE, SHA256, TARGET, fixed, read_va, relative_relocations

PACKET = ROOT / 'research/work-items/RE-008-field-i-stop-kind-115'

FIXED = {
    0x47923bf: '3cc0',              # cmp al, 0xc0           (nil)
    0x47923c3: 'c6431002',          # mov byte [rbx+0x10], 2 (None)
    0x47923f2: 'ff15a001d501',      # call [slot 0x64e2598]  (non-fix markers)
    0x479240c: '48894308',          # mov [rbx+0x8], rax     (u64)
    0x4792410: '884b10',            # mov [rbx+0x10], cl     (byte)
    0x479298d: 'ff15edfbd401',      # call [slot 0x64e2580]  (element 0)
    0x47929b2: 'e8b9770d01',        # call 0x586a170         (element 1)
    0x47929ce: '3c02',              # cmp al, 2              (missing element)
    0x47929d6: '2401',              # and al, 1
    0x4792a35: '4c896c2470',        # mov [rsp+0x70], r13    (u64 out)
    0x4792a3a: '88442478',          # mov [rsp+0x78], al     (bool out)
    0x586a1f5: 'ff159583c700',      # call [slot 0x64e2590]  (bool decoder)
    0x3482435: '31c0',              # xor eax, eax           (0xc2 false)
    0x3482549: 'b001',              # mov al, 1              (0xc3 true)
    0x348254b: '884701',            # mov [rdi+1], al
    0x348254e: 'c60709',            # mov byte [rdi], 9      (Ok)
    0x38db60b: '488d357e4decfc',    # lea rsi, "a tuple of size 2"
    0x38db612: 'ba11000000',        # mov edx, 0x11
    # panic sites (from #6099)
    0x5483903: '41f685b039000001',  # begin A: test byte [r13+0x39b0], 1
    0x5484003: '41f6852045000001',  # begin B: test byte [r13+0x4520], 1
    0x2bdf30d: 'f683b039000001',    # 0x2bdf270: test byte [rbx+0x39b0], 1
    0x5488ed4: '80bd2045000000',    # builder B: cmp byte [rbp+0x4520], 0
    0x548bfc9: '4180bc24b039000000',  # builder A: cmp byte [r12+0x39b0], 0
    0x2c7444e: '4180beb039000000',  # 0x2c71eb0: cmp byte [r14+0x39b0], 0
}
SLOTS = {0x64e2580: 0x348e980, 0x64e2590: 0x3482410, 0x64e2598: 0x3493900, 0x646be68: 0x38db600}
BOOL_TABLE = 0x78cfd8
TUPLE_TEXT = (0x7a0390, b'a tuple of size 2')
SITES = (
    ('begin A', 0x5483850, 0x5483903, 'Some((h, true))'),
    ('begin B', 0x5483f50, 0x5484003, 'Some((h, true))'),
    ('0x2bdf270', 0x2bdf270, 0x2bdf30d, 'Some((h, true))'),
    ('quorum-entry builder B', 0x5486720, 0x5488ed4, 'Some((h, false))'),
    ('quorum-entry builder A', 0x54897e0, 0x548bfc9, 'Some((h, false))'),
    ('0x2c71eb0', 0x2c71eb0, 0x2c7444e, 'Some((h, false))'),
)


def arms(rule, byte):
    return bool(byte & 1) if rule == 'Some((h, true))' else byte == 0


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    rel = relative_relocations(data)
    for slot, target in SLOTS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    table = read_va(data, BOOL_TABLE, 4 * 4)
    arm = {m: BOOL_TABLE + struct.unpack_from('<i', table, (m - 0xc0) * 4)[0] for m in (0xc0, 0xc2, 0xc3)}
    if arm[0xc2] != 0x3482435 or arm[0xc3] != 0x3482549:
        raise ValueError('bool decoder table changed')
    if read_va(data, TUPLE_TEXT[0], len(TUPLE_TEXT[1])) != TUPLE_TEXT[1]:
        raise ValueError('expecting text changed')
    samples = {str(b): {name: arms(rule, b) for name, _, _, rule in SITES} for b in (0, 1, 2)}
    if any(samples['2'].values()):
        raise ValueError('None must arm no site')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'field': 'ExchangeMisc.i at box +0x39a8 (u64) / +0x39b0 (byte)',
        'type': 'Option<(u64, bool)>; None = byte 2 (0x47923c3); bool from msgpack 0xc2/0xc3',
        'decoder': {
            'outer': '0x47922c0',
            'element0': 'slot 0x64e2580 -> 0x348e980 (call 0x479298d)',
            'element1': 'call 0x47929b2 -> 0x586a170 -> slot 0x64e2590 -> 0x3482410',
            'bool_table': {hex(m): hex(v) for m, v in arm.items()},
            'missing_element': '0x47929ce cmp al,2',
            'other_markers': 'slot 0x64e2598 -> 0x3493900; expecting 0x38db600 -> "a tuple of size 2"',
        },
        'sites': [{'site': n, 'function': hex(f), 'test': hex(t), 'arms_on': r} for n, f, t, r in SITES],
        'arm_table': samples,
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
    print(f"type={result['type'].split(';')[0]} sites={len(result['sites'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
