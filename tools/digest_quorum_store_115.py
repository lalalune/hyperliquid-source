#!/usr/bin/env python3
"""Bind the node #115 digest quorum store: its fill, its retain pass and its 1000-entry cap.

Continues #6046, which found that the step wrappers' 0x68-byte quorum entries
come from 0x5afa1f0 over the store at box +0x3d98. This tool binds:

1. the take 0x5afa1f0: it builds a 7-word closure {arg rdx, store, &store+0x48,
   &store+0x88, arg rcx, &counter (starts 0), &threshold} with
   threshold = max(0, store+0x78 - 1000), runs 0x4de1d80 on the map at
   store+0x60, then takes the Vec at store+0x48 (leaving {0,8,0}) and keeps the
   0x68-byte entries whose qword +0x20 is non-zero;
2. the map at store+0x60: first word 0x8000000000000000 selects a B-tree
   (root +0x68, height +0x70, length +0x78); 0x4de1d80 retains it through the
   extract loop 0x51515f0 and rebuilds a small form when length < 0x20. So
   store+0x78 is the map length and the threshold is length - 1000;
3. the extract predicate in 0x51515f0, per B-tree entry (key u64, value a
   12-byte time):
   - deadline1 = time + f64 [closure+0x18] seconds (store+0x88); when the
     closure time [closure+0x0] is not earlier, the entry is removed and pushed
     to the Vec at store+0x48 (0x5151a9e .. 0x5151ce5);
   - otherwise deadline2 = time + 60.0 (0x459718); when not earlier and
     counter < threshold, counter += 1 and the entry is removed without a push
     (0x51519a5, 0x5151b9d -> 0x5151ce9);
   - an overflowing addition uses the far-future tuple 0x4679d0;
4. the insert 0x5afa5d0: per incoming 0x68-byte entry, store+0x80 = max(store+0x80,
   height); map[height] = ctx+0x60 through 0x4dbe1e0 (ctx = box, whose +0x60
   #6004 binds as consensus_time); store+0x90 = 1 when height == ctx+0x10;
   then 0x5376540 with height - 50000 (saturating);
5. the selector 0x54cae80: esi (byte) through table 0x926a70: 2 -> 0x5afa5d0
   on box +0x3d98, 3 -> 0x5afa3b0 on box +0x3e50; the dispatcher 0x538cd30
   calls 0x54cae80 four times in a row with esi 0, 1, 2, 3.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import RELATIVE, SHA256, TARGET, direct_calls, fixed, frame, read_va, rip_target

PACKET = ROOT / 'research/work-items/RE-008-digest-quorum-store-115'

TAKE, RETAIN, EXTRACT, INSERT, MAP_INSERT = 0x5afa1f0, 0x4de1d80, 0x51515f0, 0x5afa5d0, 0x4dbe1e0
SELECTOR, SECOND_FILL, DISPATCHER, TABLE = 0x54cae80, 0x5afa3b0, 0x538cd30, 0x926a70
SIXTY, FAR_FUTURE = 0x459718, 0x4679d0

FIXED = {
    # take: threshold = max(0, store+0x78 - 1000)
    0x5afa208: '488b4678',              # mov rax, [rsi+0x78]          (map length)
    0x5afa20c: '31f6',                  # xor esi, esi
    0x5afa20e: '482de8030000',          # sub rax, 1000
    0x5afa214: '480f43f0',              # cmovae rsi, rax
    # take: Vec at store+0x48 left as {0, 8, 0}; keep entries with +0x20 != 0
    0x5afa277: '49c7464800000000',      # mov qword [r14+0x48], 0
    0x5afa27f: '49c7465008000000',      # mov qword [r14+0x50], 8
    0x5afa287: '49c7465800000000',      # mov qword [r14+0x58], 0
    0x5afa2b0: '48837d9800',            # cmp qword [rbp-0x68], 0      (entry +0x20)
    # retain: B-tree marker and small-form rebuild below 0x20 entries
    0x4de1d93: '49bd0000000000000080',  # movabs r13, 0x8000000000000000
    0x4de1e3f: '488b4318',              # mov rax, [rbx+0x18]          (length)
    0x4de1e43: '4c392b',                # cmp [rbx], r13
    0x4de1e49: '4883f820',              # cmp rax, 0x20
    # extract: duration from [closure+0x18]
    0x5151689: '488b4018',              # mov rax, [rax+0x18]
    0x515168d: 'f20f1000',              # movsd xmm0, [rax]
    # extract: 60 s path counts against the threshold
    0x515199a: '488b4128',              # mov rax, [rcx+0x28]          (&counter)
    0x515199e: '488b5130',              # mov rdx, [rcx+0x30]          (&threshold)
    0x51519a2: '488b08',                # mov rcx, [rax]
    0x51519a5: '483b0a',                # cmp rcx, [rdx]
    0x51519a8: '0f82ef010000',          # jb 0x5151b9d
    0x5151b9d: '48ffc1',                # inc rcx
    0x5151ba0: '488908',                # mov [rax], rcx
    0x5151ce9: '498b4608',              # mov rax, [r14+0x8]           (&length)
    0x5151ced: '48ff08',                # dec qword [rax]
    # insert: running max height, map[height] = ctx+0x60, initial-height flag, -50000
    0x5afa635: '498b4610',              # mov rax, [r14+0x10]          (ctx+0x10)
    0x5afa63e: '4983c660',              # add r14, 0x60                (ctx+0x60)
    0x5afa6ae: '498b8780000000',        # mov rax, [r15+0x80]
    0x5afa6b5: '4939c5',                # cmp r13, rax
    0x5afa6b8: '490f47c5',              # cmova rax, r13
    0x5afa6c0: '49898780000000',        # mov [r15+0x80], rax
    0x5afa6da: '498d7760',              # lea rsi, [r15+0x60]          (map)
    0x5afa6de: '4c89ea',                # mov rdx, r13                 (key = height)
    0x5afa6e1: '4c89f1',                # mov rcx, r14                 (value = ctx+0x60)
    0x5afa6f0: '4c3b6c2410',            # cmp r13, [rsp+0x10]
    0x5afa6f7: '6641c78790000000' '0100',  # mov word [r15+0x90], 1
    0x5afa701: '4981ed50c30000',        # sub r13, 50000
    0x5afa70d: '4c0f42e8',              # cmovb r13, rax               (saturate at 0)
    # selector: byte esi through a jump table
    0x54caeb0: '400fb6c6',              # movzx eax, sil
    0x54caebb: '48630481',              # movsxd rax, [rcx+rax*4]
    0x54cb042: '488dbd983d0000',        # lea rdi, [rbp+0x3d98]
    0x54cb062: '488dbd503e0000',        # lea rdi, [rbp+0x3e50]
    # dispatcher: four calls, esi 0..3
    0x5392009: '31f6',
    0x5392013: 'be01000000',
    0x5392020: 'be02000000',
    0x539202d: 'be03000000',
}
REFERENCES = (
    (0x515183b, b'\xf2\x0f\x10\x05', 8, SIXTY),
    (0x51517dc, b'\x48\x8d\x0d', 7, FAR_FUTURE + 4),
    (0x54caeb4, b'\x48\x8d\x0d', 7, TABLE),
    (0x5afa6e4, b'\x4c\x8d\x05', 7, 0x64bc830),
)
CALLS = {
    0x5afa260: RETAIN, 0x4de1fc6: EXTRACT, 0x5afa6eb: MAP_INSERT,
    0x54cb058: INSERT, 0x54cb078: SECOND_FILL,
    0x539200b: SELECTOR, 0x5392018: SELECTOR, 0x5392025: SELECTOR, 0x5392032: SELECTOR,
}


def call_target(data, va):
    raw = read_va(data, va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'call at {va:#x} changed')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, target in CALLS.items():
        if call_target(data, va) != target:
            raise ValueError(f'call at {va:#x} changed')
    if struct.unpack('<d', read_va(data, SIXTY, 8))[0] != 60.0:
        raise ValueError('60 s constant changed')
    far = struct.unpack('<III', read_va(data, FAR_FUTURE, 12))
    if far[1:] != (86399, 999999999):
        raise ValueError('far-future tuple changed')
    arms = [hex(TABLE + struct.unpack('<i', read_va(data, TABLE + 4 * i, 4))[0]) for i in range(4)]
    if arms != ['0x54caec4', '0x54cb082', '0x54cb042', '0x54cb062']:
        raise ValueError('selector table changed')
    for va in (0x539200b, 0x5392032):
        if frame(fdes, va) != DISPATCHER:
            raise ValueError('dispatcher frame changed')
    census = {hex(t): [hex(v) for v in direct_calls(data, t)]
              for t in (RETAIN, EXTRACT, INSERT, SECOND_FILL, SELECTOR, TAKE)}
    if census[hex(RETAIN)] != ['0x5afa260'] or census[hex(EXTRACT)] != ['0x4de1fc6']:
        raise ValueError('call census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'take': {
            'fn': hex(TAKE),
            'closure': '{rdx, store, &store+0x48, &store+0x88, rcx, &counter=0, &threshold}',
            'threshold': 'max(0, store+0x78 - 1000)  (store+0x78 = map length)',
            'after_retain': 'take Vec store+0x48 (leave {0,8,0}); keep entries with qword +0x20 != 0',
        },
        'map': {
            'at': 'store+0x60',
            'btree_marker': '0x8000000000000000 (root +0x68, height +0x70, length +0x78)',
            'retain': hex(RETAIN) + ' -> extract loop ' + hex(EXTRACT) + '; small form again when length < 0x20',
            'entry': 'key u64 (height), value 12-byte time',
        },
        'extract_predicate': {
            'deadline1': 'time + f64 [closure+0x18] s (store+0x88); now >= deadline1 -> remove and push to store+0x48',
            'deadline2': 'time + %.1f s (%s); now >= deadline2 and counter < threshold -> counter += 1, remove, no push'
                         % (60.0, hex(SIXTY)),
            'overflow': 'far-future tuple %s = %r' % (hex(FAR_FUTURE), far),
            'now': '[closure+0x0] (the take caller rdx)',
        },
        'insert': {
            'fn': hex(INSERT),
            'per_entry': 'store+0x80 = max(store+0x80, height); map[height] = ctx+0x60 via %s; '
                         'store+0x90 = 1 when height == ctx+0x10; then 0x5376540(height - 50000, sat)' % hex(MAP_INSERT),
            'ctx': 'box (rsi from 0x54cae80); box +0x60 = consensus_time, +0x10 = initial_height (#6004)',
        },
        'selector': {
            'fn': hex(SELECTOR),
            'table': hex(TABLE),
            'arms_esi_0_to_3': arms,
            'esi_2': hex(INSERT) + ' on box +0x3d98',
            'esi_3': hex(SECOND_FILL) + ' on box +0x3e50',
            'dispatcher': hex(DISPATCHER) + ' calls it four times in a row, esi 0, 1, 2, 3',
        },
        'direct_calls': census,
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
    print('selector arms=%s' % result['selector']['arms_esi_0_to_3'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
