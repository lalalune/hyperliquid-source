#!/usr/bin/env python3
"""Bind who adds votes into the node #115 digest quorum store (64th stage).

Continues the digest quorum store packets (open PRs #6049, #6051). #6051
found that the walker 0x5374b70 resolves the per-height values in store
+0x18 by a 2/3 stake predicate. This tool binds the path that adds a vote:

1. four handlers check a signed vote message and call a store update:
   0x5862560 (layout A) and 0x5862770 (layout B) call 0x5afa7f0 on store
   box +0x3d98 / +0x4908; 0x5869400 (A) and 0x5869610 (B) call 0x5afadd0 on
   the second store box +0x3e50 / +0x49c0. Layout B offsets are layout A
   plus 0xb70 (#6006);
2. each handler hashes the message through 0x38d2920 (serialise, then
   BLAKE3 update/finalize via slots 0x64df510 / 0x64df518), passes the
   message +0x28 and that hash to slot 0x64e0ad8 (0x1536a90), returns error
   tag 0x7e on Err, compares the returned 20 bytes with the sender (r15)
   and returns error tag 0x12e on mismatch, and rejects height
   >= 0x0ccccccccccccccc;
3. the handler builds a record at rsp+0xb0: +0x0 message +0x28, +0x8 the
   height, +0x10..+0x30 message +0x0..+0x20 (the digest), +0x30..+0x44 the
   20-byte sender, and passes r8 = box +0x3f08 (B +0x4a78), r9 = box +0xd88
   (B +0x18f8), ecx = box byte +0xb9a (B +0x170a);
4. 0x5afa7f0 calls slot 0x64e6470 (0x3c3a3f0) with (r9, ecx, sender); when
   store byte +0x90 is 0, the record height equals box +0x10 and that call
   returned true, it sets store +0x91 = 1 and copies the digest to store
   +0x92..+0xb2; it looks the sender up in a B-tree at r9 +0x30 keyed by
   20-byte memcmp; it calls slot 0x64e6478 (0x36ca5b0) with [r8+0x58] and
   the sender (tag 0x1a2 + 32 bytes); then 0x57c9430(store, height,
   digest) and the vote insert 0x537b870(store, height, ...), the only call
   of 0x537b870, which takes store +0x18 at 0x537b96c;
5. 0x5afa7f0 returns tag 0x1a2 (byte +0x2 = changed), or 0x95.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import bisect
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import SHA256, fixed, render, rip_target, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-digest-quorum-vote-insert-115'

HANDLER_A, HANDLER_B, HANDLER2_A, HANDLER2_B = 0x5862560, 0x5862770, 0x5869400, 0x5869610
UPDATE, UPDATE2, VOTE_INSERT, MSG_HASH = 0x5afa7f0, 0x5afadd0, 0x537b870, 0x38d2920

FIXED = {
    # handler A: hash, recover, compare, height bound
    0x58625b1: 'e86a0307fe',                    # call 0x38d2920
    0x58625c1: 'ff1511e5c700',                  # call [slot 0x64e0ad8]
    0x58625c7: '807c242001',                    # cmp byte [rsp+0x20], 1  (Err)
    0x58625d3: '66b97e00',                      # mov cx, 0x7e
    0x586260d: 'f3410f6f0f',                    # movdqu xmm1, [r15]       (sender 0..16)
    0x586261c: '66410f6e5710',                  # movd xmm2, [r15+0x10]    (sender 16..20)
    0x586262e: '3dffff0000',                    # cmp eax, 0xffff
    0x5862633: '7424',                          # je -> equal
    0x5862635: '66b92e01',                      # mov cx, 0x12e
    0x5862659: '48b8cccccccccccccc0c',          # movabs rax, 0x0ccccccccccccccc
    0x5862663: '4939c6',                        # cmp r14, rax
    0x5862666: '0f8399000000',                  # jae -> reject
    # handler A: record and store arguments
    0x5862671: '488db2983d0000',                # lea rsi, [rdx+0x3d98]
    0x5862678: '4c89b424b8000000',              # mov [rsp+0xb8], r14      (height)
    0x5862680: '410f104500',                    # movups xmm0, [r13]       (digest 0..16)
    0x586268b: '0f118424c0000000',              # movups [rsp+0xc0], xmm0
    0x586269c: '4c89a424b0000000',              # mov [rsp+0xb0], r12      (message +0x28)
    0x58626a4: 'f3410f6f07',                    # movdqu xmm0, [r15]
    0x58626a9: 'f30f7f8424e0000000',            # movdqu [rsp+0xe0], xmm0  (sender)
    0x58626bd: '4c8d82083f0000',                # lea r8, [rdx+0x3f08]
    0x58626c4: '4c8d8a880d0000',                # lea r9, [rdx+0xd88]
    0x58626cb: '0fb68a9a0b0000',                # movzx ecx, byte [rdx+0xb9a]
    # handler B
    0x5862881: '488db208490000',                # lea rsi, [rdx+0x4908]
    0x58628cd: '4c8d82784a0000',                # lea r8, [rdx+0x4a78]
    0x58628d4: '4c8d8af8180000',                # lea r9, [rdx+0x18f8]
    0x58628db: '0fb68a0a170000',                # movzx ecx, byte [rdx+0x170a]
    # second-store handlers
    0x5869511: '488db2503e0000',                # lea rsi, [rdx+0x3e50]
    0x5869721: '488db2c0490000',                # lea rsi, [rdx+0x49c0]
    # message hash: BLAKE3 update / finalize slots
    0x38d2a23: 'ff15e7cac002',                  # call [slot 0x64df510]
    0x38d2a31: 'ff15e1cac002',                  # call [slot 0x64df518]
    # update 0x5afa7f0
    0x5afa812: '4c8b6208',                      # mov r12, [rdx+0x8]       (height)
    0x5afa843: '4983c530',                      # add r13, 0x30            (sender)
    0x5afa847: '4c89cf',                        # mov rdi, r9
    0x5afa84a: '89ce',                          # mov esi, ecx
    0x5afa84f: 'ff151bbc9e00',                  # call [slot 0x64e6470]
    0x5afa857: '4180be9000000000',              # cmp byte [r14+0x90], 0
    0x5afa869: '4c3b6010',                      # cmp r12, [rax+0x10]      (box initial height)
    0x5afa874: '41c6869100000001',              # mov byte [r14+0x91], 1
    0x5afa88a: 'f3410f7f8692000000',            # movdqu [r14+0x92], xmm0  (digest)
    0x5afa8a5: '4c8d7330',                      # lea r14, [rbx+0x30]      (r9 +0x30 map)
    0x5afa8b9: 'ff1559a69e00',                  # call [slot 0x64e4f18]
    0x5afa945: '4c8d7e14',                      # lea r15, [rsi+0x14]      (20-byte keys)
    0x5afa949: 'ba14000000',                    # mov edx, 0x14            (memcmp length)
    0x5afa9dc: '488b4e58',                      # mov rcx, [rsi+0x58]
    0x5afa9e8: 'ff158aba9e00',                  # call [slot 0x64e6478]
    0x5afa9ee: '66817c2460a201',                # cmp word [rsp+0x60], 0x1a2
    0x5afad05: '0f954502',                      # setne byte [rbp+0x2]
    0x5afad09: '66b8a201',                      # mov ax, 0x1a2
    0x5afad26: '66b89500',                      # mov ax, 0x95
    # vote insert takes store +0x18
    0x537b899: '4989f5',                        # mov r13, rsi             (store)
    0x537b96c: '498d4518',                      # lea rax, [r13+0x18]
}
CALLS = (
    (0x58625b1, MSG_HASH),
    (0x58626e3, UPDATE),
    (0x58628f3, UPDATE),
    (0x5869583, UPDATE2),
    (0x5869793, UPDATE2),
    (0x5afaa5f, 0x57c9430),
    (0x5afab8f, VOTE_INSERT),
)
SLOTS = {0x64e0ad8: 0x1536a90, 0x64e6470: 0x3c3a3f0, 0x64e4f18: 0x3c3d240, 0x64e6478: 0x36ca5b0,
         0x64df510: 0x160b3a0, 0x64df518: 0x160bcd0}


def relocations(data):
    from elf_index import sections
    rel = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def call_sites(data, wanted):
    """One pass over .text: every E8 rel32 call whose target is in `wanted`."""
    base, code = text(data)
    out = {t: [] for t in wanted}
    lo, hi = min(wanted), max(wanted)
    pos = code.find(b'\xe8')
    while pos != -1 and pos + 5 <= len(code):
        target = base + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
        if lo <= target <= hi and target in out:
            out[target].append(base + pos)
        pos = code.find(b'\xe8', pos + 1)
    return out


SLOT_CALLS = ((0x58625c1, 0x64e0ad8), (0x5afa84f, 0x64e6470), (0x5afa8b9, 0x64e4f18),
              (0x5afa9e8, 0x64e6478), (0x38d2a23, 0x64df510), (0x38d2a31, 0x64df518))


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in CALLS:
        if rip_target(data, va, b'\xe8', 5) != target:
            raise ValueError(f'call at {va:#x} changed')
    for va, slot in SLOT_CALLS:
        if rip_target(data, va, b'\xff\x15', 6) != slot:
            raise ValueError(f'slot call at {va:#x} changed')
    rel = relocations(data)
    for slot, target in SLOTS.items():
        if rel.get(slot) != target:
            raise ValueError(f'slot {slot:#x} relocation changed')

    targets = {'handler_a': HANDLER_A, 'handler_b': HANDLER_B, 'handler2_a': HANDLER2_A,
               'handler2_b': HANDLER2_B, 'update': UPDATE, 'update2': UPDATE2, 'vote_insert': VOTE_INSERT}
    found = call_sites(data, set(targets.values()))
    starts = sorted(f['start'] for f in fdes)
    ends = {f['start']: f['end'] for f in fdes}

    def frame_of(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not starts[i] <= va < ends[starts[i]]:
            raise ValueError(f'{va:#x} has no FDE')
        return starts[i]

    census = {name: {'fn': hex(t), 'direct_calls': [hex(v) for v in found[t]],
                     'callers': sorted({hex(frame_of(v)) for v in found[t]})}
              for name, t in targets.items()}
    expected = {'update': ['0x58626e3', '0x58628f3'], 'update2': ['0x5869583', '0x5869793'],
                'vote_insert': ['0x5afab8f'], 'handler_a': ['0x550ed20', '0x55fa523'],
                'handler_b': ['0x54f86b0', '0x55fb5f3']}
    for name, sites in expected.items():
        if census[name]['direct_calls'] != sites:
            raise ValueError(f'call census changed for {name}')
    for va in (HANDLER_A, HANDLER_B, HANDLER2_A, HANDLER2_B, UPDATE, UPDATE2, VOTE_INSERT):
        if frame_of(va) != va:
            raise ValueError(f'{va:#x} is not a function start')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'census': census,
        'handlers': {
            'digest_store': {'A': [hex(HANDLER_A), 'store box +0x3d98', 'r8 box +0x3f08', 'r9 box +0xd88',
                                   'ecx box byte +0xb9a'],
                             'B': [hex(HANDLER_B), 'store box +0x4908', 'r8 box +0x4a78', 'r9 box +0x18f8',
                                   'ecx box byte +0x170a']},
            'second_store': {'A': [hex(HANDLER2_A), 'store box +0x3e50', 'update ' + hex(UPDATE2)],
                             'B': [hex(HANDLER2_B), 'store box +0x49c0', 'update ' + hex(UPDATE2)]},
            'message': 'msg +0x0..+0x20 digest, +0x20 height (r14), +0x28 passed to slot 0x64e0ad8',
            'hash': hex(MSG_HASH) + ' serialise, BLAKE3 update/finalize (slots 0x64df510 / 0x64df518)',
            'signer_check': 'slot 0x64e0ad8 -> 0x1536a90; Err -> tag 0x7e; returned 20 bytes != sender -> '
                            'tag 0x12e',
            'height_bound': 'height >= 0x0ccccccccccccccc rejected',
            'record': '+0x0 msg+0x28, +0x8 height, +0x10..+0x30 digest, +0x30..+0x44 sender (20 bytes)',
        },
        'update': {
            'fn': hex(UPDATE),
            'first_check': 'slot 0x64e6470 -> 0x3c3a3f0 (r9, ecx, sender) -> bool',
            'initial_height': 'store +0x90 == 0 and height == box +0x10 and bool -> store +0x91 = 1, '
                              'digest -> store +0x92..+0xb2',
            'sender_lookup': 'slot 0x64e4f18 -> 0x3c3d240 (r9, sender); B-tree at r9 +0x30, 20-byte memcmp keys',
            'second_lookup': 'slot 0x64e6478 -> 0x36ca5b0 ([r8+0x58], sender) -> tag 0x1a2 + 32 bytes',
            'inserts': hex(0x57c9430) + '(store, height, digest); ' + hex(VOTE_INSERT)
                       + '(store, height, ...) takes store +0x18 at 0x537b96c',
            'result': 'tag 0x1a2, byte +0x2 = changed; error tag 0x95',
        },
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
    print('update calls=%d' % len(result['census']['update']['direct_calls']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
