#!/usr/bin/env python3
"""Bind the node #115 hash_signature_tracker per-signer cap, signer replace and the 10/11 tag (66th stage).

Continues the digest quorum series (open PRs #6051, #6052, #6053). The vote
insert 0x537b870 skips a new (height, digest) record when a count is above
0x897 (2199). This tool binds:

1. the count 0x4e40990: two direct calls (0x537bf2e in 0x537b870, 0x537b11e in its twin 0x537aa60) with a tag-2 (ring)
   iterator over store +0x18 and a pointer to the caller's part byte
   (rsp+0x1ff); for each per-height value it skips the record whose digest
   equals the height's resolved key (+0x21, only when byte +0x20 is 0) and
   adds 1 for every other digest record whose signer collection contains
   the part bytes (collection +0x20 when the part byte is 1, else +0x0);
2. the search results it adds: the B-tree search 0x4d38340 writes tag 0 when
   the 32-byte memcmp finds the key (count adds tag ^ 1); the ring search
   0x57f39d0 returns 0 on a match (count adds rax == 0);
3. the key collection insert 0x4dd26f0: on a ring hit it overwrites the
   0x48-byte value of the 0x68-byte item and returns 1 (replace, no new item);
4. the 10/11 constant: both updates pass it in edi to the recorder behind
   slot 0x64e4ea8 (0x4524e40) with Locations hash_signature_tracker.rs 107:28
   and 123:32; 0x5afa7f0 passes 10, 0x5afadd0 passes 11.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
from freeze_snapshot_115 import read_va, fixed, rip_target, relative_relocations, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-hash-signature-tracker-cap-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

INSERT, COUNT, CAP = 0x537b870, 0x4e40990, 0x897
BTREE_SEARCH, RING_SEARCH = 0x4d38340, 0x57f39d0
KEY_SET_INSERT, SENDER_SET_INSERT = 0x4dd26f0, 0x4dd4f80
UPDATE_A, UPDATE_B = 0x5afa7f0, 0x5afadd0
RECORDER_SLOT, RECORDER = 0x64e4ea8, 0x4524e40
LOC_COUNT, LOC_107, LOC_123 = 0x64a7f08, 0x64bc860, 0x64bc878

FIXED = {
    # insert: ring iterator over store +0x18, part byte pointer, count, cap
    0x537bede: '41b802000000',          # mov r8d, 2                 (iterator tag 2)
    0x537bf15: '488d8424ff010000',      # lea rax, [rsp+0x1ff]       (part byte)
    0x537bf33: '483d97080000',          # cmp rax, 0x897
    0x537bf3e: '0f878cfaffff',          # ja 0x537b9d0               (skip)
    # twin insert 0x537aa60 (second store): same iterator, part byte and cap
    0x537b105: '488d8424ff010000',      # lea rax, [rsp+0x1ff]
    0x537b123: '483d97080000',          # cmp rax, 0x897
    0x537b12e: '0f878cfaffff',          # ja 0x537abc0
    # count: resolved key and skip
    0x4e409c1: '4889442430',            # mov [rsp+0x30], rax        (part byte ptr)
    0x4e409c6: '48ffc0',                # inc rax                    (part bytes)
    0x4e40c6c: '498d4921',              # lea rcx, [r9+0x21]         (resolved key)
    0x4e40c70: '4180792000',            # cmp byte [r9+0x20], 0
    0x4e40c7b: '4c0f44e9',              # cmove r13, rcx
    0x4e40fc6: 'f3410f6f4500',          # movdqu xmm0, [r13]
    0x4e40fcc: 'f3410f6f4d10',          # movdqu xmm1, [r13+0x10]
    0x4e40fd2: 'f30f6f11',              # movdqu xmm2, [rcx]         (record digest)
    0x4e40fd6: '660f74d0',              # pcmpeqb xmm2, xmm0
    0x4e40feb: '3dffff0000',            # cmp eax, 0xffff
    0x4e40ff0: '0f849afdffff',          # je 0x4e40d90               (add 0)
    # count: collection choice and accumulation
    0x4e40ffb: '803801',                # cmp byte [rax], 1          (part byte)
    0x4e4100a: '48394720',              # cmp [rdi+0x20], marker     (senders)
    0x4e4104a: '483907',                # cmp [rdi], marker          (keys)
    0x4e4107f: '3401',                  # xor al, 1                  (found tag 0 -> 1)
    0x4e41084: '4801c5',                # add rbp, rax
    0x4e410bd: '0f94c0',                # sete al                    (ring hit -> 1)
    0x4e410c3: '4801c5',                # add rbp, rax
    # searches: hit encodings
    0x4d38389: 'ba20000000',            # mov edx, 0x20              (memcmp len)
    0x4d38391: '41ffd5',                # call r13                   (memcmp)
    0x4d383f3: '31c9',                  # xor ecx, ecx               (Found = 0)
    0x4d3840a: '488908',                # mov [rax], rcx
    0x57f3a09: 'ba20000000',            # mov edx, 0x20
    0x57f3a25: '0fb6c1',                # movzx eax, cl              (0 on equal)
    0x57f3a2a: '0f8455010000',          # je 0x57f3b85               (return rax = 0)
    # insert: collection inserts and resolve
    0x537c0ed: '498d7620',              # lea rsi, [r14+0x20]        (senders)
    0x537c13f: '4c89f6',                # mov rsi, r14               (keys)
    0x537c192: 'c6432000',              # mov byte [rbx+0x20], 0     (resolved)
    # key set insert: hit replaces the 0x48-byte value
    0x4dd2951: '0f8484000000',          # je 0x4dd29db               (hit)
    0x4dd29fd: '486bc068',              # imul rax, rax, 0x68        (item stride)
    0x4dd2b6f: '410f114500',            # movups [r13], xmm0         (new value)
    0x4dd2b87: '49894d40',              # mov [r13+0x40], rcx
    0x4dd2b8b: 'b901000000',            # mov ecx, 1                 (Some(old))
    # the 10/11 tag
    0x5afaa83: 'bf0a000000',            # mov edi, 10
    0x5afac32: 'bf0a000000',            # mov edi, 10
    0x5afb063: 'bf0b000000',            # mov edi, 11
    0x5afb212: 'bf0b000000',            # mov edi, 11
}
CALLS = (
    # (va, target) for e8 rel32
    (0x537bf2e, COUNT),
    (0x537b11e, COUNT),
    (0x4e41032, 0x4d38590),
    (0x4e4106d, BTREE_SEARCH),
    (0x4e4109e, 0x57f4490),
    (0x4e410ad, RING_SEARCH),
    (0x537c106, SENDER_SET_INSERT),
    (0x537c152, KEY_SET_INSERT),
    (0x4dd2888, RING_SEARCH),
)
REFERENCES = (
    # (va, prefix, length, target)
    (0x537bf27, b'\x48\x8d\x35', 7, LOC_COUNT),
    (0x537b117, b'\x48\x8d\x35', 7, LOC_COUNT),
    (0x57f3a12, b'\xff\x15', 6, 0x64dfb50),
    (0x5afaa7c, b'\x48\x8d\x35', 7, LOC_107),
    (0x5afaa88, b'\xff\x15', 6, RECORDER_SLOT),
    (0x5afac2b, b'\x48\x8d\x35', 7, LOC_123),
    (0x5afac37, b'\xff\x15', 6, RECORDER_SLOT),
    (0x5afb05c, b'\x48\x8d\x35', 7, LOC_107),
    (0x5afb068, b'\xff\x15', 6, RECORDER_SLOT),
    (0x5afb20b, b'\x48\x8d\x35', 7, LOC_123),
    (0x5afb217, b'\xff\x15', 6, RECORDER_SLOT),
)
RELOCATIONS = {RECORDER_SLOT: RECORDER, LOC_COUNT: 0x44e7fd, LOC_107: 0x44d8e1, LOC_123: 0x44d8e1}
STRINGS = {
    0x44e7fd: b'l1/src/raw_signature_tracker.rs',
    0x44d8e1: b'l1/src/abci/hash_signature_tracker.rs',
}
LOCATIONS = {LOC_COUNT: (0x1f, 231, 9), LOC_107: (0x25, 107, 28), LOC_123: (0x25, 123, 32)}


def call_census(data, targets):
    """One pass over .text: e8 rel32 sites per target."""
    base, code = text(data)
    want = set(targets)
    out = {t: [] for t in targets}
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code):
            t = base + i + 5 + struct.unpack_from('<i', code, i + 1)[0]
            if t in want:
                out[t].append(base + i)
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
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, raw in STRINGS.items():
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'string at {va:#x} changed')
    for va, (ln, line, col) in LOCATIONS.items():
        if struct.unpack('<QII', read_va(data, va + 8, 16)) != (ln, line, col):
            raise ValueError(f'location at {va:#x} changed')

    census = call_census(data, [COUNT, KEY_SET_INSERT, SENDER_SET_INSERT])
    if census[COUNT] != [0x537b11e, 0x537bf2e]:
        raise ValueError('count call census changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'cap': {
            'compare': '0x537bf33 (insert %s) and 0x537b123 (twin 0x537aa60): cmp rax, 0x897; ja skips the new (height, digest) record' % hex(INSERT),
            'count_fn': hex(COUNT),
            'count_direct_calls': [hex(v) for v in census[COUNT]],
            'iterator': 'tag 2 (ring) over store +0x18 elements of 0x50 bytes; +0x48 = &part byte (rsp+0x1ff)',
            'overflow_location': 'l1/src/raw_signature_tracker.rs:231:9 (%s)' % hex(LOC_COUNT),
            'per_record': 'skip the digest equal to the height key +0x21 when byte +0x20 is 0; '
                          'else add 1 when the record collection contains the part bytes',
            'collection': 'part byte 1 -> senders +0x20; else keys +0x0',
            'btree_hit': '%s writes tag 0 on a 32-byte memcmp match; count adds tag ^ 1' % hex(BTREE_SEARCH),
            'ring_hit': '%s returns 0 on a match; count adds rax == 0' % hex(RING_SEARCH),
        },
        'repeat_signer': {
            'key_insert': hex(KEY_SET_INSERT),
            'key_insert_calls': [hex(v) for v in census[KEY_SET_INSERT]],
            'sender_insert': hex(SENDER_SET_INSERT),
            'sender_insert_calls': [hex(v) for v in census[SENDER_SET_INSERT]],
            'hit': 'ring hit (0x4dd2951) overwrites the 0x48-byte value at item +0x20 '
                   '(0x68-byte items) and returns 1 with the old value',
        },
        'tag_10_11': {
            'recorder': '%s via slot %s' % (hex(RECORDER), hex(RECORDER_SLOT)),
            hex(UPDATE_A): ['0x5afaa83 edi=10 loc 107:28', '0x5afac32 edi=10 loc 123:32'],
            hex(UPDATE_B): ['0x5afb063 edi=11 loc 107:28', '0x5afb212 edi=11 loc 123:32'],
            'location_file': STRINGS[0x44d8e1].decode(),
        },
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
    print('count calls=%s' % result['cap']['count_direct_calls'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
