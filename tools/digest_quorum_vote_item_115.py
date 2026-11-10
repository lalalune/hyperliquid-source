#!/usr/bin/env python3
"""Bind how node #115 turns a digest quorum vote into a signer entry (65th stage).

Continues #6051 (vote resolution) and #6052 (vote handlers and the store update
0x5afa7f0). This tool binds:

1. the store update 0x5afa7f0 builds a two-part signer candidate on the stack:
   byte tag + 32-byte key (result of slot 0x64e6478 when its tag is 0x1a2) at
   rsp+0xd8, and byte tag + 20-byte sender at rsp+0xf9; it passes the candidate
   as r8 to the vote insert 0x537b870 (one direct call, 0x5afab8f);
2. the insert reads the two tags at [r8] and [r8+0x21] and keeps a part only
   when its tag is 1;
3. a 20-byte part is kept only if found in a 20-byte-key B-tree (memcmp 0x14);
   a 32-byte part only if slot 0x64e6ac0 returns non-zero;
4. a resolved height (value byte +0x20 == 0) whose selected key at +0x21
   differs from the vote digest skips the candidate;
5. a new (height, digest) pair is refused when a census over the store
   (0x4e40990, closure table 0x64a7f08) returns more than 0x897;
6. the height value and the digest's inner value are fetched or created
   (0x4dc8170/0x4da61f0, 0x4dcd300/0x4da5bc0);
7. before adding, an unresolved height runs the quorum check 0x5373810
   (which calls the #6051 stake check 0x36c7f70); a 20-byte part is added to
   the inner value's second collection (+0x20, 0x4dd4f80), a 32-byte part to
   the first (+0x0, 0x4dd26f0);
8. when the check was false before and is true after, the height is resolved:
   byte +0x20 = 0 and the digest is copied to +0x21..+0x41;
9. the second store update 0x5afadd0 is a twin of 0x5afa7f0: after removing
   addresses inside the function, they differ only in four callees and one
   immediate, and both name l1/src/abci/hash_signature_tracker.rs.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import read_va, relative_relocations, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-digest-quorum-vote-item-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

UPDATE_A, UPDATE_B = 0x5afa7f0, 0x5afadd0
INSERT_A, INSERT_B = 0x537b870, 0x537aa60
QUORUM_CHECK, STAKE_CHECK = 0x5373810, 0x36c7f70
TWIN_CALLEES = ((0x57c9430, 0x57c96c0), (0x537b870, 0x537aa60), (0x5376540, 0x5376f80))
LOCATIONS = {0x64bc830: (174, 42), 0x64bc848: (184, 22), 0x64bc860: (107, 28), 0x64bc878: (123, 32)}
LOCATION_FILE = (0x44d8e1, b'l1/src/abci/hash_signature_tracker.rs')

FIXED = {
    # update 0x5afa7f0: candidate built on the stack
    0x5afa9ee: '66817c2460a201',          # cmp word [rsp+0x60], 0x1a2   (slot 0x64e6478 Ok)
    0x5afaaeb: '4488bc24d8000000',        # mov [rsp+0xd8], r15b         (32-byte part tag)
    0x5afaaf3: '4488b424f9000000',        # mov [rsp+0xf9], r14b         (20-byte part tag)
    0x5afab8f: 'e8dc0c88ff',              # call 0x537b870               (vote insert)
    # insert 0x537b870: parts
    0x537b8ae: '410fb610',                # movzx edx, byte [r8]
    0x537b8b2: '410fb64821',              # movzx ecx, byte [r8+0x21]
    0x537b8cd: '80fa01',                  # cmp dl, 1
    0x537b908: '80f901',                  # cmp cl, 1
    0x537bb19: 'ba14000000',              # mov edx, 0x14                (20-byte key compare)
    0x537bbed: 'ff15cdae1601',            # call [slot 0x64e6ac0]        (32-byte part check)
    # resolved height: selected key vs vote digest
    0x537b99b: 'f30f6f4721',              # movdqu xmm0, [rdi+0x21]
    0x537b9a0: 'f30f6f4f31',              # movdqu xmm1, [rdi+0x31]
    0x537b9bf: '3dffff0000',              # cmp eax, 0xffff
    # census cap
    0x537bf27: '488d35dabf1201',          # lea rsi, [0x64a7f08]
    0x537bf2e: 'e85d4aacff',              # call 0x4e40990
    0x537bf33: '483d97080000',            # cmp rax, 0x897
    # get-or-create height value and digest inner value
    0x537bf56: 'e815c2a4ff',              # call 0x4dc8170
    0x537bf60: 'e88ba2a2ff',              # call 0x4da61f0
    0x537c08d: 'e86e12a5ff',              # call 0x4dcd300
    0x537c097: 'e8249ba2ff',              # call 0x4da5bc0
    # quorum before, add, quorum after
    0x537c09f: '807b2000',                # cmp byte [rbx+0x20], 0
    0x537c0c0: 'e84b77ffff',              # call 0x5373810
    0x537c10d: '40b501',                  # mov bpl, 1                   (resolved: no re-check)
    0x537c0ed: '498d7620',                # lea rsi, [r14+0x20]          (20-byte collection)
    0x537c106: 'e8758ea5ff',              # call 0x4dd4f80
    0x537c152: 'e89965a5ff',              # call 0x4dd26f0               (32-byte collection)
    0x537c180: 'e88b76ffff',              # call 0x5373810
    0x537c185: '84c0',                    # test al, al
    0x537c192: 'c6432000',                # mov byte [rbx+0x20], 0       (resolved)
    0x537c1a8: 'f30f7f4321',              # movdqu [rbx+0x21], xmm0      (selected digest)
    0x537c1ad: 'f30f7f4b31',              # movdqu [rbx+0x31], xmm1
    # quorum check uses the stake check of #6051
    0x53738fa: 'e8714635fe',              # call 0x36c7f70
}


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def call_census(data, targets):
    base, code = text(data)
    out = {t: [] for t in targets}
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code):
            t = base + i + 5 + struct.unpack_from('<i', code, i + 1)[0]
            if t in out:
                out[t].append(base + i)
    return out


def twin_diff(data, fdes):
    ends = {f['start']: f['end'] for f in fdes}
    a, b = read_va(data, UPDATE_A, ends[UPDATE_A] - UPDATE_A), read_va(data, UPDATE_B, ends[UPDATE_B] - UPDATE_B)
    if len(a) != len(b):
        raise ValueError('update twins differ in length')
    delta = UPDATE_B - UPDATE_A
    shifted, callees, other = 0, [], []
    i = 0
    while i < len(a):
        if a[i] == b[i]:
            i += 1
            continue
        # find the rel32 field this byte belongs to: try field starts i-3..i
        for s in range(max(0, i - 3), i + 1):
            if s + 4 > len(a):
                continue
            ra, rb = struct.unpack_from('<i', a, s)[0], struct.unpack_from('<i', b, s)[0]
            ta, tb = UPDATE_A + s + 4 + ra, UPDATE_B + s + 4 + rb
            if ra - rb == delta and ta == tb:
                shifted += 1
                i = s + 4
                break
            if s > 0 and a[s - 1] == 0xe8 and b[s - 1] == 0xe8:
                callees.append((hex(ta), hex(tb)))
                i = s + 4
                break
        else:
            other.append((hex(UPDATE_A + i), a[i], b[i]))
            i += 1
    return shifted, callees, other


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    if read_va(data, LOCATION_FILE[0], len(LOCATION_FILE[1])) != LOCATION_FILE[1]:
        raise ValueError('location file changed')
    rel = relative_relocations(data)
    for va, (line, col) in LOCATIONS.items():
        if rel.get(va) != LOCATION_FILE[0] or struct.unpack('<II', read_va(data, va + 0x10, 8)) != (line, col):
            raise ValueError(f'location {va:#x} changed')
    calls = call_census(data, (INSERT_A, INSERT_B, QUORUM_CHECK))
    if calls[INSERT_A] != [0x5afab8f] or len(calls[INSERT_B]) != 1:
        raise ValueError('insert call census changed')
    shifted, callees, other = twin_diff(data, fdes)
    if sorted(callees) != sorted((hex(a), hex(b)) for a, b in TWIN_CALLEES):
        raise ValueError('twin callee set changed')
    if other != [(hex(0x5afaa84), 0xa, 0xb), (hex(0x5afac33), 0xa, 0xb)]:
        raise ValueError('twin immediate differences changed')
    if sorted(calls[QUORUM_CHECK]) != [0x537b2b0, 0x537b370, 0x537c0c0, 0x537c180]:
        raise ValueError('quorum check census changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'candidate': {
            'built_in': hex(UPDATE_A),
            'key32': 'tag byte rsp+0xd8 + 32 bytes from slot 0x64e6478 when its tag word is 0x1a2',
            'addr20': 'tag byte rsp+0xf9 + 20-byte sender (kept when found in the r9+0x30 B-tree, #6052)',
            'passed_as': 'r8 to %s at 0x5afab8f' % hex(INSERT_A),
        },
        'insert': {
            'fn': hex(INSERT_A),
            'parts': '[r8] == 1 -> 32-byte part at r8+0x1; [r8+0x21] == 1 -> 20-byte part at r8+0x22',
            'membership': {'addr20': '20-byte-key B-tree, memcmp 0x14 (0x537bb19)',
                           'key32': 'slot 0x64e6ac0 returns non-zero (0x537bbed)'},
            'resolved_mismatch_skips': 'value +0x21..+0x41 != vote digest (0x537b99b..0x537b9bf)',
            'new_pair_cap': 'census 0x4e40990 with closure table 0x64a7f08 > 0x897 skips (0x537bf33)',
            'get_or_create': {'height_value': '0x4dc8170 + 0x4da61f0', 'digest_inner': '0x4dcd300 + 0x4da5bc0'},
            'quorum_before': '0x5373810 when value +0x20 != 0, else treated as true (0x537c10d)',
            'add': {'addr20': 'inner +0x20 via 0x4dd4f80', 'key32': 'inner +0x0 via 0x4dd26f0'},
            'resolve': 'if quorum was false and 0x5373810 is now true: +0x20 = 0, +0x21..+0x41 = digest',
            'quorum_check_calls_stake_check': hex(0x53738fa),
            'direct_calls': {hex(k): [hex(v) for v in vs] for k, vs in calls.items()},
        },
        'twin_update': {
            'a': hex(UPDATE_A), 'b': hex(UPDATE_B),
            'shifted_rel32_fields': shifted,
            'callee_pairs': sorted(callees),
            'other_differing_bytes': other,
            'location_file': LOCATION_FILE[1].decode(),
            'locations': {hex(k): list(v) for k, v in LOCATIONS.items()},
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
    t = result['twin_update']
    print(f"callee_pairs={len(t['callee_pairs'])} other={len(t['other_differing_bytes'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
