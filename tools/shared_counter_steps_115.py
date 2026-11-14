#!/usr/bin/env python3
"""Bind which node #115 engine values increment the shared height counter (stage 83).

Continues #6081 (fast_height: the slow input takes an Arc clone of the fast
runner's height counter) and #6083 (the counter check runs when engine value
dword +0x0 == 2). This tool binds:

1. the two counter checks: wrapper A at 0x5a055f2 and wrapper B at 0x5a06e2a
   compare engine value dword +0x0 with 2 and skip on any other value; on 2
   they lock-increment [engine value +0x458]+0x10 and compare the new value
   with box +0x28 as read at 0x5a055e6 (A) / 0x5a06e1e (B); equal runs the
   step (A: 0x5a07ec0 at 0x5a05fc9), else the assert slot 0x64e1e68;
2. the counter is shared: 0x4fc1660 reads runner +0xb08 and lock-increments
   its first word (Arc strong count, 0x4fc1753); 0x5a6c364 receives that
   clone in r12, drops the fresh {1,1,box+0x28} Arc at rsp+0x1668
   (0x5a6c3c2..0x5a6c3d0) and stores the clone there (0x5a6c3d6);
3. the slow input's dword +0x0 is 0, not 2: the slot at rsp+0x1240 is set
   to 2 (0x5a6c3b6), dropped unless still 2 (0x5a6c518/0x5a6c520), then set
   to 0 (0x5a6c52f) before the 0x438-byte copy to rsp+0x5508 and the call to
   0x5a08f80; 0x5a08f80 passes that input unchanged in rsi to the fill
   (slot 0x64e80e8 = 0x38c6590), which keeps a tag other than 2 (0x38c65aa);
4. the fast input's dword +0x0 is 2 (0x5a6c0e0, fill at 0x5a6c104) and the
   fast counter starts at the new box +0x28 (0x5a6c0b2, 0x5a6c0dc);
5. which runner reaches which wrapper: the fast apply body 0x4fcb590 (reads
   runner byte +0xb20) calls 0x56186c0 -> wrapper B 0x5a06600; the slow body
   0x4fcac10 (reads runner byte +0xb40) calls 0x59ec200 -> 0x56185e0 ->
   wrapper A 0x5a04e40.

Reading: only engine values built with tag 2 (fast, catch-up) increment and
check the shared counter; the slow engine value (tag 0) holds the shared Arc
but skips the check. The captured binary is not executed. objdump and
readelf are not started. Addresses are ELF virtual addresses.
"""
import argparse
import bisect
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import SHA256, RELATIVE, TARGET, fixed, read_va, relative_relocations, rip_target, text

PACKET = ROOT / 'research/work-items/RE-008-shared-counter-steps-115'

FIXED = {
    # wrapper A (layout A, 0x5a04e40): tag, counter, compare
    0x5a055de: '498b842450040000',      # mov rax, [r12+0x450]     (box)
    0x5a055e6: '488b4028',              # mov rax, [rax+0x28]      (height)
    0x5a055f2: '41833c2402',            # cmp dword [r12], 2
    0x5a055f7: '7550',                  # jne (skip check)
    0x5a055f9: '498b8c2458040000',      # mov rcx, [r12+0x458]
    0x5a05601: 'f048ff4110',            # lock inc qword [rcx+0x10]
    0x5a0561a: '4839c8',                # cmp rax, rcx
    0x5a0563a: '31ff',                  # xor edi, edi
    0x5a0563c: '31c9',                  # xor ecx, ecx
    # wrapper B (layout B, 0x5a06600)
    0x5a06e1e: '488b4728',              # mov rax, [rdi+0x28]      (height)
    0x5a06e2a: '41833f02',              # cmp dword [r15], 2
    0x5a06e2e: '754e',                  # jne (skip check)
    0x5a06e30: '498b8f58040000',        # mov rcx, [r15+0x458]
    0x5a06e37: 'f048ff4110',            # lock inc qword [rcx+0x10]
    0x5a06e4f: '4839c8',                # cmp rax, rcx
    # Arc clone of runner +0xb08 in 0x4fc1660
    0x4fc174c: '488b83080b0000',        # mov rax, [rbx+0xb08]
    0x4fc1753: 'f048ff00',              # lock inc qword [rax]     (strong count)
    # 0x5a6bfb0: fast input tag 2, counter init, slow input Arc swap and tag 0
    0x5a6c0b2: '4c8b7828',              # mov r15, [rax+0x28]      (new box height)
    0x5a6c0dc: '4c897810',              # mov [rax+0x10], r15      (counter = height)
    0x5a6c0e0: '48c78424200e000002000000',  # mov qword [rsp+0xe20], 2
    0x5a6c0fc: '488db424200e0000',      # lea rsi, [rsp+0xe20]
    0x5a6c369: '4989c4',                # mov r12, rax             (clone)
    0x5a6c3b6: '48c784244012000002000000',  # mov qword [rsp+0x1240], 2
    0x5a6c3c2: 'f048ff08',              # lock dec qword [rax]     (fresh Arc)
    0x5a6c3c8: '488dbc2468160000',      # lea rdi, [rsp+0x1668]
    0x5a6c3d6: '4c89a42468160000',      # mov [rsp+0x1668], r12
    0x5a6c518: '83bc244012000002',      # cmp dword [rsp+0x1240], 2
    0x5a6c520: '740d',                  # je (no drop)
    0x5a6c52f: '48c784244012000000000000',  # mov qword [rsp+0x1240], 0
    0x5a6c5cb: '488db42440120000',      # lea rsi, [rsp+0x1240]
    0x5a6c5d3: 'ba38040000',            # mov edx, 0x438
    0x5a6c5f0: '488db42408550000',      # lea rsi, [rsp+0x5508]
    # 0x5a08f80 passes rsi to the fill unchanged
    0x5a08f92: '4c8bb620040000',        # mov r14, [rsi+0x420]
    0x5a08fb4: '488dbc2480040000',      # lea rdi, [rsp+0x480]
    # fill 0x38c6590 keeps a tag other than 2
    0x38c65a1: '48c744240802000000',    # mov qword [rsp+8], 2
    0x38c65aa: '833e02',                # cmp dword [rsi], 2
    0x38c65ad: '751a',                  # jne (copy input)
    # runner bodies
    0x4fcb5b0: '410fb686200b0000',      # movzx eax, byte [r14+0xb20]  (fast)
    0x4fcac4d: '410fb687400b0000',      # movzx eax, byte [r15+0xb40]  (slow)
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x5a0561d, b'\x0f\x84', 6, 0x5a05fc1),
    (0x5a05fc9, b'\xe8', 5, 0x5a07ec0),
    (0x5a0563e, b'\xff\x15', 6, 0x64e1e68),
    (0x5a06e52, b'\x0f\x84', 6, 0x5a077d9),
    (0x5a06e73, b'\xff\x15', 6, 0x64e1e68),
    (0x5a6c364, b'\xe8', 5, 0x4f1b280),
    (0x5a6c3d0, b'\xff\x15', 6, 0x64e6eb0),
    (0x5a6c104, b'\xff\x15', 6, 0x64e80e8),
    (0x5a6c5f8, b'\xe8', 5, 0x5a08f80),
    (0x5a08fbc, b'\xff\x15', 6, 0x64e80e8),
)
RELOCS = {0x64e80e8: 0x38c6590}
CHAINS = {
    # target: expected direct caller sites
    0x5a06600: [0x5618710],
    0x56186c0: [0x4fcb795],
    0x5a04e40: [0x5618630],
    0x56185e0: [0x54439ad, 0x59ec2a8],
    0x59ec200: [0x4fcae48],
}
FRAMES = {0x4fcb795: 0x4fcb590, 0x4fcae48: 0x4fcac10, 0x5618710: 0x56186c0,
          0x5618630: 0x56185e0, 0x59ec2a8: 0x59ec200}


def call_census(data, targets):
    """One scan of .text for E8 rel32 calls landing on any of targets."""
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


def frame_of(fdes):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]

    def frame(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
            raise ValueError(f'{va:#x} has no FDE')
        return ordered[i]['start']
    return frame


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    census = call_census(data, CHAINS)
    for target, sites in CHAINS.items():
        if census[target] != sites:
            raise ValueError(f'caller census of {target:#x} changed')
    frame = frame_of(fdes)
    for site, start in FRAMES.items():
        if frame(site) != start:
            raise ValueError(f'{site:#x} left its function')
    # nothing between the fill call's rsi setup and the call rewrites rsi in 0x5a08f80
    window = read_va(data, 0x5a08f8f, 0x5a08fbc - 0x5a08f8f)
    if re.search(rb'[\x48\x4c][\x89\x8b\x8d][\xf6\xc6\xce\xd6\xde\xe6\xee\xfe]|\x48\x8d\x34|\x48\x8d\x74|\x48\x8d\xb4', window):
        raise ValueError('rsi rewritten before the fill call')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'counter_check': {
            'wrapper_a': {'fn': '0x5a04e40', 'tag_test': '0x5a055f2 cmp dword [r12], 2; jne skips',
                          'increment': '0x5a05601 lock inc [[r12+0x458]+0x10]',
                          'compare': '0x5a0561a counter == box +0x28 read at 0x5a055e6',
                          'equal': '0x5a0561d -> 0x5a05fc1 -> step 0x5a07ec0 (0x5a05fc9)',
                          'unequal': '0x5a0563e slot 0x64e1e68 (assert, edi=0, ecx=0)'},
            'wrapper_b': {'fn': '0x5a06600', 'tag_test': '0x5a06e2a cmp dword [r15], 2; jne skips',
                          'increment': '0x5a06e37 lock inc [[r15+0x458]+0x10]',
                          'compare': '0x5a06e4f counter == box +0x28 read at 0x5a06e1e',
                          'equal': '0x5a06e52 -> 0x5a077d9',
                          'unequal': '0x5a06e73 slot 0x64e1e68'},
        },
        'shared_arc': {
            'clone': '0x4fc174c mov rax, [runner+0xb08]; 0x4fc1753 lock inc [rax] (Arc strong count)',
            'swap': '0x5a6c3c2 lock dec fresh Arc at rsp+0x1668 (drop at 0x5a6c3d0 via slot 0x64e6eb0 when zero); '
                    '0x5a6c3d6 store clone (r12) at rsp+0x1668 = slow input +0x428',
            'fast_init': '0x5a6c0b2/0x5a6c0dc counter = new box +0x28',
        },
        'engine_value_tags': {
            'fast': '0x5a6c0e0 input +0x0 = 2 -> fill 0x5a6c104 -> tag 2 (checks the counter)',
            'slow': '0x5a6c3b6 = 2, 0x5a6c518 drop unless 2, 0x5a6c52f = 0, 0x438 copy to rsp+0x5508, '
                    '0x5a08f80 (0x5a6c5f8) passes rsi to fill 0x5a08fbc -> tag 0 (skips the check)',
            'fill': '0x38c6590 (slot 0x64e80e8): tag 2 -> fresh value tag 2; other tag -> copied unchanged (0x38c65aa)',
        },
        'runner_to_wrapper': {
            'fast': '0x4fcb590 (byte +0xb20 at 0x4fcb5b0) -> 0x56186c0 (0x4fcb795) -> wrapper B 0x5a06600 (0x5618710)',
            'slow': '0x4fcac10 (byte +0xb40 at 0x4fcac4d) -> 0x59ec200 (0x4fcae48) -> 0x56185e0 (0x59ec2a8) '
                    '-> wrapper A 0x5a04e40 (0x5618630); 0x56185e0 also called from 0x5443930 (0x54439ad)',
        },
        'callers': {hex(t): [hex(s) for s in census[t]] for t in sorted(CHAINS)},
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
    generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print('shared counter: fast tag 2 checks, slow tag 0 skips')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
