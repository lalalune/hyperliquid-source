#!/usr/bin/env python3
"""Bind the node #115 call that sets the per-key action's ctr flag (stage 98).

Stage 97 (#6207) found that inside the per-key action 0x5582180 the local flag
[rsp+0x28] becomes 1 only after the call to 0x55817e0 at 0x5583117, and that
Locus ctr (box +0xab0) is incremented when the flag is set and [rsp+0x58] is
not zero. This tool binds:

1. the call site: the caller builds a one-word key record [rsp+0xb0] = 2,
   passes ecx = 0 and r9 = &record, calls 0x55817e0 and then stores 1 into the
   flag without testing any result, so the flag means "0x55817e0 has run",
   not "it succeeded";
2. 0x55817e0: a tag in [r9] selects the key (2 → the 20-byte key passed in
   rdx); it tests the key against the Locus blp collection at box +0x6c8
   (vector form when the first word is 0x8000000000000000, otherwise a map);
   a key already present skips to the tail; otherwise it calls 0x5609fb0
   with r8d = 3, then slot 0x64e7180 on Locus blp (+0x670) and, when that
   returns true, 0x5609fb0 again with r8d = 0; every path ends in 0x5580d10
   (the move_token helper); results other than 0x1a2 are dropped via
   0x5630000, so the function returns nothing to its caller;
3. 0x5580d10 formats "move_token to_spot: " and "move_token from_spot: " and
   records Locations l1/src/qtys/impl_wei.rs:6:1 and impl_ntl.rs:70:1 through
   the registry slot 0x64e4ea8 (#6056);
4. [rsp+0x58] is the per-key action's r8 argument (stored once at 0x55821af),
   so the ctr increment condition from #6206 (r8 != 0) and #6207
   ([rsp+0x58] != 0) are the same test.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import SHA256, RELATIVE, TARGET, direct_calls, fixed, frame, read_va, relative_relocations, rip_target

PACKET = ROOT / 'research/work-items/RE-008-ctr-flag-setter-115'

SETTER = 0x55817e0
KEY_ACTION = 0x5582180
CHECK = 0x5609fb0
MOVE_TOKEN = 0x5580d10
DROP = 0x5630000
BLP_SLOT = 0x64e7180
REGISTRY_SLOT = 0x64e4ea8
OK_TAG = 0x1a2

FIXED = {
    # call site in the per-key action 0x5582180
    0x55821af: '4c89442458',                 # mov [rsp+0x58], r8           (r8 argument)
    0x55830e5: '48c78424b000000002000000',   # mov qword [rsp+0xb0], 2      (key tag)
    0x558310a: '31c9',                       # xor ecx, ecx
    0x558310c: '4c8d8c24b0000000',           # lea r9, [rsp+0xb0]
    0x5583120: 'b001',                       # mov al, 1                    (no result test)
    0x5583122: '89442428',                   # mov [rsp+0x28], eax          (flag = 1)
    0x5583256: '48837c245800',               # cmp qword [rsp+0x58], 0
    0x558325c: '0f95c0',                     # setne al
    0x558325f: '84442428',                   # test [rsp+0x28], al
    0x5583273: '498b85b00a0000',             # mov rax, [r13+0xab0]         (Locus ctr)
    0x558327a: '48ffc0',                     # inc rax
    0x5583284: '480f44c1',                   # cmove rax, rcx               (saturate)
    0x5583288: '498985b00a0000',             # mov [r13+0xab0], rax
    # 0x55817e0
    0x5581800: '48bd0000000000000080',       # movabs rbp, 0x8000000000000000
    0x558180a: '498b01',                     # mov rax, [r9]                (key tag)
    0x5581810: '4883ea02',                   # sub rdx, 2
    0x5581819: '480f43ca',                   # cmovae rcx, rdx
    0x558184e: '4939afc8060000',             # cmp [r15+0x6c8], rbp         (blp vector form?)
    0x5581897: '48895c2430',                 # mov [rsp+0x30], rbx          (tag 2: key = rdx)
    0x558193d: '41b803000000',               # mov r8d, 3
    0x558194b: '66817c2430a201',             # cmp word [rsp+0x30], 0x1a2
    0x55819e1: '498dbf70060000',             # lea rdi, [r15+0x670]         (Locus blp)
    0x5581a31: '4531c0',                     # xor r8d, r8d
    0x5581bf9: '4c896c2408',                 # tail: mov [rsp+8], r13
    0x5581c19: '4531c0',                     # xor r8d, r8d
    0x5581aba: '41b803000000',               # mov r8d, 3                   (non-tag-2 path)
    0x5581b74: '41b803000000',               # mov r8d, 3                   (after map lookup)
    0x5581c21: '66817c2430a201',             # cmp word [rsp+0x30], 0x1a2
}
CALLS = (
    # (instruction va, target)
    (0x5583117, SETTER),
    (0x5581946, CHECK),
    (0x5581a37, CHECK),
    (0x5581c1c, MOVE_TOKEN),
    (0x55819bd, DROP),
    (0x5581c93, DROP),
)
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x55819ed, b'\xff\x15', 6, BLP_SLOT),
    (0x5581455, b'\x48\x8d\x35', 7, 0x432bcb),     # "move_token to_spot: "
    (0x558152a, b'\x48\x8d\x35', 7, 0x438c95),     # "move_token from_spot: "
    (0x55811f4, b'\x48\x8d\x35', 7, 0x6487478),    # Location impl_wei.rs:6:1
    (0x55811ff, b'\xff\x15', 6, REGISTRY_SLOT),
    (0x5581604, b'\x48\x8d\x35', 7, 0x64a9918),    # Location impl_ntl.rs:70:1
    (0x5581611, b'\xff\x15', 6, REGISTRY_SLOT),
)
STRINGS = {
    0x432bcb: b'\x14move_token to_spot: ',
    0x438c95: b'\x16move_token from_spot: ',
}
LOCATIONS = {
    0x6487478: (b'l1/src/qtys/impl_wei.rs', 6, 1),
    0x64a9918: (b'l1/src/qtys/impl_ntl.rs', 70, 1),
}


def location(data, rel, va):
    ptr = rel[va]
    n, line, col = __import__('struct').unpack('<QII', read_va(data, va + 8, 16))
    return read_va(data, ptr, n), line, col


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in CALLS:
        if rip_target(data, va, b'\xe8', 5) != target:
            raise ValueError(f'call at {va:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, expect in STRINGS.items():
        if read_va(data, va, len(expect)) != expect:
            raise ValueError(f'string at {va:#x} changed')
    rel = relative_relocations(data)
    for va, expect in LOCATIONS.items():
        if location(data, rel, va) != expect:
            raise ValueError(f'location at {va:#x} changed')
    if rel.get(BLP_SLOT) != 0x369b360:
        raise ValueError('blp slot relocation changed')
    if frame(fdes, 0x5583117) != KEY_ACTION or frame(fdes, 0x5581c1c) != SETTER:
        raise ValueError('frame layout changed')
    setter_calls = direct_calls(data, SETTER)
    check_calls = [v for v in direct_calls(data, CHECK) if frame(fdes, v) == SETTER]
    if check_calls != [0x5581946, 0x5581a37, 0x5581ac0, 0x5581b7d]:
        raise ValueError('check call census changed')
    if len(setter_calls) != 4 or 0x5583117 not in setter_calls:
        raise ValueError('setter call census changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'call_site': {
            'site': hex(0x5583117),
            'args': 'r9 = &[rsp+0xb0] with qword 2 (key tag), ecx = 0',
            'flag_store': hex(0x5583120) + ' mov al,1 / ' + hex(0x5583122) + ' mov [rsp+0x28],eax (no result test)',
            'ctr_condition': '[rsp+0x58] (= r8 argument, stored at %s) != 0 and flag set; saturating inc of box +0xab0'
                             % hex(0x55821af),
        },
        'setter': {
            'fn': hex(SETTER),
            'direct_calls': [hex(v) for v in setter_calls],
            'caller_frames': sorted({hex(frame(fdes, v)) for v in setter_calls}),
            'key_tag': '[r9] - 2 with floor 1 selects the path; tag 2 → key = rdx (%s)' % hex(0x5581897),
            'membership': 'box +0x6c8 == 0x8000000000000000 → vector form (+0x6d0/+0x6d8); else map; present → tail',
            'check_calls': [hex(v) for v in check_calls],
            'check_r8': {hex(0x5581946): 3, hex(0x5581a37): 0, hex(0x5581ac0): 3, hex(0x5581b7d): 3},
            'blp_slot': hex(BLP_SLOT) + ' -> 0x369b360 on Locus blp (+0x670); true → second check',
            'tail': hex(0x5581c1c) + ' call move_token ' + hex(MOVE_TOKEN),
            'results': 'non-%s results dropped through %s; nothing returned to the caller' % (hex(OK_TAG), hex(DROP)),
        },
        'move_token': {
            'fn': hex(MOVE_TOKEN),
            'strings': [s[1:].decode() for s in STRINGS.values()],
            'registry_locations': ['%s:%d:%d' % (p.decode(), l, c) for p, l, c in LOCATIONS.values()],
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
    print('setter calls=%d' % len(result['setter']['direct_calls']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
