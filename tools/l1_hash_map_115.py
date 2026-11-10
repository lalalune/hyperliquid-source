#!/usr/bin/env python3
"""Bind the node #115 l1 hash map at engine value +0x3e0 (fifty-ninth stage).

Continues the RE-008 abci packets (open #6023 digest check, #6040 l1 hash in
the steps). #6040 found that both abci steps, after computing the l1 hash at
rsp+0x180, call 0x5a046f0 with engine value +0x3e0. This tool binds:

1. 0x5a046f0 as an insert followed by a trim: it calls 0x4dce8b0 (its only
   direct caller), and when the map length at +0x18 is at least 0x33 it walks
   back from the newest entry (43 calls to 0x4e2a4e0 and 7 to 0x514dc20 in its
   extent), splits the map at the key it reaches (0x4de4a60), drops the older
   part (B-tree: 0x5248d30; ring: deallocate len*0x28 bytes) and keeps the
   rest. The digest-map insert 0x5a03fa0 has the same shape (0x4dd45c0,
   43 x 0x4e2a530, 7 x 0x514dc20, 0x4de5ad0);
2. the two step call sites (0x5a08267 A, 0x5a08ac7 B): key = the height in
   r15, value = the 32 bytes at rsp+0x180; each is preceded by a call to the
   hyperliquid_data wrapper 0x5942b40 with the name `visor_abci_state` and
   Location l1/src/abci/engine.rs:316:46, writing the stack value at rsp that
   the step built from box +0x10/+0x18, +0x28, the freeze height (+0x10e8 in
   A, +0x1c58 in B), +0x60/+0x68 and the wall clock (slot 0x64e0990);
3. the only other readers of +0x3e0 found: the step wrappers 0x5a04e40 (A)
   and 0x5a06600 (B). When engine value byte +0x0 is set they split the map
   at (engine value +0x8) + 1 (saturating), drop the part below without
   reading any value, and store the rest back. +0x0/+0x8 is a running maximum
   of key +0x0 over a slice of 0x68-byte entries ([rsp+0x180], length
   [rsp+0x188]); the wrapper stores it at 0x5a0579e/0x5a057a2;
4. drop glue 0x5a4c8a0 reads +0x3e0 to free the map.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (RELATIVE, SHA256, TARGET, direct_calls, fixed, frame,
                                 read_va, relative_relocations)

PACKET = ROOT / 'research/work-items/RE-008-l1-hash-map-115'

L1_INSERT = 0x5a046f0
DIGEST_INSERT = 0x5a03fa0
WRAPPER_A, WRAPPER_B = 0x5a04e40, 0x5a06600
STEP_A, STEP_B = 0x5a07ec0, 0x5a08720
DROP_GLUE = 0x5a4c8a0
NAME_SLICE, LOCATION = 0x64b7f70, 0x64b7f80

FIXED = {
    # insert + trim
    0x5a04708: 'e8a3a13cff',              # call 0x4dce8b0 (insert)
    0x5a0470d: '488b5318',                # mov rdx, [rbx+0x18]   (len)
    0x5a04711: '4883fa33',                # cmp rdx, 0x33
    0x5a04da7: '488d7b08',                # lea rdi, [rbx+0x8]
    0x5a04dab: 'e8803f84ff',              # call 0x5248d30 (drop old B-tree part)
    0x5a04dfa: '48c1e003',                # shl rax, 3
    0x5a04dfe: '488d3480',                # lea rsi, [rax+rax*4]  (len*0x28)
    0x5a04e04: 'ff1596a6ad00',            # call [dealloc]
    # step A: l1 out, visor_abci_state write, insert
    0x5a080a9: '488dbc2480010000',        # lea rdi, [rsp+0x180]
    0x5a080b4: 'ba01000000',              # mov edx, 1
    0x5a080b9: 'e8f229b2fe',              # call 0x452aab0
    0x5a081e4: '0f104010',                # movups xmm0, [rax+0x10]
    0x5a081f0: '4c8b6828',                # mov r13, [rax+0x28]
    0x5a081f4: '0f1080e8100000',          # movups xmm0, [rax+0x10e8]
    0x5a08203: '8b4868',                  # mov ecx, [rax+0x68]
    0x5a0820a: '488b4060',                # mov rax, [rax+0x60]
    0x5a08218: 'ff157287ad00',            # call [0x64e0990] (wall clock)
    0x5a08240: '8d3d2afdaa00',            # lea edi, [0x64b7f70]
    0x5a08246: '488d1533fdaa00',          # lea rdx, [0x64b7f80]
    0x5a0824d: '4889e6',                  # mov rsi, rsp
    0x5a08250: 'e8eba8f3ff',              # call 0x5942b40
    0x5a08255: '498dbee0030000',          # lea rdi, [r14+0x3e0]
    0x5a0825c: '488d942480010000',        # lea rdx, [rsp+0x180]
    0x5a08264: '4c89fe',                  # mov rsi, r15
    0x5a08267: 'e884c4ffff',              # call 0x5a046f0
    # step B
    0x5a08a54: '0f1080581c0000',          # movups xmm0, [rax+0x1c58]
    0x5a08aa0: '8d3dcaf4aa00',            # lea edi, [0x64b7f70]
    0x5a08ab0: 'e88ba0f3ff',              # call 0x5942b40
    0x5a08ab5: '498dbee0030000',          # lea rdi, [r14+0x3e0]
    0x5a08abc: '488d942480010000',        # lea rdx, [rsp+0x180]
    0x5a08ac7: 'e824bcffff',              # call 0x5a046f0
    # wrapper A: running max, prune
    0x5a0579e: '49890c24',                # mov [r12], rcx
    0x5a057a2: '4989542408',              # mov [r12+0x8], rdx
    0x5a0580d: '41803c2400',              # cmp byte [r12], 0
    0x5a05818: '498b442408',              # mov rax, [r12+0x8]
    0x5a0581d: '48ffc0',                  # inc rax
    0x5a05820: '48c7c1ffffffff',          # mov rcx, -1
    0x5a05827: '480f45c8',                # cmovne rcx, rax
    0x5a05833: '498d9c24e0030000',        # lea rbx, [r12+0x3e0]
    0x5a0584e: 'e80df23dff',              # call 0x4de4a60 (split)
    0x5a05e76: 'e855a87dff',              # call 0x51e06d0 (drop loop)
    0x5a05e84: '75ea',                    # jne loop
    # wrapper B
    0x5a07062: '498d9fe0030000',          # lea rbx, [r15+0x3e0]
    0x5a0707c: 'e8dfd93dff',              # call 0x4de4a60
    # drop glue
    0x5a4c8ac: '488b87e0030000',          # mov rax, [rdi+0x3e0]
}


def count_in(data, fdes, target, start):
    return sum(1 for va in direct_calls(data, target) if frame(fdes, va) == start)


def location(data, va):
    rel = relative_relocations(data)
    ptr = rel[va]
    length, line, col = struct.unpack('<QII', read_va(data, va + 8, 16))
    return read_va(data, ptr, length).decode(), line, col


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    rel = relative_relocations(data)
    if rel.get(0x64e0990) != 0x1629690:
        raise ValueError('wall clock slot changed')
    name_len = struct.unpack('<Q', read_va(data, NAME_SLICE + 8, 8))[0]
    name = read_va(data, rel[NAME_SLICE], name_len).decode()
    loc = location(data, LOCATION)
    if name != 'visor_abci_state' or loc != ('l1/src/abci/engine.rs', 316, 46):
        raise ValueError('visor_abci_state name or Location changed')

    trims = {
        'l1': {'fn': L1_INSERT, 'insert': 0x4dce8b0, 'step_back': 0x4e2a4e0, 'split': 0x4de4a60},
        'digest': {'fn': DIGEST_INSERT, 'insert': 0x4dd45c0, 'step_back': 0x4e2a530, 'split': 0x4de5ad0},
    }
    shape = {}
    for key, t in trims.items():
        if frame(fdes, t['fn']) != t['fn']:
            raise ValueError('insert extent changed')
        shape[key] = {
            'fn': hex(t['fn']),
            'callers': [hex(v) for v in direct_calls(data, t['fn'])],
            'insert_calls': count_in(data, fdes, t['insert'], t['fn']),
            'step_back_calls': count_in(data, fdes, t['step_back'], t['fn'])
                               + count_in(data, fdes, 0x514dc20, t['fn']),
            'split_calls': count_in(data, fdes, t['split'], t['fn']),
            'trim_threshold': read_va(data, t['fn'] + 0x24, 1)[0],
        }
    split_sites = [hex(v) for v in direct_calls(data, 0x4de4a60)]
    if split_sites != ['0x5a04d9a', '0x5a0584e', '0x5a0707c']:
        raise ValueError('l1 split census changed')
    if [frame(fdes, v) for v in (0x5a0584e, 0x5a0707c)] != [WRAPPER_A, WRAPPER_B]:
        raise ValueError('wrapper extents changed')
    if [frame(fdes, v) for v in (0x5a08267, 0x5a08ac7)] != [STEP_A, STEP_B]:
        raise ValueError('step extents changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'maps': shape,
        'l1_split_sites': split_sites,
        'step_inserts': {
            'A': {'step': hex(STEP_A), 'call': hex(0x5a08267), 'map': 'r14+0x3e0', 'key': 'r15', 'value': 'rsp+0x180'},
            'B': {'step': hex(STEP_B), 'call': hex(0x5a08ac7), 'map': 'r14+0x3e0', 'key': 'r15', 'value': 'rsp+0x180'},
        },
        'step_visor_write': {
            'name': name, 'location': '%s:%d:%d' % loc, 'calls': [hex(0x5a08250), hex(0x5a08ab0)],
            'fields': 'box +0x10/+0x18, +0x28, freeze (A +0x10e8, B +0x1c58), +0x60/+0x68, wall clock slot 0x64e0990',
        },
        'wrapper_prune': {
            'A': hex(WRAPPER_A), 'B': hex(WRAPPER_B),
            'bound': 'engine value +0x0 tag, +0x8 max key; split at max+1 (saturating to u64::MAX)',
            'max_source': '0x68-byte entries at [rsp+0x180], length [rsp+0x188], key +0x0',
            'older_part': 'dropped unread (B-tree via 0x51e06d0 loop, ring via dealloc)',
        },
        'drop_glue': hex(DROP_GLUE),
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
    m = result['maps']
    print('l1 step_back=%d digest step_back=%d' % (m['l1']['step_back_calls'], m['digest']['step_back_calls']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
