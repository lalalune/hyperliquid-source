#!/usr/bin/env python3
"""Bind where node #115 awaits the initial_slow_state_for_join task (71st stage).

Continues the catch-up packets (open PRs #6060 and #6064). #6064 found that
0x2b41b70 builds the 0x350-byte catch-up future and spawns it through
0x2b3aba0 under the name `initial_slow_state_for_join`. This tool binds the
await side inside 0x2b41b70:

1. 0x2b41b70 is a state machine: the state byte is at +0x21 of the state
   ([rsi]) and selects a target from the jump table 0x60499c; its only direct
   callers are 0x2af0a5f (in 0x2af0660) and 0x2cbc06b (in 0x2cbbbe0);
2. it calls 0x2af45f0 once (0x2b42429); a result dword of 2 returns pending;
3. it logs through slot 0x64e0ae8 with the WARN template 0x43460d and the
   message at 0x605fe1 ("running non-validator to get initial abci state for
   consensus");
4. it spawns the task through 0x2b3aba0 (name 0x60601e, 0x1b bytes; Location
   base/src/lu.rs:116:5) and stores the handle at state +0x3f0;
5. it polls the handle with 0x2e4aae0; a non-zero first byte stores 3 at
   state +0x3f8 and returns pending; otherwise it releases the handle
   (lock cmpxchg 0xcc -> 0x84) and tests the result word [rsp+0x438];
6. a non-zero word goes to 0x2a90e10 and the Result::unwrap panic (slot
   0x64df6a0, message 0x605542, 0x2b bytes) at node/src/startup.rs:337:49;
7. otherwise the returned box is stored at state +0x28; when box +0x28 equals
   state +0x48 the function writes the box and three more fields to its
   output and returns state 1; when they differ it calls 0x25d3e50 with box
   +0x2c20 + 0x10 and later references the template 0x44c7fa. The body of
   0x25d3e50 is not read;
8. a separate check (0x2b41eb8) panics with "invalid starting height="
   (template 0x436a4e) at node/src/startup.rs:206:37.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import read_va, fixed, rip_target, relative_relocations, text, frame

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-join-initial-state-await-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

AWAIT_FN = 0x2b41b70
NONVALIDATOR = 0x2af45f0
SPAWN = 0x2b3aba0
JOIN_POLL = 0x2e4aae0
JOIN_ERR = 0x2a90e10
PATH_CALL = 0x25d3e50

FIXED = {
    0x2b41b96: '0fb64321',              # movzx eax, byte [rbx+0x21]   (state byte)
    0x2b42429: 'e8c221fbff',            # call 0x2af45f0
    0x2b4242e: '837c247002',            # cmp dword [rsp+0x70], 2      (pending)
    0x2b425cb: '48c783d80300001b000000',  # mov qword [rbx+0x3d8], 0x1b (name length)
    0x2b4261c: 'e87f85ffff',            # call 0x2b3aba0               (spawn)
    0x2b42621: '488983f0030000',        # mov [rbx+0x3f0], rax         (handle)
    0x2b42641: 'e89a843000',            # call 0x2e4aae0               (poll handle)
    0x2b42646: '80bc243004000000',      # cmp byte [rsp+0x430], 0
    0x2b42655: 'c60003',                # mov byte [rax], 3            (state +0x3f8 = 3)
    0x2b42682: 'b984000000',            # mov ecx, 0x84
    0x2b42687: 'b8cc000000',            # mov eax, 0xcc
    0x2b4268c: 'f0480fb10f',            # lock cmpxchg [rdi], rcx      (release handle)
    0x2b4269a: '4d85e4',                # test r12, r12                (result word)
    0x2b4269d: '0f8535050000',          # jne 0x2b42bd8                (error path)
    0x2b4272b: '48896b28',              # mov [rbx+0x28], rbp          (box)
    0x2b42760: '488b5528',              # mov rdx, [rbp+0x28]
    0x2b42764: '483b5348',              # cmp rdx, [rbx+0x48]
    0x2b42774: '488bb5202c0000',        # mov rsi, [rbp+0x2c20]
    0x2b42783: 'e8c816a9ff',            # call 0x25d3e50
    0x2b429ec: '49892e',                # mov [r14], rbp               (output box)
    0x2b429ef: '4d897e08',              # mov [r14+8], r15
    0x2b42a0a: 'b001',                  # mov al, 1                    (state 1)
    0x2b42bff: 'e80ce2f4ff',            # call 0x2a90e10
    0x2b42c2b: 'be2b000000',            # mov esi, 0x2b
    0x2b41eb8: '493917',                # cmp [r15], rdx
    0x2b41ebb: '0f82460e0000',          # jb 0x2b42d07                 (invalid height)
}
REFERENCES = (
    # (va, prefix, length, target)
    (0x2b41b9a, b'\x48\x8d\x0d', 7, 0x60499c),
    (0x2b42331, b'\x48\x8d\x05', 7, 0x605fe1),
    (0x2b4239e, b'\x48\x8d\x3d', 7, 0x43460d),
    (0x2b423ad, b'\xff\x15', 6, 0x64e0ae8),
    (0x2b425bd, b'\x4c\x8d\x25', 7, 0x60601e),
    (0x2b42612, b'\x48\x8d\x35', 7, 0x6447158),
    (0x2b427b1, b'\x48\x8d\x35', 7, 0x44c7fa),
    (0x2b42c11, b'\x48\x8d\x3d', 7, 0x605542),
    (0x2b42c1f, b'\x4c\x8d\x05', 7, 0x64480b8),
    (0x2b42c30, b'\xff\x15', 6, 0x64df6a0),
    (0x2b42d2d, b'\x48\x8d\x3d', 7, 0x436a4e),
    (0x2b42d34, b'\x48\x8d\x15', 7, 0x6448040),
    (0x2b42d40, b'\xff\x15', 6, 0x64df6b8),
)
STRINGS = {
    0x605fe1: b'running non-validator to get initial abci state for consensus',
    0x60601e: b'initial_slow_state_for_join',
    0x605542: b'called `Result::unwrap()` on an `Err` value',
    0x436a4f: b'invalid starting height=',
    0x44c7fc: b'/MARKED_FOR_DELETION',
}
LOCATIONS = {
    0x6447158: ('base/src/lu.rs', 116, 5),
    0x64480b8: ('node/src/startup.rs', 337, 49),
    0x6448040: ('node/src/startup.rs', 206, 37),
}


def location(data, rel, va):
    ptr = rel.get(va)
    if ptr is None:
        raise ValueError(f'Location {va:#x} has no relocation')
    length = struct.unpack('<Q', read_va(data, va + 8, 8))[0]
    line, col = struct.unpack('<II', read_va(data, va + 16, 8))
    return read_va(data, ptr, length).decode(), line, col


def call_census(data, targets):
    """Direct rel32 calls to each target, from one pass over .text."""
    base, code = text(data)
    found = {t: [] for t in targets}
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 > len(code):
            continue
        t = base + i + 5 + struct.unpack_from('<i', code, i + 1)[0]
        if t in found:
            found[t].append(base + i)
    return found


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, expect in STRINGS.items():
        if read_va(data, va, len(expect)) != expect:
            raise ValueError(f'string at {va:#x} changed')
    rel = relative_relocations(data)
    locations = {}
    for va, expect in LOCATIONS.items():
        got = location(data, rel, va)
        if got != expect:
            raise ValueError(f'Location {va:#x} changed')
        locations[hex(va)] = '%s:%d:%d' % got
    # every pinned site lies inside the one function 0x2b41b70
    for va in list(FIXED) + [r[0] for r in REFERENCES]:
        if frame(fdes, va) != AWAIT_FN:
            raise ValueError(f'{va:#x} left 0x2b41b70')

    census = call_census(data, (AWAIT_FN, NONVALIDATOR, SPAWN, JOIN_POLL))
    callers = census[AWAIT_FN]
    if [frame(fdes, v) for v in callers] != [0x2af0660, 0x2cbbbe0]:
        raise ValueError('0x2b41b70 caller census changed')
    spawn_calls = census[SPAWN]
    if spawn_calls != [0x2b4261c]:
        raise ValueError('spawn census changed')
    nonval_in_fn = [v for v in census[NONVALIDATOR] if frame(fdes, v) == AWAIT_FN]
    if nonval_in_fn != [0x2b42429]:
        raise ValueError('non-validator call census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'function': {
            'fde': hex(AWAIT_FN),
            'state_byte': '[rsi] +0x21, jump table 0x60499c',
            'direct_callers': [[hex(v), hex(frame(fdes, v))] for v in callers],
        },
        'non_validator': {
            'call': hex(0x2b42429) + ' -> ' + hex(NONVALIDATOR),
            'pending': 'result dword 2 returns pending',
            'all_direct_calls': [[hex(v), hex(frame(fdes, v))] for v in census[NONVALIDATOR]],
            'warn': 'slot 0x64e0ae8 at 0x2b423ad, template 0x43460d, message 0x605fe1',
        },
        'spawn': {
            'call': hex(0x2b4261c) + ' -> ' + hex(SPAWN),
            'name': '0x60601e initial_slow_state_for_join (0x1b bytes)',
            'location': locations[hex(0x6447158)],
            'handle': 'state +0x3f0',
        },
        'await': {
            'poll': hex(0x2b42641) + ' -> ' + hex(JOIN_POLL),
            'pending': 'first output byte != 0: state +0x3f8 = 3, return pending',
            'release': 'lock cmpxchg 0xcc -> 0x84 on the handle',
            'error': 'result word [rsp+0x438] != 0 -> 0x2a90e10, Result::unwrap panic slot 0x64df6a0 at '
                     + locations[hex(0x64480b8)],
            'ok': 'box -> state +0x28; box +0x28 == state +0x48 -> output [r14] = box, [r14+8] = r15, '
                  'state 1; else call 0x25d3e50 with box +0x2c20 + 0x10, then template 0x44c7fa',
        },
        'invalid_starting_height': {
            'check': hex(0x2b41eb8) + ' cmp [r15], rdx; jb 0x2b42d07',
            'panic': 'template 0x436a4e via slot 0x64df6b8 at ' + locations[hex(0x6448040)],
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
    print('callers=%d spawn=%s' % (len(result['function']['direct_callers']), result['spawn']['call']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
