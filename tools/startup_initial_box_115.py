#!/usr/bin/env python3
"""Bind where node #115's startup state machine gets its last applied height
and where its returned box goes (72nd stage).

Continues the join await packet (open PR #6065), which found that
0x2b41b70 (node/src/startup.rs) spawns initial_slow_state_for_join and
returns a box. This tool binds:

1. the starting-height check in 0x2b41b70: with input byte +0x0 bit 0
   clear, the starting height is input +0x8 (kept at state +0x38); when
   input byte +0x1 is 1 the state machine calls slot 0x64e7720 (0x595b1a0);
   on its Ok result (rax != 1) it panics through template 0x436a4e
   ("invalid starting height= ... last_applied_height=") when the starting
   height is below the returned height (jb at 0x2b41ebb); it then calls slot
   0x64e4f30 (0x38d8240, the periodic paths of #6001) with the starting
   height;
2. 0x595b1a0: formats {root}/data/{} (template 0x448b77, root cell
   0x64f06c0 via slot 0x64e0918) with the 12-byte slice "replica_cmds"
   (0x64b6828 -> 0x9383d2) and loads "no end heights found";
3. the two callers: 0x2af0660 (only call 0x2aec151, in poller 0x2aeaef0)
   and 0x2cbbbe0 (only call 0x2cb7771, in poller 0x2cb6500) are the only
   direct callers of 0x2b41b70; 0x2af0660 stores the returned box at its
   state +0x60 and compares box byte +0xb9a with state +0x556;
4. in both pollers the callee's output is written to a stack buffer and
   output +0x380 is loaded into rbp, which is passed as rdi to slot
   0x64e7440 (0x5a6bfb0, the engine builder of #5916/#6008).

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from freeze_snapshot_115 import read_va, fixed, rip_target, relative_relocations, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-startup-initial-box-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

STARTUP = 0x2b41b70
CALLER_A, CALLER_B = 0x2af0660, 0x2cbbbe0
LAST_APPLIED = 0x595b1a0
PERIODIC_PATHS = 0x38d8240
ENGINE_BUILDER = 0x5a6bfb0

FIXED = {
    # startup state machine 0x2b41b70: starting height and last applied height
    0x2b41bae: '440fb66301',            # movzx r12d, byte [rbx+0x1]
    0x2b41bb3: '488b7308',              # mov rsi, [rbx+0x8]        (starting height)
    0x2b41bcd: 'f60301',                # test byte [rbx], 1
    0x2b41d2a: '4c8d7b38',              # lea r15, [rbx+0x38]
    0x2b41d2e: '48897338',              # mov [rbx+0x38], rsi
    0x2b41d32: '4180fc01',              # cmp r12b, 1
    0x2b41d42: '4883f801',              # cmp rax, 1                (Err tag)
    0x2b41d46: '0f8567010000',          # jne 0x2b41eb3             (Ok -> check)
    0x2b41eb8: '493917',                # cmp [r15], rdx
    0x2b41ebb: '0f82460e0000',          # jb 0x2b42d07              (start < last -> panic)
    0x2b41f6d: '498b37',                # mov rsi, [r15]
    # caller 0x2af0660: box to state +0x60, layout byte compare
    0x2af0a64: '48bd0000000000000080',  # movabs rbp, 0x8000000000000000
    0x2af0a6e: '488d4501',              # lea rax, [rbp+1]          (pending marker)
    0x2af0a72: '48398424f8050000',      # cmp [rsp+0x5f8], rax
    0x2af0a92: '4c8bbc24f0050000',      # mov r15, [rsp+0x5f0]      (returned box)
    0x2af0ae1: '4c897b60',              # mov [rbx+0x60], r15
    0x2af0b15: '410fb6879a0b0000',      # movzx eax, byte [r15+0xb9a]
    0x2af0b24: '388356050000',          # cmp [rbx+0x556], al
    # poller 0x2aeaef0
    0x2aec141: '488dbc24e0030000',      # lea rdi, [rsp+0x3e0]      (callee output)
    0x2aec156: '83bc24e003000002',      # cmp dword [rsp+0x3e0], 2  (pending)
    0x2aec184: '488bac2460070000',      # mov rbp, [rsp+0x760]      (output +0x380)
    0x2aec3e9: '4889ef',                # mov rdi, rbp
    # poller 0x2cb6500
    0x2cb7761: '488dbc2430070000',      # lea rdi, [rsp+0x730]
    0x2cb77a4: '488bac24b00a0000',      # mov rbp, [rsp+0xab0]      (output +0x380)
    0x2cb7a09: '4889ef',                # mov rdi, rbp
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x2b41d3c, b'\xff\x15', 6, 0x64e7720),
    (0x2b41f75, b'\xff\x15', 6, 0x64e4f30),
    (0x2b42d2d, b'\x48\x8d\x3d', 7, 0x436a4e),
    (0x2af0a5f, b'\xe8', 5, STARTUP),
    (0x2aec151, b'\xe8', 5, CALLER_A),
    (0x2cb7771, b'\xe8', 5, CALLER_B),
    (0x2aec3ef, b'\xff\x15', 6, 0x64e7440),
    (0x2cb7a0f, b'\xff\x15', 6, 0x64e7440),
    (0x595b1b0, b'\x48\x8b\x1d', 7, 0x64e0918),
    (0x595b1d7, b'\x48\x8d\x05', 7, 0x64b6828),
    (0x595b1ef, b'\x48\x8d\x35', 7, 0x448b77),
    (0x595b335, b'\x48\x8d\x3d', 7, 0x439f32),
)
RELOCS = {0x64e7720: LAST_APPLIED, 0x64e4f30: PERIODIC_PATHS, 0x64e7440: ENGINE_BUILDER,
          0x64e0918: 0x64f06c0, 0x64b6828: 0x9383d2}
STRINGS = {0x9383d2: b'replica_cmds', 0x439f33: b'no end heights found',
           0x436a4f: b'invalid starting height=', 0x448b77: b'\xc0\x06/data/\xc0\x00'}


def call_census(data, targets):
    """One pass over .text for E8 rel32 calls to each target."""
    base, code = text(data)
    out = {t: [] for t in targets}
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code):
            t = base + i + 5 + struct.unpack_from('<i', code, i + 1)[0]
            if t in out:
                out[t].append(base + i)
    return out


def bind(data):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    if struct.unpack('<Q', read_va(data, 0x64b6830, 8))[0] != 12:
        raise ValueError('replica_cmds slice length changed')
    for va, s in STRINGS.items():
        if read_va(data, va, len(s)) != s:
            raise ValueError(f'string at {va:#x} changed')
    census = call_census(data, (STARTUP, CALLER_A, CALLER_B))
    expect = {STARTUP: [0x2af0a5f, 0x2cbc06b], CALLER_A: [0x2aec151], CALLER_B: [0x2cb7771]}
    if census != expect:
        raise ValueError('call census changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'starting_height_check': {
            'fn': hex(STARTUP),
            'starting_height': 'input +0x8 -> state +0x38 when input byte +0x0 bit 0 is clear',
            'last_applied_lookup': 'when input byte +0x1 == 1: slot 0x64e7720 -> %s; rax == 1 skips the check'
                                   % hex(LAST_APPLIED),
            'panic': 'starting height < returned height (jb 0x2b41ebb) -> template 0x436a4e',
            'then': 'slot 0x64e4f30 -> %s (periodic paths, #6001) with the starting height'
                    % hex(PERIODIC_PATHS),
        },
        'last_applied_source': {
            'fn': hex(LAST_APPLIED),
            'path': '{root}/data/{} with "replica_cmds" (0x64b6828 -> 0x9383d2, len 12); root cell 0x64f06c0',
            'error_text': hex(0x439f32) + ' "no end heights found"',
        },
        'callers': {
            'startup_calls': [hex(v) for v in census[STARTUP]],
            hex(CALLER_A): {'called_from': [hex(v) for v in census[CALLER_A]], 'poller': '0x2aeaef0',
                            'box': 'state +0x60; box byte +0xb9a compared with state +0x556'},
            hex(CALLER_B): {'called_from': [hex(v) for v in census[CALLER_B]], 'poller': '0x2cb6500'},
        },
        'poller_handoff': {
            '0x2aeaef0': 'output at rsp+0x3e0; rbp = output +0x380 (0x2aec184); rdi = rbp at 0x2aec3e9; '
                         'call slot 0x64e7440 -> %s' % hex(ENGINE_BUILDER),
            '0x2cb6500': 'output at rsp+0x730; rbp = output +0x380 (0x2cb77a4); rdi = rbp at 0x2cb7a09; '
                         'call slot 0x64e7440 -> %s' % hex(ENGINE_BUILDER),
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
    result = bind(binary.read_bytes())
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
    print('startup calls=%d' % len(result['callers']['startup_calls']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
