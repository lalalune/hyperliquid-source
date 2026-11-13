#!/usr/bin/env python3
"""Bind the node #115 slow abci step wrapper 0x59ec200 (45th stage).

Continues the slow abci driver packets (open PRs #6018 and #6019). #6019 found
that the apply-block closure locks the slow runner and calls 0x59ec200 on the
engine value. This tool binds:

1. 0x59ec200 (one direct caller, 0x4fcae48) copies a 0x58-byte argument whose
   +0x50 word is the engine value, and calls the guard 0x56185e0;
2. 0x56185e0 sets a thread-local byte to 1, calls 0x5a04e40 (its only direct
   caller) and clears the byte;
3. 0x5a04e40 reads the box's scheduled freeze height (+0x10e8 tag, +0x10f0
   value) before it calls the layout-A step 0x5a07ec0, reads it again after,
   and returns a byte at result +0xf8 that is set when the Option changed;
4. 0x5a04e40 compares 32 bytes at r13+0x48 against a second 32-byte value;
   on a mismatch it saves state to /tmp/evm_db_bad_abci_digest and
   /tmp/abci_state_bad_abci_digest.rmp through 0x4e4a740 (edx = 1) and panics
   with 'computed abci digest at height=... does not match quorum value ...';
5. back in 0x59ec200: the visor_abci_state wrapper 0x5942b40 runs only when
   that byte is set; when the freeze tag is 1 and the freeze height equals
   the height (box +0x28), the height is written as a decimal string through
   the freeze path cell (slot 0x64ebc88) and the writer slot 0x64e09e8; a
   freeze height below the height panics with the exchange.rs:607:17
   assertion.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, fixed, read_va, relative_relocations, rip_target

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-slow-abci-step-wrapper-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

WRAPPER, GUARD, INNER, STEP_A = 0x59ec200, 0x56185e0, 0x5a04e40, 0x5a07ec0
VISOR_WRAPPER, SAVE, TLS_CLEAR = 0x5942b40, 0x4e4a740, 0x150bff0
FREEZE_SLOT, FREEZE_CELL, WRITER_SLOT, WRITER = 0x64ebc88, 0x64fdd00, 0x64e09e8, 0x15024a0
PANIC_SLOT, PANIC_FMT_SLOT = 0x64df730, 0x64df6b8
ASSERT_LOC = 0x64aa278

FIXED = {
    # 0x59ec200: engine value, guard result byte, visor values, freeze test
    0x59ec27f: '4c8b6950',              # mov r13, [rcx+0x50]           (engine value)
    0x59ec2b4: '498b8550040000',        # mov rax, [r13+0x450]          (box)
    0x59ec2bb: '488b5828',              # mov rbx, [rax+0x28]           (height)
    0x59ec2c7: '80bc24b803000000',      # cmp byte [rsp+0x3b8], 0       (result +0xf8)
    0x59ec2e1: 'f30f6f80e8100000',      # movdqu xmm0, [rax+0x10e8]     (freeze Option)
    0x59ec389: '83b8e810000001',        # cmp dword [rax+0x10e8], 1     (Some)
    0x59ec39e: '488b4828',              # mov rcx, [rax+0x28]
    0x59ec3a2: '483988f0100000',        # cmp [rax+0x10f0], rcx
    0x59ec3a9: '0f822c100000',          # jb 0x59ed3db                  (freeze < height -> panic)
    0x59ed3ec: 'be3e000000',            # mov esi, 62                   (assertion length)
    # 0x56185e0: thread-local guard
    0x56185f8: '6441c60701',            # mov byte fs:[r15], 1
    0x561863f: 'c60000',                # mov byte [rax], 0
    # 0x5a04e40: freeze Option before and after the step
    0x5a04ec3: '4c8b89e8100000',        # mov r9, [rcx+0x10e8]
    0x5a04eca: '4c8b91f0100000',        # mov r10, [rcx+0x10f0]
    0x5a05fd9: '8b91e8100000',          # mov edx, [rcx+0x10e8]
    0x5a05fe7: '85c2',                  # test edx, eax                 (both Some?)
    0x5a05ff3: '483b81f0100000',        # cmp rax, [rcx+0x10f0]
    0x5a05ffa: '0f95c2',                # setne dl                      (value changed)
    0x5a05fff: '09c2',                  # or edx, eax                   (either Some)
    0x5a060d4: '8890f8000000',          # mov [rax+0xf8], dl
    # 0x5a04e40: 32-byte digest compare and the mismatch save
    0x5a05d07: 'f3410f6f5548',          # movdqu xmm2, [r13+0x48]
    0x5a05d11: 'f3410f6f4558',          # movdqu xmm0, [r13+0x58]
    0x5a05d23: '3dffff0000',            # cmp eax, 0xffff               (all 32 bytes equal)
    0x5a06103: '48c78424e00000001b000000',  # len 27
    0x5a06135: '48c744242823000000',    # len 35
    0x5a0614b: 'ba01000000',            # mov edx, 1
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x59ec2a8, b'\xe8', 5, GUARD),
    (0x59ec380, b'\xe8', 5, VISOR_WRAPPER),
    (0x59ec3b5, b'\x4c\x8b\x35', 7, FREEZE_SLOT),
    (0x59ec4ef, b'\xff\x15', 6, WRITER_SLOT),
    (0x59ed3de, b'\x48\x8d\x3d', 7, 0x929b14),
    (0x59ed3e5, b'\x48\x8d\x15', 7, ASSERT_LOC),
    (0x59ed3f1, b'\xff\x15', 6, PANIC_SLOT),
    (0x5618630, b'\xe8', 5, INNER),
    (0x561863a, b'\xe8', 5, TLS_CLEAR),
    (0x5a05fc9, b'\xe8', 5, STEP_A),
    (0x5a05d28, b'\x0f\x85', 6, 0x5a060ec),
    (0x5a060f4, b'\x48\x8d\x05', 7, 0x93a5dd),
    (0x5a06129, b'\x48\x8d\x05', 7, 0x93a5f8),
    (0x5a06150, b'\xe8', 5, SAVE),
    (0x5a061ff, b'\x48\x8d\x3d', 7, 0x44c993),
    (0x5a06212, b'\xff\x15', 6, PANIC_FMT_SLOT),
)
RELOCATIONS = {FREEZE_SLOT: FREEZE_CELL, WRITER_SLOT: WRITER, ASSERT_LOC: 0x4318d3}
STRINGS = {
    0x929b14: b'assertion failed: freeze_height >= self.locus.context.height()',
    0x4318d3: b'l1/src/exchange/exchange.rs',
    0x93a5dd: b'/tmp/evm_db_bad_abci_digest',
    0x93a5f8: b'/tmp/abci_state_bad_abci_digest.rmp',
    0x44c993: b'\x1fcomputed abci digest at height=',
}
CALLERS = {WRAPPER: [0x4fcae48], GUARD: [0x54439ad, 0x59ec2a8], INNER: [0x5618630],
           STEP_A: [0x5a05fc9, 0x5a0901f], SAVE: [0x5a06150, 0x5a6deb8]}


def freeze_changed(old_tag, old_value, new_tag, new_value):
    """The byte stored at result +0xf8 (0x5a05fd9..0x5a060d4), as a model."""
    if new_tag & old_tag:
        return int(old_value != new_value)
    return int(bool(new_tag | old_tag))


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, expect in STRINGS.items():
        if read_va(data, va, len(expect)) != expect:
            raise ValueError(f'string at {va:#x} changed')
    line, col = struct.unpack('<II', read_va(data, ASSERT_LOC + 0x10, 8))
    if (line, col) != (607, 17):
        raise ValueError('assertion Location changed')
    for target, expect in CALLERS.items():
        if direct_calls(data, target) != expect:
            raise ValueError(f'direct callers of {target:#x} changed')
    starts = {f['start'] for f in fdes}
    if not {WRAPPER, GUARD, INNER, STEP_A} <= starts:
        raise ValueError('function starts changed')

    samples = {
        'None -> None': freeze_changed(0, 0, 0, 0),
        'None -> Some(h)': freeze_changed(0, 0, 1, 100),
        'Some(h) -> None': freeze_changed(1, 100, 0, 0),
        'Some(h) -> Some(h)': freeze_changed(1, 100, 1, 100),
        'Some(h) -> Some(h2)': freeze_changed(1, 100, 1, 200),
    }
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'callers': {hex(k): [hex(v) for v in vs] for k, vs in CALLERS.items()},
        'wrapper_0x59ec200': {
            'argument': '0x58-byte value copied from rdx; +0x50 is the engine value (r13); box = [r13+0x450]',
            'guard_call': hex(0x59ec2a8) + ' -> 0x56185e0 with the first 0x28 bytes and +0x20',
            'visor_write': 'only when result byte +0xf8 (rsp+0x3b8) != 0; then 0x5942b40 (visor_abci_state)',
            'freeze_file': 'box +0x10e8 == 1 and +0x10f0 == height (+0x28): decimal height via slot %s (cell %s) '
                           'and writer slot %s (%s)' % (hex(FREEZE_SLOT), hex(FREEZE_CELL), hex(WRITER_SLOT), hex(WRITER)),
            'freeze_below_height': 'jb 0x59ed3db -> panic %r at l1/src/exchange/exchange.rs:607:17'
                                   % STRINGS[0x929b14].decode(),
        },
        'guard_0x56185e0': 'thread-local byte set to 1, call 0x5a04e40 (0x5618630), byte cleared via 0x150bff0',
        'inner_0x5a04e40': {
            'freeze_before': 'r9/r10 <- box +0x10e8/+0x10f0 at 0x5a04ec3, kept at rsp+0x1f0/+0x1e8',
            'step': hex(0x5a05fc9) + ' call 0x5a07ec0 (layout A)',
            'freeze_changed_byte': 'result +0xf8 (0x5a060d4)',
            'freeze_changed_samples': samples,
            'digest_compare': '32 bytes at r13+0x48..+0x68 vs [rax..+0x20]; all equal -> continue (0x5a05d23)',
            'digest_mismatch': 'jne 0x5a060ec: paths %s (27) and %s (35), save via 0x4e4a740 edx=1, '
                               'panic_fmt %r...' % (STRINGS[0x93a5dd].decode(), STRINGS[0x93a5f8].decode(),
                                                    STRINGS[0x44c993][1:].decode()),
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
    print('step call %s, freeze byte %s' % (result['inner_0x5a04e40']['step'], result['inner_0x5a04e40']['freeze_changed_byte']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
